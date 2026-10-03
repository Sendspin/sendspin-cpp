// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file inbound_ring.h
/// @brief The shared inbound ring: its item layout, the ring wrapper the transports and the
/// protocol task use, the intrusive per-consumer item list, the per-role quotas, the
/// per-connection inbound gate, and the ring's size derivation
///
/// Every inbound WebSocket message of an admitted connection lands in one ring item: an
/// InboundItemHeader followed by the message bytes as received, which the protocol task decrypts
/// in place. An item the protocol task hands to a consumer (a player audio chunk, a visualizer
/// frame, or a marker it writes itself) stays in the ring and is linked onto that consumer's
/// InboundItemList through its own header, so no descriptor storage exists outside the ring
/// items. The consumer returns the item when it is done with it. An unadmitted connection never
/// writes into the ring (see InboundGate).

#pragma once

#include "crypto/constants.h"
#include "platform/crypto.h"
#include "platform/event_flags.h"
#include "platform/memory.h"
#include "platform/shared_ring_buffer.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <type_traits>

namespace sendspin {

// ============================================================================
// Item layout
// ============================================================================

/// @brief The WebSocket frame type an inbound message arrived in
enum class InboundKind : uint8_t {
    TEXT,    ///< A text message (the pre-transport handshake)
    BINARY,  ///< A binary message (every Noise transport frame)
    /// An item whose receive failed after it was acquired. FreeRTOS cannot cancel an acquire,
    /// and the take order depends on every acquired item being completed, so the transport
    /// marks the item DISCARD, completes it, and uncounts it (InboundGate::abandon_ring_write());
    /// InboundRing::take() returns it to the ring without handing it out.
    DISCARD,
    /// An item the protocol task wrote itself and appended to a consumer's InboundItemList at
    /// once (a codec header, a stream boundary marker, or a message the task copied out of a
    /// reassembly or fallback buffer; see InboundRing::acquire_local()). Its place in the
    /// consumer's list is where the task appended it, not where it sits in the ring, so it is
    /// returned by two parties: InboundRing::take() returns it on the protocol task's behalf when
    /// it reaches it in ring order, and its holder returns it when done (InboundRing::
    /// return_item(), which also releases the quota charge); whichever is second gives it back
    /// to the ring (see InboundItemHeader::local_returns).
    LOCAL,
};

/// @brief The roles that hold ring items after the protocol task has routed them, each against
/// its own InboundQuota. Every other message is returned to the ring as soon as it is processed,
/// or copied out first (artwork), so it is never charged.
enum class InboundHolder : uint8_t {
    PLAYER,      ///< Encoded audio chunks and markers held by the sync task
    VISUALIZER,  ///< Frames and markers held by the visualizer drain thread
};

/// Number of InboundHolder values.
static constexpr size_t INBOUND_HOLDER_COUNT = 2;

/// @brief Throttles the warning at a drop site that can drop every message of a burst
///
/// The first drop of a run logs (note_drop() returns true), the drops after it are only counted,
/// and the next delivery at the site ends the run and returns the count, which the site logs. A
/// run that no delivery follows (the stream or the connection ended) is ended where its site's
/// owner tears down: a role's recall after a teardown, a connection's destructor. A drop is
/// therefore never silent, and a sustained overrun costs two log lines rather than one per
/// message. Not thread-safe: each instance belongs to the one thread that runs its site, or to
/// whichever thread tears it down once that one is joined.
class InboundDropLog {
public:
    /// @brief Counts a drop. @return true for the first drop of a run, which the site logs.
    bool note_drop() {
        return this->dropped_++ == 0;
    }

    /// @brief Ends a run of drops. @return How many it had, 0 when there was none.
    uint32_t note_delivery() {
        const uint32_t dropped = this->dropped_;
        this->dropped_ = 0;
        return dropped;
    }

private:
    uint32_t dropped_{0};
};

/// InboundItemHeader::next for the last item of a list.
static constexpr uint32_t INBOUND_LIST_END = UINT32_MAX;

/// Bound on a transport's InboundRing::acquire() for an admitted connection's message, after
/// which the message is dropped with a warning. The ring holds every holder's quota plus a
/// pass-through allowance (derive_inbound_ring_bytes()), so an acquire waits only while the
/// protocol task is behind on taking items or while ring-order reclamation holds space behind the
/// oldest held item. Sized at the bottom of the 100-200 ms stall budget the library's threads are
/// held to:
/// longer than a protocol tick that runs a Noise handshake's DH operations (tens of milliseconds
/// on an ESP32), so a busy task does not cost a message, and short enough that a stalled one
/// costs a dropped message rather than a parked transport. On ESP each timed-out acquire parks
/// the one httpd task every inbound session shares, so every session waits behind it. The codec
/// header and the stream markers wait the same bound for room (HEADER_SEND_TIMEOUT_MS).
static constexpr uint32_t INBOUND_ACQUIRE_TIMEOUT_MS = 100;

/// The largest WebSocket message a conforming peer sends: one Noise transport frame, plaintext
/// plus the AEAD tag. Larger messages are fragmented inside the Noise transport (messaging.md
/// "Fragmentation").
static constexpr size_t INBOUND_MAX_MESSAGE_BYTES = MAX_TRANSPORT_PLAINTEXT + AEAD_TAG_SIZE;

/// Size of InboundItemHeader, paid once per ring item.
static constexpr size_t INBOUND_ITEM_HEADER_BYTES = 32;

/// The most ring storage an item costs beyond its plaintext: the ring's own item header, the
/// InboundItemHeader, the AEAD tag, and the padding to SharedRingLayout::STORAGE_ALIGNMENT. A role
/// that holds items derives the share of its quota it advertises from this against its minimum
/// chunk size.
static constexpr size_t INBOUND_ITEM_STORED_OVERHEAD_BYTES =
    SharedRingLayout::ITEM_HEADER_BYTES + INBOUND_ITEM_HEADER_BYTES + AEAD_TAG_SIZE +
    (SharedRingLayout::STORAGE_ALIGNMENT - 1);

/**
 * @brief Leads every inbound ring item; the message bytes follow it
 *
 * InboundRing::acquire() zeroes the whole header; the transport then fills connection_id,
 * receive_time_us and kind, and every other field stays zero until the protocol task fills it.
 * The protocol task fills the consumer fields (next, data_offset, data_len, generation, type) and,
 * through InboundRing::charge(), charge and holder, before it appends the item to a consumer's
 * InboundItemList; from then on only that consumer touches the item until it returns it. A
 * chunk's or frame's server timestamp is not copied here: the consumer reads it from plaintext
 * bytes 1 to 8, where it arrived.
 *
 * Every field is at most 4-byte aligned: a FreeRTOS no-split ring places items on 4-byte
 * boundaries (SharedRingLayout::STORAGE_ALIGNMENT), which rules out an int64_t or, on a 64-bit
 * host, a pointer, so the list link is a storage offset.
 */
struct InboundItemHeader {
    // 32-bit fields
    /// Storage offset of the next item in the same consumer list, or INBOUND_LIST_END. Written
    /// by the protocol task under the list's mutex; read by the consumer under it.
    uint32_t next;
    /// Low 32 bits of SendspinConnection::get_instance_id(): the connection the item arrived on.
    /// Instance ids are process-unique and monotonic, so the low word only repeats after 2^32
    /// connections, far beyond any item's life.
    uint32_t connection_id;
    /// Low 32 bits of platform_time_us() when the transport received the message. An item lives
    /// far less than the 2^32 us (about 71 minutes) wrap, so the full time is recovered against
    /// the current clock with widen_time_stamp_us().
    uint32_t receive_time_us;
    /// Ring-stored bytes charged to holder's quota, 0 for an uncharged item; released by
    /// InboundRing::return_item().
    uint32_t charge;
    /// Teardown generation the consumer's role was at when the item was appended; a consumer
    /// discards an item whose stamp no longer matches its role's generation.
    uint32_t generation;
    /// Length of the slice the consumer reads, starting data_offset bytes into the message
    /// bytes. 32 bits: a LOCAL item can hold a message reassembled from several Noise frames.
    uint32_t data_len;

    // 8-bit fields
    /// Offset of the consumer's slice within the message bytes (past the type byte and any
    /// in-band header the consumer does not need).
    uint8_t data_offset;
    InboundKind kind;
    /// Consumer-defined item type: the ChunkType for the player, the wire message type or a
    /// marker for the visualizer.
    uint8_t type;
    /// The holder the item was charged to; meaningful only while holder_set is non-zero.
    InboundHolder holder;
    /// Returns counted against an InboundKind::LOCAL item: the protocol task's take and the
    /// holder's return each add one, and the one that brings it to LOCAL_ITEM_PARTIES gives the
    /// item back to the ring; zero and unused for every other kind. A plain field, never an
    /// atomic: the ring may sit in external RAM, where the ESP32's compare-and-set cannot operate
    /// (esp_cpu_compare_and_set() refuses it). Once holder_set is non-zero it is updated only
    /// under the holder's InboundItemList mutex, which lives in internal RAM; before that both
    /// parties are the protocol task.
    uint8_t local_returns;
    /// Non-zero once InboundRing::charge() charged the item to `holder`. Written by the protocol
    /// task before the item is appended to the holder's list; never cleared.
    uint8_t holder_set;
    /// Unused; zeroed by acquire() and keeps the header free of padding.
    uint16_t reserved;
};
static_assert(std::is_trivially_copyable_v<InboundItemHeader> &&
                  std::is_standard_layout_v<InboundItemHeader>,
              "an inbound item header lives in raw ring storage");
static_assert(alignof(InboundItemHeader) <= SharedRingLayout::STORAGE_ALIGNMENT,
              "a FreeRTOS no-split ring item is only 4-byte aligned");
static_assert(sizeof(InboundItemHeader) == INBOUND_ITEM_HEADER_BYTES,
              "the header is paid once per ring item, and every held audio chunk is one item");
static_assert(std::has_unique_object_representations_v<InboundItemHeader>,
              "the header has no padding: every byte is a field acquire() zeroes");

/// The two returns an InboundKind::LOCAL item needs before it goes back to the ring: the
/// protocol task's take in ring order and the holder's return.
static constexpr uint8_t LOCAL_ITEM_PARTIES = 2;

/// @brief The header at the start of a ring item
inline InboundItemHeader* inbound_item_header(void* item) {
    return static_cast<InboundItemHeader*>(item);
}

/// @brief The message bytes following an item's header
inline uint8_t* inbound_item_bytes(void* item) {
    return static_cast<uint8_t*>(item) + sizeof(InboundItemHeader);
}

/// @brief The consumer's slice of an item: its message bytes from data_offset on
inline uint8_t* inbound_item_data(void* item) {
    return inbound_item_bytes(item) + inbound_item_header(item)->data_offset;
}

/// @brief Recovers a full platform_time_us() reading from its low 32 bits, as stored in
/// InboundItemHeader::receive_time_us, against the current clock
///
/// Exact while the stamped moment is less than 2^32 us (about 71 minutes) before `now`, which an
/// inbound message's life never approaches. Shared by the protocol task (server/time keeps the
/// transport stamp) and the visualizer drain thread (a frame's arrival).
/// @param stamp The low 32 bits of the earlier reading.
/// @param now   The current platform_time_us().
inline int64_t widen_time_stamp_us(uint32_t stamp, int64_t now) {
    // Unsigned subtraction of the low words gives the age modulo 2^32 us.
    return now - static_cast<uint32_t>(static_cast<uint32_t>(now) - stamp);
}

// ============================================================================
// Quotas
// ============================================================================

/**
 * @brief An outstanding-byte budget charged and released from any threads
 *
 * try_charge() and release() are lock-free atomic updates, so the charging thread (the protocol
 * task) and the releasing thread (a consumer returning an item, or the protocol task recalling
 * one) need no common lock. Charges are in ring-stored bytes (SharedRingLayout::stored_size()),
 * the cost an item actually has in the ring.
 */
class InboundQuota {
public:
    InboundQuota() = default;
    explicit InboundQuota(size_t limit) : limit_(limit) {}

    InboundQuota(const InboundQuota&) = delete;
    InboundQuota& operator=(const InboundQuota&) = delete;

    /// @brief Sets the budget. Call before any thread charges it.
    void set_limit(size_t limit) {
        this->limit_ = limit;
    }

    /// @brief The budget in bytes
    size_t limit() const {
        return this->limit_;
    }

    /// @brief Bytes charged and not yet released. Any thread.
    size_t outstanding() const {
        return this->outstanding_.load(std::memory_order_acquire);
    }

    /// @brief Charges `bytes` when they fit the budget. Any thread.
    /// @return false, charging nothing, when the charge would exceed the limit; the caller
    ///         drops the item and logs the drop.
    bool try_charge(size_t bytes) {
        size_t current = this->outstanding_.load(std::memory_order_relaxed);
        do {
            if (bytes > this->limit_ || current > this->limit_ - bytes) {
                return false;
            }
        } while (!this->outstanding_.compare_exchange_weak(
            current, current + bytes, std::memory_order_acq_rel, std::memory_order_relaxed));
        return true;
    }

    /// @brief Releases bytes an earlier try_charge() charged. Any thread.
    void release(size_t bytes) {
        this->outstanding_.fetch_sub(bytes, std::memory_order_acq_rel);
    }

private:
    // size_t fields
    /// Written by set_limit() before any charge; read by every charging thread.
    size_t limit_{0};
    /// Charged by the charging thread, released by the releasing thread (see the class comment).
    std::atomic<size_t> outstanding_{0};
};

// ============================================================================
// InboundRing
// ============================================================================

class InboundItemList;

/**
 * @brief The shared inbound ring: a SharedRingBuffer over its own storage, the per-role quotas,
 * and the one return path that releases a returned item's charge
 *
 * Producers are the transport threads (acquire(), complete()); every acquired item must be
 * completed. The consumer is the protocol task (take()), which also charges what it hands to a
 * holder. Any thread returns items, always through return_item().
 *
 * take() never hands out an uncompleted item. SharedRingBuffer can, on ESP, hand out the item at
 * the start of the storage right after a wrap before its producer completes it (see
 * shared_ring_buffer.h), so the ring counts completions of items at the storage start and the
 * protocol task counts its takes of them. An item there can only be acquired once the previous
 * one there was taken and returned, so the k-th such take is safe exactly when the k-th such
 * completion has happened; until then the item is held back as pending and nothing behind it is
 * taken. Stale bytes in reused storage cannot fake this, unlike a flag inside the item.
 */
class InboundRing {
public:
    InboundRing() = default;
    ~InboundRing() = default;

    InboundRing(const InboundRing&) = delete;
    InboundRing& operator=(const InboundRing&) = delete;

    /// @brief Allocates the storage and creates the ring. Call before any producer or consumer
    /// runs.
    /// @param storage_bytes From derive_inbound_ring_bytes().
    /// @param location Placement preference for the storage.
    /// @return false when the storage cannot be allocated or the size is refused.
    bool create(size_t storage_bytes, MemoryLocation location);

    /// @brief Whether create() succeeded
    bool is_created() const {
        return this->ring_.is_created();
    }

    /// @brief The ring's storage base, which InboundItemHeader::next offsets are relative to
    uint8_t* storage() const {
        return this->ring_.storage();
    }

    /// @brief The quota of one holder. Set its limit before the protocol task charges it.
    InboundQuota& quota(InboundHolder holder) {
        return this->quotas_[static_cast<size_t>(holder)];
    }

    /// @brief Reserves an item for a message of `message_len` bytes, its header zeroed.
    /// Transport threads.
    ///
    /// Every item acquired must be completed: FreeRTOS cannot cancel an acquire, an uncompleted
    /// item holds back every item behind it, and the storage-start count take() relies on counts
    /// completions. A transport whose receive fails after acquiring marks the item
    /// InboundKind::DISCARD and completes it. A peer that stalls part-way through a message
    /// keeps its item uncompleted until the liveness watchdog drops the connection, since the
    /// liveness stamp is taken when a message completes (see
    /// SendspinConnection::note_message_completed()).
    /// @param timeout_ms As SharedRingBuffer::acquire().
    /// @return The item (header first), or nullptr.
    void* acquire(size_t message_len, uint32_t timeout_ms);

    /// @brief Reserves an item the protocol task fills itself and appends to a consumer's list
    /// (InboundKind::LOCAL), its header zeroed apart from the kind. Protocol task only. Complete
    /// it with complete() as soon as it is filled: an uncompleted item holds back every item
    /// behind it.
    /// @param message_len Bytes after the header.
    /// @param timeout_ms As SharedRingBuffer::acquire(). The protocol task is the ring's only
    ///        taker, so a wait here ends only on returns from the consumers.
    /// @return The item, or nullptr.
    void* acquire_local(size_t message_len, uint32_t timeout_ms);

    /// @brief Publishes a filled item. The thread that acquired it.
    void complete(void* item);

    /// @brief Takes the oldest completed item, returning DISCARD items to the ring on the way
    /// without handing them out, and counting the protocol task's return of each LOCAL item it
    /// passes (see InboundKind::LOCAL). Protocol task only.
    /// @param[out] message_len The length of the message bytes after the header.
    /// @param timeout_ms As SharedRingBuffer::take(), applied to each underlying take.
    /// @return The item, or nullptr: nothing completed in time, a wake_receiver() interruption,
    ///         or the oldest item still being written.
    void* take(size_t* message_len, uint32_t timeout_ms);

    /// @brief Returns every item still in the ring, so a restart begins empty. Call only once
    /// every producer has stopped (each acquired item is then completed) and every holder has
    /// returned or recalled its items; the protocol task is the caller or is joined. A pending
    /// item (see pending_) is returned only after its completion is confirmed.
    void reset();

    /// @brief Charges a taken item to a holder's quota, recording the charge and the holder in
    /// its header. Protocol task only, before the item is appended to the holder's list.
    /// @param message_len The length take() reported for the item.
    /// @return false when the holder is over quota: the caller returns the item and logs the drop.
    bool charge(void* item, size_t message_len, InboundHolder holder);

    /// @brief Returns a taken item to the ring, releasing any quota charge it carries: the
    /// holder's return (the consumer, or the protocol task returning an item it did not hand
    /// over or recalled). Any thread. A LOCAL item's charge is released here, and the item goes
    /// back to the ring on the second of its two returns (see InboundKind::LOCAL).
    void return_item(void* item);

    /// @brief Registers the list that holds `holder`'s items, which counts a LOCAL item's returns
    /// under its own mutex once the item is charged to that holder; nullptr unregisters it.
    ///
    /// Lifetime: InboundItemList::create() registers the list before any item is charged, and
    /// InboundItemList::unbind() unregisters it once the holder's consumer is joined and its
    /// items recalled, before the list can be destroyed. With the list unregistered every thread
    /// that returns items is joined, so the return count needs no lock (count_local_return()).
    void register_list(InboundHolder holder, InboundItemList* list) {
        this->lists_[static_cast<size_t>(holder)] = list;
    }

    /// @brief Wakes the protocol task out of a blocking take(). Any thread.
    void wake_receiver() {
        this->ring_.wake_receiver();
    }

    /// @brief Completed items not yet taken. Any thread.
    size_t items_waiting() const {
        return this->ring_.items_waiting();
    }

private:
    /// @brief Whether every item taken at the storage start has been completed
    bool head_takes_completed() const {
        const uint32_t completions = this->head_completions_.load(std::memory_order_acquire);
        return static_cast<int32_t>(completions - this->head_takes_) >= 0;
    }

    /// @brief Hands out the pending item once it is completed, waiting up to `timeout_ms`
    void* take_pending(size_t* message_len, uint32_t timeout_ms);

    /// @brief One take from the ring, before DISCARD items are filtered out
    void* take_one(size_t* message_len, uint32_t timeout_ms);

    /// @brief The protocol task's ring-order return of a taken item that is not handed out: a
    /// DISCARD item goes back at once, a LOCAL item counts its ring-order party (see
    /// InboundKind::LOCAL).
    void return_in_ring_order(void* item);

    /// @brief Counts one of a LOCAL item's two returns: through its holder's registered list
    /// once it was charged, otherwise directly (both parties are the protocol task, or every
    /// thread is joined). @return true when this was the second.
    bool count_local_return(InboundItemHeader* header, bool release_charge);

    // Struct fields
    SharedRingBuffer ring_;
    PlatformBuffer storage_;
    /// Charged by the protocol task, released by whichever thread returns a charged item.
    std::array<InboundQuota, INBOUND_HOLDER_COUNT> quotas_{};
    /// Each holder's list (register_list()), whose mutex guards the return count of a LOCAL item
    /// charged to it. Written before any item is charged.
    std::array<InboundItemList*, INBOUND_HOLDER_COUNT> lists_{};

    // Pointer fields
    /// An item taken at the storage start before its completion was confirmed, with its message
    /// length. Protocol task only. It is never returned to the ring before its completion is
    /// confirmed: its producer may still be writing it, and returning it early would also put
    /// head_takes_ out of step with head_completions_. reset() waits for that confirmation.
    void* pending_{nullptr};

    // size_t fields
    size_t pending_len_{0};

    // 32-bit fields
    /// Completions of items at the storage start. Incremented by transport threads before the
    /// item is published; read by the protocol task.
    std::atomic<uint32_t> head_completions_{0};
    /// Takes of items at the storage start. Protocol task only. Never reset: it and
    /// head_completions_ stay in step across reset(), since every item counted by one is counted
    /// by the other once the pending item is confirmed.
    uint32_t head_takes_{0};
};

// ============================================================================
// InboundItemList
// ============================================================================

/**
 * @brief Intrusive FIFO of ring items handed from the protocol task to one consumer thread
 *
 * The link lives in each item's InboundItemHeader::next, so the list has no capacity of its
 * own: it holds exactly the items the ring holds and cannot overflow independently.
 * Back-pressure is the ring itself plus the per-role quotas. Single producer (the protocol task,
 * append()), single consumer (the sync task or the visualizer drain thread, take()); recall()
 * may run on the protocol task, or on any thread once the consumer is joined.
 *
 * mutex_ guards head_, tail_ and every next link of a linked item, and the return count of a
 * LOCAL item charged to this list's holder (InboundRing::return_item()). It is a leaf: nothing
 * is called under it, and the ring's lock is taken only after it is released (recall() detaches
 * the chain first, then returns the items).
 */
class InboundItemList {
public:
    InboundItemList() = default;
    ~InboundItemList() = default;

    InboundItemList(const InboundItemList&) = delete;
    InboundItemList& operator=(const InboundItemList&) = delete;

    /// @brief Binds the list to the ring whose items it links, registers it as `holder`'s list
    /// (InboundRing::register_list()) and creates its wake flags. Call after the ring is created
    /// and before the producer or the consumer runs.
    /// @return false when the event flags cannot be created.
    bool create(InboundRing* ring, InboundHolder holder);

    /// @brief Unregisters the list from its ring (InboundRing::register_list()). Call once the
    /// consumer is joined and the list recalled, before the list or the ring goes away; create()
    /// binds it again.
    void unbind();

    /// @brief Counts one of a LOCAL item's two returns under this list's mutex, which guards the
    /// count of every LOCAL item charged to the list's holder: the ring storage may be external
    /// RAM, where the ESP32 cannot run an atomic (see InboundItemHeader::local_returns). The
    /// holder's return also releases the item's charge against `quota`, outside the lock. Any
    /// thread; called by InboundRing.
    /// @return true when this was the second return.
    bool count_local_return(InboundItemHeader* header, bool release_charge, InboundQuota& quota);

    /// @brief Appends a ring item and wakes the consumer. Protocol task only.
    /// @param item An item taken from the bound ring, its consumer header fields filled.
    void append(void* item);

    /// @brief Takes the oldest appended item. Consumer only.
    /// @param timeout_ms Milliseconds to wait for an item: 0 does not wait, UINT32_MAX waits
    ///        indefinitely.
    /// @return The item, which the consumer hands to InboundRing::return_item() when done, or
    ///         nullptr on timeout, on a wake_receiver() interruption, or on a wake left by an
    ///         append whose item an earlier take already removed. Treat nullptr as "re-check
    ///         state and retry".
    void* take(uint32_t timeout_ms);

    /// @brief Wakes the consumer out of a blocking take(); one-shot, and redundant wakes
    /// collapse. Any thread.
    void wake_receiver() {
        this->flags_.set(WAKE);
    }

    /// @brief Unlinks every item not yet taken and returns each through
    /// InboundRing::return_item(), oldest first, releasing its charge. Protocol task, or any
    /// thread once the consumer is joined.
    /// @return The number of items returned.
    size_t recall();

    /// @brief Whether no item is linked. Any thread.
    bool is_empty() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->head_ == INBOUND_LIST_END;
    }

private:
    /// Event flag bits
    static constexpr uint32_t ITEMS_APPENDED = 1U << 0;
    static constexpr uint32_t WAKE = 1U << 1;

    /// @brief Unlinks the head item, or returns nullptr when the list is empty
    void* pop();

    /// @brief The item at a storage offset
    void* item_at(uint32_t offset) const {
        return this->storage_ + offset;
    }

    // Struct fields
    /// Set by append() and wake_receiver(); a blocking take() waits on it.
    EventFlags flags_;
    /// Guards head_, tail_ and the links of linked items; a leaf lock (see the class comment).
    mutable std::mutex mutex_;

    // Pointer fields
    /// Written once by create(), before the producer and consumer run.
    InboundRing* ring_{nullptr};
    uint8_t* storage_{nullptr};

    // 8-bit fields
    /// The holder create() registered the list for. Written once by create().
    InboundHolder holder_{InboundHolder::PLAYER};

    // 32-bit fields
    /// Storage offsets of the oldest and newest linked items, INBOUND_LIST_END when empty.
    /// Written by the protocol task (append, recall) and the consumer (take), under mutex_.
    uint32_t head_{INBOUND_LIST_END};
    uint32_t tail_{INBOUND_LIST_END};
};

/// @brief Charges an item to a holder's quota and appends it to that holder's list. Protocol task
/// only.
/// @param message_len The item's message length, as take() reported it or acquire_local() was
///        asked for.
/// @return false, appending nothing, when the holder is over quota: the caller returns the item
///         and logs the drop.
inline bool hand_inbound_item(InboundRing& ring, InboundItemList& list, InboundHolder holder,
                              void* item, size_t message_len) {
    if (!ring.charge(item, message_len, holder)) {
        return false;
    }
    list.append(item);
    return true;
}

// ============================================================================
// InboundGate
// ============================================================================

/**
 * @brief The per-connection state the transport and the protocol task share without a lock
 *
 * Embedded in SendspinConnection. It carries:
 *  - the admitted flag, which decides where the transport puts a message;
 *  - the pre-admission hand-off: an unadmitted connection never writes into the shared ring,
 *    because items returned at once still stay unreclaimable behind held audio, so a peer that
 *    holds only the Sentinel PSK could otherwise fill the ring. It delivers each complete message
 *    through its own fallback buffer, of at most PRE_ADMISSION_MESSAGE_BYTES, one message at a
 *    time. A larger message closes the connection, which is tighter than the one-frame
 *    (INBOUND_MAX_MESSAGE_BYTES) limit an admitted connection has;
 *  - the in-flight count of ring items the transport has begun writing and the protocol task
 *    has not yet taken;
 *  - the out-of-band close flag, honoured only once nothing of the connection is still queued
 *    (close_ready());
 *  - the detached flag, set once nothing reads the connection any more (it left the connection
 *    manager, or the protocol task closed it): the transport then writes nothing anywhere and
 *    drops what it receives, and a wait_until_writable() ends at once, so no transport thread a
 *    release joins is parked on this gate.
 *
 * Ordering at admission. While a pre-admission message is pending the transport writes nowhere,
 * neither into the fallback buffer nor into the ring (may_write(), and begin_ring_write() and
 * publish_pending_message() refuse), and it waits for consume_pending_message() through
 * wait_until_writable(). The protocol task handles a connection's pending message before any of
 * its ring items. The message that gets a connection admitted is therefore processed, and the
 * admitted flag set, before the transport routes its next message, which then goes to the ring.
 * The reverse transition, dropping an admitted connection, precedes its close, so ring items it
 * still has queued never need ordering against a later fallback message.
 *
 * Cost: one event group per connection for that wait (an xEventGroupCreate() heap allocation on
 * ESP, made in the constructor); is_created() reports whether it succeeded.
 */
class InboundGate {
public:
    /// The largest message an unadmitted connection may deliver: what legitimately precedes
    /// admission (the handshake, server/hello, server/activate, pairing JSON, and the role JSON
    /// a server sends right behind its activation) is the traffic
    /// MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES already bounds for one reassembled message.
    static constexpr size_t PRE_ADMISSION_MESSAGE_BYTES =
        MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES;

    /// Bound on the transport's wait_until_writable() before it gives up on an unadmitted
    /// connection and closes it. A protocol tick can wait on two things: the Noise handshake's
    /// DH operations (tens of milliseconds on an ESP32), and up to two INBOUND_ACQUIRE_TIMEOUT_MS
    /// waits for ring space for a codec header and a stream marker (200 ms). Every lock the
    /// task takes is a leaf held for a copy, so nothing else stretches a tick. 500 ms covers
    /// both with a margin; a task stalled beyond it closes the waiting connection rather than
    /// parking the transport thread, which on ESP is the httpd task every inbound connection
    /// shares.
    static constexpr uint32_t WRITABLE_WAIT_MS = 500;

    InboundGate() {
        this->consumed_flags_.create();
    }

    /// @brief Whether the gate's event group was created. Connection setup checks it and fails
    /// closed: without it the transport has no way to wait for a consume.
    bool is_created() const {
        return this->consumed_flags_.is_created();
    }

    InboundGate(const InboundGate&) = delete;
    InboundGate& operator=(const InboundGate&) = delete;

    // ---- Admission ----

    /// @brief Records whether the connection holds an admitted slot. Written on the thread that
    /// admits and drops connections.
    void set_admitted(bool admitted) {
        this->admitted_.store(admitted, std::memory_order_release);
    }

    /// @brief Whether the connection holds an admitted slot. Any thread; the transport reads it
    /// to choose between the ring and the fallback buffer.
    bool is_admitted() const {
        return this->admitted_.load(std::memory_order_acquire);
    }

    // ---- Pre-admission hand-off ----

    /// @brief Whether a pre-admission message of `len` bytes is within the cap; the transport
    /// closes the connection on one that is not
    static constexpr bool pre_admission_message_fits(size_t len) {
        return len <= PRE_ADMISSION_MESSAGE_BYTES;
    }

    /// @brief Whether the transport may write its next message anywhere: false while a
    /// pre-admission message is pending. Transport thread; only the transport sets the pending
    /// flag, so a true answer stays true until the transport itself publishes.
    bool may_write() const {
        return !this->message_pending_.load(std::memory_order_acquire);
    }

    /// @brief Waits until the protocol task has consumed the pending message. Transport thread.
    ///
    /// A CONSUMED bit can be left over from the previous message: consume_pending_message()
    /// clears the pending flag before it sets the bit, so the transport can publish the next
    /// message in between and the late bit then lands on it. The wait therefore loops on
    /// may_write() rather than trusting a single wake.
    /// @param timeout_ms Bound on the wait; UINT32_MAX waits until the message is consumed or the
    ///        gate is detached.
    /// @return may_write() at the end of the wait: false when it timed out, or at once once the
    ///         gate is detached with a message still pending.
    bool wait_until_writable(uint32_t timeout_ms);

    /// @brief Publishes the complete message now in the fallback buffer. Transport thread, after
    /// writing it; the caller then wakes the protocol task.
    /// @return false, publishing nothing, while an earlier message is still pending.
    bool publish_pending_message() {
        if (!this->may_write()) {
            return false;
        }
        // Cleared before the flag is raised, so a CONSUMED bit left by the previous message
        // cannot end the next wait_until_writable() early.
        this->consumed_flags_.clear(CONSUMED);
        this->message_pending_.store(true, std::memory_order_release);
        return true;
    }

    /// @brief Whether a published message waits in the fallback buffer. Protocol task.
    bool has_pending_message() const {
        return this->message_pending_.load(std::memory_order_acquire);
    }

    /// @brief Hands the fallback buffer back to the transport and wakes it out of
    /// wait_until_writable(). Protocol task, once it is done reading the message.
    void consume_pending_message() {
        this->message_pending_.store(false, std::memory_order_release);
        this->consumed_flags_.set(CONSUMED);
    }

    // ---- In-flight ring items ----

    /// @brief Counts a ring item the transport is about to acquire. Transport thread, before
    /// InboundRing::acquire().
    /// @return false, counting nothing, while a pre-admission message is pending (see the class
    ///         comment); the transport waits with wait_until_writable() and routes again.
    bool begin_ring_write() {
        if (!this->may_write()) {
            return false;
        }
        this->in_flight_.fetch_add(1, std::memory_order_acq_rel);
        return true;
    }

    /// @brief Uncounts an item whose acquire failed, or a DISCARD item once it is completed
    /// (InboundRing::take() returns those without the protocol task seeing them). Transport
    /// thread.
    void abandon_ring_write() {
        this->in_flight_.fetch_sub(1, std::memory_order_acq_rel);
    }

    /// @brief Uncounts an item the protocol task has taken from the ring. Protocol task.
    void note_item_taken() {
        this->in_flight_.fetch_sub(1, std::memory_order_acq_rel);
    }

    /// @brief Ring items begun and not yet taken. Any thread.
    uint32_t in_flight() const {
        return this->in_flight_.load(std::memory_order_acquire);
    }

    // ---- Close ----

    /// @brief Records that the transport has closed. Transport thread, after its last item is
    /// completed or its last message published; the caller then wakes the protocol task.
    void mark_transport_closed() {
        this->transport_closed_.store(true, std::memory_order_release);
    }

    /// @brief Whether the transport has closed, whether or not its messages are drained
    bool is_transport_closed() const {
        return this->transport_closed_.load(std::memory_order_acquire);
    }

    // ---- Detach ----

    /// @brief Records that nothing reads this connection any more and wakes a transport waiting
    /// in wait_until_writable(). Any thread: the connection manager when the connection leaves
    /// it, and the protocol task when it closes the connection. Never cleared.
    void detach() {
        this->detached_.store(true, std::memory_order_release);
        this->consumed_flags_.set(CONSUMED);
    }

    /// @brief Whether detach() ran. Any thread; the transport drops what it receives once it is
    /// true, and the protocol task drops what it takes for the connection.
    bool is_detached() const {
        return this->detached_.load(std::memory_order_acquire);
    }

    /// @brief Whether the protocol task may honour the close: the transport has closed, and
    /// every ring item it wrote has been taken and no pre-admission message waits, so acting on
    /// the close now keeps "after every message" ordering. The flag is read first: once it reads
    /// true the transport writes nothing more, so the counts read after it are final on the
    /// transport's side. An acquired-but-uncompleted item of another connection can hold this
    /// connection's completed items back in the ring, which is why the flag alone is not enough.
    /// Protocol task.
    bool close_ready() const {
        return this->is_transport_closed() && this->in_flight() == 0 &&
               !this->has_pending_message();
    }

private:
    /// Event flag bit: the protocol task consumed the pending message.
    static constexpr uint32_t CONSUMED = 1U << 0;

    // Struct fields
    /// Set by the protocol task (consume_pending_message()), waited on and cleared by the
    /// transport thread (wait_until_writable(), publish_pending_message()).
    EventFlags consumed_flags_;

    // 32-bit fields
    /// in_flight counts the items the protocol task will be handed. The transport uncounts an
    /// item it knows will never be handed over: a failed acquire at once, a DISCARD item only
    /// after complete(). So close_ready() can never be true while the transport still holds an
    /// uncompleted item. Incremented and uncounted by the transport thread; decremented by the
    /// protocol task at take.
    std::atomic<uint32_t> in_flight_{0};

    // 8-bit fields
    /// Written by the thread that admits and drops connections; read by the transport thread and
    /// any thread asking whether the connection is admitted.
    std::atomic<bool> admitted_{false};
    /// Set by the protocol task (the connection manager, or the receive path closing the
    /// connection), or by stop() once it is joined; read by the transport thread and the protocol
    /// task.
    std::atomic<bool> detached_{false};
    /// Set by the transport thread (publish), cleared by the protocol task (consume).
    std::atomic<bool> message_pending_{false};
    /// Written by the transport thread (mark_transport_closed()); read by the protocol task.
    std::atomic<bool> transport_closed_{false};
};

// ============================================================================
// InboundMessage
// ============================================================================

/**
 * @brief One complete inbound message as the protocol task processes it
 *
 * The bytes are in a ring item (`item` set: an admitted connection's message), in the
 * connection's fallback buffer (a pre-admission message), or in the Noise reassembly buffer (a
 * fragmented message); only the first can be handed to a consumer as it is. A role that keeps the
 * item (appends it to its consumer's list) clears `item`, and the caller returns whatever is left
 * set.
 */
struct InboundMessage {
    // Pointer fields
    /// The ring item holding `data`, or nullptr. Cleared by a role that takes the item over.
    void* item{nullptr};
    /// The message bytes: ciphertext as received, plaintext (type byte first) once decrypted.
    uint8_t* data{nullptr};

    // size_t fields
    /// The item's message length, as InboundRing::take() reported it (what a charge is computed
    /// from); 0 when `item` is null.
    size_t item_len{0};
    /// Length of `data`.
    size_t len{0};

    // 32-bit fields
    /// Low 32 bits of platform_time_us() when the transport received the message.
    uint32_t receive_time_us{0};

    // 8-bit fields
    InboundKind kind{InboundKind::BINARY};
};

// ============================================================================
// Ring size derivation
// ============================================================================

/// Ring storage the largest inbound item occupies.
static constexpr size_t INBOUND_MAX_ITEM_STORED_BYTES =
    SharedRingLayout::stored_size(sizeof(InboundItemHeader) + INBOUND_MAX_MESSAGE_BYTES);

/// Ring storage below which a maximal message no longer fits: a FreeRTOS no-split ring accepts
/// an item of at most half its storage (SharedRingLayout::max_item_size()).
static constexpr size_t INBOUND_RING_MIN_STORAGE_BYTES = 2 * INBOUND_MAX_ITEM_STORED_BYTES;
static_assert(SharedRingLayout::max_item_size(INBOUND_RING_MIN_STORAGE_BYTES) >=
                  sizeof(InboundItemHeader) + INBOUND_MAX_MESSAGE_BYTES,
              "the minimum ring must accept a maximal message");

/// Pass-through allowance without the artwork role, on top of the per-second budget below:
/// maximal messages (JSON, or a protocol message the task returns at once) that can arrive behind
/// a held item. Two lets one arrive while the previous is still being processed.
static constexpr size_t INBOUND_PASSTHROUGH_MESSAGES = 2;

/// Upper bound on the bytes a role message spends ahead of its payload inside one frame (the
/// type byte, an artwork part's channel and flags, an 8-byte timestamp).
static constexpr size_t INBOUND_ROLE_HEADER_ALLOWANCE = 16;

/// Bytes of an audio chunk message ahead of its encoded frame: the message type byte and the
/// 12-byte header (roles/player/v1.md "Audio Chunks (Binary)": 8-byte timestamp, 4-byte
/// send_ahead).
static constexpr size_t INBOUND_AUDIO_CHUNK_HEADER_BYTES = 13;

/// The smallest encoded audio frame the player's advertised share and the ring's hold window are
/// derived for: 20 ms of Opus at 64 kbit/s. PCM never goes below it (8 kHz mono 16-bit is 320 B
/// per 20 ms). Lower-rate Opus, and FLAC over near-silence, send smaller frames: the player's
/// quota then holds more seconds of audio than derived here, which pins more pass-through
/// traffic behind it (see derive_inbound_ring_bytes()).
static constexpr size_t INBOUND_MIN_AUDIO_FRAME_BYTES = 160;

/// Frames per second at INBOUND_MIN_AUDIO_FRAME_BYTES: one every 20 ms, Opus's default frame.
static constexpr size_t INBOUND_MIN_AUDIO_FRAMES_PER_SECOND = 50;

/// The lowest audio rate the library budgets for, in encoded bytes per second (64 kbit/s).
static constexpr size_t MIN_ADVERTISED_AUDIO_BYTES_PER_SECOND =
    INBOUND_MIN_AUDIO_FRAME_BYTES * INBOUND_MIN_AUDIO_FRAMES_PER_SECOND;

/// Ring storage per second of audio at MIN_ADVERTISED_AUDIO_BYTES_PER_SECOND: each frame stored
/// as one item with its chunk header and the stored overhead.
static constexpr size_t INBOUND_MIN_AUDIO_STORED_BYTES_PER_SECOND =
    (INBOUND_MIN_AUDIO_FRAME_BYTES + INBOUND_AUDIO_CHUNK_HEADER_BYTES +
     INBOUND_ITEM_STORED_OVERHEAD_BYTES) *
    INBOUND_MIN_AUDIO_FRAMES_PER_SECOND;

/// Ring storage budgeted per server/time reply: its JSON, well under 256 bytes, in one item.
static constexpr size_t INBOUND_TIME_REPLY_STORED_BYTES =
    SharedRingLayout::stored_size(sizeof(InboundItemHeader) + 256 + AEAD_TAG_SIZE);

/// Pass-through JSON budgeted per second apart from time replies: about one 1 KB message a second
/// (server/state for metadata, controller or color, group/update, server/command). Track metadata
/// with long strings is larger but arrives once per track.
static constexpr size_t INBOUND_STATE_BYTES_PER_SECOND = 1024;

/// The shortest track the artwork budget assumes: one track change, and so one new image per
/// artwork channel, every 30 seconds. An assumption about listening, not a protocol bound: a
/// listener skipping tracks faster than this pins more images than budgeted, which the transport
/// reports as "ring pinned behind held audio".
static constexpr size_t INBOUND_MIN_TRACK_SECONDS = 30;

/// @brief The configuration figures the ring size is derived from
///
/// A holder's quota counts each item's stored overhead (SharedRingLayout::ITEM_HEADER_BYTES,
/// the InboundItemHeader, the Noise type byte, the in-band timestamp and the AEAD tag) as well
/// as its payload, so the payload a role can have outstanding is its quota less that overhead
/// per item. The share of its buffer a role advertises to the server must therefore be derived
/// from that stored overhead against a stated minimum chunk size, not assumed to fit.
struct InboundRingBudget {
    /// The player's quota: PlayerRoleConfig::audio_buffer_capacity. 0 without the player role.
    size_t audio_hold_bytes{0};
    /// The visualizer's quota: VisualizerSupportObject::buffer_capacity. 0 without the visualizer
    /// role.
    size_t visualizer_hold_bytes{0};
    /// Ring storage the visualizer's requested frames arrive at per second: every requested type
    /// at rate_max, each frame at its stored size (VisualizerRole's
    /// stored_frame_bytes_per_second()). 0 without the visualizer role.
    size_t visualizer_stored_bytes_per_second{0};
    /// Ring storage one image per artwork channel takes: the sum over the channels of
    /// inbound_frames_stored_bytes(ImageSlotPreference::max_image_bytes). 0 without the artwork
    /// role.
    size_t artwork_images_stored_bytes{0};
    /// SendspinClientConfig::time_burst_size: server/time replies per burst.
    size_t time_burst_size{SendspinClientConfig::DEFAULT_BURST_SIZE};
    /// SendspinClientConfig::time_burst_interval_ms: milliseconds between bursts.
    int64_t time_burst_interval_ms{SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS};
};

/// @brief Ring storage a run of maximal frames carrying `payload_bytes` occupies: each whole
/// frame and the final partial one stored as one item
static constexpr size_t inbound_frames_stored_bytes(size_t payload_bytes) {
    constexpr size_t FRAME_OVERHEAD =
        sizeof(InboundItemHeader) + AEAD_TAG_SIZE + INBOUND_ROLE_HEADER_ALLOWANCE;
    constexpr size_t PAYLOAD_PER_FRAME = MAX_TRANSPORT_PLAINTEXT - INBOUND_ROLE_HEADER_ALLOWANCE;
    const size_t whole_frames = payload_bytes / PAYLOAD_PER_FRAME;
    const size_t remainder = payload_bytes % PAYLOAD_PER_FRAME;
    return whole_frames * SharedRingLayout::stored_size(PAYLOAD_PER_FRAME + FRAME_OVERHEAD) +
           (remainder > 0 ? SharedRingLayout::stored_size(remainder + FRAME_OVERHEAD) : 0);
}

/// @brief The longest the player can hold its oldest item, in whole seconds: its quota filled
/// with audio at the lowest budgeted rate (INBOUND_MIN_AUDIO_STORED_BYTES_PER_SECOND), rounded
/// up. 0 without the player.
static constexpr size_t inbound_max_hold_seconds(size_t audio_hold_bytes) {
    return (audio_hold_bytes + INBOUND_MIN_AUDIO_STORED_BYTES_PER_SECOND - 1) /
           INBOUND_MIN_AUDIO_STORED_BYTES_PER_SECOND;
}

/// @brief Pass-through traffic that can arrive during the player's hold window and is returned
/// at once, or at its display time, but stays unreclaimable behind the oldest audio item: the
/// state JSON budget, every time-burst reply in the window, and the visualizer frames the window
/// carries.
static constexpr size_t inbound_held_passthrough_bytes(const InboundRingBudget& budget) {
    const size_t hold_seconds = inbound_max_hold_seconds(budget.audio_hold_bytes);
    if (hold_seconds == 0) {
        return 0;
    }
    const size_t bursts =
        budget.time_burst_interval_ms > 0
            ? hold_seconds * 1000 / static_cast<size_t>(budget.time_burst_interval_ms) + 1
            : 0;
    return hold_seconds *
               (INBOUND_STATE_BYTES_PER_SECOND + budget.visualizer_stored_bytes_per_second) +
           bursts * budget.time_burst_size * INBOUND_TIME_REPLY_STORED_BYTES;
}

/// @brief Artwork that can sit in the ring at once: one image per channel per track change
/// within the player's hold window (INBOUND_MIN_TRACK_SECONDS), plus the set in flight, since
/// an image returned at its display time is still pinned behind audio held longer.
static constexpr size_t inbound_artwork_bytes(const InboundRingBudget& budget) {
    const size_t images =
        inbound_max_hold_seconds(budget.audio_hold_bytes) / INBOUND_MIN_TRACK_SECONDS + 1;
    return images * budget.artwork_images_stored_bytes;
}

/**
 * @brief Storage for the shared inbound ring, derived from the configuration
 *
 * Reclamation is in ring order (see shared_ring_buffer.h), so every byte that arrives while the
 * oldest held item is outstanding stays unreclaimable until it is returned: JSON, time replies,
 * visualizer frames and artwork returned at their display time, and dropped items alike. The
 * ring therefore holds:
 *  - the player's hold window (audio_hold_bytes),
 *  - the visualizer's quota (visualizer_hold_bytes), for the frames it holds before display,
 *  - the pass-through traffic arriving inside the player's hold window
 *    (inbound_held_passthrough_bytes(): the state JSON and time-burst budget and the visualizer's
 *    frame rate, times the longest hold, inbound_max_hold_seconds()). A visualizer frame is
 *    returned at its display time, a few seconds after it arrives, but stays pinned behind
 *    audio received after it and held far longer, so its own quota does not bound it,
 *  - the artwork that window carries (inbound_artwork_bytes()), or INBOUND_PASSTHROUGH_MESSAGES
 *    maximal messages without artwork,
 * and never less than INBOUND_RING_MIN_STORAGE_BYTES, rounded up to the 4-byte multiple FreeRTOS
 * requires. Unadmitted connections never write into the ring (InboundGate), so they add nothing.
 *
 * Traffic beyond this budget (a burst of large JSON, a lower audio rate than budgeted, faster
 * track changes) waits in the transport's acquire and is dropped after
 * INBOUND_ACQUIRE_TIMEOUT_MS with a warning naming the held audio.
 *
 * With the default configuration (a 1,000,000-byte player quota, no visualizer or artwork) this
 * is 1,000,000 + 111,552 held pass-through bytes (87 s at 1,024 B/s, plus 9 bursts of 8 time
 * replies at 312 stored bytes) + 131,152 for two maximal messages = 1,242,704 bytes. The separate
 * buffers it replaced held 1,000,000 bytes of encoded audio plus one maximal payload buffer per
 * open connection (1,065,551 bytes with one connection), and advertised 800,000 bytes to the
 * server against the 666,666 the player advertises now (see PlayerRole's
 * AUDIO_BUFFER_ADVERTISE_DENOMINATOR).
 */
static constexpr size_t derive_inbound_ring_bytes(const InboundRingBudget& budget) {
    const size_t allowance = budget.artwork_images_stored_bytes > 0
                                 ? inbound_artwork_bytes(budget)
                                 : INBOUND_PASSTHROUGH_MESSAGES * INBOUND_MAX_ITEM_STORED_BYTES;
    const size_t total = budget.audio_hold_bytes + budget.visualizer_hold_bytes +
                         inbound_held_passthrough_bytes(budget) + allowance;
    return SharedRingLayout::align(std::max(total, INBOUND_RING_MIN_STORAGE_BYTES));
}

}  // namespace sendspin
