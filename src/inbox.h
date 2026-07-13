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

/// @file inbox.h
/// @brief Single shared mutex, dirty-topic bitmask, and fixed-capacity event ring that
/// consolidate all main-loop-bound small-message traffic onto one endpoint

#pragma once

#include "platform/logging.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>

namespace sendspin {

// ============================================================================
// Topic bits
// ============================================================================

/// One bit per main-loop-drained endpoint. A bit is owned by exactly one InboxSlot
/// (or by the event ring); it is set when that endpoint has pending content and
/// cleared when the endpoint is drained, always under the Inbox mutex.
static constexpr uint32_t INBOX_TOPIC_EVENTS = 1u << 0;                // Shared event ring
static constexpr uint32_t INBOX_TOPIC_GROUP = 1u << 1;                 // Group update slot
static constexpr uint32_t INBOX_TOPIC_CONTROLLER = 1u << 2;            // Controller state slot
static constexpr uint32_t INBOX_TOPIC_METADATA = 1u << 3;              // Metadata delta slot
static constexpr uint32_t INBOX_TOPIC_COLOR = 1u << 4;                 // Color delta slot
static constexpr uint32_t INBOX_TOPIC_PLAYER_COMMAND = 1u << 5;        // Player command slot
static constexpr uint32_t INBOX_TOPIC_PLAYER_STREAM_PARAMS = 1u << 6;  // Player stream params slot
static constexpr uint32_t INBOX_TOPIC_VISUALIZER_CONFIG = 1u << 7;     // Visualizer config slot
static constexpr uint32_t INBOX_TOPIC_ARTWORK_DISPLAY = 1u << 8;       // Artwork display slot

// ============================================================================
// Event ring types
// ============================================================================

/// @brief Discriminates InboxEvent entries in the shared ring
///
/// The `code` field on InboxEvent carries a role-local enum value (cast to/from uint8_t by the
/// producer/consumer); the inbox does not interpret it.
enum class InboxEventType : uint8_t {
    TIME_RESPONSE,       // Time-sync measurement; payload in InboxEvent::time
    PLAYER_STREAM,       // Player stream lifecycle; code = PlayerStreamCallbackType
    PLAYER_STATE,        // Client state from sync task; code = SendspinClientState
    CONTROLLER_CLEARED,  // Controller state cleared on disconnect; no payload
    METADATA_CLEARED,    // Metadata cleared on disconnect; no payload
    COLOR_CLEARED,       // Color state cleared on disconnect; no payload
    ARTWORK_STREAM,      // Artwork stream lifecycle; code = ArtworkEventType
    VISUALIZER_STREAM,   // Visualizer stream lifecycle; code = VisualizerEventType
};

/// @brief Payload for TIME_RESPONSE events
///
/// Mirrors the fields of the current TimeResponseEvent in client.cpp; that struct migrates here
/// in a later phase.
struct TimeResponsePayload {
    int64_t offset;
    int64_t max_error;
    int64_t timestamp;
    uint64_t source_id;
};

/// @brief One entry in the shared event ring
///
/// POD; copied in and out of the ring by value.
struct InboxEvent {
    InboxEventType type;
    uint8_t code;              // Role-local enum value; 0 when unused
    TimeResponsePayload time;  // Valid only when type == InboxEventType::TIME_RESPONSE
};

// ============================================================================
// Inbox
// ============================================================================

template <typename T>
class InboxSlot;

/**
 * @brief Shared main-loop mailbox: one mutex, one dirty-topic bitmask, one fixed event ring
 *
 * Producer threads (network, decode) write latest-value state through an InboxSlot bound to
 * this Inbox, or push lifecycle events directly with push_event(). The main loop reads poll()
 * once per tick and only locks the mutex to drain topics whose bit is set.
 *
 * @note HARD RULE: no user-visible code (listener callbacks, client/role methods) may run while
 * the inbox mutex is held. merge() functors passed to InboxSlot must be pure data operations on
 * the slot value, so nothing that calls back into application code. The Inbox is a leaf in the
 * lock order: code holding any other lock in this library must not then lock the Inbox, only
 * the reverse.
 *
 * Usage:
 * 1. Declare an Inbox member and bind each InboxSlot<T> to it with a distinct INBOX_TOPIC_* bit
 * 2. Producer threads call InboxSlot::write()/merge() or Inbox::push_event()
 * 3. The main loop calls poll() once per tick and drains any topic whose bit is set
 * 4. Call reset_events() (or InboxSlot::reset()) to discard pending content on disconnect
 *
 * @code
 * Inbox inbox;
 * InboxSlot<GroupUpdateObject> group_slot(inbox, INBOX_TOPIC_GROUP);
 *
 * // Producer thread:
 * group_slot.write(update);
 *
 * // Main loop:
 * if (inbox.poll() & INBOX_TOPIC_GROUP) {
 *     GroupUpdateObject update;
 *     if (group_slot.take(update)) { ... }
 * }
 * @endcode
 */
class Inbox {
    template <typename>
    friend class InboxSlot;

public:
    static constexpr size_t EVENT_CAPACITY = 32;

    Inbox() = default;
    ~Inbox() = default;

    // Not copyable or movable
    Inbox(const Inbox&) = delete;
    Inbox& operator=(const Inbox&) = delete;

    /// @brief Lock-free hint for which topics currently have pending content
    ///
    /// Intended to be read once per main-loop tick without locking. Ground truth is always the
    /// per-endpoint content guarded by the mutex: a bit observed here can go stale the instant
    /// after this call returns (a producer thread may set or another consumer may clear it), so
    /// callers must still tolerate a drain call finding nothing (bit was cleared) and must not
    /// skip a drain call just because poll() raced and momentarily missed a freshly-set bit, as
    /// the next tick's poll() will observe it.
    /// @return Bitmask (OR of INBOX_TOPIC_* bits) of topics with pending content as of the load.
    uint32_t poll() const {
        return this->pending_.load(std::memory_order_acquire);
    }

    /// @brief Pushes one event onto the shared ring
    ///
    /// If the ring is full the new event is dropped (matching today's queue-full behavior) and
    /// existing contents are left intact; the caller should log the drop.
    /// @param event Event to append.
    /// @return true if the event was appended, false if the ring was full.
    bool push_event(const InboxEvent& event) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (this->count_ >= EVENT_CAPACITY) {
            return false;
        }
        size_t tail = (this->head_ + this->count_) % EVENT_CAPACITY;
        this->events_[tail] = event;
        ++this->count_;
        this->set_bit_locked(INBOX_TOPIC_EVENTS);
        return true;
    }

    /// @brief Copies out and removes up to max_count of the oldest ring events
    ///
    /// Events are delivered in FIFO order. If fewer than max_count events are pending, only
    /// those are copied. The INBOX_TOPIC_EVENTS bit is cleared only when the ring is fully
    /// drained; a partial drain (max_count smaller than the pending count) leaves the bit set so
    /// the remaining events are not silently missed on the next poll().
    /// @param[out] out Buffer to receive up to max_count events, oldest first.
    /// @param max_count Capacity of `out`, in elements.
    /// @return Number of events copied into `out`.
    size_t take_events(InboxEvent* out, size_t max_count) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        size_t n = std::min(max_count, this->count_);
        for (size_t i = 0; i < n; ++i) {
            out[i] = this->events_[(this->head_ + i) % EVENT_CAPACITY];
        }
        this->head_ = (this->head_ + n) % EVENT_CAPACITY;
        this->count_ -= n;
        if (this->count_ == 0) {
            this->clear_bit_locked(INBOX_TOPIC_EVENTS);
        }
        return n;
    }

    /// @brief Discards all pending ring events
    void reset_events() {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->head_ = 0;
        this->count_ = 0;
        this->clear_bit_locked(INBOX_TOPIC_EVENTS);
    }

private:
    /// @brief Sets `bit` in the dirty-topic mask. Caller must hold `mutex_`
    void set_bit_locked(uint32_t bit) {
        this->pending_.fetch_or(bit, std::memory_order_release);
    }

    /// @brief Clears `bit` in the dirty-topic mask. Caller must hold `mutex_`
    void clear_bit_locked(uint32_t bit) {
        this->pending_.fetch_and(~bit, std::memory_order_acq_rel);
    }

    /// @brief Records `bit` as owned by a slot (called from InboxSlot::bind())
    ///
    /// Enforces the exclusive-ownership invariant documented on InboxSlot: a bit claimed by two
    /// live slots would let draining one clear the other's wakeup. Loud (assertion failure) in
    /// debug builds; release builds keep today's behavior.
    void claim_bit(uint32_t bit) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        assert((this->claimed_bits_ & bit) == 0 && "INBOX_TOPIC bit already claimed by a slot");
        this->claimed_bits_ |= bit;
    }

    /// @brief Releases a slot's bit claim (called from ~InboxSlot(), which must run before this
    /// Inbox is destroyed)
    void release_bit(uint32_t bit) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->claimed_bits_ &= ~bit;
    }

    // Struct fields
    std::mutex mutex_;
    std::array<InboxEvent, EVENT_CAPACITY> events_{};

    // size_t fields
    size_t count_{0};
    size_t head_{0};

    // 32-bit fields
    // Bits owned by a live InboxSlot, plus the ring's own bit. Guarded by mutex_; exists to
    // catch a copy-pasted bind() reusing a bit, which would otherwise compile clean and drop
    // wakeups intermittently in production.
    uint32_t claimed_bits_{INBOX_TOPIC_EVENTS};
    std::atomic<uint32_t> pending_{0};
};

/// @brief Pushes a payload-free lifecycle event, logging a drop if the ring is full
///
/// Shared by the role stream-event and cleared-event producers so the build/push/log-on-drop
/// pattern stays uniform across roles. `what` names the dropped event in the log line; `code`
/// carries the role-local enum value (0 when unused).
inline void push_event_or_log(Inbox* inbox, InboxEventType type, uint8_t code, const char* tag,
                              const char* what) {
    InboxEvent event{};
    event.type = type;
    event.code = code;
    if (inbox == nullptr || !inbox->push_event(event)) {
        SS_LOGW(tag, "Inbox event ring full; dropping %s", what);
    }
}

// ============================================================================
// InboxSlot
// ============================================================================

/**
 * @brief Latest-value slot bound to a shared Inbox, replacing ShadowSlot for main-loop topics
 *
 * Owns its T storage and dirty flag but has no mutex of its own: every operation locks the
 * bound Inbox's shared mutex and, while holding it, keeps the slot's owned topic bit in sync
 * with its dirty flag. A topic bit must be owned by exactly one slot (or the event ring).
 * Sharing a bit between two slots would let draining one clear the bit while the other still
 * has pending content, silently losing that endpoint's next wakeup.
 *
 * Usage:
 * 1. Default-construct and call bind() exactly once before any producer/consumer use, or use
 *    the Inbox-taking constructor to bind at construction time
 * 2. Producer threads call write() (latest-wins) or merge() (accumulate) to publish state
 * 3. The consumer calls take() after observing the slot's topic bit set in Inbox::poll()
 * 4. Call reset() to discard a pending value, e.g. on disconnect
 *
 * @code
 * Inbox inbox;
 * InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);
 *
 * slot.write(42);
 *
 * int val;
 * if (slot.take(val)) { ... }
 * @endcode
 */
template <typename T>
class InboxSlot {
public:
    InboxSlot() = default;

    /// @brief Constructs and immediately binds to `inbox` (see bind())
    InboxSlot(Inbox& inbox, uint32_t topic_bit) {
        this->bind(inbox, topic_bit);
    }

    ~InboxSlot() {
        // Release the bit claim so a replacement slot (e.g. a role re-added before start) can
        // bind it. Requires the bound Inbox to outlive this slot.
        if (this->inbox_ != nullptr) {
            // Clear the owned topic bit if a value is still pending. release_bit() only drops the
            // claim; without this a slot destroyed while dirty would leave its bit set in
            // pending_ forever, so a phantom wakeup no live slot can clear, and one a replacement
            // slot would inherit while its own dirty_ is false.
            {
                std::lock_guard<std::mutex> lock(this->inbox_->mutex_);
                if (this->dirty_) {
                    this->inbox_->clear_bit_locked(this->topic_bit_);
                }
            }
            this->inbox_->release_bit(this->topic_bit_);
        }
    }

    // Not copyable or movable
    InboxSlot(const InboxSlot&) = delete;
    InboxSlot& operator=(const InboxSlot&) = delete;

    /// @brief Binds this slot to a shared Inbox and the topic bit it exclusively owns
    ///
    /// Must be called exactly once before any other method is used.
    /// @param inbox Shared Inbox whose mutex this slot locks for every operation. Must outlive
    /// this slot (the destructor releases the bit claim).
    /// @param topic_bit Single INBOX_TOPIC_* bit this slot owns; must not be shared with any
    /// other slot or with the event ring. Ownership is debug-asserted via Inbox::claim_bit().
    void bind(Inbox& inbox, uint32_t topic_bit) {
        assert(topic_bit != 0 && (topic_bit & (topic_bit - 1)) == 0 &&
               "InboxSlot topic_bit must be exactly one bit");
        assert(this->inbox_ == nullptr && "InboxSlot bound twice");
        inbox.claim_bit(topic_bit);
        this->inbox_ = &inbox;
        this->topic_bit_ = topic_bit;
    }

    /// @brief Overwrite the slot with a new value (latest-wins)
    /// @param value The new value to store.
    void write(T value) {
        if (!this->check_bound()) {
            return;
        }
        std::lock_guard<std::mutex> lock(this->inbox_->mutex_);
        this->slot_ = std::move(value);
        this->dirty_ = true;
        this->inbox_->set_bit_locked(this->topic_bit_);
    }

    /// @brief Merge a delta into the slot using a callable: fn(T& current, T&& delta)
    ///
    /// `fn` runs while the Inbox mutex is held, so it must be a pure data operation (no
    /// callbacks into application code); see the Inbox class documentation.
    /// @param fn Callable that merges `delta` into the current slot value.
    /// @param delta The new partial value to merge in.
    template <typename MergeFn>
    void merge(MergeFn&& fn, T delta) {
        if (!this->check_bound()) {
            return;
        }
        std::lock_guard<std::mutex> lock(this->inbox_->mutex_);
        fn(this->slot_, std::move(delta));
        this->dirty_ = true;
        this->inbox_->set_bit_locked(this->topic_bit_);
    }

    /// @brief Move the accumulated value out if dirty
    /// @param[out] out Receives the stored value if the slot is dirty.
    /// @return true if a value was taken, false if the slot was clean (or unbound).
    bool take(T& out) {
        if (!this->check_bound()) {
            return false;
        }
        std::lock_guard<std::mutex> lock(this->inbox_->mutex_);
        if (!this->dirty_) {
            return false;
        }
        out = std::move(this->slot_);
        this->slot_ = T{};
        this->dirty_ = false;
        this->inbox_->clear_bit_locked(this->topic_bit_);
        return true;
    }

    /// @brief Discard any pending value
    void reset() {
        if (!this->check_bound()) {
            return;
        }
        std::lock_guard<std::mutex> lock(this->inbox_->mutex_);
        this->slot_ = T{};
        this->dirty_ = false;
        this->inbox_->clear_bit_locked(this->topic_bit_);
    }

private:
    /// @brief Asserts (debug) and reports whether bind() has been called
    ///
    /// Using a slot before bind() is a programming error: loud (assertion failure) in debug
    /// builds, a safe no-op/false in release builds.
    bool check_bound() const {
        assert(this->inbox_ != nullptr && "InboxSlot used before bind()");
        return this->inbox_ != nullptr;
    }

    // Struct fields
    T slot_{};

    // Pointer fields
    Inbox* inbox_{nullptr};

    // 32-bit fields
    uint32_t topic_bit_{0};

    // 8-bit fields
    bool dirty_{false};
};

}  // namespace sendspin
