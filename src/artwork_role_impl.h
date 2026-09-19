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

/// @file artwork_role_impl.h
/// @brief Private implementation for the artwork role (pimpl)

#pragma once

#include "inbox.h"
#include "platform/event_flags.h"
#include "platform/memory.h"
#include "platform/thread_safe_queue.h"
#include "protocol_messages.h"
#include "sendspin/artwork_role.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred artwork event types
enum class ArtworkEventType : uint8_t {
    STREAM_END,
    STREAM_CLEAR,
};

/// @brief Maximum number of artwork slots (2-bit slot field in protocol binary type byte)
static constexpr size_t ARTWORK_MAX_SLOTS = 4;

/// @brief Ack-gate state for a slot with require_frame_done enabled
enum class SlotAckState : uint8_t {
    IDLE,              // no un-acked delivery; next frame or clear may be processed
    DECODE_DELIVERED,  // the decode thread claimed a delivery (on_image_decode fired for a frame;
                       // nothing fires for a per-channel clear), its display/clear not yet fired
    PRESENTED,         // on_image_display or on_image_clear fired, awaiting frame_done()
};

/// @brief Notification sent from the network thread to the decode thread when an image transfer
/// completes
///
/// All metadata is carried in the notification itself (not in SlotBuffer) so that the
/// ThreadSafeQueue's internal mutex provides the happens-before guarantee between the
/// network thread's writes and the decode thread's reads.
///
/// `generation` and `epoch` let the decode thread detect a stale notification: if the buffer it
/// names has since been claimed for another transfer (generation mismatch) or the slot has moved
/// on (epoch mismatch, see ArtworkRole::Impl::slot_epochs), the notification is skipped rather
/// than decoding torn or superseded data. See ArtworkRole::Impl::drain_thread_func.
///
/// `data_length == 0` marks the protocol's empty image (an announce with `total_size` 0), which
/// clears the channel. It names no buffer, so `buffer_idx`/`generation` are unused and left at 0;
/// everything else about it (queue ordering, the ack gate, and the timestamp-scheduled hand-off
/// to the main loop) matches a frame. See handle_binary().
struct ArtworkNotification {
    uint8_t slot;
    uint8_t buffer_idx;
    size_t data_length;
    int64_t timestamp;
    SendspinImageFormat format;
    uint32_t generation;
    uint32_t epoch;
};

/// @brief The one image transfer the role has in flight, across all of its channels
///
/// roles/artwork/v1.md "Artwork (Binary)" allows at most one transfer in flight per role: it
/// begins at an announce and ends when the accumulated part data reaches `total_size`, when a
/// cancel abandons it, or when the stream it belongs to goes away. One role-wide record is
/// therefore enough, and a second announce arriving while `in_flight` is set is the
/// malformed-sequence rule rather than a second record.
///
/// Guarded by DrainTask::slot_mutex: written from the network thread (handle_binary() and the
/// stream lifecycle handlers) and cleared from the main loop by cleanup().
///
/// `buffer_idx`/`generation` name the SlotBuffer the parts accumulate into, claimed once at the
/// announce so every part of the transfer lands in the same buffer. `discarding` marks a transfer
/// whose image the role will not hold (see ArtworkRole::Impl::image_cap): per "Artwork (Binary)",
/// a client discarding image data must still count each part's bytes toward `total_size`, so the
/// sequence is tracked to the end and only the bytes are dropped.
struct ArtworkTransfer {
    int64_t timestamp{0};
    uint32_t total_size{0};
    uint32_t received{0};
    uint32_t generation{0};
    bool in_flight{false};
    uint8_t slot{0};
    uint8_t buffer_idx{0};
    bool discarding{false};
};

/// @brief Double-buffered image storage for a single artwork slot
///
/// All fields here are guarded by DrainTask::slot_mutex (shared across all slots; artwork is
/// not a hot path so contention is negligible). The network thread and decode thread both read
/// and write these fields, so they must never be touched outside that lock:
///  - write_idx: which buffer the network thread writes to next.
///  - drain_active / drain_buf_idx: which buffer the decode thread is currently decoding.
///  - write_generation[i]: bumped every time buffers[i] is overwritten by the network thread.
///    The decode thread compares this against the generation stamped on the notification it
///    dequeued to detect whether the buffer was overwritten again before it could be claimed.
///  - ack_state: only meaningful when the slot has require_frame_done set (see ack_enabled());
///    tracks whether a delivery is currently un-acked for the slot (see SlotAckState).
///  - has_parked / parked: while ack_state is not IDLE, at most one newer notification is parked
///    here (latest-wins) instead of being decoded; it is replayed once the gate reopens.
struct SlotBuffer {
    PlatformBuffer buffers[2];
    uint8_t write_idx{0};
    bool drain_active{false};
    uint8_t drain_buf_idx{0};
    uint32_t write_generation[2]{0, 0};
    SlotAckState ack_state{SlotAckState::IDLE};
    bool has_parked{false};
    ArtworkNotification parked{};
};

/// @brief Latest-wins display timestamps accumulated across artwork slots
///
/// Merged cross-thread by the decode thread (one slot per merge) and taken whole by the
/// main-loop drain; a bit set in valid_mask means timestamps[i] holds a pending display.
/// epochs[i] carries the slot epoch the decode ran under, so the main-loop deadline check can
/// drop a display the slot has since moved past (a stream restart, a cancel, or a fresh announce
/// bumps the epoch but cannot reach a display already folded into the main-thread holds). A bit
/// set in clear_mask means slot i's pending delivery is a per-channel clear rather than a decoded
/// frame, so the deadline fires on_image_clear() instead of on_image_display(); it is meaningful
/// only where valid_mask is set.
struct ArtworkDisplayUpdate {
    int64_t timestamps[ARTWORK_MAX_SLOTS]{};
    uint32_t epochs[ARTWORK_MAX_SLOTS]{};
    uint8_t valid_mask{0};
    uint8_t clear_mask{0};
};

/// @brief Private implementation of the artwork role
struct ArtworkRole::Impl {
    Impl(ArtworkRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Nested types
    // ========================================

    /// @brief Persistent decode thread context for artwork image decode
    struct DrainTask {
        ThreadSafeQueue<ArtworkNotification> notify_queue;
        EventFlags event_flags;
        std::thread drain_thread;
        SlotBuffer slot_buffers[ARTWORK_MAX_SLOTS];
        /// @brief Guards every field of every entry in slot_buffers, plus the role-wide
        /// ArtworkTransfer. One mutex for all slots is intentional: artwork is not a hot path,
        /// so cross-slot contention is negligible.
        std::mutex slot_mutex;
    };

    /// @brief Deferred event state for artwork display timestamps, delivered to the main thread
    /// via the shared Inbox
    struct EventState {
        InboxSlot<ArtworkDisplayUpdate> display_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    bool start();
    void build_hello_fields(ClientHelloMessage& msg) const;
    void build_state_fields(ClientStateMessage& msg) const;
    /// @brief Handles one artwork binary message, the type byte already stripped by the caller.
    /// @param slot Artwork channel the message's type byte named (0-3).
    /// @param data The message from its flags byte on.
    /// @param len Length of `data`, one less than the message's own length.
    /// @return false when the message is a protocol error per roles/artwork/v1.md "Artwork
    /// (Binary)" and the caller MUST close the connection; true when it was processed or ignored.
    bool handle_binary(uint8_t slot, const uint8_t* data, size_t len);
    // The lifecycle handlers take the teardown generation the receive gate captured when it
    // admitted the message and re-check it where they take effect; see accepts().
    void handle_stream_start(const ServerArtworkStreamObject& stream, uint32_t generation);
    void handle_stream_end(uint32_t generation);
    void handle_stream_clear(uint32_t generation);
    void handle_stream_ring_event(ArtworkEventType event);
    // True if this tick has drainable artwork work. The display-slot bit covers newly decoded
    // images; a nonzero held_display_mask means displays folded in on a prior tick are still
    // waiting out their server-clock deadlines (see held_display_ts): the deadline itself sets
    // no inbox bit, so a nonzero mask must be polled every tick until each slot fires or is
    // dropped for a stream-epoch mismatch.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_ARTWORK_DISPLAY) != 0 || this->held_display_mask != 0;
    }
    void drain_events();
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, on the network thread, while the
    /// handler it admits runs on: a teardown can land in between (the deactivation path, unlike a
    /// lost connection, never quiesces the network thread). The dispatch captures this counter with
    /// the gate and hands it back here at each point of effect, so a teardown inside that window
    /// invalidates the whole handler instead of only the part that ran before it.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards its state. Main loop only.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Listener callbacks are queued on
    /// the inbox rather than fired here, because both callers run under the connection manager's
    /// conn_ptr_mutex_.
    void cleanup();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void frame_done(uint8_t slot) const;

    // ========================================
    // Helpers
    // ========================================

    /// @brief Asks the decode thread to exit without waiting for it; stop() joins. Lets a caller
    /// overlap the thread's exit with other teardown.
    /// @return true if a running thread was signalled, false if none was running.
    bool signal_stop() const;
    void stop() const;
    /// @brief Hands back every per-slot image buffer that the decode thread is not reading.
    /// Main thread, under slot_mutex. Called where the role stops holding an image at all: the
    /// teardown in cleanup() and the thread join in stop().
    void release_idle_slot_buffers() const;
    /// Queues a stream lifecycle event stamped with `generation`, which the drain compares
    /// against the live counter before dispatching it.
    void enqueue_stream_event(ArtworkEventType event, uint32_t generation) const;
    // Merges a single-slot display delta into the accumulated cross-thread update. Called under
    // the Inbox mutex via InboxSlot::merge() (see process_notification), so it must stay a pure
    // data operation with no callbacks into application code. `delta` carries exactly one slot's
    // bit (set by the decode thread after a single image finishes decoding or a clear is
    // validated); OR-ing valid_mask and overwriting only the masked entries preserves latest-wins
    // per slot while leaving any other slot's already-accumulated (not yet drained) entry
    // untouched. clear_mask is assigned per bit rather than OR-ed; drain_events() folds the taken
    // update into the main-thread holds with the same per-bit assignment, so the two must agree.
    // Pure and static for direct unit testing.
    static void merge_artwork_display_update(ArtworkDisplayUpdate& current,
                                             ArtworkDisplayUpdate&& delta);
    // How far past its display deadline a held slot is, in microseconds: >= 0 means due (the
    // value is the lateness reported to on_image_display), < 0 means not yet due. client_ts is
    // the server-clock deadline already converted to the client clock (0 = no connection: due
    // immediately with lateness 0, since no deadline exists); display_offset_ms shifts the
    // deadline, positive firing early (mirroring PlayerRoleConfig::fixed_delay_us) and negative
    // delaying. Pure and static for direct unit testing.
    static int64_t display_overdue_us(int64_t client_ts, int32_t display_offset_ms, int64_t now);
    // Maps a due display's overdue microseconds (from display_overdue_us) to the lateness_ms
    // reported to on_image_display(). client_ts == 0 means no connection: report 0, the
    // documented "no deadline exists" sentinel. When connected, floor the result at 1 ms so a
    // sub-millisecond-late display never truncates to 0 and collides with that sentinel; the top
    // is clamped at UINT32_MAX ms (~49 days), past which lateness is not meaningful. Pure and
    // static for direct unit testing.
    static uint32_t display_lateness_ms(int64_t client_ts, int64_t overdue_us);
    // True if `slot` is within range and configured with require_frame_done.
    bool ack_enabled(uint8_t slot) const;
    // Largest encoded image the role will hold for `slot`: the channel's configured
    // ImageSlotPreference::max_image_bytes, or 0 for a slot the role declared no channel for, so
    // an image the role never asked for is never held.
    uint32_t image_cap(uint8_t slot) const;
    // Format the decode callback reports for `slot`: the one the channel was configured with, so
    // the array index stays authoritative for slot mapping (see the Impl constructor).
    SendspinImageFormat image_format(uint8_t slot) const;
    // Discards the slot's pending image by bumping its epoch, and abandons the in-flight transfer
    // if it is that slot's. Both a cancel message and a fresh announce need exactly this.
    void discard_pending(uint8_t slot);
    // Discards every channel's pending image: bumps all the epochs, drops any transfer in flight,
    // and forgets the streamed configuration so the next stream/start compares against nothing.
    // A stream end or clear and a disconnect each end the whole stream this way; a stream/start
    // discards only the channels it changed (see changed_channel_mask()).
    void discard_all_pending();
    // Which channels this stream/start changed the configuration of, as a slot bitmask. Every
    // channel counts as changed when either side has no channel array to compare. Caller holds
    // DrainTask::slot_mutex: it reads streamed_channels.
    uint8_t changed_channel_mask(const ServerArtworkStreamObject& stream) const;
    // True if two stream/start channel entries declare the same configuration.
    static bool same_channel(const ServerArtworkChannelObject& a,
                             const ServerArtworkChannelObject& b);
    // Outcome of one transfer message. MALFORMED is the protocol error handle_binary() reports to
    // its caller; COMPLETED means the notification it filled in is ready to enqueue.
    enum class TransferOutcome : uint8_t {
        ACCEPTED,
        COMPLETED,
        MALFORMED,
    };
    // Starts the transfer an announce declares, filling `complete` and returning COMPLETED for the
    // empty image (`total_size` 0), which has no parts to wait for.
    TransferOutcome begin_transfer(uint8_t slot, const uint8_t* body,
                                   ArtworkNotification& complete);
    // Appends one part's data to the transfer in flight, filling `complete` and returning
    // COMPLETED once the accumulated data reaches `total_size`.
    TransferOutcome append_part(uint8_t slot, const uint8_t* part, size_t part_len,
                                ArtworkNotification& complete);
    // Hands a completed image (or empty image) to the decode thread.
    void enqueue_notification(const ArtworkNotification& notif) const;
    // Wakes the decode thread out of its blocking queue receive so it re-runs the parked-slot
    // sweep at the top of its loop.
    void wake_drain_thread() const;
    // Validates and, if appropriate, decodes a single notification; called both from the normal
    // queue-receive path and from the parked-slot sweep in drain_thread_func().
    void process_notification(const ArtworkNotification& notif);
    static void drain_thread_func(ArtworkRole::Impl* self);

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    ArtworkRoleConfig config;
    std::vector<ArtworkChannelFormatObject> artwork_channels;
    // The role's single image transfer in flight; guarded by DrainTask::slot_mutex.
    ArtworkTransfer transfer;
    // The channel array of the stream/start in force, kept so the next one can be compared
    // against it: only the channels whose configuration changes lose their pending image.
    // Guarded by DrainTask::slot_mutex, like `transfer`: the network thread writes it from
    // handle_stream_start() while the main loop can clear it from cleanup(), which a
    // server/activate that removes the role runs on a live connection.
    std::optional<std::vector<ServerArtworkChannelObject>> streamed_channels;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<DrainTask> drain_task;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ArtworkRoleListener* listener{nullptr};

    // 64-bit fields
    // Latest-wins display timestamps folded in from display_slot, awaiting their server-clock
    // deadlines. Main-thread only: written and read exclusively from drain_events()/
    // handle_stream_ring_event()/cleanup() on the loop thread. held_display_ts[i] is valid only
    // when bit i of held_display_mask is set.
    int64_t held_display_ts[ARTWORK_MAX_SLOTS]{};

    // 32-bit fields
    // Slot epoch each held display was decoded under; a mismatch against slot_epochs at
    // deadline-check time means the slot has since moved past it (a stream restart, a cancel, or
    // a fresh announce) and the display must be dropped, since the network thread cannot reach
    // the main-thread holds to cancel it. Main-thread only; see held_display_ts.
    uint32_t held_display_epoch[ARTWORK_MAX_SLOTS]{};

    /// @brief Teardown generation, bumped by cleanup() and stamped onto every stream event queued
    /// afterwards. At the drain an event whose stamp no longer matches is discarded, so an event
    /// queued before a teardown cannot act after it (see event_is_current() in inbox.h). Atomic
    /// because the network thread reads it (see accepts()).
    std::atomic<uint32_t> cleanup_generation{0};

    /// @brief Per-channel delivery epoch, bumped whenever the channel's pending image is
    /// discarded: by a stream start/end/clear or cleanup (every channel at once), and by a cancel
    /// message or a fresh announce (that channel alone, per roles/artwork/v1.md "Artwork
    /// (Binary)"). A notification, a decode hand-off, and a held display all carry the epoch they
    /// were made under, so each drops itself at its next check instead of having to be hunted
    /// down across three threads. An image already displayed has left the pipeline, which is what
    /// makes the current image survive a cancel.
    std::atomic<uint32_t> slot_epochs[ARTWORK_MAX_SLOTS]{};

    // 8-bit fields
    std::atomic<bool> stream_active{false};
    // Main-thread only; see held_display_ts.
    uint8_t held_display_mask{0};
    // Which held deliveries are per-channel clears rather than decoded frames: bit i selects
    // on_image_clear() over on_image_display() when slot i's deadline fires. Only meaningful where
    // held_display_mask is set. Main-thread only; see held_display_ts.
    uint8_t held_display_clear{0};
};

}  // namespace sendspin
