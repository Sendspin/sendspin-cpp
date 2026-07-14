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
#include <thread>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Deferred artwork event types
enum class ArtworkEventType : uint8_t {
    STREAM_END,
    STREAM_CLEAR,
};

/// @brief Maximum number of artwork slots (2-bit slot field in protocol binary type byte)
static constexpr size_t ARTWORK_MAX_SLOTS = 4;

/// @brief Sentinel notification slot used to wake the decode thread for a parked-frame recheck
static constexpr uint8_t ARTWORK_RECHECK_SLOT = 0xFF;

/// @brief Ack-gate state for a slot with require_frame_done enabled
enum class SlotAckState : uint8_t {
    IDLE,              // no un-acked delivery; next frame may decode
    DECODE_DELIVERED,  // on_image_decode fired, on_image_display not yet fired
    PRESENTED,         // on_image_display or on_image_clear fired, awaiting frame_done()
};

/// @brief Notification sent from the network thread to the decode thread when new image data
/// arrives
///
/// All metadata is carried in the notification itself (not in SlotBuffer) so that the
/// ThreadSafeQueue's internal mutex provides the happens-before guarantee between the
/// network thread's writes and the decode thread's reads.
///
/// `generation` and `stream_epoch` let the decode thread detect a stale notification: if the
/// buffer it names has since been overwritten (generation mismatch) or the stream has moved on
/// (stream_epoch mismatch), the notification is skipped rather than decoding torn or
/// superseded data. See ArtworkRole::Impl::drain_thread_func.
struct ArtworkNotification {
    uint8_t slot;
    uint8_t buffer_idx;
    size_t data_length;
    int64_t timestamp;
    SendspinImageFormat format;
    uint32_t generation;
    uint32_t stream_epoch;
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
/// epochs[i] carries the stream_epoch the decode ran under, so the main-loop deadline check can
/// drop a display whose stream has since been replaced (a stream restart bumps the epoch but
/// cannot reach a display already folded into the main-thread holds).
struct ArtworkDisplayUpdate {
    int64_t timestamps[ARTWORK_MAX_SLOTS]{};
    uint32_t epochs[ARTWORK_MAX_SLOTS]{};
    uint8_t valid_mask{0};
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
        /// @brief Guards every field of every entry in slot_buffers. One mutex for all slots
        /// is intentional: artwork is not a hot path, so cross-slot contention is negligible.
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
    void handle_binary(uint8_t slot, const uint8_t* data, size_t len);
    void handle_stream_start(const ServerArtworkStreamObject& stream);
    void handle_stream_end();
    void handle_stream_clear();
    void handle_stream_ring_event(ArtworkEventType event);
    // True if this tick has drainable artwork work. The display-slot bit covers newly decoded
    // images; a nonzero held_display_mask means displays folded in on a prior tick are still
    // waiting out their server-clock deadlines (see held_display_ts) -- the deadline itself sets
    // no inbox bit, so a nonzero mask must be polled every tick until each slot fires or is
    // dropped for a stream-epoch mismatch.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_ARTWORK_DISPLAY) != 0 || this->held_display_mask != 0;
    }
    void drain_events();
    void cleanup();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void frame_done(uint8_t slot);

    // ========================================
    // Helpers
    // ========================================

    void stop() const;
    void enqueue_stream_event(ArtworkEventType event) const;
    // How far past its display deadline a held slot is, in microseconds: >= 0 means due (the
    // value is the lateness reported to on_image_display), < 0 means not yet due. client_ts is
    // the server-clock deadline already converted to the client clock (0 = no connection: due
    // immediately with lateness 0, since no deadline exists); display_offset_ms shifts the
    // deadline, positive firing early (mirroring PlayerRoleConfig::fixed_delay_us) and negative
    // delaying. Pure and static for direct unit testing.
    static int64_t display_overdue_us(int64_t client_ts, int32_t display_offset_ms, int64_t now);
    // True if `slot` is within range and configured with require_frame_done.
    bool ack_enabled(uint8_t slot) const;
    // Sends a sentinel ARTWORK_RECHECK_SLOT notification to unblock the decode thread's queue
    // receive so it re-runs the parked-slot sweep at the top of its loop. Best-effort: the send
    // uses a 0 timeout and any failure is ignored, since the decode thread's 100ms receive
    // timeout plus the loop-top sweep is the fallback that guarantees the parked notification is
    // eventually rechecked even if this wakeup is dropped.
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
    // Stream epoch each held display was decoded under; a mismatch against stream_epoch at
    // deadline-check time means the stream was since replaced (e.g. a restart with no
    // intervening end/clear) and the display must be dropped, since the network thread cannot
    // reach the main-thread holds to cancel it. Main-thread only; see held_display_ts.
    uint32_t held_display_epoch[ARTWORK_MAX_SLOTS]{};

    // 8-bit fields
    std::atomic<bool> stream_active{false};
    // Main-thread only; see held_display_ts.
    uint8_t held_display_mask{0};

    /// @brief Bumped on stream start/end/clear/cleanup so in-flight notifications from a
    /// previous stream are recognized as stale and skipped by the decode thread, instead of
    /// relying on draining the notify queue (which could discard a new stream's first image
    /// if it was queued before the flush was serviced).
    std::atomic<uint32_t> stream_epoch{0};
};

}  // namespace sendspin
