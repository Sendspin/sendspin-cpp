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

#include "platform/event_flags.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
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
struct SlotBuffer {
    PlatformBuffer buffers[2];
    uint8_t write_idx{0};
    bool drain_active{false};
    uint8_t drain_buf_idx{0};
    uint32_t write_generation[2]{0, 0};
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

    /// @brief Deferred event state for thread-safe artwork stream lifecycle delivery
    struct EventState {
        ThreadSafeQueue<ArtworkEventType> queue;
    };

    /// @brief Pending display timestamps, one slot per artwork slot
    ///
    /// The decode thread writes the server timestamp after on_image_decode() completes; the
    /// main loop reads the timestamp and fires on_image_display() once it is reached. Latest-
    /// wins per slot: if a newer frame finishes decoding before the pending display fires,
    /// the older timestamp is overwritten and only the newer display is delivered.
    struct DisplayScheduler {
        ShadowSlot<int64_t> pending[ARTWORK_MAX_SLOTS];
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    bool start();
    void build_hello_fields(ClientHelloMessage& msg) const;
    void handle_binary(uint8_t slot, const uint8_t* data, size_t len);
    void handle_stream_start(const ServerArtworkStreamObject& stream);
    void handle_stream_end();
    void handle_stream_clear();
    void drain_events();
    void cleanup();

    // ========================================
    // Helpers
    // ========================================

    void stop() const;
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
    std::unique_ptr<DisplayScheduler> display_scheduler;
    ArtworkRoleListener* listener{nullptr};

    // 8-bit fields
    std::atomic<bool> stream_active{false};

    /// @brief Bumped on stream start/end/clear/cleanup so in-flight notifications from a
    /// previous stream are recognized as stale and skipped by the decode thread, instead of
    /// relying on draining the notify queue (which could discard a new stream's first image
    /// if it was queued before the flush was serviced).
    std::atomic<uint32_t> stream_epoch{0};
};

}  // namespace sendspin
