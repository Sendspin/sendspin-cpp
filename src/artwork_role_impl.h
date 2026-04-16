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
#include "sendspin/artwork_role.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Deferred artwork event types
enum class ArtworkEventType : uint8_t {
    STREAM_START,
    STREAM_END,
    STREAM_CLEAR,
};

/// @brief Maximum number of artwork slots (2-bit slot field in protocol binary type byte)
static constexpr size_t ARTWORK_MAX_SLOTS = 4;

/// @brief Double-buffered image storage for a single artwork slot
struct SlotBuffer {
    PlatformBuffer buffers[2];
    std::atomic<uint8_t> write_idx{0};      ///< Which buffer the network thread writes to next
    std::atomic<bool> drain_active{false};  ///< True while the drain thread is using a buffer
    uint8_t drain_buf_idx{0};               ///< Which buffer the drain thread is currently using
};

/// @brief Notification sent from the network thread to the drain thread when new image data arrives
///
/// All metadata is carried in the notification itself (not in SlotBuffer) so that the
/// ThreadSafeQueue's internal mutex provides the happens-before guarantee between the
/// network thread's writes and the drain thread's reads.
struct ArtworkNotification {
    uint8_t slot;
    uint8_t buffer_idx;
    size_t data_length;
    int64_t timestamp;
    SendspinImageFormat format;
};

/// @brief Private implementation of the artwork role
struct ArtworkRole::Impl {
    Impl(ArtworkRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Nested types
    // ========================================

    /// @brief Persistent drain thread context for artwork image decode and display delivery
    struct DrainTask {
        ThreadSafeQueue<ArtworkNotification> notify_queue;
        EventFlags event_flags;
        std::thread drain_thread;
        SlotBuffer slot_buffers[ARTWORK_MAX_SLOTS];
    };

    /// @brief Deferred event state for thread-safe artwork stream lifecycle delivery
    struct EventState {
        ThreadSafeQueue<ArtworkEventType> queue;
        ShadowSlot<ServerArtworkStreamObject> shadow_config;
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
    ArtworkRoleListener* listener{nullptr};

    // 8-bit fields
    std::atomic<bool> stream_active{false};
};

}  // namespace sendspin
