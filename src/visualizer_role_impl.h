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

/// @file visualizer_role_impl.h
/// @brief Private implementation for the visualizer role (pimpl)

#pragma once

#include "platform/event_flags.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
#include "platform/spsc_ring_buffer.h"
#include "platform/thread_safe_queue.h"
#include "sendspin/visualizer_role.h"

#include <atomic>
#include <memory>
#include <optional>
#include <thread>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Deferred visualizer event types (used internally in the visualizer role)
enum class VisualizerEventType : uint8_t {
    STREAM_START,
    STREAM_END,
    STREAM_CLEAR,
};

/// @brief Private implementation of the visualizer role
struct VisualizerRole::Impl {
    explicit Impl(VisualizerRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Nested types
    // ========================================

    /// @brief Persistent drain thread context and platform ring buffer for visualizer data delivery
    struct DrainTask {
        SpscRingBuffer ring_buffer;
        PlatformBuffer ring_storage;
        EventFlags event_flags;
        std::thread drain_thread;
    };

    /// @brief Deferred event state for thread-safe visualizer stream lifecycle delivery
    struct EventState {
        ThreadSafeQueue<VisualizerEventType> queue;
        ShadowSlot<ServerVisualizerStreamObject> shadow_config;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    void handle_binary(uint8_t binary_type, const uint8_t* data, size_t len);
    void handle_stream_start(const ServerVisualizerStreamObject& stream);
    void handle_stream_end();
    void handle_stream_clear();
    void drain_events() const;
    void cleanup();

    // ========================================
    // Internal helpers
    // ========================================

    void stop() const;
    void flush_ring_buffer() const;

    static void drain_thread_func(VisualizerRole::Impl* self);

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    VisualizerRoleConfig config;
    std::optional<VisualizerSupportObject> visualizer_support;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<DrainTask> drain_task;
    std::unique_ptr<EventState> event_state;
    VisualizerRoleListener* listener{nullptr};

    // Atomic fields (written by network thread, read by drain thread / cleanup)
    std::atomic<size_t> raw_frame_size{0};
    std::atomic<bool> has_f_peak{false};
    std::atomic<bool> has_loudness{false};
    std::atomic<bool> has_spectrum{false};
    std::atomic<uint8_t> spectrum_bin_count{0};
    std::atomic<bool> stream_active{false};
};

}  // namespace sendspin
