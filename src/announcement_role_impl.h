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

/// @file announcement_role_impl.h
/// @brief Private implementation for the announcement role (pimpl)

#pragma once

#include "announcement_task.h"
#include "inbox.h"
#include "sendspin/announcement_role.h"

#include <memory>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred announcement lifecycle callback types queued from the network and task threads
enum class AnnouncementStreamCallbackType : uint8_t {
    STREAM_START,     // New announcement stream is starting (from the network thread)
    STREAM_END,       // Announcement stream ended (from the network thread or cleanup)
    STREAM_CLEARED,   // Server cleared buffered announcement audio (from the network thread)
    OUTPUT_STARTED,   // Task began writing announcement audio to the sink (from the task thread)
    OUTPUT_FINISHED,  // Task finished draining the announcement (from the task thread)
};

/// @brief Private implementation of the announcement role
struct AnnouncementRole::Impl {
    Impl(AnnouncementRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        InboxSlot<ServerAnnouncementStreamObject> stream_params_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    void build_state_fields(ClientStateMessage& msg) const;
    void handle_binary(const uint8_t* data, size_t len) const;
    void handle_stream_start(const ServerAnnouncementStreamObject& announcement_obj) const;
    void handle_stream_end() const;
    void handle_stream_clear() const;
    void on_stream_ring_event(AnnouncementStreamCallbackType event);
    // True if this tick has drainable announcement work. All announcement events (lifecycle from
    // the network thread, output transitions from the announcement task) travel over the shared
    // event ring and are appended to pending_events by on_stream_ring_event() during this tick's
    // ring dispatch, so the vector is the single source of pending work. stream_params_slot needs
    // no separate topic-bit term: it is only consumed from the STREAM_START branch, which the
    // pending_events term covers.
    bool needs_drain(uint32_t /*pending_bits*/) const {
        return !this->pending_events.empty();
    }
    void drain_events();
    void cleanup();

    // ========================================
    // Helpers
    // ========================================

    void enqueue_stream_event(AnnouncementStreamCallbackType event) const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    AnnouncementRoleConfig config;
    ServerAnnouncementStreamObject current_stream_params{};
    std::vector<AnnouncementStreamCallbackType> pending_events;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    AnnouncementRoleListener* listener{nullptr};
    std::unique_ptr<AnnouncementTask> task;

    // 32-bit fields
    // Bumped by cleanup() so a drain_events() listener callback that re-enters connection
    // teardown is detected when control returns (mirrors the player role). Main-thread only.
    uint32_t cleanup_generation{0};

    // 8-bit fields
    // True while the announcement pipeline is outputting audio; reported to the server via
    // client/state.announcement. Main-thread only.
    bool announcement_playing{false};
    // True between the drained STREAM_START and the stream's end (server end, local completion,
    // or cleanup); keeps on_announcement_end() paired 1:1 with on_announcement_start().
    // Main-thread only.
    bool stream_active{false};
};

}  // namespace sendspin
