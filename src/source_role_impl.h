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

/// @file source_role_impl.h
/// @brief Private implementation for the source role (pimpl)

#pragma once

#include "inbox.h"
#include "protocol_messages.h"
#include "sendspin/source_role.h"
#include "source_task.h"

#include <memory>
#include <optional>
#include <vector>

namespace sendspin {

class ConnectionManager;
class SendspinClient;

/// @brief Deferred stream lifecycle callback types queued from the source task thread
enum class SourceStreamCallbackType : uint8_t {
    STREAMING_STARTED,  // The outbound stream opened (client-stream/start sent)
    STREAMING_STOPPED,  // The outbound stream closed (stop, connection loss, or cleanup)
};

/// @brief Private implementation of the source role
struct SourceRole::Impl {
    Impl(SourceRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Event state
    // ========================================

    /// @brief One server/command source command with the connection it arrived on
    struct SourceCommandEnvelope {
        uint64_t connection_instance_id{0};
        SourceCommand command{SourceCommand::STOP};
    };

    struct EventState {
        /// Latest-wins: commands are idempotent and only the final desired state matters
        /// (Sendspin spec, Source messages)
        InboxSlot<SourceCommandEnvelope> command_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    void build_state_fields(ClientStateMessage& msg) const;
    void handle_server_command(SourceCommand command, uint64_t connection_instance_id) const;
    void on_stream_ring_event(SourceStreamCallbackType event);
    // A pending server command, or lifecycle events appended during this tick's ring dispatch
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_SOURCE_COMMAND) != 0 || !this->pending_events.empty();
    }
    void drain_events();
    void cleanup();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    bool write_audio(const uint8_t* data, size_t len, int64_t capture_time_us);
    void set_signal(SourceSignal new_signal);

    // ========================================
    // Helpers
    // ========================================

    void enqueue_stream_event(SourceStreamCallbackType event) const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    SourceRoleConfig config;
    std::vector<SourceStreamCallbackType> pending_events;
    /// Last set_signal() value, included in client/state once set (main-thread only)
    std::optional<SourceSignal> signal;

    // Pointer fields
    SendspinClient* client;
    /// Set by add_source(); used for the instance-id check and stream binding. Outlives this
    /// role: SendspinClient destroys every role before connection_manager_.
    ConnectionManager* connection_manager{nullptr};
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    SourceRoleListener* listener{nullptr};
    std::unique_ptr<SourceTask> task;

    // 8-bit fields
    /// Set once in the constructor; an invalid config leaves the role inert
    bool config_valid{false};
    /// Main-loop latch of the server's last command on the current connection; cleanup()
    /// resets it to stopped (per-connection permission, Sendspin spec, Source messages)
    bool streaming_desired{false};
    /// Keeps the listener's started/stopped callbacks paired 1:1 (main-thread only)
    bool streaming_active{false};
};

}  // namespace sendspin
