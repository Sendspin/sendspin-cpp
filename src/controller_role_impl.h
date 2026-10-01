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

/// @file controller_role_impl.h
/// @brief Private implementation for the controller role (pimpl)

#pragma once

#include "inbox.h"
#include "sendspin/controller_role.h"

#include <atomic>
#include <memory>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Private implementation of the controller role
struct ControllerRole::Impl {
    explicit Impl(SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        // Latest-wins only, unlike metadata and color: messaging.md "server/state" scopes a
        // deferred timestamp to those two objects, so ServerStateControllerObject carries none and
        // this role needs neither their PendingXStates pair nor their held_state deadline poll.
        InboxSlot<ServerStateControllerObject> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    void handle_server_state(ServerStateControllerObject&& state, uint32_t generation) const;
    // True if a controller-state delta is waiting in the inbox slot.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_CONTROLLER) != 0;
    }
    void drain_events();
    void handle_cleared_event() const;
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, on the network thread, while the
    /// handler it admits runs on: a teardown can land in between (the deactivation path, unlike a
    /// lost connection, never quiesces the network thread). Re-checking at each point of effect
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

    void send_command(const ClientCommandControllerObject& cmd) const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    ServerStateControllerObject controller_state{};

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ControllerRoleListener* listener{nullptr};

    // 32-bit fields
    /// @brief One bit per command in controller_state.supported_commands (see command_bit()).
    /// Written with it on the main loop; atomic because send_command() may run on any thread.
    std::atomic<uint32_t> supported_commands_mask{0};
    /// @brief Teardown generation, bumped by cleanup() and re-checked at every point of effect
    /// (see accepts()). Atomic because the network thread reads it.
    std::atomic<uint32_t> cleanup_generation{0};
};

}  // namespace sendspin
