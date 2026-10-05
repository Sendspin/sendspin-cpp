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
#include "teardown_tracker.h"

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
        GenerationSlot<ServerStateControllerObject> slot;
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
    /// @brief Takes the slot, catches the role up on any teardown (complete_teardown()), then
    /// applies the taken state if it was admitted under the current generation. Main loop.
    void drain_events();
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, before the handler it admits
    /// runs, and stop()'s teardown on the main loop can land in between. Re-checking at each
    /// point of effect invalidates the whole handler instead of only the part that ran before it.
    /// The drain applies the same check to a slot payload's stamp.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards the state the protocol task can reach. Protocol task,
    /// or the main loop in SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Queues a CONTROLLER_CLEARED
    /// event stamped with the new generation; the main loop runs complete_teardown() for it
    /// (catch_up_teardown()).
    void cleanup();

    /// @brief The main-loop teardown half: resets the state only the main loop touches and fires
    /// on_controller_state_clear(). Main loop only, through catch_up_teardown().
    void complete_teardown();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    bool send_command(const ClientCommandControllerObject& cmd) const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    ServerStateControllerObject controller_state{};
    TeardownTracker teardown;  ///< Main loop only.

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ControllerRoleListener* listener{nullptr};

    // 32-bit fields
    /// @brief The commands of the applied controller_state.supported_commands, one bit each (see
    /// command_bit()) in the low half, stamped in the high half with the low 16 bits of the
    /// teardown generation the state was admitted under (see pack_supported_commands()).
    /// send_command() treats a stamp other than the current generation's as no commands, so a
    /// teardown retires the mask the instant cleanup() bumps the generation, whatever the main
    /// loop wrote around it. Written on the main loop (drain_events(), complete_teardown()); read
    /// by send_command() on any thread.
    std::atomic<uint32_t> supported_commands{0};
    /// @brief Teardown generation, bumped by cleanup() and re-checked at every point of effect
    /// (see accepts()). Written on the protocol task (or the main loop in stop() once it is
    /// joined); read on the main loop and by send_command() on any thread.
    std::atomic<uint32_t> cleanup_generation{0};
};

}  // namespace sendspin
