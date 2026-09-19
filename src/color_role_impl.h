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

/// @file color_role_impl.h
/// @brief Private implementation for the color role (pimpl)

#pragma once

#include "inbox.h"
#include "protocol_messages.h"
#include "sendspin/color_role.h"

#include <atomic>
#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Color palettes handed to the main loop but not yet drained
///
/// messaging.md "server/state" lets a server bring a client up to date and then schedule the next
/// update straight after it, so two palettes can land between two main-loop ticks: the one for
/// what is playing now, and the one timed to the next track. Both are kept, in arrival order, so
/// the current one is still applied on the tick that also takes the scheduled one. A third
/// palette arriving in the same window replaces `newest`, which no observer has seen.
struct PendingColorStates {
    std::optional<ServerColorStateObject> oldest;
    std::optional<ServerColorStateObject> newest;
};

/// @brief Private implementation of the color role
struct ColorRole::Impl {
    explicit Impl(SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        InboxSlot<PendingColorStates> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    // Takes a const reference, unlike the metadata and controller overloads: a
    // ServerColorStateObject holds only optional RGB triples and a timestamp, so there is nothing
    // for an rvalue reference to move out of.
    void handle_server_state(const ServerColorStateObject& color, uint32_t generation) const;
    // True if a slot palette needs taking, or a palette already held from a prior tick (see
    // held_state) is still waiting out its server-clock deadline -- the deadline itself sets no
    // inbox bit, so held_state must be polled every tick until it fires.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_COLOR) != 0 || this->held_state.has_value();
    }
    void drain_events();
    /// Whether a palette's server-clock deadline has passed on the synchronized client clock.
    bool state_is_due(int64_t timestamp) const;
    /// Applies the held palette and fires the listener once its server-clock deadline has passed.
    void apply_due_state();
    void handle_cleared_event() const;
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
    // Fields
    // ========================================

    // Struct fields
    ServerColorStateObject color{};
    // Palette taken from the inbox slot, awaiting its server-clock deadline. Main-thread only:
    // written and read exclusively from drain_events()/cleanup() on the loop thread.
    std::optional<ServerColorStateObject> held_state;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ColorRoleListener* listener{nullptr};

    // 32-bit fields
    /// @brief Teardown generation, bumped by cleanup(). The receive gate captures it when it
    /// admits a message and every point of effect re-checks it (see accepts()), so state written
    /// by a handler a teardown overtook is refused. Atomic because the network thread reads it.
    std::atomic<uint32_t> cleanup_generation{0};
};

}  // namespace sendspin
