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
#include "scheduled_state_slot.h"
#include "sendspin/color_role.h"
#include "teardown_tracker.h"

#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief The server-clock timestamp `color` applies at (ScheduledStateSlot)
inline int64_t scheduled_time(const ServerColorStateObject& color) {
    return color.timestamp;
}

/// @brief Private implementation of the color role
struct ColorRole::Impl : RoleTeardown {
    explicit Impl(SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        ScheduledStateSlot<ServerColorStateObject> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    /// @brief Hands a parsed palette to the slot, which copies it into the place it takes.
    /// Protocol task.
    void handle_server_state(const ServerColorStateObject& color) const;
    /// @brief True if a palette arrived, or the pending palette the last drain left in the slot
    /// has come due: the deadline sets no inbox bit, so it is checked every tick, against
    /// ScheduledStateSlot::pending_at(), without the Inbox mutex.
    bool needs_drain(uint32_t pending_bits) const {
        const std::optional<int64_t> pending_at = this->event_state->slot.pending_at();
        return (pending_bits & INBOX_TOPIC_COLOR) != 0 ||
               (pending_at.has_value() && this->state_is_due(*pending_at));
    }
    /// @brief Catches the role up on any teardown (complete_teardown()), then applies whichever
    /// palette the slot holds is due (drain_scheduled_state()). Main loop.
    void drain_events();
    /// Whether a palette's server-clock deadline has passed on the synchronized client clock.
    bool state_is_due(int64_t timestamp) const;

    /// @brief Stops the role and discards the state the protocol task can reach. Protocol task,
    /// or the main loop in SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Queues a COLOR_CLEARED event
    /// stamped with the new generation; the main loop runs complete_teardown() for it
    /// (catch_up_teardown()).
    void cleanup();

    /// @brief The main-loop teardown half: resets the state only the main loop touches and fires
    /// on_color_clear(). Main loop only, through catch_up_teardown().
    void complete_teardown();

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    /// The applied palette, the one on_color() is handed. Main loop only; the slot's commit copies
    /// the palette it delivers into it, under the Inbox mutex.
    ServerColorStateObject color{};

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ColorRoleListener* listener{nullptr};
};

}  // namespace sendspin
