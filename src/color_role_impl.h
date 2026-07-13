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

#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Private implementation of the color role
struct ColorRole::Impl {
    explicit Impl(SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        // Stores the wire-level delta type so accumulated clears (inner-nullopt) survive
        // cross-thread merging until drain_events applies them to the merged state.
        InboxSlot<ServerColorStateDelta> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    void handle_server_state(ServerColorStateDelta delta) const;
    void drain_events();
    void handle_cleared_event() const;
    void cleanup();

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    ServerColorStateObject color{};
    // Delta accumulated from the inbox slot, awaiting its server-clock deadline. Main-thread
    // only: written and read exclusively from drain_events()/cleanup() on the loop thread.
    std::optional<ServerColorStateDelta> held_delta;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    ColorRoleListener* listener{nullptr};
};

}  // namespace sendspin
