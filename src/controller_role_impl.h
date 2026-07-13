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
        InboxSlot<ServerStateControllerObject> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    void handle_server_state(ServerStateControllerObject state) const;
    void drain_events();
    void handle_cleared_event();
    void cleanup();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume,
                      std::optional<bool> mute) const;

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
};

}  // namespace sendspin
