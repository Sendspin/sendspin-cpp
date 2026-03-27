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

#pragma once

#include "sendspin/protocol.h"

#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientBridge;

/// @brief Controller role: read-only server state and outbound commands.
class ControllerRole {
    friend class SendspinClient;

public:
    ControllerRole() = default;

    /// @brief Sends a controller command to the server.
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});

    /// @brief Returns the current controller state from the server.
    const ServerStateControllerObject& get_controller_state() const {
        return this->controller_state_;
    }

private:
    void attach(ClientBridge* bridge);
    void contribute_hello(ClientHelloMessage& msg);
    void handle_server_state(ServerStateControllerObject state);
    void drain_events(std::vector<ServerStateControllerObject>& events);
    void cleanup();

    ClientBridge* bridge_{nullptr};
    ServerStateControllerObject controller_state_{};
    std::vector<ServerStateControllerObject> pending_controller_state_events_;
};

}  // namespace sendspin
