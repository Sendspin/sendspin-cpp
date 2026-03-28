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

#include "sendspin/controller_role.h"

#include "client_bridge.h"

#include <mutex>

namespace sendspin {

void ControllerRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

void ControllerRole::send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume,
                                  std::optional<bool> mute) {
    if (this->bridge_ && this->bridge_->send_text) {
        std::string command_message = format_client_command_message(cmd, volume, mute);
        this->bridge_->send_text(command_message);
    }
}

void ControllerRole::contribute_hello(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::CONTROLLER);
}

void ControllerRole::handle_server_state(ServerStateControllerObject state) {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_controller_state_events_.push_back(std::move(state));
}

void ControllerRole::drain_events(std::vector<ServerStateControllerObject>& events) {
    for (auto& controller_state : events) {
        this->controller_state_ = std::move(controller_state);
    }
    if (!events.empty() && this->on_controller_state) {
        this->on_controller_state(this->controller_state_);
    }
}

void ControllerRole::cleanup() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);

    // Discard stale events from the dead connection
    this->pending_controller_state_events_.clear();
}

}  // namespace sendspin
