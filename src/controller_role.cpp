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

#include "platform/shadow_slot.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

namespace sendspin {

/// @brief Deferred event state for thread-safe controller state delivery
struct ControllerRole::EventState {
    ShadowSlot<ServerStateControllerObject> shadow;
};

// ============================================================================
// Lifecycle
// ============================================================================

ControllerRole::ControllerRole(SendspinClient* client)
    : client_(client), event_state_(std::make_unique<EventState>()) {}

ControllerRole::~ControllerRole() = default;

// ============================================================================
// Core API
// ============================================================================

void ControllerRole::send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume,
                                  std::optional<bool> mute) {
    std::string command_message = format_client_command_message(cmd, volume, mute);
    this->client_->send_text(command_message);
}

// ============================================================================
// Internal Helpers
// ============================================================================

void ControllerRole::contribute_hello(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::CONTROLLER);
}

void ControllerRole::handle_server_state(ServerStateControllerObject state) {
    this->event_state_->shadow.write(std::move(state));
}

void ControllerRole::drain_events() {
    ServerStateControllerObject state;
    if (this->event_state_->shadow.take(state)) {
        this->controller_state_ = std::move(state);
        if (this->listener_) {
            this->listener_->on_controller_state(this->controller_state_);
        }
    }
}

void ControllerRole::cleanup() {
    this->event_state_->shadow.reset();
    this->controller_state_ = {};
}

}  // namespace sendspin
