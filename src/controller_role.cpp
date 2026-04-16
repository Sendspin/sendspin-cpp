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

#include "controller_role_impl.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

namespace sendspin {

// ============================================================================
// Impl constructor / destructor
// ============================================================================

ControllerRole::Impl::Impl(SendspinClient* client)
    : client(client), event_state(std::make_unique<EventState>()) {}

// ============================================================================
// ControllerRole forwarding (public API → Impl)
// ============================================================================

ControllerRole::ControllerRole(SendspinClient* client) : impl_(std::make_unique<Impl>(client)) {}

ControllerRole::~ControllerRole() = default;

const ServerStateControllerObject& ControllerRole::get_controller_state() const {
    return this->impl_->controller_state;
}

void ControllerRole::set_listener(ControllerRoleListener* listener) {
    this->impl_->listener = listener;
}

void ControllerRole::send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume,
                                  std::optional<bool> mute) {
    this->impl_->send_command(cmd, volume, mute);
}

// ============================================================================
// Impl method implementations
// ============================================================================

void ControllerRole::Impl::send_command(SendspinControllerCommand cmd,
                                        std::optional<uint8_t> volume,
                                        std::optional<bool> mute) const {
    std::string command_message = format_client_command_message(cmd, volume, mute);
    this->client->send_text(command_message);
}

void ControllerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::CONTROLLER);
}

void ControllerRole::Impl::handle_server_state(ServerStateControllerObject state) const {
    this->event_state->shadow.write(std::move(state));
}

void ControllerRole::Impl::drain_events() {
    ServerStateControllerObject state;
    if (this->event_state->shadow.take(state)) {
        this->controller_state = std::move(state);
        if (this->listener) {
            this->listener->on_controller_state(this->controller_state);
        }
    }
}

void ControllerRole::Impl::cleanup() {
    this->event_state->shadow.reset();
    this->controller_state = {};
}

}  // namespace sendspin
