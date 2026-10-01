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

static const char* const TAG = "sendspin.controller";

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

void ControllerRole::send_command(const ClientCommandControllerObject& cmd) {
    this->impl_->send_command(cmd);
}

// ============================================================================
// Impl method implementations
// ============================================================================

void ControllerRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->slot.bind(inbox, INBOX_TOPIC_CONTROLLER);
}

/// @brief The command's bit in ControllerRole::Impl::supported_commands_mask.
static uint32_t command_bit(SendspinControllerCommand command) {
    static_assert(static_cast<uint8_t>(SendspinControllerCommand::SEEK_RELATIVE) < 32,
                  "every command needs a bit in supported_commands_mask");
    return 1U << static_cast<uint8_t>(command);
}

/// @brief Whether `cmd` carries the parameter roles/controller/v1.md "Command behaviour" requires
/// for its command, in range.
static bool has_required_parameter(const ClientCommandControllerObject& cmd) {
    switch (cmd.command) {
        case SendspinControllerCommand::VOLUME:
            return cmd.volume.has_value() && *cmd.volume <= VOLUME_MAX;
        case SendspinControllerCommand::MUTE:
            return cmd.muted.has_value();
        case SendspinControllerCommand::SEEK:
            return cmd.position_ms.has_value();
        case SendspinControllerCommand::SEEK_RELATIVE:
            return cmd.offset_ms.has_value();
        default:
            return true;
    }
}

void ControllerRole::Impl::send_command(const ClientCommandControllerObject& cmd) const {
    // roles/controller/v1.md "client/command controller object": only a command listed in the
    // latest supported_commands, with its required parameter.
    if ((this->supported_commands_mask.load(std::memory_order_relaxed) &
         command_bit(cmd.command)) == 0) {
        SS_LOGW(TAG, "Dropping '%s': not in the server's supported_commands", to_cstr(cmd.command));
        return;
    }
    if (!has_required_parameter(cmd)) {
        SS_LOGW(TAG, "Dropping '%s': missing or out-of-range parameter", to_cstr(cmd.command));
        return;
    }
    std::string command_message = format_client_command_message(cmd);
    this->client->send_text(command_message, "controller");
}

void ControllerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::CONTROLLER);
}

void ControllerRole::Impl::handle_server_state(ServerStateControllerObject&& state,
                                               uint32_t generation) const {
    if (!this->accepts(generation)) {
        return;
    }
    this->event_state->slot.write(std::move(state));
}

void ControllerRole::Impl::drain_events() {
    ServerStateControllerObject state;
    if (this->event_state->slot.take(state)) {
        this->controller_state = std::move(state);
        uint32_t mask = 0;
        for (const auto command : this->controller_state.supported_commands) {
            mask |= command_bit(command);
        }
        this->supported_commands_mask.store(mask, std::memory_order_relaxed);
        if (this->listener) {
            this->listener->on_controller_state(this->controller_state);
        }
    }
}

void ControllerRole::Impl::handle_cleared_event() const {
    // Deferred from cleanup() to avoid invoking the listener while ConnectionManager holds
    // conn_ptr_mutex_; a listener that calls back into the client would otherwise deadlock.
    if (this->listener) {
        this->listener->on_controller_state_clear();
    }
}

void ControllerRole::Impl::cleanup() {
    // Bumped first: it invalidates any handler the gate already admitted (see accepts()).
    this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel);
    this->event_state->slot.reset();
    this->controller_state = {};
    this->supported_commands_mask.store(0, std::memory_order_relaxed);

    // Unstamped: a clear is idempotent, so it is delivered whatever teardown overtook it.
    push_event_or_log(this->inbox, InboxEventType::CONTROLLER_CLEARED, 0, TAG,
                      "controller cleared event", /*epoch=*/0);
}

}  // namespace sendspin
