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

bool ControllerRole::send_command(const ClientCommandControllerObject& cmd) {
    return this->impl_->send_command(cmd);
}

// ============================================================================
// Impl method implementations
// ============================================================================

void ControllerRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->slot.bind(inbox, INBOX_TOPIC_CONTROLLER);
}

/// @brief The command's bit in the mask half of ControllerRole::Impl::supported_commands.
static uint32_t command_bit(SendspinControllerCommand command) {
    static_assert(static_cast<uint8_t>(SendspinControllerCommand::SEEK_RELATIVE) < 16,
                  "every command needs a bit in the mask half of supported_commands");
    return 1U << static_cast<uint8_t>(command);
}

/// @brief Packs a supported-commands mask with the generation it was admitted under: the mask in
/// the low 16 bits, the generation's low 16 bits above it. One atomic word, so send_command()
/// reads a mask and its stamp together.
static uint32_t pack_supported_commands(uint32_t generation, uint32_t mask) {
    return (generation << 16) | (mask & 0xFFFFU);
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

bool ControllerRole::Impl::send_command(const ClientCommandControllerObject& cmd) const {
    // roles/controller/v1.md "client/command controller object": only a command listed in the
    // latest supported_commands, with its required parameter.
    // A mask stamped with an earlier generation belongs to a torn-down connection.
    const uint32_t packed = this->supported_commands.load(std::memory_order_acquire);
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    const uint32_t mask = (packed >> 16) == (generation & 0xFFFFU) ? (packed & 0xFFFFU) : 0;
    if ((mask & command_bit(cmd.command)) == 0) {
        SS_LOGW(TAG, "Dropping '%s': not in the server's supported_commands", to_cstr(cmd.command));
        return false;
    }
    if (!has_required_parameter(cmd)) {
        SS_LOGW(TAG, "Dropping '%s': missing or out-of-range parameter", to_cstr(cmd.command));
        return false;
    }
    std::string command_message = format_client_command_message(cmd);
    return this->client->send_text(command_message, "controller");
}

void ControllerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::CONTROLLER);
}

void ControllerRole::Impl::handle_server_state(ServerStateControllerObject&& state,
                                               uint32_t generation) const {
    if (!this->accepts(generation)) {
        return;
    }
    this->event_state->slot.write(std::move(state), generation);
}

void ControllerRole::Impl::drain_events() {
    // Taken before the catch-up: whatever the slot held, a teardown that ran before the take is
    // caught up below and drops a payload stamped before it, and one that runs after the take is
    // caught up by the next drain, behind the state applied here.
    ServerStateControllerObject state;
    uint32_t stamp = 0;
    const bool taken = this->event_state->slot.take(state, stamp);
    catch_up_teardown(*this, this->cleanup_generation.load(std::memory_order_acquire));
    if (!taken) {
        return;
    }
    // Also false once the clear callback above re-entered teardown (a listener calling stop()).
    if (!this->accepts(stamp)) {
        SS_LOGD(TAG, "Dropping controller state queued before the role was torn down");
        return;
    }
    this->controller_state = std::move(state);
    uint32_t mask = 0;
    for (const auto command : this->controller_state.supported_commands) {
        mask |= command_bit(command);
    }
    this->supported_commands.store(pack_supported_commands(stamp, mask), std::memory_order_release);
    if (this->listener) {
        this->listener->on_controller_state(this->controller_state);
    }
}

void ControllerRole::Impl::cleanup() {
    // Bumped first: it invalidates any handler the gate already admitted (see accepts()) and the
    // supported-commands mask (see supported_commands).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->event_state->slot.reset();

    // Stamped so the drain runs complete_teardown() for this generation before it applies
    // anything the next connection sends.
    push_event_or_log(this->inbox, InboxEventType::CONTROLLER_CLEARED, 0, TAG,
                      "controller cleared event", generation);
}

void ControllerRole::Impl::complete_teardown() {
    this->controller_state = {};
    this->supported_commands.store(0, std::memory_order_release);
    if (this->listener) {
        this->listener->on_controller_state_clear();
    }
}

}  // namespace sendspin
