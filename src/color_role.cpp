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

#include "color_role_impl.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

static const char* const TAG = "sendspin.color";

namespace sendspin {

// ============================================================================
// Impl constructor / destructor
// ============================================================================

ColorRole::Impl::Impl(SendspinClient* client)
    : client(client), event_state(std::make_unique<EventState>()) {}

// ============================================================================
// ColorRole forwarding (public API → Impl)
// ============================================================================

ColorRole::ColorRole(SendspinClient* client) : impl_(std::make_unique<Impl>(client)) {}

ColorRole::~ColorRole() = default;

void ColorRole::set_listener(ColorRoleListener* listener) {
    this->impl_->listener = listener;
}

// ============================================================================
// Impl method implementations
// ============================================================================

void ColorRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->slot.bind(inbox, INBOX_TOPIC_COLOR);
}

void ColorRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::COLOR);
}

void ColorRole::Impl::handle_server_state(const ServerColorStateObject& color) const {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // messaging.md "server/state": each included color object is the role's full palette, never
    // an overlay on the one before it, so it replaces the place's palette whole.
    this->event_state->slot.arrive([&color](ServerColorStateObject& place) { place = color; },
                                   generation);
}

bool ColorRole::Impl::state_is_due(int64_t timestamp) const {
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so a palette is due at once rather than starving
    // the listener.
    const int64_t client_ts = this->client->get_client_time(timestamp);
    return client_ts == 0 || client_ts <= platform_time_us();
}

void ColorRole::Impl::drain_events() {
    drain_scheduled_state(
        *this, this->event_state->slot,
        [this](const ServerColorStateObject& place) { this->color = place; },
        [this] {
            if (this->listener) {
                this->listener->on_color(this->color);
            }
        },
        TAG, "color");
}

void ColorRole::Impl::cleanup() {
    // Bumped first, so the drain discards a payload stamped before it (see RoleTeardown).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->event_state->slot.reset();

    push_event_or_log(this->inbox, InboxEventType::COLOR_CLEARED, 0, TAG, "color cleared event",
                      generation);
}

void ColorRole::Impl::complete_teardown() {
    this->color = {};
    this->event_state->slot.forget_pending();
    if (this->listener) {
        this->listener->on_color_clear();
    }
}

}  // namespace sendspin
