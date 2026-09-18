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

#include <utility>

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
    // messaging.md "server/state": each included color object is the role's full palette, so a
    // newer one replaces an undrained older one outright rather than overlaying it.
    this->event_state->slot.write(color);
}

void ColorRole::Impl::drain_events() {
    // roles/color/v1.md "Scheduled color updates": a palette whose timestamp is still in the
    // future is the pending update and a newer one replaces it, while a past or present one is
    // applied at once and discards the pending update. Both fall out of replacing held_state with
    // whatever the slot holds.
    ServerColorStateObject color{};
    if (this->event_state->slot.take(color)) {
        this->held_state = color;
    }

    if (!this->held_state.has_value()) {
        return;
    }

    // A future-dated palette is held across ticks below without any topic bit set (take() above
    // cleared it). It is re-evaluated against its deadline on later ticks only because
    // needs_drain() ORs in held_state.has_value() alongside the INBOX_TOPIC_COLOR bit test, so
    // this drain_events() keeps running each tick until the deadline fires. Dropping that OR term
    // would strand the palette until an unrelated new one re-set the topic bit.
    //
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so fire immediately rather than starving the
    // listener. No lock is held here (the slot value was already taken above).
    int64_t client_ts = this->client->get_client_time(this->held_state->timestamp);
    if (client_ts != 0 && client_ts > platform_time_us()) {
        return;
    }

    this->color = this->held_state.value();
    if (this->listener) {
        this->listener->on_color(this->color);
    }
    this->held_state.reset();
}

void ColorRole::Impl::handle_cleared_event() const {
    // Deferred from cleanup() to avoid invoking the listener while ConnectionManager holds
    // conn_ptr_mutex_; a listener that calls back into the client would otherwise deadlock.
    if (this->listener) {
        this->listener->on_color_clear();
    }
}

void ColorRole::Impl::cleanup() {
    this->event_state->slot.reset();
    this->color = {};
    this->held_state.reset();

    push_event_or_log(this->inbox, InboxEventType::COLOR_CLEARED, 0, TAG, "color cleared event");
}

}  // namespace sendspin
