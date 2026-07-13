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

namespace {

/// @brief Merges an incoming wire delta into an accumulated delta using field-overlay semantics
///
/// For each field, an outer-engaged incoming entry overwrites the accumulated entry verbatim;
/// absent (outer-nullopt) incoming fields leave the accumulated entry untouched, so pending
/// clears (inner-nullopt) from earlier deltas survive until applied. Shared by both merge sites
/// so they cannot drift: cross-thread, merging a network-thread delta into the inbox slot
/// (handle_server_state); and main-thread, folding a freshly taken slot value into the held delta
/// (ColorRole::Impl::drain_events). ServerColorStateDelta is trivially copyable (RgbColor is
/// std::array<uint8_t, 3>), so fields are assigned directly without std::move.
void merge_color_state_delta(ServerColorStateDelta& current,
                             const ServerColorStateDelta& incoming) {
    current.timestamp = incoming.timestamp;
    if (incoming.background_dark.has_value()) {
        current.background_dark = incoming.background_dark;
    }
    if (incoming.background_light.has_value()) {
        current.background_light = incoming.background_light;
    }
    if (incoming.primary.has_value()) {
        current.primary = incoming.primary;
    }
    if (incoming.accent.has_value()) {
        current.accent = incoming.accent;
    }
    if (incoming.on_dark.has_value()) {
        current.on_dark = incoming.on_dark;
    }
    if (incoming.on_light.has_value()) {
        current.on_light = incoming.on_light;
    }
}

}  // namespace

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

void ColorRole::Impl::handle_server_state(ServerColorStateDelta delta) const {
    // Merge incoming wire delta into the accumulated delta in the inbox slot; see
    // merge_color_state_delta for the field-overlay semantics.
    this->event_state->slot.merge(merge_color_state_delta, delta);
}

void ColorRole::Impl::drain_events() {
    ServerColorStateDelta delta{};
    if (this->event_state->slot.take(delta)) {
        if (this->held_delta.has_value()) {
            merge_color_state_delta(*this->held_delta, delta);
        } else {
            this->held_delta = delta;
        }
    }

    if (!this->held_delta.has_value()) {
        return;
    }

    // A future-dated delta is held across ticks below without any topic bit set (take() above
    // cleared it). It is re-evaluated against its deadline on later ticks only because
    // needs_drain() ORs in held_delta.has_value() alongside the INBOX_TOPIC_COLOR bit test, so
    // this drain_events() keeps running each tick until the deadline fires. Dropping that OR term
    // would strand the delta until an unrelated new delta re-set the topic bit.
    //
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so fire immediately rather than starving the
    // listener. No lock is held here (the slot value was already taken above), unlike the old
    // take_if predicate which ran under the shadow slot's mutex.
    int64_t client_ts = this->client->get_client_time(this->held_delta->timestamp);
    if (client_ts != 0 && client_ts > platform_time_us()) {
        return;
    }

    apply_color_state_deltas(&this->color, *this->held_delta);
    if (this->listener) {
        this->listener->on_color(this->color);
    }
    this->held_delta.reset();
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
    this->held_delta.reset();

    push_event_or_log(this->inbox, InboxEventType::COLOR_CLEARED, 0, TAG, "color cleared event");
}

}  // namespace sendspin
