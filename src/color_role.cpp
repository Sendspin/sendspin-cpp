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

void ColorRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::COLOR);
}

void ColorRole::Impl::handle_server_state(ServerColorStateDelta delta) const {
    // Merge incoming wire delta into the accumulated delta in the shadow slot. For each field, an
    // outer-engaged incoming entry overwrites the accumulated entry verbatim; absent
    // (outer-nullopt) incoming fields leave the accumulated entry untouched, so pending clears
    // (inner-nullopt) from earlier deltas survive until drain_events applies them.
    // ServerColorStateDelta is trivially copyable (RgbColor is std::array<uint8_t, 3>), so the
    // merge assigns fields directly without std::move.
    this->event_state->shadow.merge(
        [](ServerColorStateDelta& current, ServerColorStateDelta&& incoming) {
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
        },
        delta);
}

void ColorRole::Impl::drain_events() {
    // Deferred from cleanup() to avoid invoking the listener while ConnectionManager holds
    // conn_ptr_mutex_; a listener that calls back into the client would otherwise deadlock.
    if (this->event_state->pending_clear) {
        this->event_state->pending_clear = false;
        if (this->listener) {
            this->listener->on_color_clear();
        }
    }

    ServerColorStateDelta delta{};
    const bool taken =
        this->event_state->shadow.take_if(delta, [this](const ServerColorStateDelta& pending) {
            // get_client_time returns 0 when there is no current connection. Without a connection
            // we cannot honor the server-clock deadline, so fire immediately rather than starving
            // the listener.
            int64_t client_ts = this->client->get_client_time(pending.timestamp);
            if (client_ts == 0) {
                return true;
            }
            return client_ts <= platform_time_us();
        });
    if (!taken) {
        return;
    }
    apply_color_state_deltas(&this->color, delta);
    if (this->listener) {
        this->listener->on_color(this->color);
    }
}

void ColorRole::Impl::cleanup() {
    this->event_state->shadow.reset();
    this->color = {};
    this->event_state->pending_clear = true;
}

}  // namespace sendspin
