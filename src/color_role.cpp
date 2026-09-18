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

/// @brief Folds a newly arrived palette into the palettes the main loop has not taken yet
///
/// `incoming` always carries exactly one palette, in `oldest`. The first one to arrive after a
/// drain keeps that place; every later one becomes `newest`, so the pair the main loop takes is
/// the oldest undrained palette and the most recent one (see PendingColorStates). Runs under the
/// Inbox mutex, so it stays a pure data operation.
void coalesce_color_states(PendingColorStates& current, PendingColorStates&& incoming) {
    if (!current.oldest.has_value()) {
        current.oldest = incoming.oldest;
        return;
    }
    current.newest = incoming.oldest;
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

void ColorRole::Impl::handle_server_state(const ServerColorStateObject& color,
                                          uint32_t generation) const {
    if (!this->accepts(generation)) {
        return;
    }
    // messaging.md "server/state": each included color object is the role's full palette, never
    // an overlay on the one before it. Two can arrive between main-loop ticks, so the slot keeps
    // the oldest undrained palette alongside the newest (see coalesce_color_states).
    PendingColorStates arrival;
    arrival.oldest = color;
    this->event_state->slot.merge(coalesce_color_states, arrival);
}

bool ColorRole::Impl::state_is_due(int64_t timestamp) const {
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so a palette is due at once rather than starving
    // the listener.
    const int64_t client_ts = this->client->get_client_time(timestamp);
    return client_ts == 0 || client_ts <= platform_time_us();
}

void ColorRole::Impl::apply_due_state() {
    if (!this->held_state.has_value() || !this->state_is_due(this->held_state->timestamp)) {
        return;
    }

    this->color = this->held_state.value();
    this->held_state.reset();
    if (this->listener) {
        this->listener->on_color(this->color);
    }
}

void ColorRole::Impl::drain_events() {
    // roles/color/v1.md "Scheduled color updates": a palette whose timestamp is still in the
    // future is the pending update and a newer one replaces it, while a past or present one is
    // applied at once and discards the pending update. Both fall out of replacing held_state with
    // each taken palette in arrival order, applying whatever is due in between. No lock is held
    // while a deadline is evaluated (the slot value was already taken).
    PendingColorStates taken;
    if (this->event_state->slot.take(taken)) {
        const bool collapses =
            taken.newest.has_value() && this->state_is_due(taken.newest->timestamp);
        if (taken.oldest.has_value() && !collapses) {
            // The older palette is applied on its own while the one behind it is still scheduled.
            // Two palettes that are both due collapse instead: the older would be superseded
            // within this tick, so no listener could observe it.
            this->held_state = taken.oldest;
            this->apply_due_state();
        }
        if (taken.newest.has_value()) {
            this->held_state = taken.newest;
        }
    }

    // A future-dated palette is held across ticks without any topic bit set (take() above cleared
    // it). It is re-evaluated against its deadline on later ticks only because needs_drain() ORs
    // in held_state.has_value() alongside the INBOX_TOPIC_COLOR bit test, so this drain_events()
    // keeps running each tick until the deadline fires. Dropping that OR term would strand the
    // palette until an unrelated new one re-set the topic bit.
    this->apply_due_state();
}

void ColorRole::Impl::handle_cleared_event() const {
    // Deferred from cleanup() to avoid invoking the listener while ConnectionManager holds
    // conn_ptr_mutex_; a listener that calls back into the client would otherwise deadlock.
    if (this->listener) {
        this->listener->on_color_clear();
    }
}

void ColorRole::Impl::cleanup() {
    // Bumped first: it invalidates any handler the gate already admitted (see accepts()).
    this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel);
    this->event_state->slot.reset();
    this->color = {};
    this->held_state.reset();

    push_event_or_log(this->inbox, InboxEventType::COLOR_CLEARED, 0, TAG, "color cleared event");
}

}  // namespace sendspin
