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

#include "audio_stream_info.h"
#include "metadata_role_impl.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>

namespace sendspin {

// ============================================================================
// Impl constructor / destructor
// ============================================================================

MetadataRole::Impl::Impl(SendspinClient* client)
    : client(client), event_state(std::make_unique<EventState>()) {}

// ============================================================================
// MetadataRole forwarding (public API → Impl)
// ============================================================================

MetadataRole::MetadataRole(SendspinClient* client) : impl_(std::make_unique<Impl>(client)) {}

MetadataRole::~MetadataRole() = default;

void MetadataRole::set_listener(MetadataRoleListener* listener) {
    this->impl_->listener = listener;
}

uint32_t MetadataRole::get_track_duration_ms() const {
    return this->impl_->get_track_duration_ms();
}

uint32_t MetadataRole::get_track_progress_ms() const {
    return this->impl_->get_track_progress_ms();
}

// ============================================================================
// Impl method implementations
// ============================================================================

uint32_t MetadataRole::Impl::get_track_duration_ms() const {
    if (!this->metadata.progress.has_value()) {
        return 0;
    }
    return this->metadata.progress.value().track_duration;
}

uint32_t MetadataRole::Impl::get_track_progress_ms() const {
    if (!this->metadata.progress.has_value()) {
        return 0;
    }

    const auto& progress = this->metadata.progress.value();

    // If paused (playback_speed == 0), return the snapshot value directly
    if (progress.playback_speed == 0) {
        return progress.track_progress;
    }

    int64_t client_target = this->client->get_client_time(this->metadata.timestamp);
    if (client_target == 0) {
        return progress.track_progress;
    }

    // calculated_progress = track_progress + (now - metadata_client_time) * playback_speed /
    // 1_000_000
    int64_t elapsed_us = platform_time_us() - client_target;
    int64_t calculated = static_cast<int64_t>(progress.track_progress) +
                         elapsed_us * static_cast<int64_t>(progress.playback_speed) /
                             static_cast<int64_t>(US_PER_SECOND);

    if (progress.track_duration != 0) {
        calculated = std::max(std::min(calculated, static_cast<int64_t>(progress.track_duration)),
                              static_cast<int64_t>(0));
    } else {
        calculated = std::max(calculated, static_cast<int64_t>(0));
    }

    return static_cast<uint32_t>(calculated);
}

void MetadataRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::METADATA);
}

void MetadataRole::Impl::handle_server_state(ServerMetadataStateObject state) const {
    this->event_state->shadow.merge(
        [](ServerMetadataStateObject& current, ServerMetadataStateObject&& delta) {
            apply_metadata_state_deltas(&current, delta);
        },
        std::move(state));
}

void MetadataRole::Impl::drain_events() {
    ServerMetadataStateObject delta{};
    // Caveat: merged deltas carry only the newest timestamp, so a past-valid field merged
    // under a later future-valid update gets held back until the later deadline. Accepted
    // since overlapping fields are last-writer-wins anyway.
    const bool taken =
        this->event_state->shadow.take_if(delta, [this](const ServerMetadataStateObject& pending) {
            // Fire immediately if time sync isn't ready: without sync we can't honor the
            // deadline anyway, and holding forever would starve the listener.
            int64_t client_ts = this->client->get_client_time(pending.timestamp);
            if (client_ts == 0) {
                return true;
            }
            return client_ts <= platform_time_us();
        });
    if (!taken) {
        return;
    }
    apply_metadata_state_deltas(&this->metadata, delta);
    if (this->listener) {
        this->listener->on_metadata(this->metadata);
    }
}

void MetadataRole::Impl::cleanup() {
    this->event_state->shadow.reset();
    this->metadata = {};
}

}  // namespace sendspin
