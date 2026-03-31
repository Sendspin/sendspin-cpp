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

#include "sendspin/metadata_role.h"

#include "audio_stream_info.h"
#include "platform/shadow_slot.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>

namespace sendspin {

/// @brief Deferred event state for thread-safe metadata delivery to the main thread
struct MetadataRole::EventState {
    ShadowSlot<ServerMetadataStateObject> shadow;
};

// ============================================================================
// Lifecycle
// ============================================================================

MetadataRole::MetadataRole(SendspinClient* client)
    : client_(client), event_state_(std::make_unique<EventState>()) {}

MetadataRole::~MetadataRole() = default;

// ============================================================================
// Public API
// ============================================================================

uint32_t MetadataRole::get_track_duration_ms() const {
    if (!this->metadata_.progress.has_value()) {
        return 0;
    }
    return this->metadata_.progress.value().track_duration;
}

uint32_t MetadataRole::get_track_progress_ms() const {
    if (!this->metadata_.progress.has_value()) {
        return 0;
    }

    const auto& progress = this->metadata_.progress.value();

    // If paused (playback_speed == 0), return the snapshot value directly
    if (progress.playback_speed == 0) {
        return progress.track_progress;
    }

    int64_t client_target = this->client_->get_client_time(this->metadata_.timestamp);
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

// ============================================================================
// Internal Helpers
// ============================================================================

void MetadataRole::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::METADATA);
}

void MetadataRole::handle_server_state(ServerMetadataStateObject state) {
    this->event_state_->shadow.merge(
        [](ServerMetadataStateObject& current, ServerMetadataStateObject&& delta) {
            apply_metadata_state_deltas(&current, delta);
        },
        std::move(state));
}

void MetadataRole::drain_events() {
    ServerMetadataStateObject delta{};
    if (this->event_state_->shadow.take(delta)) {
        apply_metadata_state_deltas(&this->metadata_, delta);
        if (this->listener_) {
            this->listener_->on_metadata(this->metadata_);
        }
    }
}

void MetadataRole::cleanup() {
    this->event_state_->shadow.reset();
    this->metadata_ = {};
}

}  // namespace sendspin
