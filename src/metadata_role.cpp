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
#include "platform/logging.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>
#include <utility>

static const char* const TAG = "sendspin.metadata";

namespace sendspin {

namespace {

/// @brief Merges an incoming wire delta into an accumulated delta using field-overlay semantics
///
/// For each field, an outer-engaged incoming entry overwrites the accumulated entry verbatim;
/// absent (outer-nullopt) incoming fields leave the accumulated entry untouched, so pending
/// clears (inner-nullopt) from earlier deltas survive until applied. Shared by both merge sites
/// so they cannot drift: cross-thread, merging a network-thread delta into the inbox slot
/// (handle_server_state); and main-thread, folding a freshly taken slot value into the held delta
/// (MetadataRole::Impl::drain_events).
void merge_metadata_state_delta(ServerMetadataStateDelta& current,
                                ServerMetadataStateDelta&& incoming) {
    current.timestamp = incoming.timestamp;
    if (incoming.title.has_value()) {
        current.title = std::move(incoming.title);
    }
    if (incoming.artist.has_value()) {
        current.artist = std::move(incoming.artist);
    }
    if (incoming.album_artist.has_value()) {
        current.album_artist = std::move(incoming.album_artist);
    }
    if (incoming.album.has_value()) {
        current.album = std::move(incoming.album);
    }
    if (incoming.artwork_url.has_value()) {
        current.artwork_url = std::move(incoming.artwork_url);
    }
    if (incoming.year.has_value()) {
        current.year = incoming.year;
    }
    if (incoming.track.has_value()) {
        current.track = incoming.track;
    }
    if (incoming.progress.has_value()) {
        current.progress = incoming.progress;
    }
}

}  // namespace

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

void MetadataRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->slot.bind(inbox, INBOX_TOPIC_METADATA);
}

void MetadataRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::METADATA);
}

void MetadataRole::Impl::handle_server_state(ServerMetadataStateDelta delta) const {
    // Merge incoming wire delta into the accumulated delta in the inbox slot; see
    // merge_metadata_state_delta for the field-overlay semantics.
    this->event_state->slot.merge(merge_metadata_state_delta, std::move(delta));
}

void MetadataRole::Impl::drain_events() {
    // InboxSlot has no take_if (a deadline predicate must not run under the shared Inbox mutex --
    // see inbox.h), so the server-clock deadline gate that used to live inside the shadow slot's
    // take_if predicate is split in two: take() unconditionally moves any pending slot value into
    // held_delta (folding it in if a delta is already held), then the deadline is evaluated below
    // with no lock held at all.
    //
    // Caveat: merged deltas carry only the newest timestamp, so a past-valid field merged under a
    // later future-valid update gets held back until the later deadline. Accepted since
    // overlapping fields are last-writer-wins anyway. This applies identically regardless of
    // which merge site folded the fields together -- cross-thread in the slot (handle_server_state)
    // or here, folding a taken slot value into held_delta.
    ServerMetadataStateDelta delta{};
    if (this->event_state->slot.take(delta)) {
        if (this->held_delta.has_value()) {
            merge_metadata_state_delta(*this->held_delta, std::move(delta));
        } else {
            this->held_delta = std::move(delta);
        }
    }

    if (!this->held_delta.has_value()) {
        return;
    }

    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so fire immediately rather than starving the
    // listener.
    int64_t client_ts = this->client->get_client_time(this->held_delta->timestamp);
    if (client_ts != 0 && client_ts > platform_time_us()) {
        return;
    }

    apply_metadata_state_deltas(&this->metadata, *this->held_delta);
    if (this->listener) {
        this->listener->on_metadata(this->metadata);
    }
    this->held_delta.reset();
}

void MetadataRole::Impl::handle_cleared_event() {
    // Deferred from cleanup() to avoid invoking the listener while ConnectionManager holds
    // conn_ptr_mutex_; a listener that calls back into the client would otherwise deadlock.
    if (this->listener) {
        this->listener->on_metadata_clear();
    }
}

void MetadataRole::Impl::cleanup() {
    this->event_state->slot.reset();
    this->metadata = {};
    this->held_delta.reset();

    push_event_or_log(this->inbox, InboxEventType::METADATA_CLEARED, 0, TAG,
                      "metadata cleared event");
}

}  // namespace sendspin
