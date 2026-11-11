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
#include <cstring>
#include <utility>

static const char* const TAG = "sendspin.metadata";

namespace sendspin {

namespace {

/// @brief The text fields `config` keeps
EnumSet<MetadataField> kept_fields(const MetadataRoleConfig& config) {
    EnumSet<MetadataField> kept;
    const std::pair<bool, MetadataField> flags[] = {
        {config.title, MetadataField::TITLE},
        {config.artist, MetadataField::ARTIST},
        {config.album_artist, MetadataField::ALBUM_ARTIST},
        {config.album, MetadataField::ALBUM},
        {config.artwork_url, MetadataField::ARTWORK_URL},
    };
    for (const auto& [keep, field] : flags) {
        if (keep) {
            kept.insert(field);
        }
    }
    return kept;
}

/// @brief Text storage for each text field of the public state, reserved for the field's cap when
/// `layout` keeps it, and for nothing when it does not
std::array<ReservedText, METADATA_FIELD_COUNT> reserve_metadata_text(
    const MetadataTextLayout& layout) {
    const auto room = [&layout](MetadataField field) {
        return layout.kept.contains(field) ? metadata_field_cap(field) : 0;
    };
    return {ReservedText(room(MetadataField::TITLE)), ReservedText(room(MetadataField::ARTIST)),
            ReservedText(room(MetadataField::ALBUM_ARTIST)),
            ReservedText(room(MetadataField::ALBUM)),
            ReservedText(room(MetadataField::ARTWORK_URL))};
}

/// @brief The public state's member for `field`
std::optional<std::string>& text_field(ServerMetadataStateObject& state, MetadataField field) {
    switch (field) {
        case MetadataField::TITLE:
            return state.title;
        case MetadataField::ARTIST:
            return state.artist;
        case MetadataField::ALBUM_ARTIST:
            return state.album_artist;
        case MetadataField::ALBUM:
            return state.album;
        case MetadataField::ARTWORK_URL:
            return state.artwork_url;
    }
    return state.title;
}

}  // namespace

// ============================================================================
// Impl constructor / destructor
// ============================================================================

MetadataRole::Impl::Impl(MetadataRoleConfig config, SendspinClient* client)
    : config(config),
      layout(metadata_text_layout(kept_fields(config))),
      metadata_text(reserve_metadata_text(this->layout)),
      client(client),
      event_state(std::make_unique<EventState>()) {}

// ============================================================================
// MetadataRole forwarding (public API → Impl)
// ============================================================================

MetadataRole::MetadataRole(MetadataRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(config, client)) {}

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

bool MetadataRole::Impl::start() {
    const size_t bytes = METADATA_TEXT_BLOCKS * static_cast<size_t>(this->layout.block_bytes);
    if (bytes == 0 || this->text_blocks) {
        return true;
    }
    if (!this->text_blocks.allocate(bytes, this->config.buffer_location)) {
        SS_LOGE(TAG, "Failed to allocate the %zu byte metadata text buffer", bytes);
        return false;
    }
    return true;
}

void MetadataRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    msg.supported_roles.push_back(SendspinRole::METADATA);
}

MetadataStateOutcome MetadataRole::Impl::handle_server_state(JsonObject root) {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // Parsed, and rejected or cut (logged), with no lock held; only the copy runs under it.
    MetadataStateView parsed;
    const MetadataStateOutcome outcome =
        process_server_state_metadata(root, this->layout.kept, &parsed);
    if (outcome == MetadataStateOutcome::PARSED || outcome == MetadataStateOutcome::CUT) {
        // messaging.md "server/state": each included metadata object is the role's full state,
        // never an overlay on the one before it, so it replaces the place's state whole.
        this->event_state->slot.arrive(
            [this, &parsed](MetadataStateBuffer& place) { this->fill_place(place, parsed); },
            generation);
    }
    return outcome;
}

void MetadataRole::Impl::fill_place(MetadataStateBuffer& place, const MetadataStateView& parsed) {
    place.payload = parsed.payload;
    char* block = reinterpret_cast<char*>(this->text_blocks.data()) +
                  static_cast<size_t>(place.block) * this->layout.block_bytes;
    for (size_t i = 0; i < METADATA_FIELD_COUNT; ++i) {
        const uint16_t size = parsed.payload.text_sizes[i].value_or(0);
        if (size > 0) {
            // At most the field's cap, the room the layout gives it
            std::memcpy(block + this->layout.offsets[i], parsed.text[i], size);
        }
    }
}

bool MetadataRole::Impl::state_is_due(int64_t timestamp) const {
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so a state is due at once rather than starving the
    // listener.
    const int64_t client_ts = this->client->get_client_time(timestamp);
    return client_ts == 0 || client_ts <= platform_time_us();
}

std::optional<std::string_view> MetadataRole::Impl::text_of(const MetadataStateBuffer& state,
                                                            MetadataField field) const {
    const auto i = static_cast<size_t>(field);
    const std::optional<uint16_t> size = state.payload.text_sizes[i];
    if (!size.has_value()) {
        return std::nullopt;
    }
    const char* block = reinterpret_cast<const char*>(this->text_blocks.data()) +
                        static_cast<size_t>(state.block) * this->layout.block_bytes;
    return std::string_view(block + this->layout.offsets[i], *size);
}

void MetadataRole::Impl::fill_public_state(const MetadataStateBuffer& state) {
    const MetadataStatePayload& payload = state.payload;
    this->metadata.timestamp = payload.timestamp;
    this->metadata.year = payload.year;
    this->metadata.track = payload.track;
    this->metadata.progress = payload.progress;
    for (size_t i = 0; i < METADATA_FIELD_COUNT; ++i) {
        const auto field = static_cast<MetadataField>(i);
        this->metadata_text[i].fill(text_field(this->metadata, field), this->text_of(state, field));
    }
}

void MetadataRole::Impl::apply_current_state() {
    this->fill_public_state(this->current);
    if (this->listener) {
        this->listener->on_metadata(this->metadata);
    }
}

void MetadataRole::Impl::drain_events() {
    // A delivery trades blocks rather than copying text: the delivered place takes the current
    // state's block, which no state still to be delivered names, and the text is copied once, out
    // of the current block into the public state, with no lock held.
    drain_scheduled_state(
        *this, this->event_state->slot,
        [this](MetadataStateBuffer& place) { std::swap(place, this->current); },
        [this] { this->apply_current_state(); }, TAG, "metadata");
}

void MetadataRole::Impl::cleanup() {
    // Bumped first, so the drain discards a payload stamped before it (see RoleTeardown).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->event_state->slot.reset();

    push_event_or_log(this->inbox, InboxEventType::METADATA_CLEARED, 0, TAG,
                      "metadata cleared event", generation);
}

void MetadataRole::Impl::complete_teardown() {
    this->fill_public_state(MetadataStateBuffer{});
    this->event_state->slot.forget_pending();
    if (this->listener) {
        this->listener->on_metadata_clear();
    }
}

}  // namespace sendspin
