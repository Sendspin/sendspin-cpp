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

#include "announcement_role_impl.h"
#include "audio_types.h"
#include "platform/base64.h"
#include "platform/compiler.h"
#include "platform/logging.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

static const char* const TAG = "sendspin.announcement";

/// @brief Size of the big-endian 64-bit timestamp at the start of announcement binary messages.
static constexpr size_t BINARY_TIMESTAMP_SIZE = 8;
static constexpr uint32_t HEADER_SEND_TIMEOUT_MS = 100U;
// Denominator for the advertised buffer capacity fraction: advertises (N-1)/N of capacity,
// matching the player role's ring-buffer metadata headroom.
static constexpr size_t ANNOUNCEMENT_BUFFER_ADVERTISE_DENOMINATOR = 5;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

namespace sendspin {

// ============================================================================
// Helpers
// ============================================================================

/// @brief Decodes a base64-encoded string into a byte vector.
static std::vector<uint8_t> base64_decode(const std::string& input) {
    size_t output_len = 0;
    platform_base64_decode(nullptr, 0, &output_len,
                           reinterpret_cast<const unsigned char*>(input.data()), input.size());

    std::vector<uint8_t> output(output_len);
    int ret =
        platform_base64_decode(output.data(), output.size(), &output_len,
                               reinterpret_cast<const unsigned char*>(input.data()), input.size());
    if (ret != 0) {
        SS_LOGW(TAG, "base64 decode failed: %d", ret);
        return {};
    }
    output.resize(output_len);
    return output;
}

// ============================================================================
// Impl constructor / destructor
// ============================================================================

AnnouncementRole::Impl::Impl(AnnouncementRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      client(client),
      event_state(std::make_unique<EventState>()),
      task(std::make_unique<AnnouncementTask>()) {}

AnnouncementRole::Impl::~Impl() {
    // Stop the announcement task thread first, before destroying other members: the task thread
    // reads the listener pointer and the ring buffer until it has fully stopped.
    this->task.reset();
}

// ============================================================================
// AnnouncementRole forwarding (public API -> Impl)
// ============================================================================

AnnouncementRole::AnnouncementRole(AnnouncementRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(std::move(config), client)) {}

AnnouncementRole::~AnnouncementRole() = default;

void AnnouncementRole::set_listener(AnnouncementRoleListener* listener) {
    this->impl_->listener = listener;
}

const ServerAnnouncementStreamObject& AnnouncementRole::get_current_stream_params() const {
    return this->impl_->current_stream_params;
}

bool AnnouncementRole::is_playing() const {
    return this->impl_->announcement_playing;
}

// ============================================================================
// Impl: Internal integration methods
// ============================================================================

void AnnouncementRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->stream_params_slot.bind(inbox, INBOX_TOPIC_ANNOUNCEMENT_STREAM_PARAMS);
}

bool AnnouncementRole::Impl::start() {
    if (!this->config.audio_formats.empty() && this->listener && !this->task->is_initialized()) {
        if (!this->task->init(this, this->client, this->config.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize announcement task");
            return false;
        }
        if (!this->task->start(this->config.psram_stack, this->config.priority)) {
            SS_LOGE(TAG, "Failed to start announcement task thread");
            return false;
        }
    }
    return true;
}

void AnnouncementRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    if (this->config.audio_formats.empty()) {
        return;
    }

    msg.supported_roles.push_back(SendspinRole::ANNOUNCEMENT);

    // Advertise 80% of the buffer capacity to account for ring buffer metadata overhead,
    // matching the player role's convention
    AnnouncementSupportObject announcement_support = {
        .supported_formats = this->config.audio_formats,
        .buffer_capacity = this->config.audio_buffer_capacity *
                           (ANNOUNCEMENT_BUFFER_ADVERTISE_DENOMINATOR - 1) /
                           ANNOUNCEMENT_BUFFER_ADVERTISE_DENOMINATOR,
    };
    msg.announcement_v1_support = announcement_support;
}

void AnnouncementRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (this->config.audio_formats.empty()) {
        return;
    }

    ClientAnnouncementStateObject announcement_state{};
    announcement_state.playing = this->announcement_playing;
    msg.announcement = announcement_state;
}

SS_HOT void AnnouncementRole::Impl::handle_binary(const uint8_t* data, size_t len) const {
    if (this->config.audio_formats.empty()) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }
    int64_t timestamp = be64_to_host(data);
    // Announcement chunks are not sync-critical and must not be dropped for being late, so a
    // full ring buffer is the only failure here (bounded by the advertised buffer_capacity).
    if (!this->task->write_audio_chunk(data + BINARY_TIMESTAMP_SIZE, len - BINARY_TIMESTAMP_SIZE,
                                       timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
        SS_LOGW(TAG, "Failed to buffer announcement chunk");
    }
}

void AnnouncementRole::Impl::handle_stream_start(
    const ServerAnnouncementStreamObject& announcement_obj) const {
    if (this->config.audio_formats.empty()) {
        // No announcement formats configured; just defer the stream start callback
        this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_START);
        return;
    }

    bool header_sent = false;
    const ServerPlayerStreamObject& format = announcement_obj.format;

    if (!format.is_complete()) {
        SS_LOGE(TAG, "Announcement stream start missing required audio parameters");
    } else {
        auto codec = format.codec.value();

        if ((codec == SendspinCodecFormat::PCM) || (codec == SendspinCodecFormat::OPUS)) {
            DummyHeader header{};
            header.sample_rate = format.sample_rate.value();
            header.bits_per_sample = format.bit_depth.value();
            header.channels = format.channels.value();

            ChunkType chunk_type = (codec == SendspinCodecFormat::PCM)
                                       ? CHUNK_TYPE_PCM_DUMMY_HEADER
                                       : CHUNK_TYPE_OPUS_DUMMY_HEADER;

            header_sent = this->task->write_audio_chunk(reinterpret_cast<const uint8_t*>(&header),
                                                        sizeof(DummyHeader), 0, chunk_type,
                                                        HEADER_SEND_TIMEOUT_MS);
            if (!header_sent) {
                SS_LOGE(TAG, "Failed to send announcement codec header");
            }
        } else if (codec == SendspinCodecFormat::FLAC) {
            if (!format.codec_header.has_value()) {
                SS_LOGE(TAG, "FLAC codec header missing");
            } else {
                std::vector<uint8_t> flac_header = base64_decode(format.codec_header.value());
                header_sent =
                    this->task->write_audio_chunk(flac_header.data(), flac_header.size(), 0,
                                                  CHUNK_TYPE_FLAC_HEADER, HEADER_SEND_TIMEOUT_MS);
                if (!header_sent) {
                    SS_LOGE(TAG, "Failed to send announcement codec header");
                }
            }
        } else {
            SS_LOGE(TAG, "Unsupported announcement codec: %d", static_cast<int>(codec));
        }
    }

    if (!header_sent) {
        this->task->signal_stream_end();
        this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_END);
        return;
    }

    // Write stream params to the inbox slot for the main thread, then signal. Same two-step
    // write/push pattern (and the same benign cleanup race) as the player role: a concurrent
    // cleanup() may reset the slot between the two, in which case the drained STREAM_START
    // finds the slot empty and keeps the prior params, with the teardown's STREAM_END queued
    // right behind it.
    this->event_state->stream_params_slot.write(announcement_obj);
    this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_START);
}

void AnnouncementRole::Impl::handle_stream_end() const {
    this->task->signal_stream_end();
    this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_END);
}

void AnnouncementRole::Impl::handle_stream_clear() const {
    // The server replaces the announcement audio: discard what is buffered, keep the stream
    // and the ducking state active. The chunks that follow are the replacement clip.
    this->task->signal_stream_clear();
    this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_CLEARED);
}

void AnnouncementRole::Impl::on_stream_ring_event(AnnouncementStreamCallbackType event) {
    this->pending_events.push_back(event);
}

void AnnouncementRole::Impl::drain_events() {
    if (this->pending_events.empty()) {
        return;
    }

    bool state_changed = false;
    size_t processed = 0;
    bool teardown_reentered = false;

    // Indexed with a fresh size() check per iteration (not a range-for): the listener callbacks
    // below may re-enter connection teardown, whose cleanup() clears this vector mid-loop (same
    // pattern as the player role).
    // NOLINTNEXTLINE(modernize-loop-convert): body mutates the vector, see above
    for (size_t idx = 0; idx < this->pending_events.size(); ++idx) {
        const AnnouncementStreamCallbackType event = this->pending_events[idx];

        switch (event) {
            case AnnouncementStreamCallbackType::STREAM_START: {
                ServerAnnouncementStreamObject stream_params;
                if (this->event_state->stream_params_slot.take(stream_params)) {
                    this->current_stream_params = std::move(stream_params);
                }
                // Mark the stream active before invoking the listener so the STREAM_END that a
                // re-entrant cleanup() enqueues still delivers a paired on_announcement_end().
                this->stream_active = true;
                if (this->listener) {
                    const uint32_t generation = this->cleanup_generation;
                    this->listener->on_announcement_start(this->current_stream_params);
                    if (this->cleanup_generation != generation) {
                        teardown_reentered = true;
                        break;
                    }
                }
                this->task->signal_stream_start();
                break;
            }
            case AnnouncementStreamCallbackType::STREAM_END: {
                if (this->listener && this->stream_active) {
                    this->listener->on_announcement_end();
                }
                this->stream_active = false;
                if (this->announcement_playing) {
                    this->announcement_playing = false;
                    state_changed = true;
                }
                break;
            }
            case AnnouncementStreamCallbackType::STREAM_CLEARED: {
                if (this->listener && this->stream_active) {
                    this->listener->on_announcement_clear();
                }
                break;
            }
            case AnnouncementStreamCallbackType::OUTPUT_STARTED: {
                if (!this->announcement_playing) {
                    this->announcement_playing = true;
                    state_changed = true;
                }
                break;
            }
            case AnnouncementStreamCallbackType::OUTPUT_FINISHED: {
                // Local completion (drained after a server end, or the stall guard fired
                // without one): release the ducking if the server end has not already
                if (this->listener && this->stream_active) {
                    const uint32_t generation = this->cleanup_generation;
                    this->listener->on_announcement_end();
                    if (this->cleanup_generation != generation) {
                        this->stream_active = false;
                        teardown_reentered = true;
                        break;
                    }
                }
                this->stream_active = false;
                if (this->announcement_playing) {
                    this->announcement_playing = false;
                    state_changed = true;
                }
                break;
            }
        }
        if (teardown_reentered) {
            break;
        }
        ++processed;
    }

    // Clamp: a re-entrant cleanup() may have cleared the vector mid-loop.
    if (processed > this->pending_events.size()) {
        processed = this->pending_events.size();
    }
    if (processed > 0) {
        this->pending_events.erase(
            this->pending_events.begin(),
            this->pending_events.begin() + static_cast<ptrdiff_t>(processed));
    }

    if (state_changed) {
        this->client->publish_state();
    }
}

void AnnouncementRole::Impl::cleanup() {
    // Flag the teardown for a drain_events() frame that may be on the call stack right now.
    this->cleanup_generation++;

    // End any in-flight announcement: the task drains and returns to idle.
    this->task->signal_stream_end();

    // Discard stale slot content from the dead connection. Stale ring-borne events were already
    // discarded by SendspinClient::cleanup_connection_state()'s inbox.reset_events() call.
    this->event_state->stream_params_slot.reset();

    // Clear pending events (main-thread only), then enqueue a clean STREAM_END so drain_events()
    // releases the ducking and reports idle exactly once.
    this->pending_events.clear();
    this->enqueue_stream_event(AnnouncementStreamCallbackType::STREAM_END);
}

// ============================================================================
// Impl: Helpers
// ============================================================================

void AnnouncementRole::Impl::enqueue_stream_event(AnnouncementStreamCallbackType event) const {
    // A dropped STREAM_START would leave the task waiting for its start signal; a dropped
    // STREAM_END would leave media ducked. Both wedge the announcement, so log drops at ERROR.
    static const char* const EVENT_NAMES[] = {"STREAM_START", "STREAM_END", "STREAM_CLEARED",
                                              "OUTPUT_STARTED", "OUTPUT_FINISHED"};
    push_event_or_log(this->inbox, InboxEventType::ANNOUNCEMENT_STREAM, static_cast<uint8_t>(event),
                      TAG, EVENT_NAMES[static_cast<uint8_t>(event)],
                      /*error_level=*/true);
}

}  // namespace sendspin
