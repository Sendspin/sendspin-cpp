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

#include "audio_types.h"
#include "platform/base64.h"
#include "platform/logging.h"
#include "player_role_impl.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

static const char* const TAG = "sendspin.player";

/// @brief Size of the big-endian 64-bit timestamp at the start of player binary messages.
static constexpr size_t BINARY_TIMESTAMP_SIZE = 8;
static constexpr uint16_t MAX_STATIC_DELAY_MS = 5000U;
static constexpr uint32_t HEADER_SEND_TIMEOUT_MS = 100U;
// Denominator for the advertised buffer capacity fraction: advertises (N-1)/N of capacity
static constexpr size_t AUDIO_BUFFER_ADVERTISE_DENOMINATOR = 5;

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

PlayerRole::Impl::Impl(PlayerRoleConfig config, SendspinClient* client,
                       SendspinPersistenceProvider* persistence)
    : config(std::move(config)),
      client(client),
      event_state(std::make_unique<EventState>()),
      persistence(persistence),
      sync_task(std::make_unique<SyncTask>()) {
    this->event_state->stream_queue.create(8);
    this->event_state->state_queue.create(4);
}

PlayerRole::Impl::~Impl() {
    // Stop the sync task thread first, before destroying other members.
    // External callbacks (e.g., PortAudio) may still call notify_audio_played() on another thread,
    // so the sync task must be stopped while it's still valid.
    this->sync_task.reset();
}

// ============================================================================
// PlayerRole forwarding (public API → Impl)
// ============================================================================

PlayerRole::PlayerRole(PlayerRoleConfig config, SendspinClient* client,
                       SendspinPersistenceProvider* persistence)
    : impl_(std::make_unique<Impl>(std::move(config), client, persistence)) {}

PlayerRole::~PlayerRole() = default;

void PlayerRole::set_listener(PlayerRoleListener* listener) {
    this->impl_->listener = listener;
}

void PlayerRole::notify_audio_played(uint32_t frames, int64_t timestamp) {
    if (this->impl_->sync_task && this->impl_->sync_task->is_running()) {
        this->impl_->sync_task->notify_audio_played(frames, timestamp);
    }
}

void PlayerRole::update_volume(uint8_t volume) {
    this->impl_->update_volume(volume);
}

void PlayerRole::update_muted(bool muted) {
    this->impl_->update_muted(muted);
}

void PlayerRole::update_static_delay(uint16_t delay_ms) {
    this->impl_->update_static_delay(delay_ms);
}

void PlayerRole::set_static_delay_adjustable(bool adjustable) {
    this->impl_->static_delay_adjustable = adjustable;
    this->impl_->client->publish_state();
}

const ServerPlayerStreamObject& PlayerRole::get_current_stream_params() const {
    return this->impl_->current_stream_params;
}

int32_t PlayerRole::get_fixed_delay_us() const {
    return this->impl_->config.fixed_delay_us;
}

bool PlayerRole::get_muted() const {
    return this->impl_->muted;
}

uint16_t PlayerRole::get_static_delay_ms() const {
    return this->impl_->static_delay_ms;
}

uint8_t PlayerRole::get_volume() const {
    return this->impl_->volume;
}

// ============================================================================
// Impl: State updates
// ============================================================================

void PlayerRole::Impl::update_volume(uint8_t volume) {
    this->volume = volume;
    this->client->publish_state();
}

void PlayerRole::Impl::update_muted(bool muted) {
    this->muted = muted;
    this->client->publish_state();
}

void PlayerRole::Impl::update_static_delay(uint16_t delay_ms) {
    if (delay_ms > MAX_STATIC_DELAY_MS) {
        delay_ms = MAX_STATIC_DELAY_MS;
    }
    this->static_delay_ms = delay_ms;
    this->persist_static_delay();
    this->client->publish_state();
}

// ============================================================================
// Impl: Internal integration methods
// ============================================================================

bool PlayerRole::Impl::start() {
    this->load_static_delay();

    if (!this->config.audio_formats.empty() && this->listener &&
        !this->sync_task->is_initialized()) {
        if (!this->sync_task->init(this, this->client, this->config.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
            return false;
        }
        if (!this->sync_task->start(this->config.psram_stack, this->config.priority)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
            return false;
        }
    }
    return true;
}

void PlayerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    if (this->config.audio_formats.empty()) {
        return;
    }

    msg.supported_roles.push_back(SendspinRole::PLAYER);

    // Advertise 80% of the buffer capacity to account for ring buffer metadata overhead
    // and rapid stop/start scenarios
    PlayerSupportObject player_support = {
        .supported_formats = this->config.audio_formats,
        .buffer_capacity = this->config.audio_buffer_capacity *
                           (AUDIO_BUFFER_ADVERTISE_DENOMINATOR - 1) /
                           AUDIO_BUFFER_ADVERTISE_DENOMINATOR,
        .supported_commands = {SendspinPlayerCommand::VOLUME, SendspinPlayerCommand::MUTE},
    };
    msg.player_v1_support = player_support;
}

void PlayerRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (this->config.audio_formats.empty()) {
        return;
    }

    ClientPlayerStateObject player_state{};
    player_state.volume = this->volume;
    player_state.muted = this->muted;
    player_state.static_delay_ms = this->static_delay_ms;
    if (this->static_delay_adjustable) {
        player_state.supported_commands = {SendspinPlayerCommand::SET_STATIC_DELAY};
    }
    msg.player = player_state;
}

void PlayerRole::Impl::handle_binary(const uint8_t* data, size_t len) const {
    if (this->config.audio_formats.empty()) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }
    int64_t timestamp = be64_to_host(data);
    if (!this->send_audio_chunk(data + BINARY_TIMESTAMP_SIZE, len - BINARY_TIMESTAMP_SIZE,
                                timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
        SS_LOGW(TAG, "Failed to send audio chunk");
    }
}

void PlayerRole::Impl::handle_stream_start(const ServerPlayerStreamObject& player_obj) {
    if (this->config.audio_formats.empty()) {
        // No audio formats, just defer stream start callback
        this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_START, 0);
        return;
    }

    // Request high-performance networking for playback
    if (!this->high_performance_requested_for_playback) {
        this->client->acquire_high_performance();
        this->high_performance_requested_for_playback = true;
    }

    if (!player_obj.bit_depth.has_value() || !player_obj.channels.has_value() ||
        !player_obj.sample_rate.has_value() || !player_obj.codec.has_value()) {
        SS_LOGE(TAG, "Stream start message missing required audio parameters");
        return;
    }

    auto codec = player_obj.codec.value();
    bool header_sent = false;

    if ((codec == SendspinCodecFormat::PCM) || (codec == SendspinCodecFormat::OPUS)) {
        DummyHeader header{};
        header.sample_rate = player_obj.sample_rate.value();
        header.bits_per_sample = player_obj.bit_depth.value();
        header.channels = player_obj.channels.value();

        ChunkType chunk_type = (codec == SendspinCodecFormat::PCM) ? CHUNK_TYPE_PCM_DUMMY_HEADER
                                                                   : CHUNK_TYPE_OPUS_DUMMY_HEADER;

        header_sent =
            this->send_audio_chunk(reinterpret_cast<const uint8_t*>(&header), sizeof(DummyHeader),
                                   0, chunk_type, HEADER_SEND_TIMEOUT_MS);
    } else if (codec == SendspinCodecFormat::FLAC) {
        if (!player_obj.codec_header.has_value()) {
            SS_LOGE(TAG, "FLAC codec header missing");
            return;
        }
        std::vector<uint8_t> flac_header = base64_decode(player_obj.codec_header.value());
        header_sent = this->send_audio_chunk(flac_header.data(), flac_header.size(), 0,
                                             CHUNK_TYPE_FLAC_HEADER, HEADER_SEND_TIMEOUT_MS);
    }

    if (!header_sent) {
        SS_LOGE(TAG, "Failed to send codec header");
        this->sync_task->signal_stream_end();
        this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_END, 0);
        return;
    }

    // Shadow stream params for main thread, then signal
    this->event_state->shadow_stream_params.write(player_obj);
    this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_START, 0);
}

void PlayerRole::Impl::handle_stream_end() const {
    this->sync_task->signal_stream_end();
    this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_END, 0);
}

void PlayerRole::Impl::handle_stream_clear() const {
    this->sync_task->signal_stream_clear();
    this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_CLEAR, 0);
}

void PlayerRole::Impl::handle_server_command(const ServerCommandMessage& cmd) const {
    if (!cmd.player.has_value()) {
        SS_LOGV(TAG, "Server command has no player commands");
        return;
    }
    this->event_state->shadow_command.merge(
        [](ServerCommandMessage& current, ServerCommandMessage&& delta) {
            if (!delta.player.has_value()) {
                return;
            }
            if (!current.player.has_value()) {
                current.player = delta.player;
                return;
            }
            // Overlay individual optional fields so different command types
            // don't clobber each other when merged between drain ticks
            const auto& dp = delta.player.value();
            auto& cp = current.player.value();
            if (dp.volume.has_value()) {
                cp.volume = dp.volume;
            }
            if (dp.mute.has_value()) {
                cp.mute = dp.mute;
            }
            if (dp.static_delay_ms.has_value()) {
                cp.static_delay_ms = dp.static_delay_ms;
            }
        },
        cmd);
}

void PlayerRole::Impl::drain_events() {
    // --- Client state events (from sync task) ---
    SendspinClientState state{};
    SendspinClientState last_state{};
    bool has_state = false;
    while (this->event_state->state_queue.receive(state, 0)) {
        last_state = state;
        has_state = true;
    }
    if (has_state) {
        this->client->update_state(last_state);
    }

    // --- Server command events (volume, mute, static delay) ---
    // Check each field independently since multiple command types may have been
    // merged into one shadow slot between drain ticks.
    ServerCommandMessage cmd_msg{};
    if (this->event_state->shadow_command.take(cmd_msg)) {
        if (cmd_msg.player.has_value()) {
            const ServerPlayerCommandObject& player_cmd = cmd_msg.player.value();

            if (player_cmd.volume.has_value()) {
                this->update_volume(player_cmd.volume.value());
                if (this->listener) {
                    this->listener->on_volume_changed(player_cmd.volume.value());
                }
            }

            if (player_cmd.mute.has_value()) {
                this->update_muted(player_cmd.mute.value());
                if (this->listener) {
                    this->listener->on_mute_changed(player_cmd.mute.value());
                }
            }

            if (player_cmd.static_delay_ms.has_value()) {
                this->update_static_delay(player_cmd.static_delay_ms.value());
                if (this->listener) {
                    this->listener->on_static_delay_changed(this->static_delay_ms);
                }
            }
        }
    }

    // --- Stream lifecycle callback events ---
    PlayerStreamCallbackType stream_event{};
    while (this->event_state->stream_queue.receive(stream_event, 0)) {
        this->awaiting_sync_idle_events.push_back(stream_event);
    }

    // --- Process awaiting sync idle events ---
    if (!this->awaiting_sync_idle_events.empty()) {
        bool sync_idle = !this->sync_task->is_running();
        size_t processed = 0;

        for (auto& event : this->awaiting_sync_idle_events) {
            if ((event == PlayerStreamCallbackType::STREAM_END ||
                 event == PlayerStreamCallbackType::STREAM_CLEAR) &&
                !sync_idle) {
                break;  // Wait for sync task to go idle before firing this and anything after it
            }

            switch (event) {
                case PlayerStreamCallbackType::STREAM_END:
                    if (this->listener) {
                        this->listener->on_stream_end();
                    }
                    if (this->high_performance_requested_for_playback) {
                        this->client->release_high_performance();
                        this->high_performance_requested_for_playback = false;
                    }
                    break;
                case PlayerStreamCallbackType::STREAM_CLEAR:
                    if (this->listener) {
                        this->listener->on_stream_clear();
                    }
                    break;
                case PlayerStreamCallbackType::STREAM_START: {
                    ServerPlayerStreamObject stream_params;
                    if (this->event_state->shadow_stream_params.take(stream_params)) {
                        this->current_stream_params = std::move(stream_params);
                    }
                    if (this->listener) {
                        this->listener->on_stream_start();
                    }
                    this->sync_task->signal_stream_start();
                    break;
                }
            }
            ++processed;
        }

        if (processed > 0) {
            this->awaiting_sync_idle_events.erase(
                this->awaiting_sync_idle_events.begin(),
                this->awaiting_sync_idle_events.begin() + static_cast<ptrdiff_t>(processed));
        }
    }
}

void PlayerRole::Impl::cleanup() {
    // Clear all buffered audio immediately
    this->sync_task->signal_stream_clear();

    // Discard stale events from the dead connection
    this->event_state->stream_queue.reset();
    this->event_state->state_queue.reset();
    this->event_state->shadow_stream_params.reset();
    this->event_state->shadow_command.reset();

    // Enqueue a clean STREAM_END - drain_events() will fire the callback
    this->event_state->stream_queue.send(PlayerStreamCallbackType::STREAM_END, 0);

    // Clear awaiting events too (main-thread only, no mutex needed)
    this->awaiting_sync_idle_events.clear();

    if (this->high_performance_requested_for_playback) {
        this->client->release_high_performance();
        this->high_performance_requested_for_playback = false;
    }
}

// ============================================================================
// Impl: Helpers
// ============================================================================

bool PlayerRole::Impl::send_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                                        uint8_t chunk_type, uint32_t timeout_ms) const {
    if (data == nullptr || data_size == 0) {
        SS_LOGE(TAG, "Invalid data passed to send_audio_chunk");
        return false;
    }

    return this->sync_task->write_audio_chunk(data, data_size, timestamp,
                                              static_cast<ChunkType>(chunk_type), timeout_ms);
}

void PlayerRole::Impl::enqueue_state_update(SendspinClientState state) const {
    this->event_state->state_queue.send(state, 0);
}

void PlayerRole::Impl::load_static_delay() {
    if (!this->persistence) {
        // No persistence provider - use initial value from config
        if (this->config.initial_static_delay_ms > 0) {
            this->static_delay_ms = this->config.initial_static_delay_ms;
            SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms);
        }
        return;
    }

    auto delay = this->persistence->load_static_delay();
    if (delay.has_value()) {
        if (delay.value() <= MAX_STATIC_DELAY_MS) {
            this->static_delay_ms = delay.value();
            SS_LOGI(TAG, "Loaded static delay: %u ms", this->static_delay_ms);
        } else {
            SS_LOGW(TAG, "Persisted static delay out of range (%u), ignoring", delay.value());
        }
    } else if (this->config.initial_static_delay_ms > 0) {
        this->static_delay_ms = this->config.initial_static_delay_ms;
        SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms);
    }
}

void PlayerRole::Impl::persist_static_delay() const {
    if (this->persistence) {
        if (this->persistence->save_static_delay(this->static_delay_ms)) {
            SS_LOGD(TAG, "Persisted static delay: %u ms", this->static_delay_ms);
        } else {
            SS_LOGW(TAG, "Failed to persist static delay");
        }
    }
}

}  // namespace sendspin
