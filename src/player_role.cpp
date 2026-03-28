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

#include "sendspin/player_role.h"

#include "client_bridge.h"
#include "platform/base64.h"
#include "platform/logging.h"
#include "sync_task.h"
#include "sync_time_provider.h"

#include <mutex>

static const char* const TAG = "sendspin.player";

namespace sendspin {

// --- Helpers ---

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

// --- Constructor / Destructor ---

PlayerRole::PlayerRole(Config config, AudioSink* sink)
    : config_(std::move(config)), sync_task_(std::make_unique<SyncTask>()), audio_sink_(sink) {}

PlayerRole::~PlayerRole() {
    // Stop the sync task thread first, before destroying other members.
    // External callbacks (e.g., PortAudio) may still call notify_audio_played() on another thread,
    // so the sync task must be stopped while it's still valid.
    this->sync_task_.reset();
}

// --- Public API ---

void PlayerRole::set_audio_sink(AudioSink* sink) {
    this->audio_sink_ = sink;

    if (sink != nullptr && !this->config_.audio_formats.empty() &&
        !this->sync_task_->is_initialized()) {
        SS_LOGI(TAG, "Initializing sync task (buffer: %zu bytes, formats: %zu)",
                this->config_.audio_buffer_capacity, this->config_.audio_formats.size());
        if (!this->sync_task_->init(this->make_sync_time_provider_(), sink,
                                    this->config_.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
        } else if (!this->sync_task_->start(false)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
        }
    } else if (sink != nullptr && !this->sync_task_->is_initialized()) {
        SS_LOGW(TAG, "Audio sink set but no audio formats configured (%zu formats)",
                this->config_.audio_formats.size());
    }
}

void PlayerRole::notify_audio_played(uint32_t frames, int64_t timestamp) {
    if (this->sync_task_ && this->sync_task_->is_running()) {
        this->sync_task_->notify_audio_played(frames, timestamp);
    }
}

bool PlayerRole::write_audio_chunk(const uint8_t* data, size_t size, int64_t timestamp,
                                   ChunkType type, uint32_t timeout_ms) {
    return this->sync_task_->write_audio_chunk(data, size, timestamp, type, timeout_ms);
}

void PlayerRole::update_volume(uint8_t volume) {
    this->volume_ = volume;
    if (this->bridge_) {
        this->bridge_->publish_state();
    }
}

void PlayerRole::update_muted(bool muted) {
    this->muted_ = muted;
    if (this->bridge_) {
        this->bridge_->publish_state();
    }
}

void PlayerRole::update_static_delay(uint16_t delay_ms) {
    if (delay_ms > 5000) {
        delay_ms = 5000;
    }
    this->static_delay_ms_ = delay_ms;
    this->persist_static_delay_();
    if (this->bridge_) {
        this->bridge_->publish_state();
    }
}

void PlayerRole::set_static_delay_adjustable(bool adjustable) {
    this->static_delay_adjustable_ = adjustable;
    if (this->bridge_) {
        this->bridge_->publish_state();
    }
}

// --- Private integration methods ---

void PlayerRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

bool PlayerRole::start(bool psram_stack) {
    this->load_static_delay_();

    if (!this->config_.audio_formats.empty() && this->audio_sink_ != nullptr &&
        !this->sync_task_->is_initialized()) {
        if (!this->sync_task_->init(this->make_sync_time_provider_(), this->audio_sink_,
                                    this->config_.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
            return false;
        }
        if (!this->sync_task_->start(psram_stack)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
            return false;
        }
    }
    return true;
}

void PlayerRole::contribute_hello(ClientHelloMessage& msg) {
    if (this->config_.audio_formats.empty()) {
        return;
    }

    msg.supported_roles.push_back(SendspinRole::PLAYER);

    // Advertise 80% of the buffer capacity to account for ring buffer metadata overhead
    // and rapid stop/start scenarios
    PlayerSupportObject player_support = {
        .supported_formats = this->config_.audio_formats,
        .buffer_capacity = this->config_.audio_buffer_capacity * 4 / 5,
        .supported_commands = {SendspinPlayerCommand::VOLUME, SendspinPlayerCommand::MUTE},
    };
    msg.player_v1_support = player_support;
}

void PlayerRole::contribute_state(ClientStateMessage& msg) {
    if (this->config_.audio_formats.empty()) {
        return;
    }

    ClientPlayerStateObject player_state;
    player_state.volume = this->volume_;
    player_state.muted = this->muted_;
    player_state.static_delay_ms = this->static_delay_ms_;
    if (this->static_delay_adjustable_) {
        player_state.supported_commands = {SendspinPlayerCommand::SET_STATIC_DELAY};
    }
    msg.player = player_state;
}

void PlayerRole::handle_binary(const uint8_t* data, size_t len, int64_t timestamp) {
    if (!this->config_.audio_formats.empty()) {
        if (!this->send_audio_chunk_(data, len, timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
            SS_LOGW(TAG, "Failed to send audio chunk");
        }
    }
}

void PlayerRole::handle_stream_start(const StreamStartMessage& stream_msg) {
    if (this->config_.audio_formats.empty()) {
        // No audio formats, just defer stream start callback
        std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
        this->pending_stream_callback_events_.push_back(
            StreamCallbackEvent{StreamCallbackType::STREAM_START});
        return;
    }

    // Request high-performance networking for playback
    if (!this->high_performance_requested_for_playback_) {
        this->bridge_->request_high_performance();
        this->high_performance_requested_for_playback_ = true;
    }

    if (stream_msg.player.has_value()) {
        const ServerPlayerStreamObject& player_obj = stream_msg.player.value();

        if (!player_obj.bit_depth.has_value() || !player_obj.channels.has_value() ||
            !player_obj.sample_rate.has_value() || !player_obj.codec.has_value()) {
            SS_LOGE(TAG, "Stream start message missing required audio parameters");
            return;
        }

        auto codec = player_obj.codec.value();
        bool header_sent = false;

        if ((codec == SendspinCodecFormat::PCM) || (codec == SendspinCodecFormat::OPUS)) {
            DummyHeader header;
            header.sample_rate = player_obj.sample_rate.value();
            header.bits_per_sample = player_obj.bit_depth.value();
            header.channels = player_obj.channels.value();

            ChunkType chunk_type = (codec == SendspinCodecFormat::PCM)
                                       ? CHUNK_TYPE_PCM_DUMMY_HEADER
                                       : CHUNK_TYPE_OPUS_DUMMY_HEADER;

            header_sent = this->send_audio_chunk_(reinterpret_cast<const uint8_t*>(&header),
                                                  sizeof(DummyHeader), 0, chunk_type, 100);
        } else if (codec == SendspinCodecFormat::FLAC) {
            if (!player_obj.codec_header.has_value()) {
                SS_LOGE(TAG, "FLAC codec header missing");
                return;
            }
            std::vector<uint8_t> flac_header = base64_decode(player_obj.codec_header.value());
            header_sent = this->send_audio_chunk_(flac_header.data(), flac_header.size(), 0,
                                                  CHUNK_TYPE_FLAC_HEADER, 100);
        }

        if (!header_sent) {
            SS_LOGE(TAG, "Failed to send codec header");
            this->sync_task_->signal_stream_end();
            std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
            this->pending_stream_callback_events_.push_back(
                StreamCallbackEvent{StreamCallbackType::STREAM_END});
            return;
        }

        // Defer stream params update and callback to loop()
        {
            std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
            StreamCallbackEvent event{StreamCallbackType::STREAM_START};
            event.player_stream = player_obj;
            this->pending_stream_callback_events_.push_back(std::move(event));
        }
    } else {
        // No player in stream start -- sync task is already running (idle)
        {
            std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
            this->pending_stream_callback_events_.push_back(
                StreamCallbackEvent{StreamCallbackType::STREAM_START});
        }
    }
}

void PlayerRole::handle_stream_end() {
    this->sync_task_->signal_stream_end();
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_stream_callback_events_.push_back(
        StreamCallbackEvent{StreamCallbackType::STREAM_END});
}

void PlayerRole::handle_stream_clear() {
    this->sync_task_->signal_stream_clear();
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_stream_callback_events_.push_back(
        StreamCallbackEvent{StreamCallbackType::STREAM_CLEAR});
}

void PlayerRole::handle_server_command(const ServerCommandMessage& cmd) {
    if (!cmd.player.has_value()) {
        SS_LOGV(TAG, "Server command has no player commands");
        return;
    }
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_command_events_.push_back({cmd});
}

void PlayerRole::drain_events(std::vector<StreamCallbackEvent>& stream_events,
                              std::vector<ServerCommandEvent>& command_events) {
    // --- Server command events (volume, mute, static delay) ---
    for (const auto& cmd_event : command_events) {
        const auto& cmd_msg = cmd_event.command;
        if (!cmd_msg.player.has_value()) {
            continue;
        }

        const ServerPlayerCommandObject& player_cmd = cmd_msg.player.value();

        if (player_cmd.command == SendspinPlayerCommand::VOLUME && player_cmd.volume.has_value()) {
            this->update_volume(player_cmd.volume.value());
            if (this->on_volume_changed) {
                this->on_volume_changed(player_cmd.volume.value());
            }
        }

        if (player_cmd.command == SendspinPlayerCommand::MUTE && player_cmd.mute.has_value()) {
            this->update_muted(player_cmd.mute.value());
            if (this->on_mute_changed) {
                this->on_mute_changed(player_cmd.mute.value());
            }
        }

        if (player_cmd.command == SendspinPlayerCommand::SET_STATIC_DELAY &&
            player_cmd.static_delay_ms.has_value()) {
            this->update_static_delay(player_cmd.static_delay_ms.value());
            if (this->on_static_delay_changed) {
                this->on_static_delay_changed(player_cmd.static_delay_ms.value());
            }
        }
    }

    // --- Stream lifecycle callback events ---
    for (auto& stream_event : stream_events) {
        this->awaiting_sync_idle_events_.push_back(std::move(stream_event));
    }

    // --- Process awaiting sync idle events ---
    if (!this->awaiting_sync_idle_events_.empty()) {
        bool sync_idle = !this->sync_task_->is_running();
        size_t processed = 0;

        for (auto& event : this->awaiting_sync_idle_events_) {
            if ((event.type == StreamCallbackType::STREAM_END ||
                 event.type == StreamCallbackType::STREAM_CLEAR) &&
                !sync_idle) {
                break;  // Wait for sync task to go idle before firing this and anything after it
            }

            switch (event.type) {
                case StreamCallbackType::STREAM_END:
                    if (this->on_stream_end) {
                        this->on_stream_end();
                    }
                    if (this->high_performance_requested_for_playback_) {
                        this->bridge_->release_high_performance();
                        this->high_performance_requested_for_playback_ = false;
                    }
                    break;
                case StreamCallbackType::STREAM_CLEAR:
                    if (this->on_stream_clear) {
                        this->on_stream_clear();
                    }
                    break;
                case StreamCallbackType::STREAM_START:
                    if (event.player_stream.has_value()) {
                        this->current_stream_params_ = std::move(event.player_stream.value());
                    }
                    if (this->on_stream_start) {
                        this->on_stream_start();
                    }
                    this->sync_task_->signal_stream_start();
                    break;
            }
            ++processed;
        }

        if (processed > 0) {
            this->awaiting_sync_idle_events_.erase(
                this->awaiting_sync_idle_events_.begin(),
                this->awaiting_sync_idle_events_.begin() + static_cast<ptrdiff_t>(processed));
        }
    }
}

void PlayerRole::cleanup() {
    // Clear all buffered audio immediately
    this->sync_task_->signal_stream_clear();

    {
        std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);

        // Discard stale events from the dead connection
        this->pending_stream_callback_events_.clear();
        this->pending_command_events_.clear();
        this->pending_state_events_.clear();

        // Enqueue a clean STREAM_END — drain_events() will fire the callback
        this->pending_stream_callback_events_.push_back(
            StreamCallbackEvent{StreamCallbackType::STREAM_END});
    }

    // Clear awaiting events too (main-thread only, no mutex needed)
    this->awaiting_sync_idle_events_.clear();

    if (this->high_performance_requested_for_playback_) {
        this->bridge_->release_high_performance();
        this->high_performance_requested_for_playback_ = false;
    }
}

// --- Helpers ---

bool PlayerRole::send_audio_chunk_(const uint8_t* data, size_t data_size, int64_t timestamp,
                                   ChunkType chunk_type, uint32_t timeout_ms) {
    if (data == nullptr || data_size == 0) {
        SS_LOGE(TAG, "Invalid data passed to send_audio_chunk_");
        return false;
    }

    return this->sync_task_->write_audio_chunk(data, data_size, timestamp, chunk_type, timeout_ms);
}

SyncTimeProvider PlayerRole::make_sync_time_provider_() {
    return SyncTimeProvider{
        .get_client_time =
            [this](int64_t server_time) { return this->bridge_->get_client_time(server_time); },
        .is_time_synced = [this]() { return this->bridge_->is_time_synced(); },
        .get_static_delay_ms = [this]() { return this->get_static_delay_ms(); },
        .get_fixed_delay_us = [this]() { return this->get_fixed_delay_us(); },
        .update_state =
            [this](SendspinClientState state) {
                std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
                this->pending_state_events_.push_back(state);
            },
    };
}

void PlayerRole::load_static_delay_() {
    if (!this->load_static_delay) {
        // No persistence callback - use initial value from config
        if (this->config_.initial_static_delay_ms > 0) {
            this->static_delay_ms_ = this->config_.initial_static_delay_ms;
            SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms_);
        }
        return;
    }

    auto delay = this->load_static_delay();
    if (delay.has_value()) {
        if (delay.value() <= 5000) {
            this->static_delay_ms_ = delay.value();
            SS_LOGI(TAG, "Loaded static delay: %u ms", this->static_delay_ms_);
        } else {
            SS_LOGW(TAG, "Persisted static delay out of range (%u), ignoring", delay.value());
        }
    } else if (this->config_.initial_static_delay_ms > 0) {
        this->static_delay_ms_ = this->config_.initial_static_delay_ms;
        SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms_);
    }
}

void PlayerRole::persist_static_delay_() {
    if (this->save_static_delay) {
        if (this->save_static_delay(this->static_delay_ms_)) {
            SS_LOGD(TAG, "Persisted static delay: %u ms", this->static_delay_ms_);
        } else {
            SS_LOGW(TAG, "Failed to persist static delay");
        }
    }
}

}  // namespace sendspin
