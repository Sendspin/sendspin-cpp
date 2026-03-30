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

#include "platform/base64.h"
#include "platform/logging.h"
#include "platform/shadow_slot.h"
#include "platform/thread_safe_queue.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "sync_task.h"

static const char* const TAG = "sendspin.player";

/// @brief Size of the big-endian 64-bit timestamp at the start of player binary messages.
static const size_t BINARY_TIMESTAMP_SIZE = 8;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

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

// --- Event state (PIMPL) ---

/// @brief PIMPL event state: queues and shadow slots used to pass data from background threads
/// (network thread and sync task thread) to the main loop thread for the player role
struct PlayerRole::EventState {
    ThreadSafeQueue<PlayerRole::StreamCallbackType> stream_queue;
    ThreadSafeQueue<SendspinClientState> state_queue;
    ShadowSlot<ServerPlayerStreamObject> shadow_stream_params;
    ShadowSlot<ServerCommandMessage> shadow_command;
};

// --- Constructor / Destructor ---

PlayerRole::PlayerRole(Config config, SendspinClient* client,
                       SendspinPersistenceProvider* persistence)
    : config_(std::move(config)),
      persistence_(persistence),
      client_(client),
      sync_task_(std::make_unique<SyncTask>()),
      event_state_(std::make_unique<EventState>()) {
    this->event_state_->stream_queue.create(8);
    this->event_state_->state_queue.create(4);
}

PlayerRole::~PlayerRole() {
    // Stop the sync task thread first, before destroying other members.
    // External callbacks (e.g., PortAudio) may still call notify_audio_played() on another thread,
    // so the sync task must be stopped while it's still valid.
    this->sync_task_.reset();
}

// --- Public API ---

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
    this->client_->publish_state();
}

void PlayerRole::update_muted(bool muted) {
    this->muted_ = muted;
    this->client_->publish_state();
}

void PlayerRole::update_static_delay(uint16_t delay_ms) {
    if (delay_ms > 5000) {
        delay_ms = 5000;
    }
    this->static_delay_ms_ = delay_ms;
    this->persist_static_delay_();
    this->client_->publish_state();
}

void PlayerRole::set_static_delay_adjustable(bool adjustable) {
    this->static_delay_adjustable_ = adjustable;
    this->client_->publish_state();
}

// --- Private integration methods ---

bool PlayerRole::start(bool psram_stack) {
    this->load_static_delay_();

    if (!this->config_.audio_formats.empty() && this->listener_ &&
        !this->sync_task_->is_initialized()) {
        if (!this->sync_task_->init(this, this->client_, this->config_.audio_buffer_capacity)) {
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

void PlayerRole::handle_binary(const uint8_t* data, size_t len) {
    if (this->config_.audio_formats.empty()) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }
    int64_t timestamp = be64_to_host(data);
    if (!this->send_audio_chunk_(data + BINARY_TIMESTAMP_SIZE, len - BINARY_TIMESTAMP_SIZE,
                                 timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
        SS_LOGW(TAG, "Failed to send audio chunk");
    }
}

void PlayerRole::handle_stream_start(const StreamStartMessage& stream_msg) {
    if (this->config_.audio_formats.empty()) {
        // No audio formats, just defer stream start callback
        this->event_state_->stream_queue.send(StreamCallbackType::STREAM_START, 0);
        return;
    }

    // Request high-performance networking for playback
    if (!this->high_performance_requested_for_playback_) {
        this->client_->acquire_high_performance();
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
            this->event_state_->stream_queue.send(StreamCallbackType::STREAM_END, 0);
            return;
        }

        // Shadow stream params for main thread, then signal
        this->event_state_->shadow_stream_params.write(player_obj);
        this->event_state_->stream_queue.send(StreamCallbackType::STREAM_START, 0);
    } else {
        // No player in stream start -- sync task is already running (idle)
        this->event_state_->stream_queue.send(StreamCallbackType::STREAM_START, 0);
    }
}

void PlayerRole::handle_stream_end() {
    this->sync_task_->signal_stream_end();
    this->event_state_->stream_queue.send(StreamCallbackType::STREAM_END, 0);
}

void PlayerRole::handle_stream_clear() {
    this->sync_task_->signal_stream_clear();
    this->event_state_->stream_queue.send(StreamCallbackType::STREAM_CLEAR, 0);
}

void PlayerRole::handle_server_command(const ServerCommandMessage& cmd) {
    if (!cmd.player.has_value()) {
        SS_LOGV(TAG, "Server command has no player commands");
        return;
    }
    this->event_state_->shadow_command.merge(
        [](ServerCommandMessage& current, ServerCommandMessage&& delta) {
            if (!delta.player.has_value()) {
                return;
            }
            if (!current.player.has_value()) {
                current.player = std::move(delta.player);
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

void PlayerRole::drain_events() {
    // --- Client state events (from sync task) ---
    SendspinClientState state;
    SendspinClientState last_state{};
    bool has_state = false;
    while (this->event_state_->state_queue.receive(state, 0)) {
        last_state = state;
        has_state = true;
    }
    if (has_state) {
        this->client_->update_state(last_state);
    }

    // --- Server command events (volume, mute, static delay) ---
    // Check each field independently since multiple command types may have been
    // merged into one shadow slot between drain ticks.
    ServerCommandMessage cmd_msg;
    if (this->event_state_->shadow_command.take(cmd_msg)) {
        if (cmd_msg.player.has_value()) {
            const ServerPlayerCommandObject& player_cmd = cmd_msg.player.value();

            if (player_cmd.volume.has_value()) {
                this->update_volume(player_cmd.volume.value());
                if (this->listener_) {
                    this->listener_->on_volume_changed(player_cmd.volume.value());
                }
            }

            if (player_cmd.mute.has_value()) {
                this->update_muted(player_cmd.mute.value());
                if (this->listener_) {
                    this->listener_->on_mute_changed(player_cmd.mute.value());
                }
            }

            if (player_cmd.static_delay_ms.has_value()) {
                this->update_static_delay(player_cmd.static_delay_ms.value());
                if (this->listener_) {
                    this->listener_->on_static_delay_changed(player_cmd.static_delay_ms.value());
                }
            }
        }
    }

    // --- Stream lifecycle callback events ---
    StreamCallbackType stream_event;
    while (this->event_state_->stream_queue.receive(stream_event, 0)) {
        this->awaiting_sync_idle_events_.push_back(stream_event);
    }

    // --- Process awaiting sync idle events ---
    if (!this->awaiting_sync_idle_events_.empty()) {
        bool sync_idle = !this->sync_task_->is_running();
        size_t processed = 0;

        for (auto& event : this->awaiting_sync_idle_events_) {
            if ((event == StreamCallbackType::STREAM_END ||
                 event == StreamCallbackType::STREAM_CLEAR) &&
                !sync_idle) {
                break;  // Wait for sync task to go idle before firing this and anything after it
            }

            switch (event) {
                case StreamCallbackType::STREAM_END:
                    if (this->listener_) {
                        this->listener_->on_stream_end();
                    }
                    if (this->high_performance_requested_for_playback_) {
                        this->client_->release_high_performance();
                        this->high_performance_requested_for_playback_ = false;
                    }
                    break;
                case StreamCallbackType::STREAM_CLEAR:
                    if (this->listener_) {
                        this->listener_->on_stream_clear();
                    }
                    break;
                case StreamCallbackType::STREAM_START: {
                    ServerPlayerStreamObject stream_params;
                    if (this->event_state_->shadow_stream_params.take(stream_params)) {
                        this->current_stream_params_ = std::move(stream_params);
                    }
                    if (this->listener_) {
                        this->listener_->on_stream_start();
                    }
                    this->sync_task_->signal_stream_start();
                    break;
                }
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

    // Discard stale events from the dead connection
    this->event_state_->stream_queue.reset();
    this->event_state_->state_queue.reset();
    this->event_state_->shadow_stream_params.reset();
    this->event_state_->shadow_command.reset();

    // Enqueue a clean STREAM_END — drain_events() will fire the callback
    this->event_state_->stream_queue.send(StreamCallbackType::STREAM_END, 0);

    // Clear awaiting events too (main-thread only, no mutex needed)
    this->awaiting_sync_idle_events_.clear();

    if (this->high_performance_requested_for_playback_) {
        this->client_->release_high_performance();
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

void PlayerRole::enqueue_state_update_(SendspinClientState state) {
    this->event_state_->state_queue.send(state, 0);
}

void PlayerRole::load_static_delay_() {
    if (!this->persistence_) {
        // No persistence provider - use initial value from config
        if (this->config_.initial_static_delay_ms > 0) {
            this->static_delay_ms_ = this->config_.initial_static_delay_ms;
            SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms_);
        }
        return;
    }

    auto delay = this->persistence_->load_static_delay();
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
    if (this->persistence_) {
        if (this->persistence_->save_static_delay(this->static_delay_ms_)) {
            SS_LOGD(TAG, "Persisted static delay: %u ms", this->static_delay_ms_);
        } else {
            SS_LOGW(TAG, "Failed to persist static delay");
        }
    }
}

}  // namespace sendspin
