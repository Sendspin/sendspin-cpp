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

#pragma once

#include "sendspin/types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinClient;
class SendspinPersistenceProvider;
class SyncTask;
struct ClientHelloMessage;
struct ClientStateMessage;
struct StreamStartMessage;

// ============================================================================
// Player types
// ============================================================================

// Implementation-specific details not defined in the protocol specification.
// Used internally for audio chunk handling between components.
enum ChunkType : uint8_t {
    CHUNK_TYPE_ENCODED_AUDIO = 0,
    CHUNK_TYPE_DECODED_AUDIO,
    CHUNK_TYPE_PCM_DUMMY_HEADER,
    CHUNK_TYPE_OPUS_DUMMY_HEADER,
    CHUNK_TYPE_FLAC_HEADER,
};

struct DummyHeader {
    uint32_t sample_rate;
    uint8_t bits_per_sample;
    uint8_t channels;
};

enum class SendspinCodecFormat {
    FLAC,
    OPUS,
    PCM,
    UNSUPPORTED,
};

inline const char* to_cstr(SendspinCodecFormat format) {
    switch (format) {
        case SendspinCodecFormat::FLAC:
            return "flac";
        case SendspinCodecFormat::OPUS:
            return "opus";
        case SendspinCodecFormat::PCM:
            return "pcm";
        default:
            return "unsupported";
    }
}

inline std::optional<SendspinCodecFormat> codec_format_from_string(const std::string& str) {
    if (str == "flac")
        return SendspinCodecFormat::FLAC;
    if (str == "opus")
        return SendspinCodecFormat::OPUS;
    if (str == "pcm")
        return SendspinCodecFormat::PCM;
    return std::nullopt;
}

struct AudioSupportedFormatObject {
    SendspinCodecFormat codec;
    uint8_t channels;
    uint32_t sample_rate;
    uint8_t bit_depth;
};

enum class SendspinPlayerCommand {
    VOLUME,
    MUTE,
    SET_STATIC_DELAY,
};

inline const char* to_cstr(SendspinPlayerCommand cmd) {
    switch (cmd) {
        case SendspinPlayerCommand::VOLUME:
            return "volume";
        case SendspinPlayerCommand::MUTE:
            return "mute";
        case SendspinPlayerCommand::SET_STATIC_DELAY:
            return "set_static_delay";
        default:
            return "unknown";
    }
}

inline std::optional<SendspinPlayerCommand> player_command_from_string(const std::string& str) {
    if (str == "volume")
        return SendspinPlayerCommand::VOLUME;
    if (str == "mute")
        return SendspinPlayerCommand::MUTE;
    if (str == "set_static_delay")
        return SendspinPlayerCommand::SET_STATIC_DELAY;
    return std::nullopt;
}

struct PlayerSupportObject {
    std::vector<AudioSupportedFormatObject> supported_formats;
    size_t buffer_capacity;
    std::vector<SendspinPlayerCommand> supported_commands;
};

struct ClientPlayerStateObject {
    uint8_t volume;
    bool muted;
    uint16_t static_delay_ms;
    std::vector<SendspinPlayerCommand> supported_commands;
};

struct ServerPlayerStreamObject {
    std::optional<SendspinCodecFormat> codec;
    std::optional<uint32_t> sample_rate;
    std::optional<uint8_t> channels;
    std::optional<uint8_t> bit_depth;
    std::optional<std::string> codec_header;

    bool is_complete() const {
        return codec.has_value() && sample_rate.has_value() && channels.has_value() &&
               bit_depth.has_value();
    }
};

struct ServerPlayerCommandObject {
    SendspinPlayerCommand command;
    std::optional<uint8_t> volume;
    std::optional<bool> mute;
    std::optional<uint16_t> static_delay_ms;
};

struct ServerCommandMessage {
    std::optional<ServerPlayerCommandObject> player;
};

/// @brief Listener for player role events.
///
/// on_audio_write() is called from the sync task's background thread and must be thread-safe.
/// All other methods fire on the main loop thread.
class PlayerRoleListener {
public:
    virtual ~PlayerRoleListener() = default;

    /// @brief Writes decoded PCM audio to the platform's audio output.
    /// Called from the sync task's background thread. May block up to timeout_ms.
    /// Must return the number of bytes actually written.
    virtual size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) = 0;

    /// @brief Called when a new audio stream starts.
    virtual void on_stream_start() {}

    /// @brief Called when the audio stream ends.
    virtual void on_stream_end() {}

    /// @brief Called when the audio stream is cleared.
    virtual void on_stream_clear() {}

    /// @brief Called when the volume is changed by the server.
    virtual void on_volume_changed(uint8_t /*volume*/) {}

    /// @brief Called when the mute state is changed by the server.
    virtual void on_mute_changed(bool /*muted*/) {}

    /// @brief Called when the static delay is changed by the server.
    virtual void on_static_delay_changed(uint16_t /*delay_ms*/) {}
};

/// @brief Player role: owns SyncTask, handles audio playback.
class PlayerRole {
    friend class SendspinClient;
    friend class SyncTask;

public:
    /// @brief Configuration for the player role.
    struct Config {
        std::vector<AudioSupportedFormatObject> audio_formats;
        size_t audio_buffer_capacity{1000000};
        int32_t fixed_delay_us{0};
        uint16_t initial_static_delay_ms{0};
    };

    PlayerRole(Config config, SendspinClient* client, SendspinPersistenceProvider* persistence);
    ~PlayerRole();

    /// @brief Sets the listener for player events. The listener must outlive this role.
    void set_listener(PlayerRoleListener* listener) {
        this->listener_ = listener;
    }

    // --- Audio ---

    /// @brief Called by the audio output when it has played audio frames. Thread-safe.
    void notify_audio_played(uint32_t frames, int64_t timestamp);

    /// @brief Writes an audio chunk to the sync task's ring buffer.
    bool write_audio_chunk(const uint8_t* data, size_t size, int64_t timestamp, ChunkType type,
                           uint32_t timeout_ms);

    // --- State updates ---

    /// @brief Updates the volume and publishes client state to the server.
    void update_volume(uint8_t volume);

    /// @brief Updates the mute state and publishes client state to the server.
    void update_muted(bool muted);

    /// @brief Updates the static delay and publishes client state to the server.
    void update_static_delay(uint16_t delay_ms);

    /// @brief Enables or disables the static delay adjustment command.
    void set_static_delay_adjustable(bool adjustable);

    // --- Queries ---

    /// @brief Returns the current static delay in milliseconds.
    uint16_t get_static_delay_ms() const {
        return this->static_delay_ms_;
    }

    /// @brief Returns the fixed delay in microseconds (from config).
    int32_t get_fixed_delay_us() const {
        return this->config_.fixed_delay_us;
    }

    /// @brief Returns the current volume level.
    uint8_t get_volume() const {
        return this->volume_;
    }

    /// @brief Returns true if currently muted.
    bool get_muted() const {
        return this->muted_;
    }

    /// @brief Returns the audio buffer capacity from config.
    size_t get_buffer_size() const {
        return this->config_.audio_buffer_capacity;
    }

    /// @brief Returns a reference to the current stream parameters.
    const ServerPlayerStreamObject& get_current_stream_params() const {
        return this->current_stream_params_;
    }

private:
    // --- Deferred event types ---

    enum class StreamCallbackType : uint8_t {
        STREAM_START,
        STREAM_END,
        STREAM_CLEAR,
    };

    // --- Private integration methods ---

    bool start(bool psram_stack);
    void contribute_hello(ClientHelloMessage& msg);
    void contribute_state(ClientStateMessage& msg);
    void handle_binary(const uint8_t* data, size_t len);
    void handle_stream_start(const StreamStartMessage& stream_msg);
    void handle_stream_end();
    void handle_stream_clear();
    void handle_server_command(const ServerCommandMessage& cmd);
    void drain_events();
    void cleanup();

    // --- Helpers ---

    bool send_audio_chunk_(const uint8_t* data, size_t data_size, int64_t timestamp,
                           ChunkType chunk_type, uint32_t timeout_ms);
    void enqueue_state_update_(SendspinClientState state);
    void load_static_delay_();
    void persist_static_delay_();

    // --- Configuration ---

    Config config_;

    // --- Listener and client ---

    PlayerRoleListener* listener_{nullptr};
    SendspinPersistenceProvider* persistence_;
    SendspinClient* client_;

    // --- Player state ---

    uint8_t volume_{0};
    bool muted_{false};
    uint16_t static_delay_ms_{0};
    bool static_delay_adjustable_{false};
    bool high_performance_requested_for_playback_{false};
    ServerPlayerStreamObject current_stream_params_{};

    // --- Sync task ---

    std::unique_ptr<SyncTask> sync_task_;

    // --- Event state (PIMPL, hides platform queue/shadow headers) ---

    struct EventState;
    std::unique_ptr<EventState> event_state_;

    // --- Stream end/clear callbacks waiting for sync task to go idle (main thread only) ---

    std::vector<StreamCallbackType> awaiting_sync_idle_events_;
};

}  // namespace sendspin
