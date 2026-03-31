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

/// @file player_role.h
/// @brief Audio streaming role that decodes and synchronizes playback via a listener callback

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

/// @brief Audio chunk type tag used internally between components
///
/// Not part of the protocol specification.
enum ChunkType : uint8_t {
    CHUNK_TYPE_ENCODED_AUDIO = 0,  // Raw encoded audio data
    CHUNK_TYPE_DECODED_AUDIO,      // Already-decoded PCM frames
    CHUNK_TYPE_PCM_DUMMY_HEADER,   // Synthetic header for PCM streams
    CHUNK_TYPE_OPUS_DUMMY_HEADER,  // Synthetic header for Opus streams
    CHUNK_TYPE_FLAC_HEADER,        // FLAC stream header block
};

/// @brief Synthetic codec header for PCM and Opus streams that lack a real header block
struct DummyHeader {
    uint32_t sample_rate;
    uint8_t bits_per_sample;
    uint8_t channels;
};

/// @brief Audio codec format for a player stream
enum class SendspinCodecFormat {
    FLAC,         // FLAC lossless audio
    OPUS,         // Opus compressed audio
    PCM,          // Raw PCM audio
    UNSUPPORTED,  // Codec not recognized
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

/// @brief One supported audio format entry advertised by the player in the hello message
struct AudioSupportedFormatObject {
    SendspinCodecFormat codec;
    uint8_t channels;
    uint32_t sample_rate;
    uint8_t bit_depth;
};

/// @brief Command types the server can send to the player role
enum class SendspinPlayerCommand {
    VOLUME,            // Set playback volume
    MUTE,              // Set mute state
    SET_STATIC_DELAY,  // Set static playback delay
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

/// @brief Player capabilities advertised to the server during the hello handshake
struct PlayerSupportObject {
    std::vector<AudioSupportedFormatObject> supported_formats;
    size_t buffer_capacity;
    std::vector<SendspinPlayerCommand> supported_commands;
};

/// @brief Player state reported by the client to the server in client/state messages
struct ClientPlayerStateObject {
    uint8_t volume;
    bool muted;
    uint16_t static_delay_ms;
    std::vector<SendspinPlayerCommand> supported_commands;
};

/// @brief Stream parameters sent by the server in stream/start messages
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

/// @brief A single player command sent by the server, with optional parameter fields
struct ServerPlayerCommandObject {
    SendspinPlayerCommand command;
    std::optional<uint8_t> volume;
    std::optional<bool> mute;
    std::optional<uint16_t> static_delay_ms;
};

/// @brief Parsed server/command message envelope, containing per-role command objects
struct ServerCommandMessage {
    std::optional<ServerPlayerCommandObject> player;
};

/// @brief Listener for player role events
///
/// on_audio_write() is called from the sync task's background thread and must be thread-safe.
/// All other methods fire on the main loop thread.
class PlayerRoleListener {
public:
    virtual ~PlayerRoleListener() = default;

    /// @brief Writes decoded PCM audio to the platform's audio output
    ///
    /// Called from the sync task's background thread. May block up to timeout_ms.
    /// @param data Pointer to the decoded PCM audio data
    /// @param length Number of bytes to write
    /// @param timeout_ms Maximum time to wait for the write to complete
    /// @return Number of bytes actually written
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

/**
 * @brief Audio streaming role that decodes and synchronizes playback to server timestamps
 *
 * Owns a SyncTask that runs on a background thread. Encoded audio chunks arrive from the
 * WebSocket network thread, are written into an audio ring buffer, then decoded and
 * scheduled for output against the server clock via the time filter. Decoded PCM frames
 * are delivered to the platform through the PlayerRoleListener::on_audio_write() callback.
 *
 * Usage:
 * 1. Implement PlayerRoleListener with at minimum on_audio_write()
 * 2. Add the role to the client via SendspinClient::add_player()
 * 3. Call set_listener() with your listener implementation
 * 4. Call notify_audio_played() from the audio output to report consumed frames
 *
 * @code
 * struct MyPlayerListener : PlayerRoleListener {
 *     size_t on_audio_write(uint8_t* data, size_t len, uint32_t timeout_ms) override {
 *         return audio_output.write(data, len, timeout_ms);
 *     }
 *     void on_stream_start() override { audio_output.prepare(); }
 * };
 *
 * MyPlayerListener listener;
 * PlayerRole::Config config;
 * config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
 * auto& player = client.add_player(config);
 * player.set_listener(&listener);
 * @endcode
 */
class PlayerRole {
    friend class SendspinClient;
    friend class SyncTask;

public:
    /// @brief Configuration for the player role
    struct Config {
        std::vector<AudioSupportedFormatObject> audio_formats;
        size_t audio_buffer_capacity{1000000};
        int32_t fixed_delay_us{0};
        uint16_t initial_static_delay_ms{0};
    };

    PlayerRole(Config config, SendspinClient* client, SendspinPersistenceProvider* persistence);
    ~PlayerRole();

    /// @brief Sets the listener for player events
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(PlayerRoleListener* listener) {
        this->listener_ = listener;
    }

    // ========================================
    // Audio
    // ========================================

    /// @brief Called by the audio output when it has played audio frames. Thread-safe.
    /// @param frames Number of audio frames played
    /// @param timestamp Server timestamp corresponding to the played position
    void notify_audio_played(uint32_t frames, int64_t timestamp);

    /// @brief Writes an audio chunk to the sync task's ring buffer.
    /// @param data Pointer to encoded audio data
    /// @param size Size of the encoded data in bytes
    /// @param timestamp Server timestamp for this chunk
    /// @param type Codec type for this chunk
    /// @param timeout_ms Maximum time to wait for ring buffer space
    /// @return true if the chunk was written, false on timeout or error
    bool write_audio_chunk(const uint8_t* data, size_t size, int64_t timestamp, ChunkType type,
                           uint32_t timeout_ms);

    // ========================================
    // State updates
    // ========================================

    /// @brief Updates the volume and publishes client state to the server.
    /// @param volume New volume level
    void update_volume(uint8_t volume);

    /// @brief Updates the mute state and publishes client state to the server.
    /// @param muted true to mute, false to unmute
    void update_muted(bool muted);

    /// @brief Updates the static delay and publishes client state to the server.
    /// @param delay_ms Static delay in milliseconds
    void update_static_delay(uint16_t delay_ms);

    /// @brief Enables or disables the static delay adjustment command.
    /// @param adjustable true if the delay can be adjusted at runtime
    void set_static_delay_adjustable(bool adjustable);

    // ========================================
    // Queries
    // ========================================

    /// @brief Returns the audio buffer capacity from config.
    /// @return Audio ring buffer capacity in bytes.
    size_t get_buffer_size() const {
        return this->config_.audio_buffer_capacity;
    }

    /// @brief Returns a reference to the current stream parameters
    /// @return Const reference to the active stream parameters.
    const ServerPlayerStreamObject& get_current_stream_params() const {
        return this->current_stream_params_;
    }

    /// @brief Returns the fixed delay in microseconds (from config)
    /// @return Fixed pipeline delay in microseconds.
    int32_t get_fixed_delay_us() const {
        return this->config_.fixed_delay_us;
    }

    /// @brief Returns true if currently muted
    /// @return true if muted, false otherwise.
    bool get_muted() const {
        return this->muted_;
    }

    /// @brief Returns the current static delay in milliseconds
    /// @return Static playback delay in milliseconds.
    uint16_t get_static_delay_ms() const {
        return this->static_delay_ms_;
    }

    /// @brief Returns the current volume level
    /// @return Current volume level (0-255).
    uint8_t get_volume() const {
        return this->volume_;
    }

private:
    // ========================================
    // Deferred event types
    // ========================================

    /// @brief Deferred stream lifecycle callback types queued from the network thread
    enum class StreamCallbackType : uint8_t {
        STREAM_START,  // New stream is starting
        STREAM_END,    // Stream ended normally
        STREAM_CLEAR,  // Stream cleared immediately
    };

    // ========================================
    // Private integration methods
    // ========================================

    /// @brief Starts the player role and registers it with the client
    bool start(bool psram_stack);
    /// @brief Adds player role information to the outgoing hello message
    void build_hello_fields(ClientHelloMessage& msg);
    /// @brief Adds the current player state fields to an outgoing state message
    void build_state_fields(ClientStateMessage& msg);
    /// @brief Handles an incoming binary audio chunk from the server
    void handle_binary(const uint8_t* data, size_t len);
    /// @brief Handles a stream-start message from the server
    void handle_stream_start(const StreamStartMessage& stream_msg);
    /// @brief Handles a stream-end message from the server
    void handle_stream_end();
    /// @brief Handles a stream-clear message from the server
    void handle_stream_clear();
    /// @brief Handles an incoming server command message
    void handle_server_command(const ServerCommandMessage& cmd);
    /// @brief Delivers pending stream lifecycle events to the listener
    void drain_events();
    /// @brief Cleans up player state when the connection is lost
    void cleanup();

    // ========================================
    // Helpers
    // ========================================

    /// @brief Sends an audio chunk to the sync task ring buffer
    bool send_audio_chunk_(const uint8_t* data, size_t data_size, int64_t timestamp,
                           ChunkType chunk_type, uint32_t timeout_ms);
    /// @brief Enqueues a state change for delivery on the main thread
    void enqueue_state_update_(SendspinClientState state);
    /// @brief Loads the static delay preference from persistent storage
    void load_static_delay_();
    /// @brief Persists the current static delay to storage
    void persist_static_delay_();

    // Struct fields
    Config config_;
    ServerPlayerStreamObject current_stream_params_{};
    std::vector<StreamCallbackType> awaiting_sync_idle_events_;
    struct EventState;

    // Pointer fields
    SendspinClient* client_;
    std::unique_ptr<EventState> event_state_;
    PlayerRoleListener* listener_{nullptr};
    SendspinPersistenceProvider* persistence_;
    std::unique_ptr<SyncTask> sync_task_;

    // 16-bit fields
    uint16_t static_delay_ms_{0};

    // 8-bit fields
    bool high_performance_requested_for_playback_{false};
    bool muted_{false};
    bool static_delay_adjustable_{false};
    uint8_t volume_{0};
};

}  // namespace sendspin
