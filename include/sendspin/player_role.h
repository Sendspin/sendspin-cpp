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

#include "sendspin/config.h"
#include "sendspin/types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace sendspin {

class SendspinClient;
class SendspinPersistenceProvider;

// ============================================================================
// Player types
// ============================================================================

/// @brief Command types the server can send to the player role
enum class SendspinPlayerCommand : uint8_t {
    VOLUME,            // Set playback volume
    MUTE,              // Set mute state
    SET_STATIC_DELAY,  // Set static playback delay
};

/// @brief Stream parameters sent by the server in stream/start messages
struct ServerPlayerStreamObject {
    std::optional<SendspinCodecFormat> codec{};
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
    SendspinPlayerCommand command{};
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
/// THREAD SAFETY: on_audio_write() fires on the sync task's background thread.
/// Implementations must be thread-safe for this method. on_stream_start(), on_stream_end(),
/// on_stream_clear(), on_volume_changed(), on_mute_changed(), and on_static_delay_changed()
/// fire on the main loop thread via drain_events(). The listener must outlive the role.
class PlayerRoleListener {
public:
    virtual ~PlayerRoleListener() = default;

    /// @brief Writes decoded PCM audio to the platform's audio output
    ///
    /// Fires on the sync task's background thread. May block up to timeout_ms.
    /// @param data Pointer to the decoded PCM audio data
    /// @param length Number of bytes to write
    /// @param timeout_ms Maximum time to wait for the write to complete
    /// @return Number of bytes actually written
    virtual size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) = 0;

    /// @brief Called when a new audio stream starts. Fires on the main loop thread
    virtual void on_stream_start() {}

    /// @brief Called when the audio stream ends. Fires on the main loop thread
    virtual void on_stream_end() {}

    /// @brief Called when the audio stream is cleared. Fires on the main loop thread
    virtual void on_stream_clear() {}

    /// @brief Called when the volume is changed by the server. Fires on the main loop thread
    virtual void on_volume_changed(uint8_t /*volume*/) {}

    /// @brief Called when the mute state is changed by the server. Fires on the main loop thread
    virtual void on_mute_changed(bool /*muted*/) {}

    /// @brief Called when the static delay is changed by the server. Fires on the main loop thread
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
 * PlayerRoleConfig config;
 * config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
 * auto& player = client.add_player(config);
 * player.set_listener(&listener);
 * @endcode
 */
class PlayerRole {
    friend class SendspinClient;

public:
    struct Impl;

    PlayerRole(PlayerRoleConfig config, SendspinClient* client,
               SendspinPersistenceProvider* persistence);
    ~PlayerRole();

    /// @brief Sets the listener for player events
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(PlayerRoleListener* listener);

    // ========================================
    // Audio
    // ========================================

    /// @brief Called by the audio output when it has played audio frames. Thread-safe.
    /// @param frames Number of audio frames played
    /// @param timestamp Client timestamp in microseconds when the audio will finish playing
    void notify_audio_played(uint32_t frames, int64_t timestamp);

    // ========================================
    // State updates
    // ========================================

    /// @brief Updates the volume and publishes client state to the server.
    /// @param volume New volume level
    void update_volume(uint8_t volume);

    /// @brief Updates the mute state and publishes client state to the server.
    /// @param muted true to mute, false to unmute
    void update_muted(bool muted);

    /// @brief Updates the stored static delay preference and publishes client state to the server.
    ///
    /// The value is always persisted (if a persistence provider is set), independent of
    /// adjustability. If adjustability is currently disabled, the stored value has no
    /// effect on sync timing until adjustability is re-enabled.
    /// @param delay_ms Static delay in milliseconds
    void update_static_delay(uint16_t delay_ms);

    /// @brief Enables or disables the static delay adjustment command.
    ///
    /// When disabled, the stored delay is not applied to audio sync timing and is reported
    /// as 0 in client state, per the Sendspin spec (a delay that is not exposed as a knob
    /// must not be applied). The stored value is preserved and takes effect again if
    /// adjustability is re-enabled.
    /// @param adjustable true if the delay can be adjusted at runtime
    void set_static_delay_adjustable(bool adjustable);

    // ========================================
    // Queries
    // ========================================

    /// @brief Returns a reference to the current stream parameters
    /// @return Const reference to the active stream parameters.
    const ServerPlayerStreamObject& get_current_stream_params() const;

    /// @brief Returns the fixed delay in microseconds (from config)
    /// @return Fixed pipeline delay in microseconds.
    int32_t get_fixed_delay_us() const;

    /// @brief Returns true if currently muted
    /// @return true if muted, false otherwise.
    bool get_muted() const;

    /// @brief Returns the effective static delay in milliseconds
    /// @return Static playback delay in milliseconds, or 0 if the delay is not adjustable.
    uint16_t get_static_delay_ms() const;

    /// @brief Returns the current volume level
    /// @return Current volume level (0-255).
    uint8_t get_volume() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
