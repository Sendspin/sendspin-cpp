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
#include <span>
#include <type_traits>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Player types
// ============================================================================

/// @brief Command types the server can send to the player role
enum class SendspinPlayerCommand : uint8_t {
    VOLUME,            // Set playback volume
    MUTE,              // Set mute state
    SET_OUTPUT_DELAY,  // Set the output delay
};

/// @brief The format of the decoded PCM one PlayerRoleListener::on_audio_output() call carries
struct AudioFormat {
    uint32_t sample_rate{0};
    uint8_t channels{0};
    /// @brief Container depth, 8, 16, 24 or 32 (see the integration guide's PlayerRoleListener)
    uint8_t bits_per_sample{0};

    bool operator==(const AudioFormat&) const = default;
};

static_assert(std::is_trivially_copyable_v<AudioFormat>, "handed to the sink with every write");
static_assert(sizeof(AudioFormat) == 8, "the rate, channels and depth pack into eight bytes");

/// @brief The stream the server's latest stream/start announced (PlayerRole::stream_info())
struct PlayerStreamInfo {
    SendspinCodecFormat codec{};
    uint32_t sample_rate{0};
    uint8_t channels{0};
    /// @brief Bit depth the stream announced; an Opus stream reports the 16 bits it decodes to
    uint8_t bit_depth{0};

    bool operator==(const PlayerStreamInfo&) const = default;
};

static_assert(std::is_trivially_copyable_v<PlayerStreamInfo>, "returned by value");

/// @brief Stream parameters sent by the server in stream/start messages
/// @deprecated Returned only by the deprecated PlayerRole::get_current_stream_params(); removed in
/// v0.11.0.
struct [[deprecated(
    "use PlayerRole::stream_info(); removed in v0.11.0")]] ServerPlayerStreamObject {
    std::optional<SendspinCodecFormat> codec{};
    std::optional<uint32_t> sample_rate;
    std::optional<uint8_t> channels;
    std::optional<uint8_t> bit_depth;

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
    std::optional<uint16_t> output_delay_ms;
};

/// @brief Parsed server/command message envelope, containing per-role command objects
struct ServerCommandMessage {
    std::optional<ServerPlayerCommandObject> player;
};

/// @brief Listener for player role events
///
/// THREAD SAFETY: on_audio_output() fires on the sync task's background thread.
/// Implementations must be thread-safe for this method. on_stream_start(), on_stream_end(),
/// on_volume_changed(), on_mute_changed(), and on_output_delay_changed()
/// fire on the main loop thread via drain_events(). The listener must outlive the role.
class PlayerRoleListener {
public:
    virtual ~PlayerRoleListener() = default;

    /// @brief Writes decoded PCM to the platform's audio output; may block up to timeout_ms.
    /// The layout and the whole-frame rule are in the integration guide's PlayerRoleListener.
    /// @param pcm Decoded PCM, a whole number of frames
    /// @param format The format of exactly these bytes
    /// @param timeout_ms Maximum time to wait for the write to complete
    /// @return Bytes written, a whole number of frames
    virtual size_t on_audio_output(std::span<const uint8_t> pcm, const AudioFormat& format,
                                   uint32_t timeout_ms);

    /// @brief Writes decoded PCM audio; called only by the default on_audio_output()
    /// @deprecated Override on_audio_output(); removed in v0.11.0.
    [[deprecated("override on_audio_output(); removed in v0.11.0")]] virtual size_t on_audio_write(
        uint8_t* /*data*/, size_t /*length*/, uint32_t /*timeout_ms*/) {
        return 0;
    }

    /// @brief Called when a new audio stream starts
    virtual void on_stream_start() {}

    /// @brief Called when the audio stream ends
    ///
    /// Also fires when a server/activate takes the player role out of the session's active roles,
    /// which stops the decode and discards the buffered audio rather than letting it finish.
    virtual void on_stream_end() {}

    /// @brief Called when the volume is changed by the server
    virtual void on_volume_changed(uint8_t /*volume*/) {}

    /// @brief Called when the mute state is changed by the server
    virtual void on_mute_changed(bool /*muted*/) {}

    /// @brief Called when the output delay is changed by the server
    virtual void on_output_delay_changed(uint16_t /*delay_ms*/) {}
};

/**
 * @brief Audio streaming role that decodes and synchronizes playback to server timestamps
 *
 * Owns a SyncTask that runs on a background thread. Encoded audio chunks are received into the
 * client's shared inbound ring, handed to the sync task by the protocol task in place, then
 * decoded and scheduled for output against the server clock via the time filter. Decoded PCM frames
 * are delivered to the platform through the PlayerRoleListener::on_audio_output() callback.
 *
 * Usage:
 * 1. Implement PlayerRoleListener with at minimum on_audio_output()
 * 2. Add the role to the client via SendspinClient::add_player()
 * 3. Call set_listener() with your listener implementation
 * 4. Call notify_audio_played() from the audio output to report consumed frames
 *
 * @code
 * struct MyPlayerListener : PlayerRoleListener {
 *     size_t on_audio_output(std::span<const uint8_t> pcm, const AudioFormat& format,
 *                            uint32_t timeout_ms) override {
 *         return audio_output.write(pcm, format, timeout_ms);
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

    PlayerRole(PlayerRoleConfig config, SendspinClient* client);
    ~PlayerRole();

    /// @brief Sets the listener for player events. Set it before SendspinClient::start() and
    /// leave it in place while the client runs.
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

    /// @brief Updates the volume and publishes client state to the server. Main loop only.
    /// @param volume New volume level, clamped to 0-100
    void update_volume(uint8_t volume);

    /// @brief Updates the mute state and publishes client state to the server. Main loop only.
    /// @param muted true to mute, false to unmute
    void update_muted(bool muted);

    /// @brief Updates the stored output delay preference and publishes client state to the server.
    /// Main loop only.
    ///
    /// The value is always persisted (if a persistence provider is set), independent of
    /// adjustability.
    /// @param delay_ms Output delay in milliseconds, clamped to 5000
    void update_output_delay(uint16_t delay_ms);

    /// @brief Enables or disables the output delay adjustment command. Main loop only.
    ///
    /// When disabled, the stored delay is not applied to audio sync timing, is reported as 0 in
    /// client state, and a server set_output_delay command is ignored. The stored value is
    /// preserved and takes effect again if adjustability is re-enabled.
    /// @param adjustable true if the delay can be adjusted at runtime
    void set_output_delay_adjustable(bool adjustable);

    /// @brief Enables or disables the server's volume command. Main loop only.
    ///
    /// Enabled by default. While disabled, volume is omitted from client state and a server
    /// volume command is ignored; the stored volume is kept.
    /// @param adjustable true if the server may set the volume
    void set_volume_adjustable(bool adjustable);

    /// @brief Enables or disables the server's mute command. Main loop only.
    ///
    /// Enabled by default. While disabled, the mute state is omitted from client state and a
    /// server mute command is ignored; the stored state is kept.
    /// @param adjustable true if the server may set the mute state
    void set_mute_adjustable(bool adjustable);

    // ========================================
    // Queries
    // ========================================

    /// @brief Returns the stream the latest stream/start announced, or nullopt while no stream is
    /// active. For display: each write's own format comes with on_audio_output(). Main loop only.
    [[nodiscard]] std::optional<PlayerStreamInfo> stream_info() const;

    /// @brief Returns a reference to the current stream parameters. Main loop only.
    /// @deprecated Use stream_info(), and each write's format from on_audio_output(); removed in
    /// v0.11.0.
    [[deprecated("use stream_info(); removed in v0.11.0")]] const ServerPlayerStreamObject&
    get_current_stream_params() const;

    /// @brief Returns true if currently muted
    bool get_muted() const;

    /// @brief Returns the effective output delay in milliseconds, or 0 if it is not adjustable
    uint16_t get_output_delay_ms() const;

    /// @brief Returns the current volume level (0-100)
    uint8_t get_volume() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
