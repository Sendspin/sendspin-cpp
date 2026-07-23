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

/// @file announcement_role.h
/// @brief Announcement role that decodes short per-client audio clips (TTS, chimes, alerts)
/// concurrently with the media stream, with ducking hints for the embedder

#pragma once

#include "sendspin/config.h"
#include "sendspin/player_role.h"  // ServerPlayerStreamObject (shared codec-parameter shape)
#include "sendspin/types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Announcement types
// ============================================================================

/// @brief Announcement stream parameters sent by the server in stream/start messages
///
/// The codec parameters share the player stream-object shape; the additional fields carry the
/// per-announcement ducking policy and optional output level.
struct ServerAnnouncementStreamObject {
    /// @brief Default ducking ramp duration in milliseconds, used when the server omits the field
    static constexpr uint16_t DEFAULT_DUCK_RAMP_MS = 100U;

    ServerPlayerStreamObject format{};

    /// Reduction in decibel (0-50) to apply to this client's own media output while the
    /// announcement stream is active. 0 means no ducking.
    uint8_t media_duck_db{0};

    /// Ramp duration in milliseconds (0-2000) for both applying and releasing the ducking.
    uint16_t duck_ramp_ms{DEFAULT_DUCK_RAMP_MS};

    /// When set, the announcement should be rendered at the loudness that master volume
    /// `volume` (0-100) would produce, regardless of the current master volume. When absent,
    /// the announcement follows the current master volume.
    std::optional<uint8_t> volume{};

    bool is_complete() const {
        return this->format.is_complete();
    }
};

/// @brief Listener for announcement role events
///
/// THREAD SAFETY: on_announcement_write() fires on the announcement task's background thread.
/// Implementations must be thread-safe for this method. on_announcement_start(),
/// on_announcement_end(), and on_announcement_clear() fire on the main loop thread via
/// drain_events(). The listener must outlive the role.
class AnnouncementRoleListener {
public:
    virtual ~AnnouncementRoleListener() = default;

    /// @brief Writes decoded announcement PCM audio to the platform's announcement output
    ///
    /// Fires on the announcement task's background thread. May block up to timeout_ms; the
    /// blocking write is what paces the decode loop against the sink.
    /// @param data Pointer to the decoded PCM audio data
    /// @param length Number of bytes to write; always a whole number of PCM frames
    /// @param timeout_ms Maximum time to wait for the write to complete
    /// @return Number of bytes actually written; partial writes must be whole PCM frames
    virtual size_t on_announcement_write(uint8_t* data, size_t length, uint32_t timeout_ms) = 0;

    /// @brief Called when an announcement stream starts. Fires on the main loop thread
    ///
    /// The embedder applies the ducking policy here (e.g. duck the media pipeline by
    /// `params.media_duck_db` over `params.duck_ramp_ms`).
    virtual void on_announcement_start(const ServerAnnouncementStreamObject& /*params*/) {}

    /// @brief Called when the announcement stream ends (normally, aborted, or on transport
    /// loss). Fires on the main loop thread. The embedder releases the ducking here
    virtual void on_announcement_end() {}

    /// @brief Called when the server clears the announcement stream (replace). Fires on the
    /// main loop thread. The embedder drops any announcement audio it has buffered downstream;
    /// the stream and the ducking state stay active
    virtual void on_announcement_clear() {}
};

/**
 * @brief Announcement role that decodes short per-client audio clips next to the media stream
 *
 * Owns an AnnouncementTask that runs on a background thread. Encoded announcement chunks
 * arrive from the WebSocket network thread, are written into a dedicated ring buffer, decoded,
 * and delivered to the platform through AnnouncementRoleListener::on_announcement_write().
 * Unlike the player role there is no sample-accurate sync machinery: announcements are
 * per-client, start at (or as soon as possible after) their first chunk's timestamp, and are
 * paced by the sink.
 *
 * Usage:
 * 1. Implement AnnouncementRoleListener with at minimum on_announcement_write()
 * 2. Add the role to the client via SendspinClient::add_announcement()
 * 3. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyAnnouncementListener : AnnouncementRoleListener {
 *     size_t on_announcement_write(uint8_t* data, size_t len, uint32_t timeout_ms) override {
 *         return announcement_output.write(data, len, timeout_ms);
 *     }
 *     void on_announcement_start(const ServerAnnouncementStreamObject& params) override {
 *         media_mixer.apply_ducking(params.media_duck_db, params.duck_ramp_ms);
 *     }
 *     void on_announcement_end() override { media_mixer.apply_ducking(0, ramp_ms); }
 * };
 *
 * MyAnnouncementListener listener;
 * AnnouncementRoleConfig config;
 * config.audio_formats = {{SendspinCodecFormat::PCM, 1, 48000, 16}};
 * auto& announcement = client.add_announcement(config);
 * announcement.set_listener(&listener);
 * @endcode
 */
class AnnouncementRole {
    friend class SendspinClient;

public:
    struct Impl;

    AnnouncementRole(AnnouncementRoleConfig config, SendspinClient* client);
    ~AnnouncementRole();

    /// @brief Sets the listener for announcement events
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(AnnouncementRoleListener* listener);

    // ========================================
    // Queries
    // ========================================

    /// @brief Returns a reference to the current announcement stream parameters
    /// @return Const reference to the active announcement stream parameters.
    const ServerAnnouncementStreamObject& get_current_stream_params() const;

    /// @brief Returns true if announcement audio is currently being output
    /// @return true while the announcement pipeline is playing, false otherwise.
    bool is_playing() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
