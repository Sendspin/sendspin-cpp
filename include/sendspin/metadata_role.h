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

/// @file metadata_role.h
/// @brief Metadata role that receives track metadata and playback progress from the server

#pragma once

#include "sendspin/config.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Metadata types
// ============================================================================

/// @brief Playback progress fields embedded in a metadata state update
struct MetadataProgressObject {
    uint32_t track_progress;
    uint32_t track_duration;
    uint32_t playback_speed;
};

/// @brief Track metadata and playback state received from the server, handed to
/// MetadataRoleListener::on_track_metadata()
///
/// Each text field views at most 255 bytes of UTF-8 (artwork_url 2048), cut at a character
/// boundary, and has no value when its MetadataRoleConfig flag is false. The views are valid for
/// the duration of the callback; copy what is needed past it.
struct TrackMetadata {
    int64_t timestamp{};
    std::optional<std::string_view> title{};
    std::optional<std::string_view> artist{};
    std::optional<std::string_view> album_artist{};
    std::optional<std::string_view> album{};
    std::optional<std::string_view> artwork_url{};
    std::optional<uint16_t> year{};
    std::optional<uint16_t> track{};
    std::optional<MetadataProgressObject> progress{};
};

/// @brief TrackMetadata with each text field copied into a std::string
/// @deprecated Use TrackMetadata, handed to MetadataRoleListener::on_track_metadata(); removed in
/// v0.11.0.
struct [[deprecated(
    "use TrackMetadata and on_track_metadata(); removed in v0.11.0")]] ServerMetadataStateObject {
    int64_t timestamp{};
    std::optional<std::string> title;
    std::optional<std::string> artist;
    std::optional<std::string> album_artist;
    std::optional<std::string> album;
    std::optional<std::string> artwork_url;
    std::optional<uint16_t> year;
    std::optional<uint16_t> track;
    std::optional<MetadataProgressObject> progress;
};

/// @brief Listener for metadata role events. All methods fire on the main loop thread.
class MetadataRoleListener {
public:
    virtual ~MetadataRoleListener() = default;

    /// @brief Called when the server's metadata state is applied
    ///
    /// The library calls this and then the deprecated on_metadata() for each state: override one
    /// of them. A listener overriding both gets both, this one first.
    virtual void on_track_metadata(const TrackMetadata& /*metadata*/) {}

    /// @brief Called after on_track_metadata() with the same state
    /// @deprecated Override on_track_metadata(); removed in v0.11.0.
    [[deprecated("override on_track_metadata(); removed in v0.11.0")]] virtual void on_metadata(
        const ServerMetadataStateObject& /*metadata*/) {}

    /// @brief Called when the cached metadata is dropped: the connection to the server was lost,
    /// or a server/activate took the metadata role out of the session's active roles
    ///
    /// Implementations should clear any displayed track metadata, since the previous state is no
    /// longer valid. Idempotent by contract: a second clear with nothing to clear must be a
    /// no-op. A role removed from an active session
    /// can be added back by a later activation, which resumes with a fresh on_track_metadata().
    virtual void on_metadata_clear() {}
};

/**
 * @brief Metadata role that receives track metadata and playback progress from the server
 *
 * Maintains a local shadow of the server's metadata state, including track title, artist,
 * album, artwork URL, and playback progress. Each metadata state the server sends carries the
 * full state, so it replaces the shadow outright: a field it leaves out has no value, and a
 * state without `progress` clears the position. The state is delivered to the listener on the
 * main loop thread once the synchronized client clock reaches its `timestamp` (or immediately if
 * there is no active connection). Progress is interpolated locally using the server timestamp so
 * callers always get a current value.
 *
 * Usage:
 * 1. Implement MetadataRoleListener to receive metadata updates
 * 2. Add the role to the client via SendspinClient::add_metadata(), turning off in
 *    MetadataRoleConfig the text fields not to keep
 * 3. Call set_listener() with your listener implementation
 * 4. Poll get_track_progress_ms() and get_track_duration_ms() as needed for UI updates
 *
 * @code
 * struct MyMetadataListener : MetadataRoleListener {
 *     void on_track_metadata(const TrackMetadata& m) override {
 *         if (m.title) display_title(*m.title);
 *         if (m.artist) display_artist(*m.artist);
 *     }
 * };
 *
 * MyMetadataListener listener;
 * // Only the fields the listener shows: the others are dropped and cost no storage
 * auto& metadata =
 *     client.add_metadata({.album_artist = false, .album = false, .artwork_url = false});
 * metadata.set_listener(&listener);
 * uint32_t progress = metadata.get_track_progress_ms();
 * @endcode
 */
class MetadataRole {
    friend class SendspinClient;

public:
    struct Impl;

    MetadataRole(MetadataRoleConfig config, SendspinClient* client);
    ~MetadataRole();

    /// @brief Sets the listener for metadata events; it must outlive this role. Set it before
    /// SendspinClient::start() and leave it in place while the client runs.
    void set_listener(MetadataRoleListener* listener);

    /// @brief Returns the track duration in milliseconds, or 0 if unknown or the stream is live
    uint32_t get_track_duration_ms() const;

    /// @brief Returns the track progress in milliseconds, interpolated from the last server update
    uint32_t get_track_progress_ms() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
