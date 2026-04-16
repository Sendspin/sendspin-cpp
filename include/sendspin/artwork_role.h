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

/// @file artwork_role.h
/// @brief Artwork role that receives artwork images from the server

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Artwork types
// ============================================================================

/// @brief Format and resolution for a single supported artwork channel
struct ArtworkChannelFormatObject {
    SendspinImageSource source{};
    SendspinImageFormat format{};
    uint16_t media_width{};
    uint16_t media_height{};
};

/// @brief Server-side description of one artwork channel's format and dimensions
struct ServerArtworkChannelObject {
    std::optional<SendspinImageSource> source;
    std::optional<SendspinImageFormat> format;
    std::optional<uint16_t> width;
    std::optional<uint16_t> height;

    /// @brief Returns true if all fields in this channel have received data
    bool is_complete() const {
        return source.has_value() && format.has_value() && width.has_value() && height.has_value();
    }
};

/// @brief Artwork stream parameters sent by the server in stream/start messages
struct ServerArtworkStreamObject {
    std::optional<std::vector<ServerArtworkChannelObject>> channels;
};

/// @brief Listener for artwork role events
///
/// THREAD SAFETY: on_image_decode() and on_image_display() fire on a dedicated drain thread.
/// Implementations must be thread-safe for these two methods. on_image_clear(),
/// on_artwork_stream_start(), and on_artwork_stream_end() fire on the main loop thread.
class ArtworkRoleListener {
public:
    virtual ~ArtworkRoleListener() = default;

    /// @brief Called on the drain thread when encoded image data arrives
    ///
    /// The implementation should decode the image (e.g., JPEG to bitmap) synchronously.
    /// The data pointer is valid for the duration of this call.
    /// @param slot The artwork slot index.
    /// @param data Pointer to the encoded image data.
    /// @param length Length of the encoded image data in bytes.
    /// @param format Image format (JPEG, PNG, BMP).
    virtual void on_image_decode(uint8_t /*slot*/, const uint8_t* /*data*/, size_t /*length*/,
                                 SendspinImageFormat /*format*/) {}

    /// @brief Called on the drain thread at the correct timestamp when the decoded image should be
    /// displayed
    ///
    /// Fires after on_image_decode() once the server timestamp is reached.
    /// @param slot The artwork slot index.
    /// @param client_timestamp Client-domain timestamp in microseconds.
    virtual void on_image_display(uint8_t /*slot*/, int64_t /*client_timestamp*/) {}

    /// @brief Called on the main loop thread when artwork should be cleared for a slot
    ///
    /// Fires on stream end or stream clear for each configured slot.
    /// @param slot The artwork slot index to clear.
    virtual void on_image_clear(uint8_t /*slot*/) {}

    /// @brief Called on the main loop thread when a new artwork stream starts
    /// @param stream Artwork stream parameters from the server.
    virtual void on_artwork_stream_start(const ServerArtworkStreamObject& /*stream*/) {}

    /// @brief Called on the main loop thread when the artwork stream ends
    virtual void on_artwork_stream_end() {}
};

/**
 * @brief Artwork role that receives album art and artist images from the server
 *
 * Receives binary image payloads from the server and delivers them to the platform
 * through ArtworkRoleListener callbacks. A dedicated drain thread handles two-phase
 * delivery: on_image_decode() fires immediately when data arrives for decoding, then
 * on_image_display() fires at the correct timestamp for synchronized display. Lifecycle
 * callbacks fire on the main loop thread. Supports multiple image slots with configurable
 * format and resolution preferences.
 *
 * Usage:
 * 1. Implement ArtworkRoleListener with on_image_decode() and on_image_display()
 * 2. Build an ArtworkRoleConfig with the desired slot/format/resolution preferences
 * 3. Add the role to the client via SendspinClient::add_artwork()
 * 4. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyArtworkListener : ArtworkRoleListener {
 *     void on_image_decode(uint8_t slot, const uint8_t* data, size_t length,
 *                          SendspinImageFormat format) override {
 *         decoded_images[slot] = decode(data, length, format);
 *     }
 *     void on_image_display(uint8_t slot, int64_t client_timestamp) override {
 *         display.show_image(slot, decoded_images[slot]);
 *     }
 *     void on_image_clear(uint8_t slot) override {
 *         display.clear_slot(slot);
 *     }
 * };
 *
 * MyArtworkListener listener;
 * ArtworkRoleConfig config;
 * config.preferred_formats = {{0, SendspinImageSource::ALBUM,
 *                               SendspinImageFormat::JPEG, 240, 240}};
 * auto& artwork = client.add_artwork(config);
 * artwork.set_listener(&listener);
 * @endcode
 */
class ArtworkRole {
    friend class SendspinClient;

public:
    struct Impl;

    ArtworkRole(ArtworkRoleConfig config, SendspinClient* client);
    ~ArtworkRole();

    /// @brief Sets the listener for artwork events
    /// @note The listener must outlive this role.
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(ArtworkRoleListener* listener);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
