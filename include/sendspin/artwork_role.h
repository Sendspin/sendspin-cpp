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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

// ============================================================================
// Artwork types
// ============================================================================

/// @brief Image format for artwork
enum class SendspinImageFormat {
    JPEG,  // JPEG compressed image
    PNG,   // PNG image
    BMP,   // BMP image
};

inline const char* to_cstr(SendspinImageFormat format) {
    switch (format) {
        case SendspinImageFormat::JPEG:
            return "jpeg";
        case SendspinImageFormat::PNG:
            return "png";
        case SendspinImageFormat::BMP:
            return "bmp";
        default:
            return "jpeg";
    }
}

inline std::optional<SendspinImageFormat> image_format_from_string(const std::string& str) {
    if (str == "jpeg")
        return SendspinImageFormat::JPEG;
    if (str == "png")
        return SendspinImageFormat::PNG;
    if (str == "bmp")
        return SendspinImageFormat::BMP;
    return std::nullopt;
}

/// @brief Source type for an artwork image
enum class SendspinImageSource {
    ALBUM,   // Album cover art
    ARTIST,  // Artist photo
    NONE,    // No image
};

inline const char* to_cstr(SendspinImageSource source) {
    switch (source) {
        case SendspinImageSource::ALBUM:
            return "album";
        case SendspinImageSource::ARTIST:
            return "artist";
        case SendspinImageSource::NONE:
        default:
            return "none";
    }
}

inline std::optional<SendspinImageSource> image_source_from_string(const std::string& str) {
    if (str == "album")
        return SendspinImageSource::ALBUM;
    if (str == "artist")
        return SendspinImageSource::ARTIST;
    if (str == "none")
        return SendspinImageSource::NONE;
    return std::nullopt;
}

/// @brief Format and resolution for a single supported artwork channel
struct ArtworkChannelFormatObject {
    SendspinImageSource source;
    SendspinImageFormat format;
    uint16_t media_width;
    uint16_t media_height;
};

/// @brief Artwork capabilities advertised to the server during the hello handshake
struct ArtworkSupportObject {
    std::vector<ArtworkChannelFormatObject> channels;
};

/// @brief Server-side description of one artwork channel's format and dimensions
struct ServerArtworkChannelObject {
    std::optional<SendspinImageSource> source;
    std::optional<SendspinImageFormat> format;
    std::optional<uint16_t> width;
    std::optional<uint16_t> height;

    bool is_complete() const {
        return source.has_value() && format.has_value() && width.has_value() && height.has_value();
    }
};

/// @brief Artwork stream parameters sent by the server in stream/start messages
struct ServerArtworkStreamObject {
    std::optional<std::vector<ServerArtworkChannelObject>> channels;
};

/// @brief Client request for a specific artwork channel format, sent in stream/request_format
struct ClientArtworkRequestObject {
    uint8_t channel;
    std::optional<SendspinImageSource> source;
    std::optional<SendspinImageFormat> format;
    std::optional<uint16_t> media_width;
    std::optional<uint16_t> media_height;
};

/// @brief Preference for an image slot's format and resolution.
struct ImageSlotPreference {
    uint8_t slot;
    SendspinImageSource source;
    SendspinImageFormat format;
    uint16_t width;
    uint16_t height;
};

/// @brief Listener for artwork role events.
///
/// THREAD SAFETY: on_image() is called from two different contexts:
/// - From the network thread when image data is received (data != nullptr)
/// - From the main loop thread when images are cleared (data == nullptr)
/// Implementations must be thread-safe.
class ArtworkRoleListener {
public:
    virtual ~ArtworkRoleListener() = default;

    /// @brief Called when an image is received or cleared.
    /// @param slot The artwork slot index.
    /// @param data Image data, or nullptr for clears.
    /// @param length Length of image data in bytes.
    /// @param format Image format.
    /// @param timestamp Server timestamp (0 for clears).
    virtual void on_image(uint8_t /*slot*/, const uint8_t* /*data*/, size_t /*length*/,
                          SendspinImageFormat /*format*/, int64_t /*timestamp*/) {}
};

/// @brief Artwork role: receives artwork images from the server.
class ArtworkRole {
    friend class SendspinClient;

public:
    explicit ArtworkRole(SendspinClient* client);
    ~ArtworkRole();

    /// @brief Sets the listener for artwork events. The listener must outlive this role.
    void set_listener(ArtworkRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Adds a preferred image format for an artwork slot.
    void add_image_preferred_format(const ImageSlotPreference& pref);

    /// @brief Returns all configured image format preferences.
    const std::vector<ImageSlotPreference>& get_image_preferred_formats() const {
        return this->preferred_image_formats_;
    }

private:
    /// @brief Adds the artwork role and configured channels to the hello message.
    /// @param msg The hello message being assembled.
    void contribute_hello(ClientHelloMessage& msg);
    /// @brief Decodes the timestamp and delivers an image chunk directly to the listener.
    /// @param slot Artwork slot index this image belongs to.
    /// @param data Pointer to the binary payload (8-byte big-endian timestamp followed by image
    /// data).
    /// @param len Length of the binary payload in bytes.
    void handle_binary(uint8_t slot, const uint8_t* data, size_t len);
    /// @brief Enqueues a stream-end event to be delivered on the main thread.
    void handle_stream_end();
    /// @brief Sends null images to the listener for each configured slot to signal stream end.
    void drain_events();
    /// @brief Resets pending events and enqueues a stream-end to clear all slots on next drain.
    void cleanup();

    // Struct fields
    std::vector<ArtworkChannelFormatObject> artwork_channels_;
    struct EventState;
    std::vector<ImageSlotPreference> preferred_image_formats_;

    // Pointer fields
    SendspinClient* client_;
    std::unique_ptr<EventState> event_state_;
    ArtworkRoleListener* listener_{nullptr};
};

}  // namespace sendspin
