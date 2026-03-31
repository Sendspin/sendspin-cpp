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

#include <atomic>
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
enum class SendspinImageFormat : uint8_t {
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
    if (str == "jpeg") {
        return SendspinImageFormat::JPEG;
    }
    if (str == "png") {
        return SendspinImageFormat::PNG;
    }
    if (str == "bmp") {
        return SendspinImageFormat::BMP;
    }
    return std::nullopt;
}

/// @brief Source type for an artwork image
enum class SendspinImageSource : uint8_t {
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
    if (str == "album") {
        return SendspinImageSource::ALBUM;
    }
    if (str == "artist") {
        return SendspinImageSource::ARTIST;
    }
    if (str == "none") {
        return SendspinImageSource::NONE;
    }
    return std::nullopt;
}

/// @brief Format and resolution for a single supported artwork channel
struct ArtworkChannelFormatObject {
    SendspinImageSource source{};
    SendspinImageFormat format{};
    uint16_t media_width{};
    uint16_t media_height{};
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

    /// @brief Returns true if all fields in this channel have received data
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
    uint8_t channel{};
    std::optional<SendspinImageSource> source;
    std::optional<SendspinImageFormat> format;
    std::optional<uint16_t> media_width;
    std::optional<uint16_t> media_height;
};

/// @brief Preference for an image slot's format and resolution
struct ImageSlotPreference {
    uint8_t slot{};
    SendspinImageSource source{};
    SendspinImageFormat format{};
    uint16_t width{};
    uint16_t height{};
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
 * 2. Build an ArtworkRole::Config with the desired slot/format/resolution preferences
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
 * ArtworkRole::Config config;
 * config.preferred_formats = {{0, SendspinImageSource::ALBUM,
 *                               SendspinImageFormat::JPEG, 240, 240}};
 * auto& artwork = client.add_artwork(config);
 * artwork.set_listener(&listener);
 * @endcode
 */
class ArtworkRole {
    friend class SendspinClient;

public:
    /// @brief Configuration for the artwork role
    struct Config {
        std::vector<ImageSlotPreference> preferred_formats{};
    };

    ArtworkRole(Config config, SendspinClient* client);
    ~ArtworkRole();

    /// @brief Sets the listener for artwork events
    /// @note The listener must outlive this role.
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(ArtworkRoleListener* listener) {
        this->listener_ = listener;
    }

private:
    /// @brief Deferred artwork event types
    enum class EventType : uint8_t {
        STREAM_START,
        STREAM_END,
        STREAM_CLEAR,
    };

    /// @brief Starts the drain thread
    /// @param psram_stack Whether to allocate the drain thread stack in PSRAM (ESP-IDF only).
    /// @param priority FreeRTOS task priority for the drain thread (ESP-IDF only).
    /// @return True if the thread is running, false on failure.
    bool start(bool psram_stack, unsigned priority);
    /// @brief Signals the drain thread to stop and waits for it to exit
    void stop();
    /// @brief Adds the artwork role and configured channels to the hello message
    /// @param msg The hello message being assembled.
    void build_hello_fields(ClientHelloMessage& msg);
    /// @brief Copies image data to a per-slot buffer and signals the drain thread
    /// @param slot Artwork slot index this image belongs to.
    /// @param data Pointer to the binary payload (8-byte big-endian timestamp followed by image
    /// data).
    /// @param len Length of the binary payload in bytes.
    void handle_binary(uint8_t slot, const uint8_t* data, size_t len);
    /// @brief Caches stream config, signals the drain thread to flush, and enqueues a start event
    /// @param stream Stream parameters received from the server.
    void handle_stream_start(const ServerArtworkStreamObject& stream);
    /// @brief Marks the stream inactive, flushes the drain thread, and enqueues a stream-end event
    void handle_stream_end();
    /// @brief Marks the stream inactive, flushes the drain thread, and enqueues a stream-clear
    /// event
    void handle_stream_clear();
    /// @brief Delivers pending stream lifecycle events (start, end, clear) to the listener
    void drain_events();
    /// @brief Resets pending events, flushes the drain thread, and enqueues a stream-end event
    void cleanup();

    /// @brief Entry point for the drain thread; processes image decode and display callbacks
    /// @param self The ArtworkRole instance that owns this thread.
    static void drain_thread_func(ArtworkRole* self);

    struct DrainTask;
    struct EventState;

    // Struct fields
    Config config_;
    std::vector<ArtworkChannelFormatObject> artwork_channels_;

    // Pointer fields
    SendspinClient* client_;
    std::unique_ptr<DrainTask> drain_task_;
    std::unique_ptr<EventState> event_state_;
    ArtworkRoleListener* listener_{nullptr};

    // 8-bit fields
    std::atomic<bool> stream_active_{false};
};

}  // namespace sendspin
