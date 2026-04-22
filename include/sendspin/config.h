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

/// @file config.h
/// @brief Configuration structs for the Sendspin client and roles

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Client config
// ============================================================================

/// @brief Configuration for a SendspinClient instance
/// Filled in by the platform (e.g., ESPHome) before calling start_server()
struct SendspinClientConfig {
    std::string client_id;         ///< Unique client identifier (e.g., MAC address)
    std::string name;              ///< Friendly display name
    std::string product_name;      ///< Device product name
    std::string manufacturer;      ///< Manufacturer name (e.g., "ESPHome")
    std::string software_version;  ///< Software version string

    bool httpd_psram_stack{false};  ///< Allocate httpd task stack in PSRAM (ESP-IDF only)

    /// @brief Default FreeRTOS priority for the HTTP server task (ESP-IDF only)
    static constexpr unsigned DEFAULT_HTTPD_PRIORITY = 17U;

    unsigned httpd_priority{DEFAULT_HTTPD_PRIORITY};  ///< FreeRTOS priority for the HTTP server
                                                      ///< task (ESP-IDF only)
    unsigned websocket_priority{5};  ///< FreeRTOS priority for the WebSocket client task
                                     ///< (ESP-IDF only)

    uint8_t server_max_connections{2};  ///< Maximum simultaneous connections (default: 2 for
                                        ///< handoff protocol)
    uint16_t httpd_ctrl_port{0};        ///< ESP-IDF httpd control port; 0 = ESP_HTTPD_DEF_CTRL_PORT
                                        ///< + 1 (avoids conflict with web_server component)

    static constexpr int64_t DEFAULT_BURST_INTERVAL_MS = 10000;  ///< Default ms between bursts
    static constexpr int64_t DEFAULT_BURST_TIMEOUT_MS = 10000;   ///< Default burst timeout ms

    uint8_t time_burst_size{8};  ///< Number of messages per time sync burst
    int64_t time_burst_interval_ms{DEFAULT_BURST_INTERVAL_MS};  ///< Milliseconds between bursts
    int64_t time_burst_response_timeout_ms{
        DEFAULT_BURST_TIMEOUT_MS};  ///< Milliseconds before a burst message times out
};

// ============================================================================
// Player config types
// ============================================================================

/// @brief Audio codec format for a player stream
enum class SendspinCodecFormat : uint8_t {
    FLAC,         // FLAC lossless audio
    OPUS,         // Opus compressed audio
    PCM,          // Raw PCM audio
    UNSUPPORTED,  // Codec not recognized
};

/// @brief One supported audio format entry advertised by the player in the hello message
struct AudioSupportedFormatObject {
    SendspinCodecFormat codec;
    uint8_t channels;
    uint32_t sample_rate;
    uint8_t bit_depth;
};

/// @brief Configuration for the player role
struct PlayerRoleConfig {
    static constexpr size_t DEFAULT_AUDIO_BUFFER_CAPACITY = 1000000U;  ///< ~1MB default buffer
    std::vector<AudioSupportedFormatObject> audio_formats{};
    size_t audio_buffer_capacity{DEFAULT_AUDIO_BUFFER_CAPACITY};
    int32_t fixed_delay_us{0};
    uint16_t initial_static_delay_ms{0};
    bool psram_stack{false};  ///< Allocate sync task stack in PSRAM (ESP-IDF only)
    unsigned priority{2};     ///< FreeRTOS priority for the sync/decode task (ESP-IDF only)
};

// ============================================================================
// Artwork config types
// ============================================================================

/// @brief Image format for artwork
enum class SendspinImageFormat : uint8_t {
    JPEG,  // JPEG compressed image
    PNG,   // PNG image
    BMP,   // BMP image
};

/// @brief Source type for an artwork image
enum class SendspinImageSource : uint8_t {
    ALBUM,   // Album cover art
    ARTIST,  // Artist photo
    NONE,    // No image
};

/// @brief Preference for an image slot's format and resolution
struct ImageSlotPreference {
    uint8_t slot{};
    SendspinImageSource source{};
    SendspinImageFormat format{};
    uint16_t width{};
    uint16_t height{};
};

/// @brief Configuration for the artwork role
struct ArtworkRoleConfig {
    std::vector<ImageSlotPreference> preferred_formats{};
    bool psram_stack{false};  ///< Allocate decode thread stack in PSRAM (ESP-IDF only)
    unsigned priority{2};     ///< FreeRTOS priority for the decode thread (ESP-IDF only)
};

// ============================================================================
// Visualizer config types
// ============================================================================

/// @brief Visualizer data stream types
enum class VisualizerDataType : uint8_t {
    BEAT,      // Beat detection events
    LOUDNESS,  // Overall loudness level
    F_PEAK,    // Peak frequency
    SPECTRUM,  // Full frequency spectrum bins
};

/// @brief Frequency scale used for spectrum visualization bins
enum class VisualizerSpectrumScale : uint8_t {
    MEL,  // Mel perceptual scale
    LOG,  // Logarithmic scale
    LIN,  // Linear scale
};

/// @brief Spectrum visualization parameters: bin count, frequency range, scale, and rate cap
struct VisualizerSpectrumConfig {
    uint8_t n_disp_bins;
    VisualizerSpectrumScale scale;
    uint16_t f_min;
    uint16_t f_max;
    uint16_t rate_max;
};

/// @brief Visualizer capabilities advertised to the server during the hello handshake
struct VisualizerSupportObject {
    std::vector<VisualizerDataType> types{};
    size_t buffer_capacity{};
    uint8_t batch_max{};
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief Configuration for the visualizer role
struct VisualizerRoleConfig {
    VisualizerSupportObject support;
    bool psram_stack{false};  ///< Allocate drain thread stack in PSRAM (ESP-IDF only)
    unsigned priority{2};     ///< FreeRTOS priority for the drain thread (ESP-IDF only)
};

}  // namespace sendspin
