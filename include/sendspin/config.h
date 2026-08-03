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

#include "sendspin/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Persistence types (used by SendspinPersistenceProvider)
// ============================================================================

/// @brief A long-term pairing record stored on behalf of the client.
/// Mirrors `ClientPairingRecord` in `aiosendspin/noise/trust_store.py`.
/// `server_id` is absent for shared-PSK (fallback) records.
struct SendspinPairingRecord {
    std::string psk_id;
    std::array<uint8_t, 32> psk{};
    std::optional<std::string> server_id;  ///< Absent = shared-PSK record.
    std::optional<std::string> label;
    bool used{false};
};

/// @brief An accepted Pairing PSK the client stores for admitting a server.
/// Mirrors `PairingPsk` in trust_store.py.
struct SendspinPairingPsk {
    std::string psk_id;
    std::array<uint8_t, 32> psk{};
    std::optional<std::string> label;
};

/// @brief Pairing policy persisted by the client.
struct SendspinPairingConfig {
    bool pairing_psk_enabled{true};
    bool unpaired_access_enabled{false};
    // PIN fields are deferred to a later phase of the encryption port. Carried as a
    // comment for forward-compat only; do not add live fields here until that phase.
    // std::optional<std::string> static_pin;
    std::string record_mode_psk_id;  ///< psk_id of the shared-PSK fallback record.
};

// ============================================================================
// Client config
// ============================================================================

/// @brief Configuration for a SendspinClient instance
/// Filled in by the platform (e.g., ESPHome) before calling start_server()
struct SendspinClientConfig {
    /// Unique client identifier. Superseded by the derived cryptographic identity
    /// (base64url(X25519 public key), generated/persisted internally) now that the Sendspin
    /// wire protocol carries client_id in client/init rather than client/hello. No longer read
    /// by the library; kept only so existing callers do not fail to compile. Removing it (and
    /// surfacing the derived identity through a public accessor instead) is deferred to the
    /// public-API pass in a later phase.
    std::string client_id;
    std::string name;  ///< Friendly display name

    /// @brief Whether every connection must complete a Noise KKpsk2 handshake before the hello
    /// exchange (spec PR #84's always-on encryption model).
    ///
    /// Defaults to true, matching the eventual mandatory-encryption design: the client is always
    /// the Noise responder, and admission/trust enforcement (see admission.h) key off the PSK
    /// category resolved by that handshake. Set to false only to run the connection nursery
    /// (accept/reap/admission-arbitration) without the crypto layer, e.g. plaintext test
    /// fixtures that exercise nursery structure independently of Noise (already covered
    /// separately by the Noise handshake/re-handshake/admission unit tests). This knob is
    /// internal for now; it is not part of the public-API surfacing pass planned for a later
    /// phase and may be removed once every fixture speaks Noise.
    bool encryption_required{true};

    std::optional<std::string> product_name{};  ///< Device product name (optional)
    std::optional<std::string> manufacturer{};  ///< Manufacturer name, e.g., "ESPHome" (optional)
    std::optional<std::string> software_version{};  ///< Software version string (optional)

    /// @brief MAC address of the network interface the connection is opened on.
    /// Sent in the client/hello device_info object. Must be lowercase colon-separated
    /// form (e.g., "aa:bb:cc:dd:ee:ff"). When left unset, the library auto-detects it:
    /// from the default network interface (Wi-Fi or Ethernet) on ESP-IDF, and best-effort
    /// from the active routable interface on host. Set this explicitly to override the
    /// detected value (recommended on multi-homed hosts where detection may pick the wrong
    /// interface).
    std::optional<std::string> mac_address{};

    bool httpd_psram_stack{false};  ///< Allocate httpd task stack in PSRAM (ESP-IDF only)

    /// @brief Default FreeRTOS priority for the HTTP server task (ESP-IDF only)
    static constexpr unsigned DEFAULT_HTTPD_PRIORITY = 5U;

    unsigned httpd_priority{DEFAULT_HTTPD_PRIORITY};  ///< FreeRTOS priority for the HTTP server
                                                      ///< task (ESP-IDF only)
    unsigned websocket_priority{5};  ///< FreeRTOS priority for the WebSocket client task
                                     ///< (ESP-IDF only)

    static constexpr uint16_t DEFAULT_SERVER_PORT = 8928U;  ///< Default WebSocket server port

    uint16_t httpd_ctrl_port{0};  ///< ESP-IDF httpd control port; 0 = ESP_HTTPD_DEF_CTRL_PORT
                                  ///< + 1 (avoids conflict with web_server component)
    uint16_t server_port{DEFAULT_SERVER_PORT};  ///< WebSocket server port

    /// @brief Default maximum simultaneous inbound connections: one established connection, two
    /// unproven connections awaiting the hello handshake (the manager's nursery capacity), and
    /// one spare so a surplus peer can still be accepted long enough to receive a graceful
    /// client/goodbye. Values below this trade that goodbye for a transport-level refusal at
    /// accept (on ESP the surplus peer waits unanswered in the TCP backlog instead).
    static constexpr uint8_t DEFAULT_SERVER_MAX_CONNECTIONS = 4U;

    uint8_t server_max_connections{
        DEFAULT_SERVER_MAX_CONNECTIONS};  ///< Maximum simultaneous connections

    static constexpr int64_t DEFAULT_BURST_INTERVAL_MS = 10000;  ///< Default ms between bursts
    static constexpr int64_t DEFAULT_BURST_TIMEOUT_MS = 10000;   ///< Default burst timeout ms

    uint8_t time_burst_size{8};  ///< Number of messages per time sync burst
    int64_t time_burst_interval_ms{DEFAULT_BURST_INTERVAL_MS};  ///< Milliseconds between bursts
    int64_t time_burst_response_timeout_ms{
        DEFAULT_BURST_TIMEOUT_MS};  ///< Milliseconds before a burst message times out

    /// @brief Memory placement for the per-connection WebSocket payload reassembly buffer
    /// (ESP-IDF only; ignored on host). Defaults to PREFER_EXTERNAL (SPIRAM).
    MemoryLocation websocket_payload_location{MemoryLocation::PREFER_EXTERNAL};

    /// @brief Size in bytes of an internal-RAM scratch arena for parsing incoming JSON messages.
    /// When non-zero, the JSON document used to parse each incoming protocol message is allocated
    /// from a fixed internal-RAM buffer of this size instead of PSRAM, cutting PSRAM traffic on the
    /// network task; messages too large for the budget fall back to PSRAM. Costs this many bytes of
    /// internal RAM permanently. The default (2048) covers the steady-state protocol traffic,
    /// including the FLAC stream-start header; large track-metadata messages may exceed it and fall
    /// back to PSRAM, but those arrive only once per song. Set to 0 to disable the arena and keep
    /// the PSRAM-only behaviour. Smaller values just fall back more often. On host there is no
    /// PSRAM distinction, so the arena is a fixed scratch buffer for the parse (still allocated and
    /// used; harmless).
    size_t json_arena_size{2048};
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

    /// @brief Default extra silence (ms) inserted at stream start for decode-pipeline headroom
    static constexpr uint16_t DEFAULT_EXTRA_STARTUP_SILENCE_MS = 50U;

    /// @brief Extra silence (ms) inserted at stream start, after the first playback notification
    /// and before the first decoded chunk, on top of the initial-sync priming silence. Gives the
    /// decode pipeline slack to stay ahead of the sink, preventing the initial-playback stutter.
    /// Larger values trade longer startup latency for more underflow protection; 0 disables.
    uint16_t extra_startup_silence_ms{DEFAULT_EXTRA_STARTUP_SILENCE_MS};

    bool psram_stack{false};  ///< Allocate sync task stack in PSRAM (ESP-IDF only)

    /// @brief Default FreeRTOS priority for the sync/decode task (ESP-IDF only).
    /// One above SendspinClientConfig::DEFAULT_HTTPD_PRIORITY so the httpd server task
    /// cannot starve the decoder during the initial burst of incoming encoded audio that
    /// fills the audio buffer at stream start.
    static constexpr unsigned DEFAULT_SYNC_TASK_PRIORITY =
        SendspinClientConfig::DEFAULT_HTTPD_PRIORITY + 1U;

    unsigned priority{DEFAULT_SYNC_TASK_PRIORITY};  ///< FreeRTOS priority for the sync/decode
                                                    ///< task (ESP-IDF only)

    /// @brief Memory placement for the decode transfer buffer (ESP-IDF only; ignored on host).
    /// Defaults to PREFER_EXTERNAL (SPIRAM).
    MemoryLocation decode_buffer_location{MemoryLocation::PREFER_EXTERNAL};
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
    SendspinImageSource source{};
    SendspinImageFormat format{};
    uint16_t width{};
    uint16_t height{};

    /// @brief Opt-in per-slot back-pressure gate. When true, the role delivers at most one
    /// un-acked "delivery" at a time for this slot: a delivery is either a frame
    /// (on_image_decode() followed by on_image_display()) or a clear (on_image_clear()). While a
    /// delivery is un-acked, any newer payload that arrives is buffered latest-wins and only
    /// delivered once the consumer calls ArtworkRole::frame_done(slot) from the main loop (e.g.
    /// after a cross-fade animation completes). Defaults to false, which preserves today's
    /// behavior of decoding and displaying every frame as it arrives.
    bool require_frame_done{false};

    /// @brief Fires on_image_display() this many milliseconds before the server's display
    /// timestamp (negative delays it). Lets a cross-fade straddle the track boundary: with a
    /// 2 s fade, an offset of 1000 starts the fade 1 s before the boundary so the incoming image
    /// is fully shown 1 s after it. Positive-equals-earlier mirrors
    /// PlayerRoleConfig::fixed_delay_us. Best-effort: an image that arrives or decodes after the
    /// offset deadline fires as soon as it is ready, same as any past-timestamp display.
    int32_t display_offset_ms{0};
};

/// @brief Configuration for the artwork role
struct ArtworkRoleConfig {
    /// @brief Slot/channel preferences in order. The array index is the channel slot number
    /// (matched against the binary message slot byte and advertised to the server in that
    /// order). Limited to ARTWORK_MAX_SLOTS (4) entries; extra entries are truncated with a
    /// warning.
    std::vector<ImageSlotPreference> preferred_formats{};
    bool psram_stack{false};  ///< Allocate decode thread stack in PSRAM (ESP-IDF only)
    unsigned priority{2};     ///< FreeRTOS priority for the decode thread (ESP-IDF only)
};

// ============================================================================
// Visualizer config types
// ============================================================================

/// @brief Visualizer data stream types
enum class VisualizerDataType : uint8_t {
    BEAT,      // Musical beat events from tempo/beat tracking
    LOUDNESS,  // Overall loudness level
    F_PEAK,    // Dominant frequency and amplitude
    SPECTRUM,  // Full frequency spectrum bins
    PEAK,      // Energy onset (transient) events
};

/// @brief Frequency scale used for spectrum visualization bins
enum class VisualizerSpectrumScale : uint8_t {
    MEL,  // Mel perceptual scale
    LOG,  // Logarithmic scale
    LIN,  // Linear scale
};

/// @brief Spectrum visualization parameters: bin count, frequency range, and scale
struct VisualizerSpectrumConfig {
    /// @brief Number of display bins (bars on a graphical equalizer). Capped at 255 by the
    /// uint8_t width; typical equalizer bin counts are well below this
    uint8_t n_disp_bins;
    VisualizerSpectrumScale scale;
    uint16_t f_min;
    uint16_t f_max;
};

/// @brief Visualizer capabilities advertised to the server during the hello handshake
struct VisualizerSupportObject {
    /// @brief Data types the client wants to receive
    std::vector<VisualizerDataType> types{};
    /// @brief Total RAM budget in bytes for the internal ring buffer (the exact allocation size).
    /// This is not the amount of wire data that fits: each entry stores its full wire message
    /// (message-type byte + timestamp + data) plus an aligned per-entry ItemHeader, so for the
    /// small visualizer entries only roughly a third of this budget holds actual wire data. The
    /// client advertises that effective (~1/3) capacity to the server, not this raw budget, so the
    /// server's flow control does not overrun the ring
    size_t buffer_capacity{};
    /// @brief Maximum periodic visualization frames per second (applies to LOUDNESS, F_PEAK,
    /// SPECTRUM). Event types (BEAT, PEAK) are not throttled. Set to the display refresh rate
    uint16_t rate_max{};
    /// @brief Spectrum configuration, required if types includes SPECTRUM
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief Configuration for the visualizer role
struct VisualizerRoleConfig {
    VisualizerSupportObject support;
    bool psram_stack{false};  ///< Allocate drain thread stack in PSRAM (ESP-IDF only)
    unsigned priority{2};     ///< FreeRTOS priority for the drain thread (ESP-IDF only)
};

}  // namespace sendspin
