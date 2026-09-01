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
    /// Unique client identifier. When left empty, the library falls back to the detected local
    /// network interface MAC address (the same value used for device_info.mac_address).
    std::string client_id;
    std::string name;  ///< Friendly display name

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

/// @brief Audio codec format for an audio stream (player playback or source capture)
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

// ============================================================================
// Source config types
// ============================================================================

/// @brief Configuration for the source role (audio capture streamed to the server)
///
/// The configured format is the contract for every stream the role opens: there is no
/// negotiation, and write_audio() consumes PCM in exactly that format (sent untouched for the
/// PCM codec, encoded chunk-by-chunk for OPUS). An invalid config leaves the role added but
/// inert (logged at ERROR; the role is not advertised and never streams) -- spec-invalid values
/// are rejected, never clamped or repaired.
struct SourceRoleConfig {
    /// @brief Chunk duration bounds from the Sendspin spec (Source messages): chunks MUST be
    /// at most 150 ms and SHOULD be at least 5 ms
    static constexpr uint32_t CHUNK_MIN_MS = 5U;
    static constexpr uint32_t CHUNK_MAX_MS = 150U;

    /// @brief Default duration (ms) of one outbound audio chunk. Small enough to keep the
    /// capture-to-server latency and per-chunk staging buffer modest, large enough that the
    /// per-chunk framing/send overhead stays negligible; well inside the spec bounds above
    static constexpr uint32_t DEFAULT_CHUNK_MS = 25U;

    /// @brief Default capture ring capacity in milliseconds. Derived from the spec's maximum
    /// chunk duration: the ring IS the "small bound" of the spec's stall policy (Source
    /// messages) -- backlog beyond it is dropped at write_audio() and streaming resumes from
    /// live capture rather than bursting stale audio
    static constexpr uint32_t DEFAULT_CAPTURE_BUFFER_MS = CHUNK_MAX_MS;

    /// @brief Default FreeRTOS priority for the source task (ESP-IDF only). Below the HTTP
    /// server task (SendspinClientConfig::DEFAULT_HTTPD_PRIORITY = 5) and the sync/decode task
    /// (6) so outbound capture can never starve inbound playback, above the artwork/visualizer
    /// drain threads (2)
    static constexpr unsigned DEFAULT_SOURCE_TASK_PRIORITY = 3U;

    /// @brief Opus bitrate bounds in bit/s: the range libopus's OPUS_SET_BITRATE accepts
    static constexpr uint32_t OPUS_BITRATE_MIN = 500U;
    static constexpr uint32_t OPUS_BITRATE_MAX = 512000U;

    /// @brief Default Opus bitrate (bit/s): transparent-leaning for 48 kHz stereo music per
    /// Opus encoding guidance. Mono/voice configs typically run 24000-64000
    static constexpr uint32_t DEFAULT_OPUS_BITRATE = 128000U;

    /// @brief Maximum value libopus's OPUS_SET_COMPLEXITY accepts
    static constexpr uint8_t OPUS_COMPLEXITY_MAX = 10U;

    /// @brief Default Opus encoder complexity: low, to fit an ESP32-class real-time encode
    /// budget. Hosts may raise it toward OPUS_COMPLEXITY_MAX for quality per CPU
    static constexpr uint8_t DEFAULT_OPUS_COMPLEXITY = 2U;

    // 32-bit fields
    /// @brief Capture sample rate in Hz; must be > 0. OPUS accepts only libopus's rates:
    /// 8000, 12000, 16000, 24000, or 48000 (a 44100 line-in must use PCM or resample upstream)
    uint32_t sample_rate{48000};

    /// @brief Outbound chunk duration in milliseconds, validated against the spec bounds
    /// [CHUNK_MIN_MS, CHUNK_MAX_MS]. OPUS accepts only 10, 20, 40, or 60 (one
    /// chunk is exactly one legal Opus frame), so the PCM default of 25 is rejected for OPUS
    uint32_t chunk_duration_ms{DEFAULT_CHUNK_MS};

    /// @brief Capture ring capacity in milliseconds of audio in the configured format (the
    /// byte size is computed from sample_rate, channels, and bit_depth). See
    /// DEFAULT_CAPTURE_BUFFER_MS for why this doubles as the stall-policy backlog bound.
    /// Approximate: per-write ring metadata comes out of a fixed +25% margin, so many very
    /// small write_audio() calls reduce the effective audio capacity below this figure
    uint32_t capture_buffer_ms{DEFAULT_CAPTURE_BUFFER_MS};

    /// @brief Opus bitrate in bit/s, validated against [OPUS_BITRATE_MIN,
    /// OPUS_BITRATE_MAX]. Ignored (and unvalidated) when codec is PCM
    uint32_t opus_bitrate{DEFAULT_OPUS_BITRATE};

    unsigned priority{DEFAULT_SOURCE_TASK_PRIORITY};  ///< FreeRTOS priority for the source
                                                      ///< task (ESP-IDF only)

    /// @brief Memory placement for the capture ring, chunk staging buffer, and the Opus
    /// encoder's scratch buffers (ESP-IDF only; ignored on host). Bulk audio with sequential
    /// access, so PREFER_EXTERNAL (SPIRAM) -- mirrors the player decode buffer's choice
    MemoryLocation buffer_location{MemoryLocation::PREFER_EXTERNAL};

    // 8-bit fields
    /// @brief Outbound codec: PCM (chunks are the capture bytes, untouched) or OPUS (each
    /// chunk is encoded into one RFC 6716 packet). OPUS narrows the accepted format -- see the
    /// per-field validation notes on the fields above. OPUS also costs
    /// the encoder state plus micro-opus's per-thread scratch arena (~120 KB,
    /// SPIRAM-preferred, allocated lazily on the source task's first encode) -- the same
    /// per-thread arena the player's Opus decode allocates on its own task, so a device doing
    /// both holds two such arenas
    SendspinCodecFormat codec{SendspinCodecFormat::PCM};

    /// @brief Opus encoder complexity, validated to at most OPUS_COMPLEXITY_MAX.
    /// Ignored (and unvalidated) when codec is PCM
    uint8_t opus_complexity{DEFAULT_OPUS_COMPLEXITY};
    uint8_t channels{2};      ///< Capture channel count; must be > 0 (1 or 2 for OPUS)
    uint8_t bit_depth{16};    ///< Bits per sample; 16, 24 (3 packed bytes), or 32 (16 for OPUS)
    bool line_sense{false};   ///< Advertise line-input signal sensing (see SourceRole::set_signal)
    bool psram_stack{false};  ///< Allocate source task stack in PSRAM (ESP-IDF only)
};

}  // namespace sendspin
