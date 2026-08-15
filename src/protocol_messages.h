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

/// @file protocol_messages.h
/// @brief Internal protocol types, message envelope structs, and JSON serialization/parsing
/// functions for the Sendspin wire protocol

#pragma once

#include "sendspin/color_role.h"
#include "sendspin/config.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/types.h"
#include "sendspin/visualizer_role.h"
#include <ArduinoJson.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Internal protocol types
// ============================================================================

/// @brief Role field values for binary message type bytes
///
/// Bits 7-2 encode the role (upper 6 bits of the type byte); bits 1-0 encode
/// the slot. Each role therefore has 4 slots (IDs = role << 2 through role << 2 + 3).
/// The visualizer role has an expanded 8-slot allocation (IDs 16-23, bits 2-0 as slot)
/// and is dispatched by ID range rather than through this enum.
enum SendspinBinaryRole : uint8_t {
    SENDSPIN_ROLE_PLAYER = 1,   // 000001xx (IDs 4-7)
    SENDSPIN_ROLE_ARTWORK = 2,  // 000010xx (IDs 8-11)
};

/// @brief Extracts the role field from a standard 4-slot binary message type byte
/// @param type Binary message type byte.
/// @return Role portion of the type (bits 7-2).
/// @warning Valid only for the standard 4-slot roles (PLAYER/ARTWORK, IDs 4-11). The visualizer
///          range (IDs 16-23) is dispatched by range in SendspinClient::process_binary_message
///          and must not be routed through this helper: get_binary_role(16) yields 4, which
///          matches no SendspinBinaryRole enumerator.
inline uint8_t get_binary_role(uint8_t type) {
    return type >> 2;
}
/// @brief Extracts the slot field from a standard 4-slot binary message type byte
/// @param type Binary message type byte.
/// @return Slot portion of the type (bits 1-0).
/// @warning Valid only for the standard 4-slot roles (PLAYER/ARTWORK, IDs 4-11). It masks bits
///          1-0, so it cannot address the visualizer's 8-slot range (e.g. IDs 16 and 20 both
///          alias to slot 0); those messages are dispatched by range, not by slot.
inline uint8_t get_binary_slot(uint8_t type) {
    return type & 0x03;
}

/// @brief Binary message type byte values for known message kinds
enum SendspinBinaryType : uint8_t {
    SENDSPIN_BINARY_PLAYER_AUDIO = 4,   // Player slot 0: encoded audio chunk
    SENDSPIN_BINARY_ARTWORK_IMAGE = 8,  // Artwork slot 0: image data
    // Visualizer expanded allocation (IDs 16-23); each data type is its own message
    // carrying exactly one frame of [timestamp:8][data]
    SENDSPIN_BINARY_VISUALIZER_LOUDNESS = 16,  // uint16 A-weighted loudness
    SENDSPIN_BINARY_VISUALIZER_BEAT = 17,      // uint8 flags (bit 0 = downbeat)
    SENDSPIN_BINARY_VISUALIZER_F_PEAK = 18,    // uint16 freq Hz + uint16 amplitude
    SENDSPIN_BINARY_VISUALIZER_SPECTRUM = 19,  // uint16[n_disp_bins] magnitudes
    SENDSPIN_BINARY_VISUALIZER_PEAK = 20,      // uint8 onset strength
    SENDSPIN_BINARY_VISUALIZER_FIRST = 16,     // Start of visualizer ID range
    SENDSPIN_BINARY_VISUALIZER_LAST = 23,      // End of visualizer ID range (21-23 reserved)
};

/// @brief JSON message types sent from the server to the client
enum class SendspinServerToClientMessageType : uint8_t {
    SERVER_HELLO,                    // server/hello handshake
    SERVER_ACTIVATE,                 // server/activate declares activities and active_roles
    SERVER_TIME,                     // server/time clock sync reply
    SERVER_STATE,                    // server/state playback state update
    SERVER_COMMAND,                  // server/command player command
    STREAM_START,                    // stream/start new stream parameters
    STREAM_END,                      // stream/end normal stream completion
    STREAM_CLEAR,                    // stream/clear immediate buffer flush
    GROUP_UPDATE,                    // group/update group membership change
    NOISE_HANDSHAKE,                 // noise/handshake in-band re-handshake
    SERVER_PAIR_FINALIZE,            // server/pair-finalize empty ack from server
    PAIR_ABORT,                      // pair/abort pairing failure from either side
    SERVER_UNPAIR,                   // server/unpair request to drop pairing record
    MANAGEMENT_LIST_RECORDS,         // management/list-records stored record summaries
    MANAGEMENT_ADD_RECORD,           // management/add-record store a new pairing PSK
    MANAGEMENT_REMOVE_RECORD,        // management/remove-record delete a stored record
    MANAGEMENT_GET_PAIRING_CONFIG,   // management/get-pairing-config read pairing method config
    MANAGEMENT_SET_PAIRING_CONFIG,   // management/set-pairing-config update pairing method config
    MANAGEMENT_OPEN_PAIRING_WINDOW,  // management/open-pairing-window remote operator gesture
    SERVER_PAIR_INIT,                // server/pair-init: nonce_A
    SERVER_PAIR_AUTH,                // server/pair-auth: pake_msg_1
    SERVER_PAIR_CONFIRM,             // server/pair-confirm: server_kc
    UNKNOWN,                         // Unrecognized message type
};

/// @brief Protocol role identifiers used in hello messages and role negotiation
enum class SendspinRole : uint8_t {
    PLAYER,      // Audio playback role
    CONTROLLER,  // Playback command/state role
    METADATA,    // Track metadata role
    ARTWORK,     // Album artwork role
    VISUALIZER,  // Audio visualization role
    COLOR,       // Audio-derived color palette role
};

/// @brief Converts a SendspinRole value to its protocol wire string representation
/// @param role The role to convert.
/// @return Null-terminated protocol string for the role (e.g., "player@v1").
inline const char* to_cstr(SendspinRole role) {
    switch (role) {
        case SendspinRole::PLAYER:
            return "player@v1";
        case SendspinRole::CONTROLLER:
            return "controller@v1";
        case SendspinRole::METADATA:
            return "metadata@v1";
        case SendspinRole::ARTWORK:
            return "artwork@v1";
        case SendspinRole::VISUALIZER:
            return "visualizer@v1";
        case SendspinRole::COLOR:
            return "color@v1";
        default:
            return "unknown";
    }
}

/// @brief Activity declared in a server/activate message.
/// A connection declares a SET of activities rather than a single reason (spec "server/activate").
/// Mirrors Activity in aiosendspin/models/types.py.
enum class SendspinActivity : uint8_t {
    PLAYBACK,    // Active or upcoming playback
    PAIRING,     // A pairing exchange
    MANAGEMENT,  // A dedicated management session
};

/// @brief Converts a SendspinActivity value to its protocol wire string
/// @param activity The activity to convert.
/// @return Null-terminated protocol string (e.g., "playback").
inline const char* to_cstr(SendspinActivity activity) {
    switch (activity) {
        case SendspinActivity::PLAYBACK:
            return "playback";
        case SendspinActivity::PAIRING:
            return "pairing";
        case SendspinActivity::MANAGEMENT:
            return "management";
        default:
            return "unknown";
    }
}

/// @brief Parses a wire string into a SendspinActivity.
/// @param str The string to parse.
/// @return The matching enum value, or std::nullopt if the string is unrecognized.
inline std::optional<SendspinActivity> activity_from_string(const std::string& str) {
    if (str == "playback") {
        return SendspinActivity::PLAYBACK;
    }
    if (str == "pairing") {
        return SendspinActivity::PAIRING;
    }
    if (str == "management") {
        return SendspinActivity::MANAGEMENT;
    }
    return std::nullopt;
}

/// @brief Pairing method on the wire (advertised in client/hello, selected in server/activate).
enum class SendspinPairMethod : uint8_t {
    PAIRING_PSK,  // Out-of-band distributed Pairing PSK
    DYNAMIC_PIN,  // Dynamic PIN via PAKE
    STATIC_PIN,   // Static PIN via PAKE
};

/// @brief Converts a SendspinPairMethod value to its protocol wire string.
/// @param method The method to convert.
/// @return Null-terminated protocol string (e.g., "pairing_psk").
inline const char* to_cstr(SendspinPairMethod method) {
    switch (method) {
        case SendspinPairMethod::PAIRING_PSK:
            return "pairing_psk";
        case SendspinPairMethod::DYNAMIC_PIN:
            return "dynamic_pin";
        case SendspinPairMethod::STATIC_PIN:
            return "static_pin";
        default:
            return "unknown";
    }
}

/// @brief Parses a wire string into a SendspinPairMethod.
/// @param str The string to parse.
/// @return The matching enum value, or std::nullopt if unrecognized.
inline std::optional<SendspinPairMethod> pair_method_from_string(const std::string& str) {
    if (str == "pairing_psk") {
        return SendspinPairMethod::PAIRING_PSK;
    }
    if (str == "dynamic_pin") {
        return SendspinPairMethod::DYNAMIC_PIN;
    }
    if (str == "static_pin") {
        return SendspinPairMethod::STATIC_PIN;
    }
    return std::nullopt;
}

/// @brief Reason a pairing attempt was aborted.
/// Mirrors PairAbortReason in aiosendspin/models/types.py.
/// The C++ client only EMITS method_not_supported (and potentially user_cancelled /
/// attempt_timeout). The PIN-specific reasons are parsed when received but never emitted
/// by the Pairing-PSK flow.
enum class PairAbortReason : uint8_t {
    ATTEMPT_TIMEOUT,          // attempt_timeout
    CONCURRENT_ATTEMPT,       // concurrent_attempt
    METHOD_NOT_SUPPORTED,     // method_not_supported
    PIN_LENGTH_UNACCEPTABLE,  // pin_length_unacceptable
    PIN_MISMATCH,             // pin_mismatch
    USER_CANCELLED,           // user_cancelled
};

/// @brief Converts a PairAbortReason to its wire string.
/// @param reason The reason to convert.
/// @return Null-terminated wire string (e.g., "method_not_supported").
inline const char* to_cstr(PairAbortReason reason) {
    switch (reason) {
        case PairAbortReason::ATTEMPT_TIMEOUT:
            return "attempt_timeout";
        case PairAbortReason::CONCURRENT_ATTEMPT:
            return "concurrent_attempt";
        case PairAbortReason::METHOD_NOT_SUPPORTED:
            return "method_not_supported";
        case PairAbortReason::PIN_LENGTH_UNACCEPTABLE:
            return "pin_length_unacceptable";
        case PairAbortReason::PIN_MISMATCH:
            return "pin_mismatch";
        case PairAbortReason::USER_CANCELLED:
            return "user_cancelled";
        default:
            return "unknown";
    }
}

/// @brief Maps the internal PairAbortReason to the public SendspinPairAbortReason.
/// @param reason The internal reason to map.
/// @return The matching SendspinPairAbortReason, or UNKNOWN if unrecognized.
inline SendspinPairAbortReason to_public_abort_reason(PairAbortReason reason) {
    switch (reason) {
        case PairAbortReason::ATTEMPT_TIMEOUT:
            return SendspinPairAbortReason::ATTEMPT_TIMEOUT;
        case PairAbortReason::CONCURRENT_ATTEMPT:
            return SendspinPairAbortReason::CONCURRENT_ATTEMPT;
        case PairAbortReason::METHOD_NOT_SUPPORTED:
            return SendspinPairAbortReason::METHOD_NOT_SUPPORTED;
        case PairAbortReason::PIN_LENGTH_UNACCEPTABLE:
            return SendspinPairAbortReason::PIN_LENGTH_UNACCEPTABLE;
        case PairAbortReason::PIN_MISMATCH:
            return SendspinPairAbortReason::PIN_MISMATCH;
        case PairAbortReason::USER_CANCELLED:
            return SendspinPairAbortReason::USER_CANCELLED;
        default:
            return SendspinPairAbortReason::UNKNOWN;
    }
}

/// @brief Parses a wire string into a PairAbortReason.
/// @param str The string to parse.
/// @return The matching enum value, or std::nullopt if unrecognized.
inline std::optional<PairAbortReason> pair_abort_reason_from_string(const std::string& str) {
    if (str == "attempt_timeout") {
        return PairAbortReason::ATTEMPT_TIMEOUT;
    }
    if (str == "concurrent_attempt") {
        return PairAbortReason::CONCURRENT_ATTEMPT;
    }
    if (str == "method_not_supported") {
        return PairAbortReason::METHOD_NOT_SUPPORTED;
    }
    if (str == "pin_length_unacceptable") {
        return PairAbortReason::PIN_LENGTH_UNACCEPTABLE;
    }
    if (str == "pin_mismatch") {
        return PairAbortReason::PIN_MISMATCH;
    }
    if (str == "user_cancelled") {
        return PairAbortReason::USER_CANCELLED;
    }
    return std::nullopt;
}

// ============================================================================
// Conversion helpers (internal use only)
// ============================================================================

// --- types.h ---

inline const char* to_cstr(SendspinClientState state) {
    switch (state) {
        case SendspinClientState::SYNCHRONIZED:
            return "synchronized";
        case SendspinClientState::EXTERNAL_SOURCE:
            return "external_source";
        case SendspinClientState::ERROR:
            // Intentional fallthrough
        default:
            return "error";
    }
}

inline const char* to_cstr(SendspinGoodbyeReason reason) {
    switch (reason) {
        case SendspinGoodbyeReason::ANOTHER_SERVER:
            return "another_server";
        case SendspinGoodbyeReason::SHUTDOWN:
            return "shutdown";
        case SendspinGoodbyeReason::RESTART:
            return "restart";
        case SendspinGoodbyeReason::USER_REQUEST:
            return "user_request";
        case SendspinGoodbyeReason::UNAUTHORIZED:
            return "unauthorized";
        case SendspinGoodbyeReason::PAIRING_REQUIRED:
            return "pairing_required";
        case SendspinGoodbyeReason::CONCURRENT_ATTEMPT:
            return "concurrent_attempt";
        case SendspinGoodbyeReason::UNPAIRED:
            return "unpaired";
        default:
            return "shutdown";
    }
}

inline const char* to_cstr(SendspinPlaybackState state) {
    switch (state) {
        case SendspinPlaybackState::PLAYING:
            return "playing";
        case SendspinPlaybackState::STOPPED:
        default:
            return "stopped";
    }
}

inline std::optional<SendspinPlaybackState> playback_state_from_string(const std::string& str) {
    if (str == "playing") {
        return SendspinPlaybackState::PLAYING;
    }
    if (str == "stopped") {
        return SendspinPlaybackState::STOPPED;
    }
    return std::nullopt;
}

inline const char* to_cstr(ConnectionTrust trust) {
    switch (trust) {
        case ConnectionTrust::USER:
            return "user";
        case ConnectionTrust::NONE:
        default:
            return "none";
    }
}

/// @brief Optional hardware and software identity fields sent in client/hello messages
struct DeviceInfoObject {
    std::optional<std::string> product_name{};
    std::optional<std::string> manufacturer{};
    std::optional<std::string> software_version{};
    std::optional<std::string> mac_address{};
};

// --- player_role.h ---

inline const char* to_cstr(SendspinCodecFormat format) {
    switch (format) {
        case SendspinCodecFormat::FLAC:
            return "flac";
        case SendspinCodecFormat::OPUS:
            return "opus";
        case SendspinCodecFormat::PCM:
            return "pcm";
        default:
            return "unsupported";
    }
}

inline std::optional<SendspinCodecFormat> codec_format_from_string(const std::string& str) {
    if (str == "flac") {
        return SendspinCodecFormat::FLAC;
    }
    if (str == "opus") {
        return SendspinCodecFormat::OPUS;
    }
    if (str == "pcm") {
        return SendspinCodecFormat::PCM;
    }
    return std::nullopt;
}

inline const char* to_cstr(SendspinPlayerCommand cmd) {
    switch (cmd) {
        case SendspinPlayerCommand::VOLUME:
            return "volume";
        case SendspinPlayerCommand::MUTE:
            return "mute";
        case SendspinPlayerCommand::SET_STATIC_DELAY:
            return "set_static_delay";
        default:
            return "unknown";
    }
}

inline std::optional<SendspinPlayerCommand> player_command_from_string(const std::string& str) {
    if (str == "volume") {
        return SendspinPlayerCommand::VOLUME;
    }
    if (str == "mute") {
        return SendspinPlayerCommand::MUTE;
    }
    if (str == "set_static_delay") {
        return SendspinPlayerCommand::SET_STATIC_DELAY;
    }
    return std::nullopt;
}

/// @brief Player capabilities advertised to the server during the hello handshake
struct PlayerSupportObject {
    std::vector<AudioSupportedFormatObject> supported_formats{};
    size_t buffer_capacity{};
    std::vector<SendspinPlayerCommand> supported_commands{};
};

/// @brief Player state reported by the client to the server in client/state messages
struct ClientPlayerStateObject {
    uint8_t volume{};
    bool muted{};
    uint16_t static_delay_ms{};
    std::vector<SendspinPlayerCommand> supported_commands{};
};

// --- controller_role.h ---

inline const char* to_cstr(SendspinControllerCommand cmd) {
    switch (cmd) {
        case SendspinControllerCommand::PLAY:
            return "play";
        case SendspinControllerCommand::PAUSE:
            return "pause";
        case SendspinControllerCommand::STOP:
            return "stop";
        case SendspinControllerCommand::NEXT:
            return "next";
        case SendspinControllerCommand::PREVIOUS:
            return "previous";
        case SendspinControllerCommand::VOLUME:
            return "volume";
        case SendspinControllerCommand::MUTE:
            return "mute";
        case SendspinControllerCommand::REPEAT_OFF:
            return "repeat_off";
        case SendspinControllerCommand::REPEAT_ONE:
            return "repeat_one";
        case SendspinControllerCommand::REPEAT_ALL:
            return "repeat_all";
        case SendspinControllerCommand::SHUFFLE:
            return "shuffle";
        case SendspinControllerCommand::UNSHUFFLE:
            return "unshuffle";
        case SendspinControllerCommand::SWITCH:
            return "switch";
        case SendspinControllerCommand::SEEK:
            return "seek";
        case SendspinControllerCommand::SEEK_RELATIVE:
            return "seek_relative";
        default:
            return "unknown";
    }
}

inline std::optional<SendspinControllerCommand> controller_command_from_string(
    const std::string& str) {
    if (str == "play") {
        return SendspinControllerCommand::PLAY;
    }
    if (str == "pause") {
        return SendspinControllerCommand::PAUSE;
    }
    if (str == "stop") {
        return SendspinControllerCommand::STOP;
    }
    if (str == "next") {
        return SendspinControllerCommand::NEXT;
    }
    if (str == "previous") {
        return SendspinControllerCommand::PREVIOUS;
    }
    if (str == "volume") {
        return SendspinControllerCommand::VOLUME;
    }
    if (str == "mute") {
        return SendspinControllerCommand::MUTE;
    }
    if (str == "repeat_off") {
        return SendspinControllerCommand::REPEAT_OFF;
    }
    if (str == "repeat_one") {
        return SendspinControllerCommand::REPEAT_ONE;
    }
    if (str == "repeat_all") {
        return SendspinControllerCommand::REPEAT_ALL;
    }
    if (str == "shuffle") {
        return SendspinControllerCommand::SHUFFLE;
    }
    if (str == "unshuffle") {
        return SendspinControllerCommand::UNSHUFFLE;
    }
    if (str == "switch") {
        return SendspinControllerCommand::SWITCH;
    }
    if (str == "seek") {
        return SendspinControllerCommand::SEEK;
    }
    if (str == "seek_relative") {
        return SendspinControllerCommand::SEEK_RELATIVE;
    }
    return std::nullopt;
}

inline const char* to_cstr(SendspinRepeatMode mode) {
    switch (mode) {
        case SendspinRepeatMode::OFF:
            return "off";
        case SendspinRepeatMode::ONE:
            return "one";
        case SendspinRepeatMode::ALL:
            return "all";
        default:
            return "off";
    }
}

inline std::optional<SendspinRepeatMode> repeat_mode_from_string(const std::string& str) {
    if (str == "off") {
        return SendspinRepeatMode::OFF;
    }
    if (str == "one") {
        return SendspinRepeatMode::ONE;
    }
    if (str == "all") {
        return SendspinRepeatMode::ALL;
    }
    return std::nullopt;
}

// --- artwork_role.h ---

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

/// @brief Artwork capabilities advertised to the server during the hello handshake
struct ArtworkSupportObject {
    std::vector<ArtworkChannelFormatObject> channels;
};

/// @brief Client request for a specific artwork channel format, sent in stream/request_format
struct ClientArtworkRequestObject {
    uint8_t channel{};
    std::optional<SendspinImageSource> source;
    std::optional<SendspinImageFormat> format;
    std::optional<uint16_t> media_width;
    std::optional<uint16_t> media_height;
};

// --- visualizer_role.h ---

inline const char* to_cstr(VisualizerDataType type) {
    switch (type) {
        case VisualizerDataType::BEAT:
            return "beat";
        case VisualizerDataType::LOUDNESS:
            return "loudness";
        case VisualizerDataType::F_PEAK:
            return "f_peak";
        case VisualizerDataType::SPECTRUM:
            return "spectrum";
        case VisualizerDataType::PEAK:
            return "peak";
        default:
            return "unknown";
    }
}

inline std::optional<VisualizerDataType> visualizer_data_type_from_string(const std::string& str) {
    if (str == "beat") {
        return VisualizerDataType::BEAT;
    }
    if (str == "loudness") {
        return VisualizerDataType::LOUDNESS;
    }
    if (str == "f_peak") {
        return VisualizerDataType::F_PEAK;
    }
    if (str == "spectrum") {
        return VisualizerDataType::SPECTRUM;
    }
    if (str == "peak") {
        return VisualizerDataType::PEAK;
    }
    return std::nullopt;
}

inline const char* to_cstr(VisualizerSpectrumScale scale) {
    switch (scale) {
        case VisualizerSpectrumScale::MEL:
            return "mel";
        case VisualizerSpectrumScale::LOG:
            return "log";
        case VisualizerSpectrumScale::LIN:
            return "lin";
        default:
            return "mel";
    }
}

inline std::optional<VisualizerSpectrumScale> visualizer_spectrum_scale_from_string(
    const std::string& str) {
    if (str == "mel") {
        return VisualizerSpectrumScale::MEL;
    }
    if (str == "log") {
        return VisualizerSpectrumScale::LOG;
    }
    if (str == "lin") {
        return VisualizerSpectrumScale::LIN;
    }
    return std::nullopt;
}

// --- metadata_role.h ---

/// @brief Wire-level delta for the metadata role's server/state object
///
/// Each field is a tri-state: outer `nullopt` means the field was absent in the delta and the
/// merged state should be left alone; outer engaged with inner `nullopt` means the server sent an
/// explicit `null` and the merged state should clear that field; outer and inner both engaged is a
/// regular value update.
struct ServerMetadataStateDelta {
    int64_t timestamp{};
    std::optional<std::optional<std::string>> title;
    std::optional<std::optional<std::string>> artist;
    std::optional<std::optional<std::string>> album_artist;
    std::optional<std::optional<std::string>> album;
    std::optional<std::optional<std::string>> artwork_url;
    std::optional<std::optional<uint16_t>> year;
    std::optional<std::optional<uint16_t>> track;
    std::optional<std::optional<MetadataProgressObject>> progress;
};

// --- color_role.h ---

/// @brief Wire-level delta for the color role's server/state object
///
/// Each field is a tri-state: outer `nullopt` means the field was absent in the delta and the
/// merged state should be left alone; outer engaged with inner `nullopt` means the server sent an
/// explicit `null` and the merged state should clear that color; outer and inner both engaged is a
/// regular value update.
struct ServerColorStateDelta {
    int64_t timestamp{};
    std::optional<std::optional<RgbColor>> background_dark;
    std::optional<std::optional<RgbColor>> background_light;
    std::optional<std::optional<RgbColor>> primary;
    std::optional<std::optional<RgbColor>> accent;
    std::optional<std::optional<RgbColor>> on_dark;
    std::optional<std::optional<RgbColor>> on_light;
};

// ============================================================================
// Message envelope structs
// ============================================================================

// ============================================================================
// Management result types
// ============================================================================

/// @brief Result code for management/result messages.
/// Mirrors ManagementResult in aiosendspin/models/types.py.
enum class ManagementResult : uint8_t {
    OK,                 // ok
    PERMISSION_DENIED,  // permission_denied
    ALREADY_EXISTS,     // already_exists
    INVALID,            // invalid
    NOT_FOUND,          // not_found
    STORAGE_EXHAUSTED,  // storage_exhausted
};

/// @brief Converts a ManagementResult to its wire string.
/// @param result The result to convert.
/// @return Null-terminated wire string (e.g., "ok").
inline const char* to_cstr(ManagementResult result) {
    switch (result) {
        case ManagementResult::OK:
            return "ok";
        case ManagementResult::PERMISSION_DENIED:
            return "permission_denied";
        case ManagementResult::ALREADY_EXISTS:
            return "already_exists";
        case ManagementResult::INVALID:
            return "invalid";
        case ManagementResult::NOT_FOUND:
            return "not_found";
        case ManagementResult::STORAGE_EXHAUSTED:
            return "storage_exhausted";
        default:
            return "invalid";
    }
}

/// @brief One entry in a list-records result.
/// Mirrors RecordSummary in aiosendspin/models/management.py.
struct RecordSummary {
    std::string psk_id{};
    std::optional<std::string>
        server_id;     ///< Present for stored-pubkey records; absent for shared.
    bool used{false};  ///< True once a server authenticated a session with this record's PSK.
};

/// @brief Pairing method config in a get-pairing-config result.
/// Mirrors PairingMethodConfig in aiosendspin/models/management.py.
struct PairingMethodConfig {
    bool enabled{false};
    /// @brief For dynamic_pin only: shortest PIN length in digits the client will accept (4-12).
    std::optional<int> min_pin_length;
    /// @brief For dynamic_pin only: true when the method is escalated to gesture-gating by its
    /// failure counter.
    std::optional<bool> escalated;
};

/// @brief Record mode config in get/set-pairing-config messages.
/// Mirrors RecordModeConfig in aiosendspin/models/management.py.
struct RecordModeConfig {
    std::string psk_id{};
};

/// @brief Unpaired access config in get/set-pairing-config messages.
struct UnpairedAccessConfig {
    std::optional<bool> enabled;
};

/// @brief Patch for the Pairing PSK method in set-pairing-config.
/// Mirrors SetPairingPskConfig in aiosendspin/models/management.py.
struct SetPairingPskConfig {
    std::optional<bool> enabled;
    std::optional<std::string> psk;  ///< 43-char base64url 32-byte PSK; replaces current.
};

/// @brief Patch for the static-PIN method in set-pairing-config.
/// Mirrors SetStaticPinConfig in aiosendspin/models/management.py.
struct SetStaticPinConfig {
    std::optional<bool> enabled;
    std::optional<std::string> pin;  ///< 8 decimal digits; replaces the configured static PIN.
};

/// @brief Patch for the dynamic-PIN method in set-pairing-config.
/// Mirrors SetDynamicPinConfig in aiosendspin/models/management.py.
/// The failure counter is not settable: escalation de-escalates only through the client's own
/// successful server_kc verification (there is no locked_out-clearing field in the spec).
struct SetDynamicPinConfig {
    std::optional<bool> enabled;
    std::optional<int> min_pin_length;  ///< Shortest PIN length in digits accepted; must be 4-12.
};

/// @brief Operation-specific data for management/result (present only on ok).
/// Mirrors ManagementResultData in aiosendspin/models/management.py.
struct ManagementResultData {
    /// Present for list-records.
    std::optional<std::vector<RecordSummary>> records;
    /// Present for get-pairing-config: pairing_psk config.
    std::optional<PairingMethodConfig> pairing_psk;
    /// Present for get-pairing-config: record mode.
    std::optional<RecordModeConfig> record_mode;
    /// Present for get-pairing-config: unpaired access.
    std::optional<UnpairedAccessConfig> unpaired_access;
    /// Present for get-pairing-config: static_pin config.
    std::optional<PairingMethodConfig> static_pin;
    /// Present for get-pairing-config: dynamic_pin config.
    std::optional<PairingMethodConfig> dynamic_pin;
};

/// @brief Storage accounting attached to management/result responses.
/// Mirrors StorageAccounting in aiosendspin/models/management.py.
struct StorageAccountingPayload {
    int free{0};                         ///< Number of free slots; always present.
    std::optional<int> capacity;         ///< Present on list-records and get-pairing-config only.
    std::optional<int> cost_individual;  ///< Present on list-records and get-pairing-config only.
    std::optional<int> cost_shared;      ///< Present on list-records and get-pairing-config only.
};

/// @brief Result payload for management/result messages.
/// Mirrors ManagementResultPayload in aiosendspin/models/management.py.
struct ManagementResultPayload {
    ManagementResult result{ManagementResult::INVALID};
    std::optional<ManagementResultData> data;  ///< Present only on ok, and only when relevant.
    std::optional<StorageAccountingPayload>
        storage;  ///< Present when the store reports accounting.
};

// ============================================================================
// Management request message structs (server -> client)
// ============================================================================

/// @brief Parsed management/add-record payload.
struct ManagementAddRecordPayload {
    std::string psk{};  ///< 43-char base64url 32-byte PSK.
    std::optional<std::string>
        server_id;  ///< Present for stored-pubkey records; absent for shared.
};

/// @brief Parsed management/remove-record payload.
struct ManagementRemoveRecordPayload {
    std::string psk_id{};
};

/// @brief Parsed management/set-pairing-config payload.
struct ManagementSetPairingConfigPayload {
    std::optional<SetPairingPskConfig> pairing_psk;
    std::optional<SetStaticPinConfig> static_pin;
    std::optional<SetDynamicPinConfig> dynamic_pin;
    std::optional<RecordModeConfig> record_mode;
    std::optional<UnpairedAccessConfig> unpaired_access;
};

/// @brief A pairing method descriptor for client/hello supported_pair_methods.
/// Optional fields are omitted from the wire when not set (omit_none semantics).
struct PairMethodDescriptor {
    SendspinPairMethod method{SendspinPairMethod::PAIRING_PSK};
    /// @brief For methods with output channels (e.g., dynamic_pin: ["display"]).
    /// Absent for pairing_psk.
    std::optional<std::vector<std::string>> out_channels;
    /// @brief Minimum PIN length the client will accept. Absent for non-PIN methods.
    std::optional<int> min_pin_length;
    /// @brief Where the operator can find the method's configured secret:
    /// 'device' | 'leaflet' | 'operator'. Informational hint for static_pin and
    /// pairing_psk only; absent for dynamic_pin.
    std::optional<std::vector<std::string>> locations;
};

/// @brief Outgoing client/hello handshake message sent at connection startup.
/// Under encryption, client_id and version are carried in client/init (the cleartext Noise
/// handshake frame), not repeated here.
struct ClientHelloMessage {
    std::string name{};
    std::optional<DeviceInfoObject> device_info{};
    std::vector<SendspinRole> supported_roles{};
    std::optional<PlayerSupportObject> player_v1_support{};
    std::optional<ArtworkSupportObject> artwork_v1_support{};
    std::optional<VisualizerSupportObject> visualizer_support{};
    ConnectionTrust trust_level{ConnectionTrust::NONE};
    bool unpaired_access_enabled{false};
    std::vector<PairMethodDescriptor> supported_pair_methods{};
};

/// @brief Outgoing client/state message reporting client playback state to the server
struct ClientStateMessage {
    SendspinClientState state{};
    std::optional<ClientPlayerStateObject> player{};
};

/// @brief Parsed server/hello handshake message received at connection startup.
/// Under encryption, server/hello carries only the server's display name; server_id comes
/// from the Noise handshake result (set on the connection at COMPLETE), and activities/
/// active_roles come from the server/activate message that follows.
struct ServerHelloMessage {
    std::string name{};
};

/// @brief Parsed server/activate message that follows server/hello.
/// Declares the server's current activity set and active roles for this connection
/// (spec "server/activate").
struct ServerActivateMessage {
    std::vector<SendspinActivity> activities{};
    std::optional<std::vector<std::string>> active_roles;  // sticky: nullopt = keep prior set
    /// From payload.pairing.method: the pairing method the server picked. nullopt when the
    /// message carries no pairing object or names an unrecognized method string.
    std::optional<SendspinPairMethod> pairing_method;
    /// From payload.pairing.pin_length: the session PIN digit count. Required on the wire
    /// when pairing_method is dynamic_pin; validated against [min_pin_length, 12] on receipt
    /// of the activation (not at server/pair-init, which carries only nonce_A).
    std::optional<int> pairing_pin_length;
};

/// @brief Parsed group/update message containing the group state delta
struct GroupUpdateMessage {
    GroupUpdateObject group;
};

/// @brief Parsed stream/start message with per-role stream parameters
struct StreamStartMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ServerArtworkStreamObject> artwork;
    std::optional<ServerVisualizerStreamObject> visualizer;
};

/// @brief Outgoing stream/request_format message used for codec, artwork, and visualizer
/// format negotiation
struct StreamRequestFormatMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ClientArtworkRequestObject> artwork;
    std::optional<VisualizerFormatRequest> visualizer;
};

/// @brief Parsed stream/end message listing which roles the stream end applies to
struct StreamEndMessage {
    std::optional<std::vector<std::string>> roles{};
};

/// @brief Parsed stream/clear message listing which roles the buffer flush applies to
struct StreamClearMessage {
    std::optional<std::vector<std::string>> roles{};
};

/// @brief Parsed pair/abort message (received or sent during a pairing exchange)
struct PairAbortMessage {
    PairAbortReason reason{PairAbortReason::METHOD_NOT_SUPPORTED};
};

// ============================================================================
// Dynamic-PIN pairing message structs (server -> client)
// ============================================================================

/// @brief Parsed server/pair-init payload.
/// Carries only nonce_A (32 raw bytes, base64url-encoded on the wire, 43 chars); the session
/// pin_length arrives earlier, in the activation's pairing object. Sent by the server in
/// response to client/pair-init (which carried commit_B).
struct ServerPairInitPayload {
    std::array<uint8_t, 32> nonce_a{};  ///< 32-byte server nonce decoded from base64url.
};

/// @brief Parsed server/pair-auth payload.
/// Carries pake_msg_1 (32 raw bytes, base64url-encoded, 43 chars): the server's CPace share.
struct ServerPairAuthPayload {
    std::array<uint8_t, 32> pake_msg_1{};  ///< Server CPace public share.
};

/// @brief Parsed server/pair-confirm payload.
/// Carries server_kc (64 raw bytes, base64url-encoded, 86 chars): the server confirmation tag.
struct ServerPairConfirmPayload {
    std::array<uint8_t, 64> server_kc{};  ///< Server CPace confirmation tag (HMAC-SHA-512).
};

// ============================================================================
// Protocol functions
// ============================================================================

/// @brief Determines the message type of an incoming server-to-client JSON message
/// @param root Parsed JSON object from the message.
/// @return The matching message type, or UNKNOWN if not recognized.
SendspinServerToClientMessageType determine_message_type(JsonObject root);

/// @brief Parses a server/hello JSON message into the provided struct.
/// Under encryption, only the name field is parsed; server_id comes from the Noise
/// handshake result, not from server/hello.
/// @param root Parsed JSON object from the message.
/// @param hello_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_server_hello_message(JsonObject root, ServerHelloMessage* hello_msg);

/// @brief Parses a server/activate JSON message into the provided struct.
/// @param root Parsed JSON object from the message.
/// @param activate_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_server_activate_message(JsonObject root, ServerActivateMessage* activate_msg);

/// @brief Parses a server/time JSON message and computes time offset and max error
/// @param root Parsed JSON object from the message.
/// @param timestamp Client timestamp when the message was received (microseconds).
/// @param offset [out] Computed time offset between server and client clocks (microseconds).
/// @param max_error [out] Upper bound on clock error from the round-trip (microseconds).
/// @return true if parsing and computation succeeded, false otherwise.
bool process_server_time_message(JsonObject root, int64_t timestamp, int64_t* offset,
                                 int64_t* max_error);

/// @brief Parses a group/update JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param group_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_group_update_message(JsonObject root, GroupUpdateMessage* group_msg);

/// @brief Merges a GroupUpdateObject delta into the current group state
/// @param current [out] Current group state to update in place.
/// @param updates Delta object containing only the fields that changed.
void apply_group_update_deltas(GroupUpdateObject* current, const GroupUpdateObject& updates);

/// @brief Parses a server/command JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param cmd_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_server_command_message(JsonObject root, ServerCommandMessage* cmd_msg);

/// @brief Parses the metadata section of a server/state JSON message
///
/// The server/state sections are parsed individually rather than into one aggregate struct: the
/// caller runs on the network task, whose stack is small on ESP-IDF (the httpd task gets 4 KB), and
/// an aggregate would keep every section's storage live in the caller's frame for the whole parse.
/// Each function fills a caller-owned struct in place and reports whether that section was present.
///
/// @param root Parsed JSON object from the message.
/// @param metadata_delta [out] Struct to populate with the parsed delta.
/// @return true if the message carried a metadata section that parsed successfully.
bool process_server_state_metadata(JsonObject root, ServerMetadataStateDelta* metadata_delta);

/// @brief Parses the color section of a server/state JSON message
/// @param root Parsed JSON object from the message.
/// @param color_delta [out] Struct to populate with the parsed delta.
/// @return true if the message carried a color section that parsed successfully.
bool process_server_state_color(JsonObject root, ServerColorStateDelta* color_delta);

/// @brief Parses the controller section of a server/state JSON message
/// @param root Parsed JSON object from the message.
/// @param controller_state [out] Struct to populate with parsed fields.
/// @return true if the message carried a controller section that parsed successfully.
bool process_server_state_controller(JsonObject root,
                                     ServerStateControllerObject* controller_state);

/// @brief Parses a stream/start JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param stream_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_stream_start_message(JsonObject root, StreamStartMessage* stream_msg);

/// @brief Parses a stream/end JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param end_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_stream_end_message(JsonObject root, StreamEndMessage* end_msg);

/// @brief Parses a stream/clear JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param clear_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_stream_clear_message(JsonObject root, StreamClearMessage* clear_msg);

/// @brief Merges a ServerMetadataStateDelta into the current metadata state
/// @param current [out] Current metadata state to update in place.
/// @param delta Wire-level delta containing only the fields that changed; fields with an explicit
///              `null` on the wire arrive as outer-engaged + inner-`nullopt` and clear the
///              corresponding merged field.
void apply_metadata_state_deltas(ServerMetadataStateObject* current,
                                 const ServerMetadataStateDelta& delta);

/// @brief Merges a ServerColorStateDelta into the current color state
/// @param current [out] Current color state to update in place.
/// @param delta Wire-level delta containing only the fields that changed; fields with an explicit
///              `null` on the wire arrive as outer-engaged + inner-`nullopt` and clear the
///              corresponding merged field.
void apply_color_state_deltas(ServerColorStateObject* current, const ServerColorStateDelta& delta);

/// @brief Formats a client hello message as a JSON string for sending to the server
/// @param msg Message to serialize.
/// @return Hello message serialized into JSON format.
std::string format_client_hello_message(const ClientHelloMessage* msg);

/// @brief Formats a client state message as a JSON string for sending to the server
/// @param msg Message to serialize.
/// @return State message serialized into JSON format.
std::string format_client_state_message(const ClientStateMessage* msg);

/// @brief Formats a stream/request_format message as a JSON string for sending to the server
/// @param msg Message to serialize.
/// @return Stream request format message serialized into JSON format.
std::string format_stream_request_format_message(const StreamRequestFormatMessage* msg);

/// @brief Formats a client/goodbye message as a JSON string for sending to the server
/// @param reason The reason for disconnecting.
/// @return Goodbye message serialized into JSON format.
std::string format_client_goodbye_message(SendspinGoodbyeReason reason);

/// Buffer size for format_client_time_message(). Fits the longest possible message:
/// prefix (52) + '-' (1) + 19 digits + suffix (2) + padding = 75 bytes, rounded up.
static constexpr size_t TIME_MESSAGE_BUF_SIZE = 96;

/// @brief Formats a client/time JSON message into a caller-supplied buffer
///
/// Hot path on the time-sync send side: avoids any heap allocation by writing the fixed-shape
/// message directly into the caller's stack buffer. A 96-byte buffer is always large enough.
/// @param buf Destination buffer.
/// @param cap Capacity of `buf` in bytes (recommend >= 96).
/// @param client_transmitted The client transmit timestamp (microseconds). Should be captured
///                           as close as possible to the actual wire send.
/// @return Number of bytes written (excluding any null terminator), or 0 on error.
size_t format_client_time_message(char* buf, size_t cap, int64_t client_transmitted);

/// @brief Formats a client/command message as a JSON string for sending to the server
/// @param cmd The playback command plus any command-specific parameters. Only the parameter
/// relevant to the command is serialized (e.g. position_ms for SEEK); others are ignored.
/// @return Command message serialized into JSON format.
std::string format_client_command_message(const ClientCommandControllerObject& cmd);

/// @brief Formats a client/pair-finalize message carrying long_term_psk directly (Pairing PSK
/// flow only). The PSK is 32 raw bytes, base64url-encoded (no padding, 43 chars).
/// @param psk 32-byte long-term PSK to embed in the message.
/// @return JSON string for the client/pair-finalize message.
std::string format_client_pair_finalize_message(const std::array<uint8_t, 32>& psk);

/// @brief Formats a client/pair-finalize message carrying wrapped_psk (PIN flows only; see
/// spec "PSK Wrapping"). wrapped_psk is 48 raw bytes, base64url-encoded (no padding, 64
/// chars).
/// @param wrapped_psk 48-byte wrapped PSK (ciphertext || tag) to embed in the message.
/// @return JSON string for the client/pair-finalize message.
std::string format_client_pair_finalize_wrapped_message(const std::array<uint8_t, 48>& wrapped_psk);

/// @brief Formats a pair/abort message as a JSON string.
/// Sent by the client when it cannot proceed with the selected pairing method.
/// @param reason The abort reason.
/// @return JSON string for the pair/abort message.
std::string format_pair_abort_message(PairAbortReason reason);

/// @brief Parses a pair/abort JSON message into the provided struct.
/// @param root Parsed JSON object from the message.
/// @param abort_msg [out] Struct to populate with the parsed abort reason.
/// @return true if parsing succeeded, false on missing or unrecognized reason.
bool process_pair_abort_message(JsonObject root, PairAbortMessage* abort_msg);

// ============================================================================
// Dynamic-PIN pairing protocol functions
// ============================================================================

/// @brief Parses a server/pair-init JSON message into the provided struct.
/// Validates base64url encoding and decoded length of nonce_A (must be 32 bytes).
/// @param root Parsed JSON object.
/// @param payload [out] Struct to populate; nullptr for validation-only.
/// @return true if the message is well-formed, false otherwise.
bool process_server_pair_init_message(JsonObject root, ServerPairInitPayload* payload);

/// @brief Parses a server/pair-auth JSON message into the provided struct.
/// Validates base64url encoding and decoded length of pake_msg_1 (must be 32 bytes).
/// @param root Parsed JSON object.
/// @param payload [out] Struct to populate; nullptr for validation-only.
/// @return true if the message is well-formed, false otherwise.
bool process_server_pair_auth_message(JsonObject root, ServerPairAuthPayload* payload);

/// @brief Parses a server/pair-confirm JSON message into the provided struct.
/// Validates base64url encoding and decoded length of server_kc (must be 64 bytes).
/// @param root Parsed JSON object.
/// @param payload [out] Struct to populate; nullptr for validation-only.
/// @return true if the message is well-formed, false otherwise.
bool process_server_pair_confirm_message(JsonObject root, ServerPairConfirmPayload* payload);

/// @brief Formats a client/pair-pending message as a JSON string.
/// Sent immediately on receiving a pairing server/activate whose attempt is gesture-gated while
/// no pairing window is open; client/pair-init follows once a window opens. Does not start the
/// attempt or its timeout.
/// @param pairing_index Count of pairing server/activate messages received since the last Noise
///                      handshake.
/// @return JSON string for the client/pair-pending message.
std::string format_client_pair_pending_message(uint32_t pairing_index);

/// @brief Formats a client/pair-init message as a JSON string.
/// Starts the dynamic-PIN attempt; carries commit_B = SHA-256(LABEL || nonce_B) and the
/// required pairing_index counter (spec "Pairing index").
/// @param commit_b 32-byte commit_B value to embed (base64url-encoded on the wire).
/// @param pairing_index Count of pairing server/activate messages received since the last Noise
///                      handshake (see SendspinConnection::get_pairing_index()).
/// @return JSON string for the client/pair-init message.
std::string format_client_pair_init_message(const std::array<uint8_t, 32>& commit_b,
                                            uint32_t pairing_index);

/// @brief Formats a client/pair-init message with only pairing_index (static PIN).
/// Static PIN carries no commit_B (mirrors the reference's ClientPairInitPayload with omit_none:
/// commit_B is unset). Sent after the operator confirms the pairing-window gesture, before
/// starting CPace RESPONDER.
/// @param pairing_index Count of pairing server/activate messages received since the last Noise
///                      handshake.
/// @return JSON string for the client/pair-init message with only pairing_index set.
std::string format_client_pair_init_message(uint32_t pairing_index);

/// @brief Formats a client/pair-auth message as a JSON string.
/// Sent in response to server/pair-auth; carries the client's CPace public share.
/// @param pake_msg_2 32-byte client CPace public share (base64url-encoded on the wire).
/// @return JSON string for the client/pair-auth message.
std::string format_client_pair_auth_message(const std::array<uint8_t, 32>& pake_msg_2);

/// @brief Formats a client/pair-confirm message as a JSON string.
/// Sent in response to server/pair-confirm; carries client_kc and nonce_B.
/// @param client_kc 64-byte client CPace confirmation tag (base64url-encoded on the wire).
/// @param nonce_b   32-byte client nonce (base64url-encoded on the wire).
/// @return JSON string for the client/pair-confirm message.
std::string format_client_pair_confirm_message(const std::array<uint8_t, 64>& client_kc,
                                               const std::array<uint8_t, 32>& nonce_b);

/// @brief Formats a client/pair-confirm message with no nonce (static PIN).
/// Static PIN carries client_kc only (no nonce_B opening, since there is no commit_B to open).
/// @param client_kc 64-byte client CPace confirmation tag (base64url-encoded on the wire).
/// @return JSON string for the client/pair-confirm message with client_kc only.
std::string format_client_pair_confirm_message(const std::array<uint8_t, 64>& client_kc);

// ============================================================================
// Management protocol functions
// ============================================================================

/// @brief Parses a management/add-record JSON message payload into the provided struct.
/// @param root Parsed JSON object from the message.
/// @param payload [out] Struct to populate with the parsed psk and optional server_id.
/// @return true if parsing succeeded (psk field present), false otherwise.
bool process_management_add_record_message(JsonObject root, ManagementAddRecordPayload* payload);

/// @brief Parses a management/remove-record JSON message payload into the provided struct.
/// @param root Parsed JSON object from the message.
/// @param payload [out] Struct to populate with the parsed psk_id.
/// @return true if parsing succeeded (psk_id field present), false otherwise.
bool process_management_remove_record_message(JsonObject root,
                                              ManagementRemoveRecordPayload* payload);

/// @brief Parses a management/set-pairing-config JSON message payload into the provided struct.
/// @param root Parsed JSON object from the message.
/// @param payload [out] Struct to populate.
/// @return Always returns true (all fields are optional; only fields present with the right JSON
///         type are populated, leaving the corresponding optional unset otherwise).
bool process_management_set_pairing_config_message(JsonObject root,
                                                   ManagementSetPairingConfigPayload* payload);

/// @brief Formats a management/result message as a JSON string for sending to the server.
/// @param payload The result payload to serialize.
/// @return JSON string for the management/result message.
std::string format_management_result_message(const ManagementResultPayload& payload);

}  // namespace sendspin
