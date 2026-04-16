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

#include "sendspin/artwork_role.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/types.h"
#include "sendspin/visualizer_role.h"
#include <ArduinoJson.h>

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
enum SendspinBinaryRole : uint8_t {
    SENDSPIN_ROLE_PLAYER = 1,      // 000001xx (IDs 4-7)
    SENDSPIN_ROLE_ARTWORK = 2,     // 000010xx (IDs 8-11)
    SENDSPIN_ROLE_VISUALIZER = 4,  // 000100xx (IDs 16-19)
};

/// @brief Extracts the role field from a standard 4-slot binary message type byte
/// @param type Binary message type byte.
/// @return Role portion of the type (bits 7-2).
inline uint8_t get_binary_role(uint8_t type) {
    return type >> 2;
}
/// @brief Extracts the slot field from a standard 4-slot binary message type byte
/// @param type Binary message type byte.
/// @return Slot portion of the type (bits 1-0).
inline uint8_t get_binary_slot(uint8_t type) {
    return type & 0x03;
}

/// @brief Binary message type byte values for known message kinds
enum SendspinBinaryType : uint8_t {
    SENDSPIN_BINARY_PLAYER_AUDIO = 4,      // Player slot 0: encoded audio chunk
    SENDSPIN_BINARY_ARTWORK_IMAGE = 8,     // Artwork slot 0: image data
    SENDSPIN_BINARY_VISUALIZER = 16,       // Visualizer slot 0: loudness, f_peak, spectrum
    SENDSPIN_BINARY_VISUALIZER_BEAT = 17,  // Visualizer slot 1: beat events
};

/// @brief JSON message types sent from the server to the client
enum class SendspinServerToClientMessageType : uint8_t {
    SERVER_HELLO,    // server/hello handshake
    SERVER_TIME,     // server/time clock sync reply
    SERVER_STATE,    // server/state playback state update
    SERVER_COMMAND,  // server/command player command
    STREAM_START,    // stream/start new stream parameters
    STREAM_END,      // stream/end normal stream completion
    STREAM_CLEAR,    // stream/clear immediate buffer flush
    GROUP_UPDATE,    // group/update group membership change
    UNKNOWN,         // Unrecognized message type
};

/// @brief Protocol role identifiers used in hello messages and role negotiation
enum class SendspinRole : uint8_t {
    PLAYER,      // Audio playback role
    CONTROLLER,  // Playback command/state role
    METADATA,    // Track metadata role
    ARTWORK,     // Album artwork role
    VISUALIZER,  // Audio visualization role
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
            return "visualizer@_draft_r1";
        default:
            return "unknown";
    }
}

/// @brief Connection reason reported in server/hello messages
enum class SendspinConnectionReason : uint8_t {
    DISCOVERY,  // Server connected for device discovery only
    PLAYBACK,   // Server connected for active audio playback
};

/// @brief Converts a SendspinConnectionReason value to its protocol string representation
/// @param reason The connection reason to convert.
/// @return Null-terminated string representation of the reason.
inline const char* to_cstr(SendspinConnectionReason reason) {
    switch (reason) {
        case SendspinConnectionReason::DISCOVERY:
            return "discovery";
        case SendspinConnectionReason::PLAYBACK:
            return "playback";
        default:
            return "discovery";
    }
}

/// @brief Parses a protocol string into a SendspinConnectionReason
/// @param str The string to parse.
/// @return The matching enum value, or std::nullopt if the string is unrecognized.
inline std::optional<SendspinConnectionReason> connection_reason_from_string(
    const std::string& str) {
    if (str == "discovery") {
        return SendspinConnectionReason::DISCOVERY;
    }
    if (str == "playback") {
        return SendspinConnectionReason::PLAYBACK;
    }
    return std::nullopt;
}

// ============================================================================
// Conversion helpers (moved from public headers — internal use only)
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

/// @brief Optional hardware and software identity fields sent in client/hello messages
struct DeviceInfoObject {
    std::optional<std::string> product_name{};
    std::optional<std::string> manufacturer{};
    std::optional<std::string> software_version{};
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
    return std::nullopt;
}

/// @brief A playback command sent from the client to the server via client/command messages
struct ClientCommandControllerObject {
    SendspinControllerCommand command{};
    std::optional<uint8_t> volume;
    std::optional<bool> mute;
};

// --- metadata_role.h ---

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
        default:
            return "unknown";
    }
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

// ============================================================================
// Message envelope structs
// ============================================================================

/// @brief Outgoing client/hello handshake message sent at connection startup
struct ClientHelloMessage {
    std::string client_id{};
    std::string name{};
    std::optional<DeviceInfoObject> device_info{};
    uint8_t version{};
    std::vector<SendspinRole> supported_roles{};
    std::optional<PlayerSupportObject> player_v1_support{};
    std::optional<ArtworkSupportObject> artwork_v1_support{};
    std::optional<VisualizerSupportObject> visualizer_support{};
};

/// @brief Outgoing client/state message reporting client playback state to the server
struct ClientStateMessage {
    SendspinClientState state{};
    std::optional<ClientPlayerStateObject> player{};
};

/// @brief Outgoing client/command message carrying a playback command to the server
struct ClientCommandMessage {
    std::optional<ClientCommandControllerObject> controller;
};

/// @brief Parsed server/state message containing per-role state updates
struct ServerStateMessage {
    std::optional<ServerStateControllerObject> controller;
    std::optional<ServerMetadataStateObject> metadata;
};

/// @brief Parsed server/hello handshake message received at connection startup
struct ServerHelloMessage {
    ServerInformationObject server{};
    uint16_t version{};
    std::vector<std::string> active_roles{};
    SendspinConnectionReason connection_reason{};
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

/// @brief Outgoing stream/request_format message used for codec and artwork format negotiation
struct StreamRequestFormatMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ClientArtworkRequestObject> artwork;
};

/// @brief Parsed stream/end message listing which roles the stream end applies to
struct StreamEndMessage {
    std::optional<std::vector<std::string>> roles{};
};

/// @brief Parsed stream/clear message listing which roles the buffer flush applies to
struct StreamClearMessage {
    std::optional<std::vector<std::string>> roles{};
};

// ============================================================================
// Protocol functions
// ============================================================================

/// @brief Determines the message type of an incoming server-to-client JSON message
/// @param root Parsed JSON object from the message.
/// @return The matching message type, or UNKNOWN if not recognized.
SendspinServerToClientMessageType determine_message_type(JsonObject root);

/// @brief Parses a server/hello JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param hello_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_server_hello_message(JsonObject root, ServerHelloMessage* hello_msg);

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

/// @brief Parses a server/state JSON message into the provided struct
/// @param root Parsed JSON object from the message.
/// @param state_msg [out] Struct to populate with parsed fields.
/// @return true if parsing succeeded, false on missing required fields.
bool process_server_state_message(JsonObject root, ServerStateMessage* state_msg);

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

/// @brief Merges a ServerMetadataStateObject delta into the current metadata state
/// @param current [out] Current metadata state to update in place.
/// @param updates Delta object containing only the fields that changed.
void apply_metadata_state_deltas(ServerMetadataStateObject* current,
                                 const ServerMetadataStateObject& updates);

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
/// @param command The playback command to send.
/// @param volume Optional volume level to include (0-100).
/// @param mute Optional mute state to include.
/// @return Command message serialized into JSON format.
std::string format_client_command_message(SendspinControllerCommand command,
                                          std::optional<uint8_t> volume = std::nullopt,
                                          std::optional<bool> mute = std::nullopt);

}  // namespace sendspin
