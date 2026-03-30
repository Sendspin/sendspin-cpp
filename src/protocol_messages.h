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

// Binary message ID structure:
// Typically bits 7-2 for role type, bits 1-0 for message slot (4 IDs per role)
// Roles with expanded allocations use bits 2-0 for message slot (8 IDs)
enum SendspinBinaryRole : uint8_t {
    SENDSPIN_ROLE_PLAYER = 1,      // 000001xx (4-7)
    SENDSPIN_ROLE_ARTWORK = 2,     // 000010xx (8-11)
    SENDSPIN_ROLE_VISUALIZER = 4,  // 00010xxx (16-23) - expanded allocation
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

// Common binary message types
enum SendspinBinaryType : uint8_t {
    SENDSPIN_BINARY_PLAYER_AUDIO = 4,      // Player slot 0
    SENDSPIN_BINARY_ARTWORK_IMAGE = 8,     // Artwork slot 0
    SENDSPIN_BINARY_VISUALIZER = 16,       // Visualizer data (loudness, f_peak, spectrum)
    SENDSPIN_BINARY_VISUALIZER_BEAT = 17,  // Visualizer beat events
};

enum class SendspinServerToClientMessageType {
    SERVER_HELLO,
    SERVER_TIME,
    SERVER_STATE,
    SERVER_COMMAND,
    STREAM_START,
    STREAM_END,
    STREAM_CLEAR,
    GROUP_UPDATE,
    UNKNOWN,
};

enum class SendspinClientToServerMessageType {
    CLIENT_HELLO,
    CLIENT_TIME,
    CLIENT_STATE,
    CLIENT_COMMAND,
    STREAM_REQUEST_FORMAT,
    CLIENT_GOODBYE,
};

enum class SendspinRole {
    PLAYER,
    CONTROLLER,
    METADATA,
    ARTWORK,
    VISUALIZER,
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

enum class SendspinConnectionReason {
    DISCOVERY,
    PLAYBACK,
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
    if (str == "discovery")
        return SendspinConnectionReason::DISCOVERY;
    if (str == "playback")
        return SendspinConnectionReason::PLAYBACK;
    return std::nullopt;
}

struct TimeTransmittedReplacement {
    int64_t transmitted_time = 0;
    int64_t actual_transmit_time = 0;
};

// ============================================================================
// Message envelope structs
// ============================================================================

struct ClientHelloMessage {
    std::string client_id;
    std::string name;
    std::optional<DeviceInfoObject> device_info;
    uint8_t version;
    std::vector<SendspinRole> supported_roles;
    std::optional<PlayerSupportObject> player_v1_support;
    std::optional<ArtworkSupportObject> artwork_v1_support;
    std::optional<VisualizerSupportObject> visualizer_support;
};

struct ClientStateMessage {
    SendspinClientState state;
    std::optional<ClientPlayerStateObject> player;
};

struct ClientCommandMessage {
    std::optional<ClientCommandControllerObject> controller;
};

struct ClientGoodbyeMessage {
    SendspinGoodbyeReason reason;
};

struct ServerStateMessage {
    std::optional<ServerStateControllerObject> controller;
    std::optional<ServerMetadataStateObject> metadata;
};

struct ServerHelloMessage {
    ServerInformationObject server;
    uint16_t version;
    std::vector<std::string> active_roles;
    SendspinConnectionReason connection_reason;
};

struct GroupUpdateMessage {
    GroupUpdateObject group;
};

struct StreamStartMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ServerArtworkStreamObject> artwork;
    std::optional<ServerVisualizerStreamObject> visualizer;
};

struct StreamRequestFormatMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ClientArtworkRequestObject> artwork;
};

struct StreamEndMessage {
    std::optional<std::vector<std::string>> roles;
};

struct StreamClearMessage {
    std::optional<std::vector<std::string>> roles;
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
/// @param time_replacement Actual send time replacement from the outgoing time message.
/// @param offset [out] Computed time offset between server and client clocks (microseconds).
/// @param max_error [out] Upper bound on clock error from the round-trip (microseconds).
/// @return true if parsing and computation succeeded, false otherwise.
bool process_server_time_message(JsonObject root, int64_t timestamp,
                                 TimeTransmittedReplacement time_replacement, int64_t* offset,
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

/// @brief Formats a client/command message as a JSON string for sending to the server
/// @param command The playback command to send.
/// @param volume Optional volume level to include (0-100).
/// @param mute Optional mute state to include.
/// @return Command message serialized into JSON format.
std::string format_client_command_message(SendspinControllerCommand command,
                                          std::optional<uint8_t> volume = std::nullopt,
                                          std::optional<bool> mute = std::nullopt);

}  // namespace sendspin
