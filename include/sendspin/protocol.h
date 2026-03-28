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

#include <ArduinoJson.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Common types (always available)
// ============================================================================

enum class SendspinClientState {
    SYNCHRONIZED,
    ERROR,
    EXTERNAL_SOURCE,
};

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

// Binary message ID structure:
// Typically bits 7-2 for role type, bits 1-0 for message slot (4 IDs per role)
// Roles with expanded allocations use bits 2-0 for message slot (8 IDs)
enum SendspinBinaryRole : uint8_t {
    SENDSPIN_ROLE_PLAYER = 1,      // 000001xx (4-7)
    SENDSPIN_ROLE_ARTWORK = 2,     // 000010xx (8-11)
    SENDSPIN_ROLE_VISUALIZER = 4,  // 00010xxx (16-23) - expanded allocation
};

// Helper to extract role from binary message type (for standard 4-slot roles)
inline uint8_t get_binary_role(uint8_t type) {
    return type >> 2;
}
// Helper to extract slot from binary message type (for standard 4-slot roles)
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

inline std::optional<SendspinConnectionReason> connection_reason_from_string(
    const std::string& str) {
    if (str == "discovery")
        return SendspinConnectionReason::DISCOVERY;
    if (str == "playback")
        return SendspinConnectionReason::PLAYBACK;
    return std::nullopt;
}

enum class SendspinGoodbyeReason {
    ANOTHER_SERVER,
    SHUTDOWN,
    RESTART,
    USER_REQUEST,
};

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

inline std::optional<SendspinGoodbyeReason> goodbye_reason_from_string(const std::string& str) {
    if (str == "another_server")
        return SendspinGoodbyeReason::ANOTHER_SERVER;
    if (str == "shutdown")
        return SendspinGoodbyeReason::SHUTDOWN;
    if (str == "restart")
        return SendspinGoodbyeReason::RESTART;
    if (str == "user_request")
        return SendspinGoodbyeReason::USER_REQUEST;
    return std::nullopt;
}

struct DeviceInfoObject {
    std::optional<std::string> product_name;
    std::optional<std::string> manufacturer;
    std::optional<std::string> software_version;
};

struct ServerInformationObject {
    std::string server_id;
    std::string name;
};

enum class SendspinPlaybackState {
    PLAYING,
    STOPPED,
};

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
    if (str == "playing")
        return SendspinPlaybackState::PLAYING;
    if (str == "stopped")
        return SendspinPlaybackState::STOPPED;
    return std::nullopt;
}

struct GroupUpdateObject {
    std::optional<SendspinPlaybackState> playback_state;
    std::optional<std::string> group_id;
    std::optional<std::string> group_name;
};

struct TimeTransmittedReplacement {
    int64_t transmitted_time = 0;
    int64_t actual_transmit_time = 0;
};

// ============================================================================
// Forward declarations for message structs (defined in src/protocol_messages.h)
// ============================================================================

struct ClientHelloMessage;
struct ClientStateMessage;
struct ClientCommandMessage;
struct ClientGoodbyeMessage;
struct ServerHelloMessage;
struct ServerStateMessage;
struct ServerCommandMessage;
struct GroupUpdateMessage;
struct StreamStartMessage;
struct StreamRequestFormatMessage;
struct StreamEndMessage;
struct StreamClearMessage;

// Forward declarations for role-specific types used in function signatures
struct ServerMetadataStateObject;
enum class SendspinControllerCommand;

// ============================================================================
// Protocol functions
// ============================================================================

SendspinServerToClientMessageType determine_message_type(JsonObject root);

bool process_server_hello_message(JsonObject root, ServerHelloMessage* hello_msg);
bool process_server_time_message(JsonObject root, int64_t timestamp,
                                 TimeTransmittedReplacement time_replacement, int64_t* offset,
                                 int64_t* max_error);
bool process_group_update_message(JsonObject root, GroupUpdateMessage* group_msg);
void apply_group_update_deltas(GroupUpdateObject* current, const GroupUpdateObject& updates);

bool process_server_command_message(JsonObject root, ServerCommandMessage* cmd_msg);

bool process_server_state_message(JsonObject root, ServerStateMessage* state_msg);

bool process_stream_start_message(JsonObject root, StreamStartMessage* stream_msg);
bool process_stream_end_message(JsonObject root, StreamEndMessage* end_msg);
bool process_stream_clear_message(JsonObject root, StreamClearMessage* clear_msg);

void apply_metadata_state_deltas(ServerMetadataStateObject* current,
                                 const ServerMetadataStateObject& updates);

/// @brief Formats a client hello message as a JSON string for sending to the server.
/// @param msg (ClientHelloMessage *) Message to serialize
/// @return (std::string) Hello message serialized into JSON format
std::string format_client_hello_message(const ClientHelloMessage* msg);

std::string format_client_state_message(const ClientStateMessage* msg);

std::string format_stream_request_format_message(const StreamRequestFormatMessage* msg);

std::string format_client_goodbye_message(SendspinGoodbyeReason reason);

std::string format_client_command_message(SendspinControllerCommand command,
                                          std::optional<uint8_t> volume = std::nullopt,
                                          std::optional<bool> mute = std::nullopt);

}  // namespace sendspin
