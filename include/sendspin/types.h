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

/// @file types.h
/// @brief Shared types used across the Sendspin client and role APIs

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

// ============================================================================
// Common types
// ============================================================================

/// @brief Client playback state reported to the server
enum class SendspinClientState : uint8_t {
    SYNCHRONIZED,     // Client is synchronized and playing from the server
    ERROR,            // Client encountered a playback error
    EXTERNAL_SOURCE,  // Client is playing from a non-Sendspin source
};

/// @brief Converts a SendspinClientState value to its protocol string representation
/// @param state The client state to convert.
/// @return Null-terminated string representation of the state.
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

/// @brief Reason sent in a client/goodbye message when disconnecting
enum class SendspinGoodbyeReason : uint8_t {
    ANOTHER_SERVER,  // Client is switching to another server
    SHUTDOWN,        // Client is shutting down
    RESTART,         // Client is restarting
    USER_REQUEST,    // User explicitly requested disconnect
};

/// @brief Converts a SendspinGoodbyeReason value to its protocol string representation
/// @param reason The goodbye reason to convert.
/// @return Null-terminated string representation of the reason.
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

/// @brief Optional hardware and software identity fields sent in client/hello messages
struct DeviceInfoObject {
    std::optional<std::string> product_name{};
    std::optional<std::string> manufacturer{};
    std::optional<std::string> software_version{};
};

/// @brief Server identity fields received in server/hello messages
struct ServerInformationObject {
    std::string server_id{};
    std::string name{};
};

/// @brief Overall group playback state
enum class SendspinPlaybackState : uint8_t {
    PLAYING,  // Group is actively playing
    STOPPED,  // Group playback is stopped
};

/// @brief Converts a SendspinPlaybackState value to its protocol string representation
/// @param state The playback state to convert.
/// @return Null-terminated string representation of the state.
inline const char* to_cstr(SendspinPlaybackState state) {
    switch (state) {
        case SendspinPlaybackState::PLAYING:
            return "playing";
        case SendspinPlaybackState::STOPPED:
        default:
            return "stopped";
    }
}

/// @brief Parses a protocol string into a SendspinPlaybackState
/// @param str The string to parse.
/// @return The matching enum value, or std::nullopt if the string is unrecognized.
inline std::optional<SendspinPlaybackState> playback_state_from_string(const std::string& str) {
    if (str == "playing") {
        return SendspinPlaybackState::PLAYING;
    }
    if (str == "stopped") {
        return SendspinPlaybackState::STOPPED;
    }
    return std::nullopt;
}

/// @brief Group membership and playback state delta received in group/update messages
struct GroupUpdateObject {
    std::optional<SendspinPlaybackState> playback_state{};
    std::optional<std::string> group_id{};
    std::optional<std::string> group_name{};
};

}  // namespace sendspin
