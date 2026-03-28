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

#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

// ============================================================================
// Common types
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

}  // namespace sendspin
