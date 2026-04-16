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

/// @brief Reason sent in a client/goodbye message when disconnecting
enum class SendspinGoodbyeReason : uint8_t {
    ANOTHER_SERVER,  // Client is switching to another server
    SHUTDOWN,        // Client is shutting down
    RESTART,         // Client is restarting
    USER_REQUEST,    // User explicitly requested disconnect
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

/// @brief Group membership and playback state delta received in group/update messages
struct GroupUpdateObject {
    std::optional<SendspinPlaybackState> playback_state{};
    std::optional<std::string> group_id{};
    std::optional<std::string> group_name{};
};

}  // namespace sendspin
