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
#include <memory>
#include <optional>
#include <string>

namespace sendspin {

class SendspinClient;
struct ClientBridge;
struct ClientHelloMessage;

// ============================================================================
// Metadata types
// ============================================================================

struct MetadataProgressObject {
    uint32_t track_progress;
    uint32_t track_duration;
    uint32_t playback_speed;
};

enum class SendspinRepeatMode {
    OFF,
    ONE,
    ALL,
};

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
    if (str == "off")
        return SendspinRepeatMode::OFF;
    if (str == "one")
        return SendspinRepeatMode::ONE;
    if (str == "all")
        return SendspinRepeatMode::ALL;
    return std::nullopt;
}

struct ServerMetadataStateObject {
    int64_t timestamp;
    std::optional<std::string> title;
    std::optional<std::string> artist;
    std::optional<std::string> album_artist;
    std::optional<std::string> album;
    std::optional<std::string> artwork_url;
    std::optional<uint16_t> year;
    std::optional<uint16_t> track;
    std::optional<MetadataProgressObject> progress;
    std::optional<SendspinRepeatMode> repeat;
    std::optional<bool> shuffle;
};

/// @brief Listener for metadata role events. All methods fire on the main loop thread.
class MetadataRoleListener {
public:
    virtual ~MetadataRoleListener() = default;

    /// @brief Called when metadata is updated by the server.
    virtual void on_metadata(const ServerMetadataStateObject& /*metadata*/) {}
};

/// @brief Metadata role: provides track metadata and progress information.
class MetadataRole {
    friend class SendspinClient;

public:
    MetadataRole();
    ~MetadataRole();

    /// @brief Sets the listener for metadata events. The listener must outlive this role.
    void set_listener(MetadataRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Returns the interpolated track progress in milliseconds.
    uint32_t get_track_progress_ms() const;

    /// @brief Returns the track duration in milliseconds. 0 means unknown/live.
    uint32_t get_track_duration_ms() const;

private:
    void attach(ClientBridge* bridge);
    void contribute_hello(ClientHelloMessage& msg);
    void handle_server_state(ServerMetadataStateObject state);
    void drain_events();
    void cleanup();

    MetadataRoleListener* listener_{nullptr};
    ClientBridge* bridge_{nullptr};
    ServerMetadataStateObject metadata_{};

    struct EventState;
    std::unique_ptr<EventState> event_state_;
};

}  // namespace sendspin
