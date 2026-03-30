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
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

// ============================================================================
// Controller types
// ============================================================================

enum class SendspinControllerCommand {
    PLAY,
    PAUSE,
    STOP,
    NEXT,
    PREVIOUS,
    VOLUME,
    MUTE,
    REPEAT_OFF,
    REPEAT_ONE,
    REPEAT_ALL,
    SHUFFLE,
    UNSHUFFLE,
    SWITCH,
};

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
    if (str == "play")
        return SendspinControllerCommand::PLAY;
    if (str == "pause")
        return SendspinControllerCommand::PAUSE;
    if (str == "stop")
        return SendspinControllerCommand::STOP;
    if (str == "next")
        return SendspinControllerCommand::NEXT;
    if (str == "previous")
        return SendspinControllerCommand::PREVIOUS;
    if (str == "volume")
        return SendspinControllerCommand::VOLUME;
    if (str == "mute")
        return SendspinControllerCommand::MUTE;
    if (str == "repeat_off")
        return SendspinControllerCommand::REPEAT_OFF;
    if (str == "repeat_one")
        return SendspinControllerCommand::REPEAT_ONE;
    if (str == "repeat_all")
        return SendspinControllerCommand::REPEAT_ALL;
    if (str == "shuffle")
        return SendspinControllerCommand::SHUFFLE;
    if (str == "unshuffle")
        return SendspinControllerCommand::UNSHUFFLE;
    if (str == "switch")
        return SendspinControllerCommand::SWITCH;
    return std::nullopt;
}

struct ClientCommandControllerObject {
    SendspinControllerCommand command;
    std::optional<uint8_t> volume;
    std::optional<bool> mute;
};

struct ServerStateControllerObject {
    std::vector<SendspinControllerCommand> supported_commands;
    uint8_t volume;
    bool muted;
};

/// @brief Listener for controller role events. All methods fire on the main loop thread.
class ControllerRoleListener {
public:
    virtual ~ControllerRoleListener() = default;

    /// @brief Called when the server sends updated controller state.
    virtual void on_controller_state(const ServerStateControllerObject& /*state*/) {}
};

/// @brief Controller role: read-only server state and outbound commands.
class ControllerRole {
    friend class SendspinClient;

public:
    explicit ControllerRole(SendspinClient* client);
    ~ControllerRole();

    /// @brief Sets the listener for controller events. The listener must outlive this role.
    void set_listener(ControllerRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Sends a controller command to the server.
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});

    /// @brief Returns the current controller state from the server.
    const ServerStateControllerObject& get_controller_state() const {
        return this->controller_state_;
    }

private:
    void contribute_hello(ClientHelloMessage& msg);
    void handle_server_state(ServerStateControllerObject state);
    void drain_events();
    void cleanup();

    ControllerRoleListener* listener_{nullptr};
    SendspinClient* client_;
    ServerStateControllerObject controller_state_{};

    struct EventState;
    std::unique_ptr<EventState> event_state_;
};

}  // namespace sendspin
