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

/// @file controller_role.h
/// @brief Playback controller role that sends commands to and receives state from the Sendspin
/// server

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

/// @brief Playback commands the controller role can send to the server
enum class SendspinControllerCommand {
    PLAY,        // Resume or start playback
    PAUSE,       // Pause playback
    STOP,        // Stop playback
    NEXT,        // Skip to next track
    PREVIOUS,    // Skip to previous track
    VOLUME,      // Set volume level
    MUTE,        // Set mute state
    REPEAT_OFF,  // Disable repeat
    REPEAT_ONE,  // Repeat current track
    REPEAT_ALL,  // Repeat entire queue
    SHUFFLE,     // Enable shuffle
    UNSHUFFLE,   // Disable shuffle
    SWITCH,      // Switch playback source
};

/// @brief Returns a null-terminated string name for a controller command
/// @param command The command to convert
/// @return Null-terminated string, or "unknown" for unrecognized values
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

/// @brief Parses a controller command from its string representation
/// @param str The string to parse
/// @return The matching command, or std::nullopt if unrecognized
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

/// @brief A playback command sent from the client to the server via client/command messages
struct ClientCommandControllerObject {
    SendspinControllerCommand command;
    std::optional<uint8_t> volume;
    std::optional<bool> mute;
};

/// @brief Controller state received from the server in server/state messages
struct ServerStateControllerObject {
    std::vector<SendspinControllerCommand> supported_commands;
    uint8_t volume;
    bool muted;
};

/// @brief Listener for controller role events. All methods fire on the main loop thread.
class ControllerRoleListener {
public:
    virtual ~ControllerRoleListener() = default;

    /// @brief Called when the server sends updated controller state
    virtual void on_controller_state(const ServerStateControllerObject& /*state*/) {}
};

/**
 * @brief Playback controller role that sends commands to and receives state from the server
 *
 * Maintains a local copy of the server's controller state (volume, mute, supported commands)
 * and provides a send_command() method for dispatching playback control messages. State
 * updates from the server are queued and delivered to the listener on the main loop thread.
 *
 * Usage:
 * 1. Implement ControllerRoleListener to receive server state updates
 * 2. Add the role to the client via SendspinClient::add_controller()
 * 3. Call set_listener() with your listener implementation
 * 4. Call send_command() to dispatch playback commands to the server
 *
 * @code
 * struct MyControllerListener : ControllerRoleListener {
 *     void on_controller_state(const ServerStateControllerObject& state) override {
 *         update_volume_ui(state.volume, state.muted);
 *     }
 * };
 *
 * MyControllerListener listener;
 * auto& controller = client.add_controller();
 * controller.set_listener(&listener);
 * controller.send_command(SendspinControllerCommand::PLAY);
 * controller.send_command(SendspinControllerCommand::VOLUME, 128);
 * @endcode
 */
class ControllerRole {
    friend class SendspinClient;

public:
    explicit ControllerRole(SendspinClient* client);
    ~ControllerRole();

    /// @brief Returns the current controller state from the server
    /// @return Const reference to the last received server controller state
    const ServerStateControllerObject& get_controller_state() const {
        return this->controller_state_;
    }

    /// @brief Sets the listener for controller events
    /// @note The listener must outlive this role
    /// @param listener Pointer to the listener implementation
    void set_listener(ControllerRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Sends a controller command to the server
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});

private:
    /// @brief Adds the controller role to the supported roles list in the hello message
    /// @param msg The hello message being assembled.
    void contribute_hello(ClientHelloMessage& msg);
    /// @brief Stores an incoming server controller state update for delivery on the main thread
    /// Only the most recent update is retained; earlier pending updates are overwritten.
    /// @param state The controller state received from the server.
    void handle_server_state(ServerStateControllerObject state);
    /// @brief Delivers any pending controller state update to the listener
    void drain_events();
    /// @brief Resets the controller state and clears any pending events
    void cleanup();

    struct EventState;

    // Struct fields
    ServerStateControllerObject controller_state_{};

    // Pointer fields
    SendspinClient* client_;
    std::unique_ptr<EventState> event_state_;
    ControllerRoleListener* listener_{nullptr};
};

}  // namespace sendspin
