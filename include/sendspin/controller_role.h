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
#include <vector>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Controller types
// ============================================================================

/// @brief Playback commands the controller role can send to the server
enum class SendspinControllerCommand : uint8_t {
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

/// @brief Controller state received from the server in server/state messages
struct ServerStateControllerObject {
    std::vector<SendspinControllerCommand> supported_commands{};
    uint8_t volume{};
    bool muted{};
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
    struct Impl;

    explicit ControllerRole(SendspinClient* client);
    ~ControllerRole();

    /// @brief Returns the current controller state from the server
    /// @return Const reference to the last received server controller state
    const ServerStateControllerObject& get_controller_state() const;

    /// @brief Sets the listener for controller events
    /// @note The listener must outlive this role
    /// @param listener Pointer to the listener implementation
    void set_listener(ControllerRoleListener* listener);

    /// @brief Sends a controller command to the server
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
