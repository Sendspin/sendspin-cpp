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
    PLAY,           // Resume or start playback
    PAUSE,          // Pause playback
    STOP,           // Stop playback
    NEXT,           // Skip to next track
    PREVIOUS,       // Skip to previous track
    VOLUME,         // Set volume level
    MUTE,           // Set mute state
    REPEAT_OFF,     // Disable repeat
    REPEAT_ONE,     // Repeat current track
    REPEAT_ALL,     // Repeat entire queue
    SHUFFLE,        // Enable shuffle
    UNSHUFFLE,      // Disable shuffle
    SWITCH,         // Switch playback source
    SEEK,           // Seek to an absolute position
    SEEK_RELATIVE,  // Seek by a relative offset
};

/// @brief Repeat mode for playback
enum class SendspinRepeatMode : uint8_t {
    OFF,  // No repeat
    ONE,  // Repeat current track
    ALL,  // Repeat entire queue
};

/// @brief Controller state received from the server in server/state messages
struct ServerStateControllerObject {
    std::vector<SendspinControllerCommand> supported_commands{};
    uint8_t volume{};
    bool muted{};
    SendspinRepeatMode repeat{SendspinRepeatMode::OFF};
    bool shuffle{};
    // Maximum absolute position (ms) a 'seek' may target. Present only when the server offers the
    // 'seek' command and the seekable range is known; absent for live/unknown-duration streams.
    std::optional<uint32_t> seek_max_ms{};
};

/// @brief A playback command sent from the client to the server via client/command messages.
///
/// Construct with designated initializers, setting only the field the command uses:
/// @code
/// controller.send_command({.command = SendspinControllerCommand::PLAY});
/// controller.send_command({.command = SendspinControllerCommand::VOLUME, .volume = 75});
/// controller.send_command({.command = SendspinControllerCommand::MUTE, .muted = true});
/// controller.send_command({.command = SendspinControllerCommand::SEEK, .position_ms = 30000});
/// controller.send_command({.command = SendspinControllerCommand::SEEK_RELATIVE,
///                          .offset_ms = -10000});
/// @endcode
/// Fields not relevant to the command are ignored when the message is serialized.
struct ClientCommandControllerObject {
    SendspinControllerCommand command{};
    std::optional<uint8_t> volume{};        // only for VOLUME (0-100)
    std::optional<bool> muted{};            // only for MUTE
    std::optional<uint32_t> position_ms{};  // only for SEEK (0 to ServerStateControllerObject::
                                            // seek_max_ms)
    std::optional<int32_t> offset_ms{};     // only for SEEK_RELATIVE (signed offset from current)
};

/// @brief Listener for controller role events. All methods fire on the main loop thread.
class ControllerRoleListener {
public:
    virtual ~ControllerRoleListener() = default;

    /// @brief Called when the server sends updated controller state
    virtual void on_controller_state(const ServerStateControllerObject& /*state*/) {}

    /// @brief Called when the connection to the server is lost and cached controller state is
    /// dropped
    ///
    /// Implementations should clear any displayed controller state (volume, mute, repeat,
    /// shuffle, supported commands) since the previous server's state is no longer valid.
    virtual void on_controller_state_clear() {}
};

/**
 * @brief Playback controller role that sends commands to and receives state from the server
 *
 * Maintains a local copy of the server's controller state (volume, mute, repeat, shuffle,
 * supported commands) and provides a send_command() method for dispatching playback control
 * messages. State updates from the server are queued and delivered to the listener on the
 * main loop thread.
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
 *         update_repeat_ui(state.repeat);
 *         update_shuffle_ui(state.shuffle);
 *     }
 * };
 *
 * MyControllerListener listener;
 * auto& controller = client.add_controller();
 * controller.set_listener(&listener);
 * controller.send_command({.command = SendspinControllerCommand::PLAY});
 * controller.send_command({.command = SendspinControllerCommand::VOLUME, .volume = 75});
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
    /// @param cmd The command plus any command-specific parameters
    void send_command(const ClientCommandControllerObject& cmd);

    /// @brief Sends a controller command to the server
    /// @deprecated Use send_command(const ClientCommandControllerObject&) instead. This overload
    /// cannot carry seek parameters and will be removed in v0.8.0.
    [[deprecated(
        "use send_command(const ClientCommandControllerObject&); this overload cannot carry seek "
        "parameters and will be removed in v0.8.0")]]
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
