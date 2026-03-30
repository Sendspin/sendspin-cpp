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

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// Forward declarations for listener types
struct GroupUpdateObject;

/// @brief Listener for SendspinClient events. All methods fire on the main loop thread.
class SendspinClientListener {
public:
    virtual ~SendspinClientListener() = default;

    /// @brief Called when the group state is updated by the server.
    virtual void on_group_update(const GroupUpdateObject& /*group*/) {}

    /// @brief Called after a time sync burst completes with the Kalman filter error.
    virtual void on_time_sync_updated(float /*error*/) {}

    /// @brief Called when the library needs high-performance networking (e.g., disable WiFi
    /// power saving).
    virtual void on_request_high_performance() {}

    /// @brief Called when the library no longer needs high-performance networking.
    virtual void on_release_high_performance() {}
};

/// @brief Platform hook for network readiness. Must be set before start_server().
class SendspinNetworkProvider {
public:
    virtual ~SendspinNetworkProvider() = default;

    /// @brief Returns true if the network (WiFi/Ethernet) is ready for connections.
    virtual bool is_network_ready() = 0;
};

/// @brief Optional persistence provider for saving/loading client and role state.
/// All methods fire on the main loop thread.
class SendspinPersistenceProvider {
public:
    virtual ~SendspinPersistenceProvider() = default;

    /// @brief Saves the FNV1 hash of the last server that was playing. Returns true on success.
    virtual bool save_last_server_hash(uint32_t /*hash*/) {
        return false;
    }

    /// @brief Loads the persisted last-played server hash. Returns nullopt if none saved.
    virtual std::optional<uint32_t> load_last_server_hash() {
        return std::nullopt;
    }

    /// @brief Saves the player's static delay. Returns true on success.
    virtual bool save_static_delay(uint16_t /*delay_ms*/) {
        return false;
    }

    /// @brief Loads the player's persisted static delay. Returns nullopt if none saved.
    virtual std::optional<uint16_t> load_static_delay() {
        return std::nullopt;
    }
};

/// @brief Log severity levels for host builds. Has no effect on ESP-IDF builds.
enum class LogLevel : int {
    NONE = 0,
    ERROR = 1,
    WARN = 2,
    INFO = 3,
    DEBUG = 4,
    VERBOSE = 5,
};

// Forward declarations
class ConnectionManager;
class SendspinConnection;
class SendspinTimeBurst;
struct ServerInformationObject;

/// @brief Configuration for a SendspinClient instance.
/// Filled in by the platform (e.g., ESPHome) before calling start_server().
struct SendspinClientConfig {
    std::string client_id;         ///< Unique client identifier (e.g., MAC address)
    std::string name;              ///< Friendly display name
    std::string product_name;      ///< Device product name
    std::string manufacturer;      ///< Manufacturer name (e.g., "ESPHome")
    std::string software_version;  ///< Software version string
    bool psram_stack{false};       ///< Whether to allocate task stacks in PSRAM
};

/// @brief Deferred event from a callback thread, processed in loop().
struct TimeResponseEvent {
    int64_t offset;
    int64_t max_error;
    int64_t timestamp;
};

/// @brief Main orchestration class for the sendspin-cpp library.
///
/// Manages connections, message routing, time sync,
/// audio playback, and all Sendspin protocol interactions. This is the public API surface
/// of the library.
///
/// Usage:
/// 1. Create a SendspinClientConfig and fill in capabilities
/// 2. Create a SendspinClient with the config
/// 3. Add roles via add_player(), add_controller(), etc.
/// 4. Set listeners on the role objects and providers on the client
/// 5. Call start_server() to begin listening for connections
/// 6. Call loop() periodically from the main loop
class SendspinClient {
    friend class ConnectionManager;

public:
    explicit SendspinClient(SendspinClientConfig config);
    ~SendspinClient();

    /// @brief Sets the library-wide log level (host builds only, no-op on ESP-IDF).
    static void set_log_level(LogLevel level);

    /// @brief Returns the current log level (host builds only, INFO on ESP-IDF).
    static LogLevel get_log_level();

    // --- Lifecycle ---

    /// @brief Starts the WebSocket server and initializes the sync task (if audio is configured).
    /// @param priority FreeRTOS task priority for the WS server and sync task.
    /// @return true on success, false on failure.
    bool start_server(unsigned priority);

    /// @brief Initiates a client connection to a Sendspin server at the given URL.
    /// @param url WebSocket server URL (e.g., "ws://server.local:8927/sendspin").
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server with the given reason.
    /// @param reason The goodbye reason to send.
    void disconnect(SendspinGoodbyeReason reason);

    /// @brief Processes events, drives time sync, checks network. Call from main loop.
    void loop();

    // --- Role registration (call before start_server) ---

    /// @brief Adds the player role. Returns a reference for setting callbacks.
    PlayerRole& add_player(PlayerRole::Config config);

    /// @brief Adds the controller role. Returns a reference for setting callbacks.
    ControllerRole& add_controller();

    /// @brief Adds the metadata role. Returns a reference for setting callbacks.
    MetadataRole& add_metadata();

    /// @brief Adds the artwork role. Returns a reference for setting callbacks.
    ArtworkRole& add_artwork();

    /// @brief Adds the visualizer role. Returns a reference for setting callbacks.
    VisualizerRole& add_visualizer(VisualizerRole::Config config);

    // --- Role access (nullptr if not added) ---

    PlayerRole* player() {
        return this->player_.get();
    }
    const PlayerRole* player() const {
        return this->player_.get();
    }
    MetadataRole* metadata() {
        return this->metadata_.get();
    }
    const MetadataRole* metadata() const {
        return this->metadata_.get();
    }
    ControllerRole* controller() {
        return this->controller_.get();
    }
    const ControllerRole* controller() const {
        return this->controller_.get();
    }
    ArtworkRole* artwork() {
        return this->artwork_.get();
    }
    const ArtworkRole* artwork() const {
        return this->artwork_.get();
    }
    VisualizerRole* visualizer() {
        return this->visualizer_.get();
    }
    const VisualizerRole* visualizer() const {
        return this->visualizer_.get();
    }

    // --- Queries ---

    /// @brief Returns true if there is an active connection with completed handshake.
    bool is_connected() const;

    /// @brief Returns true if the time filter has received at least one measurement.
    bool is_time_synced() const;

    /// @brief Converts a server timestamp to the equivalent client timestamp.
    int64_t get_client_time(int64_t server_time) const;

    /// @brief Returns the current active connection (or nullptr).
    SendspinConnection* get_current_connection() const;

    /// @brief Returns the current group ID (empty string if none).
    std::string get_group_id() const {
        return this->group_state_.group_id.value_or("");
    }

    /// @brief Returns the current group name (empty string if none).
    std::string get_group_name() const {
        return this->group_state_.group_name.value_or("");
    }

    // --- State updates ---

    /// @brief Updates the client state (synchronized, error, external_source) and publishes.
    void update_state(SendspinClientState state);

    // --- Listener and provider setters ---

    /// @brief Sets the listener for client events. The listener must outlive this client.
    void set_listener(SendspinClientListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Sets the network provider (required before start_server()).
    /// The provider must outlive this client.
    void set_network_provider(SendspinNetworkProvider* provider) {
        this->network_provider_ = provider;
    }

    /// @brief Sets the optional persistence provider. The provider must outlive this client.
    void set_persistence_provider(SendspinPersistenceProvider* provider) {
        this->persistence_provider_ = provider;
    }

    // --- Role services (called by roles via SendspinClient pointer) ---

    /// @brief Publishes the current client state to the active connection.
    void publish_state();

    /// @brief Sends a text message over the active connection.
    void send_text(const std::string& text);

    /// @brief Acquires a ref-counted high-performance networking request.
    void acquire_high_performance();

    /// @brief Releases a ref-counted high-performance networking request.
    void release_high_performance();

private:
    /// @brief Cleans up playback state when the active streaming connection is removed.
    void cleanup_connection_state_();

    /// @brief Builds the formatted client hello message from config.
    std::string build_hello_message_();

    // --- Message processing ---

    /// @brief Processes a JSON message from a connection.
    bool process_json_message_(SendspinConnection* conn, const std::string& message,
                               int64_t timestamp);

    /// @brief Processes a binary message from a connection.
    void process_binary_message_(uint8_t* payload, size_t len);

    // --- State publishing ---

    /// @brief Publishes the current client state to the specified connection.
    void publish_client_state_(SendspinConnection* conn);

    // --- Persistence ---

    /// @brief Loads the last played server hash from persistence.
    void load_last_played_server_();

    /// @brief Persists the server ID as the last played server (hashed).
    void persist_last_played_server_(const std::string& server_id);

    // --- Connection event handlers (called by ConnectionManager via friend access) ---

    void on_handshake_complete_(SendspinConnection* conn, ServerInformationObject server);

    // --- Configuration ---

    SendspinClientConfig config_;

    // --- Connection management ---

    std::unique_ptr<ConnectionManager> connection_manager_;

    // --- Time sync ---

    std::unique_ptr<SendspinTimeBurst> time_burst_;
    std::atomic<uint8_t> high_performance_ref_count_{0};
    bool high_performance_held_for_time_{false};

    // --- Client state ---

    SendspinClientState state_{SendspinClientState::SYNCHRONIZED};
    bool started_{false};

    // --- Server and group state ---

    ServerInformationObject server_information_{};
    GroupUpdateObject group_state_{};

    // --- Deferred event state (PIMPL — hides platform queue/shadow headers) ---

    struct EventState;
    std::unique_ptr<EventState> event_state_;

    // --- Listeners and providers ---

    SendspinClientListener* listener_{nullptr};
    SendspinNetworkProvider* network_provider_{nullptr};
    SendspinPersistenceProvider* persistence_provider_{nullptr};

    // --- Roles ---

    std::unique_ptr<PlayerRole> player_;
    std::unique_ptr<ControllerRole> controller_;
    std::unique_ptr<MetadataRole> metadata_;
    std::unique_ptr<ArtworkRole> artwork_;
    std::unique_ptr<VisualizerRole> visualizer_;
};

}  // namespace sendspin
