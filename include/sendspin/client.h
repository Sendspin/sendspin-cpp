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

#include "sendspin/protocol.h"

#ifdef SENDSPIN_ENABLE_PLAYER
#include "sendspin/audio_sink.h"
#endif

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

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
class SendspinClientConnection;
class SendspinConnection;
class SendspinServerConnection;
class SendspinTimeBurst;
class SendspinWsServer;
#ifdef SENDSPIN_ENABLE_PLAYER
class SyncTask;
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
/// @brief Preference for an image slot's format and resolution.
struct ImageSlotPreference {
    uint8_t slot;
    SendspinImageSource source;
    SendspinImageFormat format;
    uint16_t width;
    uint16_t height;
};
#endif  // SENDSPIN_ENABLE_ARTWORK

/// @brief Configuration for a SendspinClient instance.
/// Filled in by the platform (e.g., ESPHome) before calling start_server().
struct SendspinClientConfig {
    std::string client_id;         ///< Unique client identifier (e.g., MAC address)
    std::string name;              ///< Friendly display name
    std::string product_name;      ///< Device product name
    std::string manufacturer;      ///< Manufacturer name (e.g., "ESPHome")
    std::string software_version;  ///< Software version string

    // Capabilities (filled by platform based on configuration)
#ifdef SENDSPIN_ENABLE_PLAYER
    std::vector<AudioSupportedFormatObject> audio_formats;  ///< Empty = no player support
    size_t audio_buffer_capacity{1000000};                  ///< Ring buffer size for encoded audio
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    std::vector<ArtworkChannelFormatObject> artwork_channels;  ///< Empty = no artwork support
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::optional<VisualizerSupportObject> visualizer;  ///< nullopt = no visualizer support
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    bool controller{false};  ///< Whether controller role is supported
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    bool metadata{false};  ///< Whether metadata role is supported
#endif
    bool psram_stack{false};  ///< Whether to allocate task stacks in PSRAM
#ifdef SENDSPIN_ENABLE_PLAYER
    int32_t fixed_delay_us{0};            ///< Fixed audio delay in microseconds
    uint16_t initial_static_delay_ms{0};  ///< Default static delay if no persisted value
#endif
};

/// @brief Deferred event from a callback thread, processed in loop().
struct TimeResponseEvent {
    int64_t offset;
    int64_t max_error;
    int64_t timestamp;
};

/// @brief Deferred server hello event, processed in loop().
struct ServerHelloEvent {
    SendspinConnection* conn;  ///< Connection that received the hello (must still be valid)
    ServerInformationObject server;
    SendspinConnectionReason connection_reason;
};

/// @brief Deferred server command event, processed in loop().
struct ServerCommandEvent {
    ServerCommandMessage command;
};

/// @brief Deferred stream lifecycle callback event, processed in loop().
enum class StreamCallbackType : uint8_t {
    STREAM_START,
    STREAM_END,
    STREAM_CLEAR,
#ifdef SENDSPIN_ENABLE_ARTWORK
    ARTWORK_STREAM_END,
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    VISUALIZER_STREAM_START,
    VISUALIZER_STREAM_END,
    VISUALIZER_STREAM_CLEAR,
#endif
};

/// @brief Deferred stream callback event, processed in loop().
struct StreamCallbackEvent {
    explicit StreamCallbackEvent(StreamCallbackType t) : type(t) {}
    StreamCallbackType type;
#ifdef SENDSPIN_ENABLE_PLAYER
    std::optional<ServerPlayerStreamObject> player_stream;  ///< Stream params for STREAM_START
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::optional<ServerVisualizerStreamObject> visualizer_stream;
#endif
};

/// @brief Hello retry state for exponential backoff.
struct HelloRetryState {
    SendspinConnection* conn{
        nullptr};              ///< Connection awaiting hello (must match current_ or pending_)
    int64_t retry_time_us{0};  ///< Next retry time in microseconds (0 = no pending retry)
    uint32_t delay_ms{100};    ///< Current backoff delay
    uint8_t attempts{3};       ///< Remaining retry attempts
};

/// @brief Main orchestration class for the sendspin-cpp library.
///
/// Replaces ESPHome's SendspinHub. Manages connections, message routing, time sync,
/// audio playback, and all Sendspin protocol interactions. This is the public API surface
/// of the library.
///
/// Usage:
/// 1. Create a SendspinClientConfig and fill in capabilities
/// 2. Create a SendspinClient with the config
/// 3. Set callbacks (on_metadata, on_stream_start, etc.)
/// 4. Set platform hooks (is_network_ready, persistence callbacks, etc.)
/// 5. Call start_server() to begin listening for connections
/// 6. Call loop() periodically from the main loop
class SendspinClient {
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

    // --- Audio ---

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Sets the audio sink for decoded audio output. Must be set before start_server().
    /// @param sink Pointer to the audio sink (owned by caller, must outlive client).
    void set_audio_sink(AudioSink* sink);

    /// @brief Called by the audio output when it has played audio frames.
    /// Thread-safe: may be called from any context (e.g., I2S callback).
    /// @param frames Number of audio frames played.
    /// @param timestamp Client timestamp when the audio finished playing.
    void notify_audio_played(uint32_t frames, int64_t timestamp);

    /// @brief Writes an audio chunk to the sync task's ring buffer.
    /// @param data Pointer to the audio data.
    /// @param size Size of the audio data in bytes.
    /// @param timestamp Server timestamp for this chunk.
    /// @param type Type of audio chunk.
    /// @param timeout_ms Milliseconds to wait if buffer is full (UINT32_MAX = wait forever).
    /// @return true if successfully written, false on error.
    bool write_audio_chunk(const uint8_t* data, size_t size, int64_t timestamp, ChunkType type,
                           uint32_t timeout_ms);
#endif  // SENDSPIN_ENABLE_PLAYER

    // --- State updates ---

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Updates the volume and publishes client state to the server.
    /// @param volume Volume level (0-100).
    void update_volume(uint8_t volume);

    /// @brief Updates the mute state and publishes client state to the server.
    /// @param muted True if muted.
    void update_muted(bool muted);

    /// @brief Updates the static delay and publishes client state to the server.
    /// The value is clamped to 5000 ms and persisted if a save callback is set.
    /// @param delay_ms Static delay in milliseconds.
    void update_static_delay(uint16_t delay_ms);

    /// @brief Enables or disables the static delay adjustment command.
    /// @param adjustable True to advertise SET_STATIC_DELAY as a supported command.
    void set_static_delay_adjustable(bool adjustable);
#endif  // SENDSPIN_ENABLE_PLAYER

    /// @brief Updates the client state (synchronized, error, external_source) and publishes.
    /// @param state The new client state.
    void update_state(SendspinClientState state);

#ifdef SENDSPIN_ENABLE_CONTROLLER
    /// @brief Sends a controller command to the server.
    /// @param cmd The command to send.
    /// @param volume Optional volume value (for VOLUME command).
    /// @param mute Optional mute value (for MUTE command).
    void send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume = {},
                      std::optional<bool> mute = {});
#endif  // SENDSPIN_ENABLE_CONTROLLER

    // --- Queries ---

    /// @brief Returns true if there is an active connection with completed handshake.
    bool is_connected() const;

    /// @brief Returns true if the time filter has received at least one measurement.
    bool is_time_synced() const;

    /// @brief Converts a server timestamp to the equivalent client timestamp.
    /// @param server_time Server timestamp in microseconds.
    /// @return Equivalent client timestamp in microseconds (0 if no active connection).
    int64_t get_client_time(int64_t server_time) const;

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Returns the current static delay in milliseconds.
    uint16_t get_static_delay_ms() const {
        return this->static_delay_ms_;
    }

    /// @brief Returns the fixed delay in microseconds (from config).
    int32_t get_fixed_delay_us() const {
        return this->config_.fixed_delay_us;
    }

    /// @brief Returns the current volume level.
    uint8_t get_volume() const {
        return this->volume_;
    }

    /// @brief Returns true if currently muted.
    bool get_muted() const {
        return this->muted_;
    }

    /// @brief Returns the audio buffer capacity from config.
    size_t get_buffer_size() const {
        return this->config_.audio_buffer_capacity;
    }

    /// @brief Returns a reference to the current stream parameters.
    ServerPlayerStreamObject& get_current_stream_params() {
        return this->current_stream_params_;
    }
#endif  // SENDSPIN_ENABLE_PLAYER

#ifdef SENDSPIN_ENABLE_METADATA
    /// @brief Returns the interpolated track progress in milliseconds.
    /// Accounts for playback speed and time elapsed since last server update.
    /// Returns 0 if no progress data is available.
    uint32_t get_track_progress_ms() const;

    /// @brief Returns the track duration in milliseconds. 0 means unknown/live.
    uint32_t get_track_duration_ms() const;
#endif  // SENDSPIN_ENABLE_METADATA

    /// @brief Returns the current group ID (empty string if none).
    std::string get_group_id() const {
        return this->group_state_.group_id.value_or("");
    }

    /// @brief Returns the current group name (empty string if none).
    std::string get_group_name() const {
        return this->group_state_.group_name.value_or("");
    }

    /// @brief Returns the current active connection (or nullptr).
    SendspinConnection* get_current_connection() const {
        return this->current_connection_.get();
    }

#ifdef SENDSPIN_ENABLE_CONTROLLER
    /// @brief Returns the current controller state from the server.
    const ServerStateControllerObject& get_controller_state() const {
        return this->controller_state_;
    }
#endif  // SENDSPIN_ENABLE_CONTROLLER

    // --- Event callbacks (set by platform before start) ---

#ifdef SENDSPIN_ENABLE_METADATA
    std::function<void(const ServerMetadataStateObject&)> on_metadata;
#endif
    std::function<void(const GroupUpdateObject&)> on_group_update;
#ifdef SENDSPIN_ENABLE_ARTWORK
    std::function<void(uint8_t, const uint8_t*, size_t, SendspinImageFormat, int64_t)> on_image;
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::function<void(const uint8_t*, size_t)> on_visualizer_data;
    std::function<void(const uint8_t*, size_t)> on_beat_data;
    std::function<void(const ServerVisualizerStreamObject&)> on_visualizer_stream_start;
    std::function<void()> on_visualizer_stream_end;
    std::function<void()> on_visualizer_stream_clear;
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
    std::function<void()> on_stream_start;
    std::function<void()> on_stream_end;
    std::function<void()> on_stream_clear;
    std::function<void(uint8_t)> on_volume_changed;
    std::function<void(bool)> on_mute_changed;
    std::function<void(uint16_t)> on_static_delay_changed;
#endif
    std::function<void(float)> on_time_sync_updated;  ///< Kalman error value after burst completes

    // --- Platform hooks ---

    /// @brief Returns true if the network (WiFi/Ethernet) is ready for connections.
    std::function<bool()> is_network_ready;

    /// @brief Called when the library needs high-performance networking (e.g., during time sync
    /// burst).
    std::function<void()> on_request_high_performance;

    /// @brief Called when the library no longer needs high-performance networking.
    std::function<void()> on_release_high_performance;

    // --- Persistence hooks (optional) ---

    /// @brief Saves the FNV1 hash of the last server that was playing. Returns true on success.
    std::function<bool(uint32_t)> save_last_server_hash;

    /// @brief Loads the persisted last-played server hash. Returns nullopt if none saved.
    std::function<std::optional<uint32_t>()> load_last_server_hash;

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Saves the static delay value. Returns true on success.
    std::function<bool(uint16_t)> save_static_delay;

    /// @brief Loads the persisted static delay value. Returns nullopt if none saved.
    std::function<std::optional<uint16_t>()> load_static_delay;
#endif

    // --- Image slot management ---

#ifdef SENDSPIN_ENABLE_ARTWORK
    /// @brief Adds a preferred image format for an artwork slot.
    void add_image_preferred_format(const ImageSlotPreference& pref);

    /// @brief Returns all configured image format preferences.
    const std::vector<ImageSlotPreference>& get_image_preferred_formats() const {
        return this->preferred_image_formats_;
    }
#endif  // SENDSPIN_ENABLE_ARTWORK

    // --- Visualizer support ---

#ifdef SENDSPIN_ENABLE_VISUALIZER
    /// @brief Sets the visualizer support configuration.
    void set_visualizer_support(const VisualizerSupportObject& support) {
        this->visualizer_support_ = support;
        this->config_.visualizer = support;
    }

    /// @brief Returns the visualizer support configuration (nullopt if not configured).
    const std::optional<VisualizerSupportObject>& get_visualizer_support() const {
        return this->visualizer_support_;
    }
#endif  // SENDSPIN_ENABLE_VISUALIZER

protected:
    /// @brief FNV-1 hash function for strings.
    static uint32_t fnv1_hash(const char* str);

    // --- Hello handshake ---

    /// @brief Initiates hello handshake with exponential backoff.
    /// @param conn The connection to send the hello message to.
    void initiate_hello_(SendspinConnection* conn);

    /// @brief Attempts to send the hello message.
    /// @param remaining_attempts Number of retry attempts remaining.
    /// @param conn The connection to send the hello message to.
    /// @return true if done (success or non-recoverable), false if should retry.
    bool send_hello_message_(uint8_t remaining_attempts, SendspinConnection* conn);

    // --- Connection management ---

    /// @brief Called when a new server connection is accepted by the WebSocket server.
    /// @param conn The new connection (ownership transferred to client).
    void on_new_connection_(std::unique_ptr<SendspinServerConnection> conn);

    /// @brief Called when a connection completes its hello handshake.
    /// @param conn Pointer to the connection that completed its handshake.
    void on_connection_handshake_complete_(SendspinConnection* conn);

    /// @brief Called when a server connection's socket is closed.
    /// @param sockfd The socket file descriptor of the closed connection.
    void on_connection_closed_(int sockfd);

    /// @brief Handles a connection being lost (closed or disconnected).
    /// @param conn Pointer to the connection that was lost.
    void on_connection_lost_(SendspinConnection* conn);

    /// @brief Determines whether to switch from current connection to a new one during handoff.
    /// @param current Pointer to the current active connection.
    /// @param new_conn Pointer to the new pending connection.
    /// @return true if should switch to new connection, false to keep current.
    bool should_switch_to_new_server_(SendspinConnection* current, SendspinConnection* new_conn);

    /// @brief Completes the handoff process by disconnecting the loser.
    /// @param switch_to_new true to promote pending to current, false to keep current.
    void complete_handoff_(bool switch_to_new);

    /// @brief Disconnects a connection and keeps it alive until goodbye completes.
    /// @param conn The connection to disconnect (ownership transferred).
    /// @param reason The goodbye reason to send.
    void disconnect_and_release_(std::unique_ptr<SendspinConnection> conn,
                                 SendspinGoodbyeReason reason);

    /// @brief Cleans up playback state when the active streaming connection is removed.
    void cleanup_connection_state_();

    // --- Message processing ---

    /// @brief Processes a JSON message from a connection.
    /// @return true if message was successfully processed, false otherwise.
    bool process_json_message_(SendspinConnection* conn, const std::string& message,
                               int64_t timestamp);

    /// @brief Processes a binary message from a connection.
    void process_binary_message_(uint8_t* payload, size_t len);

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Sends an audio chunk to the sync task's ring buffer.
    /// @return true if successfully written, false on error.
    bool send_audio_chunk_(const uint8_t* data, size_t data_size, int64_t timestamp,
                           ChunkType chunk_type, uint32_t timeout_ms);
#endif

    // --- State publishing ---

    /// @brief Publishes the current client state to the specified connection.
    /// @param conn Connection to send the state to.
    void publish_client_state_(SendspinConnection* conn);

    // --- Persistence ---

    /// @brief Loads the last played server hash from persistence.
    void load_last_played_server_();

    /// @brief Persists the server ID as the last played server (hashed).
    void persist_last_played_server_(const std::string& server_id);

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Loads the static delay from persistence.
    void load_static_delay_();

    /// @brief Persists the current static delay.
    void persist_static_delay_();
#endif

    // --- Configuration ---

    SendspinClientConfig config_;

    // --- Connection state ---

    std::unique_ptr<SendspinConnection> current_connection_;
    std::unique_ptr<SendspinConnection> pending_connection_;
    std::shared_ptr<SendspinConnection> dying_connection_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // --- Time sync ---

    std::unique_ptr<SendspinTimeBurst> time_burst_;
    bool high_performance_requested_for_time_{false};
#ifdef SENDSPIN_ENABLE_PLAYER
    bool high_performance_requested_for_playback_{false};
#endif

    // --- Hello retry state ---

    HelloRetryState hello_retry_;

    // --- Handoff state ---

    uint32_t last_played_server_hash_{0};
    bool has_last_played_server_{false};

    // --- Player state ---

#ifdef SENDSPIN_ENABLE_PLAYER
    uint8_t volume_{0};
    bool muted_{false};
    uint16_t static_delay_ms_{0};
    bool static_delay_adjustable_{false};
    SendspinClientState state_{SendspinClientState::SYNCHRONIZED};
    ServerPlayerStreamObject current_stream_params_{};
#else
    SendspinClientState state_{SendspinClientState::SYNCHRONIZED};
#endif

    // --- Controller state ---

#ifdef SENDSPIN_ENABLE_CONTROLLER
    ServerStateControllerObject controller_state_{};
#endif

    // --- Metadata state ---

#ifdef SENDSPIN_ENABLE_METADATA
    ServerMetadataStateObject metadata_{};
#endif

    // --- Group state ---

    ServerInformationObject server_information_{};
    GroupUpdateObject group_state_{};

    // --- Artwork ---

#ifdef SENDSPIN_ENABLE_ARTWORK
    std::vector<ImageSlotPreference> preferred_image_formats_;
#endif

    // --- Visualizer ---

#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::optional<VisualizerSupportObject> visualizer_support_;
#endif

    // --- Sync task ---

#ifdef SENDSPIN_ENABLE_PLAYER
    std::unique_ptr<SyncTask> sync_task_;
    AudioSink* audio_sink_{nullptr};
#endif

    // --- Deferred event queues (thread-safe, processed in loop()) ---

    std::mutex event_mutex_;
    std::vector<TimeResponseEvent> pending_time_events_;
#ifdef SENDSPIN_ENABLE_METADATA
    std::vector<ServerMetadataStateObject> pending_metadata_events_;
#endif
    std::vector<GroupUpdateObject> pending_group_events_;
    std::vector<int> pending_close_events_;
    std::vector<SendspinConnection*> pending_disconnect_events_;
    std::vector<ServerHelloEvent> pending_hello_events_;
    std::vector<ServerCommandEvent> pending_command_events_;
    std::vector<StreamCallbackEvent> pending_stream_callback_events_;
#ifdef SENDSPIN_ENABLE_CONTROLLER
    std::vector<ServerStateControllerObject> pending_controller_state_events_;
#endif
    bool dying_connection_ready_to_release_{false};

    // --- Stream end/clear callbacks waiting for sync task to go idle (main thread only) ---

#ifdef SENDSPIN_ENABLE_PLAYER
    std::vector<StreamCallbackEvent> awaiting_sync_idle_events_;
#endif

    // --- Server task priority (stored for ws_server start) ---

    unsigned task_priority_{17};
};

}  // namespace sendspin
