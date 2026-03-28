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

#include "protocol_messages.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinConnection;
class SendspinServerConnection;
class SendspinWsServer;

/// @brief Deferred server hello event, processed in ConnectionManager::loop().
struct ServerHelloEvent {
    SendspinConnection* conn;  ///< Connection that received the hello (must still be valid)
    ServerInformationObject server;
    SendspinConnectionReason connection_reason;
};

/// @brief Hello retry state for exponential backoff.
struct HelloRetryState {
    SendspinConnection* conn{
        nullptr};              ///< Connection awaiting hello (must match current_ or pending_)
    int64_t retry_time_us{0};  ///< Next retry time in microseconds (0 = no pending retry)
    uint32_t delay_ms{100};    ///< Current backoff delay
    uint8_t attempts{3};       ///< Remaining retry attempts
};

/// @brief Callbacks from ConnectionManager back to SendspinClient.
struct ConnectionManagerCallbacks {
    /// @brief Routes a JSON message to the client for processing.
    std::function<bool(SendspinConnection*, const std::string&, int64_t)> on_json_message;

    /// @brief Routes a binary message to the client for processing.
    std::function<void(uint8_t*, size_t)> on_binary_message;

    /// @brief Builds the formatted hello message string from client config.
    std::function<std::string()> build_hello_message;

    /// @brief Called when a connection's handshake completes.
    /// Client stores server info and publishes state.
    std::function<void(SendspinConnection*, ServerInformationObject)> on_handshake_complete;

    /// @brief Called when the active streaming connection is lost.
    /// Client handles sync task cleanup, user callbacks, and high-performance release.
    std::function<void()> on_active_connection_lost;

    /// @brief Resets the time burst (called when active connection changes).
    std::function<void()> reset_time_burst;

    /// @brief Returns true if the network is ready for connections.
    std::function<bool()> is_network_ready;
};

/// @brief Manages WebSocket connection lifecycle: accepts/creates connections, handles hello
/// handshake, server handoff, and graceful disconnection.
class ConnectionManager {
public:
    explicit ConnectionManager(ConnectionManagerCallbacks callbacks);
    ~ConnectionManager();

    // --- Public API ---

    /// @brief Initiates a client connection to a Sendspin server.
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server.
    void disconnect(SendspinGoodbyeReason reason);

    // --- Server lifecycle ---

    /// @brief Creates the WebSocket server and configures callbacks. Call once from start_server().
    /// @param client Client pointer passed through to ws_server (required by ws_server API).
    void init_server(SendspinClient* client, bool psram_stack, unsigned priority);

    /// @brief Drives connection state: starts server when network ready, processes lifecycle
    /// events, retries hello, calls loop() on active connections.
    void loop();

    // --- Connection queries ---

    /// @brief Returns the current active connection, or nullptr.
    SendspinConnection* current() const;

    /// @brief Returns the pending handoff connection, or nullptr.
    SendspinConnection* pending() const;

    /// @brief Returns true if there is an active connection with completed handshake.
    bool is_connected() const;

    // --- Event queuing (thread-safe) ---

    /// @brief Enqueues a server hello event for deferred processing in loop().
    void enqueue_hello(ServerHelloEvent event);

    // --- Handoff support ---

    /// @brief Sets the last-played server hash for handoff preference decisions.
    void set_last_played_server_hash(uint32_t hash);

    /// @brief FNV-1 hash function for strings.
    static uint32_t fnv1_hash(const char* str);

private:
    // --- Connection setup ---
    void setup_connection_callbacks_(SendspinConnection* conn);
    void on_new_connection_(std::unique_ptr<SendspinServerConnection> conn);

    // --- Hello handshake ---
    void initiate_hello_(SendspinConnection* conn);
    bool send_hello_message_(uint8_t remaining_attempts, SendspinConnection* conn);

    // --- Connection lifecycle ---
    void on_connection_lost_(SendspinConnection* conn);
    bool should_switch_to_new_server_(SendspinConnection* current, SendspinConnection* new_conn);
    void complete_handoff_(bool switch_to_new);
    void disconnect_and_release_(std::unique_ptr<SendspinConnection> conn,
                                 SendspinGoodbyeReason reason);

    // --- Callbacks ---
    ConnectionManagerCallbacks callbacks_;

    // --- Connections ---
    std::unique_ptr<SendspinConnection> current_connection_;
    std::unique_ptr<SendspinConnection> pending_connection_;
    std::shared_ptr<SendspinConnection> dying_connection_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // --- Server start params (stored from init_server, used when network becomes ready) ---
    SendspinClient* client_{nullptr};
    bool psram_stack_{false};
    unsigned task_priority_{17};

    // --- Hello retry ---
    HelloRetryState hello_retry_;

    // --- Handoff state ---
    uint32_t last_played_server_hash_{0};
    bool has_last_played_server_{false};

    // --- Deferred lifecycle events (protected by conn_mutex_) ---
    std::mutex conn_mutex_;
    std::vector<int> pending_close_events_;
    std::vector<SendspinConnection*> pending_disconnect_events_;
    std::vector<ServerHelloEvent> pending_hello_events_;
    bool dying_connection_ready_to_release_{false};
};

}  // namespace sendspin
