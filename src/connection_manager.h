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

/// @file connection_manager.h
/// @brief Manages WebSocket connection lifecycle including server handoff, hello handshake, and
/// graceful disconnection

#pragma once

#include "protocol_messages.h"
#include "sendspin/client.h"

#include <cstdint>
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

/// @brief Deferred server hello event, processed in ConnectionManager::loop()
struct ServerHelloEvent {
    SendspinConnection* conn;  ///< Connection that received the hello (must still be valid)
    ServerInformationObject server;
    SendspinConnectionReason connection_reason;
};

/// @brief Hello retry state for exponential backoff
struct HelloRetryState {
    SendspinConnection* conn{
        nullptr};              ///< Connection awaiting hello (must match current_ or pending_)
    int64_t retry_time_us{0};  ///< Next retry time in microseconds (0 = no pending retry)
    uint32_t delay_ms{100};    ///< Current backoff delay
    uint8_t attempts{3};       ///< Remaining retry attempts
};

/**
 * @brief Manages WebSocket connection lifecycle.
 *
 * Accepts and creates connections, handles the hello handshake, orchestrates server handoff
 * decisions, and performs graceful disconnection with deferred cleanup.
 *
 * Typical usage:
 *  1. Construct with a `SendspinClient*`.
 *  2. Call `init_server()` once to create and configure the WebSocket server.
 *  3. Call `loop()` periodically to drive connection state, process deferred events, and retry
 *     hellos.
 *  4. Call `connect_to()` to initiate an outgoing client connection when needed.
 *  5. Call `disconnect()` to gracefully close the active connection.
 *
 * @code
 * ConnectionManager manager(client);
 * manager.init_server(client, use_psram, priority);
 *
 * while (running) {
 *     manager.loop();
 * }
 *
 * manager.disconnect(SendspinGoodbyeReason::SHUTDOWN);
 * @endcode
 */
class ConnectionManager {
public:
    explicit ConnectionManager(SendspinClient* client);
    ~ConnectionManager();

    // ========================================
    // Public API
    // ========================================

    /// @brief Initiates a client connection to a Sendspin server.
    /// @param url WebSocket URL of the server to connect to.
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server.
    /// @param reason The goodbye reason to send before closing.
    void disconnect(SendspinGoodbyeReason reason);

    // ========================================
    // Server lifecycle
    // ========================================

    /// @brief Creates the WebSocket server and configures callbacks. Call once from start_server().
    /// @param client Client pointer passed through to ws_server (required by ws_server API).
    /// @param psram_stack True to allocate the server task stack from PSRAM.
    /// @param priority FreeRTOS task priority for the server task.
    void init_server(SendspinClient* client, bool psram_stack, unsigned priority);

    /// @brief Drives connection state: starts server when network ready, processes lifecycle
    /// events, retries hello, calls loop() on active connections.
    void loop();

    // ========================================
    // Connection queries
    // ========================================

    /// @brief Returns true if there is an active connection with completed handshake.
    /// @return True if connected and handshake is complete, false otherwise.
    bool is_connected() const;

    /// @brief Returns the current active connection.
    /// @return Pointer to the current connection, or nullptr if none.
    // NOTE: not inlined due to incomplete SendspinConnection type
    SendspinConnection* current() const {
        return this->current_connection_.get();
    }

    /// @brief Returns the pending handoff connection.
    /// @return Pointer to the pending connection, or nullptr if none.
    // NOTE: not inlined due to incomplete SendspinConnection type
    SendspinConnection* pending() const {
        return this->pending_connection_.get();
    }

    // ========================================
    // Event queuing (thread-safe)
    // ========================================

    /// @brief Schedules a server hello event for deferred processing in loop().
    /// @param event The server hello event to schedule (moved).
    void schedule_hello(ServerHelloEvent event);

    // ========================================
    // Handoff support
    // ========================================

    /// @brief Sets the last-played server hash for handoff preference decisions.
    /// @param hash FNV-1 hash of the last-played server ID.
    void set_last_played_server_hash(uint32_t hash);

    /// @brief FNV-1 hash function for strings.
    static uint32_t fnv1_hash(const char* str);

private:
    // ========================================
    // Connection setup
    // ========================================
    /// @brief Attaches message and lifecycle callbacks to a connection.
    /// @param conn The connection to configure.
    void setup_connection_callbacks_(SendspinConnection* conn);
    /// @brief Accepts an incoming server connection as current or pending for handoff.
    /// @param conn The newly accepted server connection.
    void on_new_connection_(std::unique_ptr<SendspinServerConnection> conn);

    // ========================================
    // Hello handshake
    // ========================================
    /// @brief Arms the hello retry state so loop() will send the hello after a 100ms initial delay.
    /// @param conn The connection to send the hello to.
    void initiate_hello_(SendspinConnection* conn);
    /// @brief Sends the hello message to a connection, returning true if no retry is needed.
    /// @param remaining_attempts Number of send attempts remaining before giving up.
    /// @param conn The connection to send the hello to.
    /// @return True if done (sent or connection invalid), false if the send failed and should
    /// retry.
    bool send_hello_message_(uint8_t remaining_attempts, SendspinConnection* conn);

    // ========================================
    // Connection lifecycle
    // ========================================
    /// @brief Tears down a lost connection and promotes the pending connection if one exists.
    /// @param conn The connection that was lost.
    void on_connection_lost_(SendspinConnection* conn);
    /// @brief Decides whether to switch from the current connection to the new one.
    /// @param current The existing active connection.
    /// @param new_conn The newly connected candidate connection.
    /// @return True if the new connection should become current, false to keep the existing one.
    bool should_switch_to_new_server_(SendspinConnection* current, SendspinConnection* new_conn);
    /// @brief Completes a server handoff by promoting or discarding the pending connection.
    /// @param switch_to_new True to promote the pending connection, false to discard it.
    void complete_handoff_(bool switch_to_new);
    /// @brief Sends a goodbye, then defers destruction of the connection until loop() runs.
    /// @param conn The connection to disconnect and release.
    /// @param reason The goodbye reason to send before closing.
    void disconnect_and_release_(std::unique_ptr<SendspinConnection> conn,
                                 SendspinGoodbyeReason reason);

    // Struct fields
    std::mutex conn_mutex_;  // Protects deferred lifecycle events
    HelloRetryState hello_retry_;
    std::vector<int> pending_close_events_;
    std::vector<SendspinConnection*> pending_disconnect_events_;
    std::vector<ServerHelloEvent> pending_hello_events_;

    // Pointer fields
    SendspinClient* client_;
    std::unique_ptr<SendspinConnection> current_connection_;
    std::shared_ptr<SendspinConnection> dying_connection_;
    std::unique_ptr<SendspinConnection> pending_connection_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // 32-bit fields
    uint32_t last_played_server_hash_{0};
    unsigned task_priority_{17};

    // 8-bit fields
    bool dying_connection_ready_to_release_{false};
    bool has_last_played_server_{false};
    bool psram_stack_{false};
};

}  // namespace sendspin
