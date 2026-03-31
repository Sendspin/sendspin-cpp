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

/// @file ws_server.h
/// @brief ESP-IDF WebSocket server listener that accepts incoming Sendspin server connections

#pragma once

#include <esp_http_server.h>

#include <functional>
#include <memory>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinServerConnection;

/**
 * @brief WebSocket server listener for Sendspin
 *
 * Manages the ESP-IDF HTTP server (httpd) that listens for incoming WebSocket
 * connections from Sendspin servers. It does not own the connections long-term;
 * instead, it creates SendspinServerConnection instances and hands them to the
 * client, which decides whether to accept or reject them based on handoff logic.
 *
 * Capabilities:
 * - Accepts incoming WebSocket connections on a dedicated port
 * - Routes WebSocket messages to the appropriate connection object
 * - Manages open/close callbacks to notify the client of connection lifecycle events
 * - Supports up to max_connections simultaneous sockets (default: 2) to enable the
 *   handoff protocol where a second server can connect while one is already active
 *
 * Usage:
 * 1. Construct with a SendspinClient pointer (passed to start())
 * 2. Register callbacks via set_new_connection_callback(), set_connection_closed_callback(),
 *    and set_find_connection_callback()
 * 3. Call start() to begin listening for incoming connections
 * 4. Call stop() to shut down the server
 *
 * @code
 * SendspinWsServer ws_server;
 * ws_server.set_new_connection_callback([&](std::unique_ptr<SendspinServerConnection> conn) {
 *     client.on_new_server_connection(std::move(conn));
 * });
 * ws_server.set_connection_closed_callback([&](int sockfd) {
 *     client.on_server_connection_closed(sockfd);
 * });
 * ws_server.set_find_connection_callback([&](int sockfd) -> SendspinServerConnection* {
 *     return client.find_server_connection(sockfd);
 * });
 * ws_server.start(&client, true, 5);
 * @endcode
 */
class SendspinWsServer {
public:
    SendspinWsServer() = default;
    ~SendspinWsServer();

    /// @brief Callback type for notifying the client of new connections
    /// The client receives ownership of the connection and must decide whether to keep it.
    using NewConnectionCallback = std::function<void(std::unique_ptr<SendspinServerConnection>)>;

    /// @brief Callback type for notifying the client when a socket closes
    /// The client needs to identify which connection owns this sockfd and clean it up.
    using ConnectionClosedCallback = std::function<void(int sockfd)>;

    /// @brief Callback type for looking up a connection by sockfd
    using FindConnectionCallback = std::function<SendspinServerConnection*(int sockfd)>;

    /// @brief Starts the HTTP server and begins listening for WebSocket connections
    /// @param client Pointer to the SendspinClient (used for context in callbacks).
    /// @param task_stack_in_psram Whether to allocate the HTTP server task stack in PSRAM.
    /// @param task_priority Priority for the HTTP server task.
    /// @return true if server started successfully, false otherwise.
    bool start(SendspinClient* client, bool task_stack_in_psram, unsigned task_priority);

    /// @brief Stops the HTTP server
    void stop();

    /// @brief Sets the callback to invoke when a socket closes
    /// @param callback The callback function.
    void set_connection_closed_callback(ConnectionClosedCallback&& callback) {
        this->connection_closed_callback_ = std::move(callback);
    }

    /// @brief Sets callback to find a connection by socket fd
    /// @param callback The callback function.
    void set_find_connection_callback(FindConnectionCallback&& callback) {
        this->find_connection_callback_ = std::move(callback);
    }

    /// @brief Configures the maximum number of simultaneous connections
    /// Default is 2 to support the handoff protocol (one active + one pending).
    /// @param max_connections Maximum number of open sockets (1-7).
    void set_max_connections(uint8_t max_connections) {
        this->max_connections_ = max_connections;
    }

    /// @brief Overrides the ESP-IDF httpd control port
    /// Defaults to 0 (uses ESP_HTTPD_DEF_CTRL_PORT + 1 to avoid conflict with web_server).
    /// @param ctrl_port Control port number; 0 = use default.
    void set_ctrl_port(uint16_t ctrl_port) {
        this->ctrl_port_ = ctrl_port;
    }

    /// @brief Sets the callback to invoke when a new connection is accepted
    /// @param callback The callback function.
    void set_new_connection_callback(NewConnectionCallback&& callback) {
        this->new_connection_callback_ = std::move(callback);
    }

    /// @brief Checks if the server is currently running
    /// @return true if the server is started, false otherwise.
    bool is_started() const {
        return this->server_ != nullptr;
    }

    /// @brief Gets the httpd handle (for use by connections)
    /// @return The httpd server handle, or nullptr if not started.
    httpd_handle_t get_server() const {
        return this->server_;
    }

protected:
    /// @brief Callback invoked when a new client opens a connection
    /// Creates a SendspinServerConnection and notifies the client.
    /// @param handle The httpd server handle.
    /// @param sockfd The socket file descriptor for the new connection.
    /// @return ESP_OK on success.
    static esp_err_t open_callback(httpd_handle_t handle, int sockfd);

    /// @brief Callback invoked when a client closes a connection
    /// @param handle The httpd server handle.
    /// @param sockfd The socket file descriptor being closed.
    static void close_callback(httpd_handle_t handle, int sockfd);

    /// @brief WebSocket message handler registered with httpd
    static esp_err_t websocket_handler(httpd_req_t* req);

    // Struct fields

    /// @brief Callback to notify the client when a socket closes
    ConnectionClosedCallback connection_closed_callback_;

    /// @brief Callback to find a connection by socket fd
    FindConnectionCallback find_connection_callback_;

    /// @brief Callback to notify the client of new connections
    NewConnectionCallback new_connection_callback_;

    // Pointer fields

    /// @brief Pointer to the SendspinClient (stored as user context for callbacks)
    SendspinClient* client_{nullptr};

    /// @brief The HTTP server handle
    httpd_handle_t server_{nullptr};

    // 8-bit fields

    /// @brief Maximum number of simultaneous connections (default: 2 for handoff)
    uint8_t max_connections_{2};

    /// @brief httpd control port override (0 = use ESP_HTTPD_DEF_CTRL_PORT + 1)
    uint16_t ctrl_port_{0};
};

}  // namespace sendspin
