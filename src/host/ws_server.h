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
/// @brief Host build WebSocket server listener that accepts incoming Sendspin server connections
/// using IXWebSocket

#pragma once

#include "sendspin/config.h"
#include <ixwebsocket/IXWebSocketServer.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinConnection;
class SendspinServerConnection;

/**
 * @brief WebSocket server that listens for incoming Sendspin client connections (host build)
 *
 * Wraps an IXWebSocket server listening on the configured port. A SendspinServerConnection is
 * created and delivered via the NewConnectionCallback only once the peer completes the WebSocket
 * upgrade (the Open event); sockets that never complete the handshake are closed by IXWebSocket's
 * server-side handshake timeout, which start() pins explicitly (WS_HANDSHAKE_TIMEOUT_SECS, 3 s)
 * so the bound cannot be silently rescoped by an IXWebSocket upgrade. Such sockets are invisible
 * to the rest of the library. Connection close events are reported via ConnectionClosedCallback.
 *
 */
class SendspinWsServer {
public:
    SendspinWsServer() = default;
    ~SendspinWsServer();

    /// @brief Callback type for notifying the client of new connections
    using NewConnectionCallback = std::function<void(std::shared_ptr<SendspinServerConnection>)>;

    /// @brief Callback type for notifying the client when a connection closes
    /// Passes the closed connection itself rather than its sockfd, matching the ESP build (where
    /// fd recycling makes fd-keyed close events ambiguous by the time the manager drains them).
    using ConnectionClosedCallback = std::function<void(std::shared_ptr<SendspinServerConnection>)>;

    /// @brief Callback type for looking up a connection by sockfd.
    /// Returns a shared_ptr to keep the connection alive during message dispatch.
    using FindConnectionCallback = std::function<std::shared_ptr<SendspinConnection>(int sockfd)>;

    /// @brief Starts the WebSocket server on the configured port; the three task parameters are
    /// ESP-IDF httpd settings and are ignored here.
    bool start(SendspinClient* client, bool task_stack_in_psram, unsigned task_priority,
               size_t task_stack_size);

    /// @brief Stops the WebSocket server and releases its resources
    void stop();

    /// @brief No-op on host builds. On ESP the manager loop drives the pending-upgrade reap
    /// through this; here IXWebSocket delivers Open events and times out stalled handshakes on
    /// its own threads (bounded by WS_HANDSHAKE_TIMEOUT_SECS, pinned in start()). Kept as an
    /// instance method for symmetry with the ESP build.
    // cppcheck-suppress functionStatic
    void tick() {}

    /// @brief Sets the callback invoked when a client connection closes
    void set_connection_closed_callback(ConnectionClosedCallback&& callback) {
        this->connection_closed_callback_ = std::move(callback);
    }

    /// @brief Sets the callback used to look up an existing connection by socket fd
    void set_find_connection_callback(FindConnectionCallback&& callback) {
        this->find_connection_callback_ = std::move(callback);
    }

    /// @brief Sets the maximum number of simultaneous client connections
    /// The default supports handoff plus graceful rejection: one established connection, the
    /// manager's nursery, and one spare socket so a surplus peer can receive a goodbye (see
    /// ConnectionManager::NURSERY_CAPACITY's socket-budget invariant). Enforced by IXWebSocket
    /// at accept.
    void set_max_connections(uint8_t max_connections) {
        this->max_connections_ = max_connections;
    }

    /// @brief Sets the TCP port the WebSocket server listens on
    void set_port(uint16_t port) {
        this->server_port_ = port;
    }

    /// @brief No-op on host builds; the control port is an ESP-IDF httpd concept. Kept as an
    /// instance method for symmetry with the ESP build.
    // cppcheck-suppress functionStatic
    void set_ctrl_port(uint16_t /*ctrl_port*/) {}

    /// @brief Sets the callback invoked when a new client connection is accepted
    void set_new_connection_callback(NewConnectionCallback&& callback) {
        this->new_connection_callback_ = std::move(callback);
    }

    /// @brief Whether the WebSocket server is currently running
    bool is_started() const {
        return this->server_ != nullptr;
    }

protected:
    // Struct fields

    ConnectionClosedCallback connection_closed_callback_;

    FindConnectionCallback find_connection_callback_;

    NewConnectionCallback new_connection_callback_;

    // Pointer fields

    /// @brief Stored as the user context for the IX callbacks
    SendspinClient* client_{nullptr};

    std::unique_ptr<ix::WebSocketServer> server_;

    // Numeric fields

    uint8_t max_connections_{SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS};

    uint16_t server_port_{SendspinClientConfig::DEFAULT_SERVER_PORT};
};

}  // namespace sendspin
