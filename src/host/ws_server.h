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

#include <ixwebsocket/IXWebSocketServer.h>

#include <cstdint>
#include <functional>
#include <memory>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinServerConnection;

class SendspinWsServer {
public:
    SendspinWsServer() = default;
    ~SendspinWsServer();

    using NewConnectionCallback = std::function<void(std::unique_ptr<SendspinServerConnection>)>;
    using ConnectionClosedCallback = std::function<void(int sockfd)>;
    using FindConnectionCallback = std::function<SendspinServerConnection*(int sockfd)>;

    /// @brief Starts the WebSocket server on port 8928.
    /// @param client Pointer to the SendspinClient (stored for context).
    /// @param task_stack_in_psram Ignored on host builds.
    /// @param task_priority Ignored on host builds.
    /// @return true if server started successfully.
    bool start(SendspinClient* client, bool task_stack_in_psram, unsigned task_priority);

    /// @brief Stops the WebSocket server and releases its resources
    void stop();

    /// @brief Sets the callback invoked when a client connection closes
    /// @param callback Function called with the socket fd of the closed connection.
    void set_connection_closed_callback(ConnectionClosedCallback&& callback) {
        this->connection_closed_callback_ = std::move(callback);
    }

    /// @brief Sets the callback used to look up an existing connection by socket fd
    /// @param callback Function that returns the connection for a given socket fd, or nullptr.
    void set_find_connection_callback(FindConnectionCallback&& callback) {
        this->find_connection_callback_ = std::move(callback);
    }

    /// @brief Sets the maximum number of simultaneous client connections
    /// @param max_connections Maximum connection count.
    void set_max_connections(uint8_t max_connections) {
        this->max_connections_ = max_connections;
    }

    /// @brief Sets the callback invoked when a new client connection is accepted
    /// @param callback Function called with ownership of the new SendspinServerConnection.
    void set_new_connection_callback(NewConnectionCallback&& callback) {
        this->new_connection_callback_ = std::move(callback);
    }

    /// @brief Returns true if the WebSocket server has been started.
    /// @return true if the server is currently running.
    bool is_started() const {
        return this->server_ != nullptr;
    }

protected:
    // Struct fields
    ConnectionClosedCallback connection_closed_callback_;
    FindConnectionCallback find_connection_callback_;
    NewConnectionCallback new_connection_callback_;

    // Pointer fields
    SendspinClient* client_{nullptr};
    std::unique_ptr<ix::WebSocketServer> server_;

    // 8-bit fields
    uint8_t max_connections_{2};
};

}  // namespace sendspin
