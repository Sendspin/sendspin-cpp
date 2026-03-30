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

/// @file Host build version of server_connection.h (IXWebSocket-based).
/// ESP-IDF version lives in src/esp/sendspin/server_connection.h.

#pragma once

#include "connection.h"
#include <ixwebsocket/IXWebSocket.h>

#include <functional>
#include <memory>

namespace sendspin {

class SendspinServerConnection : public SendspinConnection {
public:
    /// @brief Constructs a server connection wrapping an IXWebSocket.
    /// @param ws The IXWebSocket shared pointer from the server.
    /// @param sockfd Synthetic socket identifier for connection lookup.
    SendspinServerConnection(std::shared_ptr<ix::WebSocket> ws, int sockfd);

    ~SendspinServerConnection() override = default;

    /// @brief No-op on server connections; the transport is already established when this is called
    void start() override;

    /// @brief No-op on server connections; state is event-driven via handle_message()
    void loop() override;

    /// @brief Sends a goodbye message and closes the connection
    /// @param reason Reason for disconnecting.
    /// @param on_complete Callback invoked after the connection is closed.
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;

    /// @brief Returns true if the underlying WebSocket connection is open
    /// @return true if connected, false otherwise.
    bool is_connected() const override;

    /// @brief Sends a text message to the connected client
    /// @param message The message string to send.
    /// @param on_complete Callback invoked after send completes (success, actual_send_time).
    /// @return SsErr::OK if sent successfully, error code otherwise.
    SsErr send_text_message(const std::string& message, SendCompleteCallback on_complete) override;

    /// @brief Requests the WebSocket connection to close
    void trigger_close();

    /// @brief Returns the underlying socket file descriptor for this connection.
    /// @return Socket file descriptor, or -1 if not connected.
    int get_sockfd() const override {
        return this->sockfd_;
    }

    /// @brief Handles an incoming complete message from IXWebSocket.
    /// Called from the ws_server's message callback.
    void handle_message(const std::string& data, bool is_binary, int64_t receive_time);

protected:
    // Pointer fields
    std::shared_ptr<ix::WebSocket> ws_;

    // 32-bit fields
    int sockfd_{-1};
};

}  // namespace sendspin
