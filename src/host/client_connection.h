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

/// @file client_connection.h
/// @brief Host build WebSocket client connection using IXWebSocket

#pragma once

#include "connection.h"
#include <ixwebsocket/IXWebSocket.h>

#include <functional>
#include <memory>
#include <string>

namespace sendspin {

/**
 * @brief Outbound WebSocket connection to a Sendspin server (host build, IXWebSocket)
 *
 * Connects to a server URL, delivers incoming messages via the base class callbacks,
 * and automatically reconnects after connection loss. Call loop() periodically to
 * drive the reconnect timer.
 *
 * Usage:
 * 1. Construct with the server WebSocket URL
 * 2. Set the message and state callbacks on the base SendspinConnection
 * 3. Call start() to open the connection
 * 4. Call loop() from the client's periodic task
 * 5. Call disconnect() to close the connection cleanly
 *
 * @code
 * auto conn = std::make_unique<SendspinClientConnection>("ws://192.168.1.10:8928");
 * conn->on_json_message = [](SendspinConnection*, const std::string& msg, int64_t) { handle(msg);
 * }; conn->start();
 * // periodically:
 * conn->loop();
 * @endcode
 */
class SendspinClientConnection : public SendspinConnection {
public:
    /// @brief Constructs a client connection to the given WebSocket URL
    /// @param url WebSocket URL of the Sendspin server to connect to.
    explicit SendspinClientConnection(std::string url);
    ~SendspinClientConnection() override;

    /// @brief Initiates the WebSocket connection to the server
    void start() override;

    /// @brief Drives periodic connection maintenance (reconnect timer, state machine)
    void loop() override;

    /// @brief Sends a goodbye message and closes the connection
    /// @param reason Reason for disconnecting.
    /// @param on_complete Callback invoked after the connection is closed.
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;

    /// @brief Sends a text message to the server
    /// @param message The message string to send.
    /// @param cb Callback invoked after send completes (success, actual_send_time).
    /// @return SsErr::OK if queued successfully, error code otherwise.
    SsErr send_text_message(const std::string& message, SendCompleteCallback cb) override;

    /// @brief Enables or disables automatic reconnection after connection loss
    /// @param enabled True to reconnect automatically, false to stay disconnected.
    void set_auto_reconnect(bool enabled) {
        this->auto_reconnect_ = enabled;
    }

    /// @brief Returns true if the WebSocket connection is currently open
    /// @return true if connected, false otherwise.
    bool is_connected() const override;

protected:
    /// @brief Registers the IXWebSocket message callback to handle open, close, data, and error
    /// events.
    void setup_callbacks_();

    // Pointer fields
    std::string url_;
    std::unique_ptr<ix::WebSocket> ws_;

    // 32-bit fields
    uint32_t last_reconnect_attempt_{0};
    uint32_t reconnect_interval_ms_{5000};

    // 8-bit fields
    bool auto_reconnect_{true};
    bool connected_{false};
};

}  // namespace sendspin
