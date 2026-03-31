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
/// @brief ESP-IDF WebSocket client connection using esp_websocket_client

#pragma once

#include "connection.h"
#include <esp_websocket_client.h>

#include <functional>
#include <string>

namespace sendspin {

/**
 * @brief A client-side WebSocket connection for Sendspin.
 *
 * This class represents an outgoing WebSocket connection to a Sendspin server.
 * It inherits from SendspinConnection and implements the SendspinConnection interface
 * for client-initiated connections (where the ESP device acts as a WebSocket client
 * and connects to a Sendspin server).
 *
 * Handles the full connection lifecycle, auto-reconnect on connection loss, and
 * satisfies the SendspinConnection interface for message send/receive.
 *
 * Usage:
 * 1. Construct with the server URL.
 * 2. Call start() to initialize the ESP-IDF WebSocket client and connect.
 * 3. Call loop() periodically to handle reconnection attempts.
 * 4. Call disconnect() to close the connection with a goodbye message.
 *
 * @code
 * SendspinClientConnection conn("ws://server.local:8927/sendspin");
 * conn.set_auto_reconnect(true);
 * conn.start();
 * // In your main loop:
 * conn.loop();
 * // When shutting down:
 * conn.disconnect(SendspinGoodbyeReason::SHUTDOWN, []() { // done
 * });
 * @endcode
 */
class SendspinClientConnection : public SendspinConnection {
public:
    /// @brief Constructs a client connection with the given server URL
    /// @param url The WebSocket server URL (e.g., "ws://server.local:8927/sendspin").
    explicit SendspinClientConnection(std::string url);

    ~SendspinClientConnection() override;

    // ========================================
    // SendspinConnection interface implementation
    // ========================================

    /// @brief Starts the connection (initializes websocket client and connects)
    void start() override;

    /// @brief Periodic loop processing (handles reconnection attempts)
    void loop() override;

    /// @brief Disconnects from the server with a goodbye message
    /// @param reason The reason for disconnecting.
    /// @param on_complete Optional callback invoked after goodbye send completes (or fails).
    ///                    For client connections, goodbye is synchronous, so callback is invoked
    ///                    immediately.
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;

    /// @brief Checks if the websocket connection is established
    /// @return true if connected, false otherwise.
    bool is_connected() const override;

    /// @brief Sends a text message to the server with a completion callback
    /// @param msg The message string to send.
    /// @param cb Callback invoked after send completes.
    /// @return SsErr::OK if sent successfully, error code otherwise.
    SsErr send_text_message(const std::string& message, SendCompleteCallback cb) override;

    // ========================================
    // Client connection-specific configuration
    // ========================================

    /// @brief Sets whether to automatically reconnect on connection loss
    /// @param enabled True to enable auto-reconnect, false to disable.
    void set_auto_reconnect(bool enabled) {
        this->auto_reconnect_ = enabled;
    }

    /// @brief Configures the internal esp_websocket_client task
    /// @param priority FreeRTOS task priority for the WebSocket client task.
    void set_task_config(unsigned priority) {
        this->task_priority_ = priority;
    }

protected:
    /// @brief Static event handler for ESP-IDF websocket client events
    /// @param handler_args User context (pointer to this SendspinClientConnection instance).
    /// @param base Event base.
    /// @param event_id Event ID.
    /// @param event_data Event data.
    static void websocket_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id,
                                        void* event_data);

    /// @brief Handles websocket connected event
    void handle_connected();

    /// @brief Handles websocket disconnected event
    void handle_disconnected();

    /// @brief Handles websocket data event
    /// @param data Pointer to websocket event data.
    /// @param receive_time Timestamp when the event was received (for time synchronization).
    void handle_data(const esp_websocket_event_data_t* data, int64_t receive_time);

    /// @brief Handles websocket error event
    void handle_error();

    // Struct fields

    /// @brief The WebSocket server URL
    std::string url_;

    // Pointer fields

    /// @brief The ESP-IDF websocket client handle
    esp_websocket_client_handle_t client_{nullptr};

    // 32-bit fields

    /// @brief Monotonic timestamp (ms) of the last reconnection attempt
    uint32_t last_reconnect_attempt_{0};

    static constexpr uint32_t DEFAULT_RECONNECT_INTERVAL_MS = 5000U;

    /// @brief Delay in milliseconds between reconnection attempts
    uint32_t reconnect_interval_ms_{DEFAULT_RECONNECT_INTERVAL_MS};

    // 32-bit fields (unsigned)

    /// @brief FreeRTOS task priority for the internal esp_websocket_client task
    unsigned task_priority_{5};

    // 8-bit fields

    /// @brief Whether to automatically reconnect after connection loss
    bool auto_reconnect_{true};

    /// @brief Whether the websocket is currently connected
    bool connected_{false};
};

}  // namespace sendspin
