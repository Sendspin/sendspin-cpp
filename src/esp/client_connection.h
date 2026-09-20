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
#include "platform/types.h"
#include "sendspin/config.h"
#include "sendspin/types.h"
#include <esp_websocket_client.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace sendspin {

/**
 * @brief Outbound WebSocket connection to a Sendspin server (ESP-IDF, esp_websocket_client)
 *
 * Implements SendspinConnection for the client role: the ESP device connects out to the server.
 * Handles the full connection lifecycle and auto-reconnect on connection loss; loop() drives the
 * reconnect timer.
 */
class SendspinClientConnection : public SendspinConnection {
public:
    /// @brief Constructs a client connection to a URL such as "ws://server.local:8927/sendspin"
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
    /// @param on_complete Optional; the goodbye is synchronous here, so it runs immediately.
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;

    /// @brief Closes the transport immediately without blocking (see base class doc comment).
    /// Reports the loss via handle_disconnected() without touching the transport; the actual
    /// esp_websocket_client_stop() runs later in the destructor once the manager drops this
    /// connection (off the websocket task), because esp_websocket_client_stop() cannot be called
    /// from the websocket task's own event handler.
    void close_transport_now() override;

    /// @brief Whether the websocket connection is established
    bool is_connected() const override;

    /// @brief Sends a text message to the server with a completion callback
    SsErr send_text_message(const std::string& message, SendCompleteCallback cb,
                            bool allow_before_hello) override;

    /// @brief Sends a client/time message, capturing the timestamp just before send
    bool send_time_message() override;

    /// @brief Sends a binary WebSocket frame to the server
    /// @param allow_before_hello If true, bypasses the pre-hello send gate.
    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                              bool allow_before_hello) override;

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
    /// @param stack_size Task stack size in bytes. Values below
    ///     SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE are clamped up to it in start()
    ///     (see the rationale on that constant: the Noise handshake, including the in-band
    ///     re-handshake, runs inline on this task).
    void set_task_config(unsigned priority, size_t stack_size) {
        this->task_priority_ = priority;
        this->task_stack_size_ = stack_size;
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

    /// @brief Stack size in bytes for the internal esp_websocket_client task
    size_t task_stack_size_{SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE};

    // 8-bit fields

    /// @brief Whether to automatically reconnect after connection loss
    bool auto_reconnect_{true};

    /// @brief Whether the websocket is currently connected. Written by the transport task,
    /// read cross-thread via is_connected(), hence atomic.
    std::atomic<bool> connected_{false};
};

}  // namespace sendspin
