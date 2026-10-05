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
 * Handles the connection lifecycle. A lost connection is not reopened: connect_to() opens a new
 * one.
 */
class SendspinClientConnection : public SendspinConnection {
public:
    /// @brief esp_websocket_client's network_timeout_ms, set explicitly at start(): the bound on
    /// each step of the connect (the TCP connect, the upgrade request, its response) and on each
    /// transport read and write after it. esp_websocket_client's own default, which it warns
    /// about using.
    static constexpr uint32_t NETWORK_TIMEOUT_MS = 10000U;

    /// @brief How long a released connection stays parked for reaping before it is dropped with
    /// its transport still connecting (ReapEntry in connection_manager.h)
    ///
    /// The whole connect: esp_transport_connect() runs the TCP connect, the upgrade request's
    /// write and the read of its response, each bounded by NETWORK_TIMEOUT_MS, and
    /// esp_websocket_client_stop() cannot interrupt it. The DNS lookup before them
    /// (getaddrinfo()) is not under that timeout but under lwIP's resolver, which gives up on a
    /// server after 7 s (DNS_MAX_RETRIES of 4 at DNS_TMR_INTERVAL ticks of 1 s, waiting 1, 1, 2
    /// and 3 ticks) and tries each configured one in turn (CONFIG_LWIP_DNS_MAX_SERVERS, 3 by
    /// default; an mDNS query tries once). So a drop at the deadline still pays up to that
    /// resolver bound, about 21 s by default, in the destructor's stop, which waits for the
    /// websocket task to exit.
    /// The handle is not handed to esp_websocket_client_destroy_on_exit() instead: the event
    /// handler registered on it takes this connection as its argument, so the handle must not
    /// outlive the connection, and nothing short of a stop ends the attempt early.
    static constexpr uint32_t CONNECT_TIMEOUT_MS = 3 * NETWORK_TIMEOUT_MS;

    /// @brief Constructs a client connection to a URL such as "ws://server.local:8927/sendspin"
    explicit SendspinClientConnection(std::string url);

    ~SendspinClientConnection() override;

    // ========================================
    // SendspinConnection interface implementation
    // ========================================

    /// @brief Starts the connection (initializes websocket client and connects)
    void start() override;

    /// @brief Disconnects from the server with a goodbye message
    /// @param on_complete Optional; the goodbye is synchronous here, so it runs immediately.
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;

    /// @brief Closes the transport immediately without blocking (see base class doc comment).
    /// Stops taking frames without touching the transport; the actual
    /// esp_websocket_client_stop() runs later in the destructor once the manager drops this
    /// connection (off the websocket task, and for a released one once its transport reported the
    /// close or its reaping deadline passed), because esp_websocket_client_stop() cannot be called
    /// from the websocket task's own event handler and blocks until that task exits.
    void close_transport_now() override;

    /// @brief Whether the websocket connection is established
    bool is_connected() const override;

    bool is_outbound() const override {
        return true;
    }

    /// @brief Sends a text message to the server with a completion callback
    SsErr send_text_message(const std::string& message, SendCompleteCallback cb,
                            bool allow_before_hello) override;

    /// @brief Sends a binary WebSocket frame to the server
    /// @param allow_before_hello If true, bypasses the pre-hello send gate.
    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                              bool allow_before_hello) override;

    // ========================================
    // Client connection-specific configuration
    // ========================================

    /// @brief Configures the internal esp_websocket_client task
    /// @param priority FreeRTOS task priority for the WebSocket client task.
    /// @param stack_size Task stack size in bytes. Values below
    ///     SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE are clamped up to it in start().
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

    /// @brief Handles websocket data event: copies the chunk into the message's destination and
    /// hands a complete message to the protocol task
    /// @param data Pointer to websocket event data.
    /// @param receive_time Timestamp when the event was received (for time synchronization).
    void handle_data(const esp_websocket_event_data_t* data, int64_t receive_time);

    /// @brief Handles websocket error event
    void handle_error();

    /// @brief Handles the websocket task's exit (WEBSOCKET_EVENT_FINISH): the transport's close,
    /// whichever way the task ended, including a stop that posts no DISCONNECTED
    void handle_finished();

    // Struct fields

    /// @brief The WebSocket server URL
    std::string url_;

    // Pointer fields

    /// @brief The ESP-IDF websocket client handle
    esp_websocket_client_handle_t client_{nullptr};

    /// @brief Where the current single-frame message's chunks go, or nullptr while none is
    /// being received (or it is dropped). Websocket task only.
    uint8_t* chunk_dest_{nullptr};

    // 32-bit fields

    // 32-bit fields (unsigned)

    /// @brief FreeRTOS task priority for the internal esp_websocket_client task
    unsigned task_priority_{5};

    /// @brief Stack size in bytes for the internal esp_websocket_client task
    size_t task_stack_size_{SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE};

    // 8-bit fields

    /// @brief Whether the websocket is currently connected. Written by the transport task,
    /// read cross-thread via is_connected(), hence atomic.
    std::atomic<bool> connected_{false};
};

}  // namespace sendspin
