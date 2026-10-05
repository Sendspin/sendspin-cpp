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

#include "platform/memory.h"
#include "sendspin/config.h"
#include "server_connection.h"
#include <esp_err.h>
#include <esp_http_server.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinConnection;

/// @brief An accepted httpd session whose WebSocket upgrade has not yet been observed.
///
/// The session slot (httpd_sess_set_ctx) remains the authoritative owner of the connection;
/// this entry's shared_ptr is dropped when the session is delivered, closed, or reaped.
struct PendingUpgrade {
    std::shared_ptr<SendspinServerConnection> conn;  ///< Parallel refcount to the session slot
    int64_t accept_time_us{0};                       ///< Accept stamp for the upgrade deadline
    int sockfd{-1};                                  ///< httpd socket fd, the lookup key
};

/**
 * @brief WebSocket server listener for Sendspin
 *
 * Manages the ESP-IDF httpd that listens for incoming WebSocket connections. The authoritative
 * owner of each accepted SendspinServerConnection is the httpd session: open_callback() pins a
 * shared_ptr via httpd_sess_set_ctx with a free_fn deleter, and the handlers look it back up
 * with httpd_sess_get_ctx. ConnectionManager holds the same shared_ptr as a secondary observer.
 *
 * Delivery contract: a connection reaches the NewConnectionCallback only once its WebSocket
 * upgrade has been observed in the HTTP_GET branch of websocket_handler, so the rest of the
 * library never sees a socket that might not speak WebSocket; until then it waits in the pending
 * table. IDF >= 5.5.5 / 6.0.1 reaches that branch through ws_post_handshake_cb instead of native
 * GET dispatch; the component's Kconfig selects CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT
 * wherever it exists. tick() reaps sessions still undelivered after WS_UPGRADE_TIMEOUT_US, since
 * httpd has no handshake timeout of its own and max_open_sockets is small.
 */
class SendspinWsServer {
public:
    SendspinWsServer() = default;
    ~SendspinWsServer();

    /// @brief Callback type for notifying the client of new connections
    /// The client receives a shared_ptr; the connection is also pinned to the httpd session via
    /// httpd_sess_set_ctx, which acts as the authoritative owner for the connection's lifetime.
    using NewConnectionCallback = std::function<void(std::shared_ptr<SendspinServerConnection>)>;

    /// @brief Starts the HTTP server and begins listening for WebSocket connections
    /// @param client Pointer to the SendspinClient (used for context in callbacks).
    /// @param task_stack_in_psram Whether to allocate the HTTP server task stack in PSRAM.
    /// @param task_priority Priority for the HTTP server task.
    /// @param task_stack_size HTTP server task stack size in bytes. Clamped up to
    ///        SendspinClientConfig::DEFAULT_HTTPD_STACK_SIZE if lower.
    /// @return true if server started successfully, false otherwise.
    bool start(SendspinClient* client, bool task_stack_in_psram, unsigned task_priority,
               size_t task_stack_size);

    /// @brief Stops the HTTP server
    void stop();

    /// @brief Closes sessions still undelivered after WS_UPGRADE_TIMEOUT_US (raw TCP probes that
    /// never speak WebSocket; httpd has no handshake timeout of its own). Called from the
    /// ConnectionManager loop.
    void tick();

    /// @brief Configures the maximum number of simultaneous connections
    /// The default supports handoff plus graceful rejection: one established connection, the
    /// manager's nursery, and one spare socket so a surplus peer can receive a goodbye (see
    /// ConnectionManager::NURSERY_CAPACITY's socket-budget invariant).
    /// @param max_connections Maximum number of open sockets (1-7).
    void set_max_connections(uint8_t max_connections) {
        this->max_connections_ = max_connections;
    }

    /// @brief Sets the TCP port the WebSocket server listens on
    void set_port(uint16_t port) {
        this->server_port_ = port;
    }

    /// @brief Overrides the ESP-IDF httpd control port
    /// Defaults to 0 (uses ESP_HTTPD_DEF_CTRL_PORT + 1 to avoid conflict with web_server).
    void set_ctrl_port(uint16_t ctrl_port) {
        this->ctrl_port_ = ctrl_port;
    }

    /// @brief Sets the callback to invoke when a new connection is accepted
    void set_new_connection_callback(NewConnectionCallback&& callback) {
        this->new_connection_callback_ = std::move(callback);
    }

    /// @brief Whether the server is currently running
    bool is_started() const {
        return this->server_ != nullptr;
    }

    /// @brief Scratch space of INBOUND_MAX_MESSAGE_BYTES a dropped frame's payload is read into
    /// (SendspinServerConnection::discard_frame_payload()). httpd hands a frame's payload over
    /// only whole: httpd_ws_recv_frame() needs max_len >= the frame length (httpd_ws.c), so a
    /// dropped frame still needs a buffer of its size. Allocated on the first drop, PSRAM
    /// preferred, and kept until stop(), so a ring that stays full does not allocate per frame.
    /// httpd task only: every session shares that one task, so one buffer serves them all.
    /// @return nullptr when it cannot be allocated.
    uint8_t* discard_buffer();

protected:
    /// @brief Callback invoked when a new client opens a connection; creates a
    /// SendspinServerConnection and adds it to the pending table.
    static esp_err_t open_callback(httpd_handle_t handle, int sockfd);

    /// @brief Callback invoked when a client closes a connection: marks the connection closed and
    /// tells it its transport closed (SendspinConnection::notify_transport_closed())
    static void close_callback(httpd_handle_t handle, int sockfd);

    /// @brief WebSocket message handler registered with httpd. Doubles as the
    /// ws_post_handshake_cb on IDF versions that provide it: httpd then invokes it with the
    /// upgrade GET request, restoring the pre-6.0.1 dispatch so the HTTP_GET branch is the
    /// single handshake-time upgrade signal on every version.
    static esp_err_t websocket_handler(httpd_req_t* req);

    /// @brief Pops the pending entry for @p sockfd and delivers its connection, marked
    /// WS-upgraded, to the new-connection callback. No-op if the session was already closed or
    /// reaped; the pending-table pop resolves a delivery racing the tick() reap exactly-once.
    void deliver_upgraded(int sockfd);

    /// @brief Removes the pending entry for @p sockfd and returns its connection, or nullptr
    /// if the session was not pending.
    std::shared_ptr<SendspinServerConnection> pop_pending(int sockfd);

    // Struct fields

    /// @brief Guards pending_. Held only for table mutation/scan; delivery and closing happen
    /// outside it (the new-connection callback takes the manager's locks).
    std::mutex pending_mutex_;

    /// @brief Accepted sessions whose WebSocket upgrade has not yet been observed
    std::vector<PendingUpgrade> pending_;

    NewConnectionCallback new_connection_callback_;

    /// @brief Blocks for every accepted connection's queued sends. A member so it outlives each
    /// queued send (the destructor stops the server first); it adds
    /// SEND_BLOCK_SIZE * SEND_BLOCK_COUNT bytes to the server object.
    SendBlockPool send_pool_;

    /// @brief See discard_buffer(). httpd task only; released by stop() once httpd has stopped.
    PlatformBuffer discard_buf_;

    // Pointer fields

    /// @brief Stored as the httpd user context for the static callbacks
    SendspinClient* client_{nullptr};

    httpd_handle_t server_{nullptr};

    // Numeric fields

    uint8_t max_connections_{SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS};

    uint16_t server_port_{SendspinClientConfig::DEFAULT_SERVER_PORT};

    /// @brief httpd control port override (0 = use ESP_HTTPD_DEF_CTRL_PORT + 1)
    uint16_t ctrl_port_{0};
};

}  // namespace sendspin
