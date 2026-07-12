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

#include "sendspin/config.h"
#include <esp_http_server.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinConnection;
class SendspinServerConnection;

/// @brief An accepted httpd session whose WebSocket upgrade has not yet been observed.
///
/// The session slot (httpd_sess_set_ctx) remains the authoritative owner of the connection;
/// this entry's shared_ptr is dropped when the session is delivered, closed, or reaped.
struct PendingUpgrade {
    std::shared_ptr<SendspinServerConnection> conn;  ///< Parallel refcount to the session slot
    int64_t accept_time_us;                          ///< Accept stamp for the upgrade deadline
    int sockfd;                                      ///< httpd socket fd, the lookup key
};

/**
 * @brief WebSocket server listener for Sendspin
 *
 * Manages the ESP-IDF HTTP server (httpd) that listens for incoming WebSocket
 * connections from Sendspin servers. The authoritative owner of each accepted
 * SendspinServerConnection is the httpd session itself: open_callback() pins a
 * shared_ptr onto the session via httpd_sess_set_ctx with a free_fn deleter, and
 * the websocket_handler / queued workers look the connection up at run time via
 * httpd_sess_get_ctx. ConnectionManager receives the same shared_ptr as a secondary
 * observer for routing and handoff decisions.
 *
 * Delivery contract: a connection is delivered to the NewConnectionCallback only once its
 * WebSocket upgrade has been observed, so the rest of the library never sees sockets that might
 * not speak WebSocket. Accepted-but-not-yet-upgraded sessions wait in a pending table until the
 * upgrade signal fires: the HTTP_GET branch of websocket_handler. IDF <= 5.5.4 / 6.0.0 dispatches
 * the upgrade GET to the handler natively; IDF >= 5.5.5 / 6.0.1 reaches the same branch through
 * ws_post_handshake_cb, which is registered as websocket_handler itself and invoked with the same
 * GET request at the same lifecycle position. The component's Kconfig selects
 * CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT wherever it exists. tick() reaps sessions still
 * undelivered after WS_UPGRADE_TIMEOUT_US; httpd has no handshake timeout of its own and
 * max_open_sockets is small, so a held-open raw TCP probe would otherwise pin a socket slot
 * indefinitely (the ESP variant of issue #75).
 *
 * Capabilities:
 * - Accepts incoming WebSocket connections on a configurable dedicated port
 * - Routes WebSocket messages directly via the session-pinned shared_ptr (no cross-thread
 *   find-by-sockfd lookup is needed)
 * - Manages open/close callbacks to notify the client of connection lifecycle events
 * - Supports up to max_connections simultaneous sockets (default:
 *   SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS) so a second server can connect while
 *   one is already active (handoff) and a surplus peer can still be greeted with a goodbye
 *
 * Usage:
 * 1. Construct with a SendspinClient pointer (passed to start())
 * 2. Register callbacks via set_new_connection_callback() and set_connection_closed_callback()
 *    (set_find_connection_callback() is a no-op stub on ESP, kept for symmetry with the host build)
 * 3. Call start() to begin listening for incoming connections
 * 4. Call tick() periodically (the ConnectionManager loop does this) to reap sessions whose
 *    upgrade never completed
 * 5. Call stop() to shut down the server
 *
 * @code
 * SendspinWsServer ws_server;
 * ws_server.set_new_connection_callback([&](std::shared_ptr<SendspinServerConnection> conn) {
 *     client.on_new_server_connection(std::move(conn));
 * });
 * ws_server.set_connection_closed_callback([&](std::shared_ptr<SendspinServerConnection> conn) {
 *     client.on_server_connection_closed(std::move(conn));
 * });
 * ws_server.start(&client, true, 5);
 * @endcode
 */
class SendspinWsServer {
public:
    SendspinWsServer() = default;
    ~SendspinWsServer();

    /// @brief Callback type for notifying the client of new connections
    /// The client receives a shared_ptr; the connection is also pinned to the httpd session via
    /// httpd_sess_set_ctx, which acts as the authoritative owner for the connection's lifetime.
    using NewConnectionCallback = std::function<void(std::shared_ptr<SendspinServerConnection>)>;

    /// @brief Callback type for notifying the client when a session closes
    /// Passes the closed connection itself rather than its sockfd: the OS recycles fds after
    /// close(), so an fd-keyed event drained later (on the manager loop) could be mis-routed to
    /// a new connection that was accepted onto the recycled fd in the meantime.
    using ConnectionClosedCallback = std::function<void(std::shared_ptr<SendspinServerConnection>)>;

    /// @brief Callback type for looking up a connection by sockfd.
    /// Returns a shared_ptr to keep the connection alive during message dispatch.
    using FindConnectionCallback = std::function<std::shared_ptr<SendspinConnection>(int sockfd)>;

    /// @brief Starts the HTTP server and begins listening for WebSocket connections
    /// @param client Pointer to the SendspinClient (used for context in callbacks).
    /// @param task_stack_in_psram Whether to allocate the HTTP server task stack in PSRAM.
    /// @param task_priority Priority for the HTTP server task.
    /// @return true if server started successfully, false otherwise.
    bool start(SendspinClient* client, bool task_stack_in_psram, unsigned task_priority);

    /// @brief Stops the HTTP server
    void stop();

    /// @brief Closes sessions still undelivered after WS_UPGRADE_TIMEOUT_US (raw TCP probes that
    /// never speak WebSocket; httpd has no handshake timeout of its own). Called from the
    /// ConnectionManager loop.
    void tick();

    /// @brief Sets the callback to invoke when a socket closes
    /// @param callback The callback function.
    void set_connection_closed_callback(ConnectionClosedCallback&& callback) {
        this->connection_closed_callback_ = std::move(callback);
    }

    /// @brief Sets callback to find a connection by socket fd
    ///
    /// On ESP this is a no-op: `websocket_handler` runs on the httpd task and looks the connection
    /// up directly via `httpd_sess_get_ctx`, which is also where the connection's authoritative
    /// owner lives. The setter is kept for API symmetry with the host build.
    /// @param callback Ignored.
    void set_find_connection_callback(FindConnectionCallback&& /*callback*/) {}

    /// @brief Configures the maximum number of simultaneous connections
    /// The default supports handoff plus graceful rejection: one established connection, the
    /// manager's nursery, and one spare socket so a surplus peer can receive a goodbye (see
    /// ConnectionManager::NURSERY_CAPACITY's socket-budget invariant).
    /// @param max_connections Maximum number of open sockets (1-7).
    void set_max_connections(uint8_t max_connections) {
        this->max_connections_ = max_connections;
    }

    /// @brief Sets the TCP port the WebSocket server listens on
    /// @param port Port number.
    void set_port(uint16_t port) {
        this->server_port_ = port;
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

    /// @brief WebSocket message handler registered with httpd. Doubles as the
    /// ws_post_handshake_cb on IDF versions that provide it: httpd then invokes it with the
    /// upgrade GET request, restoring the pre-6.0.1 dispatch so the HTTP_GET branch is the
    /// single handshake-time upgrade signal on every version.
    static esp_err_t websocket_handler(httpd_req_t* req);

    /// @brief Pops the pending entry for @p sockfd and delivers its connection, marked
    /// WS-upgraded, to the new-connection callback. No-op if the session was already closed or
    /// reaped; the pending-table pop resolves a delivery racing the tick() reap exactly-once.
    /// @param sockfd The socket file descriptor whose upgrade was observed.
    void deliver_upgraded(int sockfd);

    /// @brief Removes the pending entry for @p sockfd and returns its connection.
    /// @param sockfd The socket file descriptor to look up.
    /// @return The pending connection, or nullptr if the session was not pending.
    std::shared_ptr<SendspinServerConnection> pop_pending(int sockfd);

    // Struct fields

    /// @brief Guards pending_. Held only for table mutation/scan; delivery and closing happen
    /// outside it (the new-connection callback takes the manager's locks).
    std::mutex pending_mutex_;

    /// @brief Accepted sessions whose WebSocket upgrade has not yet been observed
    std::vector<PendingUpgrade> pending_;

    /// @brief Callback to notify the client when a socket closes
    ConnectionClosedCallback connection_closed_callback_;

    /// @brief Callback to notify the client of new connections
    NewConnectionCallback new_connection_callback_;

    // Pointer fields

    /// @brief Pointer to the SendspinClient (stored as user context for callbacks)
    SendspinClient* client_{nullptr};

    /// @brief The HTTP server handle
    httpd_handle_t server_{nullptr};

    // Numeric fields

    /// @brief Maximum number of simultaneous connections (see set_max_connections)
    uint8_t max_connections_{SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS};

    /// @brief TCP port the WebSocket server listens on
    uint16_t server_port_{SendspinClientConfig::DEFAULT_SERVER_PORT};

    /// @brief httpd control port override (0 = use ESP_HTTPD_DEF_CTRL_PORT + 1)
    uint16_t ctrl_port_{0};
};

}  // namespace sendspin
