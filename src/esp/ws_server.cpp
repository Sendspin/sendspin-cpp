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

#include "ws_server.h"

#include "connection.h"
#include "lwip/sockets.h"  // for close()
#include "platform/compiler.h"
#include "platform/logging.h"
#include "server_connection.h"
#include <esp_idf_version.h>
#include <esp_timer.h>

namespace sendspin {

// ============================================================================
// SendspinWsServer
// ============================================================================
//
// httpd server that accepts incoming WebSocket connections. open_callback() creates each
// SendspinServerConnection and parks it in the pending table; it is delivered to the
// SendspinClient only once its WebSocket upgrade is observed (see the delivery contract in
// ws_server.h). close_callback() cleans up the socket and drops a still-pending entry; tick()
// closes sessions still undelivered after WS_UPGRADE_TIMEOUT_US.

static const char* const TAG = "sendspin.ws_server";

/// @brief Deadline for an accepted session to complete its WebSocket upgrade
///
/// httpd has no handshake timeout of its own and max_open_sockets is small, so a raw TCP probe
/// held open without ever speaking WebSocket would pin a socket slot indefinitely (the ESP variant
/// of issue #75). Pre-upgrade sockets are a transport concern the manager never sees, so the bound
/// lives here. The host build has no equivalent: IXWebSocket applies its own 3 s server-side
/// handshake timeout.
static constexpr int64_t WS_UPGRADE_TIMEOUT_US = 5LL * 1000 * 1000;

SendspinWsServer::~SendspinWsServer() {
    this->stop();
}

bool SendspinWsServer::start(SendspinClient* client, bool task_stack_in_psram,
                             unsigned task_priority) {
    if (this->server_ != nullptr) {
        SS_LOGW(TAG, "Server already started");
        return true;
    }

    this->client_ = client;

    // Configure the HTTP server
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (task_stack_in_psram) {
        config.task_caps = MALLOC_CAP_SPIRAM;
    }
    config.task_priority = task_priority;
    config.server_port = this->server_port_;
    config.max_open_sockets = this->max_connections_;
    config.open_fn = SendspinWsServer::open_callback;
    config.close_fn = SendspinWsServer::close_callback;
    config.global_user_ctx = (void*)this;
    config.global_user_ctx_free_fn = nullptr;
    // Use the configured ctrl_port, or fall back to ESP_HTTPD_DEF_CTRL_PORT + 1 to avoid
    // conflict with the web_server component
    config.ctrl_port = (this->ctrl_port_ != 0) ? this->ctrl_port_
                                               : static_cast<uint16_t>(ESP_HTTPD_DEF_CTRL_PORT + 1);

    // Start the HTTP server
    SS_LOGI(TAG, "Starting server on port: %d (max connections: %d)", config.server_port,
            this->max_connections_);
    esp_err_t err = httpd_start(&this->server_, &config);
    if (err != ESP_OK) {
        SS_LOGE(TAG, "Error starting server: %s", esp_err_to_name(err));
        return false;
    }

    // Register the WebSocket handler. IDF >= 5.5.5 / 6.0.1 does not dispatch the upgrade GET to
    // the handler (issue #70); registering the handler itself as the post-handshake callback
    // restores that dispatch, so httpd invokes it with the same GET request at the same lifecycle
    // position and the handler's HTTP_GET branch is the single upgrade signal on every IDF version.
    // There is no fallback path: no version fires both (skip-GET builds return before invoking the
    // handler), and delivery is idempotent regardless. The component's Kconfig selects the option
    // wherever it exists, and the version-gated error below trips if a future IDF breaks that.
    const httpd_uri_t sendspin_ws_uri = {.uri = "/sendspin",
                                         .method = HTTP_GET,
                                         .handler = SendspinWsServer::websocket_handler,
                                         .user_ctx = (void*)this,
                                         .is_websocket = true,
                                         .handle_ws_control_frames = false,
                                         .supported_subprotocol = nullptr,
#ifdef CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT
                                         .ws_post_handshake_cb = SendspinWsServer::websocket_handler
#endif
    };

    err = httpd_register_uri_handler(this->server_, &sendspin_ws_uri);
    if (err != ESP_OK) {
        SS_LOGE(TAG, "Error registering URI handler: %s", esp_err_to_name(err));
        httpd_stop(this->server_);
        this->server_ = nullptr;
        return false;
    }

    return true;
}

void SendspinWsServer::stop() {
    if (this->server_ != nullptr) {
        SS_LOGD(TAG, "Stopping server");
        httpd_stop(this->server_);
        this->server_ = nullptr;
    }

    // httpd_stop tore down every session (each close_callback dropped its pending entry), so
    // this is normally already empty; clear defensively so a restart begins from a clean table.
    std::vector<PendingUpgrade> stale;
    {
        std::lock_guard<std::mutex> lock(this->pending_mutex_);
        stale.swap(this->pending_);
    }
}

void SendspinWsServer::tick() {
    if (this->server_ == nullptr) {
        return;
    }

    // Pure age-based reap: any session still undelivered past the deadline is closed, whether it
    // never spoke WebSocket (a raw probe) or its upgrade signal failed to fire (only possible if a
    // future IDF breaks the post-handshake callback; see the tripwire in start()). Sparing
    // "upgraded but undelivered" sessions here would turn that failure into a silent permanent
    // wedge of httpd's small socket pool; closing them makes it a visible close-and-retry loop
    // instead. Pop under the lock, close outside it; the pop also means a delivery racing this reap
    // resolves exactly-once (the loser finds no entry and no-ops).
    std::vector<std::shared_ptr<SendspinServerConnection>> to_reap;
    const int64_t now_us = esp_timer_get_time();
    {
        std::lock_guard<std::mutex> lock(this->pending_mutex_);
        for (auto it = this->pending_.begin(); it != this->pending_.end();) {
            // A closing session is skipped, not reaped: close_callback pops its entry.
            if (it->conn->is_connected() && now_us - it->accept_time_us >= WS_UPGRADE_TIMEOUT_US) {
                to_reap.push_back(std::move(it->conn));
                it = this->pending_.erase(it);
                continue;
            }
            ++it;
        }
    }

    for (auto& conn : to_reap) {
        SS_LOGW(TAG, "Session did not complete a WebSocket upgrade within %d s, closing",
                static_cast<int>(WS_UPGRADE_TIMEOUT_US / (1000 * 1000)));
        conn->trigger_close();
    }
}

void SendspinWsServer::deliver_upgraded(int sockfd) {
    auto conn = this->pop_pending(sockfd);
    if (conn == nullptr) {
        return;  // Already closed or reaped (a duplicate delivery cannot happen: the GET branch
                 // fires once per session)
    }

    if (!this->new_connection_callback_) {
        // Normally unreachable (open_callback rejects sessions when no callback is set), but an
        // unset consumer must close the session, not throw bad_function_call on the httpd task.
        SS_LOGW(TAG, "No new connection callback set, closing upgraded session");
        conn->trigger_close();
        return;
    }

    SS_LOGD(TAG, "WebSocket upgrade complete on socket %d, delivering connection", sockfd);
    conn->mark_ws_upgraded();
    this->new_connection_callback_(std::move(conn));
}

std::shared_ptr<SendspinServerConnection> SendspinWsServer::pop_pending(int sockfd) {
    std::lock_guard<std::mutex> lock(this->pending_mutex_);
    for (auto it = this->pending_.begin(); it != this->pending_.end(); ++it) {
        if (it->sockfd == sockfd) {
            auto conn = std::move(it->conn);
            this->pending_.erase(it);
            return conn;
        }
    }
    return nullptr;
}

esp_err_t SendspinWsServer::open_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "New client connection on socket %d", sockfd);

    SendspinWsServer* server = (SendspinWsServer*)httpd_get_global_user_ctx(handle);
    if (server == nullptr) {
        SS_LOGE(TAG, "Server context is null in open_callback");
        return ESP_FAIL;
    }

    // Reject the session before allocating anything if there is nobody to deliver the connection
    // to; otherwise the session would sit pinned with no one driving its handshake until the peer
    // gives up.
    if (!server->new_connection_callback_) {
        SS_LOGW(TAG, "No new connection callback set, rejecting session");
        return ESP_FAIL;
    }

    // Pin the connection to the httpd session: a heap-allocated shared_ptr is set as the session
    // context, with a free_fn that drops the refcount when the session is torn down. httpd invokes
    // the close_fn before the free_fn, so observers (ConnectionManager) get notified first and any
    // queued workers that have already started look up the same shared_ptr via httpd_sess_get_ctx
    // and run safely until the session is freed.
    auto conn = std::make_shared<SendspinServerConnection>(handle, sockfd);
    auto* slot = new std::shared_ptr<SendspinServerConnection>(conn);
    httpd_sess_set_ctx(handle, sockfd, slot, [](void* p) {
        delete static_cast<std::shared_ptr<SendspinServerConnection>*>(p);
    });

    // Park it as pending rather than delivering: the rest of the library only ever learns about
    // connections whose WebSocket upgrade has been observed (see the delivery contract in
    // ws_server.h). A session that never upgrades is closed by tick() without the manager ever
    // knowing it existed.
    {
        std::lock_guard<std::mutex> lock(server->pending_mutex_);
        server->pending_.push_back(PendingUpgrade{std::move(conn), esp_timer_get_time(), sockfd});
    }
    return ESP_OK;
}

void SendspinWsServer::close_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "Client closed connection on socket %d", sockfd);

    // Flip the connection to disconnected immediately: queued async sends check is_connected()
    // and must not resolve this sockfd once httpd may recycle it for a new session.
    auto* slot =
        static_cast<std::shared_ptr<SendspinServerConnection>*>(httpd_sess_get_ctx(handle, sockfd));
    if (slot != nullptr && *slot != nullptr) {
        (*slot)->mark_closed();
    }

    SendspinWsServer* server = (SendspinWsServer*)httpd_get_global_user_ctx(handle);

    if (server != nullptr) {
        // Drop a still-pending entry: this session closed before its upgrade was ever observed,
        // so it must not be delivered. Popping here (before the fd can be recycled) also keeps
        // sockfd unique as a pending-table key.
        server->pop_pending(sockfd);
    }

    // Notify ConnectionManager so it can drop its observer shared_ptr. Passing the connection
    // (from the session slot) rather than the sockfd keys the event on identity: by the time the
    // manager drains it on the main loop the fd may already be recycled onto a new session. The
    // slot keeps the connection alive until httpd invokes its free_fn next, so any in-flight
    // workers still looking it up via httpd_sess_get_ctx see a valid object. For a never-delivered
    // session the manager finds no managed match and no-ops.
    if (server != nullptr && server->connection_closed_callback_ && slot != nullptr &&
        *slot != nullptr) {
        server->connection_closed_callback_(*slot);
    }

    // Shut down the receive side before close() to stop lwIP from delivering more packets
    // during teardown. Without this, lwIP can race with netconn_prepare_delete and trigger
    // pbuf_free / recv_tcp assertions or cache faults inside the close path.
    // SHUT_RD (not SHUT_RDWR) lets the FIN still go out cleanly.
    shutdown(sockfd, SHUT_RD);
    close(sockfd);
}

SS_HOT esp_err_t SendspinWsServer::websocket_handler(httpd_req_t* req) {
    // Capture timestamp immediately for accurate time synchronization
    int64_t receive_time = esp_timer_get_time();

    // Look up the connection via httpd's per-session ctx. The slot was pinned in open_callback and
    // is freed only after this handler unwinds for a given session, so the shared_ptr copy below
    // is always valid. Copying the shared_ptr keeps the conn alive for the duration of dispatch
    // even if a teardown is racing on another thread.
    int sockfd = httpd_req_to_sockfd(req);
    auto* slot = static_cast<std::shared_ptr<SendspinServerConnection>*>(
        httpd_sess_get_ctx(req->handle, sockfd));
    if (slot == nullptr || !*slot) {
        SS_LOGE(TAG, "No connection found for sockfd %d", sockfd);
        return ESP_FAIL;
    }
    std::shared_ptr<SendspinServerConnection> conn_holder = *slot;
    SendspinServerConnection* conn = conn_holder.get();

    SendspinWsServer* server =
        static_cast<SendspinWsServer*>(httpd_get_global_user_ctx(req->handle));

    // Upgrade GET: the sole upgrade signal, on every IDF version. Old IDF (<= 5.5.4 / 6.0.0)
    // dispatches the initial GET here natively after completing the handshake; new IDF reaches
    // this branch via ws_post_handshake_cb, which is registered as this same function and
    // invoked with the same GET request. Frames are processed strictly after this request cycle
    // on the same httpd task, so delivery always precedes the first frame.
    if (req->method == HTTP_GET) {
        if (server != nullptr) {
            server->deliver_upgraded(sockfd);
        }
        return ESP_OK;
    }

    // Delegate to connection's handle_data. Stale messages (i.e., after the connection has been
    // dropped from ConnectionManager's observer slots) are short-circuited inside the connection
    // via disable_message_dispatch(), so a still-alive session-pinned conn does not leak messages
    // into freshly-reset role queues. A frame on a never-delivered connection (its session
    // outliving a tick() reap by a moment) dispatches into unwired callbacks and is dropped by
    // their null guards.
    return conn->handle_data(req, receive_time);
}

}  // namespace sendspin
