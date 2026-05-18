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
#include <esp_timer.h>

namespace sendspin {

// ============================================================================
// SendspinWsServer
// ============================================================================
//
// Manages the HTTP server (httpd) that accepts incoming WebSocket connections.
//
// Key Design Points:
// - The server listener ACCEPTS connections but doesn't OWN them long-term
// - When a client connects, it creates a SendspinServerConnection and hands it to the
//   SendspinClient
// - The SendspinClient decides whether to keep or reject the connection (for handoff logic)
// - Supports max_connections=2 by default to enable handoff protocol:
//   - One active connection is managed by the client
//   - A second connection can be accepted temporarily during handoff
//   - The client completes the handshake and decides which to keep
//
// Lifecycle:
// 1. SendspinClient calls start() with callbacks and configuration
// 2. Server listens on port 8928 at /sendspin
// 3. open_callback() creates SendspinServerConnection instances
// 4. SendspinClient receives connection via new_connection_callback
// 5. SendspinClient manages connection ownership and handoff logic
// 6. close_callback() handles socket cleanup

static const char* const TAG = "sendspin.ws_server";

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
    config.server_port = 8928;
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

    // Register the WebSocket handler
    const httpd_uri_t sendspin_ws_uri = {.uri = "/sendspin",
                                         .method = HTTP_GET,
                                         .handler = SendspinWsServer::websocket_handler,
                                         .user_ctx = (void*)this,
                                         .is_websocket = true,
                                         .handle_ws_control_frames = false,
                                         .supported_subprotocol = nullptr};

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

    server->new_connection_callback_(std::move(conn));
    return ESP_OK;
}

void SendspinWsServer::close_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "Client closed connection on socket %d", sockfd);

    SendspinWsServer* server = (SendspinWsServer*)httpd_get_global_user_ctx(handle);

    // Notify ConnectionManager so it can drop its observer shared_ptr. The session slot (set in
    // open_callback) keeps the connection alive until httpd invokes the slot's free_fn next, which
    // ensures any in-flight workers that are still looking it up via httpd_sess_get_ctx see a
    // valid object.
    if (server != nullptr && server->connection_closed_callback_) {
        server->connection_closed_callback_(sockfd);
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
    // even if a teardown is racing on another thread. This replaces the previous cross-thread
    // find_connection_callback + mutex.
    int sockfd = httpd_req_to_sockfd(req);
    auto* slot = static_cast<std::shared_ptr<SendspinServerConnection>*>(
        httpd_sess_get_ctx(req->handle, sockfd));
    if (slot == nullptr || !*slot) {
        SS_LOGE(TAG, "No connection found for sockfd %d", sockfd);
        return ESP_FAIL;
    }
    std::shared_ptr<SendspinServerConnection> conn_holder = *slot;
    SendspinServerConnection* conn = conn_holder.get();

    // Handle WebSocket handshake (HTTP_GET)
    if (req->method == HTTP_GET) {
        if (conn->on_connected_cb) {
            conn->on_connected_cb(conn);
        }
        return ESP_OK;
    }

    // Delegate to connection's handle_data. Stale messages (i.e., after the connection has been
    // dropped from ConnectionManager's observer slots) are short-circuited inside the connection
    // via disable_message_dispatch(), so a still-alive session-pinned conn does not leak messages
    // into freshly-reset role queues.
    return conn->handle_data(req, receive_time);
}

}  // namespace sendspin
