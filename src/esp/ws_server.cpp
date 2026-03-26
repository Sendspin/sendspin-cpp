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

#include "lwip/sockets.h"  // for close()
#include "platform/logging.h"
#include "server_connection.h"
#include <esp_timer.h>

namespace sendspin {

/*
 * SendspinWsServer manages the HTTP server (httpd) that accepts incoming WebSocket connections.
 *
 * Key Design Points:
 * - The server listener ACCEPTS connections but doesn't OWN them long-term
 * - When a client connects, it creates a SendspinServerConnection and hands it to the
 * SendspinClient
 * - The SendspinClient decides whether to keep or reject the connection (for handoff logic)
 * - Supports max_connections=2 by default to enable handoff protocol:
 *   - One active connection is managed by the client
 *   - A second connection can be accepted temporarily during handoff
 *   - The client completes the handshake and decides which to keep
 *
 * Lifecycle:
 * 1. SendspinClient calls start() with callbacks and configuration
 * 2. Server listens on port 8928 at /sendspin
 * 3. open_callback() creates SendspinServerConnection instances
 * 4. SendspinClient receives connection via new_connection_callback
 * 5. SendspinClient manages connection ownership and handoff logic
 * 6. close_callback() handles socket cleanup
 */

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
    config.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT + 1;  // Avoid conflict with web_server component

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

    // Create a new connection instance
    auto connection = std::make_unique<SendspinServerConnection>(handle, sockfd);

    // Notify the client of the new connection (client decides whether to keep it)
    if (server->new_connection_callback_) {
        server->new_connection_callback_(std::move(connection));
    } else {
        SS_LOGW(TAG, "No new connection callback set, connection will be dropped");
    }

    return ESP_OK;
}

void SendspinWsServer::close_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "Client closed connection on socket %d", sockfd);

    SendspinWsServer* server = (SendspinWsServer*)httpd_get_global_user_ctx(handle);

    // Notify the client so it can identify and clean up the connection
    if (server != nullptr && server->connection_closed_callback_) {
        server->connection_closed_callback_(sockfd);
    }

    // Close the socket
    close(sockfd);
}

esp_err_t SendspinWsServer::websocket_handler(httpd_req_t* req) {
    // Capture timestamp immediately for accurate time synchronization
    int64_t receive_time = esp_timer_get_time();

    SendspinWsServer* server = (SendspinWsServer*)req->user_ctx;

    // Handle WebSocket handshake (HTTP_GET)
    if (req->method == HTTP_GET) {
        // Find the connection and invoke its on_connected callback
        int sockfd = httpd_req_to_sockfd(req);
        SendspinServerConnection* conn = nullptr;
        if (server->find_connection_callback_) {
            conn = server->find_connection_callback_(sockfd);
        }
        if (conn != nullptr && conn->on_connected) {
            conn->on_connected(conn);
        }
        return ESP_OK;
    }

    // Find connection by sockfd
    int sockfd = httpd_req_to_sockfd(req);
    SendspinServerConnection* conn = nullptr;
    if (server->find_connection_callback_) {
        conn = server->find_connection_callback_(sockfd);
    }

    if (conn == nullptr) {
        SS_LOGE(TAG, "No connection found for sockfd %d", sockfd);
        return ESP_FAIL;
    }

    // Delegate to connection's handle_data
    return conn->handle_data(req, receive_time);
}

}  // namespace sendspin
