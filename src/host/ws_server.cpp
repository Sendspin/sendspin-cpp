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

#include "platform/logging.h"
#include "platform/time.h"
#include "server_connection.h"

namespace sendspin {

static const char* const TAG = "sendspin.ws_server";

SendspinWsServer::~SendspinWsServer() {
    this->stop();
}

bool SendspinWsServer::start(SendspinClient* client, bool /*task_stack_in_psram*/,
                             unsigned /*task_priority*/) {
    if (this->server_ != nullptr) {
        SS_LOGW(TAG, "Server already started");
        return true;
    }

    this->client_ = client;

    // Create IXWebSocket server on port 8928
    this->server_ = std::make_unique<ix::WebSocketServer>(8928, "0.0.0.0");

    this->server_->setOnConnectionCallback([this](std::weak_ptr<ix::WebSocket> weak_ws,
                                                  std::shared_ptr<ix::ConnectionState> /*state*/) {
        auto ws = weak_ws.lock();
        if (!ws) {
            return;
        }

        // Generate a synthetic sockfd from the pointer for connection lookup
        int synthetic_sockfd = static_cast<int>(reinterpret_cast<intptr_t>(ws.get()) & 0x7FFFFFFF);

        SS_LOGD(TAG, "New client connection (synthetic sockfd %d)", synthetic_sockfd);

        // Create the server connection
        auto connection = std::make_unique<SendspinServerConnection>(ws, synthetic_sockfd);

        // Set up the message callback on the websocket to route data through the connection
        ws->setOnMessageCallback([this, synthetic_sockfd](const ix::WebSocketMessagePtr& msg) {
            int64_t receive_time = platform_time_us();

            // Find the connection by sockfd
            SendspinServerConnection* conn = nullptr;
            if (this->find_connection_callback_) {
                conn = this->find_connection_callback_(synthetic_sockfd);
            }

            if (msg->type == ix::WebSocketMessageType::Message) {
                if (conn == nullptr) {
                    SS_LOGE(TAG, "No connection found for synthetic sockfd %d", synthetic_sockfd);
                    return;
                }

                // Route through the connection's public handle_message method
                conn->handle_message(msg->str, msg->binary, receive_time);

            } else if (msg->type == ix::WebSocketMessageType::Open) {
                if (conn != nullptr && conn->on_connected_cb) {
                    conn->on_connected_cb(conn);
                }
            } else if (msg->type == ix::WebSocketMessageType::Close) {
                SS_LOGD(TAG, "Client closed connection (synthetic sockfd %d)", synthetic_sockfd);
                if (this->connection_closed_callback_) {
                    this->connection_closed_callback_(synthetic_sockfd);
                }
            } else if (msg->type == ix::WebSocketMessageType::Error) {
                SS_LOGE(TAG, "WebSocket error: %s", msg->errorInfo.reason.c_str());
            }
        });

        // Notify the client of the new connection
        if (this->new_connection_callback_) {
            this->new_connection_callback_(std::move(connection));
        } else {
            SS_LOGW(TAG, "No new connection callback set, connection will be dropped");
        }
    });

    SS_LOGI(TAG, "Starting server on port: 8928 (max connections: %d)", this->max_connections_);

    auto result = this->server_->listen();
    if (!result.first) {
        SS_LOGE(TAG, "Error starting server: %s", result.second.c_str());
        this->server_.reset();
        return false;
    }

    this->server_->start();
    return true;
}

void SendspinWsServer::stop() {
    if (this->server_ != nullptr) {
        SS_LOGD(TAG, "Stopping server");
        this->server_->stop();
        this->server_.reset();
    }
}

}  // namespace sendspin
