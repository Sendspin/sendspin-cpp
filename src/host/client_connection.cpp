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

#include "client_connection.h"

#include "platform/logging.h"
#include "platform/time.h"
#include "protocol_messages.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace sendspin {

static const char* const TAG = "sendspin.client_connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinClientConnection::SendspinClientConnection(std::string url) : url_(std::move(url)) {}

SendspinClientConnection::~SendspinClientConnection() {
    if (this->ws_) {
        this->ws_->stop();
        this->ws_.reset();
    }
}

// ============================================================================
// Public API
// ============================================================================

void SendspinClientConnection::start() {
    if (this->ws_) {
        SS_LOGW(TAG, "Client already started, stopping first");
        this->ws_->stop();
        this->ws_.reset();
    }

    this->ws_ = std::make_unique<ix::WebSocket>();
    this->ws_->setUrl(this->url_);
    this->ws_->disableAutomaticReconnection();

    this->setup_callbacks();

    this->ws_->start();
    SS_LOGD(TAG, "Client connection starting to %s", this->url_.c_str());
}

void SendspinClientConnection::loop() {
    // Handle auto-reconnect
    if (!this->is_connected() && this->auto_reconnect_) {
        uint32_t now =
            static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now().time_since_epoch())
                                      .count());
        if (now - this->last_reconnect_attempt_ > this->reconnect_interval_ms_) {
            this->last_reconnect_attempt_ = now;
            SS_LOGD(TAG, "Attempting to reconnect to %s", this->url_.c_str());
            this->start();
        }
    }
}

void SendspinClientConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye message then stop
    this->send_goodbye_reason(reason, [this, on_complete](bool /*success*/, int64_t) {
        if (this->ws_) {
            this->ws_->stop();
        }
        if (on_complete) {
            on_complete();
        }
    });
}

SsErr SendspinClientConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback cb) {
    if (!this->is_connected()) {
        if (cb) {
            cb(false, 0);
        }
        return SsErr::INVALID_STATE;
    }

    int64_t send_time = platform_time_us();
    auto info = this->ws_->send(message);
    bool success = info.success;

    if (cb) {
        cb(success, send_time);
    }

    if (!success) {
        SS_LOGE(TAG, "Failed to send text message");
        return SsErr::FAIL;
    }

    return SsErr::OK;
}

bool SendspinClientConnection::send_time_message() {
    if (!this->is_connected()) {
        return false;
    }

    char buf[96];
    const int64_t client_transmitted = platform_time_us();
    const size_t len = format_client_time_message(buf, sizeof(buf), client_transmitted);
    this->update_serialize_ema(platform_time_us() - client_transmitted);
    if (len == 0) {
        return false;
    }
    return this->ws_->send(std::string(buf, len)).success;
}

// ============================================================================
// Private helpers / callbacks
// ============================================================================

void SendspinClientConnection::setup_callbacks() {
    this->ws_->setOnMessageCallback([this](const ix::WebSocketMessagePtr& msg) {
        int64_t receive_time = platform_time_us();

        switch (msg->type) {
            case ix::WebSocketMessageType::Open:
                SS_LOGD(TAG, "WebSocket connected to %s", this->url_.c_str());
                this->connected_ = true;
                if (this->on_connected_cb) {
                    this->on_connected_cb(this);
                }
                break;

            case ix::WebSocketMessageType::Close:
                SS_LOGD(TAG, "WebSocket disconnected from %s", this->url_.c_str());
                this->connected_ = false;
                this->client_hello_sent_ = false;
                this->server_hello_received_ = false;
                this->pending_time_message_ = false;
                this->reset_websocket_payload();
                if (this->on_disconnected_cb) {
                    this->on_disconnected_cb(this);
                }
                break;

            case ix::WebSocketMessageType::Message: {
                // IXWebSocket delivers complete reassembled messages
                const std::string& data = msg->str;
                bool is_binary = msg->binary;

                if (!data.empty()) {
                    uint8_t* dest = this->prepare_receive_buffer(data.size());
                    if (dest == nullptr) {
                        SS_LOGE(TAG, "Allocation failed, dropping connection");
                        this->connected_ = false;
                        if (this->on_disconnected_cb) {
                            this->on_disconnected_cb(this);
                        }
                        return;
                    }
                    std::copy(data.begin(), data.end(), dest);
                    this->commit_receive_buffer(data.size());
                }
                this->dispatch_completed_message(!is_binary, receive_time);
                break;
            }

            case ix::WebSocketMessageType::Error:
                SS_LOGE(TAG, "WebSocket error on connection to %s: %s", this->url_.c_str(),
                        msg->errorInfo.reason.c_str());
                break;

            default:
                break;
        }
    });
}

}  // namespace sendspin
