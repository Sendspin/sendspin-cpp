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
#include "platform/types.h"
#include "protocol_messages.h"
#include "sendspin/types.h"
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

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
    this->send_goodbye_reason(reason, [this, on_complete](bool /*success*/) {
        if (this->ws_) {
            this->ws_->stop();
        }
        if (on_complete) {
            on_complete();
        }
    });
}

void SendspinClientConnection::close_transport_now() {
    // ws_->stop() (used by disconnect() above) joins IX's own worker thread, so it deadlocks (and
    // on host, crashes via an uncaught std::system_error -> std::terminate()) when called from a
    // callback already running on that thread. ws_->close() is async and does not join, so it is
    // safe here. Report the loss immediately rather than waiting for the resulting Close event;
    // that event still arrives later and repeats on_disconnected_cb, which the manager tolerates
    // (drop_connection() no-ops on a connection it no longer manages).
    this->connected_ = false;
    if (this->on_disconnected_cb) {
        this->on_disconnected_cb(this);
    }
    if (this->ws_) {
        this->ws_->close();
    }
}

SsErr SendspinClientConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback cb,
                                                  bool /*allow_before_hello*/) {
    if (!this->is_connected()) {
        if (cb) {
            cb(false);
        }
        return SsErr::INVALID_STATE;
    }

    auto info = this->ws_->send(message);
    bool success = info.success;

    if (cb) {
        cb(success);
    }

    if (!success) {
        SS_LOGE(TAG, "Failed to send text message");
        return SsErr::FAIL;
    }

    return SsErr::OK;
}

SsErr SendspinClientConnection::send_binary_message(const uint8_t* data, size_t len,
                                                    SendCompleteCallback cb,
                                                    bool /*allow_before_hello*/) {
    if (!this->is_connected()) {
        if (cb) {
            cb(false);
        }
        return SsErr::INVALID_STATE;
    }

    std::string buf(reinterpret_cast<const char*>(data), len);
    auto info = this->ws_->sendBinary(buf);
    bool success = info.success;

    if (cb) {
        cb(success);
    }

    if (!success) {
        SS_LOGE(TAG, "Failed to send binary message");
        return SsErr::FAIL;
    }

    return SsErr::OK;
}

bool SendspinClientConnection::send_time_message() {
    if (!this->is_connected()) {
        return false;
    }

    char buf[TIME_MESSAGE_BUF_SIZE];
    const int64_t client_transmitted = platform_time_us();
    const size_t len = format_client_time_message(buf, sizeof(buf), client_transmitted);
    if (len == 0) {
        return false;
    }
    this->update_serialize_ema(platform_time_us() - client_transmitted);
    // Route through send_app_json so the frame is encrypted when Noise is active;
    // the pointer/length overload encrypts straight from the stack buffer.
    return this->send_app_json(buf, len, nullptr) == SsErr::OK;
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
                        // Stop processing further frames and initiate a real transport close via
                        // close_transport_now() (stop() would join IX's thread and deadlock here;
                        // close() is async and safe; see its doc comment).
                        this->disable_message_dispatch();
                        this->close_transport_now();
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
