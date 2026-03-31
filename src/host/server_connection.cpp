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

#include "server_connection.h"

#include "platform/logging.h"
#include "platform/time.h"

#include <algorithm>

namespace sendspin {

SendspinServerConnection::SendspinServerConnection(std::shared_ptr<ix::WebSocket> ws, int sockfd)
    : ws_(std::move(ws)), sockfd_(sockfd) {
    // IXWebSocket handles TCP_NODELAY internally
}

void SendspinServerConnection::start() {
    // Connection is already established by the server; no action needed.
    // The on_connected_cb callback is invoked from the ws_server message handler
    // when the WebSocket Open message arrives.
}

void SendspinServerConnection::loop() {
    // Time message sending is handled by the hub
}

void SendspinServerConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye message, then close
    this->send_goodbye_reason(reason, [this, on_complete](bool /*success*/, int64_t) {
        this->trigger_close();
        if (on_complete) {
            on_complete();
        }
    });
}

bool SendspinServerConnection::is_connected() const {
    return this->ws_ && this->ws_->getReadyState() == ix::ReadyState::Open;
}

SsErr SendspinServerConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback on_complete) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete(false, 0);
        }
        return SsErr::INVALID_STATE;
    }

    auto info = this->ws_->send(message);
    int64_t after_send_time = platform_time_us();
    bool success = info.success;

    if (on_complete) {
        on_complete(success, after_send_time);
    }

    return success ? SsErr::OK : SsErr::FAIL;
}

void SendspinServerConnection::trigger_close() {
    if (this->ws_) {
        this->ws_->close();
    }
}

void SendspinServerConnection::handle_message(const std::string& data, bool is_binary,
                                              int64_t receive_time) {
    if (!data.empty()) {
        uint8_t* dest = this->prepare_receive_buffer(data.size());
        if (dest != nullptr) {
            std::copy(data.begin(), data.end(), dest);
            this->commit_receive_buffer(data.size());
        }
    }
    this->dispatch_completed_message(!is_binary, receive_time);
}

}  // namespace sendspin
