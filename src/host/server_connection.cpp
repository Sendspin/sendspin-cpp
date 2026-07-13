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
#include "protocol_messages.h"

#include <algorithm>

namespace sendspin {

static const char* const TAG = "sendspin.server_conn";

SendspinServerConnection::SendspinServerConnection(std::shared_ptr<ix::WebSocket> ws, int sockfd)
    : ws_(std::move(ws)), sockfd_(sockfd) {
    // No TCP_NODELAY setsockopt is needed here: IXWebSocket disables Nagle on accepted sockets
    // itself. SocketServer::run() calls SocketConnect::configure(clientFd) on every accepted
    // client fd (the same routine that sets TCP_NODELAY on outbound connects) so time messages
    // on this host-server path are not subject to Nagle coalescing delay.
}

void SendspinServerConnection::start() {
    // No action needed: the connection is constructed by the ws_server only after the WebSocket
    // Open event, so the transport is already established and upgraded by the time it exists.
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
    this->send_goodbye_reason(reason, [this, on_complete](bool /*success*/) {
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
                                                  SendCompleteCallback on_complete,
                                                  bool /*allow_before_hello*/) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::INVALID_STATE;
    }

    auto info = this->ws_->send(message);
    bool success = info.success;

    if (on_complete) {
        on_complete(success);
    }

    return success ? SsErr::OK : SsErr::FAIL;
}

bool SendspinServerConnection::send_time_message() {
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
    return this->ws_->send(std::string(buf, len)).success;
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
        if (dest == nullptr) {
            // Dispatching would hand a stale/partial buffer to the protocol layer. Drop the
            // connection instead: the close event tears the slot down on the main loop.
            SS_LOGE(TAG, "Allocation failed, dropping connection");
            this->disable_message_dispatch();
            this->reset_websocket_payload();
            this->trigger_close();
            return;
        }
        std::copy(data.begin(), data.end(), dest);
        this->commit_receive_buffer(data.size());
    }
    this->dispatch_completed_message(!is_binary, receive_time);
}

}  // namespace sendspin
