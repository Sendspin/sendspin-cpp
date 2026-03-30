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

/// @file Host build version of client_connection.h (IXWebSocket-based).
/// ESP-IDF version lives in src/esp/sendspin/client_connection.h.

#pragma once

#include "connection.h"
#include <ixwebsocket/IXWebSocket.h>

#include <functional>
#include <memory>
#include <string>

namespace sendspin {

class SendspinClientConnection : public SendspinConnection {
public:
    explicit SendspinClientConnection(std::string url);
    ~SendspinClientConnection() override;

    void start() override;
    void loop() override;
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override;
    SsErr send_text_message(const std::string& message, SendCompleteCallback cb) override;

    void set_auto_reconnect(bool enabled) {
        this->auto_reconnect_ = enabled;
    }

    bool is_connected() const override;

protected:
    void setup_callbacks_();

    // Pointer fields
    std::string url_;
    std::unique_ptr<ix::WebSocket> ws_;

    // 32-bit fields
    uint32_t last_reconnect_attempt_{0};
    uint32_t reconnect_interval_ms_{5000};

    // 8-bit fields
    bool auto_reconnect_{true};
    bool connected_{false};
};

}  // namespace sendspin
