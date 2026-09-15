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

/// @file test_support.h
/// @brief Loopback scaffolding shared by the tests that drive a whole SendspinClient: an
/// IXWebSocket endpoint that plays the Sendspin server, a network provider that is always ready,
/// and pump helpers that tick client.loop() while waiting on a predicate.

#pragma once

#include "platform/time.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <ixwebsocket/IXWebSocket.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace sendspin::test {

inline std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

inline std::string server_hello_json(const std::string& server_id, const std::string& reason) {
    return std::string(R"({"type":"server/hello","payload":{"server_id":")") + server_id +
           R"(","name":"Fake Server","version":1,"active_roles":["player"],)" +
           R"("connection_reason":")" + reason + R"("}})";
}

inline SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.client_id = "lifecycle-test-client";
    config.name = "Lifecycle Test Client";
    config.server_port = port;
    return config;
}

class TestNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return true;
    }
};

/// Pumps client.loop() until pred() is true. No timeout: a regression hangs here and the suite
/// watchdog reports it.
inline void pump_until(SendspinClient& client, const std::function<bool()>& pred) {
    for (;;) {
        client.loop();
        if (pred()) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

/// Pumps client.loop() for a fixed window. Only for spacing events or "must not happen" checks:
/// a window that is too short can miss a regression, never fail a correct run.
inline void pump_for(SendspinClient& client, int duration_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(duration_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

/// Blocks until pred() is true without pumping the client (for checks on a stopped client).
inline void wait_until(const std::function<bool()>& pred) {
    while (!pred()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

/// Behavior knobs for FakeServer.
struct FakeServerOptions {
    bool hello_on_open{false};  ///< Send server/hello immediately on Open, before any
                                ///< client/hello arrives (a nonconforming peer)
    bool answer_hello{true};    ///< Reply to client/hello with server/hello (false: mute peer
                                ///< that upgrades and then never establishes)
    bool answer_time{false};    ///< Reply to client/time with a server/time whose clock is the
                                ///< client's own (both sides read platform_time_us(), so the
                                ///< offset is ~0 and audio timestamps mean what they say)
};

/// A minimal Sendspin server: an IXWebSocket client that connects to the SendspinClient's WS
/// server (the server-initiated discovery direction), answers client/hello with server/hello per
/// the given options, and records the goodbye and close.
class FakeServer {
public:
    FakeServer(const std::string& url, std::string server_id, FakeServerOptions options = {})
        : server_id_(std::move(server_id)) {
        this->ws_.setUrl(url);
        this->ws_.disableAutomaticReconnection();
        this->ws_.setOnMessageCallback([this, options](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                if (options.hello_on_open) {
                    this->ws_.send(server_hello_json(this->server_id_, "discovery"));
                }
            } else if (msg->type == ix::WebSocketMessageType::Message) {
                const std::string& text = msg->str;
                if (text.find("client/hello") != std::string::npos) {
                    this->got_client_hello_.store(true);
                    if (options.answer_hello) {
                        this->ws_.send(server_hello_json(this->server_id_, "discovery"));
                    }
                } else if (text.find("client/time") != std::string::npos) {
                    this->got_client_time_.store(true);
                    if (options.answer_time) {
                        this->answer_time(text);
                    }
                } else if (text.find("client/goodbye") != std::string::npos) {
                    {
                        std::lock_guard<std::mutex> lock(this->goodbye_mutex_);
                        this->goodbye_message_ = text;
                    }
                    this->got_goodbye_.store(true);
                }
            } else if (msg->type == ix::WebSocketMessageType::Close ||
                       msg->type == ix::WebSocketMessageType::Error) {
                this->closed_.store(true);
            }
        });
        this->ws_.start();
    }

    ~FakeServer() {
        this->ws_.stop();
    }

    void send_text(const std::string& text) {
        this->ws_.send(text);
    }

    /// Sends one binary message: type byte, big-endian server timestamp, then the payload.
    void send_binary(uint8_t binary_type, int64_t timestamp_us, const std::string& payload) {
        std::string frame;
        frame.push_back(static_cast<char>(binary_type));
        for (int shift = 56; shift >= 0; shift -= 8) {
            frame.push_back(static_cast<char>((timestamp_us >> shift) & 0xFF));
        }
        frame.append(payload);
        this->ws_.sendBinary(frame);
    }

    /// Sends one player audio chunk: binary type 4 with a zeroed PCM payload.
    void send_audio(int64_t timestamp_us, size_t payload_bytes) {
        this->send_binary(4, timestamp_us, std::string(payload_bytes, '\0'));
    }

    bool closed() const {
        return this->closed_.load();
    }

    bool got_client_hello() const {
        return this->got_client_hello_.load();
    }

    bool got_goodbye() const {
        return this->got_goodbye_.load();
    }

    std::string goodbye_message() const {
        std::lock_guard<std::mutex> lock(this->goodbye_mutex_);
        return this->goodbye_message_;
    }

    bool got_client_time() const {
        return this->got_client_time_.load();
    }

private:
    void answer_time(const std::string& client_time_text) {
        const auto pos = client_time_text.find("\"client_transmitted\":");
        if (pos == std::string::npos) {
            return;
        }
        const long long client_transmitted =
            std::strtoll(client_time_text.c_str() + pos + 21, nullptr, 10);
        const int64_t now = platform_time_us();
        this->ws_.send(std::string(R"({"type":"server/time","payload":{)") +
                       "\"client_transmitted\":" + std::to_string(client_transmitted) +
                       ",\"server_received\":" + std::to_string(now) +
                       ",\"server_transmitted\":" + std::to_string(now) + "}}");
    }

    ix::WebSocket ws_;
    std::string server_id_;
    mutable std::mutex goodbye_mutex_;
    std::string goodbye_message_;
    std::atomic<bool> closed_{false};
    std::atomic<bool> got_client_hello_{false};
    std::atomic<bool> got_goodbye_{false};
    std::atomic<bool> got_client_time_{false};
};

}  // namespace sendspin::test
