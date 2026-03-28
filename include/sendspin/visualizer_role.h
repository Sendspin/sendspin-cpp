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

#pragma once

#include "sendspin/protocol.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientBridge;

/// @brief Visualizer role: receives real-time audio visualization data from the server.
class VisualizerRole {
    friend class SendspinClient;

public:
    /// @brief Configuration for the visualizer role.
    struct Config {
        VisualizerSupportObject support;
    };

    explicit VisualizerRole(Config config);

    /// @brief Returns the visualizer support configuration (nullopt if not configured).
    const std::optional<VisualizerSupportObject>& get_visualizer_support() const {
        return this->visualizer_support_;
    }

    /// @brief Callback for visualizer data (loudness, f_peak, spectrum).
    std::function<void(const uint8_t*, size_t)> on_visualizer_data;

    /// @brief Callback for beat events.
    std::function<void(const uint8_t*, size_t)> on_beat_data;

    /// @brief Callback when a visualizer stream starts.
    std::function<void(const ServerVisualizerStreamObject&)> on_visualizer_stream_start;

    /// @brief Callback when a visualizer stream ends.
    std::function<void()> on_visualizer_stream_end;

    /// @brief Callback when a visualizer stream is cleared.
    std::function<void()> on_visualizer_stream_clear;

private:
    /// @brief Deferred visualizer event types.
    enum class EventType : uint8_t {
        STREAM_START,
        STREAM_END,
        STREAM_CLEAR,
    };

    /// @brief Deferred visualizer event.
    struct Event {
        EventType type;
        std::optional<ServerVisualizerStreamObject> visualizer_stream;
    };

    void attach(ClientBridge* bridge);
    void contribute_hello(ClientHelloMessage& msg);
    void handle_binary(uint8_t binary_type, const uint8_t* data, size_t len);
    void handle_stream_start(const ServerVisualizerStreamObject& stream);
    void handle_stream_end();
    void handle_stream_clear();
    void drain_events(std::vector<Event>& events);
    void cleanup();

    ClientBridge* bridge_{nullptr};
    std::optional<VisualizerSupportObject> visualizer_support_;
    std::vector<Event> pending_events_;
};

}  // namespace sendspin
