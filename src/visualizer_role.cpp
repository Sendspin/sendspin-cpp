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

#include "sendspin/visualizer_role.h"

#include "client_bridge.h"
#include "protocol_messages.h"

#include <mutex>

namespace sendspin {

VisualizerRole::VisualizerRole(Config config) : visualizer_support_(std::move(config.support)) {}

void VisualizerRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

void VisualizerRole::contribute_hello(ClientHelloMessage& msg) {
    if (this->visualizer_support_.has_value()) {
        msg.supported_roles.push_back(SendspinRole::VISUALIZER);
        msg.visualizer_support = this->visualizer_support_.value();
    }
}

void VisualizerRole::handle_binary(uint8_t binary_type, const uint8_t* data, size_t len) {
    if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT) {
        if (this->on_beat_data) {
            this->on_beat_data(data, len);
        }
    } else {
        if (this->on_visualizer_data) {
            this->on_visualizer_data(data, len);
        }
    }
}

void VisualizerRole::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    Event event;
    event.type = EventType::STREAM_START;
    event.visualizer_stream = stream;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::handle_stream_end() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    Event event;
    event.type = EventType::STREAM_END;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::handle_stream_clear() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    Event event;
    event.type = EventType::STREAM_CLEAR;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::drain_events(std::vector<Event>& events) {
    for (auto& event : events) {
        switch (event.type) {
            case EventType::STREAM_START:
                if (event.visualizer_stream.has_value() && this->on_visualizer_stream_start) {
                    this->on_visualizer_stream_start(event.visualizer_stream.value());
                }
                break;
            case EventType::STREAM_END:
                if (this->on_visualizer_stream_end) {
                    this->on_visualizer_stream_end();
                }
                break;
            case EventType::STREAM_CLEAR:
                if (this->on_visualizer_stream_clear) {
                    this->on_visualizer_stream_clear();
                }
                break;
        }
    }
}

void VisualizerRole::cleanup() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);

    // Discard stale events from the dead connection
    this->pending_events_.clear();

    // Enqueue a clean STREAM_END — drain_events() will fire the callback
    Event event;
    event.type = EventType::STREAM_END;
    this->pending_events_.push_back(std::move(event));
}

}  // namespace sendspin
