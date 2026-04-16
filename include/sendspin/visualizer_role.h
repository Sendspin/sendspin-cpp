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

/// @file visualizer_role.h
/// @brief Visualizer role that receives real-time audio visualization data from the server

#pragma once

#include "sendspin/config.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Visualizer types
// ============================================================================

/// @brief Visualizer stream parameters sent by the server in stream/start messages
struct ServerVisualizerStreamObject {
    std::vector<VisualizerDataType> types{};
    uint8_t batch_max{};
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief A parsed visualizer frame with client-domain timestamp
struct VisualizerFrame {
    int64_t timestamp{};  ///< Client timestamp in microseconds
    std::optional<uint16_t> loudness;
    std::optional<uint16_t> peak_freq;
    std::vector<uint16_t> spectrum{};
};

/// @brief Listener for visualizer role events
///
/// THREAD SAFETY: on_visualizer_frame() and on_beat() fire on a dedicated drain thread.
/// Implementations must be thread-safe for these two methods (copy data quickly, defer heavy
/// processing). on_visualizer_stream_start/end/clear fire on the main loop thread.
class VisualizerRoleListener {
public:
    virtual ~VisualizerRoleListener() = default;

    /// @brief Called with a parsed visualizer frame at the correct playback timestamp
    /// Fires on the drain thread.
    virtual void on_visualizer_frame(const VisualizerFrame& /*frame*/) {}

    /// @brief Called on beat events. Fires on the drain thread
    virtual void on_beat(int64_t /*client_timestamp*/) {}

    /// @brief Called when a visualizer stream starts. Fires on the main loop thread
    virtual void on_visualizer_stream_start(const ServerVisualizerStreamObject& /*stream*/) {}

    /// @brief Called when a visualizer stream ends. Fires on the main loop thread
    virtual void on_visualizer_stream_end() {}

    /// @brief Called when a visualizer stream is cleared. Fires on the main loop thread
    virtual void on_visualizer_stream_clear() {}
};

/**
 * @brief Visualizer role that receives real-time audio visualization data from the server
 *
 * Receives timestamped spectrum, loudness, peak frequency, and beat data from the server
 * and delivers frames to the platform through VisualizerRoleListener callbacks at the
 * correct playback timestamp. A dedicated drain thread handles timing and delivery of
 * data callbacks; lifecycle callbacks fire on the main loop thread.
 *
 * Usage:
 * 1. Implement VisualizerRoleListener with on_visualizer_frame() and/or on_beat()
 * 2. Build a VisualizerSupportObject describing supported data types and buffer capacity
 * 3. Add the role to the client via SendspinClient::add_visualizer()
 * 4. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyVisualizerListener : VisualizerRoleListener {
 *     void on_visualizer_frame(const VisualizerFrame& frame) override {
 *         display.update_spectrum(frame.spectrum);
 *     }
 *     void on_beat(int64_t client_timestamp) override {
 *         display.flash_beat();
 *     }
 * };
 *
 * MyVisualizerListener listener;
 * VisualizerRoleConfig config;
 * config.support.types = {VisualizerDataType::SPECTRUM, VisualizerDataType::BEAT};
 * config.support.buffer_capacity = 4096;
 * config.support.batch_max = 4;
 * auto& visualizer = client.add_visualizer(config);
 * visualizer.set_listener(&listener);
 * @endcode
 */
class VisualizerRole {
    friend class SendspinClient;

public:
    struct Impl;

    VisualizerRole(VisualizerRoleConfig config, SendspinClient* client);
    ~VisualizerRole();

    /// @brief Sets the listener for visualizer events
    /// @note The listener must outlive this role
    void set_listener(VisualizerRoleListener* listener);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
