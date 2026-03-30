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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientBridge;
struct ClientHelloMessage;

// ============================================================================
// Visualizer types
// ============================================================================

enum class VisualizerDataType : uint8_t {
    BEAT,
    LOUDNESS,
    F_PEAK,
    SPECTRUM,
};

inline const char* to_cstr(VisualizerDataType type) {
    switch (type) {
        case VisualizerDataType::BEAT:
            return "beat";
        case VisualizerDataType::LOUDNESS:
            return "loudness";
        case VisualizerDataType::F_PEAK:
            return "f_peak";
        case VisualizerDataType::SPECTRUM:
            return "spectrum";
        default:
            return "unknown";
    }
}

enum class VisualizerSpectrumScale : uint8_t {
    MEL,
    LOG,
    LIN,
};

inline const char* to_cstr(VisualizerSpectrumScale scale) {
    switch (scale) {
        case VisualizerSpectrumScale::MEL:
            return "mel";
        case VisualizerSpectrumScale::LOG:
            return "log";
        case VisualizerSpectrumScale::LIN:
            return "lin";
        default:
            return "mel";
    }
}

struct VisualizerSpectrumConfig {
    uint8_t n_disp_bins;
    VisualizerSpectrumScale scale;
    uint16_t f_min;
    uint16_t f_max;
    uint16_t rate_max;
};

struct VisualizerSupportObject {
    std::vector<VisualizerDataType> types;
    size_t buffer_capacity;
    uint8_t batch_max;
    std::optional<VisualizerSpectrumConfig> spectrum;
};

struct ServerVisualizerStreamObject {
    std::vector<VisualizerDataType> types;
    uint8_t batch_max;
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief A parsed visualizer frame with client-domain timestamp.
struct VisualizerFrame {
    int64_t timestamp;  ///< Client timestamp in microseconds.
    std::optional<uint16_t> loudness;
    std::optional<uint16_t> peak_freq;
    std::vector<uint16_t> spectrum;
};

/// @brief Visualizer role: receives real-time audio visualization data from the server.
///
/// Lifecycle callbacks (on_visualizer_stream_start/end/clear) fire on the main loop thread.
/// Data callbacks (on_visualizer_frame, on_beat) fire on a dedicated drain thread at the
/// correct timestamp. Users must handle thread safety in data callbacks (copy data quickly,
/// defer heavy processing). This is the same contract as the player role's audio write callback.
class VisualizerRole {
    friend class SendspinClient;

public:
    /// @brief Configuration for the visualizer role.
    struct Config {
        VisualizerSupportObject support;
    };

    explicit VisualizerRole(Config config);
    ~VisualizerRole();

    /// @brief Returns the visualizer support configuration (nullopt if not configured).
    const std::optional<VisualizerSupportObject>& get_visualizer_support() const {
        return this->visualizer_support_;
    }

    /// @brief Callback for parsed visualizer frames. Fires on the drain thread.
    std::function<void(const VisualizerFrame&)> on_visualizer_frame;

    /// @brief Callback for beat events. Fires on the drain thread.
    std::function<void(int64_t)> on_beat;

    /// @brief Callback when a visualizer stream starts. Fires on the main loop thread.
    std::function<void(const ServerVisualizerStreamObject&)> on_visualizer_stream_start;

    /// @brief Callback when a visualizer stream ends. Fires on the main loop thread.
    std::function<void()> on_visualizer_stream_end;

    /// @brief Callback when a visualizer stream is cleared. Fires on the main loop thread.
    std::function<void()> on_visualizer_stream_clear;

private:
    /// @brief Deferred visualizer event types.
    enum class EventType : uint8_t {
        STREAM_START,
        STREAM_END,
        STREAM_CLEAR,
    };

    void attach(ClientBridge* bridge);
    bool start();
    void stop_();
    void contribute_hello(ClientHelloMessage& msg);
    void handle_binary(uint8_t binary_type, const uint8_t* data, size_t len);
    void handle_stream_start(const ServerVisualizerStreamObject& stream);
    void handle_stream_end();
    void handle_stream_clear();
    void drain_events();
    void cleanup();
    void flush_ring_buffer_();

    static void drain_thread_func_(VisualizerRole* self);

    ClientBridge* bridge_{nullptr};
    std::optional<VisualizerSupportObject> visualizer_support_;

    struct EventState;
    std::unique_ptr<EventState> event_state_;

    // Drain task (pimpl to avoid exposing platform headers)
    struct DrainTask;
    std::unique_ptr<DrainTask> drain_task_;

    // Cached stream config — written by the network thread in handle_stream_start(),
    // read by the network thread in handle_binary(). stream_active_ is also cleared
    // by cleanup() on the main thread.
    std::atomic<bool> stream_active_{false};
    std::atomic<bool> has_loudness_{false};
    std::atomic<bool> has_f_peak_{false};
    std::atomic<bool> has_spectrum_{false};
    std::atomic<uint8_t> spectrum_bin_count_{0};
    std::atomic<size_t> raw_frame_size_{0};
};

}  // namespace sendspin
