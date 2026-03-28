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

    /// @brief Callback for parsed visualizer frames (loudness, f_peak, spectrum).
    std::function<void(const VisualizerFrame&)> on_visualizer_frame;

    /// @brief Callback for beat events (client timestamp in microseconds).
    std::function<void(int64_t)> on_beat;

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
    void flush_ring_buffers_();

    ClientBridge* bridge_{nullptr};
    std::optional<VisualizerSupportObject> visualizer_support_;
    std::vector<Event> pending_events_;

    // Ring buffer storage (pimpl to avoid exposing platform headers)
    struct RingBuffers;
    std::unique_ptr<RingBuffers> ring_buffers_;

    // Cached stream config (written on network thread by handle_stream_start,
    // read on main thread by drain_events — safe via happens-before from event_mutex)
    bool stream_active_{false};
    bool has_loudness_{false};
    bool has_f_peak_{false};
    bool has_spectrum_{false};
    uint8_t spectrum_bin_count_{0};
    size_t raw_frame_size_{0};

    // Pending items held between drain_events calls (not yet ready for display)
    void* pending_frame_{nullptr};
    size_t pending_frame_size_{0};
    void* pending_beat_{nullptr};
    size_t pending_beat_size_{0};
};

}  // namespace sendspin
