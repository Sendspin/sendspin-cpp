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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

// ============================================================================
// Visualizer types
// ============================================================================

/// @brief Visualizer data stream types
enum class VisualizerDataType : uint8_t {
    BEAT,      // Beat detection events
    LOUDNESS,  // Overall loudness level
    F_PEAK,    // Peak frequency
    SPECTRUM,  // Full frequency spectrum bins
};

/// @brief Returns a null-terminated string name for a visualizer data type
/// @param type The data type to convert
/// @return Null-terminated string, or "unknown" for unrecognized values
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

/// @brief Frequency scale used for spectrum visualization bins
enum class VisualizerSpectrumScale : uint8_t {
    MEL,  // Mel perceptual scale
    LOG,  // Logarithmic scale
    LIN,  // Linear scale
};

/// @brief Returns a null-terminated string name for a spectrum scale type
/// @param scale The scale to convert
/// @return Null-terminated string, or "unknown" for unrecognized values
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

/// @brief Spectrum visualization parameters: bin count, frequency range, scale, and rate cap
struct VisualizerSpectrumConfig {
    uint8_t n_disp_bins;
    VisualizerSpectrumScale scale;
    uint16_t f_min;
    uint16_t f_max;
    uint16_t rate_max;
};

/// @brief Visualizer capabilities advertised to the server during the hello handshake
struct VisualizerSupportObject {
    std::vector<VisualizerDataType> types;
    size_t buffer_capacity;
    uint8_t batch_max;
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief Visualizer stream parameters sent by the server in stream/start messages
struct ServerVisualizerStreamObject {
    std::vector<VisualizerDataType> types;
    uint8_t batch_max;
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief A parsed visualizer frame with client-domain timestamp
struct VisualizerFrame {
    int64_t timestamp;  ///< Client timestamp in microseconds
    std::optional<uint16_t> loudness;
    std::optional<uint16_t> peak_freq;
    std::vector<uint16_t> spectrum;
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
 * VisualizerRole::Config config;
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
    /// @brief Configuration for the visualizer role
    struct Config {
        VisualizerSupportObject support;
    };

    VisualizerRole(Config config, SendspinClient* client);
    ~VisualizerRole();

    /// @brief Sets the listener for visualizer events
    /// @note The listener must outlive this role
    void set_listener(VisualizerRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Returns the visualizer support configuration
    /// @return The VisualizerSupportObject advertised to the server, or nullopt if not configured.
    const std::optional<VisualizerSupportObject>& get_visualizer_support() const {
        return this->visualizer_support_;
    }

private:
    /// @brief Deferred visualizer event types
    enum class EventType : uint8_t {
        STREAM_START,
        STREAM_END,
        STREAM_CLEAR,
    };

    /// @brief Starts the drain thread if the ring buffer is ready
    /// @return True if the thread is running, false if the ring buffer is not initialized.
    bool start();
    /// @brief Signals the drain thread to stop and waits for it to exit
    void stop_();
    /// @brief Adds the visualizer role and support config to the hello message
    /// @param msg The hello message being assembled.
    void contribute_hello(ClientHelloMessage& msg);
    /// @brief Parses incoming visualizer binary frames and writes them to the ring buffer
    /// @param binary_type Protocol binary type tag identifying the frame format.
    /// @param data Pointer to the raw frame data.
    /// @param len Length of the frame data in bytes.
    void handle_binary(uint8_t binary_type, const uint8_t* data, size_t len);
    /// @brief Caches stream config, signals the drain thread to flush, and enqueues a start event
    /// @param stream Stream parameters received from the server.
    void handle_stream_start(const ServerVisualizerStreamObject& stream);
    /// @brief Marks the stream inactive, flushes the ring buffer, and enqueues a stream-end event
    void handle_stream_end();
    /// @brief Marks the stream inactive, flushes the ring buffer, and enqueues a stream-clear
    /// event.
    void handle_stream_clear();
    /// @brief Delivers pending stream lifecycle events (start, end, clear) to the listener
    void drain_events();
    /// @brief Resets pending events, flushes the ring buffer, and enqueues a stream-end event
    void cleanup();
    /// @brief Drains all pending items from the ring buffer without delivering them
    void flush_ring_buffer_();

    /// @brief Entry point for the drain thread; reads ring buffer items and calls the listener
    /// @param self The VisualizerRole instance that owns this thread.
    static void drain_thread_func_(VisualizerRole* self);

    struct DrainTask;
    struct EventState;

    // Struct fields
    std::optional<VisualizerSupportObject> visualizer_support_;

    // Pointer fields
    SendspinClient* client_;
    // Drain task (pimpl to avoid exposing platform headers)
    std::unique_ptr<DrainTask> drain_task_;
    std::unique_ptr<EventState> event_state_;
    VisualizerRoleListener* listener_{nullptr};

    // size_t fields
    // Cached stream config, written by the network thread in handle_stream_start(),
    // read by the network thread in handle_binary(). stream_active_ is also cleared
    // by cleanup() on the main thread.
    std::atomic<size_t> raw_frame_size_{0};

    // 8-bit fields
    std::atomic<bool> has_f_peak_{false};
    std::atomic<bool> has_loudness_{false};
    std::atomic<bool> has_spectrum_{false};
    std::atomic<uint8_t> spectrum_bin_count_{0};
    std::atomic<bool> stream_active_{false};
};

}  // namespace sendspin
