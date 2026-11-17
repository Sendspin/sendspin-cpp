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
#include <span>
#include <type_traits>
#include <vector>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Visualizer types
// ============================================================================

/// @brief A visualizer stream/start as admitted: the data types the client will receive, which
/// leave out what the server sent beyond the request, and the stream's frame-rate cap
struct VisualizerStream {
    bool loudness : 1 {false};
    bool beat : 1 {false};
    bool f_peak : 1 {false};
    bool spectrum : 1 {false};
    bool peak : 1 {false};
    /// @brief Whether beat frames mark downbeats; false unless beat is
    bool tracks_downbeats : 1 {false};
    /// @brief Periodic frames per second per type the server will emit
    uint16_t rate_max{0};

    bool operator==(const VisualizerStream&) const = default;
};

static_assert(std::is_trivially_copyable_v<VisualizerStream>, "handed over by value");
static_assert(sizeof(VisualizerStream) == 4, "the flags and rate_max pack into four bytes");

/// @brief A visualizer stream/start as admitted: what the client will receive, which leaves out
/// what the server sent beyond the request
/// @deprecated Handed only to the deprecated on_visualizer_stream_start(); removed in v0.11.0.
struct [[deprecated(
    "override on_visualizer_stream_started(); removed in v0.11.0")]] ServerVisualizerStreamObject {
    /// @brief Data types the client will receive, each once, in enumerator order
    std::vector<VisualizerDataType> types{};
    /// @brief Periodic frames per second the server will emit
    uint16_t rate_max{};
    /// @brief True if the server's beat tracker also identifies bar starts (downbeats).
    /// Only meaningful when types includes BEAT
    bool tracks_downbeats{false};
    /// @brief Spectrum configuration, present when types includes SPECTRUM
    std::optional<VisualizerSpectrumConfig> spectrum;
};

/// @brief Listener for visualizer role events
///
/// Data values (loudness, spectrum bins, f_peak amplitude) use the full uint16 range
/// 0-65535, where 0 = silence (-60 dB) and 65535 = full scale (0 dB), A-weighted and
/// mapped linearly in dB across that range.
///
/// THREAD SAFETY: the per-type data callbacks (on_loudness, on_beat, on_f_peak,
/// on_spectrum_bins, on_peak) fire on a dedicated drain thread,
/// VisualizerRoleConfig::display_offset_ms ahead of each frame's display timestamp
/// (client_timestamp stays the display time). A frame more than 20 ms past its delivery time is
/// dropped without a callback. Implementations must be thread-safe for these methods (copy data
/// quickly, defer heavy processing). The stream callbacks fire on the main loop thread, ordered
/// against the data callbacks as docs/integration-guide.md "VisualizerRoleListener" describes.
class VisualizerRoleListener {
public:
    virtual ~VisualizerRoleListener() = default;

    /// @brief Called with an overall A-weighted loudness value
    virtual void on_loudness(int64_t /*client_timestamp*/, uint16_t /*loudness*/) {}

    /// @brief Called on musical beat events
    /// @param downbeat True if this beat is a bar start; always false unless the stream
    ///                 was started with tracks_downbeats
    virtual void on_beat(int64_t /*client_timestamp*/, bool /*downbeat*/) {}

    /// @brief Called with the dominant FFT frequency
    /// @param frequency_hz Dominant frequency in Hz (0 = no peak detected)
    /// @param amplitude Amplitude of the dominant frequency (0 when no peak detected)
    virtual void on_f_peak(int64_t /*client_timestamp*/, uint16_t /*frequency_hz*/,
                           uint16_t /*amplitude*/) {}

    /// @brief Called with spectrum magnitudes per display bin, low to high frequency: one per
    /// n_disp_bins of the stream the frame arrived in, valid for the callback
    ///
    /// The library calls this and then the deprecated on_spectrum() with the same bins: override
    /// one of them. A listener overriding both gets both, this one first.
    /// @param config The spectrum configuration the frame was received under
    virtual void on_spectrum_bins(int64_t /*client_timestamp*/, std::span<const uint16_t> /*bins*/,
                                  const VisualizerSpectrumConfig& /*config*/) {}

    /// @brief Called after on_spectrum_bins() with the same bins
    /// @deprecated Override on_spectrum_bins(); removed in v0.11.0.
    [[deprecated("override on_spectrum_bins(); removed in v0.11.0")]] virtual void on_spectrum(
        int64_t /*client_timestamp*/, const std::vector<uint16_t>& /*bins*/) {}

    /// @brief Called on energy onset (transient) events, independent of musical timing
    /// @param strength Onset strength 0-255 for scaling flash intensity
    virtual void on_peak(int64_t /*client_timestamp*/, uint8_t /*strength*/) {}

    /// @brief Called for a visualizer stream/start, a new stream's or one updating the running
    /// stream, before any frame received after it; a start whose notice a later start overwrote
    /// before it fired is folded into that later one (see docs/integration-guide.md
    /// "VisualizerRoleListener")
    virtual void on_visualizer_stream_started(const VisualizerStream& /*stream*/) {}

    /// @brief Called after on_visualizer_stream_started() with the stream as admitted
    /// @deprecated Override on_visualizer_stream_started(); removed in v0.11.0.
    [[deprecated("override on_visualizer_stream_started(); removed in v0.11.0")]] virtual void
    on_visualizer_stream_start(const ServerVisualizerStreamObject& /*stream*/) {}

    /// @brief Called when a visualizer stream ends
    ///
    /// Also fires when a server/activate takes the visualizer role out of the session's active
    /// roles, which discards the buffered frames along with the stream.
    virtual void on_visualizer_stream_end() {}

    /// @brief Called when a visualizer stream is cleared
    virtual void on_visualizer_stream_clear() {}
};

/**
 * @brief Visualizer role that receives real-time audio visualization data from the server
 *
 * Receives timestamped loudness, beat, dominant-frequency, spectrum, and onset data from
 * the server and delivers each datum to the platform through VisualizerRoleListener
 * callbacks at the correct playback timestamp. A dedicated drain thread handles timing and
 * delivery of data callbacks; lifecycle callbacks fire on the main loop thread.
 *
 * Usage:
 * 1. Implement VisualizerRoleListener with the data callbacks you need
 * 2. Fill a VisualizerRoleConfig: the buffer capacity it can hold, and the data types,
 *    frame-rate cap and spectrum layout it wants streamed
 * 3. Add the role to the client via SendspinClient::add_visualizer()
 * 4. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyVisualizerListener : VisualizerRoleListener {
 *     void on_spectrum_bins(int64_t client_timestamp, std::span<const uint16_t> bins,
 *                           const VisualizerSpectrumConfig& config) override {
 *         display.update_spectrum(bins);
 *     }
 *     void on_beat(int64_t client_timestamp, bool downbeat) override {
 *         display.flash_beat(downbeat);
 *     }
 * };
 *
 * MyVisualizerListener listener;
 * VisualizerRoleConfig config;
 * config.support.buffer_capacity = 4096;
 * config.stream.types = {VisualizerDataType::SPECTRUM, VisualizerDataType::BEAT};
 * config.stream.rate_max = 30;
 * config.stream.spectrum = VisualizerSpectrumConfig{
 *     .n_disp_bins = 32,
 *     .scale = VisualizerSpectrumScale::MEL,
 *     .f_min = 40,
 *     .f_max = 16000,
 * };
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

    /// @brief Sets the listener for visualizer events; it must outlive this role. Set it before
    /// SendspinClient::start() and leave it in place while the client runs.
    void set_listener(VisualizerRoleListener* listener);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
