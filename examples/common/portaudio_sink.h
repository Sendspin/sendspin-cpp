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

#include <portaudio.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace sendspin {

/// @brief Lock-free single-producer single-consumer ring buffer for bridging
/// push (AudioSink::write) and pull (PortAudio callback) audio models.
class PortAudioRingBuffer {
public:
    explicit PortAudioRingBuffer(size_t capacity);

    /// @brief Write data into the ring buffer (producer side).
    /// @return Number of bytes actually written (may be less than len if full).
    size_t write(const uint8_t* data, size_t len);

    /// @brief Read data from the ring buffer (consumer side).
    /// Fills remainder with silence (zeros) if insufficient data available.
    /// @return Number of actual (non-silence) bytes read.
    size_t read(uint8_t* dest, size_t len);

    /// @brief Returns the number of bytes available for reading.
    size_t available() const;

    /// @brief Returns the number of bytes that can be written.
    size_t free_space() const;

    /// @brief Request the consumer to discard all buffered data.
    /// Safe to call while the PA callback is active — the consumer performs the
    /// actual drain on its next read(), preserving the SPSC invariant.
    void clear();

    /// @brief Hard reset of all positions. Only safe when no concurrent readers/writers
    /// (i.e., after stopping the PA stream).
    void reset();

private:
    std::vector<uint8_t> buffer_;
    size_t capacity_;
    std::atomic<size_t> write_pos_{0};
    std::atomic<size_t> read_pos_{0};
    std::atomic<bool> clear_requested_{false};
};

/// @brief Plays audio through PortAudio.
///
/// Bridges the push model (on_audio_write callback) with PortAudio's pull/callback
/// model using a lock-free SPSC ring buffer.
class PortAudioSink {
public:
    PortAudioSink();
    ~PortAudioSink();

    // Not copyable or movable (PortAudio stream holds a pointer to this)
    PortAudioSink(const PortAudioSink&) = delete;
    PortAudioSink& operator=(const PortAudioSink&) = delete;

    /// @brief Writes decoded PCM audio data into the ring buffer.
    size_t write(uint8_t* data, size_t length, uint32_t timeout_ms);

    /// @brief Configure audio format and (re)open the PortAudio stream.
    bool configure(uint32_t sample_rate, uint8_t channels, uint8_t bits_per_sample);

    /// @brief Stop playback and clear the ring buffer.
    void stop();

    /// @brief Discard all buffered audio without stopping the PortAudio stream.
    void clear();

    /// @brief Set the playback volume (0-100, where 100 = full scale).
    void set_volume(uint8_t volume);

    /// @brief Set the mute state. When muted, output is silenced regardless of volume.
    void set_muted(bool muted);

    /// @brief Callback for timing feedback. Wire to client.notify_audio_played().
    std::function<void(uint32_t frames, int64_t timestamp)> on_frames_played;

private:
    static int pa_callback(const void* input, void* output, unsigned long frame_count,
                           const PaStreamCallbackTimeInfo* time_info,
                           PaStreamCallbackFlags status_flags, void* user_data);

    PortAudioRingBuffer ring_buffer_;
    PaStream* stream_{nullptr};
    uint32_t sample_rate_{0};
    uint8_t channels_{0};
    uint8_t bits_per_sample_{0};
    size_t bytes_per_frame_{0};

    // Mutex/CV for blocking write() until PA callback frees space, and for
    // serializing ring buffer mutations (write vs reset) across threads.
    // The PA callback itself never acquires this mutex — it stays lock-free.
    std::mutex write_mutex_;
    std::condition_variable write_cv_;
    std::atomic<bool> abort_write_{false};

    // Software volume control using Q32 fixed-point math.
    // UINT32_MAX = 1.0 (full scale), 0 = silence. Updated atomically so the
    // PA callback can read it lock-free. Applied per-sample for all bit depths.
    std::atomic<uint64_t> volume_multiplier_{UINT64_C(1) << 32};
    uint8_t volume_{100};
    bool muted_{false};
    void update_volume_multiplier_();
    static void apply_volume_(uint8_t* data, size_t len, uint8_t bytes_per_sample, uint64_t scale);
};

}  // namespace sendspin
