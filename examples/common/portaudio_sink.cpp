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

#include "portaudio_sink.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

namespace sendspin {

// Ring buffer capacity. With condition-variable-based blocking in write(),
// backpressure is driven by the PA callback rate (not buffer fullness), so this
// can be larger without causing the initial-sync zero-stuffing problem.
// 16KB ~= 85ms at 48kHz/16-bit/stereo, enough headroom for scheduling jitter.
static constexpr size_t RING_BUFFER_CAPACITY = 16384;

// ============================================================================
// PortAudioRingBuffer
// ============================================================================

PortAudioRingBuffer::PortAudioRingBuffer(size_t capacity) : buffer_(capacity), capacity_(capacity) {}

size_t PortAudioRingBuffer::write(const uint8_t* data, size_t len) {
    size_t write_pos = write_pos_.load(std::memory_order_relaxed);
    size_t read_pos = read_pos_.load(std::memory_order_acquire);

    // Available space: capacity - 1 to distinguish full from empty
    size_t used = (write_pos - read_pos + capacity_) % capacity_;
    size_t free_space = capacity_ - 1 - used;
    size_t to_write = std::min(len, free_space);

    if (to_write == 0) {
        return 0;
    }

    // Copy data, handling wrap-around
    size_t first_chunk = std::min(to_write, capacity_ - (write_pos % capacity_));
    std::memcpy(&buffer_[write_pos % capacity_], data, first_chunk);
    if (to_write > first_chunk) {
        std::memcpy(&buffer_[0], data + first_chunk, to_write - first_chunk);
    }

    write_pos_.store((write_pos + to_write) % capacity_, std::memory_order_release);
    return to_write;
}

size_t PortAudioRingBuffer::read(uint8_t* dest, size_t len) {
    // Check if a clear was requested. The consumer handles the actual drain so
    // that read_pos_ is only ever written by the consumer thread, preserving
    // the SPSC invariant and eliminating the race where an externally-modified
    // read_pos_ could cause the consumer to compute a bogus available count.
    if (clear_requested_.load(std::memory_order_acquire)) {
        clear_requested_.store(false, std::memory_order_relaxed);
        read_pos_.store(write_pos_.load(std::memory_order_acquire), std::memory_order_release);
        std::memset(dest, 0, len);
        return 0;
    }

    size_t read_pos = read_pos_.load(std::memory_order_relaxed);
    size_t write_pos = write_pos_.load(std::memory_order_acquire);

    size_t available = (write_pos - read_pos + capacity_) % capacity_;
    size_t to_read = std::min(len, available);

    if (to_read > 0) {
        // Copy data, handling wrap-around
        size_t first_chunk = std::min(to_read, capacity_ - (read_pos % capacity_));
        std::memcpy(dest, &buffer_[read_pos % capacity_], first_chunk);
        if (to_read > first_chunk) {
            std::memcpy(dest + first_chunk, &buffer_[0], to_read - first_chunk);
        }

        read_pos_.store((read_pos + to_read) % capacity_, std::memory_order_release);
    }

    // Fill remainder with silence
    if (to_read < len) {
        std::memset(dest + to_read, 0, len - to_read);
    }

    return to_read;
}

size_t PortAudioRingBuffer::available() const {
    size_t write_pos = write_pos_.load(std::memory_order_acquire);
    size_t read_pos = read_pos_.load(std::memory_order_acquire);
    return (write_pos - read_pos + capacity_) % capacity_;
}

size_t PortAudioRingBuffer::free_space() const {
    return capacity_ - 1 - available();
}

void PortAudioRingBuffer::clear() {
    clear_requested_.store(true, std::memory_order_release);
}

void PortAudioRingBuffer::reset() {
    clear_requested_.store(false, std::memory_order_relaxed);
    read_pos_.store(0, std::memory_order_relaxed);
    write_pos_.store(0, std::memory_order_release);
}

// ============================================================================
// PortAudioSink
// ============================================================================

PortAudioSink::PortAudioSink() : ring_buffer_(RING_BUFFER_CAPACITY) {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio init failed: %s\n", Pa_GetErrorText(err));
    }
}

PortAudioSink::~PortAudioSink() {
    stop();
    Pa_Terminate();
}

size_t PortAudioSink::write(uint8_t* data, size_t length, uint32_t timeout_ms) {
    size_t total_written = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (total_written < length) {
        {
            // Hold the mutex during ring_buffer_.write() so that stop()/reset()
            // on another thread cannot mutate the ring buffer positions mid-write.
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (abort_write_.load(std::memory_order_acquire)) {
                break;
            }
            size_t written = ring_buffer_.write(data + total_written, length - total_written);
            total_written += written;
        }

        if (total_written < length) {
            // Block until the PA callback frees space, abort is requested, or timeout.
            std::unique_lock<std::mutex> lock(write_mutex_);
            if (!write_cv_.wait_until(lock, deadline, [this]() {
                    return ring_buffer_.free_space() > 0 ||
                           abort_write_.load(std::memory_order_acquire);
                })) {
                break;  // Timed out
            }
        }
    }

    return total_written;
}

bool PortAudioSink::configure(uint32_t sample_rate, uint8_t channels, uint8_t bits_per_sample) {
    stop();
    abort_write_.store(false, std::memory_order_release);

    sample_rate_ = sample_rate;
    channels_ = channels;
    bits_per_sample_ = bits_per_sample;
    bytes_per_frame_ = channels * (bits_per_sample / 8);

    PaSampleFormat sample_format;
    switch (bits_per_sample) {
        case 16:
            sample_format = paInt16;
            break;
        case 24:
            sample_format = paInt24;
            break;
        case 32:
            sample_format = paInt32;
            break;
        default:
            fprintf(stderr, "PortAudio: unsupported bit depth %u\n", bits_per_sample);
            return false;
    }

    PaError err = Pa_OpenDefaultStream(&stream_, 0, channels, sample_format, sample_rate,
                                       paFramesPerBufferUnspecified, pa_callback, this);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio: failed to open stream: %s\n", Pa_GetErrorText(err));
        stream_ = nullptr;
        return false;
    }

    err = Pa_StartStream(stream_);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio: failed to start stream: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(stream_);
        stream_ = nullptr;
        return false;
    }

    fprintf(stderr, "PortAudio: playing %uHz %uch %ubit\n", sample_rate, channels, bits_per_sample);
    return true;
}

bool PortAudioSink::is_format_supported(uint32_t sample_rate, uint8_t channels,
                                        uint8_t bits_per_sample) {
    PaDeviceIndex device = Pa_GetDefaultOutputDevice();
    if (device == paNoDevice) {
        return false;
    }

    PaSampleFormat sample_format;
    switch (bits_per_sample) {
        case 16:
            sample_format = paInt16;
            break;
        case 24:
            sample_format = paInt24;
            break;
        case 32:
            sample_format = paInt32;
            break;
        default:
            return false;
    }

    PaStreamParameters params = {};
    params.device = device;
    params.channelCount = channels;
    params.sampleFormat = sample_format;
    params.suggestedLatency = Pa_GetDeviceInfo(device)->defaultLowOutputLatency;

    return Pa_IsFormatSupported(nullptr, &params, static_cast<double>(sample_rate)) ==
           paFormatIsSupported;
}

uint8_t PortAudioSink::max_output_channels() {
    PaDeviceIndex device = Pa_GetDefaultOutputDevice();
    if (device == paNoDevice) {
        return 0;
    }
    const PaDeviceInfo* info = Pa_GetDeviceInfo(device);
    if (info == nullptr) {
        return 0;
    }
    return static_cast<uint8_t>(std::min(info->maxOutputChannels, 255));
}

void PortAudioSink::stop() {
    // Signal any blocked writer to abort, then wake it.
    abort_write_.store(true, std::memory_order_release);
    write_cv_.notify_all();

    if (stream_ != nullptr) {
        Pa_StopStream(stream_);
        Pa_CloseStream(stream_);
        stream_ = nullptr;
    }

    // Acquire the mutex so we don't reset while a writer is mid-memcpy.
    std::lock_guard<std::mutex> lock(write_mutex_);
    ring_buffer_.reset();
}

void PortAudioSink::clear() {
    ring_buffer_.clear();
}

int PortAudioSink::pa_callback(const void* /*input*/, void* output, unsigned long frame_count,
                               const PaStreamCallbackTimeInfo* time_info,
                               PaStreamCallbackFlags /*status_flags*/, void* user_data) {
    auto* self = static_cast<PortAudioSink*>(user_data);
    size_t bytes_requested = frame_count * self->bytes_per_frame_;
    auto* out = static_cast<uint8_t*>(output);

    size_t bytes_read = self->ring_buffer_.read(out, bytes_requested);

    // Apply software volume scaling (Q32 fixed-point, all bit depths).
    uint64_t vol = self->volume_multiplier_.load(std::memory_order_relaxed);
    if (vol < (UINT64_C(1) << 32)) {
        uint8_t bps = self->bits_per_sample_ / 8;
        apply_volume_(out, bytes_requested, bps, vol);
    }

    // Wake the producer thread; space is now available in the ring buffer.
    // notify_one() is safe to call from the PA callback on desktop platforms.
    self->write_cv_.notify_one();

    // Report timing feedback using PA's DAC timing info.
    // outputBufferDacTime is when the first sample of this buffer will hit the DAC.
    // We compute the finish time (when the last frame exits the DAC) by adding
    // the frame duration. The offset from currentTime to DAC time is converted
    // from PA's clock domain to esp_timer's clock domain.
    if (bytes_read > 0 && self->on_frames_played) {
        uint32_t frames_played = static_cast<uint32_t>(bytes_read / self->bytes_per_frame_);

        // How far in the future (in seconds) the DAC will output the last frame
        double dac_offset_s = (time_info->outputBufferDacTime - time_info->currentTime) +
                              (static_cast<double>(frames_played) / self->sample_rate_);
        int64_t dac_offset_us = static_cast<int64_t>(dac_offset_s * 1e6);

        int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now().time_since_epoch())
                             .count();
        int64_t finish_timestamp = now_us + dac_offset_us;
        self->on_frames_played(frames_played, finish_timestamp);
    }

    return paContinue;
}

void PortAudioSink::set_volume(uint8_t volume) {
    volume_ = volume > 100 ? 100 : volume;
    update_volume_multiplier_();
}

void PortAudioSink::set_muted(bool muted) {
    muted_ = muted;
    update_volume_multiplier_();
}

void PortAudioSink::update_volume_multiplier_() {
    static constexpr uint64_t Q32_ONE = UINT64_C(1) << 32;
    if (muted_ || volume_ == 0) {
        volume_multiplier_.store(0, std::memory_order_relaxed);
    } else if (volume_ >= 100) {
        volume_multiplier_.store(Q32_ONE, std::memory_order_relaxed);
    } else {
        // Quadratic curve: (vol/100)^2 for perceptually uniform control.
        // Q32 multiplier = vol * vol * 2^32 / 10000
        uint64_t v = volume_;
        uint64_t multiplier = (v * v * Q32_ONE) / 10000;
        volume_multiplier_.store(multiplier, std::memory_order_relaxed);
    }
}

void PortAudioSink::apply_volume_(uint8_t* data, size_t len, uint8_t bytes_per_sample,
                                  uint64_t scale) {
    static constexpr int FRAC_BITS = 32;
    static constexpr int64_t ROUND_TERM = INT64_C(1) << (FRAC_BITS - 1);
    int64_t s_scale = static_cast<int64_t>(scale);

    switch (bytes_per_sample) {
        case 1: {
            auto* samples = reinterpret_cast<int8_t*>(data);
            for (size_t i = 0; i < len; ++i) {
                int64_t s = static_cast<int64_t>(samples[i]) * s_scale + ROUND_TERM;
                samples[i] = static_cast<int8_t>(s >> FRAC_BITS);
            }
            break;
        }
        case 2: {
            size_t count = len / 2;
            auto* samples = reinterpret_cast<int16_t*>(data);
            for (size_t i = 0; i < count; ++i) {
                int64_t s = static_cast<int64_t>(samples[i]) * s_scale + ROUND_TERM;
                samples[i] = static_cast<int16_t>(s >> FRAC_BITS);
            }
            break;
        }
        case 3: {
            size_t count = len / 3;
            for (size_t i = 0; i < count; ++i) {
                uint8_t* p = data + i * 3;
                // Unpack 24-bit LE and sign-extend to 32-bit
                int32_t sample = static_cast<int32_t>(p[0] | (p[1] << 8) | (p[2] << 16));
                if (sample & 0x800000) {
                    sample |= static_cast<int32_t>(0xFF000000);
                }
                int32_t out =
                    static_cast<int32_t>((static_cast<int64_t>(sample) * s_scale + ROUND_TERM) >>
                                         FRAC_BITS);
                p[0] = static_cast<uint8_t>(out & 0xFF);
                p[1] = static_cast<uint8_t>((out >> 8) & 0xFF);
                p[2] = static_cast<uint8_t>((out >> 16) & 0xFF);
            }
            break;
        }
        case 4: {
            size_t count = len / 4;
            auto* samples = reinterpret_cast<int32_t*>(data);
            for (size_t i = 0; i < count; ++i) {
                int64_t s = static_cast<int64_t>(samples[i]) * s_scale + ROUND_TERM;
                samples[i] = static_cast<int32_t>(s >> FRAC_BITS);
            }
            break;
        }
        default:
            break;
    }
}

}  // namespace sendspin
