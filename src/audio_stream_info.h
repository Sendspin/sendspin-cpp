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

namespace sendspin {

/// @brief Audio stream format descriptor with unit conversion helpers.
///
/// Provides conversions between bytes, samples, frames, and durations for a given audio format.
///  - A sample is a single value for one channel.
///  - A frame is one sample per channel (e.g., 2 samples for stereo).
class AudioStreamInfo {
public:
    AudioStreamInfo() : AudioStreamInfo(16, 1, 16000) {}
    AudioStreamInfo(uint8_t bits_per_sample, uint8_t channels, uint32_t sample_rate);

    uint8_t get_bits_per_sample() const {
        return this->bits_per_sample_;
    }
    uint8_t get_channels() const {
        return this->channels_;
    }
    uint32_t get_sample_rate() const {
        return this->sample_rate_;
    }

    uint32_t bytes_to_ms(size_t bytes) const {
        return bytes * 1000 / (this->sample_rate_ * this->bytes_per_sample_ * this->channels_);
    }

    uint32_t bytes_to_frames(size_t bytes) const {
        return bytes / (this->bytes_per_sample_ * this->channels_);
    }

    uint32_t bytes_to_samples(size_t bytes) const {
        return bytes / this->bytes_per_sample_;
    }

    size_t frames_to_bytes(uint32_t frames) const {
        return frames * this->bytes_per_sample_ * this->channels_;
    }

    size_t samples_to_bytes(uint32_t samples) const {
        return samples * this->bytes_per_sample_;
    }

    uint32_t ms_to_frames(uint32_t ms) const {
        return (ms * this->sample_rate_) / 1000;
    }

    size_t ms_to_bytes(uint32_t ms) const {
        return (ms * this->bytes_per_sample_ * this->channels_ * this->sample_rate_) / 1000;
    }

    uint32_t frames_to_microseconds(uint32_t frames) const;

    /// @brief Converts frames to milliseconds, updating frames with the remainder.
    uint32_t frames_to_milliseconds_with_remainder(uint32_t* frames) const;

    bool operator==(const AudioStreamInfo& rhs) const;
    bool operator!=(const AudioStreamInfo& rhs) const {
        return !operator==(rhs);
    }

protected:
    // size_t fields
    size_t bytes_per_sample_;

    // 32-bit fields
    uint32_t ms_sample_rate_gcd_;
    uint32_t sample_rate_;

    // 8-bit fields
    uint8_t bits_per_sample_;
    uint8_t channels_;
};

}  // namespace sendspin
