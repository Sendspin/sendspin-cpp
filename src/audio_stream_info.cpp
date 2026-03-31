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

#include "audio_stream_info.h"

namespace sendspin {

// ============================================================================
// Static helpers
// ============================================================================

static uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

AudioStreamInfo::AudioStreamInfo(uint8_t bits_per_sample, uint8_t channels, uint32_t sample_rate)
    : sample_rate_(sample_rate), bits_per_sample_(bits_per_sample), channels_(channels) {
    this->ms_sample_rate_gcd_ = gcd(1000, this->sample_rate_);
    this->bytes_per_sample_ = (this->bits_per_sample_ + 7) / 8;
}

// ============================================================================
// Public API
// ============================================================================

uint32_t AudioStreamInfo::frames_to_microseconds(uint32_t frames) const {
    return (frames * 1000000 + (this->sample_rate_ >> 1)) / this->sample_rate_;
}

uint32_t AudioStreamInfo::frames_to_milliseconds_with_remainder(uint32_t* total_frames) const {
    uint32_t unprocessable_frames =
        *total_frames % (this->sample_rate_ / this->ms_sample_rate_gcd_);
    uint32_t frames_for_ms_calculation = *total_frames - unprocessable_frames;

    uint32_t playback_ms = (frames_for_ms_calculation * 1000) / this->sample_rate_;
    *total_frames = unprocessable_frames;
    return playback_ms;
}

bool AudioStreamInfo::operator==(const AudioStreamInfo& rhs) const {
    return (this->bits_per_sample_ == rhs.get_bits_per_sample()) &&
           (this->channels_ == rhs.get_channels()) && (this->sample_rate_ == rhs.get_sample_rate());
}

}  // namespace sendspin
