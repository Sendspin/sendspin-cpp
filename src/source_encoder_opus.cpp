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

#include "source_encoder_opus.h"

#include "opus_state_location.h"
#include "platform/logging.h"
#include "source_task.h"
#include <opus.h>

#include <algorithm>
#include <cstring>
#include <iterator>

namespace sendspin {

static const char* const TAG = "sendspin.source_encoder";

bool OpusSourceEncoder::init(const SourceRoleConfig& config) {
    this->sample_rate_ = config.sample_rate;
    this->bytes_per_frame_ = source_bytes_per_frame(config.channels, config.bit_depth);

    const int state_size = opus_encoder_get_size(config.channels);
    if (state_size <= 0 ||
        !this->encoder_state_.allocate(static_cast<size_t>(state_size), OPUS_STATE_LOCATION)) {
        SS_LOGE(TAG, "Couldn't allocate %d bytes for the Opus encoder state", state_size);
        return false;
    }

    // AUDIO fixed for line-in/music capture; a tuning knob waits for a demonstrated need
    int err = opus_encoder_init(this->encoder_state_.as<OpusEncoder>(),
                                static_cast<opus_int32>(config.sample_rate), config.channels,
                                OPUS_APPLICATION_AUDIO);
    if (err == OPUS_OK) {
        err = opus_encoder_ctl(this->encoder_state_.as<OpusEncoder>(),
                               OPUS_SET_BITRATE(static_cast<opus_int32>(config.opus_bitrate)));
    }
    if (err == OPUS_OK) {
        err =
            opus_encoder_ctl(this->encoder_state_.as<OpusEncoder>(),
                             OPUS_SET_COMPLEXITY(static_cast<opus_int32>(config.opus_complexity)));
    }
    // OPUS_GET_LOOKAHEAD returns SAMPLES at the encoder's rate, not ms; stable for fixed
    // settings so queried once
    opus_int32 lookahead_samples = 0;
    if (err == OPUS_OK) {
        err = opus_encoder_ctl(this->encoder_state_.as<OpusEncoder>(),
                               OPUS_GET_LOOKAHEAD(&lookahead_samples));
    }
    if (err != OPUS_OK) {
        SS_LOGE(TAG, "Couldn't initialize the Opus encoder, error %d", err);
        this->encoder_state_.reset();
        return false;
    }
    this->lookahead_us_ =
        source_frames_to_us(static_cast<uint64_t>(lookahead_samples), config.sample_rate);

    // Both scratches follow the audio buffers' placement choice (same bytes, same access)
    const uint64_t chunk_bytes =
        source_ms_to_frames(config.chunk_duration_ms, config.sample_rate) * this->bytes_per_frame_;
    if (!this->pcm_scratch_.allocate(static_cast<size_t>(chunk_bytes), config.buffer_location)) {
        SS_LOGE(TAG, "Couldn't allocate the Opus chunk scratch buffer");
        this->encoder_state_.reset();
        return false;
    }
    return true;
}

bool OpusSourceEncoder::can_encode(size_t in_len) const {
    if (in_len == 0 || (in_len % this->bytes_per_frame_) != 0U) {
        return false;
    }
    // One opus_encode() call takes exactly one legal frame (RFC 6716 durations), tabled in
    // tenth-ms so 2.5 stays integral; counts are exact for every accepted rate
    static constexpr uint32_t OPUS_FRAME_TENTH_MS[] = {25, 50, 100, 200, 400, 600};
    static constexpr uint32_t TENTH_MS_PER_SECOND = 10000U;
    const size_t frames = in_len / this->bytes_per_frame_;
    return std::any_of(
        std::begin(OPUS_FRAME_TENTH_MS), std::end(OPUS_FRAME_TENTH_MS), [&](uint32_t tenth_ms) {
            return frames ==
                   static_cast<size_t>(this->sample_rate_) * tenth_ms / TENTH_MS_PER_SECOND;
        });
}

size_t OpusSourceEncoder::encode(const uint8_t* in, size_t in_len, uint8_t* out,
                                 size_t out_capacity) {
    if (!this->can_encode(in_len) || in_len > this->pcm_scratch_.size()) {
        // Defensive: the task consults can_encode() before handing over a remainder
        SS_LOGD(TAG, "Opus cannot encode a %u-byte chunk; dropping it",
                static_cast<unsigned>(in_len));
        return 0;
    }

    // `in` sits behind the 9-byte wire header and is not int16-aligned, so the PCM is copied to
    // the aligned scratch; that copy is also what honors the seam's in == out contract, so the
    // packet can be encoded straight into `out` with no second buffer or copy.
    memcpy(this->pcm_scratch_.data(), in, in_len);
    // libopus treats max_data_bytes as a hard packet cap and degrades quality to fit it, so a
    // small payload area yields a valid smaller packet rather than an error. The task offers
    // MAX_PACKET_BYTES, above every accepted config's worst case, so in-tree streams never
    // degrade.
    const auto capacity =
        static_cast<opus_int32>(std::min(out_capacity, static_cast<size_t>(MAX_PACKET_BYTES)));
    const opus_int32 written =
        opus_encode(this->encoder_state_.as<OpusEncoder>(), this->pcm_scratch_.as<opus_int16>(),
                    static_cast<int>(in_len / this->bytes_per_frame_), out, capacity);
    if (written <= 0) {
        SS_LOGE(TAG, "Opus encode failed, error %d", static_cast<int>(written));
        return 0;
    }
    return static_cast<size_t>(written);
}

void OpusSourceEncoder::reset() {
    // Keeps the allocations (unlike the decode side): this encoder's format is the role's
    // contract for every stream it opens, so the cached lookahead stays valid too
    opus_encoder_ctl(this->encoder_state_.as<OpusEncoder>(), OPUS_RESET_STATE);
}

}  // namespace sendspin
