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

#include "source_encoder_flac.h"

#include "platform/base64.h"
#include "platform/logging.h"
#include "source_task.h"

#include <cstring>
#include <memory>

namespace sendspin {

static const char* const TAG = "sendspin.source_encoder";

/// @brief One block per chunk; a chunk past FLAC's largest block gets 0, which micro-flac
/// rejects like any other block size it cannot take
static micro_flac::FLACEncoderOptions chunk_block_options(const SourceRoleConfig& config) {
    const uint64_t frames = source_ms_to_frames(config.chunk_duration_ms, config.sample_rate);
    micro_flac::FLACEncoderOptions options;
    options.block_size =
        frames > micro_flac::FLACEncoder::MAX_BLOCK_SIZE ? 0U : static_cast<uint32_t>(frames);
    return options;
}

FlacSourceEncoder::FlacSourceEncoder(const SourceRoleConfig& config)
    : encoder_(micro_flac::PcmFormat{config.sample_rate, config.channels, config.bit_depth},
               chunk_block_options(config)) {
    uint8_t header[micro_flac::FLACEncoder::HEADER_BYTES];
    size_t header_len = 0;
    if (this->encoder_.write_header(header, sizeof(header), header_len) !=
        micro_flac::FLAC_ENCODER_SUCCESS) {
        return;  // An unsupported config, which validation reports
    }
    this->codec_header_ = base64_encode(header, header_len);
}

size_t FlacSourceEncoder::max_payload_bytes(const SourceRoleConfig& config) {
    // On the heap: the encoder carries a 2 KB sample buffer
    return std::make_unique<micro_flac::FLACEncoder>(
               micro_flac::PcmFormat{config.sample_rate, config.channels, config.bit_depth},
               chunk_block_options(config))
        ->get_max_output_bytes();
}

bool FlacSourceEncoder::init(const SourceRoleConfig& config) {
    if (this->pcm_scratch_) {
        return true;
    }
    // Sized as the task assembles a chunk; micro-flac's block is the same size
    if (!this->pcm_scratch_.allocate(source_chunk_bytes(config), config.buffer_location)) {
        SS_LOGE(TAG, "Couldn't allocate the FLAC chunk scratch buffer");
        return false;
    }
    return true;
}

size_t FlacSourceEncoder::encode(const uint8_t* in, size_t in_len, uint8_t* out,
                                 size_t out_capacity) {
    // A chunk is exactly one block; shorter input is encodable only by finish()
    if (in_len != this->pcm_scratch_.size()) {
        return 0;
    }
    // Other input (an unaligned payload area the frame may overwrite) goes through the scratch
    if (in != this->pcm_scratch_.data()) {
        std::memcpy(this->pcm_scratch_.data(), in, in_len);
    }
    size_t consumed = 0;
    size_t written = 0;
    micro_flac::FLACEncoderResult result = this->encoder_.encode(
        this->pcm_scratch_.data(), in_len, out, out_capacity, consumed, written);
    if (result == micro_flac::FLAC_ENCODER_ERROR_STREAM_TOO_LONG) {
        // The frame number runs out after 2^31 - 1 frames; the chunk stamps carry the timing, so
        // the count restarts
        this->encoder_.reset();
        result = this->encoder_.encode(this->pcm_scratch_.data(), in_len, out, out_capacity,
                                       consumed, written);
    }
    if (result != micro_flac::FLAC_ENCODER_SUCCESS) {
        if (!this->failing_) {
            this->failing_ = true;
            SS_LOGE(TAG, "FLAC encode failed, error %d; dropping chunks until it recovers",
                    static_cast<int>(result));
        }
        return 0;
    }
    if (this->failing_) {
        this->failing_ = false;
        SS_LOGI(TAG, "FLAC encode recovered");
    }
    return written;
}

}  // namespace sendspin
