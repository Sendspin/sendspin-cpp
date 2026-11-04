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

/// @file source_encoder_flac.h
/// @brief FLAC implementation of the source encoder

#pragma once

#include "platform/memory.h"
#include "sendspin/config.h"
#include "source_encoder.h"
#include <micro_flac/flac_encoder.h>

#include <string>

namespace sendspin {

/**
 * @brief Encodes each assembled PCM chunk into exactly one FLAC frame, its block the chunk's
 * frames (roles/source/v1.md "client-stream/start", codec framing), with micro-flac's fixed
 * predictors. The `fLaC` marker and STREAMINFO block travel as the codec header. Lossless, with no
 * encoder delay; encode() never allocates.
 */
class FlacSourceEncoder final : public SourceEncoder {
public:
    /// @brief Configures micro-flac for `config` and builds the codec header. Allocates nothing but
    /// the header; a config micro-flac cannot encode leaves max_payload_bytes() 0.
    explicit FlacSourceEncoder(const SourceRoleConfig& config);

    /// @brief The max_payload_bytes() of an encoder for `config`, without its codec header
    static size_t max_payload_bytes(const SourceRoleConfig& config);

    /// @brief The largest frame encode() can produce: a little over the chunk's PCM, for audio
    /// whose subframes are stored verbatim
    /// @return Bytes, or 0 if micro-flac cannot encode the config's format in its chunk length.
    size_t max_payload_bytes() const {
        return this->encoder_.get_max_output_bytes();
    }

    /// @brief The client-stream/start `codec_header`, already Base64 (roles/source/v1.md
    /// "client-stream/start"), its totals unknown; empty if max_payload_bytes() is 0. Fixed since
    /// construction, so any thread may read it.
    const std::string& codec_header() const {
        return this->codec_header_;
    }

    /// @brief Allocates the PCM scratch buffer, unless an earlier call did
    /// @param config The config the encoder was constructed with.
    /// @return false on an allocation failure (logged).
    bool init(const SourceRoleConfig& config);

    size_t encode(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_capacity) override;

    int64_t lookahead_us() const override {
        return 0;
    }

    void reset() override {
        this->encoder_.reset();
    }

    uint8_t* input_buffer() override {
        return this->pcm_scratch_.data();
    }

private:
    // Struct fields
    micro_flac::FLACEncoder encoder_;
    /// The chunk under encode, 2-byte aligned for micro-flac's 16-bit input; also input_buffer()
    PlatformBuffer pcm_scratch_;
    std::string codec_header_;

    // 8-bit fields
    /// Set by a failed encode and cleared by the next success; keeps the failure log to one line
    bool failing_{false};
};

}  // namespace sendspin
