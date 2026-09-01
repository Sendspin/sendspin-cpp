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

/// @file source_encoder_opus.h
/// @brief Opus implementation of the source encoder seam

#pragma once

#include "platform/memory.h"
#include "sendspin/config.h"
#include "source_encoder.h"

namespace sendspin {

/**
 * @brief Encodes each assembled PCM chunk into exactly one bare RFC 6716 Opus packet, no
 * container (Sendspin spec, Source messages); config validation guarantees a full chunk is one
 * legal Opus frame, so encode() is a single opus_encode() call. All state is allocated once in
 * init(); the encode path allocates nothing.
 */
class OpusSourceEncoder final : public SourceEncoder {
public:
    /// @brief Upper bound on any packet encode() produces: libopus's recommended max_data_bytes
    /// ("4000 bytes is recommended", opus.h), above any accepted config's worst case
    /// (512 kbit/s x 60 ms = 3840). The task sizes its payload area to at least this.
    static constexpr size_t MAX_PACKET_BYTES = 4000U;

    /// @brief Allocates and initializes the libopus encoder state and chunk scratch buffers
    /// from an opus-validated source config
    /// @param config The role config; must have passed validate_config() for OPUS.
    /// @return true on success; false on allocation or libopus failure (logged; the caller
    ///         fails SourceTask::init() closed and the role never streams).
    bool init(const SourceRoleConfig& config);

    bool can_encode(size_t in_len) const override;

    size_t encode(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_capacity) override;

    int64_t lookahead_us() const override {
        return this->lookahead_us_;
    }

    void reset() override;

private:
    // Struct fields
    /// libopus encoder state, sized by opus_encoder_get_size() and placed by the shared
    /// OPUS_STATE_LOCATION rule (opus_state_location.h)
    PlatformBuffer encoder_state_;
    /// Aligned PCM copy of the chunk under encode; see encode() for why the input is copied
    PlatformBuffer pcm_scratch_;
    /// Encoded packet landing area, sized to libopus's recommended maximum; encode() copies
    /// the packet out to satisfy the seam's in == out contract
    PlatformBuffer packet_scratch_;

    // 64-bit fields
    /// Encoder delay in µs, converted from OPUS_GET_LOOKAHEAD samples once at init
    int64_t lookahead_us_{0};

    // size_t fields
    size_t bytes_per_frame_{0};

    // 32-bit fields
    uint32_t sample_rate_{0};
};

}  // namespace sendspin
