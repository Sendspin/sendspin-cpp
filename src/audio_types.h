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

/// @file audio_types.h
/// @brief Internal audio pipeline types shared by the decoder, the player role and the sync task

#pragma once

#include "sendspin/config.h"

#include <cstdint>
#include <optional>

namespace sendspin {

/// @brief Audio chunk type tag used internally between components
///
/// Not part of the protocol specification.
enum ChunkType : uint8_t {
    CHUNK_TYPE_ENCODED_AUDIO = 0,    // Raw encoded audio data
    CHUNK_TYPE_PCM_DUMMY_HEADER,     // Synthetic header for PCM streams
    CHUNK_TYPE_OPUS_DUMMY_HEADER,    // Synthetic header for Opus streams
    CHUNK_TYPE_FLAC_HEADER,          // FLAC stream header block
    CHUNK_TYPE_STREAM_CLEAR_MARKER,  // Boundary marker: discard everything before it (stream/clear)
};

/// @brief Synthetic codec header for PCM and Opus streams that lack a real header block
struct DummyHeader {
    uint32_t sample_rate;
    uint8_t bits_per_sample;
    uint8_t channels;
};

/// @brief A stream/start player object's audio parameters (roles/player/v1.md "stream/start
/// player object"), each present when the message carried it
struct PlayerStreamParams {
    std::optional<SendspinCodecFormat> codec{};
    std::optional<uint32_t> sample_rate;
    std::optional<uint8_t> channels;
    std::optional<uint8_t> bit_depth;

    bool is_complete() const {
        return codec.has_value() && sample_rate.has_value() && channels.has_value() &&
               bit_depth.has_value();
    }
};

}  // namespace sendspin
