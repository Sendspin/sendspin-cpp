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

/// @file source_encoder.h
/// @brief Encoder seam between the source task's PCM chunk assembly and the wire payload

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sendspin {

/// @brief Turns one assembled chunk of capture PCM into the outbound wire payload, keeping the
/// source task's chunk loop codec-agnostic
class SourceEncoder {
public:
    virtual ~SourceEncoder() = default;

    /// @brief Whether a chunk of `in_len` PCM bytes is encodable; only gates the stream-end
    /// remainder (mid-stream chunks are full by config validation), which the task skips rather
    /// than pads when this returns false -- a final short chunk is optional per the spec
    virtual bool can_encode(size_t in_len) const {
        return in_len > 0;
    }

    /// @brief Encodes one chunk of interleaved PCM into the wire payload area
    ///
    /// @param in Assembled PCM chunk. `in == out` (exact aliasing) is part of the contract:
    ///        the task assembles directly into the send buffer and encodes in place.
    /// @param in_len Length of the PCM chunk in bytes.
    /// @param out Destination payload area.
    /// @param out_capacity Capacity of `out` in bytes.
    /// @return Number of payload bytes written to `out`; 0 on encode failure (the task drops
    ///         the chunk).
    virtual size_t encode(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_capacity) = 0;

    /// @brief Algorithmic delay (µs), subtracted from each chunk's capture anchor so the wire
    /// timestamp names the audio the payload actually carries
    virtual int64_t lookahead_us() const = 0;

    /// @brief Resets encoder state between streams
    virtual void reset() = 0;
};

/// @brief Identity encoder for PCM streams: the assembled chunk already is the wire payload
class PcmPassthroughEncoder final : public SourceEncoder {
public:
    size_t encode(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_capacity) override {
        if (in_len > out_capacity) {
            return 0;  // Only reachable in the separate-buffer shape of the contract
        }
        if (in != out) {
            memcpy(out, in, in_len);
        }
        return in_len;
    }

    int64_t lookahead_us() const override {
        return 0;
    }

    void reset() override {}
};

}  // namespace sendspin
