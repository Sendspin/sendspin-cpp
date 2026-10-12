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

/// @file pcm_byte_order.h
/// @brief Converts 16-bit PCM between the library's little-endian buffers and host order

#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace sendspin {

/// @brief Converts 16-bit samples between little-endian and host byte order, in place
///
/// The library's PCM buffers are little-endian; libopus reads and writes host-order opus_int16.
/// The conversion is its own inverse, so one call serves both directions. A no-op on
/// little-endian hosts.
/// @param data Sample buffer; needs no alignment.
/// @param size Buffer size in bytes; an odd trailing byte is left alone.
inline void pcm16_le_to_from_host(uint8_t* data, size_t size) {
    if constexpr (std::endian::native == std::endian::big) {
        for (size_t i = 0; i + 1 < size; i += 2) {
            std::swap(data[i], data[i + 1]);
        }
    }
}

}  // namespace sendspin
