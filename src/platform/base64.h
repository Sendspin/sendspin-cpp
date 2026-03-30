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

#ifdef ESP_PLATFORM

#include <mbedtls/base64.h>

namespace sendspin {

/// @brief Decodes base64 data
/// @param dst Output buffer, or nullptr for a size query.
/// @param dlen Capacity of the output buffer in bytes.
/// @param[out] olen Set to the number of decoded bytes written.
/// @param src Pointer to the base64-encoded input data.
/// @param slen Length of the input data in bytes.
/// @return 0 on success, non-zero on error.
inline int platform_base64_decode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                  size_t slen) {
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
}

}  // namespace sendspin

#else  // Host

#include <cstring>

namespace sendspin {

// clang-format off
static constexpr unsigned char BASE64_DECODE_TABLE[128] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //   0-15
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //  16-31
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,  //  32-47  (+, /)
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,  //  48-63  (0-9)
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  //  64-79  (A-O)
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,  //  80-95  (P-Z)
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  //  96-111 (a-o)
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,  // 112-127 (p-z)
};
// clang-format on

/// @brief Decodes base64 data (host implementation)
/// @param dst Output buffer, or nullptr for a size query.
/// @param dlen Capacity of the output buffer in bytes.
/// @param[out] olen Set to the number of decoded bytes written.
/// @param src Pointer to the base64-encoded input data.
/// @param slen Length of the input data in bytes.
/// @return 0 on success, non-zero on error.
inline int platform_base64_decode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                  size_t slen) {
    // Skip trailing padding and whitespace
    while (slen > 0 && (src[slen - 1] == '=' || src[slen - 1] == '\n' || src[slen - 1] == '\r')) {
        slen--;
    }

    // Calculate output size
    size_t n = (slen * 3) / 4;
    *olen = n;

    if (dst == nullptr || dlen == 0) {
        return 0;  // Size query
    }

    if (dlen < n) {
        return -1;  // Buffer too small
    }

    size_t j = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < slen; i++) {
        unsigned char c = src[i];
        if (c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        if (c >= 128 || BASE64_DECODE_TABLE[c] == 255) {
            return -1;  // Invalid character
        }
        acc = (acc << 6) | BASE64_DECODE_TABLE[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (j < dlen) {
                dst[j++] = static_cast<uint8_t>((acc >> bits) & 0xFF);
            }
        }
    }

    *olen = j;
    return 0;
}

}  // namespace sendspin

#endif  // ESP_PLATFORM
