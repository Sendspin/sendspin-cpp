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

/// @file base64.h
/// @brief Platform-abstracted base64 helpers.
///
/// Provides two sets of helpers:
///
/// 1. **Standard base64 decode** (`platform_base64_decode`): wraps mbedTLS on ESP and a
///    built-in implementation on host.  Handles `+`/`/` alphabet with optional `=` padding.
///
/// 2. **URL-safe base64url** (`b64url_encode` / `b64url_decode`): portable pure-C++ helpers
///    that are *identical* on host and ESP.  Use the `-`/`_` alphabet with no `=` padding.
///    These are required for Noise-protocol key identifiers (PSK IDs, peer IDs).

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#ifdef ESP_PLATFORM

#include <mbedtls/base64.h>

namespace sendspin {

/// @brief Decodes base64 data
/// @param[out] dst Output buffer, or nullptr for a size query.
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
/// @param[out] dst Output buffer, or nullptr for a size query.
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

// ============================================================================
// Base64url helpers - portable, identical on both ESP and host.
//
// These implement the URL-safe base64 alphabet (RFC 4648 §5) with no `=` padding:
//   - encode uses `-` and `_` instead of `+` and `/`
//   - encode strips trailing `=` padding
//   - decode tolerates missing `=` padding
//
// The functions live outside the ESP/host split because they are pure
// computation with no OS or platform dependency.
// ============================================================================

namespace sendspin {

namespace detail {

// clang-format off
/// Encoding alphabet: URL-safe base64 (RFC 4648 §5).
static constexpr char B64URL_ENCODE_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decode table for the URL-safe alphabet.  255 = invalid.
static constexpr unsigned char B64URL_DECODE_TABLE[128] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //   0-15
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //  16-31
    255,255,255,255,255,255,255,255,255,255,255,255,255, 62,255,255,  //  32-47  (-, no +, no /)
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,  //  48-63  (0-9)
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  //  64-79  (A-O)
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,  //  80-95  (P-Z, _, no [,\,])
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  //  96-111 (a-o)
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,  // 112-127 (p-z)
};
// clang-format on

}  // namespace detail

/// @brief Encode bytes to base64url, no `=` padding (RFC 4648 §5).
/// @param data  Input bytes.
/// @param len   Number of bytes.
/// @return ASCII string using only `A-Z a-z 0-9 - _`.
inline std::string b64url_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) {
            b |= static_cast<uint32_t>(data[i + 1]) << 8;
        }
        if (i + 2 < len) {
            b |= static_cast<uint32_t>(data[i + 2]);
        }

        out += detail::B64URL_ENCODE_TABLE[(b >> 18) & 0x3F];
        out += detail::B64URL_ENCODE_TABLE[(b >> 12) & 0x3F];
        if (i + 1 < len) {
            out += detail::B64URL_ENCODE_TABLE[(b >> 6) & 0x3F];
        }
        if (i + 2 < len) {
            out += detail::B64URL_ENCODE_TABLE[b & 0x3F];
        }
    }
    return out;
}

/// @brief Decode base64url, tolerating missing `=` padding (RFC 4648 §5).
/// @param s  Null-terminated base64url string.
/// @return Decoded bytes, or std::nullopt on invalid input.
inline std::optional<std::vector<uint8_t>> b64url_decode(const char* s) {
    size_t slen = std::strlen(s);

    // Strip any trailing `=` padding the caller may have included.
    while (slen > 0 && s[slen - 1] == '=') {
        --slen;
    }

    // Output size: every 4 base64 chars produce 3 bytes; remainder produces 1 or 2.
    size_t out_len = (slen * 3) / 4;
    std::vector<uint8_t> out;
    out.reserve(out_len);

    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < slen; ++i) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c >= 128 || detail::B64URL_DECODE_TABLE[c] == 255) {
            return std::nullopt;  // Invalid character
        }
        acc = (acc << 6) | detail::B64URL_DECODE_TABLE[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }

    return out;
}

/// @brief Decode base64url from a std::string, tolerating missing `=` padding.
inline std::optional<std::vector<uint8_t>> b64url_decode(const std::string& s) {
    return b64url_decode(s.c_str());
}

}  // namespace sendspin
