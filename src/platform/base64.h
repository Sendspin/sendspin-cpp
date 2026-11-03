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
/// @brief Platform-abstracted base64: `platform_base64_*` wrap mbedTLS on ESP and a built-in
/// codec on host, for the standard `+`/`/` alphabet with `=` padding; base64_encode() is its
/// portable string form, and `b64url_*` are portable wrappers for the URL-safe alphabet used by
/// Noise key identifiers (PSK IDs, peer IDs).

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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

/// @brief Encodes bytes to base64 (standard `+`/`/` alphabet, `=` padded).
/// @param[out] dst Output buffer; must be non-null with dlen >= the required size (see olen).
/// @param dlen Capacity of the output buffer in bytes, including room for the trailing NUL.
/// @param[out] olen On success, the number of encoded bytes written (excluding the trailing
///             NUL that is also written to dst[olen]). On MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL,
///             the required dlen (including the trailing NUL).
/// @param src Pointer to the raw input bytes.
/// @param slen Length of the input data in bytes.
/// @return 0 on success, non-zero on error (buffer too small).
inline int platform_base64_encode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                  size_t slen) {
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
}

}  // namespace sendspin

#else  // Host

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

/// @brief Decodes base64 data (host implementation); same contract as the ESP one above.
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

// clang-format off
/// Encoding alphabet: standard base64 (RFC 4648 section 4).
static constexpr char BASE64_ENCODE_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// clang-format on

/// @brief Bits one base64 character encodes, and the mask selecting them.
static constexpr int BASE64_BITS_PER_CHAR = 6;
static constexpr uint32_t BASE64_CHAR_MASK = 0x3F;

/// @brief Encodes bytes to base64 (host implementation); same contract as the ESP one above.
inline int platform_base64_encode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                  size_t slen) {
    if (slen == 0) {
        *olen = 0;
        return 0;
    }

    size_t n = (slen / 3 + (slen % 3 != 0 ? 1 : 0)) * 4;

    if (dst == nullptr || dlen < n + 1) {
        *olen = n + 1;
        return -1;
    }

    const size_t full = (slen / 3) * 3;
    uint8_t* p = dst;
    for (size_t i = 0; i < full; i += 3) {
        uint32_t v = (static_cast<uint32_t>(src[i]) << 16) |
                     (static_cast<uint32_t>(src[i + 1]) << 8) | static_cast<uint32_t>(src[i + 2]);
        *p++ = BASE64_ENCODE_TABLE[(v >> (3 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        *p++ = BASE64_ENCODE_TABLE[(v >> (2 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        *p++ = BASE64_ENCODE_TABLE[(v >> BASE64_BITS_PER_CHAR) & BASE64_CHAR_MASK];
        *p++ = BASE64_ENCODE_TABLE[v & BASE64_CHAR_MASK];
    }

    if (full < slen) {
        const bool has_second = (full + 1) < slen;
        uint32_t v = static_cast<uint32_t>(src[full]) << 16;
        if (has_second) {
            v |= static_cast<uint32_t>(src[full + 1]) << 8;
        }
        *p++ = BASE64_ENCODE_TABLE[(v >> (3 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        *p++ = BASE64_ENCODE_TABLE[(v >> (2 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        *p++ =
            has_second ? BASE64_ENCODE_TABLE[(v >> BASE64_BITS_PER_CHAR) & BASE64_CHAR_MASK] : '=';
        *p++ = '=';
    }

    *olen = static_cast<size_t>(p - dst);
    *p = 0;
    return 0;
}

}  // namespace sendspin

#endif  // ESP_PLATFORM

// ============================================================================
// Base64url helpers (RFC 4648 section 5): the `-`/`_` alphabet, no `=` padding, identical on
// both platforms. Both transliterate the alphabet and delegate the bit-accumulator work to
// platform_base64_encode/decode rather than hand-rolling a second codec. mbedTLS's decoder
// requires input padded to a multiple of 4, so decode always re-pads; the host decoder strips
// trailing `=` itself, so one path is correct on both platforms. The `_into` forms write to a
// caller's buffer and allocate nothing.
// ============================================================================

namespace sendspin {

/// @brief Encode bytes to standard base64 (RFC 4648 section 4): `+`/`/`, `=`-padded.
inline std::string base64_encode(const uint8_t* data, size_t len) {
    if (len == 0) {
        return std::string();
    }

    // Output length, including room for the trailing NUL both platform_base64_encode
    // implementations write per the mbedtls_base64_encode contract.
    const size_t padded_len = (len / 3 + (len % 3 != 0 ? 1 : 0)) * 4;
    std::string out(padded_len + 1, '\0');
    size_t olen = 0;
    // out is sized exactly per platform_base64_encode's own contract, so this cannot fail.
    platform_base64_encode(reinterpret_cast<uint8_t*>(out.data()), out.size(), &olen, data, len);
    out.resize(olen);
    return out;
}

/// @brief Buffer size b64url_encode_into() needs for `len` bytes: the padded standard encoding
/// and its NUL, which the platform encoders write before the padding is stripped.
constexpr size_t b64url_encode_buffer_size(size_t len) {
    return (len + 2) / 3 * 4 + 1;
}

/// @brief Encode bytes to base64url into a caller's buffer.
/// @param dst Output buffer; a nonempty encoding is NUL-terminated in it.
/// @param cap Size of dst: at least b64url_encode_buffer_size(len).
/// @return The encoding, a view into dst; empty when cap is smaller than that.
inline std::string_view b64url_encode_into(char* dst, size_t cap, const uint8_t* data, size_t len) {
    size_t olen = 0;
    if (platform_base64_encode(reinterpret_cast<uint8_t*>(dst), cap, &olen, data, len) != 0) {
        return {};
    }
    while (olen > 0 && dst[olen - 1] == '=') {
        dst[--olen] = '\0';
    }
    for (size_t i = 0; i < olen; ++i) {
        if (dst[i] == '+') {
            dst[i] = '-';
        } else if (dst[i] == '/') {
            dst[i] = '_';
        }
    }
    return {dst, olen};
}

/// @brief Encode bytes to base64url: an ASCII string of `A-Z a-z 0-9 - _`, no `=` padding.
inline std::string b64url_encode(const uint8_t* data, size_t len) {
    // Encoded straight into the returned string, so it stays the only copy of the encoding:
    // callers encoding secrets (the pairing PSK) wipe the one string they get back.
    std::string out(b64url_encode_buffer_size(len), '\0');
    out.resize(b64url_encode_into(out.data(), out.size(), data, len).size());
    return out;
}

/// @brief Bytes a base64url string decodes to, ignoring trailing `=` padding.
/// @return nullopt when the length is not a base64 length under any padding.
inline std::optional<size_t> b64url_decoded_size(std::string_view s) {
    while (!s.empty() && s.back() == '=') {
        s.remove_suffix(1);
    }
    if (s.size() % 4 == 1) {
        return std::nullopt;
    }
    return s.size() / 4 * 3 + (s.size() % 4 == 0 ? 0 : s.size() % 4 - 1);
}

/// @brief Decode base64url into a caller's buffer, tolerating missing `=` padding.
///
/// Each group of four characters is transliterated to the standard alphabet on the stack and
/// decoded on its own, so no copy of the input is made.
/// @param dst Output buffer.
/// @param cap Size of dst: at least b64url_decoded_size(s).
/// @return The number of bytes written, or nullopt on invalid input or a smaller cap.
inline std::optional<size_t> b64url_decode_into(std::string_view s, uint8_t* dst, size_t cap) {
    const std::optional<size_t> size = b64url_decoded_size(s);
    if (!size.has_value() || size.value() > cap) {
        return std::nullopt;
    }
    while (!s.empty() && s.back() == '=') {
        s.remove_suffix(1);
    }

    size_t written = 0;
    for (size_t i = 0; i < s.size(); i += 4) {
        // Explicitly whitelists [A-Za-z0-9], '-' and '_'. Anything else (a literal '+' or '/',
        // whitespace, a stray '=') is rejected here rather than passed through:
        // platform_base64_decode's host implementation silently skips '\n'/'\r'/' ' instead of
        // rejecting them, so strictness must not depend on the platform decoder's laxity, or
        // accepted input would silently diverge between host and ESP (mbedTLS rejects those
        // bytes outright).
        uint8_t group[4] = {'=', '=', '=', '='};
        for (size_t k = 0; k < 4 && i + k < s.size(); ++k) {
            char c = s[i + k];
            if (c == '-') {
                c = '+';
            } else if (c == '_') {
                c = '/';
            } else if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9')) {
                return std::nullopt;
            }
            group[k] = static_cast<uint8_t>(c);
        }
        size_t olen = 0;
        if (platform_base64_decode(dst + written, cap - written, &olen, group, sizeof(group)) !=
            0) {
            return std::nullopt;
        }
        written += olen;
    }
    return written;
}

/// @brief Decode base64url, tolerating missing `=` padding; nullopt on invalid input.
inline std::optional<std::vector<uint8_t>> b64url_decode(std::string_view s) {
    const std::optional<size_t> size = b64url_decoded_size(s);
    if (!size.has_value()) {
        return std::nullopt;
    }
    std::vector<uint8_t> out(size.value());
    if (!b64url_decode_into(s, out.data(), out.size()).has_value()) {
        return std::nullopt;
    }
    return out;
}

}  // namespace sendspin
