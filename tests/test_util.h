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

/// @file test_util.h
/// @brief Shared test helpers: hex encoding/decoding for KAT comparisons, the big-endian
/// appenders the binary role messages are built with, and the JSON arena the message builders
/// take.

#pragma once

#include "platform/json_arena.h"
#include "protocol_messages.h"
#include "sendspin/config.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

/// Convert a byte buffer to its lowercase hex string.
inline std::string to_hex(const uint8_t* data, size_t len) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += HEX[(data[i] >> 4) & 0xF];
        out += HEX[data[i] & 0xF];
    }
    return out;
}

template <size_t N>
inline std::string to_hex(const std::array<uint8_t, N>& a) {
    return to_hex(a.data(), a.size());
}

inline std::string to_hex(const std::vector<uint8_t>& v) {
    return to_hex(v.data(), v.size());
}

/// Decode a lowercase hex string into a byte vector.
inline std::vector<uint8_t> from_hex(const char* s) {
    std::vector<uint8_t> out;
    while (*s && *(s + 1)) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            return static_cast<uint8_t>(c - 'a' + 10);
        };
        out.push_back(static_cast<uint8_t>((nibble(s[0]) << 4) | nibble(s[1])));
        s += 2;
    }
    return out;
}

/// Decode a lowercase hex string into a fixed-size byte array. A string shorter than N bytes
/// leaves the tail zeroed rather than reading past the decoded buffer, so a typo'd KAT vector
/// fails its comparison instead of tripping the sanitizers on unrelated memory.
template <size_t N>
inline std::array<uint8_t, N> from_hex_arr(const char* s) {
    auto v = from_hex(s);
    std::array<uint8_t, N> a{};
    std::memcpy(a.data(), v.data(), std::min(v.size(), N));
    return a;
}

/// Appends val as 8 big-endian bytes: the timestamp a binary role message carries.
inline void put_be64(std::vector<uint8_t>& out, int64_t val) {
    uint8_t bytes[sizeof(uint64_t)];
    sendspin::host_to_be64(val, bytes);
    out.insert(out.end(), std::begin(bytes), std::end(bytes));
}

/// Appends val as 4 big-endian bytes: an artwork announce's total_size.
inline void put_be32(std::vector<uint8_t>& out, uint32_t val) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
    }
}

/// A fresh arena sized like the client's default, for the message builders (the format_*()
/// family) and the Noise handshake. Used as a temporary for one builder call
/// (`format_client_leave_message(TestArena())`) or as a local where the arena must outlive the
/// call (a NoiseHandshake keeps a reference), so no two tests share one. Anything that keeps the
/// reference must take a named TestArena: the conversion operator would bind it to a temporary
/// destroyed at the end of the full expression.
struct TestArena {
    sendspin::SendspinArenaAllocator arena{sendspin::SendspinClientConfig::DEFAULT_JSON_ARENA_SIZE};

    // NOLINTNEXTLINE(google-explicit-constructor): stands in for the arena at every call site.
    operator sendspin::SendspinArenaAllocator&() {
        return this->arena;
    }
};
