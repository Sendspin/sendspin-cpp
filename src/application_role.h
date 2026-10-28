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

/// @file application_role.h
/// @brief Checks on the application-specific roles a client advertises (README.md
/// "Application-Specific Roles").

#pragma once

#include "platform/json_arena.h"
#include <ArduinoJson.h>

#include <cstddef>
#include <optional>
#include <string>

namespace sendspin {

/// @brief Whether `role` is an application-specific role name: `_`, a name, `@`, a version
///
/// README.md "Application-Specific Roles" requires the leading `_` and an explicit version. The
/// characters are held to visible ASCII so the name and its "<role>_support" key stay plain
/// identifiers on the wire. An application-specific version of a defined role (`player@_exp`) is
/// not accepted: the library implements the defined roles itself.
inline bool is_valid_application_role_name(const std::string& role) {
    if (role.size() < 4 || role[0] != '_') {
        return false;
    }
    size_t at = std::string::npos;
    for (size_t i = 0; i < role.size(); ++i) {
        const char c = role[i];
        if (c < '!' || c > '~') {
            return false;
        }
        if (c == '@') {
            if (at != std::string::npos) {
                return false;
            }
            at = i;
        }
    }
    // A name after the `_` and a version after the `@`
    return at != std::string::npos && at > 1 && at + 1 < role.size();
}

/// @brief Whether `text` is well-formed UTF-8 (RFC 3629: no overlong forms, no surrogates)
inline bool is_valid_utf8(const std::string& text) {
    // RFC 3629 section 4 byte ranges
    constexpr unsigned char CONT_MIN = 0x80;  // also the first non-ASCII byte
    constexpr unsigned char CONT_MAX = 0xBF;
    constexpr unsigned char LEAD2_MIN = 0xC2;  // 0xC0 and 0xC1 only start overlong forms
    constexpr unsigned char LEAD3_MIN = 0xE0;
    constexpr unsigned char LEAD4_MIN = 0xF0;
    constexpr unsigned char LEAD_MAX = 0xF4;        // above it lies past U+10FFFF
    constexpr unsigned char AFTER_E0_MIN = 0xA0;    // E0 80..9F is overlong
    constexpr unsigned char SURROGATE_LEAD = 0xED;  // ED A0..BF encodes a surrogate
    constexpr unsigned char AFTER_ED_MAX = 0x9F;
    constexpr unsigned char AFTER_F0_MIN = 0x90;  // F0 80..8F is overlong
    constexpr unsigned char AFTER_F4_MAX = 0x8F;  // F4 90.. is past U+10FFFF

    size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        if (lead < CONT_MIN) {
            ++i;
            continue;
        }
        if (lead < LEAD2_MIN || lead > LEAD_MAX) {
            return false;
        }
        size_t len = 2;
        unsigned char lo = CONT_MIN;  // bounds of the first continuation byte
        unsigned char hi = CONT_MAX;
        if (lead >= LEAD4_MIN) {
            len = 4;
            lo = lead == LEAD4_MIN ? AFTER_F0_MIN : CONT_MIN;
            hi = lead == LEAD_MAX ? AFTER_F4_MAX : CONT_MAX;
        } else if (lead >= LEAD3_MIN) {
            len = 3;
            lo = lead == LEAD3_MIN ? AFTER_E0_MIN : CONT_MIN;
            hi = lead == SURROGATE_LEAD ? AFTER_ED_MAX : CONT_MAX;
        }
        if (text.size() - i < len) {
            return false;
        }
        for (size_t k = 1; k < len; ++k) {
            const auto c = static_cast<unsigned char>(text[i + k]);
            if (c < lo || c > hi) {
                return false;
            }
            lo = CONT_MIN;
            hi = CONT_MAX;
        }
        i += len;
    }
    return true;
}

/// @brief Parses `json` as one JSON object and returns it re-serialized, or nullopt
///
/// ArduinoJson's parser is lenient (unquoted keys, single quotes, leading zeros), so the text that
/// goes into client/hello is its own output rather than the caller's input. Trailing bytes the
/// parse stops before, and strings that are not UTF-8 or hold a raw control byte, are refused.
/// Two inputs are changed rather than refused, since detecting them would mean comparing the
/// parse to the input: an escaped lone surrogate is dropped and an out-of-range number becomes
/// null. Both still go out as valid JSON.
inline std::optional<std::string> normalize_support_object_json(const std::string& json) {
    // ArduinoJson reader that records how far the parse consumed
    struct CountingReader {
        const std::string& text;
        size_t pos{0};
        int read() {
            return this->pos < this->text.size()
                       ? static_cast<unsigned char>(this->text[this->pos++])
                       : -1;
        }
        // NOLINTNEXTLINE(readability-identifier-naming): the name ArduinoJson's Reader calls
        size_t readBytes(char* buffer, size_t length) {
            size_t n = 0;
            while (n < length && this->pos < this->text.size()) {
                buffer[n++] = this->text[this->pos++];
            }
            return n;
        }
    };

    // Capacity 0: every block comes from the platform allocator, wiped and freed on return
    SendspinArenaAllocator allocator(0);
    JsonDocument doc = make_json_document(allocator);
    CountingReader reader{json};
    if (deserializeJson(doc, reader) || !doc.is<JsonObject>()) {
        return std::nullopt;
    }
    for (size_t i = reader.pos; i < json.size(); ++i) {
        const char c = json[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            return std::nullopt;
        }
    }
    std::string out;
    serializeJson(doc, out);
    // The serializer passes a string's raw control bytes through unescaped, and minified output
    // has no other byte below 0x20
    for (const char c : out) {
        if (static_cast<unsigned char>(c) < 0x20) {
            return std::nullopt;
        }
    }
    if (!is_valid_utf8(out)) {
        return std::nullopt;
    }
    return out;
}

}  // namespace sendspin
