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
    size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        size_t len = 0;
        unsigned char lo = 0x80;
        unsigned char hi = 0xBF;  // bounds of the first continuation byte
        if (lead < 0x80) {
            ++i;
            continue;
        } else if (lead >= 0xC2 && lead <= 0xDF) {
            len = 2;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            len = 3;
            lo = lead == 0xE0 ? 0xA0 : 0x80;
            hi = lead == 0xED ? 0x9F : 0xBF;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            len = 4;
            lo = lead == 0xF0 ? 0x90 : 0x80;
            hi = lead == 0xF4 ? 0x8F : 0xBF;
        } else {
            return false;
        }
        if (text.size() - i < len) {
            return false;
        }
        for (size_t k = 1; k < len; ++k) {
            const auto c = static_cast<unsigned char>(text[i + k]);
            if (c < (k == 1 ? lo : 0x80) || c > (k == 1 ? hi : 0xBF)) {
                return false;
            }
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
