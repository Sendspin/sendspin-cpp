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

#include "inline_text.h"
#include "platform/json_arena.h"
#include "protocol_messages.h"
#include <ArduinoJson.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

/// @brief Longest application-specific role name start() accepts, in bytes. The specification
/// does not bound role names; this library limit sizes the stack buffer client/hello builds each
/// "<role>_support" key in.
constexpr size_t MAX_APPLICATION_ROLE_NAME_BYTES = 64;

/// @brief Deepest support object start() accepts, in nesting levels with the object itself level
/// 1: client/hello's root and payload objects sit above it, within MAX_CLIENT_HELLO_NESTING.
constexpr uint8_t MAX_SUPPORT_OBJECT_NESTING = MAX_CLIENT_HELLO_NESTING - 2;

/// @brief Whether `role` is an application-specific role name: `_`, a name, `@`, a version
///
/// README.md "Application-Specific Roles" requires the leading `_` and an explicit version. The
/// characters are held to visible ASCII other than `"` and `\`, which JSON escapes, so the name
/// and its "<role>_support" key go on the wire as written, and the length to
/// MAX_APPLICATION_ROLE_NAME_BYTES. An application-specific version of a defined role
/// (`player@_exp`) is not accepted: the library implements the defined roles itself.
inline bool is_valid_application_role_name(const std::string& role) {
    if (role.size() < 4 || role.size() > MAX_APPLICATION_ROLE_NAME_BYTES || role[0] != '_') {
        return false;
    }
    size_t at = std::string::npos;
    for (size_t i = 0; i < role.size(); ++i) {
        const char c = role[i];
        if (c < '!' || c > '~' || c == '"' || c == '\\') {
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

/// @brief Parses `json` as one JSON object and returns it re-serialized, or nullopt
///
/// ArduinoJson's parser is lenient (unquoted keys, single quotes, leading zeros), so the text that
/// goes into client/hello is its own output rather than the caller's input. Trailing bytes the
/// parse stops before, nesting deeper than MAX_SUPPORT_OBJECT_NESTING, and strings that are not
/// UTF-8 or hold a raw control byte, are refused. Two inputs are changed rather than refused,
/// since detecting them would mean comparing the parse to the input: an escaped surrogate outside
/// a valid pair is dropped or replaced by another character, and an out-of-range number becomes
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
    const DeserializationOption::NestingLimit nesting(MAX_SUPPORT_OBJECT_NESTING);
    if (deserializeJson(doc, reader, nesting) || !doc.is<JsonObject>()) {
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
