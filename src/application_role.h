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
#include <string>

namespace sendspin {

/// @brief Whether `role` is an application-specific role name: `_`, a name, `@`, a version
///
/// README.md "Application-Specific Roles" requires the leading `_` and an explicit version. The
/// characters are held to visible ASCII so the name and its "<role>_support" key stay plain
/// identifiers on the wire.
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

/// @brief Whether `json` is exactly one JSON object, with nothing but whitespace after it
///
/// The text is embedded into client/hello as is, so trailing bytes deserializeJson() would stop
/// before must be refused here too.
inline bool is_valid_support_object_json(const std::string& json) {
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
        return false;
    }
    for (size_t i = reader.pos; i < json.size(); ++i) {
        const char c = json[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            return false;
        }
    }
    return true;
}

}  // namespace sendspin
