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

#include "message_trace.h"

#include "crypto/constants.h"
#include "inbound_ring.h"
#include "platform/time.h"
#include "protocol_messages.h"

#include <optional>
#include <string>
#include <string_view>

namespace sendspin {

namespace {

/// The pairing secrets a client sends (pairing.md "Wrapping"), each as its key and the opening
/// quote of its value, as ArduinoJson serializes them: with no whitespace.
constexpr std::string_view SECRET_FIELDS[] = {"\"long_term_psk\":\"", "\"wrapped_psk\":\"",
                                              "\"wrapped_nonce_B\":\""};

constexpr std::string_view REDACTED = "<redacted>";

/// @brief Copies `text` with the value of each secret field replaced by REDACTED, never copying a
/// secret byte
/// @return The redacted copy, or nullopt when `text` holds no secret field.
std::optional<std::string> redact_secrets(std::string_view text) {
    std::string out;
    size_t copied = 0;
    bool found = false;
    while (true) {
        size_t field = std::string_view::npos;
        size_t field_len = 0;
        for (const std::string_view key : SECRET_FIELDS) {
            const size_t at = text.find(key, copied);
            if (at < field) {
                field = at;
                field_len = key.size();
            }
        }
        if (field == std::string_view::npos) {
            break;
        }
        found = true;
        const size_t value_start = field + field_len;
        out.append(text.substr(copied, value_start - copied));
        out.append(REDACTED);
        // A value with no closing quote runs to the end, so nothing after its key is copied.
        const size_t value_end = text.find('"', value_start);
        copied = (value_end == std::string_view::npos) ? text.size() : value_end;
    }
    if (!found) {
        return std::nullopt;
    }
    out.append(text.substr(copied));
    return out;
}

}  // namespace

void MessageTracer::trace_inbound(bool binary, int64_t receive_time_us, const uint8_t* plaintext,
                                  size_t len) const {
    if (!this->trace_) {
        return;
    }
    SendspinTracedMessage message;
    message.connection_id = this->connection_id_;
    message.direction = SendspinTraceDirection::INBOUND;
    message.binary = binary;
    message.stamp_us = receive_time_us;
    message.plaintext = plaintext;
    message.plaintext_len = len;
    // The player hands its decoder the bytes after the chunk header (PlayerRole::Impl::
    // handle_binary(), whose AUDIO_FRAME_OFFSET is asserted equal to this header size).
    if (binary && len >= INBOUND_AUDIO_CHUNK_HEADER_BYTES &&
        plaintext[0] == SENDSPIN_BINARY_PLAYER_AUDIO) {
        message.audio_bytes = len - INBOUND_AUDIO_CHUNK_HEADER_BYTES;
    }
    this->trace_(message);
}

void MessageTracer::emit_outbound(bool binary, const uint8_t* plaintext, size_t len) const {
    if (!this->trace_) {
        return;
    }
    SendspinTracedMessage message;
    message.connection_id = this->connection_id_;
    message.direction = SendspinTraceDirection::OUTBOUND;
    message.binary = binary;
    message.stamp_us = platform_time_us();
    message.plaintext = plaintext;
    message.plaintext_len = len;
    // Only JSON carries a secret. The messages that do are far below MAX_TRANSPORT_PLAINTEXT, so
    // never fragmented.
    std::optional<std::string> redacted;
    if (!binary || (len > 0 && plaintext[0] == MSG_TYPE_JSON_BODY)) {
        redacted = redact_secrets(std::string_view(reinterpret_cast<const char*>(plaintext), len));
    }
    if (redacted.has_value()) {
        message.plaintext = reinterpret_cast<const uint8_t*>(redacted->data());
        message.plaintext_len = redacted->size();
    }
    this->trace_(message);
}

}  // namespace sendspin
