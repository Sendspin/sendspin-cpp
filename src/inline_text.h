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

/// @file inline_text.h
/// @brief Bounded text held inside the object, UTF-8 validation and safe truncation, and the
/// peer-text log bound

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace sendspin {

/// @brief High two bits of a UTF-8 byte, which 0b10 marks as a continuation byte
constexpr uint8_t UTF8_CONTINUATION_MASK = 0xC0;
/// @brief Masked value of a UTF-8 continuation byte
constexpr uint8_t UTF8_CONTINUATION_BITS = 0x80;
/// @brief Continuation bytes one UTF-8 character carries past its lead byte, at most
constexpr int UTF8_MAX_CONTINUATION_BYTES = 3;

/// @brief Returns the longest prefix of `text`, at most `max_bytes` long, that ends on a UTF-8
/// character boundary
///
/// Backs off over at most three continuation bytes, the most one UTF-8 character carries past its
/// lead byte, so text that is not UTF-8 is still cut within three bytes of `max_bytes`.
inline std::string_view utf8_truncate(std::string_view text, size_t max_bytes) {
    if (text.size() <= max_bytes) {
        return text;
    }
    size_t len = max_bytes;
    for (int backed_off = 0; backed_off < UTF8_MAX_CONTINUATION_BYTES && len > 0; ++backed_off) {
        if ((static_cast<uint8_t>(text[len]) & UTF8_CONTINUATION_MASK) != UTF8_CONTINUATION_BITS) {
            break;
        }
        --len;
    }
    return text.substr(0, len);
}

/// @brief Whether `text` is well-formed UTF-8 (RFC 3629: no overlong forms, no surrogates)
inline bool is_valid_utf8(std::string_view text) {
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

/// @brief Most bytes of a peer's text (a message type, a reason, an unrecognized value) one log
/// line prints. Every such value messaging.md and pairing.md define fits; the longest,
/// "pairing_code_mismatch", is 21 bytes.
constexpr size_t PEER_TEXT_LOG_BYTES = 32;

/// @brief `text` cut to at most PEER_TEXT_LOG_BYTES, for a log line's `%.*s`
inline std::string_view peer_text_for_log(std::string_view text) {
    return utf8_truncate(text, PEER_TEXT_LOG_BYTES);
}

/// @brief Text of at most N bytes held inline, NUL-terminated
template <size_t N>
class InlineText {
    static_assert(N <= UINT8_MAX, "InlineText holds its size in a uint8_t");

public:
    InlineText() = default;

    /// @brief Holds `text`.
    /// @return false, leaving the text empty, when `text` is longer than N.
    [[nodiscard]] bool assign(std::string_view text) {
        if (text.size() > N) {
            this->set(std::string_view{});
            return false;
        }
        this->set(text);
        return true;
    }

    std::string_view view() const {
        return {this->chars_.data(), this->size_};
    }

    const char* c_str() const {
        return this->chars_.data();
    }

    bool empty() const {
        return this->size_ == 0;
    }

    bool operator==(std::string_view other) const {
        return this->view() == other;
    }

    bool operator==(const InlineText& other) const {
        return this->view() == other.view();
    }

private:
    void set(std::string_view text) {
        text.copy(this->chars_.data(), text.size());
        this->chars_[text.size()] = '\0';
        this->size_ = static_cast<uint8_t>(text.size());
    }

    std::array<char, N + 1> chars_{};
    uint8_t size_{0};
};

}  // namespace sendspin
