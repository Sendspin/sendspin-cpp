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

#include "pairing_token.h"

#include "platform/secure_zero.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>

namespace sendspin {

namespace {

/// @brief RFC 4648 base32 alphabet (section 6): A-Z, 2-7.
constexpr char BASE32_ALPHABET[32] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                                      'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                      'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'};

/// @brief Bits one base32 character encodes, and the mask selecting them.
constexpr int BASE32_BITS_PER_CHAR = 5;
constexpr uint32_t BASE32_CHAR_MASK = 0x1F;

/// @brief The "SP:" prefix and the version character ahead of every token's body.
constexpr size_t TOKEN_HEADER_LENGTH = 4;

/// @brief Characters RFC 4648 base32 encodes `len` bytes in once its '=' padding is stripped.
constexpr size_t base32_unpadded_length(size_t len) {
    return (len * 8 + BASE32_BITS_PER_CHAR - 1) / BASE32_BITS_PER_CHAR;
}

static_assert(PAIRING_PSK_TOKEN_LENGTH ==
                  TOKEN_HEADER_LENGTH + base32_unpadded_length(X25519_KEY_SIZE + NOISE_PSK_SIZE),
              "a version-0 token is its header and the base32 of its 64-byte payload");
static_assert(PAIRING_CODE_TOKEN_LENGTH ==
                  TOKEN_HEADER_LENGTH + base32_unpadded_length(QR_PAIRING_CODE_SIZE),
              "a version-1 token is its header and the base32 of its 24-byte payload");

/// @brief Wrap a payload as a pairing token of the given version (pairing.md "Pairing Token"):
/// "SP:" and the version, then the payload in RFC 4648 base32 with the '=' padding stripped and
/// every '2' replaced by '9'. Shared by both versions so their bodies cannot diverge.
/// @tparam N The token's length, TOKEN_HEADER_LENGTH + base32_unpadded_length(payload_len).
template <size_t N>
InlineText<N> format_token(char version, const uint8_t* payload, size_t payload_len) {
    assert(N == TOKEN_HEADER_LENGTH + base32_unpadded_length(payload_len));
    std::array<char, N> chars{'S', 'P', ':', version};
    size_t length = TOKEN_HEADER_LENGTH;
    const auto emit = [&chars, &length](uint32_t value) {
        const char c = BASE32_ALPHABET[value & BASE32_CHAR_MASK];
        chars[length++] = c == '2' ? '9' : c;
    };

    // Base32 reads the payload as one big-endian bit string, five bits per character; a final
    // partial group is padded with zero bits on the right.
    uint32_t bits = 0;
    int bit_count = 0;
    for (size_t i = 0; i < payload_len; ++i) {
        bits = (bits << 8) | payload[i];
        bit_count += 8;
        while (bit_count >= BASE32_BITS_PER_CHAR) {
            bit_count -= BASE32_BITS_PER_CHAR;
            emit(bits >> bit_count);
        }
    }
    if (bit_count > 0) {
        emit(bits << (BASE32_BITS_PER_CHAR - bit_count));
    }

    InlineText<N> token;
    (void)token.assign({chars.data(), length});  // Exactly N characters
    // A version-0 body is the Pairing PSK in base32.
    secure_zero_container(chars);
    return token;
}

}  // namespace

PairingPskToken format_pairing_token(const std::array<uint8_t, X25519_KEY_SIZE>& client_key,
                                     const std::array<uint8_t, NOISE_PSK_SIZE>& pairing_psk) {
    std::array<uint8_t, X25519_KEY_SIZE + NOISE_PSK_SIZE> payload{};
    std::copy(client_key.begin(), client_key.end(), payload.begin());
    std::copy(pairing_psk.begin(), pairing_psk.end(), payload.begin() + X25519_KEY_SIZE);

    PairingPskToken token = format_token<PAIRING_PSK_TOKEN_LENGTH>(PAIRING_PSK_TOKEN_VERSION,
                                                                   payload.data(), payload.size());
    secure_zero_container(payload);
    return token;
}

PairingCodeToken format_pairing_code_token(const std::array<uint8_t, QR_PAIRING_CODE_SIZE>& code) {
    return format_token<PAIRING_CODE_TOKEN_LENGTH>(PAIRING_CODE_TOKEN_VERSION, code.data(),
                                                   code.size());
}

}  // namespace sendspin
