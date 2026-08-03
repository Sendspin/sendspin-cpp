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

#include "pin.h"

#include "platform/crypto.h"

#include <cstring>

namespace sendspin {

// ---------------------------------------------------------------------------
// pin_generate_nonce
// ---------------------------------------------------------------------------

std::array<uint8_t, PIN_NONCE_SIZE> pin_generate_nonce() {
    std::array<uint8_t, PIN_NONCE_SIZE> nonce{};
    platform_random_bytes(nonce.data(), nonce.size());
    return nonce;
}

// ---------------------------------------------------------------------------
// pin_commit: SHA-256(nonce)
// ---------------------------------------------------------------------------

std::array<uint8_t, PIN_COMMIT_SIZE> pin_commit(const uint8_t* nonce, size_t nonce_len) {
    return sha256_oneshot(nonce, nonce_len);
}

// ---------------------------------------------------------------------------
// pin_verify_commit: constant-time compare SHA-256(nonce) vs commitment
// ---------------------------------------------------------------------------

bool pin_verify_commit(const uint8_t* nonce, size_t nonce_len, const uint8_t* commitment,
                       size_t commitment_len) {
    if (commitment_len != PIN_COMMIT_SIZE || nonce_len != PIN_NONCE_SIZE) {
        return false;
    }
    auto computed = pin_commit(nonce, nonce_len);
    return constant_time_equal(computed.data(), commitment, PIN_COMMIT_SIZE);
}

// ---------------------------------------------------------------------------
// pin_derive
//
// digest = SHA-256(PIN_DERIVE_LABEL || handshake_hash || nonce_a || nonce_b)
// pin_int = big-endian interpret(digest) mod 10^pin_length
// Returns zero-padded decimal string of pin_length digits.
// ---------------------------------------------------------------------------

std::optional<std::string> pin_derive(const uint8_t* handshake_hash, size_t hash_len,
                                      const uint8_t* nonce_a, size_t nonce_a_len,
                                      const uint8_t* nonce_b, size_t nonce_b_len, int pin_length) {
    if (pin_length < PIN_MIN_DIGITS || pin_length > PIN_MAX_DIGITS) {
        return std::nullopt;
    }
    if (hash_len != PIN_NONCE_SIZE || nonce_a_len != PIN_NONCE_SIZE ||
        nonce_b_len != PIN_NONCE_SIZE) {
        return std::nullopt;
    }

    // SHA-256(label || hash || nonce_a || nonce_b)
    const auto* label = reinterpret_cast<const uint8_t*>(PIN_DERIVE_LABEL);
    size_t label_len = sizeof(PIN_DERIVE_LABEL) - 1;  // exclude NUL

    Sha256 h;
    if (!h.ok()) {
        // noise_hashstate_new_by_name() failed (allocation failure or missing algorithm); h is
        // a no-op in this state and finalize() would silently yield an all-zero digest, which
        // for PIN derivation would produce a predictable PIN instead of failing loudly.
        return std::nullopt;
    }
    h.update(label, label_len);
    h.update(handshake_hash, hash_len);
    h.update(nonce_a, nonce_a_len);
    h.update(nonce_b, nonce_b_len);
    auto digest = h.finalize();

    // Interpret as a big-endian 256-bit unsigned integer mod 10^pin_length.
    // We compute the modulus using 128-bit arithmetic to avoid overflow:
    // 10^12 = 1_000_000_000_000 < 2^40, fits in uint64_t.
    // 256-bit big-endian mod uint64_t: process bytes from most to least significant.
    uint64_t modulus = 1;
    for (int i = 0; i < pin_length; ++i) {
        modulus *= 10;
    }

    // Compute (big-endian 256-bit number) mod modulus via Horner's method.
    // pin_int = 0; for each byte b: pin_int = (pin_int * 256 + b) mod modulus
    // acc stays < modulus after every step, so acc * 256 + byte < modulus * 256. With modulus
    // <= 10^pin_length (and pin_length small enough that the result fits a uint64_t decimal), this
    // stays well within uint64_t range, so no 128-bit arithmetic is needed (and 32-bit targets
    // such as Xtensa have no __int128).
    uint64_t acc = 0;
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        acc = (acc * 256 + digest[i]) % modulus;
    }
    uint64_t pin_int = acc;

    // Format as zero-padded decimal string.
    std::string pin(static_cast<size_t>(pin_length), '0');
    for (int i = pin_length - 1; i >= 0; --i) {
        pin[static_cast<size_t>(i)] = static_cast<char>('0' + (pin_int % 10));
        pin_int /= 10;
    }
    return pin;
}

}  // namespace sendspin
