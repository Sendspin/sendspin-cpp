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

#include "keys.h"

#include "constants.h"
#include "platform/base64.h"
#include "platform/crypto.h"

#include <cstring>

// noise-c headers - include as extern "C" to silence pedantic warnings about C headers.
extern "C" {
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
}

namespace sendspin {

// -----------------------------------------------------------------------------
// PSK-ID derivation
// -----------------------------------------------------------------------------

std::string psk_id_for(const std::array<uint8_t, NOISE_PSK_SIZE>& psk) {
    auto digest = sha256_oneshot(reinterpret_cast<const uint8_t*>(PSK_ID_LABEL.data()),
                                 PSK_ID_LABEL.size(), psk.data(), psk.size());
    return b64url_encode(digest.data(), digest.size());
}

std::optional<std::string> psk_id_for(const uint8_t* psk, size_t len) {
    if (len != NOISE_PSK_SIZE) {
        return std::nullopt;
    }
    auto digest = sha256_oneshot(reinterpret_cast<const uint8_t*>(PSK_ID_LABEL.data()),
                                 PSK_ID_LABEL.size(), psk, len);
    return b64url_encode(digest.data(), digest.size());
}

// -----------------------------------------------------------------------------
// Identity
// -----------------------------------------------------------------------------

std::string Identity::peer_id() const {
    return b64url_encode(public_bytes.data(), public_bytes.size());
}

std::string Identity::private_b64u() const {
    return b64url_encode(private_bytes.data(), private_bytes.size());
}

Identity Identity::generate() {
    // Use noise-c's DHState to generate a fresh Curve25519 keypair.
    // This routes through noise-c's reference backend on both platforms.
    NoiseDHState* dh = nullptr;
    int err = noise_dhstate_new_by_name(&dh, "25519");
    Identity id{};
    if (err == NOISE_ERROR_NONE && dh != nullptr) {
        err = noise_dhstate_generate_keypair(dh);
        if (err == NOISE_ERROR_NONE) {
            size_t priv_len = noise_dhstate_get_private_key_length(dh);
            size_t pub_len = noise_dhstate_get_public_key_length(dh);
            if (priv_len == X25519_KEY_SIZE && pub_len == X25519_KEY_SIZE) {
                noise_dhstate_get_keypair(dh, id.private_bytes.data(), priv_len,
                                          id.public_bytes.data(), pub_len);
            }
        }
        noise_dhstate_free(dh);
    }
    return id;
}

std::optional<Identity> Identity::from_private_bytes(const uint8_t* priv, size_t len) {
    if (len != X25519_KEY_SIZE) {
        return std::nullopt;
    }

    NoiseDHState* dh = nullptr;
    int err = noise_dhstate_new_by_name(&dh, "25519");
    if (err != NOISE_ERROR_NONE || dh == nullptr) {
        return std::nullopt;
    }

    err = noise_dhstate_set_keypair_private(dh, priv, len);
    if (err != NOISE_ERROR_NONE) {
        noise_dhstate_free(dh);
        return std::nullopt;
    }

    Identity id{};
    size_t pub_len = noise_dhstate_get_public_key_length(dh);
    if (pub_len == X25519_KEY_SIZE) {
        std::memcpy(id.private_bytes.data(), priv, X25519_KEY_SIZE);
        noise_dhstate_get_public_key(dh, id.public_bytes.data(), pub_len);
    }
    noise_dhstate_free(dh);
    return id;
}

Identity Identity::from_private_bytes(const std::array<uint8_t, X25519_KEY_SIZE>& priv) {
    // This overload always succeeds since the size is known at compile time.
    auto result = from_private_bytes(priv.data(), priv.size());
    return result.value();  // size is guaranteed correct
}

}  // namespace sendspin
