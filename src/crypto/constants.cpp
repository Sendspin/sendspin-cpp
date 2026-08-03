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

#include "constants.h"

#include "keys.h"
#include "platform/crypto.h"

namespace sendspin {

// Sentinel PSK = SHA-256("sendspin-sentinel-psk-v1")
// Pre-computed from the label string at startup so we never hard-code the raw
// bytes; the test KAT verifies the hex matches the spec constant.
// NOLINTNEXTLINE(cert-err58-cpp)
const std::array<uint8_t, NOISE_PSK_SIZE> SENTINEL_PSK = []() {
    static constexpr char label[] = "sendspin-sentinel-psk-v1";
    return sha256_oneshot(reinterpret_cast<const uint8_t*>(label), sizeof(label) - 1);
}();

// SENTINEL_PSK_ID = base64url(SHA-256(PSK_ID_LABEL || SENTINEL_PSK))
// Computed once at startup from SENTINEL_PSK.
// NOLINTNEXTLINE(cert-err58-cpp)
const std::string SENTINEL_PSK_ID = psk_id_for(SENTINEL_PSK);

}  // namespace sendspin
