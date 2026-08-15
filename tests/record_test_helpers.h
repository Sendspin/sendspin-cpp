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

/// @file record_test_helpers.h
/// @brief Shared builders for random PSKs and SendspinPairingRecord fixtures.

#pragma once

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "platform/crypto.h"
#include "sendspin/config.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

/// Generate a random PSK of NOISE_PSK_SIZE bytes.
inline std::array<uint8_t, NOISE_PSK_SIZE> make_random_psk() {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    return psk;
}

/// Build a stored-pubkey client record bound to server_id.
inline SendspinPairingRecord make_client_record(const std::string& server_id,
                                                 const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    rec.server_id = server_id;
    rec.label = label;
    return rec;
}

/// Build a shared-PSK (fallback) record: no server_id.
inline SendspinPairingRecord make_shared_record(const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    // server_id absent = shared record
    rec.label = label;
    return rec;
}

}  // namespace sendspin
