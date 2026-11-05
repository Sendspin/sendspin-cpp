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

/// @file pairing_record.h
/// @brief PairingRecord, a long-term pairing record held inline, and its storage encoder

#pragma once

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "sendspin/config.h"
#include "sendspin/persistence_keys.h"

#include <array>
#include <cstdint>
#include <span>

namespace sendspin {

/// @brief A long-term record as the store, a pending pairing and the flush hold it: the public
/// SendspinPairingRecord's fields with its ids inline, so minting and storing one allocates
/// nothing.
struct PairingRecord {
    IdText psk_id;
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    IdText server_id;

    PairingRecord() = default;
    PairingRecord(const PairingRecord&) = default;
    PairingRecord(PairingRecord&&) = default;
    PairingRecord& operator=(const PairingRecord&) = default;
    PairingRecord& operator=(PairingRecord&&) = default;

    /// @brief The public record's fields. Its ids are the codec's (decode_pairing_record()), each
    /// PEER_ID_SIZE characters, so they fit; a longer id is left empty.
    explicit PairingRecord(const SendspinPairingRecord& record) : psk(record.psk) {
        (void)this->psk_id.assign(record.psk_id);
        (void)this->server_id.assign(record.server_id);
    }

    /// @brief Wipes `psk` on destruction; same discipline as SendspinPairingRecord (see config.h).
    ~PairingRecord() {
        detail::secure_zero_psk(this->psk);
    }
};

/// @brief Encodes `record` into `out` in the layout encode_pairing_record()
/// (sendspin/persistence_codec.h) gives the public record; defined beside it in
/// persistence_codec.cpp, sharing that layout.
/// @return false, leaving `out` unwritten, when `server_id` is not the base64url encoding of a
///         32-byte public key.
[[nodiscard]] bool encode_pairing_record_into(
    const PairingRecord& record, std::span<uint8_t, persistence_keys::RECORD_SLOT_SIZE> out);

}  // namespace sendspin
