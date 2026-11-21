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

/// @file crypto_test_helpers.h
/// @brief A one-buffer wrapper over the library's streamed HMAC-SHA-512, for the KATs.

#pragma once

#include "platform/crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace sendspin {

/// Compute HMAC-SHA-512(key, data) through hmac_sha512_streamed().
inline std::array<uint8_t, SHA512_DIGEST_SIZE> hmac_sha512(const uint8_t* key, size_t key_len,
                                                           const uint8_t* data, size_t data_len) {
    return hmac_sha512_streamed(key, key_len,
                                [data, data_len](Sha512& inner) { inner.update(data, data_len); });
}

}  // namespace sendspin
