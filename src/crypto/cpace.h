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

/// @file cpace.h
/// @brief CPace-X25519-SHA512 PAKE with explicit mutual confirmation.
///
/// Mirrors `aiosendspin/noise/cpace.py` exactly.  The Sendspin server is
/// role A (INITIATOR); the client is role B (RESPONDER).  Both roles are
/// implemented so the primitive is fully testable and round-trip tests can
/// play either side.
///
/// Errors are reported via bool return values; the caller should treat a
/// false return from derive() or verify() as a fatal pairing failure.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <utility>
#include <vector>

namespace sendspin {

// -----------------------------------------------------------------------------
// Constants (mirrors cpace.py)
// -----------------------------------------------------------------------------

/// @brief DSI string for generator derivation.
static constexpr char CPACE_DSI[] = "CPace255";

/// @brief DSI string for ISK derivation.
static constexpr char CPACE_DSI_ISK[] = "CPace255_ISK";

/// @brief Label for MAC key derivation.
static constexpr char CPACE_MAC_LABEL[] = "CPaceMac";

/// @brief SHA-512 block size in bytes.
static constexpr size_t CPACE_SHA512_BLOCK = 128;

/// @brief Curve25519 field size (and share size) in bytes.
static constexpr size_t CPACE_FIELD_BYTES = 32;

/// @brief Size of a CPace public share in bytes.
static constexpr size_t CPACE_SHARE_SIZE = 32;

/// @brief Size of a CPace confirmation tag (HMAC-SHA-512 output) in bytes.
static constexpr size_t CPACE_TAG_SIZE = 64;

// -----------------------------------------------------------------------------
// CPaceRole
// -----------------------------------------------------------------------------

/// @brief CPace protocol role.  The Sendspin server is A (INITIATOR).
enum class CPaceRole : uint8_t {
    INITIATOR = 0,  ///< Role A: sends the first share
    RESPONDER = 1,  ///< Role B: sends the second share
};

// -----------------------------------------------------------------------------
// CPace
// -----------------------------------------------------------------------------

/// @brief One side of a CPace-X25519-SHA512 exchange with mutual confirmation.
///
/// Usage:
/// @code
///   // Phase 1: start
///   CPace side;
///   std::vector<uint8_t> my_share;
///   if (!side.start(CPaceRole::RESPONDER, prs, sid, {}, {}, {})) return false;
///   my_share = side.public_share();
///
///   // Phase 2: receive peer share, derive MAC key
///   if (!side.derive(peer_share)) return false;
///
///   // Phase 3: exchange tags
///   auto my_tag = side.tag();         // send to peer
///   if (!side.verify(peer_tag)) return false;  // verify peer tag
/// @endcode
class CPace {
public:
    CPace() = default;

    /// @brief Zeroizes the scalar and MAC key on destruction.
    ~CPace();

    /// @brief Begin a CPace run, sampling a scalar and computing the public share.
    ///
    /// @param role     INITIATOR (A) or RESPONDER (B)
    /// @param prs      Password-related string (PIN ASCII digits for Sendspin)
    /// @param sid      Session identifier
    /// @param ci       Channel identifier (empty for Sendspin)
    /// @param ad       This side's associated data (empty for Sendspin)
    /// @param peer_ad  Peer's associated data (empty for Sendspin)
    /// @return false if the random scalar or generator computation fails
    bool start(CPaceRole role, const std::vector<uint8_t>& prs, const std::vector<uint8_t>& sid,
               const std::vector<uint8_t>& ci, const std::vector<uint8_t>& ad,
               const std::vector<uint8_t>& peer_ad);

    /// @brief Return this side's public share (Ya for A, Yb for B).
    /// Valid only after a successful start().
    [[nodiscard]] const std::array<uint8_t, CPACE_SHARE_SIZE>& public_share() const {
        return this->public_share_;
    }

    /// @brief Ingest the peer's public share and derive the confirmation MAC key.
    /// @return false if the peer share is the wrong size or encodes a low-order point
    bool derive(const uint8_t* peer_share, size_t peer_share_len);

    /// @brief Compute this side's confirmation tag (Ta for A, Tb for B).
    /// Returns an empty optional if derive() has not been called successfully.
    [[nodiscard]] std::optional<std::array<uint8_t, CPACE_TAG_SIZE>> tag() const;

    /// @brief Return whether peer_tag matches the peer's expected confirmation tag.
    /// Constant-time comparison.  Returns false if derive() has not been called.
    [[nodiscard]] bool verify(const uint8_t* peer_tag, size_t peer_tag_len) const;

private:
    CPaceRole role_{CPaceRole::RESPONDER};
    std::array<uint8_t, CPACE_FIELD_BYTES> scalar_{};
    std::vector<uint8_t> sid_{};
    std::vector<uint8_t> ad_{};
    std::vector<uint8_t> peer_ad_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> public_share_{};
    bool started_{false};

    // Set by derive()
    std::array<uint8_t, CPACE_TAG_SIZE> mac_key_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> initiator_share_{};
    std::vector<uint8_t> initiator_ad_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> responder_share_{};
    std::vector<uint8_t> responder_ad_{};
    bool derived_{false};

    /// @brief Compute an LV-encoded (variable-length-prefix) HMAC-SHA-512 tag
    /// over (share, ad) with mac_key_.  If own is true, uses our share/ad;
    /// otherwise uses the peer's.
    std::array<uint8_t, CPACE_TAG_SIZE> compute_mac(bool own) const;
};

// -----------------------------------------------------------------------------
// Low-level CPace building blocks (exposed for testing)
// -----------------------------------------------------------------------------

/// @brief Encode a length in CPace's variable-length prefix format.
/// Mirrors cpace.py _prepend_len.
std::vector<uint8_t> cpace_prepend_len(const uint8_t* data, size_t len);

/// @brief Concatenate LV-encoded parts.  Mirrors cpace.py _lv_cat(*parts).
/// Each element of parts is (data_ptr, data_len).
std::vector<uint8_t> cpace_lv_cat(std::initializer_list<std::pair<const uint8_t*, size_t>> parts);

/// @brief Compute the CPace generator string.  Mirrors cpace.py _generator_string.
std::vector<uint8_t> cpace_generator_string(const uint8_t* prs, size_t prs_len, const uint8_t* ci,
                                            size_t ci_len, const uint8_t* sid, size_t sid_len);

/// @brief Elligator2 map: r -> x-coordinate on Curve25519.  Mirrors cpace.py _elligator2.
/// Input r is an integer value (already reduced mod p).  Returns 32 bytes (little-endian).
std::array<uint8_t, 32> cpace_elligator2(const std::array<uint8_t, 32>& r_le);

/// @brief Decode a 32-byte little-endian value, clearing the top bit.  Mirrors _decode_u.
std::array<uint8_t, 32> cpace_decode_u(const uint8_t* value, size_t len);

/// @brief Compute the CPace generator point.  Mirrors cpace.py _calculate_generator.
std::array<uint8_t, 32> cpace_calculate_generator(const uint8_t* prs, size_t prs_len,
                                                  const uint8_t* ci, size_t ci_len,
                                                  const uint8_t* sid, size_t sid_len);

/// @brief X25519 scalar multiplication (RFC 7748, with clamping).
/// Mirrors cpace.py _scalar_mult.
/// Returns false (all-zero output) if the dhstate allocation fails.
bool x25519_scalar_mult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

}  // namespace sendspin
