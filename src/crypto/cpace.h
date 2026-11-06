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
/// Implements pairing.md "PAKE" (draft-irtf-cfrg-cpace-21).  The Sendspin server is
/// role A (INITIATOR); the client is role B (RESPONDER).  Both roles are
/// implemented so the primitive is fully testable and round-trip tests can
/// play either side.
///
/// Errors are reported via bool return values; the caller should treat a
/// false return from derive() or verify() as a fatal pairing failure.

#pragma once

#include "keys.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace sendspin {

// ============================================================================
// Constants (draft-irtf-cfrg-cpace-21)
// ============================================================================

/// @brief DSI string for generator derivation.
static constexpr std::string_view CPACE_DSI{"CPace255"};

/// @brief DSI string for ISK derivation.
static constexpr std::string_view CPACE_DSI_ISK{"CPace255_ISK"};

/// @brief Label for MAC key derivation.
static constexpr std::string_view CPACE_MAC_LABEL{"CPaceMac"};

/// @brief SHA-512 block size in bytes.
static constexpr size_t CPACE_SHA512_BLOCK = 128;

/// @brief Curve25519 field size (and share size) in bytes.
static constexpr size_t CPACE_FIELD_BYTES = 32;

/// @brief Size of a CPace public share in bytes.
static constexpr size_t CPACE_SHARE_SIZE = 32;

/// @brief Size of a CPace confirmation tag (HMAC-SHA-512 output) in bytes.
static constexpr size_t CPACE_TAG_SIZE = 64;

/// @brief Size of the CPace intermediate session key (ISK, raw SHA-512 output) in bytes.
/// See pairing.md "Wrapping": ISK feeds K_wrap = SHA-256(label || sid || ISK), with a distinct
/// label per wrapped field.
static constexpr size_t CPACE_ISK_SIZE = 64;

/// @brief Longest sid CPace::start() takes, in bytes. Sendspin's is 61 (pairing.md "PAKE": a
/// 21-byte label, the 32-byte handshake hash and two 4-byte counters), and the draft's test vectors
/// use 16.
static constexpr size_t CPACE_MAX_SID_SIZE = 64;

/// @brief Longest associated data CPace::start() takes for either side, in bytes. Sendspin's ADa
/// and ADb are 6 (pairing.md "PAKE"), and the draft's test vectors use 3.
static constexpr size_t CPACE_MAX_AD_SIZE = 16;
static_assert(CPACE_MAX_SID_SIZE <= UINT8_MAX && CPACE_MAX_AD_SIZE <= UINT8_MAX,
              "CPace holds the sid's and each AD's size in a uint8_t");

/// @brief Most bytes the draft-irtf-cfrg-cpace-21 `prepend_len` prefix of a size_t length takes:
/// seven bits per byte.
static constexpr size_t CPACE_MAX_LENGTH_PREFIX = (sizeof(size_t) * 8 + 6) / 7;

// ============================================================================
// CPaceRole
// ============================================================================

/// @brief CPace protocol role.  The Sendspin server is A (INITIATOR).
enum class CPaceRole : uint8_t {
    INITIATOR = 0,  ///< Role A: sends the first share
    RESPONDER = 1,  ///< Role B: sends the second share
};

// ============================================================================
// CPace
// ============================================================================

/// @brief One side of a CPace-X25519-SHA512 exchange with mutual confirmation.
///
/// Driven in three steps: start() samples the scalar and yields public_share(), derive() takes
/// the peer's share and computes the MAC key, then tag() and verify() exchange confirmation.
class CPace {
public:
    CPace() = default;

    /// @brief Zeroizes the scalar, MAC key and ISK on destruction.
    ~CPace();

    /// @brief Begin a CPace run, sampling a scalar and computing the public share.
    ///
    /// @param role     INITIATOR (A) or RESPONDER (B)
    /// @param prs      Password-related string (the pairing code's bytes for Sendspin)
    /// @param sid      Session identifier, at most CPACE_MAX_SID_SIZE bytes
    /// @param ci       Channel identifier (empty for Sendspin)
    /// @param ad       This side's associated data (ADb = "client" for the Sendspin client), at
    ///                 most CPACE_MAX_AD_SIZE bytes
    /// @param peer_ad  Peer's associated data (ADa = "server" for the Sendspin client), at most
    ///                 CPACE_MAX_AD_SIZE bytes
    /// @return false if sid or either AD is too long, or the random scalar or generator
    ///         computation fails
    bool start(CPaceRole role, std::span<const uint8_t> prs, std::span<const uint8_t> sid,
               std::span<const uint8_t> ci, std::span<const uint8_t> ad,
               std::span<const uint8_t> peer_ad);

    /// @brief Return this side's public share (Ya for A, Yb for B).
    /// Valid only after a successful start().
    [[nodiscard]] const std::array<uint8_t, CPACE_SHARE_SIZE>& public_share() const {
        return this->public_share_;
    }

    /// @brief Ingest the peer's public share and derive the confirmation MAC key.
    /// @return false if start() has not succeeded, if derive() has already run (it is
    ///         once-only), or if the peer share is the wrong size or encodes a low-order point
    bool derive(const uint8_t* peer_share, size_t peer_share_len);

    /// @brief Compute this side's confirmation tag (Ta for A, Tb for B).
    /// Returns an empty optional if derive() has not been called successfully.
    [[nodiscard]] std::optional<std::array<uint8_t, CPACE_TAG_SIZE>> tag() const;

    /// @brief Return whether peer_tag matches the peer's expected confirmation tag.
    /// Constant-time comparison.  Returns false if derive() has not been called.
    [[nodiscard]] bool verify(const uint8_t* peer_tag, size_t peer_tag_len) const;

    /// @brief Return the 64-byte CPace intermediate session key (ISK) computed by derive().
    /// Feeds pairing.md "Wrapping": K_wrap = SHA-256(label || sid || ISK).
    /// Returns an empty optional if derive() has not been called successfully.
    [[nodiscard]] std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> isk() const;

    /// @brief Return this side's session id (sid), as passed to start(). Needed alongside isk()
    /// to derive K_wrap (pairing.md "Wrapping").
    [[nodiscard]] std::span<const uint8_t> sid() const {
        return {this->sid_.data(), this->sid_size_};
    }

private:
    // Struct fields
    std::array<uint8_t, CPACE_MAX_AD_SIZE> ad_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> initiator_share_{};  // Set by derive()
    std::array<uint8_t, CPACE_ISK_SIZE> isk_{};                // Set by derive()
    std::array<uint8_t, CPACE_TAG_SIZE> mac_key_{};            // Set by derive()
    std::array<uint8_t, CPACE_MAX_AD_SIZE> peer_ad_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> public_share_{};
    std::array<uint8_t, CPACE_SHARE_SIZE> responder_share_{};  // Set by derive()
    std::array<uint8_t, CPACE_FIELD_BYTES> scalar_{};
    std::array<uint8_t, CPACE_MAX_SID_SIZE> sid_{};

    // 8-bit fields
    uint8_t ad_size_{0};
    bool derived_{false};  // Set by derive()
    uint8_t peer_ad_size_{0};
    CPaceRole role_{CPaceRole::RESPONDER};
    uint8_t sid_size_{0};
    bool started_{false};

    /// @brief The associated data of the initiator (ADa) or the responder (ADb)
    std::span<const uint8_t> role_ad(CPaceRole role) const;

    /// @brief Compute an LV-encoded (variable-length-prefix) HMAC-SHA-512 tag
    /// over (share, ad) with mac_key_.  If own is true, uses our share/ad;
    /// otherwise uses the peer's.
    std::array<uint8_t, CPACE_TAG_SIZE> compute_mac(bool own) const;
};

// ============================================================================
// Low-level CPace building blocks
// ============================================================================

/// @brief Write the draft-irtf-cfrg-cpace-21 `prepend_len` prefix of a `len`-byte value: the
/// length as a little-endian base-128 varint.
/// @return The number of prefix bytes written to the front of `out`.
size_t cpace_length_prefix(size_t len, std::array<uint8_t, CPACE_MAX_LENGTH_PREFIX>& out);

/// @brief Feed `data` to `sink` LV-encoded, as draft-irtf-cfrg-cpace-21 `prepend_len` builds it:
/// its length prefix, then its bytes. Successive calls make the draft's `lv_cat`.
/// @param sink Any object with update(const uint8_t*, size_t), such as a Sha512 that hashes the
///             encoding as it is produced.
template <typename Sink>
void cpace_prepend_len(Sink& sink, const uint8_t* data, size_t len) {
    std::array<uint8_t, CPACE_MAX_LENGTH_PREFIX> prefix{};
    sink.update(prefix.data(), cpace_length_prefix(len, prefix));
    sink.update(data, len);
}

/// @brief Zero bytes draft-irtf-cfrg-cpace-21 `generator_string` pads with for a `prs_len`-byte
/// PRS: whatever fills the first SHA-512 block after the LV-encoded DSI and PRS and the pad's own
/// one-byte length, or none when they already overflow it.
size_t cpace_generator_zero_pad(size_t prs_len);

/// @brief Feed `sink` the CPace generator string. Mirrors draft-irtf-cfrg-cpace-21
/// `generator_string`: lv_cat(DSI, PRS, zero_pad, CI, sid).
template <typename Sink>
void cpace_generator_string(Sink& sink, const uint8_t* prs, size_t prs_len, const uint8_t* ci,
                            size_t ci_len, const uint8_t* sid, size_t sid_len) {
    static constexpr std::array<uint8_t, CPACE_SHA512_BLOCK> ZEROS{};
    cpace_prepend_len(sink, reinterpret_cast<const uint8_t*>(CPACE_DSI.data()), CPACE_DSI.size());
    cpace_prepend_len(sink, prs, prs_len);
    cpace_prepend_len(sink, ZEROS.data(), cpace_generator_zero_pad(prs_len));
    cpace_prepend_len(sink, ci, ci_len);
    cpace_prepend_len(sink, sid, sid_len);
}

/// @brief Elligator2 map: r -> x-coordinate on Curve25519 (draft-irtf-cfrg-cpace-21).
/// Input r is an integer value (already reduced mod p).  Returns 32 bytes (little-endian).
std::array<uint8_t, CPACE_FIELD_BYTES> cpace_elligator2(
    const std::array<uint8_t, CPACE_FIELD_BYTES>& r_le);

/// @brief Decode a 32-byte little-endian value, clearing the top bit (RFC 7748).
std::array<uint8_t, CPACE_FIELD_BYTES> cpace_decode_u(const uint8_t* value, size_t len);

/// @brief Compute the CPace generator point.  Mirrors draft-irtf-cfrg-cpace-21
/// `calculate_generator`.
std::array<uint8_t, CPACE_FIELD_BYTES> cpace_calculate_generator(const uint8_t* prs, size_t prs_len,
                                                                 const uint8_t* ci, size_t ci_len,
                                                                 const uint8_t* sid,
                                                                 size_t sid_len);

/// @brief X25519 scalar multiplication (RFC 7748, with clamping).
/// Returns false (all-zero output) if the dhstate allocation fails.
bool x25519_scalar_mult(const uint8_t scalar[X25519_KEY_SIZE], const uint8_t point[X25519_KEY_SIZE],
                        uint8_t out[X25519_KEY_SIZE]);

}  // namespace sendspin
