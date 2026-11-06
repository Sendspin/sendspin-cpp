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

#include "cpace.h"

#include "field25519.h"
#include "platform/crypto.h"

#include <algorithm>
#include <cassert>
#include <cstring>

// noise-c headers for X25519 dhstate
extern "C" {
#include <noise/protocol/dhstate.h>
}

namespace sendspin {

// secure_zero() lives in platform/crypto.h so the other holders of key material (Identity,
// psk_wrap) can share one implementation.

// ============================================================================
// LV encoding: draft-irtf-cfrg-cpace-21 prepend_len
// ============================================================================

/// @brief The seven value bits each byte of the base-128 length prefix carries.
static constexpr size_t LENGTH_PREFIX_DIGIT_MASK = 0x7F;

size_t cpace_length_prefix(size_t len, std::array<uint8_t, CPACE_MAX_LENGTH_PREFIX>& out) {
    // Variable-length little-endian base-128 length prefix.
    size_t count = 0;
    size_t length = len;
    do {
        if (length < 128) {
            out[count++] = static_cast<uint8_t>(length);
        } else {
            out[count++] = static_cast<uint8_t>((length & LENGTH_PREFIX_DIGIT_MASK) | 0x80);
        }
        length >>= 7;
    } while (length > 0);
    return count;
}

// ============================================================================
// Generator string: draft-irtf-cfrg-cpace-21 generator_string
// ============================================================================

size_t cpace_generator_zero_pad(size_t prs_len) {
    std::array<uint8_t, CPACE_MAX_LENGTH_PREFIX> prefix{};
    const size_t lv_dsi = cpace_length_prefix(CPACE_DSI.size(), prefix) + CPACE_DSI.size();
    const size_t lv_prs = cpace_length_prefix(prs_len, prefix) + prs_len;

    // len_zpad = max(0, BLOCK - 1 - len(lv_prs) - len(lv_dsi))
    const size_t used = lv_dsi + lv_prs + 1;  // +1 for the zero pad's one-byte length prefix
    return CPACE_SHA512_BLOCK > used ? CPACE_SHA512_BLOCK - used : 0;
}

// ============================================================================
// decode_u: clear the top bit per RFC 7748
// ============================================================================

/// @brief Masks the unused top bit out of the most significant byte of a field element.
static constexpr uint8_t FIELD_TOP_BYTE_MASK = 0x7F;

std::array<uint8_t, CPACE_FIELD_BYTES> cpace_decode_u(const uint8_t* value, size_t len) {
    assert(len == CPACE_FIELD_BYTES);  // caller must pass a 32-byte little-endian value
    (void)len;
    std::array<uint8_t, CPACE_FIELD_BYTES> u{};
    std::memcpy(u.data(), value, CPACE_FIELD_BYTES);
    u[CPACE_FIELD_BYTES - 1] &= FIELD_TOP_BYTE_MASK;  // clear unused top bit (RFC 7748 encoding)
    return u;
}

// ============================================================================
// Elligator2 map (draft-irtf-cfrg-cpace-21)
//
// Given r (mod p), computes the Curve25519 x-coordinate:
//   v = -A * (1 + Z*r^2)^(-1) mod p       (A=486662, Z=2)
//   eps = (v^3 + A*v^2 + v)^((p-1)/2)     (Legendre symbol; B=1 so just (v^3+Av^2+v))
//   x = eps*v - (1 - eps)*A/2 mod p
//
// Returns the 32-byte little-endian encoding.
// ============================================================================

std::array<uint8_t, CPACE_FIELD_BYTES> cpace_elligator2(
    const std::array<uint8_t, CPACE_FIELD_BYTES>& r_le) {
    using namespace field25519;

    static constexpr uint64_t A_CONST = 486662;
    static constexpr uint64_t Z_CONST = 2;

    // Decode r as a field element, reducing mod p.
    Fp r = fp_from_le(r_le.data());
    // Reduce r mod p (top bit may be set from raw bytes, though decode_u clears it).
    r = fp_reduce_full(r);

    // r^2
    Fp r2 = fp_mul(r, r);

    // Z * r^2
    Fp zr2 = fp_scale(r2, Z_CONST);

    // 1 + Z*r^2
    Fp one = {{1, 0, 0, 0}};
    Fp denom = fp_add(one, zr2);

    // (1 + Z*r^2)^(-1)
    Fp denom_inv = fp_inv(denom);

    // v = -A * denom_inv mod p = (p - A*denom_inv) mod p
    // = p - scale(denom_inv, A) mod p
    Fp a_fp = fp_scale(denom_inv, A_CONST);
    // -a_fp mod p = p - a_fp
    Fp v = fp_sub({{0, 0, 0, 0}}, a_fp);  // 0 - a_fp = p - a_fp mod p

    // v^2, v^3
    Fp v2 = fp_mul(v, v);
    Fp v3 = fp_mul(v2, v);

    // A*v^2
    Fp a_v2 = fp_scale(v2, A_CONST);

    // v^3 + A*v^2 + v
    Fp poly = fp_add(fp_add(v3, a_v2), v);

    // eps = poly^((p-1)/2) mod p (Legendre symbol)
    Fp eps = fp_legendre_pow(poly);

    // eps is 0, 1, or p-1.
    // Python: x = (eps * v - (1 - eps) * A * INV2) % Q, i.e. x = eps*v - (1-eps)*A_half
    // where A_half = A * INV2 = A/2 mod p.

    // A * INV2 (= A/2 mod p)
    static constexpr Fp A_HALF = {{
        // A is even, so A/2 = 243331 exactly (no modular inverse needed).
        243331ULL,
        0,
        0,
        0,
    }};

    // eps * v
    Fp eps_v = fp_mul(eps, v);

    // (1 - eps): eps is 0, 1, or p-1.
    // If eps == 1: 1 - eps = 0
    // If eps == 0: 1 - eps = 1
    // If eps == p-1: 1 - eps = 2 (since p-1 = -1, 1 - (-1) = 2)
    Fp one_minus_eps = fp_sub(one, eps);

    // (1 - eps) * A * INV2
    Fp correction = fp_mul(one_minus_eps, A_HALF);

    // x = eps*v - (1-eps)*A*INV2
    Fp x = fp_sub(eps_v, correction);

    return fp_to_le(x);
}

// ============================================================================
// calculate_generator: draft-irtf-cfrg-cpace-21
// ============================================================================

std::array<uint8_t, CPACE_FIELD_BYTES> cpace_calculate_generator(const uint8_t* prs, size_t prs_len,
                                                                 const uint8_t* ci, size_t ci_len,
                                                                 const uint8_t* sid,
                                                                 size_t sid_len) {
    Sha512 gen_str_hash;
    cpace_generator_string(gen_str_hash, prs, prs_len, ci, ci_len, sid, sid_len);
    auto hash = gen_str_hash.finalize();
    // Take first 32 bytes as the Elligator2 input.
    auto u = cpace_decode_u(hash.data(), CPACE_FIELD_BYTES);
    return cpace_elligator2(u);
}

// ============================================================================
// x25519_scalar_mult: RFC 7748 X25519
//
// Uses noise-c's dhstate to perform RFC 7748 X25519 WITH scalar clamping.
// The clamping is done by the underlying x25519() call in dh-curve25519.c.
// ============================================================================

bool x25519_scalar_mult(const uint8_t scalar[X25519_KEY_SIZE], const uint8_t point[X25519_KEY_SIZE],
                        uint8_t out[X25519_KEY_SIZE]) {
    DhState dh_priv;
    if (!dh_priv.valid()) {
        return false;
    }
    DhState dh_pub;
    if (!dh_pub.valid()) {
        return false;
    }

    // Set private scalar (noise-c stores it as-is; clamping happens in calculate()).
    int err = noise_dhstate_set_keypair_private(dh_priv.get(), scalar, X25519_KEY_SIZE);
    if (err != NOISE_ERROR_NONE) {
        return false;
    }

    err = noise_dhstate_set_public_key(dh_pub.get(), point, X25519_KEY_SIZE);
    if (err != NOISE_ERROR_NONE) {
        return false;
    }

    err = noise_dhstate_calculate(dh_priv.get(), dh_pub.get(), out, X25519_KEY_SIZE);

    return err == NOISE_ERROR_NONE;
}

// ============================================================================
// CPace::start
// ============================================================================

bool CPace::start(CPaceRole role, std::span<const uint8_t> prs, std::span<const uint8_t> sid,
                  std::span<const uint8_t> ci, std::span<const uint8_t> ad,
                  std::span<const uint8_t> peer_ad) {
    this->started_ = false;
    this->derived_ = false;
    if (sid.size() > this->sid_.size() || ad.size() > this->ad_.size() ||
        peer_ad.size() > this->peer_ad_.size()) {
        return false;
    }
    this->role_ = role;
    std::copy(sid.begin(), sid.end(), this->sid_.begin());
    this->sid_size_ = static_cast<uint8_t>(sid.size());
    std::copy(ad.begin(), ad.end(), this->ad_.begin());
    this->ad_size_ = static_cast<uint8_t>(ad.size());
    std::copy(peer_ad.begin(), peer_ad.end(), this->peer_ad_.begin());
    this->peer_ad_size_ = static_cast<uint8_t>(peer_ad.size());

    // Sample a fresh 32-byte scalar.
    platform_random_bytes(this->scalar_.data(), this->scalar_.size());

    // generator = _calculate_generator(prs, ci, sid)
    auto gen = cpace_calculate_generator(prs.data(), prs.size(), ci.data(), ci.size(), sid.data(),
                                         sid.size());

    // public_share = _scalar_mult(scalar, generator)
    if (!x25519_scalar_mult(this->scalar_.data(), gen.data(), this->public_share_.data())) {
        return false;
    }

    this->started_ = true;
    return true;
}

std::span<const uint8_t> CPace::role_ad(CPaceRole role) const {
    if (role == this->role_) {
        return {this->ad_.data(), this->ad_size_};
    }
    return {this->peer_ad_.data(), this->peer_ad_size_};
}

// ============================================================================
// CPace::derive
// ============================================================================

bool CPace::derive(const uint8_t* peer_share, size_t peer_share_len) {
    if (!this->started_) {
        return false;
    }
    if (this->derived_) {
        // derive() must be called exactly once; a second call would silently re-key.
        return false;
    }
    if (peer_share_len != CPACE_SHARE_SIZE) {
        return false;
    }

    // shared = _scalar_mult_vfy(scalar, peer_share)
    std::array<uint8_t, CPACE_SHARE_SIZE> shared{};
    if (!x25519_scalar_mult(this->scalar_.data(), peer_share, shared.data())) {
        return false;
    }

    // Reject all-zero result (low-order point check).
    bool all_zero = true;
    for (uint8_t b : shared) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        return false;
    }

    // Assign initiator/responder shares based on role.
    if (this->role_ == CPaceRole::INITIATOR) {
        this->initiator_share_ = this->public_share_;
        std::memcpy(this->responder_share_.data(), peer_share, CPACE_SHARE_SIZE);
    } else {
        std::memcpy(this->initiator_share_.data(), peer_share, CPACE_SHARE_SIZE);
        this->responder_share_ = this->public_share_;
    }
    const std::span<const uint8_t> initiator_ad = this->role_ad(CPaceRole::INITIATOR);
    const std::span<const uint8_t> responder_ad = this->role_ad(CPaceRole::RESPONDER);

    // ISK = SHA512(lv_cat(DSI_ISK, sid, shared) || transcript), where
    // transcript = lv_cat(init_share, init_ad) || lv_cat(resp_share, resp_ad). Each LV piece is
    // hashed as it is encoded.
    Sha512 h_isk;
    cpace_prepend_len(h_isk, reinterpret_cast<const uint8_t*>(CPACE_DSI_ISK.data()),
                      CPACE_DSI_ISK.size());
    cpace_prepend_len(h_isk, this->sid_.data(), this->sid_size_);
    cpace_prepend_len(h_isk, shared.data(), shared.size());
    cpace_prepend_len(h_isk, this->initiator_share_.data(), CPACE_SHARE_SIZE);
    cpace_prepend_len(h_isk, initiator_ad.data(), initiator_ad.size());
    cpace_prepend_len(h_isk, this->responder_share_.data(), CPACE_SHARE_SIZE);
    cpace_prepend_len(h_isk, responder_ad.data(), responder_ad.size());
    // ISK is retained (not wiped) on this->isk_: PSK Wrapping derives K_wrap from it
    // after key confirmation succeeds. Zeroized in the destructor along with mac_key_.
    this->isk_ = h_isk.finalize();

    // mac_key = SHA512(MAC_LABEL + sid + ISK)
    const auto* mac_label = reinterpret_cast<const uint8_t*>(CPACE_MAC_LABEL.data());
    size_t mac_label_len = CPACE_MAC_LABEL.size();

    Sha512 h_mac;
    h_mac.update(mac_label, mac_label_len);
    h_mac.update(this->sid_.data(), this->sid_size_);
    h_mac.update(this->isk_.data(), this->isk_.size());
    this->mac_key_ = h_mac.finalize();

    // Wipe the DH shared secret from the stack; mac_key_ and isk_ are retained on the object.
    secure_zero(shared.data(), shared.size());

    this->derived_ = true;
    return true;
}

// ============================================================================
// CPace::compute_mac
// ============================================================================

std::array<uint8_t, CPACE_TAG_SIZE> CPace::compute_mac(bool own) const {
    // own == true  -> authenticates our own (share, ad)
    // own == false -> authenticates peer's (share, ad)
    //
    // Ta authenticates (Ya, ADa); Tb authenticates (Yb, ADb).
    bool use_initiator = (own == (this->role_ == CPaceRole::INITIATOR));
    const uint8_t* share =
        use_initiator ? this->initiator_share_.data() : this->responder_share_.data();
    const std::span<const uint8_t> ad =
        this->role_ad(use_initiator ? CPaceRole::INITIATOR : CPaceRole::RESPONDER);

    // The message is lv_cat(share, ad), each LV piece fed to the inner hash as it is encoded.
    return hmac_sha512_streamed(this->mac_key_.data(), this->mac_key_.size(),
                                [share, ad](Sha512& inner) {
                                    cpace_prepend_len(inner, share, CPACE_SHARE_SIZE);
                                    cpace_prepend_len(inner, ad.data(), ad.size());
                                });
}

CPace::~CPace() {
    secure_zero(this->scalar_.data(), this->scalar_.size());
    secure_zero(this->mac_key_.data(), this->mac_key_.size());
    secure_zero(this->isk_.data(), this->isk_.size());
}

// ============================================================================
// CPace::tag
// ============================================================================

std::optional<std::array<uint8_t, CPACE_TAG_SIZE>> CPace::tag() const {
    if (!this->derived_) {
        return std::nullopt;
    }
    return this->compute_mac(true);
}

// ============================================================================
// CPace::verify
// ============================================================================

bool CPace::verify(const uint8_t* peer_tag, size_t peer_tag_len) const {
    if (!this->derived_) {
        return false;
    }
    if (peer_tag_len != CPACE_TAG_SIZE) {
        return false;
    }
    auto expected = this->compute_mac(false);
    return constant_time_equal(expected.data(), peer_tag, CPACE_TAG_SIZE);
}

// ============================================================================
// CPace::isk
// ============================================================================

std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> CPace::isk() const {
    if (!this->derived_) {
        return std::nullopt;
    }
    return this->isk_;
}

}  // namespace sendspin
