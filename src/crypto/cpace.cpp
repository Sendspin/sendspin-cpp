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

#include <cassert>
#include <cstring>

// noise-c headers for X25519 dhstate
extern "C" {
#include <noise/protocol/dhstate.h>
}

namespace sendspin {

namespace {

// Overwrite a buffer through a volatile pointer so the clear is not optimized away.
void secure_zero(void* p, size_t n) {
    volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) {
        vp[i] = 0;
    }
}

}  // namespace

// ============================================================================
// LV encoding -- mirrors cpace.py _prepend_len / _lv_cat
// ============================================================================

std::vector<uint8_t> cpace_prepend_len(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out;
    // Variable-length little-endian base-128 length prefix.
    size_t length = len;
    do {
        if (length < 128) {
            out.push_back(static_cast<uint8_t>(length));
        } else {
            out.push_back(static_cast<uint8_t>((length & 0x7F) | 0x80));
        }
        length >>= 7;
    } while (length > 0);
    out.insert(out.end(), data, data + len);
    return out;
}

std::vector<uint8_t> cpace_lv_cat(std::initializer_list<std::pair<const uint8_t*, size_t>> parts) {
    std::vector<uint8_t> out;
    for (auto& [data, len] : parts) {
        auto lv = cpace_prepend_len(data, len);
        out.insert(out.end(), lv.begin(), lv.end());
    }
    return out;
}

// ============================================================================
// Generator string -- mirrors cpace.py _generator_string
// ============================================================================

std::vector<uint8_t> cpace_generator_string(const uint8_t* prs, size_t prs_len, const uint8_t* ci,
                                            size_t ci_len, const uint8_t* sid, size_t sid_len) {
    const auto* dsi = reinterpret_cast<const uint8_t*>(CPACE_DSI);
    size_t dsi_len = sizeof(CPACE_DSI) - 1;  // exclude NUL

    auto lv_dsi = cpace_prepend_len(dsi, dsi_len);
    auto lv_prs = cpace_prepend_len(prs, prs_len);

    // len_zpad = max(0, BLOCK - 1 - len(lv_prs) - len(lv_dsi))
    size_t used = lv_dsi.size() + lv_prs.size() + 1;  // +1 for the leading 0x00 pad length byte
    size_t len_zpad = 0;
    if (CPACE_SHA512_BLOCK > used) {
        len_zpad = CPACE_SHA512_BLOCK - used;
    }

    // Build: lv_cat(DSI, prs, zeros, ci, sid)
    // But zeros is a single chunk of len_zpad zero bytes.
    std::vector<uint8_t> zeros(len_zpad, 0);
    return cpace_lv_cat({
        {dsi, dsi_len},
        {prs, prs_len},
        {zeros.data(), zeros.size()},
        {ci, ci_len},
        {sid, sid_len},
    });
}

// ============================================================================
// _decode_u -- mirrors cpace.py _decode_u (clear top bit per RFC 7748)
// ============================================================================

std::array<uint8_t, 32> cpace_decode_u(const uint8_t* value, size_t len) {
    assert(len == 32);  // caller must pass a 32-byte little-endian value
    (void)len;
    std::array<uint8_t, 32> u{};
    std::memcpy(u.data(), value, 32);
    u[31] &= 0x7F;  // clear unused top bit (RFC 7748 Curve25519 encoding)
    return u;
}

// ============================================================================
// Elligator2 map -- mirrors cpace.py _elligator2
//
// Given r (mod p), computes the Curve25519 x-coordinate:
//   v = -A * (1 + Z*r^2)^(-1) mod p       (A=486662, Z=2)
//   eps = (v^3 + A*v^2 + v)^((p-1)/2)     (Legendre symbol; B=1 so just (v^3+Av^2+v))
//   x = eps*v - (1 - eps)*A/2 mod p
//
// Returns the 32-byte little-endian encoding.
// ============================================================================

std::array<uint8_t, 32> cpace_elligator2(const std::array<uint8_t, 32>& r_le) {
    using namespace field25519;

    static constexpr uint64_t A_CONST = 486662;
    static constexpr uint64_t Z_CONST = 2;

    // Decode r as a field element, reducing mod p.
    Fp r = fp_from_le(r_le.data());
    // Reduce r mod p (top bit may be set from raw bytes, though decode_u clears it).
    // fp_reduce handles this if we add 0.
    r = fp_reduce(r, 0);

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
    Fp A_fp = fp_scale(denom_inv, A_CONST);
    // -A_fp mod p = p - A_fp
    Fp v = fp_sub({{0, 0, 0, 0}}, A_fp);  // 0 - A_fp = p - A_fp mod p

    // v^2, v^3
    Fp v2 = fp_mul(v, v);
    Fp v3 = fp_mul(v2, v);

    // A*v^2
    Fp Av2 = fp_scale(v2, A_CONST);

    // v^3 + A*v^2 + v
    Fp poly = fp_add(fp_add(v3, Av2), v);

    // eps = poly^((p-1)/2) mod p -- Legendre symbol
    Fp eps = fp_legendre_pow(poly);

    // eps is 0, 1, or p-1.
    // Python: x = (eps * v - (1 - eps) * A * INV2) % Q
    // = eps*v - (1-eps) * A/2
    // = eps*v - A/2 + eps*A/2
    // = eps*(v + A/2) - A/2
    // But let's compute it directly as the Python does:
    //   x = (eps * v + (eps - 1) * A * INV2) % Q
    //   ... or: x = (eps * v - (1 - eps) * A_half) where A_half = A * INV2

    // A * INV2 (= A/2 mod p)
    static constexpr Fp A_HALF = {{
        // A/2 mod p = 486662 * ((p+1)/2) mod p
        // = 486662 * 0x3FF...F7 mod p
        // Computed: 486662/2 = 243331 (A is even, so A/2 is exact over integers, no modular inverse
        // needed for integer division)
        // Actually A = 486662 is even, so A/2 = 243331 exactly.
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
// _calculate_generator -- mirrors cpace.py _calculate_generator
// ============================================================================

std::array<uint8_t, 32> cpace_calculate_generator(const uint8_t* prs, size_t prs_len,
                                                  const uint8_t* ci, size_t ci_len,
                                                  const uint8_t* sid, size_t sid_len) {
    auto gen_str = cpace_generator_string(prs, prs_len, ci, ci_len, sid, sid_len);
    auto hash = sha512_oneshot(gen_str.data(), gen_str.size());
    // Take first 32 bytes as the Elligator2 input.
    auto u = cpace_decode_u(hash.data(), 32);
    return cpace_elligator2(u);
}

// ============================================================================
// x25519_scalar_mult -- mirrors cpace.py _scalar_mult
//
// Uses noise-c's dhstate to perform RFC 7748 X25519 WITH scalar clamping.
// The clamping is done by the underlying x25519() call in dh-curve25519.c.
// ============================================================================

bool x25519_scalar_mult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]) {
    NoiseDHState* dh_priv = nullptr;
    NoiseDHState* dh_pub = nullptr;

    int err = noise_dhstate_new_by_name(&dh_priv, "25519");
    if (err != NOISE_ERROR_NONE || dh_priv == nullptr) {
        return false;
    }
    err = noise_dhstate_new_by_name(&dh_pub, "25519");
    if (err != NOISE_ERROR_NONE || dh_pub == nullptr) {
        noise_dhstate_free(dh_priv);
        return false;
    }

    // Set private scalar (noise-c stores it as-is; clamping happens in calculate()).
    err = noise_dhstate_set_keypair_private(dh_priv, scalar, 32);
    if (err != NOISE_ERROR_NONE) {
        noise_dhstate_free(dh_priv);
        noise_dhstate_free(dh_pub);
        return false;
    }

    // Set the public point.
    err = noise_dhstate_set_public_key(dh_pub, point, 32);
    if (err != NOISE_ERROR_NONE) {
        noise_dhstate_free(dh_priv);
        noise_dhstate_free(dh_pub);
        return false;
    }

    // Perform the multiplication; result goes into out.
    err = noise_dhstate_calculate(dh_priv, dh_pub, out, 32);

    noise_dhstate_free(dh_priv);
    noise_dhstate_free(dh_pub);

    return err == NOISE_ERROR_NONE;
}

// ============================================================================
// Helper: build lv_cat over two (share, ad) pairs -- used in derive() and tags
// ============================================================================

static std::vector<uint8_t> lv_pair(const uint8_t* share, const std::vector<uint8_t>& ad) {
    return cpace_lv_cat({
        {share, CPACE_SHARE_SIZE},
        {ad.data(), ad.size()},
    });
}

// ============================================================================
// CPace::start
// ============================================================================

bool CPace::start(CPaceRole role, const std::vector<uint8_t>& prs, const std::vector<uint8_t>& sid,
                  const std::vector<uint8_t>& ci, const std::vector<uint8_t>& ad,
                  const std::vector<uint8_t>& peer_ad) {
    this->role_ = role;
    this->sid_ = sid;
    this->ad_ = ad;
    this->peer_ad_ = peer_ad;
    this->started_ = false;
    this->derived_ = false;

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
        this->initiator_ad_ = this->ad_;
        std::memcpy(this->responder_share_.data(), peer_share, CPACE_SHARE_SIZE);
        this->responder_ad_ = this->peer_ad_;
    } else {
        std::memcpy(this->initiator_share_.data(), peer_share, CPACE_SHARE_SIZE);
        this->initiator_ad_ = this->peer_ad_;
        this->responder_share_ = this->public_share_;
        this->responder_ad_ = this->ad_;
    }

    // transcript = lv_cat(init_share, init_ad) + lv_cat(resp_share, resp_ad)
    auto t_init = lv_pair(this->initiator_share_.data(), this->initiator_ad_);
    auto t_resp = lv_pair(this->responder_share_.data(), this->responder_ad_);

    // ISK input: lv_cat(DSI_ISK, sid, shared) + transcript
    const auto* dsi_isk = reinterpret_cast<const uint8_t*>(CPACE_DSI_ISK);
    size_t dsi_isk_len = sizeof(CPACE_DSI_ISK) - 1;

    auto lv_prefix = cpace_lv_cat({
        {dsi_isk, dsi_isk_len},
        {this->sid_.data(), this->sid_.size()},
        {shared.data(), shared.size()},
    });

    // ISK = SHA512(lv_prefix + transcript)
    Sha512 h_isk;
    h_isk.update(lv_prefix.data(), lv_prefix.size());
    h_isk.update(t_init.data(), t_init.size());
    h_isk.update(t_resp.data(), t_resp.size());
    // ISK is retained (not wiped) on this->isk_: PSK Wrapping (#117) derives K_wrap from it
    // after key confirmation succeeds. Zeroized in the destructor along with mac_key_.
    this->isk_ = h_isk.finalize();

    // mac_key = SHA512(MAC_LABEL + sid + ISK)
    const auto* mac_label = reinterpret_cast<const uint8_t*>(CPACE_MAC_LABEL);
    size_t mac_label_len = sizeof(CPACE_MAC_LABEL) - 1;

    Sha512 h_mac;
    h_mac.update(mac_label, mac_label_len);
    h_mac.update(this->sid_.data(), this->sid_.size());
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
    // If own == (role == INITIATOR): use initiator's data.
    bool use_initiator = (own == (this->role_ == CPaceRole::INITIATOR));
    const uint8_t* share =
        use_initiator ? this->initiator_share_.data() : this->responder_share_.data();
    const std::vector<uint8_t>& ad = use_initiator ? this->initiator_ad_ : this->responder_ad_;

    auto lv = lv_pair(share, ad);
    return hmac_sha512(this->mac_key_.data(), this->mac_key_.size(), lv.data(), lv.size());
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
