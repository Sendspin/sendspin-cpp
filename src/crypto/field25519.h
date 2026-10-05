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

/// @file field25519.h
/// @brief Self-contained constant-time modular arithmetic over GF(2^255-19), providing only what
/// CPace-X25519-SHA512 needs. No external dependencies; one code path on host and ESP32.
///
/// Constant time: every operand is derived from the CPace password (the generator is
/// Elligator2(SHA-512(PRS, ...))), and the password is a 6- or 8-digit pairing code. A running
/// time that depends on the operands lets an observer filter candidate codes offline (the
/// Dragonblood class of attacks on WPA3's hash-to-curve), so no branch, loop bound or memory
/// index below depends on an operand value. Two rules keep it that way on every target:
///
/// - Limbs are 32 bits and all additions are 32-bit, with carries and borrows computed by
///   bitwise formulas, never by a comparison. Xtensa (ESP32, ESP32-S2/S3) has no carry flag, and
///   GCC lowers a 64-bit add, a 64-bit subtract, and any `a < b ? 1 : 0` on 64-bit values to a
///   conditional branch there. The only 64-bit operation is the 32x32->64 product, which is the
///   MULL/MULUH pair on Xtensa.
/// - Conditional results are chosen by masked selection (ct_select()) behind a value barrier, so
///   the compiler cannot turn the selection back into a branch.
///
/// tests/ct/ct_field25519.cpp runs the Elligator2 map under valgrind with its input marked
/// secret and fails on any conditional jump that depends on it.

#pragma once

#include <array>
#include <cstdint>

namespace sendspin {
namespace field25519 {

/// @brief Number of 32-bit limbs in a field element.
static constexpr int FP_LIMBS = 8;

/// @brief A field element mod p = 2^255-19, stored as eight 32-bit limbs (little-endian).
///
/// Every operation returns a canonical element (in [0, p)) and expects canonical inputs, except
/// fp_reduce_full(), which accepts any 256-bit value, and fp_mul(), which accepts any two
/// 256-bit values.
struct Fp {
    uint32_t limbs[FP_LIMBS]{};  // limbs[0] = least significant 32 bits
};

// ============================================================================
// Constants
// ============================================================================

/// p = 2^255 - 19
static constexpr Fp FP_P = {{
    0xFFFFFFEDU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0x7FFFFFFFU,
}};

/// 2^256 mod p = 38 (because 2^255 = p + 19): the multiplier that folds bits past 2^256 back in.
static constexpr uint32_t FP_2_256_MOD_P = 38;

/// p - 2 (for the Fermat inverse a^(p-2) mod p)
static constexpr Fp FP_P_MINUS_2 = {{
    0xFFFFFFEBU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0x7FFFFFFFU,
}};

/// (p - 1) / 2 = 2^254 - 10 (for the Legendre symbol a^((p-1)/2) mod p)
static constexpr Fp FP_LEGENDRE = {{
    0xFFFFFFF6U,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0xFFFFFFFFU,
    0x3FFFFFFFU,
}};

// ============================================================================
// Constant-time word helpers
// ============================================================================

/// @brief Returns `x` through an empty asm statement the optimizer must treat as opaque, so a
/// mask derived from a secret bit cannot be traced back to that bit and turned into a branch.
inline uint32_t ct_value_barrier(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(x));
#endif
    return x;
}

/// @brief a + b + carry_in (carry_in 0 or 1). Returns the low 32 bits; sets carry_out to 0/1.
/// The carry is the top bit of the majority of a, b and ~sum (Hacker's Delight 2-13), so no
/// comparison is involved.
inline uint32_t ct_adc32(uint32_t a, uint32_t b, uint32_t carry_in, uint32_t& carry_out) {
    const uint32_t s1 = a + b;
    const uint32_t c1 = ((a & b) | ((a | b) & ~s1)) >> 31;
    const uint32_t s2 = s1 + carry_in;
    const uint32_t c2 = ((s1 & carry_in) | ((s1 | carry_in) & ~s2)) >> 31;
    carry_out = c1 | c2;  // a+b and +carry_in cannot both overflow.
    return s2;
}

/// @brief a - b - borrow_in (borrow_in 0 or 1). Returns the low 32 bits; sets borrow_out to 0/1.
/// Same bitwise derivation as ct_adc32(), for subtraction.
inline uint32_t ct_sbb32(uint32_t a, uint32_t b, uint32_t borrow_in, uint32_t& borrow_out) {
    const uint32_t d1 = a - b;
    const uint32_t b1 = ((~a & b) | (~(a ^ b) & d1)) >> 31;
    const uint32_t d2 = d1 - borrow_in;
    const uint32_t b2 = ((~d1 & borrow_in) | (~(d1 ^ borrow_in) & d2)) >> 31;
    borrow_out = b1 | b2;  // a-b and -borrow_in cannot both underflow.
    return d2;
}

/// @brief 32x32 -> 64 bit unsigned multiply, split into hi:lo. Lowers to MULL/MULUH on Xtensa.
inline void ct_mul32_wide(uint32_t a, uint32_t b, uint32_t& hi, uint32_t& lo) {
    const uint64_t p = static_cast<uint64_t>(a) * b;
    lo = static_cast<uint32_t>(p);
    hi = static_cast<uint32_t>(p >> 32);
}

/// @brief Returns `if_one` when bit is 1 and `if_zero` when bit is 0, reading both.
inline Fp ct_select(uint32_t bit, const Fp& if_one, const Fp& if_zero) {
    const uint32_t mask = ct_value_barrier(0U - bit);
    Fp r;
    for (int i = 0; i < FP_LIMBS; ++i) {
        r.limbs[i] = if_zero.limbs[i] ^ (mask & (if_one.limbs[i] ^ if_zero.limbs[i]));
    }
    return r;
}

// ============================================================================
// Encoding
// ============================================================================

/// @brief Decode 32 little-endian bytes into a Fp.
/// Neither the top bit nor values >= p are handled here; callers reduce with fp_reduce_full().
inline Fp fp_from_le(const uint8_t* b) {
    Fp r;
    for (uint32_t& limb : r.limbs) {
        limb = 0;
        for (int j = 0; j < 4; ++j) {
            limb |= static_cast<uint32_t>(*b++) << (j * 8);
        }
    }
    return r;
}

/// @brief Encode a Fp into 32 little-endian bytes. Does not reduce.
inline std::array<uint8_t, 32> fp_to_le(const Fp& a) {
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < FP_LIMBS; ++i) {
        for (int j = 0; j < 4; ++j) {
            out[i * 4 + j] = static_cast<uint8_t>(a.limbs[i] >> (j * 8));
        }
    }
    return out;
}

// ============================================================================
// Reduction
// ============================================================================

/// @brief One conditional subtraction of p: maps [0, 2p) to [0, p).
///
/// The subtraction is always computed; its final borrow (1 when a < p) selects the original.
inline Fp fp_reduce(const Fp& a) {
    Fp diff;
    uint32_t borrow = 0;
    for (int i = 0; i < FP_LIMBS; ++i) {
        diff.limbs[i] = ct_sbb32(a.limbs[i], FP_P.limbs[i], borrow, borrow);
    }
    return ct_select(borrow, a, diff);
}

/// @brief Fully reduce any 256-bit value to [0, p).
///
/// One subtraction is not enough: the 38-fold in fp_mul() leaves a value merely below 2^256,
/// and 2^256 = 2p + 38, so an input in [2p, 2^256) would land in [p, p+38), still
/// non-canonical. That band is reached whenever the true result is congruent to a value below
/// 38, which is exactly what an inverse or a Legendre exponentiation produces. Two passes always
/// suffice because 2^256 < 3p.
inline Fp fp_reduce_full(const Fp& a) {
    return fp_reduce(fp_reduce(a));
}

// ============================================================================
// Arithmetic
// ============================================================================

/// @brief Modular multiplication (a * b) mod p for any two 256-bit inputs.
///
/// Schoolbook 8x8-limb product into 512 bits, then n mod p = n_lo + n_hi * 38 (2^256 mod p = 38).
inline Fp fp_mul(const Fp& a, const Fp& b) {
    uint32_t t[2 * FP_LIMBS]{};

    for (int i = 0; i < FP_LIMBS; ++i) {
        uint32_t carry = 0;
        for (int j = 0; j < FP_LIMBS; ++j) {
            // a[i]*b[j] + t[i+j] + carry <= (2^32-1)^2 + 2(2^32-1) = 2^64-1, so the high word,
            // hi + c1 + c2, cannot overflow.
            uint32_t hi = 0, lo = 0;
            ct_mul32_wide(a.limbs[i], b.limbs[j], hi, lo);
            uint32_t c1 = 0, c2 = 0;
            uint32_t s = ct_adc32(lo, t[i + j], 0, c1);
            s = ct_adc32(s, carry, 0, c2);
            t[i + j] = s;
            carry = hi + c1 + c2;
        }
        t[i + FP_LIMBS] = carry;  // Not yet written by any earlier row.
    }

    // Fold the upper 256 bits: r = t_lo + t_hi * 38.
    Fp r;
    uint32_t carry = 0;
    for (int i = 0; i < FP_LIMBS; ++i) {
        uint32_t hi = 0, lo = 0;
        ct_mul32_wide(t[i + FP_LIMBS], FP_2_256_MOD_P, hi, lo);  // hi <= 37
        uint32_t c1 = 0, c2 = 0;
        uint32_t s = ct_adc32(t[i], lo, 0, c1);
        s = ct_adc32(s, carry, 0, c2);
        r.limbs[i] = s;
        carry = hi + c1 + c2;  // <= 39
    }

    // The carry out of the top limb has positional value 2^256, so it folds back in as
    // carry * 38. That addition can carry out of limb 0 (positional value 2^32), which ripples
    // through every limb, unconditionally. Only a carry out of the top limb a second time is
    // worth 2^256 again; when it happens, limbs 1..7 have wrapped to zero and limb 0 holds less
    // than carry * 38 (< 1,500), so adding prop * 38 cannot overflow.
    uint32_t prop = 0;
    r.limbs[0] = ct_adc32(r.limbs[0], carry * FP_2_256_MOD_P, 0, prop);
    for (int i = 1; i < FP_LIMBS; ++i) {
        r.limbs[i] = ct_adc32(r.limbs[i], 0, prop, prop);
    }
    r.limbs[0] += prop * FP_2_256_MOD_P;

    return fp_reduce_full(r);
}

/// @brief Modular addition (a + b) mod p for canonical a, b.
inline Fp fp_add(const Fp& a, const Fp& b) {
    // a, b < p < 2^255, so the sum is below 2p and cannot carry out of the top limb.
    Fp r;
    uint32_t carry = 0;
    for (int i = 0; i < FP_LIMBS; ++i) {
        r.limbs[i] = ct_adc32(a.limbs[i], b.limbs[i], carry, carry);
    }
    return fp_reduce(r);
}

/// @brief Modular subtraction (a - b) mod p for canonical a, b, computed as a + (p - b).
inline Fp fp_sub(const Fp& a, const Fp& b) {
    Fp p_minus_b;
    uint32_t borrow = 0;
    for (int i = 0; i < FP_LIMBS; ++i) {
        p_minus_b.limbs[i] = ct_sbb32(FP_P.limbs[i], b.limbs[i], borrow, borrow);
    }
    // p - 0 = p is the one non-canonical value here; a + p < 2p, which fp_add() reduces to a.
    return fp_add(a, p_minus_b);
}

/// @brief Modular exponentiation base^exp mod p by square-and-multiply.
///
/// Every bit computes the multiply and selects it, so the running time does not depend on the
/// exponent either (every caller passes a public constant today, but nothing enforces that).
inline Fp fp_pow(const Fp& base, const Fp& exp) {
    Fp result = {{1}};
    Fp cur = base;
    for (uint32_t e : exp.limbs) {
        for (int bit = 0; bit < 32; ++bit) {
            const Fp product = fp_mul(result, cur);
            result = ct_select((e >> bit) & 1U, product, result);
            cur = fp_mul(cur, cur);
        }
    }
    return result;
}

/// @brief Modular inverse a^(p-2) mod p (Fermat's little theorem). Maps 0 to 0.
inline Fp fp_inv(const Fp& a) {
    return fp_pow(a, FP_P_MINUS_2);
}

/// @brief Legendre symbol exponentiation a^((p-1)/2) mod p. Returns 0, 1, or p-1.
inline Fp fp_legendre_pow(const Fp& a) {
    return fp_pow(a, FP_LEGENDRE);
}

/// @brief Modular multiplication of a canonical a by a small public constant, (a * s) mod p.
inline Fp fp_scale(const Fp& a, uint32_t s) {
    return fp_mul(a, Fp{{s}});
}

}  // namespace field25519
}  // namespace sendspin
