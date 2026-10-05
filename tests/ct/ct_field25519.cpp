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

// Constant-time check for the CPace generator (ctgrind technique).
//
// The pairing code is low-entropy, so the generator computation must not branch on anything
// derived from it (see field25519.h). Run under valgrind memcheck: the password bytes are marked
// undefined, so memcheck reports every conditional jump, conditional move it cannot prove safe,
// and memory index that depends on them. Run with --error-exitcode so any such report fails:
//
//   valgrind --error-exitcode=1 ./ct_field25519
//
// Run outside valgrind, the client requests are no-ops and it only exercises the code.
//
// The check runs on the host compiler's output, not the ESP32's. field25519.h is written so the
// two agree (32-bit additions only, no comparisons), which the ESP-IDF build cannot check.

#include "crypto/cpace.h"
#include "crypto/field25519.h"
#include <valgrind/memcheck.h>

#include <array>
#include <cstdint>
#include <cstdio>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local

int main() {
    // Several values, so both outcomes of every per-limb carry and of the Legendre symbol occur.
    static constexpr int RUNS = 16;
    unsigned checksum = 0;
    for (int run = 0; run < RUNS; ++run) {
        // The full generator: SHA-512 over the generator string, decode_u, Elligator2.
        uint8_t prs[8];
        for (int i = 0; i < 8; ++i) {
            prs[i] = static_cast<uint8_t>('0' + (run * 7 + i * 3) % 10);
        }
        const uint8_t sid[16] = {
            static_cast<uint8_t>(run), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        VALGRIND_MAKE_MEM_UNDEFINED(prs, sizeof prs);
        auto gen = cpace_calculate_generator(prs, sizeof prs, nullptr, 0, sid, sizeof sid);
        VALGRIND_MAKE_MEM_DEFINED(gen.data(), gen.size());

        // Elligator2 alone, on raw field inputs including values above p.
        std::array<uint8_t, 32> r{};
        for (size_t i = 0; i < r.size(); ++i) {
            r[i] = static_cast<uint8_t>(run * 31 + i * 17 + (run & 1 ? 0xF0 : 0));
        }
        VALGRIND_MAKE_MEM_UNDEFINED(r.data(), r.size());
        auto x = cpace_elligator2(r);
        VALGRIND_MAKE_MEM_DEFINED(x.data(), x.size());

        for (size_t i = 0; i < gen.size(); ++i) {
            checksum += gen[i] ^ x[i];
        }
    }
    std::printf("ct_field25519: %d runs, checksum %u\n", RUNS, checksum);
    return 0;
}
