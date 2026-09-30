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

// Unit tests for the public persistence codec (sendspin/persistence_codec.h): the fixed binary
// layout of each persistence struct, round trips, which blobs decode rejects, and the base64url
// helpers.

#include "sendspin/persistence_codec.h"

#include "crypto/keys.h"
#include "record_test_helpers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

std::array<uint8_t, 32> make_psk(uint8_t seed) {
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(seed + i);
    }
    return psk;
}

SendspinPairingRecord make_record(uint8_t seed, bool used) {
    SendspinPairingRecord r;
    r.psk = make_psk(seed);
    r.psk_id = psk_id_for(r.psk);
    r.server_id = test_peer_id("server-" + std::to_string(seed));
    r.used = used;
    return r;
}

}  // namespace

// ============================================================================
// SendspinPairingRecord
// ============================================================================

// The layout is storage ABI: a provider may size fixed-length storage against it, and a change
// makes every stored record read as absent.
TEST(PersistenceCodec, RecordEncodesToTheDocumentedLayout) {
    for (bool used : {false, true}) {
        SCOPED_TRACE(used ? "used" : "unused");
        const SendspinPairingRecord r = make_record(0x10, used);
        auto blob = encode_pairing_record(r);
        ASSERT_TRUE(blob.has_value());
        ASSERT_EQ(blob->size(), persistence_keys::RECORD_SLOT_SIZE);

        const auto server_key = public_key_from_peer_id(r.server_id).value();
        EXPECT_TRUE(std::equal(r.psk.begin(), r.psk.end(), blob->begin()));
        EXPECT_TRUE(std::equal(server_key.begin(), server_key.end(), blob->begin() + 32));
        EXPECT_EQ((*blob)[64], used ? 0x01 : 0x00);
    }
}

// psk_id is not stored, so decode must derive it: a record that came back without it could never
// resolve the server's handshake.
TEST(PersistenceCodec, RecordRoundTripsAndDerivesPskId) {
    for (bool used : {false, true}) {
        SCOPED_TRACE(used ? "used" : "unused");
        const SendspinPairingRecord r = make_record(0x20, used);
        auto blob = encode_pairing_record(r).value();
        auto decoded = decode_pairing_record(blob.data(), blob.size());
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->psk, r.psk);
        EXPECT_EQ(decoded->psk_id, psk_id_for(r.psk));
        EXPECT_EQ(decoded->server_id, r.server_id);
        EXPECT_EQ(decoded->used, used);
    }
}

// Only bit 0 of the flags byte means anything; the rest are reserved for future flags, so a blob
// that sets them must still read back the `used` it was written with.
TEST(PersistenceCodec, RecordDecodeReadsOnlyTheUsedFlagBit) {
    struct Row {
        uint8_t flags;
        bool expect_used;
    };
    const Row rows[] = {{0xFE, false}, {0x80, false}, {0xFF, true}, {0x01, true}};
    for (const Row& row : rows) {
        SCOPED_TRACE(row.flags);
        auto blob = encode_pairing_record(make_record(0x30, false)).value();
        blob[64] = row.flags;
        auto decoded = decode_pairing_record(blob.data(), blob.size());
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->used, row.expect_used);
    }
}

TEST(PersistenceCodec, RecordDecodeRejectsUnusableBlobs) {
    const auto good = blob_bytes(encode_pairing_record(make_record(0x40, true)).value());
    std::vector<uint8_t> zero_psk = good;
    std::fill(zero_psk.begin(), zero_psk.begin() + 32, uint8_t{0});

    struct Row {
        const char* name;
        std::vector<uint8_t> blob;
        bool expect_ok;
    };
    const Row rows[] = {
        {"empty", {}, false},
        {"one byte short", std::vector<uint8_t>(good.begin(), good.end() - 1), false},
        {"one byte long", [&] {
             auto b = good;
             b.push_back(0);
             return b;
         }(),
         false},
        // What a freed slot holds.
        {"all zero", std::vector<uint8_t>(persistence_keys::RECORD_SLOT_SIZE, 0), false},
        // A zero PSK is no credential, whatever the rest of the blob holds.
        {"zero psk", zero_psk, false},
        // Control: the well-formed blob the other rows are cut from.
        {"well formed", good, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(decode_pairing_record(row.blob.data(), row.blob.size()).has_value(),
                  row.expect_ok);
    }
}

// A record stores the key, not the text, so only a server_id that decodes back to itself can be
// stored: anything else would come back as a different id after a reboot.
TEST(PersistenceCodec, RecordEncodeRequiresACanonicalServerId) {
    const std::string canonical = test_peer_id("server-canonical");
    struct Row {
        const char* name;
        std::string server_id;
        bool expect_ok;
    };
    const Row rows[] = {
        {"not base64url", "server-abc", false},
        {"nonzero trailing bits", non_canonical_spelling(canonical), false},
        {"padded", canonical + "=", false},
        // Control: the canonical spelling of the same key.
        {"canonical", canonical, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinPairingRecord r = make_record(0x50, false);
        r.server_id = row.server_id;
        EXPECT_EQ(encode_pairing_record(r).has_value(), row.expect_ok);
    }
}

// ============================================================================
// SendspinPairingPsk
// ============================================================================

TEST(PersistenceCodec, PskEncodesToTheBarePsk) {
    SendspinPairingPsk p;
    p.psk = make_psk(0x60);
    p.psk_id = psk_id_for(p.psk);

    auto blob = encode_pairing_psk(p);
    EXPECT_EQ(blob, p.psk);

    auto decoded = decode_pairing_psk(blob.data(), blob.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk, p.psk);
    EXPECT_EQ(decoded->psk_id, psk_id_for(p.psk));
}

TEST(PersistenceCodec, PskDecodeRejectsUnusableBlobs) {
    const auto good = make_psk(0x70);
    struct Row {
        const char* name;
        std::vector<uint8_t> blob;
        bool expect_ok;
    };
    const Row rows[] = {
        {"empty", {}, false},
        {"one byte short", std::vector<uint8_t>(good.begin(), good.end() - 1), false},
        {"one byte long", [&] {
             std::vector<uint8_t> b(good.begin(), good.end());
             b.push_back(0);
             return b;
         }(),
         false},
        {"all zero", std::vector<uint8_t>(persistence_keys::PAIRING_PSK_SIZE, 0), false},
        // Control: a usable PSK of the right size.
        {"well formed", std::vector<uint8_t>(good.begin(), good.end()), true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(decode_pairing_psk(row.blob.data(), row.blob.size()).has_value(),
                  row.expect_ok);
    }
}

// ============================================================================
// base64url helpers
// ============================================================================

TEST(PersistenceCodec, Base64UrlRoundTrip) {
    std::array<uint8_t, 32> psk = make_psk(0xA0);
    std::string encoded = base64url_encode(psk.data(), psk.size());
    EXPECT_EQ(encoded.size(), 43u);  // 32 bytes, no padding.
    EXPECT_EQ(encoded.find('='), std::string::npos);

    auto decoded = base64url_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), psk.size());
    EXPECT_TRUE(std::equal(decoded->begin(), decoded->end(), psk.begin()));
}

TEST(PersistenceCodec, Base64UrlDecodeToleratesPadding) {
    std::array<uint8_t, 32> psk = make_psk(0xB0);
    std::string encoded = base64url_encode(psk.data(), psk.size());
    std::string padded = encoded + "=";  // 43 chars needs one '=' to reach a multiple of 4.

    auto decoded = base64url_decode(padded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), psk.size());
    EXPECT_TRUE(std::equal(decoded->begin(), decoded->end(), psk.begin()));
}

TEST(PersistenceCodec, Base64UrlDecodeRejectsInvalidCharacters) {
    EXPECT_FALSE(base64url_decode("not*valid+base64/url").has_value());
    // Control: the url-safe alphabet over the same length decodes.
    EXPECT_TRUE(base64url_decode("notXvalidXbase64Xurl").has_value());
}

TEST(PersistenceCodec, Base64UrlEmptyRoundTrip) {
    std::string encoded = base64url_encode(nullptr, 0);
    EXPECT_TRUE(encoded.empty());
    auto decoded = base64url_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->empty());
}
