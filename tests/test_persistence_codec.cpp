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

// Unit tests for the public persistence codec (sendspin/persistence_codec.h): round-trip
// encode/decode for each persistence struct, forward/backward-compatible decode semantics
// (missing "v", unknown fields, best-effort future "v"), corrupt-input rejection, and the
// base64url helpers.

#include "sendspin/persistence_codec.h"

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

}  // namespace

// ============================================================================
// SendspinPairingRecord round-trip
// ============================================================================

TEST(PersistenceCodec, RecordRoundTripWithOptionalFields) {
    SendspinPairingRecord r;
    r.psk_id = "rec-1";
    r.psk = make_psk(0x10);
    r.server_id = "server-abc";
    r.label = "kitchen";
    r.used = true;

    std::string blob = encode_pairing_record(r);
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, r.psk_id);
    EXPECT_EQ(decoded->psk, r.psk);
    ASSERT_TRUE(decoded->server_id.has_value());
    EXPECT_EQ(decoded->server_id.value(), r.server_id.value());
    ASSERT_TRUE(decoded->label.has_value());
    EXPECT_EQ(decoded->label.value(), r.label.value());
    EXPECT_TRUE(decoded->used);
}

TEST(PersistenceCodec, RecordRoundTripWithoutOptionalFields) {
    SendspinPairingRecord r;
    r.psk_id = "rec-2";
    r.psk = make_psk(0x20);
    r.used = false;

    std::string blob = encode_pairing_record(r);
    EXPECT_EQ(blob.find("server_id"), std::string::npos);
    EXPECT_EQ(blob.find("label"), std::string::npos);

    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, r.psk_id);
    EXPECT_EQ(decoded->psk, r.psk);
    EXPECT_FALSE(decoded->server_id.has_value());
    EXPECT_FALSE(decoded->label.has_value());
    EXPECT_FALSE(decoded->used);
}

TEST(PersistenceCodec, RecordDecodeAcceptsMissingVersion) {
    std::string blob =
        R"({"psk_id":"rec-3","psk":")" +
        base64url_encode(make_psk(0x30).data(), 32) + R"(","used":false})";
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "rec-3");
}

TEST(PersistenceCodec, RecordDecodeIgnoresUnknownFields) {
    std::string blob = R"({"v":1,"psk_id":"rec-4","psk":")" +
                       base64url_encode(make_psk(0x40).data(), 32) +
                       R"(","used":false,"totally_unknown":{"nested":[1,2,3]},"another":"x"})";
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "rec-4");
}

TEST(PersistenceCodec, RecordDecodeBestEffortOnFutureVersion) {
    std::string blob = R"({"v":99,"psk_id":"rec-5","psk":")" +
                       base64url_encode(make_psk(0x50).data(), 32) + R"(","used":true})";
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "rec-5");
    EXPECT_TRUE(decoded->used);
}

TEST(PersistenceCodec, RecordDecodeRejectsParseFailure) {
    EXPECT_FALSE(decode_pairing_record("not json").has_value());
}

TEST(PersistenceCodec, RecordDecodeRejectsMissingPskId) {
    std::string blob =
        R"({"v":1,"psk":")" + base64url_encode(make_psk(0x60).data(), 32) + R"("})";
    EXPECT_FALSE(decode_pairing_record(blob).has_value());
}

TEST(PersistenceCodec, RecordDecodeRejectsEmptyPskId) {
    std::string blob = R"({"v":1,"psk_id":"","psk":")" +
                       base64url_encode(make_psk(0x61).data(), 32) + R"("})";
    EXPECT_FALSE(decode_pairing_record(blob).has_value());
}

TEST(PersistenceCodec, RecordDecodeRejectsMissingPsk) {
    std::string blob = R"({"v":1,"psk_id":"rec-6"})";
    EXPECT_FALSE(decode_pairing_record(blob).has_value());
}

TEST(PersistenceCodec, RecordDecodeRejectsBadBase64) {
    std::string blob = R"({"v":1,"psk_id":"rec-7","psk":"not!!valid!!base64"})";
    EXPECT_FALSE(decode_pairing_record(blob).has_value());
}

TEST(PersistenceCodec, RecordDecodeWrongTypedUsedFallsBackToFalse) {
    // ArduinoJson's as<bool>() coerces any non-boolean variant to true, so an unguarded read
    // would turn a corrupt "used":"false" STRING into used == true and flip the single-use
    // admission gate. A wrong-typed field must keep the struct default.
    for (const char* corrupt_used : {R"("false")", R"("yes")", R"("")", "[1,2]", "{}"}) {
        std::string blob = R"({"v":1,"psk_id":"rec-u","psk":")" +
                           base64url_encode(make_psk(0x62).data(), 32) + R"(","used":)" +
                           corrupt_used + "}";
        auto decoded = decode_pairing_record(blob);
        ASSERT_TRUE(decoded.has_value()) << blob;
        EXPECT_FALSE(decoded->used) << blob;
    }
}

TEST(PersistenceCodec, RecordDecodeRejectsWrongLengthPsk) {
    std::array<uint8_t, 16> short_psk{};
    std::string blob = R"({"v":1,"psk_id":"rec-8","psk":")" +
                       base64url_encode(short_psk.data(), short_psk.size()) + R"("})";
    EXPECT_FALSE(decode_pairing_record(blob).has_value());
}

// ============================================================================
// SendspinPairingRecord list round-trip
// ============================================================================

TEST(PersistenceCodec, RecordsArrayRoundTrip) {
    std::vector<SendspinPairingRecord> recs;
    SendspinPairingRecord r1;
    r1.psk_id = "a";
    r1.psk = make_psk(1);
    r1.server_id = "srv-a";
    recs.push_back(r1);

    SendspinPairingRecord r2;
    r2.psk_id = "b";
    r2.psk = make_psk(2);
    r2.used = true;
    recs.push_back(r2);

    std::string blob = encode_pairing_records(recs);
    // Entries do not carry their own "v" (only the array wrapper does): the "v" key substring
    // appears exactly once in the whole blob.
    size_t count = 0;
    for (size_t pos = blob.find(R"("v":)"); pos != std::string::npos;
        pos = blob.find(R"("v":)", pos + 1)) {
        ++count;
    }
    EXPECT_EQ(count, 1u);

    auto decoded = decode_pairing_records(blob);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 2u);
    EXPECT_EQ((*decoded)[0].psk_id, "a");
    ASSERT_TRUE((*decoded)[0].server_id.has_value());
    EXPECT_EQ((*decoded)[0].server_id.value(), "srv-a");
    EXPECT_EQ((*decoded)[1].psk_id, "b");
    EXPECT_TRUE((*decoded)[1].used);
}

TEST(PersistenceCodec, RecordsArrayEmptyRoundTrip) {
    std::string blob = encode_pairing_records({});
    auto decoded = decode_pairing_records(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->empty());
}

TEST(PersistenceCodec, RecordsArrayDecodeRejectsParseFailure) {
    EXPECT_FALSE(decode_pairing_records("{not json").has_value());
}

TEST(PersistenceCodec, RecordsArrayDecodeRejectsMissingRecordsField) {
    EXPECT_FALSE(decode_pairing_records(R"({"v":1})").has_value());
}

TEST(PersistenceCodec, RecordsArrayDecodeRejectsNonArrayRecordsField) {
    EXPECT_FALSE(decode_pairing_records(R"({"v":1,"records":"oops"})").has_value());
}

TEST(PersistenceCodec, RecordsArraySkipsCorruptEntryKeepsGoodOnes) {
    std::string good_psk = base64url_encode(make_psk(9).data(), 32);
    std::string blob = R"({"v":1,"records":[)"
                       R"({"psk_id":"good-1","psk":")" +
                       good_psk +
                       R"("},)"
                       R"({"psk_id":"bad","psk":"not-valid-base64!!"},)"
                       R"({"psk":")" +
                       good_psk +
                       R"("},)"  // missing psk_id
                       R"({"psk_id":"good-2","psk":")" +
                       good_psk + R"("}]})";

    auto decoded = decode_pairing_records(blob);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 2u);
    EXPECT_EQ((*decoded)[0].psk_id, "good-1");
    EXPECT_EQ((*decoded)[1].psk_id, "good-2");
}

// ============================================================================
// SendspinPairingPsk round-trip
// ============================================================================

TEST(PersistenceCodec, PskRoundTripWithLabel) {
    SendspinPairingPsk p;
    p.psk_id = "psk-1";
    p.psk = make_psk(0x70);
    p.label = "operator";

    std::string blob = encode_pairing_psk(p);
    auto decoded = decode_pairing_psk(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, p.psk_id);
    EXPECT_EQ(decoded->psk, p.psk);
    ASSERT_TRUE(decoded->label.has_value());
    EXPECT_EQ(decoded->label.value(), p.label.value());
}

TEST(PersistenceCodec, PskRoundTripWithoutLabel) {
    SendspinPairingPsk p;
    p.psk_id = "psk-2";
    p.psk = make_psk(0x80);

    std::string blob = encode_pairing_psk(p);
    EXPECT_EQ(blob.find("label"), std::string::npos);

    auto decoded = decode_pairing_psk(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->label.has_value());
}

TEST(PersistenceCodec, PskDecodeRejectsBadBase64) {
    std::string blob = R"({"v":1,"psk_id":"psk-3","psk":"!!!not-base64!!!"})";
    EXPECT_FALSE(decode_pairing_psk(blob).has_value());
}

TEST(PersistenceCodec, PskDecodeRejectsWrongLengthPsk) {
    std::array<uint8_t, 10> short_psk{};
    std::string blob = R"({"v":1,"psk_id":"psk-4","psk":")" +
                       base64url_encode(short_psk.data(), short_psk.size()) + R"("})";
    EXPECT_FALSE(decode_pairing_psk(blob).has_value());
}

TEST(PersistenceCodec, PskDecodeRejectsMissingPskId) {
    std::string blob =
        R"({"v":1,"psk":")" + base64url_encode(make_psk(0x90).data(), 32) + R"("})";
    EXPECT_FALSE(decode_pairing_psk(blob).has_value());
}

// ============================================================================
// SendspinPairingConfig round-trip
// ============================================================================

TEST(PersistenceCodec, ConfigRoundTrip) {
    SendspinPairingConfig c;
    c.pairing_psk_enabled = false;
    c.unpaired_access_enabled = true;
    c.dynamic_pin_enabled = false;
    c.static_pin_enabled = true;
    c.dynamic_pin_min_length = 8;
    c.dynamic_pin_failures = 3;
    c.pairing_psk_rotated = true;
    c.static_pin_rotated = true;
    c.record_mode_psk_id = "fallback-id";

    std::string blob = encode_pairing_config(c);
    auto decoded = decode_pairing_config(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->pairing_psk_enabled, c.pairing_psk_enabled);
    EXPECT_EQ(decoded->unpaired_access_enabled, c.unpaired_access_enabled);
    EXPECT_EQ(decoded->dynamic_pin_enabled, c.dynamic_pin_enabled);
    EXPECT_EQ(decoded->static_pin_enabled, c.static_pin_enabled);
    EXPECT_EQ(decoded->dynamic_pin_min_length, c.dynamic_pin_min_length);
    EXPECT_EQ(decoded->dynamic_pin_failures, c.dynamic_pin_failures);
    EXPECT_EQ(decoded->pairing_psk_rotated, c.pairing_psk_rotated);
    EXPECT_EQ(decoded->static_pin_rotated, c.static_pin_rotated);
    EXPECT_EQ(decoded->record_mode_psk_id, c.record_mode_psk_id);
}

TEST(PersistenceCodec, ConfigDecodeMissingFieldsTakeDefaults) {
    SendspinPairingConfig defaults;
    auto decoded = decode_pairing_config(R"({"v":1})");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->pairing_psk_enabled, defaults.pairing_psk_enabled);
    EXPECT_EQ(decoded->unpaired_access_enabled, defaults.unpaired_access_enabled);
    EXPECT_EQ(decoded->dynamic_pin_enabled, defaults.dynamic_pin_enabled);
    EXPECT_EQ(decoded->static_pin_enabled, defaults.static_pin_enabled);
    EXPECT_EQ(decoded->dynamic_pin_min_length, defaults.dynamic_pin_min_length);
    EXPECT_EQ(decoded->dynamic_pin_failures, defaults.dynamic_pin_failures);
    // A blob written before the rotation flags existed must read back as "never rotated", so an
    // upgrade keeps advertising the factory locations hint rather than inventing a rotation.
    EXPECT_FALSE(decoded->pairing_psk_rotated);
    EXPECT_FALSE(decoded->static_pin_rotated);
    EXPECT_EQ(decoded->record_mode_psk_id, defaults.record_mode_psk_id);
}

TEST(PersistenceCodec, ConfigDecodeRejectsParseFailure) {
    EXPECT_FALSE(decode_pairing_config("{{{not json").has_value());
}

TEST(PersistenceCodec, ConfigDecodeRejectsNonObjectRoot) {
    EXPECT_FALSE(decode_pairing_config("[1,2,3]").has_value());
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
}

TEST(PersistenceCodec, Base64UrlEmptyRoundTrip) {
    std::string encoded = base64url_encode(nullptr, 0);
    EXPECT_TRUE(encoded.empty());
    auto decoded = base64url_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->empty());
}

// ============================================================================
// Compatibility fixture: the host example's existing on-disk record shape (no "v")
// ============================================================================

TEST(PersistenceCodec, DecodesHostExampleLegacyRecordShape) {
    // Hand-written to match examples/common/file_persistence_provider.cpp's
    // save_pairing_record() field mapping (psk_id, psk, server_id, label, used), predating the
    // "v" field, so old on-disk records written by that example keep loading.
    std::array<uint8_t, 32> psk = make_psk(0xC0);
    std::string legacy_record = R"({"psk_id":"legacy-psk-id","psk":")" +
                                base64url_encode(psk.data(), psk.size()) +
                                R"(","server_id":"legacy-server","label":"living room",)"
                                R"("used":true})";

    auto decoded = decode_pairing_record(legacy_record);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "legacy-psk-id");
    EXPECT_EQ(decoded->psk, psk);
    ASSERT_TRUE(decoded->server_id.has_value());
    EXPECT_EQ(decoded->server_id.value(), "legacy-server");
    ASSERT_TRUE(decoded->label.has_value());
    EXPECT_EQ(decoded->label.value(), "living room");
    EXPECT_TRUE(decoded->used);
}
