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

#include <ArduinoJson.h>
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
    EXPECT_EQ(decoded->server_id, r.server_id);
    ASSERT_TRUE(decoded->label.has_value());
    EXPECT_EQ(decoded->label.value(), r.label.value());
    EXPECT_TRUE(decoded->used);
}

TEST(PersistenceCodec, RecordRoundTripWithoutOptionalFields) {
    SendspinPairingRecord r;
    r.psk_id = "rec-2";
    r.psk = make_psk(0x20);
    r.server_id = "srv-2";
    r.used = false;

    std::string blob = encode_pairing_record(r);
    EXPECT_EQ(blob.find("label"), std::string::npos);

    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, r.psk_id);
    EXPECT_EQ(decoded->psk, r.psk);
    EXPECT_EQ(decoded->server_id, r.server_id);
    EXPECT_FALSE(decoded->label.has_value());
    EXPECT_FALSE(decoded->used);
}

// A record with no server_id could never satisfy the post-match server check, so it is not a
// usable credential and the decoder rejects it (connection.md "Pre-Shared Key").
TEST(PersistenceCodec, RecordDecodeRejectsMissingServerId) {
    const std::string head = R"({"v":1,"psk_id":"rec-9","psk":")" +
                             base64url_encode(make_psk(0x21).data(), 32);
    EXPECT_FALSE(decode_pairing_record(head + R"("})").has_value());
    EXPECT_FALSE(decode_pairing_record(head + R"(","server_id":""})").has_value());
    // Control: the same record with a server_id decodes.
    EXPECT_TRUE(decode_pairing_record(head + R"(","server_id":"srv-9"})").has_value());
}

TEST(PersistenceCodec, RecordDecodeAcceptsMissingVersion) {
    std::string blob =
        R"({"server_id":"srv-rec-3","psk_id":"rec-3","psk":")" +
        base64url_encode(make_psk(0x30).data(), 32) + R"(","used":false})";
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "rec-3");
}

TEST(PersistenceCodec, RecordDecodeIgnoresUnknownFields) {
    std::string blob = R"({"v":1,"server_id":"srv-rec-4","psk_id":"rec-4","psk":")" +
                       base64url_encode(make_psk(0x40).data(), 32) +
                       R"(","used":false,"totally_unknown":{"nested":[1,2,3]},"another":"x"})";
    auto decoded = decode_pairing_record(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, "rec-4");
}

TEST(PersistenceCodec, RecordDecodeBestEffortOnFutureVersion) {
    std::string blob = R"({"v":99,"server_id":"srv-rec-5","psk_id":"rec-5","psk":")" +
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
        std::string blob = R"({"v":1,"server_id":"srv-u","psk_id":"rec-u","psk":")" +
                           base64url_encode(make_psk(0x62).data(), 32) + R"(","used":)" +
                           corrupt_used + "}";
        auto decoded = decode_pairing_record(blob);
        ASSERT_TRUE(decoded.has_value()) << blob;
        EXPECT_FALSE(decoded->used) << blob;
    }
}

TEST(PersistenceCodec, RecordDecodeRejectsWrongLengthPsk) {
    std::array<uint8_t, 16> short_psk{};
    std::string blob = R"({"v":1,"server_id":"srv-rec-8","psk_id":"rec-8","psk":")" +
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
    r2.server_id = "srv-b";
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
    EXPECT_EQ((*decoded)[0].server_id, "srv-a");
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
                       R"({"server_id":"srv-1","psk_id":"good-1","psk":")" +
                       good_psk +
                       R"("},)"
                       R"({"server_id":"srv-bad","psk_id":"bad","psk":"not-valid-base64!!"},)"
                       R"({"server_id":"srv-2","psk":")" +
                       good_psk +
                       R"("},)"  // missing psk_id
                       R"({"server_id":"srv-3","psk_id":"good-2","psk":")" +
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
    c.dynamic_pairing_code_enabled = false;
    c.static_pairing_code_enabled = true;

    std::string blob = encode_pairing_config(c);
    auto decoded = decode_pairing_config(blob);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->pairing_psk_enabled, c.pairing_psk_enabled);
    EXPECT_EQ(decoded->unpaired_access_enabled, c.unpaired_access_enabled);
    EXPECT_EQ(decoded->dynamic_pairing_code_enabled, c.dynamic_pairing_code_enabled);
    EXPECT_EQ(decoded->static_pairing_code_enabled, c.static_pairing_code_enabled);
}

// The two pairing-code flags are stored under the key strings the blob format froze them at,
// which are independent of the protocol's field names (see persistence_codec.h).
TEST(PersistenceCodec, ConfigUsesTheStoredKeyNames) {
    SendspinPairingConfig c;
    c.dynamic_pairing_code_enabled = false;
    c.static_pairing_code_enabled = true;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, encode_pairing_config(c)));
    ASSERT_TRUE(doc["dynamic_pin_enabled"].is<bool>());
    ASSERT_TRUE(doc["static_pin_enabled"].is<bool>());
    EXPECT_FALSE(doc["dynamic_pin_enabled"].as<bool>());
    EXPECT_TRUE(doc["static_pin_enabled"].as<bool>());
}

// A config blob written by an older build carries keys this codec no longer knows. They are
// ignored like any other unknown field, and the fields it does know still come through.
TEST(PersistenceCodec, ConfigDecodeIgnoresUnknownFields) {
    auto decoded = decode_pairing_config(
        R"({"v":1,"static_pin_enabled":true,"dynamic_pin_enabled":false,)"
        R"("dynamic_pin_min_length":8,"pairing_psk_rotated":true,"whatever":[1,2]})");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->static_pairing_code_enabled);
    // Control: a key this codec does know still comes through from the same blob.
    EXPECT_FALSE(decoded->dynamic_pairing_code_enabled);
}

TEST(PersistenceCodec, ConfigDecodeMissingFieldsTakeDefaults) {
    SendspinPairingConfig defaults;
    auto decoded = decode_pairing_config(R"({"v":1})");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->pairing_psk_enabled, defaults.pairing_psk_enabled);
    EXPECT_EQ(decoded->unpaired_access_enabled, defaults.unpaired_access_enabled);
    EXPECT_EQ(decoded->dynamic_pairing_code_enabled, defaults.dynamic_pairing_code_enabled);
    EXPECT_EQ(decoded->static_pairing_code_enabled, defaults.static_pairing_code_enabled);
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
    EXPECT_EQ(decoded->server_id, "legacy-server");
    ASSERT_TRUE(decoded->label.has_value());
    EXPECT_EQ(decoded->label.value(), "living room");
    EXPECT_TRUE(decoded->used);
}
