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

// The record decoder's malformed-blob family: each row malforms one required field of the
// well-formed entry the Control row carries.
TEST(PersistenceCodec, RecordDecodeRejectsMalformedBlobs) {
    const std::string good_psk = base64url_encode(make_psk(0x60).data(), 32);
    const std::array<uint8_t, 16> short_psk{};
    const std::string short_b64 = base64url_encode(short_psk.data(), short_psk.size());

    struct Row {
        const char* name;
        std::string blob;
        bool expect_ok;
    };
    const Row rows[] = {
        {"not-json", "not json", false},
        {"missing-psk_id", R"({"v":1,"server_id":"srv","psk":")" + good_psk + R"("})", false},
        {"empty-psk_id", R"({"v":1,"server_id":"srv","psk_id":"","psk":")" + good_psk + R"("})",
         false},
        {"missing-psk", R"({"v":1,"server_id":"srv","psk_id":"rec"})", false},
        {"psk-not-base64", R"({"v":1,"server_id":"srv","psk_id":"rec","psk":"not!!base64!!"})",
         false},
        {"psk-wrong-length",
         R"({"v":1,"server_id":"srv","psk_id":"rec","psk":")" + short_b64 + R"("})", false},
        // Control: the same object with every required field well formed.
        {"all-fields-present",
         R"({"v":1,"server_id":"srv","psk_id":"rec","psk":")" + good_psk + R"("})", true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(decode_pairing_record(row.blob).has_value(), row.expect_ok);
    }
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

// ============================================================================
// Slot sizing
// ============================================================================

// Records are stored one per key, so the per-slot size is what a provider sizes fixed-length
// storage against; persistence_codec.h and the integration guide quote it, and a field added to
// the storage format moves it.
TEST(PersistenceCodec, EncodedRecordMatchesTheDocumentedSlotSize) {
    struct Row {
        const char* name;
        bool used;
        size_t expected;
    };
    const Row rows[] = {
        // The documented figure: the freshly paired form, which every pairing writes first.
        {"freshly-paired-used-false", false, 185u},
        // Control: the only other state a record reaches. "true" is one byte shorter than
        // "false", so this row is what the documented figure must NOT be sized against.
        {"activated-used-true", true, 184u},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinPairingRecord r;
        // The three 43-character base64url fields a real record carries: psk_id and server_id are
        // 32-byte values encoded the same way as the psk.
        r.psk = make_psk(0x80);
        r.psk_id = base64url_encode(r.psk.data(), r.psk.size());
        r.server_id = base64url_encode(make_psk(0x81).data(), 32);
        r.used = row.used;

        EXPECT_EQ(encode_pairing_record(r).size(), row.expected)
            << "the documented per-slot size must match what the codec writes";

        // A label costs its own length plus 11 bytes of framing, which is the other half of the
        // documented figure.
        r.label = "kitchen";
        EXPECT_EQ(encode_pairing_record(r).size(), row.expected + 11u + r.label->size());
    }
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

// The pairing-PSK decoder's malformed-blob family, over the same required fields as a record
// minus server_id.
TEST(PersistenceCodec, PskDecodeRejectsMalformedBlobs) {
    const std::string good_psk = base64url_encode(make_psk(0x73).data(), 32);
    const std::array<uint8_t, 10> short_psk{};
    const std::string short_b64 = base64url_encode(short_psk.data(), short_psk.size());

    struct Row {
        const char* name;
        std::string blob;
        bool expect_ok;
    };
    const Row rows[] = {
        {"psk-not-base64", R"({"v":1,"psk_id":"psk","psk":"!!!not-base64!!!"})", false},
        {"psk-wrong-length", R"({"v":1,"psk_id":"psk","psk":")" + short_b64 + R"("})", false},
        {"missing-psk_id", R"({"v":1,"psk":")" + good_psk + R"("})", false},
        // Control: the same object with both required fields well formed.
        {"all-fields-present", R"({"v":1,"psk_id":"psk","psk":")" + good_psk + R"("})", true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(decode_pairing_psk(row.blob).has_value(), row.expect_ok);
    }
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
// ignored like any other unknown field.
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

// ArduinoJson's as<bool>() coerces any non-boolean variant to true, a "false" STRING included,
// so an unguarded read of a corrupt config blob would turn a disabled pairing method back on -
// including unpaired_access_enabled, which defaults to false and so is invisible to
// ConfigDecodeMissingFieldsTakeDefaults. Every wrong-typed field must keep its struct default.
TEST(PersistenceCodec, ConfigDecodeWrongTypedFieldsTakeDefaults) {
    const SendspinPairingConfig defaults;
    for (const char* key : {"pairing_psk_enabled", "unpaired_access_enabled", "dynamic_pin_enabled",
                            "static_pin_enabled"}) {
        for (const char* corrupt : {R"("false")", R"("yes")", R"("")", "[1,2]", "{}", "1"}) {
            std::string blob = std::string(R"({"v":1,")") + key + R"(":)" + corrupt + "}";
            auto decoded = decode_pairing_config(blob);
            ASSERT_TRUE(decoded.has_value()) << blob;
            EXPECT_EQ(decoded->pairing_psk_enabled, defaults.pairing_psk_enabled) << blob;
            EXPECT_EQ(decoded->unpaired_access_enabled, defaults.unpaired_access_enabled) << blob;
            EXPECT_EQ(decoded->dynamic_pairing_code_enabled, defaults.dynamic_pairing_code_enabled)
                << blob;
            EXPECT_EQ(decoded->static_pairing_code_enabled, defaults.static_pairing_code_enabled)
                << blob;
        }
    }

    // Control: a real boolean on each of the same four keys comes through.
    auto decoded = decode_pairing_config(
        R"({"v":1,"pairing_psk_enabled":false,"unpaired_access_enabled":true,)"
        R"("dynamic_pin_enabled":false,"static_pin_enabled":true})");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->pairing_psk_enabled);
    EXPECT_TRUE(decoded->unpaired_access_enabled);
    EXPECT_FALSE(decoded->dynamic_pairing_code_enabled);
    EXPECT_TRUE(decoded->static_pairing_code_enabled);
}

// The config decoder's malformed-root family. Field-level corruption is a different rule
// (ConfigDecodeWrongTypedFieldsTakeDefaults): a bad root loses the blob, a bad field takes its
// struct default.
TEST(PersistenceCodec, ConfigDecodeRejectsMalformedRoot) {
    struct Row {
        const char* name;
        std::string blob;
        bool expect_ok;
    };
    const Row rows[] = {
        {"not-json", "{{{not json", false},
        {"array-root", "[1,2,3]", false},
        // Control: an object root, which is all this decoder requires.
        {"object-root", R"({"v":1})", true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(decode_pairing_config(row.blob).has_value(), row.expect_ok);
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
