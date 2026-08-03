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

// Phase 8b unit tests: dynamic-PIN wire messages, PIN lockout, and CPace
// round-trip.  Mirrors the test surface described in the Phase 8b spec and
// validates against the aiosendspin Python reference behaviour.

#include "crypto/cpace.h"
#include "platform/base64.h"
#include "protocol_messages.h"
#include "record_store.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a JSON string into doc+root.  Returns false on malformed JSON.
bool parse(const std::string& json, JsonDocument& doc, JsonObject& root) {
    if (deserializeJson(doc, json)) {
        return false;
    }
    root = doc.as<JsonObject>();
    return true;
}

/// base64url-encode a fixed-size array for building test JSON strings.
template <size_t N>
static std::string b64url(const std::array<uint8_t, N>& a) {
    return b64url_encode(a.data(), a.size());
}

/// Build the wire JSON for server/pair-init from raw values.
static std::string make_pair_init_json(const std::string& nonce_a_b64, int pin_length) {
    return std::string(R"({"type":"server/pair-init","payload":{"nonce_A":")") + nonce_a_b64 +
           R"(","pin_length":)" + std::to_string(pin_length) + "}}";
}

/// Build the wire JSON for server/pair-auth from raw values.
static std::string make_pair_auth_json(const std::string& pake_msg_1_b64) {
    return std::string(R"({"type":"server/pair-auth","payload":{"pake_msg_1":")") +
           pake_msg_1_b64 + R"("}})";
}

/// Build the wire JSON for server/pair-confirm from raw values.
static std::string make_pair_confirm_json(const std::string& server_kc_b64) {
    return std::string(R"({"type":"server/pair-confirm","payload":{"server_kc":")") +
           server_kc_b64 + R"("}})";
}

}  // namespace

// ============================================================================
// process_server_pair_init_message
// ============================================================================

TEST(DynamicPin, ParseServerPairInitValid) {
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);

    const std::string json = make_pair_init_json(b64url(nonce_a), 6);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));

    EXPECT_EQ(payload.nonce_a, nonce_a);
    EXPECT_EQ(payload.pin_length, 6);
}

TEST(DynamicPin, ParseServerPairInitMissingNonce) {
    const std::string json = R"({"type":"server/pair-init","payload":{"pin_length":6}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    EXPECT_FALSE(process_server_pair_init_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairInitMissingPinLength) {
    std::array<uint8_t, 32> nonce_a{};
    const std::string json =
        std::string(R"({"type":"server/pair-init","payload":{"nonce_A":")") + b64url(nonce_a) +
        R"("}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    EXPECT_FALSE(process_server_pair_init_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairInitWrongNonceLength) {
    // Encode only 16 bytes (wrong size).
    std::array<uint8_t, 16> short_nonce{};
    const std::string nonce_b64 = b64url_encode(short_nonce.data(), short_nonce.size());
    const std::string json = make_pair_init_json(nonce_b64, 6);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    EXPECT_FALSE(process_server_pair_init_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairInitInvalidBase64) {
    const std::string json =
        R"({"type":"server/pair-init","payload":{"nonce_A":"!!!not_base64!!!","pin_length":6}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    EXPECT_FALSE(process_server_pair_init_message(root, &payload));
}

// ============================================================================
// process_server_pair_auth_message
// ============================================================================

TEST(DynamicPin, ParseServerPairAuthValid) {
    std::array<uint8_t, 32> pake_msg_1{};
    for (int i = 0; i < 32; ++i) pake_msg_1[i] = static_cast<uint8_t>(i + 10);

    const std::string json = make_pair_auth_json(b64url(pake_msg_1));

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairAuthPayload payload;
    ASSERT_TRUE(process_server_pair_auth_message(root, &payload));
    EXPECT_EQ(payload.pake_msg_1, pake_msg_1);
}

TEST(DynamicPin, ParseServerPairAuthMissingField) {
    const std::string json = R"({"type":"server/pair-auth","payload":{}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairAuthPayload payload;
    EXPECT_FALSE(process_server_pair_auth_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairAuthWrongFieldLength) {
    // 16 bytes instead of 32.
    std::array<uint8_t, 16> short_share{};
    const std::string b64 = b64url_encode(short_share.data(), short_share.size());
    const std::string json = make_pair_auth_json(b64);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairAuthPayload payload;
    EXPECT_FALSE(process_server_pair_auth_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairAuthInvalidBase64) {
    const std::string json =
        R"({"type":"server/pair-auth","payload":{"pake_msg_1":"!!!not_valid!!!"}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairAuthPayload payload;
    EXPECT_FALSE(process_server_pair_auth_message(root, &payload));
}

// ============================================================================
// process_server_pair_confirm_message
// ============================================================================

TEST(DynamicPin, ParseServerPairConfirmValid) {
    std::array<uint8_t, 64> server_kc{};
    for (int i = 0; i < 64; ++i) server_kc[i] = static_cast<uint8_t>(i);

    const std::string json = make_pair_confirm_json(b64url(server_kc));

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairConfirmPayload payload;
    ASSERT_TRUE(process_server_pair_confirm_message(root, &payload));
    EXPECT_EQ(payload.server_kc, server_kc);
}

TEST(DynamicPin, ParseServerPairConfirmMissingField) {
    const std::string json = R"({"type":"server/pair-confirm","payload":{}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairConfirmPayload payload;
    EXPECT_FALSE(process_server_pair_confirm_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairConfirmWrongFieldLength) {
    // 32 bytes instead of 64.
    std::array<uint8_t, 32> short_kc{};
    const std::string b64 = b64url_encode(short_kc.data(), short_kc.size());
    const std::string json = make_pair_confirm_json(b64);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairConfirmPayload payload;
    EXPECT_FALSE(process_server_pair_confirm_message(root, &payload));
}

TEST(DynamicPin, ParseServerPairConfirmInvalidBase64) {
    const std::string json =
        R"({"type":"server/pair-confirm","payload":{"server_kc":"!!!not_valid!!!"}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairConfirmPayload payload;
    EXPECT_FALSE(process_server_pair_confirm_message(root, &payload));
}

// ============================================================================
// format_client_pair_init_message
// ============================================================================

TEST(DynamicPin, FormatClientPairInitWireShape) {
    std::array<uint8_t, 32> commit_b{};
    for (int i = 0; i < 32; ++i) commit_b[i] = static_cast<uint8_t>(i);

    const std::string out = format_client_pair_init_message(commit_b);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out)) << "format_client_pair_init produced invalid JSON";

    // type field
    EXPECT_STREQ(doc["type"], "client/pair-init");

    // commit_B must be a 43-char unpadded base64url string (32 bytes -> 43 chars).
    ASSERT_TRUE(doc["payload"]["commit_B"].is<const char*>());
    const std::string commit_b64 = doc["payload"]["commit_B"].as<std::string>();
    EXPECT_EQ(commit_b64.size(), 43u) << "base64url of 32 bytes without padding is 43 chars";

    // Decode and verify round-trip.
    auto decoded = b64url_decode(commit_b64);
    ASSERT_TRUE(decoded.has_value()) << "commit_B is not valid base64url";
    ASSERT_EQ(decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*decoded)[i], commit_b[i]) << "decoded byte mismatch at index " << i;
    }
}

// ============================================================================
// format_client_pair_auth_message
// ============================================================================

TEST(DynamicPin, FormatClientPairAuthWireShape) {
    std::array<uint8_t, 32> pake_msg_2{};
    for (int i = 0; i < 32; ++i) pake_msg_2[i] = static_cast<uint8_t>(i + 64);

    const std::string out = format_client_pair_auth_message(pake_msg_2);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out)) << "format_client_pair_auth produced invalid JSON";

    EXPECT_STREQ(doc["type"], "client/pair-auth");

    ASSERT_TRUE(doc["payload"]["pake_msg_2"].is<const char*>());
    const std::string msg2_b64 = doc["payload"]["pake_msg_2"].as<std::string>();
    EXPECT_EQ(msg2_b64.size(), 43u);

    auto decoded = b64url_decode(msg2_b64);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*decoded)[i], pake_msg_2[i]) << "decoded byte mismatch at index " << i;
    }
}

// ============================================================================
// format_client_pair_confirm_message
// ============================================================================

TEST(DynamicPin, FormatClientPairConfirmWireShape) {
    std::array<uint8_t, 64> client_kc{};
    std::array<uint8_t, 32> nonce_b{};
    for (int i = 0; i < 64; ++i) client_kc[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 32; ++i) nonce_b[i] = static_cast<uint8_t>(i + 100);

    const std::string out = format_client_pair_confirm_message(client_kc, nonce_b);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out)) << "format_client_pair_confirm produced invalid JSON";

    EXPECT_STREQ(doc["type"], "client/pair-confirm");

    // client_kc: 64 bytes -> 86-char base64url without padding.
    ASSERT_TRUE(doc["payload"]["client_kc"].is<const char*>());
    const std::string kc_b64 = doc["payload"]["client_kc"].as<std::string>();
    EXPECT_EQ(kc_b64.size(), 86u) << "base64url of 64 bytes without padding is 86 chars";

    auto kc_decoded = b64url_decode(kc_b64);
    ASSERT_TRUE(kc_decoded.has_value());
    ASSERT_EQ(kc_decoded->size(), 64u);
    for (size_t i = 0; i < 64; ++i) {
        EXPECT_EQ((*kc_decoded)[i], client_kc[i]) << "client_kc mismatch at index " << i;
    }

    // nonce_B: 32 bytes -> 43-char base64url without padding.
    ASSERT_TRUE(doc["payload"]["nonce_B"].is<const char*>());
    const std::string nb_b64 = doc["payload"]["nonce_B"].as<std::string>();
    EXPECT_EQ(nb_b64.size(), 43u);

    auto nb_decoded = b64url_decode(nb_b64);
    ASSERT_TRUE(nb_decoded.has_value());
    ASSERT_EQ(nb_decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*nb_decoded)[i], nonce_b[i]) << "nonce_B mismatch at index " << i;
    }
}

// ============================================================================
// PIN lockout (RecordStore)
// ============================================================================

TEST(DynamicPinLockout, NotLockedOutInitially) {
    RecordStore store(nullptr);
    EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

TEST(DynamicPinLockout, LocksOutAfterThresholdFailures) {
    RecordStore store(nullptr);
    // One fewer than the threshold must NOT lock out.
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD - 1; ++i) {
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
        EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN))
            << "should not be locked out after " << (i + 1) << " failure(s)";
    }
    // The threshold-th failure locks out.
    store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    EXPECT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

TEST(DynamicPinLockout, StaysLockedAfterMoreFailures) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD + 5; ++i) {
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    EXPECT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

TEST(DynamicPinLockout, ClearFailuresUnlocks) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    ASSERT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));

    store.reset_pin_failures(SendspinPairMethod::DYNAMIC_PIN);
    EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

TEST(DynamicPinLockout, CanFailAgainAfterClear) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    store.reset_pin_failures(SendspinPairMethod::DYNAMIC_PIN);

    // Should be able to accumulate failures again.
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD - 1; ++i) {
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));

    store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    EXPECT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

// ============================================================================
// PIN lockout: per-method independence (Phase 8c)
// ============================================================================

TEST(PinLockoutPerMethod, FailureCountsAreIndependentPerMethod) {
    RecordStore store(nullptr);
    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::DYNAMIC_PIN), 0);
    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::STATIC_PIN), 0);

    store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    store.record_pin_failure(SendspinPairMethod::STATIC_PIN);

    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::DYNAMIC_PIN), 2);
    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::STATIC_PIN), 1);
}

TEST(PinLockoutPerMethod, LockoutIsIndependentPerMethod) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        store.record_pin_failure(SendspinPairMethod::STATIC_PIN);
    }
    EXPECT_TRUE(store.is_pin_locked_out(SendspinPairMethod::STATIC_PIN));
    EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
}

TEST(PinLockoutPerMethod, ResetOnlyClearsTheGivenMethod) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        store.record_pin_failure(SendspinPairMethod::STATIC_PIN);
        store.record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    ASSERT_TRUE(store.is_pin_locked_out(SendspinPairMethod::STATIC_PIN));
    ASSERT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));

    store.reset_pin_failures(SendspinPairMethod::STATIC_PIN);
    EXPECT_FALSE(store.is_pin_locked_out(SendspinPairMethod::STATIC_PIN));
    EXPECT_TRUE(store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::STATIC_PIN), 0);
    EXPECT_EQ(store.pin_failure_count(SendspinPairMethod::DYNAMIC_PIN),
              RecordStore::PIN_LOCKOUT_THRESHOLD);
}

// ============================================================================
// CPace INITIATOR + RESPONDER round-trip with shared password
// ============================================================================

namespace {

// Build a SID = "sendspin-pair-pake-v1" (21 bytes) || 32 zero bytes.
static std::vector<uint8_t> make_test_sid() {
    const char* prefix = "sendspin-pair-pake-v1";
    const size_t prefix_len = 21;
    std::vector<uint8_t> sid(prefix_len + 32, 0);
    std::memcpy(sid.data(), prefix, prefix_len);
    return sid;
}

// Convert a C string to a byte vector for CPace API calls.
static std::vector<uint8_t> to_bytes(const char* s) {
    const size_t len = std::strlen(s);
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + len);
}

}  // namespace

TEST(DynamicPinCPace, RoundTripWithMatchingPassword) {
    const auto sid = make_test_sid();
    const auto prs = to_bytes("123456");
    const std::vector<uint8_t> empty;

    // Initiator (A = server role in the protocol; we test the library regardless).
    CPace initiator;
    ASSERT_TRUE(initiator.start(CPaceRole::INITIATOR, prs, sid, empty, empty, empty));
    const auto& share_a = initiator.public_share();

    // Responder (B = client role in the protocol).
    CPace responder;
    ASSERT_TRUE(responder.start(CPaceRole::RESPONDER, prs, sid, empty, empty, empty));
    const auto& share_b = responder.public_share();

    // Cross-derive.
    ASSERT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    ASSERT_TRUE(responder.derive(share_a.data(), share_a.size()));

    // Both sides produce a tag; each side can verify the other's.
    auto tag_a = initiator.tag();
    auto tag_b = responder.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    // Initiator verifies responder tag.
    EXPECT_TRUE(initiator.verify(tag_b->data(), tag_b->size()));
    // Responder verifies initiator tag.
    EXPECT_TRUE(responder.verify(tag_a->data(), tag_a->size()));
}

TEST(DynamicPinCPace, RoundTripMismatchedPasswordFails) {
    const auto sid = make_test_sid();
    const auto prs_a = to_bytes("123456");
    const auto prs_b = to_bytes("999999");
    const std::vector<uint8_t> empty;

    CPace initiator;
    ASSERT_TRUE(initiator.start(CPaceRole::INITIATOR, prs_a, sid, empty, empty, empty));

    CPace responder;
    ASSERT_TRUE(responder.start(CPaceRole::RESPONDER, prs_b, sid, empty, empty, empty));

    const auto& share_a = initiator.public_share();
    const auto& share_b = responder.public_share();

    ASSERT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    ASSERT_TRUE(responder.derive(share_a.data(), share_a.size()));

    auto tag_a = initiator.tag();
    auto tag_b = responder.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    // With mismatched passwords, verification must fail.
    EXPECT_FALSE(initiator.verify(tag_b->data(), tag_b->size()));
    EXPECT_FALSE(responder.verify(tag_a->data(), tag_a->size()));
}

// ============================================================================
// Phase 8b: client/hello dynamic_pin method descriptor fields
// ============================================================================

TEST(DynamicPin, ClientHelloDynamicPinDescriptorOutChannels) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor dyn_pin;
    dyn_pin.method = SendspinPairMethod::DYNAMIC_PIN;
    dyn_pin.out_channels = std::vector<std::string>{"display"};
    dyn_pin.min_pin_length = 6;
    msg.supported_pair_methods.push_back(std::move(dyn_pin));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    EXPECT_STREQ(methods[0]["method"], "dynamic_pin");

    // out_channels
    JsonArrayConst ch = methods[0]["out_channels"].as<JsonArrayConst>();
    ASSERT_EQ(ch.size(), 1u);
    EXPECT_STREQ(ch[0], "display");

    // min_pin_length
    EXPECT_EQ(methods[0]["min_pin_length"].as<int>(), 6);

    // locked_out must be absent when not set.
    EXPECT_TRUE(methods[0]["locked_out"].isNull());
}

TEST(DynamicPin, ClientHelloDynamicPinLockedOutField) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor dyn_pin;
    dyn_pin.method = SendspinPairMethod::DYNAMIC_PIN;
    dyn_pin.out_channels = std::vector<std::string>{"display"};
    dyn_pin.locked_out = true;
    dyn_pin.min_pin_length = 6;
    msg.supported_pair_methods.push_back(std::move(dyn_pin));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    EXPECT_TRUE(methods[0]["locked_out"].as<bool>());
}

// A descriptor with locked_out explicitly false emits "locked_out": false on the wire
// (not omitted), matching the reference where a PIN method always carries the field.
TEST(DynamicPin, ClientHelloDynamicPinLockedOutFalseField) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor dyn_pin;
    dyn_pin.method = SendspinPairMethod::DYNAMIC_PIN;
    dyn_pin.out_channels = std::vector<std::string>{"display"};
    dyn_pin.locked_out = false;
    dyn_pin.min_pin_length = 6;
    msg.supported_pair_methods.push_back(std::move(dyn_pin));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    ASSERT_FALSE(methods[0]["locked_out"].isNull()) << "locked_out must be present when set";
    EXPECT_FALSE(methods[0]["locked_out"].as<bool>());
}

// ============================================================================
// Phase 8c: static-PIN wire messages
// ============================================================================

// format_client_pair_init_message() (no-arg overload): static PIN sends an EMPTY payload
// object, no commit_B. Mirrors ClientPairInitPayload() with omit_none in the reference
// (aiosendspin/noise/models.py ClientPairInitPayload, ~lines 138-147) and
// run_static_pin_client's `ClientPairInitMessage(payload=ClientPairInitPayload())`
// (aiosendspin/noise/pairing.py, ~line 285).
TEST(StaticPin, FormatClientPairInitEmptyWireShape) {
    const std::string out = format_client_pair_init_message();

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out))
        << "format_client_pair_init (static) produced invalid JSON";

    EXPECT_STREQ(doc["type"], "client/pair-init");

    ASSERT_TRUE(doc["payload"].is<JsonObjectConst>());
    JsonObjectConst payload_obj = doc["payload"].as<JsonObjectConst>();
    EXPECT_EQ(payload_obj.size(), 0u) << "static client/pair-init payload must be an empty object";
    EXPECT_TRUE(doc["payload"]["commit_B"].isUnbound()) << "commit_B must be absent for static PIN";
}

// format_client_pair_confirm_message() (client_kc-only overload): static PIN carries client_kc
// but NO nonce_B. Mirrors ClientPairConfirmPayload with nonce_B omitted (aiosendspin/noise/models.py
// ClientPairConfirmPayload, ~lines 225-236) and run_static_pin_client's
// `ClientPairConfirmMessage(payload=ClientPairConfirmPayload(client_kc=...))`
// (aiosendspin/noise/pairing.py, ~line 298).
TEST(StaticPin, FormatClientPairConfirmNoNonceWireShape) {
    std::array<uint8_t, 64> client_kc{};
    for (int i = 0; i < 64; ++i) client_kc[i] = static_cast<uint8_t>(i + 5);

    const std::string out = format_client_pair_confirm_message(client_kc);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out))
        << "format_client_pair_confirm (static) produced invalid JSON";

    EXPECT_STREQ(doc["type"], "client/pair-confirm");

    ASSERT_TRUE(doc["payload"]["client_kc"].is<const char*>());
    const std::string kc_b64 = doc["payload"]["client_kc"].as<std::string>();
    EXPECT_EQ(kc_b64.size(), 86u) << "base64url of 64 bytes without padding is 86 chars";

    auto decoded = b64url_decode(kc_b64);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 64u);
    for (size_t i = 0; i < 64; ++i) {
        EXPECT_EQ((*decoded)[i], client_kc[i]) << "client_kc mismatch at index " << i;
    }

    EXPECT_TRUE(doc["payload"]["nonce_B"].isUnbound()) << "nonce_B must be absent for static PIN";
}

// ============================================================================
// Phase 8c: client/hello static_pin method descriptor fields
// ============================================================================

// Reference _pair_method_descriptor: static_pin carries neither out_channels nor
// min_pin_length (those are set only for DYNAMIC_PIN); only method + locked_out.
TEST(StaticPin, ClientHelloStaticPinDescriptorShape) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor static_pin_desc;
    static_pin_desc.method = SendspinPairMethod::STATIC_PIN;
    static_pin_desc.locked_out = false;
    msg.supported_pair_methods.push_back(std::move(static_pin_desc));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    EXPECT_STREQ(methods[0]["method"], "static_pin");

    // locked_out must be present (set to false).
    ASSERT_FALSE(methods[0]["locked_out"].isNull()) << "locked_out must be present when set";
    EXPECT_FALSE(methods[0]["locked_out"].as<bool>());

    // out_channels and min_pin_length must be absent for static_pin.
    EXPECT_TRUE(methods[0]["out_channels"].isUnbound());
    EXPECT_TRUE(methods[0]["min_pin_length"].isUnbound());
}

TEST(StaticPin, ClientHelloStaticPinLockedOutTrue) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor static_pin_desc;
    static_pin_desc.method = SendspinPairMethod::STATIC_PIN;
    static_pin_desc.locked_out = true;
    msg.supported_pair_methods.push_back(std::move(static_pin_desc));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    EXPECT_TRUE(methods[0]["locked_out"].as<bool>());
}

// ============================================================================
// Phase 8c: CPace round-trip using the static-PIN SID construction
// ============================================================================

// The static-PIN SID construction is identical to dynamic PIN's (see make_test_sid() above);
// only the PRS source differs (a preconfigured static PIN vs a derived one). This exercises
// the client (RESPONDER) against a stand-in server (INITIATOR) using the SAME 8-digit PIN.
TEST(StaticPinCPace, RoundTripWithMatchingStaticPin) {
    const auto sid = make_test_sid();
    const auto prs = to_bytes("13572468");  // 8 decimal digits, per STATIC_PIN_DIGITS.
    const std::vector<uint8_t> empty;

    CPace initiator;  // Stand-in for the server.
    ASSERT_TRUE(initiator.start(CPaceRole::INITIATOR, prs, sid, empty, empty, empty));
    const auto& share_a = initiator.public_share();

    CPace responder;  // The client, per handle_pairing_window_confirmed().
    ASSERT_TRUE(responder.start(CPaceRole::RESPONDER, prs, sid, empty, empty, empty));
    const auto& share_b = responder.public_share();

    ASSERT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    ASSERT_TRUE(responder.derive(share_a.data(), share_a.size()));

    auto tag_a = initiator.tag();
    auto tag_b = responder.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    EXPECT_TRUE(initiator.verify(tag_b->data(), tag_b->size()));
    EXPECT_TRUE(responder.verify(tag_a->data(), tag_a->size()));
}

TEST(StaticPinCPace, RoundTripMismatchedStaticPinFails) {
    const auto sid = make_test_sid();
    const auto prs_a = to_bytes("13572468");
    const auto prs_b = to_bytes("99999999");
    const std::vector<uint8_t> empty;

    CPace initiator;
    ASSERT_TRUE(initiator.start(CPaceRole::INITIATOR, prs_a, sid, empty, empty, empty));

    CPace responder;
    ASSERT_TRUE(responder.start(CPaceRole::RESPONDER, prs_b, sid, empty, empty, empty));

    const auto& share_a = initiator.public_share();
    const auto& share_b = responder.public_share();

    ASSERT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    ASSERT_TRUE(responder.derive(share_a.data(), share_a.size()));

    auto tag_a = initiator.tag();
    auto tag_b = responder.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    EXPECT_FALSE(initiator.verify(tag_b->data(), tag_b->size()));
    EXPECT_FALSE(responder.verify(tag_a->data(), tag_a->size()));
}
