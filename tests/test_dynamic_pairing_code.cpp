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

// Pairing-code unit tests for both code-based methods: wire messages and the CPace
// round-trip over the sid and associated data pairing.md "PAKE" defines.

#include "crypto/cpace.h"
#include "crypto/psk_wrap.h"
#include "platform/base64.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/persistence_codec.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

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

/// Parses `json` and asserts that `parse_fn` rejects it. Collapses the malformed-payload
/// rejection tests below to their JSON literal.
template <typename Payload>
void expect_parse_rejects(bool (*parse_fn)(JsonObject, Payload*), const std::string& json) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    Payload payload;
    EXPECT_FALSE(parse_fn(root, &payload));
}

/// base64url-encode a fixed-size array for building test JSON strings.
template <size_t N>
static std::string b64url(const std::array<uint8_t, N>& a) {
    return b64url_encode(a.data(), a.size());
}

/// Build the wire JSON for server/pair-init from raw values. The payload carries ONLY nonce_A
/// (the emission format arrives in the activation's pairing object).
static std::string make_pair_init_json(const std::string& nonce_a_b64) {
    return std::string(R"({"type":"server/pair-init","payload":{"nonce_A":")") + nonce_a_b64 +
           R"("}})";
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

// Control: the same parser accepts a well-formed server/pair-init, so each rejection below is the
// field it names and not the parser refusing everything.
TEST(DynamicPairingCode, ParseServerPairInitValid) {
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);

    const std::string json = make_pair_init_json(b64url(nonce_a));

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));

    EXPECT_EQ(payload.nonce_a, nonce_a);
}

// A retry round's server/pair-init carries no nonce_A: the binding values do not move between
// rounds (pairing.md "Rounds"), so an absent field parses to an absent value rather than being
// rejected. Which rounds may omit it is the state machine's business, not the parser's.
TEST(DynamicPairingCode, ParseServerPairInitWithoutNonceYieldsNoNonce) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/pair-init","payload":{}})", doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));
    EXPECT_FALSE(payload.nonce_a.has_value());
}

// An unrecognized extra field alongside nonce_A parses fine: it is simply ignored.
TEST(DynamicPairingCode, ParseServerPairInitExtraFieldIgnored) {
    std::array<uint8_t, 32> nonce_a{};
    const std::string json =
        std::string(R"({"type":"server/pair-init","payload":{"nonce_A":")") + b64url(nonce_a) +
        R"(","unrecognized_field":6}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    EXPECT_TRUE(process_server_pair_init_message(root, &payload));
}

TEST(DynamicPairingCode, ParseServerPairInitWrongNonceLength) {
    // Encode only 16 bytes (wrong size).
    std::array<uint8_t, 16> short_nonce{};
    const std::string nonce_b64 = b64url_encode(short_nonce.data(), short_nonce.size());
    expect_parse_rejects<ServerPairInitPayload>(process_server_pair_init_message,
                                                 make_pair_init_json(nonce_b64));
}

TEST(DynamicPairingCode, ParseServerPairInitInvalidBase64) {
    expect_parse_rejects<ServerPairInitPayload>(
        process_server_pair_init_message,
        R"({"type":"server/pair-init","payload":{"nonce_A":"!!!not_base64!!!"}})");
}

// ============================================================================
// process_server_pair_auth_message
// ============================================================================

// Control: the same parser accepts a well-formed server/pair-auth, so each rejection below is the
// field it names and not the parser refusing everything.
TEST(DynamicPairingCode, ParseServerPairAuthValid) {
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

TEST(DynamicPairingCode, ParseServerPairAuthMissingField) {
    expect_parse_rejects<ServerPairAuthPayload>(process_server_pair_auth_message,
                                                 R"({"type":"server/pair-auth","payload":{}})");
}

TEST(DynamicPairingCode, ParseServerPairAuthWrongFieldLength) {
    // 16 bytes instead of 32.
    std::array<uint8_t, 16> short_share{};
    const std::string b64 = b64url_encode(short_share.data(), short_share.size());
    expect_parse_rejects<ServerPairAuthPayload>(process_server_pair_auth_message,
                                                 make_pair_auth_json(b64));
}

TEST(DynamicPairingCode, ParseServerPairAuthInvalidBase64) {
    expect_parse_rejects<ServerPairAuthPayload>(
        process_server_pair_auth_message,
        R"({"type":"server/pair-auth","payload":{"pake_msg_1":"!!!not_valid!!!"}})");
}

// ============================================================================
// process_server_pair_confirm_message
// ============================================================================

// Control: the same parser accepts a well-formed server/pair-confirm, so each rejection below is the
// field it names and not the parser refusing everything.
TEST(DynamicPairingCode, ParseServerPairConfirmValid) {
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

TEST(DynamicPairingCode, ParseServerPairConfirmMissingField) {
    expect_parse_rejects<ServerPairConfirmPayload>(
        process_server_pair_confirm_message, R"({"type":"server/pair-confirm","payload":{}})");
}

TEST(DynamicPairingCode, ParseServerPairConfirmWrongFieldLength) {
    // 32 bytes instead of 64.
    std::array<uint8_t, 32> short_kc{};
    const std::string b64 = b64url_encode(short_kc.data(), short_kc.size());
    expect_parse_rejects<ServerPairConfirmPayload>(process_server_pair_confirm_message,
                                                    make_pair_confirm_json(b64));
}

TEST(DynamicPairingCode, ParseServerPairConfirmInvalidBase64) {
    expect_parse_rejects<ServerPairConfirmPayload>(
        process_server_pair_confirm_message,
        R"({"type":"server/pair-confirm","payload":{"server_kc":"!!!not_valid!!!"}})");
}

// ============================================================================
// format_client_pair_init_message
// ============================================================================

TEST(DynamicPairingCode, FormatClientPairInitWireShape) {
    std::array<uint8_t, 32> commit_b{};
    for (int i = 0; i < 32; ++i) commit_b[i] = static_cast<uint8_t>(i);

    const std::string out = format_client_pair_init_message(commit_b, /*pairing_index=*/3);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out)) << "format_client_pair_init produced invalid JSON";

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

    // pairing_index is required on every client/pair-init (spec "Pairing index").
    ASSERT_TRUE(doc["payload"]["pairing_index"].is<uint32_t>());
    EXPECT_EQ(doc["payload"]["pairing_index"].as<uint32_t>(), 3u);
}

// ============================================================================
// format_client_pair_auth_message
// ============================================================================

TEST(DynamicPairingCode, FormatClientPairAuthWireShape) {
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

TEST(DynamicPairingCode, FormatClientPairConfirmWireShape) {
    std::array<uint8_t, 64> client_kc{};
    std::array<uint8_t, WRAPPED_VALUE_SIZE> wrapped_nonce{};
    for (int i = 0; i < 64; ++i) client_kc[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < wrapped_nonce.size(); ++i) {
        wrapped_nonce[i] = static_cast<uint8_t>(i + 100);
    }

    const std::string out = format_client_pair_confirm_message(client_kc, wrapped_nonce);

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

    // wrapped_nonce_B: 48 bytes -> 64-char base64url without padding (pairing.md
    // "Client -> Server: client/pair-confirm"). The unwrapped field name must never appear:
    // the opening only ever crosses the wire sealed.
    EXPECT_TRUE(doc["payload"]["nonce_B"].isUnbound());
    ASSERT_TRUE(doc["payload"]["wrapped_nonce_B"].is<const char*>());
    const std::string nb_b64 = doc["payload"]["wrapped_nonce_B"].as<std::string>();
    EXPECT_EQ(nb_b64.size(), 64u);

    auto nb_decoded = b64url_decode(nb_b64);
    ASSERT_TRUE(nb_decoded.has_value());
    ASSERT_EQ(nb_decoded->size(), WRAPPED_VALUE_SIZE);
    for (size_t i = 0; i < WRAPPED_VALUE_SIZE; ++i) {
        EXPECT_EQ((*nb_decoded)[i], wrapped_nonce[i]) << "wrapped_nonce_B mismatch at index " << i;
    }
}

// ============================================================================
// CPace INITIATOR + RESPONDER round-trip with shared password
// ============================================================================

namespace {

// Build a sid = "sendspin-pair-pake-v1" (21 bytes) || 32 zero bytes || 4-byte BE pairing_index
// || 4-byte BE round (pairing.md "PAKE").
static std::vector<uint8_t> make_test_sid(uint32_t pairing_index = 0, uint32_t round = 1) {
    const char* prefix = "sendspin-pair-pake-v1";
    const size_t prefix_len = 21;
    std::vector<uint8_t> sid(prefix_len + 32, 0);
    std::memcpy(sid.data(), prefix, prefix_len);
    for (uint32_t counter : {pairing_index, round}) {
        sid.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        sid.push_back(static_cast<uint8_t>(counter & 0xFF));
    }
    return sid;
}

// Convert a C string to a byte vector for CPace API calls.
static std::vector<uint8_t> to_bytes(const char* s) {
    const size_t len = std::strlen(s);
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + len);
}

// ADa = "server" (initiator's own AD), ADb = "client" (responder's own AD); per spec "PAKE".
static std::vector<uint8_t> ad_server() {
    return to_bytes("server");
}
static std::vector<uint8_t> ad_client() {
    return to_bytes("client");
}

/// What the round-trip pairs below need from a CPace(INITIATOR)/CPace(RESPONDER) exchange, with
/// the correct ADa="server"/ADb="client" association: whether each side's confirmation tag
/// verifies against the other's, plus the derived ISK/sid (only the matching-password tests
/// check these, per PSK Wrapping).
struct CPaceRoundTripResult {
    bool verify_ab{false};  // initiator.verify(tag_b)
    bool verify_ba{false};  // responder.verify(tag_a)
    std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> isk_a;
    std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> isk_b;
    std::vector<uint8_t> initiator_sid;
};

// Runs a full CPace INITIATOR/RESPONDER exchange (start, cross-derive, tag, verify) with the
// standard ADa="server"/ADb="client" association, differing only in the PRS each side uses and
// the shared sid. The matching-vs-mismatched distinction under test lives entirely in the
// returned verify_ab/verify_ba, which callers assert on themselves.
static CPaceRoundTripResult run_cpace_round_trip(const std::vector<uint8_t>& prs_a,
                                                  const std::vector<uint8_t>& prs_b,
                                                  const std::vector<uint8_t>& sid) {
    const std::vector<uint8_t> empty;

    CPace initiator;
    EXPECT_TRUE(initiator.start(CPaceRole::INITIATOR, prs_a, sid, empty, ad_server(), ad_client()));
    const auto& share_a = initiator.public_share();

    CPace responder;
    EXPECT_TRUE(responder.start(CPaceRole::RESPONDER, prs_b, sid, empty, ad_client(), ad_server()));
    const auto& share_b = responder.public_share();

    EXPECT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    EXPECT_TRUE(responder.derive(share_a.data(), share_a.size()));

    auto tag_a = initiator.tag();
    auto tag_b = responder.tag();
    EXPECT_TRUE(tag_a.has_value());
    EXPECT_TRUE(tag_b.has_value());

    CPaceRoundTripResult result;
    if (tag_a.has_value() && tag_b.has_value()) {
        result.verify_ab = initiator.verify(tag_b->data(), tag_b->size());
        result.verify_ba = responder.verify(tag_a->data(), tag_a->size());
    }
    result.isk_a = initiator.isk();
    result.isk_b = responder.isk();
    result.initiator_sid = initiator.sid();
    return result;
}

}  // namespace

TEST(DynamicPairingCodeCPace, RoundTripWithMatchingPassword) {
    const auto sid = make_test_sid(/*pairing_index=*/1);
    const auto prs = to_bytes("123456");

    // Initiator (A = server role in the protocol) and responder (B = client role in the
    // protocol) share the same password.
    auto result = run_cpace_round_trip(prs, prs, sid);

    // Both sides produce a tag; each side can verify the other's.
    EXPECT_TRUE(result.verify_ab);
    EXPECT_TRUE(result.verify_ba);

    // Both sides agree on ISK and sid, needed for the wrapping (pairing.md "Wrapping").
    ASSERT_TRUE(result.isk_a.has_value());
    ASSERT_TRUE(result.isk_b.has_value());
    EXPECT_EQ(result.isk_a.value(), result.isk_b.value());
    EXPECT_EQ(result.initiator_sid, sid);
}

TEST(DynamicPairingCodeCPace, RoundTripMismatchedPasswordFails) {
    const auto sid = make_test_sid();
    const auto prs_a = to_bytes("123456");
    const auto prs_b = to_bytes("999999");

    auto result = run_cpace_round_trip(prs_a, prs_b, sid);

    // With mismatched passwords, verification must fail.
    EXPECT_FALSE(result.verify_ab);
    EXPECT_FALSE(result.verify_ba);
}

TEST(DynamicPairingCodeCPace, MismatchedAssociatedDataFailsVerify) {
    // Distinct ADa/ADb values prevent a reflected-MAC issue (spec "PAKE"): if a side uses the
    // WRONG associated data (e.g. swapped, or both sides use the same AD instead of distinct
    // "server"/"client" values), confirmation must fail even with a matching password.
    const auto sid = make_test_sid();
    const auto prs = to_bytes("123456");
    const std::vector<uint8_t> empty;

    CPace initiator;
    // Bug: initiator uses "client" as its own AD instead of "server".
    ASSERT_TRUE(initiator.start(CPaceRole::INITIATOR, prs, sid, empty, ad_client(), ad_client()));

    CPace responder;
    ASSERT_TRUE(responder.start(CPaceRole::RESPONDER, prs, sid, empty, ad_client(), ad_server()));

    const auto& share_a = initiator.public_share();
    const auto& share_b = responder.public_share();

    ASSERT_TRUE(initiator.derive(share_b.data(), share_b.size()));
    ASSERT_TRUE(responder.derive(share_a.data(), share_a.size()));

    auto tag_a = initiator.tag();
    ASSERT_TRUE(tag_a.has_value());

    // The responder expects the initiator's tag to authenticate (Ya, ADa="server"), but the
    // initiator signed (Ya, ADa="client") instead, so verification must fail.
    EXPECT_FALSE(responder.verify(tag_a->data(), tag_a->size()));
}

// ============================================================================
// client/hello dynamic_pairing_code descriptor fields
// ============================================================================

// pairing.md "client/hello pair-method descriptor": the dynamic descriptor carries
// out_channels and formats, both required and non-empty, and no locations hint.
TEST(DynamicPairingCode, ClientHelloDescriptorCarriesChannelsAndFormats) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor dynamic_desc;
    dynamic_desc.method = SendspinPairMethod::DYNAMIC_PAIRING_CODE;
    dynamic_desc.out_channels = std::vector<SendspinPairingCodeChannel>{
        SendspinPairingCodeChannel::DISPLAY, SendspinPairingCodeChannel::SPEAKER};
    dynamic_desc.formats = std::vector<SendspinPairingCodeFormat>{
        SendspinPairingCodeFormat::DIGITS, SendspinPairingCodeFormat::QR_CODE};
    msg.supported_pair_methods.push_back(std::move(dynamic_desc));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonObjectConst methods = doc["payload"]["supported_pair_methods"].as<JsonObjectConst>();
    ASSERT_EQ(methods.size(), 1u);
    JsonVariantConst descriptor = methods["dynamic_pairing_code"];
    ASSERT_FALSE(descriptor.isUnbound());

    JsonArrayConst ch = descriptor["out_channels"].as<JsonArrayConst>();
    ASSERT_EQ(ch.size(), 2u);
    EXPECT_STREQ(ch[0], "display");
    EXPECT_STREQ(ch[1], "speaker");

    JsonArrayConst formats = descriptor["formats"].as<JsonArrayConst>();
    ASSERT_EQ(formats.size(), 2u);
    EXPECT_STREQ(formats[0], "digits");
    EXPECT_STREQ(formats[1], "qr_code");

    // locations is a static_pairing_code / pairing_psk hint: a per-session code has no resting
    // place for the operator to look it up in, so the dynamic descriptor never carries one.
    EXPECT_TRUE(descriptor["locations"].isUnbound());
}

// ============================================================================
// client/hello static_pairing_code descriptor fields
// ============================================================================

// The static descriptor carries neither out_channels nor formats (those belong to the dynamic
// method); its only optional hint is locations.
TEST(StaticPairingCode, ClientHelloDescriptorShape) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor static_desc;
    static_desc.method = SendspinPairMethod::STATIC_PAIRING_CODE;
    msg.supported_pair_methods.push_back(std::move(static_desc));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonObjectConst methods = doc["payload"]["supported_pair_methods"].as<JsonObjectConst>();
    ASSERT_EQ(methods.size(), 1u);
    JsonVariantConst descriptor = methods["static_pairing_code"];
    ASSERT_FALSE(descriptor.isUnbound());

    EXPECT_TRUE(descriptor["out_channels"].isUnbound());
    EXPECT_TRUE(descriptor["formats"].isUnbound());
    EXPECT_TRUE(descriptor["locations"].isUnbound());
}

// The locations hint ('device' | 'leaflet' | 'operator') serializes for static_pairing_code (and
// pairing_psk) descriptors that set it.
TEST(StaticPairingCode, ClientHelloLocationsHint) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor static_desc;
    static_desc.method = SendspinPairMethod::STATIC_PAIRING_CODE;
    static_desc.locations = std::vector<std::string>{"device", "leaflet"};
    msg.supported_pair_methods.push_back(std::move(static_desc));

    const std::string out = format_client_hello_message(&msg);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));

    JsonObjectConst methods = doc["payload"]["supported_pair_methods"].as<JsonObjectConst>();
    ASSERT_EQ(methods.size(), 1u);
    JsonArrayConst locations = methods["static_pairing_code"]["locations"].as<JsonArrayConst>();
    ASSERT_EQ(locations.size(), 2u);
    EXPECT_STREQ(locations[0], "device");
    EXPECT_STREQ(locations[1], "leaflet");
}

// ============================================================================
// CPace round-trip using the static pairing-code sid construction
// ============================================================================

// The static pairing-code sid construction is identical to dynamic pairing code's (see make_test_sid() above);
// only the PRS source differs (a preconfigured static pairing code vs a derived one). This exercises
// the client (RESPONDER) against a stand-in server (INITIATOR) using the SAME 8-digit code.
TEST(StaticPairingCodeCPace, RoundTripWithMatchingStaticCode) {
    const auto sid = make_test_sid();
    const auto prs = to_bytes("13572468");  // 8 decimal digits, per STATIC_PAIRING_CODE_DIGITS.

    // Initiator stands in for the server; responder is the client, per
    // handle_pairing_window_confirmed().
    auto result = run_cpace_round_trip(prs, prs, sid);

    EXPECT_TRUE(result.verify_ab);
    EXPECT_TRUE(result.verify_ba);
}

TEST(StaticPairingCodeCPace, RoundTripMismatchedStaticCodeFails) {
    const auto sid = make_test_sid();
    const auto prs_a = to_bytes("13572468");
    const auto prs_b = to_bytes("99999999");

    auto result = run_cpace_round_trip(prs_a, prs_b, sid);

    EXPECT_FALSE(result.verify_ab);
    EXPECT_FALSE(result.verify_ba);
}
