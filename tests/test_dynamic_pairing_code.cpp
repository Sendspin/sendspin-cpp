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

// ============================================================================
// Helpers
// ============================================================================

/// Parse a JSON string into doc+root.  Returns false on malformed JSON.
bool parse(const std::string& json, JsonDocument& doc, JsonObject& root) {
    if (deserializeJson(doc, json)) {
        return false;
    }
    root = doc.as<JsonObject>();
    return true;
}

/// Runs one row of a parser's malformed-payload table: `json` must be valid JSON, and `parse_fn`
/// must accept or reject it as `expect_ok` says.
template <typename Payload>
void expect_parse(bool (*parse_fn)(JsonObject, Payload*), const std::string& json,
                  bool expect_ok) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    Payload payload;
    EXPECT_EQ(parse_fn(root, &payload), expect_ok);
}

/// A row of one parser's malformed-payload table.
struct ParseRow {
    const char* name;
    std::string json;
    bool expect_ok;
};

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

// The server/pair-init parser's malformed-field family. A field that is present and unusable is
// the malformed case; a field that is absent is a different rule, covered by the
// ...YieldsNoNonce tests below.
TEST(DynamicPairingCode, ParseServerPairInitRejectsMalformedNonce) {
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 16> short_nonce{};

    const ParseRow rows[] = {
        {"nonce_A-not-a-string", R"({"type":"server/pair-init","payload":{"nonce_A":5}})", false},
        {"nonce_A-16-bytes", make_pair_init_json(b64url(short_nonce)), false},
        {"nonce_A-not-base64",
         R"({"type":"server/pair-init","payload":{"nonce_A":"!!!not_base64!!!"}})", false},
        // Control: a 32-byte base64url nonce_A.
        {"nonce_A-well-formed", make_pair_init_json(b64url(nonce_a)), true},
    };
    for (const ParseRow& row : rows) {
        SCOPED_TRACE(row.name);
        expect_parse<ServerPairInitPayload>(process_server_pair_init_message, row.json,
                                            row.expect_ok);
    }

    // The accepted nonce reaches the payload unchanged.
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(make_pair_init_json(b64url(nonce_a)), doc, root));
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

// An unrecognized extra field alongside nonce_A is ignored, and the field beside it survives
// into the payload rather than being dropped along with the one that was not recognized.
TEST(DynamicPairingCode, ParseServerPairInitExtraFieldIgnored) {
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(0xA0 + i);
    const std::string json =
        std::string(R"({"type":"server/pair-init","payload":{"nonce_A":")") + b64url(nonce_a) +
        R"(","unrecognized_field":6}})";

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));
    EXPECT_EQ(payload.nonce_a, nonce_a);
}

// An explicit JSON null is how a serializer writes a field it has nothing for, so it must mean
// the same as leaving it out (the retry-round shape) rather than being rejected.
TEST(DynamicPairingCode, ParseServerPairInitNullNonceYieldsNoNonce) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/pair-init","payload":{"nonce_A":null}})", doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));
    EXPECT_FALSE(payload.nonce_a.has_value());
}

// Same for a message with no payload object at all: nonce_A is the only field it would carry,
// and a retry round has nothing to put there.
TEST(DynamicPairingCode, ParseServerPairInitWithoutPayloadYieldsNoNonce) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/pair-init"})", doc, root));

    ServerPairInitPayload payload;
    ASSERT_TRUE(process_server_pair_init_message(root, &payload));
    EXPECT_FALSE(payload.nonce_a.has_value());
}

// ============================================================================
// process_server_pair_auth_message
// ============================================================================

// The server/pair-auth parser's malformed-field family over its single required field.
TEST(DynamicPairingCode, ParseServerPairAuthRejectsMalformedPakeMsg1) {
    std::array<uint8_t, 32> pake_msg_1{};
    for (int i = 0; i < 32; ++i) pake_msg_1[i] = static_cast<uint8_t>(i + 10);
    std::array<uint8_t, 16> short_share{};

    const ParseRow rows[] = {
        {"pake_msg_1-missing", R"({"type":"server/pair-auth","payload":{}})", false},
        {"pake_msg_1-16-bytes", make_pair_auth_json(b64url(short_share)), false},
        {"pake_msg_1-not-base64",
         R"({"type":"server/pair-auth","payload":{"pake_msg_1":"!!!not_valid!!!"}})", false},
        // Control: a 32-byte base64url pake_msg_1.
        {"pake_msg_1-well-formed", make_pair_auth_json(b64url(pake_msg_1)), true},
    };
    for (const ParseRow& row : rows) {
        SCOPED_TRACE(row.name);
        expect_parse<ServerPairAuthPayload>(process_server_pair_auth_message, row.json,
                                            row.expect_ok);
    }

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(make_pair_auth_json(b64url(pake_msg_1)), doc, root));
    ServerPairAuthPayload payload;
    ASSERT_TRUE(process_server_pair_auth_message(root, &payload));
    EXPECT_EQ(payload.pake_msg_1, pake_msg_1);
}

// ============================================================================
// process_server_pair_confirm_message
// ============================================================================

// The server/pair-confirm parser's malformed-field family; server_kc is 64 bytes, not 32.
TEST(DynamicPairingCode, ParseServerPairConfirmRejectsMalformedServerKc) {
    std::array<uint8_t, 64> server_kc{};
    for (int i = 0; i < 64; ++i) server_kc[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 32> short_kc{};

    const ParseRow rows[] = {
        {"server_kc-missing", R"({"type":"server/pair-confirm","payload":{}})", false},
        {"server_kc-32-bytes", make_pair_confirm_json(b64url(short_kc)), false},
        {"server_kc-not-base64",
         R"({"type":"server/pair-confirm","payload":{"server_kc":"!!!not_valid!!!"}})", false},
        // Control: a 64-byte base64url server_kc.
        {"server_kc-well-formed", make_pair_confirm_json(b64url(server_kc)), true},
    };
    for (const ParseRow& row : rows) {
        SCOPED_TRACE(row.name);
        expect_parse<ServerPairConfirmPayload>(process_server_pair_confirm_message, row.json,
                                               row.expect_ok);
    }

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(make_pair_confirm_json(b64url(server_kc)), doc, root));
    ServerPairConfirmPayload payload;
    ASSERT_TRUE(process_server_pair_confirm_message(root, &payload));
    EXPECT_EQ(payload.server_kc, server_kc);
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

    // commit_B must be a 43-char unpadded base64url string.
    ASSERT_TRUE(doc["payload"]["commit_B"].is<const char*>());
    const std::string commit_b64 = doc["payload"]["commit_B"].as<std::string>();
    EXPECT_EQ(commit_b64.size(), 43u) << "base64url of 32 bytes without padding is 43 chars";

    auto decoded = b64url_decode(commit_b64);
    ASSERT_TRUE(decoded.has_value()) << "commit_B is not valid base64url";
    ASSERT_EQ(decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*decoded)[i], commit_b[i]) << "decoded byte mismatch at index " << i;
    }

    // pairing_index is required on every client/pair-init (pairing.md "Pairing index").
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
// CPace associated-data binding
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

static std::vector<uint8_t> to_bytes(const char* s) {
    const size_t len = std::strlen(s);
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + len);
}

// ADa = "server" (initiator's own AD), ADb = "client" (responder's own AD); per pairing.md "PAKE".
static std::vector<uint8_t> ad_server() {
    return to_bytes("server");
}
static std::vector<uint8_t> ad_client() {
    return to_bytes("client");
}

}  // namespace

TEST(DynamicPairingCodeCPace, MismatchedAssociatedDataFailsVerify) {
    // Distinct ADa/ADb values prevent a reflected-MAC issue (pairing.md "PAKE"): if a side uses the
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
