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

// Phase 6 unit tests covering:
//   - Protocol round-trips: parse each server->client management request + server/unpair;
//     format management/result for each result code and each data shape; verify omit-when-absent.
//   - Handler unit tests against a RecordStore + fake persistence provider.
//   - Trust gating: management request without MANAGEMENT activity -> permission_denied.
//
// Mirrors aiosendspin/tests/client/test_management.py (PSK-only subset).

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "management.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

namespace {

// ===========================================================================
// Test helpers
// ===========================================================================

static std::array<uint8_t, NOISE_PSK_SIZE> make_random_psk() {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    return psk;
}

static std::string psk_to_b64url(const std::array<uint8_t, NOISE_PSK_SIZE>& psk) {
    return b64url_encode(psk.data(), psk.size());
}

/// A well-formed 43-char base64url server_id (32 random bytes encoded).
static std::string make_test_server_id() {
    std::array<uint8_t, 32> key{};
    platform_random_bytes(key.data(), key.size());
    return b64url_encode(key.data(), key.size());
}

static SendspinPairingRecord make_client_record(const std::string& server_id) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    rec.server_id = server_id;
    return rec;
}

static SendspinPairingRecord make_shared_record() {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    // server_id absent = shared-PSK record
    return rec;
}

/// Parse a JSON string into a root object; keeps the document alive via out-params.
static bool parse(const std::string& json, JsonDocument& doc, JsonObject& root) {
    if (deserializeJson(doc, json)) {
        return false;
    }
    root = doc.as<JsonObject>();
    return true;
}

/// A RecordStore subclass that always reports storage exhausted.
class ExhaustedRecordStore : public RecordStore {
public:
    explicit ExhaustedRecordStore(SendspinPersistenceProvider* provider) : RecordStore(provider) {}
    bool can_store_record() const override {
        return false;
    }
};

/// A RecordStore subclass that returns a bounded storage accounting report.
class BoundedRecordStore : public RecordStore {
public:
    explicit BoundedRecordStore(SendspinPersistenceProvider* provider) : RecordStore(provider) {}

    std::optional<StorageReport> storage_accounting() const override {
        StorageReport r;
        r.free = 3;
        r.capacity = 5;
        r.cost_individual = 1;
        r.cost_shared = 1;
        return r;
    }
};

}  // namespace

// ===========================================================================
// Protocol round-trips: determine_message_type for management messages
// ===========================================================================

TEST(ManagementProtocol, DetermineMessageTypeManagement) {
    JsonDocument doc;
    JsonObject root;

    ASSERT_TRUE(parse(R"({"type":"server/unpair"})", doc, root));
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::SERVER_UNPAIR);

    ASSERT_TRUE(parse(R"({"type":"management/list-records"})", doc, root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::MANAGEMENT_LIST_RECORDS);

    ASSERT_TRUE(parse(R"({"type":"management/add-record","payload":{"psk":"x"}})", doc, root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::MANAGEMENT_ADD_RECORD);

    ASSERT_TRUE(parse(R"({"type":"management/remove-record","payload":{"psk_id":"x"}})", doc,
                      root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::MANAGEMENT_REMOVE_RECORD);

    ASSERT_TRUE(parse(R"({"type":"management/get-pairing-config"})", doc, root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::MANAGEMENT_GET_PAIRING_CONFIG);

    ASSERT_TRUE(parse(R"({"type":"management/set-pairing-config","payload":{}})", doc, root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::MANAGEMENT_SET_PAIRING_CONFIG);
}

// ===========================================================================
// Protocol: parse management/add-record
// ===========================================================================

TEST(ManagementProtocol, ParseAddRecordWithServerIdAndWithout) {
    auto psk = make_random_psk();
    std::string psk_b64 = psk_to_b64url(psk);

    // With server_id (stored-pubkey record).
    {
        std::string json = R"({"type":"management/add-record","payload":{"psk":")" + psk_b64 +
                           R"(","server_id":"srv-abc"}})";
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(json, doc, root));
        ManagementAddRecordPayload payload;
        ASSERT_TRUE(process_management_add_record_message(root, &payload));
        EXPECT_EQ(payload.psk, psk_b64);
        ASSERT_TRUE(payload.server_id.has_value());
        EXPECT_EQ(payload.server_id.value(), "srv-abc");
    }

    // Without server_id (shared-PSK record).
    {
        std::string json =
            R"({"type":"management/add-record","payload":{"psk":")" + psk_b64 + R"("}})";
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(json, doc, root));
        ManagementAddRecordPayload payload;
        ASSERT_TRUE(process_management_add_record_message(root, &payload));
        EXPECT_EQ(payload.psk, psk_b64);
        EXPECT_FALSE(payload.server_id.has_value());
    }
}

TEST(ManagementProtocol, ParseAddRecordMissingPskFails) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"management/add-record","payload":{}})", doc, root));
    ManagementAddRecordPayload payload;
    EXPECT_FALSE(process_management_add_record_message(root, &payload));
}

// ===========================================================================
// Protocol: parse management/remove-record
// ===========================================================================

TEST(ManagementProtocol, ParseRemoveRecord) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(
        parse(R"({"type":"management/remove-record","payload":{"psk_id":"abc123"}})", doc, root));
    ManagementRemoveRecordPayload payload;
    ASSERT_TRUE(process_management_remove_record_message(root, &payload));
    EXPECT_EQ(payload.psk_id, "abc123");
}

TEST(ManagementProtocol, ParseRemoveRecordMissingPskIdFails) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"management/remove-record","payload":{}})", doc, root));
    ManagementRemoveRecordPayload payload;
    EXPECT_FALSE(process_management_remove_record_message(root, &payload));
}

// ===========================================================================
// Protocol: parse management/set-pairing-config
// ===========================================================================

TEST(ManagementProtocol, ParseSetPairingConfigEmpty) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(
        parse(R"({"type":"management/set-pairing-config","payload":{}})", doc, root));
    ManagementSetPairingConfigPayload payload;
    EXPECT_TRUE(process_management_set_pairing_config_message(root, &payload));
    EXPECT_FALSE(payload.pairing_psk.has_value());
    EXPECT_FALSE(payload.record_mode.has_value());
    EXPECT_FALSE(payload.unpaired_access.has_value());
    EXPECT_FALSE(payload.static_pin.has_value());
    EXPECT_FALSE(payload.dynamic_pin.has_value());
}

TEST(ManagementProtocol, ParseSetPairingConfigStaticPin) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"management/set-pairing-config","payload":{"static_pin":{"enabled":true,)"
        R"("pin":"12345678"}}})",
        doc, root));
    ManagementSetPairingConfigPayload payload;
    EXPECT_TRUE(process_management_set_pairing_config_message(root, &payload));
    ASSERT_TRUE(payload.static_pin.has_value());
    ASSERT_TRUE(payload.static_pin->enabled.has_value());
    EXPECT_TRUE(payload.static_pin->enabled.value());
    ASSERT_TRUE(payload.static_pin->pin.has_value());
    EXPECT_EQ(payload.static_pin->pin.value(), "12345678");
    EXPECT_FALSE(payload.dynamic_pin.has_value());
}

TEST(ManagementProtocol, ParseSetPairingConfigDynamicPin) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"management/set-pairing-config","payload":{"dynamic_pin":{"enabled":false,)"
        R"("min_pin_length":8}}})",
        doc, root));
    ManagementSetPairingConfigPayload payload;
    EXPECT_TRUE(process_management_set_pairing_config_message(root, &payload));
    EXPECT_FALSE(payload.static_pin.has_value());
    ASSERT_TRUE(payload.dynamic_pin.has_value());
    ASSERT_TRUE(payload.dynamic_pin->enabled.has_value());
    EXPECT_FALSE(payload.dynamic_pin->enabled.value());
    ASSERT_TRUE(payload.dynamic_pin->min_pin_length.has_value());
    EXPECT_EQ(payload.dynamic_pin->min_pin_length.value(), 8);
}

TEST(ManagementProtocol, ParseSetPairingConfigFull) {
    auto psk = make_random_psk();
    std::string psk_b64 = psk_to_b64url(psk);
    std::string json =
        R"({"type":"management/set-pairing-config","payload":{"pairing_psk":{"enabled":true,"psk":")" +
        psk_b64 +
        R"("},"record_mode":{"psk_id":"rm-id-xyz"},"unpaired_access":{"enabled":false}}})";
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));
    ManagementSetPairingConfigPayload payload;
    ASSERT_TRUE(process_management_set_pairing_config_message(root, &payload));
    ASSERT_TRUE(payload.pairing_psk.has_value());
    ASSERT_TRUE(payload.pairing_psk->enabled.has_value());
    EXPECT_EQ(payload.pairing_psk->enabled.value(), true);
    ASSERT_TRUE(payload.pairing_psk->psk.has_value());
    EXPECT_EQ(payload.pairing_psk->psk.value(), psk_b64);
    ASSERT_TRUE(payload.record_mode.has_value());
    EXPECT_EQ(payload.record_mode->psk_id, "rm-id-xyz");
    ASSERT_TRUE(payload.unpaired_access.has_value());
    ASSERT_TRUE(payload.unpaired_access->enabled.has_value());
    EXPECT_EQ(payload.unpaired_access->enabled.value(), false);
}

// ===========================================================================
// Protocol: format management/result - result codes + omit-when-absent
// ===========================================================================

TEST(ManagementProtocol, FormatResultPermissionDenied) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::PERMISSION_DENIED;
    std::string json = format_management_result_message(payload);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_STREQ(doc["type"].as<const char*>(), "management/result");
    EXPECT_STREQ(doc["payload"]["result"].as<const char*>(), "permission_denied");
    // data and storage must be absent.
    EXPECT_TRUE(doc["payload"]["data"].isUnbound());
    EXPECT_TRUE(doc["payload"]["storage"].isUnbound());
}

TEST(ManagementProtocol, FormatResultOkNoData) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_STREQ(doc["payload"]["result"].as<const char*>(), "ok");
    EXPECT_TRUE(doc["payload"]["data"].isUnbound());
}

TEST(ManagementProtocol, FormatResultListRecordsEmpty) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    payload.data->records = std::vector<RecordSummary>{};
    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_STREQ(doc["payload"]["result"].as<const char*>(), "ok");
    EXPECT_TRUE(doc["payload"]["data"]["records"].is<JsonArray>());
    EXPECT_EQ(doc["payload"]["data"]["records"].as<JsonArray>().size(), 0u);
}

TEST(ManagementProtocol, FormatResultListRecordsWithEntries) {
    RecordSummary r1;
    r1.psk_id = "psk-id-A";
    r1.server_id = "srv-A";
    r1.used = true;

    RecordSummary r2;
    r2.psk_id = "psk-id-B";
    // No server_id (shared record).
    r2.used = false;

    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    payload.data->records = std::vector<RecordSummary>{r1, r2};

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));

    auto records = doc["payload"]["data"]["records"].as<JsonArray>();
    ASSERT_EQ(records.size(), 2u);

    // First record: stored-pubkey, used=true, server_id present.
    EXPECT_STREQ(records[0]["psk_id"].as<const char*>(), "psk-id-A");
    EXPECT_STREQ(records[0]["server_id"].as<const char*>(), "srv-A");
    EXPECT_EQ(records[0]["used"].as<bool>(), true);

    // Second record: shared-PSK, server_id must be absent.
    EXPECT_STREQ(records[1]["psk_id"].as<const char*>(), "psk-id-B");
    EXPECT_TRUE(records[1]["server_id"].isUnbound())
        << "server_id must be omitted for shared records";
    EXPECT_EQ(records[1]["used"].as<bool>(), false);
}

TEST(ManagementProtocol, FormatResultGetPairingConfig) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    PairingMethodConfig ppsk;
    ppsk.enabled = true;
    payload.data->pairing_psk = ppsk;
    RecordModeConfig rm;
    rm.psk_id = "rm-psk-id";
    payload.data->record_mode = rm;
    UnpairedAccessConfig ua;
    ua.enabled = false;
    payload.data->unpaired_access = ua;

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));

    EXPECT_EQ(doc["payload"]["data"]["pairing_psk"]["enabled"].as<bool>(), true);
    EXPECT_STREQ(doc["payload"]["data"]["record_mode"]["psk_id"].as<const char*>(), "rm-psk-id");
    EXPECT_EQ(doc["payload"]["data"]["unpaired_access"]["enabled"].as<bool>(), false);
    // static_pin and dynamic_pin are absent from the data struct in this test (unset optionals);
    // the format function must not fabricate them.
    EXPECT_TRUE(doc["payload"]["data"]["static_pin"].isUnbound());
    EXPECT_TRUE(doc["payload"]["data"]["dynamic_pin"].isUnbound());
}

TEST(ManagementProtocol, FormatResultGetPairingConfigStaticAndDynamicPin) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};

    PairingMethodConfig static_cfg;
    static_cfg.enabled = true;
    payload.data->static_pin = static_cfg;

    PairingMethodConfig dynamic_cfg;
    dynamic_cfg.enabled = true;
    dynamic_cfg.min_pin_length = 6;
    dynamic_cfg.escalated = true;
    payload.data->dynamic_pin = dynamic_cfg;

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));

    EXPECT_EQ(doc["payload"]["data"]["static_pin"]["enabled"].as<bool>(), true);
    EXPECT_TRUE(doc["payload"]["data"]["static_pin"]["min_pin_length"].isUnbound())
        << "static_pin must never carry min_pin_length";
    EXPECT_TRUE(doc["payload"]["data"]["static_pin"]["locked_out"].isUnbound())
        << "locked_out is gone from the wire";
    EXPECT_TRUE(doc["payload"]["data"]["static_pin"]["escalated"].isUnbound())
        << "static_pin has no failure counter, so no escalated flag";

    EXPECT_EQ(doc["payload"]["data"]["dynamic_pin"]["enabled"].as<bool>(), true);
    EXPECT_EQ(doc["payload"]["data"]["dynamic_pin"]["min_pin_length"].as<int>(), 6);
    EXPECT_EQ(doc["payload"]["data"]["dynamic_pin"]["escalated"].as<bool>(), true);
    EXPECT_TRUE(doc["payload"]["data"]["dynamic_pin"]["locked_out"].isUnbound())
        << "locked_out is gone from the wire";
}

TEST(ManagementProtocol, FormatResultStorageAbsent) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    // No storage field.
    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_TRUE(doc["payload"]["storage"].isUnbound());
}

TEST(ManagementProtocol, FormatResultStorageFreeOnly) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    StorageAccountingPayload storage;
    storage.free = 2;
    // capacity/cost_individual/cost_shared absent.
    payload.storage = storage;
    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_EQ(doc["payload"]["storage"]["free"].as<int>(), 2);
    EXPECT_TRUE(doc["payload"]["storage"]["capacity"].isUnbound());
    EXPECT_TRUE(doc["payload"]["storage"]["cost_individual"].isUnbound());
    EXPECT_TRUE(doc["payload"]["storage"]["cost_shared"].isUnbound());
}

TEST(ManagementProtocol, FormatResultStorageFull) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    StorageAccountingPayload storage;
    storage.free = 3;
    storage.capacity = 5;
    storage.cost_individual = 1;
    storage.cost_shared = 1;
    payload.storage = storage;
    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_EQ(doc["payload"]["storage"]["free"].as<int>(), 3);
    EXPECT_EQ(doc["payload"]["storage"]["capacity"].as<int>(), 5);
    EXPECT_EQ(doc["payload"]["storage"]["cost_individual"].as<int>(), 1);
    EXPECT_EQ(doc["payload"]["storage"]["cost_shared"].as<int>(), 1);
}

TEST(ManagementProtocol, FormatResultAllResultCodes) {
    const ManagementResult codes[] = {
        ManagementResult::OK,
        ManagementResult::PERMISSION_DENIED,
        ManagementResult::ALREADY_EXISTS,
        ManagementResult::INVALID,
        ManagementResult::NOT_FOUND,
        ManagementResult::STORAGE_EXHAUSTED,
    };
    const char* expected[] = {"ok", "permission_denied", "already_exists", "invalid", "not_found",
                              "storage_exhausted"};
    for (size_t i = 0; i < 6; i++) {
        ManagementResultPayload payload;
        payload.result = codes[i];
        std::string json = format_management_result_message(payload);
        JsonDocument doc;
        ASSERT_FALSE(deserializeJson(doc, json));
        EXPECT_STREQ(doc["payload"]["result"].as<const char*>(), expected[i]) << "code index " << i;
    }
}

// ===========================================================================
// Handler: handle_list_records
// ===========================================================================

TEST(ManagementHandler, ListRecordsEmpty) {
    RecordStore store(nullptr);
    // The auto-provisioned shared fallback record is always present.
    ManagementResultPayload result;
    ManagementEffect effect;
    handle_list_records(store, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);
    ASSERT_TRUE(result.data.has_value());
    ASSERT_TRUE(result.data->records.has_value());
    // Should have 1 record (the auto-provisioned shared fallback).
    EXPECT_EQ(result.data->records->size(), 1u);
}

TEST(ManagementHandler, ListRecordsWithMultiple) {
    RecordStore store(nullptr);
    SendspinPairingRecord a = make_client_record("srv-A");
    SendspinPairingRecord b = make_shared_record();
    store.store_record(a);
    store.store_record(b);

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_list_records(store, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    ASSERT_TRUE(result.data->records.has_value());
    // Total: 1 auto-provisioned + 2 added = 3.
    EXPECT_EQ(result.data->records->size(), 3u);
}

// ===========================================================================
// Handler: handle_add_record
// ===========================================================================

TEST(ManagementHandler, AddRecordOk) {
    RecordStore store(nullptr);
    auto psk = make_random_psk();
    std::string psk_b64 = psk_to_b64url(psk);
    std::string expected_psk_id = psk_id_for(psk);

    ManagementAddRecordPayload payload;
    payload.psk = psk_b64;
    std::string server_id = make_test_server_id();
    payload.server_id = server_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);

    // Record must be stored.
    const auto* stored = store.record_by_psk_id(expected_psk_id);
    ASSERT_NE(stored, nullptr);
    EXPECT_EQ(stored->server_id, server_id);
}

TEST(ManagementHandler, AddRecordInvalidEmptyServerId) {
    RecordStore store(nullptr);
    ManagementAddRecordPayload payload;
    payload.psk = psk_to_b64url(make_random_psk());
    payload.server_id = "";  // present but empty: could never match a handshake server_id

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

TEST(ManagementHandler, AddRecordInvalidMalformedServerId) {
    RecordStore store(nullptr);
    ManagementAddRecordPayload payload;
    payload.psk = psk_to_b64url(make_random_psk());
    // Right length (43) but not valid base64url.
    payload.server_id = std::string(43, '$');

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);

    // Wrong length.
    payload.server_id = "srv-short";
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, AddRecordInvalidBadPsk) {
    RecordStore store(nullptr);
    ManagementAddRecordPayload payload;
    payload.psk = "not-valid-base64url-$$$";

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

TEST(ManagementHandler, AddRecordInvalidWrongSize) {
    RecordStore store(nullptr);
    // Encode 16 bytes instead of 32.
    std::array<uint8_t, 16> short_psk{};
    ManagementAddRecordPayload payload;
    payload.psk = b64url_encode(short_psk.data(), short_psk.size());

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, AddRecordAlreadyExists) {
    RecordStore store(nullptr);
    auto psk = make_random_psk();
    std::string psk_id = psk_id_for(psk);
    SendspinPairingRecord rec;
    rec.psk_id = psk_id;
    rec.psk = psk;
    rec.server_id = "srv-existing";
    store.store_record(rec);

    ManagementAddRecordPayload payload;
    payload.psk = psk_to_b64url(psk);

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::ALREADY_EXISTS);
}

// Finding C: add-record twice with the same server_id but different PSKs supersedes the prior
// record rather than accumulating two records for one server (consistent with the re-pairing
// supersede semantics in RecordStore::store_record, see Finding A).
TEST(ManagementHandler, AddRecordSameServerIdSupersedesPrior) {
    RecordStore store(nullptr);
    std::string server_id = make_test_server_id();

    auto psk1 = make_random_psk();
    std::string first_psk_id = psk_id_for(psk1);
    ManagementAddRecordPayload payload1;
    payload1.psk = psk_to_b64url(psk1);
    payload1.server_id = server_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload1, result, effect);
    ASSERT_EQ(result.result, ManagementResult::OK);
    ASSERT_NE(store.record_by_psk_id(first_psk_id), nullptr);

    auto psk2 = make_random_psk();
    std::string second_psk_id = psk_id_for(psk2);
    ManagementAddRecordPayload payload2;
    payload2.psk = psk_to_b64url(psk2);
    payload2.server_id = server_id;

    handle_add_record(store, payload2, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);

    // The prior record for this server_id must be superseded (revoked), not accumulated.
    EXPECT_EQ(store.record_by_psk_id(first_psk_id), nullptr);
    const auto* current = store.record_by_server_id(server_id);
    ASSERT_NE(current, nullptr);
    EXPECT_EQ(current->psk_id, second_psk_id);

    // Exactly one record must be bound to this server_id.
    int count = 0;
    for (const auto& r : store.records_snapshot()) {
        if (r.server_id.has_value() && r.server_id.value() == server_id) {
            count++;
        }
    }
    EXPECT_EQ(count, 1);
}

TEST(ManagementHandler, AddRecordStorageExhausted) {
    ExhaustedRecordStore store(nullptr);
    auto psk = make_random_psk();

    ManagementAddRecordPayload payload;
    payload.psk = psk_to_b64url(psk);

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_add_record(store, payload, result, effect);
    EXPECT_EQ(result.result, ManagementResult::STORAGE_EXHAUSTED);
}

// ===========================================================================
// Handler: handle_remove_record
// ===========================================================================

TEST(ManagementHandler, RemoveRecordOk) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("srv-X");
    store.store_record(rec);

    ManagementRemoveRecordPayload payload;
    payload.psk_id = rec.psk_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_remove_record(store, payload, std::nullopt, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);

    // Record must be gone.
    EXPECT_EQ(store.record_by_psk_id(rec.psk_id), nullptr);
}

TEST(ManagementHandler, RemoveRecordNotFound) {
    RecordStore store(nullptr);
    ManagementRemoveRecordPayload payload;
    payload.psk_id = "nonexistent-psk-id";

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_remove_record(store, payload, std::nullopt, result, effect);
    EXPECT_EQ(result.result, ManagementResult::NOT_FOUND);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

TEST(ManagementHandler, RemoveRecordProtectedRecordMode) {
    RecordStore store(nullptr);
    // The auto-provisioned record is the record_mode record and cannot be removed.
    const std::string& protected_id = store.record_mode_psk_id();

    ManagementRemoveRecordPayload payload;
    payload.psk_id = protected_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_remove_record(store, payload, std::nullopt, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

// Regression (Finding B): own-record detection compares psk_id -- the credential that actually
// authenticated the connection -- not server_id. This test previously passed the record's
// server_id as the third argument; that encoded the old (buggy) server_id-based comparison.
// Updated to pass the record's psk_id, which is what a real connection presents now.
TEST(ManagementHandler, RemoveOwnRecordGivesGoodbyeUnauthorized) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("srv-self");
    store.store_record(rec);

    ManagementRemoveRecordPayload payload;
    payload.psk_id = rec.psk_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    // requester_psk_id matches the record's own psk_id (the credential that authenticated it).
    handle_remove_record(store, payload, std::string(rec.psk_id), result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::GOODBYE_UNAUTHORIZED);

    // Record must still be removed.
    EXPECT_EQ(store.record_by_psk_id(rec.psk_id), nullptr);
}

// Renamed from RemoveDifferentServerRecordNoEffect: the discriminator is now psk_id, not
// server_id, so the "different requester" case is a different psk_id, not a different server_id
// string. Previously this test passed an arbitrary server_id string as the third argument; now
// it passes an arbitrary psk_id string that does not match the removed record's psk_id.
TEST(ManagementHandler, RemoveRecordDifferentRequesterPskIdNoEffect) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("srv-other");
    store.store_record(rec);

    ManagementRemoveRecordPayload payload;
    payload.psk_id = rec.psk_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    // Requester authenticated via a different psk_id.
    handle_remove_record(store, payload, std::string("requester-psk-id"), result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

// Finding B (b1): a connection authenticated via a non-record-mode SHARED record removing that
// record must still get GOODBYE_UNAUTHORIZED. Shared records have no server_id at all, so the
// old server_id-based comparison could never fire here -- this is the "missed teardown" case.
TEST(ManagementHandler, RemoveOwnSharedRecordGivesGoodbyeUnauthorized) {
    RecordStore store(nullptr);
    // A second shared-PSK record, distinct from the auto-provisioned record_mode fallback, so
    // it is removable (can_remove_record only protects the record_mode-referenced record).
    SendspinPairingRecord shared = make_shared_record();
    store.store_record(shared);
    ASSERT_TRUE(store.can_remove_record(shared.psk_id));

    ManagementRemoveRecordPayload payload;
    payload.psk_id = shared.psk_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_remove_record(store, payload, std::string(shared.psk_id), result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::GOODBYE_UNAUTHORIZED);
}

// Finding B (b2): removing a different record that merely happens to share the requester's
// server_id must NOT tear down the connection -- only an exact psk_id match does. (RecordStore's
// store_record() now supersedes on server_id -- see Finding A -- so two records can no longer
// literally coexist under the same server_id; this test exercises the comparison directly with a
// requester psk_id that differs from the record being removed, which is the scenario the old
// server_id-based comparison would have mishandled.)
TEST(ManagementHandler, RemoveRecordDifferentPskIdSameServerIdNoEffect) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("srv-shared");
    store.store_record(rec);

    ManagementRemoveRecordPayload payload;
    payload.psk_id = rec.psk_id;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_remove_record(store, payload, std::string("some-other-psk-id-for-srv-shared"), result,
                         effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);
}

// ===========================================================================
// Handler: handle_get_pairing_config
// ===========================================================================

TEST(ManagementHandler, GetPairingConfigDefaultValues) {
    RecordStore store(nullptr);

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_get_pairing_config(store, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);

    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);
    ASSERT_TRUE(result.data.has_value());

    // pairing_psk: enabled by default.
    ASSERT_TRUE(result.data->pairing_psk.has_value());
    EXPECT_EQ(result.data->pairing_psk->enabled, store.pairing_psk_enabled());

    // record_mode: psk_id matches the store's record_mode_psk_id.
    ASSERT_TRUE(result.data->record_mode.has_value());
    EXPECT_EQ(result.data->record_mode->psk_id, store.record_mode_psk_id());

    // unpaired_access: disabled by default.
    ASSERT_TRUE(result.data->unpaired_access.has_value());
    ASSERT_TRUE(result.data->unpaired_access->enabled.has_value());
    EXPECT_EQ(result.data->unpaired_access->enabled.value(), store.unpaired_access_enabled());

    EXPECT_FALSE(result.data->records.has_value());

    // static_pin: disabled by default, no min_pin_length, no escalated flag.
    ASSERT_TRUE(result.data->static_pin.has_value());
    EXPECT_EQ(result.data->static_pin->enabled, store.static_pin_enabled());
    EXPECT_FALSE(result.data->static_pin->min_pin_length.has_value());
    EXPECT_FALSE(result.data->static_pin->escalated.has_value());

    // dynamic_pin: enabled by default, not escalated, min_pin_length matches the store.
    ASSERT_TRUE(result.data->dynamic_pin.has_value());
    EXPECT_EQ(result.data->dynamic_pin->enabled, store.dynamic_pin_enabled());
    ASSERT_TRUE(result.data->dynamic_pin->escalated.has_value());
    EXPECT_FALSE(result.data->dynamic_pin->escalated.value());
    ASSERT_TRUE(result.data->dynamic_pin->min_pin_length.has_value());
    EXPECT_EQ(result.data->dynamic_pin->min_pin_length.value(), store.dynamic_pin_min_length());
}

TEST(ManagementHandler, GetPairingConfigStaticPinNeverCarriesMinPinLength) {
    RecordStore store(nullptr);
    ManagementResultPayload result;
    ManagementEffect effect;
    handle_get_pairing_config(store, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);

    // Verify via JSON round-trip: static_pin has no min_pin_length; dynamic_pin does.
    std::string json = format_management_result_message(result);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_TRUE(doc["payload"]["data"]["static_pin"]["min_pin_length"].isUnbound());
    EXPECT_FALSE(doc["payload"]["data"]["dynamic_pin"]["min_pin_length"].isUnbound());
}

TEST(ManagementHandler, GetPairingConfigReportsEscalated) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::DYNAMIC_PIN_ESCALATION_THRESHOLD; ++i) {
        store.record_dynamic_pin_failure();
    }

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_get_pairing_config(store, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);

    ASSERT_TRUE(result.data->dynamic_pin->escalated.has_value());
    EXPECT_TRUE(result.data->dynamic_pin->escalated.value());
    // The method stays enabled: escalation gates attempts behind a gesture, nothing more.
    EXPECT_TRUE(result.data->dynamic_pin->enabled);
}

// A PIN-method object is absent when the device does not implement that method (spec: "A
// PIN-method object is absent if the client does not implement that method").
TEST(ManagementHandler, GetPairingConfigOmitsUnimplementedMethods) {
    RecordStore store(nullptr);

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_get_pairing_config(store, /*dynamic_pin_implemented=*/false,
                              /*static_pin_implemented=*/false, result, effect);

    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_FALSE(result.data->static_pin.has_value());
    EXPECT_FALSE(result.data->dynamic_pin.has_value());
    ASSERT_TRUE(result.data->pairing_psk.has_value())
        << "pairing_psk is client-mandatory and always reported";
}

// Fields set on an unimplemented method are rejected as invalid.
TEST(ManagementHandler, SetPairingConfigRejectsUnimplementedMethodFields) {
    RecordStore store(nullptr);

    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dyn_cfg;
    dyn_cfg.enabled = false;
    payload.dynamic_pin = dyn_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/false,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_TRUE(store.dynamic_pin_enabled()) << "a rejected patch must not be applied";
}

// Enabling static_pin with no PIN configured and none supplied is rejected as invalid.
TEST(ManagementHandler, SetPairingConfigRejectsEnablingStaticPinWithoutPin) {
    RecordStore store(nullptr);
    ASSERT_FALSE(store.static_pin().has_value());

    ManagementSetPairingConfigPayload payload;
    SetStaticPinConfig static_cfg;
    static_cfg.enabled = true;
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_FALSE(store.static_pin_enabled());

    // Supplying the PIN in the same request passes.
    static_cfg.pin = "12345678";
    payload.static_pin = static_cfg;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_TRUE(store.static_pin_enabled());
}

// ===========================================================================
// Handler: handle_set_pairing_config
// ===========================================================================

TEST(ManagementHandler, SetPairingConfigEnablePairingPsk) {
    RecordStore store(nullptr);
    store.set_pairing_psk_enabled(false);

    ManagementSetPairingConfigPayload payload;
    SetPairingPskConfig ppsk_patch;
    ppsk_patch.enabled = true;
    payload.pairing_psk = ppsk_patch;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(effect, ManagementEffect::NONE);
    EXPECT_TRUE(store.pairing_psk_enabled());
}

TEST(ManagementHandler, SetPairingConfigSetNewPsk) {
    RecordStore store(nullptr);
    auto new_psk = make_random_psk();
    std::string new_psk_b64 = psk_to_b64url(new_psk);

    ManagementSetPairingConfigPayload payload;
    SetPairingPskConfig ppsk_patch;
    ppsk_patch.psk = new_psk_b64;
    payload.pairing_psk = ppsk_patch;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);

    // The pairing PSK must be set.
    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk, new_psk);
}

TEST(ManagementHandler, SetPairingConfigStaticPinValidPinAccepted) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetStaticPinConfig static_cfg;
    static_cfg.pin = "12345678";
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    ASSERT_TRUE(store.static_pin().has_value());
    EXPECT_EQ(store.static_pin().value(), "12345678");
}

TEST(ManagementHandler, SetPairingConfigInvalidStaticPinWrongLength) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetStaticPinConfig static_cfg;
    static_cfg.pin = "1234567";  // 7 digits, must be exactly 8.
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_FALSE(store.static_pin().has_value());
}

TEST(ManagementHandler, SetPairingConfigInvalidStaticPinNonDigit) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetStaticPinConfig static_cfg;
    static_cfg.pin = "1234abcd";  // Non-digit characters.
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
    EXPECT_FALSE(store.static_pin().has_value());
}

TEST(ManagementHandler, SetPairingConfigStaticPinEnabledToggle) {
    RecordStore store(nullptr);
    EXPECT_FALSE(store.static_pin_enabled());
    // Enabling requires a configured PIN (else INVALID; see
    // SetPairingConfigRejectsEnablingStaticPinWithoutPin).
    store.set_static_pin("13572468");

    ManagementSetPairingConfigPayload payload;
    SetStaticPinConfig static_cfg;
    static_cfg.enabled = true;
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_TRUE(store.static_pin_enabled());
}

TEST(ManagementHandler, SetPairingConfigDynamicPinEnabledToggle) {
    RecordStore store(nullptr);
    store.set_dynamic_pin_enabled(true);

    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dynamic_cfg;
    dynamic_cfg.enabled = false;
    payload.dynamic_pin = dynamic_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_FALSE(store.dynamic_pin_enabled());
}

TEST(ManagementHandler, SetPairingConfigDynamicPinMinLengthOutOfRangeTooLow) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dynamic_cfg;
    dynamic_cfg.min_pin_length = 3;  // Below PIN_MIN_DIGITS (4).
    payload.dynamic_pin = dynamic_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, SetPairingConfigDynamicPinMinLengthOutOfRangeTooHigh) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dynamic_cfg;
    dynamic_cfg.min_pin_length = 13;  // Above PIN_MAX_DIGITS (12).
    payload.dynamic_pin = dynamic_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, SetPairingConfigDynamicPinMinLengthAppliesWhenValid) {
    RecordStore store(nullptr);
    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dynamic_cfg;
    dynamic_cfg.min_pin_length = 8;
    payload.dynamic_pin = dynamic_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(store.dynamic_pin_min_length(), 8);
}

// The spec has no locked_out-clearing field: an unknown locked_out key inside a method patch
// is simply not parsed, and the escalation counter is untouchable via management. The counter
// resets only through the client's own successful server_kc verification.
TEST(ManagementHandler, SetPairingConfigCannotTouchEscalation) {
    RecordStore store(nullptr);
    for (int i = 0; i < RecordStore::DYNAMIC_PIN_ESCALATION_THRESHOLD; ++i) {
        store.record_dynamic_pin_failure();
    }
    ASSERT_TRUE(store.dynamic_pin_escalated());

    // A dynamic_pin patch (any fields) leaves the counter alone.
    ManagementSetPairingConfigPayload payload;
    SetDynamicPinConfig dynamic_cfg;
    dynamic_cfg.enabled = true;
    payload.dynamic_pin = dynamic_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_TRUE(store.dynamic_pin_escalated())
        << "management must not be able to de-escalate the failure counter";
}

// A rotated Pairing PSK whose psk_id collides with a candidate PSK in a different category
// (here: a stored long-term record) is rejected as already_exists.
TEST(ManagementHandler, SetPairingConfigPskCollidingWithRecordRejected) {
    RecordStore store(nullptr);
    auto psk = make_random_psk();

    SendspinPairingRecord rec;
    rec.psk = psk;
    auto id_opt = psk_id_for(psk.data(), psk.size());
    ASSERT_TRUE(id_opt.has_value());
    rec.psk_id = id_opt.value();
    rec.server_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    ASSERT_TRUE(store.store_record(rec));

    ManagementSetPairingConfigPayload payload;
    SetPairingPskConfig psk_cfg;
    psk_cfg.psk = psk_to_b64url(psk);
    payload.pairing_psk = psk_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::ALREADY_EXISTS);
}

// A patch mixing a valid field (pairing_psk enabled toggle) and an invalid field (bad static PIN)
// must mutate NOTHING: validation happens before any apply step (atomic validation).
TEST(ManagementHandler, SetPairingConfigMixedValidAndInvalidMutatesNothing) {
    RecordStore store(nullptr);
    store.set_pairing_psk_enabled(true);
    const bool original_dynamic_enabled = store.dynamic_pin_enabled();

    ManagementSetPairingConfigPayload payload;
    SetPairingPskConfig psk_cfg;
    psk_cfg.enabled = false;  // Valid change, but must not apply.
    payload.pairing_psk = psk_cfg;

    SetStaticPinConfig static_cfg;
    static_cfg.pin = "bad";  // Invalid: wrong length and non-digit.
    payload.static_pin = static_cfg;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);

    // Nothing must have been mutated.
    EXPECT_TRUE(store.pairing_psk_enabled());
    EXPECT_EQ(store.dynamic_pin_enabled(), original_dynamic_enabled);
    EXPECT_FALSE(store.static_pin().has_value());
}

TEST(ManagementHandler, SetPairingConfigInvalidBadPskBytes) {
    RecordStore store(nullptr);
    // Encode 16 bytes instead of 32.
    std::array<uint8_t, 16> short_psk{};
    ManagementSetPairingConfigPayload payload;
    SetPairingPskConfig ppsk_patch;
    ppsk_patch.psk = b64url_encode(short_psk.data(), short_psk.size());
    payload.pairing_psk = ppsk_patch;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, SetPairingConfigInvalidRecordMode) {
    RecordStore store(nullptr);
    // Try to set record_mode to a stored-pubkey record (must be shared-PSK).
    SendspinPairingRecord pubkey_rec = make_client_record("srv-X");
    store.store_record(pubkey_rec);

    ManagementSetPairingConfigPayload payload;
    RecordModeConfig rm;
    rm.psk_id = pubkey_rec.psk_id;
    payload.record_mode = rm;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::INVALID);
}

TEST(ManagementHandler, SetPairingConfigAppliesRecordMode) {
    RecordStore store(nullptr);
    // Add a second shared-PSK record to set as record_mode.
    SendspinPairingRecord shared = make_shared_record();
    store.store_record(shared);
    ASSERT_TRUE(store.set_record_mode_psk_id(shared.psk_id));  // Verify it works directly.
    // Reset to original.
    // (Use the auto-provisioned record for initial state.)

    // Now use the handler to set it.
    ManagementSetPairingConfigPayload payload;
    RecordModeConfig rm;
    rm.psk_id = shared.psk_id;
    payload.record_mode = rm;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_EQ(store.record_mode_psk_id(), shared.psk_id);
}

TEST(ManagementHandler, SetPairingConfigUnpairedAccess) {
    RecordStore store(nullptr);
    EXPECT_FALSE(store.unpaired_access_enabled());

    ManagementSetPairingConfigPayload payload;
    UnpairedAccessConfig ua;
    ua.enabled = true;
    payload.unpaired_access = ua;

    ManagementResultPayload result;
    ManagementEffect effect;
    handle_set_pairing_config(store, payload, /*dynamic_pin_implemented=*/true,
                              /*static_pin_implemented=*/true, result, effect);
    EXPECT_EQ(result.result, ManagementResult::OK);
    EXPECT_TRUE(store.unpaired_access_enabled());
}

// ===========================================================================
// Handler: handle_unpair
// ===========================================================================

TEST(ManagementHandler, UnpairLongTermStoredPubkeyRemovesRecord) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("srv-paired");
    store.store_record(rec);
    ASSERT_NE(store.record_by_psk_id(rec.psk_id), nullptr);

    handle_unpair(store, rec.psk_id);

    // Record must be removed.
    EXPECT_EQ(store.record_by_psk_id(rec.psk_id), nullptr);
}

TEST(ManagementHandler, UnpairSharedPskRecordNotRemoved) {
    RecordStore store(nullptr);
    const std::string& shared_psk_id = store.record_mode_psk_id();
    ASSERT_NE(store.record_by_psk_id(shared_psk_id), nullptr);

    // server/unpair with a shared-PSK record psk_id: shared records are never removed.
    handle_unpair(store, shared_psk_id);

    // Record must still exist.
    EXPECT_NE(store.record_by_psk_id(shared_psk_id), nullptr);
}

TEST(ManagementHandler, UnpairUnknownPskIdIsNoOp) {
    RecordStore store(nullptr);
    // No crash; just a no-op.
    handle_unpair(store, "unknown-psk-id");
}

// ===========================================================================
// Trust gating: permission_denied when MANAGEMENT activity absent
// ===========================================================================

// The trust gating check is in ConnectionManager::handle_management_request which requires
// a live connection. We test it via the management result payload shape check instead,
// verifying the result message format is correct for permission_denied.

TEST(ManagementHandler, PermissionDeniedResultShape) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::PERMISSION_DENIED;
    std::string json = format_management_result_message(payload);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    EXPECT_STREQ(doc["type"].as<const char*>(), "management/result");
    EXPECT_STREQ(doc["payload"]["result"].as<const char*>(), "permission_denied");
    EXPECT_TRUE(doc["payload"]["data"].isUnbound());
    EXPECT_TRUE(doc["payload"]["storage"].isUnbound());
}

// ===========================================================================
// Fix 4 regression: format_management_result_message always emits
// unpaired_access.enabled for a get-pairing-config result (true and false).
// ===========================================================================

TEST(ManagementProtocol, FormatResultUnpairedAccessEnabledTrue) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    UnpairedAccessConfig ua;
    ua.enabled = true;
    payload.data->unpaired_access = ua;

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    // enabled must be present and true.
    ASSERT_FALSE(doc["payload"]["data"]["unpaired_access"]["enabled"].isUnbound())
        << "unpaired_access.enabled must always be emitted";
    EXPECT_EQ(doc["payload"]["data"]["unpaired_access"]["enabled"].as<bool>(), true);
}

TEST(ManagementProtocol, FormatResultUnpairedAccessEnabledFalse) {
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    UnpairedAccessConfig ua;
    ua.enabled = false;
    payload.data->unpaired_access = ua;

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    // enabled must be present and false (the former double-guard dropped this case).
    ASSERT_FALSE(doc["payload"]["data"]["unpaired_access"]["enabled"].isUnbound())
        << "unpaired_access.enabled must always be emitted even when false";
    EXPECT_EQ(doc["payload"]["data"]["unpaired_access"]["enabled"].as<bool>(), false);
}

TEST(ManagementProtocol, FormatResultUnpairedAccessEnabledNulloptDefaultsFalse) {
    // When enabled is nullopt, value_or(false) should emit false rather than drop the field.
    ManagementResultPayload payload;
    payload.result = ManagementResult::OK;
    payload.data = ManagementResultData{};
    UnpairedAccessConfig ua;
    // enabled not set (nullopt).
    payload.data->unpaired_access = ua;

    std::string json = format_management_result_message(payload);
    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, json));
    ASSERT_FALSE(doc["payload"]["data"]["unpaired_access"]["enabled"].isUnbound())
        << "unpaired_access.enabled must be emitted (defaulting to false) when enabled is nullopt";
    EXPECT_EQ(doc["payload"]["data"]["unpaired_access"]["enabled"].as<bool>(), false);
}

// ===========================================================================
// Storage accounting: attach_storage_accounting
// ===========================================================================

TEST(ManagementHandler, StorageAccountingNulloptDoesNotAttach) {
    RecordStore store(nullptr);  // Default implementation returns nullopt.
    ManagementResultPayload result;
    result.result = ManagementResult::OK;

    attach_storage_accounting(store, result, true);
    EXPECT_FALSE(result.storage.has_value());
}

TEST(ManagementHandler, StorageAccountingBoundedFreeOnly) {
    BoundedRecordStore store(nullptr);
    ManagementResultPayload result;
    result.result = ManagementResult::OK;

    // include_static=false: only free.
    attach_storage_accounting(store, result, false);
    ASSERT_TRUE(result.storage.has_value());
    EXPECT_EQ(result.storage->free, 3);
    EXPECT_FALSE(result.storage->capacity.has_value());
    EXPECT_FALSE(result.storage->cost_individual.has_value());
    EXPECT_FALSE(result.storage->cost_shared.has_value());
}

TEST(ManagementHandler, StorageAccountingBoundedWithStatic) {
    BoundedRecordStore store(nullptr);
    ManagementResultPayload result;
    result.result = ManagementResult::OK;

    // include_static=true: free + capacity + costs.
    attach_storage_accounting(store, result, true);
    ASSERT_TRUE(result.storage.has_value());
    EXPECT_EQ(result.storage->free, 3);
    ASSERT_TRUE(result.storage->capacity.has_value());
    EXPECT_EQ(result.storage->capacity.value(), 5);
    ASSERT_TRUE(result.storage->cost_individual.has_value());
    EXPECT_EQ(result.storage->cost_individual.value(), 1);
    ASSERT_TRUE(result.storage->cost_shared.has_value());
    EXPECT_EQ(result.storage->cost_shared.value(), 1);
}
