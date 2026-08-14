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

#include "sendspin/persistence_codec.h"

#include "platform/base64.h"
#include "platform/crypto.h"
#include "platform/memory.h"
#include <ArduinoJson.h>

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

namespace {

/// @brief psk_id + the decoded 32-byte PSK, shared by SendspinPairingRecord and
/// SendspinPairingPsk (the two structs that carry a "psk_id"/"psk" pair).
struct PskIdAndBytes {
    std::string psk_id;
    std::array<uint8_t, 32> psk{};

    /// @brief Wipes `psk` on destruction. This is a decode-side scratch copy distinct from the
    /// SendspinPairingRecord/SendspinPairingPsk it flows into (those wipe themselves
    /// independently; see config.h), so it needs the same discipline on its own account.
    ~PskIdAndBytes() {
        secure_zero(this->psk.data(), this->psk.size());
    }
};

/// @brief Parses and validates the "psk_id"/"psk" fields common to a record and a Pairing PSK.
/// @return nullopt if psk_id is missing/empty, psk is missing, or psk does not base64url-decode
///         to exactly 32 bytes.
std::optional<PskIdAndBytes> parse_psk_id_and_psk(JsonObjectConst obj) {
    if (!obj["psk_id"].is<const char*>()) {
        return std::nullopt;
    }
    std::string psk_id = obj["psk_id"].as<const char*>();
    if (psk_id.empty()) {
        return std::nullopt;
    }
    if (!obj["psk"].is<const char*>()) {
        return std::nullopt;
    }
    // Decode straight from the JSON pool's char*, not a std::string copy of it: that copy would
    // be base64 PSK text living outside the document's (zeroizing) allocator, with nothing to
    // wipe it on the way out.
    auto decoded = b64url_decode(obj["psk"].as<const char*>());
    if (!decoded.has_value() || decoded->size() != 32) {
        return std::nullopt;
    }
    PskIdAndBytes out;
    out.psk_id = std::move(psk_id);
    std::memcpy(out.psk.data(), decoded->data(), 32);
    secure_zero(decoded->data(), decoded->size());
    return out;
}

/// @brief Parses a pairing record from a JSON object (a top-level record blob, or one entry of
/// a records array). Ignores an entry-local "v", if present.
std::optional<SendspinPairingRecord> record_from_object(JsonObjectConst obj) {
    auto core = parse_psk_id_and_psk(obj);
    if (!core.has_value()) {
        return std::nullopt;
    }
    SendspinPairingRecord rec;
    rec.psk_id = std::move(core->psk_id);
    rec.psk = core->psk;
    if (obj["server_id"].is<const char*>()) {
        rec.server_id = obj["server_id"].as<const char*>();
    }
    if (obj["label"].is<const char*>()) {
        rec.label = obj["label"].as<const char*>();
    }
    // is<bool>() guard, like every other field: ArduinoJson's as<bool>() coerces any
    // non-boolean variant (e.g. a corrupt "used":"false" string) to true, which would
    // silently invert the single-use admission gate. A wrong-typed field keeps the
    // struct default (false) instead.
    if (obj["used"].is<bool>()) {
        rec.used = obj["used"].as<bool>();
    }
    return rec;
}

/// @brief Parses an accepted Pairing PSK from a JSON object.
std::optional<SendspinPairingPsk> psk_from_object(JsonObjectConst obj) {
    auto core = parse_psk_id_and_psk(obj);
    if (!core.has_value()) {
        return std::nullopt;
    }
    SendspinPairingPsk psk;
    psk.psk_id = std::move(core->psk_id);
    psk.psk = core->psk;
    if (obj["label"].is<const char*>()) {
        psk.label = obj["label"].as<const char*>();
    }
    return psk;
}

/// @brief Parses `bytes` as JSON and returns its root as a JSON object, keeping the backing
/// JsonDocument alive via @p doc (the returned view borrows from it). Returns a null (empty)
/// JsonObjectConst on parse failure or a non-object root; callers treat that the same as "not
/// found".
JsonObjectConst parse_root_object(std::string_view bytes, JsonDocument& doc) {
    DeserializationError err = deserializeJson(doc, bytes.data(), bytes.size());
    if (err) {
        return JsonObjectConst();
    }
    return doc.as<JsonObjectConst>();
}

}  // namespace

// ============================================================================
// Pairing record
// ============================================================================

std::string encode_pairing_record(const SendspinPairingRecord& r) {
    // Every JsonDocument here uses the zeroizing allocator (not make_json_document()'s plain
    // PsramJsonAllocator): the pool holds base64 PSK text and must not be freed unwiped.
    JsonDocument doc = make_zeroizing_json_document();
    doc["v"] = RECORD_CODEC_VERSION;
    doc["psk_id"] = r.psk_id;
    std::string psk_b64 = base64url_encode(r.psk.data(), r.psk.size());
    doc["psk"] = psk_b64;
    secure_zero(psk_b64.data(), psk_b64.size());
    if (r.server_id.has_value()) {
        doc["server_id"] = r.server_id.value();
    }
    if (r.label.has_value()) {
        doc["label"] = r.label.value();
    }
    doc["used"] = r.used;
    std::string out;
    serializeJson(doc, out);
    return out;
}

std::optional<SendspinPairingRecord> decode_pairing_record(std::string_view bytes) {
    JsonDocument doc = make_zeroizing_json_document();
    JsonObjectConst obj = parse_root_object(bytes, doc);
    if (obj.isNull()) {
        return std::nullopt;
    }
    return record_from_object(obj);
}

std::string encode_pairing_records(const std::vector<SendspinPairingRecord>& v) {
    JsonDocument doc = make_zeroizing_json_document();
    doc["v"] = RECORD_CODEC_VERSION;
    JsonArray arr = doc["records"].to<JsonArray>();
    for (const auto& r : v) {
        JsonObject obj = arr.add<JsonObject>();
        obj["psk_id"] = r.psk_id;
        std::string psk_b64 = base64url_encode(r.psk.data(), r.psk.size());
        obj["psk"] = psk_b64;
        secure_zero(psk_b64.data(), psk_b64.size());
        if (r.server_id.has_value()) {
            obj["server_id"] = r.server_id.value();
        }
        if (r.label.has_value()) {
            obj["label"] = r.label.value();
        }
        obj["used"] = r.used;
    }
    std::string out;
    serializeJson(doc, out);
    return out;
}

std::optional<std::vector<SendspinPairingRecord>> decode_pairing_records(std::string_view bytes) {
    JsonDocument doc = make_zeroizing_json_document();
    JsonObjectConst root = parse_root_object(bytes, doc);
    if (root.isNull() || !root["records"].is<JsonArrayConst>()) {
        return std::nullopt;
    }
    std::vector<SendspinPairingRecord> out;
    for (JsonVariantConst entry : root["records"].as<JsonArrayConst>()) {
        auto rec = record_from_object(entry.as<JsonObjectConst>());
        if (rec.has_value()) {
            out.push_back(std::move(rec.value()));
        }
    }
    return out;
}

// ============================================================================
// Pairing PSK
// ============================================================================

std::string encode_pairing_psk(const SendspinPairingPsk& p) {
    JsonDocument doc = make_zeroizing_json_document();
    doc["v"] = RECORD_CODEC_VERSION;
    doc["psk_id"] = p.psk_id;
    std::string psk_b64 = base64url_encode(p.psk.data(), p.psk.size());
    doc["psk"] = psk_b64;
    secure_zero(psk_b64.data(), psk_b64.size());
    if (p.label.has_value()) {
        doc["label"] = p.label.value();
    }
    std::string out;
    serializeJson(doc, out);
    return out;
}

std::optional<SendspinPairingPsk> decode_pairing_psk(std::string_view bytes) {
    JsonDocument doc = make_zeroizing_json_document();
    JsonObjectConst obj = parse_root_object(bytes, doc);
    if (obj.isNull()) {
        return std::nullopt;
    }
    return psk_from_object(obj);
}

// ============================================================================
// Pairing config
// ============================================================================

std::string encode_pairing_config(const SendspinPairingConfig& c) {
    JsonDocument doc = make_json_document();
    doc["v"] = RECORD_CODEC_VERSION;
    doc["record_mode_psk_id"] = c.record_mode_psk_id;
    doc["pairing_psk_enabled"] = c.pairing_psk_enabled;
    doc["unpaired_access_enabled"] = c.unpaired_access_enabled;
    doc["dynamic_pin_enabled"] = c.dynamic_pin_enabled;
    doc["static_pin_enabled"] = c.static_pin_enabled;
    doc["dynamic_pin_min_length"] = c.dynamic_pin_min_length;
    doc["dynamic_pin_failures"] = c.dynamic_pin_failures;
    std::string out;
    serializeJson(doc, out);
    return out;
}

std::optional<SendspinPairingConfig> decode_pairing_config(std::string_view bytes) {
    JsonDocument doc = make_json_document();
    JsonObjectConst obj = parse_root_object(bytes, doc);
    if (obj.isNull()) {
        return std::nullopt;
    }
    SendspinPairingConfig cfg;
    if (obj["record_mode_psk_id"].is<const char*>()) {
        cfg.record_mode_psk_id = obj["record_mode_psk_id"].as<const char*>();
    }
    if (obj["pairing_psk_enabled"].is<bool>()) {
        cfg.pairing_psk_enabled = obj["pairing_psk_enabled"].as<bool>();
    }
    if (obj["unpaired_access_enabled"].is<bool>()) {
        cfg.unpaired_access_enabled = obj["unpaired_access_enabled"].as<bool>();
    }
    if (obj["dynamic_pin_enabled"].is<bool>()) {
        cfg.dynamic_pin_enabled = obj["dynamic_pin_enabled"].as<bool>();
    }
    if (obj["static_pin_enabled"].is<bool>()) {
        cfg.static_pin_enabled = obj["static_pin_enabled"].as<bool>();
    }
    if (obj["dynamic_pin_min_length"].is<int>()) {
        cfg.dynamic_pin_min_length = obj["dynamic_pin_min_length"].as<int>();
    }
    if (obj["dynamic_pin_failures"].is<int>()) {
        cfg.dynamic_pin_failures = obj["dynamic_pin_failures"].as<int>();
    }
    return cfg;
}

// ============================================================================
// Base64url
// ============================================================================

std::string base64url_encode(const uint8_t* data, size_t len) {
    return b64url_encode(data, len);
}

std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s) {
    return b64url_decode(std::string(s));
}

}  // namespace sendspin
