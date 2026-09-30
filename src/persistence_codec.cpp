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
#include "platform/logging.h"
#include "platform/memory.h"
#include <ArduinoJson.h>

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

static const char* const TAG = "sendspin.persistence_codec";

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
/// @param reason Set to the rejection reason when the parse fails; untouched on success. Every
///        rejection path below sets it, for the callers that log it.
/// @return nullopt if psk_id is missing/empty, psk is missing, or psk does not base64url-decode
///         to exactly 32 bytes.
std::optional<PskIdAndBytes> parse_psk_id_and_psk(JsonObjectConst obj, const char** reason) {
    if (!obj["psk_id"].is<const char*>()) {
        *reason = "psk_id is missing or not a string";
        return std::nullopt;
    }
    std::string psk_id = obj["psk_id"].as<const char*>();
    if (psk_id.empty()) {
        *reason = "psk_id is empty";
        return std::nullopt;
    }
    if (!obj["psk"].is<const char*>()) {
        *reason = "psk is missing or not a string";
        return std::nullopt;
    }
    // Decode straight from the JSON pool's char*, not a std::string copy of it: that copy would
    // be base64 PSK text living outside the document's (zeroizing) allocator, with nothing to
    // wipe it on the way out.
    auto decoded = b64url_decode(obj["psk"].as<const char*>());
    if (!decoded.has_value() || decoded->size() != 32) {
        *reason = "psk does not base64url-decode to 32 bytes";
        return std::nullopt;
    }
    PskIdAndBytes out;
    out.psk_id = std::move(psk_id);
    std::memcpy(out.psk.data(), decoded->data(), 32);
    secure_zero(decoded->data(), decoded->size());
    return out;
}

/// @brief Parses a pairing record from a decoded record blob's root object.
/// @return The record, or nullopt when the object is not a usable one.
std::optional<SendspinPairingRecord> record_from_object(JsonObjectConst obj, const char** reason) {
    auto core = parse_psk_id_and_psk(obj, reason);
    if (!core.has_value()) {
        return std::nullopt;
    }
    SendspinPairingRecord rec;
    rec.psk_id = std::move(core->psk_id);
    rec.psk = core->psk;
    // A record whose PSK is not bound to a server can never satisfy the post-match server_id
    // check (connection.md "Pre-Shared Key"), so it is not loaded.
    if (!obj["server_id"].is<const char*>()) {
        *reason = "server_id is missing or not a string";
        return std::nullopt;
    }
    rec.server_id = obj["server_id"].as<const char*>();
    if (rec.server_id.empty()) {
        *reason = "server_id is empty";
        return std::nullopt;
    }
    if (obj["label"].is<const char*>()) {
        rec.label = obj["label"].as<const char*>();
    } else if (!obj["label"].isUnbound() && !obj["label"].isNull()) {
        SS_LOGW(TAG, "Ignoring stored pairing record field 'label': expected string");
    }
    // is<bool>() guard, like every other field: ArduinoJson's as<bool>() coerces any
    // non-boolean variant (e.g. a corrupt "used":"false" string) to true, which would
    // silently invert the single-use admission gate. A wrong-typed field keeps the
    // struct default (false) instead.
    if (obj["used"].is<bool>()) {
        rec.used = obj["used"].as<bool>();
    } else if (!obj["used"].isUnbound() && !obj["used"].isNull()) {
        SS_LOGW(TAG, "Ignoring stored pairing record field 'used': expected boolean");
    }
    return rec;
}

/// @brief Writes the "psk_id"/"psk"/"server_id"/"label"/"used" fields of a record into the
/// document root encode_pairing_record() serializes.
void write_record_fields(JsonDocument& target, const SendspinPairingRecord& r) {
    target["psk_id"] = r.psk_id;
    std::string psk_b64 = base64url_encode(r.psk.data(), r.psk.size());
    target["psk"] = psk_b64;
    secure_zero(psk_b64.data(), psk_b64.size());
    target["server_id"] = r.server_id;
    if (r.label.has_value()) {
        target["label"] = r.label.value();
    }
    target["used"] = r.used;
}

/// @brief Parses an accepted Pairing PSK from a JSON object.
/// @return The Pairing PSK, or nullopt when the object does not carry a usable one.
std::optional<SendspinPairingPsk> psk_from_object(JsonObjectConst obj, const char** reason) {
    auto core = parse_psk_id_and_psk(obj, reason);
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
    write_record_fields(doc, r);
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
    const char* reason = "the codec cannot read it";
    auto rec = record_from_object(obj, &reason);
    if (!rec.has_value()) {
        // Logged here because the server that holds this record has to pair again; the caller
        // only knows which key failed, not why.
        SS_LOGW(TAG, "Rejecting stored pairing record %s: %s",
                obj["psk_id"].is<const char*>() ? obj["psk_id"].as<const char*>() : "(no psk_id)",
                reason);
    }
    return rec;
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
    const char* reason = "the codec cannot read it";
    auto psk = psk_from_object(obj, &reason);
    if (!psk.has_value()) {
        SS_LOGW(TAG, "Rejecting stored pairing PSK: %s", reason);
    }
    return psk;
}

// ============================================================================
// Pairing config
// ============================================================================

std::string encode_pairing_config(const SendspinPairingConfig& c) {
    JsonDocument doc = make_json_document();
    doc["v"] = RECORD_CODEC_VERSION;
    doc["unpaired_access_enabled"] = c.unpaired_access_enabled;
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
    if (obj["unpaired_access_enabled"].is<bool>()) {
        cfg.unpaired_access_enabled = obj["unpaired_access_enabled"].as<bool>();
    }
    // Keys this version does not define are ignored.
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
