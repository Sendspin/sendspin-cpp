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

#include "file_persistence_provider.h"

#include "platform/base64.h"
#include "platform/logging.h"
#include <ArduinoJson.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

static const char* const TAG = "sendspin.file_persist";

namespace sendspin {

// ============================================================================
// Helpers: load/save the root JSON document
// ============================================================================

namespace {

/// Read the entire file into a string. Returns empty string on error.
static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        return {};
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// Write content atomically via a temp file then rename.
static bool write_file(const std::string& path, const std::string& content) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) {
            return false;
        }
        f << content;
        if (!f.good()) {
            return false;
        }
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

/// Parse the file as JSON. Returns an empty object on parse error or if absent.
static JsonDocument load_doc(const std::string& path) {
    JsonDocument doc;
    std::string raw = read_file(path);
    if (raw.empty()) {
        doc.to<JsonObject>();  // Start as empty object.
        return doc;
    }
    DeserializationError err = deserializeJson(doc, raw);
    if (err) {
        SS_LOGW(TAG, "Failed to parse persistence file '%s': %s", path.c_str(), err.c_str());
        doc.to<JsonObject>();
    }
    return doc;
}

/// Serialize doc to the file.
static bool save_doc(const std::string& path, const JsonDocument& doc) {
    std::string out;
    serializeJson(doc, out);
    return write_file(path, out);
}

/// Decode a base64url string to a 32-byte array. Returns false on failure.
static bool b64u_to_32(const std::string& s, std::array<uint8_t, 32>& out) {
    auto decoded = b64url_decode(s);
    if (!decoded.has_value() || decoded->size() != 32) {
        return false;
    }
    std::memcpy(out.data(), decoded->data(), 32);
    return true;
}

}  // namespace

// ============================================================================
// Constructor
// ============================================================================

FilePersistenceProvider::FilePersistenceProvider(std::string path) : path_(std::move(path)) {}

// ============================================================================
// Static keypair
// ============================================================================

bool FilePersistenceProvider::save_static_keypair(const std::array<uint8_t, 32>& private_key) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["static_keypair"]["private_key"] = b64url_encode(private_key.data(), private_key.size());
    return save_doc(path_, doc);
}

std::optional<std::array<uint8_t, 32>> FilePersistenceProvider::load_static_keypair() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["static_keypair"]["private_key"].is<const char*>()) {
        return std::nullopt;
    }
    std::string s = doc["static_keypair"]["private_key"].as<const char*>();
    std::array<uint8_t, 32> out{};
    if (!b64u_to_32(s, out)) {
        SS_LOGW(TAG, "Bad static_keypair in persistence file");
        return std::nullopt;
    }
    return out;
}

// ============================================================================
// Last-played server_id
// ============================================================================

bool FilePersistenceProvider::save_last_played_server_id(const std::string& server_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["last_played_server_id"] = server_id;
    return save_doc(path_, doc);
}

std::optional<std::string> FilePersistenceProvider::load_last_played_server_id() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["last_played_server_id"].is<const char*>()) {
        return std::nullopt;
    }
    std::string s = doc["last_played_server_id"].as<const char*>();
    if (s.empty()) {
        return std::nullopt;
    }
    return s;
}

// ============================================================================
// Pairing records
// ============================================================================

std::vector<SendspinPairingRecord> FilePersistenceProvider::load_pairing_records() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    std::vector<SendspinPairingRecord> out;
    JsonArray arr = doc["pairing_records"].as<JsonArray>();
    if (arr.isNull()) {
        return out;
    }
    for (JsonObject obj : arr) {
        SendspinPairingRecord rec;
        if (!obj["psk_id"].is<const char*>() || !obj["psk"].is<const char*>()) {
            continue;
        }
        rec.psk_id = obj["psk_id"].as<const char*>();
        if (!b64u_to_32(obj["psk"].as<const char*>(), rec.psk)) {
            continue;
        }
        if (obj["server_id"].is<const char*>()) {
            rec.server_id = obj["server_id"].as<const char*>();
        }
        if (obj["label"].is<const char*>()) {
            rec.label = obj["label"].as<const char*>();
        }
        rec.used = obj["used"].as<bool>();
        out.push_back(std::move(rec));
    }
    return out;
}

bool FilePersistenceProvider::save_pairing_record(const SendspinPairingRecord& record) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    JsonArray arr = doc["pairing_records"].is<JsonArray>() ? doc["pairing_records"].as<JsonArray>()
                                                           : doc["pairing_records"].to<JsonArray>();

    // Find and replace an existing entry with the same psk_id, or append.
    for (JsonObject obj : arr) {
        if (obj["psk_id"].is<const char*>() &&
            std::string(obj["psk_id"].as<const char*>()) == record.psk_id) {
            obj["psk"] = b64url_encode(record.psk.data(), record.psk.size());
            if (record.server_id.has_value()) {
                obj["server_id"] = record.server_id.value();
            } else {
                obj.remove("server_id");
            }
            if (record.label.has_value()) {
                obj["label"] = record.label.value();
            } else {
                obj.remove("label");
            }
            obj["used"] = record.used;
            return save_doc(path_, doc);
        }
    }

    // Append new.
    JsonObject new_obj = arr.add<JsonObject>();
    new_obj["psk_id"] = record.psk_id;
    new_obj["psk"] = b64url_encode(record.psk.data(), record.psk.size());
    if (record.server_id.has_value()) {
        new_obj["server_id"] = record.server_id.value();
    }
    if (record.label.has_value()) {
        new_obj["label"] = record.label.value();
    }
    new_obj["used"] = record.used;
    return save_doc(path_, doc);
}

void FilePersistenceProvider::remove_pairing_record(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["pairing_records"].is<JsonArray>()) {
        return;
    }
    JsonArray arr = doc["pairing_records"].as<JsonArray>();
    // ArduinoJson does not provide a remove-by-index on JsonArray directly; rebuild the array.
    JsonDocument tmp;
    JsonArray new_arr = tmp["r"].to<JsonArray>();
    for (JsonObject obj : arr) {
        if (!obj["psk_id"].is<const char*>() ||
            std::string(obj["psk_id"].as<const char*>()) == psk_id) {
            continue;  // Skip the entry to remove.
        }
        new_arr.add(obj);
    }
    doc["pairing_records"].set(new_arr);
    save_doc(path_, doc);
}

// ============================================================================
// Accepted Pairing PSK
// ============================================================================

std::optional<SendspinPairingPsk> FilePersistenceProvider::load_pairing_psk() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["pairing_psk"]["psk_id"].is<const char*>() ||
        !doc["pairing_psk"]["psk"].is<const char*>()) {
        return std::nullopt;
    }
    SendspinPairingPsk p;
    p.psk_id = doc["pairing_psk"]["psk_id"].as<const char*>();
    if (!b64u_to_32(doc["pairing_psk"]["psk"].as<const char*>(), p.psk)) {
        return std::nullopt;
    }
    if (doc["pairing_psk"]["label"].is<const char*>()) {
        p.label = doc["pairing_psk"]["label"].as<const char*>();
    }
    return p;
}

bool FilePersistenceProvider::save_pairing_psk(const SendspinPairingPsk& psk) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["pairing_psk"]["psk_id"] = psk.psk_id;
    doc["pairing_psk"]["psk"] = b64url_encode(psk.psk.data(), psk.psk.size());
    if (psk.label.has_value()) {
        doc["pairing_psk"]["label"] = psk.label.value();
    }
    return save_doc(path_, doc);
}

void FilePersistenceProvider::clear_pairing_psk() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc.remove("pairing_psk");
    save_doc(path_, doc);
}

// ============================================================================
// Static PIN
// ============================================================================

std::optional<std::string> FilePersistenceProvider::load_static_pin() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["static_pin"].is<const char*>()) {
        return std::nullopt;
    }
    return std::string(doc["static_pin"].as<const char*>());
}

bool FilePersistenceProvider::save_static_pin(const std::string& pin) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["static_pin"] = pin;
    return save_doc(path_, doc);
}

void FilePersistenceProvider::clear_static_pin() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc.remove("static_pin");
    save_doc(path_, doc);
}

// ============================================================================
// Pairing config
// ============================================================================

std::optional<SendspinPairingConfig> FilePersistenceProvider::load_pairing_config() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["pairing_config"]["record_mode_psk_id"].is<const char*>()) {
        return std::nullopt;
    }
    SendspinPairingConfig cfg;
    cfg.record_mode_psk_id = doc["pairing_config"]["record_mode_psk_id"].as<const char*>();
    if (doc["pairing_config"]["pairing_psk_enabled"].is<bool>()) {
        cfg.pairing_psk_enabled = doc["pairing_config"]["pairing_psk_enabled"].as<bool>();
    }
    if (doc["pairing_config"]["unpaired_access_enabled"].is<bool>()) {
        cfg.unpaired_access_enabled = doc["pairing_config"]["unpaired_access_enabled"].as<bool>();
    }
    if (doc["pairing_config"]["dynamic_pin_enabled"].is<bool>()) {
        cfg.dynamic_pin_enabled = doc["pairing_config"]["dynamic_pin_enabled"].as<bool>();
    }
    if (doc["pairing_config"]["static_pin_enabled"].is<bool>()) {
        cfg.static_pin_enabled = doc["pairing_config"]["static_pin_enabled"].as<bool>();
    }
    if (doc["pairing_config"]["dynamic_pin_min_length"].is<int>()) {
        cfg.dynamic_pin_min_length = doc["pairing_config"]["dynamic_pin_min_length"].as<int>();
    }
    if (cfg.record_mode_psk_id.empty()) {
        return std::nullopt;
    }
    return cfg;
}

bool FilePersistenceProvider::save_pairing_config(const SendspinPairingConfig& config) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["pairing_config"]["record_mode_psk_id"] = config.record_mode_psk_id;
    doc["pairing_config"]["pairing_psk_enabled"] = config.pairing_psk_enabled;
    doc["pairing_config"]["unpaired_access_enabled"] = config.unpaired_access_enabled;
    doc["pairing_config"]["dynamic_pin_enabled"] = config.dynamic_pin_enabled;
    doc["pairing_config"]["static_pin_enabled"] = config.static_pin_enabled;
    doc["pairing_config"]["dynamic_pin_min_length"] = config.dynamic_pin_min_length;
    return save_doc(path_, doc);
}

// ============================================================================
// Player static delay
// ============================================================================

bool FilePersistenceProvider::save_static_delay(uint16_t delay_ms) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    doc["static_delay_ms"] = delay_ms;
    return save_doc(path_, doc);
}

std::optional<uint16_t> FilePersistenceProvider::load_static_delay() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(path_);
    if (!doc["static_delay_ms"].is<uint16_t>()) {
        return std::nullopt;
    }
    return doc["static_delay_ms"].as<uint16_t>();
}

}  // namespace sendspin
