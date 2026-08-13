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

#include "sendspin/config.h"
#include <ArduinoJson.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sendspin {

// ============================================================================
// Helpers: load/save the root JSON document
// ============================================================================

namespace {

// ----------------------------------------------------------------------------
// Base64url (RFC 4648 section 5, no `=` padding). Inlined here so this example helper
// depends only on the public API + ArduinoJson, not on the library's internal
// platform/ headers. Matches the library's src/platform/base64.h encoding so
// files written by either remain compatible.
// ----------------------------------------------------------------------------

// clang-format off
static constexpr char B64URL_ENCODE_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static constexpr unsigned char B64URL_DECODE_TABLE[128] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //   0-15
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,  //  16-31
    255,255,255,255,255,255,255,255,255,255,255,255,255, 62,255,255,  //  32-47  (-, no +, no /)
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,  //  48-63  (0-9)
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  //  64-79  (A-O)
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,  //  80-95  (P-Z, _)
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  //  96-111 (a-o)
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,  // 112-127 (p-z)
};
// clang-format on

/// Encode bytes to base64url, no `=` padding.
static std::string b64url_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) {
            b |= static_cast<uint32_t>(data[i + 1]) << 8;
        }
        if (i + 2 < len) {
            b |= static_cast<uint32_t>(data[i + 2]);
        }
        out += B64URL_ENCODE_TABLE[(b >> 18) & 0x3F];
        out += B64URL_ENCODE_TABLE[(b >> 12) & 0x3F];
        if (i + 1 < len) {
            out += B64URL_ENCODE_TABLE[(b >> 6) & 0x3F];
        }
        if (i + 2 < len) {
            out += B64URL_ENCODE_TABLE[b & 0x3F];
        }
    }
    return out;
}

/// Decode base64url, tolerating missing `=` padding. Returns nullopt on invalid input.
static std::optional<std::vector<uint8_t>> b64url_decode(const std::string& s) {
    size_t slen = s.size();
    while (slen > 0 && s[slen - 1] == '=') {
        --slen;
    }
    std::vector<uint8_t> out;
    out.reserve((slen * 3) / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < slen; ++i) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c >= 128 || B64URL_DECODE_TABLE[c] == 255) {
            return std::nullopt;  // Invalid character.
        }
        acc = (acc << 6) | B64URL_DECODE_TABLE[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

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
///
/// This file can hold the device's static private key, long-term PSKs, the Pairing
/// PSK, and the static PIN, so the temp file is created owner-only (0600) from the
/// moment it exists rather than chmod'd afterward -- a post-write chmod would leave
/// the secret readable by other local accounts for the duration of the write.
/// std::ofstream has no portable way to specify a creation mode, so the temp file is
/// opened with POSIX open()/O_CREAT and an explicit mode instead, and written via
/// that descriptor. Because rename() replaces the destination's directory entry
/// wholesale, the renamed-over file always ends up with the temp file's (0600)
/// permissions, which also tightens the mode of a pre-existing file that an older,
/// less careful version of this helper (or another tool) left group/world readable.
///
/// The temp file's contents are fsync'd before the rename, and the containing
/// directory is fsync'd after the rename, so a crash cannot report success for data
/// that never reached disk, and cannot leave the rename itself unobserved after a
/// power loss.
static bool write_file(const std::string& path, const std::string& content) {
    std::string tmp = path + ".tmp";

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    // Defense in depth: the mode passed to open() only applies when the file is
    // newly created. If a stale .tmp file happens to already exist with looser
    // permissions, tighten it explicitly before any content is written.
    if (::fchmod(fd, 0600) != 0) {
        ::close(fd);
        return false;
    }

    const char* data = content.data();
    size_t remaining = content.size();
    while (remaining > 0) {
        ssize_t n = ::write(fd, data, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            return false;
        }
        data += static_cast<size_t>(n);
        remaining -= static_cast<size_t>(n);
    }

    if (::fsync(fd) != 0) {
        ::close(fd);
        return false;
    }
    if (::close(fd) != 0) {
        return false;
    }

    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        return false;
    }

    // Sync the containing directory so the rename (the new directory entry) is
    // itself durable, not just the file contents it points at.
    std::filesystem::path dir = std::filesystem::path(path).parent_path();
    if (dir.empty()) {
        dir = ".";
    }
    int dfd = ::open(dir.c_str(), O_RDONLY);
    if (dfd < 0) {
        return false;
    }
    bool dir_synced = ::fsync(dfd) == 0;
    ::close(dfd);
    return dir_synced;
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
        std::fprintf(stderr, "[FilePersistenceProvider] failed to parse '%s': %s\n", path.c_str(),
                     err.c_str());
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
        std::fprintf(stderr, "[FilePersistenceProvider] bad static_keypair in persistence file\n");
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
    } else {
        // Drop any stale label left over from a previously-saved PSK that had one.
        doc["pairing_psk"].remove("label");
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
    if (doc["pairing_config"]["dynamic_pin_failures"].is<int>()) {
        cfg.dynamic_pin_failures = doc["pairing_config"]["dynamic_pin_failures"].as<int>();
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
    doc["pairing_config"]["dynamic_pin_failures"] = config.dynamic_pin_failures;
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
