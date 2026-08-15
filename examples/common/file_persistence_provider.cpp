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

#include "sendspin/persistence_codec.h"
#include <ArduinoJson.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

// Base64url encode/decode (RFC 4648 section 5, no `=` padding) comes from the library's public
// sendspin/persistence_codec.h instead of being hand-rolled here, so this file stays
// byte-compatible with the encoding used by the library's own src/platform/base64.h.

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
/// moment it exists rather than chmod'd afterward: a post-write chmod would leave
/// the secret readable by other local accounts for the duration of the write.
/// std::ofstream has no portable way to specify a creation mode, so the temp file is
/// opened with POSIX open()/O_CREAT and an explicit mode instead, and written via
/// that descriptor. Because rename() replaces the destination's directory entry
/// wholesale, the renamed-over file always ends up with the temp file's (0600)
/// permissions, which also tightens the mode of a pre-existing file that another
/// tool left group/world readable.
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
        doc.to<JsonObject>();
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

}  // namespace

// ============================================================================
// Constructor
// ============================================================================

FilePersistenceProvider::FilePersistenceProvider(std::string path) : path_(std::move(path)) {}

std::string FilePersistenceProvider::default_path(const std::string& filename) {
    const char* home_dir = getenv("HOME");
    return std::string(home_dir != nullptr ? home_dir : ".") + "/" + filename;
}

// ============================================================================
// Blob store
// ============================================================================

std::optional<std::vector<uint8_t>> FilePersistenceProvider::load_blob(const std::string& key) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(this->path_);
    if (!doc[key].is<const char*>()) {
        return std::nullopt;
    }
    auto decoded = base64url_decode(doc[key].as<const char*>());
    if (!decoded.has_value()) {
        std::fprintf(stderr, "[FilePersistenceProvider] bad base64url for key '%s'\n",
                     key.c_str());
        return std::nullopt;
    }
    return decoded;
}

bool FilePersistenceProvider::save_blob(const std::string& key, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(this->path_);
    doc[key] = base64url_encode(data, len);
    return save_doc(this->path_, doc);
}

bool FilePersistenceProvider::erase_blob(const std::string& key) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    JsonDocument doc = load_doc(this->path_);
    if (!doc[key].is<const char*>()) {
        return true;  // Nothing stored: the key is already absent.
    }
    doc.remove(key);
    return save_doc(this->path_, doc);
}

}  // namespace sendspin
