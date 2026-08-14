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

/// @file file_persistence_provider.h
/// @brief File-backed SendspinPersistenceProvider for host examples.
///
/// A minimal blob store: the whole file is one JSON document mapping each
/// persistence_keys::* key to base64url(bytes). This is a shared example/test helper, not part
/// of the library: persistence is the consumer's responsibility, and this shows one way to
/// implement the provider on host. It depends only on the public API (sendspin/client.h,
/// sendspin/persistence_codec.h) plus ArduinoJson, so it is self-contained and can be copied
/// into a downstream project as a starting point. On a real device the platform (e.g. ESPHome)
/// implements the provider against NVS/Preferences instead.
///
/// The file holds plaintext secrets (the static private key, long-term PSKs, the Pairing PSK,
/// and the static PIN), so it is written owner-only (0600) via POSIX open()/fchmod and fsync'd
/// before the rename that makes it visible, with the containing directory fsync'd after: see
/// write_file() in the .cpp. If this is copied elsewhere, keep that behavior or swap in an
/// equivalent for the target platform; do not fall back to a bare std::ofstream.
///
/// A file that is not this key-to-base64url-blob layout will not load; delete it and let the
/// device re-provision. The blob contents themselves are the codec's concern, and it accepts
/// record shapes that omit the "v" field.

#pragma once

#include "sendspin/client.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

/// @brief File-backed persistence provider: one JSON document mapping key -> base64url(bytes).
///
/// The file is overwritten atomically on every save. Each method re-reads the file on load and
/// re-serializes on save (small data, infrequent calls).
class FilePersistenceProvider : public SendspinPersistenceProvider {
public:
    /// @brief Construct with the path to the JSON persistence file.
    explicit FilePersistenceProvider(std::string path);

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override;
    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override;
    bool erase_blob(const std::string& key) override;

private:
    // save_blob(persistence_keys::RECORDS, ...) is called on the network thread during pairing
    // finalize, while the other keys are only ever touched from the main loop. This mutex
    // serializes the read-modify-write of the backing file so concurrent calls cannot lose an
    // update.
    std::mutex mutex_;
    std::string path_;
};

}  // namespace sendspin
