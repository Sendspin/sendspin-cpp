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
/// Serializes keypair, pairing records, pairing config, last-played server_id,
/// and the player static delay to a JSON file via ArduinoJson. This is a shared
/// example/test helper, not part of the library: persistence is the consumer's
/// responsibility, and this shows one way to implement the provider on host.
/// Note: the implementation currently uses private library headers
/// (platform/base64.h, platform/logging.h), so copying it into a downstream
/// project also requires inlining those helpers.
/// On a real device the platform (e.g. ESPHome) implements the provider
/// against NVS/Preferences instead.

#pragma once

#include "sendspin/client.h"

#include <mutex>
#include <string>

namespace sendspin {

/// @brief File-backed persistence provider.
///
/// All data is stored in a single JSON file at `path`. The file is
/// overwritten atomically on every save. Each method re-reads the file on
/// load and re-serializes on save (small data, infrequent calls).
class FilePersistenceProvider : public SendspinPersistenceProvider {
public:
    /// @brief Construct with the path to the JSON persistence file.
    explicit FilePersistenceProvider(std::string path);

    // ========================================================================
    // Static keypair
    // ========================================================================
    bool save_static_keypair(const std::array<uint8_t, 32>& private_key) override;
    std::optional<std::array<uint8_t, 32>> load_static_keypair() override;

    // ========================================================================
    // Last-played server_id
    // ========================================================================
    bool save_last_played_server_id(const std::string& server_id) override;
    std::optional<std::string> load_last_played_server_id() override;

    // ========================================================================
    // Pairing records
    // ========================================================================
    std::vector<SendspinPairingRecord> load_pairing_records() override;
    bool save_pairing_record(const SendspinPairingRecord& record) override;
    void remove_pairing_record(const std::string& psk_id) override;

    // ========================================================================
    // Accepted Pairing PSK
    // ========================================================================
    std::optional<SendspinPairingPsk> load_pairing_psk() override;
    bool save_pairing_psk(const SendspinPairingPsk& psk) override;
    void clear_pairing_psk() override;

    // ========================================================================
    // Static PIN
    // ========================================================================
    std::optional<std::string> load_static_pin() override;
    bool save_static_pin(const std::string& pin) override;
    void clear_static_pin() override;

    // ========================================================================
    // Pairing config
    // ========================================================================
    std::optional<SendspinPairingConfig> load_pairing_config() override;
    bool save_pairing_config(const SendspinPairingConfig& config) override;

    // ========================================================================
    // Player static delay
    // ========================================================================
    bool save_static_delay(uint16_t delay_ms) override;
    std::optional<uint16_t> load_static_delay() override;

private:
    // save_pairing_record is called on the network thread during pairing finalize, while the
    // other methods run on the main loop. This mutex serializes the read-modify-write of the
    // backing file so concurrent calls cannot lose an update.
    std::mutex mutex_;
    std::string path_;
};

}  // namespace sendspin
