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

/// @file network_info.cpp
/// @brief ESP-IDF MAC detection: MAC of the default network interface (Wi-Fi or Ethernet)

#include "platform/network_info.h"

#include "platform/logging.h"
#include <esp_mac.h>
#include <esp_netif.h>

#include <cstdint>
#include <cstdio>

namespace sendspin {

static const char* const TAG = "sendspin.network_info";

namespace {

/// @brief Size of a formatted MAC string buffer: "aa:bb:cc:dd:ee:ff" plus null terminator.
constexpr size_t MAC_STR_BUF_SIZE = 18;

/// @brief Formats six MAC octets as lowercase colon-separated text, or nullopt if all zero.
std::optional<std::string> format_mac(const uint8_t* mac) {
    bool all_zero = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        return std::nullopt;  // emulators/unprovisioned efuse can report a zeroed MAC
    }

    char buf[MAC_STR_BUF_SIZE];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
    return std::string(buf);
}

}  // namespace

std::optional<std::string> platform_get_interface_mac() {
    uint8_t mac[6] = {0};

    // Prefer the MAC of the default network interface — the one outbound connections route over.
    // This resolves to the correct address whether the device is on Wi-Fi or Ethernet.
    esp_netif_t* netif = esp_netif_get_default_netif();
    if (netif != nullptr && esp_netif_get_mac(netif, mac) == ESP_OK) {
        if (std::optional<std::string> detected = format_mac(mac); detected.has_value()) {
            return detected;
        }
    }

    // Fallback: factory Wi-Fi STA address from efuse. This does not require esp_wifi/esp_netif to
    // be initialized, so it still yields a stable identity if no default interface is up yet.
    const esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) {
        SS_LOGW(TAG, "MAC detection failed: %s", esp_err_to_name(err));
        return std::nullopt;
    }
    return format_mac(mac);
}

}  // namespace sendspin
