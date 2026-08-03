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

/// @file noise_rand.cpp
/// @brief ESP-IDF implementation of noise-c's custom RNG hook.
///
/// The esphome/noise-c component is built with NOISE_USE_CUSTOM_RAND=1 (there is no
/// /dev/urandom on ESP-IDF), so noise-c declares but does not define noise_rand_bytes()
/// and expects the consuming application to supply it. randstate.c (reseed) and the DH
/// backend (keypair generation) both call it. We back it with the ESP32 hardware RNG via
/// esp_fill_random(), which is a cryptographically secure entropy source while the RF
/// subsystem (Wi-Fi/Bluetooth) is enabled -- always the case for a running Sendspin client.
///
/// The host build instead compiles noise-c's rand_os.c with NOISE_USE_CUSTOM_RAND=0, so
/// this translation unit is ESP-only (see cmake/sources.cmake SENDSPIN_ESP_SOURCES).
///
/// The definition is WEAK on purpose: ESPHome's own API component defines a strong
/// noise_rand_bytes() when the encrypted native API is enabled (USE_API_NOISE). On a device
/// that uses both Sendspin and the encrypted API, two strong definitions would be a duplicate-
/// symbol link error. Making ours weak lets ESPHome's strong definition take precedence when
/// present, while ours still satisfies noise-c on any build that lacks one. (The sendspin-cpp
/// component is linked WHOLE_ARCHIVE so this object is pulled in even though nothing in
/// sendspin-cpp references the symbol directly - see the top-level CMakeLists.txt.)

#include "esp_random.h"

#include <cstddef>

// Prototype matching noise-c's declaration (src/protocol/internal.h in the fetched
// esphome/noise-c component, not vendored in this repo). -Wmissing-prototypes /
// -Wmissing-declarations require a declared prototype for any non-static, non-anonymous-
// namespace function; noise_rand_bytes must stay external linkage (see the WEAK rationale
// below), so the prototype is restated here rather than making the definition static.
extern "C" void noise_rand_bytes(void* bytes, size_t size);

// The definition is WEAK on purpose: ESPHome's own API component defines a strong
// noise_rand_bytes() when the encrypted native API is enabled (USE_API_NOISE). On a device
// that uses both Sendspin and the encrypted API, two strong definitions would be a duplicate-
// symbol link error. Making ours weak lets ESPHome's strong definition take precedence when
// present, while ours still satisfies noise-c on any build that lacks one. (The sendspin-cpp
// component is linked WHOLE_ARCHIVE so this object is pulled in even though nothing in
// sendspin-cpp references the symbol directly - see the top-level CMakeLists.txt.)
extern "C" __attribute__((weak)) void noise_rand_bytes(void* bytes, size_t size) {
    esp_fill_random(bytes, size);
}
