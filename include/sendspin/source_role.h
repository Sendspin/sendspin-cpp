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

/// @file source_role.h
/// @brief Audio capture role that streams audio from the client to the Sendspin server

#pragma once

#include <cstdint>

namespace sendspin {

// ============================================================================
// Source types
// ============================================================================

/// @brief Line-input signal state reported by the source role in client/state messages
enum class SourceSignal : uint8_t {
    PRESENT,  // Audio signal detected on the capture input
    ABSENT,   // No audio signal on the capture input
};

}  // namespace sendspin
