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

#pragma once

#include "sendspin/protocol.h"

#include <cstdint>
#include <functional>

namespace sendspin {

/// @brief Narrow interface providing the time synchronization and delay information
/// that SyncTask needs from its owner. Decouples SyncTask from SendspinClient.
struct SyncTimeProvider {
    /// @brief Converts a server timestamp to the equivalent client timestamp.
    std::function<int64_t(int64_t)> get_client_time;

    /// @brief Returns true if the time filter has received at least one measurement.
    std::function<bool()> is_time_synced;

    /// @brief Returns the current static delay in milliseconds.
    std::function<uint16_t()> get_static_delay_ms;

    /// @brief Returns the fixed delay in microseconds (from config).
    std::function<int32_t()> get_fixed_delay_us;

    /// @brief Updates the client state (e.g., to SYNCHRONIZED when a stream starts).
    std::function<void(SendspinClientState)> update_state;
};

}  // namespace sendspin
