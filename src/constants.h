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

/// @file constants.h
/// @brief Shared constants for unit conversions and cross-task timing

#pragma once

#include <cstdint>

namespace sendspin {

static constexpr int64_t US_PER_MS = 1000LL;
static constexpr uint32_t MS_PER_SECOND = 1000U;
static constexpr uint32_t US_PER_SECOND = 1000000U;

/// @brief Wait time (ms) between retries while a task waits for the time filter's first
/// measurement (SendspinClient::is_time_synced()). Shared by the sync and source tasks so both
/// audio pipelines gate on time sync with the same cadence.
static constexpr uint32_t WAIT_FOR_TIME_SYNC_MS = 15U;

}  // namespace sendspin
