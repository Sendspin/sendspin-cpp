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

/// @file opus_state_location.h
/// @brief Shared memory-placement rule for the libopus codec state this library allocates

#pragma once

#include "sendspin/types.h"

namespace sendspin {

// Mirrors micro-opus's CONFIG_OPUS_STATE_MEMORY_PREFERENCE for the codec-state buffers this
// library allocates itself via the *_init() variants (decoder.cpp, source_encoder_opus.cpp), so
// one placement rule governs Opus state regardless of who allocated it. The strict *_ONLY modes
// are honored as a soft preference.
#if defined(CONFIG_OPUS_STATE_PREFER_INTERNAL) || defined(CONFIG_OPUS_STATE_INTERNAL_ONLY)
constexpr MemoryLocation OPUS_STATE_LOCATION = MemoryLocation::PREFER_INTERNAL;
#else
constexpr MemoryLocation OPUS_STATE_LOCATION = MemoryLocation::PREFER_EXTERNAL;
#endif

}  // namespace sendspin
