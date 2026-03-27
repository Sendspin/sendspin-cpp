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

#include <cstddef>
#include <cstdint>

namespace sendspin {

/// @brief Abstract interface for writing decoded audio data to a platform-specific audio output.
///
/// The platform (e.g., ESPHome) provides an implementation that bridges to its audio pipeline.
class AudioSink {
public:
    virtual ~AudioSink() = default;

    /// @brief Writes decoded PCM audio data to the output.
    /// @param data Pointer to the PCM audio data.
    /// @param length Number of bytes to write.
    /// @param timeout_ms Milliseconds to block while waiting for output to accept data
    ///                   (UINT32_MAX = wait forever).
    /// @return Number of bytes actually written.
    virtual size_t write(uint8_t* data, size_t length, uint32_t timeout_ms) = 0;
};

}  // namespace sendspin
