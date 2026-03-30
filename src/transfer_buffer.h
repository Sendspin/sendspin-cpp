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

#include "platform/memory.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace sendspin {

class PlayerRoleListener;

/// @brief Simple transfer buffer for moving decoded audio data to the audio output.
///
/// Manages a flat byte array with read/write cursors. Data is written at get_buffer_end() and
/// read from get_buffer_start(). The player listener is invoked via transfer_data_to_sink().
class TransferBuffer {
public:
    ~TransferBuffer();

    /// @brief Creates a new transfer buffer.
    /// @param buffer_size Size of the buffer in bytes.
    /// @return unique_ptr if successfully allocated, nullptr otherwise.
    static std::unique_ptr<TransferBuffer> create(size_t buffer_size);

    /// @brief Sets the player listener for transfer_data_to_sink().
    void set_listener(PlayerRoleListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Writes buffered data to the sink.
    /// @param timeout_ms Milliseconds to block while waiting for the sink (UINT32_MAX = wait
    /// forever).
    /// @return Number of bytes written to the sink.
    size_t transfer_data_to_sink(uint32_t timeout_ms);

    /// @brief Returns the number of bytes available to read.
    size_t available() const {
        return this->buffer_length_;
    }

    /// @brief Returns a pointer past the end of available data (where new data can be written).
    uint8_t* get_buffer_end() const {
        return this->data_start_ + this->buffer_length_;
    }

    /// @brief Returns a pointer to the start of available data.
    uint8_t* get_buffer_start() const {
        return this->data_start_;
    }

    /// @brief Returns the allocated capacity in bytes.
    size_t capacity() const {
        return this->buffer_.size();
    }

    /// @brief Returns the number of free bytes available to write.
    size_t free() const;

    /// @brief Advances the read cursor after data has been consumed.
    void decrease_buffer_length(size_t bytes);

    /// @brief Advances the write cursor after data has been written.
    void increase_buffer_length(size_t bytes);

    /// @brief Reallocates the buffer, preserving existing data.
    /// @param new_buffer_size New size in bytes. Must be >= available().
    /// @return True if successful, false otherwise (original buffer remains valid).
    bool reallocate(size_t new_buffer_size);

protected:
    TransferBuffer() = default;

    bool allocate_buffer_(size_t buffer_size);
    void deallocate_buffer_();

    // Struct fields
    PlatformBuffer buffer_;

    // Pointer fields
    uint8_t* data_start_{nullptr};
    PlayerRoleListener* listener_{nullptr};

    // size_t fields
    size_t buffer_length_{0};
};

}  // namespace sendspin
