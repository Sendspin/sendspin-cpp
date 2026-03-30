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

/// @file audio_ring_buffer.h
/// @brief Pre-allocated SPSC ring buffer for zero-copy encoded audio chunk transfer between the
/// network and sync task

#pragma once

#include "platform/memory.h"
#include "platform/spsc_ring_buffer.h"
#include "sendspin/player_role.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

namespace sendspin {

/// @brief Header for entries stored in the ring buffer.
/// Variable-length audio data follows immediately after this struct.
struct AudioRingBufferEntry {
    int64_t timestamp;
    ChunkType chunk_type;
    size_t data_size;

    /// @brief Returns a pointer to the variable-length audio data following this header
    /// @return Pointer to the audio data bytes immediately after this struct.
    uint8_t* data() {
        return reinterpret_cast<uint8_t*>(this) + sizeof(AudioRingBufferEntry);
    }

    /// @brief Returns a const pointer to the variable-length audio data following this header
    /// @return Const pointer to the audio data bytes immediately after this struct.
    const uint8_t* data() const {
        return reinterpret_cast<const uint8_t*>(this) + sizeof(AudioRingBufferEntry);
    }
};

/// @brief Pre-allocated ring buffer for audio chunks using FreeRTOS RINGBUF_TYPE_NOSPLIT.
///
/// Threading model: Single-Producer Single-Consumer (SPSC)
/// - Producer (WS callback thread) calls write_chunk()
/// - Consumer (sync task) calls receive_chunk() / return_chunk()
///
/// Zero per-chunk heap allocation: all data is stored contiguously in the pre-allocated ring
/// buffer.
class SendspinAudioRingBuffer {
public:
    /// @brief Creates a ring buffer with the specified total storage size.
    /// @param buffer_size Total ring buffer storage in bytes.
    /// @return unique_ptr to the ring buffer, or nullptr on allocation failure.
    static std::unique_ptr<SendspinAudioRingBuffer> create(size_t buffer_size);

    ~SendspinAudioRingBuffer();

    /// @brief Writes an audio chunk into the ring buffer.
    /// @param data Pointer to the audio data.
    /// @param data_size Size of the audio data in bytes.
    /// @param timestamp Server timestamp for this chunk.
    /// @param chunk_type Type of audio chunk.
    /// @param timeout_ms Milliseconds to wait if buffer is full (UINT32_MAX = wait forever).
    /// @return true if successfully written, false if buffer full or error.
    bool write_chunk(const uint8_t* data, size_t data_size, int64_t timestamp, ChunkType chunk_type,
                     uint32_t timeout_ms);

    /// @brief Receives the next audio chunk from the ring buffer.
    /// @param timeout_ms Milliseconds to wait if buffer is empty (UINT32_MAX = wait forever).
    /// @return Pointer to the entry, or nullptr if nothing available.
    /// @note Caller MUST call return_chunk() when done with the entry.
    AudioRingBufferEntry* receive_chunk(uint32_t timeout_ms);

    /// @brief Returns a previously received chunk to the ring buffer.
    /// @param entry Pointer previously returned by receive_chunk(). May be nullptr (no-op).
    void return_chunk(AudioRingBufferEntry* entry);

    /// @brief Drains all items from the ring buffer.
    /// @note Only safe to call when the consumer task is stopped.
    void reset();

protected:
    SendspinAudioRingBuffer() = default;

    // Struct fields
    SpscRingBuffer ring_buffer_;
    PlatformBuffer storage_;

    // size_t fields
    size_t size_{0};
};

}  // namespace sendspin
