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

#ifdef SENDSPIN_ENABLE_PLAYER

#include "audio_ring_buffer.h"

#include "platform/logging.h"

namespace sendspin {

static const char* const TAG = "sendspin.ring_buffer";

std::unique_ptr<SendspinAudioRingBuffer> SendspinAudioRingBuffer::create(size_t buffer_size) {
    auto rb = std::unique_ptr<SendspinAudioRingBuffer>(new SendspinAudioRingBuffer());

    rb->size_ = buffer_size;

    if (!rb->storage_.allocate(rb->size_)) {
        SS_LOGE(TAG, "Failed to allocate %zu bytes for ring buffer", buffer_size);
        return nullptr;
    }

    if (!rb->ring_buffer_.create(rb->size_, rb->storage_.data())) {
        SS_LOGE(TAG, "Failed to create ring buffer");
        rb->storage_.reset();
        return nullptr;
    }

    return rb;
}

SendspinAudioRingBuffer::~SendspinAudioRingBuffer() = default;

bool SendspinAudioRingBuffer::write_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                                          ChunkType chunk_type, uint32_t timeout_ms) {
    size_t total_size = sizeof(AudioRingBufferEntry) + data_size;

    void* acquired_memory = this->ring_buffer_.acquire(total_size, timeout_ms);
    if (acquired_memory == nullptr) {
        return false;
    }

    // Fill the header
    auto* entry = static_cast<AudioRingBufferEntry*>(acquired_memory);
    entry->timestamp = timestamp;
    entry->chunk_type = chunk_type;
    entry->data_size = data_size;

    // Copy audio data after the header
    if (data_size > 0 && data != nullptr) {
        std::memcpy(entry->data(), data, data_size);
    }

    // Commit the entry
    return this->ring_buffer_.commit(acquired_memory);
}

AudioRingBufferEntry* SendspinAudioRingBuffer::receive_chunk(uint32_t timeout_ms) {
    size_t item_size = 0;
    void* received_item = this->ring_buffer_.receive(&item_size, timeout_ms);
    if (received_item == nullptr) {
        return nullptr;
    }

    return static_cast<AudioRingBufferEntry*>(received_item);
}

void SendspinAudioRingBuffer::return_chunk(AudioRingBufferEntry* entry) {
    if (entry == nullptr) {
        return;
    }
    this->ring_buffer_.return_item(entry);
}

void SendspinAudioRingBuffer::reset() {
    size_t item_size = 0;
    void* item = nullptr;
    while ((item = this->ring_buffer_.receive(&item_size, 0)) != nullptr) {
        this->ring_buffer_.return_item(item);
    }
}

}  // namespace sendspin

#endif  // SENDSPIN_ENABLE_PLAYER
