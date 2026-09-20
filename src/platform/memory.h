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

/// @file memory.h
/// @brief Platform-abstracted memory allocation with selectable SPIRAM-vs-internal preference on
/// ESP, plus RAII buffer and ArduinoJson allocator helpers

#pragma once

#include "platform/secure_zero.h"
#include "sendspin/types.h"
#include <ArduinoJson.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>

#ifdef ESP_PLATFORM

#include <esp_heap_caps.h>

namespace sendspin {

/// @brief Allocates memory, preferring SPIRAM on ESP-IDF. Falls back to internal RAM
inline void* platform_malloc(size_t size) {
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/// @brief Reallocates memory, preferring SPIRAM on ESP-IDF. Falls back to internal RAM
inline void* platform_realloc(void* ptr, size_t size) {
    return heap_caps_realloc_prefer(ptr, size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/// @brief Allocates memory, preferring internal RAM on ESP-IDF. Falls back to SPIRAM
inline void* platform_malloc_internal(size_t size) {
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

/// @brief Reallocates memory, preferring internal RAM on ESP-IDF. Falls back to SPIRAM
inline void* platform_realloc_internal(void* ptr, size_t size) {
    return heap_caps_realloc_prefer(ptr, size, 2, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

/// @brief Frees memory allocated by any platform_malloc[_internal] or platform_realloc[_internal]
inline void platform_free(void* ptr) {
    heap_caps_free(ptr);
}

}  // namespace sendspin

#else  // Host

namespace sendspin {

/// @brief Allocates a block of memory
inline void* platform_malloc(size_t size) {
    return malloc(size);
}

/// @brief Reallocates a previously allocated block of memory
inline void* platform_realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}

/// @brief Allocates a block of memory (host has no internal/external distinction)
inline void* platform_malloc_internal(size_t size) {
    return malloc(size);
}

/// @brief Reallocates a previously allocated block of memory (host has no internal/external
/// distinction)
inline void* platform_realloc_internal(void* ptr, size_t size) {
    return realloc(ptr, size);
}

/// @brief Frees memory allocated by any platform_malloc[_internal] or platform_realloc[_internal]
inline void platform_free(void* ptr) {
    free(ptr);
}

}  // namespace sendspin

#endif  // ESP_PLATFORM

namespace sendspin {

/**
 * @brief RAII wrapper for platform-allocated memory buffers
 *
 * Owns a block from platform_malloc / platform_malloc_internal and frees it on destruction.
 * Move-only. The MemoryLocation passed to allocate() is remembered and reused by realloc(), and
 * carries through a move.
 */
class PlatformBuffer {
public:
    PlatformBuffer() = default;

    ~PlatformBuffer() {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
        }
    }

    // Move-only
    PlatformBuffer(PlatformBuffer&& other) noexcept
        : ptr_(other.ptr_), size_(other.size_), location_(other.location_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    PlatformBuffer& operator=(PlatformBuffer&& other) noexcept {
        if (this != &other) {
            if (this->ptr_ != nullptr) {
                platform_free(this->ptr_);
            }
            this->ptr_ = other.ptr_;
            this->size_ = other.size_;
            this->location_ = other.location_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    PlatformBuffer(const PlatformBuffer&) = delete;
    PlatformBuffer& operator=(const PlatformBuffer&) = delete;

    /// @brief Allocates a new buffer. Any previously held memory is freed
    /// The location preference is remembered and reused by subsequent realloc() calls.
    /// @return true if allocation succeeded.
    bool allocate(size_t size, MemoryLocation location = MemoryLocation::PREFER_EXTERNAL) {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
        }
        this->location_ = location;
        this->ptr_ = static_cast<uint8_t*>((location == MemoryLocation::PREFER_INTERNAL)
                                               ? platform_malloc_internal(size)
                                               : platform_malloc(size));
        this->size_ = (this->ptr_ != nullptr) ? size : 0;
        return this->ptr_ != nullptr;
    }

    /// @brief Reallocates the buffer to a new size, preserving existing data
    /// Uses the location preference passed to the most recent allocate() call. On failure, the
    /// original buffer remains valid.
    /// @return true if reallocation succeeded.
    bool realloc(size_t new_size) {
        uint8_t* new_ptr =
            static_cast<uint8_t*>((this->location_ == MemoryLocation::PREFER_INTERNAL)
                                      ? platform_realloc_internal(this->ptr_, new_size)
                                      : platform_realloc(this->ptr_, new_size));
        if (new_ptr == nullptr) {
            return false;
        }
        this->ptr_ = new_ptr;
        this->size_ = new_size;
        return true;
    }

    /// @brief Returns the location preference last passed to allocate()
    MemoryLocation location() const {
        return this->location_;
    }

    /// @brief Frees the held memory
    void reset() {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
            this->ptr_ = nullptr;
            this->size_ = 0;
        }
    }

    /// @brief Pointer to the allocated buffer, or nullptr if not allocated
    uint8_t* data() {
        return this->ptr_;
    }
    /// @brief Const pointer to the allocated buffer, or nullptr if not allocated
    const uint8_t* data() const {
        return this->ptr_;
    }
    /// @brief Current allocation size in bytes
    size_t size() const {
        return this->size_;
    }
    /// @brief Whether the buffer holds an allocation
    explicit operator bool() const {
        return this->ptr_ != nullptr;
    }

    /// @brief Typed pointer into the buffer at a byte offset
    template <typename T>
    T* as(size_t byte_offset = 0) {
        return reinterpret_cast<T*>(this->ptr_ + byte_offset);
    }

    /// @brief Const typed pointer into the buffer at a byte offset
    template <typename T>
    const T* as(size_t byte_offset = 0) const {
        return reinterpret_cast<const T*>(this->ptr_ + byte_offset);
    }

private:
    // Pointer fields
    uint8_t* ptr_{nullptr};

    // size_t fields
    size_t size_{0};

    // Enum fields
    MemoryLocation location_{MemoryLocation::PREFER_EXTERNAL};
};

/// @brief ArduinoJson allocator that routes through platform_malloc/platform_realloc/platform_free
/// so JSON processing uses PSRAM on ESP32
class PsramJsonAllocator : public ArduinoJson::Allocator {
public:
    void* allocate(size_t size) override {
        return platform_malloc(size);
    }

    void deallocate(void* ptr) override {
        platform_free(ptr);
    }

    void* reallocate(void* ptr, size_t new_size) override {
        return platform_realloc(ptr, new_size);
    }

    static PsramJsonAllocator* instance() {
        static PsramJsonAllocator instance;
        return &instance;
    }
};

/// @brief Creates a JsonDocument that uses PSRAM-preferring allocation
inline JsonDocument make_json_document() {
    return JsonDocument(PsramJsonAllocator::instance());
}

/// @brief ArduinoJson allocator that wipes each block before freeing it, for documents that may
/// hold key material. `ArduinoJson::Allocator::deallocate()` receives only a pointer, so the size
/// is stashed in a small header before each block. reallocate() copies into a fresh block rather
/// than growing in place, so the old PSK-bearing block goes through this class's own wipe.
/// Not for the protocol hot path (use PsramJsonAllocator): every block pays for the header.
class ZeroizingJsonAllocator : public ArduinoJson::Allocator {
public:
    /// @brief Allocates `size` bytes, plus a hidden header recording that size for deallocate().
    void* allocate(size_t size) override {
        void* raw = platform_malloc(HEADER_SIZE + size);
        if (raw == nullptr) {
            return nullptr;
        }
        *static_cast<size_t*>(raw) = size;
        return static_cast<uint8_t*>(raw) + HEADER_SIZE;
    }

    /// @brief Wipes the block, recovering its size from the header, and frees it. Null is a
    /// no-op.
    void deallocate(void* ptr) override {
        if (ptr == nullptr) {
            return;
        }
        uint8_t* raw = static_cast<uint8_t*>(ptr) - HEADER_SIZE;
        const size_t size = *reinterpret_cast<size_t*>(raw);
        secure_zero(raw, HEADER_SIZE + size);
        platform_free(raw);
    }

    /// @brief Reallocates via a fresh allocate() + copy + deallocate() of the old block, so the
    /// old block is wiped. Returns nullptr on failure, leaving the old block intact.
    void* reallocate(void* ptr, size_t new_size) override {
        if (ptr == nullptr) {
            return this->allocate(new_size);
        }
        uint8_t* raw = static_cast<uint8_t*>(ptr) - HEADER_SIZE;
        const size_t old_size = *reinterpret_cast<size_t*>(raw);

        void* new_ptr = this->allocate(new_size);
        if (new_ptr == nullptr) {
            return nullptr;
        }
        std::memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
        this->deallocate(ptr);
        return new_ptr;
    }

    static ZeroizingJsonAllocator* instance() {
        static ZeroizingJsonAllocator instance;
        return &instance;
    }

private:
    /// Header size: rounded up to alignof(std::max_align_t) so the pointer handed back to
    /// ArduinoJson (raw + HEADER_SIZE) keeps whatever alignment platform_malloc() guarantees.
    static constexpr size_t HEADER_SIZE =
        alignof(std::max_align_t) >= sizeof(size_t) ? alignof(std::max_align_t) : sizeof(size_t);
};

/// @brief Creates a JsonDocument whose pool is wiped block-by-block as it frees memory, for
/// parsing/serializing documents that may hold PSK material (see ZeroizingJsonAllocator).
inline JsonDocument make_zeroizing_json_document() {
    return JsonDocument(ZeroizingJsonAllocator::instance());
}

}  // namespace sendspin
