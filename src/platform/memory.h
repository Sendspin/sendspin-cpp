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

#include "sendspin/types.h"
#include <ArduinoJson.h>

#include <cstddef>
#include <cstdlib>

#ifdef ESP_PLATFORM

#include <esp_heap_caps.h>

namespace sendspin {

/// @brief Allocates memory, preferring SPIRAM on ESP-IDF. Falls back to internal RAM
/// @param size Number of bytes to allocate.
/// @return Pointer to the allocated memory, or nullptr on failure.
inline void* platform_malloc(size_t size) {
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/// @brief Reallocates memory, preferring SPIRAM on ESP-IDF. Falls back to internal RAM
/// @param ptr Pointer to the block to reallocate, or nullptr to allocate a new block.
/// @param size New size in bytes.
/// @return Pointer to the reallocated memory, or nullptr on failure.
inline void* platform_realloc(void* ptr, size_t size) {
    return heap_caps_realloc_prefer(ptr, size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/// @brief Allocates memory, preferring internal RAM on ESP-IDF. Falls back to SPIRAM
/// @param size Number of bytes to allocate.
/// @return Pointer to the allocated memory, or nullptr on failure.
inline void* platform_malloc_internal(size_t size) {
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

/// @brief Reallocates memory, preferring internal RAM on ESP-IDF. Falls back to SPIRAM
/// @param ptr Pointer to the block to reallocate, or nullptr to allocate a new block.
/// @param size New size in bytes.
/// @return Pointer to the reallocated memory, or nullptr on failure.
inline void* platform_realloc_internal(void* ptr, size_t size) {
    return heap_caps_realloc_prefer(ptr, size, 2, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

/// @brief Frees memory allocated by any platform_malloc[_internal] or platform_realloc[_internal]
/// @param ptr Pointer to the block to free, or nullptr.
inline void platform_free(void* ptr) {
    heap_caps_free(ptr);
}

}  // namespace sendspin

#else  // Host

namespace sendspin {

/// @brief Allocates a block of memory
/// @param size Number of bytes to allocate.
/// @return Pointer to the allocated memory, or nullptr on failure.
inline void* platform_malloc(size_t size) {
    return malloc(size);
}

/// @brief Reallocates a previously allocated block of memory
/// @param ptr Pointer to the block to reallocate, or nullptr to allocate a new block.
/// @param size New size in bytes.
/// @return Pointer to the reallocated memory, or nullptr on failure.
inline void* platform_realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}

/// @brief Allocates a block of memory (host has no internal/external distinction)
/// @param size Number of bytes to allocate.
/// @return Pointer to the allocated memory, or nullptr on failure.
inline void* platform_malloc_internal(size_t size) {
    return malloc(size);
}

/// @brief Reallocates a previously allocated block of memory (host has no internal/external
/// distinction)
/// @param ptr Pointer to the block to reallocate, or nullptr to allocate a new block.
/// @param size New size in bytes.
/// @return Pointer to the reallocated memory, or nullptr on failure.
inline void* platform_realloc_internal(void* ptr, size_t size) {
    return realloc(ptr, size);
}

/// @brief Frees memory allocated by any platform_malloc[_internal] or platform_realloc[_internal]
/// @param ptr Pointer to the block to free, or nullptr.
inline void platform_free(void* ptr) {
    free(ptr);
}

}  // namespace sendspin

#endif  // ESP_PLATFORM

namespace sendspin {

/**
 * @brief RAII wrapper for platform-allocated memory buffers
 *
 * Owns a block of memory obtained via platform_malloc / platform_malloc_internal. Automatically
 * frees on destruction. Supports reallocation and move semantics. Not copyable.
 *
 * The MemoryLocation passed to allocate() is stored on the buffer and reused by subsequent
 * realloc() calls, so the placement preference is preserved across resizes. The location also
 * carries through move construction and move assignment.
 *
 * Usage:
 * 1. Default-construct a PlatformBuffer, then call allocate() with the desired size and (on ESP)
 *    optional MemoryLocation preference (defaults to PREFER_EXTERNAL / SPIRAM-first)
 * 2. Access the raw memory with data() or via the typed as<T>() accessor
 * 3. Optionally grow the buffer in-place with realloc(), which keeps the original location
 *    preference
 * 4. Memory is freed automatically on destruction, or explicitly via reset()
 *
 * @code
 * PlatformBuffer buf;
 * buf.allocate(1024, MemoryLocation::PREFER_INTERNAL);
 *
 * auto* header = buf.as<MyHeader>();
 * header->magic = 0xDEAD;
 *
 * buf.realloc(2048);  // also prefers internal RAM
 * @endcode
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
    /// @return The current location preference.
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

    /// @brief Returns a pointer to the allocated buffer
    /// @return Pointer to the buffer, or nullptr if not allocated.
    uint8_t* data() {
        return this->ptr_;
    }
    /// @brief Returns a const pointer to the allocated buffer
    /// @return Const pointer to the buffer, or nullptr if not allocated.
    const uint8_t* data() const {
        return this->ptr_;
    }
    /// @brief Returns the current allocation size in bytes
    /// @return Size of the allocated buffer in bytes.
    size_t size() const {
        return this->size_;
    }
    /// @brief Returns true if the buffer holds an allocation
    /// @return true if memory is currently allocated.
    explicit operator bool() const {
        return this->ptr_ != nullptr;
    }

    /// @brief Returns a typed pointer into the buffer at a byte offset
    /// @param byte_offset Byte offset from the start of the buffer.
    /// @return Typed pointer to the buffer at the given offset.
    template <typename T>
    T* as(size_t byte_offset = 0) {
        return reinterpret_cast<T*>(this->ptr_ + byte_offset);
    }

    /// @brief Returns a const typed pointer into the buffer at a byte offset
    /// @param byte_offset Byte offset from the start of the buffer.
    /// @return Const typed pointer to the buffer at the given offset.
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
    /// @brief Allocates a block of memory via platform_malloc
    /// @param size Number of bytes to allocate.
    /// @return Pointer to the allocated memory, or nullptr on failure.
    void* allocate(size_t size) override {
        return platform_malloc(size);
    }

    /// @brief Frees a block of memory via platform_free
    /// @param ptr Pointer to the block to free.
    void deallocate(void* ptr) override {
        platform_free(ptr);
    }

    /// @brief Reallocates a block of memory via platform_realloc
    /// @param ptr Pointer to the block to reallocate.
    /// @param new_size New size in bytes.
    /// @return Pointer to the reallocated memory, or nullptr on failure.
    void* reallocate(void* ptr, size_t new_size) override {
        return platform_realloc(ptr, new_size);
    }

    /// @brief Returns the singleton allocator instance
    /// @return Pointer to the shared PsramJsonAllocator instance.
    static PsramJsonAllocator* instance() {
        static PsramJsonAllocator instance;
        return &instance;
    }
};

/// @brief Creates a JsonDocument that uses PSRAM-preferring allocation
/// @return A JsonDocument configured to use the platform's PSRAM-preferring allocator
inline JsonDocument make_json_document() {
    return JsonDocument(PsramJsonAllocator::instance());
}

}  // namespace sendspin
