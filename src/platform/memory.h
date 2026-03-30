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
                                   MALLOC_CAP_INTERNAL);
}

/// @brief Reallocates memory, preferring SPIRAM on ESP-IDF. Falls back to internal RAM
/// @param ptr Pointer to the block to reallocate, or nullptr to allocate a new block.
/// @param size New size in bytes.
/// @return Pointer to the reallocated memory, or nullptr on failure.
inline void* platform_realloc(void* ptr, size_t size) {
    return heap_caps_realloc_prefer(ptr, size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                    MALLOC_CAP_INTERNAL);
}

/// @brief Frees memory allocated by platform_malloc or platform_realloc
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

/// @brief Frees memory allocated by platform_malloc or platform_realloc
/// @param ptr Pointer to the block to free, or nullptr.
inline void platform_free(void* ptr) {
    free(ptr);
}

}  // namespace sendspin

#endif  // ESP_PLATFORM

namespace sendspin {

/// @brief RAII wrapper for platform-allocated memory buffers.
///
/// Owns a block of memory obtained via platform_malloc. Automatically frees on destruction.
/// Supports reallocation and move semantics. Not copyable.
class PlatformBuffer {
public:
    PlatformBuffer() = default;

    ~PlatformBuffer() {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
        }
    }

    // Move-only
    PlatformBuffer(PlatformBuffer&& other) noexcept : ptr_(other.ptr_), size_(other.size_) {
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
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    PlatformBuffer(const PlatformBuffer&) = delete;
    PlatformBuffer& operator=(const PlatformBuffer&) = delete;

    /// @brief Allocates a new buffer. Any previously held memory is freed.
    /// @return true if allocation succeeded.
    bool allocate(size_t size) {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
        }
        this->ptr_ = static_cast<uint8_t*>(platform_malloc(size));
        this->size_ = (this->ptr_ != nullptr) ? size : 0;
        return this->ptr_ != nullptr;
    }

    /// @brief Reallocates the buffer to a new size, preserving existing data.
    /// On failure, the original buffer remains valid.
    /// @return true if reallocation succeeded.
    bool realloc(size_t new_size) {
        uint8_t* new_ptr = static_cast<uint8_t*>(platform_realloc(this->ptr_, new_size));
        if (new_ptr == nullptr) {
            return false;
        }
        this->ptr_ = new_ptr;
        this->size_ = new_size;
        return true;
    }

    /// @brief Frees the held memory.
    void reset() {
        if (this->ptr_ != nullptr) {
            platform_free(this->ptr_);
            this->ptr_ = nullptr;
            this->size_ = 0;
        }
    }

    /// @brief Returns a pointer to the allocated buffer.
    /// @return Pointer to the buffer, or nullptr if not allocated.
    uint8_t* data() {
        return this->ptr_;
    }
    /// @brief Returns a const pointer to the allocated buffer.
    /// @return Const pointer to the buffer, or nullptr if not allocated.
    const uint8_t* data() const {
        return this->ptr_;
    }
    /// @brief Returns the current allocation size in bytes.
    /// @return Size of the allocated buffer in bytes.
    size_t size() const {
        return this->size_;
    }
    /// @brief Returns true if the buffer holds an allocation.
    /// @return true if memory is currently allocated.
    explicit operator bool() const {
        return this->ptr_ != nullptr;
    }

    /// @brief Returns a typed pointer into the buffer at a byte offset.
    template <typename T>
    T* as(size_t byte_offset = 0) {
        return reinterpret_cast<T*>(this->ptr_ + byte_offset);
    }

    template <typename T>
    const T* as(size_t byte_offset = 0) const {
        return reinterpret_cast<const T*>(this->ptr_ + byte_offset);
    }

private:
    // Pointer fields
    uint8_t* ptr_{nullptr};

    // size_t fields
    size_t size_{0};
};

/// @brief ArduinoJson allocator that routes through platform_malloc/platform_realloc/platform_free
/// so JSON processing uses PSRAM on ESP32.
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

/// Creates a JsonDocument that uses PSRAM-preferring allocation.
inline JsonDocument make_json_document() {
    return JsonDocument(PsramJsonAllocator::instance());
}

}  // namespace sendspin
