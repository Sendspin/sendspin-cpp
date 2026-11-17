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

/// @file connection_block.h
/// @brief A connection object and its shared_ptr control block in one block from the platform heap

#pragma once

#include "platform/memory.h"

#include <cassert>
#include <cstddef>
#include <memory>
#include <mutex>
#include <utility>

namespace sendspin {

/// @brief Bytes reserved for one Conn: the object plus the control block std::allocate_shared()
/// places it in, whose fit ConnectionBlockAllocator::allocate() checks at compile time
///
/// 32 bytes cover a control block that counts with atomics. A libstdc++ built with the mutex lock
/// policy, as Raspbian's ARMv6 one is, also embeds a mutex in it, and std::mutex has the size of
/// that mutex.
template <typename Conn>
inline constexpr size_t CONNECTION_BLOCK_BYTES = sizeof(Conn) + 32 + sizeof(std::mutex);

/// @brief Hands std::allocate_shared() one block reserved before the call, and frees it with
/// platform_free() once the control block goes
///
/// allocate_shared() constructs into whatever allocate() returns, so an allocator cannot report a
/// failure by returning nullptr. The block is reserved from the platform_malloc family first
/// (make_connection_in_block()), where a failure refuses the connection instead of aborting as
/// operator new does, and allocate() only hands it over. Conn names the connection type the block
/// was sized for and survives the rebind to the control block's type.
template <typename T, typename Conn>
class ConnectionBlockAllocator {
public:
    using value_type = T;

    explicit ConnectionBlockAllocator(void* block) : block_(block) {}

    /// @brief The rebind allocate_shared() performs to allocate its control block
    template <typename U>
    ConnectionBlockAllocator(const ConnectionBlockAllocator<U, Conn>& other)
        : block_(other.block()) {}

    T* allocate(size_t n) {
        static_assert(sizeof(T) <= CONNECTION_BLOCK_BYTES<Conn>,
                      "CONNECTION_BLOCK_BYTES must hold the connection's control block");
        assert(n == 1);
        (void)n;
        return static_cast<T*>(this->block_);
    }

    void deallocate(T* p, size_t /*n*/) {
        platform_free(p);
    }

    void* block() const {
        return this->block_;
    }

    template <typename U>
    bool operator==(const ConnectionBlockAllocator<U, Conn>& other) const {
        return this->block_ == other.block();
    }

private:
    void* block_;
};

/// @brief Creates a connection in a block from the internal-RAM-preferring platform heap
///
/// The PSRAM fallback is safe for both connection types placed here, SendspinServerConnection
/// and SendspinClientConnection: IDF's default STDATOMIC_S32C1I_SPIRAM_WORKAROUND covers their
/// std::atomic members in external RAM on ESP32/S3, they embed no FreeRTOS object or portMUX
/// (their event groups and mutexes hold handles to blocks of their own), and no ISR touches them.
/// @return nullptr when the block cannot be allocated.
template <typename Conn, typename... Args>
std::shared_ptr<Conn> make_connection_in_block(Args&&... args) {
    void* block = platform_malloc_internal(CONNECTION_BLOCK_BYTES<Conn>);
    if (block == nullptr) {
        return nullptr;
    }
    return std::allocate_shared<Conn>(ConnectionBlockAllocator<Conn, Conn>(block),
                                      std::forward<Args>(args)...);
}

}  // namespace sendspin
