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

/// @file test_connection_block.cpp
/// @brief Tests that a connection and its shared_ptr control block fit CONNECTION_BLOCK_BYTES,
/// under the default lock policy and, on libstdc++, the mutex one

#include "client_connection.h"
#include "connection_block.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

namespace sendspin {
namespace {

using Conn = SendspinClientConnection;

// The object std::allocate_shared() constructed lies wholly inside the reserved block.
void expect_inside_block(const void* block, const Conn* conn) {
    auto begin = reinterpret_cast<uintptr_t>(block);
    auto object = reinterpret_cast<uintptr_t>(conn);
    EXPECT_GE(object, begin);
    EXPECT_LE(object + sizeof(Conn), begin + CONNECTION_BLOCK_BYTES<Conn>);
}

// The connection connect_to() makes, built the way make_connection_in_block() builds it: the block
// holds the object, and dropping the last reference frees the block (a leak would fail the
// sanitizer build).
TEST(ConnectionBlockTest, HoldsConnectionUnderDefaultPolicy) {
    void* block = platform_malloc_internal(CONNECTION_BLOCK_BYTES<Conn>);
    ASSERT_NE(block, nullptr);
    std::shared_ptr<Conn> conn =
        std::allocate_shared<Conn>(ConnectionBlockAllocator<Conn, Conn>(block), "ws://host:1/x");
    expect_inside_block(block, conn.get());
}

#if defined(__GLIBCXX__)
// Raspbian's ARMv6 libstdc++ defaults to the mutex lock policy, whose control block embeds a
// pthread_mutex_t; asking for that policy here builds the same layout on any libstdc++ host, so
// the static_assert in ConnectionBlockAllocator::allocate() fails to compile when the reserve no
// longer holds it.
TEST(ConnectionBlockTest, HoldsConnectionUnderMutexPolicy) {
    void* block = platform_malloc_internal(CONNECTION_BLOCK_BYTES<Conn>);
    ASSERT_NE(block, nullptr);
    std::__shared_ptr<Conn, __gnu_cxx::_S_mutex> conn =
        std::__allocate_shared<Conn, __gnu_cxx::_S_mutex>(
            ConnectionBlockAllocator<Conn, Conn>(block), "ws://host:1/x");
    expect_inside_block(block, conn.get());
}
#endif

}  // namespace
}  // namespace sendspin
