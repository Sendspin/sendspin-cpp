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

/// @file test_fixed_block_pool.cpp
/// @brief Tests for FixedBlockPool: size limit, exhaustion, block reuse, the claimed-block walk,
/// reset, and exclusive claims under contention

#include "fixed_block_pool.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <thread>
#include <vector>

namespace sendspin {
namespace {

// Claims every block, then checks the pool hands out nothing more until one comes back, and that
// for_each_claimed() visits exactly the blocks still claimed. Run at 3 blocks and at the full
// 32-bit mask, whose all-free value is computed differently.
template <size_t BLOCK_SIZE, size_t BLOCK_COUNT>
void check_claims_each_block_once() {
    FixedBlockPool<BLOCK_SIZE, BLOCK_COUNT> pool;
    EXPECT_EQ(pool.try_acquire(BLOCK_SIZE + 1), nullptr);

    std::set<uintptr_t> blocks;
    for (size_t i = 0; i < BLOCK_COUNT; ++i) {
        void* block = pool.try_acquire(BLOCK_SIZE);
        ASSERT_NE(block, nullptr);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(block) % alignof(std::max_align_t), 0U);
        blocks.insert(reinterpret_cast<uintptr_t>(block));
    }
    ASSERT_EQ(blocks.size(), BLOCK_COUNT);
    EXPECT_EQ(*blocks.rbegin() - *blocks.begin(), (BLOCK_COUNT - 1) * BLOCK_SIZE);
    EXPECT_EQ(pool.try_acquire(1), nullptr);

    // The released block, and only it, becomes available again.
    void* returned = reinterpret_cast<void*>(*std::next(blocks.begin(), BLOCK_COUNT / 2));
    pool.release(returned);
    std::set<uintptr_t> visited;
    pool.for_each_claimed([&visited](void* block) {
        EXPECT_TRUE(visited.insert(reinterpret_cast<uintptr_t>(block)).second) << "visited twice";
    });
    std::set<uintptr_t> still_claimed = blocks;
    still_claimed.erase(reinterpret_cast<uintptr_t>(returned));
    EXPECT_EQ(visited, still_claimed);
    EXPECT_EQ(pool.try_acquire(1), returned);
    EXPECT_EQ(pool.try_acquire(1), nullptr);

    // reset() reclaims every block, including ones never released.
    pool.reset();
    pool.for_each_claimed([](void*) { ADD_FAILURE() << "a block reads as claimed after reset()"; });
    for (size_t i = 0; i < BLOCK_COUNT; ++i) {
        EXPECT_NE(pool.try_acquire(1), nullptr);
    }
    EXPECT_EQ(pool.try_acquire(1), nullptr);
}

TEST(FixedBlockPool, ClaimsEachBlockOnceUntilReleased) {
    check_claims_each_block_once<64, 3>();
    check_claims_each_block_once<16, 32>();
}

// Two claimants holding the same block at once would overwrite each other's stamp.
TEST(FixedBlockPool, ConcurrentClaimsAreExclusive) {
    constexpr size_t BLOCK_COUNT = 3;
    constexpr int THREADS = 6;
    constexpr int ITERATIONS = 20000;
    FixedBlockPool<16, BLOCK_COUNT> pool;
    std::vector<std::thread> threads;
    threads.reserve(THREADS);
    std::vector<int> collisions(THREADS, 0);

    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&pool, &collisions, t] {
            for (int i = 0; i < ITERATIONS; ++i) {
                void* block = pool.try_acquire(sizeof(int));
                if (block == nullptr) {
                    continue;
                }
                std::memcpy(block, &t, sizeof(t));
                std::this_thread::yield();
                int owner = -1;
                std::memcpy(&owner, block, sizeof(owner));
                if (owner != t) {
                    ++collisions[t];
                }
                pool.release(block);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    for (int t = 0; t < THREADS; ++t) {
        EXPECT_EQ(collisions[t], 0) << "thread " << t;
    }
    // Every block came back: the pool is full again.
    for (size_t i = 0; i < BLOCK_COUNT; ++i) {
        EXPECT_NE(pool.try_acquire(1), nullptr);
    }
    EXPECT_EQ(pool.try_acquire(1), nullptr);
}

}  // namespace
}  // namespace sendspin
