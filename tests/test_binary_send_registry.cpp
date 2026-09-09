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

/// @file test_binary_send_registry.cpp
/// @brief Ownership transitions of the queued-work keep-alive registry backing the ESP server's
/// binary send slot (engage/claim/reclaim, owner scoping, keep-alive lifetime)

#include "binary_send_registry.h"

#include <gtest/gtest.h>

#include <memory>

namespace sendspin {
namespace {

struct FakeBlock {
    std::shared_ptr<FakeBlock> self;
    int tag{0};
};

int owner_a;
int owner_b;

// Defends BinarySendRegistry::engage()/claim(): a queued block stays alive through its parked
// self-reference even when every external reference is dropped, and the worker's claim hands
// that reference back exactly once.
TEST(BinarySendRegistry, EngageKeepsBlockAliveUntilClaimed) {
    BinarySendRegistry<FakeBlock> registry;
    std::weak_ptr<FakeBlock> observer;
    FakeBlock* raw = nullptr;
    {
        auto block = std::make_shared<FakeBlock>();
        block->tag = 7;
        observer = block;
        raw = block.get();
        registry.engage(block, &owner_a);
    }
    // External reference gone; the parked self-reference must keep it alive.
    ASSERT_FALSE(observer.expired());

    auto keep = registry.claim(raw);
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(keep->tag, 7);

    // Claim is exactly-once: a second claim (a double-run) gets nothing.
    EXPECT_EQ(registry.claim(raw), nullptr);

    keep.reset();
    EXPECT_TRUE(observer.expired());
}

// Defends reclaim()'s owner scoping: stopping one server must break only that server's queued
// work; another live server's engaged block stays claimable. This is the cross-server
// use-after-free shape the scoping exists to prevent.
TEST(BinarySendRegistry, ReclaimTouchesOnlyTheStoppedOwner) {
    BinarySendRegistry<FakeBlock> registry;
    auto block_a = std::make_shared<FakeBlock>();
    auto block_b = std::make_shared<FakeBlock>();
    registry.engage(block_a, &owner_a);
    registry.engage(block_b, &owner_b);

    EXPECT_EQ(registry.reclaim(&owner_a), 1U);
    EXPECT_EQ(block_a->self, nullptr);

    // Owner B's block is untouched and still claimable by its worker.
    ASSERT_NE(block_b->self, nullptr);
    auto keep_b = registry.claim(block_b.get());
    ASSERT_NE(keep_b, nullptr);

    // A's block is no longer engaged: a late claim gets nothing rather than a stale reference.
    EXPECT_EQ(registry.claim(block_a.get()), nullptr);
}

// Defends reclaim()'s exactly-once accounting: a claimed block is no longer the registry's to
// reclaim, and a reclaimed owner has nothing left on a second reclaim.
TEST(BinarySendRegistry, ReclaimCountsOnlyStillEngagedBlocks) {
    BinarySendRegistry<FakeBlock> registry;
    auto first = std::make_shared<FakeBlock>();
    auto second = std::make_shared<FakeBlock>();
    registry.engage(first, &owner_a);
    registry.engage(second, &owner_a);

    auto keep = registry.claim(first.get());
    ASSERT_NE(keep, nullptr);

    EXPECT_EQ(registry.reclaim(&owner_a), 1U);
    EXPECT_EQ(registry.reclaim(&owner_a), 0U);

    // Re-engaging after a reclaim works: the registry holds no stale state for the owner.
    registry.engage(second, &owner_a);
    EXPECT_NE(registry.claim(second.get()), nullptr);
}

}  // namespace
}  // namespace sendspin
