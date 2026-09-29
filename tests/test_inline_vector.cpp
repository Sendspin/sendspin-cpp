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

/// @file test_inline_vector.cpp
/// @brief Tests for InlineVector: order-preserving erase, element release at removal, and swap

#include "inline_vector.h"

#include <gtest/gtest.h>

#include <memory>

namespace sendspin {
namespace {

using SharedVector = InlineVector<std::shared_ptr<int>, 3>;

// A removed shared_ptr must drop its reference at the removal, not linger in the vacated slot:
// ConnectionManager relies on that to release connections at a known point.
TEST(InlineVector, EraseAndClearReleaseElementsImmediately) {
    auto a = std::make_shared<int>(1);
    auto b = std::make_shared<int>(2);
    auto c = std::make_shared<int>(3);
    SharedVector v;
    v.push_back(a);
    v.push_back(b);
    v.push_back(c);

    // Erasing the front shifts the tail down in order and returns the follower.
    auto next = v.erase(v.begin());
    ASSERT_EQ(v.size(), 2U);
    EXPECT_EQ(*next, b);
    EXPECT_EQ(v[0], b);
    EXPECT_EQ(v[1], c);
    EXPECT_EQ(a.use_count(), 1);

    // Erasing the last element has no follower to overwrite its slot, so the reset must.
    next = v.erase(v.begin() + 1);
    EXPECT_EQ(next, v.end());
    EXPECT_EQ(c.use_count(), 1);

    v.clear();
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(b.use_count(), 1);
}

TEST(InlineVector, SwapExchangesContentsAndSizes) {
    auto a = std::make_shared<int>(1);
    auto b = std::make_shared<int>(2);
    auto c = std::make_shared<int>(3);
    SharedVector one;
    SharedVector two;
    one.push_back(a);
    two.push_back(b);
    two.push_back(c);

    one.swap(two);

    ASSERT_EQ(one.size(), 2U);
    ASSERT_EQ(two.size(), 1U);
    EXPECT_EQ(one[0], b);
    EXPECT_EQ(one[1], c);
    EXPECT_EQ(two[0], a);
}

}  // namespace
}  // namespace sendspin
