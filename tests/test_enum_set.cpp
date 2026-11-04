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

/// @file test_enum_set.cpp
/// @brief Tests for EnumSet: unique members, visited in enumerator order through the last its
/// capacity holds

#include "enum_set.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace sendspin {
namespace {

enum class Bit : uint8_t { B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15 };

struct Case {
    const char* what;
    std::vector<Bit> inserted;
    std::vector<Bit> visited;
};

// for_each() visits each member once, in enumerator order whatever the insertion order;
// contains() answers true for exactly the visited members, through the set's last enumerator.
template <size_t Capacity>
void expect_visits(std::initializer_list<Case> cases) {
    for (const Case& c : cases) {
        EnumSet<Bit, Capacity> set;
        for (const Bit member : c.inserted) {
            set.insert(member);
        }
        std::vector<Bit> seen;
        set.for_each([&seen](Bit member) { seen.push_back(member); });
        EXPECT_EQ(seen, c.visited) << c.what;
        for (uint8_t value = 0; value < Capacity; ++value) {
            const auto member = static_cast<Bit>(value);
            const bool listed =
                std::find(c.visited.begin(), c.visited.end(), member) != c.visited.end();
            EXPECT_EQ(set.contains(member), listed) << c.what << ", enumerator " << int{value};
        }
    }
}

// The default capacity holds the enumerators a byte holds, up to the eighth.
TEST(EnumSet, VisitsEachMemberOnceInEnumeratorOrder) {
    expect_visits<8>({
        {"Control: inserted in order", {Bit::B0, Bit::B3}, {Bit::B0, Bit::B3}},
        {"inserted out of order", {Bit::B5, Bit::B1, Bit::B3}, {Bit::B1, Bit::B3, Bit::B5}},
        {"a repeated member", {Bit::B2, Bit::B4, Bit::B2}, {Bit::B2, Bit::B4}},
        {"the eighth enumerator", {Bit::B7, Bit::B0}, {Bit::B0, Bit::B7}},
        {"empty", {}, {}},
    });
}

// Capacity 16 holds the enumerators past the eighth, up to the sixteenth.
TEST(EnumSet, ASixteenWideSetHoldsThroughTheSixteenthEnumerator) {
    expect_visits<16>({
        {"Control: the low byte", {Bit::B3, Bit::B0}, {Bit::B0, Bit::B3}},
        {"the ninth and the sixteenth enumerators",
         {Bit::B15, Bit::B8, Bit::B7},
         {Bit::B7, Bit::B8, Bit::B15}},
        {"a repeated high member", {Bit::B12, Bit::B12}, {Bit::B12}},
    });
}

}  // namespace
}  // namespace sendspin
