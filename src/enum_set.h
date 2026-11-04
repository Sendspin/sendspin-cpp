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

/// @file enum_set.h
/// @brief Set of a one-byte enum's enumerators, held in one byte or two

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <type_traits>

namespace sendspin {

/// @brief A set of the enumerators 0 to Capacity - 1 of `E`, one bit each, visited in enumerator
/// order; Capacity 16 holds them in two bytes
template <typename E, size_t Capacity = 8>
class EnumSet {
    static_assert(std::is_enum_v<E> && sizeof(E) == 1, "EnumSet holds a one-byte enum");
    static_assert(Capacity == 8 || Capacity == 16, "EnumSet holds 8 or 16 enumerators");

public:
    EnumSet() = default;
    EnumSet(std::initializer_list<E> members) {
        for (const E member : members) {
            this->insert(member);
        }
    }

    void insert(E member) {
        this->bits_ |= bit(member);
    }

    bool contains(E member) const {
        return (this->bits_ & bit(member)) != 0;
    }

    /// @brief Calls fn(member) for each member, in enumerator order.
    template <typename Fn>
    void for_each(Fn&& fn) const {
        for (uint8_t value = 0; value < Capacity; ++value) {
            if ((this->bits_ & (1U << value)) != 0) {
                fn(static_cast<E>(value));
            }
        }
    }

    bool operator==(const EnumSet&) const = default;

private:
    using Bits = std::conditional_t<Capacity == 8, uint8_t, uint16_t>;

    static Bits bit(E member) {
        assert(static_cast<uint8_t>(member) < Capacity &&
               "EnumSet holds enumerators below Capacity");
        return static_cast<Bits>(1U << static_cast<uint8_t>(member));
    }

    Bits bits_{0};
};

}  // namespace sendspin
