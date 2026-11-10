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

/// @file reserved_text.h
/// @brief Reserved storage that fills a public object's optional string field without allocating

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace sendspin {

/// @brief Storage for one optional text field of a public object, reserved once for its bound so
/// filling the field never allocates: the reserved string is swapped into the field as it is set
/// and back here as it is cleared, and a swap keeps both buffers.
class ReservedText {
public:
    explicit ReservedText(size_t capacity) {
        this->spare_.reserve(capacity);
    }

    /// @brief Sets `field` to `text`, or clears it when `text` is nullopt. `text` must fit the
    /// capacity reserved at construction.
    void fill(std::optional<std::string>& field, std::optional<std::string_view> text) {
        if (!text.has_value()) {
            if (field.has_value()) {
                this->spare_.swap(*field);
                field.reset();
            }
            return;
        }
        if (!field.has_value()) {
            field.emplace();
            field->swap(this->spare_);
        }
        field->assign(*text);
    }

private:
    std::string spare_;
};

}  // namespace sendspin
