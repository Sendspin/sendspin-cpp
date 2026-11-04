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

/// @file test_inline_text.cpp
/// @brief Tests for utf8_truncate() and InlineText: cuts on a character boundary, and refusal of
/// text that does not fit

#include "inline_text.h"

#include <gtest/gtest.h>

#include <string_view>

namespace sendspin {
namespace {

// A cut never splits a character: it lands at max_bytes when that is a boundary, and otherwise
// backs off to the start of the character max_bytes falls inside.
TEST(InlineText, Utf8TruncateCutsOnACharacterBoundary) {
    struct Case {
        const char* what;
        std::string_view text;
        size_t max_bytes;
        std::string_view kept;
    };
    // "\xC3\xA9" is U+00E9 (2 bytes), "\xE2\x82\xAC" U+20AC (3), "\xF0\x9F\x8E\xB5" U+1F3B5 (4).
    const Case cases[] = {
        {"Control: fits", "abc", 3, "abc"},
        {"Control: ASCII cut at max", "abcdef", 4, "abcd"},
        {"cut before a lead byte", "abc\xC3\xA9", 3, "abc"},
        {"inside a 2-byte character", "ab\xC3\xA9", 3, "ab"},
        {"Control: after a 2-byte character", "ab\xC3\xA9x", 4, "ab\xC3\xA9"},
        {"inside a 3-byte character", "a\xE2\x82\xAC", 3, "a"},
        {"1 byte into a 4-byte character", "a\xF0\x9F\x8E\xB5", 2, "a"},
        {"3 bytes into a 4-byte character", "a\xF0\x9F\x8E\xB5", 4, "a"},
        {"a run of continuation bytes backs off at most 3", "abc\x80\x80\x80\x80\x80", 7,
         "abc\x80"},
        {"zero bytes", "abc", 0, ""},
        {"only continuation bytes before the cut", "\x80\x80", 1, ""},
    };
    for (const Case& c : cases) {
        EXPECT_EQ(utf8_truncate(c.text, c.max_bytes), c.kept) << c.what;
    }
}

// assign() refuses text over N and leaves the holder empty, NUL-terminated.
TEST(InlineText, AssignRefusesTextOverItsCapacity) {
    InlineText<4> text;
    ASSERT_TRUE(text.assign("abcd"));  // Control: text at the capacity is held
    EXPECT_EQ(text.view(), "abcd");
    EXPECT_FALSE(text.assign("abcde"));
    EXPECT_TRUE(text.empty());
    EXPECT_STREQ(text.c_str(), "");
}

}  // namespace
}  // namespace sendspin
