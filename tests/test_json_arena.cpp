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

/// @file test_json_arena.cpp
/// @brief Tests for SendspinArenaAllocator: every freed block is wiped, and a message built on
/// top of a live parsed document leaves it intact and drains back down to it.

#include "platform/json_arena.h"
#include "protocol_messages.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

constexpr uint8_t PATTERN = 0xA5;

/// Whether every byte of [p, p + len) equals `value`.
bool all_bytes(const void* p, size_t len, uint8_t value) {
    const auto* bytes = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < len; ++i) {
        if (bytes[i] != value) {
            return false;
        }
    }
    return true;
}

/// Whether [p, p + len) lies inside the arena's backing buffer, so reading it after the block is
/// freed reads the arena's own memory rather than a freed heap block.
bool in_backing(const SendspinArenaAllocator& arena, const void* p, size_t len) {
    const auto addr = reinterpret_cast<uintptr_t>(p);
    const auto base = reinterpret_cast<uintptr_t>(arena.base_);
    return addr >= base && addr + len <= base + arena.cap_;
}

}  // namespace

// ============================================================================
// Wipe on free
// ============================================================================

// Every block the arena gives up is zeroed: a freed block (an interior block's shrunk-away tail
// with it), the tail a top block's shrinking reallocate() returns to free space and the old copy
// a moving one leaves behind. The freed bytes are read back from the
// arena's backing buffer (base_ and cap_ through -fno-access-control): a freed block's address
// stays inside that buffer, so the read is of the arena's own memory. A heap fallback block
// cannot be read after its free without a use-after-free, so the heap rows show only that the
// header the wipe sizes itself by is in place (ASan reports a wrong size as an overflow or a bad
// free); the wipe of a heap block is the same secure_zero() call as the arena rows'. A heap
// block's shrink whose new block cannot be allocated keeps the old block; no allocation failure
// can be staged without a seam, so that path is untested.
TEST(JsonArena, FreedBytesAreWiped) {
    struct Row {
        const char* name;
        // Runs the scenario on a fresh 512-byte arena and checks its outcome.
        void (*run)(SendspinArenaAllocator& arena);
    };
    const Row rows[] = {
        {"Control: a live block keeps its bytes while another is freed",
         [](SendspinArenaAllocator& arena) {
             void* live = arena.allocate(64);
             void* freed = arena.allocate(64);
             std::memset(live, PATTERN, 64);
             std::memset(freed, PATTERN, 64);
             arena.deallocate(freed);
             EXPECT_TRUE(all_bytes(live, 64, PATTERN));
             EXPECT_TRUE(all_bytes(freed, 64, 0));
             arena.deallocate(live);
         }},
        {"the top block, popped", [](SendspinArenaAllocator& arena) {
             void* block = arena.allocate(64);
             std::memset(block, PATTERN, 64);
             arena.deallocate(block);
             EXPECT_EQ(arena.offset_, 0U);
             EXPECT_TRUE(all_bytes(block, 64, 0));
         }},
        {"an interior block, stranded", [](SendspinArenaAllocator& arena) {
             void* interior = arena.allocate(64);
             void* top = arena.allocate(16);
             std::memset(interior, PATTERN, 64);
             const size_t offset = arena.offset_;
             arena.deallocate(interior);
             EXPECT_EQ(arena.offset_, offset) << "an interior block is not popped";
             EXPECT_TRUE(all_bytes(interior, 64, 0));
             arena.deallocate(top);
         }},
        {"the tail a top block shrinks away", [](SendspinArenaAllocator& arena) {
             auto* block = static_cast<uint8_t*>(arena.allocate(128));
             std::memset(block, PATTERN, 128);
             EXPECT_EQ(arena.reallocate(block, 32), block);
             EXPECT_TRUE(all_bytes(block, 32, PATTERN)) << "the kept bytes survive";
             EXPECT_TRUE(all_bytes(block + 32, 96, 0));
             arena.deallocate(block);
         }},
        {"the tail an interior block shrinks away, once the block is freed",
         [](SendspinArenaAllocator& arena) {
             auto* block = static_cast<uint8_t*>(arena.allocate(128));
             void* top = arena.allocate(16);
             std::memset(block, PATTERN, 128);
             EXPECT_EQ(arena.reallocate(block, 32), block);
             EXPECT_TRUE(all_bytes(block, 32, PATTERN));
             // The tail stays the block's own (its recorded size is unchanged), so it is wiped
             // with the rest of the block when the block is freed.
             arena.deallocate(block);
             EXPECT_TRUE(all_bytes(block, 128, 0));
             arena.deallocate(top);
         }},
        {"a top block's old copy, moved to the heap", [](SendspinArenaAllocator& arena) {
             void* block = arena.allocate(64);
             std::memset(block, PATTERN, 64);
             void* moved = arena.reallocate(block, 1024);
             ASSERT_NE(moved, block);
             EXPECT_FALSE(in_backing(arena, moved, 1)) << "a 1 KB block outgrows the arena";
             EXPECT_TRUE(all_bytes(moved, 64, PATTERN)) << "the contents move with the block";
             EXPECT_EQ(arena.offset_, 0U) << "the old top is popped";
             EXPECT_TRUE(all_bytes(block, 64, 0));
             arena.deallocate(moved);
         }},
        {"an interior block's old copy, moved", [](SendspinArenaAllocator& arena) {
             void* block = arena.allocate(64);
             void* top = arena.allocate(16);
             std::memset(block, PATTERN, 64);
             void* moved = arena.reallocate(block, 128);
             ASSERT_NE(moved, block);
             EXPECT_TRUE(all_bytes(moved, 64, PATTERN));
             EXPECT_TRUE(all_bytes(block, 64, 0));
             arena.deallocate(moved);
             arena.deallocate(top);
         }},
        {"Control: a heap block grows, moves and frees whole", [](SendspinArenaAllocator& arena) {
             void* block = arena.allocate(1024);
             ASSERT_FALSE(in_backing(arena, block, 1));
             std::memset(block, PATTERN, 1024);
             auto* moved = static_cast<uint8_t*>(arena.reallocate(block, 2048));
             ASSERT_NE(moved, nullptr);
             EXPECT_TRUE(all_bytes(moved, 1024, PATTERN));
             std::memset(moved + 1024, PATTERN, 1024);
             arena.deallocate(moved);
         }},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinArenaAllocator arena(512);
        ASSERT_EQ(arena.capacity(), 512U);
        row.run(arena);
    }
}

// ============================================================================
// Nested documents
// ============================================================================

// A message built while a parsed message is live (a client/state built inside a stream/start
// handler) sits above the parsed document in the arena: the builder never resets the arena, so
// the parsed document's strings survive the build, and the build frees back down to where the
// parse left the arena. The parse itself need not drain to where it started: ArduinoJson frees a
// document's strings before its variant pools, so a key copied before the first pool was
// allocated is stranded below it, which is what the reset before each inbound message is for. The arena is
// sized so both documents fit (a host variant pool alone is 4 KB). offset_ is read through
// -fno-access-control: where the bump pointer stands is the claim under test.
TEST(JsonArena, MessageBuiltOnAParsedMessageLeavesItIntactAndDrainsBackDown) {
    SendspinArenaAllocator arena(16 * 1024);
    const size_t before_parse = arena.offset_;

    const std::string stream_start =
        R"({"type":"stream/start","payload":{"player":{"codec":"flac","sample_rate":48000,)"
        R"("channels":2,"bit_depth":16,"codec_header":"ZkxhQwAAACIQABAAAAANAAAN"}}})";
    {
        JsonDocument parsed = make_json_document(arena);
        ASSERT_FALSE(deserializeJson(parsed, stream_start.data(), stream_start.size()));
        const size_t after_parse = arena.offset_;
        ASSERT_GT(after_parse, before_parse) << "the parse must be in the arena";

        ClientStateMessage state;
        state.available = true;
        state.player = ClientPlayerStateObject{};
        const std::string built = format_client_state_message(&state, arena);
        EXPECT_NE(built.find(R"("type":"client/state")"), std::string::npos);
        EXPECT_GT(arena.high_water(), after_parse) << "the build must be above the parse";

        // Asserted before the parsed document is read: one the build overwrote can hold a member
        // list that loops.
        ASSERT_EQ(arena.offset_, after_parse) << "the build drains back down to the parse";
        JsonObjectConst player = parsed["payload"]["player"];
        EXPECT_STREQ(player["codec"] | "", "flac");
        EXPECT_STREQ(player["codec_header"] | "", "ZkxhQwAAACIQABAAAAANAAAN");
        EXPECT_EQ(player["sample_rate"] | 0, 48000);
    }
}
