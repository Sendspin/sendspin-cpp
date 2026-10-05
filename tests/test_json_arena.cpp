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
/// @brief Tests for SendspinArenaAllocator and ParsedJsonMessage: every byte the arena's own
/// buffer gives up is wiped, and a parsed message released before its reply is built leaves the
/// arena to the reply.

#include "platform/json_arena.h"
#include "protocol_messages.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <algorithm>
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

// Every block the arena's backing buffer gives up is zeroed: a freed block (an interior block's
// shrunk-away tail with it), the tail a top block's shrinking reallocate() returns to free space
// and the old copy a moving one leaves behind, including an arena block that moves to the heap.
// The freed bytes are read back from the arena's backing buffer (base_ and cap_ through
// -fno-access-control): a freed block's address stays inside that buffer, so the read is of the
// arena's own memory.
//
// Gap: the wipe of a heap fallback block is not observed. Its bytes cannot be read after
// platform_free() without a use-after-free, so the heap row shows only that the header the wipe
// sizes itself by is in place (ASan reports a wrong size as an overflow or a bad free); a change
// that skipped secure_zero() for heap blocks alone would leave this test green. A heap block's
// shrink whose new block cannot be allocated keeps the old block; no allocation failure can be
// staged without a seam, so that path is untested too.
TEST(JsonArena, FreedArenaBytesAreWiped) {
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
// One document at a time
// ============================================================================

// Extract, then release, then act: a parsed message read through ParsedJsonMessage::extract() is
// destroyed before the reply it triggers is built (a client/state after a stream/start), so the
// arena holds one or the other, never both. The arena's peak across the sequence is the larger
// of the two documents' own peaks, each measured alone on a fresh arena, not their sum, and the
// release leaves only the parse's first key stranded: ArduinoJson copies that key before its
// variant pool, and a release that freed the pool before the strings above it (clear() rather
// than destruction) would strand the pool as well. The arena is sized so both documents fit at
// once (a host variant pool alone is 4 KB), so a build on top of a live parse would show as the
// sum rather than spilling to the heap. offset_ is read through -fno-access-control: where the
// bump pointer stands after the release is the claim under test.
TEST(JsonArena, ParsedMessageIsReleasedBeforeItsReplyIsBuilt) {
    constexpr size_t ARENA_BYTES = 16 * 1024;
    // The parse's stranded first key ("type"): a block header and a short string node, against a
    // variant pool of kilobytes.
    constexpr size_t FIRST_KEY_BOUND = 64;
    const std::string stream_start =
        R"({"type":"stream/start","payload":{"player":{"codec":"flac","sample_rate":48000,)"
        R"("channels":2,"bit_depth":16,"codec_header":"ZkxhQwAAACIQABAAAAANAAAN"}}})";
    ClientStateMessage state;
    state.available = true;
    state.player = ClientPlayerStateObject{};

    size_t parse_peak = 0;
    {
        SendspinArenaAllocator alone(ARENA_BYTES);
        ParsedJsonMessage parsed(alone);
        ASSERT_TRUE(parsed.parse(stream_start.data(), stream_start.size()));
        parse_peak = alone.high_water();
    }
    size_t build_peak = 0;
    {
        SendspinArenaAllocator alone(ARENA_BYTES);
        format_client_state_message(&state, alone);
        build_peak = alone.high_water();
    }
    ASSERT_GT(parse_peak, 0U) << "the parse must be in the arena";
    ASSERT_GT(build_peak, 0U) << "the build must be in the arena";

    SendspinArenaAllocator arena(ARENA_BYTES);
    ParsedJsonMessage parsed(arena);
    ASSERT_TRUE(parsed.parse(stream_start.data(), stream_start.size()));
    StreamStartMessage stream_msg;
    ASSERT_TRUE(parsed.extract<process_stream_start_message>(&stream_msg));
    ASSERT_TRUE(stream_msg.player.has_value());
    EXPECT_EQ(stream_msg.player->sample_rate.value_or(0), 48000U) << "the fields outlive the release";

    const size_t after_release = arena.offset_;
    EXPECT_LE(after_release, FIRST_KEY_BOUND)
        << "the release must leave only the first key stranded, not the variant pool";

    const std::string built = format_client_state_message(&state, arena);
    EXPECT_NE(built.find(R"("type":"client/state")"), std::string::npos);
    EXPECT_EQ(arena.high_water(), std::max(parse_peak, after_release + build_peak))
        << "parse peak " << parse_peak << ", build peak " << build_peak;
    EXPECT_LT(arena.high_water(), parse_peak + build_peak)
        << "the reply must not be built on top of the live parse";
}
