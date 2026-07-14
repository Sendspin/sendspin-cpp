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

#include "protocol_messages.h"
#include "visualizer_role_impl.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

using namespace sendspin;

namespace {

// Appends val as 8 big-endian bytes (the server timestamp prefix of every visualizer message).
void put_be64(std::vector<uint8_t>& out, int64_t val) {
    auto u = static_cast<uint64_t>(val);
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
    }
}

void put_be16(std::vector<uint8_t>& out, uint16_t val) {
    out.push_back(static_cast<uint8_t>(val >> 8));
    out.push_back(static_cast<uint8_t>(val & 0xFF));
}

}  // namespace

// ============================================================================
// decode_visualizer_message: the drain thread's per-type validation and parsing
// ============================================================================

TEST(VisualizerDecode, LoudnessDecodesBigEndian) {
    std::vector<uint8_t> payload;
    put_be16(payload, 0x1234);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::LOUDNESS);
    EXPECT_EQ(out.loudness, 0x1234);
}

TEST(VisualizerDecode, LoudnessTooShortDropped) {
    std::vector<uint8_t> payload = {0x12};  // 1 byte, needs 2
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, BeatDownbeatGatedOnTracksDownbeats) {
    std::vector<uint8_t> payload = {0x01};  // downbeat bit set
    std::vector<uint16_t> bins;

    // Stream tracks downbeats: bit 0 is meaningful.
    auto tracked = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_BEAT, payload.data(),
                                             payload.size(), 0, true, bins);
    EXPECT_EQ(tracked.kind, VisualizerDelivery::Kind::BEAT);
    EXPECT_TRUE(tracked.downbeat);

    // Stream does not track downbeats: the bit must be ignored.
    auto untracked = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_BEAT, payload.data(),
                                               payload.size(), 0, false, bins);
    EXPECT_EQ(untracked.kind, VisualizerDelivery::Kind::BEAT);
    EXPECT_FALSE(untracked.downbeat);
}

TEST(VisualizerDecode, BeatWithoutDownbeatBit) {
    std::vector<uint8_t> payload = {0x00};
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_BEAT, payload.data(),
                                         payload.size(), 0, true, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::BEAT);
    EXPECT_FALSE(out.downbeat);
}

TEST(VisualizerDecode, BeatEmptyDropped) {
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_BEAT, nullptr, 0, 0, true, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, FPeakDecodesFreqAndAmplitude) {
    std::vector<uint8_t> payload;
    put_be16(payload, 440);
    put_be16(payload, 0xBEEF);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_F_PEAK, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::F_PEAK);
    EXPECT_EQ(out.frequency_hz, 440);
    EXPECT_EQ(out.amplitude, 0xBEEF);
}

TEST(VisualizerDecode, FPeakTooShortDropped) {
    std::vector<uint8_t> payload = {0x01, 0xB8, 0x00};  // 3 bytes, needs 4
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_F_PEAK, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, SpectrumDeliversNegotiatedBinCount) {
    std::vector<uint8_t> payload;
    put_be16(payload, 10);
    put_be16(payload, 20);
    put_be16(payload, 30);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, payload.data(),
                                         payload.size(), 3, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::SPECTRUM);
    ASSERT_EQ(bins.size(), 3U);
    EXPECT_EQ(bins[0], 10);
    EXPECT_EQ(bins[1], 20);
    EXPECT_EQ(bins[2], 30);
}

TEST(VisualizerDecode, SpectrumIgnoresTrailingBytes) {
    // 3 bins on the wire, but only 2 were negotiated: deliver 2 and ignore the rest.
    std::vector<uint8_t> payload;
    put_be16(payload, 10);
    put_be16(payload, 20);
    put_be16(payload, 30);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, payload.data(),
                                         payload.size(), 2, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::SPECTRUM);
    ASSERT_EQ(bins.size(), 2U);
    EXPECT_EQ(bins[0], 10);
    EXPECT_EQ(bins[1], 20);
}

TEST(VisualizerDecode, SpectrumShortPayloadDropped) {
    // Negotiated 4 bins (8 bytes) but only 3 bins present.
    std::vector<uint8_t> payload;
    put_be16(payload, 10);
    put_be16(payload, 20);
    put_be16(payload, 30);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, payload.data(),
                                         payload.size(), 4, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, SpectrumNotNegotiatedDropped) {
    std::vector<uint8_t> payload;
    put_be16(payload, 10);
    std::vector<uint16_t> bins;

    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, PeakDecodesStrength) {
    std::vector<uint8_t> payload = {200};
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_PEAK, payload.data(),
                                         payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::PEAK);
    EXPECT_EQ(out.strength, 200);
}

TEST(VisualizerDecode, PeakEmptyDropped) {
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_PEAK, nullptr, 0, 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

TEST(VisualizerDecode, ReservedTypeDropped) {
    std::vector<uint8_t> payload = {0, 0, 0, 0};
    std::vector<uint16_t> bins;
    auto out = decode_visualizer_message(21, payload.data(), payload.size(), 0, false, bins);
    EXPECT_EQ(out.kind, VisualizerDelivery::Kind::NONE);
}

// ============================================================================
// handle_binary: the network thread forwards messages verbatim into the ring
// buffer, doing no per-type parsing or capping.
// ============================================================================

namespace {

// A visualizer Impl with a real ring buffer and no client (handle_binary never touches it).
// Heap-allocated because Impl holds atomics and so is neither copyable nor movable. The stream is
// marked active and all defined wire types are marked negotiated so handle_binary will accept
// messages (bits 0-4 = wire types 16-20).
//
// handle_stream_start writes the stream config into an InboxSlot, which asserts it has been bound
// to an Inbox first. Give each Impl its own Inbox with program lifetime: Inbox is non-movable, so
// a deque (which never relocates existing elements) provides a stable address that outlives the
// returned Impl, which only holds a pointer to it.
std::unique_ptr<VisualizerRole::Impl> make_impl() {
    static std::deque<Inbox> inboxes;

    VisualizerRoleConfig config;
    config.support.buffer_capacity = 4096;
    auto impl = std::make_unique<VisualizerRole::Impl>(std::move(config), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    impl->stream_active = true;
    impl->negotiated_types_mask = 0x1F;
    return impl;
}

// Pops one entry from the ring buffer, or returns false if none is waiting.
bool pop_entry(VisualizerRole::Impl& impl, std::vector<uint8_t>& out) {
    size_t size = 0;
    void* item = impl.drain_task->ring_buffer.receive(&size, 0);
    if (item == nullptr) {
        return false;
    }
    const auto* bytes = static_cast<const uint8_t*>(item);
    out.assign(bytes, bytes + size);
    impl.drain_task->ring_buffer.return_item(item);
    return true;
}

}  // namespace

TEST(VisualizerHandleBinary, ForwardsMessageVerbatim) {
    auto impl = make_impl();

    // data = [server_ts(8)][loudness(2)]
    std::vector<uint8_t> data;
    put_be64(data, 123456);
    put_be16(data, 0xABCD);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());

    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    // Entry = [wire_type][data...]
    ASSERT_EQ(entry.size(), data.size() + 1);
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
    EXPECT_TRUE(std::equal(data.begin(), data.end(), entry.begin() + 1));
}

TEST(VisualizerHandleBinary, DropsMessageWithoutTimestamp) {
    auto impl = make_impl();

    std::vector<uint8_t> data(7, 0);  // fewer than the 8 timestamp bytes
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, DropsWhenStreamInactive) {
    auto impl = make_impl();
    impl->stream_active = false;

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, ForwardsOversizedMessageWithoutCapping) {
    auto impl = make_impl();

    // A loudness message with trailing junk: the network thread does not truncate.
    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x1111);
    data.insert(data.end(), 64, 0xEE);  // trailing bytes

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());

    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.size(), data.size() + 1);  // stored at full length, uncapped
}

TEST(VisualizerHandleBinary, DropsUnnegotiatedType) {
    // Only wire types the stream/start negotiated are admitted; a defined-but-unnegotiated type
    // and a reserved type (which can never be negotiated) are both dropped at the network thread.
    auto impl = make_impl();
    impl->negotiated_types_mask =
        1U << (SENDSPIN_BINARY_VISUALIZER_LOUDNESS - SENDSPIN_BINARY_VISUALIZER_FIRST);

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x0042);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size());
    impl->handle_binary(21, data.data(), data.size());  // reserved type

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));

    // Control: the negotiated type is still forwarded.
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
}

TEST(VisualizerHandleBinary, StreamStartNegotiatesTypes) {
    // handle_stream_start derives the admission mask from the advertised types.
    auto impl = make_impl();
    impl->negotiated_types_mask = 0;

    ServerVisualizerStreamObject stream;
    stream.types = {VisualizerDataType::BEAT};
    impl->handle_stream_start(stream);

    // stream/start enqueues a 1-byte boundary marker; consume it first.
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), 1U);

    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size());
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_BEAT);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// ============================================================================
// Clear-boundary marker: stream/clear (and stream/start) enqueue a sentinel so
// the drain thread discards exactly the entries that predate the boundary.
// ============================================================================

TEST(VisualizerClearMarker, StreamClearEnqueuesMarker) {
    auto impl = make_impl();

    impl->handle_stream_clear();

    // The marker is a single 0xFF byte, outside the visualizer wire-type range.
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), 1U);
    EXPECT_EQ(entry[0], 0xFF);
}

TEST(VisualizerClearMarker, DiscardPreservesPostClearFrames) {
    auto impl = make_impl();

    std::vector<uint8_t> pre;
    put_be64(pre, 1);
    put_be16(pre, 0x0001);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, pre.data(), pre.size());

    impl->handle_stream_clear();

    std::vector<uint8_t> post;
    put_be64(post, 2);
    put_be16(post, 0x0002);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, post.data(), post.size());

    impl->discard_to_clear_marker();

    // The pre-clear frame and the marker are gone; the post-clear frame survives.
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
    EXPECT_EQ(entry.back(), 0x02);
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerClearMarker, DiscardDrainsToEmptyWithoutMarker) {
    // If the marker is missing (failed enqueue or already consumed), the discard degrades to
    // draining whatever is buffered.
    auto impl = make_impl();

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x0001);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size());

    impl->discard_to_clear_marker();

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}
