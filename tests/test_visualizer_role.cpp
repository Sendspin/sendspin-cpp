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

#include "platform/time.h"
#include "protocol_messages.h"
#include "visualizer_role_impl.h"

#include "test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;

namespace {

void put_be16(std::vector<uint8_t>& out, uint16_t val) {
    out.push_back(static_cast<uint8_t>(val >> 8));
    out.push_back(static_cast<uint8_t>(val & 0xFF));
}

}  // namespace

// ============================================================================
// decode_visualizer_message: the drain thread's per-type validation and parsing
// ============================================================================

// roles/visualizer/v1.md "Server -> Client: Visualizer Data (Binary)": each wire type carries a
// fixed payload shape, a payload shorter than that shape is not deliverable, and the downbeat
// bit is meaningful only while the stream tracks downbeats. Spectrum delivers exactly the
// negotiated bin count: fewer bins on the wire than negotiated is short, more is trailing data.
TEST(VisualizerDecode, PerTypePayloadShapes) {
    struct Row {
        const char* name;
        uint8_t wire_type;
        std::vector<uint8_t> payload;
        uint8_t negotiated_bins{0};
        bool tracks_downbeats{false};
        VisualizerDelivery::Kind expected_kind{VisualizerDelivery::Kind::NONE};
        std::vector<uint16_t> expected_bins{};
        std::optional<uint16_t> expected_loudness{};
        std::optional<bool> expected_downbeat{};
        std::optional<uint16_t> expected_frequency_hz{};
        std::optional<uint16_t> expected_amplitude{};
        std::optional<uint8_t> expected_strength{};
    };

    const std::vector<Row> rows = {
        {.name = "Control: loudness is big endian",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_LOUDNESS,
         .payload = {0x12, 0x34},
         .expected_kind = VisualizerDelivery::Kind::LOUDNESS,
         .expected_loudness = 0x1234},
        {.name = "loudness one byte short",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_LOUDNESS,
         .payload = {0x12}},
        {.name = "beat downbeat bit set while tracking downbeats",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {0x01},
         .tracks_downbeats = true,
         .expected_kind = VisualizerDelivery::Kind::BEAT,
         .expected_downbeat = true},
        {.name = "beat downbeat bit set while not tracking downbeats",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {0x01},
         .tracks_downbeats = false,
         .expected_kind = VisualizerDelivery::Kind::BEAT,
         .expected_downbeat = false},
        {.name = "beat downbeat bit clear while tracking downbeats",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {0x00},
         .tracks_downbeats = true,
         .expected_kind = VisualizerDelivery::Kind::BEAT,
         .expected_downbeat = false},
        {.name = "beat with no payload byte",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {},
         .tracks_downbeats = true},
        {.name = "f_peak carries frequency then amplitude",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_F_PEAK,
         .payload = {0x01, 0xB8, 0xBE, 0xEF},
         .expected_kind = VisualizerDelivery::Kind::F_PEAK,
         .expected_frequency_hz = 440,
         .expected_amplitude = 0xBEEF},
        {.name = "f_peak one byte short of both fields",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_F_PEAK,
         .payload = {0x01, 0xB8, 0x00}},
        {.name = "spectrum delivers the negotiated bin count",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A, 0x00, 0x14, 0x00, 0x1E},
         .negotiated_bins = 3,
         .expected_kind = VisualizerDelivery::Kind::SPECTRUM,
         .expected_bins = {10, 20, 30}},
        {.name = "spectrum ignores bins past the negotiated count",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A, 0x00, 0x14, 0x00, 0x1E},
         .negotiated_bins = 2,
         .expected_kind = VisualizerDelivery::Kind::SPECTRUM,
         .expected_bins = {10, 20}},
        {.name = "spectrum one bin short of the negotiated count",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A, 0x00, 0x14, 0x00, 0x1E},
         .negotiated_bins = 4},
        {.name = "spectrum that was never negotiated",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A},
         .negotiated_bins = 0},
        {.name = "peak carries one strength byte",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_PEAK,
         .payload = {200},
         .expected_kind = VisualizerDelivery::Kind::PEAK,
         .expected_strength = 200},
        {.name = "peak with no payload byte",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_PEAK,
         .payload = {}},
        {.name = "reserved wire type",
         .wire_type = 21,
         .payload = {0x00, 0x00, 0x00, 0x00}},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        std::vector<uint16_t> bins;
        const uint8_t* payload = row.payload.empty() ? nullptr : row.payload.data();

        auto out = decode_visualizer_message(row.wire_type, payload, row.payload.size(),
                                             row.negotiated_bins, row.tracks_downbeats, bins);

        EXPECT_EQ(out.kind, row.expected_kind);
        if (row.expected_loudness.has_value()) {
            EXPECT_EQ(out.loudness, *row.expected_loudness);
        }
        if (row.expected_downbeat.has_value()) {
            EXPECT_EQ(out.downbeat, *row.expected_downbeat);
        }
        if (row.expected_frequency_hz.has_value()) {
            EXPECT_EQ(out.frequency_hz, *row.expected_frequency_hz);
        }
        if (row.expected_amplitude.has_value()) {
            EXPECT_EQ(out.amplitude, *row.expected_amplitude);
        }
        if (row.expected_strength.has_value()) {
            EXPECT_EQ(out.strength, *row.expected_strength);
        }
        if (row.expected_kind == VisualizerDelivery::Kind::SPECTRUM) {
            EXPECT_EQ(bins, row.expected_bins);
        }
    }
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

// The generation the receive gate hands a handler on a role that has not been torn down. The
// dispatch captures it with the gate check and every point of effect re-checks it, so a unit test
// driving a handler directly passes the live one.
uint32_t live_generation(const VisualizerRole::Impl& impl) {
    return impl.cleanup_generation.load(std::memory_order_acquire);
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

    const int64_t before_us = platform_time_us();
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));
    const int64_t after_us = platform_time_us();

    // Entry = [wire_type][arrival stamp(4), host order][data...]: the drain thread judges
    // staleness against the arrival time, not against when it dequeues the entry.
    constexpr size_t HEADER = 1 + sizeof(uint32_t);
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), data.size() + HEADER);
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
    uint32_t stamp = 0;
    std::memcpy(&stamp, entry.data() + 1, sizeof(stamp));
    const int64_t arrival_us = sendspin::visualizer_arrival_from_stamp(stamp, after_us);
    EXPECT_GE(arrival_us, before_us);
    EXPECT_LE(arrival_us, after_us);
    EXPECT_TRUE(std::equal(data.begin(), data.end(), entry.begin() + HEADER));

    // A message longer than any this type defines is stored whole as well: the network thread
    // neither truncates nor caps, so a spectrum with many bins survives the ring intact.
    data.insert(data.end(), 64, 0xEE);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));

    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), data.size() + HEADER);
    EXPECT_TRUE(std::equal(data.begin(), data.end(), entry.begin() + HEADER));
}

// The drain thread stores only the low 32 bits of the arrival time; the full value comes back
// from the age those bits give against `now`, including across the low word's wrap.
TEST(VisualizerArrivalStamp, RecoversTheArrivalTimeAcrossTheLowWordWrap) {
    constexpr int64_t WRAP = int64_t{1} << 32;
    struct Row {
        const char* name;
        int64_t arrival_us;
        int64_t now;
    };
    const Row rows[] = {
        {"same low word", 5'000'000, 5'001'234},
        {"low word wrapped since arrival", WRAP - 50, WRAP + 100},
        {"several wraps into the clock", 3 * WRAP + 7, 3 * WRAP + 1'000'007},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(
            sendspin::visualizer_arrival_from_stamp(static_cast<uint32_t>(row.arrival_us), row.now),
            row.arrival_us);
    }
}

// roles/visualizer/v1.md "Visualization Data (Binary)": a frame already in the past on arrival is
// dropped. Everything else is delivered display_offset_ms ahead of its display time, or on
// arrival when that is later, unless the drain thread is more than the lag bound behind that.
TEST(VisualizerDeliveryWait, DropsLateArrivalsAndBacklogAndShiftsByTheOffset) {
    constexpr int64_t MS = 1000;
    constexpr int64_t LAG = sendspin::VISUALIZER_MAX_DELIVERY_LAG_US;
    constexpr int64_t ARRIVAL = 1'000'000;
    struct Row {
        const char* name;
        int64_t client_ts;
        int32_t offset_ms;
        int64_t now;
        std::optional<int64_t> wait_us;
    };
    const Row rows[] = {
        {"Control: in time, waits for the display time", ARRIVAL + 50 * MS, 0, ARRIVAL, 50 * MS},
        {"already past on arrival", ARRIVAL - 1, 0, ARRIVAL, std::nullopt},
        {"Control: due exactly on arrival", ARRIVAL, 0, ARRIVAL, 0},
        {"reached after its display time behind a sibling", ARRIVAL + 10 * MS, 0,
         ARRIVAL + 15 * MS, 0},
        {"Control: at the lag bound", ARRIVAL + 10 * MS, 0, ARRIVAL + 10 * MS + LAG, 0},
        {"past the lag bound", ARRIVAL + 10 * MS, 0, ARRIVAL + 10 * MS + LAG + 1, std::nullopt},
        {"positive offset fires early", ARRIVAL + 50 * MS, 15, ARRIVAL, 35 * MS},
        {"negative offset delays", ARRIVAL + 50 * MS, -10, ARRIVAL, 60 * MS},
        {"offset beyond the lead delivers on arrival", ARRIVAL + 50 * MS, 100, ARRIVAL, 0},
        {"Control: lag from arrival, at the bound", ARRIVAL + 50 * MS, 100, ARRIVAL + LAG, 0},
        {"lag from arrival, past the bound", ARRIVAL + 50 * MS, 100, ARRIVAL + LAG + 1,
         std::nullopt},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(
            sendspin::visualizer_delivery_wait_us(row.client_ts, ARRIVAL, row.offset_ms, row.now),
            row.wait_us);
    }
}

TEST(VisualizerHandleBinary, DropsMessageWithoutTimestamp) {
    auto impl = make_impl();

    std::vector<uint8_t> data(7, 0);  // fewer than the 8 timestamp bytes
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, DropsWhenStreamInactive) {
    auto impl = make_impl();
    impl->stream_active = false;

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
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

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size(), live_generation(*impl));
    impl->handle_binary(21, data.data(), data.size(), live_generation(*impl));  // reserved type

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));

    // Control: the negotiated type is still forwarded.
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
}

// A teardown that lands after the receive gate admitted a message, while its handler is still
// running, invalidates the whole handler: the generation the dispatch captured no longer matches.
// Nothing here is timing-based: the captured value is taken first and the teardown applied by
// hand, which is the interleaving the network thread can otherwise produce on a live connection.
TEST(VisualizerHandleBinary, HandlersRefuseAGenerationATeardownOvertook) {
    auto impl = make_impl();
    impl->stream_active = false;
    impl->negotiated_types_mask = 0;

    ServerVisualizerStreamObject stream;
    stream.types = {VisualizerDataType::BEAT};
    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);
    std::vector<uint8_t> entry;

    // Run a live stream first and capture its generation, then tear the role down. Without the
    // live stream, handle_binary's !stream_active term alone would drop the stale frame below
    // and the generation check would never be the deciding one.
    impl->handle_stream_start(stream, live_generation(*impl));
    ASSERT_TRUE(impl->stream_active.load());
    ASSERT_TRUE(pop_entry(*impl, entry));  // the stream/start boundary marker
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();

    impl->handle_stream_start(stream, captured);
    EXPECT_FALSE(impl->stream_active.load()) << "a stopped role was re-armed by a stale handler";
    EXPECT_EQ(impl->negotiated_types_mask.load(), 0U);

    // Re-arm under the generation the role now reports, as a re-added role does, so the only
    // thing left that can refuse the captured generation's frame is the gate under test.
    impl->handle_stream_start(stream, live_generation(*impl));
    ASSERT_TRUE(impl->stream_active.load());
    ASSERT_TRUE(pop_entry(*impl, entry));  // the stream/start boundary marker

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size(), captured);
    EXPECT_FALSE(pop_entry(*impl, entry)) << "a stale frame reached the ring";

    // Control: the same frame with the generation the role now reports is forwarded.
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size(),
                        live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_BEAT);
}

// roles/visualizer/v1.md "Server -> Client: stream/start": a stream that names the spectrum type
// without a spectrum object has no bin count, so its frames are not deliverable. No wire input
// reaches this: parse_server_message() drops a visualizer object that advertises spectrum with no
// valid spectrum config, so the cached count is read out of the Impl and run through the decode
// the drain thread runs. That the served object governs the count is asserted where a consumer
// sees it, in ClientLifecycle.TheServedSpectrumBinCountGovernsTheDeliveredFrame.
TEST(VisualizerSpectrumWiring, TheSpectrumTypeWithNoSpectrumObjectDeliversNothing) {
    struct Row {
        const char* name;
        bool has_object;
        VisualizerDelivery::Kind expected_kind;
    };
    const Row rows[] = {
        {"Control: a stream carrying the spectrum object delivers its frames", true,
         VisualizerDelivery::Kind::SPECTRUM},
        {"the spectrum type with no spectrum object drops every frame", false,
         VisualizerDelivery::Kind::NONE},
    };

    // Four bins on the wire, the requested count.
    const std::vector<uint8_t> payload = {0x00, 0x0A, 0x00, 0x14, 0x00, 0x1E, 0x00, 0x28};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        impl->config.stream.spectrum = VisualizerSpectrumConfig{
            .n_disp_bins = 4, .scale = VisualizerSpectrumScale::MEL, .f_min = 40, .f_max = 16000};

        ServerVisualizerStreamObject stream;
        stream.types = {VisualizerDataType::SPECTRUM};
        if (row.has_object) {
            stream.spectrum = impl->config.stream.spectrum;
        }
        impl->handle_stream_start(stream, live_generation(*impl));

        std::vector<uint16_t> bins;
        auto out = decode_visualizer_message(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, payload.data(),
                                             payload.size(), impl->spectrum_bin_count,
                                             impl->tracks_downbeats, bins);
        EXPECT_EQ(out.kind, row.expected_kind);
    }
}

TEST(VisualizerHandleBinary, StreamStartNegotiatesTypes) {
    // handle_stream_start derives the admission mask from the advertised types.
    auto impl = make_impl();
    impl->negotiated_types_mask = 0;

    ServerVisualizerStreamObject stream;
    stream.types = {VisualizerDataType::BEAT};
    impl->handle_stream_start(stream, live_generation(*impl));

    // stream/start enqueues a 1-byte boundary marker; consume it first.
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), 1U);

    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_BEAT, data.data(), data.size(), live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry[0], SENDSPIN_BINARY_VISUALIZER_BEAT);

    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// ============================================================================
// Clear-boundary marker: stream/clear (and stream/start) enqueue a sentinel so
// the drain thread discards exactly the entries that predate the boundary.
// ============================================================================

TEST(VisualizerClearMarker, StreamClearEnqueuesMarker) {
    auto impl = make_impl();

    impl->handle_stream_clear(live_generation(*impl));

    // The marker is a single byte outside the visualizer wire-type range, so it can never be
    // mistaken for a message: the exact value is an internal encoding, the range is the contract.
    std::vector<uint8_t> entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_EQ(entry.size(), 1U);
    EXPECT_TRUE(entry[0] < SENDSPIN_BINARY_VISUALIZER_FIRST ||
                entry[0] > SENDSPIN_BINARY_VISUALIZER_LAST)
        << "the clear marker collides with wire type " << static_cast<int>(entry[0]);
}

TEST(VisualizerClearMarker, DiscardPreservesPostClearFrames) {
    auto impl = make_impl();

    std::vector<uint8_t> pre;
    put_be64(pre, 1);
    put_be16(pre, 0x0001);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, pre.data(), pre.size(), live_generation(*impl));

    impl->handle_stream_clear(live_generation(*impl));

    std::vector<uint8_t> post;
    put_be64(post, 2);
    put_be16(post, 0x0002);
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, post.data(), post.size(), live_generation(*impl));

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
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));
    impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data.data(), data.size(), live_generation(*impl));

    impl->discard_to_clear_marker();

    std::vector<uint8_t> entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// ============================================================================
// client/hello and client/state configuration reporting
// ============================================================================

// roles/visualizer/v1.md splits what the client reports: buffer_capacity is a constant capability
// in the hello support object, while the requested types, frame-rate cap and spectrum layout are
// dynamic and go in the client/state visualizer object.
TEST(VisualizerConfigReporting, HelloAdvertisesCapacityAndStateCarriesTheStreamConfig) {
    static std::deque<Inbox> inboxes;

    VisualizerRoleConfig config;
    config.support.buffer_capacity = 6144;
    config.stream.types = {VisualizerDataType::SPECTRUM, VisualizerDataType::BEAT};
    config.stream.rate_max = 25;
    config.stream.spectrum = VisualizerSpectrumConfig{
        .n_disp_bins = 16,
        .scale = VisualizerSpectrumScale::LOG,
        .f_min = 20,
        .f_max = 20000,
    };
    auto impl = std::make_unique<VisualizerRole::Impl>(std::move(config), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());

    ClientHelloMessage hello;
    impl->build_hello_fields(hello);
    ASSERT_EQ(hello.supported_roles.size(), 1u);
    EXPECT_EQ(hello.supported_roles[0], SendspinRole::VISUALIZER);
    ASSERT_TRUE(hello.visualizer_support.has_value());
    // The advertised capacity is the effective wire-data fraction of the ring's RAM budget: a
    // third of it, since the smallest entries store at about three times their wire size. The
    // server's flow control is sized from this number, so the fraction is spelled out rather
    // than bounded.
    EXPECT_EQ(hello.visualizer_support->buffer_capacity, 2048u);

    ClientStateMessage state;
    impl->build_state_fields(state);
    ASSERT_TRUE(state.visualizer.has_value());
    EXPECT_EQ(state.visualizer->types, (std::vector<VisualizerDataType>{
                                           VisualizerDataType::SPECTRUM,
                                           VisualizerDataType::BEAT,
                                       }));
    EXPECT_EQ(state.visualizer->rate_max, 25);
    ASSERT_TRUE(state.visualizer->spectrum.has_value());
    EXPECT_EQ(state.visualizer->spectrum->n_disp_bins, 16);
    EXPECT_EQ(state.visualizer->spectrum->scale, VisualizerSpectrumScale::LOG);

    // Control: a role that asks for no data still reports the object, so the server knows the
    // role is configured and streams nothing rather than waiting for a state that never comes.
    auto quiet = make_impl();
    ClientStateMessage quiet_state;
    quiet->build_state_fields(quiet_state);
    ASSERT_TRUE(quiet_state.visualizer.has_value());
    EXPECT_TRUE(quiet_state.visualizer->types.empty());
    EXPECT_FALSE(quiet_state.visualizer->spectrum.has_value());
}

// ============================================================================
// start(): a stream configuration the spec forbids refuses to run
// ============================================================================

namespace {

// A visualizer Impl carrying the given stream configuration, bound to an inbox and otherwise
// startable (the ring buffer is created from a real capacity).
std::unique_ptr<VisualizerRole::Impl> make_impl_with_stream(VisualizerStreamConfig stream) {
    static std::deque<Inbox> inboxes;

    VisualizerRoleConfig config;
    config.support.buffer_capacity = 4096;
    config.stream = std::move(stream);
    auto impl = std::make_unique<VisualizerRole::Impl>(std::move(config), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    return impl;
}

}  // namespace

// roles/visualizer/v1.md "client/state visualizer object": a types list carrying 'spectrum'
// without a spectrum object, or a rate_max of zero while asking for data, is a protocol error the
// server closes the connection for, so the role refuses the configuration rather than letting the
// consumer discover it as a disconnect.
TEST(VisualizerStartValidation, SpecInvalidStreamConfigRefusesToStart) {
    const VisualizerSpectrumConfig spectrum{
        .n_disp_bins = 16,
        .scale = VisualizerSpectrumScale::LOG,
        .f_min = 20,
        .f_max = 20000,
    };

    struct Row {
        const char* name;
        VisualizerStreamConfig stream;
        bool expected_start;
    };
    const std::vector<Row> rows = {
        {"Control: spectrum object present and a positive rate",
         VisualizerStreamConfig{.types = {VisualizerDataType::SPECTRUM},
                                .rate_max = 25,
                                .spectrum = spectrum},
         true},
        {"spectrum type with no spectrum object",
         VisualizerStreamConfig{.types = {VisualizerDataType::SPECTRUM}, .rate_max = 25}, false},
        {"zero rate_max while requesting a type",
         VisualizerStreamConfig{.types = {VisualizerDataType::BEAT}, .rate_max = 0}, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl_with_stream(row.stream);
        EXPECT_EQ(impl->start(), row.expected_start);
        if (row.expected_start) {
            impl->stop();
        }
    }
}
