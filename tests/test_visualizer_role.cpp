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

#include "inbound_test_helpers.h"
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
// handle_binary: the protocol task hands messages over verbatim, doing no per-type parsing or
// capping.
// ============================================================================

namespace {

// A visualizer Impl whose drain list is bound to a ring of its own, without the drain thread, and
// no client (handle_binary never touches it). Heap-allocated because Impl holds atomics and so is
// neither copyable nor movable. The stream is marked active and all defined wire types are marked
// negotiated so handle_binary will accept messages (bits 0-4 = wire types 16-20).
//
// handle_stream_start writes the stream config into an InboxSlot, which asserts it has been bound
// to an Inbox first. Give each Impl its own Inbox and ring with program lifetime: both are
// non-movable, so a deque (which never relocates existing elements) provides stable addresses
// that outlive the returned Impl, which only holds pointers to them.
std::unique_ptr<VisualizerRole::Impl> make_impl() {
    static std::deque<Inbox> inboxes;
    static std::deque<InboundRing> rings;

    VisualizerRoleConfig config;
    config.support.buffer_capacity = 4096;
    auto impl = std::make_unique<VisualizerRole::Impl>(std::move(config), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    impl->stream_active = true;
    impl->negotiated_types_mask = 0x1F;
    InboundRing& ring = rings.emplace_back();
    create_test_ring(ring);
    EXPECT_TRUE(impl->drain_task->event_flags.create());
    EXPECT_TRUE(impl->drain_task->inbound.bind(&ring, InboundHolder::VISUALIZER));
    return impl;
}

// The generation the receive gate hands a handler on a role that has not been torn down. The
// dispatch captures it with the gate check and every point of effect re-checks it, so a unit test
// driving a handler directly passes the live one.
uint32_t live_generation(const VisualizerRole::Impl& impl) {
    return impl.cleanup_generation.load(std::memory_order_acquire);
}

// The message handle_binary receives for wire type `type` carrying `data`: the type byte first.
std::vector<uint8_t> frame_message(uint8_t type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> message{type};
    message.insert(message.end(), data.begin(), data.end());
    return message;
}

// Hands `data` to the role as wire type `type`, outside any ring item.
void hand(VisualizerRole::Impl& impl, uint8_t type, const std::vector<uint8_t>& data,
          uint32_t generation) {
    std::vector<uint8_t> bytes = frame_message(type, data);
    InboundMessage message = message_over(bytes);
    impl.handle_binary(type, message, generation);
    take_in_ring_order(*impl.drain_task->inbound.ring());
}

// One item the drain thread would take: its item type (the wire type, or the clear marker's),
// the transport's receive stamp, and the message bytes it carries (empty for a marker).
struct Entry {
    uint8_t type{0};
    uint32_t receive_time_us{0};
    std::vector<uint8_t> message;
    const uint8_t* data{nullptr};
};

// Takes one item from the drain list, returning it to the ring, or returns false if none is
// waiting.
bool pop_entry(VisualizerRole::Impl& impl, Entry& out) {
    void* item = impl.drain_task->inbound.items().take(0);
    if (item == nullptr) {
        return false;
    }
    const InboundItemHeader* header = inbound_item_header(item);
    out.type = header->type;
    out.receive_time_us = header->receive_time_us;
    const uint8_t* bytes = inbound_item_bytes(item);
    out.message.assign(bytes, bytes + header->data_offset + header->data_len);
    out.data = bytes;
    impl.drain_task->inbound.ring()->return_item(item);
    return true;
}

}  // namespace

// The frame reaches the drain thread whole, with the transport's receive stamp, which the drain
// thread widens into the arrival time it judges staleness against (not when it takes the item).
// A frame received into a ring item stays in it; one outside any (reassembled from Noise
// fragments, or replayed) is copied into an item of its own.
TEST(VisualizerHandleBinary, ForwardsTheMessageWithItsReceiveStamp) {
    struct Row {
        const char* name;
        bool in_ring_item;
    };
    const Row rows[] = {{"received into a ring item", true},
                        {"Control: outside a ring item, copied", false}};
    constexpr uint32_t STAMP = 0xFEDC1234;

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->drain_task->inbound.ring();

        // data = [server_ts(8)][loudness(2)], then more than this type defines: the protocol task
        // neither truncates nor caps, so a spectrum with many bins survives intact.
        std::vector<uint8_t> data;
        put_be64(data, 123456);
        put_be16(data, 0xABCD);
        data.insert(data.end(), 64, 0xEE);
        std::vector<uint8_t> bytes = frame_message(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);
        InboundMessage message =
            row.in_ring_item ? receive_into_ring(ring, bytes, STAMP) : message_over(bytes, STAMP);
        const uint8_t* received_at = message.data;

        impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, message, live_generation(*impl));
        take_in_ring_order(ring);

        Entry entry;
        ASSERT_TRUE(pop_entry(*impl, entry));
        EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
        EXPECT_EQ(entry.message, bytes);
        EXPECT_EQ(entry.receive_time_us, STAMP) << "the drain thread would date the frame wrongly";
        EXPECT_TRUE(in_ring_storage(ring, entry.data));
        EXPECT_EQ(entry.data == received_at, row.in_ring_item)
            << "the frame was copied out of the item it arrived in";
    }
}

// An item header stores only the low 32 bits of the receive time; the full value comes back from
// the age those bits give against `now`, including across the low word's wrap.
TEST(InboundReceiveStamp, RecoversTheReceiveTimeAcrossTheLowWordWrap) {
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
        EXPECT_EQ(sendspin::widen_time_stamp_us(static_cast<uint32_t>(row.arrival_us), row.now),
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

// A server sends one message per visualization type for each analysis frame, all with the same
// timestamp, and a listener that takes 3 ms per frame leaves the drain thread reaching each
// sibling after that timestamp. Every sibling arrived in time, so each is delivered at once as
// long as the drain thread is within the lag bound of the display time: lateness is judged on
// arrival, not on when the drain thread reaches the frame.
TEST(VisualizerDeliveryWait, SiblingsSharingATimestampAreAllDelivered) {
    constexpr int64_t MS = 1000;
    constexpr int64_t TS = 2'000'000;
    struct Row {
        const char* name;
        int64_t arrival;
        int64_t now;
        std::optional<int64_t> wait_us;
    };
    const Row rows[] = {
        {"first sibling, reached at its display time", TS - 50 * MS, TS, 0},
        {"second sibling, 3 ms behind", TS - 50 * MS, TS + 3 * MS, 0},
        {"third sibling, 6 ms behind", TS - 50 * MS, TS + 6 * MS, 0},
        {"fourth sibling, 9 ms behind", TS - 50 * MS, TS + 9 * MS, 0},
        {"Control: a sibling that arrived after the timestamp", TS + 1, TS + 3 * MS, std::nullopt},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(sendspin::visualizer_delivery_wait_us(TS, row.arrival, 0, row.now), row.wait_us);
    }
}

TEST(VisualizerHandleBinary, DropsMessageWithoutTimestamp) {
    auto impl = make_impl();

    std::vector<uint8_t> data(7, 0);  // fewer than the 8 timestamp bytes
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, DropsWhenStreamInactive) {
    auto impl = make_impl();
    impl->stream_active = false;

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, DropsUnnegotiatedType) {
    // Only wire types the stream/start negotiated are admitted; a defined-but-unnegotiated type
    // and a reserved type (which can never be negotiated) are both dropped on the protocol task.
    auto impl = make_impl();
    impl->negotiated_types_mask =
        1U << (SENDSPIN_BINARY_VISUALIZER_LOUDNESS - SENDSPIN_BINARY_VISUALIZER_FIRST);

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x0042);

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data, live_generation(*impl));
    hand(*impl, 21, data, live_generation(*impl));  // reserved type

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));

    // Control: the negotiated type is still forwarded.
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
}

// A teardown that lands after the receive gate admitted a message, while its handler is still
// running, invalidates the whole handler: the generation the dispatch captured no longer matches.
// Nothing here is timing-based: the captured value is taken first and the teardown applied by
// hand, which is the interleaving the protocol task can otherwise produce on a live connection.
TEST(VisualizerHandleBinary, HandlersRefuseAGenerationATeardownOvertook) {
    auto impl = make_impl();
    impl->stream_active = false;
    impl->negotiated_types_mask = 0;

    ServerVisualizerStreamObject stream;
    stream.types = {VisualizerDataType::BEAT};
    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);
    Entry entry;

    // Run a live stream first and capture its generation, then tear the role down. Without the
    // live stream, handle_binary's !stream_active term alone would drop the stale frame below
    // and the generation check would never be the deciding one.
    impl->handle_stream_start(stream, live_generation(*impl));
    take_in_ring_order(*impl->drain_task->inbound.ring());
    ASSERT_TRUE(impl->stream_active.load());
    ASSERT_TRUE(pop_entry(*impl, entry));  // the stream/start boundary marker
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();

    impl->handle_stream_start(stream, captured);

    take_in_ring_order(*impl->drain_task->inbound.ring());
    EXPECT_FALSE(impl->stream_active.load()) << "a stopped role was re-armed by a stale handler";
    EXPECT_EQ(impl->negotiated_types_mask.load(), 0U);

    // Re-arm under the generation the role now reports, as a re-added role does, so the only
    // thing left that can refuse the captured generation's frame is the gate under test.
    impl->handle_stream_start(stream, live_generation(*impl));
    take_in_ring_order(*impl->drain_task->inbound.ring());
    ASSERT_TRUE(impl->stream_active.load());
    ASSERT_TRUE(pop_entry(*impl, entry));  // the stream/start boundary marker

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data, captured);
    EXPECT_FALSE(pop_entry(*impl, entry)) << "a stale frame reached the drain list";

    // Control: the same frame with the generation the role now reports is forwarded.
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data, live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_BEAT);
}

/// Counts on_visualizer_stream_start() calls.
class StreamStartCounter : public VisualizerRoleListener {
public:
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& /*config*/) override {
        ++this->starts;
    }
    int starts{0};
};

// A STREAM_START applies only the config written with its own stamp: a config left in the slot by
// a stream a teardown ended (taken by a drain on the far side of that teardown) is dropped rather
// than reported for the next stream. The slot is written with the old stamp directly, the payload
// such a drain would hold; nothing public interleaves the two threads on demand.
TEST(VisualizerStreamEvents, AStreamStartAppliesOnlyTheConfigOfItsOwnGeneration) {
    struct Row {
        const char* name;
        bool stale;
        int expected_starts;
    };
    const Row rows[] = {{"Control: written under the event's generation", false, 1},
                        {"written before a teardown", true, 0}};
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        StreamStartCounter listener;
        impl->listener = &listener;
        const uint32_t before = live_generation(*impl);
        impl->cleanup();
        ServerVisualizerStreamObject config;
        config.types = {VisualizerDataType::BEAT};
        impl->event_state->config_slot.write(config, row.stale ? before : live_generation(*impl));

        impl->handle_stream_ring_event(VisualizerEventType::STREAM_START, live_generation(*impl));

        EXPECT_EQ(listener.starts, row.expected_starts);
    }
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
        take_in_ring_order(*impl->drain_task->inbound.ring());

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
    take_in_ring_order(*impl->drain_task->inbound.ring());

    // stream/start appends a boundary marker, which carries no message bytes; consume it first.
    Entry entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_TRUE(entry.message.empty());

    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data, live_generation(*impl));
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_BEAT);

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// ============================================================================
// Clear-boundary marker: stream/clear (and stream/start) enqueue a sentinel so
// the drain thread discards exactly the entries that predate the boundary.
// ============================================================================

TEST(VisualizerClearMarker, StreamClearEnqueuesMarker) {
    auto impl = make_impl();

    impl->handle_stream_clear(live_generation(*impl));

    take_in_ring_order(*impl->drain_task->inbound.ring());

    // The marker's item type lies outside the visualizer wire-type range, so it can never be
    // mistaken for a message: the exact value is an internal encoding, the range is the contract.
    Entry entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    ASSERT_TRUE(entry.message.empty());
    EXPECT_TRUE(entry.type < SENDSPIN_BINARY_VISUALIZER_FIRST ||
                entry.type > SENDSPIN_BINARY_VISUALIZER_LAST)
        << "the clear marker collides with wire type " << static_cast<int>(entry.type);
}

// A clear marker is exempt from the quota (InboundConsumer::hand()): a server that overran the
// buffer_capacity it was told still gets its stream/clear boundary, or the drain thread would
// blur the old stream into the new one. Control: a frame over the same quota is refused, so the
// quota does bind.
TEST(VisualizerClearMarker, AClearMarkerPassesAQuotaTheServersFramesExhausted) {
    struct Row {
        const char* name;
        bool marker;
        bool listed;
    };
    const Row rows[] = {
        {"Control: a frame over quota is refused", false, false},
        {"a clear marker over quota is still handed over", true, true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->drain_task->inbound.ring();
        ring.quota(InboundHolder::VISUALIZER).set_limit(0);

        if (row.marker) {
            impl->handle_stream_clear(live_generation(*impl));
            take_in_ring_order(ring);
        } else {
            std::vector<uint8_t> data;
            put_be64(data, 1);
            put_be16(data, 0x0001);
            hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));
        }

        Entry entry;
        EXPECT_EQ(pop_entry(*impl, entry), row.listed);
        EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U);
    }
}

TEST(VisualizerClearMarker, DiscardPreservesPostClearFrames) {
    auto impl = make_impl();

    std::vector<uint8_t> pre;
    put_be64(pre, 1);
    put_be16(pre, 0x0001);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, pre, live_generation(*impl));

    impl->handle_stream_clear(live_generation(*impl));

    take_in_ring_order(*impl->drain_task->inbound.ring());

    std::vector<uint8_t> post;
    put_be64(post, 2);
    put_be16(post, 0x0002);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, post, live_generation(*impl));

    impl->discard_to_clear_marker();

    // The pre-clear frame and the marker are gone; the post-clear frame survives.
    Entry entry;
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
    EXPECT_EQ(entry.message.back(), 0x02);
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerClearMarker, DiscardDrainsToEmptyWithoutMarker) {
    // If the marker is missing (failed enqueue or already consumed), the discard degrades to
    // draining whatever is buffered.
    auto impl = make_impl();

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x0001);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data, live_generation(*impl));

    impl->discard_to_clear_marker();

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// A teardown (a dropped connection, a removed role, stop()) moves the role's generation on, and
// the old stream's frames are never delivered: the protocol task's next tick recalls what the
// drain thread has not taken, returning it and its quota charge to the shared ring, and a frame
// the drain thread takes before that tick is dropped by its generation stamp and returned the
// same way.
TEST(VisualizerClearMarker, ATeardownRecallsTheFramesTheDrainThreadHasNotTaken) {
    struct Row {
        const char* name;
        bool teardown;
        bool recall_tick;
        bool listed_before_take;
        size_t delivered;
    };
    const Row rows[] = {
        {"Control: no teardown", false, true, true, 2},
        {"torn down, recalled by the protocol task's tick", true, true, false, 0},
        {"torn down, taken by the drain thread before the recall", true, false, true, 0},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->drain_task->inbound.ring();
        std::vector<uint8_t> data;
        put_be64(data, 1);
        put_be16(data, 0x0001);
        for (int i = 0; i < 2; ++i) {
            InboundMessage message = receive_into_ring(
                ring, frame_message(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data), 0);
            impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, message,
                                live_generation(*impl));
        }
        if (row.teardown) {
            impl->cleanup();
        }
        if (row.recall_tick) {
            impl->recall_stale_items(live_generation(*impl));  // the protocol task's tick
        }

        EXPECT_EQ(!impl->drain_task->inbound.items().is_empty(), row.listed_before_take);
        // Taken under the live generation, as the drain thread takes them: a recalled or stale
        // frame is not delivered, and one left over is.
        size_t delivered = 0;
        void* item = nullptr;
        while ((item = impl->take_item(0)) != nullptr) {
            ++delivered;
            ring.return_item(item);
        }
        EXPECT_EQ(delivered, row.delivered);
        EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U)
            << "a frame of the torn-down stream kept its charge";
    }
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
    // The advertised capacity is the effective wire-data fraction of the quota: a seventh of
    // it, since the smallest frame stores in its inbound ring item at up to seven times its wire
    // size. The server's flow control is sized from this number, so the fraction is spelled out
    // rather than bounded.
    EXPECT_EQ(hello.visualizer_support->buffer_capacity, 6144u / 7);

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
        InboundRing ring;  // outlives the role, whose drain list links it
        create_test_ring(ring);
        auto impl = make_impl_with_stream(row.stream);
        EXPECT_EQ(impl->start(&ring), row.expected_start);
        if (row.expected_start) {
            impl->stop();
        }
    }
}
