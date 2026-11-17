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
// fixed payload shape, and a payload shorter than that shape is not deliverable. A spectrum or
// beat payload arrives already fitted to its stream by handle_binary() (see
// VisualizerHandleBinary.FitsSpectrumAndBeatFramesToTheStreamTheyArriveIn), so decode reads the
// bin count from the length and the downbeat from bit 0.
TEST(VisualizerDecode, PerTypePayloadShapes) {
    struct Row {
        const char* name;
        uint8_t wire_type;
        std::vector<uint8_t> payload;
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
        {.name = "beat downbeat bit set",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {0x01},
         .expected_kind = VisualizerDelivery::Kind::BEAT,
         .expected_downbeat = true},
        {.name = "Control: beat downbeat bit clear, reserved bits set",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {0xFE},
         .expected_kind = VisualizerDelivery::Kind::BEAT,
         .expected_downbeat = false},
        {.name = "beat with no payload byte",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_BEAT,
         .payload = {}},
        {.name = "f_peak carries frequency then amplitude",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_F_PEAK,
         .payload = {0x01, 0xB8, 0xBE, 0xEF},
         .expected_kind = VisualizerDelivery::Kind::F_PEAK,
         .expected_frequency_hz = 440,
         .expected_amplitude = 0xBEEF},
        {.name = "f_peak one byte short of both fields",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_F_PEAK,
         .payload = {0x01, 0xB8, 0x00}},
        {.name = "spectrum delivers one big-endian bin per two bytes",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A, 0x00, 0x14, 0x01, 0x1E},
         .expected_kind = VisualizerDelivery::Kind::SPECTRUM,
         .expected_bins = {10, 20, 0x011E}},
        {.name = "Control: spectrum of one bin",
         .wire_type = SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         .payload = {0x00, 0x0A},
         .expected_kind = VisualizerDelivery::Kind::SPECTRUM,
         .expected_bins = {10}},
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
        // Reserved past every row's bin count, as start() reserves the configured count.
        std::vector<uint16_t> bins;
        bins.reserve(8);
        const uint8_t* payload = row.payload.empty() ? nullptr : row.payload.data();

        auto out = decode_visualizer_message(row.wire_type, payload, row.payload.size(), bins);

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
    // Every type but spectrum, which needs a spectrum object, so a served type is not dropped as
    // unrequested.
    config.stream.types = {VisualizerDataType::BEAT, VisualizerDataType::LOUDNESS,
                           VisualizerDataType::F_PEAK, VisualizerDataType::PEAK};
    auto impl = std::make_unique<VisualizerRole::Impl>(std::move(config), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    impl->stream_active = true;
    impl->negotiated_types_mask = 0x1F;
    InboundRing& ring = rings.emplace_back();
    create_test_ring(ring);
    EXPECT_TRUE(impl->drain_task->inbound.bind(&ring, InboundHolder::VISUALIZER));
    return impl;
}

// The message handle_binary receives for wire type `type` carrying `data`: the type byte first.
std::vector<uint8_t> frame_message(uint8_t type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> message{type};
    message.insert(message.end(), data.begin(), data.end());
    return message;
}

// Hands `data` to the role as wire type `type`, outside any ring item.
void hand(VisualizerRole::Impl& impl, uint8_t type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> bytes = frame_message(type, data);
    InboundMessage message = message_over(bytes);
    impl.handle_binary(type, message);
    take_in_ring_order(*impl.drain_task->inbound.ring());
}

// One item the drain thread would take: its item type (the wire type) and the message bytes it
// carries.
struct Entry {
    uint8_t type{0};
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
    const uint8_t* bytes = inbound_item_bytes(item);
    out.message.assign(bytes, bytes + header->data_offset + header->data_len);
    out.data = bytes;
    impl.drain_task->inbound.ring()->return_item(item);
    return true;
}

}  // namespace

// The frame reaches the drain thread whole. A frame received into a ring item stays in it; one
// outside any (reassembled from Noise fragments, or received through the fallback buffer) is
// copied into an item of its own.
TEST(VisualizerHandleBinary, ForwardsTheWholeFrameInARingItem) {
    struct Row {
        const char* name;
        bool in_ring_item;
    };
    const Row rows[] = {{"received into a ring item", true},
                        {"Control: outside a ring item, copied", false}};

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
            row.in_ring_item ? receive_into_ring(ring, bytes, 0) : message_over(bytes);
        const uint8_t* received_at = message.data;

        impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, message);
        take_in_ring_order(ring);

        Entry entry;
        ASSERT_TRUE(pop_entry(*impl, entry));
        EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
        EXPECT_EQ(entry.message, bytes);
        EXPECT_TRUE(in_ring_storage(ring, entry.data));
        EXPECT_EQ(entry.data == received_at, row.in_ring_item)
            << "the frame was copied out of the item it arrived in";
    }
}

// roles/visualizer/v1.md "Visualization Data (Binary)": a frame is delivered display_offset_ms
// ahead of its display time, or at once when that has passed, and dropped once it is more than the
// lag bound past that delivery time. A server sends one message per visualization type for each
// analysis frame, all with the same timestamp, so a slow listener leaves the drain thread
// reaching the later ones after that timestamp; the bound lets those through.
TEST(VisualizerDeliveryWait, DropsLateFramesAndShiftsByTheOffset) {
    constexpr int64_t MS = 1000;
    constexpr int64_t LAG = sendspin::VISUALIZER_MAX_DELIVERY_LAG_US;
    constexpr int64_t NOW = 1'000'000;
    struct Row {
        const char* name;
        int64_t client_ts;
        int32_t offset_ms;
        int64_t now;
        std::optional<int64_t> wait_us;
    };
    const Row rows[] = {
        {"Control: in time, waits for the display time", NOW + 50 * MS, 0, NOW, 50 * MS},
        {"Control: due exactly now", NOW, 0, NOW, 0},
        {"reached after its display time behind a sibling", NOW - 5 * MS, 0, NOW, 0},
        {"Control: at the lag bound", NOW - LAG, 0, NOW, 0},
        {"past the lag bound", NOW - LAG - 1, 0, NOW, std::nullopt},
        {"positive offset fires early", NOW + 50 * MS, 15, NOW, 35 * MS},
        {"negative offset delays", NOW + 50 * MS, -10, NOW, 60 * MS},
        {"offset beyond the lead delivers at once", NOW + 50 * MS, 60, NOW, 0},
        {"Control: a positive offset moves the bound earlier, at it", NOW + 100 * MS - LAG, 100,
         NOW, 0},
        {"a positive offset moves the bound earlier, past it", NOW + 100 * MS - LAG - 1, 100, NOW,
         std::nullopt},
        {"Control: a negative offset moves the bound later, at it", NOW - 10 * MS - LAG, -10, NOW,
         0},
        {"a negative offset moves the bound later, past it", NOW - 10 * MS - LAG - 1, -10, NOW,
         std::nullopt},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(sendspin::visualizer_delivery_wait_us(row.client_ts, row.offset_ms, row.now),
                  row.wait_us);
    }
}

TEST(VisualizerHandleBinary, DropsMessageWithoutTimestamp) {
    auto impl = make_impl();

    std::vector<uint8_t> data(7, 0);  // fewer than the 8 timestamp bytes
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));
}

TEST(VisualizerHandleBinary, DropsWhenStreamInactive) {
    auto impl = make_impl();
    impl->stream_active = false;

    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);

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

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data);
    hand(*impl, 21, data);  // reserved type

    Entry entry;
    EXPECT_FALSE(pop_entry(*impl, entry));

    // Control: the negotiated type is still forwarded.
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_LOUDNESS);
}

// roles/visualizer/v1.md "Server -> Client: stream/start visualizer object": each frame is
// interpreted under the configuration in effect when it was received, so handle_binary() fits it
// to the negotiated stream before the hand-over. "spectrum" carries n_disp_bins bins, so a frame
// short of them is dropped and bins past them are left out; "beat" bit 0 is only meaningful when
// tracks_downbeats is true. A beat with no payload byte is handed over for decode to drop.
TEST(VisualizerHandleBinary, FitsSpectrumAndBeatFramesToTheStreamTheyArriveIn) {
    struct Row {
        const char* name;
        uint8_t type;
        std::vector<uint8_t> payload;
        bool tracks_downbeats;
        std::optional<std::vector<uint8_t>> handed;  // nullopt: dropped
    };
    const std::vector<Row> rows = {
        {"Control: spectrum of the negotiated three bins", SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         {0, 1, 0, 2, 0, 3}, false, std::vector<uint8_t>{0, 1, 0, 2, 0, 3}},
        {"spectrum one bin short", SENDSPIN_BINARY_VISUALIZER_SPECTRUM, {0, 1, 0, 2}, false,
         std::nullopt},
        {"spectrum past the negotiated bins", SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
         {0, 1, 0, 2, 0, 3, 0, 4}, false, std::vector<uint8_t>{0, 1, 0, 2, 0, 3}},
        {"Control: a downbeat while tracking downbeats", SENDSPIN_BINARY_VISUALIZER_BEAT, {0x03},
         true, std::vector<uint8_t>{0x03}},
        {"a downbeat bit while not tracking downbeats", SENDSPIN_BINARY_VISUALIZER_BEAT, {0x03},
         false, std::vector<uint8_t>{0x02}},
        {"Control: a beat with no payload byte", SENDSPIN_BINARY_VISUALIZER_BEAT, {}, false,
         std::vector<uint8_t>{}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        impl->negotiated_spectrum_bins = 3;
        impl->negotiated_tracks_downbeats = row.tracks_downbeats;
        std::vector<uint8_t> data;
        put_be64(data, 1);
        data.insert(data.end(), row.payload.begin(), row.payload.end());

        hand(*impl, row.type, data);

        Entry entry;
        ASSERT_EQ(pop_entry(*impl, entry), row.handed.has_value());
        if (row.handed.has_value()) {
            EXPECT_EQ(std::vector<uint8_t>(entry.message.begin() + 1 + 8, entry.message.end()),
                      *row.handed);
        }
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
/// Logs the stream callbacks in the order they fire, each start with its rate_max and form
/// ("started" for on_visualizer_stream_started(), "start" for the deprecated
/// on_visualizer_stream_start()), and keeps the latest stream each form reported.
class StreamEventLog : public VisualizerRoleListener {
public:
    void on_visualizer_stream_started(const VisualizerStream& stream) override {
        this->started = stream;
        this->calls.push_back("started " + std::to_string(stream.rate_max));
    }
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& stream) override {
        this->last = stream;
        this->calls.push_back("start " + std::to_string(stream.rate_max));
    }
    void on_visualizer_stream_end() override {
        this->calls.push_back("end");
    }
    void on_visualizer_stream_clear() override {
        this->calls.push_back("clear");
    }
    std::vector<std::string> calls;
    VisualizerStream started;
    ServerVisualizerStreamObject last;
};
#pragma GCC diagnostic pop

/// Hands every visualizer stream event `impl` has queued to the main loop, as the ring drain in
/// SendspinClient::drain_inbox() does once each event's stamp is current, without the role drain
/// that fires them.
void hold_stream_events(VisualizerRole::Impl& impl) {
    InboxEvent events[Inbox::EVENT_CAPACITY];
    const size_t count = impl.inbox->take_events(events, Inbox::EVENT_CAPACITY);
    for (size_t i = 0; i < count; ++i) {
        if (events[i].type == InboxEventType::VISUALIZER_STREAM) {
            impl.on_stream_ring_event(events[i]);
        }
    }
}

/// hold_stream_events(), then the role drain that fires them. No drain thread runs, so nothing
/// is held for one.
void dispatch_stream_events(VisualizerRole::Impl& impl) {
    hold_stream_events(impl);
    impl.drain_events();
}

/// Fills `impl`'s inbox event ring with events no role acts on, so the next push is dropped.
void fill_event_ring(VisualizerRole::Impl& impl) {
    InboxEvent filler{};
    filler.type = InboxEventType::CONTROLLER_CLEARED;
    while (impl.inbox->push_event(filler)) {
    }
}

/// A stream/start serving loudness at `rate_max`.
VisualizerStreamPayload loudness_stream(uint16_t rate_max) {
    VisualizerStreamPayload stream;
    stream.types = {VisualizerDataType::LOUDNESS};
    stream.rate_max = rate_max;
    return stream;
}

// roles/visualizer/v1.md "Server -> Client: stream/start visualizer object": a stream/start starts
// a stream or updates the running one, and on_visualizer_stream_started() hears both, each with
// its own stream, followed by the deprecated on_visualizer_stream_start(). A start whose notice a
// later start overwrote before it fired is folded into that later one: it reports nothing, since
// the later notice describes a newer configuration.
TEST(VisualizerStreamEvents, AStartFiresStartedThenTheDeprecatedStartUnlessALaterOneSupersedesIt) {
    enum class Step : uint8_t { START_10, START_20, END, FIRE };
    struct Row {
        const char* name;
        bool running;
        std::vector<Step> steps;
        std::vector<std::string> calls;
    };
    const Row rows[] = {
        {"Control: a start with no stream running", false, {Step::START_10},
         {"started 10", "start 10"}},
        {"a start updating the running stream", true, {Step::START_20},
         {"started 20", "start 20"}},
        {"a start, then one updating it, taken together", false, {Step::START_10, Step::START_20},
         {"started 20", "start 20"}},
        {"Control: a start fired before the one updating it",
         false,
         {Step::START_10, Step::FIRE, Step::START_20},
         {"started 10", "start 10", "started 20", "start 20"}},
        {"a start after an end", true, {Step::END, Step::START_20},
         {"end", "started 20", "start 20"}},
        {"a start superseded across an end", false, {Step::START_10, Step::END, Step::START_20},
         {"end", "started 20", "start 20"}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        impl->stream_active = row.running;
        StreamEventLog listener;
        impl->listener = &listener;
        for (Step step : row.steps) {
            if (step == Step::END) {
                impl->handle_stream_end();
            } else if (step == Step::FIRE) {
                dispatch_stream_events(*impl);
            } else {
                impl->handle_stream_start(loudness_stream(step == Step::START_10 ? 10 : 20));
            }
        }
        dispatch_stream_events(*impl);
        EXPECT_EQ(listener.calls, row.calls);
    }
}

// A stream event the main loop holds when a teardown overtakes it fires nothing: the teardown
// owes the stream its end instead (complete_teardown(), on the next drain's catch-up), and a
// stream/start queued before it must not report a stream the teardown ended. The rows hold the
// event, as the ring drain does, then run the teardown's protocol-task half before the role
// drain fires it.
TEST(VisualizerStreamEvents, AHeldEventATeardownOvertookFiresNothing) {
    struct Row {
        const char* name;
        bool clear;
        bool teardown;
        std::vector<std::string> calls;
    };
    const Row rows[] = {
        {"Control: a held start", false, false, {"started 10", "start 10"}},
        {"a held start a teardown overtook", false, true, {}},
        {"Control: a held clear", true, false, {"clear"}},
        {"a held clear a teardown overtook", true, true, {}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        impl->stream_active = false;
        impl->handle_stream_start(loudness_stream(10));
        StreamEventLog listener;
        if (row.clear) {
            dispatch_stream_events(*impl);
            impl->handle_stream_clear();
        }
        impl->listener = &listener;
        hold_stream_events(*impl);
        if (row.teardown) {
            impl->cleanup();
        }
        impl->drain_events();
        EXPECT_EQ(listener.calls, row.calls);
    }
}

// roles/visualizer/v1.md "Server -> Client: stream/start visualizer object" makes the types a
// subset of the requested ones and the spectrum the requested one, n_disp_bins aside. Each start
// reports the stream it admitted, whether it starts the stream or updates it: the types kept,
// tracks_downbeats with beat, and rate_max; the deprecated form lists the types once each, in
// enumerator order, with the spectrum as requested but for the served bin count, and a later
// stream replaces every field.
TEST(VisualizerStreamEvents, EachStartReportsTheStreamItAdmitted) {
    const VisualizerSpectrumConfig requested{
        .n_disp_bins = 16, .scale = VisualizerSpectrumScale::LOG, .f_min = 30, .f_max = 12000};
    auto impl = make_impl();
    impl->stream_active = false;
    impl->config.stream.types = {VisualizerDataType::BEAT, VisualizerDataType::LOUDNESS,
                                 VisualizerDataType::SPECTRUM, VisualizerDataType::PEAK};
    impl->config.stream.spectrum = requested;
    StreamEventLog listener;
    impl->listener = &listener;

    VisualizerSpectrumConfig served = requested;
    served.n_disp_bins = 12;
    impl->handle_stream_start({.types = {VisualizerDataType::PEAK, VisualizerDataType::SPECTRUM,
                                         VisualizerDataType::BEAT},
                               .rate_max = 24,
                               .tracks_downbeats = true,
                               .spectrum = served});
    dispatch_stream_events(*impl);
    VisualizerStream expected;
    expected.beat = true;
    expected.spectrum = true;
    expected.peak = true;
    expected.tracks_downbeats = true;
    expected.rate_max = 24;
    EXPECT_EQ(listener.started, expected);
    const auto& heard = listener.last;
    EXPECT_EQ(heard.types, (std::vector{VisualizerDataType::BEAT, VisualizerDataType::SPECTRUM,
                                        VisualizerDataType::PEAK}));
    EXPECT_EQ(heard.rate_max, 24);
    EXPECT_TRUE(heard.tracks_downbeats);
    ASSERT_TRUE(heard.spectrum.has_value());
    EXPECT_EQ(heard.spectrum->n_disp_bins, 12);
    EXPECT_EQ(heard.spectrum->scale, VisualizerSpectrumScale::LOG);
    EXPECT_EQ(heard.spectrum->f_min, 30);
    EXPECT_EQ(heard.spectrum->f_max, 12000);

    // An update that keeps loudness alone, served with downbeats it has no beat for.
    impl->handle_stream_start({.types = {VisualizerDataType::LOUDNESS}, .tracks_downbeats = true});
    dispatch_stream_events(*impl);
    expected = VisualizerStream{};
    expected.loudness = true;
    EXPECT_EQ(listener.started, expected);
    EXPECT_EQ(heard.types, std::vector{VisualizerDataType::LOUDNESS});
    EXPECT_EQ(heard.rate_max, 0);
    EXPECT_FALSE(heard.tracks_downbeats);
    EXPECT_FALSE(heard.spectrum.has_value());
    EXPECT_EQ(listener.calls,
              (std::vector<std::string>{"started 24", "start 24", "started 0", "start 0"}));
}

// The drain thread holds a frame until the main loop has fired every stream event queued before the
// frame arrived (is_acknowledged()): a stream/start, fresh or updating the running stream, or a
// stream/clear the main loop has not fired holds the frames received after it, and the frames
// received before an update keep the acknowledgement they had. The verdict holds across the
// lifecycle ordinal's wrap, which the acknowledgement every end makes keeps it near (a run of ends
// brings the next start to ordinal 0). An event the full inbox ring or the full held events drop
// never fires, so it releases its frames at once, ordered against nothing, and an earlier event
// fired after it does not take that back. A clear fired behind a start that an update queued after
// the clear superseded holds the clear's frames, received under a configuration no fired notice
// describes, until the update fires; one superseded by an update queued before the clear, which the
// full event ring dropped, holds nothing back, and ends the wait for that update, so a clear across
// the ordinal's wrap from it holds nothing back either. The rows drive the handlers and the main
// loop's drain with no drain thread, so nothing is held but what a row holds itself, and read the
// verdict on each frame left listed; the drain thread's wait on it is covered by
// VisualizerOrdering.AFrameAfterAStreamEventWaitsForItsNotice. The wrap rows fire about 65,000 ends
// or clears.
TEST(VisualizerHandshake, AFrameWaitsForTheStreamEventsQueuedBeforeIt) {
    enum class Step : uint8_t {
        START,
        CLEAR,
        FIRE,
        FRAME,
        ENDS_TO_THE_WRAP,    // Ends, each fired, until the next ordinal is the counter's 0
        CLEARS_TO_THE_WRAP,  // Clears, each fired, until the next ordinal is the counter's 0
        FILL_RING,           // The inbox event ring left full, so the next push is dropped
        FILL_HELD,           // Clears held for the drain thread until held_events is full
        HOLD,                // The queued events held, with no role drain
        DRAIN,               // The role drain alone, firing what is held
    };
    struct Row {
        const char* name;
        std::vector<Step> steps;
        std::vector<bool> acknowledged;  // Each listed frame's verdict, oldest first
    };
    // Every row begins with no stream running.
    const Row rows[] = {
        {"Control: after a start the main loop fired", {Step::START, Step::FIRE, Step::FRAME},
         {true}},
        {"after a start the main loop has not fired", {Step::START, Step::FRAME}, {false}},
        {"before and after an update the main loop has not fired",
         {Step::START, Step::FIRE, Step::FRAME, Step::START, Step::FRAME},
         {true, false}},
        {"Control: before and after an update the main loop fired",
         {Step::START, Step::FIRE, Step::FRAME, Step::START, Step::FIRE, Step::FRAME},
         {true, true}},
        {"after a clear the main loop has not fired",
         {Step::START, Step::FIRE, Step::CLEAR, Step::FRAME},
         {false}},
        {"Control: after a clear the main loop fired",
         {Step::START, Step::FIRE, Step::CLEAR, Step::FIRE, Step::FRAME},
         {true}},
        {"after a start the main loop has not fired, across the ordinal's wrap",
         {Step::START, Step::FIRE, Step::ENDS_TO_THE_WRAP, Step::START, Step::FRAME},
         {false}},
        {"Control: after a start the main loop fired, across the ordinal's wrap",
         {Step::START, Step::FIRE, Step::ENDS_TO_THE_WRAP, Step::START, Step::FIRE, Step::FRAME},
         {true}},
        {"after a start the full event ring dropped", {Step::FILL_RING, Step::START, Step::FRAME},
         {true}},
        {"after a clear the full event ring dropped",
         {Step::START, Step::FIRE, Step::FILL_RING, Step::CLEAR, Step::FRAME},
         {true}},
        {"after a clear the full event ring dropped behind a start fired later",
         {Step::START, Step::FILL_RING, Step::CLEAR, Step::FRAME, Step::FIRE},
         {true}},
        {"after a clear the full held events dropped",
         {Step::START, Step::FIRE, Step::FILL_HELD, Step::CLEAR, Step::HOLD, Step::FRAME},
         {true}},
        {"Control: after a clear held, not dropped",
         {Step::START, Step::FIRE, Step::CLEAR, Step::HOLD, Step::FRAME},
         {false}},
        {"after a clear behind a start an update after the clear superseded",
         {Step::START, Step::CLEAR, Step::FRAME, Step::HOLD, Step::START, Step::DRAIN},
         {false}},
        {"Control: after a clear behind a superseded start, once the update fired",
         {Step::START, Step::CLEAR, Step::FRAME, Step::HOLD, Step::START, Step::DRAIN, Step::FIRE},
         {true}},
        {"after a clear behind a start a dropped update before the clear superseded",
         {Step::START, Step::FILL_RING, Step::START, Step::HOLD, Step::CLEAR, Step::FRAME,
          Step::FIRE},
         {true}},
        {"after a clear across the ordinal's wrap from a dropped update that superseded a start",
         {Step::START, Step::FILL_RING, Step::START, Step::HOLD, Step::CLEARS_TO_THE_WRAP,
          Step::CLEAR, Step::FIRE, Step::FRAME},
         {true}},
    };
    std::vector<uint8_t> data;
    put_be64(data, 1);
    put_be16(data, 0x0001);
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        impl->stream_active = false;
        for (Step step : row.steps) {
            switch (step) {
                case Step::START:
                    impl->handle_stream_start(loudness_stream(10));
                    break;
                case Step::CLEAR:
                    impl->handle_stream_clear();
                    break;
                case Step::FIRE:
                    dispatch_stream_events(*impl);
                    break;
                case Step::FRAME:
                    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);
                    break;
                case Step::ENDS_TO_THE_WRAP:
                    while (impl->lifecycle_ordinal != UINT16_MAX) {
                        impl->handle_stream_end();
                        dispatch_stream_events(*impl);
                    }
                    break;
                case Step::CLEARS_TO_THE_WRAP:
                    while (impl->lifecycle_ordinal != UINT16_MAX) {
                        impl->handle_stream_clear();
                        dispatch_stream_events(*impl);
                    }
                    break;
                case Step::FILL_RING:
                    fill_event_ring(*impl);
                    break;
                case Step::FILL_HELD:
                    while (impl->held_events.size() < impl->held_events.capacity()) {
                        impl->handle_stream_clear();
                        hold_stream_events(*impl);
                    }
                    break;
                case Step::HOLD:
                    hold_stream_events(*impl);
                    break;
                case Step::DRAIN:
                    impl->drain_events();
                    break;
            }
        }
        std::vector<bool> acknowledged;
        void* item = nullptr;
        while ((item = impl->drain_task->inbound.take(0, impl->cleanup_generation)) != nullptr) {
            EXPECT_FALSE(impl->is_stale(item));
            acknowledged.push_back(impl->is_acknowledged(item));
            impl->drain_task->inbound.ring()->return_item(item);
        }
        EXPECT_EQ(acknowledged, row.acknowledged);
    }
}

// roles/visualizer/v1.md "Server -> Client: stream/start": `types` "MUST be a subset of the types
// the client requested", and the spectrum object "MUST match the client's current requested
// configuration", though "Servers MAY impose an implementation-defined upper bound on
// n_disp_bins". A served type outside the request is neither admitted nor reported to the main
// loop, nor is spectrum served with no object, more bins, or another scale or range, while the
// rest of the stream is. No wire input reaches the missing object:
// process_stream_start_message() rejects a stream/start whose visualizer object advertises
// spectrum with no valid spectrum config. That the served bin count governs the delivered frame
// is asserted where a consumer sees it, in
// ClientLifecycle.TheServedSpectrumBinCountGovernsTheDeliveredFrame.
TEST(VisualizerSpectrumWiring, OnlyRequestedTypesAndAMatchingSpectrumAreAdmitted) {
    const VisualizerSpectrumConfig four_bins{
        .n_disp_bins = 4, .scale = VisualizerSpectrumScale::MEL, .f_min = 40, .f_max = 16000};
    const auto with = [&four_bins](auto change) {
        VisualizerSpectrumConfig served = four_bins;
        change(served);
        return served;
    };
    const std::vector<VisualizerDataType> spectrum_and_loudness = {VisualizerDataType::SPECTRUM,
                                                                   VisualizerDataType::LOUDNESS};

    struct Row {
        const char* name;
        std::vector<VisualizerDataType> requested;
        std::optional<VisualizerSpectrumConfig> served_spectrum;
        VisualizerDataType handed;
        bool expected_admitted;
        uint8_t expected_bins;
        bool expected_downbeats{false};
    };
    const std::vector<Row> rows = {
        {"Control: spectrum matching the request is admitted", spectrum_and_loudness, four_bins,
         VisualizerDataType::SPECTRUM, true, 4},
        {"Control: spectrum under the requested bin count is admitted", spectrum_and_loudness,
         with([](auto& s) { s.n_disp_bins = 3; }), VisualizerDataType::SPECTRUM, true, 3},
        {"spectrum with no spectrum object is dropped", spectrum_and_loudness, std::nullopt,
         VisualizerDataType::SPECTRUM, false, 0},
        {"spectrum serving more bins than requested is dropped", spectrum_and_loudness,
         with([](auto& s) { s.n_disp_bins = 5; }), VisualizerDataType::SPECTRUM, false, 0},
        {"spectrum on another scale is dropped", spectrum_and_loudness,
         with([](auto& s) { s.scale = VisualizerSpectrumScale::LOG; }),
         VisualizerDataType::SPECTRUM, false, 0},
        {"spectrum over another frequency range is dropped", spectrum_and_loudness,
         with([](auto& s) { s.f_max = 8000; }), VisualizerDataType::SPECTRUM, false, 0},
        {"Control: a requested type flows beside a dropped spectrum", spectrum_and_loudness,
         with([](auto& s) { s.n_disp_bins = 5; }), VisualizerDataType::LOUDNESS, true, 0},
        {"spectrum the configuration does not request is dropped", {VisualizerDataType::LOUDNESS},
         four_bins, VisualizerDataType::SPECTRUM, false, 0},
        {"loudness the configuration does not request is dropped", {VisualizerDataType::SPECTRUM},
         four_bins, VisualizerDataType::LOUDNESS, false, 4},
        {"beat the configuration does not request is dropped with its downbeats",
         spectrum_and_loudness, four_bins, VisualizerDataType::BEAT, false, 4, false},
        {"Control: requested beat keeps its downbeats",
         {VisualizerDataType::SPECTRUM, VisualizerDataType::LOUDNESS, VisualizerDataType::BEAT},
         four_bins, VisualizerDataType::BEAT, true, 4, true},
    };
    const auto wire_type = [](VisualizerDataType type) -> uint8_t {
        switch (type) {
            case VisualizerDataType::SPECTRUM:
                return SENDSPIN_BINARY_VISUALIZER_SPECTRUM;
            case VisualizerDataType::BEAT:
                return SENDSPIN_BINARY_VISUALIZER_BEAT;
            default:
                return SENDSPIN_BINARY_VISUALIZER_LOUDNESS;
        }
    };

    // A timestamp, then five bins, one more than requested.
    std::vector<uint8_t> data;
    put_be64(data, 1);
    for (uint16_t bin : {10, 20, 30, 40, 50}) {
        put_be16(data, bin);
    }

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        StreamEventLog listener;
        impl->listener = &listener;
        impl->config.stream.types = row.requested;
        impl->config.stream.spectrum = four_bins;

        // The server serves all three types, tracking downbeats, whatever was requested.
        VisualizerStreamPayload stream;
        stream.types = {VisualizerDataType::SPECTRUM, VisualizerDataType::LOUDNESS,
                        VisualizerDataType::BEAT};
        stream.tracks_downbeats = true;
        stream.spectrum = row.served_spectrum;
        impl->handle_stream_start(stream);
        take_in_ring_order(*impl->drain_task->inbound.ring());

        hand(*impl, wire_type(row.handed), data);
        Entry entry;
        EXPECT_EQ(pop_entry(*impl, entry), row.expected_admitted);
        EXPECT_EQ(impl->negotiated_spectrum_bins, row.expected_bins);

        // The stream the main loop reports is the admitted one.
        dispatch_stream_events(*impl);
        ASSERT_EQ(listener.calls.size(), 2U);
        const auto& heard = listener.last;
        EXPECT_EQ(std::find(heard.types.begin(), heard.types.end(), row.handed) !=
                      heard.types.end(),
                  row.expected_admitted);
        EXPECT_EQ(heard.spectrum.has_value(), row.expected_bins != 0);
        EXPECT_EQ(heard.tracks_downbeats, row.expected_downbeats);
        EXPECT_EQ(listener.started.spectrum, row.expected_bins != 0);
        EXPECT_EQ(listener.started.tracks_downbeats, row.expected_downbeats);
    }
}

TEST(VisualizerHandleBinary, StreamStartNegotiatesTypes) {
    // handle_stream_start derives the admission mask from the advertised types.
    auto impl = make_impl();
    impl->negotiated_types_mask = 0;

    VisualizerStreamPayload stream;
    stream.types = {VisualizerDataType::BEAT};
    impl->handle_stream_start(stream);
    take_in_ring_order(*impl->drain_task->inbound.ring());

    Entry entry;
    std::vector<uint8_t> data;
    put_be64(data, 1);
    data.push_back(0x01);

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_BEAT, data);
    ASSERT_TRUE(pop_entry(*impl, entry));
    EXPECT_EQ(entry.type, SENDSPIN_BINARY_VISUALIZER_BEAT);

    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, data);
    EXPECT_FALSE(pop_entry(*impl, entry));
}

// ============================================================================
// Stream boundaries: a stream/start with no stream running, stream/end, stream/clear and a
// teardown each recall the listed frames and move the role's boundary on.
// ============================================================================

// A boundary returns the frames listed before it, so only frames sent after the latest one
// survive (roles/visualizer/v1.md "stream/end", messaging.md "stream/clear"). A stream/start that
// updates the running stream is no boundary: the client keeps the buffered frames
// (roles/visualizer/v1.md "Server -> Client: stream/start visualizer object"), those of a type
// the update stops serving included, while later frames of that type are not admitted. Every
// frame left is current, so the drain thread delivers it. The rows drive the handlers with no
// drain thread; the held frame is covered by
// ClientLifecycle.AStreamBoundaryReturnsTheVisualizerFrameHeldForItsDisplayTime and
// VisualizerDelivery.AnUpdatingStreamStartKeepsTheHeldAndListedFrames.
// Gap: a current held frame's resumed wait.
TEST(VisualizerBoundary, ABoundaryReturnsTheFramesListedBeforeIt) {
    enum class Step { END, START, START_BEAT_ONLY, CLEAR, CLEANUP, FRAME };
    struct Row {
        const char* name;
        std::vector<Step> steps;
        std::vector<uint8_t> surviving;  // the last payload byte of each frame taken
    };
    // Every row first lists two frames of the running stream (payload 0x01); each FRAME step
    // lists one carrying the next value from 0x02.
    const Row rows[] = {
        {"Control: no boundary keeps the running stream's frames", {}, {0x01, 0x01}},
        {"an end with no stream after it empties the list", {Step::END}, {}},
        {"Control: an end then a start keeps only the new stream's frame",
         {Step::END, Step::START, Step::FRAME},
         {0x02}},
        {"a clear keeps the frame sent after it", {Step::CLEAR, Step::FRAME}, {0x02}},
        {"a start updating the running stream keeps the frames before it",
         {Step::START, Step::FRAME},
         {0x01, 0x01, 0x02}},
        {"two updates keep every frame", {Step::START, Step::FRAME, Step::START, Step::FRAME},
         {0x01, 0x01, 0x02, 0x03}},
        {"an update dropping the frames' type keeps those listed before it",
         {Step::START_BEAT_ONLY, Step::FRAME},
         {0x01, 0x01}},
        {"an update and its frame followed by an end empties the list",
         {Step::START, Step::FRAME, Step::END},
         {}},
        {"a teardown then a start keeps the new stream's frame",
         {Step::CLEANUP, Step::START, Step::FRAME},
         {0x02}},
    };

    VisualizerStreamPayload stream;
    stream.types = {VisualizerDataType::LOUDNESS};
    VisualizerStreamPayload beat_only;
    beat_only.types = {VisualizerDataType::BEAT};
    auto loudness = [](uint8_t value) {
        std::vector<uint8_t> data;
        put_be64(data, value);
        put_be16(data, value);
        return data;
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->drain_task->inbound.ring();
        hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, loudness(0x01));
        hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, loudness(0x01));
        uint8_t next_value = 0x02;
        for (Step step : row.steps) {
            switch (step) {
                case Step::END:
                    impl->handle_stream_end();
                    break;
                case Step::START:
                    impl->handle_stream_start(stream);
                    break;
                case Step::START_BEAT_ONLY:
                    impl->handle_stream_start(beat_only);
                    break;
                case Step::CLEAR:
                    impl->handle_stream_clear();
                    break;
                case Step::CLEANUP:
                    impl->cleanup();
                    break;
                case Step::FRAME:
                    hand(*impl, SENDSPIN_BINARY_VISUALIZER_LOUDNESS, loudness(next_value++));
                    break;
            }
        }

        std::vector<uint8_t> surviving;
        void* item = nullptr;
        while ((item = impl->drain_task->inbound.take(0, impl->cleanup_generation)) != nullptr) {
            const InboundItemHeader* header = inbound_item_header(item);
            surviving.push_back(inbound_item_bytes(item)[header->data_offset + header->data_len - 1]);
            EXPECT_FALSE(impl->is_stale(item)) << "a frame left listed would not be delivered";
            ring.return_item(item);
        }
        EXPECT_EQ(surviving, row.surviving);
        EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U)
            << "a stale frame kept its charge";
    }
}

// roles/visualizer/v1.md "Server -> Client: stream/start visualizer object": "Servers MAY impose
// an implementation-defined upper bound on n_disp_bins", so a stream/start updating the running
// stream can change the bin count, and the frames buffered before it keep theirs. Each frame is
// judged against the count negotiated when it arrives (a frame short of it is dropped then) and
// decoded, out of the bins start() reserves for the requested count, with the count it arrived
// under.
TEST(VisualizerStreamUpdate, EachFrameKeepsTheBinCountOfTheStreamItArrivedIn) {
    const VisualizerSpectrumConfig four_bins{
        .n_disp_bins = 4, .scale = VisualizerSpectrumScale::MEL, .f_min = 40, .f_max = 16000};
    auto impl = make_impl();
    impl->config.stream.types = {VisualizerDataType::SPECTRUM};
    impl->config.stream.spectrum = four_bins;
    impl->stream_active = false;
    const auto start_with_bins = [&impl, &four_bins](uint8_t bins) {
        VisualizerStreamPayload stream;
        stream.types = {VisualizerDataType::SPECTRUM};
        stream.spectrum = four_bins;
        stream.spectrum->n_disp_bins = bins;
        impl->handle_stream_start(stream);
    };
    // A spectrum frame of `bins` bins, the first holding `first`.
    const auto spectrum = [](uint16_t first, size_t bins) {
        std::vector<uint8_t> data;
        put_be64(data, 1);
        put_be16(data, first);
        for (size_t b = 1; b < bins; ++b) {
            put_be16(data, 0);
        }
        return data;
    };

    start_with_bins(4);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_SPECTRUM, spectrum(1, 4));  // Control: four of four
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_SPECTRUM, spectrum(2, 2));  // Short of four
    start_with_bins(2);
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_SPECTRUM, spectrum(3, 2));  // Control: two of two
    hand(*impl, SENDSPIN_BINARY_VISUALIZER_SPECTRUM, spectrum(4, 1));  // Short of two

    std::vector<uint16_t> bins;
    bins.reserve(four_bins.n_disp_bins);
    std::vector<std::pair<uint16_t, size_t>> delivered;  // Each frame's first bin and bin count
    void* item = nullptr;
    while ((item = impl->drain_task->inbound.take(0, impl->cleanup_generation)) != nullptr) {
        EXPECT_FALSE(impl->is_stale(item));
        const InboundItemHeader* header = inbound_item_header(item);
        const VisualizerDelivery out = decode_visualizer_message(
            header->type, inbound_item_data(item), header->data_len, bins);
        EXPECT_EQ(out.kind, VisualizerDelivery::Kind::SPECTRUM);
        delivered.emplace_back(bins.empty() ? 0 : bins[0], bins.size());
        impl->drain_task->inbound.ring()->return_item(item);
    }
    EXPECT_EQ(delivered, (std::vector<std::pair<uint16_t, size_t>>{{1, 4}, {3, 2}}));
}

// A teardown (a dropped connection, a removed role, stop()) moves the role's generation on, and
// the old stream's frames are never delivered: cleanup() recalls what the drain thread has not
// taken, returning it and its quota charge to the shared ring, and a frame the drain thread takes
// between the generation bump and the recall is dropped by its generation stamp and returned the
// same way. That window has no observable trigger, so its row moves the generation on directly,
// leaving the frames listed.
TEST(VisualizerBoundary, ATeardownRecallsTheFramesTheDrainThreadHasNotTaken) {
    enum class Teardown { NONE, CLEANUP, GENERATION_ONLY };
    struct Row {
        const char* name;
        Teardown teardown;
        bool listed_before_take;
        size_t delivered;
    };
    const Row rows[] = {
        {"Control: no teardown", Teardown::NONE, true, 2},
        {"torn down, recalled by cleanup()", Teardown::CLEANUP, false, 0},
        {"taken by the drain thread before the recall", Teardown::GENERATION_ONLY, true, 0},
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
            impl->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, message);
        }
        if (row.teardown == Teardown::CLEANUP) {
            impl->cleanup();
        } else if (row.teardown == Teardown::GENERATION_ONLY) {
            impl->cleanup_generation.fetch_add(1, std::memory_order_acq_rel);
        }

        EXPECT_EQ(!impl->drain_task->inbound.items().is_empty(), row.listed_before_take);
        // Taken under the live generation, as the drain thread takes them: a recalled or stale
        // frame is not delivered, and one left over is.
        size_t delivered = 0;
        void* item = nullptr;
        while ((item = impl->drain_task->inbound.take(0, impl->cleanup_generation)) != nullptr) {
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
    EXPECT_EQ(std::vector<VisualizerDataType>(state.visualizer->types.begin(),
                                              state.visualizer->types.end()),
              (std::vector<VisualizerDataType>{VisualizerDataType::SPECTRUM,
                                               VisualizerDataType::BEAT}));
    EXPECT_EQ(state.visualizer->rate_max, 25);
    ASSERT_TRUE(state.visualizer->spectrum.has_value());
    EXPECT_EQ(state.visualizer->spectrum->n_disp_bins, 16);
    EXPECT_EQ(state.visualizer->spectrum->scale, VisualizerSpectrumScale::LOG);

    // Control: a role that asks for no data still reports the object, so the server knows the
    // role is configured and streams nothing rather than waiting for a state that never comes.
    auto quiet = make_impl();
    quiet->config.stream.types.clear();
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

// The drain thread delivers spectrum frames into bins start() reserves, so a first frame never
// allocates on it; only a configuration that requests the spectrum type pays for them.
TEST(VisualizerStartReservation, StartReservesTheSpectrumBinsOnlyWhenSpectrumIsRequested) {
    const VisualizerSpectrumConfig spectrum{
        .n_disp_bins = 16,
        .scale = VisualizerSpectrumScale::LOG,
        .f_min = 20,
        .f_max = 20000,
    };

    struct Row {
        const char* name;
        VisualizerStreamConfig stream;
        bool reserves;
    };
    const std::vector<Row> rows = {
        {"Control: the spectrum type reserves the configured bins",
         VisualizerStreamConfig{.types = {VisualizerDataType::LOUDNESS,
                                          VisualizerDataType::SPECTRUM},
                                .rate_max = 25,
                                .spectrum = spectrum},
         true},
        {"a spectrum object without the spectrum type reserves nothing",
         VisualizerStreamConfig{
             .types = {VisualizerDataType::LOUDNESS}, .rate_max = 25, .spectrum = spectrum},
         false},
        {"no spectrum at all reserves nothing",
         VisualizerStreamConfig{.types = {VisualizerDataType::LOUDNESS}, .rate_max = 25}, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundRing ring;  // outlives the role, whose drain list links it
        create_test_ring(ring);
        auto impl = make_impl_with_stream(row.stream);
        ASSERT_TRUE(impl->start(&ring));
        const size_t capacity = impl->drain_task->spectrum_bins.capacity();
        impl->stop();
        if (row.reserves) {
            EXPECT_GE(capacity, spectrum.n_disp_bins);
        } else {
            EXPECT_EQ(capacity, 0U);
        }
    }
}
