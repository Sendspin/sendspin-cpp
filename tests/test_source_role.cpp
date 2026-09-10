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

// Source role tests. Two layers, mirroring the acceptance criteria:
//  - Pure chunk/timestamp bookkeeping helpers from source_task.h, tested directly.
//  - SourceRole::Impl-level tests (make_impl pattern from test_artwork_role.cpp): config
//    validation, hello/state field building, the command latch's fail-closed path, and
//    lifecycle callback pairing.

#include "connection_manager.h"
#include "inbox.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "source_encoder.h"
#include "source_role_impl.h"
#include "source_task.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// ============================================================================
// Pure bookkeeping helpers (source_task.h)
// ============================================================================

// Defends the chunk_bytes_ derivation in SourceTask::init(): chunk_frames must be exactly
// chunk_duration_ms * sample_rate / 1000.
TEST(SourceBookkeeping, MsToFramesDerivesChunkFrames) {
    EXPECT_EQ(source_ms_to_frames(25, 48000), 1200U);
    EXPECT_EQ(source_ms_to_frames(5, 8000), 40U);
    EXPECT_EQ(source_ms_to_frames(150, 44100), 6615U);
    // Control: a duration too short to hold a frame truncates to zero (init() fails closed on
    // this).
    EXPECT_EQ(source_ms_to_frames(5, 100), 0U);
    // 64-bit contract: the ms x rate intermediate here is 4.8e9 > 2^32, which 32-bit
    // arithmetic (size_t on ESP32) would wrap to 505032 frames; init() additionally caps the
    // derived byte sizes before narrowing.
    EXPECT_EQ(source_ms_to_frames(100000, 48000), 4800000ULL);
}

// Defends write_audio()'s whole-frame validation unit and the payload sizing.
TEST(SourceBookkeeping, BytesPerFrame) {
    EXPECT_EQ(source_bytes_per_frame(2, 16), 4U);
    EXPECT_EQ(source_bytes_per_frame(2, 24), 6U);  // 24-bit = 3 packed bytes per sample
    EXPECT_EQ(source_bytes_per_frame(1, 32), 4U);
}

TEST(SourceBookkeeping, FramesToUs) {
    EXPECT_EQ(source_frames_to_us(1200, 48000), 25000);
    EXPECT_EQ(source_frames_to_us(48000, 48000), 1000000);
    // Truncation, not rounding: 1 frame at 48 kHz is 20.83 µs.
    EXPECT_EQ(source_frames_to_us(1, 48000), 20);
}

// Defends the chunk-anchor bookkeeping in SourceTask::stream(): the wire timestamp anchors on
// the capture time of the chunk's FIRST sample, advanced past the frames of the entry already
// consumed by earlier chunks.
TEST(SourceBookkeeping, EntryAnchorAdvancesAcrossChunkBoundaries) {
    constexpr uint32_t RATE = 48000;
    constexpr size_t BPF = 4;

    // A chunk that starts at the top of an entry anchors on the entry timestamp itself.
    EXPECT_EQ(source_entry_anchor_us(1000000, 0, BPF, RATE), 1000000);

    // Misaligned entry-vs-chunk sizes: entries of 100 frames, chunks of 64 frames. The third
    // chunk starts 28 frames into the second entry (chunk 1 took frames 0-63 of entry 0,
    // chunk 2 took frames 64-99 of entry 0 plus frames 0-27 of entry 1).
    constexpr int64_t ENTRY1_TS = 5000000;
    const int64_t anchor = source_entry_anchor_us(ENTRY1_TS, 28 * BPF, BPF, RATE);
    EXPECT_EQ(anchor, ENTRY1_TS + source_frames_to_us(28, RATE));

    // Consuming a whole 100-frame entry advances its anchor by exactly its duration.
    EXPECT_EQ(source_entry_anchor_us(ENTRY1_TS, 100 * BPF, BPF, RATE),
              ENTRY1_TS + source_frames_to_us(100, RATE));
}

// Defends every branch of PcmPassthroughEncoder::encode() (source_encoder.h): the aliased
// in == out shape the task uses, the separate-buffer shape the interface contract also
// requires, and the capacity guard.
TEST(SourceBookkeeping, PcmPassthroughEncoderContract) {
    PcmPassthroughEncoder encoder;
    uint8_t buffer[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    // Aliased (the production shape): returns the length, bytes untouched.
    EXPECT_EQ(encoder.encode(buffer, sizeof(buffer), buffer, sizeof(buffer)), sizeof(buffer));
    EXPECT_EQ(buffer[0], 1);
    EXPECT_EQ(buffer[7], 8);

    // Separate buffers: the payload is copied.
    uint8_t out[8] = {0};
    EXPECT_EQ(encoder.encode(buffer, sizeof(buffer), out, sizeof(out)), sizeof(buffer));
    EXPECT_EQ(0, memcmp(buffer, out, sizeof(buffer)));

    // Capacity guard: input larger than the output area encodes nothing.
    uint8_t small[4] = {0};
    EXPECT_EQ(encoder.encode(buffer, sizeof(buffer), small, sizeof(small)), 0U);

    EXPECT_EQ(encoder.lookahead_us(), 0);

    // can_encode(): PCM takes any nonempty chunk, so a stream-end remainder always goes out.
    EXPECT_TRUE(encoder.can_encode(6));
    EXPECT_FALSE(encoder.can_encode(0));
}

// ============================================================================
// Impl-level harness
// ============================================================================

/// Records the source lifecycle callbacks. Callbacks fire on the pumping/test thread, so plain
/// counters suffice.
class RecordingSourceListener : public SourceRoleListener {
public:
    void on_streaming_started() override {
        ++this->started;
    }
    void on_streaming_stopped() override {
        ++this->stopped;
    }

    int started{0};
    int stopped{0};
};

// A real, never-started SendspinClient plus a bound SourceRole::Impl. Heap-allocated with
// program lifetime (static deques, mirroring make_impl() in test_artwork_role.cpp): the Impl
// keeps raw SendspinClient* and ConnectionManager* pointers, so both must outlive it. The
// standalone ConnectionManager never holds a connection, so current() stays null -- exactly the
// stale-connection shape the fail-closed latch tests need.
std::unique_ptr<SourceRole::Impl> make_impl(SourceRoleConfig config) {
    static std::deque<SendspinClient> clients;
    static std::deque<ConnectionManager> managers;
    static std::deque<Inbox> inboxes;

    clients.emplace_back(SendspinClientConfig{});
    managers.emplace_back(&clients.back());
    inboxes.emplace_back();

    auto impl = std::make_unique<SourceRole::Impl>(config, &clients.back());
    impl->attach_inbox(inboxes.back());
    impl->connection_manager = &managers.back();
    return impl;
}

/// Replays pending SOURCE_STREAM ring events into the impl and drains it, mirroring the
/// dispatch order in SendspinClient::loop() (ring events first, then the role drain).
void pump_ring_and_drain(SourceRole::Impl& impl) {
    InboxEvent events[Inbox::EVENT_CAPACITY];
    size_t count = impl.inbox->take_events(events, Inbox::EVENT_CAPACITY);
    for (size_t i = 0; i < count; ++i) {
        if (events[i].type == InboxEventType::SOURCE_STREAM) {
            impl.on_stream_ring_event(static_cast<SourceStreamCallbackType>(events[i].code));
        }
    }
    impl.drain_events();
}

bool advertises_source(SourceRole::Impl& impl) {
    ClientHelloMessage msg;
    impl.build_hello_fields(msg);
    return std::find(msg.supported_roles.begin(), msg.supported_roles.end(),
                     SendspinRole::SOURCE) != msg.supported_roles.end();
}

// ============================================================================
// Config validation (rejected configs leave the role inert, never clamped)
// ============================================================================

// Defends validate_config()'s chunk-duration bounds in source_role.cpp: the spec's [5, 150] ms
// window rejects outside values instead of clamping them.
TEST(SourceConfigValidation, ChunkDurationBounds) {
    auto make_with_chunk = [](uint32_t ms) {
        SourceRoleConfig config;
        config.chunk_duration_ms = ms;
        return make_impl(config);
    };
    EXPECT_FALSE(advertises_source(*make_with_chunk(4)));
    EXPECT_FALSE(advertises_source(*make_with_chunk(151)));
    // Control: the bound values themselves and the default are accepted.
    EXPECT_TRUE(advertises_source(*make_with_chunk(5)));
    EXPECT_TRUE(advertises_source(*make_with_chunk(25)));
    EXPECT_TRUE(advertises_source(*make_with_chunk(150)));
}

// Defends validate_config()'s format checks: zero rate/channels and unsupported bit depths
// reject the whole config.
TEST(SourceConfigValidation, FormatFields) {
    {
        SourceRoleConfig config;
        config.sample_rate = 0;
        EXPECT_FALSE(advertises_source(*make_impl(config)));
    }
    {
        SourceRoleConfig config;
        config.channels = 0;
        EXPECT_FALSE(advertises_source(*make_impl(config)));
    }
    for (uint8_t depth : {uint8_t{8}, uint8_t{12}}) {
        SourceRoleConfig config;
        config.bit_depth = depth;
        EXPECT_FALSE(advertises_source(*make_impl(config)));
    }
    // Control: every supported depth is accepted.
    for (uint8_t depth : {uint8_t{16}, uint8_t{24}, uint8_t{32}}) {
        SourceRoleConfig config;
        config.bit_depth = depth;
        EXPECT_TRUE(advertises_source(*make_impl(config)));
    }
}

// Defends build_hello_fields(): a valid role advertises source@v1 with the support object
// carrying the configured line_sense flag.
TEST(SourceHello, AdvertisesSupportObject) {
    SourceRoleConfig config;
    config.line_sense = true;
    auto impl = make_impl(config);

    ClientHelloMessage msg;
    impl->build_hello_fields(msg);
    ASSERT_TRUE(advertises_source(*impl));
    ASSERT_TRUE(msg.source_v1_support.has_value());
    EXPECT_TRUE(msg.source_v1_support->line_sense);
}

// Defends build_state_fields() and set_signal(): the source state object is always present for
// a valid role, carries signal only after set_signal() with line_sense configured, and an
// invalid config contributes nothing.
TEST(SourceState, SignalOnlyWithLineSense) {
    {
        auto impl = make_impl(SourceRoleConfig{});  // line_sense defaults off
        impl->set_signal(SourceSignal::PRESENT);    // ignored with a warning
        ClientStateMessage msg;
        impl->build_state_fields(msg);
        ASSERT_TRUE(msg.source.has_value());
        EXPECT_FALSE(msg.source->signal.has_value());
    }
    {
        SourceRoleConfig config;
        config.line_sense = true;
        auto impl = make_impl(config);
        {
            ClientStateMessage msg;
            impl->build_state_fields(msg);
            ASSERT_TRUE(msg.source.has_value());
            EXPECT_FALSE(msg.source->signal.has_value());  // no signal reported yet
        }
        impl->set_signal(SourceSignal::PRESENT);
        ClientStateMessage msg;
        impl->build_state_fields(msg);
        ASSERT_TRUE(msg.source.has_value());
        ASSERT_TRUE(msg.source->signal.has_value());
        EXPECT_EQ(msg.source->signal.value(), SourceSignal::PRESENT);
    }
    {
        SourceRoleConfig config;
        config.sample_rate = 0;  // invalid
        auto impl = make_impl(config);
        ClientStateMessage msg;
        impl->build_state_fields(msg);
        EXPECT_FALSE(msg.source.has_value());
    }
}

// ============================================================================
// Command latch (fail closed) and lifecycle pairing
// ============================================================================

// Defends the instance-id check in drain_events(): a start command whose connection is no
// longer current (here: no connection at all) must be discarded, never latched -- streaming
// permission is per-connection.
TEST(SourceCommandLatch, StaleInstanceStartDiscarded) {
    auto impl = make_impl(SourceRoleConfig{});
    ASSERT_TRUE(impl->start());

    impl->handle_server_command(SourceCommand::START, 7);
    impl->drain_events();

    EXPECT_FALSE(impl->streaming_desired);
    EXPECT_FALSE(impl->task->is_running());
}

// Defends cleanup(): the latch resets to stopped unconditionally and the unconditional
// STOPPED event fires on_streaming_stopped() exactly once, paired with the earlier start.
TEST(SourceCommandLatch, CleanupResetsLatchAndPairsStop) {
    auto impl = make_impl(SourceRoleConfig{});
    RecordingSourceListener listener;
    impl->listener = &listener;

    // Simulate an open stream as the task would report it.
    impl->streaming_desired = true;
    impl->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STARTED);
    pump_ring_and_drain(*impl);
    ASSERT_EQ(listener.started, 1);
    ASSERT_TRUE(impl->streaming_active);

    impl->cleanup();
    EXPECT_FALSE(impl->streaming_desired);
    pump_ring_and_drain(*impl);
    EXPECT_EQ(listener.stopped, 1);
    EXPECT_FALSE(impl->streaming_active);

    // A second teardown (double-teardown tick) must not fire an unpaired second callback.
    impl->cleanup();
    pump_ring_and_drain(*impl);
    EXPECT_EQ(listener.stopped, 1);
}

// Defends the streaming_active gate in drain_events(): duplicate STARTED/STOPPED ring events
// collapse to one callback each, keeping the listener pairing 1:1.
TEST(SourceCommandLatch, DuplicateLifecycleEventsCollapse) {
    auto impl = make_impl(SourceRoleConfig{});
    RecordingSourceListener listener;
    impl->listener = &listener;

    impl->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STARTED);
    impl->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STARTED);
    pump_ring_and_drain(*impl);
    EXPECT_EQ(listener.started, 1);

    impl->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STOPPED);
    impl->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STOPPED);
    pump_ring_and_drain(*impl);
    EXPECT_EQ(listener.stopped, 1);
}

// Defends the accepting gate in SourceTask::write_audio(): with no open stream every write is
// rejected, whole frames or not.
TEST(SourceWriteAudio, RejectedWhenNotStreaming) {
    auto impl = make_impl(SourceRoleConfig{});
    ASSERT_TRUE(impl->start());

    const uint8_t frame[4] = {1, 2, 3, 4};
    EXPECT_FALSE(impl->write_audio(frame, sizeof(frame), 0));
}

}  // namespace
