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

// Source role tests. Three layers, mirroring the acceptance criteria:
//  - Pure chunk/timestamp bookkeeping helpers from source_task.h, tested directly.
//  - SourceRole::Impl-level tests (make_impl pattern from test_artwork_role.cpp): config
//    validation, hello/state field building, the command latch's fail-closed path, and
//    lifecycle callback pairing.
//  - End-to-end wire tests driving a real SendspinClient against an in-test loopback
//    IXWebSocket "server" (the harness test_connection_lifecycle.cpp establishes), proving the
//    wire ordering client-stream/start -> typed+stamped binary chunks -> client-stream/end and
//    every streaming gate (no start command, stale connection, no time sync, after stop).

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
#include <ixwebsocket/IXWebSocket.h>

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

// Distinct ports per wire test (and distinct from test_connection_lifecycle.cpp's 189xx range)
// so a lingering socket from one scenario cannot bleed into the next.
constexpr uint16_t WIRE_TEST_PORT = 19010;
constexpr uint16_t TIME_GATE_TEST_PORT = 19011;
constexpr uint16_t RECONNECT_TEST_PORT = 19012;

// Default-config wire framing, derived exactly as source_task.cpp derives it: 25 ms at
// 48 kHz stereo 16-bit -> 1200 frames x 4 bytes, behind a 1-byte type + 8-byte timestamp header.
constexpr size_t WIRE_BYTES_PER_FRAME = 4;
constexpr size_t WIRE_CHUNK_PAYLOAD = 1200 * WIRE_BYTES_PER_FRAME;
constexpr size_t WIRE_HEADER = 9;

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

// ============================================================================
// Wire tests: a real client against an in-test loopback Sendspin "server"
// ============================================================================

std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.client_id = "source-test-client";
    config.name = "Source Test Client";
    config.server_port = port;
    // Fast time-sync cadence so a burst that goes unanswered (the time-gate test's first
    // phase) retries within the test budget instead of the production 10 s interval.
    config.time_burst_interval_ms = 200;
    config.time_burst_response_timeout_ms = 200;
    return config;
}

class TestNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return true;
    }
};

/// Pumps client.loop() until the predicate returns true or the timeout elapses.
bool pump_until(SendspinClient& client, const std::function<bool()>& pred, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        client.loop();
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

void pump_for(SendspinClient& client, int duration_ms) {
    pump_until(
        client, [] { return false; }, duration_ms);
}

/// A minimal Sendspin "server" for source streaming: an IXWebSocket client that connects to
/// the SendspinClient's WS server, answers client/hello with server/hello, optionally answers
/// client/time with a zero-offset server/time, records every received text and binary message
/// in arrival order, and can send server/command source start/stop.
class FakeSourceServer {
public:
    struct WireEvent {
        bool binary;
        std::string data;
    };

    FakeSourceServer(const std::string& url, std::string server_id, bool answer_time = true)
        : server_id_(std::move(server_id)), answer_time_(answer_time) {
        this->ws_.setUrl(url);
        this->ws_.disableAutomaticReconnection();
        this->ws_.setOnMessageCallback([this](const ix::WebSocketMessagePtr& msg) {
            if (msg->type != ix::WebSocketMessageType::Message) {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(this->mutex_);
                this->events_.push_back({msg->binary, msg->str});
            }
            if (msg->binary) {
                return;
            }
            if (msg->str.find("client/hello") != std::string::npos) {
                this->ws_.send(
                    std::string(R"({"type":"server/hello","payload":{"server_id":")") +
                    this->server_id_ +
                    R"(","name":"Fake Source Server","version":1,"active_roles":["source"],)" +
                    R"("connection_reason":"discovery"}})");
            } else if (msg->str.find("client/time") != std::string::npos &&
                       this->answer_time_.load()) {
                // Zero-offset echo: server clock == client clock, which the Kalman filter
                // accepts as its first measurement.
                JsonDocument doc;
                if (deserializeJson(doc, msg->str) == DeserializationError::Ok) {
                    const int64_t t = doc["payload"]["client_transmitted"] | int64_t{0};
                    this->ws_.send(std::string(R"({"type":"server/time","payload":)") +
                                   R"({"client_transmitted":)" + std::to_string(t) +
                                   R"(,"server_received":)" + std::to_string(t) +
                                   R"(,"server_transmitted":)" + std::to_string(t) + "}}");
                }
            }
        });
        this->ws_.start();
    }

    ~FakeSourceServer() {
        this->ws_.stop();
    }

    void enable_time_answers() {
        this->answer_time_.store(true);
    }

    void send_source_command(const char* command) {
        this->ws_.send(std::string(R"({"type":"server/command","payload":{"source":)") +
                       R"({"command":")" + command + R"("}}})");
    }

    void disconnect() {
        this->ws_.stop();
    }

    std::vector<WireEvent> snapshot() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->events_;
    }

    size_t count_text_containing(const std::string& needle) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        size_t count = 0;
        for (const auto& event : this->events_) {
            if (!event.binary && event.data.find(needle) != std::string::npos) {
                ++count;
            }
        }
        return count;
    }

    size_t binary_count() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        size_t count = 0;
        for (const auto& event : this->events_) {
            if (event.binary) {
                ++count;
            }
        }
        return count;
    }

private:
    ix::WebSocket ws_;
    std::string server_id_;
    std::atomic<bool> answer_time_;
    mutable std::mutex mutex_;
    std::vector<WireEvent> events_;
};

/// Everything a wire test needs running: a client with the source role added and started, plus
/// helpers to bring a fake server to the handshake-complete, time-synced state.
struct WireHarness {
    explicit WireHarness(uint16_t port, const SourceRoleConfig& role_config = SourceRoleConfig{})
        : client(make_config(port)) {
        auto& role = this->client.add_source(role_config);
        role.set_listener(&this->listener);
        this->client.set_network_provider(&this->network);
    }

    bool start() {
        if (!this->client.start_server()) {
            return false;
        }
        // The WS server starts synchronously on the first loop() once the network is ready.
        pump_for(this->client, 50);
        return true;
    }

    bool establish(FakeSourceServer& fake) {
        if (!pump_until(
                this->client, [&] { return this->client.is_connected(); }, 4000)) {
            return false;
        }
        (void)fake;
        return pump_until(
            this->client, [&] { return this->client.is_time_synced(); }, 4000);
    }

    TestNetworkProvider network;
    RecordingSourceListener listener;
    SendspinClient client;
};

// Deliberately independent of protocol_messages.h's be64_to_host(): the wire tests audit the
// bytes the library produced, so the reader must not share the code under audit.
int64_t read_be64(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

// The end-to-end pipeline and its exact wire ordering: client-stream/start, then binary chunks
// carrying [type 12][BE64 first-sample capture timestamp][PCM payload], then a final short
// chunk and client-stream/end on stop -- with write_audio() gated shut before the start
// command, validating frames while open, and gated shut again after the stop.
TEST(SourceWire, StreamsPcmEndToEndWithExactOrdering) {
    WireHarness harness(WIRE_TEST_PORT);
    ASSERT_TRUE(harness.start());
    FakeSourceServer fake(server_url(WIRE_TEST_PORT), "source-server-a");
    ASSERT_TRUE(harness.establish(fake));

    SourceRole* source = harness.client.source();
    ASSERT_NE(source, nullptr);

    // Gate: no streaming (and no accepted capture) before the server commands start.
    uint8_t frame[WIRE_BYTES_PER_FRAME] = {9, 9, 9, 9};
    EXPECT_FALSE(source->write_audio(frame, sizeof(frame), 0));
    EXPECT_FALSE(source->is_streaming());

    fake.send_source_command("start");
    ASSERT_TRUE(pump_until(
        harness.client,
        [&] {
            return harness.listener.started == 1 &&
                   fake.count_text_containing("client-stream/start") == 1;
        },
        4000));
    EXPECT_TRUE(source->is_streaming());

    // Validation while open: a non-whole-frame write is rejected as a whole.
    std::vector<uint8_t> odd(WIRE_BYTES_PER_FRAME * 10 + 1, 0xAA);
    EXPECT_FALSE(source->write_audio(odd.data(), odd.size(), 0));

    // Overflow: a write larger than the whole capture ring cannot be buffered -- rejected and
    // counted as a drop, never blocked on.
    std::vector<uint8_t> oversized(WIRE_BYTES_PER_FRAME * 48000, 0);  // 1 s >> 150 ms ring
    EXPECT_FALSE(source->write_audio(oversized.data(), oversized.size(), 0));

    // 50 ms of ramp PCM in 10 ms writes, capture-stamped 10 ms apart: exactly two full 25 ms
    // chunks.
    const int64_t base = platform_time_us();
    std::vector<uint8_t> chunk(WIRE_BYTES_PER_FRAME * 480);
    size_t ramp = 0;
    for (int i = 0; i < 5; ++i) {
        for (auto& byte : chunk) {
            byte = static_cast<uint8_t>(ramp++ & 0xFF);
        }
        ASSERT_TRUE(source->write_audio(chunk.data(), chunk.size(), base + i * 10000));
    }
    ASSERT_TRUE(pump_until(
        harness.client, [&] { return fake.binary_count() == 2; }, 4000));

    // A duplicate start while streaming MUST NOT restart the stream: no second
    // client-stream/start, no second listener callback.
    fake.send_source_command("start");
    pump_for(harness.client, 300);
    EXPECT_EQ(fake.count_text_containing("client-stream/start"), 1U);
    EXPECT_EQ(harness.listener.started, 1);

    // A 10 ms remainder: full chunks only mid-stream, so it must NOT be sent yet...
    for (auto& byte : chunk) {
        byte = static_cast<uint8_t>(ramp++ & 0xFF);
    }
    ASSERT_TRUE(source->write_audio(chunk.data(), chunk.size(), base + 50000));
    pump_for(harness.client, 200);
    EXPECT_EQ(fake.binary_count(), 2U);

    // ...until stream end, where the spec allows a final short chunk before client-stream/end.
    fake.send_source_command("stop");
    ASSERT_TRUE(pump_until(
        harness.client,
        [&] {
            return harness.listener.stopped == 1 &&
                   fake.count_text_containing("client-stream/end") == 1;
        },
        4000));
    EXPECT_FALSE(source->is_streaming());
    EXPECT_FALSE(source->write_audio(frame, sizeof(frame), 0));

    // Now audit the recorded wire order and framing.
    const auto events = fake.snapshot();
    ptrdiff_t start_idx = -1;
    ptrdiff_t end_idx = -1;
    std::vector<ptrdiff_t> binary_idx;
    for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(events.size()); ++i) {
        if (events[i].binary) {
            binary_idx.push_back(i);
        } else if (events[i].data.find("client-stream/start") != std::string::npos) {
            start_idx = i;
        } else if (events[i].data.find("client-stream/end") != std::string::npos) {
            end_idx = i;
        }
    }
    ASSERT_EQ(binary_idx.size(), 3U);  // two full chunks + the final short chunk
    ASSERT_GE(start_idx, 0);
    ASSERT_GE(end_idx, 0);
    EXPECT_LT(start_idx, binary_idx.front());
    EXPECT_LT(binary_idx.back(), end_idx);

    // Framing: type byte 12, big-endian first-sample capture timestamp (zero-offset time sync,
    // so the server-domain value stays near the stamps we supplied), untouched PCM payload.
    const auto& first = events[static_cast<size_t>(binary_idx[0])].data;
    ASSERT_EQ(first.size(), WIRE_HEADER + WIRE_CHUNK_PAYLOAD);
    EXPECT_EQ(static_cast<uint8_t>(first[0]), SENDSPIN_BINARY_SOURCE_AUDIO);
    const int64_t ts1 = read_be64(reinterpret_cast<const uint8_t*>(first.data()) + 1);
    EXPECT_LT(std::llabs(ts1 - base), 1000000);
    for (size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(static_cast<uint8_t>(first[WIRE_HEADER + i]), static_cast<uint8_t>(i & 0xFF));
    }

    // The second chunk's anchor is exactly one chunk after the first (contiguous capture
    // stamps); allow slack for the time filter refining its offset between the two sends.
    const auto& second = events[static_cast<size_t>(binary_idx[1])].data;
    ASSERT_EQ(second.size(), WIRE_HEADER + WIRE_CHUNK_PAYLOAD);
    const int64_t ts2 = read_be64(reinterpret_cast<const uint8_t*>(second.data()) + 1);
    EXPECT_NEAR(static_cast<double>(ts2 - ts1), 25000.0, 2000.0);

    // The final short chunk carries the 10 ms remainder.
    const auto& last = events[static_cast<size_t>(binary_idx[2])].data;
    EXPECT_EQ(last.size(), WIRE_HEADER + WIRE_BYTES_PER_FRAME * 480);
}

// The time-sync convergence gate: a start command on a connection whose time filter has no
// measurement yet must not open the stream; it opens (without a fresh command) once sync
// converges.
TEST(SourceWire, NoStreamBeforeTimeSyncConvergence) {
    WireHarness harness(TIME_GATE_TEST_PORT);
    ASSERT_TRUE(harness.start());
    FakeSourceServer fake(server_url(TIME_GATE_TEST_PORT), "source-server-t",
                          /*answer_time=*/false);
    ASSERT_TRUE(pump_until(
        harness.client, [&] { return harness.client.is_connected(); }, 4000));

    fake.send_source_command("start");
    pump_for(harness.client, 400);
    EXPECT_EQ(fake.count_text_containing("client-stream/start"), 0U);
    EXPECT_EQ(harness.listener.started, 0);

    fake.enable_time_answers();
    ASSERT_TRUE(pump_until(
        harness.client,
        [&] {
            return harness.client.is_time_synced() &&
                   fake.count_text_containing("client-stream/start") == 1 &&
                   harness.listener.started == 1;
        },
        4000));
}

// Streaming permission is per-connection: a disconnect closes the stream, and a new connection
// (fresh handshake, fresh time sync) must not stream until IT commands start.
TEST(SourceWire, PermissionDoesNotSurviveReconnect) {
    WireHarness harness(RECONNECT_TEST_PORT);
    ASSERT_TRUE(harness.start());

    {
        FakeSourceServer fake(server_url(RECONNECT_TEST_PORT), "source-server-r1");
        ASSERT_TRUE(harness.establish(fake));
        fake.send_source_command("start");
        ASSERT_TRUE(pump_until(
            harness.client, [&] { return harness.listener.started == 1; }, 4000));

        fake.disconnect();
        ASSERT_TRUE(pump_until(
            harness.client, [&] { return harness.listener.stopped == 1; }, 4000));
        EXPECT_FALSE(harness.client.source()->is_streaming());
    }

    FakeSourceServer fake2(server_url(RECONNECT_TEST_PORT), "source-server-r2");
    ASSERT_TRUE(harness.establish(fake2));

    // The old connection's permission must not leak into this one.
    pump_for(harness.client, 400);
    EXPECT_EQ(fake2.count_text_containing("client-stream/start"), 0U);
    EXPECT_EQ(harness.listener.started, 1);

    // Only this connection's own start command opens a stream.
    fake2.send_source_command("start");
    ASSERT_TRUE(pump_until(
        harness.client,
        [&] {
            return harness.listener.started == 2 &&
                   fake2.count_text_containing("client-stream/start") == 1;
        },
        4000));
}

}  // namespace
