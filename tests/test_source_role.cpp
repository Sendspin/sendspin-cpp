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

/// Tests for the source role (roles/source/v1.md): chunk bookkeeping and config validation, the
/// capture path and chunk assembly played on the test thread, the stream lifecycle on the
/// protocol task against an in-process stand-in connection over a live Noise session, and a few
/// wire scenarios end to end against FakeEncryptedServer on loopback.

#include "connection_manager.h"
#include "crypto/constants.h"
#include "lifecycle_test_fixtures.h"
#include "loopback_connection.h"
#include "outbound_ring.h"
#include "platform/crypto.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "protocol_task.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/source_role.h"
#include "source_role_impl.h"
#include "source_task.h"
#include "time_filter.h"

#include <gtest/gtest.h>

#include <ArduinoJson.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per wire test, above the ranges the other lifecycle suites use.
constexpr uint16_t STREAM_TEST_PORT = 19200;
constexpr uint16_t CLOCK_GATE_TEST_PORT = 19201;
constexpr uint16_t CLOCK_GATE_CONTROL_TEST_PORT = 19202;
constexpr uint16_t CLIENT_RESTART_TEST_PORT = 19203;

/// The default config's chunk: 20 ms of 48 kHz stereo 16-bit PCM.
constexpr int64_t CHUNK_MS = 20;
constexpr size_t CHUNK_BYTES = 48000 / 1000 * CHUNK_MS * 2 * 2;
/// One write_audio() call: 15 ms, so most chunks start partway into a write and are stamped from
/// its own first sample, not the write's.
constexpr int64_t WRITE_MS = 15;
constexpr size_t WRITE_BYTES = 48000 / 1000 * WRITE_MS * 2 * 2;

/// How far a server clock runs ahead of the client's, so a chunk stamp mapped onto the server
/// clock differs from one left on the client's.
constexpr int64_t SERVER_CLOCK_OFFSET_US = 10 * 1000 * 1000;

class RecordingSourceListener : public SourceRoleListener {
public:
    void on_streaming_started() override {
        ++this->starts;
    }
    void on_streaming_stopped() override {
        ++this->stops;
    }

    int starts{0};
    int stops{0};
};

/// Never reports the network ready, so a started client opens no listening socket.
class NotReadyNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return false;
    }
};

/// `len` bytes counting up from `first`, wrapping at 256.
std::vector<uint8_t> counting_bytes(size_t len, size_t first) {
    std::vector<uint8_t> bytes(len);
    for (size_t i = 0; i < len; ++i) {
        bytes[i] = static_cast<uint8_t>(first + i);
    }
    return bytes;
}

std::string source_command_json(const char* command) {
    return std::string(R"({"type":"server/command","payload":{"source":{"command":")") + command +
           "\"}}}";
}

std::string activate_json(const std::string& roles_json) {
    return R"({"type":"server/activate","payload":{"activities":["playback"],"active_roles":)" +
           roles_json + "}}";
}

/// A source role whose rings exist without its task thread, so the test thread plays the
/// capture thread, the source task (SourceTask::process()) and the protocol task's take.
struct CaptureRig {
    explicit CaptureRig(SourceRoleConfig config = {})
        : client(SendspinClientConfig{}),
          source(client.add_source(config)),
          task(*source.impl_->task) {
        this->task.capture_ring_ = std::make_unique<OutboundRing>();
        EXPECT_TRUE(this->task.capture_ring_->create(source_capture_ring_bytes(config),
                                                     MemoryLocation::PREFER_EXTERNAL));
        this->task.outbound_ring_ = std::make_unique<OutboundRing>();
        EXPECT_TRUE(this->task.outbound_ring_->create(
            derive_outbound_ring_bytes(this->task.chunk_message_bytes_, OUTBOUND_RING_ITEM_COUNT),
            MemoryLocation::PREFER_EXTERNAL));
        EXPECT_TRUE(this->task.event_flags_.create());
        this->task.protocol_task_ = this->client.protocol_task_.get();
    }

    /// Opens the gate on `generation`, as the protocol task does when a stream opens.
    void open(uint32_t generation) {
        this->source.impl_->stream_gate.store(SOURCE_GATE_OPEN | generation);
    }

    void close() {
        this->source.impl_->stream_gate.store(this->source.impl_->stream_gate.load() &
                                              ~SOURCE_GATE_OPEN);
    }

    /// Writes one WRITE_MS piece of counting bytes stamped `capture_us`.
    bool write(int64_t capture_us) {
        const std::vector<uint8_t> piece = counting_bytes(WRITE_BYTES, this->next_byte);
        this->next_byte += WRITE_BYTES;
        return this->source.write_audio(piece.data(), piece.size(), capture_us);
    }

    /// Runs the source task's steps until the capture ring is drained.
    void drain() {
        for (int i = 0; i < 64; ++i) {
            this->task.process(0);
        }
    }

    /// Takes every completed outbound item: its header and its payload.
    std::vector<std::pair<OutboundItemHeader, std::vector<uint8_t>>> take_chunks() {
        std::vector<std::pair<OutboundItemHeader, std::vector<uint8_t>>> chunks;
        size_t capacity = 0;
        while (void* item = this->task.outbound_ring_->take(&capacity, 0)) {
            const OutboundItemHeader header = outbound_item_header(item);
            const uint8_t* payload = outbound_item_message(item) + SOURCE_CHUNK_HEADER_SIZE;
            const size_t payload_len = header.data_len > SOURCE_CHUNK_HEADER_SIZE
                                           ? header.data_len - SOURCE_CHUNK_HEADER_SIZE
                                           : 0;
            chunks.emplace_back(header, std::vector<uint8_t>(payload, payload + payload_len));
            this->task.outbound_ring_->return_item(item);
        }
        return chunks;
    }

    SendspinClient client;
    SourceRole& source;
    SourceTask& task;
    size_t next_byte{0};
};

}  // namespace

// ============================================================================
// Bookkeeping and validation (pure functions)
// ============================================================================

// A chunk is stamped with its own first sample: one that starts partway into a capture item is
// later than the item's stamp by the frames already consumed (roles/source/v1.md "Source Audio
// Chunks (Binary)").
TEST(SourceBookkeeping, ChunkAnchorsOnItsOwnFirstSample) {
    constexpr size_t STEREO_16 = source_bytes_per_frame(2, 16);
    EXPECT_EQ(STEREO_16, 4U);
    EXPECT_EQ(source_bytes_per_frame(1, 24), 3U);
    EXPECT_EQ(source_ms_to_frames(20, 48000), 960U);
    EXPECT_EQ(source_ms_to_frames(5, 44100), 220U);  // 220.5 frames: only whole frames count
    EXPECT_EQ(source_frames_to_us(960, 48000), 20000);

    // Control: a chunk starting at the item's first byte keeps the item's stamp.
    EXPECT_EQ(source_entry_anchor_us(1000000, 0, STEREO_16, 48000), 1000000);
    // 480 frames (10 ms) into the item.
    EXPECT_EQ(source_entry_anchor_us(1000000, 480 * STEREO_16, STEREO_16, 48000), 1010000);
}

// One chunk, with its 9-byte header, must fit one Noise transport message: the send path
// encrypts it in place and never fragments it. A chunk holding no whole frame is unusable too.
TEST(SourceBookkeeping, ChunkBytesFitOneTransportMessage) {
    struct Row {
        const char* name;
        uint32_t sample_rate;
        uint8_t channels;
        uint8_t bit_depth;
        uint32_t chunk_ms;
        size_t expected;
    };
    const Row rows[] = {
        {"Control: the default 20 ms chunk", 48000, 2, 16, 20, CHUNK_BYTES},
        {"Control: 150 ms of 48 kHz stereo 32-bit fits", 48000, 2, 32, 150, 57600},
        {"150 ms of 48 kHz 8-channel 32-bit does not", 48000, 8, 32, 150, 0},
        {"5 ms at 100 Hz holds no whole frame", 100, 1, 16, 5, 0},
        {"zero channels", 48000, 0, 16, 20, 0},
        {"zero sample rate", 0, 2, 16, 20, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SourceRoleConfig config;
        config.sample_rate = row.sample_rate;
        config.channels = row.channels;
        config.bit_depth = row.bit_depth;
        config.chunk_duration_ms = row.chunk_ms;
        EXPECT_EQ(source_chunk_bytes(config), row.expected);
    }

    // At the bound: the largest fitting chunk is accepted, one frame more is not. 8 channels of
    // 24-bit is a 24-byte frame; 65510 / 24 = 2729 frames.
    SourceRoleConfig at_bound;
    at_bound.channels = 8;
    at_bound.bit_depth = 24;
    at_bound.chunk_duration_ms = 1000;
    at_bound.sample_rate = 2729;
    EXPECT_EQ(source_chunk_bytes(at_bound), 2729U * 24U);
    at_bound.sample_rate = 2730;
    EXPECT_EQ(source_chunk_bytes(at_bound), 0U);
}

// The capture ring's margin covers the per-write overhead down to 0.5 ms writes: the default ring
// takes nearly all of its 150 ms in 96-byte writes. A size too large to compute, or too small for
// a ring, is refused.
TEST(SourceBookkeeping, CaptureRingHoldsTheBufferWithItsMargin) {
    constexpr size_t HALF_MS_WRITE = 96;  // 24 frames of 48 kHz stereo 16-bit
    const SourceRoleConfig defaults;
    OutboundRing ring;
    ASSERT_TRUE(ring.create(source_capture_ring_bytes(defaults), MemoryLocation::PREFER_EXTERNAL));
    size_t writes = 0;
    while (void* item = ring.acquire(HALF_MS_WRITE, 0)) {
        ring.complete(item);
        ++writes;
    }
    EXPECT_GE(writes / 2, 140U) << "the margin did not cover the 0.5 ms writes' overhead";

    struct Row {
        const char* name;
        uint32_t capture_ms;
        uint32_t sample_rate;
        uint8_t channels;
    };
    const Row refused[] = {
        {"too small for a ring", 1, 8000, 1},
        {"too large to size", UINT32_MAX, 48000, 2},
    };
    for (const Row& row : refused) {
        SCOPED_TRACE(row.name);
        SourceRoleConfig config;
        config.capture_buffer_ms = row.capture_ms;
        config.sample_rate = row.sample_rate;
        config.channels = row.channels;
        EXPECT_EQ(source_capture_ring_bytes(config), 0U);
    }
}

// Every way a config can be unusable leaves the role inert; values are rejected, never repaired.
TEST(SourceConfigValidation, RejectsUnusableFormats) {
    struct Row {
        const char* name;
        void (*mutate)(SourceRoleConfig&);
        bool valid;
    };
    const Row rows[] = {
        {"Control: the defaults", [](SourceRoleConfig&) {}, true},
        {"Control: 24-bit mono at the 5 ms floor",
         [](SourceRoleConfig& c) {
             c.channels = 1;
             c.bit_depth = 24;
             c.chunk_duration_ms = SourceRoleConfig::CHUNK_MIN_MS;
         },
         true},
        {"zero sample rate", [](SourceRoleConfig& c) { c.sample_rate = 0; }, false},
        {"zero channels", [](SourceRoleConfig& c) { c.channels = 0; }, false},
        {"8-bit samples", [](SourceRoleConfig& c) { c.bit_depth = 8; }, false},
        {"chunk below 5 ms", [](SourceRoleConfig& c) { c.chunk_duration_ms = 4; }, false},
        {"chunk above 150 ms", [](SourceRoleConfig& c) { c.chunk_duration_ms = 151; }, false},
        {"chunk too large for one transport message",
         [](SourceRoleConfig& c) {
             c.channels = 8;
             c.bit_depth = 32;
             c.chunk_duration_ms = 150;
         },
         false},
        {"zero capture buffer", [](SourceRoleConfig& c) { c.capture_buffer_ms = 0; }, false},
        {"capture buffer too large to size",
         [](SourceRoleConfig& c) { c.capture_buffer_ms = UINT32_MAX; }, false},
        {"opus is not offered", [](SourceRoleConfig& c) { c.codec = SendspinCodecFormat::OPUS; },
         false},
        {"flac is not offered", [](SourceRoleConfig& c) { c.codec = SendspinCodecFormat::FLAC; },
         false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SourceRoleConfig config;
        row.mutate(config);
        EXPECT_EQ(SourceRole::Impl::validate_config(config), row.valid);
    }
}

// roles/source/v1.md "client/hello source@v1 support object" and "client/state source object":
// a usable role advertises itself with its line_sense hint, an unusable one not at all, and the
// state object carries a signal only for a role that senses one.
TEST(SourceRoleObjects, HelloAndStateFields) {
    SendspinClient client(SendspinClientConfig{});
    SourceRoleConfig config;
    config.line_sense = true;
    SourceRole& source = client.add_source(config);

    ClientHelloMessage hello;
    source.impl_->build_hello_fields(hello);
    ASSERT_EQ(hello.supported_roles, std::vector<SendspinRole>{SendspinRole::SOURCE});
    ASSERT_TRUE(hello.source_v1_support.has_value());
    EXPECT_TRUE(hello.source_v1_support->line_sense);

    ClientStateMessage state;
    source.impl_->build_state_fields(state);
    ASSERT_TRUE(state.source.has_value());
    EXPECT_FALSE(state.source->signal.has_value()) << "no signal reported yet";
    source.set_signal(SourceSignal::PRESENT);
    source.impl_->build_state_fields(state);
    EXPECT_EQ(state.source->signal, SourceSignal::PRESENT);

    // Without line_sense the object is present but never carries a signal.
    SendspinClient plain_client(SendspinClientConfig{});
    SourceRole& plain = plain_client.add_source(SourceRoleConfig{});
    plain.set_signal(SourceSignal::PRESENT);
    ClientStateMessage plain_state;
    plain.impl_->build_state_fields(plain_state);
    ASSERT_TRUE(plain_state.source.has_value());
    EXPECT_FALSE(plain_state.source->signal.has_value());

    // An unusable config is never advertised, and does not fail the client's start.
    SendspinClient bad_client(SendspinClientConfig{});
    SourceRoleConfig bad_config;
    bad_config.channels = 0;
    SourceRole& bad = bad_client.add_source(bad_config);
    ClientHelloMessage bad_hello;
    bad.impl_->build_hello_fields(bad_hello);
    EXPECT_TRUE(bad_hello.supported_roles.empty());
    EXPECT_FALSE(bad_hello.source_v1_support.has_value());
    EXPECT_TRUE(bad.impl_->start(nullptr));
    EXPECT_EQ(bad.impl_->task->outbound_ring(), nullptr) << "an unusable source started its task";
}

// ============================================================================
// Capture and chunk assembly (the test thread plays the capture thread and the source task)
// ============================================================================

// write_audio() takes whole frames into an open stream, stamped with the capture time given and
// the generation the gate names; it refuses a closed gate and a partial or empty write, and puts
// nothing in the capture ring when it refuses.
TEST(SourceCapture, WritesWholeFramesIntoAnOpenStream) {
    struct Row {
        const char* name;
        bool open;
        size_t len;
        bool accepted;
    };
    const Row rows[] = {
        {"Control: whole frames into an open stream", true, WRITE_BYTES, true},
        {"the gate is closed", false, WRITE_BYTES, false},
        {"a partial frame", true, 3, false},
        {"whole frames and a partial one", true, WRITE_BYTES + 2, false},
        {"an empty write", true, 0, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        CaptureRig rig;
        if (row.open) {
            rig.open(7);
        }
        const std::vector<uint8_t> piece = counting_bytes(std::max<size_t>(row.len, 1), 0);
        EXPECT_EQ(rig.source.write_audio(piece.data(), row.len, 123456), row.accepted);

        size_t capacity = 0;
        void* item = rig.task.capture_ring_->take(&capacity, 0);
        ASSERT_EQ(item != nullptr, row.accepted);
        if (item != nullptr) {
            const OutboundItemHeader header = outbound_item_header(item);
            EXPECT_EQ(header.capture_time_us, 123456);
            EXPECT_EQ(header.generation, 7U);
            EXPECT_EQ(header.data_len, row.len);
            EXPECT_EQ(std::memcmp(outbound_item_message(item), piece.data(), row.len), 0);
            rig.task.capture_ring_->return_item(item);
        }
    }
}

// A write with no capture time ends now, so its first frame, which chunks are stamped from, is
// one write's duration earlier.
TEST(SourceCapture, UnstampedWriteEndsNow) {
    CaptureRig rig;
    rig.open(1);
    const std::vector<uint8_t> piece(WRITE_BYTES, 0);
    const int64_t before_us = platform_time_us();
    ASSERT_TRUE(rig.source.write_audio(piece.data(), piece.size(), 0));
    const int64_t after_us = platform_time_us();

    size_t capacity = 0;
    void* item = rig.task.capture_ring_->take(&capacity, 0);
    ASSERT_NE(item, nullptr);
    const int64_t stamp = outbound_item_header(item).capture_time_us;
    EXPECT_GE(stamp, before_us - WRITE_MS * 1000);
    EXPECT_LE(stamp, after_us - WRITE_MS * 1000);
    rig.task.capture_ring_->return_item(item);
}

// The source task assembles chunks of exactly chunk_duration_ms across write boundaries: the
// payloads concatenate to the captured bytes, each chunk is stamped with its own first sample's
// capture time and its stream's generation, and the protocol task is left the type byte and the
// timestamp to write.
TEST(SourceChunks, ChunksSpanWritesAndAnchorOnTheirFirstSample) {
    CaptureRig rig;
    rig.open(3);
    constexpr int64_t FIRST_CAPTURE_US = 5000000;
    for (int64_t n = 0; n < 4; ++n) {  // 60 ms
        ASSERT_TRUE(rig.write(FIRST_CAPTURE_US + n * WRITE_MS * 1000));
    }
    rig.drain();

    const auto chunks = rig.take_chunks();
    ASSERT_EQ(chunks.size(), 3U);
    for (size_t n = 0; n < chunks.size(); ++n) {
        SCOPED_TRACE(n);
        const auto& [header, payload] = chunks[n];
        EXPECT_EQ(header.generation, 3U);
        EXPECT_EQ(header.data_len, SOURCE_CHUNK_HEADER_SIZE + CHUNK_BYTES);
        EXPECT_EQ(header.capture_time_us,
                  FIRST_CAPTURE_US + static_cast<int64_t>(n) * CHUNK_MS * 1000);
        EXPECT_EQ(payload, counting_bytes(CHUNK_BYTES, n * CHUNK_BYTES));
    }
}

// A chunk carries one stream's audio only. The audio of a stream that closed is never read, a
// chunk the stream changed under part-way is completed empty (the protocol task returns it
// unsent), and the partial chunk in progress when the task stops is completed empty too.
TEST(SourceChunks, AChunkNeverOutlivesItsStream) {
    struct Chunk {
        uint32_t generation;
        bool full;
    };
    struct Row {
        const char* name;
        std::function<void(CaptureRig&)> stage;
        std::vector<Chunk> expected;
    };
    const Row rows[] = {
        {"Control: one stream throughout",
         [](CaptureRig& rig) {
             rig.open(1);
             rig.write(0);
             rig.write(15000);
             rig.drain();
         },
         {{1, true}}},
        {"the stream changes part-way through a chunk",
         [](CaptureRig& rig) {
             rig.open(1);
             rig.write(0);
             rig.drain();
             rig.open(2);
             rig.write(100000);
             rig.write(115000);
             rig.drain();
         },
         {{0, false}, {2, true}}},
        {"a closed stream's audio waiting in the capture ring",
         [](CaptureRig& rig) {
             rig.open(1);
             rig.write(0);
             rig.write(15000);
             rig.close();
             rig.drain();
         },
         {}},
        {"the task stops with a chunk in progress",
         [](CaptureRig& rig) {
             rig.open(1);
             rig.write(0);
             rig.drain();
             rig.task.event_flags_.set(SourceTaskBits::SOURCE_COMMAND_STOP);
             rig.task.run();
         },
         {{0, false}}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        CaptureRig rig;
        row.stage(rig);
        const auto chunks = rig.take_chunks();
        ASSERT_EQ(chunks.size(), row.expected.size());
        for (size_t i = 0; i < chunks.size(); ++i) {
            SCOPED_TRACE(i);
            const OutboundItemHeader& header = chunks[i].first;
            if (row.expected[i].full) {
                EXPECT_EQ(header.generation, row.expected[i].generation);
                EXPECT_EQ(header.data_len, SOURCE_CHUNK_HEADER_SIZE + CHUNK_BYTES);
            } else {
                EXPECT_EQ(header.data_len, 0U) << "a chunk mixing streams was completed";
            }
        }
    }
}

// roles/source/v1.md "Source Audio Chunks (Binary)": after a stall the source resumes from live
// capture rather than burst stale audio. A full capture ring refuses the write and the task drops
// the backlog, and the chunk it has begun, as it takes its next capture item; an outbound ring with
// no room for a chunk drops the chunk and the backlog alike. Either way the next chunk with audio
// starts at the first write made after.
TEST(SourceChunks, AStallResumesFromLiveCapture) {
    enum class Stall : uint8_t { NONE, CAPTURE_FULL, CAPTURE_FULL_MID_CHUNK, OUTBOUND_FULL };
    struct Row {
        const char* name;
        Stall stall;
    };
    const Row rows[] = {
        {"Control: no stall", Stall::NONE},
        {"the capture ring overflows", Stall::CAPTURE_FULL},
        {"the capture ring overflows part-way through a chunk", Stall::CAPTURE_FULL_MID_CHUNK},
        {"the outbound ring has no room", Stall::OUTBOUND_FULL},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        CaptureRig rig;
        rig.open(1);
        std::vector<void*> held;
        if (row.stall == Stall::OUTBOUND_FULL) {
            // Every item completed and never taken, as behind a protocol task that cannot send
            OutboundRing& outbound = *rig.task.outbound_ring_;
            while (void* item = outbound.acquire(rig.task.chunk_message_bytes_, 0)) {
                rig.task.outbound_ring_->complete(item);
                held.push_back(item);
            }
        }
        // Backlog: a few writes, or as many as the capture ring holds
        constexpr int64_t BACKLOG_US = 1000000;
        int64_t stamp = BACKLOG_US;
        for (int i = 0; i < 3; ++i) {
            ASSERT_TRUE(rig.write(stamp));
            stamp += WRITE_MS * 1000;
        }
        if (row.stall == Stall::CAPTURE_FULL_MID_CHUNK) {
            rig.task.process(0);  // The first write begins a chunk it does not fill
            ASSERT_NE(rig.task.chunk_item_, nullptr);
        }
        if (row.stall == Stall::CAPTURE_FULL || row.stall == Stall::CAPTURE_FULL_MID_CHUNK) {
            while (rig.write(stamp)) {
                stamp += WRITE_MS * 1000;
            }
        }
        if (row.stall != Stall::NONE) {
            rig.task.process(0);  // The next capture item taken, at which the backlog goes
            size_t capacity = 0;
            EXPECT_EQ(rig.task.capture_ring_->take(&capacity, 0), nullptr)
                << "the backlog was kept";
            for (size_t i = 0; i < held.size(); ++i) {
                ASSERT_NE(rig.task.outbound_ring_->take(&capacity, 0), nullptr);
            }
            for (void* item : held) {
                rig.task.outbound_ring_->return_item(item);
            }
        }

        constexpr int64_t LIVE_US = 90000000;
        ASSERT_TRUE(rig.write(LIVE_US));
        ASSERT_TRUE(rig.write(LIVE_US + WRITE_MS * 1000));
        rig.drain();
        const auto chunks = rig.take_chunks();
        const auto first_audio = std::find_if(chunks.begin(), chunks.end(), [](const auto& chunk) {
            return chunk.first.data_len != 0;
        });
        ASSERT_NE(first_audio, chunks.end());
        EXPECT_EQ(first_audio->first.capture_time_us,
                  row.stall == Stall::NONE ? BACKLOG_US : LIVE_US);
    }
}

// ============================================================================
// Stream lifecycle on the protocol task (stand-in connection)
// ============================================================================

namespace {

/// A started client with a source, its protocol task stopped so the test thread plays it, and a
/// stand-in connection over a live Noise session installed as the admitted owner of source@v1.
/// The network never reports ready, so no socket is opened. What the stand-in sends is decrypted
/// on the initiator's side, in order, into wire(), each entry tagged with the step that sent it.
class SourceStandIn {
public:
    struct Peer {
        std::shared_ptr<FailingWriteConnection> conn;
        LoopbackResult loopback;
        size_t decrypted{0};
    };

    /// @param source_config The source's config; an invalid one leaves the role not running.
    /// @param add_after_start Adds the source only once the client has started, so it never runs.
    explicit SourceStandIn(bool synced = true, SourceRoleConfig source_config = {},
                           bool add_after_start = false) {
        SendspinClientConfig config;
        config.name = "Source Stand-in Client";
        this->client = std::make_unique<SendspinClient>(config);
        this->client->set_network_provider(&this->network);
        if (!add_after_start) {
            this->source = &this->client->add_source(source_config);
        }
        EXPECT_TRUE(this->client->start());
        this->client->protocol_task_->stop();
        if (add_after_start) {
            this->source = &this->client->add_source(source_config);
        }
        this->source->set_listener(&this->listener);
        this->client->connection_manager_->liveness_timeout_us_ = 0;
        this->connect(synced);
    }

    /// Runs the final tick stop() would have the protocol task run, unless the test stopped the
    /// client itself.
    ~SourceStandIn() {
        if (this->client->is_started()) {
            this->client->connection_manager_->close_admission();
            (void)this->client->protocol_tick();
            this->client->stop();
        }
    }

    SourceStandIn(const SourceStandIn&) = delete;
    SourceStandIn& operator=(const SourceStandIn&) = delete;

    /// Installs a fresh stand-in as the admitted owner of source@v1.
    void connect(bool synced) {
        auto loopback = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
        ASSERT_TRUE(loopback.has_value());
        auto conn = std::make_shared<FailingWriteConnection>();
        conn->set_json_arena(*this->client->json_arena_);
        conn->set_noise_session(std::move(loopback->responder_session));
        conn->set_noise_handshake_result("stand-in-server", PskCategory::LONG_TERM, "stand-in");
        conn->init_time_filter();
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->apply_server_activate({SendspinActivity::PLAYBACK},
                                    std::vector<std::string>{"source@v1"}, std::nullopt,
                                    std::nullopt);
        // No time burst falls due during a test, so no client/time interleaves.
        conn->time_burst().last_burst_complete_time_ = platform_time_us() / 1000;
        if (synced) {
            sync(*conn);
        }
        this->client->connection_manager_->install_admitted(conn,
                                                            role_mask_bit(SendspinRole::SOURCE));
        this->peers.push_back(Peer{conn, std::move(loopback.value())});
    }

    FailingWriteConnection& conn() {
        return *this->peers.back().conn;
    }

    /// One measurement: the server clock runs SERVER_CLOCK_OFFSET_US ahead.
    static void sync(SendspinConnection& conn) {
        conn.get_time_filter()->update(SERVER_CLOCK_OFFSET_US, 1000, platform_time_us());
    }

    /// A server message on the current stand-in, as the protocol task dispatches it.
    void deliver(const std::string& json) {
        this->client->json_arena_->reset();
        this->client->process_json_message(this->conn(), json.data(), json.size(),
                                           platform_time_us());
    }

    /// A protocol-task tick, then a main-loop drain.
    void tick() {
        (void)this->client->protocol_tick();
        this->client->loop();
    }

    /// Writes one full chunk of `generation` into the outbound ring as the source task completes
    /// it.
    void produce_chunk(uint32_t generation) {
        SourceTask& task = *this->source->impl_->task;
        void* item = task.outbound_ring()->acquire(task.chunk_message_bytes_, 0);
        ASSERT_NE(item, nullptr);
        const std::vector<uint8_t> payload = counting_bytes(CHUNK_BYTES, 0);
        std::memcpy(outbound_item_message(item) + SOURCE_CHUNK_HEADER_SIZE, payload.data(),
                    payload.size());
        set_outbound_item_header(
            item, OutboundItemHeader{.capture_time_us = platform_time_us(),
                                     .generation = generation,
                                     .data_len = static_cast<uint32_t>(SOURCE_CHUNK_HEADER_SIZE +
                                                                       CHUNK_BYTES)});
        task.outbound_ring()->complete(item);
    }

    /// The generation the gate names, open or not.
    uint32_t generation() const {
        return this->source->impl_->stream_gate.load() & SOURCE_GENERATION_MASK;
    }

    /// Decrypts what the stand-ins sent since the last call into the log, tagged `step`: a
    /// client/state as "state+" or "state-" by its availability, a source chunk as "chunk", the
    /// stream messages as "start" and "end", anything else by its type.
    void collect(int step) {
        for (Peer& peer : this->peers) {
            const auto& frames = peer.conn->sent_binary_;
            for (; peer.decrypted < frames.size(); ++peer.decrypted) {
                std::vector<uint8_t> plaintext =
                    raw_decrypt(peer.loopback.initiator.recv_cs, frames[peer.decrypted]);
                ASSERT_FALSE(plaintext.empty()) << "a frame did not authenticate";
                std::string name;
                if (plaintext[0] == SENDSPIN_BINARY_SOURCE_AUDIO) {
                    name = "chunk";
                    this->chunks.push_back(plaintext);
                } else if (plaintext[0] == MSG_TYPE_JSON_BODY) {
                    JsonDocument doc;
                    ASSERT_FALSE(deserializeJson(
                        doc, std::string(plaintext.begin() + 1, plaintext.end())));
                    const std::string type = doc["type"] | "";
                    if (type == "client/state") {
                        name = doc["payload"]["available"].as<bool>() ? "state+" : "state-";
                    } else if (type == "client-stream/start") {
                        name = "start";
                        std::string source_object;
                        serializeJson(doc["payload"]["source"], source_object);
                        this->stream_starts.push_back(source_object);
                    } else if (type == "client-stream/end") {
                        name = "end";
                    } else {
                        name = type;
                    }
                } else {
                    name = "binary";
                }
                this->wire.push_back(std::to_string(step) + " " + name);
            }
        }
    }

    /// How many chunk items the outbound ring can hand out now; OUTBOUND_RING_ITEM_COUNT once
    /// every chunk sent or returned is back. Leaves the ring as it was.
    size_t free_outbound_items() {
        SourceTask& task = *this->source->impl_->task;
        OutboundRing& ring = *task.outbound_ring();
        std::vector<void*> items;
        while (void* item = ring.acquire(task.chunk_message_bytes_, 0)) {
            ring.complete(item);
            items.push_back(item);
        }
        size_t capacity = 0;
        for (size_t i = 0; i < items.size(); ++i) {
            EXPECT_EQ(ring.take(&capacity, 0), items[i]);
        }
        for (void* item : items) {
            ring.return_item(item);
        }
        return items.size();
    }

    NotReadyNetworkProvider network;
    RecordingSourceListener listener;
    std::unique_ptr<SendspinClient> client;
    SourceRole* source{nullptr};
    std::vector<Peer> peers;
    std::vector<std::string> wire;
    std::vector<std::vector<uint8_t>> chunks;
    /// The source object of each client-stream/start, serialized.
    std::vector<std::string> stream_starts;
};

}  // namespace

// roles/source/v1.md "Source command semantics" and connection.md "Re-handshake", played step by
// step on the protocol task. Each step is followed by a protocol tick and a main-loop drain, and
// what the server receives is tagged with the step that sent it. A chunk is one the source task
// completed with the stream's generation (or the previous stream's). The listener's
// callbacks stay paired, and an open stream holds high-performance networking.
TEST(SourceStream, CommandsOpenAndCloseTheStream) {
    enum class Step : uint8_t {
        START,
        STOP,
        UNAVAILABLE,
        AVAILABLE,
        REMOVE_ROLE,
        RESTORE_ROLE,
        CHUNK,
        CHUNK_OF_PREVIOUS_STREAM,
        SYNC,
        QUIET_WINDOW,
        ACTIVATE,
        LOSE_CONNECTION,
    };
    using enum Step;
    struct Row {
        const char* name;
        bool synced;
        std::vector<Step> steps;
        std::vector<std::string> wire;
        int starts;
        int stops;
    };
    const Row rows[] = {
        {"Control: a start opens the stream", true, {START}, {"0 start"}, 1, 0},
        {"Control: a chunk of the open stream is sent", true, {START, CHUNK},
         {"0 start", "1 chunk"}, 1, 0},
        {"a start while open has no effect", true, {START, START}, {"0 start"}, 1, 0},
        {"a stop ends the stream, and a later chunk of it is not sent", true, {START, STOP, CHUNK},
         {"0 start", "1 end"}, 1, 1},
        {"a stop with nothing open is ignored", true, {STOP}, {}, 0, 0},
        {"a chunk of the previous stream is not sent on the next", true,
         {START, STOP, START, CHUNK_OF_PREVIOUS_STREAM}, {"0 start", "1 end", "2 start"}, 2, 1},
        {"a start while unavailable is ignored, and availability does not resume it", true,
         {UNAVAILABLE, START, AVAILABLE}, {"0 state-", "2 state+"}, 0, 0},
        {"becoming unavailable ends the stream before the state reports it", true,
         {START, UNAVAILABLE}, {"0 start", "1 end", "1 state-"}, 1, 1},
        {"removing the role ends the stream; restoring it needs a new start", true,
         {START, REMOVE_ROLE, RESTORE_ROLE}, {"0 start", "1 end", "1 state+", "2 state+"}, 1, 1},
        {"a lost connection ends the stream without a message", true,
         {START, LOSE_CONNECTION, CHUNK}, {"0 start"}, 1, 1},
        {"the next connection opens on its own start", true, {START, LOSE_CONNECTION, START},
         {"0 start", "2 start"}, 2, 1},
        {"a start before the time sync opens at the first measurement", false, {START, SYNC},
         {"1 start"}, 1, 0},
        {"an opening waits for a quiet window to end", true, {QUIET_WINDOW, START, ACTIVATE},
         {"2 state+", "2 start"}, 1, 0},
        {"a chunk inside a quiet window is dropped and the stream persists", true,
         {START, QUIET_WINDOW, CHUNK, ACTIVATE, CHUNK}, {"0 start", "3 state+", "4 chunk"}, 1, 0},
        {"a stop inside a quiet window owes its end to the activation, ahead of its state", true,
         {START, QUIET_WINDOW, STOP, ACTIVATE}, {"0 start", "3 end", "3 state+"}, 1, 1},
        {"a stop and a start inside a quiet window: the owed end precedes the new start", true,
         {START, QUIET_WINDOW, STOP, START, ACTIVATE},
         {"0 start", "4 end", "4 state+", "4 start"}, 2, 1},
        {"a stop cancels an opening still waiting for the time sync", false, {START, STOP, SYNC},
         {}, 0, 0},
        {"becoming unavailable cancels an opening still waiting for the time sync", false,
         {START, UNAVAILABLE, AVAILABLE, SYNC}, {"1 state-", "3 state+"}, 0, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SourceStandIn rig(row.synced);
        uint32_t previous_generation = 0;
        for (size_t i = 0; i < row.steps.size(); ++i) {
            switch (row.steps[i]) {
                case START:
                    previous_generation = rig.generation();
                    rig.deliver(source_command_json("start"));
                    break;
                case STOP:
                    rig.deliver(source_command_json("stop"));
                    break;
                case UNAVAILABLE:
                    rig.client->set_available(false);
                    break;
                case AVAILABLE:
                    rig.client->set_available(true);
                    break;
                case REMOVE_ROLE:
                    rig.deliver(activate_json("[]"));
                    break;
                case RESTORE_ROLE:
                case ACTIVATE:
                    rig.deliver(activate_json(R"(["source@v1"])"));
                    break;
                case CHUNK:
                    rig.produce_chunk(rig.generation());
                    break;
                case CHUNK_OF_PREVIOUS_STREAM:
                    rig.produce_chunk(previous_generation);
                    break;
                case SYNC:
                    SourceStandIn::sync(rig.conn());
                    break;
                case QUIET_WINDOW:
                    // What a re-handshake's Noise message 1 does (handle_noise_rehandshake())
                    rig.conn().first_activate_received_ = false;
                    break;
                case LOSE_CONNECTION:
                    rig.conn().detach_inbound();
                    rig.tick();
                    rig.connect(true);
                    break;
            }
            rig.tick();
            rig.collect(static_cast<int>(i));
        }
        EXPECT_EQ(rig.wire, row.wire);
        EXPECT_EQ(rig.listener.starts, row.starts);
        EXPECT_EQ(rig.listener.stops, row.stops);
        const bool streaming = row.starts > row.stops;
        EXPECT_EQ(rig.source->is_streaming(), streaming);
        EXPECT_EQ(rig.client->high_performance_ref_count_, streaming ? 1 : 0);
        EXPECT_EQ(rig.free_outbound_items(), OUTBOUND_RING_ITEM_COUNT)
            << "a chunk was not returned";
        for (const std::string& start : rig.stream_starts) {
            EXPECT_EQ(start, R"({"codec":"pcm","channels":2,"sample_rate":48000,"bit_depth":16})");
        }
    }
}

// A start reaches only a running role: one whose config was rejected, or one added after the
// client started, has no task to stream, so the start is ignored and capture is refused.
TEST(SourceStream, AStartOpensOnlyARunningRole) {
    struct Row {
        const char* name;
        SourceRoleConfig config;
        bool add_after_start;
        bool opens;
    };
    SourceRoleConfig rejected;
    rejected.chunk_duration_ms = 0;
    const Row rows[] = {
        {"Control: a valid role added before start", SourceRoleConfig{}, false, true},
        {"a rejected config", rejected, false, false},
        {"a role added after start", SourceRoleConfig{}, true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SourceStandIn rig(true, row.config, row.add_after_start);
        rig.deliver(source_command_json("start"));
        rig.tick();
        rig.collect(0);
        EXPECT_EQ(rig.wire, row.opens ? std::vector<std::string>{"0 start"}
                                      : std::vector<std::string>{});
        EXPECT_EQ(rig.source->is_streaming(), row.opens);
        const std::vector<uint8_t> pcm = counting_bytes(WRITE_BYTES, 0);
        EXPECT_EQ(rig.source->write_audio(pcm.data(), pcm.size(), 0), row.opens);
    }
}

// Captured audio reaches the server as a type 12 binary message: the server-clock time of its
// first sample, mapped through the stream connection's own filter, then the captured bytes
// untouched. The source task is the real one; the test thread plays the capture thread and the
// protocol task.
TEST(SourceStream, CaptureGoesOutStampedOnTheServerClock) {
    SourceStandIn rig;
    rig.deliver(source_command_json("start"));
    rig.tick();
    ASSERT_TRUE(rig.source->is_streaming());

    const int64_t capture_us = platform_time_us();
    const std::vector<uint8_t> pcm = counting_bytes(2 * WRITE_BYTES, 0);
    ASSERT_TRUE(rig.source->write_audio(pcm.data(), WRITE_BYTES, capture_us));
    ASSERT_TRUE(rig.source->write_audio(pcm.data() + WRITE_BYTES, WRITE_BYTES,
                                        capture_us + WRITE_MS * 1000));
    // No timeout: a chunk that never arrives hangs here and the suite watchdog names it.
    while (rig.chunks.empty()) {
        rig.tick();
        rig.collect(1);
        std::this_thread::yield();
    }

    const std::vector<uint8_t>& chunk = rig.chunks.front();
    ASSERT_EQ(chunk.size(), SOURCE_CHUNK_HEADER_SIZE + CHUNK_BYTES);
    EXPECT_EQ(chunk[0], SENDSPIN_BINARY_SOURCE_AUDIO);
    EXPECT_EQ(be64_to_host(chunk.data() + 1),
              rig.conn().get_time_filter()->compute_server_time(capture_us));
    EXPECT_GT(be64_to_host(chunk.data() + 1), capture_us + SERVER_CLOCK_OFFSET_US / 2)
        << "the stamp was left on the client clock";
    EXPECT_TRUE(std::equal(chunk.begin() + SOURCE_CHUNK_HEADER_SIZE, chunk.end(), pcm.begin()));
}

// A chunk send that fails after its encrypt closes the connection, which the tick's loss pass
// drops at once: the stream closes without a message, write_audio() refuses audio and the
// listener hears the stop. The Control row's send succeeds.
TEST(SourceStream, AFailedChunkSendDropsTheConnection) {
    for (const bool fails : {false, true}) {
        SCOPED_TRACE(fails ? "the send fails" : "Control: the send succeeds");
        SourceStandIn rig;
        rig.deliver(source_command_json("start"));
        rig.tick();
        auto conn = rig.peers.back().conn;
        if (fails) {
            conn->writes_before_refusal = 0;
        }
        rig.produce_chunk(rig.generation());
        rig.tick();

        EXPECT_EQ(rig.client->connection_manager_->find_admitted(conn.get()) == nullptr, fails);
        EXPECT_EQ(conn->close_transport_now_calls_, fails ? 1 : 0);
        EXPECT_EQ(rig.listener.stops, fails ? 1 : 0);
        EXPECT_EQ(rig.source->is_streaming(), !fails);
        EXPECT_EQ(rig.free_outbound_items(), OUTBOUND_RING_ITEM_COUNT)
            << "a chunk was not returned";
        // Last: audio the open stream accepts starts a chunk on the source task's thread, which
        // then holds an item
        const std::vector<uint8_t> piece(WRITE_BYTES, 0);
        EXPECT_EQ(rig.source->write_audio(piece.data(), piece.size(), 0), !fails);
    }
}

// SendspinClient::stop() with the stream open: the shutdown pass ends the stream ahead of the
// goodbye, and the drain inside stop() reports the stop and releases the stream's hold.
TEST(SourceStream, StopEndsAnOpenStreamAheadOfTheGoodbye) {
    SourceStandIn rig;
    rig.deliver(source_command_json("start"));
    rig.tick();
    rig.collect(0);
    ASSERT_EQ(rig.client->high_performance_ref_count_, 1);

    rig.client->connection_manager_->close_admission();
    (void)rig.client->protocol_tick();
    rig.collect(1);
    rig.client->stop();
    EXPECT_EQ(rig.wire, (std::vector<std::string>{"0 start", "1 end", "1 client/goodbye"}));
    EXPECT_EQ(rig.listener.stops, 1);
    EXPECT_FALSE(rig.source->is_streaming());
    EXPECT_EQ(rig.client->high_performance_ref_count_, 0);
    const std::vector<uint8_t> piece(WRITE_BYTES, 0);
    EXPECT_FALSE(rig.source->write_audio(piece.data(), piece.size(), 0)) << "accepted when stopped";
}

// ============================================================================
// Wire behavior (loopback)
// ============================================================================

namespace {

SendspinClientConfig make_wire_config(uint16_t port) {
    SendspinClientConfig config;
    config.name = "Source Test Client";
    config.server_port = port;
    config.time_burst_interval_ms = 100;  // Sync promptly after the connect
    return config;
}

FakeEncryptedServerOptions source_server_options() {
    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.server_clock_offset_us = SERVER_CLOCK_OFFSET_US;
    options.first_roles_json = R"(["source@v1"])";
    return options;
}

/// Messages of `type` in the server's log
size_t count_of(const FakeEncryptedServer& server, const std::string& type) {
    const auto messages = server.messages();
    return static_cast<size_t>(std::count_if(messages.begin(), messages.end(),
                                             [&type](const auto& m) { return m.type == type; }));
}

/// Writes capture in WRITE_MS pieces whose bytes count up from 0, stamped back to back from the
/// first write's time, keeping at most a few pieces ahead of the chunks the server received.
class CaptureFeeder {
public:
    explicit CaptureFeeder(SourceRole& source) : source_(source) {}

    /// Returns false once a write is refused.
    bool feed(size_t chunks_received) {
        constexpr int64_t LEAD_PIECES = 4;
        if (this->written_ms() >=
            static_cast<int64_t>(chunks_received) * CHUNK_MS + LEAD_PIECES * WRITE_MS) {
            return true;
        }
        const std::vector<uint8_t> piece = counting_bytes(WRITE_BYTES, this->next_byte_);
        this->next_byte_ += WRITE_BYTES;
        if (this->first_capture_us_ == 0) {
            this->first_capture_us_ = platform_time_us();
        }
        const int64_t capture_us = this->first_capture_us_ + this->written_ms() * 1000;
        ++this->pieces_written_;
        return this->source_.write_audio(piece.data(), piece.size(), capture_us);
    }

    int64_t first_capture_us() const {
        return this->first_capture_us_;
    }

private:
    int64_t written_ms() const {
        return static_cast<int64_t>(this->pieces_written_) * WRITE_MS;
    }

    SourceRole& source_;
    size_t pieces_written_{0};
    size_t next_byte_{0};
    int64_t first_capture_us_{0};
};

}  // namespace

// A server start opens the stream: chunks carry the captured bytes untouched behind their first
// sample's server-clock capture time, and a stop closes it with client-stream/end after the last
// chunk. Capture is refused outside the stream.
TEST(SourceWire, StreamsPcmBetweenStartAndEnd) {
    RecordingSourceListener listener;
    PairedClientBundle bundle(make_wire_config(STREAM_TEST_PORT));
    SendspinClient& client = bundle.client();
    SourceRole& source = client.add_source(SourceRoleConfig{});
    source.set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    auto server = connect_paired_server(bundle.peer, STREAM_TEST_PORT, source_server_options());
    pump_until(client, [&] {
        return client.is_time_synced() && count_of(*server, "client/state") > 0;
    });

    const std::vector<uint8_t> piece(WRITE_BYTES, 0);
    EXPECT_FALSE(source.write_audio(piece.data(), piece.size(), 0)) << "accepted before a start";

    ASSERT_TRUE(server->send_app_json(source_command_json("start")));
    pump_until(client, [&] { return listener.starts == 1; });

    constexpr size_t CHUNKS = 10;
    CaptureFeeder feeder(source);
    pump_until(client, [&] {
        const size_t received = count_of(*server, "binary");
        EXPECT_TRUE(feeder.feed(received));
        return received >= CHUNKS;
    });

    ASSERT_TRUE(server->send_app_json(source_command_json("stop")));
    pump_until(client, [&] {
        return listener.stops == 1 && count_of(*server, "client-stream/end") == 1;
    });
    EXPECT_FALSE(source.write_audio(piece.data(), piece.size(), 0)) << "accepted after the end";

    const auto messages = server->messages();
    std::optional<size_t> start_index;
    std::optional<size_t> end_index;
    std::vector<size_t> chunk_indices;
    for (size_t i = 0; i < messages.size(); ++i) {
        if (messages[i].type == "client-stream/start") {
            start_index = i;
        } else if (messages[i].type == "client-stream/end") {
            end_index = i;
        } else if (messages[i].type == "binary") {
            chunk_indices.push_back(i);
        }
    }
    ASSERT_TRUE(start_index.has_value());
    ASSERT_TRUE(end_index.has_value());
    ASSERT_GE(chunk_indices.size(), CHUNKS);
    EXPECT_LT(*start_index, chunk_indices.front()) << "a chunk preceded client-stream/start";
    EXPECT_GT(*end_index, chunk_indices.back()) << "a chunk followed client-stream/end";

    // Payloads concatenate to the captured bytes from the first; stamps are on the server clock,
    // SERVER_CLOCK_OFFSET_US ahead of capture.
    size_t expected_byte = 0;
    for (size_t n = 0; n < chunk_indices.size(); ++n) {
        SCOPED_TRACE(n);
        const auto& chunk = messages[chunk_indices[n]].body;
        ASSERT_EQ(chunk.size(), SOURCE_CHUNK_HEADER_SIZE + CHUNK_BYTES);
        EXPECT_EQ(chunk[0], SENDSPIN_BINARY_SOURCE_AUDIO);
        const int64_t capture_us =
            feeder.first_capture_us() + static_cast<int64_t>(n) * CHUNK_MS * 1000;
        EXPECT_GT(be64_to_host(chunk.data() + 1), capture_us + SERVER_CLOCK_OFFSET_US / 2)
            << "the stamp was left on the client clock";
        EXPECT_LT(be64_to_host(chunk.data() + 1), capture_us + SERVER_CLOCK_OFFSET_US * 3 / 2)
            << "the stamp overshot the server clock";
        for (size_t i = SOURCE_CHUNK_HEADER_SIZE; i < chunk.size(); ++i, ++expected_byte) {
            ASSERT_EQ(chunk[i], static_cast<uint8_t>(expected_byte)) << "byte " << i;
        }
    }

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "client/state": a source reports available: true only once its clock is
// synchronized, so with source@v1 active and the time filter still empty no client/state goes
// out. The control activates no role, so its state goes out without a clock.
TEST(SourceWire, ClientStateWaitsForTheClockWhileTheSourceIsActive) {
    struct Row {
        const char* name;
        uint16_t port;
        const char* roles;
        bool state_expected;
    };
    const Row rows[] = {
        {"Control: no clocked role active", CLOCK_GATE_CONTROL_TEST_PORT, "[]", true},
        {"source@v1 active", CLOCK_GATE_TEST_PORT, R"(["source@v1"])", false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        PairedClientBundle bundle(make_wire_config(row.port));
        SendspinClient& client = bundle.client();
        client.add_source(SourceRoleConfig{});
        ASSERT_TRUE(bundle.start());

        FakeEncryptedServerOptions options;  // answer_time off: the filter never gets a sample
        options.first_roles_json = row.roles;
        auto server = connect_paired_server(bundle.peer, row.port, std::move(options));
        pump_until(client, [&] { return client.is_connected() && server->got_client_time(); });
        if (row.state_expected) {
            pump_until(client, [&] { return server->client_state_count() > 0; });
        } else {
            EXPECT_TRUE(never_within([&] { return server->client_state_count() > 0; }, 300));
        }

        client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
        pump_for(client, 100);
    }
}

// SendspinClient::stop() joins the source task with the stream open; the restarted client
// streams again on its next connection once that connection's own start arrives. Destroying a
// client mid-stream joins the task too.
TEST(SourceWire, ClientStopAndDestroyWhileStreaming) {
    std::unique_ptr<FakeEncryptedServer> server;
    {
        RecordingSourceListener listener;
        PairedClientBundle bundle(make_wire_config(CLIENT_RESTART_TEST_PORT));
        SendspinClient& client = bundle.client();
        SourceRole& source = client.add_source(SourceRoleConfig{});
        source.set_listener(&listener);
        ASSERT_TRUE(bundle.start());

        for (int run = 1; run <= 2; ++run) {
            SCOPED_TRACE(run);
            if (run == 2) {
                client.stop();
                EXPECT_EQ(listener.stops, 1);
                EXPECT_FALSE(source.is_streaming());
                const std::vector<uint8_t> piece(WRITE_BYTES, 0);
                EXPECT_FALSE(source.write_audio(piece.data(), piece.size(), 0))
                    << "accepted while stopped";
                // The shutdown pass ended the stream ahead of the goodbye.
                wait_until([&] { return count_of(*server, "client-stream/end") == 1; });
                ASSERT_TRUE(bundle.start());
            }
            server = connect_paired_server(bundle.peer, CLIENT_RESTART_TEST_PORT,
                                           source_server_options());
            pump_until(client, [&] {
                return client.is_time_synced() && count_of(*server, "client/state") > 0;
            });
            ASSERT_TRUE(server->send_app_json(source_command_json("start")));
            pump_until(client, [&] { return listener.starts == run; });
            CaptureFeeder feeder(source);
            pump_until(client, [&] {
                const size_t received = count_of(*server, "binary");
                EXPECT_TRUE(feeder.feed(received));
                return received >= 3;
            });
        }
        // The bundle, and with it the client, goes out of scope with the stream still open.
    }
    ASSERT_NE(server, nullptr);
    wait_until([&] { return server->closed(); });
}
