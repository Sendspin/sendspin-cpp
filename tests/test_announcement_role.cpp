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

// Unit tests for the announcement role's wire-protocol surface: the announcement@v1 hello
// support object, the stream/start announcement object with its ducking/volume fields, the
// client/state announcement object, and the binary type allocation.

#include "announcement_role_impl.h"
#include "inbox.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

namespace {

// Parses a JSON string and returns the root object via the out-parameter, keeping the backing
// document alive in the caller. Returns false if the JSON is malformed.
bool parse(const std::string& json, JsonDocument& doc, JsonObject& root) {
    if (deserializeJson(doc, json)) {
        return false;
    }
    root = doc.as<JsonObject>();
    return true;
}

// Records the announcement lifecycle callbacks the role delivers to the embedder.
struct RecordingListener : AnnouncementRoleListener {
    size_t on_announcement_write(uint8_t* /*data*/, size_t /*length*/,
                                 uint32_t /*timeout_ms*/) override {
        return 0;
    }
    void on_announcement_start(const ServerAnnouncementStreamObject& params) override {
        ++start_count;
        last_params = params;
    }
    void on_announcement_end() override {
        ++end_count;
    }

    int start_count{0};
    int end_count{0};
    ServerAnnouncementStreamObject last_params{};
};

// Builds an announcement role Impl bound to a program-lifetime Inbox and a real, never-started
// SendspinClient. A default-constructed client never opens a connection, so publish_state() is a
// no-op (no current connection) and the task's time conversion reports "not synced" -- both of
// which these tests rely on. Client and Inbox are non-movable/have program lifetime via static
// deques (which never relocate existing elements), giving stable addresses that outlive the
// returned Impl, which only holds pointers to them.
std::unique_ptr<AnnouncementRole::Impl> make_announcement_impl() {
    static std::deque<SendspinClient> clients;
    static std::deque<Inbox> inboxes;

    AnnouncementRoleConfig config;
    config.audio_formats.push_back({SendspinCodecFormat::PCM, 1, 48000, 16});
    clients.emplace_back(SendspinClientConfig{});
    auto impl = std::make_unique<AnnouncementRole::Impl>(std::move(config), &clients.back());
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    return impl;
}

constexpr auto POSITIVE_TIMEOUT = std::chrono::milliseconds(2000);

// A PCM stream/start parameter object; the task builds a synthetic PCM header from it. PCM decode
// is a passthrough memcpy, so bytes fed via handle_binary() reach the listener unchanged.
ServerAnnouncementStreamObject make_pcm_stream_params() {
    ServerAnnouncementStreamObject params{};
    params.format.codec = SendspinCodecFormat::PCM;
    params.format.sample_rate = 48000;
    params.format.channels = 1;
    params.format.bit_depth = 16;
    params.start_timestamp = 0;
    return params;
}

// A 128-byte PCM chunk (64 frames of mono s16) filled with a per-chunk marker byte, so the
// concatenation the listener records can be compared byte-for-byte against what was fed.
std::vector<uint8_t> make_pcm_chunk(uint8_t marker) {
    return std::vector<uint8_t>(128, marker);
}

// Records the PCM the role writes to the sink and every lifecycle callback. on_announcement_write
// runs on the task thread; the drain/end callbacks run on the "main loop" (test) thread via
// pump_announcement(). A gate lets a test hold the task inside its first write so later chunks
// stay buffered in the ring when a stream/end arrives.
struct DrainRecordingListener : AnnouncementRoleListener {
    size_t on_announcement_write(uint8_t* data, size_t length, uint32_t /*timeout_ms*/) override {
        std::unique_lock<std::mutex> lock(this->mutex);
        if (this->gate_enabled && !this->gate_released) {
            this->first_write_reached = true;
            this->cv.notify_all();
            this->cv.wait(lock, [&] { return this->gate_released; });
        }
        this->written.insert(this->written.end(), data, data + length);
        this->cv.notify_all();
        return length;
    }
    void on_announcement_start(const ServerAnnouncementStreamObject& /*params*/) override {
        std::lock_guard<std::mutex> lock(this->mutex);
        ++this->start_count;
    }
    void on_announcement_end() override {
        std::lock_guard<std::mutex> lock(this->mutex);
        ++this->end_count;
        this->written_bytes_at_end = this->written.size();
    }

    bool wait_first_write(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(this->mutex);
        return this->cv.wait_for(lock, timeout, [&] { return this->first_write_reached; });
    }
    void release_gate() {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->gate_released = true;
        }
        this->cv.notify_all();
    }
    std::vector<uint8_t> written_snapshot() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->written;
    }
    int starts() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->start_count;
    }
    int ends() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->end_count;
    }
    size_t end_bytes() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->written_bytes_at_end;
    }

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<uint8_t> written;
    bool gate_enabled{false};
    bool gate_released{false};
    bool first_write_reached{false};
    int start_count{0};
    int end_count{0};
    size_t written_bytes_at_end{0};
};

// Mimics one SendspinClient::loop() tick for the announcement role: drains the shared event ring
// (the only path the announcement task's OUTPUT_STARTED/OUTPUT_FINISHED and the network-thread
// lifecycle events travel) into the role, then runs the main-thread event drain.
void pump_announcement(AnnouncementRole::Impl& impl) {
    if ((impl.inbox->poll() & INBOX_TOPIC_EVENTS) != 0U) {
        InboxEvent events[Inbox::EVENT_CAPACITY];
        const size_t count = impl.inbox->take_events(events, Inbox::EVENT_CAPACITY);
        for (size_t i = 0; i < count; ++i) {
            if (events[i].type == InboxEventType::ANNOUNCEMENT_STREAM) {
                impl.on_stream_ring_event(
                    static_cast<AnnouncementStreamCallbackType>(events[i].code));
            }
        }
    }
    impl.drain_events();
}

// Pumps the announcement role until `pred` holds or the timeout elapses.
template <typename Pred>
bool pump_until(AnnouncementRole::Impl& impl, Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        pump_announcement(impl);
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while (std::chrono::steady_clock::now() < deadline);
    return pred();
}

}  // namespace

// ============================================================================
// Role identity and binary allocation
// ============================================================================

TEST(AnnouncementRole, RoleWireString) {
    EXPECT_STREQ(to_cstr(SendspinRole::ANNOUNCEMENT), "announcement@v1");
}

// The announcement role occupies binary role 6 (type IDs 24-27), the block after the
// visualizer's expanded 16-23 range; the source role holds 12-15.
TEST(AnnouncementRole, BinaryTypeAllocation) {
    EXPECT_EQ(SENDSPIN_BINARY_ANNOUNCEMENT_AUDIO, 24);
    EXPECT_EQ(get_binary_role(SENDSPIN_BINARY_ANNOUNCEMENT_AUDIO), SENDSPIN_ROLE_ANNOUNCEMENT);
    EXPECT_EQ(get_binary_slot(SENDSPIN_BINARY_ANNOUNCEMENT_AUDIO), 0);
}

// ============================================================================
// client/hello announcement@v1_support serialization
// ============================================================================

TEST(AnnouncementRole, HelloSupportObjectSerialization) {
    ClientHelloMessage msg;
    msg.client_id = "test-client";
    msg.name = "Test Client";
    msg.version = 1;
    msg.supported_roles.push_back(SendspinRole::PLAYER);
    msg.supported_roles.push_back(SendspinRole::ANNOUNCEMENT);

    AnnouncementSupportObject support;
    support.supported_formats.push_back({SendspinCodecFormat::PCM, 1, 48000, 16});
    support.supported_formats.push_back({SendspinCodecFormat::OPUS, 1, 48000, 16});
    support.buffer_capacity = 65536;
    msg.announcement_v1_support = support;

    const std::string json = format_client_hello_message(&msg);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));

    // The role id is listed and the support object is keyed by the versioned alias
    bool found_role = false;
    for (JsonVariantConst role : root["payload"]["supported_roles"].as<JsonArrayConst>()) {
        if (role.as<std::string>() == "announcement@v1") {
            found_role = true;
        }
    }
    EXPECT_TRUE(found_role);

    JsonObjectConst support_json = root["payload"]["announcement@v1_support"];
    ASSERT_FALSE(support_json.isNull());
    EXPECT_EQ(support_json["buffer_capacity"].as<size_t>(), 65536U);
    JsonArrayConst formats = support_json["supported_formats"];
    ASSERT_EQ(formats.size(), 2U);
    EXPECT_STREQ(formats[0]["codec"].as<const char*>(), "pcm");
    EXPECT_EQ(formats[0]["channels"].as<int>(), 1);
    EXPECT_EQ(formats[0]["sample_rate"].as<int>(), 48000);
    EXPECT_EQ(formats[0]["bit_depth"].as<int>(), 16);
    EXPECT_STREQ(formats[1]["codec"].as<const char*>(), "opus");

    // No supported_commands field exists for the announcement role
    EXPECT_TRUE(support_json["supported_commands"].isNull());
}

// A hello without announcement support must not emit the key at all
TEST(AnnouncementRole, HelloWithoutSupportOmitsKey) {
    ClientHelloMessage msg;
    msg.client_id = "test-client";
    msg.name = "Test Client";
    msg.version = 1;

    const std::string json = format_client_hello_message(&msg);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));
    EXPECT_TRUE(root["payload"]["announcement@v1_support"].isNull());
}

// ============================================================================
// stream/start announcement object parsing
// ============================================================================

TEST(AnnouncementRole, StreamStartParsesAnnouncementObject) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "server_transmitted":123,
        "announcement":{"codec":"opus","sample_rate":48000,"channels":1,"bit_depth":16,
                        "codec_header":"aGVhZGVy","start_timestamp":1700000000000000,
                        "media_duck_db":200,"duck_ramp_ms":250,"volume":60}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    ASSERT_TRUE(process_stream_start_message(root, &stream_msg));
    ASSERT_TRUE(stream_msg.announcement.has_value());
    EXPECT_FALSE(stream_msg.player.has_value());

    const ServerAnnouncementStreamObject& announcement = stream_msg.announcement.value();
    EXPECT_TRUE(announcement.is_complete());
    EXPECT_EQ(announcement.format.codec.value(), SendspinCodecFormat::OPUS);
    EXPECT_EQ(announcement.format.sample_rate.value(), 48000U);
    EXPECT_EQ(announcement.format.channels.value(), 1);
    EXPECT_EQ(announcement.format.bit_depth.value(), 16);
    EXPECT_EQ(announcement.format.codec_header.value(), "aGVhZGVy");
    EXPECT_EQ(announcement.start_timestamp, 1700000000000000LL);
    // media_duck_db is uncapped: a large value that silences the media round-trips unchanged
    EXPECT_EQ(announcement.media_duck_db, 200);
    EXPECT_EQ(announcement.duck_ramp_ms, 250);
    ASSERT_TRUE(announcement.volume.has_value());
    EXPECT_EQ(announcement.volume.value(), 60);
}

// Optional fields carry defined defaults, and both stream objects can coexist. volume defaults to
// unset when absent.
TEST(AnnouncementRole, StreamStartDefaultsAndCoexistence) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "player":{"codec":"flac","sample_rate":48000,"channels":2,"bit_depth":16,
                  "codec_header":"Zmxh"},
        "announcement":{"codec":"pcm","sample_rate":16000,"channels":1,"bit_depth":16,
                        "start_timestamp":42}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    ASSERT_TRUE(process_stream_start_message(root, &stream_msg));
    ASSERT_TRUE(stream_msg.player.has_value());
    ASSERT_TRUE(stream_msg.announcement.has_value());

    const ServerAnnouncementStreamObject& announcement = stream_msg.announcement.value();
    EXPECT_EQ(announcement.start_timestamp, 42);
    EXPECT_EQ(announcement.media_duck_db, 0);       // default: no ducking
    EXPECT_EQ(announcement.duck_ramp_ms, 100);      // default ramp
    EXPECT_FALSE(announcement.volume.has_value());  // default: follow master volume
}

// Out-of-range ramp and volume values are dropped, leaving defaults. media_duck_db has no upper
// bound, so a large value is kept.
TEST(AnnouncementRole, StreamStartRejectsOutOfRangeFields) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "announcement":{"codec":"pcm","sample_rate":16000,"channels":1,"bit_depth":16,
                        "start_timestamp":42,"media_duck_db":200,"duck_ramp_ms":2001,
                        "volume":101}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    ASSERT_TRUE(process_stream_start_message(root, &stream_msg));
    ASSERT_TRUE(stream_msg.announcement.has_value());

    const ServerAnnouncementStreamObject& announcement = stream_msg.announcement.value();
    EXPECT_EQ(announcement.media_duck_db, 200);
    EXPECT_EQ(announcement.duck_ramp_ms, 100);
    EXPECT_FALSE(announcement.volume.has_value());
}

// start_timestamp is required: an otherwise-complete announcement object without it fails the
// whole stream/start parse.
TEST(AnnouncementRole, StreamStartRequiresStartTimestamp) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "announcement":{"codec":"pcm","sample_rate":16000,"channels":1,"bit_depth":16}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    EXPECT_FALSE(process_stream_start_message(root, &stream_msg));
}

// An announcement object missing required codec fields fails the whole stream/start parse,
// matching the player object's strictness
TEST(AnnouncementRole, StreamStartRejectsIncompleteAnnouncement) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "announcement":{"codec":"pcm","sample_rate":16000}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    EXPECT_FALSE(process_stream_start_message(root, &stream_msg));
}

// ============================================================================
// Re-sent stream/start config update (main-thread event drain)
// ============================================================================

// A stream/start arriving while an announcement is active is a config update: the role adopts
// the new duck/volume params and re-invokes on_announcement_start, without ending the stream or
// flipping the playing state.
TEST(AnnouncementRole, ResentStreamStartUpdatesConfigInPlace) {
    auto impl = make_announcement_impl();
    RecordingListener listener;
    impl->listener = &listener;

    // Simulate an already-playing announcement stream.
    impl->stream_active = true;
    impl->announcement_playing = true;

    ServerAnnouncementStreamObject updated{};
    updated.format.codec = SendspinCodecFormat::PCM;
    updated.format.sample_rate = 48000;
    updated.format.channels = 1;
    updated.format.bit_depth = 16;
    updated.start_timestamp = 99;
    updated.media_duck_db = 30;
    updated.volume = 80;
    impl->event_state->stream_params_slot.write(updated);
    impl->on_stream_ring_event(AnnouncementStreamCallbackType::CONFIG_UPDATE);

    impl->drain_events();

    // The embedder is re-notified with the new policy; no end, no restart, no state change.
    EXPECT_EQ(listener.start_count, 1);
    EXPECT_EQ(listener.end_count, 0);
    EXPECT_EQ(listener.last_params.media_duck_db, 30);
    ASSERT_TRUE(listener.last_params.volume.has_value());
    EXPECT_EQ(listener.last_params.volume.value(), 80);
    EXPECT_TRUE(impl->announcement_playing);
    EXPECT_EQ(impl->current_stream_params.media_duck_db, 30);
}

// ============================================================================
// stream/end termination: graceful drain vs. non-graceful discard
// ============================================================================

// A graceful server stream/end must play out any buffered announcement audio before ending: the
// buffered tail is written to the sink, and only then does on_announcement_end() fire (releasing
// the ducking) and the role report idle. The listener gate holds the task inside its first write
// so several chunks are still buffered in the ring when the stream/end arrives.
TEST(AnnouncementRole, StreamEndDrainsBufferedAudioBeforeRelease) {
    auto impl = make_announcement_impl();
    DrainRecordingListener listener;
    listener.gate_enabled = true;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());

    impl->handle_stream_start(make_pcm_stream_params());
    // Fire on_announcement_start (duck applied) and ack the start so the task begins playback.
    ASSERT_TRUE(pump_until(*impl, [&] { return listener.starts() >= 1; }, POSITIVE_TIMEOUT));

    // Feed several chunks; the first blocks in the sink, leaving the rest buffered in the ring.
    std::vector<uint8_t> expected;
    constexpr uint8_t NUM_CHUNKS = 5;
    for (uint8_t i = 0; i < NUM_CHUNKS; ++i) {
        std::vector<uint8_t> chunk = make_pcm_chunk(static_cast<uint8_t>('A' + i));
        expected.insert(expected.end(), chunk.begin(), chunk.end());
        impl->handle_binary(chunk.data(), chunk.size());
    }
    ASSERT_TRUE(listener.wait_first_write(POSITIVE_TIMEOUT));

    // Graceful stream/end arrives while chunks are still buffered, then the sink unblocks.
    impl->handle_stream_end();
    listener.release_gate();

    ASSERT_TRUE(pump_until(*impl, [&] { return listener.ends() >= 1; }, POSITIVE_TIMEOUT));

    // Every fed byte was played out in order (nothing discarded), and the duck released only
    // after the full tail had been written.
    EXPECT_EQ(listener.written_snapshot(), expected);
    EXPECT_EQ(listener.ends(), 1);
    EXPECT_EQ(listener.end_bytes(), expected.size());
    EXPECT_FALSE(impl->announcement_playing);
}

// A non-graceful end (connection teardown via cleanup(), i.e. transport loss) must discard the
// buffered tail and release the ducking immediately -- the opposite of the graceful drain above.
TEST(AnnouncementRole, TransportLossDiscardsBufferedAudio) {
    auto impl = make_announcement_impl();
    DrainRecordingListener listener;
    listener.gate_enabled = true;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());

    impl->handle_stream_start(make_pcm_stream_params());
    ASSERT_TRUE(pump_until(*impl, [&] { return listener.starts() >= 1; }, POSITIVE_TIMEOUT));

    constexpr uint8_t NUM_CHUNKS = 5;
    constexpr size_t CHUNK_BYTES = 128;
    for (uint8_t i = 0; i < NUM_CHUNKS; ++i) {
        std::vector<uint8_t> chunk = make_pcm_chunk(static_cast<uint8_t>('A' + i));
        impl->handle_binary(chunk.data(), chunk.size());
    }
    ASSERT_TRUE(listener.wait_first_write(POSITIVE_TIMEOUT));

    // Transport loss: discard whatever is buffered and end now.
    impl->cleanup();
    listener.release_gate();

    ASSERT_TRUE(pump_until(*impl, [&] { return listener.ends() >= 1; }, POSITIVE_TIMEOUT));

    // The buffered tail was dropped rather than played out: at most the chunk already in flight
    // reached the sink, never the whole stream. The duck released immediately (via the STREAM_END
    // event), not after a drain.
    EXPECT_LT(listener.written_snapshot().size(), NUM_CHUNKS * CHUNK_BYTES);
    EXPECT_LE(listener.written_snapshot().size(), CHUNK_BYTES);
    EXPECT_EQ(listener.ends(), 1);
    EXPECT_FALSE(impl->announcement_playing);
}

// ============================================================================
// client/state announcement object serialization
// ============================================================================

TEST(AnnouncementRole, ClientStateSerializesAnnouncementObject) {
    ClientStateMessage msg;
    msg.state = SendspinClientState::SYNCHRONIZED;

    ClientAnnouncementStateObject announcement_state;
    announcement_state.playing = true;
    announcement_state.required_lead_time_ms = 500;
    msg.announcement = announcement_state;

    const std::string json = format_client_state_message(&msg);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));
    EXPECT_STREQ(root["payload"]["announcement"]["state"].as<const char*>(), "playing");
    EXPECT_EQ(root["payload"]["announcement"]["required_lead_time_ms"].as<int>(), 500);

    // And the idle transition
    msg.announcement->playing = false;
    msg.announcement->required_lead_time_ms.reset();
    const std::string idle_json = format_client_state_message(&msg);
    ASSERT_TRUE(parse(idle_json, doc, root));
    EXPECT_STREQ(root["payload"]["announcement"]["state"].as<const char*>(), "idle");
    EXPECT_TRUE(root["payload"]["announcement"]["required_lead_time_ms"].isNull());
}

// An all-empty announcement state emits no announcement key at all
TEST(AnnouncementRole, ClientStateOmitsEmptyAnnouncementObject) {
    ClientStateMessage msg;
    msg.state = SendspinClientState::SYNCHRONIZED;
    msg.announcement = ClientAnnouncementStateObject{};

    const std::string json = format_client_state_message(&msg);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(json, doc, root));
    EXPECT_TRUE(root["payload"]["announcement"].isNull());
}
