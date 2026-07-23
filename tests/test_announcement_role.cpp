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

#include "protocol_messages.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <string>

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
                        "codec_header":"aGVhZGVy","media_duck_db":20,"duck_ramp_ms":250,
                        "volume":60}}})",
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
    EXPECT_EQ(announcement.media_duck_db, 20);
    EXPECT_EQ(announcement.duck_ramp_ms, 250);
    ASSERT_TRUE(announcement.volume.has_value());
    EXPECT_EQ(announcement.volume.value(), 60);
}

// Duck/volume fields are optional with defined defaults, and both stream objects can coexist
TEST(AnnouncementRole, StreamStartDefaultsAndCoexistence) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "player":{"codec":"flac","sample_rate":48000,"channels":2,"bit_depth":16,
                  "codec_header":"Zmxh"},
        "announcement":{"codec":"pcm","sample_rate":16000,"channels":1,"bit_depth":16}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    ASSERT_TRUE(process_stream_start_message(root, &stream_msg));
    ASSERT_TRUE(stream_msg.player.has_value());
    ASSERT_TRUE(stream_msg.announcement.has_value());

    const ServerAnnouncementStreamObject& announcement = stream_msg.announcement.value();
    EXPECT_EQ(announcement.media_duck_db, 0);    // default: no ducking
    EXPECT_EQ(announcement.duck_ramp_ms, 100);   // default ramp
    EXPECT_FALSE(announcement.volume.has_value());  // default: follow master volume
}

// Out-of-range duck/volume values are dropped, leaving the defaults
TEST(AnnouncementRole, StreamStartRejectsOutOfRangeFields) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{
        "announcement":{"codec":"pcm","sample_rate":16000,"channels":1,"bit_depth":16,
                        "media_duck_db":51,"duck_ramp_ms":2001,"volume":101}}})",
                      doc, root));

    StreamStartMessage stream_msg;
    ASSERT_TRUE(process_stream_start_message(root, &stream_msg));
    ASSERT_TRUE(stream_msg.announcement.has_value());

    const ServerAnnouncementStreamObject& announcement = stream_msg.announcement.value();
    EXPECT_EQ(announcement.media_duck_db, 0);
    EXPECT_EQ(announcement.duck_ramp_ms, 100);
    EXPECT_FALSE(announcement.volume.has_value());
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
