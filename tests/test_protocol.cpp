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

// Unit tests for the wire-protocol parsing/formatting in protocol.cpp. This is the highest-value
// surface to test: lots of subtle branching (tri-state optional deltas, range validation,
// malformed-input handling) where a bug is silent rather than a crash, plus a hand-rolled int64
// formatter that we can check against snprintf as a free correctness oracle.

#include "protocol_messages.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <random>
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
// Enum <-> wire-string round-trips
// ============================================================================

TEST(Protocol, CodecRoundTrip) {
    EXPECT_EQ(codec_format_from_string("flac"), SendspinCodecFormat::FLAC);
    EXPECT_EQ(codec_format_from_string("opus"), SendspinCodecFormat::OPUS);
    EXPECT_EQ(codec_format_from_string("pcm"), SendspinCodecFormat::PCM);
    EXPECT_STREQ(to_cstr(SendspinCodecFormat::FLAC), "flac");
    EXPECT_FALSE(codec_format_from_string("mp3").has_value());  // unknown -> nullopt
}

// Every controller command must survive a to_cstr -> from_string round-trip. Catches typos in the
// wire strings that would otherwise silently drop a command.
TEST(Protocol, ControllerCommandRoundTrip) {
    const SendspinControllerCommand commands[] = {
        SendspinControllerCommand::PLAY,       SendspinControllerCommand::PAUSE,
        SendspinControllerCommand::STOP,       SendspinControllerCommand::NEXT,
        SendspinControllerCommand::PREVIOUS,   SendspinControllerCommand::VOLUME,
        SendspinControllerCommand::MUTE,       SendspinControllerCommand::REPEAT_OFF,
        SendspinControllerCommand::REPEAT_ONE, SendspinControllerCommand::REPEAT_ALL,
        SendspinControllerCommand::SHUFFLE,    SendspinControllerCommand::UNSHUFFLE,
        SendspinControllerCommand::SWITCH,
    };
    for (const auto cmd : commands) {
        const auto parsed = controller_command_from_string(to_cstr(cmd));
        ASSERT_TRUE(parsed.has_value()) << "no round-trip for " << to_cstr(cmd);
        EXPECT_EQ(parsed.value(), cmd);
    }
    EXPECT_FALSE(controller_command_from_string("not_a_command").has_value());
}

// ============================================================================
// Message-type dispatch
// ============================================================================

TEST(Protocol, DetermineMessageType) {
    JsonDocument doc;
    JsonObject root;

    ASSERT_TRUE(parse(R"({"type":"server/hello"})", doc, root));
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::SERVER_HELLO);

    ASSERT_TRUE(parse(R"({"type":"stream/clear"})", doc, root));
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::STREAM_CLEAR);

    ASSERT_TRUE(parse(R"({"type":"made/up"})", doc, root));
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::UNKNOWN);

    ASSERT_TRUE(parse(R"({})", doc, root));  // missing type field
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::UNKNOWN);
}

// ============================================================================
// server/time NTP-style offset computation
// ============================================================================

TEST(Protocol, ServerTimeOffsetAndError) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"payload":{"client_transmitted":1000,)"
                      R"("server_received":1500,"server_transmitted":1600}})",
                      doc, root));

    int64_t offset = 0;
    int64_t max_error = 0;
    const int64_t client_received = 2000;
    ASSERT_TRUE(process_server_time_message(root, client_received, &offset, &max_error));

    // offset = ((T2-T1) + (T3-T4)) / 2 = ((1500-1000) + (1600-2000)) / 2 = 50
    EXPECT_EQ(offset, 50);
    // max_error = ((T4-T1) - (T3-T2)) / 2 = ((2000-1000) - (1600-1500)) / 2 = 450
    EXPECT_EQ(max_error, 450);
}

TEST(Protocol, ServerTimeRejectsMissingFields) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"payload":{"client_transmitted":1000}})", doc, root));

    int64_t offset = 0;
    int64_t max_error = 0;
    EXPECT_FALSE(process_server_time_message(root, 2000, &offset, &max_error));
}

// ============================================================================
// Metadata tri-state delta parse + merge
//
// Each field is std::optional<std::optional<T>>:
//   absent on the wire  -> outer nullopt -> merge leaves the field alone
//   explicit JSON null   -> outer engaged, inner nullopt -> merge clears the field
//   value                -> outer + inner engaged -> merge overwrites
// ============================================================================

TEST(Protocol, MetadataValueUpdate) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"metadata":)"
                      R"({"timestamp":123,"title":"Song","artist":"Band"}}})",
                      doc, root));

    ServerStateMessage msg;
    ASSERT_TRUE(process_server_state_message(root, &msg));
    ASSERT_TRUE(msg.metadata.has_value());

    ServerMetadataStateObject current;
    apply_metadata_state_deltas(&current, msg.metadata.value());

    EXPECT_EQ(current.timestamp, 123);
    ASSERT_TRUE(current.title.has_value());
    EXPECT_EQ(current.title.value(), "Song");
    ASSERT_TRUE(current.artist.has_value());
    EXPECT_EQ(current.artist.value(), "Band");
}

TEST(Protocol, MetadataNullClearsAndAbsentPreserves) {
    // Start with both fields already populated.
    ServerMetadataStateObject current;
    current.title = "Song";
    current.artist = "Band";

    // Delta sets title to null (clear) and omits artist (preserve).
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"metadata":)"
                      R"({"timestamp":200,"title":null}}})",
                      doc, root));

    ServerStateMessage msg;
    ASSERT_TRUE(process_server_state_message(root, &msg));
    ASSERT_TRUE(msg.metadata.has_value());
    apply_metadata_state_deltas(&current, msg.metadata.value());

    EXPECT_FALSE(current.title.has_value());  // explicit null cleared it
    ASSERT_TRUE(current.artist.has_value());  // absent left it untouched
    EXPECT_EQ(current.artist.value(), "Band");
}

TEST(Protocol, MetadataMissingTimestampIsRejected) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(
        parse(R"({"type":"server/state","payload":{"metadata":{"title":"X"}}})", doc, root));

    ServerStateMessage msg;
    // The top-level call still succeeds, but the malformed metadata sub-object is dropped.
    ASSERT_TRUE(process_server_state_message(root, &msg));
    EXPECT_FALSE(msg.metadata.has_value());
}

// ============================================================================
// Color parsing: range validation + tri-state merge
// ============================================================================

TEST(Protocol, ColorRangeValidationAndMerge) {
    // Pre-populate accent and on_dark so we can observe "preserve" vs "clear".
    ServerColorStateObject current;
    current.accent = RgbColor{1, 2, 3};
    current.on_dark = RgbColor{9, 9, 9};

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"color":{"timestamp":7,)"
                      R"("primary":[10,20,30],"accent":[300,0,0],"on_dark":null}}})",
                      doc, root));

    ServerStateMessage msg;
    ASSERT_TRUE(process_server_state_message(root, &msg));
    ASSERT_TRUE(msg.color.has_value());
    apply_color_state_deltas(&current, msg.color.value());

    ASSERT_TRUE(current.primary.has_value());
    EXPECT_EQ(current.primary.value(), (RgbColor{10, 20, 30}));

    // accent had an out-of-range component (300) -> treated as absent -> preserved.
    ASSERT_TRUE(current.accent.has_value());
    EXPECT_EQ(current.accent.value(), (RgbColor{1, 2, 3}));

    // on_dark was explicit null -> cleared.
    EXPECT_FALSE(current.on_dark.has_value());
}

// ============================================================================
// format_client_time_message: hand-rolled int64 formatter checked against snprintf
// ============================================================================

// snprintf is the reference implementation; the hand-rolled formatter must match it byte-for-byte.
static std::string reference_time_message(int64_t v) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  R"({"type":"client/time","payload":{"client_transmitted":%lld}})",
                  static_cast<long long>(v));
    return std::string(buf);
}

TEST(Protocol, FormatTimeMessageMatchesSnprintf) {
    const int64_t edge_cases[] = {0,   1,     -1,     9,         10,        99,
                                  100, 12345, -12345, INT64_MAX, INT64_MIN, INT64_MIN + 1};
    char buf[TIME_MESSAGE_BUF_SIZE];
    for (const int64_t v : edge_cases) {
        const size_t n = format_client_time_message(buf, sizeof(buf), v);
        ASSERT_GT(n, 0u) << "v=" << v;
        EXPECT_EQ(std::string(buf, n), reference_time_message(v)) << "v=" << v;
    }
}

// Property/fuzz style: thousands of pseudo-random int64s, all checked against the oracle. Catches
// off-by-one digit-count bugs in the clz-based formatter that fixed cases might miss.
TEST(Protocol, FormatTimeMessageFuzzAgainstSnprintf) {
    std::mt19937_64 rng(0xC0FFEE);  // fixed seed -> deterministic, reproducible failures
    std::uniform_int_distribution<int64_t> dist(INT64_MIN, INT64_MAX);

    char buf[TIME_MESSAGE_BUF_SIZE];
    for (int i = 0; i < 20000; ++i) {
        const int64_t v = dist(rng);
        const size_t n = format_client_time_message(buf, sizeof(buf), v);
        ASSERT_GT(n, 0u) << "v=" << v;
        ASSERT_EQ(std::string(buf, n), reference_time_message(v)) << "v=" << v;
    }
}

TEST(Protocol, FormatTimeMessageRejectsTooSmallBuffer) {
    char buf[10];
    EXPECT_EQ(format_client_time_message(buf, sizeof(buf), 123), 0u);
}

// ============================================================================
// Outgoing message formatting (round-trip through the parser)
// ============================================================================

TEST(Protocol, FormatClientCommandVolume) {
    const std::string out = format_client_command_message(SendspinControllerCommand::VOLUME, 50);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["type"], "client/command");
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "volume");
    EXPECT_EQ(doc["payload"]["controller"]["volume"].as<int>(), 50);
    // The mute payload belongs to a different command and must not leak in.
    EXPECT_FALSE(doc["payload"]["controller"]["mute"].is<bool>());
}

// MUTE carries a boolean payload (a separate branch from VOLUME's uint8_t).
TEST(Protocol, FormatClientCommandMute) {
    const std::string out =
        format_client_command_message(SendspinControllerCommand::MUTE, std::nullopt, true);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "mute");
    ASSERT_TRUE(doc["payload"]["controller"]["mute"].is<bool>());
    EXPECT_TRUE(doc["payload"]["controller"]["mute"].as<bool>());
    EXPECT_FALSE(doc["payload"]["controller"]["volume"].is<int>());
}

// A no-argument command (PLAY) emits just the command, with neither payload field present.
TEST(Protocol, FormatClientCommandNoArgs) {
    const std::string out = format_client_command_message(SendspinControllerCommand::PLAY);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "play");
    EXPECT_FALSE(doc["payload"]["controller"]["volume"].is<int>());
    EXPECT_FALSE(doc["payload"]["controller"]["mute"].is<bool>());
}
