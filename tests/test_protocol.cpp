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

#include "platform/base64.h"
#include "protocol_messages.h"
#include "sendspin/color_role.h"
#include "sendspin/config.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/types.h"
#include "sendspin/visualizer_role.h"
#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

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
        SendspinControllerCommand::SWITCH,     SendspinControllerCommand::SEEK,
        SendspinControllerCommand::SEEK_RELATIVE,
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

    ServerMetadataStateDelta delta;
    ASSERT_TRUE(process_server_state_metadata(root, &delta));

    ServerMetadataStateObject current;
    apply_metadata_state_deltas(&current, delta);

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

    ServerMetadataStateDelta delta;
    ASSERT_TRUE(process_server_state_metadata(root, &delta));
    apply_metadata_state_deltas(&current, delta);

    EXPECT_FALSE(current.title.has_value());  // explicit null cleared it
    ASSERT_TRUE(current.artist.has_value());  // absent left it untouched
    EXPECT_EQ(current.artist.value(), "Band");
}

TEST(Protocol, MetadataMissingTimestampIsRejected) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(
        parse(R"({"type":"server/state","payload":{"metadata":{"title":"X"}}})", doc, root));

    // The malformed metadata section is reported as absent rather than partially applied.
    ServerMetadataStateDelta delta;
    EXPECT_FALSE(process_server_state_metadata(root, &delta));
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

    ServerColorStateDelta delta;
    ASSERT_TRUE(process_server_state_color(root, &delta));
    apply_color_state_deltas(&current, delta);

    ASSERT_TRUE(current.primary.has_value());
    EXPECT_EQ(current.primary.value(), (RgbColor{10, 20, 30}));

    // accent had an out-of-range component (300) -> treated as absent -> preserved.
    ASSERT_TRUE(current.accent.has_value());
    EXPECT_EQ(current.accent.value(), (RgbColor{1, 2, 3}));

    // on_dark was explicit null -> cleared.
    EXPECT_FALSE(current.on_dark.has_value());
}

// ============================================================================
// Scalar field validation: strict types, range bounds, warn-and-drop
// ============================================================================

namespace {

// Wraps a player command object in a server/command envelope, parses it, and returns the parsed
// player command (nullopt if the envelope or command failed to parse). The command object's fields
// are std::optional, so has_value() cleanly distinguishes an applied field from a dropped one.
std::optional<ServerPlayerCommandObject> parse_player_command(const std::string& player_json) {
    const std::string json =
        R"({"type":"server/command","payload":{"player":)" + player_json + "}}";
    JsonDocument doc;
    JsonObject root;
    if (!parse(json, doc, root)) {
        return std::nullopt;
    }
    ServerCommandMessage msg;
    if (!process_server_command_message(root, &msg)) {
        return std::nullopt;
    }
    return msg.player;
}

}  // namespace

// Volume is validated against the protocol range [0, 100]. A valid value is applied; a value that is
// in-type but out-of-range, or out-of-type entirely, is dropped (warn-and-drop) rather than silently
// wrapped into the narrow field.
TEST(Protocol, PlayerCommandVolumeRangeValidation) {
    auto valid = parse_player_command(R"({"command":"volume","volume":50})");
    ASSERT_TRUE(valid.has_value());
    ASSERT_TRUE(valid->volume.has_value());
    EXPECT_EQ(valid->volume.value(), 50);

    // 150 fits uint8 but exceeds the protocol maximum of 100 -> dropped.
    auto over_max = parse_player_command(R"({"command":"volume","volume":150})");
    ASSERT_TRUE(over_max.has_value());
    EXPECT_FALSE(over_max->volume.has_value());

    // 300 does not fit uint8 at all -> dropped (a truncating cast would have wrapped it to 44).
    auto over_type = parse_player_command(R"({"command":"volume","volume":300})");
    ASSERT_TRUE(over_type.has_value());
    EXPECT_FALSE(over_type->volume.has_value());
}

// Booleans are strict: only genuine JSON true/false is accepted; a 0/1 integer is dropped.
TEST(Protocol, PlayerCommandBooleanStrictness) {
    auto real_bool = parse_player_command(R"({"command":"mute","mute":true})");
    ASSERT_TRUE(real_bool.has_value());
    ASSERT_TRUE(real_bool->mute.has_value());
    EXPECT_TRUE(real_bool->mute.value());

    auto int_bool = parse_player_command(R"({"command":"mute","mute":1})");
    ASSERT_TRUE(int_bool.has_value());
    EXPECT_FALSE(int_bool->mute.has_value());  // integer 1 is not a JSON boolean -> dropped
}

// Integer fields reject a float representation, even one with an integral value.
TEST(Protocol, PlayerCommandRejectsFloatForInteger) {
    auto valid = parse_player_command(R"({"command":"set_static_delay","static_delay_ms":250})");
    ASSERT_TRUE(valid.has_value());
    ASSERT_TRUE(valid->static_delay_ms.has_value());
    EXPECT_EQ(valid->static_delay_ms.value(), 250);

    auto fractional = parse_player_command(R"({"command":"set_static_delay","static_delay_ms":12.5})");
    ASSERT_TRUE(fractional.has_value());
    EXPECT_FALSE(fractional->static_delay_ms.has_value());

    auto integral_float =
        parse_player_command(R"({"command":"set_static_delay","static_delay_ms":12.0})");
    ASSERT_TRUE(integral_float.has_value());
    EXPECT_FALSE(integral_float->static_delay_ms.has_value());
}

// A malformed required scalar in stream/start (channels out of range) is dropped, leaving the player
// object incomplete, so the whole message is rejected instead of being accepted with a bogus value.
TEST(Protocol, StreamStartRejectsOutOfRangeRequiredScalar) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{"player":{"codec":"pcm",)"
                      R"("sample_rate":44100,"channels":300,"bit_depth":16}}}})",
                      doc, root));
    StreamStartMessage msg;
    EXPECT_FALSE(process_stream_start_message(root, &msg));

    // Control: the same message with an in-range channel count is accepted.
    JsonDocument doc_ok;
    JsonObject root_ok;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{"player":{"codec":"pcm",)"
                      R"("sample_rate":44100,"channels":2,"bit_depth":16}}}})",
                      doc_ok, root_ok));
    StreamStartMessage ok;
    EXPECT_TRUE(process_stream_start_message(root_ok, &ok));
    ASSERT_TRUE(ok.player.has_value());
    ASSERT_TRUE(ok.player->channels.has_value());
    EXPECT_EQ(ok.player->channels.value(), 2);
}

// Enum fields are validated against the known wire strings: a recognized value is applied, an
// unrecognized one is dropped (leaving the field untouched) rather than clearing or storing garbage.
TEST(Protocol, GroupUpdatePlaybackStateValidation) {
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(
            parse(R"({"type":"group/update","payload":{"playback_state":"playing"}})", doc, root));
        GroupUpdateMessage msg;
        ASSERT_TRUE(process_group_update_message(root, &msg));
        ASSERT_TRUE(msg.group.playback_state.has_value());
        EXPECT_EQ(msg.group.playback_state.value(), SendspinPlaybackState::PLAYING);
    }
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(
            parse(R"({"type":"group/update","payload":{"playback_state":"bogus"}})", doc, root));
        GroupUpdateMessage msg;
        ASSERT_TRUE(process_group_update_message(root, &msg));
        EXPECT_FALSE(msg.group.playback_state.has_value());  // unknown state dropped
    }
}

// Under the encrypted protocol, server/hello carries only the server's display name (server_id
// comes from the Noise handshake result instead); a message missing "name" is rejected.
TEST(Protocol, ServerHelloRequiresName) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/hello","payload":{}})", doc, root));
    ServerHelloMessage msg;
    EXPECT_FALSE(process_server_hello_message(root, &msg));

    JsonDocument doc_ok;
    JsonObject root_ok;
    ASSERT_TRUE(parse(R"({"type":"server/hello","payload":{"name":"srv"}})", doc_ok, root_ok));
    ServerHelloMessage ok;
    ASSERT_TRUE(process_server_hello_message(root_ok, &ok));
    EXPECT_EQ(ok.name, "srv");
}

// If a visualizer stream advertises SPECTRUM in its `types`, a valid spectrum config with a
// non-zero bin count must be present. Otherwise the expected size of binary spectrum messages
// would be indeterminate, so the visualizer object is dropped, but only that object: the message
// itself still parses so a well-formed player/artwork start alongside it is not lost.
TEST(Protocol, StreamStartDropsSpectrumWithoutValidConfig) {
    // (a) SPECTRUM advertised but no spectrum object at all.
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(
            R"({"type":"stream/start","payload":{"visualizer":{"types":["spectrum"]}}})", doc,
            root));
        StreamStartMessage msg;
        EXPECT_TRUE(process_stream_start_message(root, &msg));
        EXPECT_FALSE(msg.visualizer.has_value());
    }
    // (b) spectrum object present but n_disp_bins is zero.
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{"visualizer":{"types":["spectrum"],)"
                          R"("spectrum":{"n_disp_bins":0}}}})",
                          doc, root));
        StreamStartMessage msg;
        EXPECT_TRUE(process_stream_start_message(root, &msg));
        EXPECT_FALSE(msg.visualizer.has_value());
    }
    // (c) n_disp_bins present but not an integer.
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{"visualizer":{"types":["spectrum"],)"
                          R"("spectrum":{"n_disp_bins":"32"}}}})",
                          doc, root));
        StreamStartMessage msg;
        EXPECT_TRUE(process_stream_start_message(root, &msg));
        EXPECT_FALSE(msg.visualizer.has_value());
    }
    // (d) a valid player start in the same message survives the malformed visualizer object.
    {
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{)"
                          R"("player":{"codec":"pcm","sample_rate":48000,"channels":2,)"
                          R"("bit_depth":16},)"
                          R"("visualizer":{"types":["spectrum"]}}})",
                          doc, root));
        StreamStartMessage msg;
        EXPECT_TRUE(process_stream_start_message(root, &msg));
        EXPECT_FALSE(msg.visualizer.has_value());
        ASSERT_TRUE(msg.player.has_value());
        EXPECT_EQ(msg.player->sample_rate, 48000U);
    }

    // Control: SPECTRUM advertised with a valid config is accepted.
    JsonDocument doc_ok;
    JsonObject root_ok;
    ASSERT_TRUE(parse(R"({"type":"stream/start","payload":{"visualizer":{"types":["spectrum"],)"
                      R"("rate_max":30,)"
                      R"("spectrum":{"n_disp_bins":32,"scale":"log","f_min":20,"f_max":20000}}}})",
                      doc_ok, root_ok));
    StreamStartMessage ok;
    ASSERT_TRUE(process_stream_start_message(root_ok, &ok));
    ASSERT_TRUE(ok.visualizer.has_value());
    EXPECT_EQ(ok.visualizer->rate_max, 30);
    EXPECT_FALSE(ok.visualizer->tracks_downbeats);
    ASSERT_TRUE(ok.visualizer->spectrum.has_value());
    EXPECT_EQ(ok.visualizer->spectrum->n_disp_bins, 32);
}

// The refactored color parser reads each component as a uint8, so a non-integer (or out-of-range)
// component fails the type check and the whole color is treated as absent.
TEST(Protocol, ColorRejectsNonIntegerComponent) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"color":)"
                      R"({"timestamp":1,"primary":[10,"x",30]}}})",
                      doc, root));
    ServerColorStateDelta delta;
    ASSERT_TRUE(process_server_state_color(root, &delta));

    ServerColorStateObject current;
    apply_color_state_deltas(&current, delta);
    EXPECT_FALSE(current.primary.has_value());  // malformed component -> whole color dropped
}

// supported_commands is validated element-by-element. The controller role is frozen at v1, so an
// unrecognized command is a non-compliant value that is dropped (and logged), while the valid
// commands around it are kept in order.
TEST(Protocol, ControllerSupportedCommandsValidation) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"controller":)"
                      R"({"supported_commands":["play","bogus","mute"]}}})",
                      doc, root));
    ServerStateControllerObject controller;
    ASSERT_TRUE(process_server_state_controller(root, &controller));

    const auto& commands = controller.supported_commands;
    ASSERT_EQ(commands.size(), 2u);  // "bogus" dropped
    EXPECT_EQ(commands[0], SendspinControllerCommand::PLAY);
    EXPECT_EQ(commands[1], SendspinControllerCommand::MUTE);
}

// seek_max_ms is parsed when the server includes it (the seekable upper bound for absolute seeks).
TEST(Protocol, ControllerSeekMaxParsed) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"controller":)"
                      R"({"supported_commands":["seek"],"seek_max_ms":215000}}})",
                      doc, root));
    ServerStateControllerObject controller;
    ASSERT_TRUE(process_server_state_controller(root, &controller));
    ASSERT_TRUE(controller.seek_max_ms.has_value());
    EXPECT_EQ(*controller.seek_max_ms, 215000u);
}

// seek_max_ms stays absent (nullopt) when omitted, so consumers can tell "unknown range" from 0.
TEST(Protocol, ControllerSeekMaxAbsentWhenOmitted) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/state","payload":{"controller":)"
                      R"({"supported_commands":["seek_relative"]}}})",
                      doc, root));
    ServerStateControllerObject controller;
    ASSERT_TRUE(process_server_state_controller(root, &controller));
    EXPECT_FALSE(controller.seek_max_ms.has_value());
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
    const std::string out = format_client_command_message(
        {.command = SendspinControllerCommand::VOLUME, .volume = 50});

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
        format_client_command_message({.command = SendspinControllerCommand::MUTE, .muted = true});

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "mute");
    ASSERT_TRUE(doc["payload"]["controller"]["mute"].is<bool>());
    EXPECT_TRUE(doc["payload"]["controller"]["mute"].as<bool>());
    EXPECT_FALSE(doc["payload"]["controller"]["volume"].is<int>());
}

// SEEK carries an absolute position_ms; unrelated payload fields must not leak in.
TEST(Protocol, FormatClientCommandSeek) {
    const std::string out = format_client_command_message(
        {.command = SendspinControllerCommand::SEEK, .position_ms = 30000});

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "seek");
    ASSERT_TRUE(doc["payload"]["controller"]["position_ms"].is<uint32_t>());
    EXPECT_EQ(doc["payload"]["controller"]["position_ms"].as<uint32_t>(), 30000u);
    EXPECT_FALSE(doc["payload"]["controller"]["offset_ms"].is<int>());
    EXPECT_FALSE(doc["payload"]["controller"]["volume"].is<int>());
}

// SEEK_RELATIVE carries a signed offset_ms (negative offsets seek backward).
TEST(Protocol, FormatClientCommandSeekRelative) {
    const std::string out = format_client_command_message(
        {.command = SendspinControllerCommand::SEEK_RELATIVE, .offset_ms = -10000});

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "seek_relative");
    ASSERT_TRUE(doc["payload"]["controller"]["offset_ms"].is<int>());
    EXPECT_EQ(doc["payload"]["controller"]["offset_ms"].as<int>(), -10000);
    EXPECT_FALSE(doc["payload"]["controller"]["position_ms"].is<int>());
}

// A parameter that does not match the command is dropped at serialization (position_ms on VOLUME).
TEST(Protocol, FormatClientCommandDropsMismatchedParam) {
    const std::string out = format_client_command_message(
        {.command = SendspinControllerCommand::VOLUME, .volume = 40, .position_ms = 99999});

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "volume");
    EXPECT_EQ(doc["payload"]["controller"]["volume"].as<int>(), 40);
    EXPECT_FALSE(doc["payload"]["controller"]["position_ms"].is<int>());
}

// A no-argument command (PLAY) emits just the command, with no payload fields present.
TEST(Protocol, FormatClientCommandNoArgs) {
    const std::string out =
        format_client_command_message({.command = SendspinControllerCommand::PLAY});

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["controller"]["command"], "play");
    EXPECT_FALSE(doc["payload"]["controller"]["volume"].is<int>());
    EXPECT_FALSE(doc["payload"]["controller"]["mute"].is<bool>());
}

// Every device_info identity field (product_name, manufacturer, software_version, mac_address)
// is optional and serialized only when present.
TEST(Protocol, FormatClientHelloDeviceInfoFieldsPresent) {
    ClientHelloMessage msg;
    msg.name = "Speaker";
    DeviceInfoObject info{};
    info.product_name = "Speaker Pro";
    info.manufacturer = "ESPHome";
    info.software_version = "1.2.3";
    info.mac_address = "aa:bb:cc:dd:ee:ff";
    msg.device_info = info;

    const std::string out = format_client_hello_message(&msg);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_STREQ(doc["payload"]["device_info"]["product_name"], "Speaker Pro");
    EXPECT_STREQ(doc["payload"]["device_info"]["manufacturer"], "ESPHome");
    EXPECT_STREQ(doc["payload"]["device_info"]["software_version"], "1.2.3");
    EXPECT_STREQ(doc["payload"]["device_info"]["mac_address"], "aa:bb:cc:dd:ee:ff");
}

// The visualizer@v1 support object serializes with the spec's field layout: types (including
// the event types), buffer_capacity, top-level rate_max, and a spectrum object without a
// nested rate cap.
TEST(Protocol, FormatClientHelloVisualizerSupport) {
    ClientHelloMessage msg;
    msg.name = "Speaker";
    msg.supported_roles.push_back(SendspinRole::VISUALIZER);
    VisualizerSupportObject vis{};
    vis.types = {VisualizerDataType::BEAT, VisualizerDataType::LOUDNESS,
                 VisualizerDataType::F_PEAK, VisualizerDataType::SPECTRUM,
                 VisualizerDataType::PEAK};
    vis.buffer_capacity = 8192;
    vis.rate_max = 60;
    vis.spectrum = VisualizerSpectrumConfig{
        .n_disp_bins = 32,
        .scale = VisualizerSpectrumScale::MEL,
        .f_min = 40,
        .f_max = 16000,
    };
    msg.visualizer_support = vis;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_STREQ(doc["payload"]["supported_roles"][0], "visualizer@v1");
    JsonObject support = doc["payload"]["visualizer@v1_support"];
    ASSERT_TRUE(support["types"].is<JsonArray>());
    EXPECT_EQ(support["types"].size(), 5U);
    EXPECT_STREQ(support["types"][4], "peak");
    EXPECT_EQ(support["buffer_capacity"].as<int>(), 8192);
    EXPECT_EQ(support["rate_max"].as<int>(), 60);
    EXPECT_EQ(support["spectrum"]["n_disp_bins"].as<int>(), 32);
    EXPECT_STREQ(support["spectrum"]["scale"], "mel");
    EXPECT_EQ(support["spectrum"]["f_min"].as<int>(), 40);
    EXPECT_EQ(support["spectrum"]["f_max"].as<int>(), 16000);
    EXPECT_FALSE(support["spectrum"]["rate_max"].is<int>());
    EXPECT_FALSE(support["batch_max"].is<int>());
}

// stream/request-format serializes the visualizer object with only the fields the caller set;
// omitted optionals keep their current server-side value and must not emit keys.
TEST(Protocol, FormatStreamRequestFormatVisualizer) {
    StreamRequestFormatMessage msg;
    VisualizerFormatRequest req{};
    req.rate_max = 24;
    msg.visualizer = req;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_stream_request_format_message(&msg)));
    EXPECT_STREQ(doc["type"], "stream/request-format");
    EXPECT_EQ(doc["payload"]["visualizer"]["rate_max"].as<int>(), 24);
    EXPECT_FALSE(doc["payload"]["visualizer"]["types"].is<JsonArray>());
    EXPECT_FALSE(doc["payload"]["visualizer"]["spectrum"].is<JsonObject>());

    // Full request: all fields emitted.
    VisualizerFormatRequest full{};
    full.types = std::vector<VisualizerDataType>{VisualizerDataType::SPECTRUM};
    full.rate_max = 30;
    full.spectrum = VisualizerSpectrumConfig{
        .n_disp_bins = 16,
        .scale = VisualizerSpectrumScale::LOG,
        .f_min = 20,
        .f_max = 20000,
    };
    msg.visualizer = full;
    JsonDocument doc2;
    ASSERT_FALSE(deserializeJson(doc2, format_stream_request_format_message(&msg)));
    EXPECT_STREQ(doc2["payload"]["visualizer"]["types"][0], "spectrum");
    EXPECT_EQ(doc2["payload"]["visualizer"]["spectrum"]["n_disp_bins"].as<int>(), 16);
    EXPECT_STREQ(doc2["payload"]["visualizer"]["spectrum"]["scale"], "log");

    // All-empty request: no "visualizer" key at all. A present-but-empty object could read as
    // "reset to defaults" rather than "no change" on the server.
    msg.visualizer = VisualizerFormatRequest{};
    JsonDocument doc3;
    ASSERT_FALSE(deserializeJson(doc3, format_stream_request_format_message(&msg)));
    EXPECT_FALSE(doc3["payload"]["visualizer"].is<JsonObject>());
}

// Unset optional identity fields must not emit their keys.
TEST(Protocol, FormatClientHelloDeviceInfoFieldsAbsent) {
    ClientHelloMessage msg;
    msg.name = "Speaker";
    msg.device_info = DeviceInfoObject{};

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_FALSE(doc["payload"]["device_info"]["product_name"].is<const char*>());
    EXPECT_FALSE(doc["payload"]["device_info"]["manufacturer"].is<const char*>());
    EXPECT_FALSE(doc["payload"]["device_info"]["software_version"].is<const char*>());
    EXPECT_FALSE(doc["payload"]["device_info"]["mac_address"].is<const char*>());
}

// ============================================================================
// client/state field set
// ============================================================================

// spec "client/state": the client-level field is the boolean `available`, not a multi-valued
// state string. SYNCHRONIZED must serialize to available:true, and no legacy top-level "state"
// key may appear (a strict-mode server hard-rejects client/state carrying an unknown field).
TEST(Protocol, FormatClientStateSynchronizedIsAvailableTrue) {
    ClientStateMessage msg;
    msg.state = SendspinClientState::SYNCHRONIZED;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_state_message(&msg)));
    EXPECT_TRUE(doc["payload"]["available"].as<bool>());
    EXPECT_FALSE(doc["payload"]["state"].is<const char*>())
        << "client/state must not carry the legacy top-level 'state' field";
}

// ERROR and EXTERNAL_SOURCE both report available:false: the current spec's client/state has no
// separate error signal, only the available boolean (see "External Source Handling").
TEST(Protocol, FormatClientStateErrorIsAvailableFalse) {
    ClientStateMessage msg;
    msg.state = SendspinClientState::ERROR;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_state_message(&msg)));
    EXPECT_FALSE(doc["payload"]["available"].as<bool>());
    EXPECT_FALSE(doc["payload"]["state"].is<const char*>())
        << "client/state must not carry the legacy top-level 'state' field";
}

TEST(Protocol, FormatClientStateExternalSourceIsAvailableFalse) {
    ClientStateMessage msg;
    msg.state = SendspinClientState::EXTERNAL_SOURCE;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_state_message(&msg)));
    EXPECT_FALSE(doc["payload"]["available"].as<bool>());
    EXPECT_FALSE(doc["payload"]["state"].is<const char*>())
        << "client/state must not carry the legacy top-level 'state' field";
}

// ============================================================================
// client/hello field set
// ============================================================================

// Under encryption, client/hello must NOT contain client_id or version (they move to client/init).
TEST(Protocol, ClientHelloNoClientIdOrVersion) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    const std::string out = format_client_hello_message(&msg);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    EXPECT_FALSE(doc["payload"]["client_id"].is<const char*>())
        << "client_id must NOT appear in client/hello under encryption";
    EXPECT_FALSE(doc["payload"]["version"].is<int>())
        << "version must NOT appear in client/hello under encryption";
}

// trust_level is always emitted (either "none" or "user").
TEST(Protocol, ClientHelloTrustLevelNone) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    msg.trust_level = ConnectionTrust::NONE;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_STREQ(doc["payload"]["trust_level"], "none");
}

TEST(Protocol, ClientHelloTrustLevelUser) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    msg.trust_level = ConnectionTrust::USER;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_STREQ(doc["payload"]["trust_level"], "user");
}

// unpaired_access.enabled is always emitted.
TEST(Protocol, ClientHelloUnpairedAccessEnabled) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    msg.unpaired_access_enabled = true;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_TRUE(doc["payload"]["unpaired_access"]["enabled"].as<bool>());
}

TEST(Protocol, ClientHelloUnpairedAccessDisabled) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    msg.unpaired_access_enabled = false;

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    EXPECT_FALSE(doc["payload"]["unpaired_access"]["enabled"].as<bool>());
}

// supported_pair_methods: pairing_psk emitted with correct wire shape.
TEST(Protocol, ClientHelloPairingPskMethodDescriptor) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    PairMethodDescriptor psk_desc;
    psk_desc.method = SendspinPairMethod::PAIRING_PSK;
    msg.supported_pair_methods.push_back(std::move(psk_desc));

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    JsonArrayConst methods = doc["payload"]["supported_pair_methods"].as<JsonArrayConst>();
    ASSERT_EQ(methods.size(), 1u);
    EXPECT_STREQ(methods[0]["method"], "pairing_psk");
}

// supported_pair_methods: the field itself is REQUIRED on the wire even when there are no
// methods to advertise (spec's "client/hello" section): it must be emitted as an empty array,
// not omitted, since every client is expected to implement at least pairing_psk.
TEST(Protocol, ClientHelloNoSupportedPairMethods) {
    ClientHelloMessage msg;
    msg.name = "TestDevice";
    // supported_pair_methods is empty by default

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&msg)));
    ASSERT_TRUE(doc["payload"]["supported_pair_methods"].is<JsonArrayConst>());
    EXPECT_EQ(doc["payload"]["supported_pair_methods"].as<JsonArrayConst>().size(), 0u);
}

// ============================================================================
// server/hello slim parse (only name)
// ============================================================================

TEST(Protocol, ServerHelloSlimParse) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/hello","payload":{"name":"MySpeaker"}})", doc, root));

    ServerHelloMessage msg;
    ASSERT_TRUE(process_server_hello_message(root, &msg));
    EXPECT_EQ(msg.name, "MySpeaker");
}

// server/hello parses successfully when only name is present; the optional fields may be absent.
TEST(Protocol, ServerHelloParsesWithOnlyName) {
    JsonDocument doc;
    JsonObject root;
    // Optional fields (connection_reason, active_roles, version, server_id) are absent.
    ASSERT_TRUE(parse(R"({"type":"server/hello","payload":{"name":"X"}})", doc, root));

    ServerHelloMessage msg;
    EXPECT_TRUE(process_server_hello_message(root, &msg));
    EXPECT_EQ(msg.name, "X");
}

TEST(Protocol, ServerHelloMissingNameFails) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/hello","payload":{}})", doc, root));

    ServerHelloMessage msg;
    EXPECT_FALSE(process_server_hello_message(root, &msg));
}

// ============================================================================
// server/activate parse
// ============================================================================

TEST(Protocol, ServerActivateActivitiesOnly) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["playback"]}})", doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    ASSERT_EQ(msg.activities.size(), 1u);
    EXPECT_EQ(msg.activities[0], SendspinActivity::PLAYBACK);
    EXPECT_FALSE(msg.active_roles.has_value());
    EXPECT_FALSE(msg.pairing_method.has_value());
}

TEST(Protocol, ServerActivateAllActivities) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["playback","pairing","management"]}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    ASSERT_EQ(msg.activities.size(), 3u);
    EXPECT_EQ(msg.activities[0], SendspinActivity::PLAYBACK);
    EXPECT_EQ(msg.activities[1], SendspinActivity::PAIRING);
    EXPECT_EQ(msg.activities[2], SendspinActivity::MANAGEMENT);
}

TEST(Protocol, ServerActivateEmptyActivities) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":[]}})", doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    EXPECT_TRUE(msg.activities.empty());
}

TEST(Protocol, ServerActivateWithActiveRoles) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["playback"],"active_roles":["player@v1","metadata@v1"]}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    ASSERT_TRUE(msg.active_roles.has_value());
    ASSERT_EQ(msg.active_roles->size(), 2u);
    EXPECT_EQ((*msg.active_roles)[0], "player@v1");
    EXPECT_EQ((*msg.active_roles)[1], "metadata@v1");
}

// active_roles absent -> nullopt (sticky: caller should keep previous set).
TEST(Protocol, ServerActivateActiveRolesAbsentIsNullopt) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["playback"]}})", doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    EXPECT_FALSE(msg.active_roles.has_value())
        << "absent active_roles must be nullopt (sticky)";
}

// The spec nests the pairing parameters: payload.pairing = {method, pin_length?, languages?}.
// The parser must accept this nested form; the flat payload.selected_pair_method field is not
// part of the current wire format.
TEST(Protocol, ServerActivateWithPairingObject) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["pairing"],"pairing":{"method":"pairing_psk"}}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    ASSERT_TRUE(msg.pairing_method.has_value());
    EXPECT_EQ(msg.pairing_method.value(), SendspinPairMethod::PAIRING_PSK);
    EXPECT_FALSE(msg.pairing_pin_length.has_value());
}

// dynamic_pin activations carry pin_length (and optionally languages) inside the pairing
// object; languages is an informational hint and deliberately unparsed, but must not break
// parsing of its siblings.
TEST(Protocol, ServerActivatePairingObjectCarriesPinLength) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["pairing"],"pairing":{"method":"dynamic_pin","pin_length":6,"languages":["ca","es","en"]}}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    ASSERT_TRUE(msg.pairing_method.has_value());
    EXPECT_EQ(msg.pairing_method.value(), SendspinPairMethod::DYNAMIC_PIN);
    ASSERT_TRUE(msg.pairing_pin_length.has_value());
    EXPECT_EQ(msg.pairing_pin_length.value(), 6);
}

// payload.selected_pair_method is not part of the current wire format: a server sending only
// that flat field yields no usable method.
TEST(Protocol, ServerActivateLegacyFlatSelectedPairMethodIgnored) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["pairing"],"selected_pair_method":"pairing_psk"}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    EXPECT_FALSE(msg.pairing_method.has_value());
}

// An unrecognized pairing.method string parses as no usable method (the caller answers
// pair/abort method_not_supported).
TEST(Protocol, ServerActivateUnknownPairingMethodIsNullopt) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(
        R"({"type":"server/activate","payload":{"activities":["pairing"],"pairing":{"method":"telepathy"}}})",
        doc, root));

    ServerActivateMessage msg;
    ASSERT_TRUE(process_server_activate_message(root, &msg));
    EXPECT_FALSE(msg.pairing_method.has_value());
}

TEST(Protocol, ServerActivateMissingActivitiesFails) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"server/activate","payload":{}})", doc, root));

    ServerActivateMessage msg;
    EXPECT_FALSE(process_server_activate_message(root, &msg));
}

// ============================================================================
// Activity enum round-trips
// ============================================================================

TEST(Protocol, ActivityToString) {
    EXPECT_STREQ(to_cstr(SendspinActivity::PLAYBACK), "playback");
    EXPECT_STREQ(to_cstr(SendspinActivity::PAIRING), "pairing");
    EXPECT_STREQ(to_cstr(SendspinActivity::MANAGEMENT), "management");
}

TEST(Protocol, ActivityFromString) {
    EXPECT_EQ(activity_from_string("playback"), SendspinActivity::PLAYBACK);
    EXPECT_EQ(activity_from_string("pairing"), SendspinActivity::PAIRING);
    EXPECT_EQ(activity_from_string("management"), SendspinActivity::MANAGEMENT);
    EXPECT_FALSE(activity_from_string("unknown_activity").has_value());
}

// ============================================================================
// PairMethod enum round-trips
// ============================================================================

TEST(Protocol, PairMethodToString) {
    EXPECT_STREQ(to_cstr(SendspinPairMethod::PAIRING_PSK), "pairing_psk");
    EXPECT_STREQ(to_cstr(SendspinPairMethod::DYNAMIC_PIN), "dynamic_pin");
    EXPECT_STREQ(to_cstr(SendspinPairMethod::STATIC_PIN), "static_pin");
}

TEST(Protocol, PairMethodFromString) {
    EXPECT_EQ(pair_method_from_string("pairing_psk"), SendspinPairMethod::PAIRING_PSK);
    EXPECT_EQ(pair_method_from_string("dynamic_pin"), SendspinPairMethod::DYNAMIC_PIN);
    EXPECT_EQ(pair_method_from_string("static_pin"), SendspinPairMethod::STATIC_PIN);
    EXPECT_FALSE(pair_method_from_string("invalid_method").has_value());
}

// ============================================================================
// SendspinGoodbyeReason
// ============================================================================

TEST(Protocol, GoodbyeReasonPairingValues) {
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::UNAUTHORIZED), "unauthorized");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::PAIRING_REQUIRED), "pairing_required");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::CONCURRENT_ATTEMPT), "concurrent_attempt");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::UNPAIRED), "unpaired");
}

TEST(Protocol, GoodbyeReasonLifecycleValues) {
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::ANOTHER_SERVER), "another_server");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::SHUTDOWN), "shutdown");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::RESTART), "restart");
    EXPECT_STREQ(to_cstr(SendspinGoodbyeReason::USER_REQUEST), "user_request");
}

// ============================================================================
// Pairing-PSK protocol messages
// ============================================================================

// Determine message type recognizes the two new pairing types.
TEST(Protocol, DetermineMessageTypePairingTypes) {
    JsonDocument doc;
    JsonObject root;

    ASSERT_TRUE(parse(R"({"type":"server/pair-finalize"})", doc, root));
    EXPECT_EQ(determine_message_type(root),
              SendspinServerToClientMessageType::SERVER_PAIR_FINALIZE);

    ASSERT_TRUE(parse(R"({"type":"pair/abort"})", doc, root));
    EXPECT_EQ(determine_message_type(root), SendspinServerToClientMessageType::PAIR_ABORT);
}

// PairAbortReason: every value survives a to_cstr -> from_string round-trip.
TEST(Protocol, PairAbortReasonRoundTrip) {
    const PairAbortReason reasons[] = {
        PairAbortReason::ATTEMPT_TIMEOUT,
        PairAbortReason::CONCURRENT_ATTEMPT,
        PairAbortReason::METHOD_NOT_SUPPORTED,
        PairAbortReason::PIN_LENGTH_UNACCEPTABLE,
        PairAbortReason::PIN_MISMATCH,
        PairAbortReason::USER_CANCELLED,
    };
    for (const auto reason : reasons) {
        const char* wire = to_cstr(reason);
        auto parsed = pair_abort_reason_from_string(wire);
        ASSERT_TRUE(parsed.has_value()) << "no round-trip for " << wire;
        EXPECT_EQ(parsed.value(), reason);
    }
    EXPECT_FALSE(pair_abort_reason_from_string("not_a_reason").has_value());
}

// format_client_pair_finalize_message: produces the exact wire shape.
// The long_term_psk field must be exactly 43 chars (base64url of 32 bytes, no padding).
TEST(Protocol, FormatClientPairFinalizeWireShape) {
    // Known 32-byte PSK: all-zeros for deterministic output.
    std::array<uint8_t, 32> psk{};
    const std::string out = format_client_pair_finalize_message(psk);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out)) << "format_client_pair_finalize produced invalid JSON";

    EXPECT_STREQ(doc["type"], "client/pair-finalize");

    // long_term_psk must be a 43-character base64url string (no padding).
    ASSERT_TRUE(doc["payload"]["long_term_psk"].is<const char*>())
        << "long_term_psk field missing or not a string";
    const std::string psk_b64 = doc["payload"]["long_term_psk"].as<std::string>();
    EXPECT_EQ(psk_b64.size(), 43u)
        << "base64url of 32 bytes without padding must be exactly 43 chars";

    // Verify the encoded value decodes back to the original 32-byte PSK.
    auto decoded = b64url_decode(psk_b64);
    ASSERT_TRUE(decoded.has_value()) << "long_term_psk is not valid base64url";
    ASSERT_EQ(decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*decoded)[i], psk[i]) << "decoded byte mismatch at index " << i;
    }
}

TEST(Protocol, FormatClientPairFinalizeNonZeroPsk) {
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < 32; ++i) {
        psk[i] = static_cast<uint8_t>(i + 1);  // 1..32
    }
    const std::string out = format_client_pair_finalize_message(psk);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, out));
    const std::string psk_b64 = doc["payload"]["long_term_psk"].as<std::string>();
    EXPECT_EQ(psk_b64.size(), 43u);

    // Decode and verify round-trip.
    auto decoded = b64url_decode(psk_b64);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 32u);
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ((*decoded)[i], psk[i]) << "round-trip mismatch at " << i;
    }
}

// format_pair_abort_message: produces the correct wire shape for every reason.
TEST(Protocol, FormatPairAbortWireShape) {
    const PairAbortReason reasons[] = {
        PairAbortReason::METHOD_NOT_SUPPORTED,
        PairAbortReason::ATTEMPT_TIMEOUT,
        PairAbortReason::USER_CANCELLED,
    };
    for (const auto reason : reasons) {
        const std::string out = format_pair_abort_message(reason);
        JsonDocument doc;
        ASSERT_FALSE(deserializeJson(doc, out)) << "invalid JSON for reason " << to_cstr(reason);
        EXPECT_STREQ(doc["type"], "pair/abort");
        ASSERT_TRUE(doc["payload"]["reason"].is<const char*>());
        EXPECT_STREQ(doc["payload"]["reason"], to_cstr(reason));
    }
}

// process_pair_abort_message: round-trips every PairAbortReason.
TEST(Protocol, PairAbortMessageParseRoundTrip) {
    const PairAbortReason reasons[] = {
        PairAbortReason::ATTEMPT_TIMEOUT,
        PairAbortReason::CONCURRENT_ATTEMPT,
        PairAbortReason::METHOD_NOT_SUPPORTED,
        PairAbortReason::PIN_LENGTH_UNACCEPTABLE,
        PairAbortReason::PIN_MISMATCH,
        PairAbortReason::USER_CANCELLED,
    };
    for (const auto reason : reasons) {
        const std::string out = format_pair_abort_message(reason);
        JsonDocument doc;
        JsonObject root;
        ASSERT_TRUE(parse(out, doc, root)) << "invalid JSON for " << to_cstr(reason);

        PairAbortMessage msg;
        ASSERT_TRUE(process_pair_abort_message(root, &msg)) << "parse failed for " << to_cstr(reason);
        EXPECT_EQ(msg.reason, reason);
    }
}

// process_pair_abort_message: missing reason field returns false.
TEST(Protocol, PairAbortMessageMissingReason) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"pair/abort","payload":{}})", doc, root));
    PairAbortMessage msg;
    EXPECT_FALSE(process_pair_abort_message(root, &msg));
}

// process_pair_abort_message: unrecognized reason returns false.
TEST(Protocol, PairAbortMessageUnknownReason) {
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse(R"({"type":"pair/abort","payload":{"reason":"not_a_reason"}})", doc, root));
    PairAbortMessage msg;
    EXPECT_FALSE(process_pair_abort_message(root, &msg))
        << "unrecognized reason should return false";
}
