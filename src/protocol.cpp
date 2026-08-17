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

#include "platform/base64.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "protocol_messages.h"
#include "sendspin/color_role.h"
#include "sendspin/config.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/types.h"
#include "sendspin/visualizer_role.h"
#include <ArduinoJson.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

static const char* const TAG = "sendspin.protocol";

// ============================================================================
// Static helpers
// ============================================================================

/// @brief Protocol maximum for volume fields (volume is 0-100 on the wire).
static constexpr uint8_t VOLUME_MAX = 100;

/// @brief Reads an optional unsigned-integer field with strict type and optional range validation.
/// Absent or null returns nullopt silently (a legal state for an optional field). A present value
/// that is the wrong JSON type, outside the target type's range, or outside [min, max] is logged
/// and dropped. Strict about representation: a float or numeric string is rejected, matching a
/// spec-compliant server that sends genuine JSON integers.
template <typename T>
static std::optional<T> read_uint_field(JsonVariantConst var, const char* name,
                                        T min = std::numeric_limits<T>::min(),
                                        T max = std::numeric_limits<T>::max()) {
    if (var.isUnbound() || var.isNull()) {
        return std::nullopt;
    }
    if (!var.is<T>()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected integer in [%llu, %llu]", name,
                static_cast<unsigned long long>(min), static_cast<unsigned long long>(max));
        return std::nullopt;
    }
    T value = var.as<T>();
    if (value < min || value > max) {
        SS_LOGW(TAG, "Ignoring field '%s': %llu outside [%llu, %llu]", name,
                static_cast<unsigned long long>(value), static_cast<unsigned long long>(min),
                static_cast<unsigned long long>(max));
        return std::nullopt;
    }
    return value;
}

/// @brief Reads an optional boolean field. Absent or null returns nullopt silently; a present
/// non-boolean value (including 0/1 integers) is logged and dropped. Strict: only genuine JSON
/// true/false is accepted, matching a spec-compliant server.
static std::optional<bool> read_bool_field(JsonVariantConst var, const char* name) {
    if (var.isUnbound() || var.isNull()) {
        return std::nullopt;
    }
    if (!var.is<bool>()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected boolean", name);
        return std::nullopt;
    }
    return var.as<bool>();
}

/// @brief Reads an optional enum field parsed from a wire string via `from_string`. Absent or null
/// returns nullopt silently; a present non-string, or a string that `from_string` does not
/// recognize, is logged and dropped. For enum fields whose policy is "apply if valid, otherwise
/// leave the current value untouched" (not for fields that map unknown values to a sentinel or that
/// reject the whole message).
template <typename E>
static std::optional<E> read_enum_field(JsonVariantConst var, const char* name,
                                        std::optional<E> (*from_string)(const std::string&)) {
    if (var.isUnbound() || var.isNull()) {
        return std::nullopt;
    }
    if (!var.is<const char*>()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected string", name);
        return std::nullopt;
    }
    std::optional<E> value = from_string(var.as<std::string>());
    if (!value) {
        SS_LOGW(TAG, "Ignoring field '%s': unknown value '%s'", name, var.as<const char*>());
    }
    return value;
}

static bool process_player_stream_object(const JsonObject player_object,
                                         ServerPlayerStreamObject* player_obj,
                                         bool require_all_fields) {
    if (player_obj == nullptr) {
        return false;
    }

    if (require_all_fields) {
        if (!player_object["bit_depth"].is<JsonVariant>() ||
            !player_object["channels"].is<JsonVariant>() ||
            !player_object["sample_rate"].is<JsonVariant>() ||
            !player_object["codec"].is<JsonVariant>()) {
            SS_LOGE(TAG, "Invalid player object: missing required fields");
            return false;
        }
    }

    if (player_object["codec"].is<JsonVariant>()) {
        std::string codec_type = player_object["codec"].as<std::string>();
        auto codec = codec_format_from_string(codec_type);
        player_obj->codec = codec.value_or(SendspinCodecFormat::UNSUPPORTED);
    }

    if (auto v = read_uint_field<uint32_t>(player_object["sample_rate"], "sample_rate")) {
        player_obj->sample_rate = v;
    }

    if (auto v = read_uint_field<uint8_t>(player_object["channels"], "channels")) {
        player_obj->channels = v;
    }

    if (auto v = read_uint_field<uint8_t>(player_object["bit_depth"], "bit_depth")) {
        player_obj->bit_depth = v;
    }

    if (player_object["codec_header"].is<JsonVariant>()) {
        player_obj->codec_header = player_object["codec_header"].as<std::string>();
    }

    // For FLAC, codec_header is required
    if (player_obj->codec.has_value() && player_obj->codec.value() == SendspinCodecFormat::FLAC &&
        !player_obj->codec_header.has_value()) {
        SS_LOGE(TAG, "Invalid player object: FLAC requires codec_header");
        return false;
    }

    return true;
}

static bool process_artwork_channel_object(const JsonObject channel_object,
                                           ServerArtworkChannelObject* channel,
                                           bool require_all_fields) {
    if (channel == nullptr) {
        return false;
    }

    if (require_all_fields) {
        if (!channel_object["source"].is<JsonVariant>() ||
            !channel_object["format"].is<JsonVariant>() ||
            !channel_object["width"].is<JsonVariant>() ||
            !channel_object["height"].is<JsonVariant>()) {
            SS_LOGE(TAG, "Invalid artwork channel: missing required fields");
            return false;
        }
    }

    if (auto source =
            read_enum_field(channel_object["source"], "source", image_source_from_string)) {
        channel->source = source;
    }

    if (auto format =
            read_enum_field(channel_object["format"], "format", image_format_from_string)) {
        channel->format = format;
    }

    if (auto v = read_uint_field<uint16_t>(channel_object["width"], "width")) {
        channel->width = v;
    }

    if (auto v = read_uint_field<uint16_t>(channel_object["height"], "height")) {
        channel->height = v;
    }

    return true;
}

static bool process_server_player_command_object(const JsonObject player_object,
                                                 ServerPlayerCommandObject* player_cmd) {
    if (player_cmd == nullptr || !player_object["command"].is<JsonVariant>()) {
        return false;
    }

    std::string command_str = player_object["command"].as<std::string>();
    auto command = player_command_from_string(command_str);

    if (!command.has_value()) {
        SS_LOGE(TAG, "Invalid server player command type: %s", command_str.c_str());
        return false;
    }
    player_cmd->command = command.value();

    // Parse optional fields
    if (auto v = read_uint_field<uint8_t>(player_object["volume"], "volume", 0, VOLUME_MAX)) {
        player_cmd->volume = v;
    }

    if (auto v = read_bool_field(player_object["mute"], "mute")) {
        player_cmd->mute = v;
    }

    if (auto v = read_uint_field<uint16_t>(player_object["static_delay_ms"], "static_delay_ms")) {
        player_cmd->static_delay_ms = v;
    }

    return true;
}

// Parses a single string field into a tri-state delta entry. Absent on the wire leaves `out`
// untouched; explicit `null` writes outer-engaged + inner-`nullopt` (clear); a string writes
// outer-engaged + inner-engaged. A present value that is neither a string nor null is logged and
// skipped (treated as absent).
static void parse_metadata_string_field(JsonVariantConst var, const char* name,
                                        std::optional<std::optional<std::string>>* out) {
    if (var.is<const char*>()) {
        *out = var.as<std::string>();
    } else if (var.isNull() && !var.isUnbound()) {
        *out = std::optional<std::string>{};
    } else if (!var.isUnbound()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected string or null", name);
    }
}

// Parses a single uint16 field into a tri-state delta entry. Same semantics as above; a present
// value that is neither a uint16 (0-65535) nor null is logged and skipped.
static void parse_metadata_uint16_field(JsonVariantConst var, const char* name,
                                        std::optional<std::optional<uint16_t>>* out) {
    if (var.is<uint16_t>()) {
        *out = var.as<uint16_t>();
    } else if (var.isNull() && !var.isUnbound()) {
        *out = std::optional<uint16_t>{};
    } else if (!var.isUnbound()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected integer in [0, 65535] or null", name);
    }
}

// Parses a single `[R, G, B]` color field into a tri-state delta entry. Absent leaves `out`
// untouched (outer nullopt); explicit `null` writes outer-engaged + inner-nullopt (clear); a
// 3-element array of 0-255 integers writes the color. Any malformed value is logged and skipped
// (treated as absent). Each component is read as a uint8, so its type check is also its range
// check.
static void parse_color_field(JsonVariantConst var, const char* name,
                              std::optional<std::optional<RgbColor>>* out) {
    if (var.isUnbound()) {
        return;
    }
    if (var.isNull()) {
        *out = std::optional<RgbColor>{};
        return;
    }
    if (!var.is<JsonArrayConst>()) {
        SS_LOGW(TAG, "Ignoring field '%s': expected [R, G, B] array", name);
        return;
    }
    JsonArrayConst arr = var.as<JsonArrayConst>();
    if (arr.size() != 3) {
        SS_LOGW(TAG, "Ignoring field '%s': expected 3 components, got %zu", name, arr.size());
        return;
    }
    RgbColor color{};
    for (size_t i = 0; i < 3; i++) {
        auto component = read_uint_field<uint8_t>(arr[i], name);
        if (!component) {
            return;  // out of [0, 255] or wrong type; already logged
        }
        color[i] = *component;
    }
    // cppcheck-suppress autoVariables
    // False positive: RgbColor is std::array<uint8_t, 3> (include/sendspin/color_role.h), a
    // plain value type. This assigns *out by value through std::optional's assignment operator;
    // it does not take the address of the local `color`.
    *out = color;
}

// ============================================================================
// Protocol functions
// ============================================================================

// Message type determination

SendspinServerToClientMessageType determine_message_type(JsonObject root) {
    if (!root["type"].is<const char*>()) {
        return SendspinServerToClientMessageType::UNKNOWN;
    }

    const std::string type_str = root["type"].as<std::string>();
    if (type_str == "server/hello") {
        return SendspinServerToClientMessageType::SERVER_HELLO;
    }
    if (type_str == "server/activate") {
        return SendspinServerToClientMessageType::SERVER_ACTIVATE;
    }
    if (type_str == "server/time") {
        return SendspinServerToClientMessageType::SERVER_TIME;
    }
    if (type_str == "server/state") {
        return SendspinServerToClientMessageType::SERVER_STATE;
    }
    if (type_str == "server/command") {
        return SendspinServerToClientMessageType::SERVER_COMMAND;
    }
    if (type_str == "stream/start") {
        return SendspinServerToClientMessageType::STREAM_START;
    }
    if (type_str == "stream/end") {
        return SendspinServerToClientMessageType::STREAM_END;
    }
    if (type_str == "stream/clear") {
        return SendspinServerToClientMessageType::STREAM_CLEAR;
    }
    if (type_str == "group/update") {
        return SendspinServerToClientMessageType::GROUP_UPDATE;
    }
    if (type_str == "noise/handshake") {
        return SendspinServerToClientMessageType::NOISE_HANDSHAKE;
    }
    if (type_str == "server/pair-finalize") {
        return SendspinServerToClientMessageType::SERVER_PAIR_FINALIZE;
    }
    if (type_str == "pair/abort") {
        return SendspinServerToClientMessageType::PAIR_ABORT;
    }
    if (type_str == "server/unpair") {
        return SendspinServerToClientMessageType::SERVER_UNPAIR;
    }
    if (type_str == "management/list-records") {
        return SendspinServerToClientMessageType::MANAGEMENT_LIST_RECORDS;
    }
    if (type_str == "management/add-record") {
        return SendspinServerToClientMessageType::MANAGEMENT_ADD_RECORD;
    }
    if (type_str == "management/remove-record") {
        return SendspinServerToClientMessageType::MANAGEMENT_REMOVE_RECORD;
    }
    if (type_str == "management/get-pairing-config") {
        return SendspinServerToClientMessageType::MANAGEMENT_GET_PAIRING_CONFIG;
    }
    if (type_str == "management/set-pairing-config") {
        return SendspinServerToClientMessageType::MANAGEMENT_SET_PAIRING_CONFIG;
    }
    if (type_str == "management/open-pairing-window") {
        return SendspinServerToClientMessageType::MANAGEMENT_OPEN_PAIRING_WINDOW;
    }
    if (type_str == "server/pair-init") {
        return SendspinServerToClientMessageType::SERVER_PAIR_INIT;
    }
    if (type_str == "server/pair-auth") {
        return SendspinServerToClientMessageType::SERVER_PAIR_AUTH;
    }
    if (type_str == "server/pair-confirm") {
        return SendspinServerToClientMessageType::SERVER_PAIR_CONFIRM;
    }

    return SendspinServerToClientMessageType::UNKNOWN;
}

// Message processing

bool process_server_hello_message(JsonObject root, ServerHelloMessage* hello_msg) {
    // Under the encrypted protocol, server/hello carries only the server name.
    // server_id is taken from the Noise handshake result, not parsed here.
    if (!root["payload"]["name"].is<const char*>()) {
        SS_LOGE(TAG, "Invalid server/hello message: missing name");
        return false;
    }

    if (hello_msg != nullptr) {
        hello_msg->name = root["payload"]["name"].as<std::string>();
    }

    return true;
}

bool process_server_activate_message(JsonObject root, ServerActivateMessage* activate_msg) {
    if (!root["payload"]["activities"].is<JsonArrayConst>()) {
        SS_LOGE(TAG, "Invalid server/activate message: missing activities array");
        return false;
    }

    if (activate_msg == nullptr) {
        return true;
    }

    activate_msg->activities.clear();
    JsonArrayConst activities_array = root["payload"]["activities"].as<JsonArrayConst>();
    for (JsonVariantConst act_var : activities_array) {
        if (act_var.is<const char*>()) {
            auto act = activity_from_string(act_var.as<std::string>());
            if (act.has_value()) {
                activate_msg->activities.push_back(act.value());
            }
        }
    }

    // active_roles is optional and sticky (omitted = keep prior set).
    JsonVariantConst roles_var = root["payload"]["active_roles"];
    if (roles_var.is<JsonArrayConst>()) {
        activate_msg->active_roles = std::vector<std::string>{};
        for (JsonVariantConst role_var : roles_var.as<JsonArrayConst>()) {
            if (role_var.is<const char*>()) {
                activate_msg->active_roles->push_back(role_var.as<std::string>());
            }
        }
    } else {
        activate_msg->active_roles = std::nullopt;
    }

    // pairing object: required when 'pairing' is in activities, ignored otherwise (the
    // activities check lives in apply_server_activate, which nulls the method outside pairing).
    activate_msg->pairing_method = std::nullopt;
    activate_msg->pairing_pin_length = std::nullopt;
    JsonVariantConst pairing_var = root["payload"]["pairing"];
    if (pairing_var.is<JsonObjectConst>()) {
        JsonVariantConst method_var = pairing_var["method"];
        if (method_var.is<const char*>()) {
            activate_msg->pairing_method = pair_method_from_string(method_var.as<std::string>());
            if (!activate_msg->pairing_method.has_value()) {
                SS_LOGW(TAG, "server/activate pairing object names an unknown method: %s",
                        method_var.as<const char*>());
            }
        }
        if (pairing_var["pin_length"].is<int>()) {
            activate_msg->pairing_pin_length = pairing_var["pin_length"].as<int>();
        }
        // pairing.languages (BCP 47 tags, descending operator preference) is an informational
        // hint for SPOKEN PIN emission only. This client emits PINs through the listener's
        // display callback, so the hint is deliberately not parsed; a client adding speaker
        // emission should parse it here and apply RFC 4647 Lookup matching.
    }

    return true;
}

bool process_server_time_message(JsonObject root, int64_t timestamp, int64_t* offset,
                                 int64_t* max_error) {
    if (!root["payload"]["client_transmitted"].is<JsonVariant>() ||
        !root["payload"]["server_received"].is<JsonVariant>() ||
        !root["payload"]["server_transmitted"].is<JsonVariant>()) {
        SS_LOGE(TAG, "Invalid server/time message");
        return false;
    }

    const int64_t client_transmitted = root["payload"]["client_transmitted"];
    const int64_t server_received = root["payload"]["server_received"];
    const int64_t server_transmitted = root["payload"]["server_transmitted"];
    const int64_t client_received = timestamp;

    if (offset != nullptr) {
        *offset =
            ((server_received - client_transmitted) + (server_transmitted - client_received)) / 2;
    }

    if (max_error != nullptr) {
        const int64_t delay =
            (client_received - client_transmitted) - (server_transmitted - server_received);
        *max_error = delay / 2;
    }

    return true;
}

bool process_group_update_message(JsonObject root, GroupUpdateMessage* group_msg) {
    if (group_msg == nullptr) {
        return true;
    }

    // Parse optional playback_state
    JsonVariantConst playback_state_var = root["payload"]["playback_state"];
    if (!playback_state_var.isUnbound() && playback_state_var.isNull()) {
        // Field set to null: clear from state
        group_msg->group.playback_state = std::nullopt;
    } else if (auto state = read_enum_field(playback_state_var, "playback_state",
                                            playback_state_from_string)) {
        group_msg->group.playback_state = state;
    }

    // Parse optional group_id; use empty string to signal clearing
    JsonVariantConst group_id_var = root["payload"]["group_id"];
    if (group_id_var.is<const char*>()) {
        group_msg->group.group_id = group_id_var.as<std::string>();
    } else if (!group_id_var.isUnbound() && group_id_var.isNull()) {
        // Field set to null: use empty string to clear
        group_msg->group.group_id = "";
    }

    // Parse optional group_name; use empty string to signal clearing
    JsonVariantConst group_name_var = root["payload"]["group_name"];
    if (group_name_var.is<const char*>()) {
        group_msg->group.group_name = group_name_var.as<std::string>();
    } else if (!group_name_var.isUnbound() && group_name_var.isNull()) {
        // Field set to null: use empty string to clear
        group_msg->group.group_name = "";
    }

    return true;
}

// State delta application

void apply_group_update_deltas(GroupUpdateObject* current, const GroupUpdateObject& updates) {
    if (current == nullptr) {
        return;
    }

    // Update playback_state if present in the delta
    if (updates.playback_state.has_value()) {
        current->playback_state = updates.playback_state;
    }

    // Update group_id if present in the delta (including empty string for clearing)
    if (updates.group_id.has_value()) {
        current->group_id = updates.group_id;
    }

    // Update group_name if present in the delta (including empty string for clearing)
    if (updates.group_name.has_value()) {
        current->group_name = updates.group_name;
    }
}

bool process_server_command_message(JsonObject root, ServerCommandMessage* cmd_msg) {
    if (cmd_msg != nullptr && root["payload"]["player"].is<JsonObject>()) {
        ServerPlayerCommandObject player_cmd{};
        if (process_server_player_command_object(root["payload"]["player"], &player_cmd)) {
            cmd_msg->player = player_cmd;
            return true;
        }
        return false;
    }
    return true;
}

// server/state is parsed one section at a time rather than into a single aggregate struct. The
// caller runs on the network task (the ESP httpd task has a 4 KB stack), and an aggregate would
// keep every section's fields alive in the caller's frame for the whole parse while the section
// parser built a second copy of the same fields in its own. Each section here is an out-of-line
// function that fills a caller-owned struct directly, so only one section's storage is live at a
// time and nothing is materialized twice.

bool process_server_state_metadata(JsonObject root, ServerMetadataStateDelta* metadata_delta) {
    if (metadata_delta == nullptr || !root["payload"]["metadata"].is<JsonObject>()) {
        return false;
    }
    const JsonObject metadata_object = root["payload"]["metadata"];

    // timestamp is required (not optional)
    if (!metadata_object["timestamp"].is<JsonVariant>()) {
        SS_LOGE(TAG, "Invalid metadata state object: missing timestamp");
        return false;
    }
    metadata_delta->timestamp = metadata_object["timestamp"].as<int64_t>();

    parse_metadata_string_field(metadata_object["title"], "title", &metadata_delta->title);
    parse_metadata_string_field(metadata_object["artist"], "artist", &metadata_delta->artist);
    parse_metadata_string_field(metadata_object["album_artist"], "album_artist",
                                &metadata_delta->album_artist);
    parse_metadata_string_field(metadata_object["album"], "album", &metadata_delta->album);
    parse_metadata_string_field(metadata_object["artwork_url"], "artwork_url",
                                &metadata_delta->artwork_url);
    parse_metadata_uint16_field(metadata_object["year"], "year", &metadata_delta->year);
    parse_metadata_uint16_field(metadata_object["track"], "track", &metadata_delta->track);

    // Parse progress object: a present object engages inner, explicit null clears, absent leaves
    // outer nullopt.
    if (metadata_object["progress"].is<JsonObject>()) {
        JsonObject progress_object = metadata_object["progress"];
        MetadataProgressObject progress{};
        if (auto v =
                read_uint_field<uint32_t>(progress_object["track_progress"], "track_progress")) {
            progress.track_progress = *v;
        }
        if (auto v =
                read_uint_field<uint32_t>(progress_object["track_duration"], "track_duration")) {
            progress.track_duration = *v;
        }
        if (auto v =
                read_uint_field<uint32_t>(progress_object["playback_speed"], "playback_speed")) {
            progress.playback_speed = *v;
        }
        metadata_delta->progress = progress;
    } else if (!metadata_object["progress"].isUnbound() && metadata_object["progress"].isNull()) {
        metadata_delta->progress = std::optional<MetadataProgressObject>{};
    }

    return true;
}

bool process_server_state_color(JsonObject root, ServerColorStateDelta* color_delta) {
    if (color_delta == nullptr || !root["payload"]["color"].is<JsonObject>()) {
        return false;
    }
    const JsonObject color_object = root["payload"]["color"];

    if (!color_object["timestamp"].is<JsonVariant>()) {
        SS_LOGE(TAG, "Invalid color state object: missing timestamp");
        return false;
    }
    color_delta->timestamp = color_object["timestamp"].as<int64_t>();

    parse_color_field(color_object["background_dark"], "background_dark",
                      &color_delta->background_dark);
    parse_color_field(color_object["background_light"], "background_light",
                      &color_delta->background_light);
    parse_color_field(color_object["primary"], "primary", &color_delta->primary);
    parse_color_field(color_object["accent"], "accent", &color_delta->accent);
    parse_color_field(color_object["on_dark"], "on_dark", &color_delta->on_dark);
    parse_color_field(color_object["on_light"], "on_light", &color_delta->on_light);

    return true;
}

bool process_server_state_controller(JsonObject root,
                                     ServerStateControllerObject* controller_state) {
    if (controller_state == nullptr || !root["payload"]["controller"].is<JsonObject>()) {
        return false;
    }
    const JsonObject controller_object = root["payload"]["controller"];

    // Parse supported_commands array. The controller role is frozen at v1, so an unrecognized
    // command is a non-compliant value rather than a forward-compatible one: drop and log it.
    if (controller_object["supported_commands"].is<JsonArray>()) {
        std::vector<SendspinControllerCommand> commands;
        JsonArrayConst commands_array =
            controller_object["supported_commands"].as<JsonArrayConst>();
        for (JsonVariantConst command_var : commands_array) {
            if (auto command = read_enum_field(command_var, "supported_commands",
                                               controller_command_from_string)) {
                commands.push_back(*command);
            }
        }
        controller_state->supported_commands = std::move(commands);
    }

    // Parse volume
    if (auto v = read_uint_field<uint8_t>(controller_object["volume"], "volume", 0, VOLUME_MAX)) {
        controller_state->volume = *v;
    }

    // Parse muted
    if (auto v = read_bool_field(controller_object["muted"], "muted")) {
        controller_state->muted = *v;
    }

    // Parse repeat
    if (auto repeat =
            read_enum_field(controller_object["repeat"], "repeat", repeat_mode_from_string)) {
        controller_state->repeat = *repeat;
    }

    // Parse shuffle
    if (auto v = read_bool_field(controller_object["shuffle"], "shuffle")) {
        controller_state->shuffle = *v;
    }

    // Parse seek_max_ms. Present only when the server offers 'seek' and the range is known;
    // left absent (nullopt) otherwise so consumers can distinguish "unknown range" from 0.
    if (auto v = read_uint_field<uint32_t>(controller_object["seek_max_ms"], "seek_max_ms")) {
        controller_state->seek_max_ms = v;
    }

    return true;
}

bool process_stream_start_message(JsonObject root, StreamStartMessage* stream_msg) {
    if (stream_msg == nullptr) {
        return true;
    }

    // Each section is parsed straight into the caller's struct rather than into a local that is
    // then moved in. Both copies would otherwise be live at once in this frame, which matters on
    // the ESP httpd task (4 KB stack); on a parse failure the section is reset instead.

    if (root["payload"]["player"].is<JsonObject>()) {
        ServerPlayerStreamObject& player_obj = stream_msg->player.emplace();
        if (!process_player_stream_object(root["payload"]["player"], &player_obj, true)) {
            stream_msg->player.reset();
            return false;
        }
        if (!player_obj.is_complete()) {
            SS_LOGE(TAG, "Invalid stream/start message: incomplete player object");
            stream_msg->player.reset();
            return false;
        }
    }

    if (root["payload"]["artwork"]["channels"].is<JsonArray>()) {
        std::vector<ServerArtworkChannelObject>& channels =
            stream_msg->artwork.emplace().channels.emplace();

        JsonArray channels_array = root["payload"]["artwork"]["channels"].as<JsonArray>();
        for (JsonObject channel_json : channels_array) {
            ServerArtworkChannelObject channel{};
            if (process_artwork_channel_object(channel_json, &channel, true)) {
                if (!channel.is_complete()) {
                    SS_LOGE(TAG, "Invalid stream/start message: incomplete artwork channel");
                    stream_msg->artwork.reset();
                    return false;
                }
                channels.push_back(channel);
            } else {
                stream_msg->artwork.reset();
                return false;
            }
        }
    }

    if (root["payload"]["visualizer"].is<JsonObject>()) {
        ServerVisualizerStreamObject& vis_obj = stream_msg->visualizer.emplace();
        JsonObject vis_json = root["payload"]["visualizer"];

        // Parse types array
        if (vis_json["types"].is<JsonArray>()) {
            JsonArray types_array = vis_json["types"].as<JsonArray>();
            for (JsonVariant type_var : types_array) {
                if (auto type =
                        read_enum_field(type_var, "types", visualizer_data_type_from_string)) {
                    vis_obj.types.push_back(*type);
                }
            }
        }

        if (auto v = read_uint_field<uint16_t>(vis_json["rate_max"], "rate_max")) {
            vis_obj.rate_max = *v;
        }

        if (auto v = read_bool_field(vis_json["tracks_downbeats"], "tracks_downbeats")) {
            vis_obj.tracks_downbeats = *v;
        }

        // Parse spectrum config if present. Every field is required by the spec; if any is
        // absent or malformed, leave the config unset so the SPECTRUM validation below rejects
        // the stream rather than acting on a fabricated default.
        if (vis_json["spectrum"].is<JsonObject>()) {
            JsonObject spec_json = vis_json["spectrum"];
            auto n_disp_bins = read_uint_field<uint8_t>(spec_json["n_disp_bins"], "n_disp_bins", 1);
            auto scale =
                read_enum_field(spec_json["scale"], "scale", visualizer_spectrum_scale_from_string);
            auto f_min = read_uint_field<uint16_t>(spec_json["f_min"], "f_min");
            auto f_max = read_uint_field<uint16_t>(spec_json["f_max"], "f_max");
            if (n_disp_bins && scale && f_min && f_max) {
                vis_obj.spectrum = VisualizerSpectrumConfig{*n_disp_bins, *scale, *f_min, *f_max};
            }
        }

        // If SPECTRUM is advertised, a fully valid spectrum config must be present; otherwise the
        // expected size of binary spectrum messages is indeterminate and they could not be
        // validated. The defect is local to the visualizer object, so drop only that object and
        // let a well-formed player/artwork start in the same message go through.
        bool advertises_spectrum = false;
        for (auto type : vis_obj.types) {
            if (type == VisualizerDataType::SPECTRUM) {
                advertises_spectrum = true;
                break;
            }
        }
        if (advertises_spectrum && !vis_obj.spectrum.has_value()) {
            SS_LOGE(TAG, "Ignoring visualizer stream config: SPECTRUM advertised without valid "
                         "spectrum config");
            stream_msg->visualizer.reset();
        }
    }

    return true;
}

bool process_stream_end_message(JsonObject root, StreamEndMessage* end_msg) {
    if (end_msg == nullptr) {
        return true;
    }

    // Parse optional roles array
    if (root["payload"]["roles"].is<JsonArray>()) {
        std::vector<std::string> roles;
        JsonArray roles_array = root["payload"]["roles"].as<JsonArray>();
        for (JsonVariant role_var : roles_array) {
            if (role_var.is<const char*>()) {
                roles.push_back(role_var.as<std::string>());
            }
        }
        end_msg->roles = std::move(roles);
    }

    return true;
}

bool process_stream_clear_message(JsonObject root, StreamClearMessage* clear_msg) {
    if (clear_msg == nullptr) {
        return true;
    }

    // Parse optional roles array
    if (root["payload"]["roles"].is<JsonArray>()) {
        std::vector<std::string> roles;
        JsonArray roles_array = root["payload"]["roles"].as<JsonArray>();
        for (JsonVariant role_var : roles_array) {
            if (role_var.is<const char*>()) {
                roles.push_back(role_var.as<std::string>());
            }
        }
        clear_msg->roles = std::move(roles);
    }

    return true;
}

void apply_metadata_state_deltas(ServerMetadataStateObject* current,
                                 const ServerMetadataStateDelta& delta) {
    if (current == nullptr) {
        return;
    }

    current->timestamp = delta.timestamp;

    // For each field, an outer-engaged delta entry overwrites the merged optional with the inner
    // optional verbatim, so an inner-`nullopt` (explicit `null` on the wire) clears the merged
    // field.
    if (delta.title.has_value()) {
        current->title = *delta.title;
    }
    if (delta.artist.has_value()) {
        current->artist = *delta.artist;
    }
    if (delta.album_artist.has_value()) {
        current->album_artist = *delta.album_artist;
    }
    if (delta.album.has_value()) {
        current->album = *delta.album;
    }
    if (delta.artwork_url.has_value()) {
        current->artwork_url = *delta.artwork_url;
    }
    if (delta.year.has_value()) {
        current->year = *delta.year;
    }
    if (delta.track.has_value()) {
        current->track = *delta.track;
    }
    if (delta.progress.has_value()) {
        current->progress = *delta.progress;
    }
}

void apply_color_state_deltas(ServerColorStateObject* current, const ServerColorStateDelta& delta) {
    if (current == nullptr) {
        return;
    }

    current->timestamp = delta.timestamp;

    // For each field, an outer-engaged delta entry overwrites the merged optional with the inner
    // optional verbatim, so an inner-`nullopt` (explicit `null` on the wire) clears the merged
    // field.
    if (delta.background_dark.has_value()) {
        current->background_dark = *delta.background_dark;
    }
    if (delta.background_light.has_value()) {
        current->background_light = *delta.background_light;
    }
    if (delta.primary.has_value()) {
        current->primary = *delta.primary;
    }
    if (delta.accent.has_value()) {
        current->accent = *delta.accent;
    }
    if (delta.on_dark.has_value()) {
        current->on_dark = *delta.on_dark;
    }
    if (delta.on_light.has_value()) {
        current->on_light = *delta.on_light;
    }
}

// Message formatting

// Writes a spectrum config as the "spectrum" key of a visualizer JSON object. Shared between
// client/hello and stream/request-format so the two serializations cannot silently diverge.
static void write_visualizer_spectrum(JsonObject vis_json, const VisualizerSpectrumConfig& spec) {
    vis_json["spectrum"]["n_disp_bins"] = spec.n_disp_bins;
    vis_json["spectrum"]["scale"] = to_cstr(spec.scale);
    vis_json["spectrum"]["f_min"] = spec.f_min;
    vis_json["spectrum"]["f_max"] = spec.f_max;
}

std::string format_client_hello_message(const ClientHelloMessage* msg) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/hello";
    // Under encryption: client_id and version are carried in client/init, not repeated here.
    root["payload"]["name"] = msg->name;
    if (msg->device_info.has_value()) {
        const auto& info = msg->device_info.value();
        if (info.product_name.has_value()) {
            root["payload"]["device_info"]["product_name"] = info.product_name.value();
        }
        if (info.manufacturer.has_value()) {
            root["payload"]["device_info"]["manufacturer"] = info.manufacturer.value();
        }
        if (info.software_version.has_value()) {
            root["payload"]["device_info"]["software_version"] = info.software_version.value();
        }
        if (info.mac_address.has_value()) {
            root["payload"]["device_info"]["mac_address"] = info.mac_address.value();
        }
    }
    root["payload"]["trust_level"] = to_cstr(msg->trust_level);
    // supported_pair_methods is REQUIRED on the wire (spec "client/hello": every client implements
    // at least pairing_psk, so the field can never be legitimately absent). Always emit the array,
    // even if empty in a degenerate configuration with every method disabled.
    {
        JsonArray methods_list = root["payload"]["supported_pair_methods"].to<JsonArray>();
        for (const auto& desc : msg->supported_pair_methods) {
            JsonObject method_obj = methods_list.add<JsonObject>();
            method_obj["method"] = to_cstr(desc.method);
            if (desc.out_channels.has_value() && !desc.out_channels->empty()) {
                JsonArray ch_arr = method_obj["out_channels"].to<JsonArray>();
                for (const auto& ch : desc.out_channels.value()) {
                    ch_arr.add(ch.c_str());
                }
            }
            if (desc.min_pin_length.has_value()) {
                method_obj["min_pin_length"] = desc.min_pin_length.value();
            }
            if (desc.locations.has_value() && !desc.locations->empty()) {
                JsonArray loc_arr = method_obj["locations"].to<JsonArray>();
                for (const auto& loc : desc.locations.value()) {
                    loc_arr.add(loc.c_str());
                }
            }
        }
    }
    root["payload"]["unpaired_access"]["enabled"] = msg->unpaired_access_enabled;
    JsonArray supported_roles_list = root["payload"]["supported_roles"].to<JsonArray>();
    for (const auto& role : msg->supported_roles) {
        supported_roles_list.add(to_cstr(role));
    }

    if (msg->player_v1_support.has_value()) {
        JsonArray formats_list =
            root["payload"]["player@v1_support"]["supported_formats"].to<JsonArray>();
        for (const auto& format : msg->player_v1_support.value().supported_formats) {
            JsonObject format_obj = formats_list.add<JsonObject>();
            format_obj["codec"] = to_cstr(format.codec);
            format_obj["channels"] = format.channels;
            format_obj["sample_rate"] = format.sample_rate;
            format_obj["bit_depth"] = format.bit_depth;
        }
        root["payload"]["player@v1_support"]["buffer_capacity"] =
            msg->player_v1_support.value().buffer_capacity;
        JsonArray commands_list =
            root["payload"]["player@v1_support"]["supported_commands"].to<JsonArray>();
        for (const auto& cmd : msg->player_v1_support.value().supported_commands) {
            commands_list.add(to_cstr(cmd));
        }
    }

    if (msg->artwork_v1_support.has_value()) {
        JsonArray channels_list = root["payload"]["artwork@v1_support"]["channels"].to<JsonArray>();
        for (const auto& channel : msg->artwork_v1_support.value().channels) {
            JsonObject channel_obj = channels_list.add<JsonObject>();
            channel_obj["source"] = to_cstr(channel.source);
            channel_obj["format"] = to_cstr(channel.format);
            channel_obj["media_width"] = channel.media_width;
            channel_obj["media_height"] = channel.media_height;
        }
    }

    if (msg->visualizer_support.has_value()) {
        const auto& vis = msg->visualizer_support.value();
        JsonObject vis_json = root["payload"]["visualizer@v1_support"].to<JsonObject>();
        JsonArray types_list = vis_json["types"].to<JsonArray>();
        for (const auto& type : vis.types) {
            types_list.add(to_cstr(type));
        }
        vis_json["buffer_capacity"] = vis.buffer_capacity;
        vis_json["rate_max"] = vis.rate_max;
        if (vis.spectrum.has_value()) {
            write_visualizer_spectrum(vis_json, vis.spectrum.value());
        }
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_state_message(const ClientStateMessage* msg) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/state";
    root["payload"]["state"] = to_cstr(msg->state);

    if (msg->player.has_value()) {
        const ClientPlayerStateObject& player_state = msg->player.value();
        root["payload"]["player"]["volume"] = player_state.volume;
        root["payload"]["player"]["muted"] = player_state.muted;
        root["payload"]["player"]["static_delay_ms"] = player_state.static_delay_ms;
        if (!player_state.supported_commands.empty()) {
            JsonArray commands_list =
                root["payload"]["player"]["supported_commands"].to<JsonArray>();
            for (const auto& cmd : player_state.supported_commands) {
                commands_list.add(to_cstr(cmd));
            }
        }
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_stream_request_format_message(const StreamRequestFormatMessage* msg) {
    (void)msg;

    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "stream/request-format";

    if (msg->player.has_value()) {
        const auto& player = msg->player.value();
        if (player.codec.has_value()) {
            root["payload"]["player"]["codec"] = to_cstr(player.codec.value());
        }
        if (player.sample_rate.has_value()) {
            root["payload"]["player"]["sample_rate"] = player.sample_rate.value();
        }
        if (player.channels.has_value()) {
            root["payload"]["player"]["channels"] = player.channels.value();
        }
        if (player.bit_depth.has_value()) {
            root["payload"]["player"]["bit_depth"] = player.bit_depth.value();
        }
    }

    if (msg->artwork.has_value()) {
        const auto& artwork = msg->artwork.value();
        root["payload"]["artwork"]["channel"] = artwork.channel;
        if (artwork.source.has_value()) {
            root["payload"]["artwork"]["source"] = to_cstr(artwork.source.value());
        }
        if (artwork.format.has_value()) {
            root["payload"]["artwork"]["format"] = to_cstr(artwork.format.value());
        }
        if (artwork.media_width.has_value()) {
            root["payload"]["artwork"]["media_width"] = artwork.media_width.value();
        }
        if (artwork.media_height.has_value()) {
            root["payload"]["artwork"]["media_height"] = artwork.media_height.value();
        }
    }

    if (msg->visualizer.has_value()) {
        const auto& vis = msg->visualizer.value();
        // Only create the "visualizer" key when at least one field is set: an all-empty request
        // must emit no key at all, since a present-but-empty object could read as "reset to
        // defaults" rather than "no change" on the server.
        if (vis.types.has_value() || vis.rate_max.has_value() || vis.spectrum.has_value()) {
            JsonObject vis_json = root["payload"]["visualizer"].to<JsonObject>();
            if (vis.types.has_value()) {
                JsonArray types_list = vis_json["types"].to<JsonArray>();
                for (const auto& type : vis.types.value()) {
                    types_list.add(to_cstr(type));
                }
            }
            if (vis.rate_max.has_value()) {
                vis_json["rate_max"] = vis.rate_max.value();
            }
            if (vis.spectrum.has_value()) {
                write_visualizer_spectrum(vis_json, vis.spectrum.value());
            }
        }
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_goodbye_message(SendspinGoodbyeReason reason) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/goodbye";
    root["payload"]["reason"] = to_cstr(reason);

    std::string output;
    serializeJson(doc, output);
    return output;
}

namespace {

/// Maximum decimal digits in a uint64_t value.
constexpr int MAX_UINT64_DIGITS = 19;

/// Radix used for two-digit-at-a-time integer formatting.
constexpr uint64_t RADIX_100 = 100U;

/// Threshold for single vs. two-digit final write.
constexpr uint64_t RADIX_10 = 10U;

// Two-digit ASCII lookup. Index 2*N..2*N+1 holds the decimal digits of N for N in [0, 99].
// Lets us emit two characters per 64-bit division instead of one, halving the libgcc
// __udivdi3 calls, which are the expensive part on a 32-bit MCU.
constexpr char TWO_DIGIT_TABLE[201] = "00010203040506070809"
                                      "10111213141516171819"
                                      "20212223242526272829"
                                      "30313233343536373839"
                                      "40414243444546474849"
                                      "50515253545556575859"
                                      "60616263646566676869"
                                      "70717273747576777879"
                                      "80818283848586878889"
                                      "90919293949596979899";

// log10(v) + 1, computed without any division. Uses clz to get an approximate base-10 length
// from the base-2 length, then a single table comparison to round to the exact value.
inline int decimal_digits(uint64_t v) {
    if (v == 0U) {
        return 1;
    }
    // floor(log2(v)) for v != 0
    const int log2 = 63 - __builtin_clzll(v);
    // floor(log10(v)) ≈ floor(log2(v) * log10(2)). 1233 / 4096 ≈ 0.30108, accurate to within 1.
    const int approx = (log2 * 1233) >> 12;
    static constexpr uint64_t POW10[20] = {1ULL,
                                           10ULL,
                                           100ULL,
                                           1000ULL,
                                           10000ULL,
                                           100000ULL,
                                           1000000ULL,
                                           10000000ULL,
                                           100000000ULL,
                                           1000000000ULL,
                                           10000000000ULL,
                                           100000000000ULL,
                                           1000000000000ULL,
                                           10000000000000ULL,
                                           100000000000000ULL,
                                           1000000000000000ULL,
                                           10000000000000000ULL,
                                           100000000000000000ULL,
                                           1000000000000000000ULL,
                                           10000000000000000000ULL};
    return approx + 1 + static_cast<int>(v >= POW10[approx + 1]);
}

}  // namespace

size_t format_client_time_message(char* buf, size_t cap, int64_t client_transmitted) {
    // Hot path on the time-sync send side. ESP-IDF newlib's snprintf("%lld", ...) costs ~50us
    // for a single int64 because it instantiates a full printf state machine and does 64-bit
    // division through generic code. We bypass it entirely: memcpy the two constant chunks
    // around a hand-rolled int64-to-decimal conversion that uses clz for digit count and a
    // two-digit-at-a-time write to halve the 64-bit division count.
    static constexpr char PREFIX[] = R"({"type":"client/time","payload":{"client_transmitted":)";
    static constexpr size_t PREFIX_LEN = sizeof(PREFIX) - 1;
    static constexpr char SUFFIX[] = "}}";
    static constexpr size_t SUFFIX_LEN = sizeof(SUFFIX) - 1;

    // Worst case: prefix + '-' + MAX_UINT64_DIGITS digits + suffix.
    if (cap < PREFIX_LEN + 1 + MAX_UINT64_DIGITS + SUFFIX_LEN) {
        return 0;
    }

    char* p = buf;
    std::memcpy(p, PREFIX, PREFIX_LEN);
    p += PREFIX_LEN;

    uint64_t v = 0;
    if (client_transmitted < 0) {
        *p++ = '-';
        // Cast through uint64_t to handle INT64_MIN without UB
        v = static_cast<uint64_t>(-(client_transmitted + 1)) + 1U;
    } else {
        v = static_cast<uint64_t>(client_transmitted);
    }

    // Place the digit cursor at the end of the integer field and write backwards, two digits
    // per loop iteration. The clz-based digit count means we know exactly where to start.
    const int n = decimal_digits(v);
    char* end = p + n;
    char* w = end;
    while (v >= RADIX_100) {
        const uint64_t q = v / RADIX_100;
        const auto r = static_cast<size_t>(v - q * RADIX_100);
        w -= 2;
        std::memcpy(w, &TWO_DIGIT_TABLE[r * 2U], 2);
        v = q;
    }
    if (v >= RADIX_10) {
        w -= 2;
        std::memcpy(w, &TWO_DIGIT_TABLE[static_cast<size_t>(v) * 2U], 2);
    } else {
        w -= 1;
        *w = static_cast<char>('0' + v);
    }
    p = end;

    std::memcpy(p, SUFFIX, SUFFIX_LEN);
    p += SUFFIX_LEN;

    return static_cast<size_t>(p - buf);
}

std::string format_client_command_message(const ClientCommandControllerObject& cmd) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/command";
    JsonObject controller = root["payload"]["controller"].to<JsonObject>();
    controller["command"] = to_cstr(cmd.command);
    if (cmd.command == SendspinControllerCommand::VOLUME && cmd.volume.has_value()) {
        controller["volume"] = cmd.volume.value();
    }
    if (cmd.command == SendspinControllerCommand::MUTE && cmd.muted.has_value()) {
        controller["mute"] = cmd.muted.value();
    }
    if (cmd.command == SendspinControllerCommand::SEEK && cmd.position_ms.has_value()) {
        controller["position_ms"] = cmd.position_ms.value();
    }
    if (cmd.command == SendspinControllerCommand::SEEK_RELATIVE && cmd.offset_ms.has_value()) {
        controller["offset_ms"] = cmd.offset_ms.value();
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

// ============================================================================
// Pairing-PSK protocol messages
// ============================================================================

std::string format_client_pair_finalize_message(const std::array<uint8_t, 32>& psk) {
    // Zeroizing document: the JSON pool holds the base64 long-term PSK, which admits a server
    // permanently. The caller wipes the returned string once it has been sent (see
    // handle_enter_pairing_psk()); everything staged on the way there is wiped here.
    JsonDocument doc = make_zeroizing_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-finalize";
    // Encode the 32-byte PSK as 43-char base64url (no padding).
    std::string psk_b64 = b64url_encode(psk.data(), psk.size());
    root["payload"]["long_term_psk"] = psk_b64;
    secure_zero(psk_b64.data(), psk_b64.size());

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_finalize_wrapped_message(
    const std::array<uint8_t, 48>& wrapped_psk) {
    // Zeroizing document to match format_client_pair_finalize_message(); see the note there.
    JsonDocument doc = make_zeroizing_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-finalize";
    // Encode the 48-byte wrapped PSK as 64-char base64url (no padding). PIN flows only (spec
    // "PSK Wrapping"); exactly one of long_term_psk/wrapped_psk is present per message.
    root["payload"]["wrapped_psk"] = b64url_encode(wrapped_psk.data(), wrapped_psk.size());

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_pair_abort_message(PairAbortReason reason) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "pair/abort";
    root["payload"]["reason"] = to_cstr(reason);

    std::string output;
    serializeJson(doc, output);
    return output;
}

bool process_pair_abort_message(JsonObject root, PairAbortMessage* abort_msg) {
    if (!root["payload"]["reason"].is<const char*>()) {
        SS_LOGE(TAG, "Invalid pair/abort message: missing reason");
        return false;
    }

    if (abort_msg == nullptr) {
        return true;
    }

    const std::string reason_str = root["payload"]["reason"].as<std::string>();
    auto reason = pair_abort_reason_from_string(reason_str);
    if (!reason.has_value()) {
        SS_LOGW(TAG, "pair/abort: unrecognized reason '%s'", reason_str.c_str());
        return false;
    }

    abort_msg->reason = reason.value();
    return true;
}

// ============================================================================
// Dynamic-PIN pairing protocol functions
// ============================================================================

bool process_server_pair_init_message(JsonObject root, ServerPairInitPayload* payload) {
    // Required field: nonce_A (base64url, 43 chars -> 32 bytes). The session pin_length is not
    // carried here; it arrived in the activation's pairing object.
    if (!root["payload"]["nonce_A"].is<const char*>()) {
        SS_LOGE(TAG, "server/pair-init: missing nonce_A");
        return false;
    }

    if (payload == nullptr) {
        return true;
    }

    const std::string nonce_a_b64 = root["payload"]["nonce_A"].as<std::string>();
    auto nonce_a_bytes = b64url_decode(nonce_a_b64);
    if (!nonce_a_bytes.has_value() || nonce_a_bytes->size() != 32) {
        SS_LOGE(TAG, "server/pair-init: nonce_A is not 32 bytes");
        return false;
    }
    std::memcpy(payload->nonce_a.data(), nonce_a_bytes->data(), 32);

    return true;
}

bool process_server_pair_auth_message(JsonObject root, ServerPairAuthPayload* payload) {
    if (!root["payload"]["pake_msg_1"].is<const char*>()) {
        SS_LOGE(TAG, "server/pair-auth: missing pake_msg_1");
        return false;
    }

    if (payload == nullptr) {
        return true;
    }

    const std::string msg1_b64 = root["payload"]["pake_msg_1"].as<std::string>();
    auto msg1_bytes = b64url_decode(msg1_b64);
    if (!msg1_bytes.has_value() || msg1_bytes->size() != 32) {
        SS_LOGE(TAG, "server/pair-auth: pake_msg_1 is not 32 bytes");
        return false;
    }
    std::memcpy(payload->pake_msg_1.data(), msg1_bytes->data(), 32);
    return true;
}

bool process_server_pair_confirm_message(JsonObject root, ServerPairConfirmPayload* payload) {
    if (!root["payload"]["server_kc"].is<const char*>()) {
        SS_LOGE(TAG, "server/pair-confirm: missing server_kc");
        return false;
    }

    if (payload == nullptr) {
        return true;
    }

    const std::string kc_b64 = root["payload"]["server_kc"].as<std::string>();
    auto kc_bytes = b64url_decode(kc_b64);
    if (!kc_bytes.has_value() || kc_bytes->size() != 64) {
        SS_LOGE(TAG, "server/pair-confirm: server_kc is not 64 bytes");
        return false;
    }
    std::memcpy(payload->server_kc.data(), kc_bytes->data(), 64);
    return true;
}

std::string format_client_pair_pending_message(uint32_t pairing_index) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-pending";
    root["payload"]["pairing_index"] = pairing_index;

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_init_message(const std::array<uint8_t, 32>& commit_b,
                                            uint32_t pairing_index) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-init";
    root["payload"]["commit_B"] = b64url_encode(commit_b.data(), commit_b.size());
    root["payload"]["pairing_index"] = pairing_index;

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_init_message(uint32_t pairing_index) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-init";
    // Static PIN: no commit_B, but pairing_index is required on every client/pair-init (spec
    // "PAKE").
    root["payload"]["pairing_index"] = pairing_index;

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_auth_message(const std::array<uint8_t, 32>& pake_msg_2) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-auth";
    root["payload"]["pake_msg_2"] = b64url_encode(pake_msg_2.data(), pake_msg_2.size());

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_confirm_message(const std::array<uint8_t, 64>& client_kc,
                                               const std::array<uint8_t, 32>& nonce_b) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-confirm";
    root["payload"]["client_kc"] = b64url_encode(client_kc.data(), client_kc.size());
    root["payload"]["nonce_B"] = b64url_encode(nonce_b.data(), nonce_b.size());

    std::string output;
    serializeJson(doc, output);
    return output;
}

std::string format_client_pair_confirm_message(const std::array<uint8_t, 64>& client_kc) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/pair-confirm";
    // Static PIN: no nonce_B opening (there was no commit_B to open).
    root["payload"]["client_kc"] = b64url_encode(client_kc.data(), client_kc.size());

    std::string output;
    serializeJson(doc, output);
    return output;
}

// ============================================================================
// Management protocol functions
// ============================================================================

bool process_management_add_record_message(JsonObject root, ManagementAddRecordPayload* payload) {
    if (!root["payload"]["psk"].is<const char*>()) {
        SS_LOGE(TAG, "management/add-record: missing psk field");
        return false;
    }

    if (payload == nullptr) {
        return true;
    }

    payload->psk = root["payload"]["psk"].as<std::string>();

    // server_id is optional (absent for shared-PSK records).
    JsonVariantConst server_id_var = root["payload"]["server_id"];
    if (server_id_var.is<const char*>()) {
        payload->server_id = server_id_var.as<std::string>();
    } else {
        payload->server_id = std::nullopt;
    }

    return true;
}

bool process_management_remove_record_message(JsonObject root,
                                              ManagementRemoveRecordPayload* payload) {
    if (!root["payload"]["psk_id"].is<const char*>()) {
        SS_LOGE(TAG, "management/remove-record: missing psk_id field");
        return false;
    }

    if (payload == nullptr) {
        return true;
    }

    payload->psk_id = root["payload"]["psk_id"].as<std::string>();
    return true;
}

bool process_management_set_pairing_config_message(JsonObject root,
                                                   ManagementSetPairingConfigPayload* payload) {
    if (payload == nullptr) {
        return true;
    }

    if (root["payload"]["pairing_psk"].is<JsonObject>()) {
        SetPairingPskConfig psk_cfg;
        JsonObject psk_obj = root["payload"]["pairing_psk"].as<JsonObject>();
        if (psk_obj["enabled"].is<bool>()) {
            psk_cfg.enabled = psk_obj["enabled"].as<bool>();
        }
        if (psk_obj["psk"].is<const char*>()) {
            psk_cfg.psk = psk_obj["psk"].as<std::string>();
        }
        payload->pairing_psk = std::move(psk_cfg);
    }

    if (root["payload"]["static_pin"].is<JsonObject>()) {
        SetStaticPinConfig static_cfg;
        JsonObject static_obj = root["payload"]["static_pin"].as<JsonObject>();
        if (static_obj["enabled"].is<bool>()) {
            static_cfg.enabled = static_obj["enabled"].as<bool>();
        }
        if (static_obj["pin"].is<const char*>()) {
            static_cfg.pin = static_obj["pin"].as<std::string>();
        }
        payload->static_pin = std::move(static_cfg);
    }

    if (root["payload"]["dynamic_pin"].is<JsonObject>()) {
        SetDynamicPinConfig dynamic_cfg;
        JsonObject dynamic_obj = root["payload"]["dynamic_pin"].as<JsonObject>();
        if (dynamic_obj["enabled"].is<bool>()) {
            dynamic_cfg.enabled = dynamic_obj["enabled"].as<bool>();
        }
        if (dynamic_obj["min_pin_length"].is<int>()) {
            dynamic_cfg.min_pin_length = dynamic_obj["min_pin_length"].as<int>();
        }
        payload->dynamic_pin = dynamic_cfg;
    }

    if (root["payload"]["record_mode"].is<JsonObject>()) {
        JsonObject rm_obj = root["payload"]["record_mode"].as<JsonObject>();
        if (rm_obj["psk_id"].is<const char*>()) {
            RecordModeConfig rm;
            rm.psk_id = rm_obj["psk_id"].as<std::string>();
            payload->record_mode = std::move(rm);
        }
    }

    if (root["payload"]["unpaired_access"].is<JsonObject>()) {
        JsonObject ua_obj = root["payload"]["unpaired_access"].as<JsonObject>();
        UnpairedAccessConfig ua;
        if (ua_obj["enabled"].is<bool>()) {
            ua.enabled = ua_obj["enabled"].as<bool>();
        }
        payload->unpaired_access = ua;
    }

    return true;
}

std::string format_management_result_message(const ManagementResultPayload& payload) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "management/result";
    root["payload"]["result"] = to_cstr(payload.result);

    if (payload.data.has_value()) {
        const ManagementResultData& data = payload.data.value();

        // records (list-records result)
        if (data.records.has_value()) {
            JsonArray records_arr = root["payload"]["data"]["records"].to<JsonArray>();
            for (const auto& rec : data.records.value()) {
                JsonObject rec_obj = records_arr.add<JsonObject>();
                rec_obj["psk_id"] = rec.psk_id;
                if (rec.server_id.has_value()) {
                    rec_obj["server_id"] = rec.server_id.value();
                }
                rec_obj["used"] = rec.used;
            }
        }

        // pairing_psk (get-pairing-config result): enabled only, no secrets.
        if (data.pairing_psk.has_value()) {
            root["payload"]["data"]["pairing_psk"]["enabled"] = data.pairing_psk->enabled;
        }

        // static_pin (get-pairing-config result): enabled only; min_pin_length and escalated
        // never set for static_pin (omitted per PairingMethodConfig contract).
        if (data.static_pin.has_value()) {
            const PairingMethodConfig& cfg = data.static_pin.value();
            root["payload"]["data"]["static_pin"]["enabled"] = cfg.enabled;
            if (cfg.min_pin_length.has_value()) {
                root["payload"]["data"]["static_pin"]["min_pin_length"] =
                    cfg.min_pin_length.value();
            }
        }

        // dynamic_pin (get-pairing-config result): enabled always; min_pin_length and
        // escalated only when set.
        if (data.dynamic_pin.has_value()) {
            const PairingMethodConfig& cfg = data.dynamic_pin.value();
            root["payload"]["data"]["dynamic_pin"]["enabled"] = cfg.enabled;
            if (cfg.min_pin_length.has_value()) {
                root["payload"]["data"]["dynamic_pin"]["min_pin_length"] =
                    cfg.min_pin_length.value();
            }
            if (cfg.escalated.has_value()) {
                root["payload"]["data"]["dynamic_pin"]["escalated"] = cfg.escalated.value();
            }
        }

        // record_mode (get-pairing-config result)
        if (data.record_mode.has_value()) {
            root["payload"]["data"]["record_mode"]["psk_id"] = data.record_mode->psk_id;
        }

        // unpaired_access (get-pairing-config result): always emit enabled when the object is
        // present. The spec requires unpaired_access:{enabled:<bool>} in every get-config result.
        if (data.unpaired_access.has_value()) {
            root["payload"]["data"]["unpaired_access"]["enabled"] =
                data.unpaired_access->enabled.value_or(false);
        }
    }

    // storage (optional accounting)
    if (payload.storage.has_value()) {
        const StorageAccountingPayload& storage = payload.storage.value();
        root["payload"]["storage"]["free"] = storage.free;
        if (storage.capacity.has_value()) {
            root["payload"]["storage"]["capacity"] = storage.capacity.value();
        }
        if (storage.cost_individual.has_value()) {
            root["payload"]["storage"]["cost_individual"] = storage.cost_individual.value();
        }
        if (storage.cost_shared.has_value()) {
            root["payload"]["storage"]["cost_shared"] = storage.cost_shared.value();
        }
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

}  // namespace sendspin
