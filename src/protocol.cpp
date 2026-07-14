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

#include "platform/logging.h"
#include "platform/memory.h"
#include "protocol_messages.h"
#include <ArduinoJson.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>

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

static bool process_server_metadata_state_object(const JsonObject metadata_object,
                                                 ServerMetadataStateDelta* metadata_delta) {
    if (metadata_delta == nullptr) {
        return false;
    }

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

    // Parse progress object - present object engages inner; explicit null clears; absent leaves
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
    *out = color;
}

static bool process_server_color_state_object(const JsonObject color_object,
                                              ServerColorStateDelta* color_delta) {
    if (color_delta == nullptr) {
        return false;
    }

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

    return SendspinServerToClientMessageType::UNKNOWN;
}

// Message processing

bool process_server_hello_message(JsonObject root, ServerHelloMessage* hello_msg) {
    if (!root["payload"]["server_id"].is<JsonVariant>() ||
        !root["payload"]["name"].is<JsonVariant>() ||
        !root["payload"]["version"].is<JsonVariant>() ||
        !root["payload"]["active_roles"].is<JsonVariant>() ||
        !root["payload"]["connection_reason"].is<const char*>()) {
        SS_LOGE(TAG, "Invalid server/hello message");
        return false;
    }

    if (hello_msg != nullptr) {
        hello_msg->server.server_id = root["payload"]["server_id"].as<std::string>();
        hello_msg->server.name = root["payload"]["name"].as<std::string>();
        auto version = read_uint_field<uint16_t>(root["payload"]["version"], "version");
        if (!version.has_value()) {
            SS_LOGE(TAG, "Invalid version in server/hello message");
            return false;
        }
        hello_msg->version = *version;

        // Parse active_roles array
        hello_msg->active_roles.clear();
        JsonArrayConst active_roles_array = root["payload"]["active_roles"].as<JsonArrayConst>();
        for (JsonVariantConst role_var : active_roles_array) {
            if (role_var.is<const char*>()) {
                hello_msg->active_roles.push_back(role_var.as<std::string>());
            }
        }

        auto reason =
            connection_reason_from_string(root["payload"]["connection_reason"].as<std::string>());
        if (!reason.has_value()) {
            SS_LOGE(TAG, "Invalid connection_reason in server/hello message: %s",
                    root["payload"]["connection_reason"].as<const char*>());
            return false;
        }
        hello_msg->connection_reason = reason.value();
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
        // Field set to null - clear from state
        group_msg->group.playback_state = std::nullopt;
    } else if (auto state = read_enum_field(playback_state_var, "playback_state",
                                            playback_state_from_string)) {
        group_msg->group.playback_state = state;
    }

    // Parse optional group_id - use empty string to signal clearing
    JsonVariantConst group_id_var = root["payload"]["group_id"];
    if (group_id_var.is<const char*>()) {
        group_msg->group.group_id = group_id_var.as<std::string>();
    } else if (!group_id_var.isUnbound() && group_id_var.isNull()) {
        // Field set to null - use empty string to clear
        group_msg->group.group_id = "";
    }

    // Parse optional group_name - use empty string to signal clearing
    JsonVariantConst group_name_var = root["payload"]["group_name"];
    if (group_name_var.is<const char*>()) {
        group_msg->group.group_name = group_name_var.as<std::string>();
    } else if (!group_name_var.isUnbound() && group_name_var.isNull()) {
        // Field set to null - use empty string to clear
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

bool process_server_state_message(JsonObject root, ServerStateMessage* state_msg) {
    if (state_msg == nullptr) {
        return true;
    }

    (void)root;

    // Parse optional metadata object
    if (root["payload"]["metadata"].is<JsonObject>()) {
        ServerMetadataStateDelta metadata_delta{};
        if (process_server_metadata_state_object(root["payload"]["metadata"], &metadata_delta)) {
            state_msg->metadata = std::move(metadata_delta);
        }
    }

    if (root["payload"]["color"].is<JsonObject>()) {
        ServerColorStateDelta color_delta{};
        if (process_server_color_state_object(root["payload"]["color"], &color_delta)) {
            state_msg->color = color_delta;
        }
    }

    if (root["payload"]["controller"].is<JsonObject>()) {
        ServerStateControllerObject controller_state{};
        JsonObject controller_object = root["payload"]["controller"];

        // Parse supported_commands array. The controller role is frozen at v1, so an unrecognized
        // command is a non-compliant value rather than a forward-compatible one: drop and log it.
        if (controller_object["supported_commands"].is<JsonArray>()) {
            std::vector<SendspinControllerCommand> commands;
            for (JsonVariantConst command_var :
                 controller_object["supported_commands"].as<JsonArrayConst>()) {
                if (auto command = read_enum_field(command_var, "supported_commands",
                                                   controller_command_from_string)) {
                    commands.push_back(*command);
                }
            }
            controller_state.supported_commands = std::move(commands);
        }

        // Parse volume
        if (auto v =
                read_uint_field<uint8_t>(controller_object["volume"], "volume", 0, VOLUME_MAX)) {
            controller_state.volume = *v;
        }

        // Parse muted
        if (auto v = read_bool_field(controller_object["muted"], "muted")) {
            controller_state.muted = *v;
        }

        // Parse repeat
        if (auto repeat =
                read_enum_field(controller_object["repeat"], "repeat", repeat_mode_from_string)) {
            controller_state.repeat = *repeat;
        }

        // Parse shuffle
        if (auto v = read_bool_field(controller_object["shuffle"], "shuffle")) {
            controller_state.shuffle = *v;
        }

        state_msg->controller = std::move(controller_state);
    }

    return true;
}

bool process_stream_start_message(JsonObject root, StreamStartMessage* stream_msg) {
    if (stream_msg == nullptr) {
        return true;
    }

    (void)root;

    if (root["payload"]["player"].is<JsonObject>()) {
        ServerPlayerStreamObject player_obj{};
        if (process_player_stream_object(root["payload"]["player"], &player_obj, true)) {
            if (!player_obj.is_complete()) {
                SS_LOGE(TAG, "Invalid stream/start message: incomplete player object");
                return false;
            }
            stream_msg->player = std::move(player_obj);
        } else {
            return false;
        }
    }

    if (root["payload"]["artwork"]["channels"].is<JsonArray>()) {
        ServerArtworkStreamObject artwork_obj{};
        std::vector<ServerArtworkChannelObject> channels;

        JsonArray channels_array = root["payload"]["artwork"]["channels"].as<JsonArray>();
        for (JsonObject channel_json : channels_array) {
            ServerArtworkChannelObject channel{};
            if (process_artwork_channel_object(channel_json, &channel, true)) {
                if (!channel.is_complete()) {
                    SS_LOGE(TAG, "Invalid stream/start message: incomplete artwork channel");
                    return false;
                }
                channels.push_back(channel);
            } else {
                return false;
            }
        }
        artwork_obj.channels = std::move(channels);
        stream_msg->artwork = std::move(artwork_obj);
    }

    if (root["payload"]["visualizer"].is<JsonObject>()) {
        ServerVisualizerStreamObject vis_obj{};
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
        } else {
            stream_msg->visualizer = std::move(vis_obj);
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
    root["payload"]["client_id"] = msg->client_id;
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
    root["payload"]["version"] = msg->version;
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

std::string format_client_command_message(SendspinControllerCommand command,
                                          std::optional<uint8_t> volume, std::optional<bool> mute) {
    JsonDocument doc = make_json_document();
    JsonObject root = doc.to<JsonObject>();

    root["type"] = "client/command";
    root["payload"]["controller"]["command"] = to_cstr(command);
    if (command == SendspinControllerCommand::VOLUME && volume.has_value()) {
        root["payload"]["controller"]["volume"] = volume.value();
    }
    if (command == SendspinControllerCommand::MUTE && mute.has_value()) {
        root["payload"]["controller"]["mute"] = mute.value();
    }

    std::string output;
    serializeJson(doc, output);
    return output;
}

}  // namespace sendspin
