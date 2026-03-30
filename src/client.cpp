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

#include "sendspin/client.h"

#include "connection.h"
#include "connection_manager.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
#include "platform/thread_safe_queue.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "time_burst.h"
#include <ArduinoJson.h>

#include <algorithm>
#include <cstring>

static const char* const TAG = "sendspin.client";

namespace sendspin {

struct SendspinClient::EventState {
    ThreadSafeQueue<TimeResponseEvent> time_queue;
    ShadowSlot<GroupUpdateObject> shadow_group;
};

// --- Constructor / Destructor ---

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      connection_manager_(std::make_unique<ConnectionManager>(this)),
      time_burst_(std::make_unique<SendspinTimeBurst>()),
      event_state_(std::make_unique<EventState>()) {
    this->event_state_->time_queue.create(16);
}

SendspinClient::~SendspinClient() {
    // Stop background threads before tearing down connections.
    this->player_.reset();
    this->visualizer_.reset();
    this->connection_manager_.reset();
}

void SendspinClient::set_log_level(LogLevel level) {
    platform_set_log_level(static_cast<int>(level));
}

LogLevel SendspinClient::get_log_level() {
    return static_cast<LogLevel>(platform_get_log_level());
}

// --- Role services ---

void SendspinClient::publish_state() {
    this->publish_client_state_(this->connection_manager_->current());
}

void SendspinClient::send_text(const std::string& text) {
    auto* conn = this->connection_manager_->current();
    if (conn != nullptr && conn->is_connected()) {
        conn->send_text_message(text, nullptr);
    }
}

void SendspinClient::acquire_high_performance() {
    if (this->high_performance_ref_count_.fetch_add(1) == 0 && this->listener_) {
        this->listener_->on_request_high_performance();
    }
}

void SendspinClient::release_high_performance() {
    if (this->high_performance_ref_count_.load() == 0) {
        return;
    }
    if (this->high_performance_ref_count_.fetch_sub(1) == 1 && this->listener_) {
        this->listener_->on_release_high_performance();
    }
}

// --- Connection event handlers ---

void SendspinClient::on_handshake_complete_(SendspinConnection* conn,
                                            ServerInformationObject server) {
    this->server_information_ = std::move(server);
    this->publish_client_state_(conn);
}

// --- Role registration ---

PlayerRole& SendspinClient::add_player(PlayerRole::Config config) {
    if (this->started_) {
        SS_LOGW(TAG,
                "add_player() called after start_server() — role may not initialize correctly");
    }
    this->player_ =
        std::make_unique<PlayerRole>(std::move(config), this, this->persistence_provider_);
    return *this->player_;
}

ControllerRole& SendspinClient::add_controller() {
    if (this->started_) {
        SS_LOGW(TAG, "add_controller() called after start_server()");
    }
    this->controller_ = std::make_unique<ControllerRole>(this);
    return *this->controller_;
}

MetadataRole& SendspinClient::add_metadata() {
    if (this->started_) {
        SS_LOGW(TAG, "add_metadata() called after start_server()");
    }
    this->metadata_ = std::make_unique<MetadataRole>(this);
    return *this->metadata_;
}

ArtworkRole& SendspinClient::add_artwork() {
    if (this->started_) {
        SS_LOGW(TAG, "add_artwork() called after start_server()");
    }
    this->artwork_ = std::make_unique<ArtworkRole>(this);
    return *this->artwork_;
}

VisualizerRole& SendspinClient::add_visualizer(VisualizerRole::Config config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_visualizer() called after start_server()");
    }
    this->visualizer_ = std::make_unique<VisualizerRole>(std::move(config), this);
    return *this->visualizer_;
}

// --- Lifecycle ---

bool SendspinClient::start_server(unsigned priority) {
    this->started_ = true;

    // Load persisted state
    this->load_last_played_server_();

    if (this->player_) {
        if (!this->player_->start(this->config_.psram_stack)) {
            return false;
        }
    }

    if (this->visualizer_) {
        if (!this->visualizer_->start()) {
            return false;
        }
    }

    // Create and configure the WebSocket server (started later when network is ready)
    this->connection_manager_->init_server(this, this->config_.psram_stack, priority);

    return true;
}

void SendspinClient::connect_to(const std::string& url) {
    this->connection_manager_->connect_to(url);
}

void SendspinClient::disconnect(SendspinGoodbyeReason reason) {
    this->connection_manager_->disconnect(reason);
}

void SendspinClient::loop() {
    // Process connection lifecycle events (close, disconnect, hello, handoff, retry)
    this->connection_manager_->loop();

    // Handle time synchronization for the active connection via burst strategy
    auto* conn = this->connection_manager_->current();
    if (conn != nullptr) {
        auto result = this->time_burst_->loop(conn);

        if (result.sent && !this->high_performance_held_for_time_) {
            this->acquire_high_performance();
            this->high_performance_held_for_time_ = true;
        }
        if (result.burst_completed && this->high_performance_held_for_time_) {
            this->release_high_performance();
            this->high_performance_held_for_time_ = false;
        }
        if (result.burst_completed && this->listener_ && conn->get_time_filter()) {
            this->listener_->on_time_sync_updated(
                static_cast<float>(conn->get_time_filter()->get_error()));
        }
    }

    // Process deferred events -- all state mutations and user callbacks happen here,
    // on the main loop thread, to avoid cross-thread data races.
    // Each role drains its own queues/shadows internally.

    // --- Time sync events ---
    {
        TimeResponseEvent time_event;
        while (this->event_state_->time_queue.receive(time_event, 0)) {
            auto* current = this->connection_manager_->current();
            if (current != nullptr) {
                this->time_burst_->on_time_response(current, time_event.offset,
                                                    time_event.max_error, time_event.timestamp);
            }
        }
    }

    // --- Role events (each role handles its own synchronization) ---
    if (this->player_) {
        this->player_->drain_events();
    }
    if (this->controller_) {
        this->controller_->drain_events();
    }
    if (this->metadata_) {
        this->metadata_->drain_events();
    }
    if (this->artwork_) {
        this->artwork_->drain_events();
    }
    if (this->visualizer_) {
        this->visualizer_->drain_events();
    }

    // --- Group update events ---
    {
        GroupUpdateObject group_delta;
        if (this->event_state_->shadow_group.take(group_delta)) {
            apply_group_update_deltas(&this->group_state_, group_delta);

            if (this->listener_) {
                this->listener_->on_group_update(group_delta);
            }

            // Persist last played server when playback starts
            if (group_delta.playback_state.has_value() &&
                group_delta.playback_state.value() == SendspinPlaybackState::PLAYING) {
                auto* current = this->connection_manager_->current();
                if (current != nullptr) {
                    const std::string& server_id = current->get_server_id();
                    if (!server_id.empty()) {
                        this->persist_last_played_server_(server_id);
                    }
                }
            }

            SS_LOGD(TAG, "Group update - state: %s, id: %s, name: %s",
                    this->group_state_.playback_state.has_value()
                        ? to_cstr(this->group_state_.playback_state.value())
                        : "unchanged",
                    this->group_state_.group_id.value_or("").c_str(),
                    this->group_state_.group_name.value_or("").c_str());
        }
    }
}

// --- State updates ---

void SendspinClient::update_state(SendspinClientState state) {
    this->state_ = state;
    this->publish_client_state_(this->connection_manager_->current());
}

// --- Queries ---

bool SendspinClient::is_connected() const {
    return this->connection_manager_->is_connected();
}

bool SendspinClient::is_time_synced() const {
    auto* conn = this->connection_manager_->current();
    return conn != nullptr && conn->is_time_synced();
}

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    auto* conn = this->connection_manager_->current();
    return conn != nullptr ? conn->get_client_time(server_time) : 0;
}

SendspinConnection* SendspinClient::get_current_connection() const {
    return this->connection_manager_->current();
}

// --- Hello message construction ---

std::string SendspinClient::build_hello_message_() {
    ClientHelloMessage msg;
    msg.client_id = this->config_.client_id;
    msg.name = this->config_.name;

    DeviceInfoObject device_info;
    device_info.product_name = this->config_.product_name;
    device_info.manufacturer = this->config_.manufacturer;
    device_info.software_version = this->config_.software_version;
    msg.device_info = device_info;

    msg.version = 1;

    // Let each role contribute to the hello message
    if (this->player_) {
        this->player_->contribute_hello(msg);
    }
    if (this->controller_) {
        this->controller_->contribute_hello(msg);
    }
    if (this->metadata_) {
        this->metadata_->contribute_hello(msg);
    }
    if (this->artwork_) {
        this->artwork_->contribute_hello(msg);
    }
    if (this->visualizer_) {
        this->visualizer_->contribute_hello(msg);
    }

    return format_client_hello_message(&msg);
}

// --- Connection state cleanup ---

void SendspinClient::cleanup_connection_state_() {
    SS_LOGV(TAG, "Cleaning up connection state");

    // Reset client event state
    this->event_state_->time_queue.reset();
    this->event_state_->shadow_group.reset();

    if (this->player_) {
        this->player_->cleanup();
    }
    if (this->controller_) {
        this->controller_->cleanup();
    }
    if (this->metadata_) {
        this->metadata_->cleanup();
    }
    if (this->artwork_) {
        this->artwork_->cleanup();
    }
    if (this->visualizer_) {
        this->visualizer_->cleanup();
    }

    // Release high-performance networking for time sync
    if (this->high_performance_held_for_time_) {
        this->release_high_performance();
        this->high_performance_held_for_time_ = false;
    }
}

// --- Message processing ---

void SendspinClient::process_binary_message_(uint8_t* payload, size_t len) {
    if (len < 2) {
        return;
    }

    uint8_t binary_type = payload[0];
    uint8_t role = get_binary_role(binary_type);
    uint8_t slot = get_binary_slot(binary_type);

    // Strip the type byte; each role parses its own binary format from here
    const uint8_t* data = payload + 1;
    size_t data_len = len - 1;

    switch (role) {
        case SENDSPIN_ROLE_PLAYER: {
            if (this->player_) {
                if (slot == 0) {
                    this->player_->handle_binary(data, data_len);
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
            break;
        }
        case SENDSPIN_ROLE_ARTWORK: {
            if (this->artwork_) {
                this->artwork_->handle_binary(slot, data, data_len);
            }
            break;
        }
        case SENDSPIN_ROLE_VISUALIZER: {
            if (this->visualizer_) {
                this->visualizer_->handle_binary(binary_type, data, data_len);
            }
            break;
        }
        default: {
            SS_LOGW(TAG, "Unknown binary role %d (type %d)", role, binary_type);
            break;
        }
    }
}

bool SendspinClient::process_json_message_(SendspinConnection* conn, const std::string& message,
                                           int64_t timestamp) {
    JsonDocument doc = make_json_document();
    DeserializationError error = deserializeJson(doc, message.c_str(), message.size());
    if (error || doc.isNull()) {
        SS_LOGW(TAG, "Failed to parse JSON message");
        return false;
    }
    JsonObject root = doc.as<JsonObject>();

    SendspinServerToClientMessageType message_type = determine_message_type(root);

    switch (message_type) {
        case SendspinServerToClientMessageType::STREAM_START: {
            SS_LOGD(TAG, "Stream Started");

            StreamStartMessage stream_msg;
            if (!process_stream_start_message(root, &stream_msg)) {
                SS_LOGE(TAG, "Failed to parse stream/start message");
                break;
            }

            if (this->player_) {
                this->player_->handle_stream_start(stream_msg);
            }

            if (this->visualizer_ && stream_msg.visualizer.has_value()) {
                this->visualizer_->handle_stream_start(stream_msg.visualizer.value());
            }
            break;
        }
        case SendspinServerToClientMessageType::STREAM_END: {
            StreamEndMessage end_msg;
            if (process_stream_end_message(root, &end_msg)) {
                bool end_player = !end_msg.roles.has_value();
                bool end_artwork = !end_msg.roles.has_value();
                bool end_visualizer = !end_msg.roles.has_value();

                if (end_msg.roles.has_value()) {
                    for (const auto& role : end_msg.roles.value()) {
                        if (role == "player") {
                            end_player = true;
                        } else if (role == "artwork") {
                            end_artwork = true;
                        } else if (role == "visualizer") {
                            end_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream ended - player:%d artwork:%d visualizer:%d", end_player,
                        end_artwork, end_visualizer);

                if (this->player_ && end_player) {
                    this->player_->handle_stream_end();
                }

                if (this->artwork_ && end_artwork) {
                    this->artwork_->handle_stream_end();
                }

                if (this->visualizer_ && end_visualizer) {
                    this->visualizer_->handle_stream_end();
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::STREAM_CLEAR: {
            StreamClearMessage clear_msg;
            if (process_stream_clear_message(root, &clear_msg)) {
                bool clear_player = !clear_msg.roles.has_value();
                bool clear_visualizer = !clear_msg.roles.has_value();

                if (clear_msg.roles.has_value()) {
                    for (const auto& role : clear_msg.roles.value()) {
                        if (role == "player") {
                            clear_player = true;
                        } else if (role == "visualizer") {
                            clear_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream clear - player:%d visualizer:%d", clear_player,
                        clear_visualizer);

                if (this->player_ && clear_player) {
                    this->player_->handle_stream_clear();
                }

                if (this->visualizer_ && clear_visualizer) {
                    this->visualizer_->handle_stream_clear();
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_HELLO: {
            ServerHelloMessage hello_msg;
            if (process_server_hello_message(root, &hello_msg)) {
                SS_LOGD(TAG, "Connected to server %s with id %s (reason: %s)",
                        hello_msg.server.name.c_str(), hello_msg.server.server_id.c_str(),
                        to_cstr(hello_msg.connection_reason));

                if (conn != nullptr) {
                    conn->set_server_id(hello_msg.server.server_id);
                    conn->set_server_name(hello_msg.server.name);
                    conn->set_connection_reason(hello_msg.connection_reason);
                    conn->set_server_hello_received(true);

                    this->connection_manager_->enqueue_hello(
                        {conn, std::move(hello_msg.server), hello_msg.connection_reason});
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_TIME: {
            if (conn == nullptr) {
                SS_LOGW(TAG, "Received time message but no connection context");
                break;
            }

            int64_t offset;
            int64_t max_error;
            if (process_server_time_message(root, timestamp, conn->peek_time_replacement(), &offset,
                                            &max_error)) {
                this->event_state_->time_queue.send({offset, max_error, timestamp}, 0);
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_STATE: {
            ServerStateMessage state_msg;
            if (process_server_state_message(root, &state_msg)) {
                if (this->controller_ && state_msg.controller.has_value()) {
                    this->controller_->handle_server_state(std::move(state_msg.controller.value()));
                }

                if (this->metadata_ && state_msg.metadata.has_value()) {
                    this->metadata_->handle_server_state(state_msg.metadata.value());
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_COMMAND: {
            if (this->player_) {
                ServerCommandMessage cmd_msg;
                if (process_server_command_message(root, &cmd_msg)) {
                    this->player_->handle_server_command(cmd_msg);
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::GROUP_UPDATE: {
            GroupUpdateMessage group_msg;
            if (process_group_update_message(root, &group_msg)) {
                this->event_state_->shadow_group.merge(
                    [](GroupUpdateObject& current, GroupUpdateObject&& delta) {
                        apply_group_update_deltas(&current, delta);
                    },
                    std::move(group_msg.group));
            }
            break;
        }
        default:
            SS_LOGW(TAG, "Unhandled server message type: %s",
                    root["type"].is<const char*>() ? root["type"].as<const char*>() : "unknown");
    }

    return true;
}

// --- State publishing ---

void SendspinClient::publish_client_state_(SendspinConnection* conn) {
    if (conn == nullptr || !conn->is_connected() || !conn->is_handshake_complete()) {
        return;
    }

    ClientStateMessage state_msg;
    state_msg.state = this->state_;

    if (this->player_) {
        this->player_->contribute_state(state_msg);
    }

    std::string state_message = format_client_state_message(&state_msg);
    conn->send_text_message(state_message, nullptr);
}

// --- Persistence ---

void SendspinClient::load_last_played_server_() {
    if (!this->persistence_provider_) {
        return;
    }

    auto hash = this->persistence_provider_->load_last_server_hash();
    if (hash.has_value() && hash.value() != 0) {
        this->connection_manager_->set_last_played_server_hash(hash.value());
        SS_LOGI(TAG, "Loaded last played server hash: 0x%08X", hash.value());
    }
}

void SendspinClient::persist_last_played_server_(const std::string& server_id) {
    if (server_id.empty()) {
        return;
    }

    uint32_t hash = ConnectionManager::fnv1_hash(server_id.c_str());
    this->connection_manager_->set_last_played_server_hash(hash);

    if (this->persistence_provider_) {
        if (this->persistence_provider_->save_last_server_hash(hash)) {
            SS_LOGD(TAG, "Persisted last played server: %s (hash: 0x%08X)", server_id.c_str(),
                    hash);
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

}  // namespace sendspin
