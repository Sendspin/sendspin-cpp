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

#include "client_bridge.h"
#include "connection.h"
#include "connection_manager.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/time.h"
#include "time_burst.h"
#include <ArduinoJson.h>

#include <algorithm>
#include <cstring>

static const char* const TAG = "sendspin.client";

static const size_t SENDSPIN_BINARY_CHUNK_HEADER_SIZE = 9;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

namespace sendspin {

// --- Constructor / Destructor ---

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      connection_manager_(std::make_unique<ConnectionManager>(ConnectionManagerCallbacks{
          .on_json_message =
              [this](SendspinConnection* conn, const std::string& message, int64_t timestamp) {
                  return this->process_json_message_(conn, message, timestamp);
              },
          .on_binary_message = [this](uint8_t* payload,
                                      size_t len) { this->process_binary_message_(payload, len); },
          .build_hello_message = [this]() { return this->build_hello_message_(); },
          .on_handshake_complete =
              [this](SendspinConnection* conn, ServerInformationObject server) {
                  this->server_information_ = std::move(server);
                  this->publish_client_state_(conn);
              },
          .on_active_connection_lost = [this]() { this->cleanup_connection_state_(); },
          .reset_time_burst = [this]() { this->time_burst_->reset(); },
          .is_network_ready = [this]() -> bool {
              return this->is_network_ready && this->is_network_ready();
          },
      })),
      time_burst_(std::make_unique<SendspinTimeBurst>()) {}

SendspinClient::~SendspinClient() {
    // Stop the player's sync task thread first, before tearing down connections.
    this->player_.reset();
    this->connection_manager_.reset();
}

void SendspinClient::set_log_level(LogLevel level) {
    platform_set_log_level(static_cast<int>(level));
}

LogLevel SendspinClient::get_log_level() {
    return static_cast<LogLevel>(platform_get_log_level());
}

// --- Bridge ---

ClientBridge* SendspinClient::make_bridge_() {
    if (this->bridge_) {
        return this->bridge_.get();
    }
    this->bridge_ = std::make_unique<ClientBridge>(ClientBridge{
        .get_client_time =
            [this](int64_t server_time) { return this->get_client_time(server_time); },
        .is_time_synced = [this]() { return this->is_time_synced(); },
        .publish_state =
            [this]() { this->publish_client_state_(this->connection_manager_->current()); },
        .send_text =
            [this](const std::string& text) {
                auto* conn = this->connection_manager_->current();
                if (conn != nullptr && conn->is_connected()) {
                    conn->send_text_message(text, nullptr);
                }
            },
        .request_high_performance =
            [this]() {
                if (this->on_request_high_performance) {
                    this->on_request_high_performance();
                }
            },
        .release_high_performance =
            [this]() {
                if (this->on_release_high_performance) {
                    this->on_release_high_performance();
                }
            },
        .event_mutex = this->event_mutex_,
    });
    return this->bridge_.get();
}

// --- Role registration ---

PlayerRole& SendspinClient::add_player(PlayerRole::Config config, AudioSink* sink) {
    if (this->started_) {
        SS_LOGW(TAG,
                "add_player() called after start_server() — role may not initialize correctly");
    }
    this->player_ = std::make_unique<PlayerRole>(std::move(config), sink);
    this->player_->attach(this->make_bridge_());
    return *this->player_;
}

ControllerRole& SendspinClient::add_controller() {
    if (this->started_) {
        SS_LOGW(TAG, "add_controller() called after start_server()");
    }
    this->controller_ = std::make_unique<ControllerRole>();
    this->controller_->attach(this->make_bridge_());
    return *this->controller_;
}

MetadataRole& SendspinClient::add_metadata() {
    if (this->started_) {
        SS_LOGW(TAG, "add_metadata() called after start_server()");
    }
    this->metadata_ = std::make_unique<MetadataRole>();
    this->metadata_->attach(this->make_bridge_());
    return *this->metadata_;
}

ArtworkRole& SendspinClient::add_artwork() {
    if (this->started_) {
        SS_LOGW(TAG, "add_artwork() called after start_server()");
    }
    this->artwork_ = std::make_unique<ArtworkRole>();
    this->artwork_->attach(this->make_bridge_());
    return *this->artwork_;
}

VisualizerRole& SendspinClient::add_visualizer(VisualizerRole::Config config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_visualizer() called after start_server()");
    }
    this->visualizer_ = std::make_unique<VisualizerRole>(std::move(config));
    this->visualizer_->attach(this->make_bridge_());
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

        if (result.sent && !this->high_performance_requested_for_time_ &&
            this->on_request_high_performance) {
            this->on_request_high_performance();
            this->high_performance_requested_for_time_ = true;
        }
        if (result.burst_completed && this->high_performance_requested_for_time_ &&
            this->on_release_high_performance) {
            this->on_release_high_performance();
            this->high_performance_requested_for_time_ = false;
        }
        if (result.burst_completed && this->on_time_sync_updated && conn->get_time_filter()) {
            this->on_time_sync_updated(static_cast<float>(conn->get_time_filter()->get_error()));
        }
    }

    // Process deferred events -- all state mutations and user callbacks happen here,
    // on the main loop thread, to avoid cross-thread data races.
    {
        std::vector<TimeResponseEvent> time_events;
        std::vector<GroupUpdateObject> group_events;

        // Player event vectors
        std::vector<PlayerRole::StreamCallbackEvent> player_stream_events;
        std::vector<PlayerRole::ServerCommandEvent> player_command_events;
        std::vector<SendspinClientState> player_state_events;

        // Controller event vectors
        std::vector<ServerStateControllerObject> controller_state_events;

        // Metadata event vectors
        std::vector<ServerMetadataStateObject> metadata_events;

        // Artwork event vectors
        std::vector<bool> artwork_stream_end_events;

        // Visualizer event vectors
        std::vector<VisualizerRole::Event> visualizer_events;

        {
            std::lock_guard<std::mutex> lock(this->event_mutex_);
            time_events.swap(this->pending_time_events_);
            group_events.swap(this->pending_group_events_);

            if (this->player_) {
                player_stream_events.swap(this->player_->pending_stream_callback_events_);
                player_command_events.swap(this->player_->pending_command_events_);
                player_state_events.swap(this->player_->pending_state_events_);
            }
            if (this->controller_) {
                controller_state_events.swap(this->controller_->pending_controller_state_events_);
            }
            if (this->metadata_) {
                metadata_events.swap(this->metadata_->pending_metadata_events_);
            }
            if (this->artwork_) {
                artwork_stream_end_events.swap(this->artwork_->pending_stream_end_);
            }
            if (this->visualizer_) {
                visualizer_events.swap(this->visualizer_->pending_events_);
            }
        }

        // --- Client state events (deferred from sync task thread) ---
        if (this->player_ && !player_state_events.empty()) {
            this->update_state(player_state_events.back());
        }

        // --- Time sync events ---
        for (const auto& event : time_events) {
            auto* current = this->connection_manager_->current();
            if (current != nullptr) {
                this->time_burst_->on_time_response(current, event.offset, event.max_error,
                                                    event.timestamp);
            }
        }

        // --- Controller events ---
        if (this->controller_) {
            this->controller_->drain_events(controller_state_events);
        }

        // --- Player events ---
        if (this->player_) {
            this->player_->drain_events(player_stream_events, player_command_events);
        }

        // --- Metadata events ---
        if (this->metadata_) {
            this->metadata_->drain_events(metadata_events);
        }

        // --- Artwork events ---
        if (this->artwork_) {
            this->artwork_->drain_events(artwork_stream_end_events);
        }

        // --- Visualizer events ---
        if (this->visualizer_) {
            this->visualizer_->drain_events(visualizer_events);
        }

        // --- Group update events ---
        for (const auto& group_update : group_events) {
            apply_group_update_deltas(&this->group_state_, group_update);

            if (this->on_group_update) {
                this->on_group_update(group_update);
            }

            // Persist last played server when playback starts
            if (group_update.playback_state.has_value() &&
                group_update.playback_state.value() == SendspinPlaybackState::PLAYING) {
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

    if (this->player_) {
        this->player_->cleanup();
    }

    if (this->visualizer_) {
        this->visualizer_->cleanup();
    }

    // Release high-performance networking for time sync
    if (this->high_performance_requested_for_time_ && this->on_release_high_performance) {
        this->on_release_high_performance();
        this->high_performance_requested_for_time_ = false;
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

    switch (role) {
        case SENDSPIN_ROLE_PLAYER: {
            if (this->player_) {
                if (len < SENDSPIN_BINARY_CHUNK_HEADER_SIZE) {
                    return;
                }
                int64_t server_timestamp = be64_to_host(payload + 1);
                if (slot == 0) {
                    this->player_->handle_binary(payload + SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                                 len - SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                                 server_timestamp);
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
            break;
        }
        case SENDSPIN_ROLE_ARTWORK: {
            if (this->artwork_) {
                if (len < SENDSPIN_BINARY_CHUNK_HEADER_SIZE) {
                    return;
                }
                int64_t server_timestamp = be64_to_host(payload + 1);
                this->artwork_->handle_binary(slot, payload + SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                              len - SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                              server_timestamp);
            }
            break;
        }
        case SENDSPIN_ROLE_VISUALIZER: {
            if (this->visualizer_) {
                this->visualizer_->handle_binary(binary_type, payload, len);
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
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                this->pending_time_events_.push_back({offset, max_error, timestamp});
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
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                this->pending_group_events_.push_back(group_msg.group);
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
    if (!this->load_last_server_hash) {
        return;
    }

    auto hash = this->load_last_server_hash();
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

    if (this->save_last_server_hash) {
        if (this->save_last_server_hash(hash)) {
            SS_LOGD(TAG, "Persisted last played server: %s (hash: 0x%08X)", server_id.c_str(),
                    hash);
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

}  // namespace sendspin
