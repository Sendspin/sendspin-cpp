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
#include "inbox.h"
#include "platform/compiler.h"
#include "platform/json_arena.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/network_info.h"
#include "platform/time.h"
#ifdef SENDSPIN_ENABLE_ARTWORK
#include "artwork_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_COLOR
#include "color_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
#include "controller_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_METADATA
#include "metadata_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
#include "player_role_impl.h"
#endif
#include "protocol_messages.h"
#ifdef SENDSPIN_ENABLE_VISUALIZER
#include "visualizer_role_impl.h"
#endif
#include "time_burst.h"
#include <ArduinoJson.h>

#include <algorithm>
#include <cstring>

static const char* const TAG = "sendspin.client";

namespace sendspin {

/// @brief Deferred event state for time responses and group updates on the main thread
struct SendspinClient::EventState {
    Inbox inbox;
    InboxSlot<GroupUpdateObject> group_slot{inbox, INBOX_TOPIC_GROUP};
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      connection_manager_(std::make_unique<ConnectionManager>(this)),
      event_state_(std::make_unique<EventState>()),
      time_burst_(std::make_unique<SendspinTimeBurst>()) {
    if (this->config_.json_arena_size > 0) {
        this->json_arena_ = std::make_unique<SendspinArenaAllocator>(this->config_.json_arena_size);
    }
    this->time_burst_->configure(this->config_.time_burst_size,
                                 this->config_.time_burst_interval_ms,
                                 this->config_.time_burst_response_timeout_ms);
}

SendspinClient::~SendspinClient() {
    // Stop background threads before tearing down connections. Every role is reset explicitly
    // (not just the threaded ones): role InboxSlots release their topic-bit claims against
    // event_state_'s Inbox on destruction, so all roles must be gone before the alphabetized
    // member order destroys event_state_.
#ifdef SENDSPIN_ENABLE_PLAYER
    this->player_.reset();
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    this->visualizer_.reset();
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    this->artwork_.reset();
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    this->controller_.reset();
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    this->metadata_.reset();
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    this->color_.reset();
#endif
    this->connection_manager_.reset();
}

void SendspinClient::set_log_level(LogLevel level) {
    platform_set_log_level(static_cast<int>(level));
}

LogLevel SendspinClient::get_log_level() {
    return static_cast<LogLevel>(platform_get_log_level());
}

// ============================================================================
// Lifecycle
// ============================================================================

bool SendspinClient::start_server() {
    this->started_ = true;

    // Load persisted state
    this->load_last_played_server();

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        if (!this->player_->impl_->start()) {
            return false;
        }
    }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        if (!this->visualizer_->impl_->start()) {
            return false;
        }
    }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        if (!this->artwork_->impl_->start()) {
            return false;
        }
    }
#endif

    // Create and configure the WebSocket server (started later when network is ready)
    this->connection_manager_->init_server(this);

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

    // Process deferred events: all state mutations and user callbacks happen here, on the main
    // loop thread, to avoid cross-thread data races. Each role drains its own queues/shadows
    // internally.
    const uint32_t inbox_bits = this->event_state_->inbox.poll();

    // --- Time sync events ---
    if (inbox_bits & INBOX_TOPIC_EVENTS) {
        // Drain in small batches to bound the stack cost on the shared main-loop task (the ring
        // holds up to EVENT_CAPACITY entries of ~40 bytes each). A batch that comes back partial
        // means the ring is empty, ending the loop; events pushed mid-drain are still delivered
        // this tick as long as full batches keep arriving. Sized as a fraction of the ring so the
        // batch/ring ratio (and the stack cost above) tracks EVENT_CAPACITY automatically.
        constexpr size_t EVENT_DRAIN_BATCH_SIZE = Inbox::EVENT_CAPACITY / 4;
        InboxEvent events[EVENT_DRAIN_BATCH_SIZE];
        size_t event_count = 0;
        do {
            event_count = this->event_state_->inbox.take_events(events, EVENT_DRAIN_BATCH_SIZE);
            for (size_t i = 0; i < event_count; ++i) {
                const InboxEvent& event = events[i];
                switch (event.type) {
                    case InboxEventType::TIME_RESPONSE: {
                        auto* current = this->connection_manager_->current();
                        // Apply only measurements from the connection that is still current; a
                        // response queued by a since-displaced (or pending) server carries that
                        // server's clock and would contaminate this connection's Kalman filter.
                        if (current != nullptr &&
                            current->get_instance_id() == event.time.source_id) {
                            this->time_burst_->on_time_response(current, event.time.offset,
                                                                event.time.max_error,
                                                                event.time.timestamp);
                        }
                        break;
                    }
                    // CONTROLLER_CLEARED / METADATA_CLEARED / COLOR_CLEARED: pushed by each
                    // role's cleanup() in place of the old boolean coalescing flag. At most one
                    // CLEARED per role is ever pending when this drain runs: cleanup() is called
                    // only from cleanup_connection_state(), which first calls inbox.reset_events()
                    // (wiping the whole ring) before any role re-pushes its CLEARED, and that path
                    // runs only under conn_ptr_mutex_ (ConnectionManager::drop_connection), so it
                    // cannot interleave with itself. So even a back-to-back disconnect/reconnect
                    // coalesces to a single CLEARED -- the reset_events() ordering is what
                    // guarantees it, not clear-callback idempotency. (Callbacks are idempotent by
                    // contract anyway; see on_controller_state_clear() / on_metadata_clear() /
                    // on_color_clear().)
                    case InboxEventType::CONTROLLER_CLEARED: {
#ifdef SENDSPIN_ENABLE_CONTROLLER
                        if (this->controller_) {
                            this->controller_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::METADATA_CLEARED: {
#ifdef SENDSPIN_ENABLE_METADATA
                        if (this->metadata_) {
                            this->metadata_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::COLOR_CLEARED: {
#ifdef SENDSPIN_ENABLE_COLOR
                        if (this->color_) {
                            this->color_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    default: {
                        // No role event types are produced yet; unhandled types are logged and
                        // dropped.
                        SS_LOGD(TAG, "Unhandled inbox event type: %d",
                                static_cast<int>(event.type));
                        break;
                    }
                }
            }
        } while (event_count == EVENT_DRAIN_BATCH_SIZE);
    }

    // --- Role events (each role handles its own synchronization) ---
    // These drains must stay unconditional (gated only on the role existing), NOT wrapped in an
    // `inbox_bits & INBOX_TOPIC_*` test like the group slot below. metadata/color drain_events()
    // take() clears the topic bit even when it defers a future-dated delta into held_delta; that
    // deferred delta is re-evaluated against its deadline on later ticks only because this call
    // runs every tick. Bit-gating it would strand the delta until an unrelated new delta happened
    // to re-set the bit, silently starving deadline-based delivery.
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->drain_events();
    }
#endif

    // --- Group update events ---
    if (inbox_bits & INBOX_TOPIC_GROUP) {
        GroupUpdateObject group_delta;
        if (this->event_state_->group_slot.take(group_delta)) {
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
                        this->persist_last_played_server(server_id);
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

// ============================================================================
// Role registration (call before start_server)
// ============================================================================

#ifdef SENDSPIN_ENABLE_PLAYER
PlayerRole& SendspinClient::add_player(PlayerRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_player() called after start_server(); role may not initialize correctly");
    }
    this->player_ =
        std::make_unique<PlayerRole>(std::move(config), this, this->persistence_provider_);
    return *this->player_;
}
#endif

#ifdef SENDSPIN_ENABLE_CONTROLLER
ControllerRole& SendspinClient::add_controller() {
    if (this->started_) {
        SS_LOGW(TAG, "add_controller() called after start_server()");
    }
    this->controller_ = std::make_unique<ControllerRole>(this);
    this->controller_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->controller_;
}
#endif

#ifdef SENDSPIN_ENABLE_METADATA
MetadataRole& SendspinClient::add_metadata() {
    if (this->started_) {
        SS_LOGW(TAG, "add_metadata() called after start_server()");
    }
    this->metadata_ = std::make_unique<MetadataRole>(this);
    this->metadata_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->metadata_;
}
#endif

#ifdef SENDSPIN_ENABLE_COLOR
ColorRole& SendspinClient::add_color() {
    if (this->started_) {
        SS_LOGW(TAG, "add_color() called after start_server()");
    }
    this->color_ = std::make_unique<ColorRole>(this);
    this->color_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->color_;
}
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
ArtworkRole& SendspinClient::add_artwork(ArtworkRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_artwork() called after start_server()");
    }
    this->artwork_ = std::make_unique<ArtworkRole>(std::move(config), this);
    return *this->artwork_;
}
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
VisualizerRole& SendspinClient::add_visualizer(VisualizerRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_visualizer() called after start_server()");
    }
    this->visualizer_ = std::make_unique<VisualizerRole>(std::move(config), this);
    return *this->visualizer_;
}
#endif

// ============================================================================
// Queries
// ============================================================================

bool SendspinClient::is_connected() const {
    return this->connection_manager_->is_connected();
}

bool SendspinClient::is_time_synced() const {
    // current_shared(): called from role threads (sync task, drain threads), so the shared_ptr
    // must keep the connection alive while it is dereferenced.
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr && conn->is_time_synced();
}

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    // current_shared(): called from role threads; see is_time_synced().
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr ? conn->get_client_time(server_time) : 0;
}

std::optional<ServerInformationObject> SendspinClient::get_server_information() const {
    // current_shared(): public accessor, callable from any thread.
    auto conn = this->connection_manager_->current_shared();
    if (conn == nullptr || !conn->is_handshake_complete()) {
        return std::nullopt;
    }
    return conn->get_server_information();
}

// ============================================================================
// State updates
// ============================================================================

void SendspinClient::update_state(SendspinClientState state) {
    this->state_ = state;
    this->publish_client_state(this->connection_manager_->current());
}

// ============================================================================
// Role services (called by roles via SendspinClient pointer)
// ============================================================================

void SendspinClient::publish_state() {
    this->publish_client_state(this->connection_manager_->current());
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
    // Compare-exchange loop so two concurrent releases at count 1 can't both pass a
    // plain zero-check and underflow the counter
    uint8_t count = this->high_performance_ref_count_.load();
    while (count != 0) {
        if (this->high_performance_ref_count_.compare_exchange_weak(count, count - 1)) {
            if (count == 1 && this->listener_) {
                this->listener_->on_release_high_performance();
            }
            return;
        }
    }
}

// ============================================================================
// Private helpers
// ============================================================================

void SendspinClient::cleanup_connection_state() {
    SS_LOGV(TAG, "Cleaning up connection state");

    // The time burst is per-connection state too; resetting it here keeps it impossible to tear
    // down a connection without also stopping its burst.
    this->time_burst_->reset();

    // Reset client event state
    this->event_state_->inbox.reset_events();
    this->event_state_->group_slot.reset();

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->cleanup();
    }
#endif

    // Release high-performance networking for time sync
    if (this->high_performance_held_for_time_) {
        this->release_high_performance();
        this->high_performance_held_for_time_ = false;
    }
}

std::string SendspinClient::build_hello_message() {
    ClientHelloMessage msg;
    msg.name = this->config_.name;

    // Use the explicitly configured MAC when provided; otherwise fall back to platform detection
    // (reliable on ESP, best-effort on host). Leaves the field absent if neither is available.
    const std::optional<std::string> interface_mac =
        this->config_.mac_address ? this->config_.mac_address : platform_get_interface_mac();

    // Some integrations use the network MAC as the Sendspin client_id. If they leave it empty,
    // default to the same active-interface MAC advertised in device_info instead of forcing them
    // to duplicate platform-specific MAC detection.
    msg.client_id = this->config_.client_id;
    if (msg.client_id.empty() && interface_mac.has_value()) {
        msg.client_id = interface_mac.value();
    }

    DeviceInfoObject device_info{};
    device_info.product_name = this->config_.product_name;
    device_info.manufacturer = this->config_.manufacturer;
    device_info.software_version = this->config_.software_version;
    device_info.mac_address = interface_mac;
    msg.device_info = device_info;

    msg.version = 1;

    // Let each role add its fields to the hello message
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->build_hello_fields(msg);
    }
#endif

    return format_client_hello_message(&msg);
}

// ============================================================================
// Message processing
// ============================================================================

void SendspinClient::process_json_message(SendspinConnection* conn, const char* data, size_t len,
                                          int64_t timestamp) {
    // Two connections can deliver JSON concurrently on their own network threads (current +
    // pending during a handoff, or an outbound connect_to() transport alongside the inbound
    // server). Serialize the shared arena and the parse itself; JSON control messages are
    // infrequent, so contention is negligible.
    std::lock_guard<std::mutex> lock(this->json_processing_mutex_);

    // Reuse the internal-RAM scratch arena if configured. Safe to reset here: the JsonDocument
    // from the previous call was already destroyed when that call returned.
    if (this->json_arena_) {
        this->json_arena_->reset();
    }
    JsonDocument doc =
        this->json_arena_ ? make_json_document(*this->json_arena_) : make_json_document();
    DeserializationError error = deserializeJson(doc, data, len);
    if (error || doc.isNull()) {
        SS_LOGW(TAG, "Failed to parse JSON message");
        return;
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

#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_ && stream_msg.player.has_value()) {
                this->player_->impl_->handle_stream_start(stream_msg.player.value());
            }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
            if (this->artwork_ && stream_msg.artwork.has_value()) {
                this->artwork_->impl_->handle_stream_start(stream_msg.artwork.value());
            }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
            if (this->visualizer_ && stream_msg.visualizer.has_value()) {
                this->visualizer_->impl_->handle_stream_start(stream_msg.visualizer.value());
            }
#endif
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

#ifdef SENDSPIN_ENABLE_PLAYER
                if (this->player_ && end_player) {
                    this->player_->impl_->handle_stream_end();
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (this->artwork_ && end_artwork) {
                    this->artwork_->impl_->handle_stream_end();
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && end_visualizer) {
                    this->visualizer_->impl_->handle_stream_end();
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::STREAM_CLEAR: {
            StreamClearMessage clear_msg;
            if (process_stream_clear_message(root, &clear_msg)) {
                bool clear_player = !clear_msg.roles.has_value();
                bool clear_artwork = !clear_msg.roles.has_value();
                bool clear_visualizer = !clear_msg.roles.has_value();

                if (clear_msg.roles.has_value()) {
                    for (const auto& role : clear_msg.roles.value()) {
                        if (role == "player") {
                            clear_player = true;
                        } else if (role == "artwork") {
                            clear_artwork = true;
                        } else if (role == "visualizer") {
                            clear_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream clear - player:%d artwork:%d visualizer:%d", clear_player,
                        clear_artwork, clear_visualizer);

#ifdef SENDSPIN_ENABLE_PLAYER
                if (this->player_ && clear_player) {
                    this->player_->impl_->handle_stream_clear();
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (this->artwork_ && clear_artwork) {
                    this->artwork_->impl_->handle_stream_clear();
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && clear_visualizer) {
                    this->visualizer_->impl_->handle_stream_clear();
                }
#endif
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
                    conn->set_server_information(std::move(hello_msg.server));
                    conn->set_connection_reason(hello_msg.connection_reason);
                    // Set last: this atomic store publishes the fields above to the manager's
                    // promotion scan on the main loop, which observes is_handshake_complete()
                    // and establishes the connection; nothing needs to be scheduled here.
                    conn->set_server_hello_received(true);
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_TIME: {
            if (conn == nullptr) {
                SS_LOGW(TAG, "Received time message but no connection context");
                break;
            }

            int64_t offset{0};
            int64_t max_error{0};
            if (process_server_time_message(root, timestamp, &offset, &max_error)) {
                InboxEvent event{};
                event.type = InboxEventType::TIME_RESPONSE;
                event.time =
                    TimeResponsePayload{offset, max_error, timestamp, conn->get_instance_id()};
                if (!this->event_state_->inbox.push_event(event)) {
                    SS_LOGW(TAG, "Inbox event ring full; dropping time response measurement");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_STATE: {
            ServerStateMessage state_msg;
            if (process_server_state_message(root, &state_msg)) {
#ifdef SENDSPIN_ENABLE_CONTROLLER
                if (this->controller_ && state_msg.controller.has_value()) {
                    this->controller_->impl_->handle_server_state(
                        std::move(state_msg.controller.value()));
                }
#endif

#ifdef SENDSPIN_ENABLE_METADATA
                if (this->metadata_ && state_msg.metadata.has_value()) {
                    this->metadata_->impl_->handle_server_state(
                        std::move(state_msg.metadata.value()));
                }
#endif

#ifdef SENDSPIN_ENABLE_COLOR
                if (this->color_ && state_msg.color.has_value()) {
                    this->color_->impl_->handle_server_state(state_msg.color.value());
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_COMMAND: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_) {
                ServerCommandMessage cmd_msg;
                if (process_server_command_message(root, &cmd_msg)) {
                    this->player_->impl_->handle_server_command(cmd_msg);
                }
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::GROUP_UPDATE: {
            GroupUpdateMessage group_msg;
            if (process_group_update_message(root, &group_msg)) {
                this->event_state_->group_slot.merge(
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
}

SS_HOT void SendspinClient::process_binary_message(const uint8_t* payload, size_t len) {
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
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_) {
                if (slot == 0) {
                    this->player_->impl_->handle_binary(data, data_len);
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
#endif
            break;
        }
        case SENDSPIN_ROLE_ARTWORK: {
#ifdef SENDSPIN_ENABLE_ARTWORK
            if (this->artwork_) {
                this->artwork_->impl_->handle_binary(slot, data, data_len);
            }
#endif
            break;
        }
        case SENDSPIN_ROLE_VISUALIZER: {
#ifdef SENDSPIN_ENABLE_VISUALIZER
            if (this->visualizer_) {
                this->visualizer_->impl_->handle_binary(binary_type, data, data_len);
            }
#endif
            break;
        }
        default: {
            SS_LOGW(TAG, "Unknown binary role %d (type %d)", role, binary_type);
            break;
        }
    }
}

// ============================================================================
// State publishing
// ============================================================================

void SendspinClient::publish_client_state(SendspinConnection* conn) {
    if (conn == nullptr || !conn->is_connected() || !conn->is_handshake_complete()) {
        return;
    }

    ClientStateMessage state_msg;
    state_msg.state = this->state_;

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->build_state_fields(state_msg);
    }
#endif

    std::string state_message = format_client_state_message(&state_msg);
    conn->send_text_message(state_message, nullptr);
}

// ============================================================================
// Persistence
// ============================================================================

void SendspinClient::load_last_played_server() {
    if (!this->persistence_provider_) {
        return;
    }

    auto hash = this->persistence_provider_->load_last_server_hash();
    if (hash.has_value() && hash.value() != 0) {
        this->connection_manager_->set_last_played_server_hash(hash.value());
        SS_LOGI(TAG, "Loaded last played server hash: 0x%08X", hash.value());
    }
}

void SendspinClient::persist_last_played_server(const std::string& server_id) {
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

// ============================================================================
// Connection event handlers (called by ConnectionManager via friend access)
// ============================================================================

void SendspinClient::on_handshake_complete(SendspinConnection* conn) {
    this->publish_client_state(conn);
}

}  // namespace sendspin
