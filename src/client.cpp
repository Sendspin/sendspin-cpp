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

#include "client_connection.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/time.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"
#include <ArduinoJson.h>

#ifdef SENDSPIN_ENABLE_PLAYER
#include "platform/base64.h"
#include "sync_task.h"
#endif

#include <algorithm>
#include <cstring>

static const char* const TAG = "sendspin.client";

#if defined(SENDSPIN_ENABLE_PLAYER) || defined(SENDSPIN_ENABLE_ARTWORK)
static const size_t SENDSPIN_BINARY_CHUNK_HEADER_SIZE = 9;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}
#endif  // SENDSPIN_ENABLE_PLAYER || SENDSPIN_ENABLE_ARTWORK

namespace sendspin {

// --- Helpers ---

uint32_t SendspinClient::fnv1_hash(const char* str) {
    uint32_t hash = 2166136261UL;
    while (*str) {
        hash *= 16777619UL;
        hash ^= static_cast<uint8_t>(*str++);
    }
    return hash;
}

#ifdef SENDSPIN_ENABLE_PLAYER

/// @brief Decodes a base64-encoded string into a byte vector.
static std::vector<uint8_t> base64_decode(const std::string& input) {
    // mbedtls needs at most 3/4 of input size for output
    size_t output_len = 0;
    // First call to determine output length
    platform_base64_decode(nullptr, 0, &output_len,
                           reinterpret_cast<const unsigned char*>(input.data()), input.size());

    std::vector<uint8_t> output(output_len);
    int ret =
        platform_base64_decode(output.data(), output.size(), &output_len,
                               reinterpret_cast<const unsigned char*>(input.data()), input.size());
    if (ret != 0) {
        SS_LOGW(TAG, "base64 decode failed: %d", ret);
        return {};
    }
    output.resize(output_len);
    return output;
}

#endif  // SENDSPIN_ENABLE_PLAYER

// --- Constructor / Destructor ---

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      time_burst_(std::make_unique<SendspinTimeBurst>())
#ifdef SENDSPIN_ENABLE_PLAYER
      ,
      sync_task_(std::make_unique<SyncTask>())
#endif
{
}

SendspinClient::~SendspinClient() {
#ifdef SENDSPIN_ENABLE_PLAYER
    // Stop the sync task thread first, before tearing down connections or destroying members.
    // External callbacks (e.g., PortAudio) may still call notify_audio_played() on another thread,
    // so the sync task must be stopped while it's still valid.
    this->sync_task_.reset();
#endif

    if (this->current_connection_ != nullptr) {
        this->current_connection_.reset();
    }
    if (this->pending_connection_ != nullptr) {
        this->pending_connection_.reset();
    }
    this->dying_connection_.reset();
}

void SendspinClient::set_log_level(LogLevel level) {
    platform_set_log_level(static_cast<int>(level));
}

LogLevel SendspinClient::get_log_level() {
    return static_cast<LogLevel>(platform_get_log_level());
}

#ifdef SENDSPIN_ENABLE_PLAYER
SyncTimeProvider SendspinClient::make_sync_time_provider_() {
    return SyncTimeProvider{
        .get_client_time =
            [this](int64_t server_time) { return this->get_client_time(server_time); },
        .is_time_synced = [this]() { return this->is_time_synced(); },
        .get_static_delay_ms = [this]() { return this->get_static_delay_ms(); },
        .get_fixed_delay_us = [this]() { return this->get_fixed_delay_us(); },
        .update_state =
            [this](SendspinClientState state) {
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                this->pending_state_events_.push_back(state);
            },
    };
}
#endif  // SENDSPIN_ENABLE_PLAYER

// --- Lifecycle ---

bool SendspinClient::start_server(unsigned priority) {
    this->task_priority_ = priority;

    // Load persisted state
    this->load_last_played_server_();
#ifdef SENDSPIN_ENABLE_PLAYER
    this->load_static_delay_();

    // Initialize and start sync task if audio formats are configured.
    // May already be initialized if set_audio_sink() was called before start_server().
    if (!this->config_.audio_formats.empty() && this->audio_sink_ != nullptr &&
        !this->sync_task_->is_initialized()) {
        if (!this->sync_task_->init(this->make_sync_time_provider_(), this->audio_sink_,
                                    this->config_.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
            return false;
        }
        if (!this->sync_task_->start(this->config_.psram_stack)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
            return false;
        }
    }
#endif  // SENDSPIN_ENABLE_PLAYER

    // Create the WebSocket server listener
    this->ws_server_ = std::make_unique<SendspinWsServer>();

    // Configure callbacks for the server
    this->ws_server_->set_new_connection_callback(
        [this](std::unique_ptr<SendspinServerConnection> conn) {
            this->on_new_connection_(std::move(conn));
        });

    this->ws_server_->set_connection_closed_callback(
        [this](int sockfd) { this->on_connection_closed_(sockfd); });

    // Set up connection lookup callback for routing messages
    this->ws_server_->set_find_connection_callback([this](int sockfd) -> SendspinServerConnection* {
        if (this->current_connection_ != nullptr &&
            this->current_connection_->get_sockfd() == sockfd) {
            return static_cast<SendspinServerConnection*>(this->current_connection_.get());
        }
        if (this->pending_connection_ != nullptr &&
            this->pending_connection_->get_sockfd() == sockfd) {
            return static_cast<SendspinServerConnection*>(this->pending_connection_.get());
        }
        if (this->dying_connection_ != nullptr && this->dying_connection_->get_sockfd() == sockfd) {
            return static_cast<SendspinServerConnection*>(this->dying_connection_.get());
        }
        return nullptr;
    });

    return true;
}

void SendspinClient::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_unique<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);

    // Set up callbacks
    client_conn->on_connected = [this](SendspinConnection* conn) { this->initiate_hello_(conn); };
    client_conn->on_json_message = [this](SendspinConnection* conn, const std::string& message,
                                          int64_t timestamp) {
        this->process_json_message_(conn, message, timestamp);
    };
    client_conn->on_binary_message = [this](SendspinConnection* /*conn*/, uint8_t* payload,
                                            size_t len) {
        this->process_binary_message_(payload, len);
    };
    client_conn->on_handshake_complete = [this](SendspinConnection* conn) {
        this->on_connection_handshake_complete_(conn);
    };
    client_conn->on_disconnected = [this](SendspinConnection* conn) {
        // Defer to loop() — this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->event_mutex_);
        this->pending_disconnect_events_.push_back(conn);
    };

    client_conn->init_time_filter();

    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        SS_LOGD(TAG, "Existing connection active, new connection will go through handoff");
        this->pending_connection_ = std::move(client_conn);
        this->pending_connection_->start();
    } else {
        this->current_connection_ = std::move(client_conn);
        this->current_connection_->start();
    }
}

void SendspinClient::disconnect(SendspinGoodbyeReason reason) {
    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        this->current_connection_->disconnect(reason, nullptr);
    }
}

void SendspinClient::loop() {
    // Process deferred connection lifecycle events (queued by httpd/WebSocket thread callbacks)
    {
        std::vector<int> close_events;
        std::vector<SendspinConnection*> disconnect_events;
        bool release_dying = false;
        {
            std::lock_guard<std::mutex> lock(this->event_mutex_);
            close_events.swap(this->pending_close_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            release_dying = this->dying_connection_ready_to_release_;
            this->dying_connection_ready_to_release_ = false;
        }
        // Server connection close events (ESP httpd)
        for (int sockfd : close_events) {
            if (this->current_connection_ != nullptr &&
                this->current_connection_->get_sockfd() == sockfd) {
                this->on_connection_lost_(this->current_connection_.get());
            } else if (this->pending_connection_ != nullptr &&
                       this->pending_connection_->get_sockfd() == sockfd) {
                this->on_connection_lost_(this->pending_connection_.get());
            }
        }
        // Client connection disconnect events (host IXWebSocket)
        for (SendspinConnection* conn : disconnect_events) {
            this->on_connection_lost_(conn);
        }
        if (release_dying) {
            this->dying_connection_.reset();
        }
    }

#ifdef SENDSPIN_ENABLE_PLAYER
    // Process queued player stream lifecycle callbacks in order.
    // STREAM_END/CLEAR block until the sync task has gone idle (audio fully stopped).
    // STREAM_START fires immediately but is queued behind any pending end/clear to
    // guarantee the consumer always sees end → start ordering.
    if (!this->awaiting_sync_idle_events_.empty()) {
        bool sync_idle = !this->sync_task_->is_running();
        size_t processed = 0;

        for (auto& event : this->awaiting_sync_idle_events_) {
            if ((event.type == StreamCallbackType::STREAM_END ||
                 event.type == StreamCallbackType::STREAM_CLEAR) &&
                !sync_idle) {
                break;  // Wait for sync task to go idle before firing this and anything after it
            }

            switch (event.type) {
                case StreamCallbackType::STREAM_END:
                    if (this->on_stream_end) {
                        this->on_stream_end();
                    }
                    if (this->high_performance_requested_for_playback_ &&
                        this->on_release_high_performance) {
                        this->on_release_high_performance();
                        this->high_performance_requested_for_playback_ = false;
                    }
                    break;
                case StreamCallbackType::STREAM_CLEAR:
                    if (this->on_stream_clear) {
                        this->on_stream_clear();
                    }
                    break;
                case StreamCallbackType::STREAM_START:
                    if (event.player_stream.has_value()) {
                        this->current_stream_params_ = std::move(event.player_stream.value());
                    }
                    if (this->on_stream_start) {
                        this->on_stream_start();
                    }
                    this->sync_task_->signal_stream_start();
                    break;
                default:
                    break;
            }
            ++processed;
        }

        if (processed > 0) {
            this->awaiting_sync_idle_events_.erase(
                this->awaiting_sync_idle_events_.begin(),
                this->awaiting_sync_idle_events_.begin() + static_cast<ptrdiff_t>(processed));
        }
    }
#endif  // SENDSPIN_ENABLE_PLAYER

    // Handle time synchronization for the active connection via burst strategy
    if (this->current_connection_ != nullptr) {
        auto result = this->time_burst_->loop(this->current_connection_.get());

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
        if (result.burst_completed && this->on_time_sync_updated &&
            this->current_connection_->get_time_filter()) {
            this->on_time_sync_updated(
                static_cast<float>(this->current_connection_->get_time_filter()->get_error()));
        }
    }

    // Start the WebSocket server when network is connected
    if (this->ws_server_ != nullptr && !this->ws_server_->is_started()) {
        if (this->is_network_ready && this->is_network_ready()) {
            this->ws_server_->start(this, this->config_.psram_stack, this->task_priority_);
        }
    }

    // Call loop on the current connection if it exists
    if (this->current_connection_ != nullptr) {
        this->current_connection_->loop();
    }

    // Call loop on pending connection if it exists (during handoff)
    if (this->pending_connection_ != nullptr) {
        this->pending_connection_->loop();
    }

    // Check hello retry timer
    if (this->hello_retry_.retry_time_us > 0 &&
        platform_time_us() >= this->hello_retry_.retry_time_us) {
        this->hello_retry_.retry_time_us = 0;
        SendspinConnection* conn = this->hello_retry_.conn;

        // Verify connection is still valid
        if (conn == this->current_connection_.get() || conn == this->pending_connection_.get()) {
            if (!this->send_hello_message_(this->hello_retry_.attempts - 1, conn)) {
                // Transient failure - retry with exponential backoff
                if (this->hello_retry_.attempts > 1) {
                    this->hello_retry_.delay_ms *= 2;
                    this->hello_retry_.attempts--;
                    this->hello_retry_.retry_time_us =
                        platform_time_us() +
                        static_cast<int64_t>(this->hello_retry_.delay_ms) * 1000;
                }
            }
        }
    }

    // Process deferred events — all state mutations and user callbacks happen here,
    // on the main loop thread, to avoid cross-thread data races.
    {
        std::vector<TimeResponseEvent> time_events;
        std::vector<GroupUpdateObject> group_events;
        std::vector<ServerHelloEvent> hello_events;
        std::vector<ServerCommandEvent> command_events;
        std::vector<StreamCallbackEvent> stream_callback_events;
#ifdef SENDSPIN_ENABLE_METADATA
        std::vector<ServerMetadataStateObject> metadata_events;
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
        std::vector<ServerStateControllerObject> controller_state_events;
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
        std::vector<SendspinClientState> state_events;
#endif

        {
            std::lock_guard<std::mutex> lock(this->event_mutex_);
            time_events.swap(this->pending_time_events_);
            hello_events.swap(this->pending_hello_events_);
            command_events.swap(this->pending_command_events_);
            stream_callback_events.swap(this->pending_stream_callback_events_);
#ifdef SENDSPIN_ENABLE_METADATA
            metadata_events.swap(this->pending_metadata_events_);
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
            controller_state_events.swap(this->pending_controller_state_events_);
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
            state_events.swap(this->pending_state_events_);
#endif
            group_events.swap(this->pending_group_events_);
        }

        // --- Server hello events (handshake completion, handoff logic) ---
        for (auto& event : hello_events) {
            this->server_information_ = std::move(event.server);

            // Verify the connection is still one we manage
            if (event.conn == this->current_connection_.get() ||
                event.conn == this->pending_connection_.get()) {
                this->on_connection_handshake_complete_(event.conn);
            }
        }

#ifdef SENDSPIN_ENABLE_PLAYER
        // --- Client state events (deferred from sync task thread) ---
        if (!state_events.empty()) {
            this->update_state(state_events.back());
        }
#endif

        // --- Time sync events ---
        for (const auto& event : time_events) {
            if (this->current_connection_ != nullptr) {
                this->time_burst_->on_time_response(this->current_connection_.get(), event.offset,
                                                    event.max_error, event.timestamp);
            }
        }

#ifdef SENDSPIN_ENABLE_CONTROLLER
        // --- Controller state events ---
        for (auto& controller_state : controller_state_events) {
            this->controller_state_ = std::move(controller_state);
        }
#endif

#ifdef SENDSPIN_ENABLE_PLAYER
        // --- Server command events (volume, mute, static delay) ---
        for (const auto& cmd_event : command_events) {
            const auto& cmd_msg = cmd_event.command;
            if (!cmd_msg.player.has_value()) {
                continue;
            }

            const ServerPlayerCommandObject& player_cmd = cmd_msg.player.value();

            if (player_cmd.command == SendspinPlayerCommand::VOLUME &&
                player_cmd.volume.has_value()) {
                this->update_volume(player_cmd.volume.value());
                if (this->on_volume_changed) {
                    this->on_volume_changed(player_cmd.volume.value());
                }
            }

            if (player_cmd.command == SendspinPlayerCommand::MUTE && player_cmd.mute.has_value()) {
                this->update_muted(player_cmd.mute.value());
                if (this->on_mute_changed) {
                    this->on_mute_changed(player_cmd.mute.value());
                }
            }

            if (player_cmd.command == SendspinPlayerCommand::SET_STATIC_DELAY &&
                player_cmd.static_delay_ms.has_value()) {
                this->update_static_delay(player_cmd.static_delay_ms.value());
                if (this->on_static_delay_changed) {
                    this->on_static_delay_changed(player_cmd.static_delay_ms.value());
                }
            }
        }
#endif  // SENDSPIN_ENABLE_PLAYER

        // --- Stream lifecycle callback events ---
        for (auto& stream_event : stream_callback_events) {
            switch (stream_event.type) {
#ifdef SENDSPIN_ENABLE_PLAYER
                case StreamCallbackType::STREAM_START:
                case StreamCallbackType::STREAM_END:
                case StreamCallbackType::STREAM_CLEAR:
                    // Queue all player stream events so they fire in order.
                    // STREAM_END/CLEAR wait for sync task idle before firing;
                    // STREAM_START is held back too if a previous end/clear is still waiting,
                    // to guarantee the consumer always sees end → start ordering.
                    this->awaiting_sync_idle_events_.push_back(std::move(stream_event));
                    break;
#endif  // SENDSPIN_ENABLE_PLAYER
#ifdef SENDSPIN_ENABLE_ARTWORK
                case StreamCallbackType::ARTWORK_STREAM_END:
                    if (this->on_image) {
                        for (const auto& pref : this->preferred_image_formats_) {
                            this->on_image(pref.slot, nullptr, 0, pref.format, 0);
                        }
                    }
                    break;
#endif  // SENDSPIN_ENABLE_ARTWORK
#ifdef SENDSPIN_ENABLE_VISUALIZER
                case StreamCallbackType::VISUALIZER_STREAM_START:
                    if (stream_event.visualizer_stream.has_value() &&
                        this->on_visualizer_stream_start) {
                        this->on_visualizer_stream_start(stream_event.visualizer_stream.value());
                    }
                    break;
                case StreamCallbackType::VISUALIZER_STREAM_END:
                    if (this->on_visualizer_stream_end) {
                        this->on_visualizer_stream_end();
                    }
                    break;
                case StreamCallbackType::VISUALIZER_STREAM_CLEAR:
                    if (this->on_visualizer_stream_clear) {
                        this->on_visualizer_stream_clear();
                    }
                    break;
#endif  // SENDSPIN_ENABLE_VISUALIZER
            }
        }

#ifdef SENDSPIN_ENABLE_METADATA
        // --- Metadata events ---
        for (const auto& metadata_update : metadata_events) {
            apply_metadata_state_deltas(&this->metadata_, metadata_update);
            if (this->on_metadata) {
                this->on_metadata(this->metadata_);
            }
        }
#endif  // SENDSPIN_ENABLE_METADATA

        // --- Group update events ---
        for (const auto& group_update : group_events) {
            apply_group_update_deltas(&this->group_state_, group_update);

            if (this->on_group_update) {
                this->on_group_update(group_update);
            }

            // Persist last played server when playback starts
            if (group_update.playback_state.has_value() &&
                group_update.playback_state.value() == SendspinPlaybackState::PLAYING) {
                if (this->current_connection_ != nullptr) {
                    const std::string& server_id = this->current_connection_->get_server_id();
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

// --- Audio ---

#ifdef SENDSPIN_ENABLE_PLAYER

void SendspinClient::set_audio_sink(AudioSink* sink) {
    this->audio_sink_ = sink;

    // Initialize and start sync task now that we have an audio sink (may have been deferred from
    // start_server)
    if (sink != nullptr && !this->config_.audio_formats.empty() &&
        !this->sync_task_->is_initialized()) {
        SS_LOGI(TAG, "Initializing sync task (buffer: %zu bytes, formats: %zu)",
                this->config_.audio_buffer_capacity, this->config_.audio_formats.size());
        if (!this->sync_task_->init(this->make_sync_time_provider_(), sink,
                                    this->config_.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
        } else if (!this->sync_task_->start(this->config_.psram_stack)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
        }
    } else if (sink != nullptr && !this->sync_task_->is_initialized()) {
        SS_LOGW(TAG, "Audio sink set but no audio formats configured (%zu formats)",
                this->config_.audio_formats.size());
    }
}

void SendspinClient::notify_audio_played(uint32_t frames, int64_t timestamp) {
    if (this->sync_task_ && this->sync_task_->is_running()) {
        this->sync_task_->notify_audio_played(frames, timestamp);
    }
}

bool SendspinClient::write_audio_chunk(const uint8_t* data, size_t size, int64_t timestamp,
                                       ChunkType type, uint32_t timeout_ms) {
    return this->sync_task_->write_audio_chunk(data, size, timestamp, type, timeout_ms);
}

#endif  // SENDSPIN_ENABLE_PLAYER

// --- State updates ---

#ifdef SENDSPIN_ENABLE_PLAYER

void SendspinClient::update_volume(uint8_t volume) {
    this->volume_ = volume;
    this->publish_client_state_(this->current_connection_.get());
}

void SendspinClient::update_muted(bool muted) {
    this->muted_ = muted;
    this->publish_client_state_(this->current_connection_.get());
}

void SendspinClient::update_static_delay(uint16_t delay_ms) {
    if (delay_ms > 5000) {
        delay_ms = 5000;
    }
    this->static_delay_ms_ = delay_ms;
    this->persist_static_delay_();
    this->publish_client_state_(this->current_connection_.get());
}

void SendspinClient::set_static_delay_adjustable(bool adjustable) {
    this->static_delay_adjustable_ = adjustable;
    this->publish_client_state_(this->current_connection_.get());
}

#endif  // SENDSPIN_ENABLE_PLAYER

void SendspinClient::update_state(SendspinClientState state) {
    this->state_ = state;
    this->publish_client_state_(this->current_connection_.get());
}

#ifdef SENDSPIN_ENABLE_CONTROLLER

void SendspinClient::send_command(SendspinControllerCommand cmd, std::optional<uint8_t> volume,
                                  std::optional<bool> mute) {
    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        std::string command_message = format_client_command_message(cmd, volume, mute);
        this->current_connection_->send_text_message(command_message, nullptr);
    }
}

#endif  // SENDSPIN_ENABLE_CONTROLLER

// --- Queries ---

bool SendspinClient::is_connected() const {
    return this->current_connection_ != nullptr && this->current_connection_->is_connected() &&
           this->current_connection_->is_handshake_complete();
}

bool SendspinClient::is_time_synced() const {
    if (this->current_connection_ == nullptr) {
        return false;
    }
    return this->current_connection_->is_time_synced();
}

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    if (this->current_connection_ == nullptr) {
        return 0;
    }
    return this->current_connection_->get_client_time(server_time);
}

#ifdef SENDSPIN_ENABLE_METADATA

uint32_t SendspinClient::get_track_progress_ms() const {
    if (!this->metadata_.progress.has_value()) {
        return 0;
    }

    const auto& progress = this->metadata_.progress.value();

    // If paused (playback_speed == 0), return the snapshot value directly
    if (progress.playback_speed == 0) {
        return progress.track_progress;
    }

    int64_t client_target = this->get_client_time(this->metadata_.timestamp);
    if (client_target == 0) {
        return progress.track_progress;
    }

    // calculated_progress = track_progress + (now - metadata_client_time) * playback_speed /
    // 1_000_000
    int64_t elapsed_us = platform_time_us() - client_target;
    int64_t calculated = static_cast<int64_t>(progress.track_progress) +
                         elapsed_us * static_cast<int64_t>(progress.playback_speed) / 1000000;

    if (progress.track_duration != 0) {
        calculated = std::max(std::min(calculated, static_cast<int64_t>(progress.track_duration)),
                              static_cast<int64_t>(0));
    } else {
        calculated = std::max(calculated, static_cast<int64_t>(0));
    }

    return static_cast<uint32_t>(calculated);
}

uint32_t SendspinClient::get_track_duration_ms() const {
    if (!this->metadata_.progress.has_value()) {
        return 0;
    }
    return this->metadata_.progress.value().track_duration;
}

#endif  // SENDSPIN_ENABLE_METADATA

// --- Image slot management ---

#ifdef SENDSPIN_ENABLE_ARTWORK

void SendspinClient::add_image_preferred_format(const ImageSlotPreference& pref) {
    this->preferred_image_formats_.push_back(pref);
    this->config_.artwork_channels.push_back({pref.source, pref.format, pref.width, pref.height});
}

#endif  // SENDSPIN_ENABLE_ARTWORK

// --- Hello handshake ---

void SendspinClient::initiate_hello_(SendspinConnection* conn) {
    // Set up retry state: 100ms initial delay, 3 attempts
    this->hello_retry_.conn = conn;
    this->hello_retry_.delay_ms = 100;
    this->hello_retry_.attempts = 3;
    this->hello_retry_.retry_time_us = platform_time_us() + 100 * 1000;  // 100ms from now
}

bool SendspinClient::send_hello_message_(uint8_t remaining_attempts, SendspinConnection* conn) {
    // Verify the connection is still one of our managed connections
    if (conn != this->current_connection_.get() && conn != this->pending_connection_.get()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    ClientHelloMessage msg;
    msg.client_id = this->config_.client_id;
    msg.name = this->config_.name;

    DeviceInfoObject device_info;
    device_info.product_name = this->config_.product_name;
    device_info.manufacturer = this->config_.manufacturer;
    device_info.software_version = this->config_.software_version;
    msg.device_info = device_info;

    msg.version = 1;

    std::vector<SendspinRole> supported_roles;

#ifdef SENDSPIN_ENABLE_CONTROLLER
    // Controller role
    if (this->config_.controller) {
        supported_roles.push_back(SendspinRole::CONTROLLER);
    }
#endif

#ifdef SENDSPIN_ENABLE_PLAYER
    // Player role
    if (!this->config_.audio_formats.empty()) {
        supported_roles.push_back(SendspinRole::PLAYER);

        // Advertise 80% of the buffer capacity to account for ring buffer metadata overhead
        // and rapid stop/start scenarios
        PlayerSupportObject player_support = {
            .supported_formats = this->config_.audio_formats,
            .buffer_capacity = this->config_.audio_buffer_capacity * 4 / 5,
            .supported_commands = {SendspinPlayerCommand::VOLUME, SendspinPlayerCommand::MUTE},
        };
        msg.player_v1_support = player_support;
    }
#endif

#ifdef SENDSPIN_ENABLE_METADATA
    // Metadata role
    if (this->config_.metadata) {
        supported_roles.push_back(SendspinRole::METADATA);
    }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
    // Artwork role
    if (!this->config_.artwork_channels.empty()) {
        supported_roles.push_back(SendspinRole::ARTWORK);

        ArtworkSupportObject artwork_support = {
            .channels = this->config_.artwork_channels,
        };
        msg.artwork_v1_support = artwork_support;
    }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    // Visualizer role
    if (this->config_.visualizer.has_value()) {
        supported_roles.push_back(SendspinRole::VISUALIZER);
        msg.visualizer_support = this->config_.visualizer.value();
    }
#endif

    msg.supported_roles = supported_roles;

    std::string hello_message = format_client_hello_message(&msg);

    SsErr err =
        conn->send_text_message(hello_message, [conn](bool success, int64_t actual_send_time) {
            if (success) {
                conn->set_client_hello_sent(true);
                conn->set_last_sent_time_message(actual_send_time);
            } else {
                SS_LOGW(TAG, "Hello message send failed");
            }
        });

    if (err == SsErr::OK) {
        return true;  // Successfully queued
    }

    if (err == SsErr::INVALID_STATE) {
        SS_LOGW(TAG, "No client connected for hello message");
        return true;  // Don't retry
    }

    SS_LOGW(TAG, "Failed to queue hello message (err=%d), %d attempts remaining",
            static_cast<int>(err), remaining_attempts);
    return false;
}

// --- Connection management ---

void SendspinClient::on_new_connection_(std::unique_ptr<SendspinServerConnection> conn) {
    // Called from httpd open_callback thread. Connection pointer assignment must happen inline
    // because the httpd find_connection_callback needs to locate this connection immediately
    // for subsequent message routing on the same thread.
    conn->init_time_filter();

    // Set up message callbacks
    conn->on_json_message = [this](SendspinConnection* c, const std::string& message,
                                   int64_t timestamp) {
        this->process_json_message_(c, message, timestamp);
    };
    conn->on_binary_message = [this](SendspinConnection* /*c*/, uint8_t* payload, size_t len) {
        this->process_binary_message_(payload, len);
    };
    conn->on_handshake_complete = [this](SendspinConnection* c) {
        this->on_connection_handshake_complete_(c);
    };
    conn->on_connected = [this](SendspinConnection* c) { this->initiate_hello_(c); };
    conn->on_disconnected = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_closed_ triggered by the server
    };

    if (this->current_connection_ == nullptr) {
        SS_LOGD(TAG, "No existing connection, accepting as current");
        this->current_connection_ = std::move(conn);
    } else {
        SS_LOGD(TAG, "Existing connection present, setting as pending for handoff");
        if (this->pending_connection_ != nullptr) {
            SS_LOGW(TAG, "Already have pending connection, rejecting new connection");
            this->disconnect_and_release_(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
            return;
        }
        this->pending_connection_ = std::move(conn);
    }
}

void SendspinClient::on_connection_handshake_complete_(SendspinConnection* conn) {
    SS_LOGI(TAG, "Connection handshake complete: server_id=%s, connection_reason=%s",
            conn->get_server_id().c_str(), to_cstr(conn->get_connection_reason()));

#ifdef SENDSPIN_ENABLE_PLAYER
    // Send client state so server knows our current volume
    if (!this->config_.audio_formats.empty()) {
        this->publish_client_state_(conn);
    }
#endif

    // Check if this is the pending connection completing authentication
    if (this->pending_connection_ != nullptr && this->pending_connection_.get() == conn) {
        bool should_switch =
            this->should_switch_to_new_server_(this->current_connection_.get(), conn);
        SS_LOGI(TAG, "Handoff decision: %s", should_switch ? "switch to new" : "keep current");
        this->complete_handoff_(should_switch);
    }
}

void SendspinClient::on_connection_closed_(int sockfd) {
    SS_LOGD(TAG, "Connection closed callback for socket %d", sockfd);

    // Defer the actual cleanup to loop() to avoid use-after-free.
    // This callback runs in the httpd thread, but there may be pending httpd_queue_work items
    // (e.g., async_send_text) with raw pointers to the connection object. If we destroy the
    // connection here, those pending work items would dereference freed memory when processed.
    std::lock_guard<std::mutex> lock(this->event_mutex_);
    this->pending_close_events_.push_back(sockfd);
}

void SendspinClient::on_connection_lost_(SendspinConnection* conn) {
    if (conn == nullptr) {
        return;
    }

    if (this->current_connection_ != nullptr && this->current_connection_.get() == conn) {
        SS_LOGI(TAG, "Current connection lost");
        this->time_burst_->reset();
        this->cleanup_connection_state_();
        this->current_connection_.reset();

        if (this->pending_connection_ != nullptr) {
            SS_LOGD(TAG, "Promoting pending connection to current");
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else if (this->pending_connection_ != nullptr && this->pending_connection_.get() == conn) {
        SS_LOGD(TAG, "Pending connection lost");
        this->pending_connection_.reset();
    }
}

bool SendspinClient::should_switch_to_new_server_(SendspinConnection* current,
                                                  SendspinConnection* new_conn) {
    if (current == nullptr || new_conn == nullptr) {
        return new_conn != nullptr;
    }

    auto new_reason = new_conn->get_connection_reason();
    auto current_reason = current->get_connection_reason();

    // New server wants playback -> switch to new
    if (new_reason == SendspinConnectionReason::PLAYBACK) {
        SS_LOGD(TAG, "New server has playback reason, switching");
        return true;
    }

    // New is discovery, current had playback -> keep current
    if (new_reason == SendspinConnectionReason::DISCOVERY &&
        current_reason == SendspinConnectionReason::PLAYBACK) {
        SS_LOGD(TAG, "New is discovery, current had playback, keeping current");
        return false;
    }

    // Both discovery -> prefer last played server
    if (this->has_last_played_server_) {
        if (fnv1_hash(new_conn->get_server_id().c_str()) == this->last_played_server_hash_) {
            SS_LOGD(TAG, "New server matches last played server, switching");
            return true;
        }
        if (fnv1_hash(current->get_server_id().c_str()) == this->last_played_server_hash_) {
            SS_LOGD(TAG, "Current server matches last played server, keeping");
            return false;
        }
    }

    SS_LOGD(TAG, "Default handoff decision: keep existing");
    return false;
}

void SendspinClient::complete_handoff_(bool switch_to_new) {
    if (switch_to_new) {
        SS_LOGD(TAG, "Completing handoff: switching to new server");
        if (this->current_connection_ != nullptr) {
            this->time_burst_->reset();
            this->cleanup_connection_state_();
            auto old_current = std::move(this->current_connection_);
            this->current_connection_ = std::move(this->pending_connection_);
            this->disconnect_and_release_(std::move(old_current),
                                          SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else {
        SS_LOGD(TAG, "Completing handoff: keeping current server");
        if (this->pending_connection_ != nullptr) {
            this->disconnect_and_release_(std::move(this->pending_connection_),
                                          SendspinGoodbyeReason::ANOTHER_SERVER);
        }
    }
}

void SendspinClient::disconnect_and_release_(std::unique_ptr<SendspinConnection> conn,
                                             SendspinGoodbyeReason reason) {
    this->dying_connection_ = std::shared_ptr<SendspinConnection>(std::move(conn));
    this->dying_connection_->disconnect(reason, [this]() {
        // Defer the actual destruction to loop() to avoid use-after-free.
        // This callback runs in the httpd worker thread (async_send_text), but the connection
        // must stay alive until all pending httpd_queue_work items have been processed.
        std::lock_guard<std::mutex> lock(this->event_mutex_);
        this->dying_connection_ready_to_release_ = true;
    });
}

void SendspinClient::cleanup_connection_state_() {
    SS_LOGV(TAG, "Cleaning up connection state");

#ifdef SENDSPIN_ENABLE_PLAYER
    // Signal sync task to clear all buffered audio (non-blocking)
    this->sync_task_->signal_stream_clear();
    if (this->on_stream_end) {
        this->on_stream_end();
    }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->on_visualizer_stream_end) {
        this->on_visualizer_stream_end();
    }
#endif

#ifdef SENDSPIN_ENABLE_PLAYER
    // Release high-performance networking
    if (this->high_performance_requested_for_time_ && this->on_release_high_performance) {
        this->on_release_high_performance();
        this->high_performance_requested_for_time_ = false;
    }
    if (this->high_performance_requested_for_playback_ && this->on_release_high_performance) {
        this->on_release_high_performance();
        this->high_performance_requested_for_playback_ = false;
    }
#endif
}

// --- Message processing ---

void SendspinClient::process_binary_message_(uint8_t* payload, size_t len) {
    if (len < 2) {
        return;
    }

    uint8_t binary_type = payload[0];
    uint8_t role = get_binary_role(binary_type);
    [[maybe_unused]] uint8_t slot = get_binary_slot(binary_type);

    switch (role) {
#ifdef SENDSPIN_ENABLE_PLAYER
        case SENDSPIN_ROLE_PLAYER: {
            if (len < SENDSPIN_BINARY_CHUNK_HEADER_SIZE) {
                return;
            }

            int64_t server_timestamp = be64_to_host(payload + 1);

            if (!this->config_.audio_formats.empty()) {
                if (slot == 0) {
                    if (!this->send_audio_chunk_(payload + SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                                 len - SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                                                 server_timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
                        SS_LOGW(TAG, "Failed to send audio chunk");
                    }
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
            break;
        }
#endif  // SENDSPIN_ENABLE_PLAYER
#ifdef SENDSPIN_ENABLE_ARTWORK
        case SENDSPIN_ROLE_ARTWORK: {
            if (len < SENDSPIN_BINARY_CHUNK_HEADER_SIZE) {
                return;
            }

            int64_t server_timestamp = be64_to_host(payload + 1);

            if (!this->preferred_image_formats_.empty() && this->on_image) {
                SendspinImageFormat image_format = SendspinImageFormat::JPEG;
                for (const auto& pref : this->preferred_image_formats_) {
                    if (pref.slot == slot) {
                        image_format = pref.format;
                        break;
                    }
                }
                this->on_image(slot, payload + SENDSPIN_BINARY_CHUNK_HEADER_SIZE,
                               len - SENDSPIN_BINARY_CHUNK_HEADER_SIZE, image_format,
                               server_timestamp);
            }
            break;
        }
#endif  // SENDSPIN_ENABLE_ARTWORK
#ifdef SENDSPIN_ENABLE_VISUALIZER
        case SENDSPIN_ROLE_VISUALIZER: {
            if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT) {
                if (this->on_beat_data) {
                    this->on_beat_data(payload, len);
                }
            } else {
                if (this->on_visualizer_data) {
                    this->on_visualizer_data(payload, len);
                }
            }
            break;
        }
#endif  // SENDSPIN_ENABLE_VISUALIZER
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

#ifdef SENDSPIN_ENABLE_PLAYER
            // Player stream start — ring buffer writes and sync task management stay inline
            // to preserve ordering with binary audio chunks. State updates and user callbacks
            // are deferred to loop().
            if (!this->config_.audio_formats.empty()) {
                // Request high-performance networking for playback
                if (!this->high_performance_requested_for_playback_ &&
                    this->on_request_high_performance) {
                    this->on_request_high_performance();
                    this->high_performance_requested_for_playback_ = true;
                }

                if (stream_msg.player.has_value()) {
                    const ServerPlayerStreamObject& player_obj = stream_msg.player.value();

                    // The codec header written to the ring buffer below wakes the idle sync task.

                    if (!player_obj.bit_depth.has_value() || !player_obj.channels.has_value() ||
                        !player_obj.sample_rate.has_value() || !player_obj.codec.has_value()) {
                        SS_LOGE(TAG, "Stream start message missing required audio parameters");
                        break;
                    }

                    auto codec = player_obj.codec.value();
                    bool header_sent = false;

                    if ((codec == SendspinCodecFormat::PCM) ||
                        (codec == SendspinCodecFormat::OPUS)) {
                        DummyHeader header;
                        header.sample_rate = player_obj.sample_rate.value();
                        header.bits_per_sample = player_obj.bit_depth.value();
                        header.channels = player_obj.channels.value();

                        ChunkType chunk_type = (codec == SendspinCodecFormat::PCM)
                                                   ? CHUNK_TYPE_PCM_DUMMY_HEADER
                                                   : CHUNK_TYPE_OPUS_DUMMY_HEADER;

                        header_sent =
                            this->send_audio_chunk_(reinterpret_cast<const uint8_t*>(&header),
                                                    sizeof(DummyHeader), 0, chunk_type, 100);
                    } else if (codec == SendspinCodecFormat::FLAC) {
                        if (!player_obj.codec_header.has_value()) {
                            SS_LOGE(TAG, "FLAC codec header missing");
                            break;
                        }
                        std::vector<uint8_t> flac_header =
                            base64_decode(player_obj.codec_header.value());
                        header_sent = this->send_audio_chunk_(
                            flac_header.data(), flac_header.size(), 0, CHUNK_TYPE_FLAC_HEADER, 100);
                    }

                    if (!header_sent) {
                        SS_LOGE(TAG, "Failed to send codec header");
                        this->sync_task_->signal_stream_end();
                        // Defer stream_end callback
                        std::lock_guard<std::mutex> lock(this->event_mutex_);
                        this->pending_stream_callback_events_.push_back(
                            StreamCallbackEvent{StreamCallbackType::STREAM_END});
                        break;
                    }

                    // Defer stream params update and callback to loop()
                    {
                        std::lock_guard<std::mutex> lock(this->event_mutex_);
                        StreamCallbackEvent event{StreamCallbackType::STREAM_START};
                        event.player_stream = player_obj;
                        this->pending_stream_callback_events_.push_back(std::move(event));
                    }
                } else {
                    // No player in stream start — sync task is already running (idle)
                    {
                        std::lock_guard<std::mutex> lock(this->event_mutex_);
                        this->pending_stream_callback_events_.push_back(
                            StreamCallbackEvent{StreamCallbackType::STREAM_START});
                    }
                }
            } else {
                // No audio formats, just defer stream start callback
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                this->pending_stream_callback_events_.push_back(
                    StreamCallbackEvent{StreamCallbackType::STREAM_START});
            }
#endif  // SENDSPIN_ENABLE_PLAYER

#ifdef SENDSPIN_ENABLE_VISUALIZER
            // Defer visualizer stream start callback to loop()
            if (stream_msg.visualizer.has_value()) {
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                StreamCallbackEvent event{StreamCallbackType::VISUALIZER_STREAM_START};
                event.visualizer_stream = stream_msg.visualizer.value();
                this->pending_stream_callback_events_.push_back(std::move(event));
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
                if (end_player) {
                    // Signal sync task to end stream (non-blocking) — it drains and goes idle
                    this->sync_task_->signal_stream_end();
                    // Defer user callback and high-performance release to loop()
                    std::lock_guard<std::mutex> lock(this->event_mutex_);
                    this->pending_stream_callback_events_.push_back(
                        StreamCallbackEvent{StreamCallbackType::STREAM_END});
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (end_artwork) {
                    std::lock_guard<std::mutex> lock(this->event_mutex_);
                    this->pending_stream_callback_events_.push_back(
                        StreamCallbackEvent{StreamCallbackType::ARTWORK_STREAM_END});
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (end_visualizer) {
                    std::lock_guard<std::mutex> lock(this->event_mutex_);
                    this->pending_stream_callback_events_.push_back(
                        StreamCallbackEvent{StreamCallbackType::VISUALIZER_STREAM_END});
                }
#endif
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

                std::lock_guard<std::mutex> lock(this->event_mutex_);
#ifdef SENDSPIN_ENABLE_PLAYER
                if (clear_player) {
                    this->sync_task_->signal_stream_clear();
                    this->pending_stream_callback_events_.push_back(
                        StreamCallbackEvent{StreamCallbackType::STREAM_CLEAR});
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (clear_visualizer) {
                    this->pending_stream_callback_events_.push_back(
                        StreamCallbackEvent{StreamCallbackType::VISUALIZER_STREAM_CLEAR});
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
                    // Set connection state inline — these are owned by the connection object
                    // and must be set before subsequent messages arrive on this connection.
                    conn->set_server_id(hello_msg.server.server_id);
                    conn->set_server_name(hello_msg.server.name);
                    conn->set_connection_reason(hello_msg.connection_reason);
                    conn->set_server_hello_received(true);

                    // Defer handshake completion to loop() — it triggers handoff logic,
                    // connection pointer manipulation, and state publishing.
                    std::lock_guard<std::mutex> lock(this->event_mutex_);
                    this->pending_hello_events_.push_back(
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
                std::lock_guard<std::mutex> lock(this->event_mutex_);
#ifdef SENDSPIN_ENABLE_CONTROLLER
                if (state_msg.controller.has_value()) {
                    this->pending_controller_state_events_.push_back(
                        std::move(state_msg.controller.value()));
                }
#endif

#ifdef SENDSPIN_ENABLE_METADATA
                if (state_msg.metadata.has_value()) {
                    this->pending_metadata_events_.push_back(state_msg.metadata.value());
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_COMMAND: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->config_.audio_formats.empty()) {
                break;
            }

            ServerCommandMessage cmd_msg;
            if (process_server_command_message(root, &cmd_msg)) {
                if (!cmd_msg.player.has_value()) {
                    SS_LOGV(TAG, "Server command has no player commands");
                    break;
                }

                // Defer command processing to loop() — it updates shared state
                // (volume_, muted_, static_delay_ms_) and fires user callbacks.
                std::lock_guard<std::mutex> lock(this->event_mutex_);
                this->pending_command_events_.push_back({std::move(cmd_msg)});
            }
#endif  // SENDSPIN_ENABLE_PLAYER
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

#ifdef SENDSPIN_ENABLE_PLAYER

bool SendspinClient::send_audio_chunk_(const uint8_t* data, size_t data_size, int64_t timestamp,
                                       ChunkType chunk_type, uint32_t timeout_ms) {
    if (data == nullptr || data_size == 0) {
        SS_LOGE(TAG, "Invalid data passed to send_audio_chunk_");
        return false;
    }

    return this->sync_task_->write_audio_chunk(data, data_size, timestamp, chunk_type, timeout_ms);
}

#endif  // SENDSPIN_ENABLE_PLAYER

// --- State publishing ---

void SendspinClient::publish_client_state_(SendspinConnection* conn) {
    if (conn == nullptr || !conn->is_connected() || !conn->is_handshake_complete()) {
        return;
    }

    ClientStateMessage state_msg;
    state_msg.state = this->state_;

#ifdef SENDSPIN_ENABLE_PLAYER
    if (!this->config_.audio_formats.empty()) {
        ClientPlayerStateObject player_state;
        player_state.volume = this->volume_;
        player_state.muted = this->muted_;
        player_state.static_delay_ms = this->static_delay_ms_;
        if (this->static_delay_adjustable_) {
            player_state.supported_commands = {SendspinPlayerCommand::SET_STATIC_DELAY};
        }
        state_msg.player = player_state;
    }
#endif

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
        this->last_played_server_hash_ = hash.value();
        this->has_last_played_server_ = true;
        SS_LOGI(TAG, "Loaded last played server hash: 0x%08X", this->last_played_server_hash_);
    }
}

void SendspinClient::persist_last_played_server_(const std::string& server_id) {
    if (server_id.empty()) {
        return;
    }

    uint32_t hash = fnv1_hash(server_id.c_str());
    this->last_played_server_hash_ = hash;
    this->has_last_played_server_ = true;

    if (this->save_last_server_hash) {
        if (this->save_last_server_hash(hash)) {
            SS_LOGD(TAG, "Persisted last played server: %s (hash: 0x%08X)", server_id.c_str(),
                    hash);
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

#ifdef SENDSPIN_ENABLE_PLAYER

void SendspinClient::load_static_delay_() {
    if (!this->load_static_delay) {
        // No persistence callback - use initial value from config
        if (this->config_.initial_static_delay_ms > 0) {
            this->static_delay_ms_ = this->config_.initial_static_delay_ms;
            SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms_);
        }
        return;
    }

    auto delay = this->load_static_delay();
    if (delay.has_value()) {
        if (delay.value() <= 5000) {
            this->static_delay_ms_ = delay.value();
            SS_LOGI(TAG, "Loaded static delay: %u ms", this->static_delay_ms_);
        } else {
            SS_LOGW(TAG, "Persisted static delay out of range (%u), ignoring", delay.value());
        }
    } else if (this->config_.initial_static_delay_ms > 0) {
        this->static_delay_ms_ = this->config_.initial_static_delay_ms;
        SS_LOGI(TAG, "Using initial static delay from config: %u ms", this->static_delay_ms_);
    }
}

void SendspinClient::persist_static_delay_() {
    if (this->save_static_delay) {
        if (this->save_static_delay(this->static_delay_ms_)) {
            SS_LOGD(TAG, "Persisted static delay: %u ms", this->static_delay_ms_);
        } else {
            SS_LOGW(TAG, "Failed to persist static delay");
        }
    }
}

#endif  // SENDSPIN_ENABLE_PLAYER

}  // namespace sendspin
