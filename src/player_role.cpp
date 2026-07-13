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

#include "audio_types.h"
#include "platform/base64.h"
#include "platform/compiler.h"
#include "platform/logging.h"
#include "player_role_impl.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

static const char* const TAG = "sendspin.player";

/// @brief Size of the big-endian 64-bit timestamp at the start of player binary messages.
static constexpr size_t BINARY_TIMESTAMP_SIZE = 8;
static constexpr uint16_t MAX_STATIC_DELAY_MS = 5000U;
static constexpr uint32_t HEADER_SEND_TIMEOUT_MS = 100U;
// Denominator for the advertised buffer capacity fraction: advertises (N-1)/N of capacity
static constexpr size_t AUDIO_BUFFER_ADVERTISE_DENOMINATOR = 5;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

namespace sendspin {

// ============================================================================
// Helpers
// ============================================================================

/// @brief Decodes a base64-encoded string into a byte vector.
static std::vector<uint8_t> base64_decode(const std::string& input) {
    size_t output_len = 0;
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

// ============================================================================
// Impl constructor / destructor
// ============================================================================

PlayerRole::Impl::Impl(PlayerRoleConfig config, SendspinClient* client,
                       SendspinPersistenceProvider* persistence)
    : config(std::move(config)),
      client(client),
      event_state(std::make_unique<EventState>()),
      persistence(persistence),
      sync_task(std::make_unique<SyncTask>()) {}

PlayerRole::Impl::~Impl() {
    // Stop the sync task thread first, before destroying other members.
    // External callbacks (e.g., PortAudio) may still call notify_audio_played() on another thread,
    // so the sync task must be stopped while it's still valid.
    this->sync_task.reset();
}

// ============================================================================
// PlayerRole forwarding (public API → Impl)
// ============================================================================

PlayerRole::PlayerRole(PlayerRoleConfig config, SendspinClient* client,
                       SendspinPersistenceProvider* persistence)
    : impl_(std::make_unique<Impl>(std::move(config), client, persistence)) {}

PlayerRole::~PlayerRole() = default;

void PlayerRole::set_listener(PlayerRoleListener* listener) {
    this->impl_->listener = listener;
}

void PlayerRole::notify_audio_played(uint32_t frames, int64_t timestamp) {
    if (this->impl_->sync_task && this->impl_->sync_task->is_running()) {
        this->impl_->sync_task->notify_audio_played(frames, timestamp);
    }
}

void PlayerRole::update_volume(uint8_t volume) {
    this->impl_->update_volume(volume);
}

void PlayerRole::update_muted(bool muted) {
    this->impl_->update_muted(muted);
}

void PlayerRole::update_static_delay(uint16_t delay_ms) {
    this->impl_->update_static_delay(delay_ms);
}

void PlayerRole::set_static_delay_adjustable(bool adjustable) {
    this->impl_->static_delay_adjustable.store(adjustable, std::memory_order_relaxed);
    this->impl_->client->publish_state();
}

const ServerPlayerStreamObject& PlayerRole::get_current_stream_params() const {
    return this->impl_->current_stream_params;
}

int32_t PlayerRole::get_fixed_delay_us() const {
    return this->impl_->config.fixed_delay_us;
}

bool PlayerRole::get_muted() const {
    return this->impl_->muted;
}

uint16_t PlayerRole::get_static_delay_ms() const {
    return this->impl_->get_effective_static_delay_ms();
}

uint8_t PlayerRole::get_volume() const {
    return this->impl_->volume;
}

// ============================================================================
// Impl: State updates
// ============================================================================

void PlayerRole::Impl::update_volume(uint8_t volume) {
    this->volume = volume;
    this->client->publish_state();
}

void PlayerRole::Impl::update_muted(bool muted) {
    this->muted = muted;
    this->client->publish_state();
}

void PlayerRole::Impl::update_static_delay(uint16_t delay_ms) {
    if (delay_ms > MAX_STATIC_DELAY_MS) {
        delay_ms = MAX_STATIC_DELAY_MS;
    }
    this->static_delay_ms.store(delay_ms, std::memory_order_relaxed);
    this->persist_static_delay();
    this->client->publish_state();
}

// ============================================================================
// Impl: Internal integration methods
// ============================================================================

void PlayerRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->stream_params_slot.bind(inbox, INBOX_TOPIC_PLAYER_STREAM_PARAMS);
    this->event_state->command_slot.bind(inbox, INBOX_TOPIC_PLAYER_COMMAND);
    this->event_state->state_slot.bind(inbox, INBOX_TOPIC_PLAYER_STATE);
}

bool PlayerRole::Impl::start() {
    this->load_static_delay();

    if (!this->config.audio_formats.empty() && this->listener &&
        !this->sync_task->is_initialized()) {
        if (!this->sync_task->init(this, this->client, this->config.audio_buffer_capacity)) {
            SS_LOGE(TAG, "Failed to initialize sync task");
            return false;
        }
        if (!this->sync_task->start(this->config.psram_stack, this->config.priority)) {
            SS_LOGE(TAG, "Failed to start sync task thread");
            return false;
        }
    }
    return true;
}

void PlayerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    if (this->config.audio_formats.empty()) {
        return;
    }

    msg.supported_roles.push_back(SendspinRole::PLAYER);

    // Advertise 80% of the buffer capacity to account for ring buffer metadata overhead
    // and rapid stop/start scenarios
    PlayerSupportObject player_support = {
        .supported_formats = this->config.audio_formats,
        .buffer_capacity = this->config.audio_buffer_capacity *
                           (AUDIO_BUFFER_ADVERTISE_DENOMINATOR - 1) /
                           AUDIO_BUFFER_ADVERTISE_DENOMINATOR,
        .supported_commands = {SendspinPlayerCommand::VOLUME, SendspinPlayerCommand::MUTE},
    };
    msg.player_v1_support = player_support;
}

void PlayerRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (this->config.audio_formats.empty()) {
        return;
    }

    ClientPlayerStateObject player_state{};
    player_state.volume = this->volume;
    player_state.muted = this->muted;
    bool adjustable = this->static_delay_adjustable.load(std::memory_order_relaxed);
    player_state.static_delay_ms =
        adjustable ? this->static_delay_ms.load(std::memory_order_relaxed) : 0;
    if (adjustable) {
        player_state.supported_commands = {SendspinPlayerCommand::SET_STATIC_DELAY};
    }
    msg.player = player_state;
}

SS_HOT void PlayerRole::Impl::handle_binary(const uint8_t* data, size_t len) const {
    if (this->config.audio_formats.empty()) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }
    int64_t timestamp = be64_to_host(data);
    if (!this->send_audio_chunk(data + BINARY_TIMESTAMP_SIZE, len - BINARY_TIMESTAMP_SIZE,
                                timestamp, CHUNK_TYPE_ENCODED_AUDIO, 0)) {
        SS_LOGW(TAG, "Failed to send audio chunk");
    }
}

void PlayerRole::Impl::handle_stream_start(const ServerPlayerStreamObject& player_obj) const {
    if (this->config.audio_formats.empty()) {
        // No audio formats, just defer stream start callback
        this->enqueue_stream_event(PlayerStreamCallbackType::STREAM_START);
        return;
    }

    bool header_sent = false;

    if (!player_obj.bit_depth.has_value() || !player_obj.channels.has_value() ||
        !player_obj.sample_rate.has_value() || !player_obj.codec.has_value()) {
        SS_LOGE(TAG, "Stream start message missing required audio parameters");
    } else {
        auto codec = player_obj.codec.value();

        if ((codec == SendspinCodecFormat::PCM) || (codec == SendspinCodecFormat::OPUS)) {
            DummyHeader header{};
            header.sample_rate = player_obj.sample_rate.value();
            header.bits_per_sample = player_obj.bit_depth.value();
            header.channels = player_obj.channels.value();

            ChunkType chunk_type = (codec == SendspinCodecFormat::PCM)
                                       ? CHUNK_TYPE_PCM_DUMMY_HEADER
                                       : CHUNK_TYPE_OPUS_DUMMY_HEADER;

            header_sent =
                this->send_audio_chunk(reinterpret_cast<const uint8_t*>(&header),
                                       sizeof(DummyHeader), 0, chunk_type, HEADER_SEND_TIMEOUT_MS);
            if (!header_sent) {
                SS_LOGE(TAG, "Failed to send codec header");
            }
        } else if (codec == SendspinCodecFormat::FLAC) {
            if (!player_obj.codec_header.has_value()) {
                SS_LOGE(TAG, "FLAC codec header missing");
            } else {
                std::vector<uint8_t> flac_header = base64_decode(player_obj.codec_header.value());
                header_sent =
                    this->send_audio_chunk(flac_header.data(), flac_header.size(), 0,
                                           CHUNK_TYPE_FLAC_HEADER, HEADER_SEND_TIMEOUT_MS);
                if (!header_sent) {
                    SS_LOGE(TAG, "Failed to send codec header");
                }
            }
        } else {
            SS_LOGE(TAG, "Unsupported codec: %d", static_cast<int>(codec));
        }
    }

    if (!header_sent) {
        this->sync_task->signal_stream_end();
        this->enqueue_stream_event(PlayerStreamCallbackType::STREAM_END);
        return;
    }

    // Write stream params to the inbox slot for the main thread, then signal. The high-performance
    // acquire for playback happens when the main loop drains the STREAM_START event, keeping
    // high_performance_requested_for_playback main-thread-only. The params write and the event push
    // are two separate Inbox lock acquisitions, not one critical section: the mutex orders the
    // write before the push for visibility, but a concurrent main-thread cleanup() can slip its
    // stream_params_slot.reset() between them. If that happens the drain takes START and finds the
    // slot empty, so take() returns false and current_stream_params keeps its prior value (see
    // stream_params_slot.take() in drain_events()). That window is benign: the same teardown
    // enqueues a STREAM_END right behind this START.
    this->event_state->stream_params_slot.write(player_obj);
    this->enqueue_stream_event(PlayerStreamCallbackType::STREAM_START);
}

void PlayerRole::Impl::handle_stream_end() const {
    this->sync_task->signal_stream_end();
    this->enqueue_stream_event(PlayerStreamCallbackType::STREAM_END);
}

void PlayerRole::Impl::handle_stream_clear() const {
    // stream/clear is a seek within the active stream: the server flushes our buffered audio and
    // immediately resumes sending new audio with the same codec/params (no new stream/start). Tell
    // the sync task to discard buffered audio, then enqueue a marker so it knows exactly where the
    // discarded (pre-seek) audio ends and the new audio begins. The flag is set before the marker
    // so the sync task starts draining (freeing ring-buffer space) before we write the marker.
    // No listener callback: a seek is not a stream lifecycle event for the consumer.
    this->sync_task->signal_stream_clear();
    if (!this->sync_task->write_audio_chunk(nullptr, 0, 0, CHUNK_TYPE_STREAM_CLEAR_MARKER,
                                            HEADER_SEND_TIMEOUT_MS)) {
        // The marker couldn't be enqueued (ring buffer full). The sync task will still drain to
        // empty and apply the clear, but the pre-seek/post-seek boundary is lost, so new audio
        // may be discarded along with the old.
        SS_LOGW(TAG, "Failed to enqueue stream/clear marker; seek boundary may be imprecise");
    }
}

void PlayerRole::Impl::handle_server_command(const ServerCommandMessage& cmd) const {
    if (!cmd.player.has_value()) {
        SS_LOGV(TAG, "Server command has no player commands");
        return;
    }
    this->event_state->command_slot.merge(
        [](ServerCommandMessage& current, ServerCommandMessage&& delta) {
            if (!delta.player.has_value()) {
                return;
            }
            if (!current.player.has_value()) {
                current.player = delta.player;
                return;
            }
            // Overlay individual optional fields so different command types
            // don't clobber each other when merged between drain ticks
            const auto& dp = delta.player.value();
            auto& cp = current.player.value();
            if (dp.volume.has_value()) {
                cp.volume = dp.volume;
            }
            if (dp.mute.has_value()) {
                cp.mute = dp.mute;
            }
            if (dp.static_delay_ms.has_value()) {
                cp.static_delay_ms = dp.static_delay_ms;
            }
        },
        cmd);
}

void PlayerRole::Impl::on_stream_ring_event(PlayerStreamCallbackType event) {
    this->awaiting_sync_idle_events.push_back(event);
}

void PlayerRole::Impl::drain_events() {
    // --- Client state events (from the sync task, via the latest-wins state slot) ---
    SendspinClientState state{};
    if (this->event_state->state_slot.take(state)) {
        this->client->update_state(state);
    }

    // --- Server command events (volume, mute, static delay) ---
    // Check each field independently since multiple command types may have been
    // merged into one inbox slot between drain ticks.
    ServerCommandMessage cmd_msg{};
    if (this->event_state->command_slot.take(cmd_msg)) {
        if (cmd_msg.player.has_value()) {
            const ServerPlayerCommandObject& player_cmd = cmd_msg.player.value();

            if (player_cmd.volume.has_value()) {
                this->update_volume(player_cmd.volume.value());
                if (this->listener) {
                    this->listener->on_volume_changed(player_cmd.volume.value());
                }
            }

            if (player_cmd.mute.has_value()) {
                this->update_muted(player_cmd.mute.value());
                if (this->listener) {
                    this->listener->on_mute_changed(player_cmd.mute.value());
                }
            }

            if (player_cmd.static_delay_ms.has_value()) {
                this->update_static_delay(player_cmd.static_delay_ms.value());
                if (this->listener) {
                    this->listener->on_static_delay_changed(
                        this->static_delay_ms.load(std::memory_order_relaxed));
                }
            }
        }
    }

    // --- Process awaiting sync idle events ---
    // Stream lifecycle arrivals (STREAM_START/STREAM_END) are appended directly to
    // awaiting_sync_idle_events by on_stream_ring_event(), called from the ring drain in
    // SendspinClient::loop() before role drain_events() runs each tick -- so every event pushed
    // this tick is already in the vector below in FIFO arrival order.
    if (!this->awaiting_sync_idle_events.empty()) {
        bool sync_idle = !this->sync_task->is_running();
        size_t processed = 0;
        bool teardown_reentered = false;

        // Indexed with a fresh size() check per iteration (not a range-for): the listener
        // callbacks below may re-enter connection teardown, whose cleanup() clears this vector
        // mid-loop. Cached range-for iterators would dangle; re-checking size() ends the loop
        // and the clamp before the erase below keeps the range valid.
        for (size_t idx = 0; idx < this->awaiting_sync_idle_events.size(); ++idx) {
            const PlayerStreamCallbackType event = this->awaiting_sync_idle_events[idx];
            if (event == PlayerStreamCallbackType::STREAM_END && !sync_idle) {
                break;  // Wait for sync task to go idle before firing this and anything after it
            }

            switch (event) {
                case PlayerStreamCallbackType::STREAM_END:
                    // Only fire the callback when a stream is actually open: cleanup() enqueues
                    // an unconditional STREAM_END (and a failed stream start enqueues one with no
                    // preceding START), so gating here keeps on_stream_end() paired 1:1 with
                    // on_stream_start()
                    if (this->listener && this->stream_active) {
                        this->listener->on_stream_end();
                    }
                    this->stream_active = false;
                    if (this->high_performance_requested_for_playback) {
                        this->client->release_high_performance();
                        this->high_performance_requested_for_playback = false;
                    }
                    break;
                case PlayerStreamCallbackType::STREAM_START: {
                    // Request high-performance networking for playback (deferred from the
                    // network thread's handle_stream_start so the listener callback and the
                    // pairing flag stay on the main thread)
                    if (!this->config.audio_formats.empty() &&
                        !this->high_performance_requested_for_playback) {
                        this->client->acquire_high_performance();
                        this->high_performance_requested_for_playback = true;
                    }
                    ServerPlayerStreamObject stream_params;
                    if (this->event_state->stream_params_slot.take(stream_params)) {
                        this->current_stream_params = std::move(stream_params);
                    }
                    // Mark the stream active before invoking the listener. on_stream_start() may
                    // re-enter teardown, and the STREAM_END that cleanup() enqueues fires
                    // on_stream_end() only when stream_active is set (see the gate above). Setting
                    // it first keeps start/end paired even when the batch is abandoned below.
                    this->stream_active = true;
                    if (this->listener) {
                        const uint32_t generation = this->cleanup_generation;
                        this->listener->on_stream_start();
                        // on_stream_start() may re-enter connection teardown, whose cleanup()
                        // already ended the stream, cleared this vector, and enqueued a fresh
                        // STREAM_END. Re-arming the sync task below would resurrect the dead
                        // stream, so abandon the batch instead (the clamp below then erases
                        // nothing from the already-cleared vector). stream_active stays true so the
                        // enqueued STREAM_END still delivers a paired on_stream_end().
                        if (this->cleanup_generation != generation) {
                            teardown_reentered = true;
                            break;
                        }
                    }
                    this->sync_task->signal_stream_start();
                    // The sync task sets TASK_RUNNING asynchronously after this signal, so the
                    // pre-loop snapshot is stale now: a STREAM_END later in this same batch must
                    // wait for the just-started task to drain
                    sync_idle = false;
                    break;
                }
            }
            if (teardown_reentered) {
                break;
            }
            ++processed;
        }

        // Clamp: a re-entrant cleanup() may have cleared the vector mid-loop, so processed can
        // exceed the current size.
        if (processed > this->awaiting_sync_idle_events.size()) {
            processed = this->awaiting_sync_idle_events.size();
        }
        if (processed > 0) {
            this->awaiting_sync_idle_events.erase(
                this->awaiting_sync_idle_events.begin(),
                this->awaiting_sync_idle_events.begin() + static_cast<ptrdiff_t>(processed));
        }
    }
}

void PlayerRole::Impl::cleanup() {
    // Flag the teardown for a drain_events() frame that may be on the call stack right now (a
    // listener callback re-entering teardown); see the STREAM_START branch there.
    this->cleanup_generation++;

    // End the current stream: the sync task drains and returns to idle. (Not signal_stream_clear():
    // that path is a seek within a live stream and expects a marker to follow.)
    this->sync_task->signal_stream_end();

    // Discard stale slot content from the dead connection. Stale ring-borne events (an
    // in-flight STREAM_START/STREAM_END queued before this cleanup) are already discarded by
    // SendspinClient::cleanup_connection_state()'s inbox.reset_events() call, which runs before
    // any role's cleanup() -- so there is no per-queue ring reset to do here.
    this->event_state->stream_params_slot.reset();
    this->event_state->command_slot.reset();
    this->event_state->state_slot.reset();

    // Enqueue a clean STREAM_END - drain_events() will fire the callback (the ring was just
    // reset above us, so this push should not fail; enqueue_stream_event() logs if it somehow does)
    this->enqueue_stream_event(PlayerStreamCallbackType::STREAM_END);

    // Clear awaiting events too (main-thread only, no mutex needed)
    this->awaiting_sync_idle_events.clear();

    if (this->high_performance_requested_for_playback) {
        this->client->release_high_performance();
        this->high_performance_requested_for_playback = false;
    }
}

// ============================================================================
// Impl: Helpers
// ============================================================================

bool PlayerRole::Impl::send_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                                        uint8_t chunk_type, uint32_t timeout_ms) const {
    if (data == nullptr || data_size == 0) {
        SS_LOGE(TAG, "Invalid data passed to send_audio_chunk");
        return false;
    }

    return this->sync_task->write_audio_chunk(data, data_size, timestamp,
                                              static_cast<ChunkType>(chunk_type), timeout_ms);
}

void PlayerRole::Impl::enqueue_state_update(SendspinClientState state) const {
    // Latest-wins slot, never the shared event ring: consecutive transitions between drains
    // collapse to the newest (matching the drain's semantics), and a sync task that keeps
    // transitioning while the main loop stalls cannot fill the ring and starve the
    // non-idempotent lifecycle events that live there.
    this->event_state->state_slot.write(state);
}

void PlayerRole::Impl::enqueue_stream_event(PlayerStreamCallbackType event) const {
    // A dropped STREAM_START would leave the sync task waiting for its start signal forever;
    // a dropped STREAM_END would leave the consumer believing the stream is still active. Both
    // wedge the stream, so log the drop at ERROR (the helper defaults to WARN, which suits the
    // idempotent CLEARED events but understates a wedged player stream).
    push_event_or_log(
        this->inbox, InboxEventType::PLAYER_STREAM, static_cast<uint8_t>(event), TAG,
        event == PlayerStreamCallbackType::STREAM_START ? "STREAM_START" : "STREAM_END",
        /*error_level=*/true);
}

void PlayerRole::Impl::load_static_delay() {
    if (!this->persistence) {
        // No persistence provider - use initial value from config
        if (this->config.initial_static_delay_ms > 0) {
            this->static_delay_ms.store(this->config.initial_static_delay_ms,
                                        std::memory_order_relaxed);
            SS_LOGI(TAG, "Using initial static delay from config: %u ms",
                    this->config.initial_static_delay_ms);
        }
        return;
    }

    auto delay = this->persistence->load_static_delay();
    if (delay.has_value()) {
        if (delay.value() <= MAX_STATIC_DELAY_MS) {
            this->static_delay_ms.store(delay.value(), std::memory_order_relaxed);
            SS_LOGI(TAG, "Loaded static delay: %u ms", delay.value());
        } else {
            SS_LOGW(TAG, "Persisted static delay out of range (%u), ignoring", delay.value());
        }
    } else if (this->config.initial_static_delay_ms > 0) {
        this->static_delay_ms.store(this->config.initial_static_delay_ms,
                                    std::memory_order_relaxed);
        SS_LOGI(TAG, "Using initial static delay from config: %u ms",
                this->config.initial_static_delay_ms);
    }
}

uint16_t PlayerRole::Impl::get_effective_static_delay_ms() const {
    return this->static_delay_adjustable.load(std::memory_order_relaxed)
               ? this->static_delay_ms.load(std::memory_order_relaxed)
               : 0;
}

void PlayerRole::Impl::persist_static_delay() const {
    if (this->persistence) {
        uint16_t delay = this->static_delay_ms.load(std::memory_order_relaxed);
        if (this->persistence->save_static_delay(delay)) {
            SS_LOGD(TAG, "Persisted static delay: %u ms", delay);
        } else {
            SS_LOGW(TAG, "Failed to persist static delay");
        }
    }
}

}  // namespace sendspin
