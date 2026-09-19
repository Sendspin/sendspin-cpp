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

/// @file player_role_impl.h
/// @brief Private implementation for the player role (pimpl)

#pragma once

#include "inbox.h"
#include "sendspin/player_role.h"
#include "sync_task.h"

#include <atomic>
#include <memory>
#include <optional>
#include <vector>

namespace sendspin {

class SendspinClient;
class SendspinPersistenceProvider;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred stream lifecycle callback types queued from the network thread
enum class PlayerStreamCallbackType : uint8_t {
    STREAM_START,  // New stream is starting
    STREAM_END,    // Stream ended normally
};

/// @brief One binary audio chunk, split into the parts roles/player/v1.md "Audio Chunks
/// (Binary)" defines after the message type byte.
struct AudioChunk {
    /// Server clock time when the first sample should be output (bytes 1-8, big-endian int64).
    int64_t timestamp_us{0};
    /// Encoded audio frame, starting at byte 13. Points into the caller's buffer.
    const uint8_t* audio{nullptr};
    size_t audio_len{0};
};

/// @brief Private implementation of the player role
struct PlayerRole::Impl {
    Impl(PlayerRoleConfig config, SendspinClient* client, SendspinPersistenceProvider* persistence);
    ~Impl();

    /// @brief Splits one audio chunk's bytes (after the message type byte) into its timestamp
    /// and its encoded audio frame.
    ///
    /// Bytes 9-12 carry `send_ahead`, the lead the server had in hand when it transmitted. It
    /// carries no scheduling meaning, so the chunk is parsed past it rather than through it.
    /// @param data Chunk bytes with the message type byte already stripped.
    /// @param len  Number of bytes at @p data.
    /// @return The split chunk, or nullopt when @p len is too short to hold the header.
    static std::optional<AudioChunk> parse_audio_chunk(const uint8_t* data, size_t len);

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        InboxSlot<ServerPlayerStreamObject> stream_params_slot;
        InboxSlot<ServerCommandMessage> command_slot;
        // Client state from the sync task. Latest-wins by design (the old ring events were
        // collapsed to the newest at drain time anyway), and deliberately NOT on the event
        // ring: the sync task is the one producer that can keep emitting while the main loop
        // stalls, and un-coalesced state transitions must not be able to fill the shared ring
        // and starve non-idempotent lifecycle events out of it.
        InboxSlot<SendspinClientState> state_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    void build_state_fields(ClientStateMessage& msg) const;
    // Each handler takes the teardown generation the receive gate captured when it admitted the
    // message and re-checks it where it takes effect; see accepts().
    void handle_binary(const uint8_t* data, size_t len, uint32_t generation) const;
    void handle_stream_start(const ServerPlayerStreamObject& player_obj, uint32_t generation) const;
    void handle_stream_end(uint32_t generation) const;
    void handle_stream_clear(uint32_t generation) const;
    void handle_server_command(const ServerCommandMessage& cmd, uint32_t generation) const;
    void on_stream_ring_event(PlayerStreamCallbackType event);
    // True if this tick has drainable player work. The command-slot bit covers server
    // volume/mute/output-delay commands; the state-slot bit covers client-state updates from
    // the sync task; a non-empty awaiting_sync_idle_events is a main-thread-only flag set by
    // on_stream_ring_event() above during this tick's ring dispatch, or carried over from a
    // prior tick while a STREAM_END waits for the sync task to go idle. stream_params_slot's
    // own topic bit (INBOX_TOPIC_PLAYER_STREAM_PARAMS) needs no separate term here: it is only
    // ever consumed from the STREAM_START branch while that event sits in
    // awaiting_sync_idle_events, which the awaiting_sync_idle_events term above already covers.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & (INBOX_TOPIC_PLAYER_COMMAND | INBOX_TOPIC_PLAYER_STATE)) != 0 ||
               !this->awaiting_sync_idle_events.empty();
    }
    void drain_events();
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, on the network thread, while the
    /// handler it admits runs on: a teardown can land in between (the deactivation path, unlike a
    /// lost connection, never quiesces the network thread). The dispatch captures this counter with
    /// the gate and hands it back here at each point of effect, so a teardown inside that window
    /// invalidates the whole handler instead of only the part that ran before it.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards its state. Main loop only.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Listener callbacks are queued on
    /// the inbox rather than fired here, because both callers run under the connection manager's
    /// conn_ptr_mutex_.
    void cleanup();
    /// @brief Joins the sync task thread and discards its buffered audio; no-op if not started.
    void stop() const;

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void update_volume(uint8_t volume);
    void update_muted(bool muted);
    void update_output_delay(uint16_t delay_ms);

    // ========================================
    // Helpers
    // ========================================

    bool send_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                          uint8_t chunk_type, uint32_t timeout_ms) const;
    void enqueue_state_update(SendspinClientState state) const;
    /// Queues a stream lifecycle event stamped with `generation`, which the drain compares
    /// against the live counter before dispatching it.
    void enqueue_stream_event(PlayerStreamCallbackType event, uint32_t generation) const;
    void load_output_delay();
    void persist_output_delay() const;
    uint16_t get_effective_output_delay_ms() const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    PlayerRoleConfig config;
    ServerPlayerStreamObject current_stream_params{};
    std::vector<PlayerStreamCallbackType> awaiting_sync_idle_events;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    PlayerRoleListener* listener{nullptr};
    SendspinPersistenceProvider* persistence;
    std::unique_ptr<SyncTask> sync_task;

    // 32-bit fields
    // Bumped by cleanup(), stamped onto every stream event queued afterwards, and serving two
    // purposes. At the drain it decides whether a ring event is still current: an event queued
    // before the teardown must not act after it, or a STREAM_START would re-arm the sync task for
    // a stream that is gone. Within drain_events() it also detects a listener callback that
    // re-entered teardown while the STREAM_START tail was running. Atomic because the network
    // thread reads it (see accepts()).
    std::atomic<uint32_t> cleanup_generation{0};

    // 16-bit fields
    std::atomic<uint16_t> output_delay_ms{0};

    // 8-bit fields
    bool high_performance_requested_for_playback{false};
    bool muted{false};
    // True between the drained STREAM_START and STREAM_END callbacks (main-thread only); keeps
    // on_stream_end() from firing without a matching on_stream_start()
    bool stream_active{false};
    std::atomic<bool> output_delay_adjustable{false};
    uint8_t volume{0};
};

}  // namespace sendspin
