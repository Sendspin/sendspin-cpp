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

#include "audio_types.h"
#include "inbound_ring.h"
#include "inbox.h"
#include "sendspin/player_role.h"
#include "sync_task.h"
#include "teardown_tracker.h"

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinClient;
class SendspinPersistenceProvider;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred stream lifecycle callback types queued from the protocol task
enum class PlayerStreamCallbackType : uint8_t {
    STREAM_START,  // New stream is starting
    STREAM_END,    // Stream ended normally
};

/// @brief One binary audio chunk, split into the parts roles/player/v1.md "Audio Chunks
/// (Binary)" defines after the message type byte.
struct AudioChunk {
    /// Server clock time when the first sample should be output (spec bytes 1-8, big-endian
    /// int64, i.e. the first eight bytes of `data`).
    int64_t timestamp_us{0};
    /// Encoded audio frame, starting at spec byte 13 (offset 12 in `data`). Points into the
    /// caller's buffer.
    const uint8_t* audio{nullptr};
    size_t audio_len{0};
};

/// @brief Private implementation of the player role
struct PlayerRole::Impl {
    Impl(PlayerRoleConfig config, SendspinClient* client);
    ~Impl();

    /// @brief Splits one audio chunk's bytes (after the message type byte) into its timestamp
    /// and its encoded audio frame.
    ///
    /// Spec bytes 9-12 carry `send_ahead`, the lead the server had in hand when it transmitted;
    /// it carries no scheduling meaning, so the chunk is parsed past it.
    /// @param data Chunk bytes with the message type byte already stripped.
    /// @return The split chunk, or nullopt when @p len is too short to hold the header.
    static std::optional<AudioChunk> parse_audio_chunk(const uint8_t* data, size_t len);

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        GenerationSlot<ServerPlayerStreamObject> stream_params_slot;
        GenerationSlot<ServerCommandMessage> command_slot;
        /// Written by the sync task each time it returns to idle from a stream it was running or
        /// about to run, so a STREAM_END the drain holds for the sync task to go idle is
        /// re-examined then (see awaiting_sync_idle) rather than on every loop().
        InboxSlot<bool> sync_idle_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    /// @param persistence The client's provider at this start, or nullptr; replaces the one
    ///        add_player() set.
    /// @param ring The client's inbound ring for this run, which the sync task's item list links.
    bool start(SendspinPersistenceProvider* persistence, InboundRing* ring);
    void build_hello_fields(ClientHelloMessage& msg);
    /// @brief The buffer_capacity client/hello advertises: the share of the quota that holds
    /// encoded frames at the smallest frame size (see AUDIO_BUFFER_ADVERTISE_DENOMINATOR in
    /// player_role.cpp), which also bounds the longest chunk the server sends.
    size_t advertised_buffer_capacity() const;
    void build_state_fields(ClientStateMessage& msg) const;
    // Each handler takes the teardown generation the receive gate captured when it admitted the
    // message and re-checks it where it takes effect; see accepts(). All run on the protocol task.
    /// @brief Hands an audio chunk to the sync task: by its ring item when it has one (clearing
    /// `message.item`), otherwise copied into an item the protocol task acquires.
    /// @param message The decrypted chunk; `data` points at its message type byte.
    void handle_binary(InboundMessage& message, uint32_t generation);
    void handle_stream_start(const ServerPlayerStreamObject& player_obj, uint32_t generation);
    void handle_stream_end(uint32_t generation) const;
    void handle_stream_clear(uint32_t generation);
    void handle_server_command(const ServerCommandMessage& cmd, uint32_t generation) const;
    void on_stream_ring_event(PlayerStreamCallbackType event);
    /// @brief Tells the main loop the sync task returned to idle from a stream (sync_idle_slot).
    /// Sync task.
    void note_sync_idle() const {
        this->event_state->sync_idle_slot.write(true);
    }
    // True if this tick has drainable player work: a server command (volume/mute/output delay)
    // in command_slot; the sync task having left a stream (sync_idle_slot) while a STREAM_END
    // waits for it; or stream lifecycle events in awaiting_sync_idle_events, appended by
    // on_stream_ring_event() during this tick's ring dispatch, that are not held for the sync
    // task. stream_params_slot's own topic bit needs no term: it is only ever consumed from the
    // STREAM_START branch while that event sits in awaiting_sync_idle_events.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & (INBOX_TOPIC_PLAYER_COMMAND | INBOX_TOPIC_PLAYER_SYNC_IDLE)) != 0 ||
               (!this->awaiting_sync_idle_events.empty() && !this->awaiting_sync_idle);
    }
    void drain_events();
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, before the handler it admits
    /// runs, and stop()'s teardown on the main loop can land in between. Re-checking at each point
    /// of effect invalidates the whole handler instead of only the part that ran before it. The
    /// drain applies the same check to a slot payload's stamp.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards the state the protocol task can reach. Protocol task,
    /// or the main loop in SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). The STREAM_END is queued on
    /// the inbox, stamped with the new generation, and the main loop runs complete_teardown() for
    /// it before acting on that event (catch_up_teardown()).
    void cleanup();

    /// @brief The main-loop teardown half: drops the stream events the teardown overtook and
    /// releases the playback high-performance hold. Main loop only, through catch_up_teardown().
    void complete_teardown();

    /// @brief Joins the sync task thread and returns its buffered audio to the inbound ring;
    /// no-op if not started.
    void stop() const;

    /// @brief Recalls the items the sync task has not taken once a teardown has moved the
    /// generation past the one they were appended under. Protocol task only: each tick, and
    /// before each item it hands over, so no item of the new generation is ever recalled.
    /// @param generation The generation about to be appended under, or the live one.
    void recall_stale_items(uint32_t generation);

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void update_volume(uint8_t volume);
    void update_muted(bool muted);
    void update_output_delay(uint16_t delay_ms);

    // ========================================
    // Helpers
    // ========================================

    /// @brief Fills an item's consumer fields and hands it to the sync task, returning it to the
    /// ring with a warning when the player is over quota. Protocol task only.
    /// @param item_len The item's message length (InboundMessage::item_len, or what
    ///        acquire_local() was asked for).
    /// @param data_offset Where the sync task's bytes start in the item's message bytes.
    /// @param data_len How many bytes the sync task reads.
    /// @return false when the item was returned instead of handed over.
    bool hand_item(void* item, size_t item_len, ChunkType chunk_type, uint8_t data_offset,
                   uint32_t data_len, uint32_t generation);

    /// @brief Writes `len` bytes into an item the protocol task acquires itself and hands it to
    /// the sync task: a codec header, a stream/clear marker (len 0), or a chunk that reached the
    /// protocol task outside a ring item. Protocol task only.
    /// @param timeout_ms Bound on waiting for ring space.
    /// @return false when the ring had no room in time or the player is over quota.
    bool hand_local_item(const uint8_t* data, size_t len, ChunkType chunk_type, uint8_t data_offset,
                         uint32_t receive_time_us, uint32_t timeout_ms, uint32_t generation);

    /// @brief Base64-decodes a FLAC codec header straight into an item the protocol task
    /// acquires and hands it to the sync task. Protocol task only.
    /// @return false when the header does not decode, the ring had no room in time, or the
    ///         player is over quota.
    bool hand_flac_header(const std::string& codec_header, uint32_t generation);
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
    TeardownTracker teardown;  ///< Main loop only.

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    PlayerRoleListener* listener{nullptr};
    SendspinPersistenceProvider* persistence{nullptr};
    std::unique_ptr<SyncTask> sync_task;

    /// Throttles the over-quota drop warning in hand_item(). Protocol task only.
    InboundDropLog over_quota_log;
    /// Throttles the warning for a chunk that could not be copied into a ring item. Protocol task
    /// only.
    InboundDropLog copy_drop_log;

    // 32-bit fields
    /// The teardown generation the sync task's item list was last recalled for
    /// (recall_stale_items()). Protocol task only.
    uint32_t recalled_generation{0};
    // Bumped by cleanup() and stamped onto every stream event and slot payload queued
    // afterwards. At the drain it decides whether a ring event or a payload is still current: a
    // STREAM_START queued before the teardown must not re-arm the sync task for a stream that is
    // gone. Within drain_events() it also detects a listener callback that re-entered teardown.
    // Written on the protocol task (or the main loop in stop() once it is joined); read on the
    // main loop, the sync task (which drops items of an older generation) and the protocol task.
    std::atomic<uint32_t> cleanup_generation{0};

    // 16-bit fields
    std::atomic<uint16_t> output_delay_ms{0};

    // 8-bit fields
    // True while the head of awaiting_sync_idle_events is a STREAM_END waiting for the sync task
    // to go idle; the drain then runs again when sync_idle_slot is written. Main loop only.
    bool awaiting_sync_idle{false};
    bool high_performance_requested_for_playback{false};
    bool muted{false};
    // True between the drained STREAM_START and STREAM_END callbacks (main-thread only); keeps
    // on_stream_end() from firing without a matching on_stream_start()
    bool stream_active{false};
    std::atomic<bool> output_delay_adjustable{false};
    // Set by the client while it is unavailable; read by handle_binary() on the protocol task.
    std::atomic<bool> discard_audio{false};
    uint8_t volume{0};
};

}  // namespace sendspin
