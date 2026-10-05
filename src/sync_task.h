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

/// @file sync_task.h
/// @brief Background sync task that decodes encoded audio, synchronizes to server timestamps, and
/// writes PCM to the audio sink

#pragma once

#include "audio_stream_info.h"
#include "audio_types.h"
#include "decoder.h"
#include "inbound_ring.h"
#include "platform/event_flags.h"
#include "platform/shadow_slot.h"
#include "sendspin/player_role.h"
#include "transfer_buffer.h"

#include <atomic>
#include <memory>
#include <thread>

namespace sendspin {

/// @brief Timing feedback from the audio output: frames played and the finish timestamp
struct PlaybackProgress {
    uint32_t frames_played;    // Number of audio frames played since last progress update
    int64_t finish_timestamp;  // The timestamp when the audio frames should finish playing
};

/// @brief States of the sync task's inner decode/playback loop
enum class SyncTaskState : uint8_t {
    INITIAL_SYNC,       // Priming the audio pipeline with silence before playback
    LOAD_CHUNK,         // Loading and decoding the next encoded chunk
    SYNCHRONIZE_AUDIO,  // Applying sync corrections (hard or soft) to align playback
    TRANSFER_AUDIO,     // Sending buffered PCM frames to the audio sink
};

/// @brief Result of decoding a single encoded audio chunk
enum class DecodeResult : uint8_t {
    SUCCESS,            // Audio decoded successfully (or header processed)
    SKIPPED,            // Chunk skipped because it cannot be played in time
    FAILED,             // Decoder failed to decode the chunk
    ALLOCATION_FAILED,  // Buffer allocation failed; task should stop
};

/// @brief Working state shared across the sync task's inner decode/sync/transfer loop
struct SyncContext {
    // Struct fields
    AudioStreamInfo current_stream_info;  // Contains uint32_t and smaller members

    // Pointer fields
    std::unique_ptr<TransferBuffer> decode_buffer;  // Reusable decode + output buffer; reserves one
                                                    // spare frame past the decoded data for
                                                    // soft-sync frame insertion
    std::unique_ptr<SendspinDecoder> decoder;
    /// The inbound ring item being decoded: an audio chunk, decoded straight from the ring
    /// storage it was received and decrypted into, or a codec header or stream/clear marker the
    /// protocol task wrote. Returned to the ring once processed.
    void* encoded_item{nullptr};

    // 64-bit fields
    int64_t decoded_timestamp{0};  // Timestamp for decoded audio
    int64_t new_audio_client_playtime{0};

    // size_t fields
    size_t bytes_per_frame{0};
    size_t silence_remaining{0};  // Bytes of silence still to emit before the next/held chunk
                                  // (initial-sync priming or hard-sync gap fill)

    // 32-bit fields
    uint32_t buffered_frames{0};

    // 8-bit fields
    bool hard_syncing{true};  // Starts true so initial sync uses tight settle threshold
    bool initial_decode{false};
    bool release_chunk{false};
    bool aligning{true};  // True during initial-sync alignment (both priming phases) and post-seek
                          // re-alignment; cleared on first in-tolerance sync. Hard syncs while
                          // aligning are expected and are not a loss of sync.
    bool sync_lost{false};  // True between an unexpected hard sync and the next in-tolerance
                            // sync; edge-triggers the lost/regained log lines.
};

/// @brief Event flag bits used for sync task lifecycle and command signaling
enum EventGroupBits : uint16_t {
    COMMAND_STOP = (1 << 0),          // Signal task to stop
    COMMAND_STREAM_END = (1 << 1),    // Signal end of current stream
    COMMAND_STREAM_CLEAR = (1 << 2),  // Seek: discard buffered audio up to the clear marker
    COMMAND_START = (1 << 3),         // Signal stream start acknowledged
    TASK_RUNNING = (1 << 8),          // Task is actively processing a stream
    TASK_STOPPED = (1 << 10),         // Task thread has exited
    TASK_ERROR = (1 << 11),           // Task encountered a fatal error
    TASK_IDLE = (1 << 12),            // Task is idle, waiting for a new stream
};

/// @brief Self-contained sync task for Sendspin synchronized audio playback
///
/// Manages a persistent background thread that takes encoded audio from its item list (the
/// shared inbound ring items the protocol task appends to it, see InboundItemList), decodes each
/// chunk in place, synchronizes it to server timestamps, and writes PCM data via the player
/// listener. The thread starts once during initialization and idles between streams to avoid
/// thread create/destroy churn on embedded devices.
///
/// The task communicates with the caller via event flags (lifecycle/commands) and a
/// playback progress queue (timing feedback from the audio output).
class SyncTask {
public:
    SyncTask() = default;
    ~SyncTask();

    /// @brief Creates the event flags
    /// @param player_impl The owning PlayerRole::Impl, used for delay, listener, and state
    ///        updates.
    /// @return false on allocation failure.
    bool init(PlayerRole::Impl* player_impl);

    /// @brief Binds the item list to this run's inbound ring, then creates and starts the
    /// persistent sync background thread
    /// Call after init(), once per client start. The thread idles until a codec header arrives.
    /// @param ring The client's inbound ring for this run.
    /// @param task_stack_in_psram Whether to allocate the task stack in PSRAM (ESP-IDF only).
    bool start(InboundRing* ring, bool task_stack_in_psram, unsigned priority);

    /// @brief Signals the task to stop, joins the thread, and returns every item it held or had
    /// not taken to the ring. A later start() creates a fresh thread on the same (still
    /// initialized) flags. No-op when the thread is not running. Main-loop thread only: joins the
    /// sync thread.
    void stop();

    /// @brief Whether init() has been called successfully
    bool is_initialized() const {
        return this->event_flags_.is_created();
    }

    /// @brief Whether the item list is bound to a ring (between start() and stop()), so the
    /// protocol task may hand it items. Protocol task.
    bool accepts_items() const {
        return this->ring_.load(std::memory_order_acquire) != nullptr;
    }

    /// @brief The ring the item list is bound to, or nullptr outside a run. Protocol task.
    InboundRing* ring() const {
        return this->ring_.load(std::memory_order_acquire);
    }

    /// @brief Charges an item to the player's quota and appends it to the item list, waking the
    /// thread. Protocol task only; requires accepts_items().
    /// @param item_len The item's message length (see InboundMessage::item_len).
    /// @return false, appending nothing, when the player is over quota: the caller returns the
    ///         item and logs the drop.
    bool hand_item(void* item, size_t item_len) {
        return hand_inbound_item(*this->ring(), this->encoded_items_, InboundHolder::PLAYER, item,
                                 item_len);
    }

    /// @brief Returns every item the thread has not taken yet to the ring. Protocol task, or the
    /// main loop once the thread is joined.
    void recall_items() {
        this->encoded_items_.recall();
    }

    /// @brief Whether the sync task is actively decoding and syncing a stream; false when idle
    /// (waiting for a stream) or stopped.
    bool is_running() const {
        // Guarded so callers may query before init(); reading uncreated event flags is a
        // null-handle crash on ESP
        if (!this->is_initialized()) {
            return false;
        }
        return (this->event_flags_.get() & EventGroupBits::TASK_RUNNING) != 0U;
    }

    /// @brief Signals the sync task to end the current stream. Non-blocking
    /// The task drains stale audio from its item list and returns to idle.
    /// Thread-safe: may be called from any context.
    void signal_stream_end();

    /// @brief Signals the sync task that a stream/clear (seek) occurred. Non-blocking
    /// The task discards buffered audio up to the CHUNK_TYPE_STREAM_CLEAR_MARKER that the caller
    /// must append immediately after this call, then keeps processing the same stream with its
    /// existing codec, decoder, and playtime accounting intact. It does not return to idle.
    /// Thread-safe: may be called from any context.
    void signal_stream_clear();

    /// @brief Signals the sync task that the client has processed the stream start
    /// The sync task waits for this after finding a codec header before transitioning
    /// to the active state, so the client's stream lifecycle callbacks
    /// (end/clear -> start) fire before the task begins decoding.
    /// Thread-safe: may be called from any context.
    void signal_stream_start();

    /// @brief The ChunkType of an item on the list (InboundItemHeader::type)
    static ChunkType chunk_type(void* item) {
        return static_cast<ChunkType>(inbound_item_header(item)->type);
    }

    /// @brief The encoded bytes an item carries: an audio chunk's frame or a codec header, read in
    /// place from the item
    static const uint8_t* encoded_data(void* item) {
        return inbound_item_data(item);
    }

    /// @brief Length of encoded_data()
    static size_t encoded_size(void* item) {
        return inbound_item_header(item)->data_len;
    }

    /// @brief An audio chunk's server timestamp: roles/player/v1.md "Audio Chunks (Binary)" bytes
    /// 1-8, big-endian, read from the plaintext where it arrived
    static int64_t server_timestamp(void* item);

    /// @brief Called by the audio output when it has played audio frames
    /// Thread-safe: may be called from any context.
    /// @param timestamp Client timestamp when the audio finished playing.
    void notify_audio_played(uint32_t frames, int64_t timestamp);

protected:
    /// @brief Entry point for the persistent sync background thread; `params` is the owning
    /// SyncTask.
    static void thread_entry(void* params);

    /// @brief Handles the INITIAL_SYNC state: feeds zeros to prime the audio pipeline
    SyncTaskState handle_initial_sync(SyncContext& sync_context);

    /// @brief Handles the LOAD_CHUNK state: loads and decodes the next encoded chunk
    SyncTaskState handle_load_chunk(SyncContext& sync_context);

    /// @brief Handles the SYNCHRONIZE_AUDIO state: applies sync corrections based on predicted
    /// error.
    SyncTaskState handle_synchronize_audio(SyncContext& sync_context);

    /// @brief Handles the TRANSFER_AUDIO state: sends buffered audio to the sink
    SyncTaskState handle_transfer_audio(SyncContext& sync_context);

    /// @brief Updates buffered_frames and new_audio_client_playtime after sending audio to the
    /// speaker. These two must always be updated together to keep the playtime estimate consistent.
    void track_sent_audio(SyncContext& sync_context, size_t bytes_sent);

    /// @brief Sends one chunk of pending silence (initial-sync priming or hard-sync gap fill) to
    /// the sink and updates the playtime estimate. No-op when no silence is pending.
    void send_pending_silence(SyncContext& sync_context);

    /// @brief Bridges an encoded-chunk underflow while aligning (startup/post-seek) by feeding the
    /// sink silence (up to UNDERFLOW_SILENCE_KEEPALIVE_MS) instead of letting the DAC run dry,
    /// stopping after the current silence write once a chunk lands or a lifecycle command fires.
    /// Only called while aligning; see handle_load_chunk().
    void fill_underflow_silence(SyncContext& sync_context);

    /// @brief Transfers pending silence (if any) then the decoded chunk to the sink
    /// Returns true when all data has been sent, false if more transfers are needed.
    bool transfer_audio(SyncContext& sync_context);

    /// @brief Loads the next encoded chunk from the item list
    /// Returns true if a chunk is available, false if none ready yet.
    bool load_next_chunk(SyncContext& sync_context);

    /// @brief Takes the next item from the list, returning to the ring any whose teardown
    /// generation the player has moved past (it was appended for a stream a teardown ended)
    /// @param timeout_ms As InboundItemList::take(), applied to the first take only.
    /// @return The item, or nullptr: treat it as "re-check state and retry".
    void* take_item(uint32_t timeout_ms);

    /// @brief Returns an item to the ring
    void return_item(void* item) const {
        this->ring()->return_item(item);
    }

    /// @brief Removes last decoded frame, blending into the second-to-last to minimize glitches
    /// Returns -1 if a frame was removed, 0 if preconditions not met.
    int32_t soft_sync_drop_frame(SyncContext& sync_context);

    /// @brief Adds one interpolated frame between the last two decoded frames (average of the two),
    /// moving the original last frame into the decode buffer's reserved spare frame
    /// Returns 1 if a frame was added, 0 if preconditions not met.
    int32_t soft_sync_insert_frame(SyncContext& sync_context);

    /// @brief Decodes the current encoded chunk
    DecodeResult decode_chunk(SyncContext& sync_context);

    /// @brief Decodes all of the current encoded chunk into the decode buffer, growing it as the
    /// decoder asks. On failure the buffer is left as it was. Reads and writes only
    /// `sync_context`.
    static bool decode_whole_chunk(SyncContext& sync_context);

    /// @brief Waits in IDLE for a codec header to arrive on the item list
    /// Discards stale audio chunks. Returns true if a codec header was found.
    /// Returns false if COMMAND_STOP was signaled.
    bool wait_for_codec_header(SyncContext& sync_context);

    /// @brief Non-blocking drain of audio data from the item list, preserving codec headers
    void drain_items(SyncContext& sync_context);

    /// @brief Handles a stream/clear (seek) while a stream is active: discards queued chunks
    /// up to (and including) the CHUNK_TYPE_STREAM_CLEAR_MARKER, then applies apply_stream_clear()
    void discard_to_clear_marker(SyncContext& sync_context);

    /// @brief Drops in-flight decoded audio and pending silence (they carry the pre-seek timeline),
    /// forces hard_syncing on, and clears COMMAND_STREAM_CLEAR. Codec/decoder state, playtime
    /// accounting, and initial_decode are left intact; the next chunk's server timestamp lets the
    /// sync logic re-align on its own. The caller re-enters the loop at INITIAL_SYNC so unfinished
    /// priming resumes.
    void apply_stream_clear(SyncContext& sync_context);

    /// @brief Resets SyncContext between streams without deallocating buffers
    void reset_context(SyncContext& sync_context);

    /// @brief Processes playback progress messages from the speaker to update buffered_frames and
    /// playtime.
    void process_playback_progress(SyncContext& sync_context);

    // Struct fields
    EventFlags event_flags_;
    // Latest-wins slot that merges (sum frames, keep latest finish_timestamp)
    // updates from the audio callback and is drained by the sync thread.
    ShadowSlot<PlaybackProgress> playback_progress_slot_;
    std::thread sync_thread_;

    /// The encoded chunks and markers the protocol task hands the thread (appended on the
    /// protocol task, taken on the sync thread; recalled on the protocol task or, once the thread
    /// is joined, on the main loop). No storage of its own: it links ring items.
    InboundItemList encoded_items_;

    // Pointer fields
    PlayerRole::Impl* player_impl_{nullptr};
    /// The ring the item list is bound to for the current run, or nullptr outside one. Written by
    /// start() and stop() on the main loop, read by the protocol task and the sync thread.
    std::atomic<InboundRing*> ring_{nullptr};
};

}  // namespace sendspin
