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

#pragma once

#include "audio_ring_buffer.h"
#include "audio_stream_info.h"
#include "decoder.h"
#include "platform/event_flags.h"
#include "platform/thread_safe_queue.h"
#include "transfer_buffer.h"

#include <atomic>
#include <memory>
#include <thread>

namespace sendspin {

class PlayerRole;

// Stores the timing information of audio played received from the speaker
struct PlaybackProgress {
    uint32_t frames_played;    // Number of audio frames played since last progress update
    int64_t finish_timestamp;  // The timestamp when the audio frames should finish playing
};

enum class SyncTaskState : uint8_t {
    INITIAL_SYNC,
    LOAD_CHUNK,
    SYNCHRONIZE_AUDIO,
    TRANSFER_AUDIO,
};

enum class DecodeResult : uint8_t {
    SUCCESS,            // Audio decoded successfully (or header processed)
    SKIPPED,            // Chunk skipped because it can't be played in time
    FAILED,             // Decoder failed to decode the chunk
    ALLOCATION_FAILED,  // Buffer allocation failed, task should stop
};

// Stores all the variables needed by segments of the sync task
struct SyncContext {
    // Smart pointers (4 bytes each on ESP32)
    std::unique_ptr<TransferBuffer> decode_buffer;  // Reusable decode + output buffer
    std::unique_ptr<TransferBuffer> interpolation_transfer_buffer;
    std::unique_ptr<SendspinDecoder> decoder;

    // Raw pointers (4 bytes each on ESP32)
    AudioRingBufferEntry* encoded_entry{nullptr};
    AudioWriteCallback audio_write_callback;  // Set from task owner, outlives this context

    // 64-bit members
    int64_t decoded_timestamp{0};  // Timestamp for decoded audio
    int64_t new_audio_client_playtime{0};

    // 32-bit members
    uint32_t buffered_frames{0};
    size_t bytes_per_frame{0};
    AudioStreamInfo current_stream_info;  // Contains uint32_t and smaller members

    // 8-bit members
    bool release_chunk{false};
    bool initial_decode{false};
    bool hard_syncing{true};  // Starts true so initial sync uses tight settle threshold
};

enum EventGroupBits : uint32_t {
    COMMAND_STOP = (1 << 0),
    COMMAND_STREAM_END = (1 << 1),
    COMMAND_STREAM_CLEAR = (1 << 2),
    COMMAND_START = (1 << 3),
    TASK_STARTING = (1 << 7),
    TASK_RUNNING = (1 << 8),
    TASK_STOPPING = (1 << 9),
    TASK_STOPPED = (1 << 10),
    TASK_ERROR = (1 << 11),
    TASK_IDLE = (1 << 12),
};

/// @brief Self-contained sync task for Sendspin synchronized audio playback.
///
/// Manages a persistent background thread that reads encoded audio from the ring buffer,
/// decodes it, synchronizes it to server timestamps, and writes PCM data to an AudioSink.
/// The thread starts once during initialization and idles between streams to avoid
/// thread create/destroy churn on embedded devices.
///
/// The task communicates with the caller via event flags (lifecycle/commands) and a
/// playback progress queue (timing feedback from the audio output).
class SyncTask {
public:
    SyncTask() = default;
    ~SyncTask();

    /// @brief Initializes queues and creates the encoded ring buffer.
    /// @param player The owning PlayerRole, used for time sync, delay, and audio write access.
    /// @param buffer_size Size of the encoded audio ring buffer in bytes.
    /// @return true on success, false on allocation failure.
    bool init(PlayerRole* player, size_t buffer_size);

    /// @brief Creates and starts the persistent sync background thread.
    /// Call once after init(). The thread idles until a codec header arrives in the ring buffer.
    /// @param task_stack_in_psram Whether to allocate the task stack in PSRAM (ESP-IDF only).
    /// @return true if thread started successfully, false otherwise.
    bool start(bool task_stack_in_psram = false);

    /// @brief Returns true if init() has been called successfully.
    bool is_initialized() const {
        return this->event_flags_.is_created();
    }

    /// @brief Returns true if the sync task is actively processing a stream.
    /// Returns false when idle (waiting for a stream) or stopped.
    bool is_running() const;

    /// @brief Signals the sync task to end the current stream. Non-blocking.
    /// The task drains stale audio from the ring buffer and returns to idle.
    /// Thread-safe: may be called from any context.
    void signal_stream_end();

    /// @brief Signals the sync task to clear all buffered audio. Non-blocking.
    /// The task immediately drains the ring buffer and returns to idle.
    /// Thread-safe: may be called from any context.
    void signal_stream_clear();

    /// @brief Signals the sync task that the client has processed the stream start.
    /// The sync task waits for this after finding a codec header before transitioning
    /// to the active state. This ensures the client's stream lifecycle callbacks
    /// (end/clear → start) fire before the task begins decoding.
    /// Thread-safe: may be called from any context.
    void signal_stream_start();

    /// @brief Writes an encoded audio chunk into the ring buffer.
    /// Called from the client's audio chunk callback (may be any thread).
    /// @param data Pointer to the audio data.
    /// @param data_size Size of the audio data in bytes.
    /// @param timestamp Server timestamp for this chunk.
    /// @param chunk_type Type of audio chunk.
    /// @param timeout_ms Milliseconds to wait if buffer is full (UINT32_MAX = wait forever).
    /// @return true if successfully written, false if buffer full or error.
    bool write_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                           ChunkType chunk_type, uint32_t timeout_ms);

    /// @brief Called by the audio output when it has played audio frames.
    /// Thread-safe: may be called from any context.
    /// @param frames Number of audio frames played.
    /// @param timestamp Client timestamp when the audio finished playing.
    void notify_audio_played(uint32_t frames, int64_t timestamp);

    /// @brief Gets the event flags for monitoring task lifecycle.
    EventFlags& get_event_flags() {
        return this->event_flags_;
    }

    /// @brief Checks if the last run ended with an error.
    bool had_error() const {
        return this->last_run_had_error_;
    }

protected:
    static void sync_task(void* params);

    /// @brief Handles the INITIAL_SYNC state: feeds zeros to prime the audio pipeline.
    SyncTaskState sync_handle_initial_sync_(SyncContext& sync_context);

    /// @brief Handles the LOAD_CHUNK state: loads and decodes the next encoded chunk.
    SyncTaskState sync_handle_load_chunk_(SyncContext& sync_context);

    /// @brief Handles the SYNCHRONIZE_AUDIO state: applies sync corrections based on predicted
    /// error.
    SyncTaskState sync_handle_synchronize_audio_(SyncContext& sync_context);

    /// @brief Handles the TRANSFER_AUDIO state: sends buffered audio to the sink.
    SyncTaskState sync_handle_transfer_audio_(SyncContext& sync_context);

    /// @brief Updates buffered_frames and new_audio_client_playtime after sending audio to the
    /// speaker. These two must always be updated together to keep the playtime estimate consistent.
    void sync_track_sent_audio_(SyncContext& sync_context, size_t bytes_sent);

    /// @brief Transfers audio from interpolation and decode buffers to the sink.
    /// Returns true when all data has been sent, false if more transfers are needed.
    bool sync_transfer_audio_(SyncContext& sync_context);

    /// @brief Loads the next encoded chunk from the ring buffer.
    /// Returns true if a chunk is available, false if none ready yet.
    bool sync_load_next_chunk_(SyncContext& sync_context);

    /// @brief Removes last decoded frame, blending into the second-to-last to minimize glitches.
    /// Returns -1 if a frame was removed, 0 if preconditions not met.
    int32_t sync_soft_sync_remove_audio_(SyncContext& sync_context);

    /// @brief Adds one interpolated frame between the first two decoded frames.
    /// Returns 1 if a frame was added, 0 if preconditions not met.
    int32_t sync_soft_sync_add_audio_(SyncContext& sync_context);

    /// @brief Decodes the current encoded chunk.
    DecodeResult sync_decode_audio_(SyncContext& sync_context);

    /// @brief Waits in IDLE for a codec header to arrive in the ring buffer.
    /// Discards stale audio chunks. Returns true if a codec header was found.
    /// Returns false if COMMAND_STOP was signaled.
    bool sync_idle_wait_for_header_(SyncContext& sync_context);

    /// @brief Non-blocking drain of audio data from the ring buffer, preserving codec headers.
    void sync_drain_ring_buffer_(SyncContext& sync_context);

    /// @brief Resets SyncContext between streams without deallocating buffers.
    void sync_reset_context_(SyncContext& sync_context);

    /// @brief Processes playback progress messages from the speaker to update buffered_frames and
    /// playtime.
    void sync_process_playback_progress_(SyncContext& sync_context);

    /// @brief Signals the task to stop and waits for the thread to finish.
    void stop_();

    // Smart pointers
    std::unique_ptr<SendspinAudioRingBuffer> encoded_ring_buffer_;

    // Platform-agnostic concurrency primitives
    EventFlags event_flags_;
    ThreadSafeQueue<PlaybackProgress> playback_progress_queue_;
    std::thread sync_thread_;

    // Owning player role (set by init, outlives this task)
    PlayerRole* player_{nullptr};

    // Tracks whether the last task run ended with an error
    bool last_run_had_error_{false};
};

}  // namespace sendspin
