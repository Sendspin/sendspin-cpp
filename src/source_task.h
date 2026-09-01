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

/// @file source_task.h
/// @brief Background task that assembles captured audio into timestamped chunks and streams
/// them to the Sendspin server

#pragma once

#include "audio_ring_buffer.h"
#include "constants.h"
#include "platform/event_flags.h"
#include "platform/memory.h"
#include "sendspin/source_role.h"
#include "source_encoder.h"

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

namespace sendspin {

class ConnectionManager;
class SendspinClient;
class SendspinConnection;

/// @brief Event flag bits for source task lifecycle and command signaling (distinct names from
/// the sync task's EventGroupBits: both unscoped enums can be visible in one translation unit)
enum SourceTaskBits : uint16_t {
    SOURCE_COMMAND_STOP = (1 << 0),    // Signal task thread to exit
    SOURCE_COMMAND_UPDATE = (1 << 1),  // Desired streaming state changed; re-read the atomic
    SOURCE_SEND_COMPLETE = (1 << 2),   // A binary send's completion callback fired
    SOURCE_TASK_RUNNING = (1 << 8),    // Task is actively streaming to the server
    SOURCE_TASK_STOPPED = (1 << 10),   // Task thread has exited
    SOURCE_TASK_IDLE = (1 << 12),      // Task is idle, waiting for a start command
};

// ============================================================================
// Chunk/timestamp bookkeeping (pure helpers)
// ============================================================================

/// @brief Bytes in one frame (one sample across all channels) of the given capture format
constexpr size_t source_bytes_per_frame(uint8_t channels, uint8_t bit_depth) {
    return static_cast<size_t>(channels) * (static_cast<size_t>(bit_depth) / 8U);
}

/// @brief Frames in `ms` milliseconds at sample_rate. 64-bit so the product cannot wrap on
/// 32-bit targets; SourceTask::init() caps the derived byte sizes before narrowing.
constexpr uint64_t source_ms_to_frames(uint32_t ms, uint32_t sample_rate) {
    return static_cast<uint64_t>(ms) * sample_rate / MS_PER_SECOND;
}

/// @brief Duration in microseconds of frame_count frames at sample_rate
constexpr int64_t source_frames_to_us(uint64_t frame_count, uint32_t sample_rate) {
    return static_cast<int64_t>(frame_count * US_PER_SECOND / sample_rate);
}

/// @brief Capture time of the first not-yet-consumed sample in a ring entry: a chunk starting
/// mid-entry anchors on its own first sample (Sendspin spec, Source messages), not the entry's
constexpr int64_t source_entry_anchor_us(int64_t entry_capture_us, size_t consumed_bytes,
                                         size_t bytes_per_frame, uint32_t sample_rate) {
    return entry_capture_us + source_frames_to_us(consumed_bytes / bytes_per_frame, sample_rate);
}

/**
 * @brief Background task that drains the capture ring, assembles timestamped chunks, and sends
 * them (plus the stream's client-stream/start and end messages, so wire ordering holds by
 * construction) on the connection the stream was opened on
 *
 * The thread starts once and idles between streams (no create/destroy churn on embedded); the
 * desired streaming state is a latest-wins atomic the task converges on.
 */
class SourceTask {
public:
    SourceTask() = default;
    ~SourceTask();

    /// @brief Initializes event flags, the capture ring, and the chunk staging buffer
    /// @param source_impl The owning SourceRole::Impl, used for config, events, and listener.
    /// @param client The owning SendspinClient, used for shared services.
    /// @param connections The client's connection manager (outlives this task); each stream is
    ///        bound to one connection via current_shared().
    /// @return true on success, false on allocation failure.
    bool init(SourceRole::Impl* source_impl, SendspinClient* client,
              ConnectionManager* connections);

    /// @brief Creates and starts the persistent source background thread
    /// Call once after init(). The thread idles until signal_start().
    /// @param task_stack_in_psram Whether to allocate the task stack in PSRAM (ESP-IDF only).
    /// @param priority Thread priority (ESP-IDF only).
    /// @return true if thread started successfully, false otherwise.
    bool start(bool task_stack_in_psram, unsigned priority);

    /// @brief Returns true if init() has been called successfully
    /// @return true if the source task has been initialized, false otherwise.
    bool is_initialized() const {
        return this->event_flags_.is_created();
    }

    /// @brief Returns true if the task is opening or running a stream
    /// @return true from stream bring-up (time-sync wait) until stream close, false when idle
    ///         or stopped.
    bool is_running() const {
        // Reading uncreated event flags is a null-handle crash on ESP
        if (!this->is_initialized()) {
            return false;
        }
        return (this->event_flags_.get() & SourceTaskBits::SOURCE_TASK_RUNNING) != 0U;
    }

    /// @brief Requests the task to open the outbound stream. Non-blocking
    /// Thread-safe: may be called from any context.
    void signal_start();

    /// @brief Requests the task to close the outbound stream. Non-blocking
    /// Thread-safe: may be called from any context.
    void signal_stop();

    /// @brief Writes captured audio into the capture ring
    ///
    /// Hot path: exactly one producer thread, non-blocking, non-allocating. Rejects writes
    /// while the stream is not open and non-whole-frame writes (a partial frame would shift
    /// every later sample across channels).
    /// @param data Interleaved PCM in the configured format.
    /// @param len Length in bytes; must be a whole number of frames.
    /// @param capture_time_us Local-clock capture time of the first sample; 0 stamps now.
    /// @return true if buffered; false when rejected or the ring is full (drop counted, warned
    ///         once per episode).
    bool write_audio(const uint8_t* data, size_t len, int64_t capture_time_us);

protected:
    /// @brief Entry point for the persistent source background thread
    /// @param params Pointer to the owning SourceTask instance.
    static void thread_entry(void* params);

    /// @brief Outer task loop: idle -> bind -> stream -> idle
    void run();

    /// @brief Runs one stream on the given bound connection: waits for time sync, sends
    /// client-stream/start, loops assembling and sending chunks, and closes with
    /// client-stream/end. Returns when the desired state drops to stopped, the bound
    /// connection stops being current, or the task is told to exit.
    void stream(const std::shared_ptr<SendspinConnection>& conn);

    /// @brief Waits until the bound connection's time filter has a measurement (Sendspin spec,
    /// Source messages: a source must not stream before time sync converges)
    /// @return true once synced; false if streaming was cancelled while waiting.
    bool wait_for_time_sync(const std::shared_ptr<SendspinConnection>& conn);

    /// @brief Encodes, stamps, and sends the currently assembled chunk on the bound connection
    /// @param conn The bound connection.
    /// @return true if the send completed successfully, false on any failure (the caller
    ///         treats a failure as a stall: the chunk is dropped and the ring flushed).
    bool send_chunk(const std::shared_ptr<SendspinConnection>& conn);

    /// @brief Returns the in-progress ring entry (if any) and discards everything buffered in
    /// the capture ring, so streaming resumes from live capture (the spec's stall policy).
    /// @return Number of ring entries discarded.
    size_t flush_ring_to_live();

    /// @brief True while the task should keep the current stream open: desired state still
    /// streaming, task not told to exit, and the bound connection still current (streaming
    /// permission is per-connection; a swap ends the stream).
    bool stream_still_open(const std::shared_ptr<SendspinConnection>& conn) const;

    /// @brief Signals the task to stop and waits for the thread to finish
    void stop();

    // Struct fields
    EventFlags event_flags_;
    /// Built once in init(); per-send copies stay in std::function's small-buffer storage (no
    /// allocation). Must not call back into the connection (may run mid-teardown on the
    /// transport's thread): it only records last_send_ok_ and sets SOURCE_SEND_COMPLETE.
    std::function<void(bool)> send_complete_cb_;
    /// Wire chunk under assembly: [type byte][BE64 server-clock capture µs][payload]
    /// (Sendspin spec, Source messages)
    PlatformBuffer staging_;
    std::thread task_thread_;

    // Pointer fields
    SendspinClient* client_{nullptr};
    ConnectionManager* connections_{nullptr};
    /// Entry being consumed across chunk boundaries; returned once fully consumed or on flush
    AudioRingBufferEntry* current_entry_{nullptr};
    std::unique_ptr<SendspinAudioRingBuffer> capture_ring_;
    std::unique_ptr<SourceEncoder> encoder_;
    SourceRole::Impl* source_impl_{nullptr};

    // 64-bit fields
    /// Local-clock capture time of the assembled chunk's first sample
    int64_t chunk_anchor_us_{0};

    // size_t fields
    size_t bytes_per_frame_{0};
    size_t chunk_bytes_{0};  // Payload bytes per full chunk: chunk_frames * bytes_per_frame
    /// Bytes of the current entry already consumed into chunks
    size_t entry_consumed_bytes_{0};
    /// Payload bytes assembled into staging_ so far for the chunk in progress
    size_t chunk_filled_bytes_{0};
    /// Ring entries dropped in the current task-side stall episode (failed sends)
    size_t stall_flushed_entries_{0};

    // 32-bit fields
    /// Producer-thread-only count of writes dropped in the current overflow episode
    uint32_t producer_dropped_writes_{0};

    // 8-bit fields
    /// write_audio() gate, open only between client-stream/start and stream close. A lone
    /// atomic, not a ShadowSlot: single flag on a lock-free hot path (the Inbox bitmask trade)
    std::atomic<bool> accepting_audio_{false};
    /// Latest-wins desired streaming state from the role's main-loop command latch
    std::atomic<bool> stream_requested_{false};
    /// Result of the last binary send, written before SOURCE_SEND_COMPLETE is set
    std::atomic<bool> last_send_ok_{false};
    /// Task-side stall episode (send failed); episode edges are the only log sites
    bool stall_episode_{false};
    // Producer-thread-only episode flags for write_audio()'s throttled warnings
    bool producer_drop_episode_{false};
    bool producer_frame_warned_{false};
};

}  // namespace sendspin
