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

/// @file announcement_task.h
/// @brief Background task that decodes announcement audio and writes PCM to the announcement sink

#pragma once

#include "audio_ring_buffer.h"
#include "audio_stream_info.h"
#include "decoder.h"
#include "platform/event_flags.h"
#include "sendspin/announcement_role.h"

#include <memory>
#include <thread>
#include <vector>

namespace sendspin {

class SendspinClient;

/// @brief Event flag bits used for announcement task lifecycle and command signaling
///
/// Kept distinct from the sync task's EventGroupBits: both enums are unscoped in this namespace
/// and may be visible in the same translation unit.
enum AnnouncementTaskBits : uint16_t {
    ANNOUNCEMENT_COMMAND_STOP = (1 << 0),          // Signal task to stop
    ANNOUNCEMENT_COMMAND_STREAM_END = (1 << 1),    // Signal end of current announcement stream
    ANNOUNCEMENT_COMMAND_STREAM_CLEAR = (1 << 2),  // Replace: discard buffered announcement audio
    ANNOUNCEMENT_COMMAND_START = (1 << 3),         // Signal stream start acknowledged
    ANNOUNCEMENT_TASK_RUNNING = (1 << 8),          // Task is actively playing an announcement
    ANNOUNCEMENT_TASK_STOPPED = (1 << 10),         // Task thread has exited
    ANNOUNCEMENT_TASK_IDLE = (1 << 12),            // Task is idle, waiting for an announcement
};

/// @brief Self-contained background task for announcement playback
///
/// Manages a persistent background thread that reads encoded announcement audio from a
/// dedicated ring buffer, decodes it, and writes PCM data via the announcement listener.
/// Unlike the player's SyncTask there is no sample-accurate sync machinery: announcements are
/// per-client, the first chunk starts at (or as soon as possible after) its timestamp, and
/// subsequent output is paced by the sink's blocking writes. A stalled stream (buffer drained,
/// no data arriving) is ended locally after a timeout.
///
/// The thread starts once during initialization and idles between announcements to avoid
/// thread create/destroy churn on embedded devices.
class AnnouncementTask {
public:
    AnnouncementTask() = default;
    ~AnnouncementTask();

    /// @brief Initializes event flags and creates the encoded ring buffer
    /// @param announcement_impl The owning AnnouncementRole::Impl, used for listener and events.
    /// @param client The owning SendspinClient, used for time conversion.
    /// @param buffer_size Size of the encoded announcement ring buffer in bytes.
    /// @return true on success, false on allocation failure.
    bool init(AnnouncementRole::Impl* announcement_impl, SendspinClient* client,
              size_t buffer_size);

    /// @brief Creates and starts the persistent announcement background thread
    /// Call once after init(). The thread idles until a codec header arrives in the ring buffer.
    /// @param task_stack_in_psram Whether to allocate the task stack in PSRAM (ESP-IDF only).
    /// @param priority Thread priority (ESP-IDF only).
    /// @return true if thread started successfully, false otherwise.
    bool start(bool task_stack_in_psram, unsigned priority);

    /// @brief Returns true if init() has been called successfully
    /// @return true if the announcement task has been initialized, false otherwise.
    bool is_initialized() const {
        return this->event_flags_.is_created();
    }

    /// @brief Returns true if the announcement task is actively playing an announcement
    /// @return true if actively decoding and playing, false when idle or stopped.
    bool is_running() const {
        // Guarded so callers may query before init(); reading uncreated event flags is a
        // null-handle crash on ESP
        if (!this->is_initialized()) {
            return false;
        }
        return (this->event_flags_.get() & AnnouncementTaskBits::ANNOUNCEMENT_TASK_RUNNING) != 0U;
    }

    /// @brief Signals the task to end the current announcement stream. Non-blocking
    /// The task drains stale audio from the ring buffer and returns to idle.
    /// Thread-safe: may be called from any context.
    void signal_stream_end();

    /// @brief Signals the task that the server cleared the announcement stream (replace).
    /// Non-blocking. The task discards currently buffered announcement audio and keeps the
    /// stream open for the chunks that follow.
    /// Thread-safe: may be called from any context.
    void signal_stream_clear();

    /// @brief Signals the task that the client has processed the announcement stream start
    /// The task waits for this after finding a codec header, so the main-thread
    /// on_announcement_start() callback (where the embedder applies ducking) fires before any
    /// announcement audio is written to the sink.
    /// Thread-safe: may be called from any context.
    void signal_stream_start();

    /// @brief Writes an encoded announcement chunk into the ring buffer
    /// Called from the client's binary message callback (may be any thread).
    /// @param data Pointer to the audio data.
    /// @param data_size Size of the audio data in bytes.
    /// @param timestamp Server timestamp for this chunk.
    /// @param chunk_type Type of audio chunk.
    /// @param timeout_ms Milliseconds to wait if buffer is full (UINT32_MAX = wait forever).
    /// @return true if successfully written, false if buffer full or error.
    bool write_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                           ChunkType chunk_type, uint32_t timeout_ms);

protected:
    /// @brief Entry point for the persistent announcement background thread
    /// @param params Pointer to the owning AnnouncementTask instance.
    static void thread_entry(void* params);

    /// @brief Outer task loop: idle -> header -> start ack -> play -> idle
    void run();

    /// @brief Waits in IDLE for a codec header to arrive in the ring buffer
    /// Discards stale audio chunks. Returns true if a codec header was processed into the
    /// decoder. Returns false if ANNOUNCEMENT_COMMAND_STOP was signaled.
    bool wait_for_codec_header(AudioStreamInfo* stream_info);

    /// @brief Plays one announcement stream until end/stop/stall, writing PCM to the listener
    void play_stream();

    /// @brief Sleeps until the first chunk's timestamp (translated to the local clock), bounded
    /// and abortable. No-op when time sync is unavailable or the timestamp already passed
    void wait_for_start_time(int64_t server_timestamp);

    /// @brief Non-blocking drain of all chunks currently in the ring buffer
    void drain_ring_buffer();

    /// @brief Signals the task to stop and waits for the thread to finish
    void stop();

    // Struct fields
    EventFlags event_flags_;
    std::thread task_thread_;
    std::vector<uint8_t> decode_buffer_;

    // Pointer fields
    AnnouncementRole::Impl* announcement_impl_{nullptr};
    SendspinClient* client_{nullptr};
    std::unique_ptr<SendspinDecoder> decoder_;
    std::unique_ptr<SendspinAudioRingBuffer> encoded_ring_buffer_;
};

}  // namespace sendspin
