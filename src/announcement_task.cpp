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

#include "announcement_task.h"

#include "announcement_role_impl.h"
#include "platform/logging.h"
#include "platform/thread.h"
#include "platform/time.h"
#include "sendspin/client.h"

#include <algorithm>

namespace sendspin {

static const char* const TAG = "sendspin.announcement_task";

/// @brief Task stack size; Opus decode dominates, same budget as the sync task
static constexpr size_t ANNOUNCEMENT_TASK_STACK_SIZE = 6192;

/// @brief Timeout (ms) for receiving the next encoded chunk from the ring buffer
static constexpr uint32_t ANNOUNCEMENT_CHUNK_RECEIVE_TIMEOUT_MS = 15U;

/// @brief Wait slice (ms) while waiting for the main loop's stream start acknowledgement
static constexpr uint32_t START_ACK_WAIT_MS = 20U;

/// @brief Timeout (ms) for on_announcement_write pushes; bounds how long the task blocks on the
/// sink before re-checking command flags
static constexpr uint32_t ANNOUNCEMENT_WRITE_TIMEOUT_MS = 20U;

/// @brief Wait slice (ms) while sleeping toward the first chunk's start time
static constexpr uint32_t START_WAIT_SLICE_MS = 10U;

/// @brief Underrun guard: an open announcement stream whose buffer has drained with no data
/// arriving for this long is ended locally (5 s, per the spec's recommendation)
static constexpr int64_t ANNOUNCEMENT_STALL_TIMEOUT_US = 5000000;

/// @brief Upper bound on how long the task waits for the first chunk's timestamp; a farther
/// future timestamp starts playback anyway (announcements are near-now by design)
static constexpr int64_t ANNOUNCEMENT_MAX_START_WAIT_US = 5000000;

// ============================================================================
// Lifecycle
// ============================================================================

AnnouncementTask::~AnnouncementTask() {
    this->stop();
}

bool AnnouncementTask::init(AnnouncementRole::Impl* announcement_impl, SendspinClient* client,
                            size_t buffer_size) {
    this->announcement_impl_ = announcement_impl;
    this->client_ = client;

    if (!this->event_flags_.create()) {
        SS_LOGE(TAG, "Couldn't create event flags.");
        return false;
    }

    this->encoded_ring_buffer_ = SendspinAudioRingBuffer::create(buffer_size);
    if (this->encoded_ring_buffer_ == nullptr) {
        SS_LOGE(TAG, "Couldn't create encoded announcement ring buffer.");
        return false;
    }

    this->decoder_ = std::make_unique<SendspinDecoder>();

    return true;
}

bool AnnouncementTask::start(bool task_stack_in_psram, unsigned priority) {
    if (!this->is_initialized()) {
        SS_LOGE(TAG, "Announcement task not initialized (call init() first)");
        return false;
    }

    if (this->task_thread_.joinable()) {
        SS_LOGW(TAG, "Announcement task thread already started");
        return false;
    }

    this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_TASK_RUNNING |
                             AnnouncementTaskBits::ANNOUNCEMENT_TASK_STOPPED |
                             AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE |
                             AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                             AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END |
                             AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR |
                             AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_START);

    platform_configure_thread("SendspinAnnc", ANNOUNCEMENT_TASK_STACK_SIZE,
                              static_cast<int>(priority), task_stack_in_psram);

    this->task_thread_ = std::thread(thread_entry, this);

    // Wait for the thread to reach IDLE before returning
    this->event_flags_.wait(AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE |
                                AnnouncementTaskBits::ANNOUNCEMENT_TASK_STOPPED,
                            false, false, UINT32_MAX);

    return true;
}

// ============================================================================
// Public API
// ============================================================================

void AnnouncementTask::signal_stream_end() {
    // Lifecycle signals arrive unconditionally from the role, but init() only runs when the
    // role has announcement formats and a listener; setting bits on uncreated event flags is a
    // null-handle crash on ESP, so all signal/query paths guard on is_initialized().
    if (!this->is_initialized()) {
        return;
    }
    this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END);
}

void AnnouncementTask::signal_stream_clear() {
    if (!this->is_initialized()) {
        return;
    }
    this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR);
}

void AnnouncementTask::signal_stream_start() {
    if (!this->is_initialized()) {
        return;
    }
    this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_START);
}

bool AnnouncementTask::write_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                                         ChunkType chunk_type, uint32_t timeout_ms) {
    if (this->encoded_ring_buffer_ == nullptr) {
        return false;
    }
    return this->encoded_ring_buffer_->write_chunk(data, data_size, timestamp, chunk_type,
                                                   timeout_ms);
}

// ============================================================================
// Task loop
// ============================================================================

void AnnouncementTask::thread_entry(void* params) {
    auto* task = static_cast<AnnouncementTask*>(params);
    task->run();
}

void AnnouncementTask::run() {
    this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE);

    while ((this->event_flags_.get() & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP) == 0U) {
        AudioStreamInfo stream_info{};
        if (!this->wait_for_codec_header(&stream_info)) {
            break;  // COMMAND_STOP
        }

        // Wait for the main loop's start acknowledgement so on_announcement_start() (where the
        // embedder applies the ducking) fires before any announcement audio reaches the sink.
        bool start_acked = false;
        while (true) {
            const uint32_t flags = this->event_flags_.get();
            if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP) != 0U) {
                break;
            }
            if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END) != 0U) {
                this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END);
                this->drain_ring_buffer();
                break;
            }
            if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_START) != 0U) {
                this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_START);
                start_acked = true;
                break;
            }
            this->event_flags_.wait(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_START |
                                        AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                                        AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END,
                                    false, false, START_ACK_WAIT_MS);
        }
        if (!start_acked) {
            this->decoder_->reset_decoders();
            continue;
        }

        this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE);
        this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_TASK_RUNNING);

        this->play_stream();

        this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_TASK_RUNNING);
        this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE);
        this->decoder_->reset_decoders();
        this->announcement_impl_->enqueue_stream_event(
            AnnouncementStreamCallbackType::OUTPUT_FINISHED);
    }

    this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_TASK_IDLE |
                             AnnouncementTaskBits::ANNOUNCEMENT_TASK_RUNNING);
    this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_TASK_STOPPED);
}

bool AnnouncementTask::wait_for_codec_header(AudioStreamInfo* stream_info) {
    while (true) {
        const uint32_t flags = this->event_flags_.get();
        if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP) != 0U) {
            return false;
        }
        if ((flags & (AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END |
                      AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR)) != 0U) {
            // Stale commands from a stream that ended while idle
            this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END |
                                     AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR);
        }

        AudioRingBufferEntry* entry =
            this->encoded_ring_buffer_->receive_chunk(ANNOUNCEMENT_CHUNK_RECEIVE_TIMEOUT_MS);
        if (entry == nullptr) {
            continue;
        }

        const ChunkType chunk_type = entry->chunk_type;
        if (chunk_type == CHUNK_TYPE_ENCODED_AUDIO ||
            chunk_type == CHUNK_TYPE_STREAM_CLEAR_MARKER) {
            // Stale audio from a previous announcement; discard until a codec header arrives
            this->encoded_ring_buffer_->return_chunk(entry);
            continue;
        }

        const bool header_ok = this->decoder_->process_header(entry->data(), entry->data_size,
                                                              chunk_type, stream_info);
        this->encoded_ring_buffer_->return_chunk(entry);
        if (header_ok) {
            this->decode_buffer_.resize(this->decoder_->get_decode_buffer_size());
            return true;
        }
        SS_LOGE(TAG, "Failed to process announcement codec header");
    }
}

void AnnouncementTask::play_stream() {
    bool output_started = false;
    int64_t last_data_us = platform_time_us();

    while (true) {
        const uint32_t flags = this->event_flags_.get();
        if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP) != 0U) {
            break;
        }
        if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END) != 0U) {
            // Stream over (server end or abort): discard any remaining buffered audio
            this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END);
            this->drain_ring_buffer();
            break;
        }
        if ((flags & AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR) != 0U) {
            // Replace: drop what is buffered, keep playing what follows. The clear boundary is
            // approximate (chunks racing the drain may be dropped with the old clip), which the
            // silence-padded replacement stream tolerates.
            this->event_flags_.clear(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR);
            this->drain_ring_buffer();
            continue;
        }

        AudioRingBufferEntry* entry =
            this->encoded_ring_buffer_->receive_chunk(ANNOUNCEMENT_CHUNK_RECEIVE_TIMEOUT_MS);
        if (entry == nullptr) {
            if (platform_time_us() - last_data_us > ANNOUNCEMENT_STALL_TIMEOUT_US) {
                SS_LOGW(TAG, "Announcement stream stalled; ending locally");
                break;
            }
            continue;
        }
        last_data_us = platform_time_us();

        if (entry->chunk_type != CHUNK_TYPE_ENCODED_AUDIO) {
            if (entry->chunk_type == CHUNK_TYPE_STREAM_CLEAR_MARKER) {
                this->encoded_ring_buffer_->return_chunk(entry);
                continue;
            }
            // Mid-stream codec header (configuration update): re-initialize the decoder
            AudioStreamInfo new_info{};
            if (this->decoder_->process_header(entry->data(), entry->data_size, entry->chunk_type,
                                               &new_info)) {
                this->decode_buffer_.resize(this->decoder_->get_decode_buffer_size());
            } else {
                SS_LOGE(TAG, "Failed to process mid-stream announcement codec header");
            }
            this->encoded_ring_buffer_->return_chunk(entry);
            continue;
        }

        size_t decoded_size = 0;
        bool decode_ok = this->decoder_->decode_audio_chunk(
            entry->data(), entry->data_size, this->decode_buffer_.data(),
            this->decode_buffer_.size(), &decoded_size);
        if (!decode_ok && this->decoder_->get_decode_buffer_size() > this->decode_buffer_.size()) {
            // Opus decode-buffer growth: enlarge and retry once
            this->decode_buffer_.resize(this->decoder_->get_decode_buffer_size());
            decode_ok = this->decoder_->decode_audio_chunk(
                entry->data(), entry->data_size, this->decode_buffer_.data(),
                this->decode_buffer_.size(), &decoded_size);
        }
        const int64_t chunk_timestamp = entry->timestamp;
        this->encoded_ring_buffer_->return_chunk(entry);

        if (!decode_ok) {
            SS_LOGW(TAG, "Failed to decode announcement chunk");
            continue;
        }
        if (decoded_size == 0) {
            continue;
        }

        if (!output_started) {
            // Loose start scheduling: begin at the first chunk's timestamp when time sync is
            // available, or as soon as possible otherwise. Announcement chunks are never dropped
            // for lateness.
            this->wait_for_start_time(chunk_timestamp);
            if ((this->event_flags_.get() &
                 (AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                  AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END |
                  AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR)) != 0U) {
                continue;  // Re-enter the loop head to handle the command
            }
            output_started = true;
            this->announcement_impl_->enqueue_stream_event(
                AnnouncementStreamCallbackType::OUTPUT_STARTED);
        }

        // Push the decoded PCM to the sink; the blocking write is what paces this loop
        AnnouncementRoleListener* listener = this->announcement_impl_->listener;
        size_t offset = 0;
        while (offset < decoded_size && listener != nullptr) {
            if ((this->event_flags_.get() &
                 (AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                  AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END |
                  AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_CLEAR)) != 0U) {
                break;
            }
            const size_t written = listener->on_announcement_write(
                this->decode_buffer_.data() + offset, decoded_size - offset,
                ANNOUNCEMENT_WRITE_TIMEOUT_MS);
            if (written == 0) {
                if (platform_time_us() - last_data_us > ANNOUNCEMENT_STALL_TIMEOUT_US) {
                    SS_LOGW(TAG, "Announcement sink stalled; ending locally");
                    return;
                }
                continue;
            }
            last_data_us = platform_time_us();
            offset += written;
        }
    }
}

void AnnouncementTask::wait_for_start_time(int64_t server_timestamp) {
    if (this->client_ == nullptr || !this->client_->is_time_synced()) {
        return;
    }
    const int64_t target_us = this->client_->get_client_time(server_timestamp);
    const int64_t wait_deadline_us = platform_time_us() + ANNOUNCEMENT_MAX_START_WAIT_US;

    while (true) {
        if ((this->event_flags_.get() & (AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                                         AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END)) !=
            0U) {
            return;
        }
        const int64_t now_us = platform_time_us();
        if (now_us >= target_us || now_us >= wait_deadline_us) {
            return;
        }
        const int64_t remaining_ms = (std::min(target_us, wait_deadline_us) - now_us) / 1000;
        const uint32_t slice_ms =
            static_cast<uint32_t>(std::min<int64_t>(remaining_ms + 1, START_WAIT_SLICE_MS));
        this->event_flags_.wait(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP |
                                    AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STREAM_END,
                                false, false, slice_ms);
    }
}

void AnnouncementTask::drain_ring_buffer() {
    while (true) {
        AudioRingBufferEntry* entry = this->encoded_ring_buffer_->receive_chunk(0);
        if (entry == nullptr) {
            return;
        }
        this->encoded_ring_buffer_->return_chunk(entry);
    }
}

void AnnouncementTask::stop() {
    if (this->is_initialized()) {
        this->event_flags_.set(AnnouncementTaskBits::ANNOUNCEMENT_COMMAND_STOP);
    }
    if (this->task_thread_.joinable()) {
        this->task_thread_.join();
    }
}

}  // namespace sendspin
