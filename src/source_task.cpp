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

#include "source_task.h"

#include "audio_types.h"
#include "connection.h"
#include "connection_manager.h"
#include "platform/logging.h"
#include "platform/thread.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "source_encoder_opus.h"
#include "source_role_impl.h"
#include "time_filter.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace sendspin {

static const char* const TAG = "sendspin.source_task";

/// @brief Same budget as the sync task: the deepest paths are the stream start/end JSON build
/// and the transport send; Opus working buffers live on micro-opus's pseudostack, not here
static constexpr size_t SOURCE_TASK_STACK_SIZE = 6192;

/// @brief Ring receive timeout (ms) bounding how long the task waits before re-checking the
/// stop/connection conditions; same cadence as the sync task's encoded-chunk receive
static constexpr uint32_t CAPTURE_RECEIVE_TIMEOUT_MS = 15U;

/// @brief Binary type byte plus the BE64 capture timestamp (Sendspin spec, Source messages)
static constexpr size_t SOURCE_WIRE_HEADER_SIZE = 1U + BINARY_TIMESTAMP_SIZE;

/// @brief Backoff (ms) before retrying a failed stream open on a still-live connection; coarse
/// because opens are lifecycle-rare and the failure means transient pressure needing time
static constexpr uint32_t SOURCE_OPEN_RETRY_MS = 500U;

/// @brief Ring metadata margin: +1/4 over audio capacity for per-write entry headers, the
/// inverse of the player's 1/5 advertise fraction (AUDIO_BUFFER_ADVERTISE_DENOMINATOR)
static constexpr size_t CAPTURE_RING_OVERHEAD_DENOMINATOR = 4U;

// ============================================================================
// Lifecycle
// ============================================================================

SourceTask::~SourceTask() {
    this->stop();
}

bool SourceTask::init(SourceRole::Impl* source_impl, SendspinClient* client,
                      ConnectionManager* connections) {
    this->source_impl_ = source_impl;
    this->client_ = client;
    this->connections_ = connections;

    const SourceRoleConfig& config = source_impl->config;
    this->bytes_per_frame_ = source_bytes_per_frame(config.channels, config.bit_depth);

    // 64-bit intermediates with a fail-closed cap: ms x rate x bytes-per-frame can wrap a
    // 32-bit size_t, and a wrapped size would be a repaired config rather than a rejected one
    constexpr uint64_t MAX_BUFFER_BYTES = UINT32_MAX / 2;
    const uint64_t chunk_bytes =
        source_ms_to_frames(config.chunk_duration_ms, config.sample_rate) * this->bytes_per_frame_;
    if (chunk_bytes == 0 || chunk_bytes > MAX_BUFFER_BYTES) {
        // Zero: a sample rate so low the chunk duration holds no whole frame
        SS_LOGE(TAG, "Source chunk of %u ms at %u Hz is unusable (%llu bytes)",
                config.chunk_duration_ms, config.sample_rate,
                static_cast<unsigned long long>(chunk_bytes));
        return false;
    }
    this->chunk_bytes_ = static_cast<size_t>(chunk_bytes);

    const uint64_t audio_bytes =
        source_ms_to_frames(config.capture_buffer_ms, config.sample_rate) * this->bytes_per_frame_;
    if (audio_bytes > MAX_BUFFER_BYTES) {
        SS_LOGE(TAG, "Source capture buffer of %u ms at %u Hz is too large (%llu bytes)",
                config.capture_buffer_ms, config.sample_rate,
                static_cast<unsigned long long>(audio_bytes));
        return false;
    }

    if (!this->event_flags_.create()) {
        SS_LOGE(TAG, "Couldn't create event flags.");
        return false;
    }

    this->capture_ring_ = SendspinAudioRingBuffer::create(
        static_cast<size_t>(audio_bytes + audio_bytes / CAPTURE_RING_OVERHEAD_DENOMINATOR),
        config.buffer_location);
    if (this->capture_ring_ == nullptr) {
        SS_LOGE(TAG, "Couldn't create capture ring buffer.");
        return false;
    }

    size_t payload_capacity = this->chunk_bytes_;
    if (config.codec == SendspinCodecFormat::OPUS) {
        auto opus_encoder = std::make_unique<OpusSourceEncoder>();
        if (!opus_encoder->init(config)) {
            return false;  // Cause already logged; no streaming without a working encoder
        }
        this->encoder_ = std::move(opus_encoder);
        // An opus packet can exceed the chunk's PCM size (small chunks vs a high bitrate), so
        // the payload area covers the encoder's max packet: no accepted config drops on capacity
        payload_capacity = std::max(payload_capacity, OpusSourceEncoder::MAX_PACKET_BYTES);
    } else {
        this->encoder_ = std::make_unique<PcmPassthroughEncoder>();
    }

    if (!this->staging_.allocate(SOURCE_WIRE_HEADER_SIZE + payload_capacity,
                                 config.buffer_location)) {
        SS_LOGE(TAG, "Couldn't allocate chunk staging buffer.");
        return false;
    }

    this->send_complete_cb_ = [this](bool ok) {
        this->last_send_ok_.store(ok, std::memory_order_release);
        this->event_flags_.set(SourceTaskBits::SOURCE_SEND_COMPLETE);
    };

    return true;
}

bool SourceTask::start(bool task_stack_in_psram, unsigned priority) {
    if (!this->is_initialized()) {
        SS_LOGE(TAG, "Source task not initialized (call init() first)");
        return false;
    }

    if (this->task_thread_.joinable()) {
        SS_LOGW(TAG, "Source task thread already started");
        return false;
    }

    this->event_flags_.clear(
        SourceTaskBits::SOURCE_TASK_RUNNING | SourceTaskBits::SOURCE_TASK_STOPPED |
        SourceTaskBits::SOURCE_TASK_IDLE | SourceTaskBits::SOURCE_COMMAND_STOP |
        SourceTaskBits::SOURCE_COMMAND_UPDATE | SourceTaskBits::SOURCE_SEND_COMPLETE);

    platform_configure_thread("SsSrc", SOURCE_TASK_STACK_SIZE, static_cast<int>(priority),
                              task_stack_in_psram);

    this->task_thread_ = std::thread(thread_entry, this);

    // Wait for the thread to reach IDLE before returning
    this->event_flags_.wait(SourceTaskBits::SOURCE_TASK_IDLE | SourceTaskBits::SOURCE_TASK_STOPPED,
                            false, false, UINT32_MAX);

    return true;
}

// ============================================================================
// Public API
// ============================================================================

void SourceTask::signal_start() {
    // Setting bits on uncreated event flags is a null-handle crash on ESP; init() only runs
    // for a valid config, so every signal/query path guards on is_initialized()
    if (!this->is_initialized()) {
        return;
    }
    this->stream_requested_.store(true, std::memory_order_release);
    this->event_flags_.set(SourceTaskBits::SOURCE_COMMAND_UPDATE);
}

void SourceTask::signal_stop() {
    if (!this->is_initialized()) {
        return;
    }
    this->stream_requested_.store(false, std::memory_order_release);
    this->event_flags_.set(SourceTaskBits::SOURCE_COMMAND_UPDATE);
}

bool SourceTask::write_audio(const uint8_t* data, size_t len, int64_t capture_time_us) {
    // Defaults false and is only set by a running task, so a never-initialized role rejects too
    if (!this->accepting_audio_.load(std::memory_order_acquire)) {
        return false;
    }
    if (data == nullptr || len == 0 || (len % this->bytes_per_frame_) != 0U) {
        // A forwarded partial frame would shift the channel interleaving of every later sample;
        // warn once per episode so a misconfigured caller cannot flood the log at capture rate
        if (!this->producer_frame_warned_) {
            this->producer_frame_warned_ = true;
            SS_LOGW(TAG, "write_audio() rejected: %u bytes is not a whole number of %u-byte frames",
                    static_cast<unsigned>(len), static_cast<unsigned>(this->bytes_per_frame_));
        }
        return false;
    }
    if (capture_time_us == 0) {
        // Best-effort arrival stamp for callers that cannot timestamp their ADC
        capture_time_us = platform_time_us();
    }
    if (!this->capture_ring_->write_chunk(data, len, capture_time_us, CHUNK_TYPE_ENCODED_AUDIO,
                                          0)) {
        // The ring bounds the stall backlog (capture_buffer_ms); warn once per overflow
        // episode, the recovery log carries the total
        ++this->producer_dropped_writes_;
        if (!this->producer_drop_episode_) {
            this->producer_drop_episode_ = true;
            SS_LOGW(TAG, "Capture ring full; dropping writes until it drains");
        }
        return false;
    }
    if (this->producer_drop_episode_) {
        this->producer_drop_episode_ = false;
        SS_LOGI(TAG, "Capture resumed after dropping %u writes", this->producer_dropped_writes_);
        this->producer_dropped_writes_ = 0;
    }
    this->producer_frame_warned_ = false;
    return true;
}

// ============================================================================
// Task loop
// ============================================================================

void SourceTask::thread_entry(void* params) {
    auto* task = static_cast<SourceTask*>(params);
    task->run();
}

void SourceTask::run() {
    this->event_flags_.set(SourceTaskBits::SOURCE_TASK_IDLE);

    while (true) {
        const uint32_t flags = this->event_flags_.wait(
            SourceTaskBits::SOURCE_COMMAND_STOP | SourceTaskBits::SOURCE_COMMAND_UPDATE, false,
            false, UINT32_MAX);
        if ((flags & SourceTaskBits::SOURCE_COMMAND_STOP) != 0U) {
            break;
        }
        this->event_flags_.clear(SourceTaskBits::SOURCE_COMMAND_UPDATE);
        if (!this->stream_requested_.load(std::memory_order_acquire)) {
            continue;  // A stop that raced an earlier start; nothing to do while idle
        }

        // Streaming permission is per-connection (Sendspin spec, Source messages): bind the
        // stream to one connection for its whole life; a swap ends it rather than migrating it
        auto conn = this->connections_->current_shared();
        if (conn == nullptr) {
            continue;  // Vanished since the latch; the role's cleanup wakes this loop again
        }

        this->event_flags_.clear(SourceTaskBits::SOURCE_TASK_IDLE);
        this->event_flags_.set(SourceTaskBits::SOURCE_TASK_RUNNING);
        this->stream(conn);
        this->event_flags_.clear(SourceTaskBits::SOURCE_TASK_RUNNING);
        this->event_flags_.set(SourceTaskBits::SOURCE_TASK_IDLE);

        // stream() exiting with desired-state still streaming on a still-current connection
        // means the open itself failed (every other exit clears one of these conditions);
        // the server will not repeat its start, so back off and re-attempt instead of parking
        if ((this->event_flags_.get() & SourceTaskBits::SOURCE_COMMAND_STOP) == 0U &&
            this->stream_requested_.load(std::memory_order_acquire) &&
            this->connections_->current_shared() == conn) {
            this->event_flags_.wait(
                SourceTaskBits::SOURCE_COMMAND_STOP | SourceTaskBits::SOURCE_COMMAND_UPDATE, false,
                false, SOURCE_OPEN_RETRY_MS);
            this->event_flags_.set(SourceTaskBits::SOURCE_COMMAND_UPDATE);
        }
    }

    this->event_flags_.clear(SourceTaskBits::SOURCE_TASK_IDLE |
                             SourceTaskBits::SOURCE_TASK_RUNNING);
    this->event_flags_.set(SourceTaskBits::SOURCE_TASK_STOPPED);
}

void SourceTask::stream(const std::shared_ptr<SendspinConnection>& conn) {
    if (!this->wait_for_time_sync(conn)) {
        return;  // Cancelled while waiting; nothing was sent, so nothing to close
    }

    // No negotiation: the add_source() config is the announced format (Sendspin spec, Source
    // messages -- client-stream/start). JSON on this thread is fine, open/close is rare.
    const SourceRoleConfig& config = this->source_impl_->config;
    ClientStreamStartMessage start_msg;
    start_msg.codec = config.codec;
    start_msg.channels = config.channels;
    start_msg.sample_rate = config.sample_rate;
    start_msg.bit_depth = config.bit_depth;
    if (conn->send_text_message(format_client_stream_start_message(&start_msg), nullptr) !=
        SsErr::OK) {
        SS_LOGW(TAG, "Failed to send client-stream/start; stream not opened");
        return;
    }

    this->encoder_->reset();
    this->chunk_filled_bytes_ = 0;
    this->stall_episode_ = false;
    this->stall_flushed_entries_ = 0;

    // Flush while the gate is still closed (no writer can race it), so the first chunk is live
    // audio by construction; then open for capture -- chunks must follow client-stream/start
    this->flush_ring_to_live();
    this->accepting_audio_.store(true, std::memory_order_release);
    this->source_impl_->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STARTED);

    while (this->stream_still_open(conn)) {
        if (this->current_entry_ == nullptr) {
            this->current_entry_ = this->capture_ring_->receive_chunk(CAPTURE_RECEIVE_TIMEOUT_MS);
            this->entry_consumed_bytes_ = 0;
            if (this->current_entry_ == nullptr) {
                continue;  // No capture yet; re-check the stream conditions
            }
        }

        if (this->chunk_filled_bytes_ == 0) {
            // Anchor on the chunk's own first sample, past any already-consumed entry frames
            this->chunk_anchor_us_ =
                source_entry_anchor_us(this->current_entry_->timestamp, this->entry_consumed_bytes_,
                                       this->bytes_per_frame_, config.sample_rate);
        }

        uint8_t* payload = this->staging_.data() + SOURCE_WIRE_HEADER_SIZE;
        const size_t take = std::min(this->current_entry_->data_size - this->entry_consumed_bytes_,
                                     this->chunk_bytes_ - this->chunk_filled_bytes_);
        memcpy(payload + this->chunk_filled_bytes_,
               this->current_entry_->data() + this->entry_consumed_bytes_, take);
        this->chunk_filled_bytes_ += take;
        this->entry_consumed_bytes_ += take;
        if (this->entry_consumed_bytes_ == this->current_entry_->data_size) {
            this->capture_ring_->return_chunk(this->current_entry_);
            this->current_entry_ = nullptr;
        }

        if (this->chunk_filled_bytes_ == this->chunk_bytes_) {
            const bool sent = this->send_chunk(conn);
            this->chunk_filled_bytes_ = 0;
            if (!sent) {
                // Drop the backlog and resume from live capture rather than bursting stale
                // audio (Sendspin spec, Source messages -- stall policy); warn once per episode
                this->stall_flushed_entries_ += this->flush_ring_to_live();
                if (!this->stall_episode_) {
                    this->stall_episode_ = true;
                    SS_LOGW(TAG, "Source send stalled; dropping to live capture");
                }
            } else if (this->stall_episode_) {
                this->stall_episode_ = false;
                SS_LOGI(TAG, "Source send recovered; %u buffered entries were dropped",
                        static_cast<unsigned>(this->stall_flushed_entries_));
                this->stall_flushed_entries_ = 0;
            }
        }
    }

    // Close: stop accepting capture first so the tail below is finite
    this->accepting_audio_.store(false, std::memory_order_release);

    // A final short chunk is allowed at stream end but not required (Sendspin spec, Source
    // messages): a remainder the encoder cannot take is dropped rather than padded
    if (this->chunk_filled_bytes_ > 0 && this->encoder_->can_encode(this->chunk_filled_bytes_)) {
        this->send_chunk(conn);
        this->chunk_filled_bytes_ = 0;
    }

    // Sent from this thread so it is ordered after the last chunk by construction; best-effort,
    // the connection may already be gone
    conn->send_text_message(format_client_stream_end_message(), nullptr);
    this->source_impl_->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STOPPED);

    this->flush_ring_to_live();
}

bool SourceTask::wait_for_time_sync(const std::shared_ptr<SendspinConnection>& conn) {
    // Asked of the bound connection directly: the stream must not open on the strength of a
    // different connection's sync
    while (!conn->is_time_synced()) {
        if (!this->stream_still_open(conn)) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_TIME_SYNC_MS));
    }
    return this->stream_still_open(conn);
}

bool SourceTask::send_chunk(const std::shared_ptr<SendspinConnection>& conn) {
    // First-sample capture time minus encoder lookahead, converted with offset AND drift and
    // never a playback/static delay term (Sendspin spec, Source messages -- timestamping)
    const int64_t server_ts = conn->get_time_filter()->compute_server_time(
        this->chunk_anchor_us_ - this->encoder_->lookahead_us());

    uint8_t* staging = this->staging_.data();
    const size_t payload_len = this->encoder_->encode(
        staging + SOURCE_WIRE_HEADER_SIZE, this->chunk_filled_bytes_,
        staging + SOURCE_WIRE_HEADER_SIZE, this->staging_.size() - SOURCE_WIRE_HEADER_SIZE);
    if (payload_len == 0) {
        SS_LOGW(TAG, "Source encoder produced no payload; dropping chunk");
        return false;
    }

    staging[0] = SENDSPIN_BINARY_SOURCE_AUDIO;
    host_to_be64(server_ts, staging + 1);

    const SsErr err = conn->send_binary_message(staging, SOURCE_WIRE_HEADER_SIZE + payload_len,
                                                this->send_complete_cb_);

    // Consume the completion unconditionally: the callback fires exactly once for EVERY call
    // (connection.h contract), so skipping the wait on an error would leave a stale bit pacing
    // the next send, and waiting every send out is what makes staging reuse and teardown safe
    this->event_flags_.wait(SourceTaskBits::SOURCE_SEND_COMPLETE, false, true, UINT32_MAX);
    return err == SsErr::OK && this->last_send_ok_.load(std::memory_order_acquire);
}

size_t SourceTask::flush_ring_to_live() {
    size_t flushed = 0;
    if (this->current_entry_ != nullptr) {
        this->capture_ring_->return_chunk(this->current_entry_);
        this->current_entry_ = nullptr;
        ++flushed;
    }
    this->entry_consumed_bytes_ = 0;
    while (true) {
        AudioRingBufferEntry* entry = this->capture_ring_->receive_chunk(0);
        if (entry == nullptr) {
            return flushed;
        }
        this->capture_ring_->return_chunk(entry);
        ++flushed;
    }
}

bool SourceTask::stream_still_open(const std::shared_ptr<SendspinConnection>& conn) const {
    if ((this->event_flags_.get() & SourceTaskBits::SOURCE_COMMAND_STOP) != 0U) {
        return false;
    }
    if (!this->stream_requested_.load(std::memory_order_acquire)) {
        return false;
    }
    // Permission is per-connection: the stream ends as soon as its connection stops being
    // current (drop or handoff), without waiting for the main loop's cleanup to latch the stop.
    return this->connections_->current_shared() == conn;
}

void SourceTask::stop() {
    if (!this->task_thread_.joinable()) {
        return;
    }
    this->event_flags_.set(SourceTaskBits::SOURCE_COMMAND_STOP);
    this->task_thread_.join();
}

}  // namespace sendspin
