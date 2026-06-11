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

#include "sync_task.h"

#include "audio_utils.h"
#include "constants.h"
#include "platform/logging.h"
#include "platform/thread.h"
#include "player_role_impl.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace sendspin {

// ============================================================================
// Static helpers
// ============================================================================

static constexpr int64_t HARD_SYNC_THRESHOLD_US = 5000;
static constexpr int64_t HARD_SYNC_SETTLE_THRESHOLD_US =
    500;  // Tighter threshold used while settling after a hard sync
static constexpr int64_t SOFT_SYNC_THRESHOLD_US = 100;

static constexpr uint32_t INITIAL_SYNC_ZEROS_DURATION_MS = 25;

static constexpr size_t SYNC_TASK_STACK_SIZE = 6192;  // Opus uses more stack than FLAC

/// @brief Wait time (ms) between retries when time sync is not yet available
static constexpr uint32_t WAIT_FOR_TIME_SYNC_MS = 15U;

/// @brief Timeout (ms) for receiving the next encoded audio chunk from the ring buffer
static constexpr uint32_t ENCODED_CHUNK_RECEIVE_TIMEOUT_MS = 15U;

/// @brief Silence (ms) queued per encoded-chunk underflow to keep the DAC fed between chunks. A bit
/// above ENCODED_CHUNK_RECEIVE_TIMEOUT_MS so it spans one more load wait, though not a strict
/// bound: the fill bails as soon as a chunk lands and is paced by sink backpressure.
static constexpr uint32_t UNDERFLOW_SILENCE_KEEPALIVE_MS = 20U;

/// @brief Timeout (ms) for on_audio_write pushes; bounds how long the sync task blocks on the
/// sink before returning to its inner loop to re-check flags and drift.
static constexpr uint32_t AUDIO_WRITE_TIMEOUT_MS = 20U;

/// @brief Minimum sleep (ms) after an initial-sync push, to let the audio stack begin draining
/// before the next push.
static constexpr uint32_t INITIAL_SYNC_SETTLE_MIN_MS = 2U;

/// @brief Size of the shared silence scratch buffer. Bounds the bytes pushed to the sink per call;
/// silence longer than this is sent over multiple iterations.
static constexpr size_t SILENCE_SCRATCH_BYTES = 1024;

/// @brief Chunk of zeros streamed to the sink for initial-sync priming and hard-sync gap fills.
/// Never written after zero-initialization (the sink only ever reads its input). Deliberately
/// non-const so it lands in .bss (internal SRAM on ESP-IDF) rather than .rodata (flash): the
/// initial-sync push happens exactly when the server is flooding the ring buffer in PSRAM, and on
/// the ESP32 flash shares the SPI bus with PSRAM, so a flash read here would contend with that
/// flood. .bss costs no heap and no flash; it is reserved and zeroed once at startup.
static uint8_t silence_scratch[SILENCE_SCRATCH_BYTES] = {};

/// @brief Byte count for `duration_ms` of silence, rounded down to whole frames so per-write chunks
/// and track_sent_audio() accounting stay on frame boundaries (the ms->bytes result need not
/// align).
static size_t frame_aligned_silence_bytes(const AudioStreamInfo& stream_info,
                                          uint32_t duration_ms) {
    return stream_info.frames_to_bytes(
        stream_info.bytes_to_frames(stream_info.ms_to_bytes(duration_ms)));
}

static const char* const TAG = "sendspin.sync_task";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SyncTask::~SyncTask() {
    this->stop();
}

bool SyncTask::init(PlayerRole::Impl* player_impl, SendspinClient* client, size_t buffer_size) {
    this->player_impl_ = player_impl;
    this->client_ = client;

    if (!this->event_flags_.create()) {
        SS_LOGE(TAG, "Couldn't create event flags.");
        return false;
    }

    this->encoded_ring_buffer_ = SendspinAudioRingBuffer::create(buffer_size);
    if (this->encoded_ring_buffer_ == nullptr) {
        SS_LOGE(TAG, "Couldn't create encoded audio ring buffer.");
        return false;
    }

    return true;
}

bool SyncTask::start(bool task_stack_in_psram, unsigned priority) {
    if (!this->is_initialized()) {
        SS_LOGE(TAG, "Sync task not initialized (call init() first or set audio sink)");
        return false;
    }

    if (this->sync_thread_.joinable()) {
        SS_LOGW(TAG, "Sync task thread already started");
        return false;
    }

    this->event_flags_.clear(EventGroupBits::TASK_RUNNING | EventGroupBits::TASK_STOPPED |
                             EventGroupBits::TASK_IDLE | EventGroupBits::COMMAND_STOP |
                             EventGroupBits::COMMAND_STREAM_END |
                             EventGroupBits::COMMAND_STREAM_CLEAR | EventGroupBits::COMMAND_START);

    platform_configure_thread("Sendspin", SYNC_TASK_STACK_SIZE, static_cast<int>(priority),
                              task_stack_in_psram);

    this->sync_thread_ = std::thread(thread_entry, this);

    // Wait for the thread to reach IDLE before returning
    this->event_flags_.wait(EventGroupBits::TASK_IDLE | EventGroupBits::TASK_STOPPED, false, false,
                            UINT32_MAX);

    return true;
}

// ============================================================================
// Public API
// ============================================================================

void SyncTask::signal_stream_end() {
    this->event_flags_.set(EventGroupBits::COMMAND_STREAM_END);
}

void SyncTask::signal_stream_clear() {
    this->event_flags_.set(EventGroupBits::COMMAND_STREAM_CLEAR);
}

void SyncTask::signal_stream_start() {
    this->event_flags_.set(EventGroupBits::COMMAND_START);
}

bool SyncTask::write_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                                 ChunkType chunk_type, uint32_t timeout_ms) {
    if (this->encoded_ring_buffer_ == nullptr) {
        return false;
    }
    return this->encoded_ring_buffer_->write_chunk(data, data_size, timestamp, chunk_type,
                                                   timeout_ms);
}

void SyncTask::notify_audio_played(uint32_t frames, int64_t timestamp) {
    // Merge into the shadow slot: sum frames across unread updates and keep
    // the most recent finish_timestamp. The sync thread drains on each inner
    // loop iteration.
    this->playback_progress_slot_.merge(
        [](PlaybackProgress& current, PlaybackProgress&& delta) {
            current.frames_played += delta.frames_played;
            current.finish_timestamp = delta.finish_timestamp;
        },
        PlaybackProgress{frames, timestamp});
}

// ============================================================================
// Private sync helpers
// ============================================================================

SyncTaskState SyncTask::handle_initial_sync(SyncContext& sync_context) {
    if (!sync_context.initial_decode) {
        // Priming done. process_playback_progress() queued the extra startup silence on the first
        // playback notification; drain it before the first real chunk so the decode pipeline has
        // slack to stay ahead of the sink.
        this->send_pending_silence(sync_context);
        if (sync_context.silence_remaining > 0) {
            return SyncTaskState::INITIAL_SYNC;
        }
        return SyncTaskState::LOAD_CHUNK;
    }

    if (sync_context.silence_remaining == 0) {
        sync_context.silence_remaining = frame_aligned_silence_bytes(
            sync_context.current_stream_info, INITIAL_SYNC_ZEROS_DURATION_MS);
    }
    this->send_pending_silence(sync_context);

    return SyncTaskState::INITIAL_SYNC;
}

SyncTaskState SyncTask::handle_load_chunk(SyncContext& sync_context) {
    if (!this->client_->is_time_synced()) {
        // Wait for the time filter to receive its first measurement before processing audio chunks.
        // Without a valid time offset, server timestamps can't be correctly converted to client
        // timestamps.
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_TIME_SYNC_MS));
        return SyncTaskState::LOAD_CHUNK;
    }
    if (!this->load_next_chunk(sync_context)) {
        // Bridge underflows with silence only while aligning (startup/post-seek). In steady state
        // an empty buffer means the stream is winding down; stuffing silence would pile up in the
        // sink and delay a rapid restart (and a real underrun is better surfaced as an error than
        // masked).
        if (sync_context.aligning) {
            this->fill_underflow_silence(sync_context);
        }
        return SyncTaskState::LOAD_CHUNK;
    }
    DecodeResult decode_result = this->decode_chunk(sync_context);
    if ((decode_result == DecodeResult::SKIPPED) || (decode_result == DecodeResult::FAILED)) {
        return SyncTaskState::LOAD_CHUNK;
    }
    if (decode_result == DecodeResult::ALLOCATION_FAILED) {
        this->event_flags_.set(EventGroupBits::TASK_ERROR | EventGroupBits::COMMAND_STOP);
        return SyncTaskState::LOAD_CHUNK;
    }
    if (sync_context.decode_buffer == nullptr || sync_context.decode_buffer->available() == 0) {
        // No decoded audio available yet, try again (probably just processed a header)
        return SyncTaskState::LOAD_CHUNK;
    }
    return SyncTaskState::SYNCHRONIZE_AUDIO;
}

SyncTaskState SyncTask::handle_synchronize_audio(SyncContext& sync_context) {
    // Predicted error: positive means chunk should play later than our current buffer endpoint
    int64_t raw_error = sync_context.decoded_timestamp - sync_context.new_audio_client_playtime;

    // Use tighter threshold while settling after a hard sync (or during initial sync) to ensure
    // precise alignment. The normal threshold detects when hard sync is needed; the settle
    // threshold keeps hard-syncing until well-aligned.
    const int64_t active_threshold =
        sync_context.hard_syncing ? HARD_SYNC_SETTLE_THRESHOLD_US : HARD_SYNC_THRESHOLD_US;

    if ((raw_error > active_threshold) || (raw_error < -active_threshold)) {
        // A hard sync is needed. While aligning (initial-sync priming/alignment or post-seek
        // re-alignment) hard syncs are expected, so they do not report an error. Otherwise this is
        // an unexpected loss of sync (e.g. buffer underrun): report ERROR once and keep filling
        // with silence until we re-align, at which point SYNCHRONIZED is reported.
        if (!sync_context.aligning && !sync_context.reported_error) {
            sync_context.reported_error = true;
            this->player_impl_->enqueue_state_update(SendspinClientState::ERROR);
            SS_LOGW(TAG, "Lost sync (%" PRId64 "us off), reporting error", raw_error);
        }
    }

    if (raw_error > active_threshold) {
        // Buffer will run out before this chunk is supposed to play - insert silence to fill the
        // gap
        sync_context.hard_syncing = true;

        // Compute silence directly in frames from microseconds (avoids ms truncation)
        uint32_t silence_frames = static_cast<uint32_t>(
            (static_cast<uint64_t>(raw_error) *
             static_cast<uint64_t>(sync_context.current_stream_info.get_sample_rate())) /
            static_cast<uint64_t>(US_PER_SECOND));
        sync_context.silence_remaining =
            sync_context.current_stream_info.frames_to_bytes(silence_frames);

        // Playtime estimate is advanced by transfer_audio() when the silence is actually sent
        sync_context.release_chunk = false;  // Keep decoded audio for after the silence

        SS_LOGV(TAG,
                "Hard sync: adding %" PRIu32 " frames of silence for %" PRId64 "us future error",
                silence_frames, raw_error);
    } else if (raw_error < -active_threshold) {
        // Chunk should have started playing already - drop only the late prefix from the front of
        // the buffer and play the remainder. By the time we get here, silence has already been
        // inserted to fill the gap (one audible discontinuity); a partial drop keeps the
        // follow-up disturbance smaller than discarding the whole chunk would. Any sub-threshold
        // residual is left for the next chunk's soft sync to absorb.
        sync_context.hard_syncing = true;

        uint32_t late_frames = static_cast<uint32_t>(
            (static_cast<uint64_t>(-raw_error) *
             static_cast<uint64_t>(sync_context.current_stream_info.get_sample_rate())) /
            static_cast<uint64_t>(US_PER_SECOND));
        size_t late_bytes = sync_context.current_stream_info.frames_to_bytes(late_frames);
        size_t actual_drop = std::min(late_bytes, sync_context.decode_buffer->available());
        sync_context.decode_buffer->decrease_buffer_length(actual_drop);
        uint32_t dropped_frames = sync_context.current_stream_info.bytes_to_frames(actual_drop);
        sync_context.decoded_timestamp +=
            sync_context.current_stream_info.frames_to_microseconds(dropped_frames);

        SS_LOGV(TAG,
                "Hard sync: dropping %" PRIu32 " frames from start of chunk, %" PRId64 "us behind",
                dropped_frames, -raw_error);

        if (sync_context.decode_buffer->available() == 0) {
            // Entire chunk was late
            return SyncTaskState::LOAD_CHUNK;
        }
        sync_context.release_chunk = true;
    } else {
        // Within tolerance - exit hard sync mode and use sample insertion/deletion for fine
        // corrections
        sync_context.hard_syncing = false;

        // First in-tolerance alignment completes initial-sync/post-seek alignment. If we had
        // reported a sync error, we have now recovered: report SYNCHRONIZED.
        sync_context.aligning = false;
        if (sync_context.reported_error) {
            sync_context.reported_error = false;
            this->player_impl_->enqueue_state_update(SendspinClientState::SYNCHRONIZED);
            SS_LOGI(TAG, "Regained sync, reporting synchronized");
        }

        if (raw_error > SOFT_SYNC_THRESHOLD_US) {
            // Slightly behind - add one interpolated frame between the last two decoded frames
            // Playtime estimate is advanced by transfer_audio() when the extra frame is sent
            this->soft_sync_insert_frame(sync_context);
        } else if (raw_error < -SOFT_SYNC_THRESHOLD_US) {
            // Slightly ahead - remove last frame, blend into second-to-last
            // Playtime estimate naturally reflects the removed frame: transfer_audio() sends
            // fewer bytes
            this->soft_sync_drop_frame(sync_context);
        }
        // else: Dead zone - pass decoded audio through directly
        sync_context.release_chunk = true;
    }
    return SyncTaskState::TRANSFER_AUDIO;
}

SyncTaskState SyncTask::handle_transfer_audio(SyncContext& sync_context) {
    if (!this->transfer_audio(sync_context)) {
        return SyncTaskState::TRANSFER_AUDIO;  // Not done transferring yet
    }
    if (sync_context.decode_buffer != nullptr && sync_context.decode_buffer->available() > 0) {
        // Decoded audio still waiting (was held back while silence was sent) - re-sync it
        return SyncTaskState::SYNCHRONIZE_AUDIO;
    }
    return SyncTaskState::LOAD_CHUNK;
}

void SyncTask::track_sent_audio(SyncContext& sync_context, size_t bytes_sent) {
    uint32_t frames_sent = sync_context.current_stream_info.bytes_to_frames(bytes_sent);
    sync_context.buffered_frames += frames_sent;
    sync_context.new_audio_client_playtime +=
        sync_context.current_stream_info.frames_to_microseconds(frames_sent);
}

void SyncTask::send_pending_silence(SyncContext& sync_context) {
    if (sync_context.silence_remaining == 0) {
        return;
    }

    size_t chunk = std::min<size_t>(sync_context.silence_remaining, sizeof(silence_scratch));
    // Push whole frames only: the scratch size is not necessarily a multiple of bytes_per_frame
    // (e.g. 24-bit stereo), and unaligned writes would mis-account playtime in track_sent_audio()
    // and can violate frame-alignment expectations of some sinks. silence_remaining is itself
    // frame-aligned, so the final chunk stays whole.
    if (sync_context.bytes_per_frame > 0) {
        chunk -= chunk % sync_context.bytes_per_frame;
        if (chunk == 0) {
            chunk = std::min<size_t>(sync_context.silence_remaining, sync_context.bytes_per_frame);
        }
    }
    size_t bytes_written = 0;
    if (this->player_impl_->listener != nullptr) {
        bytes_written = this->player_impl_->listener->on_audio_write(silence_scratch, chunk,
                                                                     AUDIO_WRITE_TIMEOUT_MS);
    }
    this->track_sent_audio(sync_context, bytes_written);
    sync_context.silence_remaining -= bytes_written;

    if ((bytes_written > 0) && sync_context.initial_decode) {
        // Sent priming zeros - delay slightly to give the audio stack time to start consuming
        std::this_thread::sleep_for(std::chrono::milliseconds(
            std::max<uint32_t>(INITIAL_SYNC_SETTLE_MIN_MS,
                               sync_context.current_stream_info.bytes_to_ms(bytes_written) / 2)));
    }
}

void SyncTask::fill_underflow_silence(SyncContext& sync_context) {
    // Bridge a startup/post-seek underflow: keep the sink fed with silence until the next chunk
    // arrives instead of spinning and draining the DAC. Feeding silence advances
    // new_audio_client_playtime, so handle_synchronize_audio() re-aligns the next chunk against it
    // once one arrives.
    if (this->player_impl_->listener == nullptr) {
        return;
    }
    if (sync_context.silence_remaining == 0) {
        sync_context.silence_remaining = frame_aligned_silence_bytes(
            sync_context.current_stream_info, UNDERFLOW_SILENCE_KEEPALIVE_MS);
    }
    // Drain the window block by block; send_pending_silence() blocks on sink backpressure. The loop
    // re-checks between blocks, so it stops after the current write once a chunk lands or a
    // lifecycle command fires.
    while (
        (sync_context.silence_remaining > 0) &&
        (this->encoded_ring_buffer_->chunks_waiting() == 0) &&
        !(this->event_flags_.get() & (COMMAND_STOP | COMMAND_STREAM_END | COMMAND_STREAM_CLEAR))) {
        this->send_pending_silence(sync_context);
    }
}

bool SyncTask::transfer_audio(SyncContext& sync_context) {
    // Pending silence (priming or hard-sync gap fill) goes out before the decoded chunk
    this->send_pending_silence(sync_context);

    if (sync_context.silence_remaining == 0 && sync_context.release_chunk) {
        size_t decode_bytes_written =
            sync_context.decode_buffer->transfer_data_to_sink(AUDIO_WRITE_TIMEOUT_MS);
        this->track_sent_audio(sync_context, decode_bytes_written);
    }

    // When decode buffer fully consumed and released, mark done
    if (sync_context.decode_buffer->available() == 0 && sync_context.release_chunk) {
        sync_context.release_chunk = false;
    }

    // Keep transferring if there's still data to send
    if (sync_context.silence_remaining > 0) {
        return false;
    }
    if (sync_context.release_chunk && sync_context.decode_buffer->available() > 0) {
        return false;
    }

    return true;
}

bool SyncTask::load_next_chunk(SyncContext& sync_context) {
    if (sync_context.encoded_entry == nullptr) {
        sync_context.encoded_entry =
            this->encoded_ring_buffer_->receive_chunk(ENCODED_CHUNK_RECEIVE_TIMEOUT_MS);
        if (sync_context.encoded_entry == nullptr) {
            // No chunk available to process
            return false;
        }
    }

    return true;
}

int32_t SyncTask::soft_sync_drop_frame(SyncContext& sync_context) {
    // Small sync adjustment after getting slightly ahead.
    // Removes the last frame in the chunk to get in sync. The second to last frame is replaced with
    // the average of it and the removed frame to minimize audible glitches.

    const uint32_t num_channels = sync_context.current_stream_info.get_channels();
    const uint32_t bytes_per_sample = sync_context.bytes_per_frame / num_channels;

    if (sync_context.decode_buffer->available() >= 2 * sync_context.bytes_per_frame) {
        for (uint32_t chan = 0; chan < num_channels; ++chan) {
            const size_t chan_offset =
                static_cast<size_t>(chan) * static_cast<size_t>(bytes_per_sample);
            const int32_t first_sample =
                unpack_audio_sample_to_q31(sync_context.decode_buffer->get_buffer_end() -
                                               2 * sync_context.bytes_per_frame + chan_offset,
                                           bytes_per_sample);
            const int32_t second_sample =
                unpack_audio_sample_to_q31(sync_context.decode_buffer->get_buffer_end() -
                                               sync_context.bytes_per_frame + chan_offset,
                                           bytes_per_sample);
            int32_t replacement_sample = first_sample / 2 + second_sample / 2;
            pack_q31_as_audio_sample(replacement_sample,
                                     sync_context.decode_buffer->get_buffer_end() -
                                         2 * sync_context.bytes_per_frame + chan_offset,
                                     bytes_per_sample);
        }

        sync_context.decode_buffer->decrease_buffer_length(sync_context.bytes_per_frame);
        return -1;
    }
    return 0;
}

int32_t SyncTask::soft_sync_insert_frame(SyncContext& sync_context) {
    // Small sync adjustment after getting slightly behind.
    // Adds one new frame to get in sync. The new frame is inserted between the last two frames of
    // the chunk and set to the average of those two frames to minimize audible glitches. The
    // original last frame is moved into the spare frame the decode buffer reserves past the decoded
    // data, so no second buffer is needed.

    if ((sync_context.decode_buffer->available() < 2 * sync_context.bytes_per_frame) ||
        (sync_context.decode_buffer->free() < sync_context.bytes_per_frame)) {
        return 0;
    }

    const uint32_t num_channels = sync_context.current_stream_info.get_channels();
    const uint32_t bytes_per_sample = sync_context.bytes_per_frame / num_channels;

    uint8_t* last_frame =
        sync_context.decode_buffer->get_buffer_end() - sync_context.bytes_per_frame;
    uint8_t* second_last_frame = last_frame - sync_context.bytes_per_frame;
    uint8_t* spare_frame = sync_context.decode_buffer->get_buffer_end();

    // Move the original last frame into the spare slot, then blend the new frame into its old slot.
    std::memcpy(spare_frame, last_frame, sync_context.bytes_per_frame);
    for (uint32_t chan = 0; chan < num_channels; ++chan) {
        const size_t chan_offset =
            static_cast<size_t>(chan) * static_cast<size_t>(bytes_per_sample);
        const int32_t second_last_sample =
            unpack_audio_sample_to_q31(second_last_frame + chan_offset, bytes_per_sample);
        const int32_t last_sample =
            unpack_audio_sample_to_q31(last_frame + chan_offset, bytes_per_sample);
        const int32_t blended_sample = second_last_sample / 2 + last_sample / 2;
        pack_q31_as_audio_sample(blended_sample, last_frame + chan_offset, bytes_per_sample);
    }
    sync_context.decode_buffer->increase_buffer_length(sync_context.bytes_per_frame);
    return 1;
}

DecodeResult SyncTask::decode_chunk(SyncContext& sync_context) {
    if (sync_context.encoded_entry != nullptr &&
        sync_context.encoded_entry->chunk_type == CHUNK_TYPE_STREAM_CLEAR_MARKER) {
        // Reached the stream/clear marker before the inner loop noticed COMMAND_STREAM_CLEAR
        // (the marker was at the front of an otherwise-empty ring buffer). Apply the clear here.
        this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
        sync_context.encoded_entry = nullptr;
        this->apply_stream_clear(sync_context);
        return DecodeResult::SKIPPED;
    }

    if (sync_context.decode_buffer != nullptr && sync_context.decode_buffer->available() > 0) {
        // Already have decoded audio
        return DecodeResult::SUCCESS;
    }

    if ((sync_context.encoded_entry->chunk_type != CHUNK_TYPE_ENCODED_AUDIO) &&
        (sync_context.encoded_entry->chunk_type != CHUNK_TYPE_DECODED_AUDIO)) {
        // New codec header
        sync_context.decoder->reset_decoders();
        AudioStreamInfo decoded_stream_info;
        if (!sync_context.decoder->process_header(
                sync_context.encoded_entry->data(), sync_context.encoded_entry->data_size,
                sync_context.encoded_entry->chunk_type, &decoded_stream_info)) {
            SS_LOGE(TAG, "Failed to process audio codec header");
        } else {
            SS_LOGI(TAG,
                    "Processed new codec header: %s, %" PRIu32 " Hz, %" PRIu8 " ch, %" PRIu8 "-bit",
                    to_cstr(sync_context.decoder->get_current_codec()),
                    decoded_stream_info.get_sample_rate(), decoded_stream_info.get_channels(),
                    decoded_stream_info.get_bits_per_sample());
            // Update stream info from the codec header (authoritative source of stream parameters)
            if (decoded_stream_info != sync_context.current_stream_info) {
                sync_context.current_stream_info = decoded_stream_info;
                sync_context.bytes_per_frame = sync_context.current_stream_info.frames_to_bytes(1);
            }

            // Create or resize the decode buffer using the decoder's current required size
            // estimate; some codecs (for example, Opus) may require this to grow later. One extra
            // frame is reserved past the decoded data for soft-sync frame insertion.
            size_t needed =
                sync_context.decoder->get_decode_buffer_size() + sync_context.bytes_per_frame;
            if (sync_context.decode_buffer == nullptr) {
                sync_context.decode_buffer = TransferBuffer::create(
                    needed, this->player_impl_->config.decode_buffer_location);
                if (sync_context.decode_buffer == nullptr) {
                    SS_LOGE(TAG, "Failed to allocate decode buffer");
                    this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
                    sync_context.encoded_entry = nullptr;
                    return DecodeResult::ALLOCATION_FAILED;
                }
                if (this->player_impl_->listener) {
                    sync_context.decode_buffer->set_listener(this->player_impl_->listener);
                }
            } else if (needed > sync_context.decode_buffer->capacity()) {
                if (!sync_context.decode_buffer->reallocate(needed)) {
                    SS_LOGE(TAG, "Failed to reallocate decode buffer");
                    this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
                    sync_context.encoded_entry = nullptr;
                    return DecodeResult::ALLOCATION_FAILED;
                }
            }
        }
    } else if ((sync_context.decoder->get_current_codec() != SendspinCodecFormat::UNSUPPORTED) &&
               (sync_context.encoded_entry->chunk_type == CHUNK_TYPE_ENCODED_AUDIO)) {
        int64_t client_timestamp =
            this->client_->get_client_time(sync_context.encoded_entry->timestamp) -
            static_cast<int64_t>(this->player_impl_->get_effective_static_delay_ms()) * US_PER_MS -
            this->player_impl_->config.fixed_delay_us;

        if (client_timestamp < sync_context.new_audio_client_playtime - HARD_SYNC_THRESHOLD_US) {
            // This chunk will arrive too late to be played, skip it!
            this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
            sync_context.encoded_entry = nullptr;
            return DecodeResult::SKIPPED;
        }

        size_t decoded_size = 0;
        bool decoded = sync_context.decoder->decode_audio_chunk(
            sync_context.encoded_entry->data(), sync_context.encoded_entry->data_size,
            sync_context.decode_buffer->get_buffer_end(), sync_context.decode_buffer->free(),
            &decoded_size);
        if (!decoded) {
            // The decoder raises its decoded-size estimate when it meets an unusually large chunk
            // (e.g. a multi-frame Opus packet bigger than the typical 20ms buffer). Grow the
            // buffer to the new estimate (plus the reserved spare frame) and retry once.
            size_t needed =
                sync_context.decoder->get_decode_buffer_size() + sync_context.bytes_per_frame;
            if (needed > sync_context.decode_buffer->capacity() &&
                sync_context.decode_buffer->reallocate(needed)) {
                decoded = sync_context.decoder->decode_audio_chunk(
                    sync_context.encoded_entry->data(), sync_context.encoded_entry->data_size,
                    sync_context.decode_buffer->get_buffer_end(),
                    sync_context.decode_buffer->free(), &decoded_size);
            }
        }
        if (!decoded) {
            SS_LOGE(TAG, "Failed to decode audio chunk");
            this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
            sync_context.encoded_entry = nullptr;
            return DecodeResult::FAILED;
        }
        sync_context.decode_buffer->increase_buffer_length(decoded_size);
        sync_context.decoded_timestamp = client_timestamp;
    }

    // Return the encoded entry to the ring buffer
    this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
    sync_context.encoded_entry = nullptr;

    return DecodeResult::SUCCESS;
}

bool SyncTask::wait_for_codec_header(SyncContext& sync_context) {
    // Wait for a codec header to arrive in the ring buffer, discarding stale audio chunks.
    // Uses a long timeout (500ms) so the task yields CPU and barely wakes when idle.
    static const uint32_t IDLE_RECEIVE_TIMEOUT_MS = 500;

    while (
        !(this->event_flags_.get() & (COMMAND_STOP | COMMAND_STREAM_END | COMMAND_STREAM_CLEAR))) {
        auto* entry = this->encoded_ring_buffer_->receive_chunk(IDLE_RECEIVE_TIMEOUT_MS);
        if (entry == nullptr) {
            continue;  // Timed out; check flags and try again
        }
        if (entry->chunk_type != CHUNK_TYPE_ENCODED_AUDIO &&
            entry->chunk_type != CHUNK_TYPE_DECODED_AUDIO &&
            entry->chunk_type != CHUNK_TYPE_STREAM_CLEAR_MARKER) {
            // Found a codec header
            sync_context.encoded_entry = entry;
            return true;
        }
        // Stale audio data (or a leftover stream/clear marker) from a previous stream, discard it
        this->encoded_ring_buffer_->return_chunk(entry);
    }
    return false;
}

void SyncTask::drain_ring_buffer(SyncContext& sync_context) {
    // Non-blocking drain of audio data from the ring buffer, preserving codec headers.
    // If a codec header is found, it is kept in sync_context.encoded_entry so the idle
    // wait loop can process it immediately.
    while (true) {
        auto* entry = this->encoded_ring_buffer_->receive_chunk(0);
        if (entry == nullptr) {
            break;
        }
        if (entry->chunk_type != CHUNK_TYPE_ENCODED_AUDIO &&
            entry->chunk_type != CHUNK_TYPE_DECODED_AUDIO &&
            entry->chunk_type != CHUNK_TYPE_STREAM_CLEAR_MARKER) {
            // Codec header for the next stream; hold onto it
            sync_context.encoded_entry = entry;
            break;
        }
        this->encoded_ring_buffer_->return_chunk(entry);
    }
}

void SyncTask::apply_stream_clear(SyncContext& sync_context) {
    // Drop in-flight decoded audio (it carries the pre-seek timestamp; appending post-seek audio to
    // it would mis-stamp the buffer) and any pending hard-sync gap-fill silence. Codec/decoder
    // state, buffered_frames and new_audio_client_playtime are deliberately left intact: the audio
    // already handed to the sink keeps draining, and the next chunk's server timestamp lets the
    // sync logic re-align on its own. Force hard_syncing on so that re-alignment uses the tight
    // settle threshold (the post-seek timestamp jump would trigger it anyway, but this is
    // explicit). initial_decode is left as-is: if priming has not finished the caller resumes it
    // via the INITIAL_SYNC state; if it has, we must not re-prime an already-running sink.
    sync_context.silence_remaining = 0;
    sync_context.release_chunk = false;
    sync_context.hard_syncing = true;
    // Post-seek re-alignment hard syncs are expected, not a loss of sync. Leave reported_error
    // as-is so a pre-seek error still recovers to SYNCHRONIZED once we re-align.
    sync_context.aligning = true;
    if (sync_context.decode_buffer != nullptr) {
        sync_context.decode_buffer->decrease_buffer_length(sync_context.decode_buffer->available());
    }
    this->event_flags_.clear(EventGroupBits::COMMAND_STREAM_CLEAR);
}

void SyncTask::discard_to_clear_marker(SyncContext& sync_context) {
    // A stream/clear arrived: discard buffered audio up to the marker the client enqueued right
    // after signaling.
    if (sync_context.encoded_entry != nullptr) {
        bool is_marker = sync_context.encoded_entry->chunk_type == CHUNK_TYPE_STREAM_CLEAR_MARKER;
        this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
        sync_context.encoded_entry = nullptr;
        if (is_marker) {
            this->apply_stream_clear(sync_context);
            return;
        }
    }

    while (!(this->event_flags_.get() & COMMAND_STOP)) {
        auto* entry = this->encoded_ring_buffer_->receive_chunk(0);
        if (entry == nullptr) {
            break;
        }
        ChunkType type = entry->chunk_type;
        this->encoded_ring_buffer_->return_chunk(entry);
        if (type == CHUNK_TYPE_STREAM_CLEAR_MARKER) {
            break;
        }
    }
    this->apply_stream_clear(sync_context);
}

void SyncTask::reset_context(SyncContext& sync_context) {
    // Reset SyncContext between streams without deallocating buffers.
    sync_context.encoded_entry = nullptr;
    sync_context.decoded_timestamp = 0;
    sync_context.new_audio_client_playtime = 0;
    sync_context.buffered_frames = 0;
    sync_context.current_stream_info = AudioStreamInfo{};
    sync_context.bytes_per_frame = sync_context.current_stream_info.frames_to_bytes(1);
    sync_context.release_chunk = false;
    sync_context.initial_decode = true;
    sync_context.hard_syncing = true;
    sync_context.aligning = true;
    sync_context.reported_error = false;
    sync_context.silence_remaining = 0;

    // Empty the decode buffer without deallocating
    if (sync_context.decode_buffer) {
        sync_context.decode_buffer->decrease_buffer_length(sync_context.decode_buffer->available());
    }
    if (sync_context.decoder) {
        sync_context.decoder->reset_decoders();
    }
}

void SyncTask::process_playback_progress(SyncContext& sync_context) {
    PlaybackProgress playback_progress{};
    if (this->playback_progress_slot_.take(playback_progress)) {
        uint32_t frames_played = playback_progress.frames_played;

        if (sync_context.initial_decode && frames_played) {
            // First audio reached the sink. Queue the extra startup silence (replacing any unsent
            // priming silence) for decode-pipeline slack before the sink drains;
            // handle_initial_sync() drains it before the first real chunk.
            sync_context.initial_decode = false;
            sync_context.silence_remaining =
                frame_aligned_silence_bytes(sync_context.current_stream_info,
                                            this->player_impl_->config.extra_startup_silence_ms);
        }

        if (frames_played > sync_context.buffered_frames) {
            SS_LOGW(TAG,
                    "Buffered frames underflow: played %" PRIu32 " but only %" PRIu32 " buffered",
                    frames_played, sync_context.buffered_frames);
            sync_context.buffered_frames = 0;
        } else {
            sync_context.buffered_frames -= frames_played;
        }

        int64_t unplayed_us =
            sync_context.current_stream_info.frames_to_microseconds(sync_context.buffered_frames);
        sync_context.new_audio_client_playtime = playback_progress.finish_timestamp + unplayed_us;
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

void SyncTask::stop() {
    if (!this->sync_thread_.joinable()) {
        return;
    }

    this->event_flags_.set(EventGroupBits::COMMAND_STOP);
    this->sync_thread_.join();
}

// ============================================================================
// Sync task thread
// ============================================================================

void SyncTask::thread_entry(void* params) {
    SyncTask* this_task = static_cast<SyncTask*>(params);

    // Allocate SyncContext once on the task stack, reused across streams. The decode buffer is
    // created lazily once the first codec header arrives.
    SyncContext sync_context;
    sync_context.bytes_per_frame = sync_context.current_stream_info.frames_to_bytes(1);
    sync_context.decoder = std::make_unique<SendspinDecoder>();

    // === OUTER LOOP: persists for the lifetime of the client ===
    while (!(this_task->event_flags_.get() & COMMAND_STOP)) {
        // --- IDLE STATE ---
        this_task->event_flags_.clear(
            EventGroupBits::TASK_RUNNING | EventGroupBits::COMMAND_STREAM_END |
            EventGroupBits::COMMAND_STREAM_CLEAR | EventGroupBits::COMMAND_START);
        this_task->event_flags_.set(EventGroupBits::TASK_IDLE);

        this_task->reset_context(sync_context);
        this_task->playback_progress_slot_.reset();

        // Wait for a codec header to arrive in the ring buffer (yields CPU with long timeout)
        bool got_header = this_task->wait_for_codec_header(sync_context);

        if (this_task->event_flags_.get() & COMMAND_STOP) {
            break;
        }

        if (!got_header) {
            // Woke due to STREAM_END or STREAM_CLEAR during idle.
            // Only drain audio on STREAM_CLEAR; codec headers are preserved.
            if (this_task->event_flags_.get() & COMMAND_STREAM_CLEAR) {
                this_task->drain_ring_buffer(sync_context);
                // If the drain found a codec header, treat it as if we got one
                got_header = (sync_context.encoded_entry != nullptr);
            }
            if (!got_header) {
                continue;
            }
        }

        // --- WAIT FOR CLIENT TO ACKNOWLEDGE START ---
        // The sync task has a codec header and is ready to decode, but must wait for
        // the client's main loop to process any pending stream lifecycle callbacks
        // (end/clear → start) before proceeding. This prevents the task from racing
        // through idle so fast that the client never observes the idle transition.
        this_task->event_flags_.wait(EventGroupBits::COMMAND_START | EventGroupBits::COMMAND_STOP |
                                         EventGroupBits::COMMAND_STREAM_END |
                                         EventGroupBits::COMMAND_STREAM_CLEAR,
                                     false, false, UINT32_MAX);

        if (this_task->event_flags_.get() & COMMAND_STOP) {
            break;
        }

        // A new clear/end arrived while waiting; loop back to idle to process it
        if (this_task->event_flags_.get() &
            (EventGroupBits::COMMAND_STREAM_END | EventGroupBits::COMMAND_STREAM_CLEAR)) {
            if (sync_context.encoded_entry != nullptr) {
                this_task->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
                sync_context.encoded_entry = nullptr;
            }
            continue;
        }

        // --- ACTIVE STATE ---
        this_task->event_flags_.clear(EventGroupBits::TASK_IDLE | EventGroupBits::COMMAND_START);

        // Drain any stale playback progress from the previous stream's I2S callbacks
        // before setting TASK_RUNNING. The I2S hardware may still be draining its DMA
        // buffer from the old stream, and those callbacks would corrupt the new stream's
        // buffered_frames tracking.
        this_task->playback_progress_slot_.reset();

        this_task->event_flags_.set(EventGroupBits::TASK_RUNNING);

        this_task->player_impl_->enqueue_state_update(SendspinClientState::SYNCHRONIZED);

        // Decode the initial codec header
        if (sync_context.encoded_entry != nullptr) {
            this_task->decode_chunk(sync_context);
        }

        SyncTaskState sync_state = SyncTaskState::INITIAL_SYNC;

        // === INNER LOOP: state machine for active stream ===
        while (true) {
            uint32_t flags = this_task->event_flags_.get();
            if (flags & (COMMAND_STOP | COMMAND_STREAM_END)) {
                break;
            }
            if (flags & COMMAND_STREAM_CLEAR) {
                // Seek within the current stream: discard buffered audio up to the marker, keep the
                // codec/decoder and playtime accounting, and continue decoding the new audio.
                // Re-enter at INITIAL_SYNC: if priming had not finished it resumes there; otherwise
                // handle_initial_sync() falls straight through to LOAD_CHUNK on the next tick.
                this_task->discard_to_clear_marker(sync_context);
                sync_state = SyncTaskState::INITIAL_SYNC;
                continue;
            }

            this_task->process_playback_progress(sync_context);

            switch (sync_state) {
                case SyncTaskState::INITIAL_SYNC:
                    sync_state = this_task->handle_initial_sync(sync_context);
                    break;
                case SyncTaskState::LOAD_CHUNK:
                    sync_state = this_task->handle_load_chunk(sync_context);
                    break;
                case SyncTaskState::SYNCHRONIZE_AUDIO:
                    sync_state = this_task->handle_synchronize_audio(sync_context);
                    break;
                case SyncTaskState::TRANSFER_AUDIO:
                    sync_state = this_task->handle_transfer_audio(sync_context);
                    break;
            }
        }

        // Return any borrowed ring buffer entry
        if (sync_context.encoded_entry != nullptr) {
            this_task->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
            sync_context.encoded_entry = nullptr;
        }

        if (this_task->event_flags_.get() & COMMAND_STOP) {
            break;
        }

        // Don't drain the ring buffer here; the idle wait loop already discards
        // stale audio and stops at codec headers. Draining here would throw away
        // a codec header that arrived during a rapid seek (STREAM_END → STREAM_START).
    }

    this_task->event_flags_.set(EventGroupBits::TASK_STOPPED);
}

}  // namespace sendspin
