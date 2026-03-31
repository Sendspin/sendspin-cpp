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
#include "platform/logging.h"
#include "platform/thread.h"
#include "sendspin/client.h"
#include "sendspin/player_role.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace sendspin {

#define SENDSPIN_SYNC_TASK_DEBUG

// ============================================================================
// Static helpers
// ============================================================================

static const int64_t HARD_SYNC_THRESHOLD_US = 5000;
static const int64_t HARD_SYNC_SETTLE_THRESHOLD_US =
    500;  // Tighter threshold used while settling after a hard sync
static const int64_t SOFT_SYNC_THRESHOLD_US = 100;

static const uint32_t INITIAL_SYNC_ZEROS_DURATION_MS = 25;

static const size_t SYNC_TASK_STACK_SIZE = 6192;  // Opus uses more stack than FLAC
static const int SYNC_TASK_PRIORITY = 2;

static const char* const TAG = "sendspin_sync_task";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SyncTask::~SyncTask() {
    this->stop_();
}

bool SyncTask::init(PlayerRole* player, SendspinClient* client, size_t buffer_size) {
    this->player_ = player;
    this->client_ = client;

    if (!this->event_flags_.create()) {
        SS_LOGE(TAG, "Couldn't create event flags.");
        return false;
    }

    if (!this->playback_progress_queue_.create(50)) {
        SS_LOGE(TAG, "Couldn't create playback progress queue.");
        return false;
    }

    this->encoded_ring_buffer_ = SendspinAudioRingBuffer::create(buffer_size);
    if (this->encoded_ring_buffer_ == nullptr) {
        SS_LOGE(TAG, "Couldn't create encoded audio ring buffer.");
        return false;
    }

    return true;
}

bool SyncTask::start(bool task_stack_in_psram) {
    if (!this->is_initialized()) {
        SS_LOGE(TAG, "Sync task not initialized (call init() first or set audio sink)");
        return false;
    }

    if (this->sync_thread_.joinable()) {
        SS_LOGW(TAG, "Sync task thread already started");
        return false;
    }

    this->event_flags_.clear(EventGroupBits::TASK_STARTING | EventGroupBits::TASK_RUNNING |
                             EventGroupBits::TASK_STOPPING | EventGroupBits::TASK_STOPPED |
                             EventGroupBits::TASK_IDLE | EventGroupBits::COMMAND_STOP |
                             EventGroupBits::COMMAND_STREAM_END |
                             EventGroupBits::COMMAND_STREAM_CLEAR | EventGroupBits::COMMAND_START);
    this->last_run_had_error_ = false;

    platform_configure_thread("Sendspin", SYNC_TASK_STACK_SIZE, SYNC_TASK_PRIORITY,
                              task_stack_in_psram);

    this->sync_thread_ = std::thread(sync_task, this);

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
    PlaybackProgress playback_progress = {.frames_played = frames, .finish_timestamp = timestamp};
    if (!this->playback_progress_queue_.send(playback_progress, 0)) {
        SS_LOGE(TAG, "Playback info queue was full");
    }
}

// ============================================================================
// Private sync helpers
// ============================================================================

SyncTaskState SyncTask::sync_handle_initial_sync_(SyncContext& sync_context) {
    if (!sync_context.initial_decode) {
        return SyncTaskState::LOAD_CHUNK;
    }

    if (sync_context.interpolation_transfer_buffer->available() > 0) {
        const uint32_t duration_in_transfer_buffers = sync_context.current_stream_info.bytes_to_ms(
            sync_context.interpolation_transfer_buffer->available());
        size_t bytes_written = sync_context.interpolation_transfer_buffer->transfer_data_to_sink(
            duration_in_transfer_buffers / 2);
        this->sync_track_sent_audio_(sync_context, bytes_written);
        if ((bytes_written > 0) && sync_context.initial_decode) {
            // Sent initial zeros, delay slightly to give it some time to work through the audio
            // stack
            std::this_thread::sleep_for(std::chrono::milliseconds(
                sync_context.current_stream_info.bytes_to_ms(bytes_written) / 2));
        }
    } else {
        const size_t zeroed_bytes = sync_context.interpolation_transfer_buffer->free();
        std::memset((void*)sync_context.interpolation_transfer_buffer->get_buffer_end(), 0,
                    zeroed_bytes);
        sync_context.interpolation_transfer_buffer->increase_buffer_length(
            std::min(zeroed_bytes,
                     sync_context.current_stream_info.ms_to_bytes(INITIAL_SYNC_ZEROS_DURATION_MS)));
    }

    return SyncTaskState::INITIAL_SYNC;
}

SyncTaskState SyncTask::sync_handle_load_chunk_(SyncContext& sync_context) {
    if (!this->client_->is_time_synced()) {
        // Wait for the time filter to receive its first measurement before processing audio chunks.
        // Without a valid time offset, server timestamps can't be correctly converted to client
        // timestamps.
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        return SyncTaskState::LOAD_CHUNK;
    }
    if (!this->sync_load_next_chunk_(sync_context)) {
        return SyncTaskState::LOAD_CHUNK;
    }
    DecodeResult decode_result = this->sync_decode_audio_(sync_context);
    if ((decode_result == DecodeResult::SKIPPED) || (decode_result == DecodeResult::FAILED)) {
        return SyncTaskState::LOAD_CHUNK;
    } else if (decode_result == DecodeResult::ALLOCATION_FAILED) {
        this->event_flags_.set(EventGroupBits::TASK_ERROR | EventGroupBits::COMMAND_STOP);
        return SyncTaskState::LOAD_CHUNK;
    }
    if (sync_context.decode_buffer == nullptr || sync_context.decode_buffer->available() == 0) {
        // No decoded audio available yet, try again (probably just processed a header)
        return SyncTaskState::LOAD_CHUNK;
    }
    return SyncTaskState::SYNCHRONIZE_AUDIO;
}

SyncTaskState SyncTask::sync_handle_synchronize_audio_(SyncContext& sync_context) {
    // Predicted error: positive means chunk should play later than our current buffer endpoint
    int64_t raw_error = sync_context.decoded_timestamp - sync_context.new_audio_client_playtime;

    // Use tighter threshold while settling after a hard sync (or during initial sync) to ensure
    // precise alignment. The normal threshold detects when hard sync is needed; the settle
    // threshold keeps hard-syncing until well-aligned.
    const int64_t active_threshold =
        sync_context.hard_syncing ? HARD_SYNC_SETTLE_THRESHOLD_US : HARD_SYNC_THRESHOLD_US;

    if (raw_error > active_threshold) {
        // Buffer will run out before this chunk is supposed to play - insert silence to fill the
        // gap
        sync_context.hard_syncing = true;

        // Clear any stale interpolation data
        sync_context.interpolation_transfer_buffer->decrease_buffer_length(
            sync_context.interpolation_transfer_buffer->available());

        // Compute silence directly in frames from microseconds (avoids ms truncation)
        uint32_t silence_frames = (static_cast<uint64_t>(raw_error) *
                                   sync_context.current_stream_info.get_sample_rate()) /
                                  1000000;
        size_t silence_bytes = sync_context.current_stream_info.frames_to_bytes(silence_frames);

        // Cap at buffer capacity
        const size_t buffer_free = sync_context.interpolation_transfer_buffer->free();
        size_t actual_bytes = std::min(silence_bytes, buffer_free);

        std::memset((void*)sync_context.interpolation_transfer_buffer->get_buffer_end(), 0,
                    actual_bytes);
        sync_context.interpolation_transfer_buffer->increase_buffer_length(actual_bytes);

        // Playtime estimate is advanced by sync_transfer_audio_() when the silence is actually sent
        sync_context.release_chunk = false;  // Keep decoded audio for after the silence

#ifdef SENDSPIN_SYNC_TASK_DEBUG
        uint32_t frames_added = sync_context.current_stream_info.bytes_to_frames(actual_bytes);
        SS_LOGD(TAG,
                "Hard sync: adding %" PRIu32 " frames of silence for %" PRId64 "us future error",
                frames_added, raw_error);
#endif
    } else if (raw_error < -active_threshold) {
        // Chunk should have played already - we're behind, drop it
        // The skip logic in sync_decode_audio_ will keep dropping until we catch up
        sync_context.hard_syncing = true;
        sync_context.decode_buffer->decrease_buffer_length(sync_context.decode_buffer->available());
#ifdef SENDSPIN_SYNC_TASK_DEBUG
        SS_LOGD(TAG, "Hard sync: dropping decoded chunk, %" PRId64 "us behind", -raw_error);
#endif
        return SyncTaskState::LOAD_CHUNK;
    } else {
        // Within tolerance - exit hard sync mode and use sample insertion/deletion for fine
        // corrections
        sync_context.hard_syncing = false;

        if (raw_error > SOFT_SYNC_THRESHOLD_US) {
            // Slightly behind - add one interpolated frame between the first two decoded frames
            // Playtime estimate is advanced by sync_transfer_audio_() when the extra frame is sent
            this->sync_soft_sync_add_audio_(sync_context);
        } else if (raw_error < -SOFT_SYNC_THRESHOLD_US) {
            // Slightly ahead - remove last frame, blend into second-to-last
            // Playtime estimate naturally reflects the removed frame: sync_transfer_audio_() sends
            // fewer bytes
            this->sync_soft_sync_remove_audio_(sync_context);
        }
        // else: Dead zone - pass decoded audio through directly
        sync_context.release_chunk = true;
    }
    return SyncTaskState::TRANSFER_AUDIO;
}

SyncTaskState SyncTask::sync_handle_transfer_audio_(SyncContext& sync_context) {
    if (!this->sync_transfer_audio_(sync_context)) {
        return SyncTaskState::TRANSFER_AUDIO;  // Not done transferring yet
    }
    if (sync_context.decode_buffer != nullptr && sync_context.decode_buffer->available() > 0) {
        // Decoded audio still waiting (was held back while silence was sent) - re-sync it
        return SyncTaskState::SYNCHRONIZE_AUDIO;
    }
    return SyncTaskState::LOAD_CHUNK;
}

void SyncTask::sync_track_sent_audio_(SyncContext& sync_context, size_t bytes_sent) {
    uint32_t frames_sent = sync_context.current_stream_info.bytes_to_frames(bytes_sent);
    sync_context.buffered_frames += frames_sent;
    uint32_t remainder = frames_sent;
    int64_t ms = sync_context.current_stream_info.frames_to_milliseconds_with_remainder(&remainder);
    sync_context.new_audio_client_playtime +=
        1000LL * ms +
        static_cast<int64_t>(sync_context.current_stream_info.frames_to_microseconds(remainder));
}

bool SyncTask::sync_transfer_audio_(SyncContext& sync_context) {
    size_t decode_available =
        sync_context.release_chunk ? sync_context.decode_buffer->available() : 0;
    const uint32_t duration_in_transfer_buffers = sync_context.current_stream_info.bytes_to_ms(
        decode_available + sync_context.interpolation_transfer_buffer->available());

    size_t bytes_written = sync_context.interpolation_transfer_buffer->transfer_data_to_sink(
        duration_in_transfer_buffers / 2);
    this->sync_track_sent_audio_(sync_context, bytes_written);

    if ((bytes_written > 0) && sync_context.initial_decode) {
        // Sent initial zeros, delay slightly to give it some time to work through the audio stack
        std::this_thread::sleep_for(std::chrono::milliseconds(
            sync_context.current_stream_info.bytes_to_ms(bytes_written) / 2));
    }

    if (sync_context.interpolation_transfer_buffer->available() == 0 &&
        sync_context.release_chunk) {
        // No interpolation bytes available, send main audio data
        size_t decode_bytes_written =
            sync_context.decode_buffer->transfer_data_to_sink(3 * duration_in_transfer_buffers / 2);
        this->sync_track_sent_audio_(sync_context, decode_bytes_written);
    }

    // When decode buffer fully consumed and released, mark done
    if (sync_context.decode_buffer->available() == 0 && sync_context.release_chunk) {
        sync_context.release_chunk = false;
    }

    // Keep transferring if there's still data to send
    if (sync_context.interpolation_transfer_buffer->available() > 0) {
        return false;
    }
    if (sync_context.release_chunk && sync_context.decode_buffer->available() > 0) {
        return false;
    }

    return true;
}

bool SyncTask::sync_load_next_chunk_(SyncContext& sync_context) {
    if (sync_context.encoded_entry == nullptr) {
        sync_context.encoded_entry = this->encoded_ring_buffer_->receive_chunk(15);
        if (sync_context.encoded_entry == nullptr) {
            // No chunk available to process
            return false;
        }
    }

    return true;
}

int32_t SyncTask::sync_soft_sync_remove_audio_(SyncContext& sync_context) {
    // Small sync adjustment after getting slightly ahead.
    // Removes the last frame in the chunk to get in sync. The second to last frame is replaced with
    // the average of it and the removed frame to minimize audible glitches.

    const uint32_t num_channels = sync_context.current_stream_info.get_channels();
    const uint32_t bytes_per_sample = sync_context.bytes_per_frame / num_channels;

    if (sync_context.decode_buffer->available() >= 2 * sync_context.bytes_per_frame) {
        for (uint32_t chan = 0; chan < num_channels; ++chan) {
            const int32_t first_sample = unpack_audio_sample_to_q31(
                sync_context.decode_buffer->get_buffer_end() - 2 * sync_context.bytes_per_frame +
                    chan * bytes_per_sample,
                bytes_per_sample);
            const int32_t second_sample = unpack_audio_sample_to_q31(
                sync_context.decode_buffer->get_buffer_end() - sync_context.bytes_per_frame +
                    chan * bytes_per_sample,
                bytes_per_sample);
            int32_t replacement_sample = first_sample / 2 + second_sample / 2;
            pack_q31_as_audio_sample(replacement_sample,
                                     sync_context.decode_buffer->get_buffer_end() -
                                         2 * sync_context.bytes_per_frame + chan * bytes_per_sample,
                                     bytes_per_sample);
        }

        sync_context.decode_buffer->decrease_buffer_length(sync_context.bytes_per_frame);
        return -1;
    }
    return 0;
}

int32_t SyncTask::sync_soft_sync_add_audio_(SyncContext& sync_context) {
    // Small sync adjustment after getting slightly behind.
    // Adds one new frame to get in sync. The new frame is inserted between the first and second
    // frames. The new frame is the average of the first two frames in the chunk to minimize audible
    // glitches.

    if ((sync_context.interpolation_transfer_buffer->free() >= sync_context.bytes_per_frame) &&
        (sync_context.decode_buffer->available() >= 2 * sync_context.bytes_per_frame)) {
        const uint32_t num_channels = sync_context.current_stream_info.get_channels();
        const uint32_t bytes_per_sample = sync_context.bytes_per_frame / num_channels;

        for (uint32_t chan = 0; chan < num_channels; ++chan) {
            const int32_t first_sample = unpack_audio_sample_to_q31(
                sync_context.decode_buffer->get_buffer_start() + chan * bytes_per_sample,
                bytes_per_sample);
            const int32_t second_sample = unpack_audio_sample_to_q31(
                sync_context.decode_buffer->get_buffer_start() + chan * bytes_per_sample +
                    sync_context.bytes_per_frame,
                bytes_per_sample);
            int32_t new_sample = first_sample / 2 + second_sample / 2;
            pack_q31_as_audio_sample(
                new_sample,
                sync_context.decode_buffer->get_buffer_start() + chan * bytes_per_sample,
                bytes_per_sample);
            pack_q31_as_audio_sample(
                first_sample,
                sync_context.interpolation_transfer_buffer->get_buffer_start() +
                    chan * bytes_per_sample,
                bytes_per_sample);
        }
        sync_context.interpolation_transfer_buffer->increase_buffer_length(
            sync_context.bytes_per_frame);
        return 1;
    }
    return 0;
}

DecodeResult SyncTask::sync_decode_audio_(SyncContext& sync_context) {
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
            SS_LOGI(TAG, "Processed new codec header");
            // Update stream info from the codec header (authoritative source of stream parameters)
            if (decoded_stream_info != sync_context.current_stream_info) {
                sync_context.current_stream_info = decoded_stream_info;
                sync_context.bytes_per_frame = sync_context.current_stream_info.frames_to_bytes(1);

                // Resize interpolation buffer if needed for the actual stream parameters
                size_t needed_interp_size =
                    sync_context.current_stream_info.ms_to_bytes(INITIAL_SYNC_ZEROS_DURATION_MS);
                if (sync_context.interpolation_transfer_buffer != nullptr &&
                    needed_interp_size > sync_context.interpolation_transfer_buffer->capacity()) {
                    if (!sync_context.interpolation_transfer_buffer->reallocate(
                            needed_interp_size)) {
                        SS_LOGW(TAG, "Failed to resize interpolation buffer for new stream info");
                    }
                }
            }

            // Create or resize the decode buffer now that we know the maximum decoded size
            size_t needed = sync_context.decoder->get_maximum_decoded_size();
            if (sync_context.decode_buffer == nullptr) {
                sync_context.decode_buffer = TransferBuffer::create(needed);
                if (sync_context.decode_buffer == nullptr) {
                    SS_LOGE(TAG, "Failed to allocate decode buffer");
                    this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
                    sync_context.encoded_entry = nullptr;
                    return DecodeResult::ALLOCATION_FAILED;
                }
                if (this->player_->listener_) {
                    sync_context.decode_buffer->set_listener(this->player_->listener_);
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
            static_cast<int64_t>(this->player_->get_static_delay_ms()) * 1000 -
            this->player_->get_fixed_delay_us();

        if (client_timestamp < sync_context.new_audio_client_playtime - HARD_SYNC_THRESHOLD_US) {
            // This chunk will arrive too late to be played, skip it!
            this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
            sync_context.encoded_entry = nullptr;
            return DecodeResult::SKIPPED;
        }

        size_t decoded_size = 0;
        if (!sync_context.decoder->decode_audio_chunk(
                sync_context.encoded_entry->data(), sync_context.encoded_entry->data_size,
                sync_context.decode_buffer->get_buffer_end(), sync_context.decode_buffer->free(),
                &decoded_size)) {
            SS_LOGE(TAG, "Failed to decode audio chunk");
            this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
            sync_context.encoded_entry = nullptr;
            return DecodeResult::FAILED;
        } else {
            sync_context.decode_buffer->increase_buffer_length(decoded_size);
            sync_context.decoded_timestamp = client_timestamp;
        }
    }

    // Return the encoded entry to the ring buffer
    this->encoded_ring_buffer_->return_chunk(sync_context.encoded_entry);
    sync_context.encoded_entry = nullptr;

    return DecodeResult::SUCCESS;
}

bool SyncTask::sync_idle_wait_for_header_(SyncContext& sync_context) {
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
            entry->chunk_type != CHUNK_TYPE_DECODED_AUDIO) {
            // Found a codec header
            sync_context.encoded_entry = entry;
            return true;
        }
        // Stale audio data from a previous stream, discard it
        this->encoded_ring_buffer_->return_chunk(entry);
    }
    return false;
}

void SyncTask::sync_drain_ring_buffer_(SyncContext& sync_context) {
    // Non-blocking drain of audio data from the ring buffer, preserving codec headers.
    // If a codec header is found, it is kept in sync_context.encoded_entry so the idle
    // wait loop can process it immediately.
    while (true) {
        auto* entry = this->encoded_ring_buffer_->receive_chunk(0);
        if (entry == nullptr) {
            break;
        }
        if (entry->chunk_type != CHUNK_TYPE_ENCODED_AUDIO &&
            entry->chunk_type != CHUNK_TYPE_DECODED_AUDIO) {
            // Codec header for the next stream; hold onto it
            sync_context.encoded_entry = entry;
            break;
        }
        this->encoded_ring_buffer_->return_chunk(entry);
    }
}

void SyncTask::sync_reset_context_(SyncContext& sync_context) {
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

    // Empty buffers without deallocating
    if (sync_context.decode_buffer) {
        sync_context.decode_buffer->decrease_buffer_length(sync_context.decode_buffer->available());
    }
    if (sync_context.interpolation_transfer_buffer) {
        sync_context.interpolation_transfer_buffer->decrease_buffer_length(
            sync_context.interpolation_transfer_buffer->available());
    }
    if (sync_context.decoder) {
        sync_context.decoder->reset_decoders();
    }
}

void SyncTask::sync_process_playback_progress_(SyncContext& sync_context) {
    PlaybackProgress playback_progress;
    bool received = false;
    while (this->playback_progress_queue_.receive(playback_progress, 0)) {
        received = true;
        uint32_t frames_played = playback_progress.frames_played;

        if (sync_context.initial_decode && frames_played) {
            sync_context.initial_decode = false;
        }

        if (frames_played > sync_context.buffered_frames) {
#ifdef SENDSPIN_SYNC_TASK_DEBUG
            SS_LOGW(TAG,
                    "Buffered frames underflow: played %" PRIu32 " but only %" PRIu32 " buffered",
                    frames_played, sync_context.buffered_frames);
#endif
            sync_context.buffered_frames = 0;
        } else {
            sync_context.buffered_frames -= frames_played;
        }
    }
    if (received) {
        uint32_t unplayed_frames = sync_context.buffered_frames;
        int64_t unplayed_ms =
            sync_context.current_stream_info.frames_to_milliseconds_with_remainder(
                &unplayed_frames);
        int64_t unplayed_us =
            1000LL * unplayed_ms +
            static_cast<int64_t>(
                sync_context.current_stream_info.frames_to_microseconds(unplayed_frames));
        sync_context.new_audio_client_playtime = playback_progress.finish_timestamp + unplayed_us;
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

void SyncTask::stop_() {
    if (!this->sync_thread_.joinable()) {
        return;
    }

    this->event_flags_.set(EventGroupBits::COMMAND_STOP);
    this->sync_thread_.join();
}

// ============================================================================
// Sync task thread
// ============================================================================

void SyncTask::sync_task(void* params) {
    SyncTask* this_task = static_cast<SyncTask*>(params);

    this_task->event_flags_.set(EventGroupBits::TASK_STARTING);

    // Allocate SyncContext once on the task stack, reused across streams.
    SyncContext sync_context;
    sync_context.bytes_per_frame = sync_context.current_stream_info.frames_to_bytes(1);

    sync_context.interpolation_transfer_buffer = TransferBuffer::create(
        sync_context.current_stream_info.ms_to_bytes(INITIAL_SYNC_ZEROS_DURATION_MS));
    if (sync_context.interpolation_transfer_buffer == nullptr) {
        SS_LOGE(TAG, "Failed to allocate interpolation transfer buffer");
        this_task->event_flags_.set(EventGroupBits::TASK_ERROR | EventGroupBits::TASK_STOPPED);
        return;
    }

    if (this_task->player_->listener_) {
        sync_context.interpolation_transfer_buffer->set_listener(this_task->player_->listener_);
    }
    sync_context.decoder = std::make_unique<SendspinDecoder>();

    // === OUTER LOOP: persists for the lifetime of the client ===
    while (!(this_task->event_flags_.get() & COMMAND_STOP)) {
        // --- IDLE STATE ---
        this_task->event_flags_.clear(EventGroupBits::TASK_RUNNING | EventGroupBits::TASK_STOPPING |
                                      EventGroupBits::COMMAND_STREAM_END |
                                      EventGroupBits::COMMAND_STREAM_CLEAR |
                                      EventGroupBits::COMMAND_START);
        this_task->event_flags_.set(EventGroupBits::TASK_IDLE);

        this_task->sync_reset_context_(sync_context);
        this_task->playback_progress_queue_.reset();

        // Wait for a codec header to arrive in the ring buffer (yields CPU with long timeout)
        bool got_header = this_task->sync_idle_wait_for_header_(sync_context);

        if (this_task->event_flags_.get() & COMMAND_STOP) {
            break;
        }

        if (!got_header) {
            // Woke due to STREAM_END or STREAM_CLEAR during idle.
            // Only drain audio on STREAM_CLEAR; codec headers are preserved.
            if (this_task->event_flags_.get() & COMMAND_STREAM_CLEAR) {
                this_task->sync_drain_ring_buffer_(sync_context);
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
        this_task->playback_progress_queue_.reset();

        this_task->event_flags_.set(EventGroupBits::TASK_RUNNING);

        this_task->player_->enqueue_state_update_(SendspinClientState::SYNCHRONIZED);

        // Decode the initial codec header
        if (sync_context.encoded_entry != nullptr) {
            this_task->sync_decode_audio_(sync_context);
        }

        SyncTaskState sync_state = SyncTaskState::INITIAL_SYNC;

        // === INNER LOOP: state machine for active stream ===
        while (true) {
            uint32_t flags = this_task->event_flags_.get();
            if (flags & (COMMAND_STOP | COMMAND_STREAM_END | COMMAND_STREAM_CLEAR)) {
                break;
            }

            this_task->sync_process_playback_progress_(sync_context);

            switch (sync_state) {
                case SyncTaskState::INITIAL_SYNC:
                    sync_state = this_task->sync_handle_initial_sync_(sync_context);
                    break;
                case SyncTaskState::LOAD_CHUNK:
                    sync_state = this_task->sync_handle_load_chunk_(sync_context);
                    break;
                case SyncTaskState::SYNCHRONIZE_AUDIO:
                    sync_state = this_task->sync_handle_synchronize_audio_(sync_context);
                    break;
                case SyncTaskState::TRANSFER_AUDIO:
                    sync_state = this_task->sync_handle_transfer_audio_(sync_context);
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

        this_task->event_flags_.set(EventGroupBits::TASK_STOPPING);

        // Check if the stream ended with an error
        this_task->last_run_had_error_ =
            (this_task->event_flags_.get() & EventGroupBits::TASK_ERROR) != 0;

        // Don't drain the ring buffer here; the idle wait loop already discards
        // stale audio and stops at codec headers. Draining here would throw away
        // a codec header that arrived during a rapid seek (STREAM_END → STREAM_START).
    }

    this_task->event_flags_.set(EventGroupBits::TASK_STOPPED);
}

}  // namespace sendspin
