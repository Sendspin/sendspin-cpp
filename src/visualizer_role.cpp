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

#include "sendspin/visualizer_role.h"

#include "client_bridge.h"
#include "platform/event_flags.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
#include "platform/spsc_ring_buffer.h"
#include "platform/thread.h"
#include "platform/thread_safe_queue.h"
#include "platform/time.h"
#include "protocol_messages.h"

#include <cstring>
#include <thread>

static const char* const TAG = "sendspin.visualizer";

// --- Entry format constants ---

// Type tag in first byte of each ring buffer entry
static constexpr uint8_t ENTRY_BEAT = 0x00;
static constexpr uint8_t ENTRY_FRAME = 0x80;  // bit 7 distinguishes frame from beat

// Frame field flags packed into bits 0-2 of the type byte
static constexpr uint8_t FLAG_HAS_LOUDNESS = (1 << 0);
static constexpr uint8_t FLAG_HAS_F_PEAK = (1 << 1);
static constexpr uint8_t FLAG_HAS_SPECTRUM = (1 << 2);

// Entry header sizes (before the 8-byte server timestamp)
static constexpr size_t FRAME_HEADER_SIZE = 2;  // type+flags byte, bin_count byte
static constexpr size_t BEAT_HEADER_SIZE = 1;   // type byte only
static constexpr size_t TIMESTAMP_SIZE = 8;

// Event flag bits for drain thread signaling
static constexpr uint32_t COMMAND_STOP = (1 << 0);
static constexpr uint32_t COMMAND_FLUSH = (1 << 1);

static constexpr int64_t TOO_OLD_THRESHOLD_US = 20000;  // 20ms

// --- Big-endian helpers ---

static int64_t read_be64(const uint8_t* p) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | p[i];
    }
    return static_cast<int64_t>(val);
}

static uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) << 8 | static_cast<uint16_t>(p[1]);
}

namespace sendspin {

// --- Drain task pimpl ---

struct VisualizerRole::DrainTask {
    SpscRingBuffer ring_buffer;
    PlatformBuffer ring_storage;
    EventFlags event_flags;
    std::thread drain_thread;
};

struct VisualizerRole::EventState {
    ThreadSafeQueue<VisualizerRole::EventType> queue;
    ShadowSlot<ServerVisualizerStreamObject> shadow_config;
};

// --- Lifecycle ---

VisualizerRole::VisualizerRole(Config config)
    : visualizer_support_(std::move(config.support)), event_state_(std::make_unique<EventState>()) {
    this->event_state_->queue.create(8);

    if (this->visualizer_support_.has_value()) {
        this->drain_task_ = std::make_unique<DrainTask>();

        // The ring buffer needs more space than the raw data capacity because each entry
        // has internal overhead: an 8-byte ItemHeader plus our 1-2 byte entry header, all
        // aligned to 8 bytes. Allocate 3x the advertised capacity to account for this.
        size_t capacity = this->visualizer_support_->buffer_capacity * 3;
        if (this->drain_task_->ring_storage.allocate(capacity)) {
            this->drain_task_->ring_buffer.create(capacity, this->drain_task_->ring_storage.data());
        }
    }
}

VisualizerRole::~VisualizerRole() {
    this->stop_();
}

void VisualizerRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

bool VisualizerRole::start() {
    if (!this->drain_task_ || !this->drain_task_->ring_buffer.is_created()) {
        return false;
    }
    if (this->drain_task_->drain_thread.joinable()) {
        return true;  // Already running
    }
    if (!this->drain_task_->event_flags.is_created() && !this->drain_task_->event_flags.create()) {
        return false;
    }

    platform_configure_thread("SsVis", 4096, 2, false);
    this->drain_task_->drain_thread = std::thread(drain_thread_func_, this);
    return true;
}

void VisualizerRole::stop_() {
    if (!this->drain_task_ || !this->drain_task_->drain_thread.joinable()) {
        return;
    }
    this->drain_task_->event_flags.set(COMMAND_STOP);
    this->drain_task_->drain_thread.join();
}

void VisualizerRole::contribute_hello(ClientHelloMessage& msg) {
    if (this->visualizer_support_.has_value()) {
        msg.supported_roles.push_back(SendspinRole::VISUALIZER);
        msg.visualizer_support = this->visualizer_support_.value();
    }
}

// --- Binary handling (network thread) ---

void VisualizerRole::handle_binary(uint8_t binary_type, const uint8_t* data, size_t len) {
    if (!this->stream_active_ || !this->drain_task_ ||
        !this->drain_task_->ring_buffer.is_created()) {
        return;
    }

    // Build the frame flags byte from cached config
    uint8_t flags = ENTRY_FRAME;
    if (this->has_loudness_)
        flags |= FLAG_HAS_LOUDNESS;
    if (this->has_f_peak_)
        flags |= FLAG_HAS_F_PEAK;
    if (this->has_spectrum_)
        flags |= FLAG_HAS_SPECTRUM;

    if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT) {
        // Beat format: [num_beats(1)][per-beat: server_timestamp(8)]
        if (len < 1)
            return;
        uint8_t num_beats = data[0];
        size_t offset = 1;

        for (uint8_t i = 0; i < num_beats; ++i) {
            if (offset + TIMESTAMP_SIZE > len)
                break;

            // Build beat entry: [ENTRY_BEAT][8-byte server_ts]
            uint8_t entry[BEAT_HEADER_SIZE + TIMESTAMP_SIZE];
            entry[0] = ENTRY_BEAT;
            std::memcpy(entry + BEAT_HEADER_SIZE, data + offset, TIMESTAMP_SIZE);

            this->drain_task_->ring_buffer.send(entry, sizeof(entry), 0);
            offset += TIMESTAMP_SIZE;
        }
    } else {
        // Visualizer data format: [num_frames(1)][per-frame: timestamp(8) + fields...]
        if (len < 1)
            return;
        uint8_t num_frames = data[0];
        size_t offset = 1;
        size_t wire_frame_size = TIMESTAMP_SIZE + this->raw_frame_size_;
        size_t entry_size = FRAME_HEADER_SIZE + TIMESTAMP_SIZE + this->raw_frame_size_;

        for (uint8_t i = 0; i < num_frames; ++i) {
            if (offset + wire_frame_size > len)
                break;

            // Build frame entry: [flags][bin_count][8-byte server_ts][raw field bytes]
            // Use acquire+commit to avoid double-copy
            void* dest = this->drain_task_->ring_buffer.acquire(entry_size, 0);
            if (dest == nullptr)
                break;  // Buffer full, drop remaining frames

            auto* entry = static_cast<uint8_t*>(dest);
            entry[0] = flags;
            entry[1] = this->spectrum_bin_count_;
            std::memcpy(entry + FRAME_HEADER_SIZE, data + offset, wire_frame_size);

            this->drain_task_->ring_buffer.commit(dest);
            offset += wire_frame_size;
        }
    }
}

// --- Stream lifecycle (network thread) ---

void VisualizerRole::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    // Cache stream config for handle_binary (same thread)
    this->has_loudness_ = false;
    this->has_f_peak_ = false;
    this->has_spectrum_ = false;
    this->spectrum_bin_count_ = 0;

    for (auto type : stream.types) {
        if (type == VisualizerDataType::LOUDNESS)
            this->has_loudness_ = true;
        if (type == VisualizerDataType::F_PEAK)
            this->has_f_peak_ = true;
        if (type == VisualizerDataType::SPECTRUM)
            this->has_spectrum_ = true;
    }
    if (this->has_spectrum_ && stream.spectrum.has_value()) {
        this->spectrum_bin_count_ = stream.spectrum->n_disp_bins;
    }

    this->raw_frame_size_ = (this->has_loudness_ ? 2 : 0) + (this->has_f_peak_ ? 2 : 0) +
                            (this->has_spectrum_ ? 2 * this->spectrum_bin_count_ : 0);
    this->stream_active_ = true;

    // Signal drain thread to flush old data
    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    // Shadow the config for main-thread callback, then signal
    this->event_state_->shadow_config.write(stream);
    this->event_state_->queue.send(EventType::STREAM_START, 0);
}

void VisualizerRole::handle_stream_end() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.send(EventType::STREAM_END, 0);
}

void VisualizerRole::handle_stream_clear() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.send(EventType::STREAM_CLEAR, 0);
}

// --- Event draining (main thread) — lifecycle events only ---

void VisualizerRole::drain_events() {
    EventType event_type;
    while (this->event_state_->queue.receive(event_type, 0)) {
        switch (event_type) {
            case EventType::STREAM_START: {
                ServerVisualizerStreamObject config;
                if (this->event_state_->shadow_config.take(config) &&
                    this->on_visualizer_stream_start) {
                    this->on_visualizer_stream_start(config);
                }
                break;
            }
            case EventType::STREAM_END:
                if (this->on_visualizer_stream_end) {
                    this->on_visualizer_stream_end();
                }
                break;
            case EventType::STREAM_CLEAR:
                if (this->on_visualizer_stream_clear) {
                    this->on_visualizer_stream_clear();
                }
                break;
        }
    }
}

// --- Cleanup (main thread) ---

void VisualizerRole::cleanup() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.reset();
    this->event_state_->shadow_config.reset();
    this->event_state_->queue.send(EventType::STREAM_END, 0);
}

// --- Drain thread ---

void VisualizerRole::flush_ring_buffer_() {
    if (!this->drain_task_)
        return;
    size_t item_size = 0;
    void* item = nullptr;
    while ((item = this->drain_task_->ring_buffer.receive(&item_size, 0)) != nullptr) {
        this->drain_task_->ring_buffer.return_item(item);
    }
}

void VisualizerRole::drain_thread_func_(VisualizerRole* self) {
    SS_LOGD(TAG, "Drain thread started");

    auto& rb = self->drain_task_->ring_buffer;
    auto& flags = self->drain_task_->event_flags;

    while (true) {
        // Non-blocking check for commands
        uint32_t cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, 0);
        if (cmd & COMMAND_STOP)
            break;
        if (cmd & COMMAND_FLUSH) {
            self->flush_ring_buffer_();
            continue;
        }

        // Blocking receive with 50ms timeout (allows periodic command checks)
        size_t item_size = 0;
        void* item = rb.receive(&item_size, 50);
        if (item == nullptr)
            continue;

        // Wait for time sync
        if (!self->bridge_ || !self->bridge_->is_time_synced()) {
            rb.return_item(item);
            continue;
        }

        auto* raw = static_cast<const uint8_t*>(item);
        uint8_t type_byte = raw[0];
        bool is_frame = (type_byte & ENTRY_FRAME) != 0;

        // Read server timestamp
        size_t ts_offset = is_frame ? FRAME_HEADER_SIZE : BEAT_HEADER_SIZE;
        if (item_size < ts_offset + TIMESTAMP_SIZE) {
            rb.return_item(item);
            continue;
        }
        int64_t server_ts = read_be64(raw + ts_offset);
        int64_t client_ts = self->bridge_->get_client_time(server_ts);

        if (client_ts == 0) {
            rb.return_item(item);
            continue;
        }

        // Sleep until display time (interruptible via event flags)
        int64_t now = platform_time_us();
        if (client_ts > now) {
            uint32_t wait_ms = static_cast<uint32_t>((client_ts - now) / 1000);
            if (wait_ms > 0) {
                cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, wait_ms);
                if (cmd & COMMAND_STOP) {
                    rb.return_item(item);
                    break;
                }
                if (cmd & COMMAND_FLUSH) {
                    rb.return_item(item);
                    self->flush_ring_buffer_();
                    continue;
                }
            }
        }

        // Check if too old after waking
        now = platform_time_us();
        if (now - client_ts > TOO_OLD_THRESHOLD_US) {
            rb.return_item(item);
            continue;
        }

        // Parse and deliver
        if (is_frame && self->on_visualizer_frame) {
            uint8_t frame_flags = type_byte & 0x7F;
            uint8_t bin_count = raw[1];
            const uint8_t* fields = raw + FRAME_HEADER_SIZE + TIMESTAMP_SIZE;
            size_t data_len = item_size - FRAME_HEADER_SIZE - TIMESTAMP_SIZE;
            size_t offset = 0;

            VisualizerFrame frame;
            frame.timestamp = client_ts;

            if ((frame_flags & FLAG_HAS_LOUDNESS) && offset + 2 <= data_len) {
                frame.loudness = read_be16(fields + offset);
                offset += 2;
            }
            if ((frame_flags & FLAG_HAS_F_PEAK) && offset + 2 <= data_len) {
                frame.peak_freq = read_be16(fields + offset);
                offset += 2;
            }
            if ((frame_flags & FLAG_HAS_SPECTRUM) && bin_count > 0) {
                frame.spectrum.resize(bin_count);
                for (uint8_t b = 0; b < bin_count && offset + 2 <= data_len; ++b) {
                    frame.spectrum[b] = read_be16(fields + offset);
                    offset += 2;
                }
            }

            rb.return_item(item);
            self->on_visualizer_frame(frame);
        } else if (!is_frame && self->on_beat) {
            rb.return_item(item);
            self->on_beat(client_ts);
        } else {
            rb.return_item(item);
        }
    }

    SS_LOGD(TAG, "Drain thread stopped");
}

}  // namespace sendspin
