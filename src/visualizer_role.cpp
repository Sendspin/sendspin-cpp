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
#include "platform/memory.h"
#include "platform/spsc_ring_buffer.h"
#include "platform/time.h"
#include "protocol_messages.h"

#include <mutex>

static constexpr size_t BEAT_BUFFER_SIZE = 1024;
static constexpr int64_t TOO_OLD_THRESHOLD_US = 30000;  // 20ms

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

// --- Ring buffer pimpl ---

struct VisualizerRole::RingBuffers {
    SpscRingBuffer frame_rb;
    PlatformBuffer frame_storage;
    SpscRingBuffer beat_rb;
    PlatformBuffer beat_storage;
};

// --- Lifecycle ---

VisualizerRole::VisualizerRole(Config config) : visualizer_support_(std::move(config.support)) {
    if (this->visualizer_support_.has_value()) {
        this->ring_buffers_ = std::make_unique<RingBuffers>();

        size_t frame_capacity = this->visualizer_support_->buffer_capacity;
        if (this->ring_buffers_->frame_storage.allocate(frame_capacity)) {
            this->ring_buffers_->frame_rb.create(frame_capacity,
                                                 this->ring_buffers_->frame_storage.data());
        }

        if (this->ring_buffers_->beat_storage.allocate(BEAT_BUFFER_SIZE)) {
            this->ring_buffers_->beat_rb.create(BEAT_BUFFER_SIZE,
                                                this->ring_buffers_->beat_storage.data());
        }
    }
}

VisualizerRole::~VisualizerRole() = default;

void VisualizerRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

void VisualizerRole::contribute_hello(ClientHelloMessage& msg) {
    if (this->visualizer_support_.has_value()) {
        msg.supported_roles.push_back(SendspinRole::VISUALIZER);
        msg.visualizer_support = this->visualizer_support_.value();
    }
}

// --- Binary handling (network thread) ---

void VisualizerRole::handle_binary(uint8_t binary_type, const uint8_t* data, size_t len) {
    if (!this->stream_active_ || !this->ring_buffers_ ||
        !this->ring_buffers_->frame_rb.is_created() || !this->ring_buffers_->beat_rb.is_created()) {
        return;
    }

    if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT) {
        // Beat format: [num_beats(1)][per-beat: server_timestamp(8)]
        if (len < 1)
            return;
        uint8_t num_beats = data[0];
        size_t offset = 1;

        for (uint8_t i = 0; i < num_beats; ++i) {
            if (offset + 8 > len)
                break;
            this->ring_buffers_->beat_rb.send(data + offset, 8, 0);
            offset += 8;
        }
    } else {
        // Visualizer data format: [num_frames(1)][per-frame: timestamp(8) + fields...]
        if (len < 1)
            return;
        uint8_t num_frames = data[0];
        size_t offset = 1;
        size_t entry_size = 8 + this->raw_frame_size_;

        for (uint8_t i = 0; i < num_frames; ++i) {
            if (offset + entry_size > len)
                break;
            this->ring_buffers_->frame_rb.send(data + offset, entry_size, 0);
            offset += entry_size;
        }
    }
}

// --- Stream lifecycle (network thread) ---

void VisualizerRole::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);

    // Cache stream config for binary parsing (same thread as handle_binary)
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

    // Enqueue the stream_start event for main-thread delivery
    Event event;
    event.type = EventType::STREAM_START;
    event.visualizer_stream = stream;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::handle_stream_end() {
    this->stream_active_ = false;

    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    Event event;
    event.type = EventType::STREAM_END;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::handle_stream_clear() {
    this->stream_active_ = false;

    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    Event event;
    event.type = EventType::STREAM_CLEAR;
    this->pending_events_.push_back(std::move(event));
}

// --- Event draining (main thread) ---

void VisualizerRole::drain_events(std::vector<Event>& events) {
    // Process lifecycle events first
    for (auto& event : events) {
        switch (event.type) {
            case EventType::STREAM_START:
                this->flush_ring_buffers_();
                if (event.visualizer_stream.has_value() && this->on_visualizer_stream_start) {
                    this->on_visualizer_stream_start(event.visualizer_stream.value());
                }
                break;
            case EventType::STREAM_END:
                this->flush_ring_buffers_();
                if (this->on_visualizer_stream_end) {
                    this->on_visualizer_stream_end();
                }
                break;
            case EventType::STREAM_CLEAR:
                this->flush_ring_buffers_();
                if (this->on_visualizer_stream_clear) {
                    this->on_visualizer_stream_clear();
                }
                break;
        }
    }

    // Drain ring buffers with timestamp-gated release
    if (!this->ring_buffers_ || !this->ring_buffers_->frame_rb.is_created() || !this->bridge_ ||
        !this->bridge_->is_time_synced()) {
        return;
    }

    int64_t now = platform_time_us();

    // Drain visualizer frames
    if (this->on_visualizer_frame) {
        while (true) {
            void* item;
            size_t item_size;

            if (this->pending_frame_ != nullptr) {
                item = this->pending_frame_;
                item_size = this->pending_frame_size_;
                this->pending_frame_ = nullptr;
                this->pending_frame_size_ = 0;
            } else {
                item = this->ring_buffers_->frame_rb.receive(&item_size, 0);
                if (item == nullptr)
                    break;
            }

            auto* raw = static_cast<const uint8_t*>(item);
            int64_t server_ts = read_be64(raw);
            int64_t client_ts = this->bridge_->get_client_time(server_ts);

            if (client_ts == 0) {
                // Time sync lost — stash and stop
                this->pending_frame_ = item;
                this->pending_frame_size_ = item_size;
                break;
            }

            if (client_ts > now) {
                // Future frame — stash for next drain cycle
                this->pending_frame_ = item;
                this->pending_frame_size_ = item_size;
                break;
            }

            if (now - client_ts > TOO_OLD_THRESHOLD_US) {
                // Too old, drop
                this->ring_buffers_->frame_rb.return_item(item);
                continue;
            }

            // Parse the frame fields after the 8-byte timestamp
            VisualizerFrame frame;
            frame.timestamp = client_ts;
            const uint8_t* fields = raw + 8;
            size_t data_len = item_size - 8;
            size_t offset = 0;

            if (this->has_loudness_ && offset + 2 <= data_len) {
                frame.loudness = read_be16(fields + offset);
                offset += 2;
            }
            if (this->has_f_peak_ && offset + 2 <= data_len) {
                frame.peak_freq = read_be16(fields + offset);
                offset += 2;
            }
            if (this->has_spectrum_ && this->spectrum_bin_count_ > 0) {
                frame.spectrum.resize(this->spectrum_bin_count_);
                for (uint8_t b = 0; b < this->spectrum_bin_count_ && offset + 2 <= data_len; ++b) {
                    frame.spectrum[b] = read_be16(fields + offset);
                    offset += 2;
                }
            }

            this->ring_buffers_->frame_rb.return_item(item);
            this->on_visualizer_frame(frame);
        }
    }

    // Drain beat events
    if (this->on_beat) {
        while (true) {
            void* item;
            size_t item_size;

            if (this->pending_beat_ != nullptr) {
                item = this->pending_beat_;
                item_size = this->pending_beat_size_;
                this->pending_beat_ = nullptr;
                this->pending_beat_size_ = 0;
            } else {
                item = this->ring_buffers_->beat_rb.receive(&item_size, 0);
                if (item == nullptr)
                    break;
            }

            auto* raw = static_cast<const uint8_t*>(item);
            int64_t server_ts = read_be64(raw);
            int64_t client_ts = this->bridge_->get_client_time(server_ts);

            if (client_ts == 0) {
                this->pending_beat_ = item;
                this->pending_beat_size_ = item_size;
                break;
            }

            if (client_ts > now) {
                this->pending_beat_ = item;
                this->pending_beat_size_ = item_size;
                break;
            }

            if (now - client_ts > TOO_OLD_THRESHOLD_US) {
                this->ring_buffers_->beat_rb.return_item(item);
                continue;
            }

            this->ring_buffers_->beat_rb.return_item(item);
            this->on_beat(client_ts);
        }
    }
}

// --- Cleanup ---

void VisualizerRole::cleanup() {
    this->stream_active_ = false;
    this->flush_ring_buffers_();

    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_events_.clear();

    Event event;
    event.type = EventType::STREAM_END;
    this->pending_events_.push_back(std::move(event));
}

void VisualizerRole::flush_ring_buffers_() {
    if (!this->ring_buffers_)
        return;

    // Return any pending (checked-out) items first
    if (this->pending_frame_ != nullptr) {
        this->ring_buffers_->frame_rb.return_item(this->pending_frame_);
        this->pending_frame_ = nullptr;
        this->pending_frame_size_ = 0;
    }
    if (this->pending_beat_ != nullptr) {
        this->ring_buffers_->beat_rb.return_item(this->pending_beat_);
        this->pending_beat_ = nullptr;
        this->pending_beat_size_ = 0;
    }

    // Drain remaining items
    size_t item_size = 0;
    void* item = nullptr;
    while ((item = this->ring_buffers_->frame_rb.receive(&item_size, 0)) != nullptr) {
        this->ring_buffers_->frame_rb.return_item(item);
    }
    while ((item = this->ring_buffers_->beat_rb.receive(&item_size, 0)) != nullptr) {
        this->ring_buffers_->beat_rb.return_item(item);
    }
}

}  // namespace sendspin
