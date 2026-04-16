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

#include "constants.h"
#include "platform/logging.h"
#include "platform/thread.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "visualizer_role_impl.h"

#include <cstring>

static const char* const TAG = "sendspin.visualizer";

// ============================================================================
// Entry format constants
// ============================================================================

// Type tag in first byte of each ring buffer entry
static constexpr uint8_t ENTRY_BEAT = 0x00;
static constexpr uint8_t ENTRY_FRAME = 0x80;  // bit 7 distinguishes frame from beat

// Frame field flags packed into bits 0-2 of the type byte
static constexpr uint8_t FLAG_HAS_LOUDNESS = (1 << 0);
static constexpr uint8_t FLAG_HAS_F_PEAK = (1 << 1);
static constexpr uint8_t FLAG_HAS_SPECTRUM = (1 << 2);

/// @brief Mask to extract the flags portion (bits 0-6) from a frame type byte
static constexpr uint8_t FRAME_FLAGS_MASK = 0x7FU;

// Entry header sizes (before the 8-byte server timestamp)
static constexpr size_t FRAME_HEADER_SIZE = 2;  // type+flags byte, bin_count byte
static constexpr size_t BEAT_HEADER_SIZE = 1;   // type byte only
static constexpr size_t TIMESTAMP_SIZE = 8;

// Event flag bits for drain thread signaling
static constexpr uint32_t COMMAND_STOP = (1 << 0);
static constexpr uint32_t COMMAND_FLUSH = (1 << 1);

/// @brief Timeout for blocking ring buffer receive in drain thread (allows periodic command checks)
static constexpr uint32_t DRAIN_RECEIVE_TIMEOUT_MS = 50U;

static constexpr int64_t TOO_OLD_THRESHOLD_US = 20000;  // 20ms

// ============================================================================
// Big-endian helpers
// ============================================================================

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

// ============================================================================
// Impl constructor / destructor
// ============================================================================

VisualizerRole::Impl::Impl(VisualizerRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      visualizer_support(std::move(this->config.support)),
      client(client),
      event_state(std::make_unique<EventState>()) {
    this->event_state->queue.create(8);

    if (this->visualizer_support.has_value()) {
        this->drain_task = std::make_unique<DrainTask>();

        // The ring buffer needs more space than the raw data capacity because each entry
        // has internal overhead: an 8-byte ItemHeader plus our 1-2 byte entry header, all
        // aligned to 8 bytes. Allocate 3x the advertised capacity to account for this.
        size_t capacity = this->visualizer_support->buffer_capacity * 3;
        if (this->drain_task->ring_storage.allocate(capacity)) {
            this->drain_task->ring_buffer.create(capacity, this->drain_task->ring_storage.data());
        }
    }
}

VisualizerRole::Impl::~Impl() {
    this->stop();
}

// ============================================================================
// VisualizerRole forwarding (public API → Impl)
// ============================================================================

VisualizerRole::VisualizerRole(VisualizerRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(std::move(config), client)) {}

VisualizerRole::~VisualizerRole() = default;

void VisualizerRole::set_listener(VisualizerRoleListener* listener) {
    this->impl_->listener = listener;
}

// ============================================================================
// Impl method implementations
// ============================================================================

bool VisualizerRole::Impl::start() {
    if (!this->drain_task || !this->drain_task->ring_buffer.is_created()) {
        SS_LOGE(TAG, "Failed to start visualizer: drain task not initialized");
        return false;
    }
    if (this->drain_task->drain_thread.joinable()) {
        return true;  // Already running
    }
    if (!this->drain_task->event_flags.is_created() && !this->drain_task->event_flags.create()) {
        SS_LOGE(TAG, "Failed to create visualizer event flags");
        return false;
    }

    platform_configure_thread("SsVis", 4096, static_cast<int>(this->config.priority),
                              this->config.psram_stack);
    this->drain_task->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

void VisualizerRole::Impl::stop() const {
    if (!this->drain_task || !this->drain_task->drain_thread.joinable()) {
        return;
    }
    this->drain_task->event_flags.set(COMMAND_STOP);
    this->drain_task->drain_thread.join();
}

void VisualizerRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    if (this->visualizer_support.has_value()) {
        msg.supported_roles.push_back(SendspinRole::VISUALIZER);
        msg.visualizer_support = this->visualizer_support.value();
    }
}

// ============================================================================
// Binary handling (network thread)
// ============================================================================

void VisualizerRole::Impl::handle_binary(uint8_t binary_type, const uint8_t* data, size_t len) {
    if (!this->stream_active || !this->drain_task || !this->drain_task->ring_buffer.is_created()) {
        return;
    }

    // Build the frame flags byte from cached config
    uint8_t flags = ENTRY_FRAME;
    if (this->has_loudness) {
        flags |= FLAG_HAS_LOUDNESS;
    }
    if (this->has_f_peak) {
        flags |= FLAG_HAS_F_PEAK;
    }
    if (this->has_spectrum) {
        flags |= FLAG_HAS_SPECTRUM;
    }

    if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT) {
        // Beat format: [num_beats(1)][per-beat: server_timestamp(8)]
        if (len < 1) {
            return;
        }
        uint8_t num_beats = data[0];
        size_t offset = 1;

        for (uint8_t i = 0; i < num_beats; ++i) {
            if (offset + TIMESTAMP_SIZE > len) {
                break;
            }

            // Build beat entry: [ENTRY_BEAT][8-byte server_ts]
            uint8_t entry[BEAT_HEADER_SIZE + TIMESTAMP_SIZE];
            entry[0] = ENTRY_BEAT;
            std::memcpy(entry + BEAT_HEADER_SIZE, data + offset, TIMESTAMP_SIZE);

            this->drain_task->ring_buffer.send(entry, sizeof(entry), 0);
            offset += TIMESTAMP_SIZE;
        }
    } else {
        // Visualizer data format: [num_frames(1)][per-frame: timestamp(8) + fields...]
        if (len < 1) {
            return;
        }
        uint8_t num_frames = data[0];
        size_t offset = 1;
        size_t wire_frame_size = TIMESTAMP_SIZE + this->raw_frame_size;
        size_t entry_size = FRAME_HEADER_SIZE + TIMESTAMP_SIZE + this->raw_frame_size;

        for (uint8_t i = 0; i < num_frames; ++i) {
            if (offset + wire_frame_size > len) {
                break;
            }

            // Build frame entry: [flags][bin_count][8-byte server_ts][raw field bytes]
            // Use acquire+commit to avoid double-copy
            void* dest = this->drain_task->ring_buffer.acquire(entry_size, 0);
            if (dest == nullptr) {
                break;  // Buffer full, drop remaining frames
            }

            auto* entry = static_cast<uint8_t*>(dest);
            entry[0] = flags;
            entry[1] = this->spectrum_bin_count;
            std::memcpy(entry + FRAME_HEADER_SIZE, data + offset, wire_frame_size);

            this->drain_task->ring_buffer.commit(dest);
            offset += wire_frame_size;
        }
    }
}

// ============================================================================
// Stream lifecycle (network thread)
// ============================================================================

void VisualizerRole::Impl::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    // Cache stream config for handle_binary (same thread)
    this->has_loudness = false;
    this->has_f_peak = false;
    this->has_spectrum = false;
    this->spectrum_bin_count = 0;

    for (auto type : stream.types) {
        if (type == VisualizerDataType::LOUDNESS) {
            this->has_loudness = true;
        }
        if (type == VisualizerDataType::F_PEAK) {
            this->has_f_peak = true;
        }
        if (type == VisualizerDataType::SPECTRUM) {
            this->has_spectrum = true;
        }
    }
    if (this->has_spectrum && stream.spectrum.has_value()) {
        this->spectrum_bin_count = stream.spectrum->n_disp_bins;
    }

    this->raw_frame_size = (this->has_loudness ? 2 : 0) + (this->has_f_peak ? 2 : 0) +
                           (this->has_spectrum ? 2 * this->spectrum_bin_count : 0);
    this->stream_active = true;

    // Signal drain thread to flush old data
    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    // Shadow the config for main-thread callback, then signal
    this->event_state->shadow_config.write(stream);
    this->event_state->queue.send(VisualizerEventType::STREAM_START, 0);
}

void VisualizerRole::Impl::handle_stream_end() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state->queue.send(VisualizerEventType::STREAM_END, 0);
}

void VisualizerRole::Impl::handle_stream_clear() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state->queue.send(VisualizerEventType::STREAM_CLEAR, 0);
}

// ============================================================================
// Event draining (main thread) - lifecycle events only
// ============================================================================

void VisualizerRole::Impl::drain_events() const {
    VisualizerEventType event_type{};
    while (this->event_state->queue.receive(event_type, 0)) {
        switch (event_type) {
            case VisualizerEventType::STREAM_START: {
                ServerVisualizerStreamObject config{};
                if (this->event_state->shadow_config.take(config) && this->listener) {
                    this->listener->on_visualizer_stream_start(config);
                }
                break;
            }
            case VisualizerEventType::STREAM_END:
                if (this->listener) {
                    this->listener->on_visualizer_stream_end();
                }
                break;
            case VisualizerEventType::STREAM_CLEAR:
                if (this->listener) {
                    this->listener->on_visualizer_stream_clear();
                }
                break;
        }
    }
}

// ============================================================================
// Cleanup (main thread)
// ============================================================================

void VisualizerRole::Impl::cleanup() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state->queue.reset();
    this->event_state->shadow_config.reset();
    this->event_state->queue.send(VisualizerEventType::STREAM_END, 0);
}

// ============================================================================
// Drain thread helpers
// ============================================================================

void VisualizerRole::Impl::flush_ring_buffer() const {
    if (!this->drain_task) {
        return;
    }
    size_t item_size = 0;
    void* item = nullptr;
    while ((item = this->drain_task->ring_buffer.receive(&item_size, 0)) != nullptr) {
        this->drain_task->ring_buffer.return_item(item);
    }
}

void VisualizerRole::Impl::drain_thread_func(VisualizerRole::Impl* self) {
    SS_LOGD(TAG, "Drain thread started");

    auto& rb = self->drain_task->ring_buffer;
    auto& flags = self->drain_task->event_flags;

    while (true) {
        // Non-blocking check for commands
        uint32_t cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, 0);
        if (cmd & COMMAND_STOP) {
            break;
        }
        if (cmd & COMMAND_FLUSH) {
            self->flush_ring_buffer();
            continue;
        }

        // Blocking receive with 50ms timeout (allows periodic command checks)
        size_t item_size = 0;
        void* item = rb.receive(&item_size, DRAIN_RECEIVE_TIMEOUT_MS);
        if (item == nullptr) {
            continue;
        }

        // Wait for time sync
        if (!self->client->is_time_synced()) {
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
        int64_t client_ts = self->client->get_client_time(server_ts);

        if (client_ts == 0) {
            rb.return_item(item);
            continue;
        }

        // Sleep until display time (interruptible via event flags)
        int64_t now = platform_time_us();
        if (client_ts > now) {
            uint32_t wait_ms = static_cast<uint32_t>((client_ts - now) / US_PER_MS);
            if (wait_ms > 0) {
                cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, wait_ms);
                if (cmd & COMMAND_STOP) {
                    rb.return_item(item);
                    break;
                }
                if (cmd & COMMAND_FLUSH) {
                    rb.return_item(item);
                    self->flush_ring_buffer();
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
        if (is_frame && self->listener) {
            uint8_t frame_flags = type_byte & FRAME_FLAGS_MASK;
            uint8_t bin_count = raw[1];
            const uint8_t* fields = raw + FRAME_HEADER_SIZE + TIMESTAMP_SIZE;
            size_t data_len = item_size - FRAME_HEADER_SIZE - TIMESTAMP_SIZE;
            size_t offset = 0;

            VisualizerFrame frame{};
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
            self->listener->on_visualizer_frame(frame);
        } else if (!is_frame && self->listener) {
            rb.return_item(item);
            self->listener->on_beat(client_ts);
        } else {
            rb.return_item(item);
        }
    }

    SS_LOGD(TAG, "Drain thread stopped");
}

}  // namespace sendspin
