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

// Each ring buffer entry preserves the full wire message: [wire_type(1)][server_ts(8)][payload].
// This matches the spec's buffer_capacity accounting, which counts each message's full wire
// size (message-type byte + timestamp + data).
static constexpr size_t ENTRY_TYPE_SIZE = 1;
static constexpr size_t TIMESTAMP_SIZE = 8;

// Minimum payload bytes after the timestamp, per wire message type
static constexpr size_t LOUDNESS_PAYLOAD_SIZE = 2;  // uint16 value
static constexpr size_t BEAT_PAYLOAD_SIZE = 1;      // uint8 flags
static constexpr size_t F_PEAK_PAYLOAD_SIZE = 4;    // uint16 freq + uint16 amp
static constexpr size_t PEAK_PAYLOAD_SIZE = 1;      // uint8 strength

/// @brief Bit 0 of the beat flags byte marks a downbeat (bar start)
static constexpr uint8_t BEAT_FLAG_DOWNBEAT = 0x01;

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
    if (this->visualizer_support.has_value()) {
        this->drain_task = std::make_unique<DrainTask>();

        // buffer_capacity is the total RAM budget for the ring buffer. Each entry carries an
        // 8-byte ItemHeader aligned to 8 bytes, so with the small visualizer entries roughly a
        // third of this storage holds actual wire data and the rest is per-entry overhead.
        size_t capacity = this->visualizer_support->buffer_capacity;
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

void VisualizerRole::request_format(const VisualizerFormatRequest& request) {
    this->impl_->request_format(request);
}

// ============================================================================
// Impl method implementations
// ============================================================================

void VisualizerRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->config_slot.bind(inbox, INBOX_TOPIC_VISUALIZER_CONFIG);
}

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

void VisualizerRole::Impl::request_format(const VisualizerFormatRequest& request) const {
    StreamRequestFormatMessage msg{};
    msg.visualizer = request;
    this->client->send_text(format_stream_request_format_message(&msg));
}

// ============================================================================
// Binary handling (network thread)
// ============================================================================

void VisualizerRole::Impl::handle_binary(uint8_t binary_type, const uint8_t* data, size_t len) {
    if (!this->stream_active || !this->drain_task || !this->drain_task->ring_buffer.is_created()) {
        return;
    }

    // Forward the raw message verbatim: [wire_type][server_ts(8)][payload]. Like the player and
    // artwork roles, the network thread stays dumb -- it records the message and hands it to the
    // drain thread, which owns all structural validation and per-type truncation. The only check
    // here is that a timestamp is present, since the drain thread needs it to schedule the entry.
    // No size cap is applied: the ring buffer records each entry's length, so an oversized message
    // is self-limiting (it either fits or is dropped when acquire() fails).
    if (len < TIMESTAMP_SIZE) {
        return;
    }

    // Build entry: [wire_type][server_ts(8)][payload]. Use acquire+commit to avoid double-copy.
    size_t entry_size = ENTRY_TYPE_SIZE + len;
    void* dest = this->drain_task->ring_buffer.acquire(entry_size, 0);
    if (dest == nullptr) {
        return;  // Buffer full, drop
    }

    auto* entry = static_cast<uint8_t*>(dest);
    entry[0] = binary_type;
    std::memcpy(entry + ENTRY_TYPE_SIZE, data, len);

    this->drain_task->ring_buffer.commit(dest);
}

// ============================================================================
// Stream lifecycle (network thread)
// ============================================================================

void VisualizerRole::Impl::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    // Cache stream config for handle_binary (same thread) and the drain thread
    uint8_t bin_count = 0;
    bool has_spectrum = false;
    for (auto type : stream.types) {
        if (type == VisualizerDataType::SPECTRUM) {
            has_spectrum = true;
        }
    }
    if (has_spectrum && stream.spectrum.has_value()) {
        bin_count = stream.spectrum->n_disp_bins;
    }
    this->spectrum_bin_count = bin_count;
    this->tracks_downbeats = stream.tracks_downbeats;
    this->stream_active = true;

    // Signal drain thread to flush old data
    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    // Write the config to the inbox slot for the main thread, then push the event. Both lock the
    // same shared Inbox mutex, in this order, so a consumer that later takes the START event is
    // guaranteed to observe this config (see config_slot.take() in handle_stream_ring_event()).
    this->event_state->config_slot.write(stream);
    this->enqueue_stream_event(VisualizerEventType::STREAM_START);
}

void VisualizerRole::Impl::handle_stream_end() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->enqueue_stream_event(VisualizerEventType::STREAM_END);
}

void VisualizerRole::Impl::handle_stream_clear() {
    // Per spec, stream/clear discards buffered data but the stream stays active; data
    // received after this message continues to flow.
    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->enqueue_stream_event(VisualizerEventType::STREAM_CLEAR);
}

void VisualizerRole::Impl::enqueue_stream_event(VisualizerEventType event) const {
    const char* name = "STREAM_CLEAR";
    if (event == VisualizerEventType::STREAM_START) {
        name = "STREAM_START";
    } else if (event == VisualizerEventType::STREAM_END) {
        name = "STREAM_END";
    }
    push_event_or_log(this->inbox, InboxEventType::VISUALIZER_STREAM, static_cast<uint8_t>(event),
                      TAG, name);
}

// ============================================================================
// Event dispatch (main thread) - lifecycle events only, called from the ring drain in
// SendspinClient::loop()
// ============================================================================

void VisualizerRole::Impl::handle_stream_ring_event(VisualizerEventType event) const {
    switch (event) {
        case VisualizerEventType::STREAM_START: {
            ServerVisualizerStreamObject config{};
            if (this->event_state->config_slot.take(config) && this->listener) {
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

// ============================================================================
// Cleanup (main thread)
// ============================================================================

void VisualizerRole::Impl::cleanup() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    // Discard stale slot content from the dead connection. Stale ring-borne events (an in-flight
    // STREAM_START/STREAM_END/STREAM_CLEAR queued before this cleanup) are already discarded by
    // SendspinClient::cleanup_connection_state()'s inbox.reset_events() call, which runs before
    // any role's cleanup() -- so there is no per-event ring reset to do here.
    this->event_state->config_slot.reset();

    // Enqueue a clean STREAM_END - handle_stream_ring_event() will fire the callback (the ring
    // was just reset above us, so this push should not fail; enqueue_stream_event() logs if it
    // somehow does).
    this->enqueue_stream_event(VisualizerEventType::STREAM_END);
}

// ============================================================================
// Drain thread helpers
// ============================================================================

VisualizerDelivery decode_visualizer_message(uint8_t wire_type, const uint8_t* payload,
                                             size_t payload_len, uint8_t configured_bins,
                                             bool tracks_downbeats,
                                             std::vector<uint16_t>& spectrum_out) {
    VisualizerDelivery out;
    switch (wire_type) {
        case SENDSPIN_BINARY_VISUALIZER_LOUDNESS:
            if (payload_len < LOUDNESS_PAYLOAD_SIZE) {
                break;
            }
            out.kind = VisualizerDelivery::Kind::LOUDNESS;
            out.loudness = read_be16(payload);
            break;
        case SENDSPIN_BINARY_VISUALIZER_BEAT:
            if (payload_len < BEAT_PAYLOAD_SIZE) {
                break;
            }
            out.kind = VisualizerDelivery::Kind::BEAT;
            // Bit 0 is only meaningful when the stream tracks downbeats
            out.downbeat = tracks_downbeats && (payload[0] & BEAT_FLAG_DOWNBEAT) != 0;
            break;
        case SENDSPIN_BINARY_VISUALIZER_F_PEAK:
            if (payload_len < F_PEAK_PAYLOAD_SIZE) {
                break;
            }
            out.kind = VisualizerDelivery::Kind::F_PEAK;
            out.frequency_hz = read_be16(payload);
            out.amplitude = read_be16(payload + 2);
            break;
        case SENDSPIN_BINARY_VISUALIZER_SPECTRUM:
            // Deliver exactly the negotiated n_disp_bins. Drop the frame if SPECTRUM was not
            // negotiated (bin count 0) or the payload is short; ignore any trailing bytes.
            if (configured_bins == 0 || payload_len < 2U * configured_bins) {
                break;
            }
            spectrum_out.resize(configured_bins);
            for (uint8_t b = 0; b < configured_bins; ++b) {
                spectrum_out[b] = read_be16(payload + 2 * b);
            }
            out.kind = VisualizerDelivery::Kind::SPECTRUM;
            break;
        case SENDSPIN_BINARY_VISUALIZER_PEAK:
            if (payload_len < PEAK_PAYLOAD_SIZE) {
                break;
            }
            out.kind = VisualizerDelivery::Kind::PEAK;
            out.strength = payload[0];
            break;
        default:
            break;  // Reserved types 21-23
    }
    return out;
}

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

    // Reused across iterations to avoid a heap alloc/free per frame. The vector's capacity
    // grows to the largest bin count seen and is resized (not reallocated) after that.
    std::vector<uint16_t> spectrum_bins;

    // RAII guard so the ring-buffer slot is returned exactly once on every exit path. Each branch
    // calls release() to hand the slot back *before* invoking the listener callback, so a slow
    // callback never blocks the network producer; if a branch exits without releasing (a short-
    // payload drop, or a future wire type that forgets), the destructor returns it. Stack-only.
    struct SlotGuard {
        SpscRingBuffer& rb;
        void* item;
        bool released = false;
        void release() {
            if (!this->released) {
                this->rb.return_item(this->item);
                this->released = true;
            }
        }
        ~SlotGuard() {
            this->release();
        }
    };

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

        // Entry format: [wire_type][server_ts(8)][payload]
        if (item_size < ENTRY_TYPE_SIZE + TIMESTAMP_SIZE) {
            rb.return_item(item);
            continue;
        }
        auto* raw = static_cast<const uint8_t*>(item);
        uint8_t wire_type = raw[0];
        int64_t server_ts = read_be64(raw + ENTRY_TYPE_SIZE);
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

        if (self->listener == nullptr) {
            rb.return_item(item);
            continue;
        }

        // Decode and deliver. The network thread forwards messages verbatim, so decode validates
        // each payload's length before reading. Copy out of the slot, release it via the guard,
        // then deliver -- so a slow listener callback never blocks the network producer.
        const uint8_t* payload = raw + ENTRY_TYPE_SIZE + TIMESTAMP_SIZE;
        size_t payload_len = item_size - ENTRY_TYPE_SIZE - TIMESTAMP_SIZE;

        SlotGuard guard{rb, item};
        VisualizerDelivery out =
            decode_visualizer_message(wire_type, payload, payload_len, self->spectrum_bin_count,
                                      self->tracks_downbeats, spectrum_bins);
        guard.release();

        switch (out.kind) {
            case VisualizerDelivery::Kind::LOUDNESS:
                self->listener->on_loudness(client_ts, out.loudness);
                break;
            case VisualizerDelivery::Kind::BEAT:
                self->listener->on_beat(client_ts, out.downbeat);
                break;
            case VisualizerDelivery::Kind::F_PEAK:
                self->listener->on_f_peak(client_ts, out.frequency_hz, out.amplitude);
                break;
            case VisualizerDelivery::Kind::SPECTRUM:
                self->listener->on_spectrum(client_ts, spectrum_bins);
                break;
            case VisualizerDelivery::Kind::PEAK:
                self->listener->on_peak(client_ts, out.strength);
                break;
            case VisualizerDelivery::Kind::NONE:
                break;
        }
    }

    SS_LOGD(TAG, "Drain thread stopped");
}

}  // namespace sendspin
