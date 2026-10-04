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

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <utility>

static const char* const TAG = "sendspin.visualizer";

// ============================================================================
// Entry format constants
// ============================================================================

// Each frame stays in the inbound ring item it arrived in: its plaintext is
// [wire_type(1)][server_ts(8)][payload], the item header carries the wire type, the payload's
// offset and length, and the transport's receive stamp. buffer_capacity is the visualizer's quota
// of ring storage, not a wire-data quota: each frame also costs the ring's per-item overhead, so
// effective wire-data capacity is smaller (see the buffer_capacity note in config.h).
static constexpr size_t ENTRY_TYPE_SIZE = 1;
static constexpr size_t TIMESTAMP_SIZE = 8;
/// @brief Offset of a frame's payload in its plaintext
static constexpr size_t FRAME_PAYLOAD_OFFSET = ENTRY_TYPE_SIZE + TIMESTAMP_SIZE;

// Minimum payload bytes after the timestamp, per wire message type
static constexpr size_t LOUDNESS_PAYLOAD_SIZE = 2;  // uint16 value
static constexpr size_t BEAT_PAYLOAD_SIZE = 1;      // uint8 flags
static constexpr size_t F_PEAK_PAYLOAD_SIZE = 4;    // uint16 freq + uint16 amp
static constexpr size_t PEAK_PAYLOAD_SIZE = 1;      // uint8 strength

/// @brief Bit 0 of the beat flags byte marks a downbeat (bar start)
static constexpr uint8_t BEAT_FLAG_DOWNBEAT = 0x01;

/// @brief The smallest frame on the wire: a beat or peak, one payload byte behind the type byte and
/// the timestamp
static constexpr size_t MIN_FRAME_WIRE_BYTES = FRAME_PAYLOAD_OFFSET + BEAT_PAYLOAD_SIZE;

// buffer_capacity is the visualizer's quota of inbound ring storage, but each frame is held at
// its stored cost, at most sendspin::INBOUND_ITEM_STORED_OVERHEAD_BYTES over its wire size, so
// the smallest frames (10 wire bytes stored as 68) leave only about a seventh of the quota for
// wire data. Advertise that fraction to the server (not the raw budget) so its flow control never
// sends more than the quota holds. This mirrors the player role's derived buffer advertisement.
static constexpr size_t BUFFER_ADVERTISE_DIVISOR =
    (MIN_FRAME_WIRE_BYTES + sendspin::INBOUND_ITEM_STORED_OVERHEAD_BYTES + MIN_FRAME_WIRE_BYTES -
     1) /
    MIN_FRAME_WIRE_BYTES;

/// @brief The smallest buffer_capacity the role starts with: one that advertises at least one
/// smallest frame (MIN_FRAME_WIRE_BYTES) to the server, which also holds that frame's stored size.
static constexpr size_t MIN_BUFFER_CAPACITY = BUFFER_ADVERTISE_DIVISOR * MIN_FRAME_WIRE_BYTES;
static_assert(MIN_BUFFER_CAPACITY >=
                  sendspin::SharedRingLayout::stored_size(sizeof(sendspin::InboundItemHeader) +
                                                          MIN_FRAME_WIRE_BYTES +
                                                          sendspin::AEAD_TAG_SIZE),
              "the floor must hold one stored frame");

/// @brief Whether a message with `payload_size` bytes after its timestamp stores within the
/// advertised fraction.
static constexpr bool fits_advertised_fraction(size_t payload_size) {
    const size_t wire_size = FRAME_PAYLOAD_OFFSET + payload_size;
    return BUFFER_ADVERTISE_DIVISOR * wire_size >=
           sendspin::SharedRingLayout::stored_size(sizeof(sendspin::InboundItemHeader) + wire_size +
                                                   sendspin::AEAD_TAG_SIZE);
}
static_assert(fits_advertised_fraction(BEAT_PAYLOAD_SIZE) &&
                  fits_advertised_fraction(PEAK_PAYLOAD_SIZE) &&
                  fits_advertised_fraction(LOUDNESS_PAYLOAD_SIZE) &&
                  fits_advertised_fraction(F_PEAK_PAYLOAD_SIZE),
              "the advertised buffer_capacity would exceed the visualizer's quota");

// Event flag bits for drain thread signaling
static constexpr uint32_t COMMAND_STOP = (1 << 0);
static constexpr uint32_t COMMAND_FLUSH = (1 << 1);  // Drain to empty (producer already stopped)
static constexpr uint32_t COMMAND_CLEAR = (1 << 2);  // Discard up to the clear marker entry

// Type of the item marking a stream/start or stream/clear boundary on the item list. Frames
// before the marker predate the boundary and are discarded; frames after it survive. The value
// is outside the visualizer wire-type range (16-23) so it can never collide with a real message,
// and the marker carries no timestamp, so the drain loop drops any leftover marker encountered in
// normal flow.
static constexpr uint8_t ENTRY_TYPE_CLEAR_MARKER = 0xFF;

/// @brief Timeout for acquiring ring space for the clear marker (see
/// sendspin::INBOUND_ACQUIRE_TIMEOUT_MS). The drain thread is concurrently discarding, so space
/// frees quickly; if this still times out the boundary is lost and the drain falls back to
/// discarding everything it finds (matching the player's marker semantics).
static constexpr uint32_t MARKER_ENQUEUE_TIMEOUT_MS = sendspin::INBOUND_ACQUIRE_TIMEOUT_MS;

/// @brief Fallback wakeup interval for the drain thread's blocking item list take. Stop,
/// flush, and clear commands wake the take immediately via wake_receiver(), so this is only
/// a safety net against a missed wake: long enough to keep an idle thread asleep, short enough
/// that a wake bug degrades to a slow reaction rather than a hang.
static constexpr uint32_t DRAIN_RECEIVE_TIMEOUT_MS = 5000U;

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

/// @brief Maps a negotiated data type to its binary wire-type byte
static uint8_t wire_type_for(sendspin::VisualizerDataType type) {
    switch (type) {
        case sendspin::VisualizerDataType::LOUDNESS:
            return sendspin::SENDSPIN_BINARY_VISUALIZER_LOUDNESS;
        case sendspin::VisualizerDataType::BEAT:
            return sendspin::SENDSPIN_BINARY_VISUALIZER_BEAT;
        case sendspin::VisualizerDataType::F_PEAK:
            return sendspin::SENDSPIN_BINARY_VISUALIZER_F_PEAK;
        case sendspin::VisualizerDataType::SPECTRUM:
            return sendspin::SENDSPIN_BINARY_VISUALIZER_SPECTRUM;
        case sendspin::VisualizerDataType::PEAK:
            return sendspin::SENDSPIN_BINARY_VISUALIZER_PEAK;
    }
    return 0;
}

namespace sendspin {

// ============================================================================
// Impl constructor / destructor
// ============================================================================

VisualizerRole::Impl::Impl(VisualizerRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      visualizer_support(this->config.support),
      client(client),
      event_state(std::make_unique<EventState>()) {
    this->drain_task = std::make_unique<DrainTask>();
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

void VisualizerRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->config_slot.bind(inbox, INBOX_TOPIC_VISUALIZER_CONFIG);
}

bool VisualizerRole::Impl::start(InboundRing* ring) {
    // roles/visualizer/v1.md "client/state visualizer object": rate_max is a positive integer,
    // and a types list containing 'spectrum' without a spectrum object is a protocol error the
    // server SHOULD close the connection for. The configuration is reported as given, so a
    // config the spec forbids refuses to start here rather than being discovered as an
    // unexplained disconnect, the same posture the player takes on its format list.
    const VisualizerStreamConfig& stream = this->config.stream;
    if (stream.rate_max == 0 && !stream.types.empty()) {
        SS_LOGE(TAG, "VisualizerStreamConfig::rate_max must be positive while types are requested");
        return false;
    }
    // A quota that advertises less than one frame (or cannot store one) drops every frame;
    // refuse it as the configuration error it is.
    if (this->visualizer_support.buffer_capacity < MIN_BUFFER_CAPACITY) {
        SS_LOGE(TAG, "VisualizerSupportObject::buffer_capacity must be at least %zu bytes",
                MIN_BUFFER_CAPACITY);
        return false;
    }
    if (!stream.spectrum.has_value() &&
        std::find(stream.types.begin(), stream.types.end(), VisualizerDataType::SPECTRUM) !=
            stream.types.end()) {
        SS_LOGE(TAG, "VisualizerStreamConfig::spectrum is required to request the spectrum type");
        return false;
    }
    if (this->drain_task->drain_thread.joinable()) {
        return true;  // Already running
    }
    if (!this->drain_task->event_flags.is_created() && !this->drain_task->event_flags.create()) {
        SS_LOGE(TAG, "Failed to create visualizer event flags");
        return false;
    }
    if (!this->drain_task->inbound.bind(ring, InboundHolder::VISUALIZER)) {
        SS_LOGE(TAG, "Failed to create the visualizer item list");
        return false;
    }

    // The flags survive a stop()/start() cycle, and a flush or clear signalled between the join
    // and this start (cleanup() on a stopped role) is still set. Clear the whole group so the new
    // thread starts from a clean command state whatever bits the role defines (stop() already
    // emptied the list).
    this->drain_task->event_flags.clear_all();

    platform_configure_thread("SsVis", 4096, static_cast<int>(this->config.priority),
                              this->config.psram_stack);
    this->drain_task->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

bool VisualizerRole::Impl::signal_stop() const {
    if (!this->drain_task || !this->drain_task->drain_thread.joinable()) {
        return false;
    }
    // Set the flag before waking: the thread re-checks its command flags at the top of every
    // loop iteration, so this ordering guarantees it observes the stop no matter which wait
    // it was parked in (display-time flags wait or item list take).
    this->drain_task->event_flags.set(COMMAND_STOP);
    this->drain_task->inbound.items().wake_receiver();
    return true;
}

void VisualizerRole::Impl::stop() const {
    if (!this->signal_stop()) {
        return;
    }
    this->drain_task->drain_thread.join();
    this->drain_task->inbound.unbind();
}

size_t VisualizerRole::Impl::stored_frame_bytes_per_second() const {
    // roles/visualizer/v1.md "client/state visualizer object": rate_max caps the frames per second
    // the server sends of each periodic type (loudness, f_peak, spectrum). Beat and peak frames
    // are events the spec does not throttle; they are budgeted at the same rate, an assumption
    // (onsets and beats come at most a few times a second), not a bound.
    const VisualizerStreamConfig& stream = this->config.stream;
    size_t per_round = 0;
    for (const VisualizerDataType type : stream.types) {
        size_t payload = 0;
        switch (type) {
            case VisualizerDataType::LOUDNESS:
                payload = LOUDNESS_PAYLOAD_SIZE;
                break;
            case VisualizerDataType::BEAT:
                payload = BEAT_PAYLOAD_SIZE;
                break;
            case VisualizerDataType::F_PEAK:
                payload = F_PEAK_PAYLOAD_SIZE;
                break;
            case VisualizerDataType::PEAK:
                payload = PEAK_PAYLOAD_SIZE;
                break;
            case VisualizerDataType::SPECTRUM:
                payload = stream.spectrum.has_value()
                              ? sizeof(uint16_t) * stream.spectrum->n_disp_bins
                              : 0;
                break;
        }
        per_round += SharedRingLayout::stored_size(sizeof(InboundItemHeader) +
                                                   FRAME_PAYLOAD_OFFSET + payload + AEAD_TAG_SIZE);
    }
    return per_round * stream.rate_max;
}

void VisualizerRole::Impl::build_hello_fields(ClientHelloMessage& msg) const {
    msg.supported_roles.push_back(SendspinRole::VISUALIZER);
    // Advertise the effective wire-data capacity, not the raw budget: the quota is
    // buffer_capacity bytes of ring storage, but per-item overhead leaves only a fraction of it
    // for wire data (see BUFFER_ADVERTISE_DIVISOR). The quota itself is the full value.
    VisualizerSupportObject advertised = this->visualizer_support;
    advertised.buffer_capacity = this->advertised_buffer_capacity();
    msg.visualizer_support = advertised;
}

size_t VisualizerRole::Impl::advertised_buffer_capacity() const {
    // Unlike the player's, never capped at the ring's largest item, since it never reaches it:
    // the ring holds the whole quota (derive_inbound_ring_bytes()), so its largest item, half the
    // storage, is over half the quota, while this is a seventh of it.
    return this->visualizer_support.buffer_capacity / BUFFER_ADVERTISE_DIVISOR;
}

void VisualizerRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    ClientVisualizerStateObject visualizer_state{};
    visualizer_state.types = this->config.stream.types;
    visualizer_state.rate_max = this->config.stream.rate_max;
    visualizer_state.spectrum = this->config.stream.spectrum;
    msg.visualizer = std::move(visualizer_state);
}

// ============================================================================
// Binary handling (protocol task)
// ============================================================================

void VisualizerRole::Impl::handle_binary(uint8_t binary_type, InboundMessage& message) {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    InboundConsumer& inbound = this->drain_task->inbound;
    if (!this->stream_active || inbound.ring() == nullptr) {
        return;
    }

    // Admit only wire types the active stream negotiated in stream/start. The mask is written by
    // handle_stream_start on this same thread, so a message is always judged against the config
    // in force when it arrived. The caller guarantees binary_type is in the visualizer range.
    uint8_t type_bit = 1U << (binary_type - SENDSPIN_BINARY_VISUALIZER_FIRST);
    if ((this->negotiated_types_mask & type_bit) == 0) {
        return;
    }

    // Hand the message over verbatim. Like the player and artwork roles, the protocol task stays
    // dumb: it records the message and hands it to the drain thread, which owns all structural
    // validation and per-type truncation. The only other check here is that a timestamp is
    // present, since the drain thread needs it to schedule the frame. No size cap is applied:
    // the frame is one ring item, charged against the quota.
    if (message.len < FRAME_PAYLOAD_OFFSET) {
        return;
    }
    void* item = std::exchange(message.item, nullptr);
    size_t item_len = message.item_len;
    if (item == nullptr) {
        // A frame reassembled from Noise fragments or routed through the fallback buffer (longer
        // than the ring takes) is not in a ring item: copied into one, whole, keeping the
        // transport's receive stamp. A frame longer than the ring's largest item can never be
        // copied in, which is logged apart from a momentarily full ring.
        if (message.len > inbound.ring()->max_item_message_bytes()) {
            inbound.note_drop("received a frame longer than the ring's largest item; dropping");
            return;
        }
        item = inbound.copy_local(message.data, message.len, message.receive_time_us, 0);
        if (item == nullptr) {
            inbound.note_drop("has no ring space to copy a frame into; dropping");
            return;
        }
        item_len = message.len;
    }
    // Otherwise the frame stays in the ring item it was received and decrypted into.
    this->hand_item(item, item_len, binary_type,
                    static_cast<uint32_t>(message.len - FRAME_PAYLOAD_OFFSET), generation);
}

bool VisualizerRole::Impl::hand_item(void* item, size_t item_len, uint8_t type, uint32_t data_len,
                                     uint32_t generation) const {
    InboundItemHeader* header = inbound_item_header(item);
    header->type = type;
    const bool marker = type == ENTRY_TYPE_CLEAR_MARKER;
    header->data_offset = static_cast<uint8_t>(marker ? 0 : FRAME_PAYLOAD_OFFSET);
    header->data_len = data_len;
    // A marker is exempt from the quota (InboundConsumer::hand()).
    return this->drain_task->inbound.hand(item, item_len, generation, /*exempt=*/marker);
}

// ============================================================================
// Stream lifecycle (protocol task)
// ============================================================================

void VisualizerRole::Impl::handle_stream_start(const ServerVisualizerStreamObject& stream) {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // Cache stream config for handle_binary (same thread) and the drain thread
    uint8_t bin_count = 0;
    uint8_t types_mask = 0;
    bool has_spectrum = false;
    for (auto type : stream.types) {
        if (type == VisualizerDataType::SPECTRUM) {
            has_spectrum = true;
        }
        types_mask |= 1U << (wire_type_for(type) - SENDSPIN_BINARY_VISUALIZER_FIRST);
    }
    if (has_spectrum) {
        // roles/visualizer/v1.md "Server -> Client: stream/start": the spectrum object is present
        // when types includes 'spectrum' and MUST match the requested configuration. The object is
        // reported to the listener as the server sent it, so a mismatch is logged, not rejected.
        const std::optional<VisualizerSpectrumConfig>& requested = this->config.stream.spectrum;
        if (!stream.spectrum.has_value()) {
            SS_LOGW(TAG, "Visualizer stream/start requests the spectrum type with no spectrum "
                         "object; spectrum frames will be dropped");
        } else if (requested.has_value()) {
            const VisualizerSpectrumConfig& srv = stream.spectrum.value();
            if (srv.n_disp_bins != requested->n_disp_bins) {
                SS_LOGW(TAG, "Spectrum bin count mismatch: server %" PRIu8 ", expected %" PRIu8,
                        srv.n_disp_bins, requested->n_disp_bins);
            }
            if (srv.scale != requested->scale) {
                SS_LOGW(TAG, "Spectrum scale mismatch");
            }
            if (srv.f_min != requested->f_min || srv.f_max != requested->f_max) {
                SS_LOGW(TAG,
                        "Spectrum frequency range mismatch: server %" PRIu16 "-%" PRIu16
                        ", expected %" PRIu16 "-%" PRIu16,
                        srv.f_min, srv.f_max, requested->f_min, requested->f_max);
            }
        }
    }
    if (has_spectrum && stream.spectrum.has_value()) {
        bin_count = stream.spectrum->n_disp_bins;
    }
    this->spectrum_bin_count = bin_count;
    this->tracks_downbeats = stream.tracks_downbeats;
    this->negotiated_types_mask = types_mask;
    this->stream_active = true;

    // Mark the config boundary: buffered frames predate this (re)start and must be discarded,
    // while frames arriving after it belong to the new config and must survive.
    this->signal_clear_marker(generation);

    // Write the config to the inbox slot for the main thread, then push the event. Both lock the
    // same shared Inbox mutex, in this order, so a consumer that later takes the START event is
    // guaranteed to observe this config (see config_slot.take() in handle_stream_ring_event()).
    // Both carry `generation`, so a config left over from a torn-down stream is never applied.
    this->event_state->config_slot.write(stream, generation);
    this->enqueue_stream_event(VisualizerEventType::STREAM_START, generation);
}

void VisualizerRole::Impl::handle_stream_end() {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    this->stream_active = false;
    this->negotiated_types_mask = 0;

    if (this->drain_task->event_flags.is_created()) {
        // Flag first, then wake, so a drain thread parked in its item list take starts the
        // flush immediately instead of at its next idle-receive timeout.
        this->drain_task->event_flags.set(COMMAND_FLUSH);
        this->drain_task->inbound.items().wake_receiver();
    }

    this->enqueue_stream_event(VisualizerEventType::STREAM_END, generation);
}

void VisualizerRole::Impl::handle_stream_clear() {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // messaging.md "stream/clear" discards buffered data but the stream stays active; data
    // received after this message continues to flow. The marker separates the two: a blind
    // flush would race this thread and drop post-clear frames it has already appended.
    this->signal_clear_marker(generation);

    this->enqueue_stream_event(VisualizerEventType::STREAM_CLEAR, generation);
}

void VisualizerRole::Impl::enqueue_stream_event(VisualizerEventType event,
                                                uint32_t generation) const {
    const char* name = "STREAM_CLEAR";
    if (event == VisualizerEventType::STREAM_START) {
        name = "STREAM_START";
    } else if (event == VisualizerEventType::STREAM_END) {
        name = "STREAM_END";
    }
    push_event_or_log(this->inbox, InboxEventType::VISUALIZER_STREAM, static_cast<uint8_t>(event),
                      TAG, name, generation);
}

// ============================================================================
// Event dispatch (main thread) - lifecycle events only, called from the ring drain in
// SendspinClient::drain_inbox()
// ============================================================================

void VisualizerRole::Impl::handle_stream_ring_event(VisualizerEventType event,
                                                    uint32_t generation) const {
    switch (event) {
        case VisualizerEventType::STREAM_START: {
            ServerVisualizerStreamObject config{};
            uint32_t stamp = 0;
            if (!this->event_state->config_slot.take(config, stamp)) {
                break;
            }
            if (stamp != generation) {
                SS_LOGD(TAG, "Dropping a visualizer config queued before the role was torn down");
                break;
            }
            if (this->listener) {
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
// Cleanup (protocol task, or the main loop in stop() once it is joined)
// ============================================================================

void VisualizerRole::Impl::cleanup() {
    // Stamps every event queued from here on, so an event queued for the stream this teardown
    // ends is discarded (see cleanup_generation).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->stream_active = false;
    this->negotiated_types_mask = 0;

    // Return the frames the drain thread has not taken; one it takes before this carries the
    // earlier stamp, which its take() discards.
    this->drain_task->inbound.recall();

    if (this->drain_task->event_flags.is_created()) {
        // Flag first, then wake, matching handle_stream_end().
        this->drain_task->event_flags.set(COMMAND_FLUSH);
        this->drain_task->inbound.items().wake_receiver();
    }

    // Discard stale slot content. Stale ring-borne events (an in-flight
    // STREAM_START/STREAM_END/STREAM_CLEAR queued before this teardown) need no per-event ring
    // reset either way: on the connection-loss path
    // SendspinClient::cleanup_connection_state()'s inbox.reset_events() has already wiped them,
    // and on the deactivation path, which leaves the ring alone for the roles that stay active,
    // they carry the generation this teardown just left behind and the drain discards them (see
    // event_is_current()).
    this->event_state->config_slot.reset();

    push_event_or_log(this->inbox, InboxEventType::VISUALIZER_CLEARED, 0, TAG,
                      "visualizer cleared event", generation);
}

void VisualizerRole::Impl::complete_teardown() const {
    if (this->listener) {
        this->listener->on_visualizer_stream_end();
    }
}

// ============================================================================
// Drain thread helpers
// ============================================================================

std::optional<int64_t> visualizer_delivery_wait_us(int64_t client_ts, int64_t arrival_us,
                                                   int32_t display_offset_ms, int64_t now) {
    // A frame that arrived in time and only waited behind others sharing its timestamp is not
    // stale.
    if (client_ts < arrival_us) {
        return std::nullopt;
    }
    const int64_t deliver_at_us = client_ts - static_cast<int64_t>(display_offset_ms) * US_PER_MS;
    if (now - std::max(deliver_at_us, arrival_us) > VISUALIZER_MAX_DELIVERY_LAG_US) {
        return std::nullopt;
    }
    return std::max<int64_t>(deliver_at_us - now, 0);
}

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
            if (configured_bins == 0 || payload_len < static_cast<size_t>(configured_bins) * 2) {
                break;
            }
            spectrum_out.resize(configured_bins);
            for (uint8_t b = 0; b < configured_bins; ++b) {
                spectrum_out[b] = read_be16(payload + static_cast<size_t>(b) * 2);
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

void VisualizerRole::Impl::flush_items() const {
    InboundConsumer& inbound = this->drain_task->inbound;
    void* item = nullptr;
    while ((item = inbound.items().take(0)) != nullptr) {
        inbound.return_item(item);
    }
}

void* VisualizerRole::Impl::take_item(uint32_t timeout_ms) const {
    return this->drain_task->inbound.take(timeout_ms, this->cleanup_generation);
}

void VisualizerRole::Impl::signal_clear_marker(uint32_t generation) const {
    // Protocol-task side of a clear boundary. Set the flag before appending the marker (like
    // PlayerRole::handle_stream_clear) so the drain thread starts discarding (freeing ring space)
    // while the marker waits for room.
    InboundConsumer& inbound = this->drain_task->inbound;
    if (inbound.ring() == nullptr) {
        return;
    }
    // Flag first, then wake, matching the other command signals. The marker's append below
    // would usually wake the drain thread anyway, but the explicit wake keeps the discard prompt
    // even when the marker cannot be appended.
    this->drain_task->event_flags.set(COMMAND_CLEAR);
    inbound.items().wake_receiver();

    void* item = inbound.copy_local(nullptr, 0, 0, MARKER_ENQUEUE_TIMEOUT_MS);
    if (item == nullptr) {
        // Boundary lost: the drain thread will discard to empty instead, so frames appended after
        // this point may be dropped along with the old ones (brief visual gap, no harm).
        SS_LOGW(TAG, "Failed to append clear marker; clear boundary may be imprecise");
        return;
    }
    this->hand_item(item, 0, ENTRY_TYPE_CLEAR_MARKER, 0, generation);
}

void VisualizerRole::Impl::discard_to_clear_marker() const {
    // Drain-thread side of a clear boundary: discard frames up to and including the marker.
    // Stopping at the marker preserves frames the protocol task appended after the clear,
    // which messaging.md "stream/clear" requires to survive. If the list empties without a
    // marker, either the marker could not be appended or it was already consumed in normal flow
    // (the drain loop drops it); nothing is left to discard either way.
    InboundConsumer& inbound = this->drain_task->inbound;
    void* item = nullptr;
    while ((item = inbound.items().take(0)) != nullptr) {
        const bool is_marker = inbound_item_header(item)->type == ENTRY_TYPE_CLEAR_MARKER;
        inbound.return_item(item);
        if (is_marker) {
            return;
        }
    }
}

void VisualizerRole::Impl::drain_thread_func(VisualizerRole::Impl* self) {
    SS_LOGD(TAG, "Drain thread started");

    // Bound by start() before this thread exists and unbound by stop() only after it is joined.
    InboundRing& ring = *self->drain_task->inbound.ring();
    auto& flags = self->drain_task->event_flags;
    const int32_t offset_ms = self->config.display_offset_ms;

    // Reused across iterations to avoid a heap alloc/free per frame. The vector's capacity
    // grows to the largest bin count seen and is resized (not reallocated) after that.
    std::vector<uint16_t> spectrum_bins;

    // RAII guard so the ring item is returned exactly once on every exit path. Each branch calls
    // release() to hand the item back *before* invoking the listener callback, so a slow callback
    // never holds ring space; if a branch exits without releasing (a short-payload drop, or a
    // future wire type that forgets), the destructor returns it. Stack-only.
    struct ItemGuard {
        InboundRing& ring;
        void* item = nullptr;
        bool released = false;
        void release() {
            if (!this->released) {
                this->ring.return_item(this->item);
                this->released = true;
            }
        }
        ~ItemGuard() {
            this->release();
        }
    };

    while (true) {
        // Non-blocking check for commands
        uint32_t cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH | COMMAND_CLEAR, false, true, 0);
        if (cmd & COMMAND_STOP) {
            break;
        }
        if (cmd & (COMMAND_FLUSH | COMMAND_CLEAR)) {
            if (cmd & COMMAND_FLUSH) {
                self->flush_items();
            }
            if (cmd & COMMAND_CLEAR) {
                self->discard_to_clear_marker();
            }
            continue;
        }

        // Blocking take; returns early (nullptr) when wake_receiver() signals a stop, flush, or
        // clear. The timeout is only a safety net against a missed wake (see
        // DRAIN_RECEIVE_TIMEOUT_MS).
        void* item = self->take_item(DRAIN_RECEIVE_TIMEOUT_MS);
        if (item == nullptr) {
            continue;
        }
        const InboundItemHeader* header = inbound_item_header(item);

        // Waiting for time sync.
        if (!self->client->is_time_synced()) {
            ring.return_item(item);
            continue;
        }

        // A clear marker whose COMMAND_CLEAR was already handled carries no timestamp: everything
        // before it was consumed in order, so the boundary it marks has already been honored.
        if (header->type == ENTRY_TYPE_CLEAR_MARKER) {
            ring.return_item(item);
            continue;
        }
        const uint8_t wire_type = header->type;
        const int64_t server_ts = read_be64(inbound_item_bytes(item) + ENTRY_TYPE_SIZE);
        int64_t client_ts = self->client->get_client_time(server_ts);

        if (client_ts == 0) {
            ring.return_item(item);
            continue;
        }

        const int64_t now = platform_time_us();
        const std::optional<int64_t> wait_us = visualizer_delivery_wait_us(
            client_ts, widen_time_stamp_us(header->receive_time_us, now), offset_ms, now);
        if (!wait_us.has_value()) {
            ring.return_item(item);
            continue;
        }

        // Sleep until delivery time (interruptible via event flags)
        const auto wait_ms =
            static_cast<uint32_t>(std::min<int64_t>(*wait_us / US_PER_MS, UINT32_MAX));
        if (wait_ms > 0) {
            cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH | COMMAND_CLEAR, false, true, wait_ms);
            if (cmd & COMMAND_STOP) {
                ring.return_item(item);
                break;
            }
            if (cmd & (COMMAND_FLUSH | COMMAND_CLEAR)) {
                // The held item was taken before the signal, so it predates the boundary and is
                // discarded along with the queued pre-boundary frames.
                ring.return_item(item);
                if (cmd & COMMAND_FLUSH) {
                    self->flush_items();
                }
                if (cmd & COMMAND_CLEAR) {
                    self->discard_to_clear_marker();
                }
                continue;
            }
        }

        if (self->listener == nullptr) {
            ring.return_item(item);
            continue;
        }

        // Decode and deliver. The protocol task hands messages over verbatim, so decode validates
        // each payload's length before reading. Decode out of the item, release it via the
        // guard, then deliver, so a slow listener callback never holds ring space.
        ItemGuard guard{ring, item};
        VisualizerDelivery out = decode_visualizer_message(
            wire_type, inbound_item_data(item), header->data_len, self->spectrum_bin_count,
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
