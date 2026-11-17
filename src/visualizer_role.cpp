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
#include <span>
#include <utility>

static const char* const TAG = "sendspin.visualizer";

// ============================================================================
// Entry format constants
// ============================================================================

// Each frame stays in the inbound ring item it arrived in: its plaintext is
// [wire_type(1)][server_ts(8)][payload], and the item header carries the wire type and the
// payload's offset and length. buffer_capacity is the visualizer's quota of ring storage, not a
// wire-data quota: each frame also costs the ring's per-item overhead, so effective wire-data
// capacity is smaller (see the buffer_capacity note in config.h).
static constexpr size_t ENTRY_TYPE_SIZE = 1;
/// @brief Offset of a frame's payload in its plaintext
static constexpr size_t FRAME_PAYLOAD_OFFSET = ENTRY_TYPE_SIZE + sendspin::BINARY_TIMESTAMP_SIZE;

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

// Drain thread command bits, signalled on its item list's flags (InboundItemList::signal())
static constexpr uint32_t COMMAND_STOP = sendspin::InboundItemList::FIRST_CONSUMER_BIT;
// boundary_ordinal moved on (move_boundary(), recall_frames()).
static constexpr uint32_t COMMAND_BOUNDARY = sendspin::InboundItemList::FIRST_CONSUMER_BIT << 1;
// acked_ordinal moved on (acknowledge()): by the main loop for each stream event it fires or
// finds held_events full for (on_stream_ring_event()), or by the protocol task for one the full
// inbox ring dropped (enqueue_stream_event()).
static constexpr uint32_t COMMAND_ACK = sendspin::InboundItemList::FIRST_CONSUMER_BIT << 2;
static_assert(COMMAND_ACK <= sendspin::InboundItemList::LAST_CONSUMER_BIT,
              "the drain thread's command bits must fit the list's usable event bits");
static constexpr uint32_t DRAIN_COMMANDS = COMMAND_STOP | COMMAND_BOUNDARY | COMMAND_ACK;

// How far boundary_ordinal and drain_passed may trail the ordinals compared with them: a quarter
// of the lifecycle ordinal's range. A run of updating stream/starts moves no boundary, so each
// pulls boundary_ordinal up to this far behind its own ordinal, and each event the main loop
// judges pulls drain_passed up likewise, which keeps every count_after() on them within half the
// range, as acknowledged_through() keeps acked_ordinal near the live ordinal. Only a frame still
// buffered more than 16,384 stream/starts after it arrived turns stale by it. A frame callback
// that blocks through more than half the range of further events can still leave an end held
// until the counter comes round again; frames keep flowing meanwhile.
static constexpr uint16_t ORDINAL_TRAIL = 0x4000;

// ============================================================================
// Big-endian helpers
// ============================================================================

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
    this->stream_object.types.reserve(VISUALIZER_DATA_TYPE_COUNT);
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
    this->event_state->start_slot.bind(inbox, INBOX_TOPIC_VISUALIZER_START);
    this->event_state->passed_slot.bind(inbox, INBOX_TOPIC_VISUALIZER_PASSED);
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
    if (!this->drain_task->inbound.bind(ring, InboundHolder::VISUALIZER)) {
        SS_LOGE(TAG, "Failed to create the visualizer item list");
        return false;
    }

    // So a restart inherits no command from the previous run.
    this->drain_task->inbound.items().clear_signals();

    // Reserved here rather than as the first spectrum frame arrives, where operator new would
    // abort on failure; a consumer that requests no spectrum reserves nothing.
    this->drain_task->spectrum_bins.reserve(this->configured_spectrum_bins());

    platform_configure_thread("SsVis", 4096, static_cast<int>(this->config.priority),
                              this->config.psram_stack);
    this->drain_task->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

bool VisualizerRole::Impl::signal_stop() const {
    if (!this->drain_task || !this->drain_task->drain_thread.joinable()) {
        return false;
    }
    this->drain_task->inbound.items().signal(COMMAND_STOP);
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
    msg.visualizer = visualizer_state;
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

    // Of the other types' lengths, only the timestamp's is checked here; the drain thread checks
    // each one's payload length (decode_visualizer_message()).
    if (message.len < FRAME_PAYLOAD_OFFSET) {
        inbound.note_drop(InboundConsumer::DropReason::TOO_SHORT);
        return;
    }
    size_t data_len = message.len - FRAME_PAYLOAD_OFFSET;

    // roles/visualizer/v1.md "Server -> Client: stream/start visualizer object": each frame is
    // interpreted under the configuration in effect when it was received, which is the one
    // negotiated now, since this thread handles stream/start and the frames in arrival order. So
    // the frame is fitted to it here and decoded with none on the drain thread.
    if (binary_type == SENDSPIN_BINARY_VISUALIZER_SPECTRUM) {
        // "spectrum": n = n_disp_bins. A frame short of them is dropped, uncounted like another
        // type's short payload (decode_visualizer_message()), and bins past them are left out of
        // the hand-over.
        const size_t spectrum_len = sizeof(uint16_t) * this->negotiated_spectrum_bins;
        if (data_len < spectrum_len) {
            return;
        }
        data_len = spectrum_len;
    } else if (binary_type == SENDSPIN_BINARY_VISUALIZER_BEAT && data_len >= BEAT_PAYLOAD_SIZE &&
               !this->negotiated_tracks_downbeats) {
        // "beat": bit 0 is only meaningful when tracks_downbeats is true, so a server setting it
        // anyway reports no downbeat.
        message.data[FRAME_PAYLOAD_OFFSET] &= static_cast<uint8_t>(~BEAT_FLAG_DOWNBEAT);
    }

    (void)inbound.hand_message(message,
                               {.data_len = static_cast<uint32_t>(data_len),
                                .serial = this->lifecycle_ordinal,
                                .type = binary_type,
                                .data_offset = static_cast<uint8_t>(FRAME_PAYLOAD_OFFSET)},
                               generation);
}

// ============================================================================
// Stream lifecycle (protocol task)
// ============================================================================

void VisualizerRole::Impl::handle_stream_start(const VisualizerStreamPayload& stream) {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // Cache stream config for handle_binary (same thread).
    // roles/visualizer/v1.md "Server -> Client: stream/start": `types` "MUST be a subset of the
    // types the client requested", and the spectrum object "MUST match the client's current
    // requested configuration". A served type outside the request is dropped, and so is spectrum
    // with no object or one that does not match; the rest of the stream flows.
    const auto type_bit = [](VisualizerDataType type) -> uint8_t {
        return static_cast<uint8_t>(1U << (wire_type_for(type) - SENDSPIN_BINARY_VISUALIZER_FIRST));
    };
    uint8_t requested_mask = 0;
    for (const VisualizerDataType type : this->config.stream.types) {
        requested_mask |= type_bit(type);
    }
    uint8_t served_mask = 0;
    stream.types.for_each([&](VisualizerDataType type) { served_mask |= type_bit(type); });
    uint8_t types_mask = served_mask & requested_mask;

    uint8_t bin_count = 0;
    const uint8_t spectrum_bit = type_bit(VisualizerDataType::SPECTRUM);
    if ((types_mask & spectrum_bit) != 0) {
        const std::optional<VisualizerSpectrumConfig>& requested = this->config.stream.spectrum;
        // Fewer bins than requested match: "Servers MAY impose an implementation-defined upper
        // bound on n_disp_bins". More would also outgrow the bins start() reserved.
        if (stream.spectrum.has_value() && requested.has_value() &&
            stream.spectrum->n_disp_bins <= this->configured_spectrum_bins() &&
            stream.spectrum->scale == requested->scale &&
            stream.spectrum->f_min == requested->f_min &&
            stream.spectrum->f_max == requested->f_max) {
            bin_count = stream.spectrum->n_disp_bins;
        } else {
            types_mask &= static_cast<uint8_t>(~spectrum_bit);
        }
    }
    if (served_mask != types_mask) {
        SS_LOGW(TAG,
                "Visualizer stream/start breaks roles/visualizer/v1.md (types MUST be a subset of "
                "the request, spectrum MUST match it); dropping types mask 0x%02x (bit N: wire "
                "type %u + N)",
                static_cast<unsigned>(served_mask & ~types_mask),
                static_cast<unsigned>(SENDSPIN_BINARY_VISUALIZER_FIRST));
    }

    // The main loop reports the admitted stream: only the types kept, and tracks_downbeats only
    // with beat, the frames it describes.
    const auto admits = [&](VisualizerDataType type) { return (types_mask & type_bit(type)) != 0; };
    VisualizerStream admitted;
    admitted.loudness = admits(VisualizerDataType::LOUDNESS);
    admitted.beat = admits(VisualizerDataType::BEAT);
    admitted.f_peak = admits(VisualizerDataType::F_PEAK);
    admitted.spectrum = admits(VisualizerDataType::SPECTRUM);
    admitted.peak = admits(VisualizerDataType::PEAK);
    admitted.tracks_downbeats = admitted.beat && stream.tracks_downbeats;
    admitted.rate_max = stream.rate_max;

    // roles/visualizer/v1.md "Server -> Client: stream/start visualizer object": one that updates
    // the running stream keeps the buffered frames, each fitted already to the configuration it
    // arrived under (handle_binary()), so only a new stream is a boundary. Every frame from here
    // on carries this start's ordinal, so the drain thread holds it until the main loop has fired
    // the start (is_acknowledged()).
    const bool update = this->stream_active;
    this->negotiated_spectrum_bins = bin_count;
    this->negotiated_tracks_downbeats = admitted.tracks_downbeats;
    this->negotiated_types_mask = types_mask;
    this->stream_active = true;
    uint16_t ordinal = 0;
    if (update) {
        ordinal = this->next_ordinal();
        // See ORDINAL_TRAIL. No event waits for the trail, and the frames it dates stale arrived
        // ORDINAL_TRAIL starts ago or earlier, so it recalls nothing and wakes no thread: the
        // drain thread reads it at its next staleness check or report.
        const auto trail = static_cast<uint16_t>(ordinal - ORDINAL_TRAIL);
        if (count_after(trail, this->boundary_ordinal.load(std::memory_order_relaxed))) {
            this->boundary_ordinal.store(trail, std::memory_order_release);
        }
    } else {
        ordinal = this->move_boundary();
        this->recall_frames();
    }

    // The notice before the event, so the main loop that takes the event finds it, or a later
    // start's. The event carries `generation`, so a start queued before a teardown is never
    // reported.
    this->event_state->start_slot.write(
        StartNotice{.stream = admitted, .spectrum_bins = bin_count, .ordinal = ordinal});
    this->enqueue_stream_event(VisualizerEventType::STREAM_START, generation, ordinal);
}

void VisualizerRole::Impl::handle_stream_end() {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    this->stream_active = false;
    this->negotiated_types_mask = 0;

    // roles/visualizer/v1.md "stream/end": every listed frame is now stale. The boundary moves
    // before the event is queued, so the drain thread can pass it by the time the main loop holds
    // the event for it.
    const uint16_t ordinal = this->move_boundary();
    this->recall_frames();

    this->enqueue_stream_event(VisualizerEventType::STREAM_END, generation, ordinal);
}

void VisualizerRole::Impl::handle_stream_clear() {
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);
    // messaging.md "stream/clear": buffered frames are discarded, later ones still flow, each held
    // by the drain thread until the main loop has fired the clear.
    const uint16_t ordinal = this->move_boundary();
    this->recall_frames();

    this->enqueue_stream_event(VisualizerEventType::STREAM_CLEAR, generation, ordinal);
}

void VisualizerRole::Impl::enqueue_stream_event(VisualizerEventType event, uint32_t generation,
                                                uint16_t ordinal) {
    const char* name = "STREAM_CLEAR";
    if (event == VisualizerEventType::STREAM_START) {
        name = "STREAM_START";
    } else if (event == VisualizerEventType::STREAM_END) {
        name = "STREAM_END";
    }
    // A dropped event never fires, so it is acknowledged here, or the drain thread would hold
    // every later frame for it until each is dropped late. The stream keeps its frames but loses
    // their order against the dropped event's callback, so the drop logs at ERROR, as the
    // player's stream events do.
    if (!push_event_or_log(this->inbox, InboxEventType::VISUALIZER_STREAM,
                           static_cast<uint8_t>(event), TAG, name, generation,
                           /*error_level=*/true, ordinal)) {
        this->acknowledge(acknowledged_through(event, ordinal));
    }
}

// ============================================================================
// Event dispatch (main thread): the stream events the ring drain in
// SendspinClient::drain_inbox() hands over, fired from the role drain
// ============================================================================

void VisualizerRole::Impl::on_stream_ring_event(const InboxEvent& event) {
    if (this->held_events.size() == Inbox::EVENT_CAPACITY) {
        // Acknowledged as a dropped push is (enqueue_stream_event()).
        SS_LOGE(TAG, "Visualizer stream events held for the drain thread are full; dropping one");
        this->acknowledge(
            acknowledged_through(static_cast<VisualizerEventType>(event.code), event.serial));
        return;
    }
    this->held_events.push_back(event);
}

void VisualizerRole::Impl::drain_events() {
    // The passed note is taken before the events are judged against it, so a boundary the drain
    // thread passes after this sets the bit again for the next drain.
    uint16_t passed = 0;
    if (this->event_state->passed_slot.take(passed)) {
        this->drain_passed = passed;
    }
    // A joined drain thread runs no frame callback, so nothing is held for it: stop() joins it
    // before the teardown whose end this delivers.
    const bool drain_running = this->drain_task->drain_thread.joinable();
    // An event a teardown has overtaken since it was held fires nothing: the next drain's
    // catch-up replaces it with the end the teardown owes (complete_teardown()), and its frames
    // are stale.
    const uint32_t generation = this->cleanup_generation.load(std::memory_order_acquire);

    this->awaiting_drain = false;
    size_t processed = 0;
    for (const InboxEvent& event : this->held_events) {
        // See ORDINAL_TRAIL. Every event ahead of this one has been processed, and none behind
        // it is numbered ORDINAL_TRAIL before it while the main loop keeps up, so the pull
        // passes no boundary an event awaits.
        const auto trail = static_cast<uint16_t>(event.serial - ORDINAL_TRAIL);
        if (count_after(trail, this->drain_passed)) {
            this->drain_passed = trail;
        }
        const auto type = static_cast<VisualizerEventType>(event.code);
        if (!event_is_current(event.epoch, generation, TAG, "a held visualizer stream event")) {
            ++processed;
            continue;
        }
        if (type != VisualizerEventType::STREAM_START && drain_running &&
            count_after<uint16_t>(event.serial, this->drain_passed)) {
            // Wait for the drain thread to pass this boundary before firing this and anything
            // after it. It writes passed_slot when it does, which runs this drain again.
            this->awaiting_drain = true;
            break;
        }
        bool fired = true;
        switch (type) {
            case VisualizerEventType::STREAM_START: {
                // A start a later stream/start superseded fires and acknowledges nothing: the
                // later notice describes a newer configuration, and the later start's
                // acknowledgement, after that notice, releases this start's frames, as frames
                // received before an in-place start may follow its notice. A boundary between
                // the two makes them stale instead.
                StartNotice notice{.ordinal = event.serial};
                fired = this->take_start_notice(event.serial, notice);
                if (fired) {
                    this->fire_stream_start(notice);
                } else {
                    this->owed_start_ordinal = notice.ordinal;
                }
                this->start_owed = !fired;
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
        if (fired) {
            uint16_t through = acknowledged_through(type, event.serial);
            if (type == VisualizerEventType::STREAM_CLEAR && this->start_owed) {
                // See acknowledged_through()
                if (count_after<uint16_t>(this->owed_start_ordinal, event.serial)) {
                    through = static_cast<uint16_t>(event.serial - 1);
                } else {
                    this->start_owed = false;
                }
            }
            this->acknowledge(through);
        }
        ++processed;
    }
    while (processed-- > 0) {
        this->held_events.erase(this->held_events.begin());
    }
}

bool VisualizerRole::Impl::take_start_notice(uint16_t ordinal, StartNotice& out) const {
    bool taken = false;
    this->event_state->start_slot.edit([&out, &taken, ordinal](StartNotice& pending) {
        out = pending;
        if (pending.ordinal != ordinal) {
            return true;  // A later start's: left for its own STREAM_START
        }
        taken = true;
        return false;
    });
    return taken;
}

void VisualizerRole::Impl::fire_stream_start(const StartNotice& notice) {
    const VisualizerStream& stream = notice.stream;
    if (this->listener == nullptr) {
        return;
    }
    this->listener->on_visualizer_stream_started(stream);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ServerVisualizerStreamObject& out = this->stream_object;
    out.types.clear();
    // In enumerator order, as the deprecated object lists them.
    const std::pair<bool, VisualizerDataType> types[] = {
        {stream.beat, VisualizerDataType::BEAT},
        {stream.loudness, VisualizerDataType::LOUDNESS},
        {stream.f_peak, VisualizerDataType::F_PEAK},
        {stream.spectrum, VisualizerDataType::SPECTRUM},
        {stream.peak, VisualizerDataType::PEAK},
    };
    for (const auto& [admitted, type] : types) {
        if (admitted) {
            out.types.push_back(type);
        }
    }
    out.rate_max = stream.rate_max;
    out.tracks_downbeats = stream.tracks_downbeats;
    // The admitted spectrum matches the request but for a bin count it may lower
    // (handle_stream_start()).
    out.spectrum.reset();
    if (stream.spectrum && this->config.stream.spectrum.has_value()) {
        out.spectrum = this->config.stream.spectrum;
        out.spectrum->n_disp_bins = notice.spectrum_bins;
    }
    this->listener->on_visualizer_stream_start(out);
#pragma GCC diagnostic pop
}

void VisualizerRole::Impl::acknowledge(uint16_t ordinal) {
    // Forward only: the protocol task's acknowledgement of a dropped event can pass events the
    // main loop has yet to fire, whose own acknowledgements then change nothing. Release pairs
    // with is_acknowledged()'s acquire, so a frame the drain thread delivers on this
    // acknowledgement follows the callbacks fired before it.
    uint16_t acked = this->acked_ordinal.load(std::memory_order_relaxed);
    do {
        if (!count_after(ordinal, acked)) {
            return;
        }
    } while (!this->acked_ordinal.compare_exchange_weak(acked, ordinal, std::memory_order_release,
                                                        std::memory_order_relaxed));
    if (this->drain_task->inbound.ring() != nullptr) {
        this->drain_task->inbound.items().signal(COMMAND_ACK);
    }
}

uint16_t VisualizerRole::Impl::acknowledged_through(VisualizerEventType type, uint16_t ordinal) {
    // An end acknowledges through the ordinal before its own. Its own is a boundary, so every
    // frame stamped before it is stale and this releases none, while its own can be a later
    // start's, whose frames still wait: the end a teardown owes takes the boundary it reads then
    // (complete_teardown()). Acknowledging at every end keeps acked_ordinal, which
    // is_acknowledged() compares with count_after(), within half the counter's range of the live
    // ordinal through a run of ends and teardowns that fires no start or clear.
    //
    // drain_events() acknowledges a clear through the ordinal before its own too, in place of the
    // clear's own this returns, while a start superseded by one queued after the clear has fired
    // nothing (start_owed, owed_start_ordinal): the clear's frames arrived under the superseded
    // start's configuration, which no fired notice describes, so they wait for the later start's
    // acknowledgement, which follows its notice. Every frame stamped before the clear is stale,
    // so this releases none, and none is stranded: the later start fires, or is itself superseded
    // by a later start, whose acknowledgement follows, or is lost and acknowledged where it is
    // lost, past the clear either way, or a teardown overtakes it, whose boundary makes the
    // clear's frames stale. A clear behind a superseding start queued before it acknowledges its
    // own ordinal and ends start_owed: that start was lost or overtaken by a teardown, so the
    // frames are ordered against nothing, and no later clear waits for it either. An end or a
    // teardown leaves start_owed set: no frame is admitted after either until a stream/start, whose
    // STREAM_START sets start_owed afresh, and the frames of a clear behind such a start that is
    // lost still wait for an owed start queued after the clear.
    if (type == VisualizerEventType::STREAM_END) {
        return static_cast<uint16_t>(ordinal - 1);
    }
    return ordinal;
}

// ============================================================================
// Cleanup (protocol task, or the main loop in stop() once it is joined)
// ============================================================================

void VisualizerRole::Impl::cleanup() {
    // The boundary before the generation, so a main loop that sees the new generation reads it
    // (complete_teardown()). Every frame stamped before it is stale.
    (void)this->move_boundary();

    // Stamps every event queued from here on, so an event queued for the stream this teardown
    // ends is discarded (see cleanup_generation).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->stream_active = false;
    this->negotiated_types_mask = 0;

    // Returns the frames the drain thread has not taken (one it takes before this carries the
    // earlier stamp, which its take() discards) and a frame it holds.
    this->recall_frames();

    // Stale ring-borne events (an in-flight STREAM_START/STREAM_END/STREAM_CLEAR queued before
    // this teardown) need no per-event ring reset either way: on the connection-loss path
    // SendspinClient::cleanup_connection_state()'s inbox.reset_events() has already wiped them,
    // and on the deactivation path, which leaves the ring alone for the roles that stay active,
    // they carry the generation this teardown just left behind and the drain discards them (see
    // event_is_current()).
    push_event_or_log(this->inbox, InboxEventType::VISUALIZER_CLEARED, 0, TAG,
                      "visualizer cleared event", generation);
}

void VisualizerRole::Impl::complete_teardown() {
    // The events the teardown overtook, replaced by the end it owes the listener, numbered with
    // the teardown's boundary (or a later one): drain_events() fires it once the drain thread has
    // passed that, so no frame callback of the torn-down stream follows it.
    this->held_events.clear();
    InboxEvent end{};
    end.type = InboxEventType::VISUALIZER_STREAM;
    end.code = static_cast<uint8_t>(VisualizerEventType::STREAM_END);
    end.epoch = this->cleanup_generation.load(std::memory_order_acquire);
    end.serial = this->boundary_ordinal.load(std::memory_order_acquire);
    this->held_events.push_back(end);
    this->awaiting_drain = false;
}

// ============================================================================
// Drain thread helpers
// ============================================================================

std::optional<int64_t> visualizer_delivery_wait_us(int64_t client_ts, int32_t display_offset_ms,
                                                   bool acknowledged, int64_t now) {
    const int64_t deliver_at_us = client_ts - static_cast<int64_t>(display_offset_ms) * US_PER_MS;
    const int64_t drop_at_us = deliver_at_us + VISUALIZER_MAX_DELIVERY_LAG_US;
    if (now > drop_at_us) {
        return std::nullopt;
    }
    return std::max<int64_t>((acknowledged ? deliver_at_us : drop_at_us) - now, 0);
}

VisualizerDelivery decode_visualizer_message(uint8_t wire_type, const uint8_t* payload,
                                             size_t payload_len,
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
            out.downbeat = (payload[0] & BEAT_FLAG_DOWNBEAT) != 0;
            break;
        case SENDSPIN_BINARY_VISUALIZER_F_PEAK:
            if (payload_len < F_PEAK_PAYLOAD_SIZE) {
                break;
            }
            out.kind = VisualizerDelivery::Kind::F_PEAK;
            out.frequency_hz = read_be16(payload);
            out.amplitude = read_be16(payload + 2);
            break;
        case SENDSPIN_BINARY_VISUALIZER_SPECTRUM: {
            // handle_binary() cut the payload to the frame's own n_disp_bins.
            const size_t bins = payload_len / sizeof(uint16_t);
            spectrum_out.resize(bins);
            for (size_t b = 0; b < bins; ++b) {
                spectrum_out[b] = read_be16(payload + b * sizeof(uint16_t));
            }
            out.kind = VisualizerDelivery::Kind::SPECTRUM;
            break;
        }
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

uint16_t VisualizerRole::Impl::move_boundary() {
    const uint16_t ordinal = this->next_ordinal();
    // Release pairs with is_stale()'s acquire. The drain thread's wake (recall_frames()) follows
    // the store, so the woken thread reads the new value.
    this->boundary_ordinal.store(ordinal, std::memory_order_release);
    return ordinal;
}

void VisualizerRole::Impl::recall_frames() const {
    // Every listed frame predates the boundary, since the protocol task is the only appender.
    InboundConsumer& inbound = this->drain_task->inbound;
    inbound.recall();
    if (inbound.ring() != nullptr) {
        inbound.items().signal(COMMAND_BOUNDARY);
    }
}

uint8_t VisualizerRole::Impl::configured_spectrum_bins() const {
    const VisualizerStreamConfig& stream = this->config.stream;
    if (!stream.spectrum.has_value() ||
        std::find(stream.types.begin(), stream.types.end(), VisualizerDataType::SPECTRUM) ==
            stream.types.end()) {
        return 0;
    }
    return stream.spectrum->n_disp_bins;
}

bool VisualizerRole::Impl::is_stale(void* item) const {
    return count_after<uint16_t>(this->boundary_ordinal.load(std::memory_order_acquire),
                                 inbound_item_header(item)->serial);
}

bool VisualizerRole::Impl::is_acknowledged(void* item) const {
    return !count_after<uint16_t>(inbound_item_header(item)->serial,
                                  this->acked_ordinal.load(std::memory_order_acquire));
}

void VisualizerRole::Impl::drain_thread_func(VisualizerRole::Impl* self) {
    SS_LOGD(TAG, "Drain thread started");

    // Bound by start() before this thread exists and unbound by stop() only after it is joined.
    InboundRing& ring = *self->drain_task->inbound.ring();
    InboundItemList& items = self->drain_task->inbound.items();
    const int32_t offset_ms = self->config.display_offset_ms;

    // Resized within the capacity start() reserved: handle_stream_start() admits spectrum only
    // within it, and handle_binary() cuts each frame to the admitted count.
    std::vector<uint16_t>& spectrum_bins = self->drain_task->spectrum_bins;

    // Returns the ring item exactly once: a skip leaves it to the destructor, and delivery
    // releases it before the listener callback so a slow callback never holds ring space.
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

    // The frames' spectrum configuration: the requested one, which a stream's spectrum matches
    // but for the bin count each frame carries (handle_stream_start()).
    VisualizerSpectrumConfig spectrum_config =
        self->config.stream.spectrum.value_or(VisualizerSpectrumConfig{});

    // Reports the latest boundary this thread has seen to the main loop, which holds a
    // STREAM_END or STREAM_CLEAR until it has (drain_events()). Called only outside a frame
    // callback, before each wait: every staleness check after it loads that boundary or a later
    // one, so no frame stamped before it is delivered from then on.
    bool reported = false;
    uint16_t reported_boundary = 0;
    const auto report_passed = [&] {
        const uint16_t boundary = self->boundary_ordinal.load(std::memory_order_acquire);
        if (!reported || boundary != reported_boundary) {
            reported = true;
            reported_boundary = boundary;
            self->event_state->passed_slot.write(boundary);
        }
    };

    while (true) {
        if (items.take_signals(DRAIN_COMMANDS, 0) & COMMAND_STOP) {
            break;
        }
        report_passed();

        // A command ends the take early with nullptr.
        void* item = self->drain_task->inbound.take(INBOUND_CONSUMER_FALLBACK_WAKE_MS,
                                                    self->cleanup_generation);
        if (item == nullptr) {
            continue;
        }
        ItemGuard guard{ring, item};
        const InboundItemHeader* header = inbound_item_header(item);

        // Waiting for time sync.
        if (!self->client->is_time_synced()) {
            continue;
        }

        const uint8_t wire_type = header->type;
        const int64_t server_ts = be64_to_host(inbound_item_bytes(item) + ENTRY_TYPE_SIZE);
        int64_t client_ts = self->client->get_client_time(server_ts);

        if (client_ts == 0) {
            continue;
        }

        // Wait for the delivery time, and first for the main loop to have fired every stream
        // event queued before the frame arrived (is_acknowledged()), which a frame waits for no
        // later than its lag bound before it is dropped as late: the frame keeps its ring item
        // through both, as it does for its delivery time. Every command wakes the wait to judge
        // the frame again; the first one to run out with the frame acknowledged delivers it.
        bool stop = false;
        bool deliver = false;
        bool ran_out = false;
        while (!self->is_stale(item)) {
            const bool acknowledged = self->is_acknowledged(item);
            const std::optional<int64_t> left_us =
                visualizer_delivery_wait_us(client_ts, offset_ms, acknowledged, platform_time_us());
            if (!left_us.has_value()) {
                break;
            }
            if (ran_out || *left_us < US_PER_MS) {
                deliver = acknowledged;
                break;
            }
            report_passed();
            const auto wait_ms =
                static_cast<uint32_t>(std::min<int64_t>(*left_us / US_PER_MS, UINT32_MAX));
            const uint32_t cmd = items.take_signals(DRAIN_COMMANDS, wait_ms);
            stop = (cmd & COMMAND_STOP) != 0;
            if (stop) {
                break;
            }
            ran_out = cmd == 0;
        }
        if (stop) {
            break;
        }
        // A boundary landing after the last staleness check still reaches the decode; the main
        // loop holds its event until this thread reports passing it after the callback.
        if (!deliver) {
            continue;
        }

        if (self->listener == nullptr) {
            continue;
        }

        // Decode and deliver. The protocol task fits only spectrum and beat frames to their
        // stream, so decode validates each payload's length before reading. Decode out of the
        // item, release it via the guard, then deliver, so a slow listener callback never holds
        // ring space.
        VisualizerDelivery out = decode_visualizer_message(wire_type, inbound_item_data(item),
                                                           header->data_len, spectrum_bins);
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
                spectrum_config.n_disp_bins = static_cast<uint8_t>(spectrum_bins.size());
                self->listener->on_spectrum_bins(
                    client_ts, std::span<const uint16_t>(spectrum_bins), spectrum_config);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                self->listener->on_spectrum(client_ts, spectrum_bins);
#pragma GCC diagnostic pop
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
