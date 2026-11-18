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

/// @file visualizer_role_impl.h
/// @brief Private implementation for the visualizer role (pimpl)

#pragma once

#include "inbound_ring.h"
#include "inbox.h"
#include "inline_vector.h"
#include "protocol_messages.h"
#include "sendspin/visualizer_role.h"
#include "teardown_tracker.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred visualizer event types (used internally in the visualizer role). Each carries
/// its lifecycle ordinal in InboxEvent::serial.
enum class VisualizerEventType : uint8_t {
    STREAM_START,
    STREAM_END,
    STREAM_CLEAR,
};

/// @brief Result of decoding one visualizer wire message, ready to hand to the listener.
/// A kind of None means the entry was malformed, short, or non-deliverable and should be dropped.
/// For Spectrum, the decoded bins are written into the caller-supplied scratch vector.
struct VisualizerDelivery {
    enum class Kind : uint8_t { NONE, LOUDNESS, BEAT, F_PEAK, SPECTRUM, PEAK };
    Kind kind{Kind::NONE};
    uint16_t loudness{0};
    bool downbeat{false};
    uint16_t frequency_hz{0};
    uint16_t amplitude{0};
    uint8_t strength{0};
};

/// @brief Validates and decodes one visualizer entry payload. Pure drain-thread logic with no I/O,
/// factored out so it can be unit tested independently of the client and drain thread. It needs
/// no stream configuration: handle_binary() already fitted the frame to the one it arrived under.
/// @param wire_type    SENDSPIN_BINARY_VISUALIZER_* type byte.
/// @param payload      Bytes following the entry's wire-type byte and 8-byte timestamp.
/// @param spectrum_out Scratch vector reused for SPECTRUM bins, resized to one bin per two
///                     payload bytes, within the capacity start() reserved.
/// @return What to deliver; Kind::None if the entry is malformed, short, or non-deliverable.
VisualizerDelivery decode_visualizer_message(uint8_t wire_type, const uint8_t* payload,
                                             size_t payload_len,
                                             std::vector<uint16_t>& spectrum_out);

/// @brief How far past its delivery time a frame may still be delivered, so frames sharing a
/// timestamp all reach the listener when it takes them one after another; past it, the frame is
/// dropped rather than replayed late.
static constexpr int64_t VISUALIZER_MAX_DELIVERY_LAG_US = 20000;

/// @brief Decides when the drain thread delivers a frame, judged again on every wake. Pure, so
/// the timing rules are unit tested with `now` as an argument.
///
/// roles/visualizer/v1.md "Visualization Data (Binary)": a frame is delivered display_offset_ms
/// ahead of its display time (negative delays it), or at once when that has passed, and dropped
/// once it is more than VISUALIZER_MAX_DELIVERY_LAG_US past that delivery time, acknowledged or
/// not, so a frame awaiting its acknowledgement waits no later than that.
/// @param client_ts         Display time in client time.
/// @param display_offset_ms VisualizerRoleConfig::display_offset_ms.
/// @param acknowledged      Whether every stream event queued before the frame arrived has fired
///                          (VisualizerRole::Impl::is_acknowledged()).
/// @param now               The current platform_time_us().
/// @return Microseconds to wait: until the delivery time when acknowledged (0 to deliver now),
///         otherwise until the lag bound; or std::nullopt to drop.
std::optional<int64_t> visualizer_delivery_wait_us(int64_t client_ts, int32_t display_offset_ms,
                                                   bool acknowledged, int64_t now);

/// @brief Private implementation of the visualizer role
struct VisualizerRole::Impl : RoleTeardown {
    explicit Impl(VisualizerRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Nested types
    // ========================================

    /// @brief Persistent drain thread context and the visualizer's end of the inbound ring,
    /// through which the protocol task hands it frames
    struct DrainTask {
        /// Its item list's flags also carry the drain thread's command bits.
        InboundConsumer inbound;
        std::thread drain_thread;
        /// The bins on_spectrum_bins() views and on_spectrum() receives, reserved by start() for
        /// configured_spectrum_bins(), beyond which no spectrum is admitted, so the drain thread
        /// never grows it. Main loop in start() before the thread is spawned, then the drain
        /// thread.
        std::vector<uint16_t> spectrum_bins;
    };

    /// @brief A stream/start as admitted, for the main loop to report (fire_stream_start())
    struct StartNotice {
        VisualizerStream stream{};
        /// The admitted spectrum n_disp_bins, 0 unless stream.spectrum, for the deprecated
        /// ServerVisualizerStreamObject.
        uint8_t spectrum_bins{0};
        /// The lifecycle ordinal of the STREAM_START this notice belongs to.
        uint16_t ordinal{0};
    };

    /// @brief What the protocol task and the drain thread hand the main loop beside the stream
    /// events (see docs/internals.md "Visualizer Stream Events")
    struct EventState {
        /// The latest stream/start's notice, overwritten by the next one (latest-wins). The main
        /// loop reports it at the STREAM_START numbered with its ordinal, and an earlier
        /// STREAM_START, which it supersedes, reports nothing. A notice whose STREAM_START the
        /// main loop never reaches (queued before a teardown, or dropped by the full event ring)
        /// stays until the next start overwrites it; its topic bit wakes nothing, since the
        /// STREAM_START events drive the drain. Protocol task to main loop.
        InboxSlot<StartNotice> start_slot;
        /// The latest boundary ordinal the drain thread has passed (boundary_ordinal, loaded
        /// outside any frame callback), written each time it moves on, so a STREAM_END or
        /// STREAM_CLEAR the main loop holds for it is re-examined then (see awaiting_drain).
        InboxSlot<uint16_t> passed_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    /// @param ring The client's inbound ring for this run, which the drain thread's item list
    ///        links.
    bool start(InboundRing* ring);
    void build_hello_fields(ClientHelloMessage& msg) const;
    /// @brief The buffer_capacity client/hello advertises: the share of the quota left for wire
    /// data (see BUFFER_ADVERTISE_DIVISOR in visualizer_role.cpp), which also bounds the longest
    /// message the server sends.
    size_t advertised_buffer_capacity() const;
    /// @brief Inbound ring storage the requested stream arrives at per second: every requested
    /// type at rate_max, each frame at its stored size (a spectrum frame with the configured bin
    /// count), for the ring's pass-through budget (InboundRingBudget).
    size_t stored_frame_bytes_per_second() const;
    void build_state_fields(ClientStateMessage& msg) const;
    // Each handler loads the role's teardown generation once at entry and stamps what it queues
    // with it; see RoleTeardown. All run on the protocol task.
    /// @brief Hands a frame to the drain thread: by its ring item when it has one (clearing
    /// `message.item`), otherwise copied into an item the protocol task acquires.
    /// @param message The decrypted frame; `data` points at its message type byte.
    void handle_binary(uint8_t binary_type, InboundMessage& message);
    void handle_stream_start(const VisualizerStreamPayload& stream);
    void handle_stream_end();
    void handle_stream_clear();
    /// @brief A stream/clear with from_timestamp: discards the frames at or after `from_us` and
    /// keeps the earlier ones. No stream event: the stream continues for the listener.
    void handle_stream_clear_from(int64_t from_us);
    /// @brief Holds a current VISUALIZER_STREAM event in held_events for drain_events() to fire,
    /// or acknowledges one that finds it full. Main loop.
    void on_stream_ring_event(const InboxEvent& event);
    /// True if this tick has drainable visualizer work: the drain thread having passed a boundary
    /// (passed_slot) while a STREAM_END or STREAM_CLEAR waits for it, or events in held_events,
    /// appended by on_stream_ring_event() during this tick's ring dispatch or by a teardown's
    /// catch-up (complete_teardown()), that are not held for the drain thread.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_VISUALIZER_PASSED) != 0 ||
               (!this->held_events.empty() && !this->awaiting_drain);
    }
    /// @brief Fires held_events in order, holding a STREAM_END or STREAM_CLEAR, and everything
    /// behind it, until the drain thread has passed its boundary, and acknowledging each event to
    /// the drain thread once its callbacks return (acknowledged_through()). Skips an event a
    /// teardown has since overtaken, and a STREAM_START a later one supersedes. Main loop.
    void drain_events();
    /// @brief The main-loop teardown half: replaces the events the teardown overtook with the
    /// stream end it owes the listener (on_visualizer_stream_end()), which drain_events() fires
    /// once the drain thread has passed the teardown's boundary. It leaves the other main-loop
    /// state: stream_object, refilled by each STREAM_START, and start_owed (see
    /// acknowledged_through()). Main loop only, through catch_up_teardown().
    void complete_teardown();

    /// @brief Stops the role and discards its state. Protocol task, or the main loop in
    /// SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Queues VISUALIZER_CLEARED,
    /// stamped with the new generation, for the main loop to catch up on (catch_up_teardown()).
    void cleanup();

    // ========================================
    // Internal helpers
    // ========================================

    /// @brief Asks the drain thread to exit without waiting for it; stop() joins. Lets a caller
    /// overlap the thread's exit with other teardown.
    /// @return true if a running thread was signalled, false if none was running.
    bool signal_stop() const;
    /// @brief Joins the drain thread and returns every frame it had not taken to the ring
    void stop() const;
    /// @brief Takes the next lifecycle ordinal for a stream event or a teardown. Protocol task.
    uint16_t next_ordinal() {
        return ++this->lifecycle_ordinal;
    }
    /// @brief Makes the next lifecycle ordinal a boundary: every frame stamped before it is stale
    /// from here on. Protocol task.
    /// @return The boundary's ordinal.
    uint16_t move_boundary();
    /// @brief Returns every listed frame to the ring and signals the drain thread, which returns
    /// a frame it holds once it sees the boundary move_boundary() made, when one is running.
    void recall_frames() const;
    /// @brief Whether a boundary has passed since `item` was listed. Drain thread.
    bool is_stale(void* item) const;
    /// @brief Whether the main loop has fired every stream event queued before `item` was listed.
    /// Drain thread.
    bool is_acknowledged(void* item) const;
    /// @brief Tells the drain thread every stream event up to `ordinal` has fired or never will,
    /// moving acked_ordinal on to it unless it is there already. The main loop, or the protocol
    /// task for an event the full inbox ring dropped (enqueue_stream_event()).
    void acknowledge(uint16_t ordinal);
    /// @brief The ordinal that firing (or losing) a `type` event numbered `ordinal` acknowledges
    /// through: its own for a STREAM_START or STREAM_CLEAR, the one before it for a STREAM_END.
    static uint16_t acknowledged_through(VisualizerEventType type, uint16_t ordinal);
    /// @brief Takes the notice of the STREAM_START numbered `ordinal` from start_slot.
    /// @return false when a later stream/start's notice has replaced it, which stays for its own
    ///         STREAM_START and is copied to `out`.
    bool take_start_notice(uint16_t ordinal, StartNotice& out) const;
    /// @brief Fires on_visualizer_stream_started() and then the deprecated
    /// on_visualizer_stream_start() with a STREAM_START's admitted stream. Main loop.
    void fire_stream_start(const StartNotice& notice);
    /// @brief The spectrum bins the configuration requests: n_disp_bins when its types include
    /// SPECTRUM, otherwise none.
    uint8_t configured_spectrum_bins() const;
    /// Queues a stream lifecycle event numbered `ordinal` and stamped with `generation`, which the
    /// drain compares against the live counter before dispatching it. One the full ring drops is
    /// acknowledged here instead, so no frame waits for it.
    void enqueue_stream_event(VisualizerEventType event, uint32_t generation, uint16_t ordinal);

    static void drain_thread_func(VisualizerRole::Impl* self);

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    /// Fixed at construction: client/state snapshots view its stream types
    /// (ClientVisualizerStateObject::types).
    VisualizerRoleConfig config;
    VisualizerSupportObject visualizer_support;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    /// The stream the deprecated on_visualizer_stream_start() reports, filled in place from each
    /// STREAM_START into the types capacity the constructor reserves for every type, so a fill
    /// never allocates. Main loop.
    ServerVisualizerStreamObject stream_object{};
#pragma GCC diagnostic pop
    /// The stream events taken from the inbox ring, oldest first, while a STREAM_END or
    /// STREAM_CLEAR at their head waits for the drain thread. As many as the inbox event ring
    /// holds, a policy rather than a bound: each drain can add a full ring's worth while the head
    /// waits. One arriving while this is full is dropped with an error and acknowledged
    /// (on_stream_ring_event()), so no frame waits for it. Main loop.
    InlineVector<InboxEvent, Inbox::EVENT_CAPACITY> held_events;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<DrainTask> drain_task;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    VisualizerRoleListener* listener{nullptr};

    // Atomic fields
    /// The lifecycle ordinal of the latest boundary (a stream/start with no stream running,
    /// stream/end, stream/clear, a teardown), or of the trail an updating stream/start pulls it up
    /// to when that is later (ORDINAL_TRAIL in visualizer_role.cpp): a frame stamped before it is
    /// stale. Written by move_boundary() and handle_stream_start() on the protocol task (or the
    /// main loop in stop() after the join), with release; read with acquire on the drain thread
    /// and, for a teardown's owed end, the main loop (complete_teardown()).
    std::atomic<uint16_t> boundary_ordinal{0};
    /// The lifecycle ordinal through which every stream event has fired, or was dropped: a frame
    /// stamped later waits for it. Moved only forward by acknowledge(), with release, on the main
    /// loop and, for a dropped event, the protocol task; read with acquire on the drain thread.
    std::atomic<uint16_t> acked_ordinal{0};

    // 16-bit fields
    /// Counts the stream events the role queues (every stream/start, stream/end and stream/clear)
    /// and its teardowns, wrapping. handle_binary() stamps each frame with it
    /// (InboundItemHeader::serial). Protocol task only, like negotiated_types_mask.
    uint16_t lifecycle_ordinal{0};
    /// The latest boundary ordinal the drain thread reported passing (passed_slot), pulled up
    /// behind each event drain_events() judges (ORDINAL_TRAIL in visualizer_role.cpp). Main loop.
    uint16_t drain_passed{0};
    /// While start_owed, the ordinal of the latest notice in start_slot when the superseded
    /// STREAM_START was processed, the later start it waits for. Main loop.
    uint16_t owed_start_ordinal{0};

    // 8-bit fields
    /// Bitmask of negotiated wire types, bit N = wire type SENDSPIN_BINARY_VISUALIZER_FIRST + N.
    /// Written by handle_stream_start() and read by handle_binary() on the protocol task, so
    /// admission is always judged against the config in force when a message arrives. Protocol
    /// task only; stop() runs cleanup() on the main loop once the task is joined.
    uint8_t negotiated_types_mask{0};
    /// The negotiated spectrum n_disp_bins, while negotiated_types_mask admits spectrum. Protocol
    /// task only, like negotiated_types_mask.
    uint8_t negotiated_spectrum_bins{0};
    /// Whether the negotiated stream's beat frames report downbeats. Protocol task only, like
    /// negotiated_types_mask.
    bool negotiated_tracks_downbeats{false};
    /// Whether a stream is running, so a stream/start updates it in place. Protocol task only,
    /// like negotiated_types_mask.
    bool stream_active{false};
    /// True while the head of held_events is a STREAM_END or STREAM_CLEAR waiting for the drain
    /// thread to pass its boundary. Main loop.
    bool awaiting_drain{false};
    /// True from a superseded STREAM_START until a STREAM_START fires or a clear queued after
    /// owed_start_ordinal does. While it is, drain_events() holds back the acknowledgement of a
    /// clear queued before owed_start_ordinal (see acknowledged_through()). Main loop.
    bool start_owed{false};
};

}  // namespace sendspin
