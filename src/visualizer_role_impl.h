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
#include "platform/event_flags.h"
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

/// @brief Deferred visualizer event types (used internally in the visualizer role)
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
/// factored out so it can be unit tested independently of the client and drain thread.
/// @param wire_type        SENDSPIN_BINARY_VISUALIZER_* type byte.
/// @param payload          Bytes following the entry's wire-type byte and 8-byte timestamp.
/// @param configured_bins  Negotiated spectrum n_disp_bins (0 if SPECTRUM was not negotiated).
/// @param tracks_downbeats Whether the active stream reports downbeats.
/// @param spectrum_out     Scratch vector reused for SPECTRUM bins; resized to configured_bins.
/// @return What to deliver; Kind::None if the entry is malformed, short, or non-deliverable.
VisualizerDelivery decode_visualizer_message(uint8_t wire_type, const uint8_t* payload,
                                             size_t payload_len, uint8_t configured_bins,
                                             bool tracks_downbeats,
                                             std::vector<uint16_t>& spectrum_out);

/// @brief How far behind its delivery time a frame that arrived in time may still be delivered. A
/// frame only falls this far behind when the listener has held the drain thread; past it, the
/// backlog is dropped rather than replayed late.
static constexpr int64_t VISUALIZER_MAX_DELIVERY_LAG_US = 20000;

/// @brief Decides when the drain thread delivers a frame. Pure, so the timing rules are unit
/// tested with `now` as an argument.
///
/// roles/visualizer/v1.md "Visualization Data (Binary)": a frame already in the past on arrival
/// is dropped. The rest are delivered display_offset_ms ahead of the display time (negative
/// delays them), or on arrival when that is later, unless the drain thread has fallen more than
/// VISUALIZER_MAX_DELIVERY_LAG_US behind that point.
/// @param client_ts         Display time in client time.
/// @param arrival_us        When the transport received the frame (widen_time_stamp_us() of its
///                          ring item's receive_time_us).
/// @param display_offset_ms VisualizerRoleConfig::display_offset_ms.
/// @param now               The current platform_time_us().
/// @return Microseconds to wait before delivering (0 to deliver now), or std::nullopt to drop.
std::optional<int64_t> visualizer_delivery_wait_us(int64_t client_ts, int64_t arrival_us,
                                                   int32_t display_offset_ms, int64_t now);

/// @brief Private implementation of the visualizer role
struct VisualizerRole::Impl {
    explicit Impl(VisualizerRoleConfig config, SendspinClient* client);
    ~Impl();

    // ========================================
    // Nested types
    // ========================================

    /// @brief Persistent drain thread context and the item list the protocol task hands it frames
    /// through
    struct DrainTask {
        /// Frames and clear markers: appended on the protocol task, taken on the drain thread,
        /// recalled on the protocol task or, once the thread is joined, on the main loop. Links
        /// shared inbound ring items; no storage of its own.
        InboundItemList items;
        EventFlags event_flags;
        std::thread drain_thread;
        /// The ring the list is bound to for the current run, or nullptr outside one. Written by
        /// start() and stop() on the main loop; read by the protocol task and the drain thread.
        std::atomic<InboundRing*> ring{nullptr};
    };

    /// @brief Deferred event state for the visualizer stream config, delivered to the main thread
    /// via the shared Inbox
    struct EventState {
        GenerationSlot<ServerVisualizerStreamObject> config_slot;
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
    // Each handler takes the teardown generation the receive gate captured when it admitted the
    // message and re-checks it where it takes effect; see accepts(). handle_stream_end() skips
    // the check: cleanup() performs everything it does. All run on the protocol task.
    /// @brief Hands a frame to the drain thread: by its ring item when it has one (clearing
    /// `message.item`), otherwise copied into an item the protocol task acquires.
    /// @param message The decrypted frame; `data` points at its message type byte.
    void handle_binary(uint8_t binary_type, InboundMessage& message, uint32_t generation);
    void handle_stream_start(const ServerVisualizerStreamObject& stream, uint32_t generation);
    void handle_stream_end(uint32_t generation);
    void handle_stream_clear(uint32_t generation);
    /// @brief Fires the listener callback for a current stream event. Main loop.
    /// @param generation The event's stamp: a STREAM_START applies only the config written with
    ///        the same stamp.
    void handle_stream_ring_event(VisualizerEventType event, uint32_t generation) const;
    /// @brief The main-loop teardown half, which the event drain runs through
    /// catch_up_teardown() like every role's. The visualizer keeps no main-loop state (its
    /// stream events carry everything the listener hears, and the STREAM_END cleanup() queues is
    /// its clear), so there is nothing to reset.
    void complete_teardown() {}
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, before the handler it admits
    /// runs, and stop()'s teardown on the main loop can land in between. Re-checking at each point
    /// of effect invalidates the whole handler instead of only the part that ran before it.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards its state. Protocol task, or the main loop in
    /// SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Listener callbacks are queued on
    /// the inbox, stamped with the new generation.
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
    /// @brief Returns every frame on the list to the ring. Drain thread, or the main loop once it
    /// is joined.
    void flush_items() const;
    /// @brief Protocol-task side of a clear boundary: flags the drain thread and appends a marker
    void signal_clear_marker(uint32_t generation);
    /// @brief Drain-thread side: returns frames up to and including the marker
    void discard_to_clear_marker() const;
    /// @brief Recalls the frames the drain thread has not taken once a teardown has moved the
    /// generation past the one they were appended under. Protocol task only: each tick, and
    /// before each item it hands over.
    void recall_stale_items(uint32_t generation);
    /// @brief Fills an item's consumer fields and hands it to the drain thread, returning it to
    /// the ring with a warning when the visualizer is over quota. Protocol task only.
    bool hand_item(void* item, size_t item_len, uint8_t type, uint32_t data_len,
                   uint32_t generation);
    /// Queues a stream lifecycle event stamped with `generation`, which the drain compares
    /// against the live counter before dispatching it.
    void enqueue_stream_event(VisualizerEventType event, uint32_t generation) const;

    static void drain_thread_func(VisualizerRole::Impl* self);

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    VisualizerRoleConfig config;
    VisualizerSupportObject visualizer_support;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<DrainTask> drain_task;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    VisualizerRoleListener* listener{nullptr};

    TeardownTracker teardown;  ///< Main loop only.

    /// Throttles the over-quota drop warning in hand_item(). Protocol task only.
    InboundDropLog over_quota_log;
    /// Throttles the warning for a frame that could not be copied into a ring item. Protocol task
    /// only.
    InboundDropLog copy_drop_log;

    // 32-bit fields
    /// The teardown generation the item list was last recalled for (recall_stale_items()).
    /// Protocol task only.
    uint32_t recalled_generation{0};

    // Atomic fields (written by the protocol task, read by drain thread / cleanup)
    /// @brief Teardown generation, bumped by cleanup() and stamped onto every stream event, config
    /// payload and handed-over item queued afterwards. At the drain an event whose stamp no longer
    /// matches is discarded, so it cannot act after the teardown (see event_is_current() in
    /// inbox.h). Written on the protocol task (or the main loop in stop() once it is joined);
    /// read on the main loop, the drain thread and the protocol task.
    std::atomic<uint32_t> cleanup_generation{0};

    std::atomic<uint8_t> spectrum_bin_count{0};
    std::atomic<bool> tracks_downbeats{false};
    std::atomic<bool> stream_active{false};
    // Bitmask of negotiated wire types, bit N = wire type SENDSPIN_BINARY_VISUALIZER_FIRST + N.
    // Written by handle_stream_start and read by handle_binary on the same protocol task, so
    // admission is always judged against the config in force when a message arrives; atomic only
    // because stop() runs cleanup() on the main loop once the protocol task is joined.
    std::atomic<uint8_t> negotiated_types_mask{0};
};

}  // namespace sendspin
