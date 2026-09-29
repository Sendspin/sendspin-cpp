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

#include "inbox.h"
#include "platform/event_flags.h"
#include "platform/memory.h"
#include "platform/spsc_ring_buffer.h"
#include "sendspin/visualizer_role.h"

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

/// @brief Recovers a frame's arrival time from the low 32 bits of platform_time_us() the network
/// thread stored with it. Exact while the frame is younger than 2^32 us (about 71 minutes).
int64_t visualizer_arrival_from_stamp(uint32_t stamp, int64_t now);

/// @brief Decides when the drain thread delivers a frame. Pure, so the timing rules are unit
/// tested with `now` as an argument.
///
/// roles/visualizer/v1.md "Visualization Data (Binary)": a frame already in the past on arrival
/// is dropped. The rest are delivered display_offset_ms ahead of the display time (negative
/// delays them), or on arrival when that is later, unless the drain thread has fallen more than
/// VISUALIZER_MAX_DELIVERY_LAG_US behind that point.
/// @param client_ts         Display time in client time.
/// @param arrival_us        When the network thread received the frame.
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

    /// @brief Persistent drain thread context and platform ring buffer for visualizer data delivery
    struct DrainTask {
        SpscRingBuffer ring_buffer;
        PlatformBuffer ring_storage;
        EventFlags event_flags;
        std::thread drain_thread;
    };

    /// @brief Deferred event state for the visualizer stream config, delivered to the main thread
    /// via the shared Inbox
    struct EventState {
        InboxSlot<ServerVisualizerStreamObject> config_slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    bool start();
    void build_hello_fields(ClientHelloMessage& msg) const;
    void build_state_fields(ClientStateMessage& msg) const;
    // Each handler takes the teardown generation the receive gate captured when it admitted the
    // message and re-checks it where it takes effect; see accepts(). handle_stream_end() skips
    // the check: cleanup() performs everything it does.
    void handle_binary(uint8_t binary_type, const uint8_t* data, size_t len, uint32_t generation);
    void handle_stream_start(const ServerVisualizerStreamObject& stream, uint32_t generation);
    void handle_stream_end(uint32_t generation);
    void handle_stream_clear(uint32_t generation) const;
    void handle_stream_ring_event(VisualizerEventType event) const;
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, on the network thread, while the
    /// handler it admits runs on: a teardown can land in between (the deactivation path, unlike a
    /// lost connection, never quiesces the network thread). Re-checking at each point of effect
    /// invalidates the whole handler instead of only the part that ran before it.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards its state. Main loop only.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Listener callbacks are queued on
    /// the inbox rather than fired here, because both callers run under the connection manager's
    /// conn_ptr_mutex_.
    void cleanup();

    // ========================================
    // Internal helpers
    // ========================================

    /// @brief Asks the drain thread to exit without waiting for it; stop() joins. Lets a caller
    /// overlap the thread's exit with other teardown.
    /// @return true if a running thread was signalled, false if none was running.
    bool signal_stop() const;
    void stop() const;
    void flush_ring_buffer() const;
    void signal_clear_marker() const;
    void discard_to_clear_marker() const;
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

    // Atomic fields (written by network thread, read by drain thread / cleanup)
    /// @brief Teardown generation, bumped by cleanup() and stamped onto every stream event queued
    /// afterwards. At the drain an event whose stamp no longer matches is discarded, so it cannot
    /// act after the teardown (see event_is_current() in inbox.h). Atomic because the network
    /// thread reads it (see accepts()).
    std::atomic<uint32_t> cleanup_generation{0};

    std::atomic<uint8_t> spectrum_bin_count{0};
    std::atomic<bool> tracks_downbeats{false};
    std::atomic<bool> stream_active{false};
    // Bitmask of negotiated wire types, bit N = wire type SENDSPIN_BINARY_VISUALIZER_FIRST + N.
    // Written by handle_stream_start and read by handle_binary on the same network thread, so
    // admission is always judged against the config in force when a message arrives; atomic only
    // because cleanup() clears it from the main thread.
    std::atomic<uint8_t> negotiated_types_mask{0};
};

}  // namespace sendspin
