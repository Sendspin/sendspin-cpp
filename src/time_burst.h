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

/// @file time_burst.h
/// @brief Burst-based time synchronization coordinator that selects the best RTT sample per burst
/// for Kalman filter input

#pragma once

#include <cstdint>
#include <limits>

namespace sendspin {

class SendspinConnection;

/// @brief Result of a single SendspinTimeBurst::loop() call
struct TimeBurstResult {
    bool sent;             ///< A time message was sent this call.
    bool burst_completed;  ///< The burst just finished (Kalman filter updated).
};

/**
 * @brief Burst-based time synchronization coordinator for a single connection
 *
 * Sends a rapid burst of time messages over a WebSocket connection, tracks each RTT
 * measurement, and feeds only the best sample (lowest round-trip delay) to the
 * connection's Kalman filter. Waiting for the inter-burst interval between rounds
 * reduces filter update frequency while still capturing clean measurements.
 *
 * Usage:
 * 1. Call loop() on each iteration of the hub's main loop, passing the active connection
 * 2. Call on_time_response() when a SERVER_TIME response arrives for that connection
 * 3. Call reset() when the connection is lost or replaced
 * 4. Check TimeBurstResult::burst_completed to know when to act on updated time estimates
 *
 * @code
 * SendspinTimeBurst burst;
 * burst.reset();
 *
 * // In the hub loop:
 * TimeBurstResult result = burst.loop(conn);
 * if (result.burst_completed) {
 *     int64_t server_now = conn->get_time_filter()->compute_server_time(platform_time_us());
 * }
 *
 * // When a SERVER_TIME response arrives:
 * burst.on_time_response(conn, offset, max_error, timestamp);
 * @endcode
 */
class SendspinTimeBurst {
public:
    /// @brief Drive the burst state machine. Called from hub's loop()
    /// @param conn The active connection to send time messages on.
    /// @return Result indicating whether a message was sent and/or the burst completed.
    TimeBurstResult loop(SendspinConnection* conn);

    /// @brief Called when a SERVER_TIME response arrives
    /// @param conn The connection that received the response.
    /// @param offset Computed time offset from the NTP-style exchange.
    /// @param max_error Half the round-trip delay (RTT proxy).
    /// @param timestamp Client timestamp when measurement was taken.
    /// @return true if this completed the burst (Kalman filter was updated).
    bool on_time_response(SendspinConnection* conn, int64_t offset, int64_t max_error,
                          int64_t timestamp);

    /// @brief Reset state (call on connection loss/change)
    void reset();

protected:
    static const uint8_t BURST_SIZE = 8;
    static const int64_t BURST_INTERVAL_MS = 10000;
    static const int64_t RESPONSE_TIMEOUT_MS = 10000;

    // 64-bit fields
    // Best measurement in current burst
    int64_t best_max_error_{std::numeric_limits<int64_t>::max()};
    int64_t best_offset_{0};
    int64_t best_timestamp_{0};
    int64_t current_message_sent_time_{0};
    int64_t last_burst_complete_time_{0};

    // 8-bit fields
    uint8_t burst_index_{BURST_SIZE};  // starts "complete" so first loop triggers a burst
    // Flag set by on_time_response() when burst completes, consumed by loop()
    bool pending_burst_completed_{false};
};

}  // namespace sendspin
