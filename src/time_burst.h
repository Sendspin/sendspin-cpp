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
    // ========================================
    // Public API
    // ========================================

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

    // ========================================
    // Lifecycle
    // ========================================

    /// @brief Configures burst parameters. Call before the first loop() invocation.
    /// Defaults match the library's built-in values if configure() is never called.
    /// @param burst_size Number of time messages per burst.
    /// @param burst_interval_ms Milliseconds between bursts.
    /// @param response_timeout_ms Milliseconds before an individual message times out.
    void configure(uint8_t burst_size, int64_t burst_interval_ms, int64_t response_timeout_ms);

    /// @brief Reset state (call on connection loss/change)
    void reset();

protected:
    // 64-bit fields
    int64_t best_max_error_{std::numeric_limits<int64_t>::max()};
    int64_t best_offset_{0};
    int64_t best_timestamp_{0};
    int64_t current_message_sent_time_{0};
    int64_t last_burst_complete_time_{0};
    int64_t burst_interval_ms_{10000};
    int64_t response_timeout_ms_{10000};

    // 8-bit fields
    uint8_t burst_size_{8};
    uint8_t burst_index_{8};  // starts "complete" so first loop triggers a burst
    // Flag set by on_time_response() when burst completes, consumed by loop()
    bool pending_burst_completed_{false};
};

}  // namespace sendspin
