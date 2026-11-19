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

#include "sendspin/config.h"

#include <cstdint>
#include <limits>

namespace sendspin {

class SendspinConnection;

/// @brief One server/time reply, measured on the protocol task and handed to its connection's
/// time burst
struct TimeResponse {
    int64_t offset{0};     ///< Server clock minus client clock (microseconds).
    int64_t max_error{0};  ///< Half the round-trip delay (microseconds).
    int64_t timestamp{0};  ///< When the reply arrived, on the client clock (microseconds).
    /// The client_transmitted the reply echoed, identifying the client/time it answers.
    int64_t client_transmitted{0};
};

/// @brief Result of a single SendspinTimeBurst::loop() call
struct TimeBurstResult {
    bool sent;             ///< A time message was sent this call.
    bool burst_completed;  ///< A burst ended since the last call (Kalman filter updated).
};

/**
 * @brief Burst-based time synchronization coordinator for a single connection
 *
 * Sends a rapid burst of time messages over a WebSocket connection, tracks each RTT
 * measurement, and feeds only the best sample (lowest round-trip delay) to the
 * connection's Kalman filter.
 *
 * A burst opens one interval after the last one opened. Each message waits at most
 * interval / (burst size + 1) for its reply before the next is sent, so a burst that gets no reply
 * still sends every message and ends a share before the next opens, so the caller can release its
 * high-performance hold until then; a burst still running when the next falls due (opened or
 * driven late) ends there. messaging.md "Clock Synchronization" bounds both the burst size and the
 * spacing.
 *
 * Each SendspinConnection owns one, beside its time filter, and drives it on the protocol task:
 * 1. Call loop() on each tick while the connection is admitted and operational, and wake again
 *    after ms_until_due(); starts_burst() says when the next loop() opens a burst, which the
 *    caller may hold back until the platform is ready for it
 * 2. Call on_time_response() when a SERVER_TIME response arrives for that connection
 * 3. Call reset() when the connection is dropped
 * 4. Check TimeBurstResult::burst_completed to know when to act on updated time estimates
 *
 * @code
 * SendspinTimeBurst burst;
 * burst.reset();
 *
 * // On the protocol task's tick:
 * const int64_t now_ms = platform_time_us() / US_PER_MS;
 * TimeBurstResult result = burst.loop(conn, now_ms, burst.starts_burst(now_ms));
 * if (result.burst_completed) {
 *     int64_t server_now = conn->time_filter().compute_server_time(platform_time_us());
 * }
 *
 * // When a SERVER_TIME response arrives:
 * burst.on_time_response(conn, response);
 * @endcode
 */
class SendspinTimeBurst {
public:
    // ========================================
    // Public API
    // ========================================

    /// @brief Drive the burst state machine. Protocol task only.
    ///
    /// A time message the connection does not send counts as one that went unanswered, so a send
    /// that keeps failing ends the burst instead of re-ticking the protocol task at once.
    /// @param conn The connection that owns this burst, to send time messages on; connected and
    ///        operational (ConnectionManager::run_time_sync() gates it; loop() does not recheck).
    /// @param now_ms platform_time_us() / US_PER_MS, read once by the caller for this call and
    ///        its starts_burst().
    /// @param may_open_burst Whether a burst that is due may be opened (its first time message
    ///        sent) by this call. A burst already open runs on regardless.
    /// @return Result indicating whether a message was sent and/or a burst completed.
    TimeBurstResult loop(SendspinConnection* conn, int64_t now_ms, bool may_open_burst);

    /// @brief Called when a SERVER_TIME response arrives; ignored unless it answers the time
    /// message still pending
    /// @param conn The connection that received the response.
    /// @param response The measurement and the echo identifying the message it answers.
    /// @return true if this completed the burst (Kalman filter was updated).
    bool on_time_response(SendspinConnection* conn, const TimeResponse& response);

    /// @brief Whether the next loop() opens a new burst, which sends its first time frame: none is
    /// running, or the one running is due to end, and the interval since the last opened has
    /// elapsed
    /// @param now_ms platform_time_us() / US_PER_MS, the value the caller passes loop().
    [[nodiscard]] bool starts_burst(int64_t now_ms) const {
        return now_ms >= this->next_burst_due_time_;
    }

    /// @brief Whether a burst is open: its messages are not all sent and answered or retired
    [[nodiscard]] bool burst_running() const {
        return this->burst_index_ < this->burst_size_;
    }

    /// @brief Milliseconds until loop() has something to do: the next message of a burst (0),
    /// the end of the wait of the message in flight, or the next burst's start
    /// @param now_ms platform_time_us() / US_PER_MS, as loop() reads it.
    /// @return 0 when loop() is due now.
    [[nodiscard]] uint32_t ms_until_due(int64_t now_ms) const;

    // ========================================
    // Lifecycle
    // ========================================

    /// @brief Configures burst parameters and resets the burst. Call before the first loop()
    /// invocation. Defaults match the library's built-in values if configure() is never called.
    /// @param burst_size Number of time messages per burst.
    /// @param burst_interval_ms Milliseconds from one burst's start to the next's; at least
    ///        burst_size + 1, so a message waits at least 1 ms.
    void configure(uint8_t burst_size, int64_t burst_interval_ms);

    /// @brief Reset state (call on connection loss/change); the next burst is due at once
    void reset();

protected:
    // ========================================
    // Internal helpers
    // ========================================

    /// @brief Ends the current message without a measurement (unanswered or not sent); at the
    /// burst's last message, completes the burst.
    /// @param conn The connection that owns this burst.
    /// @return true if this completed the burst.
    bool retire_message(SendspinConnection* conn);

    /// @brief Ends the burst, feeding its best measurement, if it has one, to the time filter
    /// @param conn The connection that owns this burst.
    void complete_burst(SendspinConnection* conn);

    // 64-bit fields
    int64_t best_max_error_{std::numeric_limits<int64_t>::max()};
    int64_t best_offset_{0};
    int64_t best_timestamp_{0};
    int64_t current_message_sent_time_{0};
    // When the next burst opens: one interval after the last opened, 0 (due at once on any clock
    // reading) after reset()
    int64_t next_burst_due_time_{0};
    int64_t burst_interval_ms_{SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS};
    // The longest a message waits for its reply (see the class comment)
    int64_t message_wait_ms_{SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS /
                             (SendspinClientConfig::DEFAULT_BURST_SIZE + 1)};
    // client_transmitted of the time message awaiting a reply, 0 when none is (see
    // on_time_response())
    int64_t pending_embedded_{0};

    // 8-bit fields
    uint8_t burst_size_{SendspinClientConfig::DEFAULT_BURST_SIZE};
    // Messages of the open burst answered or retired; burst_size_ when none is open
    uint8_t burst_index_{SendspinClientConfig::DEFAULT_BURST_SIZE};
    // Flag set by on_time_response() when burst completes, consumed by loop()
    bool pending_burst_completed_{false};
};

}  // namespace sendspin
