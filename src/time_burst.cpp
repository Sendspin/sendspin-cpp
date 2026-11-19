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

#include "time_burst.h"

#include "connection.h"
#include "constants.h"
#include "platform/logging.h"
#include "time_filter.h"

#include <algorithm>

namespace sendspin {

static const char* const TAG = "sendspin.time_burst";

// ============================================================================
// Public API
// ============================================================================

TimeBurstResult SendspinTimeBurst::loop(SendspinConnection* conn, int64_t now_ms,
                                        bool may_open_burst) {
    // A completion on_time_response() recorded between loop() calls.
    bool completed = this->pending_burst_completed_;
    this->pending_burst_completed_ = false;

    if (conn == nullptr) {
        return {.sent = false, .burst_completed = completed};
    }

    // The schedule, not the burst, decides when the next burst starts (messaging.md "Clock
    // Synchronization" bounds the spacing), so a burst still running then ends here.
    if (this->burst_running() && this->starts_burst(now_ms)) {
        SS_LOGD(TAG, "Time burst ended at message %u/%u by the next one", this->burst_index_ + 1,
                this->burst_size_);
        if (this->pending_embedded_ != 0) {
            conn->cancel_time_frame();
            this->pending_embedded_ = 0;
        }
        this->complete_burst(conn);
        completed = true;
    }

    if (!this->burst_running()) {
        // The caller's permission is the one gate on opening a burst: the burst it opens is the one
        // starts_burst() reported at the same `now_ms`, which the caller has prepared for.
        if (!may_open_burst || !this->starts_burst(now_ms)) {
            return {.sent = false, .burst_completed = completed};
        }
        this->burst_index_ = 0;
        this->best_max_error_ = std::numeric_limits<int64_t>::max();
        this->next_burst_due_time_ = now_ms + this->burst_interval_ms_;
        SS_LOGV(TAG, "Starting new time burst");
    } else if (this->pending_embedded_ != 0) {
        if (now_ms - this->current_message_sent_time_ < this->message_wait_ms_) {
            return {.sent = false, .burst_completed = completed};
        }
        SS_LOGW(TAG, "Time message %u/%u got no reply", this->burst_index_ + 1, this->burst_size_);
        conn->cancel_time_frame();
        this->pending_embedded_ = 0;
        if (this->retire_message(conn)) {
            return {.sent = false, .burst_completed = true};
        }
    }

    const int64_t embedded = conn->send_time_message();
    if (embedded != 0) {
        this->pending_embedded_ = embedded;
        this->current_message_sent_time_ = now_ms;
        SS_LOGV(TAG, "Sent time message %u/%u", this->burst_index_ + 1, this->burst_size_);
        return {.sent = true, .burst_completed = completed};
    }

    SS_LOGD(TAG, "Time message %u/%u not sent", this->burst_index_ + 1, this->burst_size_);
    const bool retired_last = this->retire_message(conn);
    return {.sent = false, .burst_completed = completed || retired_last};
}

bool SendspinTimeBurst::on_time_response(SendspinConnection* conn, const TimeResponse& response) {
    // Compare the whole echo (the claim matched only its low 32 bits): a claimed reply can still
    // be drained after loop() gave up on its message or sent the next. A claimed echo is never 0,
    // so nothing matches while no message is pending.
    if (response.client_transmitted != this->pending_embedded_) {
        return false;
    }

    // Track the best (lowest RTT) measurement in this burst.
    // max_error is half the round-trip delay and must be strictly positive; zero or negative
    // values arise from clock skew or timestamp quantization in the time message and would
    // yield zero/negative measurement variance in the Kalman filter (risking divide-by-zero
    // in the update step), so we skip updating the best_* tracking for those samples.
    if (response.max_error > 0 && response.max_error < this->best_max_error_) {
        this->best_max_error_ = response.max_error;
        this->best_offset_ = response.offset;
        this->best_timestamp_ = response.timestamp;
    } else if (response.max_error <= 0) {
        SS_LOGW(TAG, "Dropping time response with non-positive max_error: %" PRId64 " us",
                response.max_error);
    }

    this->pending_embedded_ = 0;
    this->burst_index_++;
    if (this->burst_running()) {
        return false;
    }
    this->complete_burst(conn);
    this->pending_burst_completed_ = true;
    return true;
}

// ============================================================================
// Lifecycle
// ============================================================================

uint32_t SendspinTimeBurst::ms_until_due(int64_t now_ms) const {
    if (this->pending_burst_completed_) {
        return 0;
    }
    int64_t due_ms = now_ms;
    if (!this->burst_running()) {
        due_ms = this->next_burst_due_time_;
    } else if (this->pending_embedded_ != 0) {
        due_ms = std::min(this->current_message_sent_time_ + this->message_wait_ms_,
                          this->next_burst_due_time_);
    }
    return ms_until(due_ms * US_PER_MS, now_ms * US_PER_MS);
}

void SendspinTimeBurst::configure(uint8_t burst_size, int64_t burst_interval_ms) {
    this->burst_size_ = burst_size;
    this->burst_interval_ms_ = burst_interval_ms;
    this->message_wait_ms_ = burst_interval_ms / (burst_size + 1);
    this->reset();
}

void SendspinTimeBurst::reset() {
    this->burst_index_ = this->burst_size_;
    this->next_burst_due_time_ = 0;
    this->current_message_sent_time_ = 0;
    this->pending_burst_completed_ = false;
    this->pending_embedded_ = 0;
    this->best_max_error_ = std::numeric_limits<int64_t>::max();
    this->best_offset_ = 0;
    this->best_timestamp_ = 0;
}

// ============================================================================
// Internal helpers
// ============================================================================

bool SendspinTimeBurst::retire_message(SendspinConnection* conn) {
    this->burst_index_++;
    if (this->burst_running()) {
        return false;
    }
    this->complete_burst(conn);
    return true;
}

void SendspinTimeBurst::complete_burst(SendspinConnection* conn) {
    this->burst_index_ = this->burst_size_;
    if (this->best_max_error_ < std::numeric_limits<int64_t>::max()) {
        conn->time_filter().update(this->best_offset_, this->best_max_error_,
                                   this->best_timestamp_);
        SS_LOGV(TAG, "Burst complete, best max_error: %" PRId64 " us", this->best_max_error_);
    }
}

}  // namespace sendspin
