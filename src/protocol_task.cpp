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

#include "protocol_task.h"

#include "platform/logging.h"
#include "platform/thread.h"

#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.protocol";

// ============================================================================
// Lifecycle
// ============================================================================

ProtocolTask::ProtocolTask(size_t server_max_connections)
    : accept_slots_(ACCEPT_SLOTS_PER_SOCKET * server_max_connections),
      capacity_(this->accept_slots_ + CONSUMER_COMMAND_BURST) {
    this->commands_ = std::make_unique<ProtocolCommand[]>(this->capacity_);
}

ProtocolTask::~ProtocolTask() {
    this->stop();
}

bool ProtocolTask::start(Tick tick, size_t stack_size, unsigned priority, bool stack_in_psram) {
    if (this->thread_.joinable()) {
        SS_LOGW(TAG, "Protocol task already running");
        return false;
    }
    if (!this->event_flags_.is_created() && !this->event_flags_.create()) {
        SS_LOGE(TAG, "Couldn't create the protocol task's event flags");
        return false;
    }
    // A restart inherits nothing: no stop or wake left over from the previous run.
    this->event_flags_.clear_all();
    this->tick_ = std::move(tick);

    platform_configure_thread("SsProto", stack_size, static_cast<int>(priority), stack_in_psram);
    this->thread_ = std::thread(thread_entry, this);
    return true;
}

void ProtocolTask::stop() {
    if (!this->thread_.joinable()) {
        return;
    }
    // Setting the bit is the wake: the thread's wait returns on it and runs its final tick.
    this->event_flags_.set(COMMAND_STOP);
    this->thread_.join();

    // Joined, so this thread is the only consumer. Drop what the final tick left (or what was
    // pushed while it ran) one command at a time through one reused local: each may hold a
    // connection or a lease whose release must not run under the queue lock.
    ProtocolCommand command;
    while (this->take_command(command)) {}
    clear_command(command);
    std::optional<ClientStateMessage> dropped;
    {
        std::lock_guard<std::mutex> lock(this->command_mutex_);
        dropped.swap(this->latest_state_);
    }
}

void ProtocolTask::thread_entry(ProtocolTask* self) {
    for (;;) {
        const uint32_t next_deadline_ms = self->tick_();
        // NO_DEADLINE is UINT32_MAX, which EventFlags::wait() takes as no timeout.
        const uint32_t bits =
            self->event_flags_.wait(COMMAND_STOP | WORK_PENDING, false, true, next_deadline_ms);
        if ((bits & COMMAND_STOP) != 0) {
            // One final tick, so the work queued before stop() was called is seen by the task.
            self->tick_();
            return;
        }
    }
}

void ProtocolTask::wake() {
    // The flags exist from the first start() on; nothing produces work for the task before the
    // client that owns it has started.
    if (this->event_flags_.is_created()) {
        this->event_flags_.set(WORK_PENDING);
    }
}

// ============================================================================
// Command queue
// ============================================================================

bool ProtocolTask::push_command(ProtocolCommand&& command) {
    const bool is_accept = command.type == ProtocolCommandType::ACCEPT_CONNECTION;
    bool queued = false;
    {
        std::lock_guard<std::mutex> lock(this->command_mutex_);
        const size_t others_queued = this->command_count_ - this->accepts_queued_;
        const bool has_room = is_accept ? this->accepts_queued_ < this->accept_slots_
                                        : others_queued < CONSUMER_COMMAND_BURST;
        if (has_room) {
            // The slot is empty (moved-from or default), so this move frees nothing.
            this->commands_[(this->command_head_ + this->command_count_) % this->capacity_] =
                std::move(command);
            ++this->command_count_;
            if (is_accept) {
                ++this->accepts_queued_;
            }
            queued = true;
        }
    }
    if (!queued) {
        if (is_accept) {
            SS_LOGE(TAG, "All %zu accept slots are taken; refusing a delivered connection",
                    this->accept_slots_);
        } else {
            SS_LOGW(TAG, "Protocol command queue full (%zu); dropping a command of type %d",
                    CONSUMER_COMMAND_BURST, static_cast<int>(command.type));
        }
        return false;
    }
    this->wake();
    return true;
}

bool ProtocolTask::take_command(ProtocolCommand& out) {
    // Released before the lock is taken, so the move below lands in an empty command.
    clear_command(out);
    std::lock_guard<std::mutex> lock(this->command_mutex_);
    if (this->command_count_ == 0) {
        return false;
    }
    // Leaves the slot moved-from: empty, holding nothing heap-backed.
    out = std::move(this->commands_[this->command_head_]);
    this->command_head_ = (this->command_head_ + 1) % this->capacity_;
    --this->command_count_;
    if (out.type == ProtocolCommandType::ACCEPT_CONNECTION) {
        --this->accepts_queued_;
    }
    return true;
}

void ProtocolTask::clear_command(ProtocolCommand& command) {
    command.lease.reset();
    command.connection.reset();
    command.text.clear();
    command.text.shrink_to_fit();
    command.type = ProtocolCommandType::SEND_TEXT;
    command.reason = SendspinGoodbyeReason::SHUTDOWN;
    command.role = SendspinRole::CONTROLLER;
    command.enabled = false;
}

// ============================================================================
// State slot
// ============================================================================

void ProtocolTask::publish_state(ClientStateMessage state) {
    std::optional<ClientStateMessage> replaced(std::move(state));
    {
        std::lock_guard<std::mutex> lock(this->command_mutex_);
        replaced.swap(this->latest_state_);
    }
    // `replaced` now holds the superseded snapshot, destroyed here outside the lock.
    this->wake();
}

bool ProtocolTask::take_state(ClientStateMessage& out) {
    std::optional<ClientStateMessage> taken;
    {
        std::lock_guard<std::mutex> lock(this->command_mutex_);
        taken.swap(this->latest_state_);
    }
    if (!taken.has_value()) {
        return false;
    }
    out = std::move(*taken);
    return true;
}

}  // namespace sendspin
