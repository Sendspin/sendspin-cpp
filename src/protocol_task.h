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

/// @file protocol_task.h
/// @brief The library-owned protocol thread and the bounded command queue that feeds it from the
/// main loop and consumer threads

#pragma once

#include "platform/event_flags.h"
#include "protocol_messages.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace sendspin {

class SendspinConnection;

// ============================================================================
// Commands
// ============================================================================

/// @brief What a ProtocolCommand asks the protocol task to do
enum class ProtocolCommandType : uint8_t {
    ACCEPT_CONNECTION,       ///< A platform server delivered a WebSocket-upgraded connection
    CONNECT_TO,              ///< SendspinClient::connect_to()
    DISCONNECT,              ///< SendspinClient::disconnect()
    LEAVE,                   ///< SendspinClient::leave()
    PAIRING_WINDOW_CANCEL,   ///< SendspinClient::cancel_pairing_window()
    PAIRING_WINDOW_CONFIRM,  ///< SendspinClient::confirm_pairing_window()
    SEND_TEXT,               ///< SendspinClient::send_text()
    SET_UNPAIRED_ACCESS,     ///< SendspinClient::set_unpaired_access_enabled()
};

/**
 * @brief A buffer a command hands to the protocol task, returned to its owner through a hook
 *
 * Move-only. The owner's release hook runs exactly once: when the protocol task calls reset()
 * after it is done with the bytes, or when the lease is destroyed still holding them, which is
 * what returns a buffer whose command was dropped (a full queue, or a stop() that discards what
 * is queued) without any caller having to remember to.
 *
 * This is the hand-off point for a producer thread's send slot: the producer fills a slot it
 * owns, leases it to the protocol task inside a command, and the protocol task encrypts it in
 * place, hands it to the transport, and resets the lease, whose hook marks the slot free again.
 * The hook runs on whichever thread drops the lease, under no library lock, so it must be safe
 * from any thread.
 */
class CommandLease {
public:
    /// @brief Returns a leased buffer to its owner
    /// @param owner The owner pointer the lease was created with.
    /// @param data The leased buffer.
    using ReleaseHook = void (*)(void* owner, uint8_t* data);

    CommandLease() = default;
    CommandLease(uint8_t* data, size_t size, ReleaseHook release, void* owner)
        : data_(data), owner_(owner), release_(release), size_(size) {}
    ~CommandLease() {
        this->reset();
    }

    CommandLease(CommandLease&& other) noexcept
        : data_(other.data_), owner_(other.owner_), release_(other.release_), size_(other.size_) {
        other.data_ = nullptr;
        other.release_ = nullptr;
        other.size_ = 0;
    }
    CommandLease& operator=(CommandLease&& other) noexcept {
        if (this != &other) {
            this->reset();
            this->data_ = other.data_;
            this->owner_ = other.owner_;
            this->release_ = other.release_;
            this->size_ = other.size_;
            other.data_ = nullptr;
            other.release_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }
    CommandLease(const CommandLease&) = delete;
    CommandLease& operator=(const CommandLease&) = delete;

    /// @brief Runs the release hook if the lease still holds a buffer, and empties it
    void reset() {
        if (this->release_ != nullptr && this->data_ != nullptr) {
            this->release_(this->owner_, this->data_);
        }
        this->data_ = nullptr;
        this->release_ = nullptr;
        this->size_ = 0;
    }

    /// @brief The leased bytes, or nullptr for an empty lease
    uint8_t* data() const {
        return this->data_;
    }

    /// @brief Number of leased bytes
    size_t size() const {
        return this->size_;
    }

    /// @brief Whether the lease holds a buffer
    explicit operator bool() const {
        return this->data_ != nullptr;
    }

private:
    // Pointer fields
    uint8_t* data_{nullptr};
    void* owner_{nullptr};
    ReleaseHook release_{nullptr};

    // size_t fields
    size_t size_{0};
};

/// @brief One request handed to the protocol task. Only the fields its type names are set.
/// Move-only, since it may carry a connection reference and a lease. A client/state snapshot is
/// not a command: it goes through ProtocolTask::publish_state().
struct ProtocolCommand {
    // Struct fields
    /// CONNECT_TO: the URL. SEND_TEXT: the message.
    std::string text{};
    /// A buffer handed over with the command (see CommandLease).
    CommandLease lease{};

    // Pointer fields
    /// ACCEPT_CONNECTION: the delivered connection.
    std::shared_ptr<SendspinConnection> connection{};

    // 8-bit fields
    ProtocolCommandType type{ProtocolCommandType::SEND_TEXT};
    /// DISCONNECT: the goodbye reason.
    SendspinGoodbyeReason reason{SendspinGoodbyeReason::SHUTDOWN};
    /// SEND_TEXT: the role the message belongs to.
    SendspinRole role{SendspinRole::CONTROLLER};
    /// SET_UNPAIRED_ACCESS: the new setting.
    bool enabled{false};
};

// ============================================================================
// ProtocolTask
// ============================================================================

/**
 * @brief The thread that owns every connection and performs all protocol work
 *
 * Runs the tick the client hands to start() whenever it is woken (a command, a state snapshot,
 * an inbound ring item, a transport close) and when the tick's own next deadline passes. The
 * tick returns the milliseconds until its earliest timer deadline, or NO_DEADLINE, and the task
 * waits for a wake for that long, so an idle task with no timer pending does not run at all.
 *
 * Lifecycle matches the role threads: start() clears every flag and spawns the thread; stop()
 * sets COMMAND_STOP, wakes the wait, lets the thread run one final tick so commands queued
 * before the stop are seen by the task, joins it, and then drops anything still queued one
 * command at a time.
 */
class ProtocolTask {
public:
    /// What a tick returns when none of its timers is pending: the task then waits for a wake
    /// alone. Every source of work wakes the task (wake(), push_command(), publish_state()), and
    /// every timer-driven step reports its own deadline, the network-readiness poll included, so
    /// no periodic re-evaluation is needed.
    static constexpr uint32_t NO_DEADLINE = UINT32_MAX;

    /// Queue slots for consumer commands: the gestures one main-loop tick can issue, each
    /// meaningful at most once per tick (connect_to(), disconnect(), leave(),
    /// confirm_pairing_window(), cancel_pairing_window(), set_unpaired_access_enabled()), plus
    /// two send_text() controller commands. That last term is an assumption: it holds for a
    /// handler that sends a volume change and a play, not for a rotary encoder that issues a
    /// volume step per detent faster than the protocol task drains the queue. A command past the
    /// burst is refused and push_command() returns false, a drop the client must pass back to
    /// whoever called send_text() rather than swallow. A client/state snapshot takes no slot
    /// (publish_state()), and a transport close is out of band (InboundGate), so neither counts.
    static constexpr size_t CONSUMER_COMMAND_BURST = 8;

    /// Accept slots reserved per socket of SendspinClientConfig::server_max_connections. A
    /// socket can close out of band while its accept is still queued, and the platform server
    /// can then deliver an accept for the socket that replaces it, so a queue the task has not
    /// drained can hold one accept per socket plus one per socket that churned. Two per socket
    /// covers a close and a reopen of every socket between two drains of the queue; churn
    /// beyond that while the task is stalled refuses the accept (push_command() returns false
    /// and leaves the connection with the caller).
    static constexpr size_t ACCEPT_SLOTS_PER_SOCKET = 2;

    /// @brief The protocol work; runs on the protocol task only
    /// @return Milliseconds until the tick's earliest timer deadline (0 runs it again at once), or
    ///         NO_DEADLINE.
    using Tick = std::function<uint32_t()>;

    /// @brief Creates the command queue: CONSUMER_COMMAND_BURST consumer slots plus
    /// ACCEPT_SLOTS_PER_SOCKET accept slots per socket
    /// @param server_max_connections The client's SendspinClientConfig::server_max_connections.
    explicit ProtocolTask(size_t server_max_connections);
    ~ProtocolTask();

    ProtocolTask(const ProtocolTask&) = delete;
    ProtocolTask& operator=(const ProtocolTask&) = delete;

    /// @brief Spawns the thread, which runs `tick` once at once and then on every wake or
    /// deadline. Main loop only.
    /// @param tick The protocol work.
    /// @param stack_size Task stack size in bytes (ESP-IDF only).
    /// @param priority FreeRTOS task priority (ESP-IDF only).
    /// @param stack_in_psram Allocate the stack in PSRAM (ESP-IDF only).
    /// @return false when the event flags could not be created or the task already runs.
    bool start(Tick tick, size_t stack_size, unsigned priority, bool stack_in_psram);

    /// @brief Signals the thread, waits for its final tick and joins it, then drops every
    /// command and state snapshot still queued, one command at a time. No-op when the thread is
    /// not running. Main loop only.
    void stop();

    /// @brief Whether the thread is running. Main loop only.
    bool is_running() const {
        return this->thread_.joinable();
    }

    /// @brief Wakes the task out of its wait so the tick runs. Any thread.
    void wake();

    /// @brief Queues a command and wakes the task. Any thread.
    /// @return false when the command's slots are all taken (consumer commands share
    ///         CONSUMER_COMMAND_BURST slots, accepts their reserved ones): the refusal is logged
    ///         and the command is left with the caller unchanged, so destroying it releases any
    ///         lease it carries on the caller's thread, outside the queue lock.
    bool push_command(ProtocolCommand&& command);

    /// @brief Takes the oldest queued command. Protocol task only, or the thread that joined it.
    /// @param[out] out Receives the command; whatever it held before is released first, outside
    ///        the queue lock.
    /// @return false when the queue is empty.
    bool take_command(ProtocolCommand& out);

    /// @brief Replaces the latest client/state snapshot and wakes the task. Any thread.
    ///
    /// One slot beside the command queue: a snapshot is never refused, only the newest matters,
    /// and the one it replaces is destroyed outside the lock. The tick applies it after draining
    /// the command queue; its order relative to queued commands is not a semantic requirement,
    /// since a snapshot describes the client's whole state rather than a step.
    void publish_state(ClientStateMessage state);

    /// @brief Takes the latest snapshot, if one was published since the last take. Protocol task
    /// only.
    /// @param[out] out Receives the snapshot; what it held before is destroyed outside the lock.
    /// @return false when no snapshot is waiting.
    bool take_state(ClientStateMessage& out);

private:
    /// Event flag bits
    static constexpr uint32_t COMMAND_STOP = 1U << 0;
    static constexpr uint32_t WORK_PENDING = 1U << 1;

    /// @brief Thread body: tick, wait for a wake or the tick's deadline, repeat; on COMMAND_STOP
    /// run one final tick and exit
    static void thread_entry(ProtocolTask* self);

    /// @brief Releases what a command holds and resets it, without a temporary command
    static void clear_command(ProtocolCommand& command);

    // Struct fields
    /// Ring of queued commands, capacity_ entries. Pushed from any thread, taken by the protocol
    /// task (or the thread that joined it); guarded by command_mutex_. A slot is only ever
    /// moved into while empty (moved-from or default), so no heap memory is freed under the
    /// lock.
    std::unique_ptr<ProtocolCommand[]> commands_;
    /// Guards commands_, the counts and latest_state_. A leaf: no lock is taken and nothing
    /// heap-backed is destroyed under it.
    std::mutex command_mutex_;
    EventFlags event_flags_;
    /// The newest client/state snapshot not yet taken. Written from any thread, taken by the
    /// protocol task; guarded by command_mutex_ and only ever swapped under it.
    std::optional<ClientStateMessage> latest_state_;
    std::thread thread_;
    /// The protocol work, set by start() before the thread exists and read only by the thread.
    Tick tick_;

    // size_t fields
    /// Slots reserved for ACCEPT_CONNECTION: ACCEPT_SLOTS_PER_SOCKET per socket. Fixed at
    /// construction.
    const size_t accept_slots_;
    /// accept_slots_ + CONSUMER_COMMAND_BURST. Fixed at construction.
    const size_t capacity_;
    /// Queued commands in total, and the accepts among them. Guarded by command_mutex_.
    size_t command_count_{0};
    size_t command_head_{0};
    size_t accepts_queued_{0};
};

}  // namespace sendspin
