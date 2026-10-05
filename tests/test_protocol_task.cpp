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

/// @file test_protocol_task.cpp
/// @brief Tests for the protocol task's plumbing: the command queue's order, its reserved accept
/// slots and lease release, the latest-state slot, delivery to the running task, the
/// no-deadline wait, and stop()

#include "protocol_task.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <string>
#include <thread>

namespace sendspin {
namespace {

ProtocolCommand make_command(ProtocolCommandType type, std::string text = {}) {
    ProtocolCommand command;
    command.type = type;
    command.text = std::move(text);
    return command;
}

// Counts the leases handed back through the release hook.
struct LeaseOwner {
    static void release(void* owner, uint8_t* /*data*/) {
        static_cast<LeaseOwner*>(owner)->released.fetch_add(1);
    }
    CommandLease lease() {
        return CommandLease(this->slot, sizeof(this->slot), &LeaseOwner::release, this);
    }
    uint8_t slot[16]{};
    std::atomic<int> released{0};
};

constexpr size_t MAX_CONNECTIONS = SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS;
constexpr size_t ACCEPT_SLOTS = ProtocolTask::ACCEPT_SLOTS_PER_SOCKET * MAX_CONNECTIONS;
constexpr size_t TEST_STACK = 8192;
constexpr unsigned TEST_PRIORITY = 5;

// Commands come out in the order they went in, accepts and consumer commands interleaved.
TEST(ProtocolTaskCommands, TakesCommandsInPushOrder) {
    ProtocolTask task(MAX_CONNECTIONS);
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::CONNECT_TO, "ws://a")));
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::ACCEPT_CONNECTION)));
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::SEND_TEXT, "hello")));

    ProtocolCommand out;
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::CONNECT_TO);
    EXPECT_EQ(out.text, "ws://a");
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::ACCEPT_CONNECTION);
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::SEND_TEXT);
    EXPECT_EQ(out.text, "hello");
    EXPECT_FALSE(task.take_command(out));
}

// Consumer commands are bounded by CONSUMER_COMMAND_BURST, and a burst that fills them cannot
// take an accept's reserved slot: every one of the ACCEPT_SLOTS accepts still queues. The push
// past the burst is refused and leaves the command with its caller, whose lease is released when
// the caller drops it. Control: every push within the bounds is accepted and keeps its lease.
TEST(ProtocolTaskCommands, ConsumerBurstIsBoundedAndAcceptsKeepTheirReservedSlots) {
    ProtocolTask task(MAX_CONNECTIONS);
    LeaseOwner owner;
    for (size_t i = 0; i < ProtocolTask::CONSUMER_COMMAND_BURST; ++i) {
        ProtocolCommand command = make_command(ProtocolCommandType::SEND_TEXT, std::to_string(i));
        command.lease = owner.lease();
        ASSERT_TRUE(task.push_command(std::move(command)));
    }
    {
        ProtocolCommand overflow = make_command(ProtocolCommandType::SEND_TEXT, "overflow");
        overflow.lease = owner.lease();
        EXPECT_FALSE(task.push_command(std::move(overflow)));
        // NOLINTNEXTLINE(bugprone-use-after-move): a refused push does not move from it
        EXPECT_TRUE(overflow.lease) << "a refused command stays with its caller";
        EXPECT_EQ(owner.released.load(), 0);
    }
    EXPECT_EQ(owner.released.load(), 1);

    for (size_t i = 0; i < ACCEPT_SLOTS; ++i) {
        EXPECT_TRUE(task.push_command(make_command(ProtocolCommandType::ACCEPT_CONNECTION)));
    }
    EXPECT_FALSE(task.push_command(make_command(ProtocolCommandType::ACCEPT_CONNECTION)));

    ProtocolCommand out;
    size_t taken = 0;
    while (task.take_command(out)) {
        ++taken;
    }
    EXPECT_EQ(taken, ProtocolTask::CONSUMER_COMMAND_BURST + ACCEPT_SLOTS);
    EXPECT_EQ(owner.released.load(), static_cast<int>(ProtocolTask::CONSUMER_COMMAND_BURST) + 1);
}

// A lease moved between commands is released exactly once, by whichever holder drops it last.
TEST(ProtocolTaskCommands, LeaseReleasesExactlyOnceAcrossMoves) {
    LeaseOwner owner;
    {
        CommandLease first = owner.lease();
        CommandLease second = std::move(first);
        EXPECT_FALSE(first);
        CommandLease third;
        third = std::move(second);
        EXPECT_EQ(third.data(), owner.slot);
        EXPECT_EQ(owner.released.load(), 0);
    }
    EXPECT_EQ(owner.released.load(), 1);
}

// The state slot keeps only the newest snapshot and is emptied by a take. Control: a take with
// nothing published finds nothing.
TEST(ProtocolTaskState, SlotKeepsOnlyTheNewestSnapshot) {
    ProtocolTask task(MAX_CONNECTIONS);
    ClientStateMessage out;
    EXPECT_FALSE(task.take_state(out)) << "Control";

    ClientStateMessage older;
    older.available = false;
    ClientStateMessage newer;
    newer.available = true;
    newer.player = ClientPlayerStateObject{};
    task.publish_state(older);
    task.publish_state(newer);

    ASSERT_TRUE(task.take_state(out));
    EXPECT_TRUE(out.available);
    EXPECT_TRUE(out.player.has_value());
    EXPECT_FALSE(task.take_state(out));
}

// stop() leaves the commands the final tick did not take queued for the joining thread, which
// takes them (an accept refused after the join) or drops them, and the leases they carry go back
// to their owner on the drop. The state snapshot describes a run that is over, so stop() drops it.
// The tick never takes a command, so only the joining thread can release them.
TEST(ProtocolTaskCommands, StopLeavesQueuedCommandsForTheJoiningThread) {
    ProtocolTask task(MAX_CONNECTIONS);
    LeaseOwner owner;
    ASSERT_TRUE(task.start([] { return ProtocolTask::NO_DEADLINE; }, TEST_STACK, TEST_PRIORITY,
                           false));
    for (int i = 0; i < 3; ++i) {
        ProtocolCommand command = make_command(ProtocolCommandType::SEND_TEXT);
        command.lease = owner.lease();
        ASSERT_TRUE(task.push_command(std::move(command)));
    }
    task.publish_state(ClientStateMessage{});
    task.stop();
    EXPECT_FALSE(task.is_running());
    EXPECT_EQ(owner.released.load(), 0) << "stop() released a command the joining thread owns";
    ClientStateMessage state;
    EXPECT_FALSE(task.take_state(state)) << "the snapshot outlived the run";

    // The joining thread takes one, then drops the rest.
    ProtocolCommand out;
    ASSERT_TRUE(task.take_command(out));
    out.lease.reset();
    EXPECT_EQ(owner.released.load(), 1);
    task.drop_commands();
    EXPECT_EQ(owner.released.load(), 3);
    EXPECT_FALSE(task.take_command(out));
}

// A command pushed from another thread reaches the running task, which takes it inside its tick.
// The push happens only after the first tick, which asked for no deadline, so only the push's
// wake can deliver it; the future has no timeout, so a push that does not wake the task hangs
// here and the watchdog names the test.
TEST(ProtocolTaskCommands, CommandFromAnotherThreadWakesTheTick) {
    ProtocolTask task(MAX_CONNECTIONS);
    std::promise<void> first_tick;
    std::promise<std::string> taken;
    std::atomic<int> ticks{0};
    bool fulfilled = false;
    ASSERT_TRUE(task.start(
        [&]() {
            if (++ticks == 1) {
                first_tick.set_value();
            }
            ProtocolCommand command;
            while (task.take_command(command)) {
                if (!fulfilled && command.type == ProtocolCommandType::CONNECT_TO) {
                    fulfilled = true;
                    taken.set_value(command.text);
                }
            }
            return ProtocolTask::NO_DEADLINE;
        },
        TEST_STACK, TEST_PRIORITY, false));

    first_tick.get_future().get();
    std::thread producer([&]() {
        task.push_command(make_command(ProtocolCommandType::CONNECT_TO, "ws://from-producer"));
    });
    EXPECT_EQ(taken.get_future().get(), "ws://from-producer");
    producer.join();
    task.stop();
}

// A state published while the task waits on NO_DEADLINE wakes it, and the tick it wakes takes
// the snapshot. The push happens only after the first tick, so only publish_state()'s own wake
// can run the second; the future has no timeout, so a publish that does not wake the task hangs
// here and the watchdog names the test.
TEST(ProtocolTaskState, PublishedStateWakesAParkedTask) {
    ProtocolTask task(MAX_CONNECTIONS);
    std::promise<void> first_tick;
    std::promise<bool> applied;
    std::atomic<int> ticks{0};
    bool fulfilled = false;
    ASSERT_TRUE(task.start(
        [&]() {
            if (++ticks == 1) {
                first_tick.set_value();
            }
            ClientStateMessage state;
            if (!fulfilled && task.take_state(state)) {
                fulfilled = true;
                applied.set_value(state.available);
            }
            return ProtocolTask::NO_DEADLINE;
        },
        TEST_STACK, TEST_PRIORITY, false));

    first_tick.get_future().get();
    ClientStateMessage published;
    published.available = false;
    task.publish_state(published);
    EXPECT_FALSE(applied.get_future().get());
    task.stop();
}

// A tick that reports no deadline runs again only on a wake: wake() runs it at once. The second
// tick checks that the wake had been issued before it ran, which a re-run on a timer would not
// see; the future has no timeout, so a wake that does not run the tick hangs here and the
// watchdog names the test.
TEST(ProtocolTaskWait, WakeRunsATickThatAskedForNoDeadline) {
    ProtocolTask task(MAX_CONNECTIONS);
    std::atomic<bool> woken{false};
    std::atomic<int> ticks{0};
    std::promise<void> first_tick;
    std::promise<bool> second_tick_saw_wake;
    ASSERT_TRUE(task.start(
        [&]() {
            const int n = ++ticks;
            if (n == 1) {
                first_tick.set_value();
            } else if (n == 2) {
                second_tick_saw_wake.set_value(woken.load());
            }
            return ProtocolTask::NO_DEADLINE;
        },
        TEST_STACK, TEST_PRIORITY, false));

    first_tick.get_future().get();
    woken = true;
    task.wake();
    EXPECT_TRUE(second_tick_saw_wake.get_future().get());
    task.stop();
}

// start() refuses a second start while running; after stop() the task starts again and runs the
// new tick. Control: the first start succeeds.
TEST(ProtocolTaskLifecycle, RestartsAfterStopAndRefusesADoubleStart) {
    ProtocolTask task(MAX_CONNECTIONS);
    std::promise<void> first_ran;
    std::atomic<bool> first_set{false};
    ASSERT_TRUE(task.start(
        [&]() {
            if (!first_set.exchange(true)) {
                first_ran.set_value();
            }
            return ProtocolTask::NO_DEADLINE;
        },
        TEST_STACK, TEST_PRIORITY, false));
    first_ran.get_future().get();
    EXPECT_FALSE(task.start([] { return ProtocolTask::NO_DEADLINE; }, TEST_STACK, TEST_PRIORITY,
                            false));
    task.stop();
    EXPECT_FALSE(task.is_running());

    std::promise<void> second_ran;
    std::atomic<bool> second_set{false};
    ASSERT_TRUE(task.start(
        [&]() {
            if (!second_set.exchange(true)) {
                second_ran.set_value();
            }
            return ProtocolTask::NO_DEADLINE;
        },
        TEST_STACK, TEST_PRIORITY, false));
    second_ran.get_future().get();
    EXPECT_TRUE(task.is_running());
    task.stop();
}

}  // namespace
}  // namespace sendspin
