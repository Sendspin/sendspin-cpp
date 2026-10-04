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
/// @brief Tests for the protocol task's plumbing: the command queue's order and its reserved
/// accept slots, the latest-state and lifecycle-request slots, delivery to the running task, the
/// no-deadline wait, and stop()

#include "protocol_task.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <thread>

namespace sendspin {
namespace {

// A command whose controller-command volume tags it, so a take can tell which push it came from.
ProtocolCommand make_command(ProtocolCommandType type, uint8_t tag = 0) {
    ProtocolCommand command;
    command.type = type;
    command.controller_command.volume = tag;
    return command;
}

constexpr size_t MAX_CONNECTIONS = SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS;
constexpr size_t ACCEPT_SLOTS = ProtocolTask::ACCEPT_SLOTS_PER_SOCKET * MAX_CONNECTIONS;
constexpr size_t TEST_STACK = 8192;
constexpr unsigned TEST_PRIORITY = 5;

// Commands come out in the order they went in, accepts and consumer commands interleaved.
TEST(ProtocolTaskCommands, TakesCommandsInPushOrder) {
    ProtocolTask task(MAX_CONNECTIONS);
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND, 1)));
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::ACCEPT_CONNECTION)));
    ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND, 2)));

    ProtocolCommand out;
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::SEND_CONTROLLER_COMMAND);
    EXPECT_EQ(out.controller_command.volume, 1);
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::ACCEPT_CONNECTION);
    ASSERT_TRUE(task.take_command(out));
    EXPECT_EQ(out.type, ProtocolCommandType::SEND_CONTROLLER_COMMAND);
    EXPECT_EQ(out.controller_command.volume, 2);
    EXPECT_FALSE(task.take_command(out));
}

// Consumer commands are bounded by CONSUMER_COMMAND_BURST, and a burst that fills them cannot
// take an accept's reserved slot: every one of the ACCEPT_SLOTS accepts still queues. The push
// past either bound is refused. Control: every push within the bounds is accepted.
TEST(ProtocolTaskCommands, ConsumerBurstIsBoundedAndAcceptsKeepTheirReservedSlots) {
    ProtocolTask task(MAX_CONNECTIONS);
    for (size_t i = 0; i < ProtocolTask::CONSUMER_COMMAND_BURST; ++i) {
        ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND)));
    }
    EXPECT_FALSE(task.push_command(make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND)));

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

// stop() leaves the commands and the lifecycle requests the final tick did not take for the
// joining thread, which takes them (an accept refused after the join) or drops them. The state
// snapshot describes a run that is over, so stop() drops it. The tick never takes anything, so
// only the joining thread can.
TEST(ProtocolTaskCommands, StopLeavesQueuedCommandsForTheJoiningThread) {
    ProtocolTask task(MAX_CONNECTIONS);
    ASSERT_TRUE(task.start([] { return ProtocolTask::NO_DEADLINE; }, TEST_STACK, TEST_PRIORITY,
                           false));
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(task.push_command(make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND)));
    }
    task.post_requests({.leave = true});
    task.publish_state(ClientStateMessage{});
    task.stop();
    EXPECT_FALSE(task.is_running());
    ClientStateMessage state;
    EXPECT_FALSE(task.take_state(state)) << "the snapshot outlived the run";

    // The joining thread takes one command and the request, then drops the rest of the commands
    // and a request posted after the take.
    ProtocolCommand out;
    ASSERT_TRUE(task.take_command(out)) << "stop() dropped a command the joining thread owns";
    LifecycleRequests requests;
    ASSERT_TRUE(task.take_requests(requests)) << "stop() dropped a request the joining thread owns";
    EXPECT_TRUE(requests.leave);
    task.post_requests({.leave = true});
    task.drop_commands();
    EXPECT_FALSE(task.take_command(out));
    EXPECT_FALSE(task.take_requests(requests)) << "a request outlived drop_commands()";
}

// A command pushed, or a lifecycle request posted, from another thread reaches the running task,
// which takes it inside its tick. The producer runs only after the first tick, which asked for no
// deadline, so only the push's or the post's own wake can deliver it; the future has no timeout,
// so one that does not wake the task hangs here and the watchdog names the test.
TEST(ProtocolTaskCommands, CommandOrRequestFromAnotherThreadWakesTheTick) {
    constexpr uint8_t PRODUCER_TAG = 42;
    for (const bool request : {false, true}) {
        SCOPED_TRACE(request ? "a lifecycle request" : "a queued command");
        ProtocolTask task(MAX_CONNECTIONS);
        std::promise<void> first_tick;
        std::promise<void> taken;
        std::atomic<int> ticks{0};
        bool fulfilled = false;
        ASSERT_TRUE(task.start(
            [&]() {
                if (++ticks == 1) {
                    first_tick.set_value();
                }
                ProtocolCommand command;
                bool seen = false;
                while (task.take_command(command)) {
                    seen = seen || command.controller_command.volume == PRODUCER_TAG;
                }
                LifecycleRequests requests;
                seen = seen || (task.take_requests(requests) && requests.leave);
                if (seen && !fulfilled) {
                    fulfilled = true;
                    taken.set_value();
                }
                return ProtocolTask::NO_DEADLINE;
            },
            TEST_STACK, TEST_PRIORITY, false));

        first_tick.get_future().get();
        std::thread producer([&]() {
            if (request) {
                task.post_requests({.leave = true});
            } else {
                task.push_command(
                    make_command(ProtocolCommandType::SEND_CONTROLLER_COMMAND, PRODUCER_TAG));
            }
        });
        taken.get_future().get();
        producer.join();
        task.stop();
    }
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
