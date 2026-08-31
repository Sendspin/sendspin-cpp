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

// White-box test for ConnectionManager's promotion scan, reaching private state directly
// (compiled with -fno-access-control, see CMakeLists.txt) rather than through a real socket:
// reproducing the STOPPING-window race described by the accepting_ finding requires a nursery
// peer whose server/hello is processed by the network thread concurrently with (or immediately
// after) begin_stop()'s goodbye send, which is not reliably reproducible through a real
// WebSocket transport on host (IXWebSocket's server-side disconnect is synchronous, so
// is_connected() flips false in the same call as the goodbye send, closing the timing window
// that would let a real socket test hit it deterministically). Driving ConnectionManager's
// private nursery_/accepting_/current_connection_ state directly exercises the exact guarded
// code path (the promotion scan in ConnectionManager::loop()) under the exact precondition
// (accepting_ == false, a nursery entry with is_handshake_complete() == true) without depending
// on that race.

#include "connection.h"
#include "connection_manager.h"
#include "platform/time.h"
#include "sendspin/client.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

/// Minimal concrete SendspinConnection: no real transport, just enough state to drive the
/// handshake-complete and connected flags the promotion scan reads.
class FakeConnection : public SendspinConnection {
public:
    void start() override {}
    void loop() override {}

    void disconnect(SendspinGoodbyeReason /*reason*/, std::function<void()> on_complete) override {
        this->connected_.store(false);
        if (on_complete) {
            on_complete();
        }
    }

    bool is_connected() const override {
        return this->connected_.load();
    }

    SsErr send_text_message(const std::string& /*message*/, SendCompleteCallback cb,
                            bool /*allow_before_hello*/) override {
        ++this->send_count_;
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    bool send_time_message() override {
        return true;
    }

    void set_connected(bool connected) {
        this->connected_.store(connected);
    }

    int send_count() const {
        return this->send_count_;
    }

private:
    std::atomic<bool> connected_{false};
    int send_count_{0};
};

SendspinClientConfig make_config() {
    SendspinClientConfig config;
    config.client_id = "conn-manager-test-client";
    config.name = "Connection Manager Test Client";
    return config;
}

}  // namespace

// Finding: the promotion scan in ConnectionManager::loop() must not promote a nursery peer whose
// handshake completes while the manager is stopping (accepting_ cleared by begin_stop()). A
// connected nursery peer's message dispatch stays enabled through the goodbye window (unlike a
// released nursery entry), so an in-flight server/hello can still flip is_handshake_complete()
// during STOPPING; promoting it would hand it a client/state message after it was already told
// SHUTDOWN. (Parking it costs nothing: has_connections() counts nursery entries too, so the
// teardown deadline behaves the same either way.)
TEST(ConnectionManagerInternal, PromotionSkippedWhileStopping) {
    SendspinClientConfig config = make_config();
    SendspinClient client(config);
    // Private member access via -fno-access-control: exercises the manager owned by a real
    // client rather than standing up a duplicate one.
    ConnectionManager& manager = *client.connection_manager_;

    auto fake = std::make_shared<FakeConnection>();
    fake->set_connected(true);
    fake->set_client_hello_sent(true);
    fake->set_server_hello_received(true);
    ASSERT_TRUE(fake->is_handshake_complete());
    // Fresh timestamp so the nursery establish-deadline reap (30 s) does not fire first and mask
    // whether the promotion scan itself was skipped.
    fake->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.push_nursery_entry(NurseryEntry{fake, /*inbound=*/true});
    }

    // Simulate begin_stop() having already cleared the admission door.
    manager.accepting_.store(false, std::memory_order_release);

    manager.loop();

    // Not promoted: the current slot stays empty and the entry is neither sent a client/state
    // message nor released out of the nursery.
    EXPECT_EQ(manager.current(), nullptr);
    EXPECT_TRUE(manager.has_connections());
    EXPECT_EQ(fake->send_count(), 0);
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        ASSERT_EQ(manager.nursery_.size(), 1U);
        EXPECT_EQ(manager.nursery_.front().conn.get(), fake.get());
    }

    // Once accepting_ is restored (as init_server() does for a fresh start()), the same
    // already-established entry is free to promote on the very next tick: the fix leaves it
    // parked, not permanently stranded.
    manager.accepting_.store(true, std::memory_order_release);
    manager.loop();

    EXPECT_EQ(manager.current(), fake.get());
    EXPECT_EQ(fake->send_count(), 1);
}

// Finding: the hello scans in ConnectionManager::loop() must not send a client/hello to a peer
// that begin_stop() has already goodbyed. initiate_hello() never sends inline -- it arms a retry
// entry whose send happens on a later tick through the retry scan -- and disconnect() leaves a
// connected nursery peer parked with its entry intact, so without the accepting_ guard a peer
// admitted in the tick before request_stop() is handed a hello after its SHUTDOWN goodbye.
TEST(ConnectionManagerInternal, HelloNotSentWhileStopping) {
    SendspinClientConfig config = make_config();
    SendspinClient client(config);
    ConnectionManager& manager = *client.connection_manager_;

    auto fake = std::make_shared<FakeConnection>();
    fake->set_connected(true);
    // Fresh timestamp so the nursery establish-deadline reap (30 s) cannot release the entry and
    // mask whether the hello scan itself was skipped.
    fake->set_provisional_time_us(platform_time_us());
    ASSERT_FALSE(fake->is_handshake_complete());

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.push_nursery_entry(NurseryEntry{fake, /*inbound=*/true});
        // Exactly what on_new_connection() does at admission: arm the hello, send nothing yet.
        manager.initiate_hello(fake.get());
    }
    ASSERT_EQ(fake->send_count(), 0);

    // Simulate begin_stop() having already cleared the admission door and goodbyed this peer.
    manager.accepting_.store(false, std::memory_order_release);

    manager.loop();

    EXPECT_EQ(fake->send_count(), 0);
    EXPECT_TRUE(manager.has_connections());

    // Control: the same armed entry sends its hello on the very next tick once accepting_ is
    // restored, so the guard defers the send rather than silently dropping the handshake.
    manager.accepting_.store(true, std::memory_order_release);
    manager.loop();

    EXPECT_EQ(fake->send_count(), 1);
}

// Finding: loop()'s STOPPING completion gate must finish the teardown at the grace deadline even
// when a peer never delivers its close event. Without the deadline disjunct, has_connections()
// stays true forever and the client is stranded in STOPPING with on_stopped() never firing.
// Driven white-box because a real host socket cannot reproduce it: IXWebSocket's server-side
// disconnect is synchronous, so a real peer's close event always lands immediately.
TEST(ConnectionManagerInternal, StopDeadlineFinishesTeardownWhenPeerNeverCloses) {
    SendspinClientConfig config = make_config();
    SendspinClient client(config);
    ConnectionManager& manager = *client.connection_manager_;

    ASSERT_TRUE(client.start());

    // A peer that is connected when begin_stop() runs is goodbyed and left parked in the nursery
    // until its close event arrives. This one never delivers one.
    auto fake = std::make_shared<FakeConnection>();
    fake->set_connected(true);
    fake->set_provisional_time_us(platform_time_us());
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.push_nursery_entry(NurseryEntry{fake, /*inbound=*/true});
    }

    client.request_stop();
    ASSERT_EQ(client.get_run_state(), SendspinRunState::STOPPING);
    ASSERT_TRUE(manager.has_connections());

    // Control: pumping inside the grace window must not complete the teardown. Without this the
    // assertion below would also pass if the has_connections() gate had finished it early, and
    // the deadline would still be untested.
    for (int i = 0; i < 20; ++i) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_EQ(client.get_run_state(), SendspinRunState::STOPPING);
    EXPECT_TRUE(manager.has_connections());

    // Past STOP_GRACE_MS (750 ms, client.cpp) the deadline forces completion regardless.
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    client.loop();

    EXPECT_EQ(client.get_run_state(), SendspinRunState::STOPPED);
    EXPECT_FALSE(manager.has_connections());
}
