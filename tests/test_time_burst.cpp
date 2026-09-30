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

/// @file test_time_burst.cpp
/// @brief Tests for SendspinTimeBurst's handling of server/time replies

#include "connection.h"
#include "time_burst.h"

#include <gtest/gtest.h>

#include <functional>
#include <string>

namespace sendspin {
namespace {

/// Socketless connection whose sends succeed; send_time_message() still fails, having no Noise
/// session.
class StubConnection : public SendspinConnection {
public:
    void start() override {}
    void loop() override {}
    void disconnect(SendspinGoodbyeReason /*reason*/, std::function<void()> on_complete) override {
        if (on_complete) {
            on_complete();
        }
    }
    void close_transport_now() override {}
    bool is_connected() const override {
        return true;
    }
    SsErr send_text_message(const std::string& /*message*/, SendCompleteCallback cb,
                            bool /*allow_before_hello*/) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
    SsErr send_binary_message(const uint8_t* /*data*/, size_t /*len*/, SendCompleteCallback cb,
                              bool /*allow_before_hello*/) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
};

// A reply counts only when it answers the message still pending. One with no message pending (its
// message already answered or timed out), or one matched to an earlier message on the network
// thread and drained after the next was sent, must not count: counted, it would complete a
// two-message burst after one real exchange.
TEST(TimeBurst, OnlyAReplyToThePendingMessageCounts) {
    // Long enough that loop() never times a message out during the test.
    constexpr int64_t RESPONSE_TIMEOUT_MS = 60000;
    StubConnection conn;
    conn.init_time_filter();
    conn.set_client_hello_sent(true);
    conn.set_server_hello_received(true);
    SendspinTimeBurst burst;
    burst.configure(/*burst_size=*/2, /*burst_interval_ms=*/0, RESPONSE_TIMEOUT_MS);

    // loop() starts the burst. The stub has no Noise transport, so the send fails after
    // send_time_message() records the frame in flight; the test marks the message pending itself,
    // as a successful send would.
    burst.loop(&conn);
    const int64_t embedded = conn.get_time_frame_stamp().embedded;
    conn.set_pending_time_message(true);

    EXPECT_FALSE(burst.on_time_response(&conn, /*offset=*/10, /*max_error=*/50, /*timestamp=*/1,
                                        embedded - 1));
    EXPECT_TRUE(conn.is_pending_time_message()) << "a reply to an earlier message must not count";

    EXPECT_FALSE(burst.on_time_response(&conn, 10, 50, 2, embedded));
    EXPECT_FALSE(conn.is_pending_time_message());

    EXPECT_FALSE(burst.on_time_response(&conn, 10, 50, 3, embedded)) << "no message is pending";

    conn.set_pending_time_message(true);
    EXPECT_TRUE(burst.on_time_response(&conn, 10, 50, 4, embedded))
        << "the second real reply ends the burst";
}

}  // namespace
}  // namespace sendspin
