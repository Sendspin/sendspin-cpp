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

// The plaintext message trace (SendspinClientConfig::message_trace). Built only with
// SENDSPIN_ENABLE_MESSAGE_TRACE.

#include "lifecycle_test_fixtures.h"
#include "message_trace.h"
#include "platform/time.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {
namespace {

constexpr uint16_t TRACE_TEST_PORT = 19110;

/// Encoded audio bytes in the chunk the fake server sends.
constexpr size_t AUDIO_PAYLOAD_BYTES = 1000;

/// One traced message, copied out of the callback.
struct TraceRecord {
    uint64_t connection_id{0};
    SendspinTraceDirection direction{SendspinTraceDirection::INBOUND};
    bool binary{false};
    int64_t stamp_us{0};
    std::vector<uint8_t> plaintext;
    size_t audio_bytes{0};

    /// The JSON `type` of a cleartext message or a transport JSON body, or "binary <id>" for any
    /// other transport message.
    std::string type() const {
        const bool json = !this->binary || (!this->plaintext.empty() && this->plaintext[0] == 0);
        if (!json) {
            return "binary " + std::to_string(this->plaintext.empty() ? -1 : this->plaintext[0]);
        }
        const size_t offset = this->binary ? 1 : 0;
        JsonDocument doc;
        if (deserializeJson(doc, reinterpret_cast<const char*>(this->plaintext.data()) + offset,
                            this->plaintext.size() - offset)) {
            return "unparsable";
        }
        return doc["type"].as<std::string>();
    }
};

/// Collects every traced message. The trace runs on the protocol task; the test thread reads.
class TraceCollector {
public:
    SendspinMessageTraceFn callback() {
        return [this](const SendspinTracedMessage& message) {
            TraceRecord record;
            record.connection_id = message.connection_id;
            record.direction = message.direction;
            record.binary = message.binary;
            record.stamp_us = message.stamp_us;
            record.plaintext.assign(message.plaintext, message.plaintext + message.plaintext_len);
            record.audio_bytes = message.audio_bytes;
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->records_.push_back(std::move(record));
        };
    }

    std::vector<TraceRecord> records() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->records_;
    }

    bool has(SendspinTraceDirection direction, const std::string& type) const {
        for (const TraceRecord& record : this->records()) {
            if (record.direction == direction && record.type() == type) {
                return true;
            }
        }
        return false;
    }

private:
    mutable std::mutex mutex_;
    std::vector<TraceRecord> records_;
};

using Dir = SendspinTraceDirection;

// A server-initiated connection read through the trace alone: the handshake in order, transport
// messages as plaintext, and an audio chunk's encoded audio bytes.
TEST(MessageTrace, RecordsTheHandshakeTheTransportMessagesAndAnAudioChunk) {
    TraceCollector collector;
    SendspinClientConfig config;
    config.name = "Message Trace Test Client";
    config.server_port = TRACE_TEST_PORT;
    config.message_trace = collector.callback();

    const int64_t start_us = platform_time_us();
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"([])";
    auto server = connect_paired_server(bundle.peer, TRACE_TEST_PORT, std::move(options));
    pump_until(client, [&] { return collector.has(Dir::INBOUND, "server/activate"); });

    // Traced before dispatch, so the chunk shows although no player takes it.
    ASSERT_TRUE(server->send_audio(platform_time_us(), AUDIO_PAYLOAD_BYTES));
    pump_until(client, [&] { return collector.has(Dir::INBOUND, "binary 4"); });
    // Snapshot first: the protocol task may trace more messages while this runs.
    const std::vector<TraceRecord> records = collector.records();
    const int64_t end_us = platform_time_us();

    // Each step answers the one before it, so the order is fixed (messaging.md "Communication").
    // Readable transport JSON shows it was traced before the encrypt and after the decrypt.
    struct Expected {
        Dir direction;
        bool binary;
        const char* type;
    };
    const std::vector<Expected> expected_prefix = {
        {Dir::OUTBOUND, false, "client/init"},     {Dir::INBOUND, false, "server/init"},
        {Dir::INBOUND, false, "noise/handshake"},  {Dir::OUTBOUND, false, "noise/handshake"},
        {Dir::INBOUND, true, "server/hello"},      {Dir::OUTBOUND, true, "client/hello"},
        {Dir::INBOUND, true, "server/activate"},
    };
    ASSERT_GT(records.size(), expected_prefix.size());
    for (size_t i = 0; i < expected_prefix.size(); ++i) {
        EXPECT_EQ(records[i].direction, expected_prefix[i].direction) << "entry " << i;
        EXPECT_EQ(records[i].binary, expected_prefix[i].binary) << "entry " << i;
        EXPECT_EQ(records[i].type(), expected_prefix[i].type) << "entry " << i;
    }

    // The audio chunk: type byte, 8-byte timestamp, 4-byte send_ahead, then the audio.
    size_t audio_chunks = 0;
    for (const TraceRecord& record : records) {
        if (record.type() == "binary 4") {
            ++audio_chunks;
            EXPECT_EQ(record.plaintext.size(), 1 + 8 + 4 + AUDIO_PAYLOAD_BYTES);
            EXPECT_EQ(record.audio_bytes, AUDIO_PAYLOAD_BYTES);
        } else {
            EXPECT_EQ(record.audio_bytes, 0U) << record.type();
        }
    }
    EXPECT_EQ(audio_chunks, 1U);

    // One connection, and every stamp read from the clock while the test ran.
    for (const TraceRecord& record : records) {
        EXPECT_NE(record.connection_id, 0U);
        EXPECT_EQ(record.connection_id, records.front().connection_id);
        EXPECT_GE(record.stamp_us, start_us) << record.type();
        EXPECT_LE(record.stamp_us, end_us) << record.type();
    }

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Each pairing secret reads "<redacted>" and nothing else changes; a message with no secret, and
// a binary message, reach the trace as the very bytes sent.
TEST(MessageTrace, RedactsThePairingSecretsAndNothingElse) {
    struct Row {
        const char* name;
        bool binary;
        std::string sent;
        std::string traced;  // Empty: the sent bytes, unchanged and not copied.
    };
    const std::string json_body(1, '\0');
    const std::string audio("\x04", 1);
    const std::vector<Row> rows = {
        {"cleartext long_term_psk", false,
         R"({"type":"client/pair-finalize","payload":{"long_term_psk":"SECRETSECRET"}})",
         R"({"type":"client/pair-finalize","payload":{"long_term_psk":"<redacted>"}})"},
        {"transport wrapped_psk", true,
         json_body + R"({"type":"client/pair-finalize","payload":{"wrapped_psk":"SECRET"}})",
         json_body + R"({"type":"client/pair-finalize","payload":{"wrapped_psk":"<redacted>"}})"},
        {"wrapped_nonce_B beside client_kc", true,
         json_body +
             R"({"type":"client/pair-confirm","payload":{"client_kc":"TAG","wrapped_nonce_B":"SECRET"}})",
         json_body +
             R"({"type":"client/pair-confirm","payload":{"client_kc":"TAG","wrapped_nonce_B":"<redacted>"}})"},
        {"unterminated value", true, json_body + R"({"payload":{"wrapped_psk":"SECR)",
         json_body + R"({"payload":{"wrapped_psk":"<redacted>)"},
        {"no secret", true, json_body + R"({"type":"client/state","payload":{}})", ""},
        {"binary audio", true, audio + R"("wrapped_psk":"BYTES")", ""},
    };

    for (const Row& row : rows) {
        std::vector<std::string> traced;
        std::vector<const uint8_t*> pointers;
        MessageTracer tracer;
        tracer.configure(
            [&](const SendspinTracedMessage& message) {
                traced.emplace_back(reinterpret_cast<const char*>(message.plaintext),
                                    message.plaintext_len);
                pointers.push_back(message.plaintext);
            },
            1);
        const auto* sent = reinterpret_cast<const uint8_t*>(row.sent.data());
        if (row.binary) {
            tracer.trace_outbound(sent, row.sent.size());
        } else {
            tracer.trace_outbound_text(row.sent);
        }

        ASSERT_EQ(traced.size(), 1U) << row.name;
        if (row.traced.empty()) {
            EXPECT_EQ(pointers[0], sent) << row.name;
        } else {
            EXPECT_EQ(traced[0], row.traced) << row.name;
            EXPECT_EQ(traced[0].find("SECR"), std::string::npos) << row.name;
        }
    }
}

}  // namespace
}  // namespace sendspin
