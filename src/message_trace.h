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

/// @file message_trace.h
/// @brief Compiled only with SENDSPIN_ENABLE_MESSAGE_TRACE

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace sendspin {

/// @brief Builds each SendspinTracedMessage for one connection and hands it to the client's
/// trace (SendspinClientConfig::message_trace). Protocol task only.
class MessageTracer {
public:
    /// @brief Installs the client's trace for one connection; an empty trace leaves tracing off
    void configure(const SendspinMessageTraceFn& trace, uint64_t connection_id) {
        this->trace_ = trace;
        this->connection_id_ = connection_id;
    }

    /// @brief Traces one complete received message; `receive_time_us` is on platform_time_us()
    void trace_inbound(bool binary, int64_t receive_time_us, const uint8_t* plaintext,
                       size_t len) const;

    /// @brief Traces one frame about to be encrypted, type byte first
    void trace_outbound(const uint8_t* plaintext, size_t len) const {
        this->emit_outbound(true, plaintext, len);
    }

    /// @brief Traces one cleartext text frame about to be sent
    void trace_outbound_text(std::string_view text) const {
        this->emit_outbound(false, reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

private:
    /// @brief Hands the trace one outbound message, stamped now, with its secrets redacted
    void emit_outbound(bool binary, const uint8_t* plaintext, size_t len) const;

    SendspinMessageTraceFn trace_;
    uint64_t connection_id_{0};
};

}  // namespace sendspin
