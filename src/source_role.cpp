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

#include "connection.h"
#include "connection_manager.h"
#include "platform/logging.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "source_role_impl.h"

#include <algorithm>
#include <iterator>

static const char* const TAG = "sendspin.source";

namespace sendspin {

// ============================================================================
// Helpers
// ============================================================================

/// @brief Validates the capture format contract, logging every rejection at ERROR. Fail
/// closed, never clamp or repair; an invalid config leaves the role inert (added, but never
/// advertised or streaming), like a player with no audio formats.
static bool validate_config(const SourceRoleConfig& config) {
    bool valid = true;
    if (config.codec != SendspinCodecFormat::PCM && config.codec != SendspinCodecFormat::OPUS) {
        SS_LOGE(TAG, "Rejecting source config: codec must be pcm or opus (got %d)",
                static_cast<int>(config.codec));
        valid = false;
    }
    if (config.codec == SendspinCodecFormat::OPUS) {
        // libopus accepts exactly these rates; a 44100 line-in must use PCM or resample
        static constexpr uint32_t OPUS_SAMPLE_RATES[] = {8000, 12000, 16000, 24000, 48000};
        // Single legal Opus frames within the spec's chunk bounds
        static constexpr uint32_t OPUS_CHUNK_DURATIONS_MS[] = {10, 20, 40, 60};
        const auto contains = [](const auto& values, uint32_t value) {
            return std::find(std::begin(values), std::end(values), value) != std::end(values);
        };
        if (!contains(OPUS_SAMPLE_RATES, config.sample_rate)) {
            SS_LOGE(TAG,
                    "Rejecting source config: opus sample_rate must be 8000, 12000, 16000, "
                    "24000, or 48000 (got %u)",
                    config.sample_rate);
            valid = false;
        }
        if (config.channels != 1 && config.channels != 2) {
            SS_LOGE(TAG, "Rejecting source config: opus channels must be 1 or 2 (got %u)",
                    config.channels);
            valid = false;
        }
        if (config.bit_depth != 16) {
            // The capture contract: the encoder consumes 16-bit PCM (the wire field is ignored
            // by servers for opus per the Sendspin spec)
            SS_LOGE(TAG, "Rejecting source config: opus bit_depth must be 16 (got %u)",
                    config.bit_depth);
            valid = false;
        }
        if (!contains(OPUS_CHUNK_DURATIONS_MS, config.chunk_duration_ms)) {
            // One chunk is one opus_encode() call, so it must be one legal frame; the PCM
            // default of 25 is deliberately not remapped -- fail closed beats silent repair
            SS_LOGE(TAG,
                    "Rejecting source config: opus chunk_duration_ms must be 10, 20, 40, or 60 "
                    "(got %u)",
                    config.chunk_duration_ms);
            valid = false;
        }
        if (config.opus_bitrate < SourceRoleConfig::OPUS_BITRATE_MIN ||
            config.opus_bitrate > SourceRoleConfig::OPUS_BITRATE_MAX) {
            // libopus's accepted OPUS_SET_BITRATE range
            SS_LOGE(TAG, "Rejecting source config: opus_bitrate %u outside [%u, %u]",
                    config.opus_bitrate, SourceRoleConfig::OPUS_BITRATE_MIN,
                    SourceRoleConfig::OPUS_BITRATE_MAX);
            valid = false;
        }
        if (config.opus_complexity > SourceRoleConfig::OPUS_COMPLEXITY_MAX) {
            SS_LOGE(TAG, "Rejecting source config: opus_complexity %u exceeds %u",
                    config.opus_complexity, SourceRoleConfig::OPUS_COMPLEXITY_MAX);
            valid = false;
        }
    } else {
        // PCM format rules (also applied to a rejected codec value)
        if (config.sample_rate == 0) {
            SS_LOGE(TAG, "Rejecting source config: sample_rate must be > 0");
            valid = false;
        }
        if (config.channels == 0) {
            SS_LOGE(TAG, "Rejecting source config: channels must be > 0");
            valid = false;
        }
        if (config.bit_depth != 16 && config.bit_depth != 24 && config.bit_depth != 32) {
            SS_LOGE(TAG, "Rejecting source config: bit_depth must be 16, 24, or 32 (got %u)",
                    config.bit_depth);
            valid = false;
        }
        if (config.chunk_duration_ms < SourceRoleConfig::CHUNK_MIN_MS ||
            config.chunk_duration_ms > SourceRoleConfig::CHUNK_MAX_MS) {
            // Sendspin spec, Source messages: MUST <= 150 ms, SHOULD >= 5 ms; the SHOULD is
            // deliberately enforced as hard as the MUST
            SS_LOGE(TAG, "Rejecting source config: chunk_duration_ms %u outside [%u, %u]",
                    config.chunk_duration_ms, SourceRoleConfig::CHUNK_MIN_MS,
                    SourceRoleConfig::CHUNK_MAX_MS);
            valid = false;
        }
    }
    if (config.capture_buffer_ms == 0) {
        SS_LOGE(TAG, "Rejecting source config: capture_buffer_ms must be > 0");
        valid = false;
    }
    return valid;
}

// ============================================================================
// Impl constructor / destructor
// ============================================================================

SourceRole::Impl::Impl(SourceRoleConfig config, SendspinClient* client)
    : config(config),
      client(client),
      event_state(std::make_unique<EventState>()),
      task(std::make_unique<SourceTask>()),
      config_valid(validate_config(config)) {}

SourceRole::Impl::~Impl() {
    // Join the task first: the consumer's capture thread may still be inside write_audio(),
    // so the task and its capture ring must outlive that call
    this->task.reset();
}

// ============================================================================
// SourceRole forwarding (public API -> Impl)
// ============================================================================

SourceRole::SourceRole(SourceRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(config, client)) {}

SourceRole::~SourceRole() = default;

void SourceRole::set_listener(SourceRoleListener* listener) {
    this->impl_->listener = listener;
}

bool SourceRole::write_audio(const uint8_t* data, size_t len, int64_t capture_time_us) {
    return this->impl_->write_audio(data, len, capture_time_us);
}

void SourceRole::set_signal(SourceSignal signal) {
    this->impl_->set_signal(signal);
}

bool SourceRole::is_streaming() const {
    return this->impl_->streaming_active;
}

// ============================================================================
// Impl: Internal integration methods
// ============================================================================

void SourceRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->command_slot.bind(inbox, INBOX_TOPIC_SOURCE_COMMAND);
}

bool SourceRole::Impl::start() {
    if (this->config_valid && !this->task->is_initialized()) {
        if (!this->task->init(this, this->client, this->connection_manager)) {
            SS_LOGE(TAG, "Failed to initialize source task");
            return false;
        }
        if (!this->task->start(this->config.psram_stack, this->config.priority)) {
            SS_LOGE(TAG, "Failed to start source task thread");
            return false;
        }
    }
    return true;
}

void SourceRole::Impl::build_hello_fields(ClientHelloMessage& msg) {
    if (!this->config_valid) {
        return;
    }

    msg.supported_roles.push_back(SendspinRole::SOURCE);
    msg.source_v1_support = SourceSupportObject{.line_sense = this->config.line_sense};
}

void SourceRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (!this->config_valid) {
        return;
    }

    // The source object may legitimately be present and empty; signal is included only when
    // line_sense is configured and a state has been reported (Sendspin spec, Source messages --
    // Client state object)
    ClientSourceStateObject source_state{};
    if (this->config.line_sense && this->signal.has_value()) {
        source_state.signal = this->signal;
    }
    msg.source = source_state;
}

void SourceRole::Impl::handle_server_command(SourceCommand command,
                                             uint64_t connection_instance_id) const {
    this->event_state->command_slot.write(SourceCommandEnvelope{connection_instance_id, command});
}

void SourceRole::Impl::on_stream_ring_event(SourceStreamCallbackType event) {
    this->pending_events.push_back(event);
}

void SourceRole::Impl::drain_events() {
    // --- Server command latch ---
    SourceCommandEnvelope envelope;
    if (this->event_state->command_slot.take(envelope)) {
        auto* current = this->connection_manager->current();
        if (current == nullptr || current->get_instance_id() != envelope.connection_instance_id) {
            // Per-connection permission (Sendspin spec, Source messages): a command from a
            // displaced connection must not grant the current one
            SS_LOGD(TAG, "Discarding source command from a stale connection");
        } else {
            const bool start = envelope.command == SourceCommand::START;
            // Only a transition reaches the task: commands are idempotent per the spec
            if (start != this->streaming_desired) {
                this->streaming_desired = start;
                if (start) {
                    this->task->signal_start();
                } else {
                    this->task->signal_stop();
                }
            }
        }
    }

    // --- Stream lifecycle events from the task ---
    if (this->pending_events.empty()) {
        return;
    }

    size_t processed = 0;
    // Indexed with a fresh size() check per iteration: a listener callback may re-enter
    // cleanup(), which clears this vector mid-loop (player-role pattern)
    // NOLINTNEXTLINE(modernize-loop-convert): body mutates the vector, see above
    for (size_t idx = 0; idx < this->pending_events.size(); ++idx) {
        const SourceStreamCallbackType event = this->pending_events[idx];
        switch (event) {
            case SourceStreamCallbackType::STREAMING_STARTED: {
                if (!this->streaming_active) {
                    this->streaming_active = true;
                    if (this->listener) {
                        this->listener->on_streaming_started();
                    }
                }
                break;
            }
            case SourceStreamCallbackType::STREAMING_STOPPED: {
                // streaming_active keeps the callbacks paired 1:1 (cleanup() enqueues an
                // unconditional STOPPED)
                if (this->streaming_active) {
                    this->streaming_active = false;
                    if (this->listener) {
                        this->listener->on_streaming_stopped();
                    }
                }
                break;
            }
        }
        ++processed;
    }

    // A re-entrant cleanup() may have cleared the vector mid-loop
    if (processed > this->pending_events.size()) {
        processed = this->pending_events.size();
    }
    if (processed > 0) {
        this->pending_events.erase(
            this->pending_events.begin(),
            this->pending_events.begin() + static_cast<ptrdiff_t>(processed));
    }
}

void SourceRole::Impl::cleanup() {
    // Permission does not survive the connection (Sendspin spec, Source messages)
    this->streaming_desired = false;
    this->task->signal_stop();

    // Discard a stale command from the dead connection
    this->event_state->command_slot.reset();

    // STREAMING_STOPPED is pushed unconditionally: a second teardown in the same tick wipes the
    // ring before it drains (see cleanup_connection_state()); streaming_active keeps the
    // listener callbacks paired, so an extra STOPPED is harmless
    this->pending_events.clear();
    this->enqueue_stream_event(SourceStreamCallbackType::STREAMING_STOPPED);
}

// ============================================================================
// Impl: Consumer-facing method implementations
// ============================================================================

bool SourceRole::Impl::write_audio(const uint8_t* data, size_t len, int64_t capture_time_us) const {
    return this->task->write_audio(data, len, capture_time_us);
}

void SourceRole::Impl::set_signal(SourceSignal new_signal) {
    if (!this->config.line_sense) {
        SS_LOGW(TAG, "set_signal() ignored: line_sense not configured");
        return;
    }
    this->signal = new_signal;
    this->client->publish_state();
}

// ============================================================================
// Impl: Helpers
// ============================================================================

void SourceRole::Impl::enqueue_stream_event(SourceStreamCallbackType event) const {
    // A dropped lifecycle event wedges the listener state, so drops log at ERROR
    push_event_or_log(this->inbox, InboxEventType::SOURCE_STREAM, static_cast<uint8_t>(event), TAG,
                      event == SourceStreamCallbackType::STREAMING_STARTED ? "STREAMING_STARTED"
                                                                           : "STREAMING_STOPPED",
                      /*error_level=*/true);
}

}  // namespace sendspin
