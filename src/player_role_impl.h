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

/// @file player_role_impl.h
/// @brief Private implementation for the player role (pimpl)

#pragma once

#include "platform/shadow_slot.h"
#include "platform/thread_safe_queue.h"
#include "sendspin/player_role.h"
#include "sync_task.h"

#include <memory>
#include <vector>

namespace sendspin {

class SendspinClient;
class SendspinPersistenceProvider;
struct ClientHelloMessage;
struct ClientStateMessage;

/// @brief Deferred stream lifecycle callback types queued from the network thread
enum class PlayerStreamCallbackType : uint8_t {
    STREAM_START,  // New stream is starting
    STREAM_END,    // Stream ended normally
    STREAM_CLEAR,  // Stream cleared immediately
};

/// @brief Private implementation of the player role
struct PlayerRole::Impl {
    Impl(PlayerRoleConfig config, SendspinClient* client, SendspinPersistenceProvider* persistence);
    ~Impl();

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        ThreadSafeQueue<PlayerStreamCallbackType> stream_queue;
        ThreadSafeQueue<SendspinClientState> state_queue;
        ShadowSlot<ServerPlayerStreamObject> shadow_stream_params;
        ShadowSlot<ServerCommandMessage> shadow_command;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    void build_state_fields(ClientStateMessage& msg) const;
    void handle_binary(const uint8_t* data, size_t len) const;
    void handle_stream_start(const ServerPlayerStreamObject& player_obj);
    void handle_stream_end() const;
    void handle_stream_clear() const;
    void handle_server_command(const ServerCommandMessage& cmd) const;
    void drain_events();
    void cleanup();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    void update_volume(uint8_t volume);
    void update_muted(bool muted);
    void update_static_delay(uint16_t delay_ms);

    // ========================================
    // Helpers
    // ========================================

    bool send_audio_chunk(const uint8_t* data, size_t data_size, int64_t timestamp,
                          uint8_t chunk_type, uint32_t timeout_ms) const;
    void enqueue_state_update(SendspinClientState state) const;
    void load_static_delay();
    void persist_static_delay() const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    PlayerRoleConfig config;
    ServerPlayerStreamObject current_stream_params{};
    std::vector<PlayerStreamCallbackType> awaiting_sync_idle_events;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    PlayerRoleListener* listener{nullptr};
    SendspinPersistenceProvider* persistence;
    std::unique_ptr<SyncTask> sync_task;

    // 16-bit fields
    uint16_t static_delay_ms{0};

    // 8-bit fields
    bool high_performance_requested_for_playback{false};
    bool muted{false};
    bool static_delay_adjustable{false};
    uint8_t volume{0};
};

}  // namespace sendspin
