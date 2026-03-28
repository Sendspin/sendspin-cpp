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

#pragma once

#include "sendspin/client.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

/// @brief A discovered Sendspin server from mDNS browsing.
struct DiscoveredServer {
    std::string name;  ///< Friendly server name from mDNS
    std::string host;  ///< Resolved IP address or hostname
    uint16_t port{0};  ///< Server port
    std::string path;  ///< WebSocket path from TXT record (e.g., "/sendspin")
};

/// @brief Shared state between SendspinClient callbacks and the TUI render thread.
/// All fields are protected by the mutex.
struct TuiState {
    mutable std::mutex mutex;

    // Metadata
    std::string title;
    std::string artist;
    std::string album;

    // Volume
    uint8_t group_volume{0};
    uint8_t player_volume{0};
    bool group_muted{false};
    bool player_muted{false};

    // Progress
    uint32_t track_progress_ms{0};
    uint32_t track_duration_ms{0};

    // Playback
    SendspinRepeatMode repeat_mode{SendspinRepeatMode::OFF};
    bool shuffle{false};
    SendspinPlaybackState playback_state{SendspinPlaybackState::STOPPED};

    // Stream info
    std::optional<SendspinCodecFormat> codec;
    std::optional<uint32_t> sample_rate;
    std::optional<uint8_t> bit_depth;
    std::optional<uint8_t> channels;
    uint16_t static_delay_ms{0};

    // Connection
    bool connected{false};
    bool time_synced{false};
    std::string group_name;
    bool streaming{false};

    // Server selector
    bool server_selector_active{false};
    int server_selector_index{0};
    std::vector<DiscoveredServer> discovered_servers;

    // Shortcut highlight feedback
    std::string highlighted_label;
    std::chrono::steady_clock::time_point highlight_expire;

    // Visualizer
    bool visualizer_active{false};
    uint16_t vis_loudness{0};
    uint16_t vis_peak_freq{0};
    std::vector<uint16_t> vis_spectrum;         // raw target values from server
    std::vector<float> vis_display_spectrum;     // smoothed display values (decay toward target)
    float vis_display_loudness{0.0f};            // smoothed loudness for display
    bool vis_beat{false};
    int64_t vis_beat_expire_us{0};

    // Tab state
    bool show_visualizer{false};
};

/// @brief Creates the FTXUI component tree with rendering and key handling.
/// @param client The SendspinClient for sending commands.
/// @param state Shared TUI state (updated by callbacks and polling).
/// @param screen The FTXUI screen (needed for Exit on quit).
/// @return The root FTXUI component.
ftxui::Component create_tui_component(SendspinClient& client, TuiState& state,
                                      ftxui::ScreenInteractive& screen);

/// @brief Polls client state that doesn't have callbacks (progress, controller state, etc.).
/// Called periodically from the background thread.
void update_polled_state(TuiState& state, SendspinClient& client);

}  // namespace sendspin
