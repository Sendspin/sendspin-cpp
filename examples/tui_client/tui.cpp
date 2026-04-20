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

#include "tui.h"

#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>

namespace sendspin {

using namespace ftxui;

// Immutable snapshot of TuiState for rendering without holding the mutex.
struct TuiSnapshot {
    std::string title;
    std::string artist;
    std::string album;
    uint8_t group_volume{0};
    uint8_t player_volume{0};
    bool group_muted{false};
    bool player_muted{false};
    uint32_t track_progress_ms{0};
    uint32_t track_duration_ms{0};
    std::chrono::steady_clock::time_point progress_updated_at;
    SendspinRepeatMode repeat_mode{SendspinRepeatMode::OFF};
    bool shuffle{false};
    SendspinPlaybackState playback_state{SendspinPlaybackState::STOPPED};
    std::optional<SendspinCodecFormat> codec;
    std::optional<uint32_t> sample_rate;
    std::optional<uint8_t> bit_depth;
    std::optional<uint8_t> channels;
    uint16_t static_delay_ms{0};
    bool connected{false};
    bool time_synced{false};
    std::string group_name;
    bool streaming{false};
    std::string connected_host;
    uint16_t connected_port{0};

    // Server selector
    bool server_selector_active{false};
    int server_selector_index{0};
    std::vector<DiscoveredServer> discovered_servers;

    // Shortcut highlight feedback
    std::string highlighted_label;
    bool highlight_active{false};

    // Visualizer
    bool show_visualizer{false};
    bool visualizer_active{false};
    uint16_t vis_peak_freq{0};
    std::vector<float> vis_display_spectrum;
    float vis_display_loudness{0.0f};
    bool vis_beat{false};
};

static TuiSnapshot take_snapshot(TuiState& state) {
    std::lock_guard<std::mutex> lock(state.mutex);
    TuiSnapshot snap;
    snap.title = state.title;
    snap.artist = state.artist;
    snap.album = state.album;
    snap.group_volume = state.group_volume;
    snap.player_volume = state.player_volume;
    snap.group_muted = state.group_muted;
    snap.player_muted = state.player_muted;
    snap.track_progress_ms = state.track_progress_ms;
    snap.track_duration_ms = state.track_duration_ms;
    snap.progress_updated_at = state.progress_updated_at;
    snap.repeat_mode = state.repeat_mode;
    snap.shuffle = state.shuffle;
    snap.playback_state = state.playback_state;
    snap.codec = state.codec;
    snap.sample_rate = state.sample_rate;
    snap.bit_depth = state.bit_depth;
    snap.channels = state.channels;
    snap.static_delay_ms = state.static_delay_ms;
    snap.connected = state.connected;
    snap.time_synced = state.time_synced;
    snap.group_name = state.group_name;
    snap.streaming = state.streaming;
    snap.connected_host = state.connected_host;
    snap.connected_port = state.connected_port;
    snap.server_selector_active = state.server_selector_active;
    snap.server_selector_index = state.server_selector_index;
    snap.discovered_servers = state.discovered_servers;
    auto now = std::chrono::steady_clock::now();
    if (!state.highlighted_label.empty() && now < state.highlight_expire) {
        snap.highlighted_label = state.highlighted_label;
        snap.highlight_active = true;
    }
    snap.show_visualizer = state.show_visualizer;
    snap.visualizer_active = state.visualizer_active;
    snap.vis_peak_freq = state.vis_peak_freq;
    snap.vis_display_spectrum = state.vis_display_spectrum;
    snap.vis_display_loudness = state.vis_display_loudness;
    snap.vis_beat = state.vis_beat;
    return snap;
}

static std::string format_time(uint32_t ms) {
    uint32_t total_seconds = ms / 1000;
    uint32_t minutes = total_seconds / 60;
    uint32_t seconds = total_seconds % 60;
    char buf[16];
    snprintf(buf, sizeof(buf), "%02u:%02u", minutes, seconds);
    return buf;
}

static std::string format_sample_rate(uint32_t rate) {
    if (rate % 1000 == 0) {
        return std::to_string(rate / 1000) + " kHz";
    }
    char buf[16];
    snprintf(buf, sizeof(buf), "%.1f kHz", rate / 1000.0);
    return buf;
}

static std::string repeat_mode_str(SendspinRepeatMode mode) {
    switch (mode) {
        case SendspinRepeatMode::OFF:
            return "Off";
        case SendspinRepeatMode::ONE:
            return "One";
        case SendspinRepeatMode::ALL:
            return "All";
        default:
            return "Off";
    }
}

static std::string codec_str(SendspinCodecFormat codec) {
    switch (codec) {
        case SendspinCodecFormat::FLAC:
            return "FLAC";
        case SendspinCodecFormat::OPUS:
            return "Opus";
        case SendspinCodecFormat::PCM:
            return "PCM";
        default:
            return "---";
    }
}

// Set the highlight label and expiry time (call with mutex held).
static void set_highlight(TuiState& state, const std::string& label) {
    state.highlighted_label = label;
    state.highlight_expire = std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
}

// Returns true if the given label should be rendered highlighted.
static bool is_highlighted(const TuiSnapshot& snap, const std::string& label) {
    return snap.highlight_active && snap.highlighted_label == label;
}

// Render a shortcut key label with highlight if active.
static Element shortcut_label(const TuiSnapshot& snap, const std::string& label,
                              const std::string& display) {
    if (is_highlighted(snap, label)) {
        return text(display) | bold | color(Color::Yellow) | inverted;
    }
    return text(display) | bold | color(Color::Cyan);
}

static Element render_now_playing(const TuiSnapshot& snap) {
    auto make_shortcuts = [&] {
        return vbox({
            separator(),
            hbox({
                text("  "),
                shortcut_label(snap, "<", "\u2190"),
                text(" prev  ") | color(Color::White) | dim,
                shortcut_label(snap, "Space", "<space>"),
                text(" play/pause  ") | color(Color::White) | dim,
                shortcut_label(snap, ">", "\u2192"),
                text(" next") | color(Color::White) | dim,
            }),
        });
    };

    // Not connected: show connection guidance
    if (!snap.connected) {
        return window(text(" Now Playing ") | bold, vbox({
            text("  Waiting for server connection...") | color(Color::White) | dim,
            text("  Press s to browse for servers") | color(Color::White) | dim,
            text(""),
            make_shortcuts(),
        })) | color(Color::Blue);
    }

    // Connected but stopped with no metadata: show playback guidance
    if (snap.playback_state == SendspinPlaybackState::STOPPED && snap.title.empty()) {
        return window(text(" Now Playing ") | bold, vbox({
            text("  Ready to play") | color(Color::White) | dim,
            text("  Press <space> to start playback") | color(Color::White) | dim,
            text("  Press g to join a group") | color(Color::White) | dim,
            make_shortcuts(),
        })) | color(Color::Blue);
    }

    // Normal display with metadata
    auto title_text = snap.title.empty() ? "\u2014" : snap.title;
    auto artist_text = snap.artist.empty() ? "Unknown artist" : snap.artist;
    auto album_text = snap.album.empty() ? "Unknown album" : snap.album;

    return window(text(" Now Playing ") | bold, vbox({
        hbox({text("  Title:  ") | color(Color::White) | dim, text(title_text) | bold | color(Color::White) | flex}),
        hbox({text("  Artist: ") | color(Color::White) | dim, text(artist_text) | color(Color::Cyan) | flex}),
        hbox({text("  Album:  ") | color(Color::White) | dim, text(album_text) | color(Color::White) | dim | flex}),
        make_shortcuts(),
    })) | color(Color::Blue);
}

static Element render_volume(const TuiSnapshot& snap) {
    auto vol_row = [](const std::string& label, uint8_t vol, bool muted) {
        float level = muted ? 0.0f : vol / 100.0f;
        auto bar_color = muted ? Color::GrayDark : Color::Cyan;
        Elements row_elems = {
            text("  " + label) | color(Color::White) | dim,
            gauge(level) | flex | color(bar_color),
        };
        if (muted) {
            row_elems.push_back(text(" [MUTED]") | color(Color::Red));
        } else {
            row_elems.push_back(text(" " + std::to_string(vol) + "%") | color(Color::Cyan));
        }
        return hbox(std::move(row_elems));
    };

    return window(text(" Volume ") | bold, vbox({
        vol_row("Group:  ", snap.group_volume, snap.group_muted),
        vol_row("Player: ", snap.player_volume, snap.player_muted),
        separator(),
        hbox({
            text("  "),
            shortcut_label(snap, "Up/Dn", "\u2191/\u2193"),
            text(" player  ") | color(Color::White) | dim,
            shortcut_label(snap, "m", "m"),
            text(" mute") | color(Color::White) | dim,
        }),
        hbox({
            text("  "),
            shortcut_label(snap, "[ / ]", "[/]"),
            text(" group  ") | color(Color::White) | dim,
            shortcut_label(snap, "M", "M"),
            text(" mute") | color(Color::White) | dim,
        }),
    })) | color(Color::Magenta);
}

static Element render_progress_bar(float progress, int width) {
    // ASCII progress bar: [====>--------]
    int bar_width = std::max(0, width - 2);  // subtract [ and ]
    int filled = static_cast<int>(progress * bar_width);
    filled = std::clamp(filled, 0, bar_width);
    int empty = bar_width - filled;

    // Build: [=====>-------]
    Elements elems;
    elems.push_back(text("[") | dim);
    if (filled > 0) {
        elems.push_back(text(std::string(filled - 1, '=') + ">") | bold | color(Color::Green));
    } else {
        elems.push_back(text(">") | bold | color(Color::Green));
        empty = std::max(0, empty - 1);
    }
    if (empty > 0) {
        elems.push_back(text(std::string(empty, '-')) | dim);
    }
    elems.push_back(text("]") | dim);
    return hbox(std::move(elems));
}

static Element render_progress(const TuiSnapshot& snap) {
    // Interpolate progress during playback for smooth movement
    uint32_t display_progress_ms = snap.track_progress_ms;
    if (snap.playback_state == SendspinPlaybackState::PLAYING &&
        snap.progress_updated_at.time_since_epoch().count() > 0 &&
        snap.track_duration_ms > 0) {
        auto elapsed = std::chrono::steady_clock::now() - snap.progress_updated_at;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        display_progress_ms += static_cast<uint32_t>(elapsed_ms);
        display_progress_ms = std::min(display_progress_ms, snap.track_duration_ms);
    }

    float progress = snap.track_duration_ms > 0
                         ? static_cast<float>(display_progress_ms) / snap.track_duration_ms
                         : 0.0f;
    progress = std::clamp(progress, 0.0f, 1.0f);

    // Get terminal width to size the bar. Subtract padding for time + borders.
    int term_width = Terminal::Size().dimx;
    int time_width = 14;   // "  MM:SS " + " MM:SS  " ≈ 14 chars + border
    int bar_width = std::max(10, term_width - time_width - 4);

    return window(text(" Progress ") | bold, hbox({
        text("  " + format_time(display_progress_ms) + " ") | color(Color::Cyan),
        render_progress_bar(progress, bar_width) | flex,
        text(" " + format_time(snap.track_duration_ms) + "  ") | color(Color::Cyan),
    })) | color(Color::Green);
}

static Element render_info_panels(const TuiSnapshot& snap, int terminal_width) {
    // Helper for dim label + cyan value rows
    auto info_row = [](const std::string& label, const std::string& value, bool has_value = true) {
        if (has_value) {
            return hbox({text("  " + label) | color(Color::White) | dim, text(value) | color(Color::Cyan)});
        }
        return hbox({text("  " + label) | color(Color::White) | dim, text("\u2014") | color(Color::White) | dim});
    };

    auto repeat_val = repeat_mode_str(snap.repeat_mode);
    bool repeat_active = snap.repeat_mode != SendspinRepeatMode::OFF;
    auto shuffle_val = snap.shuffle ? "On" : "Off";

    auto playback_panel = window(text(" Playback ") | bold, vbox({
        hbox({text("  Repeat:  ") | color(Color::White) | dim,
              repeat_active ? text(repeat_val) | color(Color::Cyan) : text(repeat_val) | color(Color::White) | dim}),
        hbox({text("  Shuffle: ") | color(Color::White) | dim,
              snap.shuffle ? text(shuffle_val) | color(Color::Cyan) : text(shuffle_val) | color(Color::White) | dim}),
        text(""),
        text(""),
        text(""),
        separator(),
        hbox({
            text("  "),
            shortcut_label(snap, "r", "r"),
            text(" repeat  ") | color(Color::White) | dim,
            shortcut_label(snap, "x", "x"),
            text(" shuffle") | color(Color::White) | dim,
        }),
    })) | color(Color::Yellow);

    std::string codec_display = snap.codec ? codec_str(*snap.codec) : "";
    std::string rate_display = snap.sample_rate ? format_sample_rate(*snap.sample_rate) : "";
    std::string depth_display = snap.bit_depth ? std::to_string(*snap.bit_depth) + "bit" : "";
    std::string channels_display;
    if (snap.channels) {
        channels_display = (*snap.channels == 2) ? "Stereo" : std::to_string(*snap.channels) + "ch";
    }
    bool has_stream = snap.codec.has_value();

    auto stream_panel = window(text(" Stream ") | bold, vbox({
        info_row("Codec:    ", codec_display, has_stream),
        info_row("Rate:     ", rate_display, has_stream),
        info_row("Depth:    ", depth_display, has_stream),
        info_row("Channels: ", channels_display, has_stream),
        info_row("Delay:    ", "+" + std::to_string(snap.static_delay_ms) + "ms", true),
        separator(),
        hbox({
            text("  "),
            shortcut_label(snap, ", / .", ",/."),
            text(" adjust delay") | color(Color::White) | dim,
        }),
    })) | color(Color::Yellow);

    auto connection_color = snap.connected ? Color::Green : Color::Red;
    auto connection_str = snap.connected ? "Connected" : "Disconnected";
    auto host_display = snap.connected_host.empty() ? "\u2014" : snap.connected_host;
    auto port_display = snap.connected_port > 0 ? std::to_string(snap.connected_port) : "\u2014";

    // Build server info rows — group only shown when set (matches reference)
    Elements server_rows;
    server_rows.push_back(hbox({text("  Status: ") | color(Color::White) | dim, text(connection_str) | bold | color(connection_color)}));
    server_rows.push_back(info_row("Host:    ", host_display, !snap.connected_host.empty()));
    if (snap.connected_port > 0) {
        server_rows.push_back(info_row("Port:    ", port_display, true));
    }
    if (!snap.group_name.empty()) {
        server_rows.push_back(info_row("Group:   ", snap.group_name, true));
    }
    // Pad to match stream panel height (5 data rows + separator + shortcut = 7)
    while (server_rows.size() < 5) {
        server_rows.push_back(text(""));
    }
    server_rows.push_back(separator());

    auto server_panel = window(text(" Server ") | bold, vbox({
        vbox(std::move(server_rows)),
        hbox({
            text("  "),
            shortcut_label(snap, "g", "g"),
            text(" group  ") | color(Color::White) | dim,
            shortcut_label(snap, "s", "s"),
            text(" server") | color(Color::White) | dim,
        }),
    })) | color(Color::Yellow);

    // Responsive: stack vertically if terminal is narrow
    if (terminal_width < 80) {
        return vbox({playback_panel, stream_panel, server_panel});
    }
    return hbox({playback_panel | flex, stream_panel | flex, server_panel | flex});
}

static Color spectrum_color_for_bin(int bin, int total_bins) {
    // Gradient: blue (low freq) -> green (mid) -> red (high)
    float t = total_bins > 1 ? static_cast<float>(bin) / (total_bins - 1) : 0.0f;
    if (t < 0.5f) {
        // Blue to green
        float s = t * 2.0f;
        uint8_t r = 0;
        uint8_t g = static_cast<uint8_t>(255 * s);
        uint8_t b = static_cast<uint8_t>(255 * (1.0f - s));
        return Color::RGB(r, g, b);
    } else {
        // Green to red
        float s = (t - 0.5f) * 2.0f;
        uint8_t r = static_cast<uint8_t>(255 * s);
        uint8_t g = static_cast<uint8_t>(255 * (1.0f - s));
        uint8_t b = 0;
        return Color::RGB(r, g, b);
    }
}

static Element render_visualizer(const TuiSnapshot& snap) {
    // Block characters for bar heights (index 0 = empty, 8 = full block)
    static const char* blocks[] = {" ", "\u2581", "\u2582", "\u2583",
                                    "\u2584", "\u2585", "\u2586", "\u2587", "\u2588"};

    if (!snap.visualizer_active && snap.vis_display_spectrum.empty()) {
        auto shortcuts = hbox({
            text("  "),
            text("v") | bold | color(Color::Cyan), text(" player  ") | dim,
            text("q") | bold | color(Color::Cyan), text(" quit") | dim,
        });

        return vbox({
            window(text(" Visualizer ") | bold, vbox({
                text(""),
                text("  Waiting for visualizer stream...") | dim,
                text("  Start playback on the server to see the spectrum.") | dim,
                text(""),
            })),
            filler(),
            shortcuts,
        });
    }

    int num_bins = static_cast<int>(snap.vis_display_spectrum.size());
    int num_rows = 8;  // vertical resolution in rows

    // Determine bar width: scale to fill terminal width
    // Account for window border (2 chars) and left padding (1 char)
    int term_width = Terminal::Size().dimx;
    int available_width = std::max(num_bins, term_width - 4);
    int bar_width = num_bins > 0 ? available_width / num_bins : 1;
    bar_width = std::max(1, bar_width);

    // Build the repeated block string for a given fill level
    auto make_bar = [&](int fill, int width) -> std::string {
        std::string result;
        const char* block = blocks[fill];
        for (int w = 0; w < width; ++w) {
            result += block;
        }
        return result;
    };

    // Build spectrum rows from top to bottom
    Elements spectrum_rows;
    for (int row = num_rows - 1; row >= 0; --row) {
        Elements bar_elements;
        bar_elements.push_back(text(" "));
        for (int bin = 0; bin < num_bins; ++bin) {
            // Display values are already 0.0-1.0 normalized
            float normalized = std::clamp(snap.vis_display_spectrum[bin], 0.0f, 1.0f);
            int total_height = static_cast<int>(normalized * num_rows * 8);
            int row_start = row * 8;
            int fill = std::clamp(total_height - row_start, 0, 8);

            auto col = spectrum_color_for_bin(bin, num_bins);
            bar_elements.push_back(text(make_bar(fill, bar_width)) | color(col));
        }
        spectrum_rows.push_back(hbox(std::move(bar_elements)));
    }

    auto spectrum_box = window(text(" Spectrum ") | bold, vbox(std::move(spectrum_rows)));

    // Loudness bar (smoothed display value, already 0.0-1.0)
    float loudness_pct = std::clamp(snap.vis_display_loudness, 0.0f, 1.0f);
    auto loudness_row = hbox({
        text("  Loudness: ") | bold,
        gauge(loudness_pct) | flex | color(Color::Magenta),
        text(" " + std::to_string(static_cast<int>(loudness_pct * 100)) + "% "),
    });

    // Peak frequency
    auto peak_row = hbox({
        text("  Peak:     ") | bold,
        text(std::to_string(snap.vis_peak_freq) + " Hz"),
    });

    // Beat indicator
    Element beat_elem;
    if (snap.vis_beat) {
        beat_elem = hbox({
            text("  "),
            text("\xe2\x97\x8f Beat") | bold | color(Color::Yellow),
        });
    } else {
        beat_elem = hbox({
            text("  "),
            text("\xe2\x97\x8b Beat") | dim,
        });
    }

    auto info_panel = window(text(" Analysis ") | bold, vbox({
        loudness_row,
        peak_row,
        beat_elem,
    }));

    auto shortcuts = hbox({
        text("  "),
        text("v") | bold | color(Color::Cyan), text(" player  ") | dim,
        text("<space>") | bold | color(Color::Cyan), text(" play/pause  ") | dim,
        text("\u2190/\u2192") | bold | color(Color::Cyan), text(" prev/next  ") | dim,
        text("q") | bold | color(Color::Cyan), text(" quit") | dim,
    });

    return vbox({
        spectrum_box,
        info_panel,
        filler(),
        shortcuts,
    });
}

static Element render_server_selector(const TuiSnapshot& snap) {
    Elements rows;
    if (snap.discovered_servers.empty()) {
        rows.push_back(text("  Searching for servers...") | color(Color::White) | dim);
    } else {
        for (int i = 0; i < static_cast<int>(snap.discovered_servers.size()); ++i) {
            const auto& server = snap.discovered_servers[i];
            bool selected = (i == snap.server_selector_index);
            bool is_current = (!snap.connected_host.empty() && server.host == snap.connected_host &&
                               server.port == snap.connected_port);

            // Line 1: indicator + name + (current)
            Elements name_elems;
            if (selected) {
                name_elems.push_back(text(" > ") | bold | color(Color::Cyan));
                name_elems.push_back(text(server.name) | bold | color(Color::White));
            } else {
                name_elems.push_back(text("   ") | color(Color::White));
                name_elems.push_back(text(server.name) | color(Color::White));
            }
            if (is_current) {
                name_elems.push_back(text(" (current)") | color(Color::Green) | dim);
            }
            rows.push_back(hbox(std::move(name_elems)));

            // Line 2: host:port
            std::string addr = server.host + ":" + std::to_string(server.port);
            if (selected) {
                rows.push_back(text("      " + addr) | color(Color::Cyan));
            } else {
                rows.push_back(text("      " + addr) | color(Color::White) | dim);
            }
        }
    }

    auto shortcuts = hbox({
        text("  "),
        shortcut_label(snap, "selector-up", "\u2191"),
        text("/"),
        shortcut_label(snap, "selector-down", "\u2193"),
        text(" navigate  ") | color(Color::White) | dim,
        shortcut_label(snap, "selector-enter", "enter"),
        text(" connect  ") | color(Color::White) | dim,
        shortcut_label(snap, "selector-refresh", "r"),
        text(" refresh  ") | color(Color::White) | dim,
        text("q") | bold | color(Color::Cyan),
        text(" back") | color(Color::White) | dim,
    });

    return vbox({
        window(text(" Select Server ") | bold, vbox(rows) | flex) | flex | color(Color::Cyan),
        filler(),
        shortcuts,
    });
}

static Element render_footer(const TuiSnapshot& snap) {
    return hbox({
        filler(),
        shortcut_label(snap, "v", "v"),
        text(" visualizer  ") | dim,
        text("q") | bold | color(Color::Cyan),
        text(" quit  ") | dim,
    });
}

static Element render_tui(TuiState& state) {
    auto snap = take_snapshot(state);

    if (snap.server_selector_active) {
        return render_server_selector(snap);
    }

    if (snap.show_visualizer) {
        return render_visualizer(snap);
    }

    int width = Terminal::Size().dimx;

    Element top_section;
    if (width < 80) {
        top_section = vbox({
            render_now_playing(snap),
            render_volume(snap),
        });
    } else {
        top_section = hbox({
            render_now_playing(snap) | flex,
            render_volume(snap),
        });
    }

    return vbox({
        top_section,
        render_progress(snap),
        render_info_panels(snap, width),
        filler(),
        render_footer(snap),
    });
}

static bool handle_selector_key(const Event& event, SendspinClient& client, TuiState& state) {
    // Navigate up
    if (event == Event::ArrowUp) {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.server_selector_index > 0) {
            --state.server_selector_index;
        }
        return true;
    }

    // Navigate down
    if (event == Event::ArrowDown) {
        std::lock_guard<std::mutex> lock(state.mutex);
        int max_index = static_cast<int>(state.discovered_servers.size()) - 1;
        if (state.server_selector_index < max_index) {
            ++state.server_selector_index;
        }
        return true;
    }

    // Connect to selected server
    if (event == Event::Return) {
        std::string url;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (state.discovered_servers.empty()) {
                return true;
            }
            int idx = state.server_selector_index;
            if (idx < 0 || idx >= static_cast<int>(state.discovered_servers.size())) {
                return true;
            }
            const auto& server = state.discovered_servers[idx];
            std::string path = server.path.empty() ? "/sendspin" : server.path;
            url = "ws://" + server.host + ":" + std::to_string(server.port) + path;
            state.connected_host = server.host;
            state.connected_port = server.port;
            state.server_selector_active = false;
        }
        client.connect_to(url);
        return true;
    }

    // Refresh: handled in main.cpp via on_selector_refresh callback; just a no-op here
    if (event == Event::Character('r')) {
        // The refresh is signaled by setting a flag that the browser monitors.
        // For now, this is a visual acknowledgement; browsing is continuous.
        return true;
    }

    // Back to main view
    if (event == Event::Escape || event == Event::Character('q')) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.server_selector_active = false;
        return true;
    }

    return false;
}

static bool handle_key(const Event& event, SendspinClient& client, TuiState& state,
                       ScreenInteractive& screen) {
    // Check if server selector is active
    bool selector_active;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        selector_active = state.server_selector_active;
    }
    if (selector_active) {
        return handle_selector_key(event, client, state);
    }

    // Toggle visualizer view
    if (event == Event::Character('v') || event == Event::Tab) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.show_visualizer = !state.show_visualizer;
        set_highlight(state, "v");
        return true;
    }

    // Enter server selector mode
    if (event == Event::Character('s')) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.server_selector_active = true;
        state.server_selector_index = 0;
        set_highlight(state, "s");
        return true;
    }

    // Play/Pause
    if (event == Event::Character(' ')) {
        SendspinPlaybackState current;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            current = state.playback_state;
            set_highlight(state, "Space");
        }
        if (current == SendspinPlaybackState::PLAYING) {
            client.controller()->send_command(SendspinControllerCommand::PAUSE);
        } else {
            client.controller()->send_command(SendspinControllerCommand::PLAY);
        }
        return true;
    }

    // Next track
    if (event == Event::ArrowRight) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, ">");
        }
        client.controller()->send_command(SendspinControllerCommand::NEXT);
        return true;
    }

    // Previous track
    if (event == Event::ArrowLeft) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "<");
        }
        client.controller()->send_command(SendspinControllerCommand::PREVIOUS);
        return true;
    }

    // Player volume up
    if (event == Event::ArrowUp) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "Up/Dn");
        }
        uint8_t vol = client.player()->get_volume();
        uint8_t new_vol = static_cast<uint8_t>(std::min(100, vol + 5));
        client.player()->update_volume(new_vol);
        return true;
    }

    // Player volume down
    if (event == Event::ArrowDown) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "Up/Dn");
        }
        uint8_t vol = client.player()->get_volume();
        uint8_t new_vol = static_cast<uint8_t>(std::max(0, vol - 5));
        client.player()->update_volume(new_vol);
        return true;
    }

    // Group volume up
    if (event == Event::Character(']')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "[ / ]");
        }
        auto& cs = client.controller()->get_controller_state();
        uint8_t new_vol = static_cast<uint8_t>(std::min(100, cs.volume + 5));
        client.controller()->send_command(SendspinControllerCommand::VOLUME, new_vol);
        return true;
    }

    // Group volume down
    if (event == Event::Character('[')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "[ / ]");
        }
        auto& cs = client.controller()->get_controller_state();
        uint8_t new_vol = static_cast<uint8_t>(std::max(0, cs.volume - 5));
        client.controller()->send_command(SendspinControllerCommand::VOLUME, new_vol);
        return true;
    }

    // Player mute toggle
    if (event == Event::Character('m')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "m");
        }
        client.player()->update_muted(!client.player()->get_muted());
        return true;
    }

    // Group mute toggle
    if (event == Event::Character('M')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "M");
        }
        auto& cs = client.controller()->get_controller_state();
        client.controller()->send_command(SendspinControllerCommand::MUTE, std::nullopt, !cs.muted);
        return true;
    }

    // Cycle repeat mode: OFF -> ALL -> ONE -> OFF
    if (event == Event::Character('r')) {
        SendspinRepeatMode current;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            current = state.repeat_mode;
            set_highlight(state, "r");
        }
        switch (current) {
            case SendspinRepeatMode::OFF:
                client.controller()->send_command(SendspinControllerCommand::REPEAT_ALL);
                break;
            case SendspinRepeatMode::ALL:
                client.controller()->send_command(SendspinControllerCommand::REPEAT_ONE);
                break;
            case SendspinRepeatMode::ONE:
                client.controller()->send_command(SendspinControllerCommand::REPEAT_OFF);
                break;
        }
        return true;
    }

    // Toggle shuffle
    if (event == Event::Character('x')) {
        bool current;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            current = state.shuffle;
            set_highlight(state, "x");
        }
        client.controller()->send_command(current ? SendspinControllerCommand::UNSHUFFLE
                                                  : SendspinControllerCommand::SHUFFLE);
        return true;
    }

    // Join group
    if (event == Event::Character('g')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, "g");
        }
        client.controller()->send_command(SendspinControllerCommand::SWITCH);
        return true;
    }

    // Static delay increase
    if (event == Event::Character('.')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, ", / .");
        }
        uint16_t delay = client.player()->get_static_delay_ms();
        client.player()->update_static_delay(delay + 10);
        return true;
    }

    // Static delay decrease
    if (event == Event::Character(',')) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            set_highlight(state, ", / .");
        }
        uint16_t delay = client.player()->get_static_delay_ms();
        client.player()->update_static_delay(delay >= 10 ? delay - 10 : 0);
        return true;
    }

    // Quit
    if (event == Event::Character('q') || event == Event::Character('Q')) {
        screen.Exit();
        return true;
    }

    return false;
}

Component create_tui_component(SendspinClient& client, TuiState& state,
                               ScreenInteractive& screen) {
    auto renderer = Renderer([&state] { return render_tui(state); });

    return CatchEvent(renderer, [&](Event event) -> bool {
        return handle_key(event, client, state, screen);
    });
}

void update_polled_state(TuiState& state, SendspinClient& client) {
    std::lock_guard<std::mutex> lock(state.mutex);
    uint32_t new_progress = client.metadata() ? client.metadata()->get_track_progress_ms() : 0;
    if (new_progress != state.track_progress_ms) {
        state.track_progress_ms = new_progress;
        state.progress_updated_at = std::chrono::steady_clock::now();
    }
    state.track_duration_ms = client.metadata() ? client.metadata()->get_track_duration_ms() : 0;
    state.connected = client.is_connected();
    state.time_synced = client.is_time_synced();
    state.static_delay_ms = client.player() ? client.player()->get_static_delay_ms() : 0;
    state.player_volume = client.player() ? client.player()->get_volume() : 0;
    state.player_muted = client.player() ? client.player()->get_muted() : false;
    state.group_name = client.get_group_state().group_name.value_or("");

    if (client.controller()) {
        auto& cs = client.controller()->get_controller_state();
        state.group_volume = cs.volume;
        state.group_muted = cs.muted;
    }
}

}  // namespace sendspin
