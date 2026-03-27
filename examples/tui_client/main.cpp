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

/// @file TUI client example for sendspin-cpp.
///
/// Runs a SendspinClient with a terminal user interface showing playback info,
/// volume, progress, and keyboard controls.
///
/// Usage: ./tui_client [options] [name]
///   name:  Optional friendly name (default: "TUI Client")
///
/// Options:
///   -h        Show usage

#include "tui.h"

#include "sendspin/client.h"
#ifdef SENDSPIN_HAS_PORTAUDIO
#include "portaudio_sink.h"
#endif

#include <arpa/inet.h>
#include <dns_sd.h>
#include <getopt.h>
#include <sys/select.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;

static const uint16_t SENDSPIN_PORT = 8928;
static const char* SENDSPIN_PATH = "/sendspin";

// Big-endian helpers for binary visualizer data parsing
static int64_t be64(const uint8_t* p) {
    return static_cast<int64_t>(p[0]) << 56 | static_cast<int64_t>(p[1]) << 48 |
           static_cast<int64_t>(p[2]) << 40 | static_cast<int64_t>(p[3]) << 32 |
           static_cast<int64_t>(p[4]) << 24 | static_cast<int64_t>(p[5]) << 16 |
           static_cast<int64_t>(p[6]) << 8 | static_cast<int64_t>(p[7]);
}

static uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) << 8 | static_cast<uint16_t>(p[1]);
}

static int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Audio sink that discards all audio data (used when PortAudio is not available)
class NullAudioSink : public AudioSink {
public:
    size_t write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        return length;
    }
};

// Manages mDNS service advertisement via dns_sd.h
class MdnsAdvertiser {
public:
    ~MdnsAdvertiser() {
        stop();
    }

    bool start(const std::string& name, uint16_t port, const std::string& path) {
        TXTRecordRef txt;
        TXTRecordCreate(&txt, 0, nullptr);
        TXTRecordSetValue(&txt, "path", static_cast<uint8_t>(path.size()), path.c_str());
        TXTRecordSetValue(&txt, "name", static_cast<uint8_t>(name.size()), name.c_str());

        DNSServiceErrorType err =
            DNSServiceRegister(&service_ref_, 0, 0, name.c_str(), "_sendspin._tcp", nullptr,
                               nullptr, htons(port), TXTRecordGetLength(&txt),
                               TXTRecordGetBytesPtr(&txt), nullptr, nullptr);

        TXTRecordDeallocate(&txt);

        return err == kDNSServiceErr_NoError;
    }

    void stop() {
        if (service_ref_ != nullptr) {
            DNSServiceRefDeallocate(service_ref_);
            service_ref_ = nullptr;
        }
    }

private:
    DNSServiceRef service_ref_{nullptr};
};

// Manages mDNS service browsing to discover Sendspin servers via dns_sd.h.
// Runs a background thread that processes DNS-SD events non-blockingly.
class MdnsBrowser {
public:
    ~MdnsBrowser() {
        stop();
    }

    bool start() {
        DNSServiceErrorType err = DNSServiceBrowse(&browse_ref_, 0, 0, "_sendspin._tcp", nullptr,
                                                   browse_callback, this);
        if (err != kDNSServiceErr_NoError) {
            return false;
        }

        running_.store(true);
        thread_ = std::thread([this] { run_loop(); });
        return true;
    }

    void stop() {
        running_.store(false);
        if (thread_.joinable()) {
            thread_.join();
        }
        // Clean up all resolve/addr refs
        {
            std::lock_guard<std::mutex> lock(resolve_mutex_);
            for (auto& ref : pending_resolves_) {
                DNSServiceRefDeallocate(ref);
            }
            pending_resolves_.clear();
        }
        if (browse_ref_ != nullptr) {
            DNSServiceRefDeallocate(browse_ref_);
            browse_ref_ = nullptr;
        }
    }

    // Returns a snapshot of currently discovered servers.
    std::vector<DiscoveredServer> get_servers() const {
        std::lock_guard<std::mutex> lock(servers_mutex_);
        std::vector<DiscoveredServer> result;
        result.reserve(servers_.size());
        for (const auto& [key, server] : servers_) {
            result.push_back(server);
        }
        return result;
    }

private:
    // Key for deduplicating discovered services: name + regtype + domain
    struct ServiceKey {
        std::string name;
        std::string regtype;
        std::string domain;

        bool operator<(const ServiceKey& o) const {
            if (name != o.name) return name < o.name;
            if (regtype != o.regtype) return regtype < o.regtype;
            return domain < o.domain;
        }
    };

    // Context passed through the resolve chain
    struct ResolveContext {
        MdnsBrowser* browser;
        ServiceKey key;
        std::string name;
        uint16_t port{0};
        std::string path;
    };

    void run_loop() {
        while (running_.load()) {
            // Collect all active refs to poll
            std::vector<DNSServiceRef> refs;
            refs.push_back(browse_ref_);
            {
                std::lock_guard<std::mutex> lock(resolve_mutex_);
                refs.insert(refs.end(), pending_resolves_.begin(), pending_resolves_.end());
            }

            fd_set read_fds;
            FD_ZERO(&read_fds);
            int max_fd = -1;

            for (auto ref : refs) {
                int fd = DNSServiceRefSockFD(ref);
                if (fd >= 0) {
                    FD_SET(fd, &read_fds);
                    if (fd > max_fd) max_fd = fd;
                }
            }

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200000;  // 200ms timeout

            int result = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (result > 0) {
                for (auto ref : refs) {
                    int fd = DNSServiceRefSockFD(ref);
                    if (fd >= 0 && FD_ISSET(fd, &read_fds)) {
                        DNSServiceProcessResult(ref);
                    }
                }
            }
        }
    }

    void add_resolve_ref(DNSServiceRef ref) {
        std::lock_guard<std::mutex> lock(resolve_mutex_);
        pending_resolves_.push_back(ref);
    }

    void remove_resolve_ref(DNSServiceRef ref) {
        std::lock_guard<std::mutex> lock(resolve_mutex_);
        pending_resolves_.erase(
            std::remove(pending_resolves_.begin(), pending_resolves_.end(), ref),
            pending_resolves_.end());
    }

    static void DNSSD_API browse_callback(DNSServiceRef /*ref*/, DNSServiceFlags flags,
                                           uint32_t interface_index, DNSServiceErrorType error,
                                           const char* name, const char* regtype,
                                           const char* domain, void* context) {
        if (error != kDNSServiceErr_NoError) return;
        auto* browser = static_cast<MdnsBrowser*>(context);

        ServiceKey key{name, regtype, domain};

        if (flags & kDNSServiceFlagsAdd) {
            // Service appeared — resolve it
            auto* ctx = new ResolveContext{browser, key, name, 0, ""};

            DNSServiceRef resolve_ref = nullptr;
            DNSServiceErrorType err = DNSServiceResolve(
                &resolve_ref, 0, interface_index, name, regtype, domain, resolve_callback, ctx);
            if (err == kDNSServiceErr_NoError) {
                browser->add_resolve_ref(resolve_ref);
            } else {
                delete ctx;
            }
        } else {
            // Service removed
            std::lock_guard<std::mutex> lock(browser->servers_mutex_);
            browser->servers_.erase(key);
        }
    }

    static void DNSSD_API resolve_callback(DNSServiceRef ref, DNSServiceFlags /*flags*/,
                                            uint32_t interface_index, DNSServiceErrorType error,
                                            const char* /*fullname*/, const char* hosttarget,
                                            uint16_t port, uint16_t txt_len,
                                            const unsigned char* txt_record, void* context) {
        auto* ctx = static_cast<ResolveContext*>(context);

        if (error != kDNSServiceErr_NoError) {
            ctx->browser->remove_resolve_ref(ref);
            DNSServiceRefDeallocate(ref);
            delete ctx;
            return;
        }

        ctx->port = ntohs(port);

        // Extract "path" from TXT record
        uint8_t path_len = 0;
        const void* path_val =
            TXTRecordGetValuePtr(txt_len, txt_record, "path", &path_len);
        if (path_val != nullptr && path_len > 0) {
            ctx->path = std::string(static_cast<const char*>(path_val), path_len);
        }

        // Done with resolve ref
        ctx->browser->remove_resolve_ref(ref);
        DNSServiceRefDeallocate(ref);

        // Now resolve the hostname to an IP address
        DNSServiceRef addr_ref = nullptr;
        DNSServiceErrorType err = DNSServiceGetAddrInfo(
            &addr_ref, 0, interface_index, kDNSServiceProtocol_IPv4, hosttarget,
            addr_info_callback, ctx);
        if (err == kDNSServiceErr_NoError) {
            ctx->browser->add_resolve_ref(addr_ref);
        } else {
            delete ctx;
        }
    }

    static void DNSSD_API addr_info_callback(DNSServiceRef ref, DNSServiceFlags /*flags*/,
                                              uint32_t /*interface_index*/,
                                              DNSServiceErrorType error, const char* /*hostname*/,
                                              const struct sockaddr* address, uint32_t /*ttl*/,
                                              void* context) {
        auto* ctx = static_cast<ResolveContext*>(context);

        if (error != kDNSServiceErr_NoError || address == nullptr) {
            ctx->browser->remove_resolve_ref(ref);
            DNSServiceRefDeallocate(ref);
            delete ctx;
            return;
        }

        // Extract IP address string
        char addr_str[INET6_ADDRSTRLEN] = {};
        if (address->sa_family == AF_INET) {
            const auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(address);
            inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        } else if (address->sa_family == AF_INET6) {
            const auto* addr_in6 = reinterpret_cast<const struct sockaddr_in6*>(address);
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        }

        if (addr_str[0] != '\0') {
            DiscoveredServer server;
            server.name = ctx->name;
            server.host = addr_str;
            server.port = ctx->port;
            server.path = ctx->path;

            std::lock_guard<std::mutex> lock(ctx->browser->servers_mutex_);
            ctx->browser->servers_[ctx->key] = std::move(server);
        }

        ctx->browser->remove_resolve_ref(ref);
        DNSServiceRefDeallocate(ref);
        delete ctx;
    }

    DNSServiceRef browse_ref_{nullptr};
    std::atomic<bool> running_{false};
    std::thread thread_;

    mutable std::mutex servers_mutex_;
    std::map<ServiceKey, DiscoveredServer> servers_;

    std::mutex resolve_mutex_;
    std::vector<DNSServiceRef> pending_resolves_;
};

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [name]\n", prog);
    fprintf(stderr, "  name          Friendly name (default: \"TUI Client\")\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u URL        Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)\n");
    fprintf(stderr, "  -V            Disable visualizer\n");
    fprintf(stderr, "  -h            Show this help\n");
}

int main(int argc, char* argv[]) {
    // Parse command line options
    bool enable_visualizer = true;
    std::string connect_url;
    int opt;
    while ((opt = getopt(argc, argv, "u:Vh")) != -1) {
        switch (opt) {
            case 'u':
                connect_url = optarg;
                break;
            case 'V':
                enable_visualizer = false;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Suppress library logging since FTXUI owns the terminal
    SendspinClient::set_log_level(LogLevel::NONE);

    std::string friendly_name = (optind < argc) ? argv[optind] : "TUI Client";

    // Configure the client
    SendspinClientConfig config;
    config.client_id = "host-tui-example";
    config.name = friendly_name;
    config.product_name = "sendspin-cpp host TUI";
    config.manufacturer = "sendspin-cpp";
    config.software_version = "0.1.0";
    config.controller = true;
    config.metadata = true;

    config.audio_formats = {
        {SendspinCodecFormat::FLAC, 2, 44100, 16}, {SendspinCodecFormat::FLAC, 2, 48000, 16},
        {SendspinCodecFormat::OPUS, 2, 48000, 16}, {SendspinCodecFormat::PCM, 2, 44100, 16},
        {SendspinCodecFormat::PCM, 2, 48000, 16},
    };

    // Visualizer support (disabled with -V flag)
    if (enable_visualizer) {
        VisualizerSupportObject vis;
        vis.types = {VisualizerDataType::BEAT, VisualizerDataType::LOUDNESS,
                     VisualizerDataType::F_PEAK, VisualizerDataType::SPECTRUM};
        vis.buffer_capacity = 8192;
        vis.batch_max = 4;
        vis.spectrum = VisualizerSpectrumConfig{
            .n_disp_bins = 32,
            .scale = VisualizerSpectrumScale::MEL,
            .f_min = 40,
            .f_max = 16000,
            .rate_max = 30,
        };
        config.visualizer = vis;
    }

    // Create audio sink
#ifdef SENDSPIN_HAS_PORTAUDIO
    PortAudioSink audio_sink;
#else
    NullAudioSink audio_sink;
#endif

    SendspinClient client(std::move(config));
    client.set_audio_sink(&audio_sink);

#ifdef SENDSPIN_HAS_PORTAUDIO
    audio_sink.on_frames_played = [&client](uint32_t frames, int64_t timestamp) {
        client.notify_audio_played(frames, timestamp);
    };
#endif

    client.is_network_ready = []() { return true; };

    // Shared TUI state
    TuiState state;

    // Wire callbacks to update TUI state
    client.on_metadata = [&state](const ServerMetadataStateObject& metadata) {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (metadata.title.has_value()) {
            state.title = *metadata.title;
        }
        if (metadata.artist.has_value()) {
            state.artist = *metadata.artist;
        }
        if (metadata.album.has_value()) {
            state.album = *metadata.album;
        }
        if (metadata.repeat.has_value()) {
            state.repeat_mode = *metadata.repeat;
        }
        if (metadata.shuffle.has_value()) {
            state.shuffle = *metadata.shuffle;
        }
    };

    client.on_group_update = [&state](const GroupUpdateObject& group) {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (group.playback_state.has_value()) {
            state.playback_state = *group.playback_state;
        }
        if (group.group_name.has_value()) {
            state.group_name = *group.group_name;
        }
    };

    client.on_volume_changed = [&state
#ifdef SENDSPIN_HAS_PORTAUDIO
                                ,
                                &audio_sink
#endif
    ](uint8_t vol) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.player_volume = vol;
        }
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.set_volume(vol);
#endif
    };

    client.on_mute_changed = [&state
#ifdef SENDSPIN_HAS_PORTAUDIO
                               ,
                               &audio_sink
#endif
    ](bool muted) {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.player_muted = muted;
        }
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.set_muted(muted);
#endif
    };

    client.on_static_delay_changed = [&state](uint16_t delay) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.static_delay_ms = delay;
    };

    client.on_stream_start = [&state, &client
#ifdef SENDSPIN_HAS_PORTAUDIO
                              ,
                              &audio_sink
#endif
    ]() {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            auto& params = client.get_current_stream_params();
            state.codec = params.codec;
            state.sample_rate = params.sample_rate;
            state.bit_depth = params.bit_depth;
            state.channels = params.channels;
            state.streaming = true;
        }
#ifdef SENDSPIN_HAS_PORTAUDIO
        auto& params = client.get_current_stream_params();
        if (params.sample_rate.has_value() && params.channels.has_value() &&
            params.bit_depth.has_value()) {
            audio_sink.configure(*params.sample_rate, *params.channels, *params.bit_depth);
        }
#endif
    };

    client.on_stream_end = [&state
#ifdef SENDSPIN_HAS_PORTAUDIO
                            ,
                            &audio_sink
#endif
    ]() {
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.streaming = false;
            state.codec = std::nullopt;
            state.sample_rate = std::nullopt;
            state.bit_depth = std::nullopt;
            state.channels = std::nullopt;
        }
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.clear();
#endif
    };

    client.on_stream_clear = [
#ifdef SENDSPIN_HAS_PORTAUDIO
                               &audio_sink
#endif
    ]() {
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.clear();
#endif
    };

    // Visualizer callbacks
    client.on_visualizer_stream_start = [&state](const ServerVisualizerStreamObject& vis_stream) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.visualizer_active = true;
        state.vis_active_types = vis_stream.types;
        if (vis_stream.spectrum.has_value()) {
            state.vis_stream_bin_count = vis_stream.spectrum->n_disp_bins;
            state.vis_spectrum.resize(vis_stream.spectrum->n_disp_bins, 0);
            state.vis_display_spectrum.resize(vis_stream.spectrum->n_disp_bins, 0.0f);
        }
        state.vis_display_loudness = 0.0f;
        state.vis_frames.clear();
        state.vis_beat_times.clear();
    };

    client.on_visualizer_stream_end = [&state]() {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.visualizer_active = false;
        state.vis_frames.clear();
        state.vis_beat_times.clear();
        state.vis_loudness = 0;
        state.vis_peak_freq = 0;
        std::fill(state.vis_spectrum.begin(), state.vis_spectrum.end(), uint16_t{0});
        std::fill(state.vis_display_spectrum.begin(), state.vis_display_spectrum.end(), 0.0f);
        state.vis_display_loudness = 0.0f;
        state.vis_beat = false;
    };

    client.on_visualizer_stream_clear = [&state]() {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.vis_frames.clear();
        state.vis_beat_times.clear();
        state.vis_loudness = 0;
        state.vis_peak_freq = 0;
        std::fill(state.vis_spectrum.begin(), state.vis_spectrum.end(), uint16_t{0});
        std::fill(state.vis_display_spectrum.begin(), state.vis_display_spectrum.end(), 0.0f);
        state.vis_display_loudness = 0.0f;
        state.vis_beat = false;
    };

    client.on_visualizer_data = [&state](const uint8_t* data, size_t len) {
        // Binary format: [type=16][num_frames][per-frame data...]
        if (len < 2) return;
        // byte 0 is type (16), byte 1 is num_frames
        uint8_t num_frames = data[1];
        size_t offset = 2;

        std::lock_guard<std::mutex> lock(state.mutex);

        bool has_loudness = false;
        bool has_f_peak = false;
        bool has_spectrum = false;
        for (auto t : state.vis_active_types) {
            if (t == VisualizerDataType::LOUDNESS) has_loudness = true;
            if (t == VisualizerDataType::F_PEAK) has_f_peak = true;
            if (t == VisualizerDataType::SPECTRUM) has_spectrum = true;
        }
        uint8_t bin_count = state.vis_stream_bin_count;

        for (uint8_t i = 0; i < num_frames; ++i) {
            if (offset + 8 > len) break;
            VisFrame frame;
            frame.server_time = be64(data + offset);
            offset += 8;

            if (has_loudness) {
                if (offset + 2 > len) break;
                frame.loudness = be16(data + offset);
                offset += 2;
            }
            if (has_f_peak) {
                if (offset + 2 > len) break;
                frame.peak_freq = be16(data + offset);
                offset += 2;
            }
            if (has_spectrum) {
                frame.spectrum.resize(bin_count);
                for (uint8_t b = 0; b < bin_count; ++b) {
                    if (offset + 2 > len) break;
                    frame.spectrum[b] = be16(data + offset);
                    offset += 2;
                }
            }

            state.vis_frames.push_back(std::move(frame));
            // Cap buffer size to avoid unbounded growth
            if (state.vis_frames.size() > 512) {
                state.vis_frames.pop_front();
            }
        }
    };

    client.on_beat_data = [&state](const uint8_t* data, size_t len) {
        // Binary format: [type=17][num_beats][per-beat: 8 bytes timestamp]
        if (len < 2) return;
        uint8_t num_beats = data[1];
        size_t offset = 2;

        std::lock_guard<std::mutex> lock(state.mutex);
        for (uint8_t i = 0; i < num_beats; ++i) {
            if (offset + 8 > len) break;
            int64_t server_time = be64(data + offset);
            offset += 8;
            state.vis_beat_times.push_back(server_time);
            if (state.vis_beat_times.size() > 128) {
                state.vis_beat_times.pop_front();
            }
        }
    };

    // Start the server
    if (!client.start_server(5)) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    // Advertise via mDNS
    MdnsAdvertiser mdns;
    mdns.start(friendly_name, SENDSPIN_PORT, SENDSPIN_PATH);

    // Start mDNS browsing for servers
    MdnsBrowser mdns_browser;
    mdns_browser.start();

    // Auto-connect if a URL was provided via -u
    if (!connect_url.empty()) {
        client.connect_to(connect_url);
    }

    // Create FTXUI screen and component
    auto screen = ftxui::ScreenInteractive::Fullscreen();
    auto component = create_tui_component(client, state, screen);

    // Background thread: drives client protocol and posts UI refresh events
    std::atomic<bool> running{true};
    std::thread client_thread([&] {
        int tick = 0;
        int vis_refresh_counter = 0;
        while (running.load()) {
            client.loop();

            // Process visualizer frames every tick (10ms) for smooth display
            {
                int64_t current_us = now_us();
                std::lock_guard<std::mutex> lock(state.mutex);

                // Process visualizer data frames
                while (!state.vis_frames.empty()) {
                    auto& frame = state.vis_frames.front();
                    int64_t display_time = client.get_client_time(frame.server_time);
                    if (display_time == 0) {
                        // Time sync not ready, discard
                        state.vis_frames.pop_front();
                        continue;
                    }
                    if (display_time > current_us) {
                        break;  // Not time yet
                    }
                    // Apply this frame to target state
                    state.vis_loudness = frame.loudness;
                    state.vis_peak_freq = frame.peak_freq;
                    if (!frame.spectrum.empty()) {
                        state.vis_spectrum = frame.spectrum;
                    }
                    state.vis_frames.pop_front();
                }

                // Smooth decay: display values chase target values each tick.
                // Rise fast (attack ~30ms), fall slow (decay ~200ms).
                // At 10ms ticks: attack_alpha ~0.33, decay_alpha ~0.05
                constexpr float ATTACK_ALPHA = 0.33f;
                constexpr float DECAY_ALPHA = 0.05f;
                constexpr float LOUDNESS_MAX = 65535.0f;

                // Ensure display vectors are sized
                if (state.vis_display_spectrum.size() != state.vis_spectrum.size()) {
                    state.vis_display_spectrum.resize(state.vis_spectrum.size(), 0.0f);
                }

                // Find max for normalization (floor at 8192 to avoid over-amplification)
                uint16_t max_val = 1;
                for (auto v : state.vis_spectrum) {
                    if (v > max_val) max_val = v;
                }
                if (max_val < 8192) max_val = 8192;
                float norm = 1.0f / static_cast<float>(max_val);

                for (size_t i = 0; i < state.vis_spectrum.size(); ++i) {
                    float target = static_cast<float>(state.vis_spectrum[i]) * norm;
                    float current = state.vis_display_spectrum[i];
                    float alpha = (target > current) ? ATTACK_ALPHA : DECAY_ALPHA;
                    state.vis_display_spectrum[i] = current + alpha * (target - current);
                }

                // Smooth loudness
                {
                    float target = static_cast<float>(state.vis_loudness) / LOUDNESS_MAX;
                    float current = state.vis_display_loudness;
                    float alpha = (target > current) ? ATTACK_ALPHA : DECAY_ALPHA;
                    state.vis_display_loudness = current + alpha * (target - current);
                }

                // Process beat timestamps
                while (!state.vis_beat_times.empty()) {
                    int64_t server_time = state.vis_beat_times.front();
                    int64_t display_time = client.get_client_time(server_time);
                    if (display_time == 0) {
                        state.vis_beat_times.pop_front();
                        continue;
                    }
                    if (display_time > current_us) {
                        break;
                    }
                    state.vis_beat = true;
                    state.vis_beat_expire_us = current_us + 100000;  // 100ms flash
                    state.vis_beat_times.pop_front();
                }

                // Expire beat flash
                if (state.vis_beat && current_us >= state.vis_beat_expire_us) {
                    state.vis_beat = false;
                }
            }

            // Post UI refresh at ~30fps (every 3 ticks) when visualizer is showing
            bool vis_showing;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                vis_showing = state.show_visualizer;
            }
            if (vis_showing) {
                if (++vis_refresh_counter % 3 == 0) {
                    screen.PostEvent(ftxui::Event::Custom);
                }
            }

            if (++tick % 25 == 0) {  // every 250ms
                update_polled_state(state, client);
#ifdef SENDSPIN_HAS_PORTAUDIO
                // Sync audio sink volume with client state every poll cycle.
                // This catches all volume sources: key presses (update_volume),
                // server commands (on_volume_changed), and polling updates.
                audio_sink.set_volume(client.get_volume());
                audio_sink.set_muted(client.get_muted());
#endif
                // Update discovered servers list
                {
                    auto servers = mdns_browser.get_servers();
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.discovered_servers = std::move(servers);
                    // Clamp selector index to valid range
                    int max_index = static_cast<int>(state.discovered_servers.size()) - 1;
                    if (state.server_selector_index > max_index) {
                        state.server_selector_index = std::max(0, max_index);
                    }
                }
                if (!vis_showing) {
                    screen.PostEvent(ftxui::Event::Custom);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // Run the TUI event loop (blocks until quit)
    screen.Loop(component);

    // Cleanup
    running.store(false);
    client_thread.join();
    mdns_browser.stop();
    mdns.stop();
    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);

    return 0;
}
