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
///   -f FORMAT Audio format as codec:rate:bits:channels (repeatable)
///   -h        Show usage

#include "tui.h"

#include "sendspin/client.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#ifdef SENDSPIN_HAS_PORTAUDIO
#include "portaudio_sink.h"
#endif

#include <arpa/inet.h>
#include <dns_sd.h>
#include <netdb.h>
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
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;

static const uint16_t SENDSPIN_PORT = 8928;
static const char* SENDSPIN_PATH = "/sendspin";

// Big-endian helpers for binary visualizer data parsing
static int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Null audio write callback (used when PortAudio is not available)
static size_t null_audio_write(uint8_t*, size_t length, uint32_t) {
    return length;
}

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
            // Service appeared -- resolve it
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
                                            uint32_t /*interface_index*/, DNSServiceErrorType error,
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

        // Resolve the hostname to an IP address using POSIX getaddrinfo.
        // DNSServiceGetAddrInfo is a Bonjour extension not available in Avahi on Linux.
        std::thread([ctx, host = std::string(hosttarget)]() {
            struct addrinfo hints {};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            struct addrinfo* res = nullptr;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res != nullptr) {
                char addr_str[INET_ADDRSTRLEN] = {};
                const auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
                inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
                freeaddrinfo(res);

                if (addr_str[0] != '\0') {
                    DiscoveredServer server;
                    server.name = ctx->name;
                    server.host = addr_str;
                    server.port = ctx->port;
                    server.path = ctx->path;

                    std::lock_guard<std::mutex> lock(ctx->browser->servers_mutex_);
                    ctx->browser->servers_[ctx->key] = std::move(server);
                }
            } else if (res != nullptr) {
                freeaddrinfo(res);
            }
            delete ctx;
        }).detach();
    }

    DNSServiceRef browse_ref_{nullptr};
    std::atomic<bool> running_{false};
    std::thread thread_;

    mutable std::mutex servers_mutex_;
    std::map<ServiceKey, DiscoveredServer> servers_;

    std::mutex resolve_mutex_;
    std::vector<DNSServiceRef> pending_resolves_;
};

/// Parse an audio format string like "flac:48000:24:2" into an AudioSupportedFormatObject.
/// Returns true on success.
static bool parse_audio_format(const std::string& str, sendspin::AudioSupportedFormatObject& fmt) {
    std::istringstream ss(str);
    std::string codec_str, rate_str, bits_str, channels_str;

    if (!std::getline(ss, codec_str, ':') || !std::getline(ss, rate_str, ':') ||
        !std::getline(ss, bits_str, ':') || !std::getline(ss, channels_str, ':')) {
        return false;
    }

    // Parse codec
    std::transform(codec_str.begin(), codec_str.end(), codec_str.begin(), ::tolower);
    if (codec_str == "flac") {
        fmt.codec = sendspin::SendspinCodecFormat::FLAC;
    } else if (codec_str == "opus") {
        fmt.codec = sendspin::SendspinCodecFormat::OPUS;
    } else if (codec_str == "pcm") {
        fmt.codec = sendspin::SendspinCodecFormat::PCM;
    } else {
        fprintf(stderr, "Unknown codec: %s (expected flac, opus, or pcm)\n", codec_str.c_str());
        return false;
    }

    // Parse numeric fields
    char* end = nullptr;
    unsigned long rate = strtoul(rate_str.c_str(), &end, 10);
    if (*end != '\0' || rate == 0) {
        fprintf(stderr, "Invalid sample rate: %s\n", rate_str.c_str());
        return false;
    }
    fmt.sample_rate = static_cast<uint32_t>(rate);

    unsigned long bits = strtoul(bits_str.c_str(), &end, 10);
    if (*end != '\0' || bits == 0 || bits > 32) {
        fprintf(stderr, "Invalid bit depth: %s\n", bits_str.c_str());
        return false;
    }
    fmt.bit_depth = static_cast<uint8_t>(bits);

    unsigned long channels = strtoul(channels_str.c_str(), &end, 10);
    if (*end != '\0' || channels == 0 || channels > 8) {
        fprintf(stderr, "Invalid channel count: %s\n", channels_str.c_str());
        return false;
    }
    fmt.channels = static_cast<uint8_t>(channels);

    return true;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [name]\n", prog);
    fprintf(stderr, "  name          Friendly name (default: \"TUI Client\")\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u URL        Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)\n");
    fprintf(stderr, "  -f FORMAT     Audio format as codec:rate:bits:channels (e.g. flac:48000:24:2)\n");
    fprintf(stderr, "                Can be specified multiple times. Codecs: flac, opus, pcm\n");
    fprintf(stderr, "  -V            Disable visualizer\n");
    fprintf(stderr, "  -h            Show this help\n");
}

int main(int argc, char* argv[]) {
    // Parse command line options
    bool enable_visualizer = true;
    std::string connect_url;
    std::vector<sendspin::AudioSupportedFormatObject> audio_formats;
    int opt;
    while ((opt = getopt(argc, argv, "u:f:Vh")) != -1) {
        switch (opt) {
            case 'u':
                connect_url = optarg;
                break;
            case 'f': {
                sendspin::AudioSupportedFormatObject fmt;
                if (!parse_audio_format(optarg, fmt)) {
                    return 1;
                }
                audio_formats.push_back(fmt);
                break;
            }
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

    // Create audio output
#ifdef SENDSPIN_HAS_PORTAUDIO
    PortAudioSink audio_sink;

    // Validate explicitly requested formats against PortAudio device capabilities
    if (!audio_formats.empty()) {
        for (const auto& fmt : audio_formats) {
            if (!PortAudioSink::is_format_supported(fmt.sample_rate, fmt.channels, fmt.bit_depth)) {
                fprintf(stderr,
                        "Audio format not supported by output device: %uHz %uch %ubit\n",
                        fmt.sample_rate, fmt.channels, fmt.bit_depth);
                return 1;
            }
        }
    } else {
        // Build default format list based on device capabilities
        uint8_t max_ch = PortAudioSink::max_output_channels();
        if (max_ch == 0) {
            fprintf(stderr, "No audio output device available\n");
            return 1;
        }
        uint8_t channels = std::min(max_ch, static_cast<uint8_t>(2));

        static constexpr uint32_t SAMPLE_RATES[] = {44100, 48000, 88200, 96000};
        static constexpr uint8_t BIT_DEPTHS[] = {16, 24, 32};
        static constexpr SendspinCodecFormat CODECS[] = {
            SendspinCodecFormat::FLAC, SendspinCodecFormat::OPUS, SendspinCodecFormat::PCM,
        };

        for (uint32_t rate : SAMPLE_RATES) {
            for (uint8_t bits : BIT_DEPTHS) {
                if (!PortAudioSink::is_format_supported(rate, channels, bits)) {
                    continue;
                }
                for (SendspinCodecFormat codec : CODECS) {
                    // Opus always decodes to 48kHz 16-bit
                    if (codec == SendspinCodecFormat::OPUS && (rate != 48000 || bits != 16)) {
                        continue;
                    }
                    audio_formats.push_back({codec, channels, rate, bits});
                }
            }
        }

        if (audio_formats.empty()) {
            fprintf(stderr, "No supported audio formats found for default output device\n");
            return 1;
        }
    }
#else
    if (audio_formats.empty()) {
        audio_formats = {
            {SendspinCodecFormat::FLAC, 2, 44100, 16}, {SendspinCodecFormat::FLAC, 2, 48000, 16},
            {SendspinCodecFormat::OPUS, 2, 48000, 16}, {SendspinCodecFormat::PCM, 2, 44100, 16},
            {SendspinCodecFormat::PCM, 2, 48000, 16},
        };
    }
#endif

    SendspinClient client(std::move(config));

    // Add roles
    PlayerRole::Config player_config;
    player_config.audio_formats = std::move(audio_formats);
    auto& player = client.add_player(std::move(player_config));
    player.set_static_delay_adjustable(true);
    auto& controller = client.add_controller();
    auto& metadata = client.add_metadata();

    // Suppress unused variable warning
    (void)controller;

    // Visualizer support (disabled with -V flag)
    VisualizerRole* vis_role = nullptr;
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
        vis_role = &client.add_visualizer(VisualizerRole::Config{.support = vis});
    }

    // --- Listener implementations ---

    struct TuiPlayerListener : PlayerRoleListener {
        TuiState& state;
        PlayerRole& player;
#ifdef SENDSPIN_HAS_PORTAUDIO
        PortAudioSink& sink;
        TuiPlayerListener(TuiState& s, PlayerRole& p, PortAudioSink& a)
            : state(s), player(p), sink(a) {}
#else
        TuiPlayerListener(TuiState& s, PlayerRole& p) : state(s), player(p) {}
#endif

        size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) override {
#ifdef SENDSPIN_HAS_PORTAUDIO
            return sink.write(data, length, timeout_ms);
#else
            return null_audio_write(data, length, timeout_ms);
#endif
        }

        void on_stream_start() override {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                auto& params = player.get_current_stream_params();
                state.codec = params.codec;
                state.sample_rate = params.sample_rate;
                state.bit_depth = params.bit_depth;
                state.channels = params.channels;
                state.streaming = true;
            }
#ifdef SENDSPIN_HAS_PORTAUDIO
            auto& params = player.get_current_stream_params();
            if (params.sample_rate.has_value() && params.channels.has_value() &&
                params.bit_depth.has_value()) {
                sink.configure(*params.sample_rate, *params.channels, *params.bit_depth);
            }
#endif
        }

        void on_stream_end() override {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                state.streaming = false;
                state.codec = std::nullopt;
                state.sample_rate = std::nullopt;
                state.bit_depth = std::nullopt;
                state.channels = std::nullopt;
            }
#ifdef SENDSPIN_HAS_PORTAUDIO
            sink.clear();
#endif
        }

        void on_stream_clear() override {
#ifdef SENDSPIN_HAS_PORTAUDIO
            sink.clear();
#endif
        }

        void on_volume_changed(uint8_t vol) override {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                state.player_volume = vol;
            }
#ifdef SENDSPIN_HAS_PORTAUDIO
            sink.set_volume(vol);
#endif
        }

        void on_mute_changed(bool muted) override {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                state.player_muted = muted;
            }
#ifdef SENDSPIN_HAS_PORTAUDIO
            sink.set_muted(muted);
#endif
        }

        void on_static_delay_changed(uint16_t delay) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.static_delay_ms = delay;
        }
    };

    struct TuiMetadataListener : MetadataRoleListener {
        TuiState& state;
        explicit TuiMetadataListener(TuiState& s) : state(s) {}

        void on_metadata(const ServerMetadataStateObject& md) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (md.title.has_value()) {
                state.title = *md.title;
            }
            if (md.artist.has_value()) {
                state.artist = *md.artist;
            }
            if (md.album.has_value()) {
                state.album = *md.album;
            }
            if (md.repeat.has_value()) {
                state.repeat_mode = *md.repeat;
            }
            if (md.shuffle.has_value()) {
                state.shuffle = *md.shuffle;
            }
        }
    };

    struct TuiClientListener : SendspinClientListener {
        TuiState& state;
        explicit TuiClientListener(TuiState& s) : state(s) {}

        void on_group_update(const GroupUpdateObject& group) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (group.playback_state.has_value()) {
                state.playback_state = *group.playback_state;
            }
            if (group.group_name.has_value()) {
                state.group_name = *group.group_name;
            }
        }
    };

    struct TuiVisualizerListener : VisualizerRoleListener {
        TuiState& state;
        explicit TuiVisualizerListener(TuiState& s) : state(s) {}

        void on_visualizer_stream_start(const ServerVisualizerStreamObject& vis_stream) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.visualizer_active = true;
            if (vis_stream.spectrum.has_value()) {
                state.vis_spectrum.resize(vis_stream.spectrum->n_disp_bins, 0);
                state.vis_display_spectrum.resize(vis_stream.spectrum->n_disp_bins, 0.0f);
            }
            state.vis_display_loudness = 0.0f;
        }

        void on_visualizer_stream_end() override {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.visualizer_active = false;
            state.vis_loudness = 0;
            state.vis_peak_freq = 0;
            std::fill(state.vis_spectrum.begin(), state.vis_spectrum.end(), uint16_t{0});
            std::fill(state.vis_display_spectrum.begin(), state.vis_display_spectrum.end(), 0.0f);
            state.vis_display_loudness = 0.0f;
            state.vis_beat = false;
        }

        void on_visualizer_stream_clear() override {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.vis_loudness = 0;
            state.vis_peak_freq = 0;
            std::fill(state.vis_spectrum.begin(), state.vis_spectrum.end(), uint16_t{0});
            std::fill(state.vis_display_spectrum.begin(), state.vis_display_spectrum.end(), 0.0f);
            state.vis_display_loudness = 0.0f;
            state.vis_beat = false;
        }

        void on_visualizer_frame(const VisualizerFrame& frame) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (frame.loudness.has_value()) {
                state.vis_loudness = *frame.loudness;
            }
            if (frame.peak_freq.has_value()) {
                state.vis_peak_freq = *frame.peak_freq;
            }
            if (!frame.spectrum.empty()) {
                state.vis_spectrum = frame.spectrum;
            }
        }

        void on_beat(int64_t /*client_timestamp*/) override {
            std::lock_guard<std::mutex> lock(state.mutex);
            int64_t current_us = now_us();
            state.vis_beat = true;
            state.vis_beat_expire_us = current_us + 100000;  // 100ms flash
        }
    };

    struct HostNetworkProvider : SendspinNetworkProvider {
        bool is_network_ready() override { return true; }
    };

    // Shared TUI state
    TuiState state;

    // Create and wire listeners
#ifdef SENDSPIN_HAS_PORTAUDIO
    TuiPlayerListener player_listener(state, player, audio_sink);
    audio_sink.on_frames_played = [&player](uint32_t frames, int64_t timestamp) {
        player.notify_audio_played(frames, timestamp);
    };
#else
    TuiPlayerListener player_listener(state, player);
#endif
    TuiMetadataListener metadata_listener(state);
    TuiClientListener client_listener(state);
    TuiVisualizerListener visualizer_listener(state);
    HostNetworkProvider network_provider;

    player.set_listener(&player_listener);
    metadata.set_listener(&metadata_listener);
    client.set_listener(&client_listener);
    client.set_network_provider(&network_provider);
    if (vis_role) {
        vis_role->set_listener(&visualizer_listener);
    }

    // Start the server
    if (!client.start_server()) {
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
        // Parse host and port from ws://host:port/path for display
        {
            std::string url_tmp = connect_url;
            auto scheme_end = url_tmp.find("://");
            if (scheme_end != std::string::npos) {
                url_tmp = url_tmp.substr(scheme_end + 3);
            }
            auto path_start = url_tmp.find('/');
            std::string host_port = (path_start != std::string::npos)
                                        ? url_tmp.substr(0, path_start)
                                        : url_tmp;
            auto colon = host_port.rfind(':');
            if (colon != std::string::npos) {
                state.connected_host = host_port.substr(0, colon);
                state.connected_port =
                    static_cast<uint16_t>(std::stoul(host_port.substr(colon + 1)));
            } else {
                state.connected_host = host_port;
                state.connected_port = SENDSPIN_PORT;
            }
        }
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

            bool vis_showing;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                vis_showing = state.show_visualizer;
            }

            // Smooth visualizer display values every tick (10ms) — only when visible
            if (vis_showing) {
                int64_t current_us = now_us();
                std::lock_guard<std::mutex> lock(state.mutex);

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

                // Expire beat flash
                if (state.vis_beat && current_us >= state.vis_beat_expire_us) {
                    state.vis_beat = false;
                }
            }

            // Post UI refresh at ~30fps (every 3 ticks) when visualizer is showing
            if (vis_showing) {
                if (++vis_refresh_counter % 3 == 0) {
                    screen.PostEvent(ftxui::Event::Custom);
                }
            }

            if (++tick % 25 == 0) {  // every 250ms
                // Snapshot previous state to detect changes
                uint32_t prev_progress, prev_duration;
                bool prev_connected;
                uint8_t prev_group_vol, prev_player_vol;
                bool prev_group_muted, prev_player_muted;
                std::string prev_group_name;
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    prev_progress = state.track_progress_ms;
                    prev_duration = state.track_duration_ms;
                    prev_connected = state.connected;
                    prev_group_vol = state.group_volume;
                    prev_player_vol = state.player_volume;
                    prev_group_muted = state.group_muted;
                    prev_player_muted = state.player_muted;
                    prev_group_name = state.group_name;
                }

                update_polled_state(state, client);
#ifdef SENDSPIN_HAS_PORTAUDIO
                // Sync audio sink volume with client state every poll cycle.
                // This catches all volume sources: key presses (update_volume),
                // server commands (on_volume_changed), and polling updates.
                audio_sink.set_volume(player.get_volume());
                audio_sink.set_muted(player.get_muted());
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

                // Only post a redraw if something actually changed
                if (!vis_showing) {
                    bool changed;
                    {
                        std::lock_guard<std::mutex> lock(state.mutex);
                        changed = (state.track_progress_ms != prev_progress ||
                                   state.track_duration_ms != prev_duration ||
                                   state.connected != prev_connected ||
                                   state.group_volume != prev_group_vol ||
                                   state.player_volume != prev_player_vol ||
                                   state.group_muted != prev_group_muted ||
                                   state.player_muted != prev_player_muted ||
                                   state.group_name != prev_group_name);
                    }
                    if (changed) {
                        screen.PostEvent(ftxui::Event::Custom);
                    }
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
