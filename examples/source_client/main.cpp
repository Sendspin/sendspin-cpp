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

/// @file Host example application streaming audio capture to a Sendspin server.
///
/// Runs a SendspinClient with the source role on the host computer, capturing
/// the default PortAudio input device and streaming it to the server when the
/// server commands the stream to start. When built with mDNS support
/// (dns_sd.h available), advertises via mDNS so Sendspin servers can discover
/// and connect automatically; otherwise the user must connect manually with
/// `-u ws://<server-host>:<port>/<path>`.
///
/// Usage: ./source_client [options] [name]
///   name:  Optional friendly name (default: "Source Client")
///
/// Options:
///   -u URL    Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)
///   -p PORT   Listen on PORT (default: 8928)
///   -o        Stream Opus-encoded audio instead of PCM
///   -l LEVEL  Set log level: none, error, warn, info (default), debug, verbose
///   -v        Verbose logging (same as -l verbose)
///   -q        Quiet logging (same as -l error)
///   -h        Show usage

#include "sendspin/client.h"
#include "sendspin/source_role.h"

#include <getopt.h>
#include <portaudio.h>

#ifdef SENDSPIN_HAS_MDNS
#include <arpa/inet.h>
#include <dns_sd.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

using namespace sendspin;

static constexpr uint16_t DEFAULT_SENDSPIN_PORT = SendspinClientConfig::DEFAULT_SERVER_PORT;
static const char* SENDSPIN_PATH = "/sendspin";

// 48 kHz / 16-bit: a format PortAudio input backends deliver everywhere, and one of the
// sample rates libopus accepts natively, so the same capture format is legal for both the
// PCM default and the -o Opus path. The channel count follows the default input device
// (clamped to stereo) since many capture devices are mono.
static constexpr uint32_t CAPTURE_SAMPLE_RATE = 48000;
static constexpr uint8_t CAPTURE_BIT_DEPTH = 16;

// One outbound chunk must be exactly one legal Opus frame; 20 ms is Opus's canonical frame
// duration, splitting the difference between capture latency (10 ms) and per-packet
// overhead (40/60 ms). The PCM path keeps the library's default chunk duration.
static constexpr uint32_t OPUS_CHUNK_MS = 20;

#ifdef SENDSPIN_HAS_MDNS
// Manages mDNS service advertisement via dns_sd.h
class MdnsAdvertiser {
public:
    ~MdnsAdvertiser() {
        stop();
    }

    bool start(const std::string& name, uint16_t port, const std::string& path) {
        // Build TXT record with path and name keys
        TXTRecordRef txt;
        TXTRecordCreate(&txt, 0, nullptr);
        TXTRecordSetValue(&txt, "path", static_cast<uint8_t>(path.size()), path.c_str());
        TXTRecordSetValue(&txt, "name", static_cast<uint8_t>(name.size()), name.c_str());

        DNSServiceErrorType err = DNSServiceRegister(
            &service_ref_,
            0,                    // flags
            0,                    // interface index (0 = all)
            name.c_str(),         // service name
            "_sendspin._tcp",     // service type
            nullptr,              // domain (default)
            nullptr,              // host (default)
            htons(port),          // port (network byte order)
            TXTRecordGetLength(&txt),
            TXTRecordGetBytesPtr(&txt),
            nullptr,              // callback (not needed for simple registration)
            nullptr               // context
        );

        TXTRecordDeallocate(&txt);

        if (err != kDNSServiceErr_NoError) {
            fprintf(stderr, "Failed to register mDNS service: error %d\n", err);
            return false;
        }

        fprintf(stderr, "mDNS: Advertising _sendspin._tcp on port %u (name: %s)\n", port,
                name.c_str());
        return true;
    }

    void stop() {
        if (service_ref_ != nullptr) {
            DNSServiceRefDeallocate(service_ref_);
            service_ref_ = nullptr;
            fprintf(stderr, "mDNS: Service advertisement stopped\n");
        }
    }

private:
    DNSServiceRef service_ref_{nullptr};
};
#endif  // SENDSPIN_HAS_MDNS

/// @brief Captures the default PortAudio input device and feeds the source role: the input
/// callback forwards each buffer to write_audio() (callback-safe) with its capture time mapped
/// onto the local steady clock; the listener callbacks start and stop the capture stream.
class PortAudioCapture {
public:
    PortAudioCapture() {
        PaError err = Pa_Initialize();
        initialized_ = (err == paNoError);
        if (!initialized_) {
            fprintf(stderr, "Pa_Initialize failed: %s\n", Pa_GetErrorText(err));
        }
    }

    ~PortAudioCapture() {
        stop();
        if (stream_ != nullptr) {
            Pa_CloseStream(stream_);
        }
        if (initialized_) {
            Pa_Terminate();
        }
    }

    // Not copyable or movable (the PortAudio stream holds a pointer to this)
    PortAudioCapture(const PortAudioCapture&) = delete;
    PortAudioCapture& operator=(const PortAudioCapture&) = delete;

    /// @brief Returns the default input device's channel count clamped to stereo, or 0 when
    /// no input device is available.
    uint8_t default_input_channels() const {
        if (!initialized_) {
            return 0;
        }
        PaDeviceIndex device = Pa_GetDefaultInputDevice();
        if (device == paNoDevice) {
            return 0;
        }
        const PaDeviceInfo* info = Pa_GetDeviceInfo(device);
        if (info == nullptr || info->maxInputChannels <= 0) {
            return 0;
        }
        return static_cast<uint8_t>(std::min(info->maxInputChannels, 2));
    }

    /// @brief Opens (but does not start) the capture stream on the default input device.
    bool open(SourceRole& source, uint32_t sample_rate, uint8_t channels) {
        if (!initialized_) {
            return false;
        }
        source_ = &source;
        bytes_per_frame_ = static_cast<size_t>(channels) * (CAPTURE_BIT_DEPTH / 8U);

        PaStreamParameters params;
        memset(&params, 0, sizeof(params));
        params.device = Pa_GetDefaultInputDevice();
        if (params.device == paNoDevice) {
            fprintf(stderr, "No default input device available\n");
            return false;
        }
        params.channelCount = channels;
        params.sampleFormat = paInt16;
        params.suggestedLatency = Pa_GetDeviceInfo(params.device)->defaultLowInputLatency;

        PaError err = Pa_OpenStream(&stream_, &params, nullptr, sample_rate,
                                    paFramesPerBufferUnspecified, paClipOff, pa_callback, this);
        if (err != paNoError) {
            fprintf(stderr, "Pa_OpenStream failed: %s\n", Pa_GetErrorText(err));
            stream_ = nullptr;
            return false;
        }
        const PaDeviceInfo* info = Pa_GetDeviceInfo(params.device);
        fprintf(stderr, "Capturing from \"%s\" (%u Hz, %u ch)\n", info->name, sample_rate,
                channels);
        return true;
    }

    /// @brief Starts capture; the callback begins feeding write_audio().
    bool start() {
        if (stream_ == nullptr || Pa_IsStreamActive(stream_) == 1) {
            return stream_ != nullptr;
        }
        PaError err = Pa_StartStream(stream_);
        if (err != paNoError) {
            fprintf(stderr, "Pa_StartStream failed: %s\n", Pa_GetErrorText(err));
            return false;
        }
        return true;
    }

    /// @brief Stops capture, draining the callback before returning.
    void stop() {
        if (stream_ != nullptr && Pa_IsStreamActive(stream_) == 1) {
            Pa_StopStream(stream_);
        }
    }

    /// @brief Returns the number of rejected writes since the last call and resets the count.
    uint32_t take_dropped_writes() {
        return dropped_writes_.exchange(0, std::memory_order_relaxed);
    }

private:
    static int pa_callback(const void* input, void* /*output*/, unsigned long frame_count,
                           const PaStreamCallbackTimeInfo* time_info,
                           PaStreamCallbackFlags /*status_flags*/, void* user_data) {
        auto* self = static_cast<PortAudioCapture*>(user_data);
        if (input == nullptr) {
            return paContinue;  // Input overflow gap; nothing to forward
        }

        // Only the buffer's age (currentTime - inputBufferAdcTime) is portable across
        // PortAudio backends; subtract it from the local steady clock to get the capture time
        // in the client's domain. Backends reporting zero timestamps get the library's
        // documented pass-0 arrival-stamp fallback.
        int64_t capture_us = 0;
        if (time_info != nullptr && time_info->currentTime > 0 &&
            time_info->inputBufferAdcTime > 0) {
            int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count();
            double age_us =
                (time_info->currentTime - time_info->inputBufferAdcTime) * 1000000.0;
            capture_us = now_us - static_cast<int64_t>(std::round(age_us));
        }

        if (!self->source_->write_audio(static_cast<const uint8_t*>(input),
                                        frame_count * self->bytes_per_frame_, capture_us)) {
            // Counted here and reported from the main loop; this example adds no logging of
            // its own on the audio callback (the library itself warns once per overflow
            // episode from this thread). A rejected write means the capture ring is full, or
            // the stream closed while this callback was in flight.
            self->dropped_writes_.fetch_add(1, std::memory_order_relaxed);
        }
        return paContinue;
    }

    SourceRole* source_{nullptr};
    PaStream* stream_{nullptr};
    size_t bytes_per_frame_{0};
    std::atomic<uint32_t> dropped_writes_{0};
    bool initialized_{false};
};

static std::atomic<bool> running{true};

static void signal_handler(int /*sig*/) {
    running.store(false);
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [name]\n", prog);
    fprintf(stderr, "  name          Friendly name (default: \"Source Client\")\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u URL        Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)\n");
    fprintf(stderr, "  -p PORT       Listen on PORT (default: %u)\n", DEFAULT_SENDSPIN_PORT);
    fprintf(stderr, "  -o            Stream Opus-encoded audio instead of PCM\n");
    fprintf(stderr, "  -l LEVEL      Log level: none, error, warn, info (default), debug, verbose\n");
    fprintf(stderr, "  -v            Verbose logging (same as -l verbose)\n");
    fprintf(stderr, "  -q            Quiet logging (same as -l error)\n");
    fprintf(stderr, "  -h            Show this help\n");
}

static bool parse_log_level(const char* str, LogLevel& level) {
    if (strcmp(str, "none") == 0) { level = LogLevel::NONE; return true; }
    if (strcmp(str, "error") == 0) { level = LogLevel::ERROR; return true; }
    if (strcmp(str, "warn") == 0) { level = LogLevel::WARN; return true; }
    if (strcmp(str, "info") == 0) { level = LogLevel::INFO; return true; }
    if (strcmp(str, "debug") == 0) { level = LogLevel::DEBUG; return true; }
    if (strcmp(str, "verbose") == 0) { level = LogLevel::VERBOSE; return true; }
    return false;
}

static bool parse_port(const char* str, uint16_t& port) {
    char* end = nullptr;
    unsigned long value = strtoul(str, &end, 10);
    if (*str == '\0' || *end != '\0' || value == 0 || value > 65535UL) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

int main(int argc, char* argv[]) {
    // Set up signal handler for clean shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Parse command line options
    LogLevel log_level = LogLevel::INFO;
    std::string connect_url;
    uint16_t server_port = DEFAULT_SENDSPIN_PORT;
    bool use_opus = false;
    int opt;
    while ((opt = getopt(argc, argv, "u:p:ol:vqh")) != -1) {
        switch (opt) {
            case 'u':
                connect_url = optarg;
                break;
            case 'p':
                if (!parse_port(optarg, server_port)) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'o':
                use_opus = true;
                break;
            case 'l':
                if (!parse_log_level(optarg, log_level)) {
                    fprintf(stderr, "Unknown log level: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'v':
                log_level = LogLevel::VERBOSE;
                break;
            case 'q':
                log_level = LogLevel::ERROR;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    SendspinClient::set_log_level(log_level);

    // Optional name from remaining arguments
    std::string friendly_name = (optind < argc) ? argv[optind] : "Source Client";

    // The capture channel count comes from the hardware, and the format is fixed at
    // add_source() time, so probe the device before configuring the client.
    PortAudioCapture capture;
    uint8_t channels = capture.default_input_channels();
    if (channels == 0) {
        fprintf(stderr, "No usable input device; cannot stream\n");
        return 1;
    }

    // --- Listener implementations ---
    // Declared before the client: the client and role retain raw pointers to these for their
    // whole lifetime, so they must be destroyed after the client (reverse declaration order).

    struct CaptureSourceListener : SourceRoleListener {
        PortAudioCapture& capture;
        explicit CaptureSourceListener(PortAudioCapture& c) : capture(c) {}

        void on_streaming_started() override {
            fprintf(stderr, ">>> Streaming started\n");
            if (!capture.start()) {
                // The stream is open on the wire but capture cannot run; exit the main loop so
                // shutdown closes the stream instead of leaving the server waiting on silence.
                fprintf(stderr, ">>> Failed to start capture; shutting down\n");
                running.store(false);
            }
        }

        void on_streaming_stopped() override {
            fprintf(stderr, ">>> Streaming stopped\n");
            capture.stop();
        }
    };

    struct HostNetworkProvider : SendspinNetworkProvider {
        bool is_network_ready() override { return true; }
    };

    CaptureSourceListener source_listener(capture);
    HostNetworkProvider network_provider;

    // Configure the client
    SendspinClientConfig config;
    config.client_id = "source-client-example";
    config.name = friendly_name;
    config.product_name = "sendspin-cpp host example";
    config.manufacturer = "sendspin-cpp";
    config.software_version = "0.1.0";
    config.server_port = server_port;

    SendspinClient client(std::move(config));

    // Add the source role. The config is the capture format contract for every stream this
    // role opens; Opus narrows it to one legal frame duration per chunk.
    SourceRoleConfig source_config{
        .sample_rate = CAPTURE_SAMPLE_RATE,
        .chunk_duration_ms =
            use_opus ? OPUS_CHUNK_MS : SourceRoleConfig::DEFAULT_CHUNK_MS,
        .codec = use_opus ? SendspinCodecFormat::OPUS : SendspinCodecFormat::PCM,
        .channels = channels,
        .bit_depth = CAPTURE_BIT_DEPTH,
    };
    auto& source = client.add_source(source_config);

    if (!capture.open(source, CAPTURE_SAMPLE_RATE, channels)) {
        return 1;
    }

    source.set_listener(&source_listener);
    client.set_network_provider(&network_provider);

    // Start the server
    fprintf(stderr, "Starting Sendspin source client on port %u (%s)...\n", server_port,
            use_opus ? "opus" : "pcm");

    if (!client.start_server()) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

#ifdef SENDSPIN_HAS_MDNS
    MdnsAdvertiser mdns;
    if (!mdns.start(friendly_name, server_port, SENDSPIN_PATH)) {
        fprintf(stderr, "Warning: mDNS advertisement failed, server still running\n");
        fprintf(stderr, "Connect manually to ws://<this-host>:%u%s\n", server_port,
                SENDSPIN_PATH);
    }
#else
    fprintf(stderr,
            "mDNS advertisement not compiled in. Either restart with "
            "-u ws://<server-host>:<port>/<path> to dial a server, or tell a server "
            "to connect to ws://<this-host>:%u%s.\n",
            server_port, SENDSPIN_PATH);
#endif

    // Auto-connect if a URL was provided via -u
    if (!connect_url.empty()) {
        fprintf(stderr, "Connecting to %s...\n", connect_url.c_str());
        client.connect_to(connect_url);
    }

    fprintf(stderr, "Press Ctrl+C to stop. The server controls when streaming starts.\n");
    fprintf(stderr,
            "NOTE: on this protocol revision any Sendspin server that completes the handshake\n"
            "can start capture from the default input; keep this example on trusted networks\n"
            "(pairing-based authorization arrives with the encryption work).\n\n");

    // Main loop
    constexpr auto DROP_REPORT_INTERVAL = std::chrono::seconds(5);
    auto next_drop_report = std::chrono::steady_clock::now() + DROP_REPORT_INTERVAL;
    while (running.load()) {
        client.loop();
        // Surface capture drops off the audio callback (which only counts them)
        if (std::chrono::steady_clock::now() >= next_drop_report) {
            next_drop_report += DROP_REPORT_INTERVAL;
            uint32_t dropped = capture.take_dropped_writes();
            if (dropped > 0) {
                fprintf(stderr, ">>> Dropped %u capture writes in the last %lld s\n", dropped,
                        static_cast<long long>(DROP_REPORT_INTERVAL.count()));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    fprintf(stderr, "\nShutting down...\n");
#ifdef SENDSPIN_HAS_MDNS
    mdns.stop();
#endif
    // Stop feeding audio before the client tears down the stream
    capture.stop();
    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);

    return 0;
}
