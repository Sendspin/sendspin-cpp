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
/// the default PortAudio input device and streaming it to the server while the
/// server has the stream started. When built with mDNS support (dns_sd.h
/// available), advertises via mDNS so Sendspin servers can discover and connect
/// automatically; otherwise the user must connect manually with
/// `-u ws://<server-host>:<port>/<path>`.
///
/// Usage: ./source_client [options] [name]
///   name:  Optional friendly name (default: "Source Client")
///
/// Options:
///   -u URL    Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)
///   -p PORT   Listen on PORT (default: 8928)
///   -o        Stream Opus-encoded audio instead of PCM (needs SENDSPIN_ENABLE_OPUS)
///   -l LEVEL  Set log level: none, error, warn, info (default), debug, verbose
///   -v        Verbose logging (same as -l verbose)
///   -q        Quiet logging (same as -l error)
///   -h        Show usage

#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/source_role.h"
#include "sendspin/types.h"
#include "file_persistence_provider.h"

#include <getopt.h>
#include <portaudio.h>

#ifdef SENDSPIN_HAS_MDNS
// IWYU pragma: begin_keep
// The include-what-you-use checker misattributes arpa/inet.h's htons/ntohs/htonl/ntohl to
// macOS libc++'s private headers when analyzed on a macOS host toolchain; arpa/inet.h is
// still the correct, portable header on both macOS and Linux CI.
#include <arpa/inet.h>
// IWYU pragma: end_keep
#include <dns_sd.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <utility>

using namespace sendspin;

static constexpr uint16_t DEFAULT_SENDSPIN_PORT = SendspinClientConfig::DEFAULT_SERVER_PORT;
static const char* SENDSPIN_PATH = "/sendspin";

// 48 kHz / 16-bit: what most input devices deliver natively, and legal for both PCM and -o Opus.
// The channel count follows the default input device, clamped to stereo. Each callback carries
// one chunk's worth of frames, well inside what one write_audio() call may hold.
static constexpr uint32_t CAPTURE_SAMPLE_RATE = 48000;
static constexpr uint8_t CAPTURE_BIT_DEPTH = 16;
static constexpr unsigned long CAPTURE_FRAMES_PER_BUFFER = CAPTURE_SAMPLE_RATE / 50;

#ifdef SENDSPIN_HAS_MDNS
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
/// callback forwards each buffer to write_audio(), which never blocks, with its capture time
/// mapped onto the client's clock; the listener callbacks start and stop the capture stream.
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

    /// @brief The default input device's channel count clamped to stereo, or 0 when no input
    /// device is available
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

    /// @brief Opens (but does not start) the capture stream on the default input device
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
                                    CAPTURE_FRAMES_PER_BUFFER, paClipOff, pa_callback, this);
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

    /// @brief Starts capture; the callback begins feeding write_audio()
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

    /// @brief Stops capture, draining the callback before returning
    void stop() {
        if (stream_ != nullptr && Pa_IsStreamActive(stream_) == 1) {
            Pa_StopStream(stream_);
        }
    }

    /// @brief The number of refused writes since the last call, resetting the count
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

        // Only the buffer's age (currentTime - inputBufferAdcTime) is portable across PortAudio
        // backends, so it is subtracted from the steady clock, the client's clock on host.
        // The result is the first sample's capture time, as write_audio() expects. Backends that
        // report zero timestamps, or an ADC time ahead of the current time, pass 0, which
        // write_audio() stamps as ending now.
        int64_t capture_us = 0;
        if (time_info != nullptr && time_info->currentTime > 0 &&
            time_info->inputBufferAdcTime > 0 &&
            time_info->inputBufferAdcTime <= time_info->currentTime) {
            int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count();
            double age_us = (time_info->currentTime - time_info->inputBufferAdcTime) * 1000000.0;
            capture_us = now_us - static_cast<int64_t>(std::round(age_us));
        }

        if (!self->source_->write_audio(static_cast<const uint8_t*>(input),
                                        frame_count * self->bytes_per_frame_, capture_us)) {
            // Counted here and reported from the main loop, so the audio callback does no I/O.
            // A refused write means the capture buffer is full, or the stream closed while this
            // callback was in flight.
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
#ifdef SENDSPIN_ENABLE_OPUS
    fprintf(stderr, "  -o            Stream Opus-encoded audio instead of PCM\n");
#endif
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
#ifdef SENDSPIN_ENABLE_OPUS
                use_opus = true;
                break;
#else
                fprintf(stderr, "-o needs a library built with SENDSPIN_ENABLE_OPUS\n");
                return 1;
#endif
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

    // The capture channel count comes from the hardware, and the format is fixed at add_source()
    // time, so the device is probed before the client is configured.
    PortAudioCapture capture;
    uint8_t channels = capture.default_input_channels();
    if (channels == 0) {
        fprintf(stderr, "No usable input device; cannot stream\n");
        return 1;
    }

    // Configure the client
    SendspinClientConfig config;
    // client_id is derived from the static X25519 keypair; do not set it here.
    config.name = friendly_name;
    config.product_name = "sendspin-cpp host example";
    config.manufacturer = "sendspin-cpp";
    config.software_version = "0.1.0";
    config.server_port = server_port;
    // The example prints the pairing code to the terminal, so the client can advertise the
    // dynamic_pairing_code method alongside the mandatory pairing_psk one. A terminal is a
    // display but cannot render a QR code, so only the digits format is offered.
    config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
    config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};

    // Persist the static keypair and pairing records so client_id and pairings survive
    // restarts. A file of its own, so this example and basic_client are separate clients.
    const std::string persistence_path =
        FilePersistenceProvider::default_path(".sendspin-source.json");
    FilePersistenceProvider persistence_provider(persistence_path);

    SendspinClient client(std::move(config));
    client.set_persistence_provider(&persistence_provider);

    // The config is the capture format of every stream the role opens. A 20 ms chunk is one
    // legal Opus frame, so the default chunk duration serves both codecs.
    SourceRoleConfig source_config;
    source_config.sample_rate = CAPTURE_SAMPLE_RATE;
    source_config.channels = channels;
    source_config.bit_depth = CAPTURE_BIT_DEPTH;
    source_config.codec = use_opus ? SendspinCodecFormat::OPUS : SendspinCodecFormat::PCM;
    auto& source = client.add_source(std::move(source_config));

    if (!capture.open(source, CAPTURE_SAMPLE_RATE, channels)) {
        return 1;
    }

    // --- Listener implementations ---

    struct CaptureSourceListener : SourceRoleListener {
        PortAudioCapture& capture;
        explicit CaptureSourceListener(PortAudioCapture& c) : capture(c) {}

        void on_streaming_started() override {
            fprintf(stderr, ">>> Streaming started\n");
            if (!capture.start()) {
                // The stream is open on the wire but capture cannot run; leave the main loop so
                // shutdown closes the stream rather than leave the server waiting on silence.
                fprintf(stderr, ">>> Failed to start capture; shutting down\n");
                running.store(false);
            }
        }

        void on_streaming_stopped() override {
            fprintf(stderr, ">>> Streaming stopped\n");
            capture.stop();
        }
    };

    struct SourceClientListener : SendspinClientListener {
        // The client holds high-performance networking while the input stream is open. A host
        // has no radio power saving to toggle, so the example only logs the hold.
        void on_request_high_performance() override {
            fprintf(stderr, ">>> High-performance networking requested\n");
        }

        void on_release_high_performance() override {
            fprintf(stderr, ">>> High-performance networking released\n");
        }

        void on_trust_changed(ConnectionTrust trust) override {
            if (trust == ConnectionTrust::USER) {
                fprintf(stderr, ">>> Trust: user (paired server)\n");
            } else {
                fprintf(stderr, ">>> Trust: none (unpaired)\n");
            }
        }

        void on_pairing_started(const std::string& server_id) override {
            fprintf(stderr, ">>> Pairing started with server: %s\n", server_id.c_str());
        }

        void on_pairing_succeeded(const std::string& server_id) override {
            fprintf(stderr, ">>> Pairing succeeded with server: %s\n", server_id.c_str());
        }

        void on_pairing_failed(const std::string& server_id,
                               SendspinPairAbortReason reason) override {
            fprintf(stderr, ">>> Pairing failed with server: %s (reason %d)\n", server_id.c_str(),
                    static_cast<int>(reason));
        }

        void on_display_pairing_code(const std::string& code,
                                     SendspinPairingCodeFormat /*format*/) override {
            // Only digits are offered. pairing.md "Pairing Code Presentation" asks for a 3-3
            // grouping; the separator is presentation only and never part of the code.
            fprintf(stderr, "\n>>> Pairing code: %s-%s\n", code.substr(0, 3).c_str(),
                    code.substr(3).c_str());
            fprintf(stderr, "    Enter this code on the server to finish pairing.\n\n");
        }

        void on_clear_pairing_code() override {
            fprintf(stderr, ">>> Pairing code withdrawn\n");
        }
    };

    struct HostNetworkProvider : SendspinNetworkProvider {
        bool is_network_ready() override { return true; }
    };

    CaptureSourceListener source_listener(capture);
    SourceClientListener client_listener;
    HostNetworkProvider network_provider;

    source.set_listener(&source_listener);
    client.set_listener(&client_listener);
    client.set_network_provider(&network_provider);

    // Start the server
    fprintf(stderr, "Starting Sendspin source client on port %u (%s)...\n", server_port,
            use_opus ? "opus" : "pcm");

    if (!client.start()) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    fprintf(stderr, "client_id: %s\n", client.client_id().c_str());
    fprintf(stderr, "Persistence: %s\n", persistence_path.c_str());

    // The pairing token carries the client_id and the Pairing PSK together. Paste it into a
    // server that asks for one to pair via the pairing_psk method; pairing with a code instead
    // needs nothing from here (the code is printed when the server starts that flow).
    auto token = client.pairing_token();
    if (token.has_value()) {
        fprintf(stderr, "Pairing token: %s\n", token->c_str());
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

    // Unpaired access stays off, so only a server this client has paired with can open the
    // stream.
    fprintf(stderr, "Press Ctrl+C to stop. A paired server controls when streaming starts.\n\n");

    // Main loop
    constexpr auto DROP_REPORT_INTERVAL = std::chrono::seconds(5);
    auto next_drop_report = std::chrono::steady_clock::now() + DROP_REPORT_INTERVAL;
    while (running.load()) {
        client.loop();
        // Surface capture drops off the audio callback, which only counts them
        if (std::chrono::steady_clock::now() >= next_drop_report) {
            next_drop_report += DROP_REPORT_INTERVAL;
            uint32_t dropped = capture.take_dropped_writes();
            if (dropped > 0) {
                // A stop also refuses the few callbacks still in flight before capture stops
                fprintf(stderr, ">>> Refused %u capture writes in the last %lld s\n", dropped,
                        static_cast<long long>(DROP_REPORT_INTERVAL.count()));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    fprintf(stderr, "\nShutting down...\n");
#ifdef SENDSPIN_HAS_MDNS
    mdns.stop();
#endif
    // Stop the capture callback first: write_audio() must not run once the client is destroyed
    capture.stop();
    client.stop();
    return 0;
}
