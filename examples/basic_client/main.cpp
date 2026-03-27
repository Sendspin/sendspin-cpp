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

/// @file Host example application for sendspin-cpp.
///
/// Runs a SendspinClient on the host computer, listening for incoming
/// connections from a Sendspin server on port 8928. Advertises via mDNS
/// so Sendspin servers can discover and connect automatically.
///
/// Usage: ./basic_client [options] [name]
///   name:  Optional friendly name (default: "Basic Client")
///
/// Options:
///   -u URL    Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)
///   -l LEVEL  Set log level: none, error, warn, info (default), debug, verbose
///   -v        Verbose logging (same as -l verbose)
///   -q        Quiet logging (same as -l error)
///   -h        Show usage

#include "sendspin/client.h"
#ifdef SENDSPIN_HAS_PORTAUDIO
#include "portaudio_sink.h"
#endif

#include <dns_sd.h>
#include <getopt.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

using namespace sendspin;

static const uint16_t SENDSPIN_PORT = 8928;
static const char* SENDSPIN_PATH = "/sendspin";

// Audio sink that discards all audio data
class NullAudioSink : public AudioSink {
public:
    size_t write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        total_bytes_ += length;
        return length;
    }

    size_t total_bytes() const {
        return total_bytes_;
    }

private:
    size_t total_bytes_{0};
};

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

static std::atomic<bool> running{true};

static void signal_handler(int /*sig*/) {
    running.store(false);
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [name]\n", prog);
    fprintf(stderr, "  name          Friendly name (default: \"Basic Client\")\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u URL        Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)\n");
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

int main(int argc, char* argv[]) {
    // Set up signal handler for clean shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Parse command line options
    LogLevel log_level = LogLevel::INFO;
    std::string connect_url;
    int opt;
    while ((opt = getopt(argc, argv, "u:l:vqh")) != -1) {
        switch (opt) {
            case 'u':
                connect_url = optarg;
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
    std::string friendly_name = (optind < argc) ? argv[optind] : "Basic Client";

    // Configure the client
    SendspinClientConfig config;
    config.client_id = "basic-client-example";
    config.name = friendly_name;
    config.product_name = "sendspin-cpp host example";
    config.manufacturer = "sendspin-cpp";
    config.software_version = "0.1.0";
    config.controller = true;
    config.metadata = true;

    // Support common audio formats
    config.audio_formats = {
        {SendspinCodecFormat::FLAC, 2, 44100, 16},
        {SendspinCodecFormat::FLAC, 2, 48000, 16},
        {SendspinCodecFormat::OPUS, 2, 48000, 16},
        {SendspinCodecFormat::PCM, 2, 44100, 16},
        {SendspinCodecFormat::PCM, 2, 48000, 16},
    };

    // Create audio sink and client
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

    // Network is always ready on host
    client.is_network_ready = []() { return true; };

    // Log callbacks
    client.on_stream_start = [&]() {
        fprintf(stderr, ">>> Stream started\n");
#ifdef SENDSPIN_HAS_PORTAUDIO
        auto& params = client.get_current_stream_params();
        if (params.sample_rate.has_value() && params.channels.has_value() &&
            params.bit_depth.has_value()) {
            audio_sink.configure(*params.sample_rate, *params.channels, *params.bit_depth);
        } else {
            fprintf(stderr, ">>> Stream params not yet available for PortAudio\n");
        }
#endif
    };

    client.on_stream_end = [&]() {
        fprintf(stderr, ">>> Stream ended\n");
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.clear();
#endif
    };

    client.on_stream_clear = [&]() {
        fprintf(stderr, ">>> Stream clear\n");
#ifdef SENDSPIN_HAS_PORTAUDIO
        audio_sink.clear();
#endif
    };

    client.on_metadata = [](const ServerMetadataStateObject& metadata) {
        if (metadata.title.has_value()) {
            fprintf(stderr, ">>> Metadata: %s - %s\n",
                    metadata.artist.value_or("Unknown").c_str(), metadata.title->c_str());
        }
    };

#ifdef SENDSPIN_HAS_PORTAUDIO
    client.on_volume_changed = [&audio_sink](uint8_t vol) {
        audio_sink.set_volume(vol);
    };
    client.on_mute_changed = [&audio_sink](bool muted) {
        audio_sink.set_muted(muted);
    };
#endif

    client.on_time_sync_updated = [](float error) {
        if (SendspinClient::get_log_level() >= LogLevel::DEBUG) {
            fprintf(stderr, ">>> Time sync error: %.1f us\n", error);
        }
    };

    // Start the server
    fprintf(stderr, "Starting Sendspin basic client on port %u...\n", SENDSPIN_PORT);

    if (!client.start_server(5)) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    // Advertise via mDNS
    MdnsAdvertiser mdns;
    if (!mdns.start(friendly_name, SENDSPIN_PORT, SENDSPIN_PATH)) {
        fprintf(stderr, "Warning: mDNS advertisement failed, server still running\n");
        fprintf(stderr, "Connect manually to ws://<this-host>:%u%s\n", SENDSPIN_PORT,
                SENDSPIN_PATH);
    }

    // Auto-connect if a URL was provided via -u
    if (!connect_url.empty()) {
        fprintf(stderr, "Connecting to %s...\n", connect_url.c_str());
        client.connect_to(connect_url);
    }

    fprintf(stderr, "Press Ctrl+C to stop.\n\n");

    // Main loop
    int tick = 0;
    while (running.load()) {
        client.loop();
#ifdef SENDSPIN_HAS_PORTAUDIO
        // Sync audio sink volume periodically (catches all volume change sources)
        if (++tick % 25 == 0) {
            audio_sink.set_volume(client.get_volume());
            audio_sink.set_muted(client.get_muted());
        }
#else
        ++tick;
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    fprintf(stderr, "\nShutting down...\n");
    mdns.stop();
    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);

#ifndef SENDSPIN_HAS_PORTAUDIO
    fprintf(stderr, "Total audio bytes received: %zu\n", audio_sink.total_bytes());
#endif
    return 0;
}
