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
/// connections from a Sendspin server on the configured port. When built with mDNS
/// support (dns_sd.h available), advertises via mDNS so Sendspin servers
/// can discover and connect automatically; otherwise the user must connect
/// manually with `-u ws://<server-host>:<port>/<path>`.
///
/// Usage: ./basic_client [options] [name]
///   name:  Optional friendly name (default: "Basic Client")
///
/// Options:
///   -u URL    Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)
///   -p PORT   Listen on PORT (default: 8928)
///   -s CODE   Offer the static pairing code CODE (8 digits) instead of the dynamic one
///   -l LEVEL  Set log level: none, error, warn, info (default), debug, verbose
///   -v        Verbose logging (same as -l verbose)
///   -q        Quiet logging (same as -l error)
///   -h        Show usage

#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/types.h"
#include "file_persistence_provider.h"
#ifdef SENDSPIN_HAS_PORTAUDIO
#include "portaudio_sink.h"
#endif

#include <getopt.h>

#ifdef SENDSPIN_HAS_MDNS
// IWYU pragma: begin_keep
// The include-what-you-use checker misattributes arpa/inet.h's htons/ntohs/htonl/ntohl to
// macOS libc++'s private headers when analyzed on a macOS host toolchain; arpa/inet.h is
// still the correct, portable header on both macOS and Linux CI.
#include <arpa/inet.h>
// IWYU pragma: end_keep
#include <dns_sd.h>
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

using namespace sendspin;

static constexpr uint16_t DEFAULT_SENDSPIN_PORT = SendspinClientConfig::DEFAULT_SERVER_PORT;
static const char* SENDSPIN_PATH = "/sendspin";

// Tracks total audio bytes received (used when PortAudio is unavailable)
static size_t null_audio_total_bytes = 0;

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

static std::atomic<bool> running{true};

/// The pairing-window gesture and its cancellation, relayed from a signal handler: SIGUSR1 opens
/// the window pairing.md "Pairing Window" gates every static_pairing_code attempt on, SIGUSR2
/// closes it. A headless example has no button to press, and a signal is the one thing a handler
/// may safely set, so the main loop below turns the flags into the client calls.
static std::atomic<bool> window_gesture{false};
static std::atomic<bool> window_cancel{false};

static void signal_handler(int /*sig*/) {
    running.store(false);
}

static void window_signal_handler(int sig) {
    if (sig == SIGUSR1) {
        window_gesture.store(true);
    } else {
        window_cancel.store(true);
    }
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [name]\n", prog);
    fprintf(stderr, "  name          Friendly name (default: \"Basic Client\")\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u URL        Connect to a WebSocket URL (e.g. ws://192.168.1.10:8928/sendspin)\n");
    fprintf(stderr, "  -p PORT       Listen on PORT (default: %u)\n", DEFAULT_SENDSPIN_PORT);
    fprintf(stderr, "  -s CODE       Offer the static pairing code CODE (8 digits) instead of\n");
    fprintf(stderr, "                the dynamic one; SIGUSR1 is the pairing-window gesture and\n");
    fprintf(stderr, "                SIGUSR2 cancels it\n");
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
    std::signal(SIGUSR1, window_signal_handler);
    std::signal(SIGUSR2, window_signal_handler);

    // Parse command line options
    LogLevel log_level = LogLevel::INFO;
    std::string connect_url;
    std::string static_pairing_code;
    uint16_t server_port = DEFAULT_SENDSPIN_PORT;
    int opt;
    while ((opt = getopt(argc, argv, "u:p:s:l:vqh")) != -1) {
        switch (opt) {
            case 'u':
                connect_url = optarg;
                break;
            case 's':
                static_pairing_code = optarg;
                if (static_pairing_code.size() != 8 ||
                    static_pairing_code.find_first_not_of("0123456789") != std::string::npos) {
                    fprintf(stderr, "Static pairing code must be exactly 8 digits: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'p':
                if (!parse_port(optarg, server_port)) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
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
    // client_id is derived from the static X25519 keypair; do not set it here.
    config.name = friendly_name;
    config.product_name = "sendspin-cpp host example";
    config.manufacturer = "sendspin-cpp";
    config.software_version = "0.1.0";
    config.server_port = server_port;
    if (static_pairing_code.empty()) {
        // The example prints the pairing code to the terminal, so the client can advertise the
        // dynamic_pairing_code method alongside the mandatory pairing_psk one. A terminal is a
        // display but cannot render a QR code, so only the digits format is offered.
        config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
        config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};
    } else {
        // A device offers at most one pairing-code method (messaging.md "client/hello"), and one
        // with an out-channel offers the dynamic code, so offering the static one means leaving
        // the out-channel unset. Every static_pairing_code attempt is gesture-gated
        // (pairing.md "Pairing Window"), which SIGUSR1 stands in for here.
        config.pairing_window_supported = true;
        config.static_pairing_code_locations = {"device"};
    }

    // Create audio output and client
#ifdef SENDSPIN_HAS_PORTAUDIO
    PortAudioSink audio_sink;
#endif

    // Persist the static keypair (and pairing state) so client_id and pairing records survive
    // restarts. Path: $HOME/.sendspin.json (regenerated if the file is absent).
    const std::string persistence_path = FilePersistenceProvider::default_path(".sendspin.json");
    FilePersistenceProvider persistence_provider(persistence_path);

    // The static pairing code and the pairing config are provisioned state the store reads once
    // at start(), so they are written before the client is built.
    if (!static_pairing_code.empty()) {
        persistence_provider.save_blob(
            persistence_keys::STATIC_PAIRING_CODE,
            reinterpret_cast<const uint8_t*>(static_pairing_code.data()),
            static_pairing_code.size());
        SendspinPairingConfig pairing_config;
        if (auto blob = persistence_provider.load_blob(persistence_keys::PAIR_CONFIG)) {
            std::string_view text(reinterpret_cast<const char*>(blob->data()), blob->size());
            if (auto decoded = decode_pairing_config(text)) {
                pairing_config = decoded.value();
            }
        }
        pairing_config.static_pairing_code_enabled = true;
        const std::string encoded = encode_pairing_config(pairing_config);
        persistence_provider.save_blob(persistence_keys::PAIR_CONFIG,
                                       reinterpret_cast<const uint8_t*>(encoded.data()),
                                       encoded.size());
    }

    SendspinClient client(std::move(config));
    client.set_persistence_provider(&persistence_provider);

    // Add roles
    PlayerRoleConfig player_config;
    player_config.audio_formats = {
        {SendspinCodecFormat::FLAC, 2, 44100, 16},
        {SendspinCodecFormat::FLAC, 2, 48000, 16},
        {SendspinCodecFormat::OPUS, 2, 48000, 16},
        {SendspinCodecFormat::PCM, 2, 44100, 16},
        {SendspinCodecFormat::PCM, 2, 48000, 16},
    };
    auto& player = client.add_player(std::move(player_config));
    player.set_output_delay_adjustable(true);
    auto& controller = client.add_controller();
    auto& metadata = client.add_metadata();

    // Suppress unused variable warnings for roles used only for their side effects
    (void)controller;

    // --- Listener implementations ---

    struct BasicPlayerListener : PlayerRoleListener {
#ifdef SENDSPIN_HAS_PORTAUDIO
        PortAudioSink& sink;
        PlayerRole& player;
        BasicPlayerListener(PortAudioSink& s, PlayerRole& p) : sink(s), player(p) {}
#endif

        size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) override {
#ifdef SENDSPIN_HAS_PORTAUDIO
            return sink.write(data, length, timeout_ms);
#else
            (void)data;
            (void)timeout_ms;
            null_audio_total_bytes += length;
            return length;
#endif
        }

        void on_stream_start() override {
            fprintf(stderr, ">>> Stream started\n");
#ifdef SENDSPIN_HAS_PORTAUDIO
            auto& params = player.get_current_stream_params();
            if (params.sample_rate.has_value() && params.channels.has_value() &&
                params.bit_depth.has_value()) {
                sink.configure(*params.sample_rate, *params.channels, *params.bit_depth);
            } else {
                fprintf(stderr, ">>> Stream params not yet available for PortAudio\n");
            }
#endif
        }

        void on_stream_end() override {
            fprintf(stderr, ">>> Stream ended\n");
#ifdef SENDSPIN_HAS_PORTAUDIO
            sink.clear();
#endif
        }

#ifdef SENDSPIN_HAS_PORTAUDIO
        void on_volume_changed(uint8_t vol) override { sink.set_volume(vol); }
        void on_mute_changed(bool muted) override { sink.set_muted(muted); }
#endif
    };

    struct BasicMetadataListener : MetadataRoleListener {
        void on_metadata(const ServerMetadataStateObject& md) override {
            if (md.title.has_value()) {
                fprintf(stderr, ">>> Metadata: %s - %s\n",
                        md.artist.value_or("Unknown").c_str(), md.title->c_str());
            }
        }
    };

    struct BasicClientListener : SendspinClientListener {
        void on_time_sync_updated(float error) override {
            if (SendspinClient::get_log_level() >= LogLevel::DEBUG) {
                fprintf(stderr, ">>> Time sync error: %.1f us\n", error);
            }
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
            fprintf(stderr, "    Long-term record stored. Future connections from this server\n");
            fprintf(stderr, "    will be trusted (ConnectionTrust::USER).\n");
        }

        void on_pairing_failed(const std::string& server_id,
                               SendspinPairAbortReason reason) override {
            fprintf(stderr, ">>> Pairing failed with server: %s (reason %d)\n", server_id.c_str(),
                    static_cast<int>(reason));
        }

        void on_display_pairing_code(const std::string& code,
                                     SendspinPairingCodeFormat format) override {
            if (format == SendspinPairingCodeFormat::QR_CODE) {
                // This example never offers qr_code (a terminal cannot render one), so a server
                // can only select digits; print the token verbatim if one ever arrives anyway.
                fprintf(stderr, "\n>>> Pairing token: %s\n", code.c_str());
                fprintf(stderr, "    Scan or paste this into the server to finish pairing.\n\n");
                return;
            }
            // pairing.md "Pairing Code Presentation" asks for a 3-3 grouping; the separator is
            // presentation only and never part of the code the operator types.
            fprintf(stderr, "\n>>> Pairing code: %s-%s\n", code.substr(0, 3).c_str(),
                    code.substr(3).c_str());
            fprintf(stderr, "    Enter this code on the server to finish pairing.\n\n");
        }

        void on_clear_pairing_code() override {
            fprintf(stderr, ">>> Pairing code withdrawn\n");
        }

        void on_open_pairing_window() override {
            fprintf(stderr,
                    "\n>>> Pairing window gesture required: send SIGUSR1 to this process to "
                    "allow the attempt (SIGUSR2 cancels it).\n\n");
        }

        void on_close_pairing_window() override {
            fprintf(stderr, ">>> Pairing window prompt dismissed\n");
        }
    };

    struct HostNetworkProvider : SendspinNetworkProvider {
        bool is_network_ready() override { return true; }
    };

#ifdef SENDSPIN_HAS_PORTAUDIO
    BasicPlayerListener player_listener(audio_sink, player);
    audio_sink.on_frames_played = [&player](uint32_t frames, int64_t timestamp) {
        player.notify_audio_played(frames, timestamp);
    };
#else
    BasicPlayerListener player_listener;
#endif
    BasicMetadataListener metadata_listener;
    BasicClientListener client_listener;
    HostNetworkProvider network_provider;

    player.set_listener(&player_listener);
    metadata.set_listener(&metadata_listener);
    client.set_listener(&client_listener);
    client.set_network_provider(&network_provider);

    // Start the server
    fprintf(stderr, "Starting Sendspin basic client on port %u...\n", server_port);

    if (!client.start()) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    // client_id is base64url(static X25519 public key), 43 chars.
    // The server uses this to identify the client. The keypair is persisted in
    // ~/.sendspin.json and regenerated only if the file is absent.
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

    fprintf(stderr, "Press Ctrl+C to stop.\n\n");

    // Main loop
    int tick = 0;
    while (running.load()) {
        if (window_gesture.exchange(false)) {
            fprintf(stderr, ">>> Pairing window gesture received\n");
            client.confirm_pairing_window();
        }
        if (window_cancel.exchange(false)) {
            fprintf(stderr, ">>> Pairing window cancelled\n");
            client.cancel_pairing_window();
        }
        client.loop();
#ifdef SENDSPIN_HAS_PORTAUDIO
        // Sync audio sink volume periodically (catches all volume change sources)
        if (++tick % 25 == 0) {
            audio_sink.set_volume(player.get_volume());
            audio_sink.set_muted(player.get_muted());
        }
#else
        ++tick;
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    fprintf(stderr, "\nShutting down...\n");
#ifdef SENDSPIN_HAS_MDNS
    mdns.stop();
#endif
    client.stop();

#ifndef SENDSPIN_HAS_PORTAUDIO
    fprintf(stderr, "Total audio bytes received: %zu\n", null_audio_total_bytes);
#endif
    return 0;
}
