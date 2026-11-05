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

// Counts the library's operator new calls while a connection is accepted, handshakes and is
// admitted, on the per-message paths after it, and through the record store's flushes. On ESPHome
// builds operator new draws only on internal RAM and aborts when it fails, so each allocation in
// these windows is one that internal heap exhaustion turns into a crash instead of a refused
// connection.
//
// This file replaces the global allocation functions, so it builds into its own binary
// (sendspin_alloc_tests): in sendspin_tests the replacement would take the place of the
// sanitizers' operator new and its mismatch checks.
//
// Every allocation inside a window records its size and stack, and the stack decides whose it is:
// the fake server's handlers and its IXWebSocket client thread are the test's own; IXWebSocket's
// server threads and the host transport classes are the host transport, which ESP replaces with
// esp_http_server; everything else is the library's. Only the library's count is asserted. Run
// with SENDSPIN_ALLOC_REPORT=1 to print each window's allocations grouped by call site, with each
// frame's offset into the binary for atos or addr2line; a count that differs prints its window.

#include "fake_persistence.h"
#include "lifecycle_test_fixtures.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <gtest/gtest.h>
#include <ArduinoJson.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

constexpr size_t MAX_RECORDS = 4096;
constexpr int MAX_FRAMES = 40;
// Library frames a report groups an allocation by and prints.
constexpr size_t CHAIN_DEPTH = 3;

struct AllocationRecord {
    size_t size;
    int frame_count;
    std::array<void*, MAX_FRAMES> frames;
};

// Static storage, since the hook must not allocate. writers counts the threads inside the hook,
// so closing a window can wait for a record still being written.
std::atomic<bool> window_open{false};
std::atomic<int> writers{0};
std::atomic<size_t> record_count{0};
std::array<AllocationRecord, MAX_RECORDS> records;
// Set while a thread records, so backtrace() cannot recurse, and over the test's own allocations.
thread_local bool unrecorded = false;

void note_allocation(size_t size) {
    if (unrecorded) {
        return;
    }
    writers.fetch_add(1);
    if (window_open.load()) {
        unrecorded = true;
        const size_t index = record_count.fetch_add(1);
        if (index < MAX_RECORDS) {
            AllocationRecord& record = records[index];
            record.size = size;
            record.frame_count = backtrace(record.frames.data(), MAX_FRAMES);
        }
        unrecorded = false;
    }
    writers.fetch_sub(1);
}

void* counted_allocate(size_t size) {
    note_allocation(size);
    return std::malloc(size == 0 ? 1 : size);
}

void* counted_allocate_aligned(size_t size, std::align_val_t alignment) {
    note_allocation(size);
    void* ptr = nullptr;
    const size_t align = std::max(static_cast<size_t>(alignment), sizeof(void*));
    return posix_memalign(&ptr, align, size == 0 ? 1 : size) == 0 ? ptr : nullptr;
}

}  // namespace

// The replaceable global allocation functions ([new.delete]), every form, so no allocation escapes
// the count and every pointer goes back through free().
void* operator new(size_t size) {
    void* ptr = counted_allocate(size);
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    return ptr;
}
void* operator new[](size_t size) {
    return ::operator new(size);
}
void* operator new(size_t size, const std::nothrow_t& /*tag*/) noexcept {
    return counted_allocate(size);
}
void* operator new[](size_t size, const std::nothrow_t& /*tag*/) noexcept {
    return counted_allocate(size);
}
void* operator new(size_t size, std::align_val_t alignment) {
    void* ptr = counted_allocate_aligned(size, alignment);
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    return ptr;
}
void* operator new[](size_t size, std::align_val_t alignment) {
    return ::operator new(size, alignment);
}
void* operator new(size_t size, std::align_val_t alignment,
                   const std::nothrow_t& /*tag*/) noexcept {
    return counted_allocate_aligned(size, alignment);
}
void* operator new[](size_t size, std::align_val_t alignment,
                     const std::nothrow_t& /*tag*/) noexcept {
    return counted_allocate_aligned(size, alignment);
}
void operator delete(void* ptr) noexcept {
    std::free(ptr);
}
void operator delete[](void* ptr) noexcept {
    std::free(ptr);
}
void operator delete(void* ptr, size_t /*size*/) noexcept {
    std::free(ptr);
}
void operator delete[](void* ptr, size_t /*size*/) noexcept {
    std::free(ptr);
}
void operator delete(void* ptr, const std::nothrow_t& /*tag*/) noexcept {
    std::free(ptr);
}
void operator delete[](void* ptr, const std::nothrow_t& /*tag*/) noexcept {
    std::free(ptr);
}
void operator delete(void* ptr, std::align_val_t /*alignment*/) noexcept {
    std::free(ptr);
}
void operator delete[](void* ptr, std::align_val_t /*alignment*/) noexcept {
    std::free(ptr);
}
void operator delete(void* ptr, size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
    std::free(ptr);
}
void operator delete[](void* ptr, size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
    std::free(ptr);
}

namespace {

// UNATTRIBUTED is a stack with no named library, IXWebSocket or fixture frame: one dladdr() could
// not name (glibc sees only exported symbols), asserted absent so a gap cannot move the count.
enum class Owner { LIBRARY, HOST_TRANSPORT, TEST, UNATTRIBUTED };

struct Frame {
    std::string name;            // demangled; "?" when dladdr() finds no symbol
    uintptr_t symbol_offset{0};  // from the symbol's start, so two sites in one function differ
    uintptr_t image_offset{0};   // from the binary's load address, for atos or addr2line
};

struct Allocation {
    size_t size;
    Owner owner;
    std::vector<Frame> chain;  // the library frames, innermost first
};

Frame resolve(void* pc) {
    Frame frame{"?"};
    Dl_info info{};
    if (dladdr(pc, &info) == 0) {
        return frame;
    }
    const auto address = reinterpret_cast<uintptr_t>(pc);
    frame.image_offset = address - reinterpret_cast<uintptr_t>(info.dli_fbase);
    if (info.dli_sname == nullptr) {
        return frame;
    }
    frame.symbol_offset = address - reinterpret_cast<uintptr_t>(info.dli_saddr);
    int status = 0;
    char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
    frame.name = (status == 0 && demangled != nullptr) ? demangled : info.dli_sname;
    std::free(demangled);
    return frame;
}

// The qualified name a demangled frame's function has, without its return type, template
// arguments or parameters: `void ns::f<x::T>(int)` gives `ns::f`.
std::string function_name(const std::string& demangled) {
    std::string name = demangled;
    constexpr std::string_view ANONYMOUS = "(anonymous namespace)";
    for (size_t at = name.find(ANONYMOUS); at != std::string::npos; at = name.find(ANONYMOUS)) {
        name.replace(at, ANONYMOUS.size(), "{anonymous}");
    }
    int depth = 0;
    size_t start = 0;
    std::string out;
    for (const char c : name) {
        if (c == '(' && depth == 0) {
            break;
        }
        if (c == '<' || c == '(' || c == '[') {
            ++depth;
        } else if (c == '>' || c == ')' || c == ']') {
            --depth;
        } else if (depth == 0) {
            if (c == ' ') {
                start = out.size() + 1;
            }
            out += c;
        }
    }
    return out.substr(std::min(start, out.size()));
}

bool in_namespace(const Frame& frame, std::string_view ns) {
    return function_name(frame.name).rfind(ns, 0) == 0;
}

bool names_any(const std::string& name, std::initializer_list<std::string_view> needles) {
    return std::any_of(needles.begin(), needles.end(), [&](std::string_view needle) {
        return name.find(needle) != std::string::npos;
    });
}

Allocation classify(const AllocationRecord& record) {
    Allocation allocation{record.size, Owner::LIBRARY, {}};
    bool fixture = false;
    bool ix = false;
    bool ix_server = false;
    bool ix_before_library = false;
    bool host_transport = false;
    for (int i = 0; i < record.frame_count; ++i) {
        Frame frame = resolve(record.frames[i]);
        if (names_any(frame.name, {"FakeEncryptedServer", "NoiseInitiatorFixtureBase"})) {
            fixture = true;
        }
        if (names_any(frame.name, {"ix::WebSocketServer", "ix::SocketServer"})) {
            ix_server = true;
        }
        if (in_namespace(frame, "ix::")) {
            ix = true;
            ix_before_library = ix_before_library || allocation.chain.empty();
        }
        if (in_namespace(frame, "sendspin::")) {
            if (allocation.chain.empty() &&
                names_any(function_name(frame.name),
                          {"SendspinServerConnection", "SendspinWsServer"})) {
                host_transport = true;
            }
            allocation.chain.push_back(std::move(frame));
        }
    }
    if (fixture || (ix_before_library && allocation.chain.empty() && !ix_server)) {
        // The fake server's handlers, or its IXWebSocket client thread.
        allocation.owner = Owner::TEST;
    } else if (host_transport || ix_before_library) {
        allocation.owner = Owner::HOST_TRANSPORT;
    } else if (allocation.chain.empty() && !ix) {
        allocation.owner = Owner::UNATTRIBUTED;
    }
    return allocation;
}

/// The allocations made while one window was open.
struct Window {
    std::vector<Allocation> allocations;
    bool overflowed{false};

    size_t count(Owner owner) const {
        return std::count_if(this->allocations.begin(), this->allocations.end(),
                             [&](const Allocation& a) { return a.owner == owner; });
    }

    /// Prints every allocation but the test's, grouped by its innermost library frames, most
    /// frequent first.
    void print(const char* title) const {
        std::printf("\n=== %s: %zu library, %zu host transport, %zu test, %zu unattributed%s ===\n",
                    title, this->count(Owner::LIBRARY), this->count(Owner::HOST_TRANSPORT),
                    this->count(Owner::TEST), this->count(Owner::UNATTRIBUTED),
                    this->overflowed ? " (records overflowed)" : "");
        for (Owner owner : {Owner::LIBRARY, Owner::HOST_TRANSPORT, Owner::UNATTRIBUTED}) {
            struct Group {
                std::vector<size_t> sizes;
                const Allocation* first{nullptr};
            };
            std::map<std::string, Group> groups;
            for (const Allocation& a : this->allocations) {
                if (a.owner != owner) {
                    continue;
                }
                std::string key = a.chain.empty() ? "?" : std::to_string(a.chain[0].symbol_offset);
                for (size_t i = 0; i < a.chain.size() && i < CHAIN_DEPTH; ++i) {
                    key += " " + function_name(a.chain[i].name);
                }
                Group& group = groups[key];
                if (group.first == nullptr) {
                    group.first = &a;
                }
                group.sizes.push_back(a.size);
            }
            std::vector<Group> sorted;
            for (auto& entry : groups) {
                sorted.push_back(std::move(entry.second));
            }
            std::stable_sort(sorted.begin(), sorted.end(), [](const Group& l, const Group& r) {
                return l.sizes.size() > r.sizes.size();
            });
            std::printf("--- %s ---\n", owner == Owner::LIBRARY          ? "library"
                                        : owner == Owner::HOST_TRANSPORT ? "host transport"
                                                                         : "unattributed");
            for (const Group& group : sorted) {
                size_t total = 0;
                std::string sizes;
                for (size_t s : group.sizes) {
                    total += s;
                    sizes += " " + std::to_string(s);
                }
                std::printf("%4zu x %6zu B [%s ]\n", group.sizes.size(), total, sizes.c_str());
                const auto& chain = group.first->chain;
                for (size_t i = 0; i < chain.size() && i < CHAIN_DEPTH; ++i) {
                    std::printf("        %s %s+%#lx (image+%#lx)\n", i == 0 ? "at" : "<-",
                                function_name(chain[i].name).c_str(),
                                static_cast<unsigned long>(chain[i].symbol_offset),
                                static_cast<unsigned long>(chain[i].image_offset));
                }
            }
        }
    }
};

void open_window() {
    record_count.store(0);
    window_open.store(true);
}

Window close_window() {
    window_open.store(false);
    while (writers.load() != 0) {
        std::this_thread::yield();
    }
    Window window;
    const size_t total = record_count.load();
    window.overflowed = total > MAX_RECORDS;
    for (size_t i = 0; i < std::min(total, MAX_RECORDS); ++i) {
        window.allocations.push_back(classify(records[i]));
    }
    return window;
}

/// The test thread's allocations inside this scope are the test's own and go unrecorded.
class TestOwned {
public:
    TestOwned() {
        unrecorded = true;
    }
    ~TestOwned() {
        unrecorded = false;
    }
    TestOwned(const TestOwned&) = delete;
    TestOwned& operator=(const TestOwned&) = delete;
};

/// pump_until() without its std::function, which may allocate on the test thread. The last loop()
/// drains what the tick that satisfied pred() handed the main loop.
template <typename Pred>
void pump_while_not(SendspinClient& client, Pred pred) {
    while (!pred()) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    client.loop();
}

/// Counts the completed time bursts the main loop reports. on_time_sync_updated() comes only after
/// a burst's last reply and its completion have run on the protocol task, so the count bounds a
/// burst on the client's side. Main loop (the test thread) only.
class BurstCountingListener : public SendspinClientListener {
public:
    void on_time_sync_updated(float /*error*/) override {
        ++this->bursts;
    }

    int bursts{0};
};

/// Closes the open window in on_stream_start() when asked to. The main loop calls it before it
/// signals the sync task to start the stream, and the sync task decodes nothing before that
/// signal, so the window holds the protocol task's and the main loop's work on a stream/start and
/// none of the sync task's.
class WindowClosingPlayerListener : public CountingPlayerListener {
public:
    void on_stream_start() override {
        CountingPlayerListener::on_stream_start();
        if (this->close_on_start) {
            this->close_on_start = false;
            this->window = close_window();
        }
    }

    bool close_on_start{false};
    Window window;
};

void expect_library_allocations(const Window& window, const char* title, size_t expected) {
    EXPECT_FALSE(window.overflowed) << title;
    EXPECT_EQ(window.count(Owner::LIBRARY), expected) << title;
    EXPECT_EQ(window.count(Owner::UNATTRIBUTED), 0U) << title;
    const char* report = std::getenv("SENDSPIN_ALLOC_REPORT");
    if ((report != nullptr && report[0] != '\0' && report[0] != '0') ||
        window.count(Owner::LIBRARY) != expected || window.count(Owner::UNATTRIBUTED) != 0) {
        window.print(title);
    }
}

/// Checks that the `index`th client/state `server` received carries both configured artwork
/// channels and the visualizer's loudness type, so the window just closed measured their build.
/// Parsed after the window closes, outside the count.
void expect_role_objects(const FakeEncryptedServer& server, size_t index) {
    const std::vector<std::string> states = server.client_states();
    ASSERT_GT(states.size(), index);
    JsonDocument doc;
    ASSERT_EQ(deserializeJson(doc, states[index]), DeserializationError::Ok);
    EXPECT_EQ(doc["payload"]["artwork"]["channels"].size(), 2U);
    EXPECT_STREQ(doc["payload"]["artwork"]["channels"][1]["source"], "artist");
    EXPECT_EQ(doc["payload"]["visualizer"]["types"].size(), 1U);
    EXPECT_STREQ(doc["payload"]["visualizer"]["types"][0], "loudness");
}

/// Checks that the client/hello `server` received lists both configured application roles and
/// carries the one support object as start() normalized it, so the admission window measured
/// their build. Read after the window closes, outside the count.
void expect_application_roles(const FakeEncryptedServer& server) {
    const std::vector<FakeEncryptedServer::WireMessage> messages = server.messages();
    const auto hello = std::find_if(messages.begin(), messages.end(), [](const auto& message) {
        return message.type == "client/hello";
    });
    ASSERT_NE(hello, messages.end());
    const std::string text(hello->body.begin(), hello->body.end());
    // The configured text has an unquoted key, which only the wire text can show was quoted
    EXPECT_NE(
        text.find(R"("_allocation_test_local_pairing@v1_support":{"port":8930,)"
                  R"("path":"/allocation-test-endpoint"})"),
        std::string::npos)
        << text;
    JsonDocument doc;
    ASSERT_EQ(deserializeJson(doc, text), DeserializationError::Ok);
    JsonArrayConst roles = doc["payload"]["supported_roles"];
    ASSERT_GE(roles.size(), 2U);
    EXPECT_STREQ(roles[roles.size() - 2], "_allocation_test_local_pairing@v1");
    EXPECT_STREQ(roles[roles.size() - 1], "_allocation_test_display@v1");
    EXPECT_TRUE(doc["payload"]["_allocation_test_display@v1_support"].isUnbound());
}

constexpr uint16_t ALLOCATION_TEST_PORT = 19300;
constexpr int TIME_BURST_SIZE = 8;

constexpr size_t ADMISSION_ALLOCATIONS = 0;
constexpr size_t CLIENT_STATE_ALLOCATIONS = 0;
constexpr size_t TIME_BURST_ALLOCATIONS = 0;
constexpr size_t CONTROLLER_STATE_ALLOCATIONS = 0;
constexpr size_t STREAM_MESSAGES_ALLOCATIONS = 0;
constexpr size_t PLAYER_FLAC_STREAM_START_ALLOCATIONS = 0;
constexpr size_t UNTAKEN_STREAM_START_ALLOCATIONS = 0;

// One paired connection with a player, a controller, metadata, two artwork channels, a visualizer
// and two application-specific roles, one with a support object, so client/hello lists the
// application roles and the player, artwork and visualizer objects of client/state are built: from
// the fake server's connect through admission and the first client/state, then one client/state
// publish, then one full burst of client/time and server/time exchanges, then the first
// controller server/state, then an artwork and visualizer stream/start and a stream/end and a
// stream/clear that name their roles, then a FLAC stream/start the player takes, then a
// stream/start whose player section the connection, no longer owning the player, does not take.
// The roles' public command and type lists are reserved when the roles are built, so even the
// first fill on the main loop allocates nothing.
TEST(Allocations, AcceptToAdmissionAndPerMessagePaths) {
    // Each string but the MAC address is longer than libc++'s 22-character inline capacity, so the
    // host counts every copy libstdc++ (15 characters) makes of a realistic one.
    SendspinClientConfig config;
    config.name = "Allocation Test Living Room Speaker";
    config.product_name = "Allocation Test Product Name";
    config.manufacturer = "Allocation Test Manufacturer";
    config.software_version = "2026.11.0-allocation-test";
    config.mac_address = "aa:bb:cc:dd:ee:ff";
    config.server_port = ALLOCATION_TEST_PORT;
    config.time_burst_size = static_cast<uint8_t>(TIME_BURST_SIZE);
    config.time_burst_interval_ms = 100;
    config.application_roles = {
        {"_allocation_test_local_pairing@v1",
         std::string(R"({port:8930,"path":"/allocation-test-endpoint"})")},
        {"_allocation_test_display@v1", std::nullopt},
    };

    BurstCountingListener burst_listener;  // Outlives the client
    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.set_listener(&burst_listener);
    WindowClosingPlayerListener player_listener;
    // Lists FLAC for the streams below (roles/player/v1.md "stream/start player object")
    PlayerRoleConfig player_config = make_pcm_player_config();
    player_config.audio_formats.push_back({SendspinCodecFormat::FLAC, 2, 48000, 16});
    client.add_player(std::move(player_config)).set_listener(&player_listener);
    ControllerRole& controller = client.add_controller();
    client.add_metadata();
    ArtworkRoleConfig artwork_config;
    artwork_config.preferred_formats = {
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 320, 320},
        {SendspinImageSource::ARTIST, SendspinImageFormat::PNG, 64, 64},
    };
    client.add_artwork(std::move(artwork_config));
    CountingVisualizerListener visualizer_listener;
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    std::unique_ptr<FakeEncryptedServer> server;

    open_window();
    {
        TestOwned test_owned;
        server = connect_paired_server(bundle.peer, ALLOCATION_TEST_PORT, std::move(options));
    }
    pump_while_not(client,
                   [&] { return client.is_connected() && server->client_state_count() > 0; });
    expect_library_allocations(close_window(), "accept to admission and the first client/state",
                               ADMISSION_ALLOCATIONS);
    expect_role_objects(*server, 0);
    expect_application_roles(*server);

    pump_while_not(client, [&] { return client.is_time_synced(); });

    const int states_before = server->client_state_count();
    open_window();
    client.set_available(false);
    pump_while_not(client, [&] { return server->client_state_count() > states_before; });
    expect_library_allocations(close_window(), "client/state", CLIENT_STATE_ALLOCATIONS);
    expect_role_objects(*server, static_cast<size_t>(states_before));

    // Opens just after the main loop reports a completed burst and closes once it reports the
    // next: one burst's sends, its replies and its completion. The next burst starts
    // time_burst_interval_ms after a completion, so none of it is in flight at the open.
    const int bursts_seen = burst_listener.bursts;
    pump_while_not(client, [&] { return burst_listener.bursts > bursts_seen; });
    open_window();
    pump_while_not(client, [&] { return burst_listener.bursts > bursts_seen + 1; });
    expect_library_allocations(close_window(), "client/time and server/time burst",
                               TIME_BURST_ALLOCATIONS);

    // Every command, so a reservation short of the full set fails the window. The main loop has
    // applied the state once get_controller_state() reports its volume.
    open_window();
    {
        TestOwned test_owned;
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"server/state","payload":{"controller":{"supported_commands":)"
            R"(["play","pause","stop","next","previous","volume","mute","repeat_off",)"
            R"("repeat_one","repeat_all","shuffle","unshuffle","switch","seek",)"
            R"("seek_relative"],"volume":20,"muted":false,"repeat":"off","shuffle":false,)"
            R"("seek_max_ms":1000}}})"));
    }
    pump_while_not(client, [&] { return controller.get_controller_state().volume == 20; });
    expect_library_allocations(close_window(), "controller server/state",
                               CONTROLLER_STATE_ALLOCATIONS);
    EXPECT_EQ(controller.get_controller_state().supported_commands.size(),
              CONTROLLER_COMMAND_COUNT);

    const int starts_before_streams = visualizer_listener.stream_starts;

    // Closes on the client/state the trailing volume command publishes, which the protocol task
    // sends only after handling the three stream messages ahead of it.
    const int states_before_streams = server->client_state_count();
    open_window();
    {
        TestOwned test_owned;
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"stream/start","payload":{"artwork":{"channels":[)"
            R"({"source":"album","format":"jpeg","width":320,"height":320},)"
            R"({"source":"artist","format":"png","width":64,"height":64}]},)"
            R"("visualizer":{"types":["loudness"],"rate_max":30}}})"));
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"stream/end","payload":{"roles":["artwork","visualizer"]}})"));
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"stream/clear","payload":{"roles":["player","visualizer"]}})"));
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"server/command","payload":{"player":{"command":"volume","volume":17}}})"));
    }
    pump_while_not(client, [&] { return server->client_state_count() > states_before_streams; });
    expect_library_allocations(close_window(),
                               "stream/start, stream/end and stream/clear with roles",
                               STREAM_MESSAGES_ALLOCATIONS);
    EXPECT_EQ(visualizer_listener.stream_starts, starts_before_streams + 1)
        << "the window closed before the main loop reported the visualizer stream";

    // A FLAC stream/start the player takes, its codec header the fLaC marker and STREAMINFO of a
    // 48 kHz stereo 16-bit stream: the parse decodes it into fixed storage and the player copies
    // it into the sync task's ring item.
    constexpr const char* FLAC_STREAM_START =
        R"({"type":"stream/start","payload":{"player":{"codec":"flac","sample_rate":48000,)"
        R"("channels":2,"bit_depth":16,)"
        R"("codec_header":"ZkxhQ4AAACIQABAAAAAAAAAAC7gC8AAAAAAAAAAAAAAAAAAAAAAAAAAA"}}})";
    constexpr const char* PLAYER_STREAM_END =
        R"({"type":"stream/end","payload":{"roles":["player"]}})";
    const auto play_flac_stream = [&](bool measured) {
        const int starts_before = player_listener.stream_starts;
        const int ends_before = player_listener.stream_ends;
        if (measured) {
            player_listener.close_on_start = true;
            open_window();
        }
        {
            TestOwned test_owned;
            ASSERT_TRUE(server->send_app_json(FLAC_STREAM_START));
        }
        pump_while_not(client, [&] { return player_listener.stream_starts > starts_before; });
        if (measured) {
            expect_library_allocations(player_listener.window,
                                       "FLAC stream/start the player takes",
                                       PLAYER_FLAC_STREAM_START_ALLOCATIONS);
        }
        {
            TestOwned test_owned;
            ASSERT_TRUE(server->send_app_json(PLAYER_STREAM_END));
        }
        pump_while_not(client, [&] { return player_listener.stream_ends > ends_before; });
    };
    // The first, outside any window, grows the main loop's held stream event list, which keeps
    // its capacity for later streams.
    play_flac_stream(false);
    // The second closes as the main loop reports the stream started.
    play_flac_stream(true);

    // An activation that leaves the player out takes the role from the connection, outside any
    // window. The window holds a FLAC stream/start whose player section a parse would validate
    // and decode, and closes on the client/state of the activation behind it that hands the
    // player back.
    const int states_before_removal = server->client_state_count();
    {
        TestOwned test_owned;
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"server/activate","payload":{"activities":["playback"],"active_roles":)"
            R"(["controller@v1","metadata@v1","color@v1","artwork@v1","visualizer@v1"]}})"));
    }
    pump_while_not(client, [&] { return server->client_state_count() > states_before_removal; });
    const int states_before_untaken = server->client_state_count();
    const int player_starts_before_untaken = player_listener.stream_starts;
    open_window();
    {
        TestOwned test_owned;
        ASSERT_TRUE(server->send_app_json(FLAC_STREAM_START));
        ASSERT_TRUE(server->send_app_json(
            R"({"type":"server/activate","payload":{"activities":["playback"],"active_roles":)"
            R"(["player@v1","controller@v1","metadata@v1","color@v1","artwork@v1",)"
            R"("visualizer@v1"]}})"));
    }
    pump_while_not(client, [&] { return server->client_state_count() > states_before_untaken; });
    expect_library_allocations(close_window(), "stream/start for a role the connection lacks",
                               UNTAKEN_STREAM_START_ALLOCATIONS);
    EXPECT_EQ(player_listener.stream_starts, player_starts_before_untaken)
        << "the player started a stream from a connection that did not own it";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

/// A blob store whose own bookkeeping is the test's: the main loop calls it inside the record
/// flushes the windows below measure.
class TestOwnedPersistence : public InMemoryPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        TestOwned test_owned;
        return InMemoryPersistenceProvider::save_blob(key, data, len);
    }

    bool commit() override {
        TestOwned test_owned;
        return InMemoryPersistenceProvider::commit();
    }

    /// save_attempts() without the test's own allocations, for a pump predicate.
    int writes(const std::string& key) const {
        TestOwned test_owned;
        return this->save_attempts(key);
    }
};

/// Counts on_pairing_succeeded() on the main loop (the test thread).
class PairingCountingListener : public SendspinClientListener {
public:
    void on_pairing_succeeded(const std::string& /*server_id*/) override {
        ++this->succeeded;
    }

    int succeeded{0};
};

constexpr uint16_t RECORD_FLUSH_TEST_PORT = 19301;
constexpr uint16_t PAIRING_TEST_PORT = 19302;

constexpr size_t PLAYBACK_HANDOFF_ALLOCATIONS = 0;
constexpr size_t UNPAIR_ALLOCATIONS = 0;
// The growth of the pairing-note list the protocol task fills for the main loop (two), and the
// std::string server_id on_pairing_started() and on_pairing_succeeded() each take (two).
constexpr size_t PAIRING_ALLOCATIONS = 4;

// Two paired servers, the incoming one's record the least recently used: from the incoming
// server's connect, through the playback activate that displaces the incumbent and the main
// loop's flush of the record order it moved, then a server/unpair of the incoming server's record
// through the flush that empties its slot.
TEST(Allocations, RecordFlushesAfterAPlaybackHandoffAndAnUnpair) {
    PairedPeer incoming = make_paired_peer();
    PairedPeer incumbent = make_paired_peer();
    TestOwnedPersistence persistence;
    seed_records(persistence, {incoming.record, incumbent.record});

    SendspinClientConfig config;
    config.name = "Allocation Test Record Flush Client";
    config.mac_address = "aa:bb:cc:dd:ee:ff";
    config.server_port = RECORD_FLUSH_TEST_PORT;
    TestNetworkProvider network;
    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = "[]";
    std::unique_ptr<FakeEncryptedServer> incumbent_server =
        connect_paired_server(incumbent, RECORD_FLUSH_TEST_PORT, options);
    pump_while_not(client, [&] {
        return client.is_connected() && persistence.writes(persistence_keys::LAST_PLAYED) > 0;
    });

    const int order_writes = persistence.writes(persistence_keys::RECORD_ORDER);
    std::unique_ptr<FakeEncryptedServer> incoming_server;
    open_window();
    {
        TestOwned test_owned;
        incoming_server = connect_paired_server(incoming, RECORD_FLUSH_TEST_PORT, options);
    }
    pump_while_not(client, [&] {
        return persistence.writes(persistence_keys::RECORD_ORDER) > order_writes &&
               persistence.writes(persistence_keys::LAST_PLAYED) > 1;
    });
    expect_library_allocations(close_window(), "playback handoff and its record flush",
                               PLAYBACK_HANDOFF_ALLOCATIONS);
    EXPECT_EQ(stored_record_order(persistence), (std::vector<uint8_t>{1, 0}))
        << "the handoff must make the incoming server's record the most recent";

    const int slot_writes = persistence.writes(persistence_keys::record_slot_key(0));
    open_window();
    {
        TestOwned test_owned;
        ASSERT_TRUE(incoming_server->send_app_json(R"({"type":"server/unpair","payload":{}})"));
    }
    pump_while_not(client, [&] {
        return persistence.writes(persistence_keys::record_slot_key(0)) > slot_writes;
    });
    expect_library_allocations(close_window(), "server/unpair and its record flush",
                               UNPAIR_ALLOCATIONS);
    EXPECT_EQ(persisted_psk_ids(persistence), std::vector<std::string>{incumbent.record.psk_id})
        << "the unpair must empty the incoming server's slot";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A pairing_psk pairing (pairing.md "Pairing PSK Flow") on a connection made on the configured
// Pairing PSK, from the pairing activate through the main loop's flush of the new record and the
// on_pairing_succeeded() that follows it.
TEST(Allocations, PairingThroughItsRecordFlush) {
    std::array<uint8_t, NOISE_PSK_SIZE> pairing_psk{};
    platform_random_bytes(pairing_psk.data(), pairing_psk.size());
    TestOwnedPersistence persistence;
    PairingCountingListener listener;  // Outlives the client

    SendspinClientConfig config;
    config.name = "Allocation Test Pairing Client";
    config.mac_address = "aa:bb:cc:dd:ee:ff";
    config.server_port = PAIRING_TEST_PORT;
    config.pairing_psk = SendspinPsk(pairing_psk);
    TestNetworkProvider network;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    // The activate waits for the test, so the window opens after the hello exchange.
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.suppress_activate = true;
    FakeEncryptedServer server(server_url(PAIRING_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               Identity::generate().value(), psk_id_for(pairing_psk), pairing_psk,
                               options);
    pump_while_not(client, [&] {
        TestOwned test_owned;
        return !server.hello_pair_methods().empty();
    });

    open_window();
    {
        TestOwned test_owned;
        ASSERT_TRUE(server.send_app_json(
            R"({"type":"server/activate","payload":{"activities":["pairing"],"active_roles":[],)"
            R"("pairing":{"method":"pairing_psk"}}})"));
    }
    pump_while_not(client, [&] { return listener.succeeded > 0; });
    expect_library_allocations(close_window(), "pairing through its record flush",
                               PAIRING_ALLOCATIONS);
    EXPECT_EQ(persisted_psk_ids(persistence),
              std::vector<std::string>{server.learned_psk_id().value_or("")})
        << "the flush must store the record the pairing minted";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

}  // namespace
