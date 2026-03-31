# sendspin-cpp

Standalone C++ library implementing the Sendspin synchronized audio streaming protocol. Builds on both ESP-IDF (ESP32) and host platforms (macOS/Linux). Designed to be consumed by ESPHome but has no ESPHome dependencies.

## Architecture

The library provides `SendspinClient` as the main public API. It handles the full protocol lifecycle: WebSocket connections, time synchronization, audio decoding/sync, and message routing.

### Key classes

- `SendspinClient` (`client.h`): main orchestration class, owns connections, time sync, and message routing
- `PlayerRole` (`player_role.h`): audio streaming role, owns `SyncTask`, writes decoded audio via `on_audio_write` callback
- `ControllerRole` (`controller_role.h`): sends playback commands to the server
- `MetadataRole` (`metadata_role.h`): receives track metadata and progress
- `ArtworkRole` (`artwork_role.h`): receives album artwork images
- `VisualizerRole` (`visualizer_role.h`): receives spectrum/beat visualization data
- `SyncTask` (`sync_task.h`): decodes encoded audio, synchronizes to server timestamps, writes PCM via audio write callback
- `SendspinConnection` (`connection.h`): abstract WebSocket connection base
- `SendspinServerConnection` / `SendspinClientConnection`: platform-specific WebSocket transports (ESP uses `esp_websocket_client`/`esp_http_server`, host uses IXWebSocket)
- `SendspinTimeFilter` (`time_filter.h`): 2D Kalman filter for NTP-style time sync
- `SendspinTimeBurst` (`time_burst.h`): burst-based time message coordinator
- `SendspinDecoder` (`decoder.h`): FLAC/Opus/PCM decoder wrapper

### Role composition

Roles are added to the client at runtime via `add_player()`, `add_metadata()`, etc. Each role receives a `SendspinClient*` at construction time and uses it to access shared services (time sync, state publishing, message sending). The consumer provides behavior by implementing listener interfaces (`PlayerRoleListener`, `MetadataRoleListener`, etc.) and setting them via `set_listener()`. Required callbacks are pure virtual; optional callbacks have default no-op implementations. The client dispatches messages to roles via null-pointer checks on role pointers; no preprocessor guards.

```cpp
// Implement listener interfaces
struct MyPlayerListener : PlayerRoleListener {
    size_t on_audio_write(uint8_t* data, size_t len, uint32_t timeout_ms) override {
        return audio_output.write(data, len, timeout_ms);
    }
    void on_stream_start() override { /* ... */ }
};

struct MyMetadataListener : MetadataRoleListener {
    void on_metadata(const ServerMetadataStateObject& m) override { /* ... */ }
};

struct MyNetworkProvider : SendspinNetworkProvider {
    bool is_network_ready() override { return true; }
};

MyPlayerListener player_listener;
MyMetadataListener metadata_listener;
MyNetworkProvider network_provider;

SendspinClient client(config);
auto& player = client.add_player(player_config);
player.set_listener(&player_listener);
auto& metadata = client.add_metadata();
metadata.set_listener(&metadata_listener);
client.set_network_provider(&network_provider);
client.add_controller();
client.start_server();
```

### Platform integration

The platform (e.g., ESPHome) provides:

- A `PlayerRoleListener` implementation with `on_audio_write()` to receive decoded PCM audio
- An optional `SendspinPersistenceProvider` for saving/loading preferences
- A `SendspinNetworkProvider` for network readiness
- An optional `SendspinClientListener` for high-performance WiFi power management callbacks
- Playback progress feedback via `notify_audio_played()`

## Project layout

```text
include/sendspin/     - Public API headers (client.h, types.h, *_role.h)
src/                        - Cross-platform source files (.cpp) and private headers (.h)
src/platform/               - Platform abstraction headers and host-only source files
src/esp/                    - ESP-IDF networking implementations and headers
src/host/                   - Host (IXWebSocket) networking implementations and headers
cmake/                      - CMake modules (sources.cmake, host.cmake)
examples/common/            - Shared PortAudio audio sink used by host examples
examples/basic_client/      - Standalone host example with PortAudio audio output
examples/tui_client/        - Terminal UI host example with PortAudio audio output
```

### Header visibility

- **Public** (`include/sendspin/`): `client.h`, `types.h`, and role headers (`player_role.h`, `controller_role.h`, `metadata_role.h`, `artwork_role.h`, `visualizer_role.h`). These are the consumer-facing API. Each role header defines its own protocol types (enums, structs, conversion functions). `types.h` contains shared types used across the client and roles.
- **Private** (`src/`): All internal headers (decoder, sync_task, time_filter, ring buffers, protocol_messages, etc.). Not exposed to consumers. `protocol_messages.h` contains message envelope structs, internal protocol enums, and protocol function declarations.
- **Platform-specific** (`src/esp/`, `src/host/`): Networking headers with the same names (`client_connection.h`, `server_connection.h`, `ws_server.h`) but different implementations per platform.

### Platform abstraction

Headers in `src/platform/` use `#ifdef ESP_PLATFORM` to provide unified APIs across platforms:

- `logging.h`: `SS_LOGE`/`SS_LOGW`/`SS_LOGI`/`SS_LOGD`/`SS_LOGV` macros (ESP: `esp_log.h`, host: `printf`-based)
- `memory.h`: `platform_malloc`/`platform_realloc`/`platform_free` (ESP: SPIRAM-preferring `heap_caps_malloc`, host: standard `malloc`)
- `thread.h`: threading utilities
- `time.h`: time utilities
- `base64.h`: base64 encoding/decoding
- `types.h`: platform type abstractions
- `spsc_ring_buffer.h`: single-producer/single-consumer ring buffer (ESP: FreeRTOS `xRingbuffer`, host: mutex/condition variable)
- `thread_safe_queue.h`: thread-safe queue (ESP: FreeRTOS queue, host: mutex/condition variable)
- `event_flags.h`: event flag group (ESP: FreeRTOS event group, host: mutex/condition variable)

Core source files in `src/` have no `#ifdef ESP_PLATFORM` guards; all platform differences are isolated to the platform layer and the `src/esp/`/`src/host/` directories.

## Build

- **ESP-IDF**: Used as an IDF component via `idf_component.yml`. Sources defined in `cmake/sources.cmake`.
- **PlatformIO**: Via `library.json`
- **Host (CMake)**: `cmake -B build && cmake --build build`. Fetches dependencies (ArduinoJson, micro-flac, micro-opus, IXWebSocket) via FetchContent.
- **ESP dependencies**: ArduinoJson, esp_websocket_client, micro-flac, micro-opus, esp_http_server, mbedtls, pthread, esp_ringbuf
- **Host dependencies**: ArduinoJson, micro-flac, micro-opus, IXWebSocket, pthreads

## Coding conventions

- C++20 (`gnu++20` on ESP, `cxx_std_20` on host)
- Namespace: `sendspin`
- Logging: Platform macros `SS_LOGE`, `SS_LOGW`, `SS_LOGI`, `SS_LOGD`, `SS_LOGV` (not raw `ESP_LOG*`)
- Memory: `platform_malloc`/`platform_realloc`/`platform_free` from `platform/memory.h` (not raw `heap_caps_malloc`)
- Threading: `std::mutex`, `std::thread` (via pthreads on both platforms). ESP build also uses FreeRTOS primitives (`xRingbuffer`, queues, event groups) for performance via the platform abstraction layer.
- Role composition: Roles are added at runtime via `add_player()`, `add_metadata()`, etc. No compile-time feature flags in library code. Audio codec dependencies (micro-flac, micro-opus) are always linked.
- Apache 2.0 license headers on all files

## Pre-commit hooks

Configured in `.pre-commit-config.yaml`:

- `end-of-file-fixer` and `trailing-whitespace`
- `clang-format` (v18) for C/C++ files under `src/` and `include/`
- `markdownlint-fix` for markdown files
