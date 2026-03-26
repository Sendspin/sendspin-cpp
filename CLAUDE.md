# sendspin-cpp

Standalone C++ library implementing the Sendspin synchronized audio streaming protocol. Builds on both ESP-IDF (ESP32) and host platforms (macOS/Linux). Designed to be consumed by ESPHome but has no ESPHome dependencies.

## Architecture

The library provides `SendspinClient` as the main public API. It handles the full protocol lifecycle: WebSocket connections, time synchronization, audio decoding/sync, and message routing.

### Key classes

- `SendspinClient` (`client.h`) — main orchestration class, owns everything
- `SyncTask` (`sync_task.h`) — decodes encoded audio, synchronizes to server timestamps, writes PCM to an `AudioSink`
- `SendspinConnection` (`connection.h`) — abstract WebSocket connection base
- `SendspinServerConnection` / `SendspinClientConnection` — platform-specific WebSocket transports (ESP uses `esp_websocket_client`/`esp_http_server`, host uses IXWebSocket)
- `SendspinTimeFilter` (`time_filter.h`) — 2D Kalman filter for NTP-style time sync
- `SendspinTimeBurst` (`time_burst.h`) — burst-based time message coordinator
- `SendspinDecoder` (`decoder.h`) — FLAC/Opus/PCM decoder wrapper

### Platform integration

The platform (e.g., ESPHome) provides:

- An `AudioSink` implementation to receive decoded PCM audio
- Persistence callbacks for saving/loading preferences
- Network readiness and WiFi power management callbacks
- Playback progress feedback via `notify_audio_played()`

## Project layout

```text
include/sendspin/     — Public API headers (client.h, protocol.h, audio_sink.h)
src/                        — Cross-platform source files (.cpp) and private headers (.h)
src/platform/               — Platform abstraction headers and host-only source files
src/esp/                    — ESP-IDF networking implementations and headers
src/host/                   — Host (IXWebSocket) networking implementations and headers
cmake/                      — CMake modules (sources.cmake, host.cmake)
examples/common/            — Shared PortAudio audio sink used by host examples
examples/basic_client/      — Standalone host example with PortAudio audio output
examples/tui_client/        — Terminal UI host example with PortAudio audio output
```

### Header visibility

- **Public** (`include/sendspin/`): Only `client.h`, `protocol.h`, `audio_sink.h`. These are the consumer-facing API.
- **Private** (`src/`): All internal headers (decoder, sync_task, time_filter, ring buffers, etc.). Not exposed to consumers.
- **Platform-specific** (`src/esp/`, `src/host/`): Networking headers with the same names (`client_connection.h`, `server_connection.h`, `ws_server.h`) but different implementations per platform.

### Platform abstraction

Headers in `src/platform/` use `#ifdef ESP_PLATFORM` to provide unified APIs across platforms:

- `logging.h` — `SS_LOGE`/`SS_LOGW`/`SS_LOGI`/`SS_LOGD`/`SS_LOGV` macros (ESP: `esp_log.h`, host: `printf`-based)
- `memory.h` — `platform_malloc`/`platform_realloc`/`platform_free` (ESP: SPIRAM-preferring `heap_caps_malloc`, host: standard `malloc`)
- `thread.h` — threading utilities
- `time.h` — time utilities
- `base64.h` — base64 encoding/decoding
- `types.h` — platform type abstractions
- `spsc_ring_buffer.h` — single-producer/single-consumer ring buffer (ESP: FreeRTOS `xRingbuffer`, host: mutex/condition variable)
- `thread_safe_queue.h` — thread-safe queue (ESP: FreeRTOS queue, host: mutex/condition variable)
- `event_flags.h` — event flag group (ESP: FreeRTOS event group, host: mutex/condition variable)

Core source files in `src/` have no `#ifdef ESP_PLATFORM` guards — all platform differences are isolated to the platform layer and the `src/esp/`/`src/host/` directories.

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
- Feature flags: `SENDSPIN_ENABLE_PLAYER`, `SENDSPIN_ENABLE_CONTROLLER`, `SENDSPIN_ENABLE_METADATA`, `SENDSPIN_ENABLE_ARTWORK`, `SENDSPIN_ENABLE_VISUALIZER`. Defined as CMake compile definitions — `cmake/esp-idf.cmake` translates Kconfig options, `cmake/host.cmake` enables all unconditionally.
- Apache 2.0 license headers on all files

## Pre-commit hooks

Configured in `.pre-commit-config.yaml`:

- `end-of-file-fixer` and `trailing-whitespace`
- `clang-format` (v18) for C/C++ files under `src/` and `include/`
- `markdownlint-fix` for markdown files
