# sendspin-cpp

Standalone C++ library implementing the Sendspin synchronized audio streaming protocol. Builds on both ESP-IDF (ESP32) and host platforms (macOS/Linux). Designed to be consumed by ESPHome but has no ESPHome dependencies.

## Architecture

The library provides `SendspinClient` as the main public API. It handles the full protocol lifecycle: WebSocket connections, time synchronization, audio decoding/sync, and message routing. One library-owned protocol task owns every connection and does all protocol work; transports only receive (into the shared inbound ring or a connection's fallback buffer) and report closes; `loop()` only polls the network provider and drains the inbox (and, while stopped, frees parked outbound attempts). `docs/internals.md` has the threads, the cross-thread channels, the tick order and the cross-file invariants.

### Key classes

- `SendspinClient` (`client.h`): main orchestration class; owns the protocol task, the connection manager, the inbound ring and the message routing. Its protocol-task half (the tick, the command handler, the JSON and binary dispatch) is in `client_dispatch.cpp`
- `ProtocolTask` (`protocol_task.h`): the `SsProto` thread, its bounded command queue, the latest client/state slot and the never-refused lifecycle-request slot; ticks through `SendspinClient::protocol_tick()` to its next deadline
- `ConnectionManager` (`connection_manager.h`): the admitted array with role ownership, the nursery, the reaping list, admission and arbitration, time bursts, watchdogs and the published time filter and server information; pairing state machines in `connection_manager_pairing.cpp`
- `InboundRing` / `InboundItemList` / `InboundConsumer` / `InboundGate` (`inbound_ring.h`): the shared ring every admitted transport receives into (over `SharedRingBuffer`), the intrusive per-role item lists that hand audio, visualizer frames and artwork image parts to their consumer threads in place, and the per-connection transport/protocol-task hand-off
- `OutboundRing` (`outbound_ring.h`): a ring one producer thread (the source task) writes outbound binary messages into; the protocol task encrypts each in place and lends its item to the transport, which returns it once the frame is written. The source's capture ring reuses the class
- `PlayerRole` (`player_role.h`): audio streaming role, owns `SyncTask`, writes decoded audio via `on_audio_write` callback
- `ControllerRole` (`controller_role.h`): sends playback commands to the server
- `MetadataRole` (`metadata_role.h`): receives track metadata and progress
- `ArtworkRole` (`artwork_role.h`): receives album artwork images; its decode thread takes each image's announce, parts and discard markers from its item list, copies each part into one buffer per channel and returns its item at once, and parks a complete image there while the channel's `frame_done()` gate is closed
- `VisualizerRole` (`visualizer_role.h`): receives spectrum/beat visualization data
- `ColorRole` (`color_role.h`): receives audio-derived RGB color palette from the server
- `SourceRole` (`source_role.h`): streams captured audio to the server (source@v1); takes PCM through `write_audio()` from the consumer's capture thread, and runs the input stream's lifecycle and chunk sends on the protocol task
- `SourceTask` (`source_task.h`): assembles the capture ring's writes into timestamped chunks, encoded through the `SourceEncoder` seam (`source_encoder.h`: the PCM passthrough, or `OpusSourceEncoder` in `source_encoder_opus.h` when built with `SENDSPIN_ENABLE_OPUS`) into the source's outbound ring for the protocol task to send
- `SyncTask` (`sync_task.h`): decodes encoded audio from its item list in place, synchronizes to server timestamps, writes PCM via audio write callback
- `SendspinConnection` (`connection.h`): abstract WebSocket connection base
- `SendspinServerConnection` / `SendspinClientConnection`: platform-specific WebSocket transports (ESP uses `esp_websocket_client`/`esp_http_server`, host uses IXWebSocket)
- `NoiseHandshake` (`noise_handshake.h`): drives the Noise KKpsk2 handshake frames and resolves the PSK through `RecordStore`
- `NoiseSession` (`noise_session.h`): noise-c wrapper holding the KKpsk2 handshake and transport cipher states
- `NoiseTransport` (`noise_transport.h`): per-connection encrypted framing, owns fragmentation and reassembly around the session
- `RecordStore` (`record_store.h`): pairing records and the Pairing PSK (configured, stored, or generated), seeded from the client config and the persistence provider
- `Inbox` / `InboxSlot` / `GenerationSlot` (`inbox.h`): single-mutex mailbox for all main-loop-bound cross-thread state - atomic topic bitmask polled lock-free by `loop()`, plus a fixed event ring for ordered lifecycle events
- `RoleTeardown` / `TeardownTracker` (`teardown_tracker.h`): every role's teardown generation and the main-loop half of a role's teardown
- `SendspinTimeFilter` (`time_filter.h`): 2D Kalman filter for NTP-style time sync
- `SendspinTimeBurst` (`time_burst.h`): burst-based time message coordinator, one per connection
- `SendspinDecoder` (`decoder.h`): FLAC/PCM decoder wrapper, plus Opus when built with `SENDSPIN_ENABLE_OPUS`

### Role composition

Roles are added to the client at runtime via `add_player()`, `add_metadata()`, etc. Each role receives a `SendspinClient*` at construction time and uses it to access shared services (time sync, state publishing, message sending). The consumer provides behavior by implementing listener interfaces (`PlayerRoleListener`, `MetadataRoleListener`, etc.) and setting them via `set_listener()`. Required callbacks are pure virtual; optional callbacks have default no-op implementations. The client dispatches messages to roles via null-pointer checks on role pointers.

Roles can be disabled at compile time via `SENDSPIN_ENABLE_*` cmake options (host build) or Kconfig entries (ESP-IDF build). When a role is disabled, its source files are not compiled and its `add_*()` declaration, accessor, and `unique_ptr` member are removed from `client.h`. Role `#ifdef` guards live in exactly two places in the library: `cmake/sources.cmake` (source lists) and `include/sendspin/client.h`, `src/client.cpp` and `src/client_dispatch.cpp` (dispatch points); the codec gate `SENDSPIN_ENABLE_OPUS` (cmake option / Kconfig entry, default on) lives only in `src/decoder.h`, `src/decoder.cpp`, `src/player_role.cpp`, `src/source_role.cpp`, and `src/source_task.cpp`, plus the `SENDSPIN_SOURCE_OPUS_SOURCES` list (`src/source_encoder_opus.cpp`) in `cmake/sources.cmake`. Examples and tests guard their own role and opus usage like any consumer. micro-flac is only linked when the player role is enabled; micro-opus only with `SENDSPIN_ENABLE_OPUS` and the player or source role enabled.

The consuming platform (e.g., ESPHome) supplies the listener implementations plus `SendspinNetworkProvider` and the optional `SendspinPersistenceProvider`/`SendspinClientListener` providers; `docs/integration-guide.md` has the full wiring, including a minimal working example.

## Project layout

```text
include/sendspin/     - Public API headers (client.h, config.h, types.h, persistence_keys.h, persistence_codec.h, *_role.h)
src/                        - Cross-platform source files (.cpp) and private headers (.h)
src/crypto/                 - Crypto primitives and Noise/pairing constants (CPace, pairing codes and tokens, PSK wrapping)
src/platform/               - Platform abstraction headers and host-only source files
src/esp/                    - ESP-IDF networking implementations and headers
src/host/                   - Host (IXWebSocket) networking implementations and headers
cmake/                      - CMake modules (sources.cmake, host.cmake)
examples/common/            - Shared host-example helpers (PortAudio sink, file-backed persistence provider)
examples/basic_client/      - Standalone host example with PortAudio audio output
examples/tui_client/        - Terminal UI host example with PortAudio audio output
examples/source_client/     - Host example streaming the default PortAudio input (source role)
tests/                      - Host unit tests (GoogleTest)
tests/esp_idf/              - Build-only ESP-IDF project checking the component's codec dependencies
tools/stack_usage/          - Script and indirect-call tables that derive the ESP task stack defaults from -fcallgraph-info
docs/                       - integration-guide.md (consumer guide), internals.md (how the parts fit together: threads, cross-thread channels, tick order, cross-file invariants), playback-sync.md (clock sync and audio alignment), conventions.md (normative design standards)
.claude/skills/             - Review checklists applying the standards to a diff (docs-sync, embedded-review, house-patterns, test-standards)
```

### Header visibility

- **Public** (`include/sendspin/`): `client.h`, `config.h`, `types.h`, `persistence_keys.h`, `persistence_codec.h`, and role headers (`player_role.h`, `controller_role.h`, `metadata_role.h`, `artwork_role.h`, `visualizer_role.h`, `color_role.h`, `source_role.h`). These are the consumer-facing API. `config.h` contains all configuration structs (`SendspinClientConfig` and role configs). Each role header defines its own protocol types (enums, structs, conversion functions). `types.h` contains shared types used across the client and roles. `persistence_keys.h` holds the fixed storage keys and blob sizes `SendspinPersistenceProvider` is called with (`client.h` includes it). `persistence_codec.h` provides the binary, fixed-size storage codec the library itself uses to turn the pairing structs into the blobs it hands to `SendspinPersistenceProvider::save_blob()`; it is public so a custom provider or test can inspect/seed that same content.
- **Private** (`src/`): All internal headers (decoder, sync_task, time_filter, ring buffers, protocol_messages, etc.). Not exposed to consumers. `protocol_messages.h` contains message envelope structs, internal protocol enums, and protocol function declarations.
- **Platform-specific** (`src/esp/`, `src/host/`): Networking headers with the same names (`client_connection.h`, `server_connection.h`, `ws_server.h`) but different implementations per platform.

### Platform abstraction

Headers in `src/platform/` use `#ifdef ESP_PLATFORM` to provide unified APIs across platforms:

- `logging.h`: `SS_LOGE`/`SS_LOGW`/`SS_LOGI`/`SS_LOGD`/`SS_LOGV` macros (ESP: `esp_log.h`, host: `printf`-based)
- `memory.h`: `platform_malloc`/`platform_realloc`/`platform_malloc_internal`/`platform_realloc_internal`/`platform_free` (ESP: SPIRAM-preferring or internal-RAM-preferring `heap_caps_malloc_prefer`, host: standard `malloc`). `PlatformBuffer` accepts a `MemoryLocation` (defined in `include/sendspin/types.h`) to select the preference.
- `thread.h`: threading utilities
- `time.h`: time utilities
- `base64.h`: base64 encoding/decoding
- `compiler.h`: compiler hints and platform-specific macros
- `crypto.h`: SHA-256/SHA-512, HMAC-SHA-512, X25519, one-shot ChaChaPoly AEAD, CSPRNG, constant-time compare and secure zero
- `json_arena.h`: bounded internal-RAM bump-arena ArduinoJson allocator, wiping every block it frees, that backs every JSON document the protocol task parses or builds, plus `ParsedJsonMessage`, the extract-then-release reader every parsed message goes through
- `network_info.h`: best-effort lookup of the local network interface MAC address
- `types.h`: platform type abstractions
- `shared_ring_buffer.h`: multi-producer ring buffer with acquire/complete writes, one ordered consumer, any-order returns and ring-order reclamation (ESP: FreeRTOS no-split `xRingbuffer`, host: mutex/condition variable over the same layout)
- `event_flags.h`: event flag group (ESP: FreeRTOS event group, host: mutex/condition variable)
- `shadow_slot.h`: mutex-protected single-writer/single-reader slot between two threads (the sync task's playback-progress slot); state the main loop reads goes through the inbox (`inbox.h`) instead

Core source files in `src/` have no `#ifdef ESP_PLATFORM` guards; all platform differences are isolated to the platform layer and the `src/esp/`/`src/host/` directories.

## Build

- **ESP-IDF**: Used as an IDF component via `idf_component.yml`. Sources defined in `cmake/sources.cmake`.
- **Host (CMake)**: `cmake -B build && cmake --build build`. Uses ccache when installed (`SENDSPIN_USE_CCACHE`, default on when standalone). Fetches dependencies via FetchContent: ArduinoJson, noise-c, IXWebSocket, micro-flac for the player role, and micro-opus for the player or source role when `SENDSPIN_ENABLE_OPUS` is on.
- **Tests**: `cmake -B build-tests -DSENDSPIN_BUILD_TESTS=ON -DENABLE_SANITIZERS=ON -DBUILD_EXAMPLES=OFF .`, then `cmake --build build-tests --target sendspin_tests` and `ctest --test-dir build-tests --output-on-failure`.
- **ThreadSanitizer tests**: `cmake -B build-tsan -DSENDSPIN_BUILD_TESTS=ON -DENABLE_TSAN=ON -DBUILD_EXAMPLES=OFF .`, then `cmake --build build-tsan --target sendspin_tests` and `TSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-tsan --output-on-failure`. `ENABLE_TSAN` applies the thread sanitizer to every target, including the fetched dependencies, and cannot be combined with `ENABLE_SANITIZERS`.
- **Stack budgets**: the ESP task stack defaults in `config.h` are static call-graph bounds from `tools/stack_usage/` (recipe and per-task figures in its README); re-derive them, and update the README table with them, after a change that deepens a task's call chain.
- **ESP dependencies**: ArduinoJson, noise-c, esp_websocket_client, micro-flac, micro-opus (with `SENDSPIN_ENABLE_OPUS`), esp_http_server, mbedtls, pthread, esp_ringbuf, esp_hw_support
- **Host dependencies**: ArduinoJson, noise-c, micro-flac, micro-opus (with `SENDSPIN_ENABLE_OPUS`), IXWebSocket, pthreads

## Coding conventions

- Design standards: `docs/conventions.md` is the normative reference (threading/Inbox rules, validation posture, platform abstraction, embedded resource discipline, public API shape, testing, documentation sync); the bullets below are a summary
- C++20 (`gnu++20` on ESP, `cxx_std_20` on host)
- Namespace: `sendspin`
- Logging: Platform macros `SS_LOGE`, `SS_LOGW`, `SS_LOGI`, `SS_LOGD`, `SS_LOGV` (not raw `ESP_LOG*`)
- Memory: the `platform_malloc` family from `platform/memory.h`, never raw `heap_caps_malloc`/`malloc` in core code (variant semantics under Platform abstraction above)
- Threading: `std::mutex`, `std::thread` (via pthreads on both platforms). ESP build also uses FreeRTOS primitives (`xRingbuffer`, queues, event groups) for performance via the platform abstraction layer. Connection state belongs to the protocol task; requests that act on a connection go through its command queue or, for latest-wins lifecycle requests, its request slot, and work bound for the main loop goes through the inbox. Every library lock is a leaf, so there is no lock order.
- Tests: host-only and white-box; a test file that reaches private members compiles with `-fno-access-control` (`tests/CMakeLists.txt` says what and why), never through a production seam
- Apache 2.0 license headers on all files

## Pre-commit hooks

Configured in `.pre-commit-config.yaml`:

- `end-of-file-fixer` and `trailing-whitespace`
- `clang-format` (v18) for C/C++ files under `src/` and `include/`
- `markdownlint-fix` for markdown files
