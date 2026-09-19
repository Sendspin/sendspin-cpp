# Sendspin-cpp Internals

This document describes the internal architecture of the sendspin-cpp library, focusing on threading, inter-class communication, and the ordering guarantees that keep everything correct.

## Pimpl Architecture

Each role class uses the pimpl (pointer to implementation) pattern. The public header (`include/sendspin/<role>_role.h`) exposes only the consumer-facing API: protocol types, the listener interface, and a thin role class with `struct Impl; std::unique_ptr<Impl> impl_;`. All private state, internal methods, and thread-management code live in a private impl header (`src/<role>_role_impl.h`) and the corresponding `.cpp` file.

`SendspinClient` is a `friend` of each role class, giving it access to `impl_->` for internal dispatch (message routing, event draining, lifecycle management). The `SyncTask` holds a `PlayerRole::Impl*` directly (passed at init time), so it accesses player state without indirection through the public `PlayerRole` class.

Throughout this document, internal field and method references use the `Impl` qualification (e.g., `PlayerRole::Impl::drain_events()`) to reflect the actual code location.

## Conditional Compilation

Roles can be disabled at build time via `SENDSPIN_ENABLE_*` (CMake options on host, Kconfig entries on ESP-IDF). Two mechanisms cooperate, with a strict boundary between them:

1. **CMake source-list exclusion** (`cmake/sources.cmake`). Each role has its own `SENDSPIN_<ROLE>_SOURCES` list. When a role is disabled, its translation units are not added to the build, so the code never compiles and its transitive dependencies are not required; e.g., micro-flac and micro-opus for the player. The ESP-IDF component manifest (`idf_component.yml`) similarly gates the audio codec dependencies on `SENDSPIN_ENABLE_PLAYER` so they are not even fetched.
2. **`#ifdef SENDSPIN_ENABLE_<ROLE>` guards** in `include/sendspin/client.h` and `src/client.cpp`. These are the only core files that must reference role types directly (the `std::unique_ptr<RoleClass>` members, `add_*()` / accessor declarations, and dispatch branches in message handlers). Nowhere else in the core should use these guards.

The split exists because the two problems are different. CMake handles "don't compile this file and don't require its dependencies," while `#ifdef` handles "core code needs to conditionally mention a type." Using `#ifdef` to gate entire files would still force the codec headers onto the include path; using CMake to gate individual member declarations is not possible.

As a consequence, role-only headers;e.g., `src/decoder.h`, which pulls in `<micro_flac/flac_decoder.h>` and `<opus.h>`, must only be reachable through role-only sources or through `#ifdef`-guarded includes in `client.cpp`. Public role headers in `include/sendspin/` must remain free of codec dependencies so that core files like `src/transfer_buffer.cpp` and `src/protocol_messages.h` can include them unconditionally.

When adding a new role, the checklist is: add a `SENDSPIN_<ROLE>_SOURCES` list in `cmake/sources.cmake`, add the member/accessor/dispatch guards in `client.h` and `client.cpp`, and keep any heavy dependencies behind the role's private headers.

A separate `#ifdef` axis lives in `src/platform/`: headers there use `#ifdef ESP_PLATFORM` to select between ESP-IDF (FreeRTOS, `heap_caps_malloc`, `esp_log`, etc.) and host (std primitives, `malloc`, `printf`) implementations behind a common API. This is orthogonal to role selection; the split is between build targets, not features. Core sources outside `src/platform/`, `src/esp/`, and `src/host/` should never use `#ifdef ESP_PLATFORM` directly, so platform differences stay isolated to the abstraction layer.

## Thread Model

The library uses a small number of long-lived threads. All state mutations and user-facing callbacks happen on the caller's main loop thread unless explicitly noted otherwise.

### Threads

| Thread | Name | Created by | Stack (ESP) | Priority (ESP) | Purpose |
|--------|------|-----------|-------------|-----------------|---------|
| **Main loop** | (caller's) | User code | - | - | Drives `SendspinClient::loop()`. All role event processing and listener callbacks run here. |
| **Sync task** | `Sendspin` | `PlayerRole::Impl::start()` → `SyncTask::start()` | 6192 B | 6 | Decodes audio, synchronizes to server timestamps, writes PCM to the audio sink via `on_audio_write`. |
| **Visualizer drain** | `SsVis` | `VisualizerRole::Impl::start()` | 4096 B | 2 | Reads visualization frames from a ring buffer and delivers them to the listener at the correct playback time. |
| **Artwork decode** | `SsArt` | `ArtworkRole::Impl::start()` | 4096 B | 2 | Receives image notifications and calls the decode callback. Hands the server display timestamp off to the main loop, which fires the display callback at the correct time. |
| **Network** | (library-internal) | IXWebSocket (host) or esp_http_server (ESP) | - | - | WebSocket I/O. Callbacks fire on these threads and must defer work to the main loop. |

On host builds, `platform_configure_thread()` is a no-op; threads use OS defaults. On ESP-IDF it calls `esp_pthread_set_cfg()` to set stack size, priority, name, and optional PSRAM allocation before the `std::thread` is constructed.

### Thread Lifecycle

**Sync task** (`SyncTask::start()`, `stop()` and `thread_entry()` in `src/sync_task.cpp`):

1. `SyncTask::start()` configures the thread and spawns it.
2. The caller blocks until the thread reaches IDLE state (`TASK_IDLE` event flag) or exits early due to an allocation failure (`TASK_STOPPED`).
3. The thread runs a persistent outer loop for one started session, until `stop()`.
4. `SyncTask::stop()` sets `COMMAND_STOP`, wakes the ring buffer receive via `wake_receiver()`, and joins the thread; after the join it clears `TASK_RUNNING` (a stop mid-stream leaves it set, and the player's sync-idle gate must read a stopped task as idle) and resets the encoded ring buffer, so a later `start()` begins with an empty ring. Called from `PlayerRole::Impl::stop()` (`SendspinClient::stop()` and the client destructor) and from `SyncTask`'s destructor, which is triggered by `sync_task_.reset()` in `PlayerRole::Impl`'s destructor.
5. `SyncTask::start()` clears every command and state flag before spawning, so a restart after `stop()` inherits nothing from the previous thread.

**Visualizer drain** (`src/visualizer_role.cpp`):

1. `VisualizerRole::Impl::start()` spawns the drain thread.
2. The thread blocks on ring buffer receives; commands interrupt the receive immediately via `wake_receiver()`. The 5 s receive timeout is only a fallback against a missed wake.
3. `VisualizerRole::Impl::stop()` (from `SendspinClient::stop()`, the client destructor, and the `Impl` destructor) sets `COMMAND_STOP`, wakes the ring buffer receive, joins, and then flushes the ring buffer: with the thread joined it is the ring's only consumer, and a restart must not deliver the previous session's frames. `start()` clears `COMMAND_STOP`, `COMMAND_FLUSH`, and `COMMAND_CLEAR` before spawning, since `cleanup()` on a stopped role leaves a flush flagged.

**Artwork decode** (`src/artwork_role.cpp`):

1. `ArtworkRole::Impl::start()` spawns the decode thread.
2. The thread blocks on notification queue receives; commands interrupt the receive immediately via `wake_receiver()`. The 5 s receive timeout is only a fallback against a missed wake.
3. On notification: calls `on_image_decode()`, then merges an `ArtworkDisplayUpdate` (the slot's server display timestamp plus the slot epoch it was decoded under) into the `ArtworkRole::Impl::EventState::display_slot` `InboxSlot` via `merge_artwork_display_update`. The main loop's `ArtworkRole::Impl::drain_events()` folds the taken update into its main-thread-only `held_display_*` state and fires `on_image_display()` once the timestamp is reached. Latest-wins per slot: if a newer frame's timestamp overwrites the pending one before the main loop takes it, only the newer display fires; the per-slot epoch lets the deadline sweep drop a display the channel has moved past since the hand-off (a stream boundary, a cancel, or a fresh announce).
4. `ArtworkRole::Impl::stop()` (from `SendspinClient::stop()`, the client destructor, and the `Impl` destructor) sets `COMMAND_STOP`, wakes the queue receive, joins, and then resets the notification queue so a restart does not decode the previous session's images. `start()` clears `COMMAND_STOP` before spawning.

**Destruction order** matters because external audio callbacks may still reference the sync task. `PlayerRole::Impl`'s destructor resets the sync task first (`sync_task_.reset()`) before tearing down anything else, so the thread is fully joined before any shared state is destroyed.

## Synchronization Primitives

All primitives are abstracted in `src/platform/` with ESP-IDF (FreeRTOS) and host (std::mutex/condition_variable) implementations.

### EventFlags (`src/platform/event_flags.h`)

Atomic bit flags with blocking wait. Used for thread lifecycle control:

```api
COMMAND_STOP         (1 << 0)   Stop the thread
COMMAND_STREAM_END   (1 << 1)   End current stream
COMMAND_STREAM_CLEAR (1 << 2)   Seek: discard buffered audio up to the stream/clear marker
COMMAND_START        (1 << 3)   Main loop acknowledged stream start
TASK_RUNNING         (1 << 8)   Actively decoding
TASK_STOPPED         (1 << 10)  Thread has exited
TASK_ERROR           (1 << 11)  Allocation or decode failure
TASK_IDLE            (1 << 12)  Waiting for work
```

The sync task, visualizer drain thread, and artwork decode thread all use event flags for command signaling from the main loop and status reporting back. The artwork decode thread uses a simpler subset: just `COMMAND_STOP`. The visualizer drain thread adds `COMMAND_FLUSH` and `COMMAND_CLEAR`. `COMMAND_CLEAR` discards buffered entries up to a 1-byte marker the network thread enqueues on `stream/start` and `stream/clear` (mirroring the sync task's clear-marker chunk) so frames received after the boundary survive; `COMMAND_FLUSH` (drain to empty) is only used when the producer is already stopped (`stream/end`, cleanup).

### ThreadSafeQueue (`src/platform/thread_safe_queue.h`)

Fixed-depth FIFO queue with timed send/receive. A blocking `receive()` is interruptible from any thread via `wake_receiver()` (see SpscRingBuffer below for the shared mechanism). Used to hand work from a network thread to a dedicated worker thread:

| Queue | Depth | Data | Producer | Consumer |
|-------|-------|------|----------|----------|
| `ArtworkRole::Impl::DrainTask::notify_queue` | 8 | `ArtworkNotification` | Network thread | Artwork decode thread |

### ShadowSlot (`src/platform/shadow_slot.h`)

Single-slot state container with "latest wins" or custom merge semantics for a single-writer/single-reader thread pair, regardless of which (if either) side is the main loop. The writer thread writes or merges; the reader thread takes the accumulated value. Main-loop-bound cross-thread state with many producers to consolidate goes through the Inbox / `InboxSlot` instead (see below), which puts them behind one shared mutex and a single lock-free `poll()` read per tick. Its users are the sync task's playback-progress slot (audio-callback thread to sync-task thread) and a connection's pending pairing record (main-loop writer, network-thread reader, also reset from the main loop):

| Shadow Slot | Data | Merge Strategy |
|-------------|------|----------------|
| `SyncTask::playback_progress_slot_` | `PlaybackProgress` | Sum `frames_played`, keep latest `finish_timestamp` |
| `SendspinConnection::pending_pairing_slot_` | `std::optional<SendspinPairingRecord>` | Latest wins |

The field-by-field merge pattern - preserving, say, a volume change and a mute change that arrive between two drain ticks because the merge only overwrites fields present in the delta - is what the player's `command_slot` and the group slot below use. Each server object the metadata and color slots carry is a full state, so nothing is merged field-by-field there; instead the slot keeps the oldest and the newest arrival, so a current state and the update scheduled right behind it both survive one tick.

### Inbox (`src/inbox.h`)

Shared main-loop mailbox that consolidates client-level cross-thread traffic behind a single mutex and a lock-free dirty-topic bitmask. It provides two endpoint styles:

- A fixed-capacity event ring (`push_event` / `take_events`) for lifecycle events, discriminated by `InboxEventType`. The ring drops on full and the producer logs the drop.
- `InboxSlot<T>`, a latest-value slot (`write` / `merge` / `take`) that replaces `ShadowSlot` for a single topic. Each slot exclusively owns one `INBOX_TOPIC_*` bit.

The main loop calls `poll()` once per tick to read the bitmask lock-free and only locks the mutex to drain topics whose bit is set. A bit set by a producer just after the snapshot is never lost: it stays set until a consumer drains it, so the next tick observes it. The Inbox is a leaf in the lock order, and merge functors must be pure data operations (no callbacks into application code while the mutex is held).

State currently on the Inbox:

| Endpoint | Topic bit | Data | Producer |
|----------|-----------|------|----------|
| Event ring | `INBOX_TOPIC_EVENTS` | Lifecycle events (`TimeResponsePayload`, `PLAYER_STREAM` STREAM_START/STREAM_END, `ARTWORK_STREAM` STREAM_END/STREAM_CLEAR, `VISUALIZER_STREAM` STREAM_START/STREAM_END/STREAM_CLEAR, plus `CONTROLLER_CLEARED` / `METADATA_CLEARED` / `COLOR_CLEARED`) via `InboxEvent` | Network thread (`TimeResponsePayload`, `PLAYER_STREAM`, `ARTWORK_STREAM`, `VISUALIZER_STREAM`) / main-loop thread (`*_CLEARED` and the synthetic `cleanup()` stream events) |
| `Client::group_slot` | `INBOX_TOPIC_GROUP` | `GroupUpdateObject` (field-by-field delta merge) | Network thread |
| `Client::records_dirty_slot` | `INBOX_TOPIC_RECORDS` | `bool` (pure wakeup, latest wins) | Network thread (`server/pair-finalize` handler) |
| `ControllerRole::Impl::slot` | `INBOX_TOPIC_CONTROLLER` | `ServerStateControllerObject` (latest wins) | Network thread |
| `MetadataRole::Impl::slot` | `INBOX_TOPIC_METADATA` | `PendingMetadataStates` (oldest + newest `ServerMetadataStateObject`, coalescing merge) | Network thread |
| `ColorRole::Impl::slot` | `INBOX_TOPIC_COLOR` | `PendingColorStates` (oldest + newest `ServerColorStateObject`, coalescing merge) | Network thread |
| `PlayerRole::Impl::EventState::stream_params_slot` | `INBOX_TOPIC_PLAYER_STREAM_PARAMS` | `ServerPlayerStreamObject` (latest wins) | Network thread |
| `PlayerRole::Impl::EventState::command_slot` | `INBOX_TOPIC_PLAYER_COMMAND` | `ServerCommandMessage` (field-by-field merge) | Network thread |
| `PlayerRole::Impl::EventState::state_slot` | `INBOX_TOPIC_PLAYER_STATE` | `SendspinClientState` (latest wins) | Sync task thread |
| `VisualizerRole::Impl::EventState::config_slot` | `INBOX_TOPIC_VISUALIZER_CONFIG` | `ServerVisualizerStreamObject` (latest wins) | Network thread |
| `ArtworkRole::Impl::EventState::display_slot` | `INBOX_TOPIC_ARTWORK_DISPLAY` | `ArtworkDisplayUpdate` (per-slot display timestamp + epoch, merged) | Artwork decode thread |

One family of main-loop-bound notifications deliberately stays off the Inbox: the pairing/trust listener notifications (`on_pairing_started`, `on_pairing_succeeded`, `on_pairing_failed`, `on_trust_changed`, and the pairing-code/pairing-window prompts). They are queued as tagged `PairingNote` entries in `SendspinClient::EventState::pairing_notes` by the `note_*()` methods, produced only on the main loop (by `ConnectionManager` while `conn_ptr_mutex_` is held, and by `stop()` for the pairing-UI dismissals) and dispatched later in the same `SendspinClient::loop()` tick after that lock is released. The deferral exists to fire the callbacks unlocked, not to cross threads, and the payloads carry strings the POD-only ring cannot, so no mutex or topic bit is involved. Dispatch moves the queue out first (so a callback that re-enters connection teardown cannot invalidate the iteration), then fires grouped by note type in a fixed precedence order (started, succeeded, trust, failed, display-code, clear-code, open-window, close-window) rather than queue order; the window/code-clear types coalesce to at most one callback per tick. `cleanup_connection_state()` clears the queue and bumps the same drain generation the ring drain uses, so a teardown re-entered from a dispatch callback also abandons the rest of that tick's already-moved batch.

All roles have been migrated onto the Inbox. The controller/metadata/color roles write or merge server state into their `InboxSlot` from `handle_server_state()`, and their disconnect clear arrives as a `*_CLEARED` lifecycle event on the shared ring rather than a per-role flag. The player role owns three `InboxSlot`s (stream params, command, and client state, on its `EventState`) plus `PLAYER_STREAM` lifecycle events on the shared ring; its disconnect clear is the synthetic STREAM_END that `cleanup()` pushes onto the ring. The visualizer role writes its stream config to `config_slot` and delivers STREAM_START/END/CLEAR as `VISUALIZER_STREAM` ring events (no per-tick `drain_events()`; the config is taken when the START event is dispatched). The artwork role merges per-slot display timestamps (tagged with the channel's decode-time `slot_epochs[slot]` value) into `display_slot`, delivers STREAM_END/CLEAR as `ARTWORK_STREAM` ring events, and keeps a per-tick `drain_events()` for its server-clock display-deadline sweep. Both roles' disconnect clears are synthetic stream events that `cleanup()` pushes onto the ring.

### SpscRingBuffer (`src/platform/spsc_ring_buffer.h`)

Single-producer/single-consumer ring buffer for variable-size binary data. Two-phase API: `acquire` → `commit` (producer), `receive` → `return_item` (consumer). Also supports a single-phase `send` for the producer.

A blocking `receive()` is interruptible from any thread via `wake_receiver()`: the blocked (or next blocking) receive returns null early without consuming data, and the consumer re-checks its command flags. This is what makes role stop and stream commands take effect immediately instead of at the next receive timeout, so the receive timeouts are pure idle-wakeup tuning. On ESP the mechanism is an internal binary "items-or-wake" semaphore: every producer send/commit and every `wake_receiver()` gives it, and `receive()` polls the buffer non-blocking, then blocks on the semaphore, then polls again. Because the semaphore is binary, a burst of sends collapses into one token; the poll-before-block (repeated on every call while data remains) is what keeps items from being stranded behind a collapsed token, and a wake absorbed by a racing item's delivery is covered by the consumers' loop-top command checks. The flip side of that poll is a stale token: an item taken by the poll leaves its send's token behind, so the next blocking `receive()` after a burst is drained returns null once without waiting. The semaphore is binary, so this happens at most once per drained burst, and every consumer already treats a null return as "re-check state and retry" (the same spurious-wakeup discipline a condition variable demands), so the cost is one extra loop iteration rather than a busy loop. On host it is a `wake_pending_` flag on the receive condition variable with the same semantics.

Used for:

- **Encoded audio**: Via the `SendspinAudioRingBuffer` wrapper (which adds chunk headers and exposes `write_chunk` / `receive_chunk` / `return_chunk`). Network thread writes chunks; sync task reads and decodes them.
- **Visualizer frames**: Used directly. Network thread writes one entry per visualizer binary message; drain thread reads them at the correct playback time.

### Other Primitives

- **`std::mutex`** on `ConnectionManager::conn_mutex_`: protects deferred connection event vectors.
- **`std::mutex`** on `SendspinTimeFilter::state_mutex_`: protects Kalman filter state (offset, drift, covariance).
- **`std::atomic<bool>`** on `SendspinConnection::message_dispatch_enabled_`: allows the main loop to instantly suppress message delivery from the network thread.
- **`std::atomic<bool/uint8_t>`** on `VisualizerRole::Impl`: network thread writes stream config atomically; drain thread reads it.
- **`std::atomic<bool>`** on `ArtworkRole::Impl::stream_active`: guards `handle_binary()` from writing when no stream is active.
- **`std::atomic<uint32_t>[]`** on `ArtworkRole::Impl::slot_epochs`: one epoch per artwork channel, bumped whenever the channel's pending image is discarded (a stream end or clear and `cleanup()` bump all four; a `stream/start` bumps the channels it reconfigured, and a cancel message or a fresh announce bumps one). A queued notification, a decode hand-off and a held display each carry the epoch they were made under and drop themselves at their next check, so no thread has to reach into another's state to cancel a delivery.
- **`std::mutex`** on `ArtworkRole::Impl::DrainTask::slot_mutex`: guards every field of `SlotBuffer`, plus the role-wide `ArtworkTransfer` (shared across all slots; artwork is not a hot path, so contention is negligible). Under that lock `write_idx` tracks which of the two per-slot buffers the network thread writes to next, `drain_active`/`drain_buf_idx` record which buffer the decode thread is decoding, `write_generation[]` lets the decode thread detect a buffer overwritten before it could be claimed, and `ack_state`/`has_parked`/`parked` hold the per-slot frame-done gate. The transfer record is written by the network thread as an image arrives and cleared from the main loop by `cleanup()`, which is what the lock buys it.
- **`std::atomic<uint8_t>`** on `SendspinClient::high_performance_ref_count_`: ref-counted high-performance networking requests from time sync and playback.

## Message Flow

### WebSocket Receive Path

Encryption is mandatory, so the frame type does not select the handler: every application
message arrives as a binary Noise frame and is routed by the leading byte of its *decrypted*
plaintext. Text frames carry only the pre-transport handshake.

```api
Network thread (IXWebSocket / esp_http_server)
  │
  ├─ Assembles fragmented WebSocket frames into complete messages
  │  (connection.cpp: prepare_receive_buffer / commit_receive_buffer)
  │
  └─ dispatch_completed_message()
     ├─ Text frame → handshake driver only (server/init, noise/handshake).
     │  Dropped once transport is active; never reaches a role handler.
     │
     └─ Binary frame → Noise transport active?
        ├─ no  → refused (UNAUTHORIZED if a handshake is pending, else dropped)
        └─ yes → decrypt_in_place() → accept_plaintext() reassembly
                 └─ dispatch_complete_noise_message()
                    ├─ checks message_dispatch_enabled_ (teardown guard)
                    └─ routes on the plaintext type byte:
                       ├─ MSG_TYPE_JSON_BODY → SendspinClient::process_json_message()
                       └─ other → SendspinClient::process_binary_message()
```

Note that `message_dispatch_enabled_` is checked after decryption and reassembly, not before
frame dispatch: a frame that arrives during teardown is still decrypted (advancing the nonce)
before it is discarded. See [Transport Stack](#transport-stack-srcnoise_transporth-srcnoise_transportcpp)
for the framing and fragmentation details.

### JSON Message Dispatch (network thread)

`dispatch_json_message()` (`src/client.cpp`) parses the message type and routes:

| Message | Action on Network Thread |
|---------|------------------------|
| `SERVER_HELLO` | Stores server info and connection reason on the connection, then sets `server_hello_received_` (an atomic store that publishes the fields to the main loop; the manager's promotion scan observes `is_handshake_complete()` on its next tick) |
| `SERVER_TIME` | Pushes a `TIME_RESPONSE` `InboxEvent` onto the shared inbox ring |
| `SERVER_STATE` | Writes into the controller, metadata, and color `InboxSlot`s via each role's `handle_server_state()` |
| `SERVER_COMMAND` | Merges into the player's `command_slot` (`InboxSlot<ServerCommandMessage>`) |
| `GROUP_UPDATE` | Merges into `Client::group_slot` (`InboxSlot<GroupUpdateObject>`) |
| `STREAM_START` | Writes to the player's `stream_params_slot`, pushes a `PLAYER_STREAM` (STREAM_START) event onto the inbox ring. Marks the artwork stream active, ends any transfer in flight, and bumps the slot epoch of every channel whose configuration changed (`changed_channel_mask()`), releasing those channels' `DECODE_DELIVERED` ack gates; the notification queue and `display_slot` are left alone, since the epoch stamp is what invalidates stale entries. Writes the config to the visualizer's `config_slot` and pushes a `VISUALIZER_STREAM` (STREAM_START) event onto the inbox ring. |
| `STREAM_END` | Pushes a `PLAYER_STREAM` (STREAM_END) event onto the inbox ring and signals sync task `COMMAND_STREAM_END`; pushes `ARTWORK_STREAM` (STREAM_END) and `VISUALIZER_STREAM` (STREAM_END) events onto the inbox ring |
| `STREAM_CLEAR` | Pushes `ARTWORK_STREAM` (STREAM_CLEAR) and `VISUALIZER_STREAM` (STREAM_CLEAR) events onto the inbox ring; for the player, signals sync task `COMMAND_STREAM_CLEAR` and enqueues a `CHUNK_TYPE_STREAM_CLEAR_MARKER` chunk into the encoded ring buffer (no player listener callback - a seek is not a stream lifecycle event) |

#### JSON parse arena (`src/platform/json_arena.h`)

The `JsonDocument` used to parse each incoming message comes from `make_json_document()`. By default that allocates the document's variant pool and copied strings out of PSRAM (`PsramJsonAllocator`), which puts PSRAM traffic on the CPU-hot network thread for every message. When `SendspinClientConfig::json_arena_size > 0` (the default is `2048`), `SendspinClient` instead owns a `SendspinArenaAllocator` (a fixed internal-RAM bump arena) and `process_json_message()` calls `reset()` on it and parses into a document backed by it. An allocation that does not fit the remaining budget falls back to `platform_malloc` (PSRAM-preferring), so an unexpectedly large message (e.g. track metadata) still parses, just slowly.

The bump arena suits ArduinoJson's allocation pattern: during a parse the variant pool is allocated once up front and the deserializer's string scratch buffer is always the most-recently-allocated block while it grows and shrinks, so those reallocations happen in place; document teardown frees strings newest-first and the pool last (LIFO), draining the arena back to empty on its own. `reset()` between messages is a safety net for any arena block left behind by a non-LIFO free; it cannot free PSRAM fallbacks (those are released by `deallocate()` on document teardown like any other allocation). The allocator is not thread-safe; the single instance is owned by `SendspinClient` and touched only on the network thread (`process_json_message()` runs serialized on the httpd worker task, and the previous call's `JsonDocument` is destroyed before the next call). Outgoing-message serialization in `src/protocol.cpp` still uses the PSRAM allocator.

### Binary Message Dispatch (network thread)

`process_binary_message()` extracts the type byte and routes:

| Binary Type | Handler |
|-------------|---------|
| Player audio | `PlayerRole::Impl::handle_binary()`: writes to encoded audio ring buffer |
| Artwork transfer message | `ArtworkRole::Impl::handle_binary()`: accumulates the announced image into a per-slot double buffer and, on completion, enqueues a notification for the artwork decode thread |
| Visualizer data (binary types 16-20) | `VisualizerRole::Impl::handle_binary()`: writes to visualizer ring buffer |

An audio chunk is laid out per roles/player/v1.md "Audio Chunks (Binary)": the type byte, then bytes 1-8 the big-endian int64 playback timestamp in the server's clock, bytes 9-12 the big-endian uint32 `send_ahead`, and the encoded audio frame from byte 13. `send_ahead` reports the lead the server had in hand when it transmitted and carries no scheduling meaning, so `handle_binary()` parses past it; a chunk too short to hold the header is logged and dropped. Visualizer messages carry the 8-byte timestamp alone, with no `send_ahead`.

An artwork image is transferred as several messages, per roles/artwork/v1.md "Server -> Client: Artwork (Binary)". After the type byte, byte 1 is a flags byte: bit 1 marks an announce (`[timestamp(8)][total_size(4)]`, 14 bytes with the type byte), bit 0 a cancel (2 bytes, nothing else), and neither a part, whose remaining bytes are the next stretch of the encoded image. A `stream/start` discards the pending image of only the channels whose configuration it changes (`changed_channel_mask()` compares its channel array against the one in force; every channel counts as changed when either side omits the array), because the server re-sends an image only for the channels that changed. `ArtworkRole::Impl` keeps one `ArtworkTransfer` for the whole role, since the spec allows only one in flight across all of its channels: the announce claims one of the slot's two buffers, sizes it to `total_size`, and each part is copied in at the accumulated offset until the image is complete, which is when the decode thread is notified. An announce with `total_size` 0 is the empty image and completes at once, notifying with `data_length == 0` (the clear that `on_image_clear()` delivers). Malformed messages (shorter than 2 bytes, past the 65519-byte cap, an announce that is not 14 bytes, a cancel with a body, a reserved flag bit, both flag bits set) and malformed sequences within an active stream (an announce while a transfer is in flight, a part with none in flight or on another channel, a part running past `total_size`) make `handle_binary()` return false, and `process_binary_message()` closes the connection.

An image larger than `ArtworkRole::Impl::image_cap()` for its channel is not held: the cap is the channel's configured `ImageSlotPreference::max_image_bytes` (128 KiB by default), refused before a byte of it is allocated, which is what bounds the role's image memory at twice that per configured channel. A role with no listener takes the same path, since it has nowhere to put an image either. roles/artwork/v1.md "Artwork (Binary)" requires a client that discards image data to keep counting each part's bytes toward `total_size`, so such a transfer still runs to its end with its bytes dropped, leaving the sequence intact for the transfers that follow. A channel the role declared no preference for has a cap of 0 and therefore holds nothing. The buffers are grown, never shrunk, so a channel settles at its largest image and later transfers reuse the allocation.

### Main Loop Processing

`SendspinClient::loop()` (`src/client.cpp`) is a no-op while the client is stopped (a stopped client has no connections or threads, and the manager loop must not restart the WebSocket server). While started it runs the following steps **in order** on each tick; steps 3 onward are `SendspinClient::drain_inbox()`, which `stop()` also calls once so the clear callbacks are delivered synchronously:

```api
1. connection_manager_->loop()   (sections gated on lock-free atomic hints - see below)
   ├─ Start WS server if network ready
   ├─ Swap deferred connection events under mutex   (only when has_pending_events_)
   ├─ Process close/disconnect events (on_connection_lost)
   ├─ Promotion scan: establish nursery connections whose hello handshake completed
   │  (handoff decisions against the incumbent)
   ├─ flush_pending_record_ops(): perform the persistence writes the activate, unpair, and
   │  promotion handlers decided on (records blob, last-played), unlocked
   ├─ flush_pending_admission(): admit the connection the promotion scan installed, unlocked
   ├─ Call loop() on the current and nursery connections   (only when has_current_ or nursery_size_)
   ├─ Check per-connection hello retry timers   (only when nursery_size_)
   ├─ Reap nursery connections past the establish deadline
   ├─ Liveness: drop the current connection once inbound silence reaches liveness_timeout_us_
   │  (only when has_current_; stamped per complete inbound message at dispatch)
   ├─ flush_deferred_releases()   (early-returns without locking when deferred_size_ is 0)
   ├─ Tick the platform ws_server (ESP: reap stalled upgrades; host: no-op)
   ├─ scan_pairing_attempt_timeout(): abort a pairing attempt past PAIRING_ATTEMPT_TIMEOUT_US
   └─ scan_reprove_watchdog(): drop a current connection that never re-proved itself
      (flush_deferred_releases() also runs after the admission flush and after each scan)

2. time_burst_->loop(conn)  (requires conn != nullptr && conn->is_operational(), so it is
                             skipped before the first server/activate and while a
                             re-handshake awaits the next one; a pairing attempt does not
                             stop it)
   ├─ Send next time message if ready
   ├─ Acquire/release high-performance networking around burst
   └─ Notify listener of sync error when burst completes

3. Flush deferred high-performance releases, then persist a staged pairing record
   (when INBOX_TOPIC_RECORDS is set) via RecordStore::persist_records()

4. Drain inbox event ring (when INBOX_TOPIC_EVENTS is set)
   ├─ Feed TIME_RESPONSE events into time_burst_->on_time_response()
   ├─ Fire CONTROLLER/METADATA/COLOR_CLEARED via each role's handle_cleared_event()
   ├─ Dispatch PLAYER_STREAM via player_->impl_->on_stream_ring_event()
   ├─ Dispatch ARTWORK_STREAM via artwork_->impl_->handle_stream_ring_event()
   └─ Dispatch VISUALIZER_STREAM via visualizer_->impl_->handle_stream_ring_event()

5. Dispatch deferred pairing/trust notes (when EventState::pairing_notes is non-empty)
   └─ Fire on_pairing_started/succeeded/failed, on_trust_changed, and the pairing-code/window
      prompts, unlocked, grouped by note type in precedence order

6. Role event draining (each role's impl_->drain_events(), gated on impl_->needs_drain(slot_bits))
   ├─ player_->impl_->drain_events()
   ├─ controller_->impl_->drain_events()
   ├─ metadata_->impl_->drain_events()
   ├─ color_->impl_->drain_events()
   └─ artwork_->impl_->drain_events()   (display-deadline sweep; visualizer has no drain_events())

7. Drain group_slot (when INBOX_TOPIC_GROUP is set in slot_bits)
   └─ Apply group deltas, fire on_group_update, persist last played server
```

This ordering matters: connection lifecycle events are processed before role events, and time sync before audio processing, so that roles always see a consistent connection and time state.

Each `loop()` section that would otherwise take a mutex first consults a lock-free atomic hint, so an idle tick pays only for the atomic loads it needs to decide there is nothing to do. `ConnectionManager` keeps five such hints, each refreshed under the owning mutex right after the container/pointer it mirrors changes (always re-derived from `.size()` or the assigned value, never incremented in place, so the hint cannot drift from ground truth):

- `has_pending_events_` (under `conn_mutex_`): set at every push into any of the deferred `pending_*_events_` queues and by the two pairing-window gesture schedulers, cleared once `loop()` has swapped every queue and flag out. Lets `loop()` skip the `conn_mutex_` acquisition when nothing is pending.
- `nursery_size_` (under `conn_ptr_mutex_`): mirrors `nursery_.size()`. Lets `loop()` skip the current/nursery copy-and-`loop()` block, the hello-retry scan, and the nursery reap scan when the nursery is empty, while keeping the lifecycle block running while any nursery connection exists (its promotion scan is level-triggered on connection flags, not on events).
- `has_current_` (under `conn_ptr_mutex_`): true whenever `current_connection_` is non-null. Lets `loop()` skip the copy-and-`loop()` block when there is no current connection and the nursery is empty.
- `deferred_size_` (under `conn_ptr_mutex_`): mirrors `deferred_releases_.size()`. Lets `flush_deferred_releases()` early-return without locking when nothing is queued.
- `pending_record_ops_size_` (under `conn_ptr_mutex_`): mirrors `pending_record_ops_.size()`. Lets `flush_pending_record_ops()` early-return without locking when nothing is staged.

Steady state is therefore a handful of atomic loads plus the `conn_ptr_mutex_` acquisitions the ungated per-tick scans take: `flush_pending_admission()`, `scan_pairing_attempt_timeout()`, and `scan_reprove_watchdog()` lock unconditionally, so disconnected-and-idle costs three, and connected-and-idle five (the current/nursery copy ahead of the `conn->loop()` calls, and the liveness check). The mutex-protected containers and pointers remain the ground truth in every case; the hints only decide whether it is worth locking to look.

The Inbox drain steps gate the same way, off two lock-free `poll()` snapshots of the topic bitmask. `inbox_bits` is taken first and gates the deferred record persist (step 3) and the event-ring drain (step 4). `slot_bits` is taken *after* that drain completes and gates the role drains (step 6) and the group drain (step 7); the second snapshot catches topic bits a producer set while the ring drain was running (including a ring event's own side effects re-entering the inbox). A bit either snapshot races and misses is not lost - it stays set and the next tick's `poll()` observes it (bounded staleness, per `Inbox::poll()`). Each role's `needs_drain(slot_bits)` decides whether its drain runs: mostly a simple `slot_bits & INBOX_TOPIC_*` test, but the player, metadata, and artwork roles OR in a main-thread-only carry-over term (the player's `awaiting_sync_idle_events`, the metadata role's future-dated `held_state`, the artwork role's nonzero `held_display_mask`) so that work waiting out a deadline no inbox bit tracks still gets a drain every tick until it fires.

## Role Event Draining

Most roles implement `drain_events()` to process their deferred state on the main loop thread; stream lifecycle events instead ride the shared inbox ring and are dispatched from the ring drain (step 4 above) via each role's `handle_stream_ring_event()` / `on_stream_ring_event()` / `handle_cleared_event()`. Together these convert cross-thread inbox writes into sequential, single-threaded callback delivery. (The visualizer role has no `drain_events()` - all its delivery is ring-driven.)

### PlayerRole::Impl::drain_events() (`src/player_role.cpp`)

Three stages, processed in order:

**1. Client state updates**: Takes from `state_slot` (latest-wins `InboxSlot`, written by the sync task). Calls `client_->update_state()`.

**2. Server commands**: Takes from `command_slot`. Checks each field independently (volume, mute, output_delay) and fires the corresponding listener callback.

**3. Stream lifecycle**: The most complex part:

```api
PLAYER_STREAM ring events → on_stream_ring_event() → awaiting_sync_idle_events list
                       │
                       ▼
         For each event in order:
           ├─ STREAM_END:
           │    If sync task is still running → wait for next tick
           │    If sync task is idle → fire on_stream_end(), continue
           │
           └─ STREAM_START:
                Take stream_params_slot
                Mark stream active, fire on_stream_start()
                Signal sync task COMMAND_START
```

The `awaiting_sync_idle_events` list (on `PlayerRole::Impl`) is the key ordering mechanism. STREAM_END callbacks are held until the sync task has reached its IDLE state, preventing the main loop from processing a new STREAM_START before the sync task has finished with the old stream. Events ahead of the blocked event also wait, preserving FIFO order. (`stream/clear` is not queued here - it is handled synchronously in `handle_stream_clear()` by signaling the sync task and enqueuing a marker chunk.)

### Other Roles

- **ControllerRole**: Takes the latest `ServerStateControllerObject` from its `InboxSlot`, fires `on_controller_state()`. The disconnect clear is not handled here; it arrives as a `CONTROLLER_CLEARED` event on the shared ring, whose `handle_cleared_event()` fires `on_controller_state_clear()` (deferred from `cleanup()` to avoid invoking the listener while `ConnectionManager` holds `conn_ptr_mutex_`).
- **MetadataRole**: each `server/state` metadata object is the role's full state, so nothing is merged field-by-field across messages: a field a later object omits has no value, and an omitted `progress` clears the position. The slot keeps the oldest and the newest arrival (`PendingMetadataStates`). `InboxSlot` has no `take_if`, so the deadline gate is split in two: `take()` unconditionally moves the pending states into a main-thread-only `held_state`, applying the earlier one first when it is due before holding the later one (each replaces an already-held state, per roles/metadata/v1.md "Scheduled metadata updates"), then the server-clock deadline is evaluated with no lock held, applying the state and firing `on_metadata()` once the `timestamp` is reached (or immediately if there is no active connection). A future-dated `held_state` persists across ticks with no topic bit set, which is why `needs_drain()` ORs in `held_state.has_value()` alongside the `INBOX_TOPIC_METADATA` bit test: the deadline sets no inbox bit, so without that term a bit-gated tick would strand the state until an unrelated new one happened to re-set the bit, silently starving deadline-based delivery. The clear arrives separately as a `METADATA_CLEARED` ring event (`handle_cleared_event()` fires `on_metadata_clear()`), deferred from `cleanup()` for the same `conn_ptr_mutex_` reason.
- **ColorRole**: Same structure as MetadataRole: `take()` into `held_state`, a lock-free server-clock deadline gate firing `on_color()`, and a `COLOR_CLEARED` ring event driving `on_color_clear()`.
- **ArtworkRole**: Stream end/clear lifecycle is handled earlier in the tick by `handle_stream_ring_event()` (dispatched from the ring drain, before this call), which clears `held_display_mask`/`display_slot` and fires `on_image_clear()` for each configured slot, so a lifecycle event is ordered ahead of any display delivery for the tick. `drain_events()` itself folds any taken `display_slot` update into the main-thread-only `held_display_*` state (latest-wins per slot), then sweeps the held slots and fires `on_image_display(slot, lateness_ms)` for any whose timestamp is due on the synced client clock (or immediately if there is no active connection). The deadline is computed by the pure `display_overdue_us()` helper, which applies the slot's `display_offset_ms` shift (positive fires early) and returns the overdue microseconds; `display_lateness_ms()` maps that to the `lateness_ms` argument, reserving `0` for the no-connection case (a connected on-time display is floored to 1 ms so it never collides with that sentinel). Per-slot epochs drop a held display the channel has moved past since the decode hand-off: a stream end, clear or disconnect, a `stream/start` that changed that channel's configuration, a cancel message, or the announce of a newer image, all of which discard the channel's pending image. `needs_drain()` ORs a nonzero `held_display_mask` into the `INBOX_TOPIC_ARTWORK_DISPLAY` bit test (the same carry-over pattern the metadata role uses for `held_state`) so held displays keep getting a drain every tick until their deadline fires, even though the deadline sets no inbox bit; `on_image_decode` still happens on the dedicated artwork decode thread.
  - **Ack gate (`require_frame_done`)**: A slot can opt into per-slot back-pressure. Each `SlotBuffer` carries a `SlotAckState` (`IDLE` -> `DECODE_DELIVERED` once `on_image_decode()` fires -> `PRESENTED` once `on_image_display()`/`on_image_clear()` fires), all guarded by `slot_mutex`. An announce discards the channel's pending image, so a payload arriving while the outstanding delivery is only `DECODE_DELIVERED` supersedes it: the epoch bump drops that display and releases the gate. A delivery that already reached `on_image_display()`/`on_image_clear()` is the current image, which no announce discards, so it stays armed until `frame_done()`; that is an acknowledgment contract, not a promise about the decode buffer, whose contents are only guaranteed for the duration of `on_image_decode()`. While a gated slot is not `IDLE`, the decode thread (`process_notification()`) does not decode a newer notification; it *parks* it latest-wins in `SlotBuffer::parked` (`has_parked`) instead of decoding concurrently with the un-acked delivery. `ArtworkRole::frame_done(slot)` (main loop) returns the gate to `IDLE` and, if a notification is parked, calls `wake_drain_thread()` (`notify_queue.wake_receiver()`), which unblocks the decode thread's `notify_queue.receive()` so it re-runs the top-of-loop parked-slot sweep. The parked notification is re-validated on replay, so a since-stale generation/epoch is simply skipped. A clear counts as a delivery: `handle_stream_ring_event()` drops any parked notification and forces gated slots to `PRESENTED`, so exactly one `frame_done()` is owed after it. A stream restart releases only `DECODE_DELIVERED` slots (their display can no longer fire); `PRESENTED` stays armed because the consumer may still be mid-fade on the prior stream's last delivery. There is no timeout.
- **VisualizerRole**: Has no `drain_events()`. STREAM_START/END/CLEAR are dispatched entirely from `handle_stream_ring_event()` (from the ring drain): STREAM_START `take()`s the config from `config_slot` and fires `on_visualizer_stream_start()`; STREAM_END/CLEAR fire `on_visualizer_stream_end()`/`on_visualizer_stream_clear()`.

## Sync Task State Machine

The sync task (`SyncTask::thread_entry`, `src/sync_task.cpp`) runs a two-level state machine on its dedicated thread.

### Outer Loop (per-stream lifecycle)

```api
┌──────────────────────────────────────────────────────────┐
│                    COMMAND_STOP?                          │
│                    ┌─── yes ──→ exit thread               │
│                    │                                      │
│  ┌─────────────────┴──────────────────┐                  │
│  │           IDLE STATE               │                  │
│  │  • Clear TASK_RUNNING and all      │                  │
│  │    COMMAND flags                   │                  │
│  │  • Set TASK_IDLE                   │                  │
│  │  • Reset context + progress queue  │                  │
│  │  • Wait for codec header (wake)    │◄──┐              │
│  └────────────┬───────────────────────┘   │              │
│               │ got header                │              │
│               ▼                           │              │
│  ┌────────────────────────────────────┐   │              │
│  │     WAIT FOR CLIENT ACK            │   │              │
│  │  • Wait on COMMAND_START or        │   │              │
│  │    STOP/END/CLEAR                  │   │              │
│  │  • If END/CLEAR arrives, return    │───┘              │
│  │    header to buffer and loop back  │                  │
│  └────────────┬───────────────────────┘                  │
│               │ COMMAND_START                             │
│               ▼                                          │
│  ┌────────────────────────────────────┐                  │
│  │         ACTIVE STATE               │                  │
│  │  • Clear TASK_IDLE, COMMAND_START  │                  │
│  │  • Drain stale playback progress   │                  │
│  │  • Set TASK_RUNNING                │                  │
│  │  • Pin the current connection      │                  │
│  │  • Enqueue SYNCHRONIZED state      │                  │
│  │  • Decode initial codec header     │                  │
│  │  • Run inner state machine loop    │                  │
│  └────────────┬───────────────────────┘                  │
│               │ STOP/END/CLEAR                           │
│               ▼                                          │
│  ┌────────────────────────────────────┐                  │
│  │  Release the pin, then return the  │──────→ loop back │
│  │  borrowed ring buffer entry        │                  │
│  └────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────┘
```

### Stream Connection Pin

Every timestamp the sync task converts belongs to one connection's `SendspinTimeFilter`. The task resolves that connection once, as the stream goes active, and holds it as a `std::shared_ptr` (`SyncTask::stream_connection_`, resolved through `ConnectionManager::current_shared()`, which the client hands the task at role registration) until the stream ends. The per-chunk conversion then dereferences the pin and takes only the filter's own `state_mutex_`; it never touches `ConnectionManager::conn_ptr_mutex_`, which is a lifetime lock and not a time-sync one. The pin is sync-thread-only state, so it needs no lock of its own.

The pin stays correct for the whole stream because a connection's filter is created once in `SendspinConnection::init_time_filter()` and never replaced, and because the admitted slot cannot be handed to a different server while a stream runs: `ConnectionManager::drop_connection()` calls `cleanup_connection_state()` on the outgoing connection, which ends the player's stream, before `promote_or_arbitrate_nursery_entry()` installs the successor. An in-band re-handshake keeps the same `SendspinConnection` object, so it does not disturb the pin either.

If no connection is current when the stream goes active, the pin is null. That reads as "not time synced" for the rest of that stream, the same as a connectionless `get_client_time()`: LOAD_CHUNK waits and no chunk is decoded. The next stream resolves the pin again.

The pin regularly outlives `drop_connection()`: the manager queues and flushes its own release in the same tick, while the sync task learns the stream ended only when it next reaches the top of its inner loop, so the pin is normally the last reference. It is not the one that destroys the connection. `~SendspinConnection` joins the transport thread, which would put the transport teardown on a stack sized for Opus decode and stall playback for the length of the join (the transport thread can be parked on encoded-ring space for up to `HEADER_SEND_TIMEOUT_MS`). The task therefore hands the reference back through `ConnectionManager::release_from_role_thread()`, which queues it as an ordinary goodbye-less `DeferredRelease`, and `flush_deferred_releases()` destroys it on the main loop. That is the one deferred-release push site that does not flush on its own thread; `loop()` flushes twice per tick, so the hand-over outlives its stream by at most one tick.

Two orderings close the ends of that path. `SendspinClient::stop()` runs `close_transports()` (which sweeps the manager's queue) before `stop_role_threads()`, so a pin handed over during the join lands after the sweep; `stop()` calls `flush_deferred_releases()` once more after the join, which is the last flush of the run. In `~SendspinClient` the roles are destroyed before the manager (`player_.reset()` joins the sync task, `connection_manager_.reset()` comes after it), so no hand-over can arrive at a dead manager, and `~ConnectionManager` destroys whatever the join queued, on the main thread and outside its locks.

The **WAIT FOR CLIENT ACK** step is critical. Without it, the sync task could race from IDLE back to ACTIVE so fast that the main loop never observes TASK_IDLE, and the `awaiting_sync_idle_events` mechanism in `PlayerRole::drain_events()` would deadlock waiting for an idle transition that already passed.

### Inner State Machine (active stream)

```api
INITIAL_SYNC ──→ LOAD_CHUNK ──→ SYNCHRONIZE_AUDIO ──→ TRANSFER_AUDIO
     │                ▲               │                       │
     │                └───────────────┴───────────────────────┘
     │                        (cycle per chunk)
     └──→ LOAD_CHUNK (once first playback progress callback confirms frames were consumed)
```

**INITIAL_SYNC**: Fills the audio pipeline with silence to prime DMA buffers. Sleeps briefly after sending to let the audio stack start consuming. Once the first playback-progress callback confirms frames were consumed, it queues `extra_startup_silence_ms` of additional silence (see `PlayerRoleConfig`) and drains it before advancing to LOAD_CHUNK. This extra lead gives the decode pipeline slack to stay ahead of the sink at stream start, preventing the initial-playback stutter caused by the decoder briefly falling behind.

**LOAD_CHUNK**: Reads the next encoded chunk from the ring buffer. Waits for time sync (on the pinned connection's filter) if not yet available. Decodes audio via FLAC/Opus/PCM decoder. On a ring-buffer underflow (no chunk ready) **while still aligning** (startup or post-seek), it feeds silence toward the sink to keep the DAC fed while the decode pipeline catches up, instead of letting it run dry; SYNCHRONIZE_AUDIO then re-aligns the next chunk against wherever the silence carried us. In steady state it does **not** fill - an empty buffer there means the stream is winding down, and stuffing silence would pile up in the sink and delay a rapid restart (a genuine underrun instead surfaces as an error in SYNCHRONIZE_AUDIO).

**SYNCHRONIZE_AUDIO**: Computes the sync error:

```cpp
error = decoded_timestamp - new_audio_client_playtime
```

Where `decoded_timestamp` is the server timestamp converted to client time (via Kalman filter) minus static and fixed delays, and `new_audio_client_playtime` is the predicted time that the next audio will actually play.

| Error Range | Action |
|-------------|--------|
| > +5000 us (or +500 us settling) | **Hard sync ahead**: insert silence frames to fill the gap |
| < -5000 us (or -500 us settling) | **Hard sync behind**: drop the decoded chunk |
| +100 to +5000 us | **Soft sync**: insert one interpolated frame near the end (average of last two) |
| -100 to -5000 us | **Soft sync**: remove last frame (blend into second-to-last) |
| -100 to +100 us | **Dead zone**: pass audio through unmodified |

Hard sync sets a flag that switches to a tighter 500 us settle threshold until the error is small enough to exit hard sync mode.

**TRANSFER_AUDIO**: Writes PCM data to the audio sink via `on_audio_write`. If silence was inserted (hard sync ahead), transfers silence first, then re-enters SYNCHRONIZE_AUDIO for the held-back decoded data.

### Playback Progress Tracking

The audio output hardware reports consumed frames via `notify_audio_played()` → `playback_progress_slot_` (a `ShadowSlot` whose merge strategy sums `frames_played` across unread updates and keeps the latest `finish_timestamp`). The sync task takes the accumulated value on every inner loop iteration to maintain an accurate `new_audio_client_playtime` estimate:

```cpp
new_audio_client_playtime = last_finish_timestamp + remaining_buffered_frames_as_microseconds
```

This feedback loop is what makes the sync error calculation accurate.

## Time Synchronization

### Burst Strategy (`src/time_burst.h`)

Time sync uses a burst-based NTP-style protocol:

1. Send 8 time request messages per burst (each with a 10-second response timeout).
2. Wait 10 seconds between bursts.
3. Select the measurement with the lowest round-trip time (lowest `max_error`).
4. Feed the best measurement into the Kalman filter.

High-performance networking (e.g., disabling WiFi power saving) is acquired for the duration of a burst and released when complete.

### Kalman Filter (`src/time_filter.h`)

Two-dimensional state vector: `[offset, drift]`.

- First measurement establishes the offset baseline.
- Second measurement estimates initial drift from finite differences.
- Subsequent measurements: predict offset forward by `drift * dt`, then correct using the new measurement.
- Adaptive forgetting: if the residual exceeds `3.0 * max_error`, the covariance is inflated by a forgetting factor (2.0) to recover from step changes.
- Drift compensation is only enabled after 100 samples and only when drift significance exceeds its noise floor.

The filter is protected by `state_mutex_` so that `compute_client_time()` can be called from the sync task thread while `update()` runs from the main loop thread.

## Noise Encryption

Every connection is encrypted with Noise KKpsk2. The C++ library is always the Noise responder; the Python server is always the initiator.

### Transport Stack (`src/noise_transport.h`, `src/noise_transport.cpp`)

Once transport is active, all application-level messages travel through `NoiseTransport`. The wire framing is:

```api
[type byte][app payload] --> Noise encrypt --> [ciphertext]   (binary WebSocket frame)
[ciphertext] (binary WebSocket frame) --> Noise decrypt --> [type byte][app payload]
```

The ciphertext is the body of a binary WebSocket frame; there is no application-level length prefix (the WebSocket layer delimits frames). The first byte of the decrypted plaintext is a type tag (`src/crypto/constants.h`):

| Type byte | Constant | Meaning |
|-----------|----------|---------|
| 0 | `MSG_TYPE_JSON_BODY` | JSON message (UTF-8, no null terminator) |
| 1 | `MSG_TYPE_FRAGMENT` | One fragment of a larger message |
| 2-3 | -- | Reserved by messaging.md "Binary Message ID Structure"; received ones are ignored |
| other | -- | Binary role message, dispatched in `process_binary_message()`: the visualizer's expanded allocation (IDs 16-23, of which 16-20 are defined) is matched by range first, and the player and artwork IDs are then decoded with `get_binary_role()`/`get_binary_slot()` |

Type 1 implements app-level fragmentation for payloads too large for a single Noise transport frame (`MAX_TRANSPORT_PLAINTEXT`, 65519 bytes, of which 65518 are payload). Per messaging.md "Fragmentation", the first fragment carries `[1][flags][orig_type][chunk]` and every later one carries `[1][flags][chunk]`, where `flags` bit 1 marks the first fragment, bit 0 the last, and bits 2-7 are reserved and zero. `NoiseTransport::accept_plaintext()` reassembles them and returns the completed `[orig_type][data...]` message when a fragment with bit 0 set arrives; `SendspinConnection` dispatches it from there. The reassembly buffer (`reasm_buf_`, a `PlatformBuffer`) accumulates the final message shape directly rather than staging a separate copy, grows geometrically as fragments arrive, retains its capacity across messages (capped at `MAX_REASSEMBLED_MESSAGE_BYTES`, 1 MiB, or at `MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES`, 16 KiB, until the connection holds the admitted slot: what precedes admission is hello, activate, pairing JSON and the role JSON held for replay under `MAX_HELD_BYTES` (8 KiB in total), none of which approaches the tighter cap, and every peer on the network can reach that path with the Sentinel PSK alone), and is placed per `SendspinClientConfig::noise_buffer_location` (PSRAM-preferring by default on ESP). The ~64 KB per-frame fragmentation buffer used when *sending* a large payload is placed the same way.

Only one fragmented message is in flight per direction, so the send path holds the Noise session lock across every frame of one message and the receive path keeps a single reassembly buffer plus the in-flight `orig_type`. A message whose `orig_type` is a reserved ID, or that outgrows the reassembly cap, is discarded without buffering while its sequence is still tracked to the last fragment. The five malformed sequences messaging.md enumerates (a first fragment while one is in flight, a non-first fragment with none in flight, a non-fragment message while one is in flight, a nonzero reserved flag bit, and an `orig_type` of `1`) set `CompleteMessage::malformed`, and `SendspinConnection` closes the connection on it.

### Cleartext Handshake (Initial Exchange)

Before Noise transport is active, a short cleartext exchange establishes the prologue and carries the cipher suite. All frames in this phase are WebSocket text (JSON).

```api
Client -> Server: client/init   (client_id, version, cipher suite)
Server -> Client: server/init   (server_id, cipher suite selection)
Server -> Client: noise/handshake msg1 (Noise KKpsk2 initiator message)
Client -> Server: noise/handshake msg2 (Noise KKpsk2 responder message)
-- transport active from here --
Server -> Client: server/hello  (encrypted, server name)
Client -> Server: client/hello  (encrypted, device info, pair_methods)
Server -> Client: server/activate (encrypted, activities, active_roles)
```

The prologue fed into the Noise handshake is `bytes(client/init) || bytes(server/init)`. `ConnectionManager` sends `client/init` as soon as the WebSocket upgrade completes (`init_noise_handshake()` followed by `send_noise_client_init()`), for both inbound (`on_new_connection`) and outbound (the connected-event scan in `loop()`, once `connect_to()`'s upgrade completes) connections. The client always proposes `NOISE_SUITE_CHACHAPOLY` (`Noise_KKpsk2_25519_ChaChaPoly_SHA256`, see `src/crypto/constants.h`); it builds its Noise session from that same proposal and never reads `server/init`'s suite field back, so there is nothing to select between.

### PSK Resolution (`src/record_store.cpp`)

The Noise KKpsk2 handshake requires a pre-shared key (PSK). The server embeds a `psk_id` and a `psk_category` in msg1; `RecordStore::resolve_by_psk_id()` matches the `psk_id` against the candidates of that one category (connection.md "Pre-Shared Key"), so the same `psk_id` held under another category is a lookup miss rather than a match. The categories, and their wire codes:

1. `lt`: long-term record stored after a successful pairing. `PskCategory::LONG_TERM`. Every such record is bound to the `server_id` it was minted for, and `handle_msg1()` rejects the match when the peer is a different server (connection.md "Pre-Shared Key").
2. `pr`: accepted Pairing PSK (distributed out-of-band). `PskCategory::PAIRING`. Generated by `RecordStore`'s constructor when none is persisted (`pairing_psk` is the client-mandatory pairing method, so it must always have a key behind it) and surfaced to the operator by `SendspinClient::pairing_token()`.
3. `sn`: Sentinel PSK, the published well-known key, so it authenticates nothing on its own. `PskCategory::SENTINEL`.

On a lookup miss in the **initial** handshake the client completes msg2 with the Sentinel PSK instead of failing (connection.md "Sentinel Fallback"), and the connection proceeds as an ordinary Sentinel-keyed one: the server, which holds the PSK it referenced, cannot read that msg2 and so receives an authenticated credential-mismatch signal it can offer its operator. The fallback is only there. A miss during a re-handshake fails the handshake, and so does a failed stored-`server_id` post-match check, which is a misbinding rather than a miss.

A msg1 payload whose `psk_category` is missing or outside those three codes is malformed, which the connection.md "Failure Handling" makes a silent failure: the handshake aborts and the connection closes with nothing sent. A cleartext `server/error`, which a server sends in place of `server/init` when it cannot accept our `client/init`, aborts the same way; its `reason` is unauthenticated, so the client only records it (`NoiseHandshake::server_error_reason()`) and names it in the log line it closes with.

The resolved `PskCategory` is stored on the connection and determines the `ConnectionTrust` value delivered to `SendspinClientListener::on_trust_changed`.

### Deferred PSK Binding (`src/noise_handshake.cpp`)

In KKpsk2 the PSK is mixed only into msg2, so msg1 can be read with the static keys alone (KK's `es`/`ss` tokens). The client does not know which PSK applies until it reads the `psk_id` carried in msg1's payload, so it cannot supply the real PSK up front. noise-c allows `noise_handshakestate_set_pre_shared_key()` to be called at any point before the "psk" token is processed, so a single responder session handles the whole exchange:

1. Build a responder with no PSK bound and read msg1 through it. This succeeds and exposes the `psk_id` and `psk_category` in the decrypted payload.
2. Resolve the `psk_id`, within the declared category, to the real PSK via `RecordStore` (or, on a miss in the initial handshake, take the Sentinel PSK) and bind it onto the SAME responder (`NoiseSession::set_psk`).
3. Write msg2 and split into transport keys.

The in-band re-handshake below uses the same deferred-binding sequence.

### In-Band Re-Handshake (Key Rotation)

After transport is active, the server may initiate a new KKpsk2 handshake to rotate session keys or move an admitted connection onto a different PSK (e.g. the post-pairing rekey below). The server sends a `noise/handshake` JSON envelope (decrypted through the active transport). `SendspinConnection::handle_noise_rehandshake()`:

1. Runs the deferred-PSK-binding msg1 read with the re-handshake PSK.
2. Builds msg2 and encrypts it under the old session.
3. Atomically swaps the active `NoiseSession` under a per-connection mutex (`session_mutex_` in `NoiseTransport`).
4. Resets `first_activate_received_`, so the connection goes momentarily non-operational while it waits for the `server/activate` that connection.md "Re-handshake" makes the server's first message under the new keys. Neither `server/hello` nor `client/hello` is re-sent, so the hello flags carry over untouched and that activation alone restores the connection. The re-proving watchdog (`REPROVE_TIMEOUT_US`, `scan_reprove_watchdog()`) drops a connection whose server rekeys and then never activates it.

The client starts no application message between Noise message 1 and that activation, as connection.md "Re-handshake" requires. `client/time` gates on `is_operational()`; `client/state`, `client/leave`, role-originated sends through `send_text()` and the pairing attempt-timeout `pair/abort` in `scan_pairing_attempt_timeout()` all gate on `first_activate_received()`. A held attempt-timeout abort fires on the tick after the activation arrives, or never, because `scan_reprove_watchdog()` closed the connection first; that watchdog closes without a goodbye for the same reason.

This is the mechanism that upgrades a Pairing-PSK connection to a long-term PSK immediately after pairing finalizes.

### Pairing Flow (Pairing-PSK Method)

When the server's `server/activate` declares a `pairing` activity with a `pairing` object naming `method=pairing_psk`, `promote_or_arbitrate_nursery_entry()` (or the subsequent-activate branch in the main activate-event loop, for an already-operational connection) calls `handle_enter_pairing()`. pairing.md "Entering and leaving pairing" runs pairing alongside playback, so nothing is quiesced for it: streams stay open, active roles keep driving their own traffic, and time sync keeps running. An activation that declares `playback` as well goes operational first and then enters pairing, because going operational is what clears any stale pairing state; one that declares pairing alone is not announced as operational until the attempt finishes and the post-finalize re-handshake activates the connection again.

```api
Server -> Client: server/activate (activities=["pairing"], method=pairing_psk)
-- ConnectionManager::handle_enter_pairing (main loop) --
Client -> Server: client/pair-finalize (long-term PSK, base64url-encoded)
-- server/pair-finalize received on network thread; record committed to RAM immediately --
Client stores the long-term pairing record in RecordStore (thread-safe mutator; the
durable provider write is deferred to the next loop() tick)
Server -> Client: noise/handshake msg1 (re-keying onto the new long-term PSK)
Client -> Server: noise/handshake msg2
-- transport upgraded to long-term PSK --
Server -> Client: server/activate (normal operational flow)
```

The long-term record is committed to RAM on the network thread (synchronously, inside `SendspinClient::dispatch_json_message()`'s `SERVER_PAIR_FINALIZE` handler) so the immediately following `noise/handshake` msg1 can resolve the new `psk_id` from the record store. That handler calls `RecordStore::store_record_superseding()`, which retires any prior record for the same `server_id` in the same locked section that inserts the new one and never touches the persistence provider (the provider contract is main-loop-only). The durable write is staged through the client's records-dirty `InboxSlot` (`INBOX_TOPIC_RECORDS`) and flushed by `SendspinClient::loop()` via `RecordStore::persist_records()`; the destructor flushes a still-pending write so an orderly shutdown does not lose the pairing. None of the store's persisting paths holds `mutex_` across that write: they mutate `records_` and encode the whole array under the lock, then save the encoded blob after dropping it, so a network-thread `resolve_by_psk_id()` (which takes the same mutex for every handshake, and is adjacent to this flush by construction: the server re-handshakes onto the new PSK right after the ack) never waits out an NVS commit. The two halves do not have to be atomic because all three persisting paths are main-loop-only, so their encode/save pairs are serialized by thread confinement; a network-thread `store_record_superseding()` landing between them only means the saved blob predates that insert, which the flush the insert schedules then repairs. `RecordStoreConcurrency::ResolveRunsWhileARecordsWriteIsInFlight` pins it.

- **Success**: `ConnectionManager::schedule_pairing_succeeded()` posts the server_id through the same `pending_*_events_` / `has_pending_events_` idiom every other cross-thread mutation in `ConnectionManager` uses; `loop()` drains it and calls `SendspinClient::note_pairing_succeeded()`, which queues the actual `on_pairing_succeeded` listener callback for `SendspinClient::loop()` to fire unlocked. The handler writes the records-dirty slot before scheduling the note, so the tick that fires `on_pairing_succeeded` has already attempted the durable write. `conn->note_pairing_finalize_ack()` re-arms the 30 s provisional timeout so the connection is still bounded if the server never follows up with the re-handshake.
- **Capacity**: a pairing never fails for lack of record storage (pairing.md "Pairing Records"), so a net-new record arriving at a full store evicts one. `ConnectionManager::open_connection_psk_ids()` hands `store_record_superseding()` the `psk_id` of every open connection, provisional or admitted, and the victim is the least recently used record among the rest: `records_` is ordered least-recently-used first, because `note_record_used()` (called on the first activate of every long-term session) moves the touched record to the back. That reorder is RAM-only; only the first flip of the durable `used` flag is persisted, so the order is rebuilt from use after a reboot rather than restored. The connection budget keeps a victim available (the admitted connection plus a full nursery is `MAX_OPEN_CONNECTIONS`, which a static assertion holds below `RecordStore::MIN_MAX_RECORDS`), so the remaining rejection path (nothing evictable) is unreachable. Were it ever reached, the record would not be retained and `schedule_pairing_succeeded()` would be skipped: the server rekeys onto that PSK regardless (it already acked pair-finalize), the client cannot resolve the `psk_id`, and the re-handshake drops the connection.
- **Persistence failure**: a provider that rejects the deferred `persist_records()` write does not fail the pairing. The RAM-committed record stays authoritative for the current boot (the re-handshake succeeds, `on_pairing_succeeded` fires) and a warning is logged that the pairing will not survive a reboot; nothing is retried, since a provider that cannot write will not start writing because it is asked again.

If the server sends `pair/abort` at any point, `ConnectionManager::handle_pair_abort()` runs on the main loop and fires `on_pairing_failed` (only reason `concurrent_attempt` also closes the connection). The two pairing-code methods (CPace PAKE) follow a similar main-loop-only state-machine shape but are driven by their own deferred event types (`ServerPairingMessageEvent`, the pairing-window confirm and cancel flags); see `handle_pairing_message()` / `local_abort_pairing()` / `start_pairing_attempt()` in `connection_manager.cpp`.

### Pairing-code specifics

The emission format arrives in the activation's `pairing` object and is checked against the advertised `formats` there (`pair/abort` reason `method_not_supported` for one that was never offered). `server/pair-init` carries `nonce_A` in the attempt's first round only.

Each round runs its own CPace exchange under `sid = "sendspin-pair-pake-v1" || h || pairing_index || round`, both counters big-endian `uint32`, the round starting at 1 (pairing.md "PAKE"). On a `server_kc` that does not verify, the dynamic flow sends `client/pair-retry` and waits for the next `server/pair-init`, keeping the emitted code and the running attempt timeout; `ConnectionManager::pairing_rounds_since_verified_kc_` counts the rounds and the twentieth failure aborts with `pairing_code_mismatch` instead (pairing.md "Rounds"). The static flow runs one round and never retries.

A gesture-gated attempt (every `static_pairing_code` attempt, and a dynamic one held back by a standing round limit) answers the activation with `client/pair-pending` and waits, without an attempt timeout, for a pairing window. The window is standing state on `ConnectionManager` with a 5-minute lifetime, opened by `confirm_pairing_window()` (which also clears the round count, being the deliberate operator action pairing.md "Rounds" asks for). It binds to the connection carrying its first attempt and admits only that connection afterwards, and closes on a completed pairing, on its fifth failed attempt (an attempt that ends on a `server_kc` mismatch; a dynamic retry within one attempt does not count), on the drop of that connection, on `cancel_pairing_window()`, or on expiry (pairing.md "Pairing Window"). "Completed" is the `server/pair-finalize` ack, not the `client/pair-confirm` before it: a `server/activate` arriving in place of that ack persists nothing, so the window closes where the record is stored, in the `pairing_succeeded` drain.

### PSK Admission (trust gating)

The `server/activate` handler in `ConnectionManager::drain_lifecycle_events()` (called from `loop()`) evaluates each activate against `RecordStore::unpaired_access_enabled()` and the connection's resolved `PskCategory`, via the pure functions in `src/admission.h`:

The allowed sets are the table in messaging.md "server/activate":

- `LONG_TERM`: the empty set or `{playback}`. A paired server has no pairing activity to declare.
- `PAIRING` and `SENTINEL`: the empty set and `{pairing}` always; `{playback}` and `{playback, pairing}` only when `unpaired_access_enabled` is true.

Only a *playback-capable* connection may carry a non-empty `active_roles`: one whose activities extended with `playback` are also an allowed set. That holds even while `playback` is not currently declared, so an idle long-term connection keeps its roles, and a pairing-PSK connection holds them only under unpaired access.

`unpaired_access_enabled` is persisted in `SendspinPairingConfig`. Its value on a device that has never persisted a pairing config comes from `SendspinClientConfig::initial_unpaired_access_enabled`, which the first-boot seed then persists. `RecordStore`'s constructor applies that seed only when `!loaded_config && !previously_provisioned`, where `previously_provisioned` means any surviving record or Pairing PSK. `!loaded_config` alone is not evidence of a first boot and gating on it would fail open: the provider interface cannot distinguish "never stored" from "stored but unreadable", so a device whose config blob was lost or corrupted while its records survived would otherwise re-seed unpaired access ON. Any surviving provisioned material vetoes the seed; a store that lost everything is indistinguishable from a factory-fresh device, so the seed does apply there.

A rejected activate closes the connection with `SendspinGoodbyeReason::PAIRING_REQUIRED` when it would have been admissible had unpaired access been enabled (an unpaired connection requesting `{playback}` while unpaired access is off), and `SendspinGoodbyeReason::UNAUTHORIZED` otherwise. That order is the one messaging.md "server/activate" gives; a long-term connection declaring `pairing` never reaches the first rule, because no setting would admit it.

Multi-server admission arbitration (deciding whether an incoming connection displaces the current one) ranks each side by its highest activity (`activity_rank()` in `admission.h`: playback=2, pairing=1, none=0, so a connection declaring both ranks as playback) and applies `should_admit_connection()`'s rules, described in [Handshake and Handoff](#handshake-and-handoff) above.

## Connection Lifecycle

### Connection Management (`src/connection_manager.cpp`)

The `ConnectionManager` maintains one established slot plus a bounded nursery of unproven connections:

| Slot | Purpose |
|------|---------|
| `current_connection_` | Active connection receiving messages; holds only connections that completed the hello handshake |
| `nursery_` | Unproven connections (inbound or outbound) awaiting establishment, bounded by `NURSERY_CAPACITY` inbound + 1 outbound |

All are `std::shared_ptr<SendspinConnection>`, and on the ESP server path they are observers rather than authoritative owners; the authoritative owner of a `SendspinServerConnection` is the httpd session itself (see [Server connection ownership (ESP)](#server-connection-ownership-esp)). On the host (IXWebSocket) client path the `shared_ptr` in these slots is the only owner.

### Handshake and Handoff

1. A new connection (outbound or inbound) enters the nursery. Inbound connections are delivered by the platform ws_server only after their WebSocket upgrade is observed.
2. The connection first runs the cleartext Noise handshake (`client/init` / `server/init` / `noise/handshake` msg1 / msg2) on the network thread before any application message is processed; see [Noise Encryption](#noise-encryption) below. No `client/hello` is sent until Noise transport is active.
3. The connection sends `client/hello` (over the encrypted transport, once Noise is active). Retry with exponential backoff (100 ms base, 3 attempts). Each managed connection has its own retry entry in `ConnectionManager::hello_retries_`, so a handoff candidate arriving mid-handshake cannot clobber another connection's pending hello.
4. The handshake state lives on the connection as two atomic flags: `client_hello_sent_` (set by the hello send-completion callback) and `server_hello_received_` (set when `server/hello` is processed on the network thread, after the server info fields it publishes). `is_handshake_complete()` (`client_hello_sent_ && server_hello_received_`) therefore already implies the Noise handshake completed, since `client/hello` cannot be sent before transport is active.
5. Establishment is level-triggered: each `loop()` tick, the promotion scan promotes any nursery connection whose `is_operational()` (`is_handshake_complete() && first_activate_received()`) is true, so it does not matter whether the hello handshake or the first `server/activate` completes first. `server/activate` trust enforcement (admissibility against the connection's PSK category) runs as soon as the activate event is processed, independent of promotion timing; a rejected activate closes the connection immediately. Admission arbitration against an incumbent (rank by highest activity: playback > pairing > none; equal non-zero rank admits the incoming connection; an in-flight pairing is not displaced by an incoming pairing or playback connection) happens inside the promotion scan itself. See [PSK Admission (trust gating)](#psk-admission-trust-gating) below.
6. Handoff executes: disable the loser's message dispatch -> cleanup client state (winner only gets `on_handshake_complete`) -> send goodbye to the rejected connection via the deferred-release queue.

Role-bound traffic (`server/state`, `server/command`, `stream/*`, `group/update`) is dispatched only for the admitted connection (`requires_admitted_connection()` in `client.cpp`). A server begins sending it as soon as it has sent its `server/activate`, while step 5 above resolves that activate a `loop()` tick later, so the messages in that window are held on the connection (`SendspinConnection::hold_pre_admission_message()`, bounded to 8 messages and 8 KB in one lazily allocated `PlatformBuffer`; the two budgets and their derivation are on the `MAX_HELD_MESSAGES` / `MAX_HELD_BYTES` declarations) and replayed in arrival order by `SendspinClient::admit_connection()` when the connection takes the current slot. The replay and the `admitted_` store happen under one hold of `json_processing_mutex_`, which is the same mutex the network thread's dispatch path holds, so nothing can slip between the last replayed message and the flag, and `admitted_` is stored last so the binary path (which does not take that mutex) starts feeding the roles only after the replay has finished. Only traffic that follows an activate is held: a peer that drives roles without activating anything is dropped where it always was, and a connection that never wins admission replays nothing.

The replay runs with no manager lock held. `set_current_connection()` only stages the connection in `pending_admission_`; `ConnectionManager::flush_pending_admission()`, called from `loop()` right after the lifecycle block drops `conn_ptr_mutex_`, is what calls `admit_connection()`. That keeps the client's single lock order (`docs/conventions.md`, "Threading and cross-thread state"): `json_processing_mutex_` outside `conn_ptr_mutex_`, which the live receive path requires, because the `server/pair-finalize` handler runs under the JSON lock and asks the manager for the open connections' psk_ids (`open_connection_psk_ids()`) before handing them to `RecordStore::store_record_superseding()`. Admitting under `conn_ptr_mutex_` would close that cycle: the main loop would wait for the JSON lock while a network thread finishing a pairing waited for `conn_ptr_mutex_`. The deferral is the same shape `flush_deferred_releases()` uses for work that must not run under the manager lock, and `EncryptedLifecycle::PairFinalizeDoesNotDeadlockAgainstAnAdmission` drives both halves at once so a regression hangs the suite (named by the watchdog in `tests/main.cpp`) rather than a device.

Persistence writes the lifecycle handlers decide on are deferred the same way, for a different reason. `RecordStore::note_record_used()`'s durable half (first activate on a long-term record), the records-blob write a `server/unpair` revocation owes, and the last-played write are provider calls, which on ESP are NVS commits of tens of milliseconds, and the role drains resolve the current connection through `current_shared()`. The handlers therefore only stage which write is owed, as a `PendingRecordOp`, and `flush_pending_record_ops()` performs them in staging order once the lifecycle block drops the lock, ahead of the admission and goodbye flushes so the store is settled on flash before a session is told to leave. Two of the three cases split rather than defer wholesale, because their RAM half has to take effect inside the locked section: `SendspinClient::note_last_played_server()` updates `last_played_server_id_` under the lock, because handoff arbitration reads it later in the same block, and `RecordStore::note_record_removed()` erases the revoked record under the lock, because a re-handshake on that psk_id resolves against the store on the network thread and must miss it from that instant. Only the durable halves, `write_last_played_server()` and a `RecordStore::persist_records()` flush of the array, are staged. Several ops touching the records array in one tick share one blob write: the flush applies the RAM half of each op that still owes one, in staging order, and then calls `RecordStore::persist_records()` once, since every one of them rewrites the whole array anyway and each write is an NVS erase cycle. The last-played value is a different key and keeps its own write. `flush_pending_record_ops()` is called unconditionally, like the admission and release flushes beside it, so it is no longer coupled to that block's gate, and `ConnectionManager::stop()` calls it once more so the last tick's staging cannot outlive the run; a staging site added after it within a tick would still need a second call, the way `flush_deferred_releases()` has one. It early-returns on a `pending_record_ops_size_` hint atomic, so a tick with nothing staged pays one acquire-load and no lock. `EncryptedLifecycle::ARecordWriteDoesNotHoldTheManagerLock` parks a provider inside the flush's `RecordStore::persist_records()` and requires a `current_shared()` caller to return meanwhile.

A handler reachable from the replay may therefore reach the current-connection accessors without wedging, but it still must not: the receive-path rule (`docs/conventions.md`) keeps replayed handlers off the current-connection accessors and off the listener, so the replay costs the same as the live path and fires no listener from inside `loop()`'s connection block.

Binary messages arriving in the same window are still dropped: the hold covers the JSON half only. A player resynchronizes from the next chunk and artwork re-sends on its next frame, so the cost is bounded, but a stream's first chunks can be lost this way.

### Disconnection and Cleanup

When a connection is lost (`on_connection_lost`):

```api
1. conn->disable_message_dispatch()      ← atomic, immediate on network thread
2. client_->cleanup_connection_state()  ← stop time sync, reset the inbox event ring and every
                                           role's slots, signal stream end
3. Queue the connection on deferred_releases_ (released outside the manager lock)
4. The current slot stays empty; the next promotion scan fills it from the nursery
```

`disable_message_dispatch()` is the first step because it's an atomic flag that the network thread checks before invoking any callback. This prevents stale messages from a dead connection from racing into freshly-reset role queues.

### Role Removal on a Later Activation

`server/activate` may be re-sent at any time to move the active role set. `ConnectionManager::process_activate_event()` copies the connection's roles before `apply_server_activate()` writes the new ones, and for the admitted connection it hands both sets to `SendspinClient::apply_role_removals()`. A role is *removed* when the versioned name this library implements (`player@v1`, `metadata@v1`, ...) was in the old set and is not in the new one, which covers an explicit drop, the implicit clearing of the roles when an activation leaves the connection no longer playback-capable, and messaging.md "server/activate"'s "replacement of an active role version".

Each removed role runs its own `cleanup()`, the same teardown a lost connection runs: the player ends the stream and returns the sync task to idle, the artwork and visualizer roles drop their in-flight transfers and buffered frames and clear their channels, and the metadata, color and controller roles drop their current state and any held scheduled update. That is exactly what messaging.md "server/activate" asks for on removal ("stop its remaining output, clear its buffers ... immediately discard the current state and any pending scheduled update"). The player applies no ducking or other temporary output effect of its own, so the clause about releasing them is satisfied by the stream ending; the consumer's own output is stopped through `on_stream_end()`.

Two things differ from the connection-loss path, both because the connection survives:

- The inbox event ring is **not** reset first. `cleanup_connection_state()` wipes it because every role is going down together; here the roles that stay active must keep their queued lifecycle events, so the removed role's synthetic `STREAM_END`/`CLEARED` is simply appended behind whatever is already queued for it and delivered in order. What the ring reset would otherwise have prevented is handled per role instead: each stream role keeps a `cleanup_generation` that `cleanup()` bumps and `enqueue_stream_event()` stamps onto every event it queues, and the ring drain in `loop()` discards an event whose stamp no longer matches (`event_is_current()` in `inbox.h`). This matters because `connection_manager_->loop()` runs ahead of the drain in the same tick: a `stream/start` the network thread queued before the activate would otherwise be dispatched after the teardown, firing `on_stream_start()` for a removed role and re-arming the sync task with the codec header already in its ring. The teardown's own `STREAM_END` carries the new generation, so it still delivers.
- The role can be added back. A later activation that re-adds it publishes a `client/state` carrying its object again (the `roles_changed` publish in the same function), which is what lets the server start its stream a second time; the role itself comes back through its ordinary start path.

Callbacks follow the same rule as every other teardown: `apply_role_removals()` runs under `conn_ptr_mutex_`, so it queues the clear and stream-end events on the inbox and `loop()` fires the listener after the manager returns.

### Role Traffic for an Inactive Role

The teardown would be a one-shot if the next message could put the role back in service, so the receive path is gated too. Every role dispatch point in `client.cpp` (the `server/state` objects, `server/command`, `stream/start`, `stream/end`, `stream/clear`, and the binary IDs) checks `SendspinConnection::is_role_active(SendspinRole)` and skips the role's handling when the role is not active. The message is still *recognized*: it is parsed and validated as usual, nothing is closed for it, and only the role's own handling is skipped, which is what messaging.md "Communication" asks for ("An ID the receiver implements is still recognized when its role is inactive", together with "the validation, direction, and sequencing rules for recognized messages still apply"). The artwork binary path is the one dispatch that is deliberately not gated: `ArtworkRole::Impl::handle_binary()` runs the malformed-*message* checks that close the connection before its own stream gate, so handing the message to the role is what keeps those checks running while the payload is dropped.

The gate reads an atomic mask on the connection rather than `active_roles_`, because it runs on the network thread while the main loop applies activations. The mask is built with the same exact-versioned-name test role removal uses, so the two can never disagree. The outbound side asks the same question of the same mask: `SendspinClient::send_text()` resolves the role family its caller names to the version this library implements (`role_for_family()`) and gates on `is_role_active(SendspinRole)`, as do the per-role objects in `publish_client_state()`. A server that activates a version this client never offered therefore silences the role in both directions, rather than tearing it down while still reporting it. It is updated twice: `note_activated_roles()` ORs in a newly received activation's roles on the network thread, so traffic the server sends immediately behind an activation that *adds* a role is accepted without waiting for the client's next tick (messaging.md "server/state" has the server send a re-added role's state promptly), and `apply_server_activate()` stores the exact mask on the main loop, which is where *removals* take effect - the same step that tears the removed roles down.

### Client Start and Stop

`SendspinClient::start()` creates the `RecordStore` and loads or generates the static X25519 identity (returning false if the identity cannot be produced, which is why `connect_to()` refuses before a successful `start()`), loads persisted state, starts the threaded roles (player sync task, visualizer drain, artwork decode; a failure part-way stops the ones that did start), and calls `ConnectionManager::start()`, which opens admission (`accepting_`) and creates the `SendspinWsServer` on first use. The server itself is started by the manager's `loop()` once the network provider reports ready, so `is_started()` means "running", not "listening".

`SendspinClient::stop()` is synchronous and ordered so that every producer is gone before any state is reset. The client's lifecycle is one atomic `lifecycle_` field (`STOPPED`, `RUNNING`, `STOPPING`); `is_started()` reads it from any thread.

```api
0. lifecycle_ = STOPPING (is_started() reads false; loop() is a no-op; start() is refused and
   stop()/connect_to()/disconnect() are ignored from here on, so a callback fired below cannot
   recurse into the teardown)
1. VisualizerRole/ArtworkRole::Impl::signal_stop(): set COMMAND_STOP and wake, no join, so a
   slow on_image_decode() or a parked drain exits while the transports close. The player is
   not signalled yet: a network thread blocked on its ring (write_audio_chunk) needs the sync
   task alive until the network threads are gone
2. ConnectionManager::stop(SHUTDOWN)
   ├─ Under conn_ptr_mutex_: accepting_ = false; snapshot each connection's pairing-code / window
   │  display flags (PairingUiSnapshot); disable_message_dispatch() on every managed
   │  connection; move the current slot, the nursery, and the deferred releases out; clear the
   │  hello retries and close any standing pairing window
   ├─ Outside the lock: conn->disconnect(SHUTDOWN, completion) on each, completion counted by a
   │  shared GoodbyeWait; wait up to GOODBYE_FLUSH_TIMEOUT_MS (50 ms) per goodbye for the count
   │  to reach zero (the ESP httpd worker hands the frames to lwIP one at a time)
   ├─ ws_server_->stop() regardless (host: joins every accepted connection thread, a WebSocket
   │  peer within its ~300 ms close handshake and a raw never-upgraded socket within the 3 s
   │  WS_HANDSHAKE_TIMEOUT_SECS; ESP: httpd_stop(), which runs queued sends first,
   │  then every session's close_fn and ctx free_fn, polling at 100 ms)
   └─ swap_out_pending_events(): move every pending event queue (lifecycle, activate,
      re-handshake, pairing, unpair) out under conn_mutex_; every moved-out shared_ptr is
      released outside the locks (an outbound connection's destructor stops its transport
      synchronously). Returns the pairing-UI snapshot
3. Role threads: PlayerRole/VisualizerRole/ArtworkRole::Impl::stop() join, then each discards
   its ring/queue content (sole consumer after the join)
4. cleanup_connection_state() (the same reset a lost connection triggers, including the group
   slot), then group_state_ and state_ are reset. The pairing-code / window dismissals the
   snapshot from step 2 calls for are queued now (note_clear_pairing_code() /
   note_close_pairing_window()), after the cleanup that would have wiped them
5. drain_inbox() delivers the CLEARED / STREAM_END callbacks and pairing notes step 4 queued,
   and persists a pairing record a pair-finalize left staged. Every getter already
   reports the stopped state, so a callback that reads the client sees what a caller sees once
   stop() returns
6. lifecycle_ = STOPPED
```

The goodbye completion is best-effort: on ESP a session that closes before its queued worker runs, or whose `weak_ptr` no longer resolves, never reports, which is why the wait is bounded rather than exact. The `GoodbyeWait` record is held by `shared_ptr` and captured by value in each completion, so a completion that runs late on a transport thread touches nothing `stop()` owns. A peer delivered by the ws_server while admission is closed is rejected in `on_new_connection()` with a shutdown goodbye, the same shape as the nursery-full rejection.

`ConnectionManager::start()` creates and configures the server object on the first call only; the client config is immutable for the client's lifetime, so a restart reuses the object and its settings.

Each threaded role's `start()` calls `EventFlags::clear_all()` before creating its thread rather than clearing a hand-listed set of bits: a command signalled between the previous join and the restart (`cleanup()` on a stopped role) would otherwise survive into the new thread's first wait, and a bit added to the role's enum later cannot be forgotten.

The client destructor performs steps 1 and 2 only, so a consumer that destroyed its listeners first is never called into; the roles' own destructors then join their threads as before.

### High-performance release delivery

`release_high_performance()` calls the listener inline, so the teardown paths that run under `conn_ptr_mutex_` do not use it: `cleanup_connection_state()` (the time-burst hold) and the player's `cleanup()` (the playback hold) hand their release to `release_high_performance_deferred()` instead, and `drain_inbox()` performs it at the head of the next drain, with no ConnectionManager lock held. The reference itself stays held until that flush, so an acquire between the deferral and the flush cannot be reordered ahead of the release. The listener contract for `on_request_high_performance()` / `on_release_high_performance()` is unchanged: the body toggles the platform's networking mode and nothing else.

### Graceful Disconnect

`disconnect_and_release()` calls `conn->disconnect(reason, nullptr)` and lets the local `shared_ptr` go out of scope.

- **ESP server**: the goodbye text is queued as an httpd worker job. The worker resolves the connection by `lock()`ing the `weak_ptr` captured in the queued arg when the goodbye was enqueued; if it resolves it sends the frame, then runs the completion lambda that calls `trigger_close()`. The session slot installed in `open_callback` keeps the connection alive across that whole sequence even after `ConnectionManager`'s observer `shared_ptr` is dropped. The session is finally freed when httpd invokes the slot's `free_fn` (see [Server connection ownership (ESP)](#server-connection-ownership-esp)). The completion lambda also captures a `weak_ptr` to make this lifetime explicit - `trigger_close()` is skipped if the conn has already been freed. Goodbye is one of the two application messages that pass `allow_before_hello=true`, so it is not blocked by the pre-hello send gate (a rejected connection is told to leave before it ever sends a hello).
- **Host client**: the IXWebSocket send is synchronous, so the goodbye and close have both completed by the time `disconnect()` returns and the `shared_ptr` drops the last reference.

### Server connection ownership (ESP)

On the ESP build, `SendspinServerConnection` lifetime is pinned to the httpd session rather than to `ConnectionManager`:

1. `SendspinWsServer::open_callback` (the httpd `open_fn`) creates the `shared_ptr<SendspinServerConnection>`, heap-allocates a `shared_ptr*` slot, and calls `httpd_sess_set_ctx(handle, sockfd, slot, free_fn)` with a deleter that `delete`s the slot. That slot is the authoritative reference.
2. The same shared_ptr is forwarded into `ConnectionManager::on_new_connection`, which admits it into the nursery as a *secondary observer* (it moves to `current_connection_` only once its hello handshake completes).
3. The httpd WebSocket handler (`websocket_handler`) looks the connection up by `httpd_sess_get_ctx(handle, sockfd)` at run time, copying the slot's `shared_ptr` for the duration of its work; it never assumes the manager's observer slot is alive. The queued send workers (`async_send_frame`, `async_send_time_text`) instead capture a `weak_ptr<SendspinServerConnection>` to the originating connection and `lock()` it when they run.
4. When the socket closes, httpd calls the `close_fn` first (which fires `connection_closed_callback_` so `ConnectionManager` can drop its observer in the next `loop()`), then later calls the slot's `free_fn` to release the authoritative reference once no workers are queued for that session.

Queued send workers capture a `weak_ptr<SendspinServerConnection>` to the originating connection - `AsyncRespArg` for text and binary sends, `SessionLookup` for time sends - and `lock()` it when the worker runs. This is deliberately **not** a `{httpd_handle_t, int sockfd}` pair: identifying the target by sockfd risked binding to a *different* connection that had recycled the same fd after the original closed, sending a frame to the wrong peer. The `weak_ptr` resolves to the exact connection that queued the work, or to null if it has since been destroyed, in which case the worker no-ops cleanly. Because these structs now hold non-trivial members (the `weak_ptr`, and `AsyncRespArg`'s completion `std::function`), they are constructed with placement-new and explicitly destroyed before `platform_free` rather than treated as POD. Both are allocated through `platform_malloc` / `platform_malloc_internal`.

The send workers also enforce the protocol's "hello is always first" rule: a frame is dropped unless `client_hello_sent_` is set on the resolved connection, *unless* the caller passed `allow_before_hello=true`. Besides the whole pre-transport handshake (`client/init`, `noise/handshake`) and the Noise transport frames themselves, exactly two application messages do: the `client/hello` itself (which would otherwise gate its own send and deadlock) and `client/goodbye`. So a stale or out-of-order frame can never precede the handshake. The `weak_ptr` guards identity; the gate guards ordering; the two are independent.

The host build does not need this scheme: `SendspinWsServer` (host) routes IXWebSocket messages by calling `find_connection_callback_` to resolve a synthetic sockfd back to the connection that `ConnectionManager` is holding. The ESP build keeps the `set_find_connection_callback()` setter as a no-op stub for symmetry; see the comment at the call site in `ConnectionManager::start`.

## Ordering Guarantees Summary

### Network Thread → Main Loop

All network thread actions are deferred to the main loop, primarily through the shared `Inbox` (its event ring and `InboxSlot`s), with a few remaining per-thread queues and mutex-protected vectors. The main loop processes them in a fixed order each tick (connections → time → roles → group). This guarantees that:

- Connection state is settled before roles process events.
- Time sync is updated before audio sync decisions.
- Role events fire in FIFO order per role.

### Stream Lifecycle Ordering

The combination of `awaiting_sync_idle_events` (main loop) and `COMMAND_START` (sync task wait) creates a two-way handshake:

1. Network thread pushes STREAM_END → STREAM_START as `PLAYER_STREAM` events onto the inbox event ring.
2. Sync task receives `COMMAND_STREAM_END`, finishes active stream, enters IDLE, sets `TASK_IDLE`.
3. Main loop drains the ring into `awaiting_sync_idle_events`, sees STREAM_END, checks `is_running()` → false (idle), fires `on_stream_end()`.
4. Main loop sees STREAM_START, fires `on_stream_start()`, signals `COMMAND_START`.
5. Sync task receives `COMMAND_START`, exits wait, enters ACTIVE.

This prevents the sync task from starting a new stream before the main loop has processed the end of the old one.

### Playback Progress

Audio output callbacks run on a platform audio thread. They report consumed frames via `notify_audio_played()` → `playback_progress_slot_` (merging sums frames and keeps the latest timestamp). The sync task takes the accumulated value non-blockingly on each iteration of its inner loop, keeping the playtime estimate accurate without blocking the audio thread.

### Cleanup Atomicity

`disable_message_dispatch()` + queue draining + event flag signaling ensures that after cleanup:

- No new messages will be delivered from the old connection.
- All pending events are discarded.
- The sync task is signaled to end its current stream.
- The main loop will process the synthetic STREAM_END on its next tick.

### Re-entrant Teardown During Callback Dispatch

A listener callback fired from the main loop can synchronously re-enter connection teardown - for example an `on_stream_start()` or `on_*_clear()` handler that calls `connect_to()`, whose `drop_connection()` runs `cleanup_connection_state()` on the same stack. That cleanup wipes the inbox event ring (`reset_events()`) and each role re-pushes its synthetic clear/STREAM_END, so a drain already in progress must not act on the stale events it copied out before the wipe. Two plain `uint32_t` generation counters, both touched only on the main loop, guard this:

- `SendspinClient::event_state_->drain_generation`, bumped by `cleanup_connection_state()`. The event-ring drain in `loop()` snapshots it before the batch and aborts the instant it changes, discarding the events it had already copied out (they were wiped deliberately) and leaving the cleanup's freshly re-pushed events in the live ring for the next tick. The abort is checked both at the top of the inner per-event loop and once more after the loop body, so a teardown that re-enters on the final event of a full batch cannot fall through into a second `take_events()` that would destructively pull, and then drop, those re-pushed events.
- `PlayerRole::Impl::cleanup_generation`, bumped by the player's `cleanup()` (and stamped onto its queued stream events, see [Role Removal on a Later Activation](#role-removal-on-a-later-activation)). `drain_events()` snapshots it around each `on_stream_start()` call; if it changes, the stream was torn down from inside the callback, so the player abandons the rest of the batch rather than re-arm the sync task for a dead stream. `stream_active` is set before the callback runs, so the STREAM_END that `cleanup()` enqueued still passes its gate and delivers a paired `on_stream_end()`.

`drain_generation` needs no atomics: it only lets an in-flight drain notice that teardown ran underneath it and stop touching state that cleanup already reset. `cleanup_generation` is atomic because the network thread reads it, both to stamp the events it queues and to re-check, at each point of effect, the verdict the receive gate gave it.
