# Sendspin-cpp Internals

This document maps how the library's parts work together: which threads exist, how state crosses between them, the order of one `loop()` tick, and the invariants that span several files. It covers only facts that span files. Why a single function or member behaves as it does is documented at that function or member, and the protocol itself is specified by the Sendspin spec, cited here by section. The design rules new code must follow are in `docs/conventions.md`.

## Code Organization

Each role class uses the pimpl pattern. The public header (`include/sendspin/<role>_role.h`) exposes the protocol types, the listener interface, and a thin role class holding `std::unique_ptr<Impl> impl_`; all private state and thread management live in `src/<role>_role_impl.h` and the role's `.cpp`. `SendspinClient` is a `friend` of each role class so it can dispatch into `impl_`. Internal references below use the `Impl` qualification (e.g. `PlayerRole::Impl::drain_events()`).

Roles are disabled at build time through two cooperating mechanisms. `cmake/sources.cmake` keeps a source list per role, so a disabled role's translation units are never compiled and its dependencies are never required; `#ifdef SENDSPIN_ENABLE_<ROLE>` guards in `include/sendspin/client.h` and `src/client.cpp` remove the members, accessors, and dispatch branches that must name the role's type. The split exists because CMake cannot gate individual declarations, and `#ifdef` around whole files would still put the codec headers on the include path. On ESP-IDF the codec dependencies are gated by `idf_component.yml`'s Kconfig rules alone, because ESP-IDF collects `REQUIRES` before `sdkconfig` is loaded. The Opus decoder is a third gate inside the player role (`SENDSPIN_ENABLE_OPUS`), confined to `src/decoder.h`, `src/decoder.cpp`, and `src/player_role.cpp`.

Adding a role therefore means: a `SENDSPIN_<ROLE>_SOURCES` list in `cmake/sources.cmake`, the guarded member, accessor, and dispatch branches in `client.h` and `client.cpp`, and any heavy dependency kept behind the role's private headers. A role-private header such as `src/decoder.h`, which pulls in the codec headers, may only be reached from the role's own sources or a guarded include in `client.cpp`; public role headers stay codec-free because core files such as `src/protocol_messages.h` include them unconditionally.

## Thread Model

All state mutations and listener callbacks happen on the caller's main loop unless noted otherwise.

| Thread | Name | Created by | Purpose |
|--------|------|-----------|---------|
| **Main loop** | (caller's) | User code | Drives `SendspinClient::loop()`. All role event processing and listener callbacks run here. |
| **Sync task** | `Sendspin` | `SyncTask::start()` | Decodes audio, synchronizes it to server timestamps, writes PCM via `on_audio_write`. |
| **Visualizer drain** | `SsVis` | `VisualizerRole::Impl::start()` | Delivers visualization frames from a ring buffer at their playback time. |
| **Artwork decode** | `SsArt` | `ArtworkRole::Impl::start()` | Calls `on_image_decode()` for completed images; hands the display deadline to the main loop. |
| **Network** | (library-internal) | IXWebSocket (host); esp_http_server for inbound and esp_websocket_client for outbound connections (ESP) | WebSocket I/O. Handlers here hand work to the main loop or a role thread. |

On ESP-IDF, `platform_configure_thread()` sets each thread's stack size, priority, and name before the `std::thread` is constructed; priorities come from the role configs in `config.h`. On host it is a no-op.

The three role threads share one lifecycle shape. `start()` clears every event flag (`EventFlags::clear_all()`) and spawns the thread, so a restart inherits nothing from the previous run. The thread blocks on its ring buffer or queue, and `wake_receiver()` interrupts that wait, so commands take effect immediately rather than at the receive timeout. `stop()` sets `COMMAND_STOP`, wakes the receive, joins, and only then discards the ring or queue content, since after the join it is the sole consumer. `PlayerRole::Impl`'s destructor resets the sync task before anything else, so the thread is joined before any state the audio callbacks reference is destroyed.

## Cross-Thread State

The primitives live in `src/platform/` with FreeRTOS implementations on ESP and `std::mutex`/condition-variable implementations on host. `docs/conventions.md` ("Threading and cross-thread state") says which to use when.

| Primitive | Use |
|-----------|-----|
| `EventFlags` | Command and status bits between the main loop or network thread and a role thread (`COMMAND_STOP`, `COMMAND_STREAM_END`, `TASK_IDLE`, ...) |
| `ThreadSafeQueue` | Fixed-depth hand-off from the network thread to a worker (the artwork notification queue) |
| `SpscRingBuffer` | Variable-size binary data from the network thread to a role thread (encoded audio, visualizer frames) |
| `ShadowSlot` | Single-writer/single-reader state whose reader is not the main loop, latest-wins or merged (sync-task playback progress, a connection's pending pairing record) |
| `Inbox` (`src/inbox.h`) | Cross-thread state bound for the main loop, apart from the exemption below |

### Inbox

The Inbox is a single-mutex mailbox with a lock-free dirty-topic bitmask. It offers two endpoint styles: a fixed-capacity event ring for ordered lifecycle events, and `InboxSlot<T>` latest-value slots for state, each owning one `INBOX_TOPIC_*` bit. The main loop calls `poll()` to read the bitmask without locking and only locks to drain topics whose bit is set; a bit set after the snapshot stays set, so the next tick sees it.

| Endpoint | Topic bit | Producer |
|----------|-----------|----------|
| Event ring | `INBOX_TOPIC_EVENTS` | Network thread (time responses, player/artwork/visualizer stream events); main loop (`*_CLEARED` and the synthetic stream events `cleanup()` pushes) |
| `SendspinClient::EventState::group_slot` | `INBOX_TOPIC_GROUP` | Network thread |
| `SendspinClient::EventState::records_dirty_slot` | `INBOX_TOPIC_RECORDS` | Network thread (`server/pair-finalize` handler); main loop (`start()`) |
| `ControllerRole::Impl::EventState::slot` | `INBOX_TOPIC_CONTROLLER` | Network thread |
| `MetadataRole::Impl::EventState::slot` | `INBOX_TOPIC_METADATA` | Network thread |
| `ColorRole::Impl::EventState::slot` | `INBOX_TOPIC_COLOR` | Network thread |
| `PlayerRole::Impl::EventState::stream_params_slot` | `INBOX_TOPIC_PLAYER_STREAM_PARAMS` | Network thread |
| `PlayerRole::Impl::EventState::command_slot` | `INBOX_TOPIC_PLAYER_COMMAND` | Network thread |
| `VisualizerRole::Impl::EventState::config_slot` | `INBOX_TOPIC_VISUALIZER_CONFIG` | Network thread |
| `ArtworkRole::Impl::EventState::display_slot` | `INBOX_TOPIC_ARTWORK_DISPLAY` | Artwork decode thread |

`ConnectionManager`'s `pending_*_events_` queues are the one exemption (`docs/conventions.md`): they carry connection events whose payloads the POD-only ring cannot hold. `deferred_releases_` is a release queue, not a state channel: the thread that queues an entry flushes it outside the manager lock, except the sync task's stream pin, which `release_from_role_thread()` marks main-loop-only for the main loop to destroy (see [Stream Connection Pin](#stream-connection-pin)). The pairing and trust listener notifications are not cross-thread either: they are queued as `PairingNote`s on the main loop itself, so they can fire after `ConnectionManager` releases its lock.

## One Main Loop Tick

`SendspinClient::loop()` is a no-op while the client is stopped. While started, each tick runs these steps in order; steps 3 onward are `drain_inbox()`, which `stop()` also calls once so teardown callbacks are delivered synchronously.

```api
1. connection_manager_->loop()
   ├─ Start the WS server once the network is ready
   ├─ Swap out deferred connection events; process close/disconnect (on_connection_lost),
   │  start the Noise handshake on newly connected outbound connections, then process
   │  server/activate events (trust check, role removals)
   ├─ Promotion scan: establish operational nursery connections
   │  (admission arbitration against the incumbent); then pairing and unpair events
   ├─ flush_pending_record_ops(), flush_pending_admission(), flush_deferred_releases(),
   │  all unlocked, so the incoming connection drives the roles before the outgoing one
   │  is told to leave
   ├─ Call loop() on the current and nursery connections; send pending hellos
   ├─ Reap nursery connections past the establish deadline; drop a silent current connection;
   │  then a release flush and the platform ws_server tick
   └─ Pairing attempt timeout and re-prove watchdog scans, each followed by a release flush

2. time_burst_->loop(conn)   (only while the current connection is operational); send a
   client/state held for clock sync once synced

3. Flush deferred high-performance releases; persist a staged pairing record

4. Drain the inbox event ring
   ├─ TIME_RESPONSE → time_burst_->on_time_response()
   ├─ *_CLEARED → each role's handle_cleared_event()
   └─ PLAYER/ARTWORK/VISUALIZER_STREAM → each role's stream-event handler

5. Dispatch deferred pairing/trust notes

6. Role drains: each role's impl_->drain_events(), gated on impl_->needs_drain(slot_bits)

7. Drain group_slot: apply deltas, fire on_group_update
```

The nursery, promotion, and admission are described under [Connection Lifecycle](#connection-lifecycle). The high-performance hold is a ref-counted request, surfaced to the consumer through `on_request_high_performance()` / `on_release_high_performance()`, for the platform to keep networking responsive (e.g. disable WiFi power saving) during time sync and playback.

Connection lifecycle runs before role events and time sync before audio, so roles always see settled connection and clock state. Most `ConnectionManager` sections check a lock-free hint atomic before locking; the admission flush and the two watchdog scans take `conn_ptr_mutex_` unconditionally. The Inbox steps gate on two `poll()` snapshots: one before the ring drain (steps 3 and 4) and one after it (steps 6 and 7), which catches bits set while the ring was draining. Roles whose pending work waits on a deadline or on the sync task rather than on a new message (the player's held stream events, the metadata and color roles' future-dated state, artwork's held displays) add a carry-over term to `needs_drain()`, since no inbox bit tracks that wait.

## Ordering Guarantees

### Network Thread to Main Loop

Network-thread work bound for the main loop is deferred through the Inbox, `ConnectionManager`'s event queues, or connection-state atomics the main loop polls (the hello and handshake flags), and processed in the fixed tick order above. Inbound arrival is the exception: the network thread inserts the new connection into the nursery directly under `conn_ptr_mutex_`. Connection state is settled before roles process events, time sync is updated before audio decisions, and role events fire in FIFO order per role.

### Stream End and Start

`stream/end` followed by `stream/start` crosses three threads, and a two-way handshake keeps them in order:

1. The network thread pushes STREAM_END and STREAM_START as `PLAYER_STREAM` events onto the inbox ring and signals the sync task `COMMAND_STREAM_END`.
2. The sync task finishes the stream and returns to IDLE, clearing `TASK_RUNNING`.
3. The main loop moves the ring events into `awaiting_sync_idle_events`. It holds STREAM_END, and everything behind it, until `SyncTask::is_running()` reads false, then fires `on_stream_end()`.
4. The main loop fires `on_stream_start()` and signals `COMMAND_START`.
5. The sync task, which has been waiting for `COMMAND_START` since it saw the new codec header, goes ACTIVE.

Step 5's wait is what makes step 3 safe: without it the sync task could pass through IDLE and back to ACTIVE before the main loop ever observed it not running, and the held STREAM_END would wait forever. `stream/clear` does not use this path; it signals the sync task directly and enqueues a marker chunk into the encoded ring, and the sync task stays ACTIVE while it discards up to the marker.

### Cleanup

When a connection is lost, `disable_message_dispatch()` runs first. It is an atomic flag the network thread checks before dispatching, so no message dispatched after the flip reaches the roles; a handler already past the check is caught by its role's teardown-generation re-check. `cleanup_connection_state()` then stops time sync, resets the inbox ring and every role's slots, and has each role push its synthetic STREAM_END or `*_CLEARED`, which the main loop delivers on its next drain. Cleanup can run under `ConnectionManager`'s lock, so it never calls a listener directly; even the high-performance release it owes is handed to the next `drain_inbox()`.

### Re-entrant Teardown During Callback Dispatch

A listener callback fired from the main loop can re-enter connection teardown, for example an `on_*_clear()` (fired from the ring drain) or `on_stream_start()` (fired from the player's drain) that calls `connect_to()` while the current connection is present but already disconnected. That teardown wipes the inbox ring and resets the roles underneath the drain that fired the callback. Two generation counters keep the drain from acting on what it already copied out:

- `drain_generation` (on the client's `EventState`) is bumped by `cleanup_connection_state()`. The ring drain snapshots it and stops as soon as it changes, leaving the cleanup's re-pushed events in the live ring for the next tick. The pairing-note dispatch follows the same rule.
- Each stream role's `cleanup_generation` is bumped by its `cleanup()` and stamped onto every stream event it queues; the ring drain drops events whose stamp no longer matches (`event_is_current()`). The player also checks it around each `on_stream_start()` and abandons the rest of the batch if the stream was torn down inside the callback.

## Message Flow

### Receive Path

Encryption is mandatory, so every application message arrives as a binary Noise frame and is routed by the first byte of its decrypted plaintext. Text frames carry only the pre-transport handshake.

```api
Network thread (IXWebSocket / esp_http_server)
  │
  ├─ Assembles fragmented WebSocket frames into complete messages
  │
  └─ dispatch_completed_message()
     ├─ Text frame → handshake driver only (server/init, noise/handshake)
     │
     └─ Binary frame → Noise transport active?
        ├─ no  → refused
        └─ yes → decrypt, reassemble Noise-level fragments
                 └─ dispatch_complete_noise_message()
                    ├─ checks message_dispatch_enabled_ (teardown guard)
                    └─ routes on the plaintext type byte:
                       ├─ MSG_TYPE_JSON_BODY → SendspinClient::process_json_message()
                       └─ other → SendspinClient::process_binary_message()
```

### Dispatch (network thread)

Role dispatch points skip a role the server has not activated (`SendspinConnection::is_role_active()`), except that artwork binary messages still reach the role so its malformed-message checks run. Role-bound traffic is dispatched only for the admitted connection (see [Handshake and Admission](#handshake-and-admission)).

| Message | Action on the network thread |
|---------|------------------------------|
| `server/hello` | Records server info on the connection and sets `server_hello_received_` |
| `server/time` | Pushes a `TIME_RESPONSE` event onto the inbox ring |
| `server/state` | Writes the controller, metadata, and color `InboxSlot`s |
| `server/command` | Merges into the player's `command_slot` |
| `group/update` | Merges into `group_slot` |
| `stream/start` | Player writes the codec header into the encoded ring (a bounded blocking send), then writes its params slot and pushes STREAM_START; visualizer enqueues a clear marker into its ring, writes its config slot, and pushes STREAM_START; artwork marks its stream active and discards the pending image of each channel whose configuration changed |
| `stream/end` | Pushes STREAM_END events for each streaming role and signals the sync task |
| `stream/clear` | Visualizer enqueues a clear marker into its ring and pushes STREAM_CLEAR; player signals the sync task and enqueues a clear marker into the encoded ring |
| Player audio (binary) | `PlayerRole::Impl::handle_binary()` writes the chunk to the encoded audio ring |
| Artwork (binary) | `ArtworkRole::Impl::handle_binary()` accumulates the image and, when complete, notifies the decode thread |
| Visualizer (binary) | `VisualizerRole::Impl::handle_binary()` writes the frame to the visualizer ring |

## Stream Lifecycle

### Player Drain

`PlayerRole::Impl::drain_events()` first applies any server command (volume, mute, output delay), then walks `awaiting_sync_idle_events`:

```api
PLAYER_STREAM ring events → on_stream_ring_event() → awaiting_sync_idle_events
                       │
                       ▼
         For each event in order:
           ├─ STREAM_END:
           │    Sync task still running → wait for next tick
           │    Sync task idle → fire on_stream_end(), continue
           │
           └─ STREAM_START:
                Take stream_params_slot
                Mark stream active, fire on_stream_start()
                Signal sync task COMMAND_START
```

The other roles are simpler. Controller, metadata, and color take their slot and fire their state callback, metadata and color holding a future-dated state until its server-clock timestamp. Artwork holds each decoded image's display deadline and fires `on_image_display()` when it passes. Visualizer has no drain; it is driven entirely by its ring events.

### Sync Task

The sync task (`SyncTask::thread_entry()`, `src/sync_task.cpp`) runs a two-level state machine.

```api
┌──────────────────────────────────────────────────────────┐
│                    COMMAND_STOP?                          │
│                    ┌─── yes ──→ exit thread               │
│                    │                                      │
│  ┌─────────────────┴──────────────────┐                  │
│  │           IDLE STATE               │                  │
│  │  • Clear TASK_RUNNING and the      │                  │
│  │    stream COMMAND flags            │                  │
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
│  │  • Pin the current connection      │                  │
│  │  • Set TASK_RUNNING                │                  │
│  │  • Decode initial codec header     │                  │
│  │  • Run inner state machine loop    │                  │
│  └────────────┬───────────────────────┘                  │
│               │ STOP/END                                 │
│               ▼                                          │
│  ┌────────────────────────────────────┐                  │
│  │  Return the borrowed ring buffer   │──────→ loop back │
│  │  entry, then release the pin       │                  │
│  └────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────┘
```

```api
INITIAL_SYNC ──→ LOAD_CHUNK ──→ SYNCHRONIZE_AUDIO ──→ TRANSFER_AUDIO
     │                ▲               │                       │
     │                └───────────────┴───────────────────────┘
     │                        (cycle per chunk)
     └──→ LOAD_CHUNK (once first playback progress callback confirms frames were consumed)

COMMAND_STREAM_CLEAR from any state → discard up to the clear marker → INITIAL_SYNC
```

INITIAL_SYNC primes the audio pipeline with silence. LOAD_CHUNK takes and decodes the next encoded chunk once the clock is synced. SYNCHRONIZE_AUDIO compares the chunk's playback time, converted to the client clock, with the time the next written audio will actually play, and corrects the difference by inserting silence or dropping late audio (large errors) or by adding or removing a single frame (small ones). TRANSFER_AUDIO writes the PCM through `on_audio_write`.

The "will actually play" estimate comes from the audio sink: `notify_audio_played()` reports consumed frames into the sync task's playback-progress `ShadowSlot`, which the inner loop takes on every iteration without blocking the audio thread.

### Stream Connection Pin

Every timestamp a stream converts belongs to one connection's time filter, so the sync task pins that connection (`ConnectionManager::current_shared()`) as the stream goes active and holds it until the stream ends. The pin stays valid because a filter is never replaced and the admitted slot cannot change servers mid-stream: dropping a connection runs `cleanup_connection_state()`, which ends the stream, before a successor is installed. The pin is often the last reference to a dropped connection, and an outbound connection's destructor joins its transport thread, so the sync task never destroys it: `ConnectionManager::release_from_role_thread()` hands the reference to the main loop's next `flush_deferred_releases()`.

## Time Synchronization

`SendspinTimeBurst` (`src/time_burst.h`) runs NTP-style bursts: a configurable number of `client/time` exchanges whose lowest-round-trip measurement goes to the filter, then a pause until the next burst. High-performance networking is held for the duration of each burst. `SendspinTimeFilter` (`src/time_filter.h`) is a two-state `[offset, drift]` Kalman filter with adaptive forgetting for step changes; its `state_mutex_` lets the sync task and the visualizer drain thread convert timestamps while the main loop updates it. The filter's first measurement gates playback and, while the player role is active, the client's `client/state` reporting `available: true` (messaging.md "client/state").

## Noise Encryption

Every connection is encrypted with Noise KKpsk2; the library is always the responder.

### Handshake

```api
Client -> Server: client/init   (client_id, version, cipher suite)
Server -> Client: server/init   (server_id, cipher suite)
Server -> Client: noise/handshake msg1 (Noise KKpsk2 initiator message)
Client -> Server: noise/handshake msg2 (Noise KKpsk2 responder message)
-- transport active from here --
Server -> Client: server/hello  (encrypted, server name)
Client -> Server: client/hello  (encrypted, device info, pair_methods)
Server -> Client: server/activate (encrypted, activities, active_roles)
```

`ConnectionManager` sends `client/init` as soon as the WebSocket upgrade completes, inbound or outbound. msg1 names the PSK to use by `psk_id` and category, and `RecordStore::resolve_by_psk_id()` resolves it on the network thread (connection.md "Pre-Shared Key"):

- `lt`: a long-term record from a completed pairing, bound to its `server_id`
- `pr`: the Pairing PSK, from the config, persistence, or generated at first start
- `sn`: the published Sentinel PSK, which authenticates nothing

A lookup miss in the initial handshake completes with the Sentinel PSK (connection.md "Sentinel Fallback"); a miss during a re-handshake fails it. The resolved category is stored on the connection. It decides which activations the connection may be admitted with (`src/admission.h`, messaging.md "server/activate") and, once admitted, the client's `ConnectionTrust`.

### Transport

Once active, every message travels through `NoiseTransport` as `[type byte][payload]`, encrypted into one binary WebSocket frame. `MSG_TYPE_JSON_BODY` marks JSON, `MSG_TYPE_FRAGMENT` a fragment of a message too large for one Noise frame (messaging.md "Fragmentation"), and every other type a binary role message.

The server may start a new handshake inside the transport at any time (connection.md "Re-handshake"). The connection swaps its `NoiseSession` once msg2 is written, then goes non-operational until the next `server/activate`; until then the client sends no application message, and a watchdog drops a connection that is never re-activated.

### Pairing

A `server/activate` declaring the `pairing` activity starts a pairing attempt on the main loop, alongside any playback (pairing.md "Entering and leaving pairing"). For the Pairing PSK method:

```api
Server -> Client: server/activate (activities=["pairing"], method=pairing_psk)
Client -> Server: client/pair-init
Client -> Server: client/pair-finalize (long-term PSK)
Server -> Client: server/pair-finalize
Server -> Client: noise/handshake msg1 (re-keying onto the new long-term PSK)
Client -> Server: noise/handshake msg2
Server -> Client: server/activate (normal operational flow)
```

The new long-term record must resolve for the re-handshake that immediately follows, so the `server/pair-finalize` handler commits it to `RecordStore` in RAM on the network thread. The persistence provider is main-loop-only, so the durable write is staged through `records_dirty_slot` and performed by the next `drain_inbox()`, before `on_pairing_succeeded` fires. The pairing-code methods (CPace) follow the same main-loop state-machine shape in `ConnectionManager`.

## Connection Lifecycle

### Slots

| Slot | Purpose |
|------|---------|
| `current_connection_` | The admitted connection; holds only connections that became operational |
| `nursery_` | Unproven connections (inbound or outbound) awaiting establishment, bounded by `MAX_NURSERY_ENTRIES` |

Both hold `std::shared_ptr<SendspinConnection>`. On the ESP server path these are observers; see [Server Connection Ownership (ESP)](#server-connection-ownership-esp).

### Handshake and Admission

1. A new connection enters the nursery and runs the Noise handshake on the network thread.
2. Once transport is active, the main loop's hello scan sends `client/hello`.
3. The connection is operational once both hellos are exchanged and its first `server/activate` arrives, in either order. That activate is checked against the connection's trust when it is processed, and a rejected one closes the connection.
4. The next promotion scan establishes the operational connection, arbitrating against the incumbent, mainly by highest activity (playback over pairing over none); `should_admit_connection()` in `src/admission.h` has the full rules.
5. The loser's dispatch is disabled and it is sent a goodbye through the deferred-release queue; client state is cleaned up only when the loser is the incumbent.

A server sends role traffic right behind its `server/activate`, a tick before promotion admits the connection. The connection holds that JSON (bounded by `MAX_HELD_MESSAGES` / `MAX_HELD_BYTES`), and `SendspinClient::admit_connection()` replays it in arrival order. The first `client/state` is also held until admission, because it opens the server's binary traffic for the roles, and binary messages arriving before admission are dropped rather than held. Admission runs after `ConnectionManager` drops its lock, to keep the library's lock order (`docs/conventions.md`). The persistence writes the lifecycle handlers decide on run there too, so a slow flash commit never holds the lock the network threads need.

A later `server/activate` can remove roles. Each removed role runs the same `cleanup()` a lost connection runs, but the inbox ring is not reset, since the roles that stay active keep their queued events; the `cleanup_generation` stamp drops the removed role's stale ones instead. Nothing is restarted when an activation adds the role back: its role thread never stopped, so it returns through the `client/state` that activation publishes and, for a stream role, the next `stream/start`.

### Client Start and Stop

`SendspinClient::start()` validates the pairing config, creates the `RecordStore` and identity, loads persisted state, starts the threaded roles, and opens `ConnectionManager` for admission. The WebSocket server itself starts on a later `loop()` once the network is ready.

`SendspinClient::stop()` is synchronous and ordered so that every producer is gone before any state is reset:

```api
0. lifecycle_ = STOPPING (loop() becomes a no-op; start/stop/connect_to/disconnect are
   refused or ignored, so a callback fired below cannot recurse into the teardown)
1. Signal the visualizer and artwork threads to stop, without joining. The player is not
   signalled yet: a network thread blocked writing to its ring needs the sync task alive
2. ConnectionManager::stop(): close admission, snapshot the pairing-UI flags, disable
   dispatch on every connection, send goodbyes with a bounded wait, stop the ws_server
   (joining its network threads), and release every queued connection outside the locks
3. Join all role threads; each then discards its ring or queue content. Then flush the
   deferred releases once more, for a stream pin handed back during the join
4. cleanup_connection_state(), then queue the pairing-UI dismissals the step 2 snapshot calls for
5. drain_inbox() delivers the CLEARED / STREAM_END callbacks and pairing notes step 4 queued
6. lifecycle_ = STOPPED
```

The client destructor performs steps 1 and 2 and releases any outstanding high-performance hold, but dispatches no teardown or clear callback; the roles' destructors then join their threads, so listeners must outlive the client.

### Server Connection Ownership (ESP)

On ESP, a `SendspinServerConnection`'s lifetime belongs to its httpd session rather than to `ConnectionManager`:

1. `SendspinWsServer::open_callback` creates the `shared_ptr` and stores a heap-allocated copy as the session context, with a `free_fn` that deletes it. That copy is the authoritative reference.
2. `ConnectionManager::on_new_connection()` receives the same `shared_ptr` and holds it as an observer.
3. The WebSocket handler looks the connection up through the session context each time it runs. Queued send workers capture a `weak_ptr` and lock it when they run, rather than a socket number, which httpd can reuse for a different session after the original closes.
4. On close, httpd calls `close_fn` (which tells `ConnectionManager` to drop its observer), then `free_fn` once no worker is queued for the session.

On host, IXWebSocket callbacks resolve the connection through `ConnectionManager` directly, so this scheme is not needed.
