# Sendspin-cpp Internals

This document maps how the library's parts work together: which threads exist, how state crosses between them, the order of one `loop()` tick, and the invariants that span several files. It covers only facts that span files. Why a single function or member behaves as it does is documented at that function or member, and the protocol itself is specified by the Sendspin spec, cited here by section. The design rules new code must follow are in `docs/conventions.md`. How the library keeps audio in time with the server (clock sync and the sync task's alignment) is in `docs/playback-sync.md`.

## Code Organization

Each role class uses the pimpl pattern. The public header (`include/sendspin/<role>_role.h`) exposes the protocol types, the listener interface, and a thin role class holding `std::unique_ptr<Impl> impl_`; all private state and thread management live in `src/<role>_role_impl.h` and the role's `.cpp`. `SendspinClient` is a `friend` of each role class so it can dispatch into `impl_`. Internal references below use the `Impl` qualification (e.g. `PlayerRole::Impl::drain_events()`).

Roles are disabled at build time through two cooperating mechanisms. `cmake/sources.cmake` keeps a source list per role, so a disabled role's translation units are never compiled and its dependencies are never required; `#ifdef SENDSPIN_ENABLE_<ROLE>` guards in `include/sendspin/client.h` and `src/client.cpp` remove the members, accessors, and dispatch branches that must name the role's type. The split exists because CMake cannot gate individual declarations, and `#ifdef` around whole files would still put the codec headers on the include path. On ESP-IDF the codec dependencies are gated by `idf_component.yml`'s Kconfig rules alone, because ESP-IDF collects `REQUIRES` before `sdkconfig` is loaded. The Opus decoder is a third gate inside the player role (`SENDSPIN_ENABLE_OPUS`), confined to `src/decoder.h`, `src/decoder.cpp`, and `src/player_role.cpp`.

Adding a role therefore means: a `SENDSPIN_<ROLE>_SOURCES` list in `cmake/sources.cmake`, the guarded member, accessor, and dispatch branches in `client.h` and `client.cpp`, and any heavy dependency kept behind the role's private headers. A role-private header such as `src/decoder.h`, which pulls in the codec headers, may only be reached from the role's own sources or a guarded include in `client.cpp`; public role headers stay codec-free because core files such as `src/protocol_messages.h` include them unconditionally.

## Thread Model

All state mutations and listener callbacks happen on the caller's main loop unless noted otherwise.

| Thread | Name | Created by | Purpose |
|--------|------|-----------|---------|
| **Main loop** | (caller's) | User code | Drives `SendspinClient::loop()`. All role event processing and listener callbacks run here. |
| **Protocol task** | `SsProto` | `ProtocolTask::start()`, from `SendspinClient::start()` | All per-connection protocol work: decrypt, Noise reassembly, the handshake, JSON and binary dispatch, the admission replay, close reporting. Ticks on a wake or a deadline (`SendspinClient::protocol_tick()`). |
| **Sync task** | `Sendspin` | `SyncTask::start()` | Decodes audio, aligns it to server timestamps (`docs/playback-sync.md`), writes PCM via `on_audio_write`. |
| **Visualizer drain** | `SsVis` | `VisualizerRole::Impl::start()` | Delivers visualization frames from its item list at their playback time. |
| **Artwork decode** | `SsArt` | `ArtworkRole::Impl::start()` | Calls `on_image_decode()` for completed images; hands the display deadline to the main loop. |
| **Transport** | (library-internal) | IXWebSocket (host); esp_http_server for inbound and esp_websocket_client for outbound connections (ESP) | WebSocket I/O only: receives each complete message into the shared inbound ring or the connection's fallback buffer, reports a close, and wakes the protocol task. |

On ESP-IDF, `platform_configure_thread()` sets each thread's stack size, priority, and name before the `std::thread` is constructed; priorities come from the client and role configs in `config.h`. On host it is a no-op.

The three role threads share one lifecycle shape. `start()` clears every event flag (`EventFlags::clear_all()`) and spawns the thread, so a restart inherits nothing from the previous run. The thread blocks on its item list or queue, and `wake_receiver()` interrupts that wait, so commands take effect immediately rather than at the receive timeout. `stop()` sets `COMMAND_STOP`, wakes the receive, joins, and only then returns the list's items to the ring or discards the queue content, since after the join it is the sole consumer. `PlayerRole::Impl`'s destructor resets the sync task before anything else, so the thread is joined before any state the audio callbacks reference is destroyed.

## Cross-Thread State

The primitives other than the Inbox live in `src/platform/`, with FreeRTOS implementations on ESP and `std::mutex`/condition-variable implementations on host. `docs/conventions.md` ("Threading and cross-thread state") says which to use when.

| Primitive | Use |
|-----------|-----|
| `EventFlags` | Command and status bits between the main loop or protocol task and a role thread (`COMMAND_STOP`, `COMMAND_STREAM_END`, `TASK_IDLE`, ...) |
| `ThreadSafeQueue` | Fixed-depth hand-off from the protocol task to a worker (the artwork notification queue) |
| `InboundRing` (`src/inbound_ring.h`) | The one shared ring every admitted connection's transport receives into; the protocol task takes its items in arrival order |
| `InboundItemList` | A role's FIFO of inbound ring items, linked through the items themselves: the protocol task appends, the sync task or visualizer drain thread takes and returns. Each holder's items are charged to its `InboundQuota`. Its mutex also guards the two-party return count of a task-written (LOCAL) item charged to that holder, since the ring storage may be external RAM, where the ESP32 cannot run an atomic |
| `InboundGate` | Per connection, between its transport and the protocol task: the admitted and detached flags, the one pre-admission message in flight, the count of ring items not yet taken, and the out-of-band close |
| `ProtocolTask` command queue | Bounded requests from the main loop and consumers to the protocol task |
| `ShadowSlot` | Single-writer/single-reader state whose reader is not the main loop, latest-wins or merged (sync-task playback progress, a connection's pending pairing record) |
| `Inbox` (`src/inbox.h`) | Cross-thread state bound for the main loop, apart from the exemption below |

Two locks sit outside these primitives, both for time conversion. Each connection's `SendspinTimeFilter` guards its state with its own `state_mutex_`, because the main loop updates it while the sync task and the visualizer drain thread convert timestamps through it (`docs/playback-sync.md`). `ConnectionManager::time_filter_mutex_` guards the slot those threads resolve the current filter from, an exemption from the primitives (`docs/conventions.md`; see [Current Time Filter Slot](#current-time-filter-slot)).

### Inbox

The Inbox is a single-mutex mailbox with a lock-free dirty-topic bitmask. It offers two endpoint styles: a fixed-capacity event ring for ordered lifecycle events, and `InboxSlot<T>` latest-value slots for state, each owning one `INBOX_TOPIC_*` bit. The main loop calls `poll()` to read the bitmask without locking and only locks to drain topics whose bit is set; a bit set after the snapshot stays set, so the next tick sees it.

| Endpoint | Topic bit | Producer |
|----------|-----------|----------|
| Event ring | `INBOX_TOPIC_EVENTS` | Protocol task (player/artwork/visualizer stream events); main loop (`*_CLEARED` and the synthetic stream events `cleanup()` pushes) |
| `SendspinClient::EventState::time_slot` | `INBOX_TOPIC_TIME` | Protocol task (`server/time` handler) |
| `SendspinClient::EventState::group_slot` | `INBOX_TOPIC_GROUP` | Protocol task |
| `SendspinClient::EventState::persist_slot` | `INBOX_TOPIC_PERSIST` | Protocol task (`server/pair-finalize` handler); main loop (`start()`, the unpair drain, a playback activate) |
| `ControllerRole::Impl::EventState::slot` | `INBOX_TOPIC_CONTROLLER` | Protocol task |
| `MetadataRole::Impl::EventState::slot` | `INBOX_TOPIC_METADATA` | Protocol task |
| `ColorRole::Impl::EventState::slot` | `INBOX_TOPIC_COLOR` | Protocol task |
| `PlayerRole::Impl::EventState::stream_params_slot` | `INBOX_TOPIC_PLAYER_STREAM_PARAMS` | Protocol task |
| `PlayerRole::Impl::EventState::command_slot` | `INBOX_TOPIC_PLAYER_COMMAND` | Protocol task |
| `VisualizerRole::Impl::EventState::config_slot` | `INBOX_TOPIC_VISUALIZER_CONFIG` | Protocol task |
| `ArtworkRole::Impl::EventState::display_slot` | `INBOX_TOPIC_ARTWORK_DISPLAY` | Artwork decode thread |

`ConnectionManager`'s `pending_*_events_` queues are the one exemption (`docs/conventions.md`): they carry connection events whose payloads the POD-only ring cannot hold. `deferred_releases_` is main-loop-only (see `DeferredRelease`), not a cross-thread channel. The pairing and trust listener notifications are not cross-thread either: they are queued as `PairingNote`s on the main loop itself, so they can fire after `ConnectionManager` releases its lock.

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
   ├─ flush_pending_persistence(), flush_pending_admission(), flush_deferred_releases(),
   │  all unlocked, so the incoming connection drives the roles before the outgoing one
   │  is told to leave
   ├─ Call loop() on the current and nursery connections; send pending hellos
   ├─ Reap nursery connections past the establish deadline; drop a silent current connection;
   │  then a release flush and the platform ws_server tick
   └─ Pairing attempt timeout and re-prove watchdog scans, each followed by a release flush

2. time_burst_->loop(conn)   (only while the current connection is operational); send a
   client/state held for clock sync once synced

3. Flush deferred high-performance releases; perform a provider write requested since step 1
   (a pairing the protocol task committed); feed a claimed time measurement from the current
   connection into time_burst_->on_time_response()

4. Drain the inbox event ring
   ├─ *_CLEARED → each role's handle_cleared_event()
   └─ PLAYER/ARTWORK/VISUALIZER_STREAM → each role's stream-event handler

5. Dispatch deferred pairing/trust notes

6. Role drains: each role's impl_->drain_events(), gated on impl_->needs_drain(slot_bits)

7. Drain group_slot: apply deltas, fire on_group_update
```

The nursery, promotion, and admission are described under [Connection Lifecycle](#connection-lifecycle). The high-performance hold is a ref-counted request, surfaced to the consumer through `on_request_high_performance()` / `on_release_high_performance()`, for the platform to keep networking responsive (e.g. disable WiFi power saving) during time sync and playback.

Connection lifecycle runs before role events and time sync before audio, so roles always see settled connection and clock state. Most `ConnectionManager` sections check a lock-free hint atomic before locking; the admission flush and the two watchdog scans take `conn_ptr_mutex_` unconditionally. The Inbox steps gate on two `poll()` snapshots: one before the ring drain (steps 3 and 4) and one after it (steps 6 and 7), which catches bits set while the ring was draining. Roles whose pending work waits on a deadline or on the sync task rather than on a new message (the player's held stream events, the metadata and color roles' future-dated state, artwork's held displays) add a carry-over term to `needs_drain()`, since no inbox bit tracks that wait.

The role drains in step 6 are simple apart from the player's, which is the main loop's half of the stream end/start handshake (see [Stream End and Start](#stream-end-and-start)). Controller, metadata, and color take their slot and fire their state callback, metadata and color holding a future-dated state until its server-clock timestamp. Artwork holds each decoded image's display deadline and fires `on_image_display()` when it passes. Visualizer has no drain; it is driven entirely by its ring events.

## Ordering Guarantees

### Protocol Task to Main Loop

Protocol-task work bound for the main loop is deferred through the Inbox, `ConnectionManager`'s event queues, or connection-state atomics the main loop polls (the hello and handshake flags), and processed in the fixed tick order above. A transport close reaches the main loop the same way: the transport marks its connection's `InboundGate` closed and wakes the task, and the task reports the loss (`ConnectionManager::report_connection_lost()`) once nothing the connection received is left untaken, so the messages before a close are dispatched before it. Inbound arrival is the exception: the transport thread inserts the new connection into the nursery directly under `conn_ptr_mutex_`. Connection state is settled before roles process events, time sync is updated before audio decisions, and role events fire in FIFO order per role.

### Stream End and Start

`stream/end` followed by `stream/start` crosses three threads, and a two-way handshake keeps them in order:

1. On `stream/end` the protocol task signals the sync task `COMMAND_STREAM_END`, then pushes STREAM_END as a `PLAYER_STREAM` event onto the inbox ring; on `stream/start` it appends the codec header to the sync task's item list, then pushes STREAM_START.
2. The sync task finishes the stream and returns to IDLE, clearing `TASK_RUNNING`.
3. The main loop moves the ring events into `awaiting_sync_idle_events`. It holds STREAM_END, and everything behind it, until `SyncTask::is_running()` reads false, then fires `on_stream_end()`.
4. The main loop fires `on_stream_start()` and signals `COMMAND_START`.
5. The sync task, which has been waiting for `COMMAND_START` since it saw the new codec header (WAIT FOR CLIENT ACK in `docs/playback-sync.md`), goes ACTIVE.

Signalling before pushing is what lets the `is_running()` gate in step 3 release only an end the sync task has already been told to honour. Step 5's wait is what makes step 3 safe: without it the sync task could pass through IDLE and back to ACTIVE before the main loop ever observed it not running, and the held STREAM_END would wait forever. `stream/clear` does not use this path; it signals the sync task directly and appends a marker item to its list, and the sync task stays ACTIVE while it discards up to the marker.

The hold in step 3, and step 4, run in `PlayerRole::Impl::drain_events()`, which first applies any server command (volume, mute, output delay), then walks `awaiting_sync_idle_events`:

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

### Cleanup

When a connection is lost, `detach_inbound()` runs first. It detaches the connection's `InboundGate`: its transport drops what it receives from then on, and the protocol task checks the flag before processing each of the connection's messages, so no message processed after the flip reaches the roles; a JSON role handler, or a player or visualizer binary handler, already past the check is caught by its role's teardown-generation re-check. Items a stream role holds for the torn-down stream are recalled to the ring on the protocol task's next tick (`recall_stale_items()`), and a consumer that takes one first discards it by its generation stamp. `cleanup_connection_state()` then stops time sync, resets the inbox ring and every role's slots, and has each role push its synthetic STREAM_END or `*_CLEARED`, which the main loop delivers on its next drain. Cleanup can run under `ConnectionManager`'s lock, so it never calls a listener directly; even the high-performance release it owes is handed to the next `drain_inbox()`.

### Re-entrant Teardown During Callback Dispatch

A listener callback fired from the main loop can re-enter connection teardown, for example an `on_*_clear()` (fired from the ring drain) or `on_stream_start()` (fired from the player's drain) that calls `connect_to()` while the current connection is present but already disconnected. That teardown wipes the inbox ring and resets the roles underneath the drain that fired the callback. Two generation counters keep the drain from acting on what it already copied out:

- `drain_generation` (on the client's `EventState`) is bumped by `cleanup_connection_state()`. The ring drain snapshots it and stops as soon as it changes, leaving the cleanup's re-pushed events in the live ring for the next tick. The pairing-note dispatch follows the same rule.
- Each stream role's `cleanup_generation` is bumped by its `cleanup()` and stamped onto every stream event it queues; the ring drain drops events whose stamp no longer matches (`event_is_current()`). The player also checks it around each `on_stream_start()` and abandons the rest of the batch if the stream was torn down inside the callback.

## Message Flow

### Receive Path

Encryption is mandatory, so every application message arrives as a binary Noise frame and is routed by the first byte of its decrypted plaintext. Text frames carry only the pre-transport handshake.

```api
Transport thread (IXWebSocket / esp_http_server / esp_websocket_client)
  │
  ├─ Admitted connection: receives the message straight into an InboundRing item
  │  (waits up to INBOUND_ACQUIRE_TIMEOUT_MS for room, else drops it with a warning)
  ├─ Unadmitted connection: receives into its fallback buffer and publishes it as the one
  │  pending message (waits up to InboundGate::WRITABLE_WAIT_MS for the previous one, else
  │  closes); a message over InboundGate::PRE_ADMISSION_MESSAGE_BYTES closes
  ├─ A message split across WebSocket frames is assembled in the fallback buffer, then copied
  │  into a ring item (admitted) or published (unadmitted)
  └─ wakes the protocol task
         │
Protocol task: SendspinClient::protocol_tick()
  ├─ per connection: replay held messages once admitted, then its pending message
  └─ ring items in arrival order → SendspinConnection::process_inbound_message()
     ├─ detached connection → dropped (teardown guard)
     ├─ Text frame → handshake driver only (server/init, noise/handshake)
     └─ Binary frame → Noise transport active?
        ├─ no  → refused
        └─ yes → decrypt in place, reassemble Noise-level fragments (copied)
                 └─ dispatch_complete_noise_message() routes on the plaintext type byte:
                    ├─ MSG_TYPE_JSON_BODY → SendspinClient::process_json_message()
                    └─ other → SendspinClient::process_binary_message(), which hands
                       a player or visualizer message over in its ring item
```

### Dispatch (protocol task)

Role dispatch points skip a role the server has not activated (`SendspinConnection::is_role_active()`), except that artwork binary messages still reach the role so its malformed-message checks run. Role-bound traffic is dispatched only for the admitted connection (see [Handshake and Admission](#handshake-and-admission)).

| Message | Action on the protocol task |
|---------|------------------------------|
| `server/hello` | Records server info on the connection and sets `server_hello_received_` |
| `server/time` | Claims the connection's `client/time` frame in flight, dropping a reply that answers none, and writes the measurement to `time_slot` |
| `server/state` | Writes the controller, metadata, and color `InboxSlot`s |
| `server/command` | Merges into the player's `command_slot` |
| `group/update` | Merges into `group_slot` |
| `stream/start` | Player writes the codec header into an item it acquires from the inbound ring (a bounded wait) and appends it to the sync task's list, then writes its params slot and pushes STREAM_START; visualizer appends a clear marker to its list, writes its config slot, and pushes STREAM_START; artwork marks its stream active and discards the pending image of each channel whose configuration changed |
| `stream/end` | Pushes STREAM_END events for each streaming role and signals the sync task |
| `stream/clear` | Visualizer appends a clear marker to its list and pushes STREAM_CLEAR; player signals the sync task and appends a clear marker to its list |
| Player audio (binary) | `PlayerRole::Impl::handle_binary()` charges the chunk's ring item to the player's quota and appends it to the sync task's list (a reassembled chunk is first copied into an item); over quota it is dropped with a warning |
| Artwork (binary) | `ArtworkRole::Impl::handle_binary()` accumulates the image and, when complete, notifies the decode thread |
| Visualizer (binary) | `VisualizerRole::Impl::handle_binary()` hands the frame's ring item to the drain thread the same way, against the visualizer's quota; the drain thread dates it from the transport's receive stamp |

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

`ConnectionManager` sends `client/init` once the WebSocket upgrade completes: at once for an inbound connection, on the next tick for an outbound one. msg1 names the PSK to use by `psk_id` and category, and `RecordStore::resolve_by_psk_id()` resolves it on the protocol task (connection.md "Pre-Shared Key"):

- `lt`: a long-term record from a completed pairing, bound to its `server_id`
- `pr`: the Pairing PSK, from the config, persistence, or generated at first start
- `sn`: the published Sentinel PSK, which authenticates nothing

A lookup miss in the initial handshake completes with the Sentinel PSK (connection.md "Sentinel Fallback"); a miss during a re-handshake fails it. The resolved category is stored on the connection. It decides which activations the connection may be admitted with (`src/admission.h`, messaging.md "server/activate") and, once admitted, the client's `ConnectionTrust`.

### Transport

Once active, each Noise frame carries `[type byte][payload]` in one binary WebSocket frame, and a message too large for one frame is split into `MSG_TYPE_FRAGMENT` frames (messaging.md "Fragmentation"). `MSG_TYPE_JSON_BODY` marks JSON, and every other type is a binary role message.

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

The new long-term record must resolve for the re-handshake that immediately follows, so the `server/pair-finalize` handler commits it to `RecordStore` in RAM on the protocol task. The persistence provider is main-loop-only, so the durable write is staged through `persist_slot` and performed by the next tick's `flush_pending_persistence()` (in `ConnectionManager::loop()` or `drain_inbox()`), or by the client destructor if it comes first, before `on_pairing_succeeded` fires. Every other change to persisted state (an unpair, a playback handoff) takes the same route: the RAM half runs where the change is decided, often under `conn_ptr_mutex_`, and `request_persist()` leaves the provider write to `flush_pending_persistence()`, which holds no lock and runs once `ConnectionManager::loop()` has dropped its own. The pairing-code methods (CPace) follow the same main-loop state-machine shape in `ConnectionManager`.

## Connection Lifecycle

### Slots

| Slot | Purpose |
|------|---------|
| `current_connection_` | The admitted connection; holds only connections that became operational |
| `nursery_` | Unproven connections (inbound or outbound) awaiting establishment, bounded by `MAX_NURSERY_ENTRIES` |

Both hold `std::shared_ptr<SendspinConnection>`. On the ESP server path these are observers; see [Server Connection Ownership (ESP)](#server-connection-ownership-esp).

### Handshake and Admission

1. A new connection enters the nursery and sends `client/init`: from the transport thread for an inbound connection, from the main loop's connected-event pass for an outbound one. The rest of the Noise handshake runs on the protocol task as messages arrive.
2. Once transport is active, the main loop's hello scan sends `client/hello`.
3. The connection is operational once both hellos are exchanged and its first `server/activate` arrives, in either order. That activate is checked against the connection's trust when it is processed, and a rejected one closes the connection.
4. The next promotion scan establishes the operational connection, arbitrating against the incumbent, mainly by highest activity (playback over pairing over none); `should_admit_connection()` in `src/admission.h` has the full rules.
5. The loser's inbound gate is detached and it is sent a goodbye through the deferred-release queue; client state is cleaned up only when the loser is the incumbent.

A server sends role traffic right behind its `server/activate`, a tick before promotion admits the connection. The connection holds that JSON (bounded by `MAX_HELD_MESSAGES` / `MAX_HELD_BYTES`). `SendspinClient::admit_connection()` sets the admitted flag and wakes the protocol task, which replays the held messages in arrival order (`replay_admitted_messages()`) before the connection's next message. The first `client/state` is also held until admission, because it opens the server's binary traffic for the roles, and binary messages arriving before admission are dropped rather than held. Admission runs after `ConnectionManager` drops its lock, to keep the library's lock order (`docs/conventions.md`). The persistence writes the lifecycle handlers decide on run there too, so a slow flash commit never holds the lock the protocol task and transports need.

A later `server/activate` can remove roles. Each removed role runs the same `cleanup()` a lost connection runs, but the inbox ring is not reset, since the roles that stay active keep their queued events; the `cleanup_generation` stamp drops the removed role's stale ones instead. Nothing is restarted when an activation adds the role back: its role thread never stopped, so it returns through the `client/state` that activation publishes and, for a stream role, the next `stream/start`.

### Current Time Filter Slot

Role threads convert server timestamps through `SendspinClient::is_time_synced()` and `get_client_time()`: the sync task per chunk, the visualizer drain thread per frame. Both resolve the current connection's `SendspinTimeFilter` through `ConnectionManager::current_time_filter()`, which reads a slot of its own (`current_time_filter_`, under the leaf `time_filter_mutex_`) rather than `conn_ptr_mutex_`, which main-loop sections hold across blocking work such as an application send. `set_current_connection()` writes the slot, so it always names the current connection's filter.

Each getter reads the slot once, so a caller that checks `is_time_synced()` and then calls `get_client_time()` can see two different connections across a server handoff. A drop or handoff commands the stream to end before it changes the slot, so the sync task leaves the stream before transferring such a chunk; `ConnectionManager::stop()` empties the slot before the role threads stop, and the 0 an empty slot returns reads as late.

### Client Start and Stop

`SendspinClient::start()` validates the pairing config, creates the `RecordStore` and identity, loads persisted state, creates the inbound ring (sized by `derive_inbound_ring_bytes()` from the player's and visualizer's quotas, the pass-through traffic that arrives while the player holds its oldest chunk (state JSON, time-burst replies and visualizer frames), and the artwork images that window carries), starts the threaded roles with it, starts the protocol task, and opens `ConnectionManager` for admission. The WebSocket server itself starts on a later `loop()` once the network is ready.

`SendspinClient::stop()` is synchronous and ordered so that every producer is gone before any state is reset:

```api
0. lifecycle_ = STOPPING (loop() becomes a no-op; start/stop/connect_to/disconnect are
   refused or ignored, so a callback fired below cannot recurse into the teardown)
1. Signal the visualizer and artwork threads to stop, without joining. The player is not
   signalled yet: it keeps returning the ring items it plays, so a transport waiting for ring
   space is not parked behind a stopped consumer
2. ConnectionManager::stop(): close admission, snapshot the pairing-UI flags, detach every
   connection's inbound gate, send goodbyes with a bounded wait, stop the ws_server
   (joining its transport threads), and release every managed connection outside the locks
3. ProtocolTask::stop(): one final tick, then the join; the losses it reported for connections
   step 2 already released are dropped
4. Join all role threads; each then returns its items to the ring or discards its queue
   content, and the emptied inbound ring is released
5. cleanup_connection_state(), then queue the pairing-UI dismissals the step 2 snapshot calls for
6. drain_inbox() delivers the CLEARED / STREAM_END callbacks and pairing notes step 5 queued
7. lifecycle_ = STOPPED
```

The client destructor performs steps 1 and 2 and releases any outstanding high-performance hold, but dispatches no teardown or clear callback; the roles' destructors then join their threads, so listeners must outlive the client.

### Server Connection Ownership (ESP)

On ESP, a `SendspinServerConnection`'s lifetime belongs to its httpd session rather than to `ConnectionManager`:

1. `SendspinWsServer::open_callback` creates the `shared_ptr` and stores a heap-allocated copy as the session context, with a `free_fn` that deletes it. That copy is the authoritative reference.
2. `ConnectionManager::on_new_connection()` receives the same `shared_ptr`; its nursery entry keeps a copy as an observer.
3. The WebSocket handler looks the connection up through the session context each time it runs. Queued send workers capture a `weak_ptr` and lock it when they run, rather than a socket number, which httpd can reuse for a different session after the original closes.
4. On close, httpd calls `close_fn`, which marks the connection's inbound gate closed and wakes the protocol task; the task reports the loss, so `ConnectionManager` drops its observer, once the messages the session delivered before closing are processed. httpd calls `free_fn` once no worker is queued for the session.

On host, IXWebSocket callbacks hold a `weak_ptr` to the connection the manager accepted and lock it per message, so this scheme is not needed.
