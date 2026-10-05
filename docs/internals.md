# Sendspin-cpp Internals

This document maps how the library's parts work together: which threads exist, how state crosses between them, the order of one protocol-task tick and one `loop()` drain, and the invariants that span several files. It covers only facts that span files. Why a single function or member behaves as it does is documented at that function or member, and the protocol itself is specified by the Sendspin spec, cited here by section. The design rules new code must follow are in `docs/conventions.md`. How the library keeps audio in time with the server (clock sync and the sync task's alignment) is in `docs/playback-sync.md`.

## Code Organization

Each role class uses the pimpl pattern. The public header (`include/sendspin/<role>_role.h`) exposes the protocol types, the listener interface, and a thin role class holding `std::unique_ptr<Impl> impl_`; all private state and thread management live in `src/<role>_role_impl.h` and the role's `.cpp`. `SendspinClient` is a `friend` of each role class so it can dispatch into `impl_`. Internal references below use the `Impl` qualification (e.g. `PlayerRole::Impl::drain_events()`).

Roles are disabled at build time through two cooperating mechanisms. `cmake/sources.cmake` keeps a source list per role, so a disabled role's translation units are never compiled and its dependencies are never required; `#ifdef SENDSPIN_ENABLE_<ROLE>` guards in `include/sendspin/client.h`, `src/client.cpp` and `src/client_dispatch.cpp` (the protocol task's tick and message dispatch) remove the members, accessors, and dispatch branches that must name the role's type. The split exists because CMake cannot gate individual declarations, and `#ifdef` around whole files would still put the codec headers on the include path. On ESP-IDF the codec dependencies are gated by `idf_component.yml`'s Kconfig rules alone, because ESP-IDF collects `REQUIRES` before `sdkconfig` is loaded. The Opus decoder is a third gate inside the player role (`SENDSPIN_ENABLE_OPUS`), confined to `src/decoder.h`, `src/decoder.cpp`, and `src/player_role.cpp`.

Adding a role therefore means: a `SENDSPIN_<ROLE>_SOURCES` list in `cmake/sources.cmake`, the guarded member, accessor, and dispatch branches in `client.h`, `client.cpp` and `client_dispatch.cpp`, and any heavy dependency kept behind the role's private headers. A role-private header such as `src/decoder.h`, which pulls in the codec headers, may only be reached from the role's own sources or a guarded include in `client.cpp` or `client_dispatch.cpp`; public role headers stay codec-free because core files such as `src/protocol_messages.h` include them unconditionally.

## Thread Model

Listener callbacks fire on the caller's main loop unless noted otherwise. Connection state belongs to the protocol task.

| Thread | Name | Created by | Purpose |
|--------|------|-----------|---------|
| **Main loop** | (caller's) | User code | Drives `SendspinClient::loop()`, which only drains the Inbox: every role event, listener callback, high-performance request and persistence-provider write runs here. Calls `start()`/`stop()`. |
| **Protocol task** | `SsProto` | `ProtocolTask::start()`, from `SendspinClient::start()` | Owns every connection and the `ConnectionManager` slots: decrypt, Noise reassembly and handshakes, hello, activation, admission and role ownership, pairing, JSON and binary dispatch, time bursts, watchdogs, every send, and the consumer requests in its command queue and request slot. Every JSON document it parses or builds is allocated from the client's JSON arena (`SendspinArenaAllocator`, `src/platform/json_arena.h`), which no other thread touches (a controller command crosses the queue as its struct and is formatted here). `process_inbound()` resets it before each inbound message, the Noise handshake frames included, since ArduinoJson does not free a document in LIFO order and a parse strands its first key below its variant pool. The arena holds one document at a time: every parse on the task (the message dispatch, the Noise handshake frames, a msg1 payload) goes through `ParsedJsonMessage`, which copies the fields out and releases the document before anything acts on them, so the reply a handler builds never shares the arena with the parse that triggered it. Ticks on a wake or at its next deadline (`SendspinClient::protocol_tick()`, see [The Protocol Task's Tick](#the-protocol-tasks-tick)). Runs no single-precision float of its own, with one exposure: ArduinoJson's `parseNumber()` converts a JSON number with a fraction or an exponent through `float` even with `ARDUINOJSON_USE_DOUBLE`, and on ESP-IDF a task's first FPU instruction pins it to its current core for good (ESP-IDF's FreeRTOS notes on floating point). No protocol field carries such a number. A parse filter skips unknown fields without converting them, but cannot help for a field the library keeps, so a peer that sends such a number there pins the task; the library adds no core pinning of its own. |
| **Sync task** | `SsSync` | `SyncTask::start()` | Decodes audio, aligns it to server timestamps (`docs/playback-sync.md`), writes PCM via `on_audio_write`, and notes its return to idle to the main loop through the Inbox. |
| **Visualizer drain** | `SsVis` | `VisualizerRole::Impl::start()` | Delivers visualization frames from its item list at their playback time. |
| **Artwork decode** | `SsArt` | `ArtworkRole::Impl::start()` | Takes each image's announce, parts and discard markers from its item list, copies each part into the channel's assembly buffer and returns its item at once, parks a completed image there while the channel's gate holds an un-acked delivery, calls `on_image_decode()` for completed images, and hands the display deadline to the main loop. |
| **Transport** | (library-internal) | IXWebSocket (host); esp_http_server for inbound and esp_websocket_client for outbound connections (ESP) | WebSocket I/O only: receives each complete message into the shared inbound ring or the connection's fallback buffer, reports a close, delivers an upgraded inbound connection to the command queue, and wakes the protocol task. An outbound transport released while still connecting runs on until its attempt ends, its connection parked in `ConnectionManager`'s reaping list (see [Slots](#slots)). |

On ESP-IDF, `platform_configure_thread()` sets each thread's stack size, priority, and name before the `std::thread` is constructed; priorities come from the client and role configs in `config.h`. On host it is a no-op.

The three role threads share one lifecycle shape. `start()` clears every event flag and spawns the thread, so a restart inherits nothing from the previous run. The thread blocks on its item list, and a command wakes that wait at once: the sync task's through its own `EventFlags` and `wake_receiver()`, the visualizer's and artwork's through `InboundItemList::signal()`, since their command bits live on the list's flags. `stop()` sets `COMMAND_STOP`, wakes the take, joins, and only then returns the list's items to the ring, since after the join it is the sole consumer. `PlayerRole::Impl`'s destructor resets the sync task before anything else, so the thread is joined before any state the audio callbacks reference is destroyed. The protocol task has the same shape, with one difference: `ProtocolTask::stop()` lets the thread run one final tick before the join, so the commands queued and the requests posted before the stop are acted on.

## Cross-Thread State

The primitives other than the Inbox and the inbound ring live in `src/platform/`, with FreeRTOS implementations on ESP and `std::mutex`/condition-variable implementations on host. `docs/conventions.md` ("Threading and cross-thread state") says which to use when. Every channel between two threads:

| Channel | Producer | Consumer |
|---------|----------|----------|
| `InboundRing` (`src/inbound_ring.h`, see [The Inbound Ring](#the-inbound-ring)) | Transport threads, each admitted connection's messages; the protocol task, the items it writes itself (codec headers, artwork announces, markers, copied chunks and parts) | The protocol task, in arrival order; an item handed to a role is returned by that role's consumer thread |
| The player's `InboundConsumer` (`SyncTask::inbound_`) | Protocol task, appending the items it charges to the player's quota | Sync task, which takes and returns them; the protocol task recalls a torn-down stream's in the role's `cleanup()`, and the main loop the rest once the thread is joined |
| The visualizer's `InboundConsumer` (`DrainTask::inbound`) | Protocol task, against the visualizer's quota | Visualizer drain thread, likewise |
| The artwork role's `InboundConsumer` (`DrainTask::inbound`) | Protocol task: each image's announce, its parts (against the artwork quota) and the markers that discard a channel's pending image, in message order | Artwork decode thread, likewise; it returns each item as soon as it has copied it out |
| `InboundGate`, one per connection | The connection's transport: the fallback message in flight, the count of ring items not yet taken, the out-of-band close | The protocol task, which takes and consumes them and detaches the gate; the connection manager detaches it when the connection leaves it, from any thread |
| `ProtocolTask` command queue (`ProtocolCommand`) | Transport threads (accepts of upgraded inbound connections, in slots reserved per socket); any thread (controller commands, in `CONSUMER_COMMAND_BURST` slots, the push past them refused, each stamped with the controller's teardown generation it was validated under and dropped by the task if a teardown has moved it on since) | The protocol task; at `stop()`, the joining thread for what the final tick left |
| `ProtocolTask` state slot (`publish_state()`) | Main loop (`SendspinClient::publish_state()` and `start()`), latest-wins `client/state` | The protocol task |
| `ProtocolTask` request slot (`post_requests()`, `LifecycleRequests`) | Any thread, latest-wins and never refused: `connect_to()` (the latest URL), `disconnect()` (the latest reason, and it drops a waiting `connect_to()`), `leave()`, the pairing-window gestures (the later of a confirm and a cancel), unpaired-access changes | The protocol task; at `stop()`, the joining thread for what the final tick left |
| Role command bits (the sync task's `EventFlags`; the visualizer's and artwork's on their item list's flags, through `InboundItemList::signal()`) | The protocol task, or the main loop in `stop()` (`COMMAND_STOP`, `COMMAND_STREAM_END`, ...); the main loop (`COMMAND_START`) | The role's thread |
| Sync-task stream ordinals (`SyncTask::started_ordinal_`, `ended_ordinal_`) | The main loop's start acknowledgement; the protocol task's stream end | Sync task (see [Stream End and Start](#stream-end-and-start)) |
| Sync-task status bits (`TASK_RUNNING`, `TASK_IDLE`, `TASK_STOPPED` in its `EventFlags`) | Sync task | Main loop (`is_running()` gates a held STREAM_END), and the thread in `start()` waiting for IDLE |
| Artwork `SlotGate`s (`DrainTask::slot_gates`, under `slot_mutex`) | Artwork decode thread (arms a gate, parks a complete image); main loop (presents, acks, drops a park at a stream end) | Each other |
| `ShadowSlot` (sync-task playback progress) | The consumer's audio thread (`notify_audio_played()`) | Sync task |
| `Inbox` (`src/inbox.h`, see [Inbox](#inbox)) | Protocol task, sync task, artwork decode thread | Main loop |
| `ConnectionManager` published primary slot (time filter and server information) | Protocol task (`refresh_published_state()`) | Any thread (`time_filter()`, `server_information()`) |
| Each connection's `SendspinTimeFilter` | Protocol task (its burst's measurements) | Sync task and visualizer drain thread, converting timestamps |
| `RecordStore` | Protocol task (resolves and changes records) | Main loop (writes them to the provider) |

Plain atomics carry the rest: the `connected_` flag on `ConnectionManager`; the admission flag `accepting_` on `ProtocolTask`, written on the main loop under the queue lock; the unpaired-access setting, the lifecycle state and the high-performance grant count (`high_performance_granted_`, see [One Main Loop Drain](#one-main-loop-drain)) on `SendspinClient`; and each role's teardown generation (`cleanup_generation`), written by the protocol task and read by the main loop and the role's thread. The role- and connection-local atomics (a connection's last-arrival stamp, upgrade flag and time-frame write time; artwork's `stream_active` and slot epochs, the visualizer's `spectrum_bin_count`, `tracks_downbeats` and `boundary_sequence`, the player's output delay, the controller's supported commands) each state their writer and reader at their declaration.

### Locks

Every library lock is a leaf: it is held only to copy or update its own state, never across a call that takes another library lock, a send, a listener or the persistence provider, so no two library locks are ever held at once and there is no lock order. The locks are the Inbox's `mutex_`; the inbound ring's own (`SharedRingBuffer::mtx_` on host, the FreeRTOS ring's internal lock on ESP); each `InboundItemList::mutex_`; `ProtocolTask::command_mutex_` (the command queue, the state slot and the request slot); `ConnectionManager::published_mutex_` (which also serialises the role threads' `time_filter()` reads behind `server_information()` copies); each `SendspinTimeFilter::state_mutex_`; `RecordStore::mutex_`; the artwork role's `DrainTask::slot_mutex` (its ack gates, between the decode thread and the main loop); each `ShadowSlot::mutex_`; the ESP server's `SendspinWsServer::pending_mutex_`; and, on host, the mutex inside `EventFlags`. Connection state has no lock at all: only the protocol task touches it, except the transport's own atomics, which state their writer and reader at their declaration.

### The Inbound Ring

One `InboundRing` serves every admitted connection, created by `start()` whatever roles are enabled. A transport receives each complete message of an admitted connection straight into an item it acquires; the protocol task decrypts it in place and either dispatches it and returns the item at once (JSON, time replies, an artwork announce or cancel) or hands the item itself to a role's consumer thread through that role's item list (a player audio chunk, a visualizer frame, an artwork image part), which returns it when done. An unadmitted connection never writes the ring: it delivers one message at a time through its fallback buffer (`InboundGate`), so an unauthenticated peer cannot pin ring space.

Space is reclaimed in ring order, so everything received while the oldest held item is out stays allocated until it returns. Each holder's outstanding items are charged to its own `InboundQuota` on the protocol task, all but the codec headers, artwork announces and stream markers the task writes itself: a role over its quota has the new item dropped and returned with a warning, and the other holders keep flowing. `derive_inbound_ring_bytes()` (`src/inbound_ring.h`) sizes the ring from the quotas, the pass-through traffic that arrives during the longest hold (state JSON, time-burst replies, and visualizer frames behind held audio), the artwork images that window carries, and a baseline every configuration pays of two of the longest messages the enabled roles need in one item, which is also its floor: a JSON message (`INBOUND_JSON_MESSAGE_BYTES`), the longest chunk the player's and the visualizer's advertised buffers allow, or a maximal Noise frame with artwork. A message longer than the ring takes (`InboundRing::max_message_bytes()`) goes through the connection's fallback buffer, in order behind the ring items the connection wrote before it. The buffer each stream role advertises is capped at the ring's largest item (see `PlayerRole::Impl::advertised_buffer_capacity()`).

The same ordering bounds the control traffic. Everything an admitted connection receives goes through the ring, the control messages (`stream/end`, `server/activate`, the pairing messages) and the `server/time` replies included, and while the oldest audio chunk or visualizer frame a role holds, or an artwork part waiting for the decode thread to copy it, is out, they have only the pass-through allowance the derivation budgets for that hold: the state JSON at `INBOUND_STATE_BYTES_PER_SECOND` and the time bursts at the configured cadence. Once it is used up (a sync task stalled in `on_audio_write()`, a server far over the buffer it was advertised, a visualizer stream sparser than its `rate_max`, or control traffic well above that rate), a message finds no room within `INBOUND_ACQUIRE_TIMEOUT_MS` and the transport closes the connection at once, on host and ESP alike, with the warning `No inbound ring space for a <len>-byte message within <timeout> ms: ring pinned behind held items (<held> bytes held); closing the connection` (`SendspinConnection::route_inbound_message()`). A message routed to the fallback buffer closes it the same way when the previous one is still unconsumed after the same bound (`Fallback buffer still holds the previous message after <timeout> ms; closing the connection for a <len>-byte message`, `SendspinConnection::route_to_fallback()`). Neither message can be dropped and the connection kept: the Noise receive nonce counts every frame, so a frame never decrypted leaves the connection unable to authenticate the next one. The protocol task reports the loss once, as for any transport close.

### Inbox

The Inbox is a single-mutex mailbox with a lock-free dirty-topic bitmask. It offers two endpoint styles: a fixed-capacity event ring for ordered lifecycle events, and `InboxSlot<T>` latest-value slots for state, each owning one `INBOX_TOPIC_*` bit. The main loop calls `poll()` to read the bitmask without locking and only locks to drain topics whose bit is set; a bit set after the snapshot stays set, so the next drain sees it. It is the only way work reaches the main loop: `loop()` runs `drain_inbox()` and nothing else, and the only state it reads to find work outside the Inbox is each role's teardown generation, loaded once per drain for the catch-up that heads it (see [One Main Loop Drain](#one-main-loop-drain)).

Every role state slot is a `GenerationSlot<T>`: each payload carries the stamp its producer passes, the role's teardown generation it was admitted under, and the slot keeps the newest generation's content; it is the same stamp the role's ring events carry (see [Cleanup](#cleanup)). The player's `sync_idle_slot` is a plain `InboxSlot`: it carries no state, only the wake.

| Endpoint | Topic bit | Producer |
|----------|-----------|----------|
| Event ring | `INBOX_TOPIC_EVENTS` | Protocol task (stream events, and the `*_CLEARED` event each role's `cleanup()` pushes); the main loop in `stop()` once the task is joined |
| `SendspinClient::EventState::time_sync_slot` | `INBOX_TOPIC_TIME` | Protocol task (the primary connection's completed time burst) |
| `SendspinClient::EventState::group_slot` | `INBOX_TOPIC_GROUP` | Protocol task (`group/update` from the primary connection) |
| `SendspinClient::EventState::persist_slot` | `INBOX_TOPIC_PERSIST` | Protocol task (`server/pair-finalize`, an unpair, a playback activate, a last-played change); main loop (`start()`) |
| `SendspinClient::EventState::pairing_slot` | `INBOX_TOPIC_PAIRING` | Protocol task (pairing and trust notes); main loop (`stop()`'s dismissals) |
| `SendspinClient::EventState::high_performance_slot` | `INBOX_TOPIC_HIGH_PERFORMANCE` | Protocol task (time-burst acquires and releases, counted separately) |
| `ControllerRole::Impl::EventState::slot` (generation-stamped) | `INBOX_TOPIC_CONTROLLER` | Protocol task |
| `MetadataRole::Impl::EventState::slot` (generation-stamped) | `INBOX_TOPIC_METADATA` | Protocol task |
| `ColorRole::Impl::EventState::slot` (generation-stamped) | `INBOX_TOPIC_COLOR` | Protocol task |
| `PlayerRole::Impl::EventState::stream_params_slot` (generation-stamped) | `INBOX_TOPIC_PLAYER_STREAM_PARAMS` | Protocol task |
| `PlayerRole::Impl::EventState::command_slot` (generation-stamped) | `INBOX_TOPIC_PLAYER_COMMAND` | Protocol task |
| `PlayerRole::Impl::EventState::sync_idle_slot` | `INBOX_TOPIC_PLAYER_SYNC_IDLE` | Sync task (returned to idle from a stream) |
| `VisualizerRole::Impl::EventState::config_slot` (generation-stamped) | `INBOX_TOPIC_VISUALIZER_CONFIG` | Protocol task |
| `ArtworkRole::Impl::EventState::display_slot` (generation-stamped) | `INBOX_TOPIC_ARTWORK_DISPLAY` | Artwork decode thread |

## The Protocol Task's Tick

`SendspinClient::protocol_tick()` runs whenever the task is woken (a command, a state snapshot, a lifecycle request, an inbound ring item, a transport close, a new pending upgrade) and when its own next deadline passes. Each tick runs these steps in order:

```api
1. The lifecycle requests posted since the last tick (apply_lifecycle_requests()): an
   unpaired-access change, the pairing-window gesture, leave, disconnect, then connect_to, all
   dropped once admission is closed (a connect_to and a disconnect resolve by call order: one
   posted after a disconnect is kept and applied after it, one before it is dropped); then the
   commands, in queue order (handle_command()): accepts into the nursery, or refused with a
   shutdown goodbye once admission is closed; controller commands, dropped once admission is
   closed or when a teardown has moved the controller's generation past the stamp the command
   was validated under. Requests go before the commands queued in the same window, so a send
   queued before a disconnect finds its connection dropped, while an accept queued before it
   still enters the nursery: a disconnect addresses the connections it finds, not a newcomer
2. Once admission is closed: the shutdown pass (ConnectionManager::shutdown())
3. The newest client/state snapshot, sent to every admitted connection; its availability
   gates player audio in step 5
4. client/init on outbound connections whose WebSocket upgrade completed
5. The receive pass over a snapshot of the managed connections: each connection's message
   pending in its fallback buffer once the ring items it wrote before it are taken, then up to
   MAX_ITEMS_PER_TICK ring items in arrival order
6. Losses: a connection whose gate is detached (by a close of the receive path, a failed send
   or a release) or whose close is ready is dropped (ConnectionManager::on_connection_lost()); a
   fallback message the ring items just taken held back makes the tick run again at once
7. ConnectionManager::tick(): the nursery's hello sends, the promotion of operational nursery
   connections, the establish reap; the admitted connections' liveness, re-prove and
   pairing-attempt watchdogs; the pairing window's expiry; the reap of released outbound
   connections whose transport closed or opened, or whose deadline passed; the platform server's
   upgrade reap; the WebSocket server start once the network is ready
8. ConnectionManager::run_time_sync(): each admitted, operational connection's time burst, and
   the client/state that waited for its first measurement
9. Losses from the sends of steps 7 and 8: a connection a failed send detached is dropped, as in
   step 6, before anything is published
10. ConnectionManager::refresh_published_state(): the published primary slot (time filter and
    server information); then publish_connected(), the connected flag other threads read,
    raised only here, after every handler of the tick, so is_connected() never reads true
    before the tick's whole effect (the published slots and the events it queued for the
    drain); a loss lowers it at once
```

The tick returns the milliseconds until the earliest of its timers: a nursery entry's establish deadline, an admitted connection's liveness, re-prove or pairing-attempt deadline, the pairing window, a released outbound connection's reaping deadline, a pending upgrade on the ESP server, the WebSocket server retry or network poll (`NETWORK_POLL_INTERVAL_MS`), and each time burst's next send or response timeout. With none pending it returns `ProtocolTask::NO_DEADLINE` and the task waits for a wake alone; a receive pass stopped by its item bound, or one that freed a held-back fallback message, returns 0 and runs again at once. No timer is periodic except the network poll, which runs only while the server is down, so an idle admitted connection wakes the task for its time bursts (one deadline per `time_burst_interval_ms`, then one wake per reply) and its inbound traffic. Every handler a message reaches runs inside step 5, so an activation is applied, and a nursery connection that it makes operational admitted, before the connection's next message is parsed.

## One Main Loop Drain

`SendspinClient::loop()` is a no-op while the client is stopped. While started, each call runs `drain_inbox()`, which `stop()` also calls once so teardown callbacks are delivered synchronously:

```api
1. Each role catches up to its current teardown generation (catch_up_teardown()): one
   acquire load per role
2. High-performance requests: every acquire, the grant for them, then every release
3. The time-sync report: on_time_sync_updated()
4. The inbox event ring; each event's role first catches up on the teardown the event is
   stamped with (catch_up_teardown())
   ├─ *_CLEARED → the catch-up alone: the role's main-loop half delivers its clear
   └─ PLAYER/ARTWORK/VISUALIZER_STREAM → a current event's handler, after the catch-up
5. Take the pairing and trust notes, then perform the provider writes owed since the last
   drain (flush_pending_persistence(), which polls for itself)
6. Dispatch the notes taken in step 5, grouped by type
7. Role drains: each role's impl_->drain_events(), gated on impl_->needs_drain(slot_bits)
8. Drain group_slot: apply deltas, fire on_group_update
```

Step 1 is what still runs a teardown's main-loop half, and delivers its clear, when the full event ring dropped its stamped `*_CLEARED`. It can only run a half earlier, never apply anything: a payload is applied only when its stamp is the current generation, and the events and role drains after it catch up again at the stamp they act on. The steps gate on two `poll()` snapshots: one before the ring drain (steps 2 to 4) and one after it (steps 6 to 8), which catches bits set while the ring was draining. Provider writes run after the notes are taken and before they are dispatched, so `on_pairing_succeeded` finds the record committed: the protocol task requests the write before it queues the note. Pairing notes follow the event ring, so a role's clear can be delivered ahead of a note queued before it: the two never describe the same listener state, and the one ordering between them that matters, the provider write ahead of `on_pairing_succeeded`, is step 5. Roles whose pending work waits on a deadline rather than on a new message (the metadata and color roles' future-dated state, artwork's held displays) add a carry-over term to `needs_drain()`, since no inbox bit tracks that wait; the player's STREAM_END held for the sync task waits instead for `sync_idle_slot`, which the sync task writes each time it returns to idle from a stream.

The high-performance hold is a ref-counted request, surfaced to the consumer through `on_request_high_performance()` / `on_release_high_performance()`, for the platform to keep networking responsive (e.g. disable WiFi power saving) during time sync and playback. A time burst requests it through `high_performance_slot` when it comes due, and sends its first time frame only once the main loop has granted that request: step 2 calls the listener for every acquire it took, then adds them to `SendspinClient::high_performance_granted_` and wakes the protocol task, which compares the burst's ticket against that count (`high_performance_granted()`). Acquires and releases are counted separately, so an acquire and a release queued inside one stalled tick (a connection dropped before its grant) still reach the listener as a request followed by its release. Releases wait for nothing. The player holds the same ref count from its drained STREAM_START to its STREAM_END on the main loop.

Every role drain in step 7 has the same head: it takes its slot first, catches the role up on its current teardown generation (`catch_up_teardown()`), then applies the taken payload only if its stamp is still the current generation, dropping a stale one with a debug log. Controller, metadata, and color then fire their state callback, metadata and color holding a future-dated state until its server-clock timestamp. Artwork folds its displays into its holds and fires `on_image_display()` when each deadline passes. The player's drain is the main loop's half of the stream end/start handshake (see [Stream End and Start](#stream-end-and-start)). Visualizer has no drain; it is driven entirely by its ring events, its STREAM_START applying the config written with the same stamp, and by its teardown catch-up.

## Ordering Guarantees

### Protocol Task to Main Loop

Protocol-task work bound for the main loop crosses through the Inbox only, and is delivered in the fixed drain order above. A transport close reaches the protocol task out of band: the transport marks its connection's `InboundGate` closed and wakes the task, and the task drops the connection once nothing it received is left untaken, so the messages before a close are dispatched before it. An upgraded inbound connection reaches the task as an accept in the command queue. Connection state is settled on the protocol task before any role event it produces is queued, and role events fire in FIFO order per role.

### Stream End and Start

`stream/end` followed by `stream/start` crosses three threads, and a two-way handshake keeps them in order. Every `stream/start` the player serves gets the next stream ordinal (`PlayerRole::Impl::stream_ordinal`), which numbers both its codec header item and its STREAM_START event:

1. On `stream/end` the protocol task signals the sync task `COMMAND_STREAM_END` with the ordinal of the latest stream it started (`signal_stream_end()`), then pushes STREAM_END as a `PLAYER_STREAM` event onto the inbox ring; on `stream/start` it appends the numbered codec header to the sync task's item list, then pushes the STREAM_START carrying the same ordinal.
2. The sync task finishes the stream and returns to IDLE, clearing `TASK_RUNNING`. A codec header numbered no later than the ended ordinal is discarded when the sync task takes it, so a header whose end overtook it is never started; a later header it takes while the ended stream is still ACTIVE is kept for IDLE rather than decoded into that stream.
3. The main loop moves the ring events into `awaiting_sync_idle_events`. It holds STREAM_END, and everything behind it, until `SyncTask::is_running()` reads false, then fires `on_stream_end()`. While it holds, the drain runs again only when the sync task writes `sync_idle_slot` on its way back to idle.
4. The main loop fires `on_stream_start()` and acknowledges the event's ordinal (`signal_stream_start()`, which sets `COMMAND_START` as the wake).
5. The sync task, which has been holding the codec header since it took it (WAIT FOR CLIENT ACK in `docs/playback-sync.md`), goes ACTIVE once the acknowledged ordinal reaches the header's.

Stream events the main loop drains together still end each stream before the next starts, however the sync task interleaved with them: every codec header the task takes is either discarded (its stream ended), held for its own acknowledgement, or decoded into the stream still active, which is only ever its own stream or one it changes the format of. An acknowledgement for an earlier stream than the header the sync task holds, or one that finds no header pending (the task took that stream's header, met its end and returned it), is stale: the sync task notes idle for it, which releases the STREAM_END the main loop holds behind that start, and the held header waits for its own acknowledgement.

Signalling before pushing is what lets the `is_running()` gate in step 3 release only an end the sync task has already been told to honour. Step 5's wait is what makes step 3 safe: without it the sync task could pass through IDLE and back to ACTIVE before the main loop ever observed it not running, and the held STREAM_END would wait forever. `stream/clear` does not use this path; it signals the sync task directly and appends a marker item to its list, and the sync task discards up to the marker without leaving the stream, keeping its codec header: ACTIVE, or still in WAIT FOR CLIENT ACK.

The hold in step 3, and step 4, run in `PlayerRole::Impl::drain_events()`, which first applies any current server command (volume, mute, output delay), then walks `awaiting_sync_idle_events`:

```api
PLAYER_STREAM ring events → on_stream_ring_event() → awaiting_sync_idle_events
                       │
                       ▼
         For each event in order:
           ├─ STREAM_END:
           │    Sync task still running → wait for next tick
           │    Sync task idle → fire on_stream_end() if a stream is open, continue
           │
           └─ STREAM_START:
                Take stream_params_slot (applied if its stamp is current)
                Mark stream active, fire on_stream_start()
                Acknowledge the event's ordinal to the sync task
```

### Cleanup

When a connection leaves the admitted array, `detach_inbound()` runs first. It detaches the connection's `InboundGate`: its transport drops what it receives from then on, and the protocol task checks the flag before processing each of the connection's messages. Every handler runs on the protocol task, so none of the connection's messages is mid-dispatch while it is dropped. Items a stream role holds for the torn-down stream go back to the ring in the role's own teardown, below.

`cleanup_connection_state()` then tears down the roles no remaining admitted connection owns, on the protocol task. When that is every role it also resets the inbox ring and the group and time-sync slots, and drops the pending pairing notes other than a dismissal whose prompt an earlier drain delivered. Each role's teardown is split in two halves, with a `TeardownTracker` (`src/teardown_tracker.h`) on each role recording which teardowns the main loop has caught up with:

- The protocol-task half, the role's `cleanup()`, bumps its `cleanup_generation`, resets its Inbox slots, signals its thread, and pushes its `*_CLEARED` event stamped with the new generation. Everything the role queues from then on, events and slot payloads alike, carries the new generation. A teardown runs on the protocol task between two handlers, or from `stop()` once that task is joined, so a role handler loads the generation once at entry, runs whole under it and does not check it: the stamp is for the main loop and the role threads, which take what the handler queued on either side of a later teardown.
- The main-loop half, the role's `complete_teardown()`, resets what only the main loop touches (the player's held stream events and playback high-performance hold, the controller, metadata and color state, artwork's held displays) and delivers the role's clear: the controller, metadata and color clear callbacks, artwork's `on_image_clear()` for every channel, the visualizer's `on_visualizer_stream_end()`, and the player's STREAM_END, which it queues in `awaiting_sync_idle_events` for the drain to fire once the sync task reads idle. `catch_up_teardown()` runs it once per teardown generation: at the head of every drain, from the event drain before the main loop acts on an event stamped with a newer generation, and from each role drain before it applies a slot payload. A role drain takes its slot first and only then catches up to the role's current generation, so a payload the next connection wrote right after the teardown is applied after the clear, never wiped by it, and a payload from the torn-down connection, stamped with the older generation, is dropped instead of applied after its clear. The controller's supported-commands mask carries the same stamp, so `send_command()` reads a torn-down connection's mask as empty, and the command it queues carries the stamp it passed under, so a teardown between the check and the protocol task's drain drops the command there.

The player's, the visualizer's and the artwork role's `cleanup()` also return what the sync task, the visualizer drain thread or the artwork decode thread has not taken, right after the generation bump and on the thread that hands the items over (`InboundConsumer::recall()`), so every item recalled carries an older stamp; a consumer that takes such an item between the bump and the recall returns it, by its stamp, without acting on it. The visualizer's `cleanup()` also moves its boundary sequence on (see the `stream/end` row under [Dispatch](#dispatch-protocol-task)), so its drain thread returns a frame it holds for its delivery time. The artwork decode thread, woken by its `cleanup()`, also drops the images it assembles or parks once it sees the generation move on. A role removed by a `server/activate` takes the same path. In `stop()` the role threads are joined and their lists returned and unbound (`InboundConsumer::unbind()`) before the main loop runs the roles' `cleanup()`, whose recall then finds no ring bound.

### Re-entrant Teardown During Callback Dispatch

Requests a listener callback makes (`connect_to()`, `disconnect()`, ...) are queued or posted to the protocol task, so no callback tears a connection down under the drain that fired it. `stop()` is the exception: called from a callback, it joins the protocol task, tears every role down on the main loop and runs a drain of its own beneath the one that fired the callback, and a `start()` that follows it in the same callback begins a new run. Two generation counters keep the outer drain from acting on what it already took:

- `drain_generation` (on the client's `EventState`) is bumped by `stop()` before its teardown. The outer drain snapshots it once and stops as soon as it changes: the event ring between events, the pairing-note dispatch between notes, and the role drains and the group update before each starts.
- Each role's `cleanup_generation` is bumped by its `cleanup()` and stamped onto every event and slot payload it queues afterwards; the ring drain drops stream events whose stamp no longer matches (`event_is_current()`). Inside a role drain the same counter catches a callback that re-entered teardown: the player checks it after each server-command callback and around each `on_stream_start()` and `on_stream_end()`, metadata and color after applying the earlier of two taken states, and artwork after each display or clear, and each abandons the rest of its work when it moved on.

## Message Flow

### Receive Path

Encryption is mandatory, so every application message arrives as a binary Noise frame and is routed by the first byte of its decrypted plaintext. Text frames carry only the pre-transport handshake.

```api
Transport thread (IXWebSocket / esp_http_server / esp_websocket_client)
  │
  ├─ Admitted connection: receives the message straight into an InboundRing item
  │  (waits up to INBOUND_ACQUIRE_TIMEOUT_MS for room, else closes the connection with a
  │  warning: see The Inbound Ring); a message longer than the ring takes
  │  (InboundRing::max_message_bytes()) goes to the fallback buffer, waiting the same bound
  │  for the previous one to be consumed, else closing the connection the same way; a
  │  detached connection's messages are dropped (the ESP server drains each frame into a
  │  discard buffer sized to the longest message a conforming server sends,
  │  InboundRing::largest_message_bytes(), and closes on a longer one)
  ├─ Unadmitted connection: receives into its fallback buffer and publishes it as the one
  │  pending message (waits up to InboundGate::WRITABLE_WAIT_MS for the previous one, else
  │  closes); a message over InboundGate::PRE_ADMISSION_MESSAGE_BYTES closes
  ├─ A message split across WebSocket frames is assembled in the fallback buffer, then copied
  │  into a ring item (admitted) or published (unadmitted)
  └─ wakes the protocol task
         │
Protocol task: SendspinClient::protocol_tick()
  ├─ per connection: its pending fallback message, once its earlier ring items are taken
  └─ ring items in arrival order
     → both through SendspinClient::process_inbound() → SendspinConnection::process_inbound_message()
     ├─ detached connection → dropped (teardown guard)
     ├─ Text frame → handshake driver only (server/init, noise/handshake)
     └─ Binary frame → Noise transport active?
        ├─ no  → refused
        └─ yes → decrypt in place, reassemble Noise-level fragments (copied)
                 └─ SendspinClient::process_inbound() dispatches on the plaintext type byte:
                    ├─ MSG_TYPE_JSON_BODY → SendspinClient::process_json_message()
                    └─ other → SendspinClient::process_binary_message(), which hands
                       a player, visualizer or artwork part message over in its ring item
```

### Dispatch (protocol task)

Role-bound traffic reaches a role only from the admitted connection that owns it (`ConnectionManager::owns_role()`); ownership implies the role is active on that connection. Artwork binary messages are the exception: they reach the role from any admitted connection unless another one owns it, so the role's malformed-message checks run. Establishment and pairing traffic is handled for any managed connection (see [Handshake and Admission](#handshake-and-admission)).

| Message | Action on the protocol task |
|---------|------------------------------|
| `server/hello` | Records server info on the connection and sets `server_hello_received_` |
| `server/activate` | `ConnectionManager::on_server_activate()`: trust and pairing-method checks, role ownership and removals, and admission of a nursery connection the activation makes operational |
| `server/time` | Claims the connection's `client/time` frame in flight, dropping a reply that answers none, and feeds the measurement to the connection's own time burst |
| `server/state` | Writes the controller, metadata, and color `InboxSlot`s |
| `server/command` | Merges into the player's `command_slot` |
| `group/update` | Merges into `group_slot`, from the primary admitted connection only |
| `stream/start` | Player writes the codec header, numbered with the stream's ordinal, into an item it acquires from the inbound ring (a bounded wait) and appends it to the sync task's list, then writes its params slot and pushes STREAM_START; visualizer moves its boundary sequence on (below), writes its config slot, and pushes STREAM_START; artwork marks its stream active, discards the pending image of each channel whose configuration changed, and appends a marker naming those channels to its decode thread's list |
| `stream/end` | Pushes STREAM_END events for each streaming role, signals the sync task with the ordinal the stream ended, recalls the visualizer's listed frames and moves its boundary sequence on (`VisualizerRole::Impl::signal_boundary()`; every stream command and `cleanup()` do both, and the drain thread returns the frame it holds), and appends a marker for every channel to the artwork decode thread's list |
| `stream/clear` | Visualizer moves its boundary sequence on (see `stream/end`) and pushes STREAM_CLEAR; player signals the sync task and appends a clear marker to its list |
| Pairing messages, `pair/abort`, `server/unpair` | The pairing state machine and record revocation in `ConnectionManager` |
| `server/pair-finalize` | Commits the pending record to `RecordStore` in RAM and queues the provider write |
| Player audio (binary) | Discarded while the adopted client/state snapshot reports the client unavailable (`SendspinClient::adopted_state_available()`), so the gate flips with the `client/state` the tick sends; otherwise `PlayerRole::Impl::handle_binary()` charges the chunk's ring item to the player's quota and appends it to the sync task's list (a reassembled chunk is first copied into an item); over quota, or too short for its header, it is dropped with a throttled warning |
| Artwork (binary) | `ArtworkRole::Impl::handle_binary()` checks the transfer sequence and hands the decode thread an announce item, then each part in its ring item, charged to the artwork quota (a reassembled part is first copied into an item); a cancel, a refused image or a part dropped over quota hands a marker that discards the channel's pending image instead |
| Visualizer (binary) | `VisualizerRole::Impl::handle_binary()` hands the frame's ring item, stamped with the boundary sequence (see `stream/end`), to the drain thread the same way, against the visualizer's quota (a frame too short for its timestamp is dropped with the same throttled warning); the drain thread dates it from the transport's receive stamp |

## Noise Encryption

Every connection is encrypted with Noise KKpsk2; the library is always the responder.

### Handshake

```api
Client -> Server: client/init   (client_id, version, cipher suite)
Server -> Client: server/init   (server_id, cipher suite)
Server -> Client: noise/handshake msg1 (Noise KKpsk2 initiator message)
Client -> Server: noise/handshake msg2 (Noise KKpsk2 responder message)
-- transport active from here --
Server -> Client: server/hello  (encrypted, server name, source codec set)
Client -> Server: client/hello  (encrypted, device info, pair_methods)
Server -> Client: server/activate (encrypted, activities, active_roles)
```

`ConnectionManager` sends `client/init` once the WebSocket upgrade completes: when the accept is taken for an inbound connection, on the next tick for an outbound one. msg1 names the PSK to use by `psk_id` and category, and `RecordStore::resolve_by_psk_id()` resolves it on the protocol task (connection.md "Pre-Shared Key"):

- `lt`: a long-term record from a completed pairing, bound to its `server_id`
- `pr`: the Pairing PSK, from the config, persistence, or generated at first start
- `sn`: the published Sentinel PSK, which authenticates nothing

A lookup miss in the initial handshake completes with the Sentinel PSK (connection.md "Sentinel Fallback"); a miss during a re-handshake fails it. The resolved category is stored on the connection. It decides which activations the connection may be admitted with (`src/admission.h`, messaging.md "server/activate") and, once admitted, the client's `ConnectionTrust`.

### Transport

Once active, each Noise frame carries `[type byte][payload]` in one binary WebSocket frame, and a message too large for one frame is split into `MSG_TYPE_FRAGMENT` frames (messaging.md "Fragmentation"). `MSG_TYPE_JSON_BODY` marks JSON, and every other type is a binary role message.

A send that fails from the encrypt on leaves the peer unable to authenticate any later frame: `NoiseTransport` refuses every later send before its encrypt (`is_send_desynced()`), and the connection closes itself without a goodbye (`SendspinConnection::settle_noise_send()`). The detached gate is the loss report: the tick drops the connection in step 6 for a send of steps 1 to 5 and in step 9 for one of steps 7 and 8. A send refused before its encrypt spends nothing and leaves the connection up. A release detaches the gate before its goodbye, so a failed goodbye closes nothing twice. The ESP server writes on its httpd worker after the send returns, so a write that fails there closes the connection from the worker, reported through `close_callback`.

The server may start a new handshake inside the transport at any time (connection.md "Re-handshake"). The connection swaps its `NoiseSession` once msg2 is written, then goes non-operational until the next `server/activate`; until then the client sends no application message, and a watchdog drops a connection that is never re-activated.

### Pairing

A `server/activate` declaring the `pairing` activity starts a pairing attempt on the protocol task, alongside any playback (pairing.md "Entering and leaving pairing"). For the Pairing PSK method:

```api
Server -> Client: server/activate (activities=["pairing"], method=pairing_psk)
Client -> Server: client/pair-init
Client -> Server: client/pair-finalize (long-term PSK)
Server -> Client: server/pair-finalize
Server -> Client: noise/handshake msg1 (re-keying onto the new long-term PSK)
Client -> Server: noise/handshake msg2
Server -> Client: server/activate (normal operational flow)
```

The new long-term record must resolve for the re-handshake that immediately follows, so the `server/pair-finalize` handler commits it to `RecordStore` in RAM on the protocol task. The persistence provider is main-loop-only, so the durable write is staged through `persist_slot` and performed by the next drain's `flush_pending_persistence()`, or by the client destructor if it comes first, before `on_pairing_succeeded` fires. Every other change to persisted state (an unpair, a playback handoff, the last-played server) takes the same route: the RAM half runs on the protocol task where the change is decided, and the provider write is left to `flush_pending_persistence()` on the main loop, so a slow flash commit never stalls connection work. The pairing-code methods (CPace) run their state machines in `ConnectionManager` on the protocol task too.

## Connection Lifecycle

### Slots

Every slot belongs to the protocol task; nothing else reads or writes it.

| Slot | Purpose |
|------|---------|
| `admitted_` | The admitted connections, `MAX_ADMITTED` entries (one today), each with the roles it owns (`AdmittedEntry`) |
| `nursery_` | Unproven connections (inbound or outbound) awaiting establishment, bounded by `MAX_NURSERY_ENTRIES` |
| `reaping_` | Released outbound connections whose transport may still be connecting, bounded by `REAPING_CAPACITY` (`ReapEntry`) |
| `closing_` | Connections the shutdown pass took out of the slots and closed, kept for `finish_stop()` to release |

All hold `std::shared_ptr<SendspinConnection>`. On the ESP server path these are observers; see [Server Connection Ownership (ESP)](#server-connection-ownership-esp). The other holders of a connection reference are the protocol task's per-tick snapshot (`snapshot_connections()`), an accept waiting in the command queue, and the ESP platform server (the httpd session slot, the owner on ESP). No reference leaves the protocol task for a consumer or role thread: what they read about the connection goes through the published slots.

An outbound connection's destructor joins its transport, which for one still connecting waits out the rest of the connect. So the protocol task never drops a released outbound attempt still connecting itself: every release of one (a `disconnect()`, a `connect_to()` replacing the pending attempt, the establish reap, a displaced or lost connection that never opened) closes its transport without blocking, which leaves the attempt to end on its own (`close_transport_now()` on each platform says why), and parks it in `reaping_`. The reap pass in the tick drops it once its inbound gate reports the transport closed or its upgrade completes, when the join is short, or at its deadline (`SendspinClientConnection::CONNECT_TIMEOUT_MS` after the release); a release that finds the list full drops the entry parked longest instead, and in those two cases the join is bounded by what remains of the connect. On ESP that includes the DNS lookup, which `CONNECT_TIMEOUT_MS` does not cover: lwIP's resolver gives up on a server after 7 s and tries each configured one (`CONFIG_LWIP_DNS_MAX_SERVERS`, 3 by default), so a drop at the deadline can hold the protocol task for up to about 21 s behind a stalled lookup. A connection whose upgrade had completed is released in place: the protocol task pays its destructor's stop of an open transport, on ESP up to the websocket task's one-second read poll on an idle socket, and a goodbye release has already stopped it synchronously, usually at once since the peer closes on the goodbye. `finish_stop()` closes and drops what is still parked on the main loop, which pays those joins.

Every role this client drives has at most one owner among the admitted connections. Ownership gates role dispatch, the routing of role messages (controller commands) and the role objects of each connection's `client/state`. A connection owns the roles it activates that no other admitted connection owns (`claimable_roles()`); arbitration runs only when a newcomer wants a role an admitted connection owns, or when no slot is free (`admission_conflicts()`). The primary admitted connection, the owner of the player or else the first admitted one, is the one whose clock, server information and group the client reports. With one slot every role is owned by the one admitted connection; raising `MAX_ADMITTED` admits connections that share the roles between them.

### Handshake and Admission

1. An inbound connection is delivered by the platform server once its WebSocket upgrade completes, as an accept in the command queue; the protocol task takes it into the nursery and sends `client/init`. An outbound connection enters the nursery from `connect_to()` and sends `client/init` once its upgrade completes. The rest of the Noise handshake runs on the protocol task as messages arrive.
2. Once transport is active, the nursery scan sends `client/hello`.
3. The connection is operational once both hellos are exchanged and its first `server/activate` arrives, in either order. That activate is checked against the connection's trust when it is processed, and a rejected one closes the connection.
4. The activation handler admits a connection the activation makes operational before it returns (the nursery scan covers a hello that completes after the activation), arbitrating against the admitted connections it conflicts with, mainly by highest activity (playback over pairing over none); `should_admit_connection()` in `src/admission.h` has the full rules.
5. A losing newcomer is released with a goodbye; a displaced incumbent is dropped, and the roles no remaining connection owns are torn down.

Because the activation is applied before the connection's next message is parsed, the role traffic a server sends right behind its `server/activate` finds the connection admitted and owning its roles. The first `client/state` goes out from the admission itself; it opens the server's binary traffic for the roles, so it is never sent to a connection that is not admitted yet.

A later `server/activate` can remove roles. Each removed role runs the same `cleanup()` a lost connection runs, but the inbox ring is not reset, since the roles that stay active keep their queued events; the `cleanup_generation` stamp drops the removed role's stale ones instead. Nothing is restarted when an activation adds the role back: its role thread never stopped, so it returns through the `client/state` that activation publishes and, for a stream role, the next `stream/start`.

### Time Filter Slot

Role threads convert server timestamps through `SendspinClient::is_time_synced()` and `get_client_time()`: the sync task per chunk, the visualizer drain thread per frame. Both resolve the primary admitted connection's `SendspinTimeFilter` through `ConnectionManager::time_filter()`, which reads the `PublishedPrimary` slot (`published_`, under the leaf `published_mutex_`) and never waits on the protocol task. `refresh_published_state()` writes that one slot, holding both the filter and the server information, whenever the primary connection changes, so it always names the primary connection's filter; a role thread holding the filter never holds the connection, whose destructor can join a transport thread.

Each getter reads the slot once, so a caller that checks `is_time_synced()` and then calls `get_client_time()` can see two different connections across a server handoff. A drop or handoff commands the stream to end before it changes the slot, so the sync task leaves the stream before transferring such a chunk; the shutdown pass empties the slot before the role threads stop, and the 0 an empty slot returns reads as late.

### Client Start and Stop

`SendspinClient::start()` validates the pairing config, creates the `RecordStore` and identity, loads persisted state, creates the inbound ring whatever roles are enabled, since every admitted connection receives into it, the time replies included (see [The Inbound Ring](#the-inbound-ring)), starts the threaded roles with it, publishes the first `client/state` snapshot, opens `ConnectionManager` for admission (starting the WebSocket server at once when the network is already up, otherwise the protocol task starts it once it is), and starts the protocol task. An accept the server delivers before the task starts waits in the command queue.

`SendspinClient::stop()` is synchronous and ordered so that every producer is gone before any state is reset:

```api
0. lifecycle_ = STOPPING (loop() becomes a no-op; start/stop and every request that queues a
   command or posts a request are refused or ignored, so a callback fired below cannot recurse
   into the teardown)
1. Signal the visualizer and artwork threads to stop, without joining. The player is not
   signalled yet: it keeps returning the ring items it plays, so a transport waiting for ring
   space is not parked behind a stopped consumer
2. ConnectionManager::close_admission(), which closes admission under the queue lock
   (ProtocolTask::close_accepts()): a delivery from here on is refused at its push, on the
   delivering thread, and its transport closes it without a goodbye
3. ProtocolTask::stop(): the final tick acts on the commands queued and the requests posted so
   far (an accept already queued is refused with a shutdown goodbye) and runs the shutdown pass
   (snapshot the pairing-UI flags, detach every connection, goodbye and close each with reason
   shutdown), then the join
4. ConnectionManager::finish_stop(): close every released outbound connection still parked for
   reaping, stop the ws_server (joining its transport threads), release those connections and
   the ones the shutdown pass kept; then drop any command still queued and any request still
   posted
5. Join all role threads; each then returns its items to the ring, and the emptied inbound ring
   is released
6. Bump drain_generation, cleanup_connection_state() for every role (the protocol-task halves
   run here, on the main loop), then queue the pairing-UI dismissals the step 3 snapshot calls
   for
7. drain_inbox() runs each role's main-loop half (its clear; the player's on_stream_end()), the
   high-performance releases the shutdown pass queued, the owed provider writes, and the
   pairing notes step 6 queued, each exactly once: a dismissal step 6 queues beside one an
   earlier drop left pending is a coalesced note type, delivered once
8. lifecycle_ = STOPPED
```

The library's last reference to a connection is therefore dropped on the protocol task, or on the main loop in step 4 once the task is joined, never on a role thread. An ESP inbound connection, owned by its httpd session, is destroyed by its transport when the session is freed, and a host connection the client refused at delivery by its transport's open handler once the delivery has returned (see [Server Connection Ownership (ESP)](#server-connection-ownership-esp)). The client destructor performs steps 1 to 5 (the transport teardown, the role threads' join and the inbound ring's release), then drops the high-performance requests no drain applied (they were never granted, so the listener never heard them) and releases the holds the main loop applied, its only listener call; it dispatches no teardown or clear callback, and performs the provider writes still owed once the connection manager is gone. A role thread's callback can run until step 5 joins it, so listeners must outlive the client.

On the ESP server, each shutdown-pass `disconnect()` posts two messages to httpd's control socket (the queued goodbye and the close), so a stop with many peers posts a burst there that lwIP's UDP receive mailbox must hold; a stop with `server_max_connections` peers is on the on-device checklist.

### Server Connection Ownership (ESP)

On ESP, a `SendspinServerConnection`'s lifetime belongs to its httpd session rather than to `ConnectionManager`:

1. `SendspinWsServer::open_callback` creates the `shared_ptr` and stores a heap-allocated copy as the session context, with a `free_fn` that deletes it. That copy is the authoritative reference.
2. Once the upgrade completes, `ConnectionManager::on_new_connection()` receives the same `shared_ptr` on the httpd task and queues it as an accept; the protocol task's nursery entry keeps a copy as an observer. A refused accept (a full command queue, or admission closed) makes the server close the session, whose slot still owns the connection, so the refusal never destroys it on the httpd task.
3. The WebSocket handler looks the connection up through the session context each time it runs. Queued send workers capture a `weak_ptr` and lock it when they run, rather than a socket number, which httpd can reuse for a different session after the original closes.
4. On close, httpd calls `close_fn`, which marks the connection's inbound gate closed and wakes the protocol task; the task drops its observer once the messages the session delivered before closing are processed. httpd calls `free_fn` once no worker is queued for the session.

On host, IXWebSocket callbacks hold a `weak_ptr` to the connection the manager accepted and lock it per message, so this scheme is not needed. A connection the client refuses at delivery is closed and released by the open handler once the delivery has returned, so the refusal does not destroy it inside the delivery either; holding it until the socket's Close would only add a reference cycle through the WebSocket's own callback, since its destructor is trivial and the IX server owns the WebSocket.
