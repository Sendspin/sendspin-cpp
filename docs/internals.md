# Sendspin-cpp Internals

This document describes the internal architecture of the sendspin-cpp library, focusing on threading, inter-class communication, and the ordering guarantees that keep everything correct.

## Pimpl Architecture

Each role class uses the pimpl (pointer to implementation) pattern. The public header (`include/sendspin/<role>_role.h`) exposes only the consumer-facing API: protocol types, the listener interface, and a thin role class with `struct Impl; std::unique_ptr<Impl> impl_;`. All private state, internal methods, and thread-management code live in a private impl header (`src/<role>_role_impl.h`) and the corresponding `.cpp` file.

`SendspinClient` is a `friend` of each role class, giving it access to `impl_->` for internal dispatch (message routing, event draining, lifecycle management). The `SyncTask` holds a `PlayerRole::Impl*` directly (passed at init time), so it accesses player state without indirection through the public `PlayerRole` class.

Throughout this document, internal field and method references use the `Impl` qualification (e.g., `PlayerRole::Impl::drain_events()`) to reflect the actual code location.

## Thread Model

The library uses a small number of long-lived threads. All state mutations and user-facing callbacks happen on the caller's main loop thread unless explicitly noted otherwise.

### Threads

| Thread | Name | Created by | Stack (ESP) | Priority (ESP) | Purpose |
|--------|------|-----------|-------------|-----------------|---------|
| **Main loop** | (caller's) | User code | - | - | Drives `SendspinClient::loop()`. All role event processing and listener callbacks run here. |
| **Sync task** | `Sendspin` | `PlayerRole::Impl::start()` → `SyncTask::start()` | 6192 B | 2 | Decodes audio, synchronizes to server timestamps, writes PCM to the audio sink via `on_audio_write`. |
| **Visualizer drain** | `SsVis` | `VisualizerRole::Impl::start()` | 4096 B | 2 | Reads visualization frames from a ring buffer and delivers them to the listener at the correct playback time. |
| **Artwork decode** | `SsArt` | `ArtworkRole::Impl::start()` | 4096 B | 2 | Receives image notifications and calls the decode callback. Hands the server display timestamp off to the main loop, which fires the display callback at the correct time. |
| **Network** | (library-internal) | IXWebSocket (host) or esp_http_server (ESP) | - | - | WebSocket I/O. Callbacks fire on these threads and must defer work to the main loop. |

On host builds, `platform_configure_thread()` is a no-op; threads use OS defaults. On ESP-IDF it calls `esp_pthread_set_cfg()` to set stack size, priority, name, and optional PSRAM allocation before the `std::thread` is constructed.

### Thread Lifecycle

**Sync task** (`src/sync_task.cpp:620`):

1. `SyncTask::start()` configures the thread and spawns it.
2. The caller blocks until the thread reaches IDLE state (`TASK_IDLE` event flag) or exits early due to an allocation failure (`TASK_STOPPED`).
3. The thread runs a persistent outer loop for the lifetime of the client.
4. `SyncTask::stop()` sets `COMMAND_STOP` and joins the thread. Called from `SyncTask`'s destructor, which is triggered by `sync_task_.reset()` in `PlayerRole::Impl`'s destructor.

**Visualizer drain** (`src/visualizer_role.cpp:120`):

1. `VisualizerRole::Impl::start()` spawns the drain thread.
2. The thread blocks on ring buffer receives with a 50 ms timeout.
3. `VisualizerRole::Impl` destructor sets `COMMAND_STOP` and joins.

**Artwork decode** (`src/artwork_role.cpp`):

1. `ArtworkRole::Impl::start()` spawns the decode thread.
2. The thread blocks on notification queue receives with a 100 ms timeout.
3. On notification: calls `on_image_decode()`, then writes the server display timestamp into a per-slot `ShadowSlot<int64_t>` (`DisplayScheduler::pending[slot]`). The main loop's `ArtworkRole::Impl::drain_events()` fires `on_image_display()` once the timestamp is reached. Latest-wins per slot: if a newer frame's timestamp overwrites the pending one before the main loop takes it, only the newer display fires.
4. `ArtworkRole::Impl` destructor sets `COMMAND_STOP` and joins.

**Destruction order** matters because external audio callbacks may still reference the sync task. `PlayerRole::Impl`'s destructor resets the sync task first (`sync_task_.reset()`) before tearing down anything else, so the thread is fully joined before any shared state is destroyed.

## Synchronization Primitives

All primitives are abstracted in `src/platform/` with ESP-IDF (FreeRTOS) and host (std::mutex/condition_variable) implementations.

### EventFlags (`src/platform/event_flags.h`)

Atomic bit flags with blocking wait. Used for thread lifecycle control:

```api
COMMAND_STOP         (1 << 0)   Stop the thread
COMMAND_STREAM_END   (1 << 1)   End current stream
COMMAND_STREAM_CLEAR (1 << 2)   Clear all buffered audio
COMMAND_START        (1 << 3)   Main loop acknowledged stream start
TASK_RUNNING         (1 << 8)   Actively decoding
TASK_STOPPED         (1 << 10)  Thread has exited
TASK_ERROR           (1 << 11)  Allocation or decode failure
TASK_IDLE            (1 << 12)  Waiting for work
```

The sync task, visualizer drain thread, and artwork decode thread all use event flags for command signaling from the main loop and status reporting back. The artwork decode thread and visualizer drain thread use a simpler subset: `COMMAND_STOP` and `COMMAND_FLUSH`.

### ThreadSafeQueue (`src/platform/thread_safe_queue.h`)

Fixed-depth FIFO queue with timed send/receive. Used to defer events from network threads to the main loop:

| Queue | Depth | Data | Producer | Consumer |
|-------|-------|------|----------|----------|
| `PlayerRole::Impl::stream_queue` | 8 | `PlayerStreamCallbackType` | Network thread | Main loop (`drain_events`) |
| `PlayerRole::Impl::state_queue` | 4 | `SendspinClientState` | Sync task thread | Main loop (`drain_events`) |
| `Client::time_queue` | 16 | `TimeResponseEvent` | Network thread | Main loop (`loop`) |
| `ArtworkRole::Impl::notify_queue` | 8 | `ArtworkNotification` | Network thread | Artwork decode thread |
| `ArtworkRole::Impl::queue` | 8 | `ArtworkEventType` | Network thread | Main loop (`drain_events`) |
| `VisualizerRole::Impl::queue` | 8 | `VisualizerEventType` | Network thread | Main loop (`drain_events`) |

### ShadowSlot (`src/platform/shadow_slot.h`)

Single-slot state container with "latest wins" or custom merge semantics. The network thread writes or merges; the main loop takes the accumulated value:

| Shadow Slot | Data | Merge Strategy |
|-------------|------|----------------|
| `Client::shadow_group` | `GroupUpdateObject` | Field-by-field delta merge |
| `PlayerRole::Impl::shadow_stream_params` | `ServerPlayerStreamObject` | Latest wins |
| `PlayerRole::Impl::shadow_command` | `ServerCommandMessage` | Field-by-field merge (volume, mute, delay independent) |
| `ControllerRole::Impl::shadow` | `ServerStateControllerObject` | Latest wins |
| `MetadataRole::Impl::shadow` | `ServerMetadataStateObject` | Field-by-field delta merge |
| `ArtworkRole::Impl::display_scheduler->pending[slot]` (×4) | `int64_t` (server display timestamp) | Latest wins |
| `VisualizerRole::Impl::shadow_config` | `ServerVisualizerStreamObject` | Latest wins |
| `SyncTask::playback_progress_slot_` | `PlaybackProgress` | Sum `frames_played`, keep latest `finish_timestamp` |

The merge strategy for `shadow_command` is important: if a volume change and a mute change arrive between two drain ticks, both are preserved because the merge function only overwrites fields that have values in the delta.

### SpscRingBuffer (`src/platform/spsc_ring_buffer.h`)

Single-producer/single-consumer ring buffer for variable-size binary data. Two-phase API: `acquire` → `commit` (producer), `receive` → `return_item` (consumer). Also supports a single-phase `send` for the producer.

Used for:

- **Encoded audio**: Via the `SendspinAudioRingBuffer` wrapper (which adds chunk headers and exposes `write_chunk` / `receive_chunk` / `return_chunk`). Network thread writes chunks; sync task reads and decodes them.
- **Visualizer frames**: Used directly. Network thread writes frame/beat entries; drain thread reads them at the correct playback time.

### Other Primitives

- **`std::mutex`** on `ConnectionManager::conn_mutex_`: protects deferred connection event vectors.
- **`std::mutex`** on `SendspinTimeFilter::state_mutex_`: protects Kalman filter state (offset, drift, covariance).
- **`std::atomic<bool>`** on `SendspinConnection::message_dispatch_enabled_`: allows the main loop to instantly suppress message delivery from the network thread.
- **`std::atomic<bool/uint8_t/size_t>`** on `VisualizerRole::Impl`: network thread writes stream config atomically; drain thread reads it.
- **`std::atomic<bool>`** on `ArtworkRole::Impl::stream_active`: guards `handle_binary()` from writing when no stream is active.
- **`std::atomic<uint8_t>`** on `ArtworkRole::Impl::SlotBuffer::write_idx`: tracks which of two double-buffers the network thread writes to next.
- **`std::atomic<bool>`** on `ArtworkRole::Impl::SlotBuffer::drain_active`: set by the decode thread while decoding, checked by the network thread to avoid overwriting an in-use buffer.
- **`std::atomic<uint8_t>`** on `SendspinClient::high_performance_ref_count_`: ref-counted high-performance networking requests from time sync and playback.

## Message Flow

### WebSocket Receive Path

```api
Network thread (IXWebSocket / esp_http_server)
  │
  ├─ Assembles fragmented WebSocket frames into complete messages
  │  (connection.cpp: prepare_receive_buffer_ / commit_receive_buffer_)
  │
  ├─ Checks message_dispatch_enabled_ atomic flag
  │  (returns immediately if disabled; used during teardown)
  │
  └─ Invokes callback on network thread:
     ├─ Text → SendspinClient::process_json_message_()
     └─ Binary → SendspinClient::process_binary_message_()
```

### JSON Message Dispatch (network thread)

`process_json_message()` (`src/client.cpp:457`) parses the message type and routes:

| Message | Action on Network Thread |
|---------|------------------------|
| `SERVER_HELLO` | Enqueues `ServerHelloEvent` into `ConnectionManager`'s mutex-protected vector |
| `SERVER_TIME` | Enqueues `TimeResponseEvent` into `time_queue` |
| `SERVER_STATE` | Writes to `ControllerRole::Impl::shadow` and `MetadataRole::Impl::shadow` |
| `SERVER_COMMAND` | Merges into `PlayerRole::Impl::shadow_command` |
| `GROUP_UPDATE` | Merges into `Client::shadow_group` |
| `STREAM_START` | Writes to `PlayerRole::Impl::shadow_stream_params`, enqueues `STREAM_START` into `stream_queue`. Marks the artwork stream active, flushes the decode thread's notification queue, and resets any pending per-slot display timestamps. Writes to `VisualizerRole::Impl::shadow_config`, enqueues a start event. |
| `STREAM_END` | Enqueues `STREAM_END` into player/artwork/visualizer queues, signals sync task `COMMAND_STREAM_END` |
| `STREAM_CLEAR` | Enqueues `STREAM_CLEAR` into player/artwork/visualizer queues, signals sync task `COMMAND_STREAM_CLEAR` |

### Binary Message Dispatch (network thread)

`process_binary_message()` extracts the type byte and routes:

| Binary Type | Handler |
|-------------|---------|
| Player audio | `PlayerRole::Impl::handle_binary()`: writes to encoded audio ring buffer |
| Artwork image | `ArtworkRole::Impl::handle_binary()`: copies image data to a per-slot double buffer and enqueues a notification for the artwork decode thread |
| Visualizer frame/beat | `VisualizerRole::Impl::handle_binary()`: writes to visualizer ring buffer |

### Main Loop Processing

`SendspinClient::loop()` (`src/client.cpp:148`) runs the following steps **in order** on each tick:

```api
1. connection_manager_->loop()
   ├─ Start WS server if network ready
   ├─ Swap deferred connection events under mutex
   ├─ Process close/disconnect events (on_connection_lost)
   ├─ Process hello events (handshake completion, handoff decisions)
   ├─ Call loop() on current and pending connections
   └─ Check hello retry timer

2. time_burst_->loop(conn)  (skipped when no current connection)
   ├─ Send next time message if ready
   ├─ Acquire/release high-performance networking around burst
   └─ Notify listener of sync error when burst completes

3. Drain time_queue
   └─ Feed time responses into time_burst_->on_time_response()

4. Role event draining (each role's impl_->drain_events())
   ├─ player_->impl_->drain_events()
   ├─ controller_->impl_->drain_events()
   ├─ metadata_->impl_->drain_events()
   ├─ artwork_->impl_->drain_events()
   └─ visualizer_->impl_->drain_events()

5. Drain shadow_group
   └─ Apply group deltas, fire on_group_update, persist last played server
```

This ordering matters: connection lifecycle events are processed before role events, and time sync before audio processing, so that roles always see a consistent connection and time state.

## Role Event Draining

Each role implements `drain_events()` to process its deferred events on the main loop thread. This is the mechanism that converts thread-safe queue/shadow writes into sequential, single-threaded callback delivery.

### PlayerRole::Impl::drain_events() (`src/player_role.cpp:341`)

Three stages, processed in order:

**1. Client state updates**: Drains `state_queue` (last value wins). Calls `client_->update_state()`.

**2. Server commands**: Takes from `shadow_command`. Checks each field independently (volume, mute, static_delay) and fires the corresponding listener callback.

**3. Stream lifecycle**: The most complex part:

```api
stream_queue → awaiting_sync_idle_events_ list
                       │
                       ▼
         For each event in order:
           ├─ STREAM_END or STREAM_CLEAR:
           │    If sync task is still running → STOP, wait for next tick
           │    If sync task is idle → fire callback, continue
           │
           └─ STREAM_START:
                Take shadow_stream_params
                Fire on_stream_start()
                Signal sync task COMMAND_START
```

The `awaiting_sync_idle_events` list (on `PlayerRole::Impl`) is the key ordering mechanism. STREAM_END/CLEAR callbacks are held until the sync task has reached its IDLE state, preventing the main loop from processing a new STREAM_START before the sync task has finished with the old stream. Events ahead of the blocked event also wait, preserving FIFO order.

### Other Roles

- **ControllerRole**: Takes from shadow, fires `on_controller_state()`.
- **MetadataRole**: Takes from shadow when the pending update's `timestamp` has been reached on the synced client clock (or immediately if time sync is not yet ready), applies deltas, fires `on_metadata()`.
- **ArtworkRole**: Drains event queue for stream end/clear lifecycle events first (resetting all per-slot pending display timestamps and firing `on_image_clear()` for each configured slot). Then iterates the per-slot `DisplayScheduler::pending` shadow slots and fires `on_image_display(slot)` for any slot whose pending timestamp is due on the synced client clock (or immediately if time sync is not yet ready). `on_image_decode` still happens on the dedicated artwork decode thread.
- **VisualizerRole**: Drains event queue, processes stream start/end/clear with shadow config.

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
│  │  • Wait for codec header (500ms)   │◄──┐              │
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
│  │  • Enqueue SYNCHRONIZED state      │                  │
│  │  • Decode initial codec header     │                  │
│  │  • Run inner state machine loop    │                  │
│  └────────────┬───────────────────────┘                  │
│               │ STOP/END/CLEAR                           │
│               ▼                                          │
│  ┌────────────────────────────────────┐                  │
│  │  Return borrowed ring buffer entry │──────→ loop back │
│  └────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────┘
```

The **WAIT FOR CLIENT ACK** step is critical. Without it, the sync task could race from IDLE back to ACTIVE so fast that the main loop never observes TASK_IDLE, and the `awaiting_sync_idle_events_` mechanism in `PlayerRole::drain_events()` would deadlock waiting for an idle transition that already passed.

### Inner State Machine (active stream)

```api
INITIAL_SYNC ──→ LOAD_CHUNK ──→ SYNCHRONIZE_AUDIO ──→ TRANSFER_AUDIO
     │                ▲               │                       │
     │                └───────────────┴───────────────────────┘
     │                        (cycle per chunk)
     └──→ LOAD_CHUNK (once first playback progress callback confirms frames were consumed)
```

**INITIAL_SYNC**: Fills the audio pipeline with silence to prime DMA buffers. Sleeps briefly after sending to let the audio stack start consuming.

**LOAD_CHUNK**: Reads the next encoded chunk from the ring buffer. Waits for time sync if not yet available. Decodes audio via FLAC/Opus/PCM decoder.

**SYNCHRONIZE_AUDIO**: Computes the sync error:

```cpp
error = decoded_timestamp - new_audio_client_playtime
```

Where `decoded_timestamp` is the server timestamp converted to client time (via Kalman filter) minus static and fixed delays, and `new_audio_client_playtime` is the predicted time that the next audio will actually play.

| Error Range | Action |
|-------------|--------|
| > +5000 us (or +500 us settling) | **Hard sync ahead**: insert silence frames to fill the gap |
| < -5000 us (or -500 us settling) | **Hard sync behind**: drop the decoded chunk |
| +100 to +5000 us | **Soft sync**: insert one interpolated frame (average of first two) |
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
- Adaptive forgetting: if the residual exceeds `2.0 * max_error`, the covariance is inflated by a forgetting factor (1.1) to recover from step changes.
- Drift compensation is only enabled after 100 samples and only when drift significance exceeds its noise floor.

The filter is protected by `state_mutex_` so that `compute_client_time()` can be called from the sync task thread while `update()` runs from the main loop thread.

## Connection Lifecycle

### Connection Management (`src/connection_manager.cpp`)

The `ConnectionManager` maintains up to three connection slots:

| Slot | Purpose |
|------|---------|
| `current_connection_` | Active connection receiving messages |
| `pending_connection_` | Handoff candidate completing its handshake |
| `dying_connection_` | Gracefully disconnecting (kept alive as shared_ptr until goodbye is sent) |

### Handshake and Handoff

1. A new connection (outbound or inbound) is started. If a current connection exists, the new one becomes `pending_connection_`.
2. The connection sends a CLIENT_HELLO. Retry with exponential backoff (100 ms base, 3 attempts).
3. SERVER_HELLO arrives on the network thread → enqueued into mutex-protected vector.
4. Main loop processes the hello event:
   - Stores server info on the connection.
   - If this was the pending connection, runs handoff decision logic:
     - Prefer PLAYBACK reason over DISCOVERY.
     - Among two DISCOVERY connections, prefer the last-played server.
     - Default: keep current.
5. Handoff executes: disable old message dispatch → cleanup state → move connections → send goodbye to the rejected connection.

### Disconnection and Cleanup

When a connection is lost (`on_connection_lost`):

```api
1. conn->disable_message_dispatch()      ← atomic, immediate on network thread
2. time_burst_->reset()                  ← stop time sync
3. client_->cleanup_connection_state()  ← drain all role queues/shadows, signal stream end
4. current_connection_.reset()           ← destroy connection
5. Promote pending to current if exists
```

`disable_message_dispatch()` is the first step because it's an atomic flag that the network thread checks before invoking any callback. This prevents stale messages from a dead connection from racing into freshly-reset role queues.

### Graceful Disconnect

`disconnect_and_release()` moves the connection into `dying_connection_` (as a `shared_ptr`) and sends a goodbye message with a completion callback. The callback sets a flag under the connection mutex, and the main loop's next tick destroys the connection. This two-phase approach prevents use-after-free when platform worker threads (e.g., ESP httpd) have pending work items referencing the connection.

## Ordering Guarantees Summary

### Network Thread → Main Loop

All network thread actions are deferred to the main loop via queues, shadow slots, or mutex-protected vectors. The main loop processes them in a fixed order each tick (connections → time → roles → group). This guarantees that:

- Connection state is settled before roles process events.
- Time sync is updated before audio sync decisions.
- Role events fire in FIFO order per role.

### Stream Lifecycle Ordering

The combination of `awaiting_sync_idle_events_` (main loop) and `COMMAND_START` (sync task wait) creates a two-way handshake:

1. Network thread enqueues STREAM_END → STREAM_START into `stream_queue`.
2. Sync task receives `COMMAND_STREAM_END`, finishes active stream, enters IDLE, sets `TASK_IDLE`.
3. Main loop sees STREAM_END in queue, checks `is_running()` → false (idle), fires `on_stream_end()`.
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
