# Playback Sync

This document explains how the library keeps audio in time with the server: estimating the server's clock, and aligning decoded audio to it before it reaches the sink. Which thread owns what, and how the sync task coordinates with the main loop, is in `docs/internals.md`. Tuning constants are named here, not quoted; look their values up at the declarations.

## Clock Synchronization

Each connection owns one `SendspinTimeFilter` (`src/time_filter.h`), created once when the connection is set up and never replaced, and one `SendspinTimeBurst`. Only that connection's own measurements feed its filter: the protocol task hands a `server/time` reply to the burst of the connection it arrived on, and only when it answers that connection's `client/time` in flight. The role threads convert through the primary admitted connection's filter (`docs/internals.md`, "Time Filter Slot").

`SendspinTimeBurst` (`src/time_burst.h`) collects measurements in NTP-style bursts: `time_burst_size` `client/time` exchanges whose lowest-round-trip measurement goes to the filter, then a pause of `time_burst_interval_ms` until the next burst (both in `SendspinClientConfig`). The protocol task runs each admitted connection's burst while that connection is operational, and high-performance networking is held for its duration so the round trips are not inflated by power saving: the burst sends its first `client/time` only once the main loop has delivered the request to the listener (`docs/internals.md`, "One Main Loop Drain").

Each `client/time` round trip is timed from the socket write, not from the time the message carries: `SendspinConnection::send_time_message()` hands `NoiseTransport::send_json()` a hook that the transport runs immediately before writing the message's last frame, and the echoed `client_transmitted` only identifies the frame a `server/time` answers (`SendspinConnection::claim_time_frame()`). Recording the write time before the write, never after it, keeps every scheduling delay on the side that lengthens the measured round trip, which `max_error` reports and the burst's lowest-round-trip selection discards.

The filter is a two-state `[offset, drift]` Kalman filter, tuned by `SendspinTimeFilter::Config`. Drift is estimated from the second measurement on, but applied to time conversions only once it is statistically significant (`drift_significance_threshold`). Once `min_samples` measurements have accumulated, a residual larger than `adaptive_cutoff` times the measurement's round-trip error inflates the covariances, so the filter recovers quickly from a step change in the server's clock. Its `state_mutex_` lets the sync task and the visualizer drain thread convert timestamps while the protocol task updates it.

The filter's first measurement gates playback: the sync task decodes no audio until the clock is synced. While the player role is active, it also gates the client's `client/state` reporting `available: true` (messaging.md "client/state").

## Sync Task

The sync task (`SyncTask::thread_entry()`, `src/sync_task.cpp`) turns encoded chunks into PCM that plays at the server's timestamps. Its input is an `InboundItemList` of inbound ring items the protocol task appends to: each audio chunk is decoded in place from the ring item it was received and decrypted into, with its server timestamp read from plaintext bytes 1 to 8, and the item goes back to the ring once decoded. It runs a two-level state machine: an outer loop per stream, and an inner loop per chunk.

### Outer Loop

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
│  │  • Leaving a stream: note sync     │                  │
│  │    idle to the main loop's inbox   │                  │
│  │  • Reset context + progress slot   │                  │
│  │  • Wait for codec header (wake);   │◄──┐              │
│  │    a COMMAND_START with no header  │   │              │
│  │    pending is stale: loop back     │   │              │
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
│  │  • Decode initial codec header     │                  │
│  │  • Run inner state machine loop    │                  │
│  └────────────┬───────────────────────┘                  │
│               │ STOP/END                                 │
│               ▼                                          │
│  ┌────────────────────────────────────┐                  │
│  │  Return the held ring item         │──────→ loop back │
│  └────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────┘
```

The WAIT FOR CLIENT ACK step is the sync task's half of the stream end/start handshake with the main loop (`docs/internals.md`, "Stream End and Start"). A `COMMAND_START` that reaches the task while it waits for a header, with none pending, belongs to a stream the task already left (a `stream/start` and `stream/end` the main loop drained together): the task takes it as stale and loops back through IDLE, which clears it and notes the idle state the main loop's held STREAM_END waits for, so the next stream waits for its own start (except in the case `docs/internals.md`, "Stream End and Start", names as a gap).

### Inner Loop

```api
INITIAL_SYNC ──→ LOAD_CHUNK ──→ SYNCHRONIZE_AUDIO ──→ TRANSFER_AUDIO
     │                ▲               │  ▲                    │
     │                │               │  └────────────────────┤ (silence sent, chunk held back)
     │                └───────────────┴───────────────────────┘
     │                        (cycle per chunk)
     └──→ LOAD_CHUNK (once first playback progress callback confirms frames were consumed)

COMMAND_STREAM_CLEAR from any state → discard up to the clear marker → INITIAL_SYNC
```

- **INITIAL_SYNC** primes the audio pipeline with `INITIAL_SYNC_PRIMING_MS` of silence, then adds `extra_startup_silence_ms` (`PlayerRoleConfig`) of lead once the sink confirms it is consuming, so the decoder starts with slack ahead of the sink.
- **LOAD_CHUNK** takes and decodes the next encoded chunk once the clock is synced; a chunk already too late to play is discarded undecoded. While aligning (at stream start or after a seek) it feeds silence on an empty item list (`UNDERFLOW_SILENCE_KEEPALIVE_MS` at a time, in `src/sync_task.cpp`) to keep the sink fed; in steady state an empty list is left empty, so a stream winding down does not pile silence into the sink.
- **SYNCHRONIZE_AUDIO** compares the chunk's playback time, converted to the client clock and adjusted for the output delay and `fixed_delay_us`, with the time the next written audio will actually play. An error beyond `HARD_SYNC_THRESHOLD_US` is corrected at once (a hard sync): silence is inserted when the audio is early, and late audio is dropped. A smaller error beyond `SOFT_SYNC_THRESHOLD_US` is corrected gradually (a soft sync): one frame is added or removed per chunk. Errors inside that dead zone pass through unmodified. From stream start or a seek, and after any hard sync, the tighter `HARD_SYNC_SETTLE_THRESHOLD_US` applies until the error settles, and a hard sync outside alignment is logged as a loss of sync. These thresholds are in `src/sync_task.cpp`.
- **TRANSFER_AUDIO** writes the PCM through `on_audio_write`. When a hard sync inserted silence, it writes that first and then returns to SYNCHRONIZE_AUDIO to re-check the chunk it held back.

A `stream/clear` (a seek) keeps the stream ACTIVE: the inner loop discards encoded and already-decoded audio up to the clear marker the protocol task appended, keeps the decoder and playtime accounting, and re-enters INITIAL_SYNC, which resumes priming only if it had not finished and otherwise passes straight to LOAD_CHUNK. The next chunk then re-aligns under the alignment rules above.

### Playback Progress

The "will actually play" estimate is fed back from the audio sink. The consumer calls `notify_audio_played()` from its audio thread as frames are consumed; that merges into the sync task's playback-progress `ShadowSlot` (frame counts summed, latest finish timestamp kept), which the inner loop takes on every iteration, with only a brief lock on either side. The estimate is the last finish timestamp plus the duration of the frames still buffered in the sink, and its accuracy is what bounds the sync error the task can see.
