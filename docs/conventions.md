# Design Conventions

This document states the design standards that code in this repository is
held to.
It is normative: `docs/internals.md` maps how the current code fits together,
while this document describes how new code should be shaped. The review
checklists in `.claude/skills/` apply these standards to a diff.

## Threading and cross-thread state

- A transport thread is a pipe: it receives a complete message into the
  shared inbound ring (an admitted connection) or the connection's fallback
  buffer (an unadmitted one, or a message split across WebSocket frames),
  reports a close, delivers an upgraded inbound connection as an accept in the
  protocol task's command queue, and wakes the protocol task. Every connection
  belongs to the protocol task: the receive side (decrypt, reassembly, the
  handshake, dispatch, close handling), the lifecycle (hello, activation,
  admission, role ownership, pairing, watchdogs, time bursts) and every send
  run there, so no connection state needs a lock. Any other thread reaches a
  connection only by queueing a `ProtocolCommand`; a request that the full
  queue refuses is reported to the caller (`send_text()` returns false) or
  logged, never dropped silently. A connection refused at delivery is left with
  the transport that delivered it, which releases it after the delivery
  returns (on ESP, with its httpd session), so no refusal destroys a connection
  inside the delivery. Payload validation and
  decoding happen on the drain or worker thread that consumes the data, following the pattern the player and artwork
  roles establish; the protocol task hands audio and visualizer frames over in
  the ring item they arrived in rather than copying them.
- All main-loop-bound cross-thread state goes through the `Inbox`
  (`src/inbox.h`). `loop()` runs the Inbox drain and nothing else: do not add
  mutex-protected endpoints or atomics that `loop()` polls for work. The
  protocol task calls no listener, a role thread calls only the data-path
  callbacks `docs/integration-guide.md` names for it (`on_audio_write()` on
  the sync task, `on_image_decode()` on the artwork decode thread, the
  visualizer data callbacks on its drain thread), and only the main loop
  calls the persistence provider: everything else a consumer hears it hears
  from the main loop's drain. A thread that must wait for the main loop to
  have called a listener waits for a grant the drain publishes (the
  high-performance grant), never for the main loop itself.
- The Inbox event ring is for ordered lifecycle events only (stream start and
  end, cleared, connection events). Latest-wins state (player state, metadata,
  progress) belongs on a collapsing `InboxSlot`, never the ring: a flood of
  state updates must not be able to evict a lifecycle event.
- State published from one writer thread to one reader thread uses a
  `ShadowSlot` (`src/platform/shadow_slot.h`), whichever side (if either) the
  main loop is on. State the main loop *reads* goes through the Inbox instead.
  The values read by several threads without being consumed, the primary
  admitted connection's time filter and server information, sit in
  `ConnectionManager`'s own slots behind leaf mutexes (`time_filter()`,
  `server_information()`), written by the protocol task; a flag read the same
  way is a plain atomic.
- Event producers push through `push_event_or_log()` rather than hand-rolling
  the build, push, and log-on-drop sequence.
- A bounded queue or ring that drops an item never drops it silently: log at
  least a warning at the drop site. A site that can drop every message of a
  burst throttles it with `InboundDropLog`: one warning when the drops start,
  one with their count when they stop.
- An event or a slot payload whose delivery must not survive its producer
  being torn down carries the producer's teardown generation and is checked
  against it at the drain (`push_event_or_log()` / `event_is_current()` for
  events, `GenerationSlot` for a role's slots), rather than relying on the
  ring or the slot being reset: a teardown that leaves other producers running
  cannot reset it, and a drain can take a slot on either side of a teardown.
- Callback dispatch must tolerate re-entrant teardown: a listener callback may
  call back into the client. See "Re-entrant Teardown During Callback
  Dispatch" in `docs/internals.md` for the guard patterns in use.
- A message handler on the protocol task does the connection work the message
  calls for in place (an activation's trust check, admission and role
  ownership, a pairing step, a `noise/handshake` re-handshake, the RAM commit
  of a pairing record), and hands role and consumer work on through Inbox
  slots, role item lists and buffers. It never calls a listener or the
  persistence provider, and it does not wait on the main loop: those belong on
  the main-loop drain, and one connection's message must not delay every other
  connection's. The roles a teardown takes away are torn down in two halves:
  the protocol task resets what its handlers and the role threads reach and
  stamps the role's events and slot payloads with the new teardown generation,
  and the main loop runs the role's own half once per generation, through the
  role's `TeardownTracker` (`catch_up_teardown()`), before acting on anything
  stamped with it. A role drain takes its slot before it catches up, then
  applies only a payload stamped with the current generation.
- A protocol-task step has a bounded wait or none: the Noise DH operations, a
  ring acquire bounded by `INBOUND_ACQUIRE_TIMEOUT_MS`, a transport send
  bounded by the transport's own send timeout, and at shutdown the goodbye
  flush bounded by `GOODBYE_FLUSH_TIMEOUT_MS` per goodbye. Its tick returns the
  time to its earliest deadline, or `ProtocolTask::NO_DEADLINE`, and never
  wakes on a fixed period. A transport's wait on the task is bounded too: an
  admitted connection waits at most `INBOUND_ACQUIRE_TIMEOUT_MS` for ring space
  and drops the message with a warning, and an unadmitted one waits at most
  `InboundGate::WRITABLE_WAIT_MS` for its previous message to be consumed and
  is closed if it is not.
- Every library lock is a leaf: it is held only to copy or update its own
  state, never across a call that takes another library lock, a send, a
  listener or the persistence provider, so the library has no lock order to
  cite. The leaves are `ConnectionManager::time_filter_mutex_` and
  `server_info_mutex_`, `RecordStore::mutex_`, the Inbox mutex, each
  `SendspinTimeFilter`'s `state_mutex_`, the inbound ring's, item lists' and
  protocol task command queue's own locks, `GoodbyeWait`'s, the artwork role's
  slot mutex, `ShadowSlot`'s and the ESP server's pending-upgrade mutex. A
  change that would take a second library lock under one of them is a design
  change, not a local trade-off.

## Protocol validation

- Validation fails closed and uniformly. A malformed or missing required field
  rejects the whole enclosing object; do not silently default, clamp, or
  repair spec-invalid values. Log what was rejected and why.
- Sibling fields of the same object are validated to the same standard. If one
  field rejects on bad input, all of them do.
- Use the shared parsing helpers in `src/protocol.cpp` (for example
  `read_enum_field()`) instead of hand-rolled per-field logic.
- When two code paths serialize or parse the same structure, extract a shared
  helper so they cannot diverge.
- Behavior mandated by the Sendspin protocol spec is commented with the spec
  section it implements.

## Platform abstraction

- Core sources in `src/` contain no `#ifdef ESP_PLATFORM`. Platform
  differences live in `src/platform/`, `src/esp/`, and `src/host/`. Within
  the library, role compile-gates (`#ifdef SENDSPIN_ENABLE_*`) live only in
  `cmake/sources.cmake` and the dispatch points in
  `include/sendspin/client.h` / `src/client.cpp`, and the codec gate
  `SENDSPIN_ENABLE_OPUS` only in `src/decoder.h`, `src/decoder.cpp`, and
  `src/player_role.cpp`; consumers, including the examples, guard their own
  role and codec usage (see Public API).
- Logging uses the `SS_LOG*` macros; allocation uses the `platform_malloc`
  family with an explicit `MemoryLocation` choice where it matters.
- Code that only builds on one platform still keeps the other platform's build
  coherent: source lists, Kconfig, and CMake options stay in sync even when
  the change cannot be compiled locally for every target.

## Embedded resource discipline

- Stack is a measured budget, not a vibe. Large stack frames on paths
  reachable from ESP tasks (the httpd receive path, the protocol task, the sync task, `loop()`)
  are defects; when in doubt, measure with `-fstack-usage` on the target
  compiler at the shipped optimization level and record the numbers in the PR.
  Watch for aggressive inlining aggregating several frames into one.
- Hot paths (per audio chunk, per binary message, per visualizer frame) do not
  allocate. Reuse persistent buffers; size them once with a stated derivation.
- Buffer and queue capacities are justified numbers. Derive related constants
  from each other (`constexpr size_t X = Y / 4;`) so they cannot drift apart,
  and do not grow a budget without recording why.
- Flash matters: avoid log branches for unreachable conditions, duplicated
  format strings, and template instantiation bloat.
- Trivially copyable types are copied, not `std::move`d; heap-backed types
  (strings, vectors, buffers) are moved. Do not add moves that clang-tidy will
  correctly flag as pointless.
- Persistence writes (NVS on ESP) are coalesced and deferred; flash wear is a
  budget like any other.

## Public API

- The consumer-facing API is exactly `include/sendspin/`. Internal types,
  helpers, and headers stay in `src/` and never leak into public headers.
  Nothing appears in a public header solely for tests or internal plumbing.
- Configuration and commands are passed as structs with designated
  initializers, not growing lists of positional optional parameters.
- Contracts are documented and enforced by documentation, not by defensive
  code. If the header says a listener must be set before streaming, the
  library does not null-check the listener on every call; adding such checks
  obscures the contract. The inverse also holds: if a check exists in one of
  three sibling sites, either all three need it or none do.
- Deprecations carry both a `@deprecated` doc comment and a `[[deprecated]]`
  attribute, plus the version at which removal is planned. Breaking changes
  land before a release freezes the API, not after.
- Public headers document threading requirements (which thread may call what)
  at the declaration site.
- Examples are consumers too: they must build under every
  `SENDSPIN_ENABLE_*` combination, guarding role usage the same way an
  external consumer would.

## Consistency

- Reuse before invention: before writing a helper, guard, or pattern, look for
  the existing one. New roles copy the structure of the sibling role that
  already solves the same problem; if the sibling's pattern is wrong, fix it
  everywhere rather than diverging.
- A fix to a flagged pattern is complete only after the tree is swept for
  other instances of the same pattern.
- A change that substantially rewrites a region conforms any drifted
  patterns inside the touched region in the same PR, rather than carrying
  them forward because the old code already had them.
- Parallel code paths (stream start versus stream clear, one role's
  `client/state` object versus another's) stay structurally identical so a reader can diff them
  mentally. Deliberate asymmetry gets a comment at the asymmetric site
  explaining why, so nobody "fixes" it back.
- When two things must stay in sync at every call site, do not rely on care:
  create a chokepoint (a helper that updates both, a `std::optional` instead
  of a paired flag and value, a derived constant) so the invariant holds by
  construction.

## Testing

- Tests are host-only, white-box, and live in `tests/`; they include private
  headers from `src/` and run under ASan/UBSan in CI. The ESP-IDF side is
  covered by the build-only project in `tests/esp_idf/`.
- Production code in `src/` and `include/` acquires nothing for the sake of
  tests: no friends, test-only hooks, widened visibility, extra template
  parameters, injectable clocks or transports, or fixture-aware naming.
  Logic that is hard to reach is extracted into a pure static member or
  free function and tested directly; a timing decision becomes a predicate
  that takes `now` as an argument while the call site keeps reading the real
  clock.
- A test defends a specific production line or branch and fails when that
  line is deleted or its condition inverted. A test that cannot fail that
  way is filler and is deleted.
- The unit of a test is a behavior, not a branch. A family of related guards
  (the rejection cases of one parser, the rows of one admission table, the
  length checks of one function) is one table-driven test whose rows are the
  branches; a guard gets its own test only when it has its own spec citation
  or its own failure mode. Each table carries at least one accepting row as
  its control, marked `Control:`, so a rejection is distinguishable from
  rejecting everything. Controls live beside what they control, not as
  separate tests.
- Tests assert on outcomes, not on log wording. A guard whose only
  observable effect is a log line is covered by the test of the behavior it
  protects or not at all; a log substring is asserted only where the message
  is the documented contract.
- Tests assert on what a caller or peer can observe. Private state, queue
  contents, and which thread ran a step are reached only when no observable
  outcome distinguishes the correct path, and the test says so.
- Elapsed time is never a pass/fail condition. A blocked call is proven by
  waiting with no timeout, by a value only the correct path can produce, or
  by a structural failure; hangs are caught by the suite watchdog and the
  CTest timeout, not by per-test bounds.
- Fixtures satisfy production invariants rather than stubbing around them.
  Test doubles are hand-written fakes that record outcomes; the tree uses no
  gmock.
- Coverage that cannot be obtained without a production seam is named as a
  gap in the PR rather than approximated by a test that appears to cover it.

## Documentation

- Comments and docs describe the current state of the code. No history
  narration ("previously", "used to", "now uses"), no phase or porting
  language, and no references to PR numbers as rationale. Cite the Sendspin
  protocol spec by section when a behavior is spec-driven.
- Documentation drift is a defect. A change in behavior is not complete until
  every description of that behavior is updated in the same PR:

  | If the change touches...                  | Update...                                      |
  | ----------------------------------------- | ---------------------------------------------- |
  | Cross-file threading or lifecycle design  | `docs/internals.md`                            |
  | Clock sync or audio alignment             | `docs/playback-sync.md`                        |
  | Public API, config, listener contracts    | `docs/integration-guide.md` and header docs    |
  | Architecture, layout, conventions         | `CLAUDE.md`                                    |
  | Anything shown in usage examples          | `@code` blocks in headers, `examples/`, README |

- `docs/internals.md` holds only facts that span files: the thread model,
  cross-thread channels, the protocol task's tick and the `loop()` drain order,
  and invariants that hold
  across classes. Why a single function or member behaves as it does belongs
  in a comment at that function or member, and protocol behavior is cited
  from the spec rather than restated. Do not add test names or numeric
  constants there; point to the declaration that owns the value.
- `docs/playback-sync.md` explains the clock-sync and audio-alignment
  method under the same limits as `docs/internals.md`: it names tuning
  constants rather than quoting their values, adds no test names, cites the
  spec rather than restating it, and leaves per-function detail to the code.
- Numeric values quoted in docs (defaults, sizes, timeouts, filter constants)
  must match the code. Pruning stale text counts as much as adding new text,
  and inline comments elsewhere in the tree that describe the changed
  behavior must be updated too, even in files the PR does not otherwise
  touch.
- Docs never present a workaround as designed behavior.
