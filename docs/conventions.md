# Design Conventions

This document states the design standards that code in this repository is
held to.
It is normative: `docs/internals.md` describes how the current code works,
while this document describes how new code should be shaped. The review
checklists in `.claude/skills/` apply these standards to a diff.

## Threading and cross-thread state

- The network thread does minimal work: receive, copy, validate framing, and
  hand off. Payload validation and decoding happen on the drain or worker
  thread that consumes the data, following the pattern the player and artwork
  roles establish.
- All main-loop-bound cross-thread state goes through the `Inbox`
  (`src/inbox.h`). Do not add new mutex-protected endpoints polled by
  `loop()`.
- The Inbox event ring is for ordered lifecycle events only (stream start and
  end, cleared, connection events). Latest-wins state (player state, metadata,
  progress) belongs on a collapsing `InboxSlot`, never the ring: a flood of
  state updates must not be able to evict a lifecycle event.
- State published between two non-main-loop threads uses a `ShadowSlot`
  (`src/platform/shadow_slot.h`).
- Event producers push through `push_event_or_log()` rather than hand-rolling
  the build, push, and log-on-drop sequence.
- A bounded queue or ring that drops an item never drops it silently: log at
  least a warning at the drop site.
- Callback dispatch must tolerate re-entrant teardown: a listener callback may
  call back into the client. See "Re-entrant Teardown During Callback
  Dispatch" in `docs/internals.md` for the guard patterns in use.

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
  `include/sendspin/client.h` / `src/client.cpp`; consumers, including the
  examples, guard their own role usage (see Public API).
- Logging uses the `SS_LOG*` macros; allocation uses the `platform_malloc`
  family with an explicit `MemoryLocation` choice where it matters.
- Code that only builds on one platform still keeps the other platform's build
  coherent: source lists, Kconfig, and CMake options stay in sync even when
  the change cannot be compiled locally for every target.

## Embedded resource discipline

- Stack is a measured budget, not a vibe. Large stack frames on paths
  reachable from ESP tasks (the httpd receive path, the sync task, `loop()`)
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
- Parallel code paths (stream start versus stream clear, hello versus
  request-format) stay structurally identical so a reader can diff them
  mentally. Deliberate asymmetry gets a comment at the asymmetric site
  explaining why, so nobody "fixes" it back.
- When two things must stay in sync at every call site, do not rely on care:
  create a chokepoint (a helper that updates both, a `std::optional` instead
  of a paired flag and value, a derived constant) so the invariant holds by
  construction.

## Documentation

- Comments and docs describe the current state of the code. No history
  narration ("previously", "used to", "now uses"), no phase or porting
  language, and no references to PR numbers as rationale. Cite the Sendspin
  protocol spec by section when a behavior is spec-driven.
- Documentation drift is a defect. A change in behavior is not complete until
  every description of that behavior is updated in the same PR:

  | If the change touches...                  | Update...                                      |
  | ----------------------------------------- | ---------------------------------------------- |
  | Threading, draining, connection lifecycle | `docs/internals.md`                            |
  | Public API, config, listener contracts    | `docs/integration-guide.md` and header docs    |
  | Architecture, layout, conventions         | `CLAUDE.md`                                    |
  | Anything shown in usage examples          | `@code` blocks in headers, `examples/`, README |

- Numeric values quoted in docs (defaults, sizes, timeouts, filter constants)
  must match the code. Pruning stale text counts as much as adding new text,
  and inline comments elsewhere in the tree that describe the changed
  behavior must be updated too, even in files the PR does not otherwise
  touch.
- Docs never present a workaround as designed behavior.
