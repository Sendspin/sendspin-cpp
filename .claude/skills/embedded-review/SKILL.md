---
name: embedded-review
description: Review a branch or PR for embedded-target suitability - stack frames, heap churn on hot paths, flash cost, bounded queues, memory placement, and resource-budget justification for ESP32-class targets. This is a distinct review axis from correctness; use it before merging any change that runs on device.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash
---

# Embedded Suitability Review

Review the change under review for suitability on ESP32-class embedded
targets. This axis is independent of correctness: code can be perfectly
correct and still unshippable on a microcontroller. Report findings only; do
not edit files. The normative rules live in `docs/conventions.md` ("Embedded
resource discipline"); this checklist applies them to a diff.

## Scope

Determine the diff: if `$ARGUMENTS` contains a PR number, use
`gh pr diff <N>`; otherwise `git diff main...HEAD`, falling back to
`git diff HEAD`. If the review environment already supplies the diff (for
example an automated PR review), review that diff directly instead of
computing one. Read the full definitions of changed functions, not just the
hunks: resource problems live in context.

## Stack

- Flag stack arrays and objects larger than roughly 128 bytes on paths
  reachable from ESP tasks: the httpd/WebSocket receive path, JSON message
  handling, the sync task, and `loop()`. ESP task stacks are a few KB total.
- Watch for frame aggregation: several modest locals across helpers that GCC
  will inline into one large frame. Splitting parsing into out-of-line
  functions that fill caller-owned structs is the established fix.
- Deep or unbounded recursion is a finding regardless of frame size.
- When the verdict genuinely depends on numbers, the measurement recipe is
  `-fstack-usage` with the xtensa/riscv GCC at the shipped optimization
  level; significant stack changes should quote before/after numbers in the
  PR.

## Heap

- Hot paths (per audio chunk, per binary message, per visualizer frame, per
  loop tick) must not allocate. Look for `new`, `malloc`, `std::string` and
  `std::vector` growth, and temporary `JsonDocument`s inside them. Persistent
  reusable buffers are the established pattern.
- Allocation goes through the `platform_malloc` family or
  `PlatformBuffer`/`TransferBuffer` with a deliberate `MemoryLocation`:
  internal RAM for latency-critical or DMA-adjacent data, SPIRAM-preferring
  for bulk buffers. Raw `heap_caps_malloc`/`malloc` in core code is a finding.
- Fragmentation pressure counts: repeated free/realloc cycles of large blocks
  are worth flagging even when each allocation individually succeeds.

## Bounded resources

- Every queue, ring, and cache must have a fixed capacity and an explicit,
  intentional overflow behavior.
- A drop on a full queue is never silent: there must be at least a warning
  log at the drop site.
- Latest-wins state belongs on a collapsing slot, not on an ordered event
  ring, so state floods cannot evict lifecycle events (see
  `docs/conventions.md`, "Threading and cross-thread state").

## CPU and thread budget

- The network thread only receives, copies, and hands off; validation and
  decoding belong on the consuming thread. New work added to the network
  thread or to `loop()` needs justification.
- No blocking calls (locks held across I/O, unbounded waits) on `loop()` or
  the network thread.

## Flash and code size

- Avoid log branches for unreachable conditions, duplicated format strings,
  and needless template instantiations. "Not worth the flash" is a valid
  reason to reject a defensive branch.
- Logging uses `SS_LOG*` with a level matching the event's importance;
  per-frame logging above verbose is a finding.

## Budget justification

- Any grown buffer, stack size, queue depth, or timeout must come with a
  stated derivation. "It crashed with the old value" is a trigger for
  measurement, not a justification by itself.
- Constants that depend on other constants are derived from them
  (`constexpr size_t X = Y / 4;`), never restated as a second literal that
  can drift.
- Trivially copyable types are copied, not moved; heap-backed types are
  moved. Flag pointless `std::move` on scalars/PODs and missing moves on
  strings and vectors.

## Persistence

- NVS/flash writes are coalesced and deferred; anything that could write
  per-tick, per-message, or per-connection-cycle is a wear finding.

## Report format

For each finding: location (file:line), which budget it strains (stack, heap,
flash, CPU, wear), why it matters at ESP32 scale, and the suggested fix,
preferring patterns already used in this codebase. Order by severity. If a
finding depends on a measurement you cannot perform, say exactly what to
measure and how.
