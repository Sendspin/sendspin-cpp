---
name: house-patterns
description: Review a branch or PR for fit with sendspin-cpp's design conventions - helper reuse, sibling-role parity, threading and Inbox discipline, validation posture, platform abstraction, header visibility, and public API shape. Use to check whether functionally correct code is shaped the way this library shapes it.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash
---

# House Patterns Review

Review the change under review for fit with this library's design
conventions. The premise: the code is assumed functionally correct; the
question is whether it is shaped the way sendspin-cpp shapes it. Report
findings only; do not edit files. The normative rules live in
`docs/conventions.md`; this checklist applies them to a diff.

## Scope

Determine the diff: if `$ARGUMENTS` contains a PR number, use
`gh pr diff <N>`; otherwise `git diff main...HEAD`, falling back to
`git diff HEAD`. If the review environment already supplies the diff (for
example an automated PR review), review that diff directly instead of
computing one. For each area below, read the sibling code the diff should
resemble before judging the diff.

Back every claim with a command. A "checked and clean" statement in the
report must rest on an actual grep, diff, or file read performed during this
review, never on recollection or on how the code is expected to look.

## Reuse before invention

- New parsing/validation logic must use the shared helpers in
  `src/protocol.cpp` (for example `read_enum_field()`) rather than
  hand-rolled per-field logic. New event producers push through
  `push_event_or_log()` (`src/inbox.h`).
- Before accepting a new helper, guard, or utility, search the tree for an
  existing one that already does the job. Duplicating an existing mechanism
  is a finding even when the duplicate is correct.
- A new role or feature copies the structure of the sibling that already
  solves the same problem (the player and artwork roles are the reference for
  binary data handling). "Drifted stylistically from its siblings" is a
  defect: either conform to the sibling pattern or fix all siblings.
- When a diff substantially rewrites a region, drifted patterns inside the
  touched region get conformed in the same PR. "The old code already did it
  this way" excuses a one-line addition to an existing chain, not a rewrite
  that carries a known-nonconforming pattern forward.

## Threading and Inbox discipline

Check against `docs/conventions.md` ("Threading and cross-thread state") and
the descriptions in `docs/internals.md`:

- First, map each changed function to the thread(s) that execute it (network
  thread, drain/decode thread, sync task, main loop) by tracing its callers;
  every rule below is judged against that mapping, and a function whose
  thread you have not identified is not yet reviewed.
- Main-loop-bound cross-thread state goes through the `Inbox`; no new
  mutex-protected endpoints polled by `loop()`.
- Event ring for ordered lifecycle events only; latest-wins state on an
  `InboxSlot`; two non-main-loop threads communicate via `ShadowSlot`.
- Payload validation and decoding on the consuming thread, not the network
  thread.
- Callback dispatch tolerates re-entrant teardown (a listener may call back
  into the client mid-callback).
- Silent drops on bounded queues are findings; drop sites log a warning.

## Validation posture

- Fail closed and uniformly: a malformed required field rejects the whole
  enclosing object. No silent defaulting, clamping, or repair of
  spec-invalid values. Sibling fields validate to the same standard.
- Two code paths serializing or parsing the same structure share an extracted
  helper so they cannot diverge.
- Spec-driven behavior is commented with the protocol spec section it
  implements, not with PR numbers or history.

## Platform abstraction and compile gates

- No `#ifdef ESP_PLATFORM` in core `src/` files; platform differences live in
  `src/platform/`, `src/esp/`, `src/host/`.
- Role compile-gates (`SENDSPIN_ENABLE_*`) appear only in
  `cmake/sources.cmake` and the dispatch points in
  `include/sendspin/client.h` / `src/client.cpp`. Examples must build with
  roles disabled: role usage in `examples/` is guarded like an external
  consumer would guard it. Verify this by grepping the example for the
  role's types and calls and confirming each use sits inside the matching
  `#ifdef`; do not report gate coverage without that check.
- `SS_LOG*` for logging, `platform_malloc` family for allocation. Raw
  `ESP_LOG*` or `heap_caps_*` in cross-platform code is a finding.
- Changes keep both platforms' builds coherent (source lists, Kconfig, CMake
  options) even when only one platform is compiled locally.

## Header visibility and API shape

- Only consumer-facing API in `include/sendspin/`; internal types and helpers
  stay in `src/`. Nothing appears in a public header solely for tests or
  internal plumbing.
- Config and commands travel as structs with designated initializers, not
  growing positional optional parameters.
- Contracts are enforced by documentation, not defensive code: no null or
  state checks that contradict a documented precondition. Flag both a new
  defensive check against a documented contract and an asymmetric check that
  exists at one of N equivalent sites.
- Deprecations carry `@deprecated` docs plus a `[[deprecated]]` attribute and
  a versioned removal target.
- Public declarations state their threading requirements where non-obvious.

## Consistency completion

- A fixed pattern is swept across the tree: grep for other instances of the
  same shape before calling the fix complete.
- Parallel code paths (start versus clear, hello versus request-format) stay
  structurally identical; deliberate asymmetry carries an explanatory comment
  at the asymmetric site.
- Invariants that require N call sites to cooperate are restructured so they
  hold by construction: a chokepoint helper, `std::optional` instead of a
  paired flag and value, constants derived from the constants they depend on.

## Report format

For each finding: location (file:line), the convention violated (cite the
`docs/conventions.md` section), the sibling code or helper that shows the
expected shape (file:line), and the suggested change. Distinguish "must
conform" findings from "sibling pattern itself may deserve fixing" findings.
