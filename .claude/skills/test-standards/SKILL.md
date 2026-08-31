---
name: test-standards
description: Review the tests in a branch or PR against sendspin-cpp's test-quality standards - extract-for-testability, mutation-survivable assertions, control cases, no filler tests, no test seams in production code, and scaffolding that satisfies production invariants. Use when reviewing new or changed tests, or when asked whether a change is adequately tested.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash
---

# Test Standards Review

Review the tests a change adds or modifies, and whether the change's logic is
testable at all. A test's job is to fail when the production code is broken;
a test that cannot fail that way is filler, and filler has negative value.
Report findings only; do not edit files.

## Scope

Determine the diff: if `$ARGUMENTS` contains a PR number, use
`gh pr diff <N>`; otherwise `git diff main...HEAD`, falling back to
`git diff HEAD`. If the review environment already supplies the diff (for
example an automated PR review), review that diff directly instead of
computing one. Consider both directions: new tests that are weak, and new
logic that ships without a test that could catch its breakage.

## Extract for testability

- Nontrivial pure logic buried inside a threaded or I/O-coupled path should
  be extracted into a static member or free function with no thread, socket,
  or callback dependencies, then unit-tested directly. This is the
  established pattern: `decode_visualizer_message()`
  (`src/visualizer_role.cpp`) and the static display-timing helpers in
  `src/artwork_role.cpp` exist for exactly this reason.
- Extraction purely for testability is encouraged; it needs no other
  justification. Flag new decision-heavy logic that is only reachable through
  a thread or a full client as a testability finding.

## Mutation survival

- For every new test, identify the production line or branch it defends, and
  check: if that line were deleted or its condition inverted, would this test
  fail? A test that would still pass is filler.
- Watch for self-referential tests: asserting on state the test itself set,
  exercising only the mock, or re-deriving the expected value with the same
  code path the production code uses.
- When a test's protective value is non-obvious, a comment or the PR
  description saying which mutation it catches ("deleting X makes tests Y and
  Z fail") helps; its absence on a subtle test is worth a note, not a
  blocker.

## Validation-test template

- Tests for parsing/validation pair every malformed-input case with an
  explicit control case (comment prefix `Control:`) proving the same parser
  accepts valid input. A rejection suite with no control case cannot
  distinguish "rejects bad input" from "rejects everything".
- Cover the reject-the-whole-object rule: one bad sibling field must reject
  the enclosing object, and the test must show neighboring valid fields did
  not survive into the output.

## No filler

- No tests that restate the implementation line by line, duplicate an
  existing case with cosmetic variation, or exist to inflate a count.
  Recommending deletion of a weak test is a valid review outcome.
- Test names and comments describe the behavior under test, not the defect
  history ("rejects spectrum config missing n_disp_bins", not "regression
  test for the config bug").

## No test seams in production

- Production code in `src/` and `include/` must not acquire friends,
  test-only hooks, widened visibility, extra template parameters, or
  fixture-aware naming in order to be testable. The fix for hard-to-reach
  code is extraction (above) or test-side techniques, never a seam in the
  shipped code.

## Scaffolding parity

- Test harnesses satisfy production invariants instead of stubbing around
  them: if production code asserts a bound `Inbox`, the test fixture binds
  one. A harness that suppresses an invariant hides every bug that invariant
  guards.
- Concurrency tests observe real effects rather than self-referential timing:
  never assert on a counter that the thread under test would have been the
  one to advance, and never use fixed sleeps as synchronization; use the
  code's own observable outputs or event flags.

## Sanitizers

- The suite must pass under ASan/UBSan (`-DENABLE_SANITIZERS=ON`, the CI
  configuration).

## Honest gaps

- A coverage gap that cannot be closed cheaply (for example, logic needing an
  injectable clock) is named explicitly in the PR rather than papered over
  with a test that appears to cover it. Flag apparent coverage that does not
  actually exercise the gap.

## Report format

For each finding: location (file:line), the standard it misses, and the
concrete improvement (including "delete this test" where warranted). Separate
sections for weak tests, missing tests, and production-testability issues.
