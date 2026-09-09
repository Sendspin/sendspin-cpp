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
logic that ships without a test that could catch its breakage. "Pre-existing"
means present on `main`; new files and new hunks in the diff are the PR's code
and are in scope regardless of who wrote them.

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

- For every new test, identify the production line or branch its name or
  comment claims to defend, and check: if that line were deleted or its
  condition inverted, would this test fail? A test that would still pass is
  filler. Mutations are scoped to that line, not to every line reachable from
  the test; prefer edits a person would plausibly make (dropping a reset,
  inverting a comparison, removing a guard) over line-by-line deletion. A
  surviving mutation is a defect of the test only when it breaks a contract
  the test claims to cover; otherwise it belongs under "Honest gaps".
- An assertion that claims to cover several failure modes must fail for each
  one on its own; a single aggregate check detects only the mode that
  dominates it. Regress each path alone to confirm the others.
- A mutation claim is verified by building and running the mutant after the
  unmutated build passes, and the finding states the command and result; a
  stale build directory has passed mutations here before, so check that the
  objects rebuilt. This is the same overclaim that "Granularity and
  independence" catches by reading; report it once.
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

## Granularity and independence

- One behavior per test: not one assertion per test, and not one test per
  bug. Several assertions about the same behavior belong together and
  splitting them is filler; a long test spanning several behaviors is the
  opposite failure and gets split along the behaviors it conflates.
  `MetadataNullClearsAndAbsentPreserves` (`tests/test_protocol.cpp`) asserts
  three things about the single delta-merge rule it covers.
- A test name describes the behavior closely enough that a red CI run
  identifies the break without opening the file (see the naming bullet under
  "No filler").
- A test's assertions establish what its name and comment claim, no more and
  no less. A comment that promises a property the assertions do not check is
  an overclaim; add the assertion or narrow the comment.
- `ASSERT_*` aborts the test function while `EXPECT_*` continues, so an
  over-merged test masks later failures behind the first one. Reserve
  `ASSERT_*` for the point where continuing would be meaningless, such as a
  parse that must succeed before its result is read.
- No test depends on execution order, on another test having run first, or on
  shared mutable global state; each test sets up the world it needs.

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
  one to advance; use the code's own observable outputs or event flags. A
  fixed sleep is not a synchronization tool; the narrow ordering use it is
  allowed is in "No wall-clock assertions".

## No wall-clock assertions

- A unit test never makes elapsed time the pass/fail condition
  (`EXPECT_LT(elapsed, x)`, `EXPECT_GE(elapsed, y)`). A stopwatch measures
  the runner and the scheduler, not the code, and the bound it needs is a
  guess about machine speed that is eventually wrong. A bounded wait that
  only decides when to sample an observation is scheduling, not an
  assertion; the last bullet says when that is allowed.
- An elapsed-time assertion is a symptom: the call under test has a second
  way to return (a timeout) and the clock exists only to tell the two apart.
  Remove the second exit instead. Wait with no timeout so the event under
  test is the only way out and completion is the proof; assert on a value
  that only a correctly blocked call could produce ("the consumer received
  the item sent after it parked"); or rely on a structural failure
  (`std::thread` terminates on a joinable thread, the sanitizers catch a
  use-after-free). Timing decisions inside production code are covered by
  extracting a pure predicate (see "Honest gaps"), not by timing the test.
- If the property is latency itself, it is a benchmark, not a unit test.
  Name it under "Honest gaps" rather than approximating it with a bound.
- The CTest `TIMEOUT` in `tests/CMakeLists.txt` is a hang guard, not an
  assertion. It sits far above any real run time so a regression reports
  instead of hanging forever. It only fires under `ctest`; a hung wait in a
  direct or debugger run hangs, and a timeout gives no diagnostic beyond
  the test name. That is the accepted price of removing the bound.
- A fixed sleep may order events between threads only when a delayed thread
  yields a false pass, never a false failure: sleep so a consumer is likely
  parked before the wake, and if it was not yet parked the wake is held and
  the test still passes. It is never itself an assertion. A bounded window
  is likewise acceptable only for a "must not happen" check on a monotonic
  observation (a flag or counter that cannot un-set within the test), where
  a short window can only miss a regression. A watchdog is tested the same
  way: wait with no timeout for "it fires", a bounded window for "not yet".

## Sanitizers

- The suite must pass under ASan/UBSan (`-DENABLE_SANITIZERS=ON`, the CI
  configuration).

## Honest gaps

- A coverage gap that cannot be closed cheaply is named explicitly in the PR
  rather than papered over with a test that appears to cover it. Flag
  apparent coverage that does not actually exercise the gap.
- Naming the gap is the finding. Do not recommend a production seam to close
  it: an injectable clock, a virtual hook, or a swappable transport added to
  `src/` or `include/` for a test's benefit is the seam violation above, not
  the remedy for it. This project has no clock injection seam and a review
  must not propose introducing one; where a timing decision needs direct
  coverage, extract it into a pure predicate the test calls with supplied
  values. Unlike a seam, the predicate takes `now` as an ordinary argument
  and the production call site still reads the real clock; nothing becomes
  swappable. `display_overdue_us` in `src/artwork_role.cpp` is the shape.
- The host suite compiles only the host arm of `#ifdef ESP_PLATFORM`. A
  finding that touches platform-guarded code states which arm the test
  exercises; a change to the ESP arm is a gap to name, and a host mutation
  result says nothing about it.
- A test that fails without a code change is a defect in the test. Fix it or
  delete it; never retry it into passing.

## Report format

For each finding: location (file:line), the standard it misses, and the
concrete improvement (including "delete this test" where warranted); a
mutation finding also states the command run and the observed result. Separate
sections for weak tests, missing tests, and production-testability issues.
