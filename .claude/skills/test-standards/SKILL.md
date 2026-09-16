---
name: test-standards
description: Review the tests in a branch or PR against sendspin-cpp's test-quality standards - extract-for-testability, mutation-survivable assertions, control cases, no filler tests, no wall-clock assertions, no test seams in production code, and scaffolding that satisfies production invariants. Use when reviewing new or changed tests, or when asked whether a change is adequately tested.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash, Edit
---

# Test Standards Review

Review the tests a change adds or modifies, and whether the change's logic is
testable at all. A test's job is to fail when the production code is broken;
a test that cannot fail that way is filler, and filler has negative value.
Report findings only. The normative rules live in `docs/conventions.md`
("Testing"); this checklist applies them to a diff. The only edits this
review makes are temporary mutations of production code for the checks
under "Mutation survival", and every one of them is reverted before the
report is written.

## Scope

Determine the diff: if `$ARGUMENTS` contains a PR number, use
`gh pr diff <N>`; otherwise `git diff main...HEAD`, falling back to
`git diff HEAD`. If the review environment already supplies the diff (for
example an automated PR review), review that diff directly instead of
computing one. Consider both directions: new tests that are weak, and new
logic that ships without a test that could catch its breakage. New files and
new hunks are in scope whether a person or a coding agent wrote them; a test
already weak on `main` is out of scope unless the diff touches it or relies
on it for coverage.

Back every claim with a command: a "checked and clean" statement, a mutation
result, or "the suite passes" rests on a build, run, grep, or read performed
during this review.

## Extract for testability

- Nontrivial pure logic buried inside a threaded or I/O-coupled path is
  extracted into a static member or free function with no thread, socket, or
  callback dependencies, then unit-tested directly. `decode_visualizer_message()`
  (`src/visualizer_role.cpp`) is the established pattern. Extraction purely
  for testability needs no other justification; flag new decision-heavy
  logic that is only reachable through a thread or a full client.
- A timing decision is extracted into a pure predicate that takes `now` as an
  ordinary argument; the production call site still reads the real clock and
  nothing becomes swappable. `display_overdue_us` in `src/artwork_role.cpp`
  is the shape. This project has no clock injection seam by decision, and a
  review must not propose one. A predicate covers a decision, not a sequence
  over time; sequencing that needs direct coverage is a gap to name.

## No test seams in production

- Production code in `src/` and `include/` must not acquire friends,
  test-only hooks, widened visibility, extra template parameters, injectable
  clocks or transports, or fixture-aware naming in order to be testable. The
  fix is extraction (above), a test-side technique, or a named gap.
- Allowed test-side techniques: tests are white-box and include private
  headers from `src/`; a fixture may construct and drive a role's `Impl`
  directly (`tests/test_artwork_role.cpp`); connection tests use real
  loopback sockets (`tests/test_connection_lifecycle.cpp`).

## Mutation survival

- For every new test, identify the production line or branch its name or
  comment claims to defend and ask: if that line were deleted or its
  condition inverted, would this test fail? A test that would still pass is
  filler. Scope mutations to that line, preferring edits a person would
  plausibly make (dropping a reset, inverting a comparison, removing a guard)
  over line-by-line deletion.
- Reasoning alone may clear a test whose assertion obviously pins the line
  it claims. A survival finding, or a certification that a subtle test is
  adequate, requires building and running the mutant after the unmutated
  build passes, and the report states the command and the result.
- Running a mutant: apply the edit, rebuild, run, then revert with
  `git checkout -- <file>` and confirm `git status` shows the tree as it was
  before the review. Build under ASan/UBSan (`-DENABLE_SANITIZERS=ON`); a
  mutant that changes thread interaction (a dropped lock, a reordered store,
  a removed join) is built under ThreadSanitizer (`-DENABLE_TSAN=ON`) instead,
  since ASan does not see it. A stale build directory has passed mutations
  here before, so check that the build output shows the mutated object
  recompiling.
- A surviving mutation is a defect of the test only when it breaks a contract
  the test claims to cover; otherwise it is a gap. A surviving mutation and
  an overclaiming comment on the same test are one finding.
- An assertion that claims to cover several failure modes must fail for each
  one on its own; break each path alone to confirm.
- Watch for self-referential tests: asserting on state the test itself set,
  exercising only the fake, or re-deriving the expected value with the same
  code path the production code uses.

## Validation tests

- Tests for parsing/validation pair every malformed-input case with an
  explicit control case (comment prefix `Control:`) proving the same parser
  accepts valid input; without one, "rejects bad input" is indistinguishable
  from "rejects everything".
- Cover the reject-the-whole-object rule: one bad sibling field must reject
  the enclosing object, and the test must show neighboring valid fields did
  not survive into the output.

## No filler

- No tests that restate the implementation line by line, duplicate an
  existing case with cosmetic variation, or exist to inflate a count.
  Recommending deletion of a weak test is a valid review outcome.
- Test names and comments describe the behavior under test, not the defect
  history ("rejects spectrum config missing n_disp_bins", not "regression
  test for the config bug"), closely enough that a red CI run identifies the
  break without opening the file.

## Granularity and independence

- One behavior per test: not one assertion per test, and not one test per
  bug. Several assertions about the same behavior belong together; a test
  spanning several behaviors is split along the behaviors it conflates.
  `MetadataNullClearsAndAbsentPreserves` (`tests/test_protocol.cpp`) asserts
  three things about the single delta-merge rule it covers.
- A test's assertions establish what its name and comment claim, no more and
  no less; a comment that promises an unchecked property is an overclaim.
- `ASSERT_*` aborts the test function while `EXPECT_*` continues; reserve
  `ASSERT_*` for the point where continuing would be meaningless, such as a
  parse that must succeed before its result is read.
- An assertion whose failure would not explain itself carries a `<<` message
  with the observed value: a "must not happen" window reports the count it
  saw, a multi-step sequence reports which step it reached. A red run should
  be diagnosable from the log alone.
- No test depends on execution order, on another test having run first, or on
  shared mutable global state. A test that fails without a code change is a
  defect in the test: fix it or delete it, never retry it into passing.

## Scaffolding and test doubles

- Test harnesses satisfy production invariants instead of stubbing around
  them: if production code asserts a bound `Inbox`, the fixture binds one. A
  harness that suppresses an invariant hides every bug it guards.
- Production `assert()` calls are contracts for callers, not behavior under
  test; the suite has no death tests and a review does not ask for one.
- Doubles are hand-written fakes that record outcomes; the tree uses no
  gmock. A test that asserts on which calls were made rather than on what
  resulted is exercising the double, not the code.
- Concurrency tests observe real effects: never assert on a counter the
  thread under test would have been the one to advance; use the code's own
  observable outputs or event flags.
- CI runs the suite under ASan/UBSan and, in a separate job, ThreadSanitizer
  (`-DENABLE_TSAN=ON`; the two cannot be combined). A concurrency finding, or
  a certification that a threaded test is adequate, is backed by a TSan run
  and states the command. A race TSan reports is real until shown otherwise;
  the review never proposes a suppressions file.

## No wall-clock assertions

- A unit test never makes elapsed time the pass/fail condition
  (`EXPECT_LT(elapsed, x)`, `EXPECT_GE(elapsed, y)`); the bound is a guess
  about machine speed that is eventually wrong. If the property is latency
  itself, it is a benchmark: name it as a gap.
- An elapsed-time assertion means the call under test has a second exit (a
  timeout) and the clock exists to tell the two apart. Remove the second
  exit: wait with no timeout so completion is the proof; assert on a value
  only a correctly blocked call could produce ("the consumer received the
  item sent after it parked"); or rely on a structural failure (`std::thread`
  terminates on a joinable thread, the sanitizers catch a use-after-free).
  Hangs are guarded by the watchdog in `tests/main.cpp` and the CTest
  `TIMEOUT` in `tests/CMakeLists.txt`, both far above any test's real
  duration.
- Allowed: a bounded wait that only decides when to sample; a fixed sleep
  that orders threads only when a late thread yields a false pass, never a
  false failure (sleep so the consumer is likely parked, and if it was not,
  the wake is held and the test still passes); a bounded window for a "must
  not happen" check on a monotonic observation, where a short window can
  only miss a regression. A watchdog is tested with these: no timeout for
  "it fires", a bounded window for "not yet".
- Sleeps and windows are the minimum that reliably orders the threads, on
  the order of milliseconds. A test that takes longer than a few hundred
  milliseconds carries a comment saying why; the watchdog budget is shared
  by the whole suite and slow tests hide hangs behind it.

## Honest gaps

- A coverage gap that cannot be closed cheaply is named explicitly in the PR
  rather than papered over with a test that appears to cover it. Flag
  apparent coverage that does not exercise the gap. Naming the gap is the
  finding; never recommend a production seam to close it.
- The host suite compiles only the host arm of `#ifdef ESP_PLATFORM`. A
  finding that touches platform-guarded code states which arm the test
  exercises; a change to the ESP arm is a gap to name, and a host mutation
  result says nothing about it.

## Report format

For each finding: location (file:line), the standard it misses, and the
concrete improvement (including "delete this test" where warranted); a
mutation finding also states the command run and the observed result.
Separate sections for weak tests, missing tests, production-testability
issues, and named gaps (coverage that is missing by acknowledged decision,
listed so the PR can state them; no action requested). Close with the
`git status` output showing every mutation was reverted.
