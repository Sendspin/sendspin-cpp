# Unit tests

Host-only unit tests for the cross-platform logic in `src/`. They link against the `sendspin`
static library and run on macOS/Linux with [GoogleTest](https://github.com/google/googletest)
(fetched automatically via CMake `FetchContent`).

## Running

From the repository root:

```bash
cmake -B build-tests -DSENDSPIN_BUILD_TESTS=ON -DBUILD_EXAMPLES=OFF .
cmake --build build-tests --target sendspin_tests
ctest --test-dir build-tests --output-on-failure
```

Run the test binary directly to use GoogleTest filters:

```bash
./build-tests/tests/sendspin_tests --gtest_filter='Protocol.*'
```

## Running under sanitizers

Add `-DENABLE_SANITIZERS=ON` to build with AddressSanitizer and UndefinedBehaviorSanitizer. This
is what CI runs, and it is the recommended way to exercise the pointer-heavy code (the message
formatter, JSON parsing):

```bash
cmake -B build-tests-asan -DSENDSPIN_BUILD_TESTS=ON -DENABLE_SANITIZERS=ON -DBUILD_EXAMPLES=OFF .
cmake --build build-tests-asan --target sendspin_tests
ctest --test-dir build-tests-asan --output-on-failure
```

`-DENABLE_TSAN=ON` builds with ThreadSanitizer instead. CI runs this as a separate job because
TSan cannot be combined with ASan/UBSan. It is the configuration to reach for on the threaded code
(the sync task, the connection threads, the inbox handoffs) the way ASan is for the parsers. The
flag applies to every target, including the fetched dependencies, because TSan cannot see atomics
in uninstrumented code and reports IXWebSocket's stop flags as false races otherwise:

```bash
cmake -B build-tsan -DSENDSPIN_BUILD_TESTS=ON -DENABLE_TSAN=ON -DBUILD_EXAMPLES=OFF .
cmake --build build-tsan --target sendspin_tests
TSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-tsan --output-on-failure
```

CI also builds and runs the suite with `-DSENDSPIN_ENABLE_OPUS=OFF` (under ASan/UBSan).
`test_client_lifecycle.cpp` has one test that only compiles in that configuration, so add the flag
to a build directory of your own when touching the player's codec handling.

## Layout

`main.cpp` is the entry point. It registers a hang watchdog that aborts the binary with the
name and stack of any test still running after 55 s; the CTest `TIMEOUT` of 60 s is the backstop
behind it. Tests wait on events with no per-test timeout, so a regression that hangs shows up as
a watchdog report rather than a flaky elapsed-time assertion.

Each `test_*.cpp` file covers one unit of cross-platform logic:

- `test_protocol.cpp`: wire-protocol parsing/formatting: enum round-trips, message dispatch, the
  tri-state metadata/color deltas, and the hand-rolled `client/time` formatter checked against
  `snprintf`.
- `test_time_filter.cpp`: `SendspinTimeFilter` invariants (monotonic-timestamp rejection, reset,
  offset round-trip, convergence).
- `test_audio_stream_info.cpp`: byte/frame/sample/duration conversions.
- `test_network_info.cpp`: local interface MAC lookup is well-formed or absent.
- `test_spsc_ring_buffer.cpp`: `SpscRingBuffer` wrap-around accounting with unaligned storage
  sizes, and the `wake_receiver()` contract.
- `test_thread_safe_queue.cpp`: `ThreadSafeQueue`'s `wake_receiver()` contract: a wake unblocks
  a parked receive, is held pending, is consumed once, and never drops a queued item.
- `test_inline_vector.cpp`: `InlineVector` order-preserving erase, element release at removal,
  and swap.
- `test_inbox.cpp`: `Inbox`/`InboxSlot` topic bits, event ring ordering, and slot binding.
- `test_visualizer_role.cpp`: `decode_visualizer_message()` and the visualizer role's
  negotiation and dispatch.
- `test_artwork_role.cpp`: the artwork role's `Impl` driven directly: decode thread, slot
  gating, `frame_done()` acks, and stream restart/clear.
- `test_connection_lifecycle.cpp`: the connection nursery (prove-then-admit) over real loopback
  sockets: junk probes, slow peers, early server hello, capacity, and the liveness timeout.
- `test_client_lifecycle.cpp`: `SendspinClient` `start()`/`stop()`/restart over loopback: peers
  are goodbyed, role state is reset before `stop()` returns, a restarted client is live again,
  and the player's codec checks.
- `test_client_teardown.cpp`: destroying a client that runs every threaded role joins the role
  threads.

These are white-box tests: they include private headers from `src/`, so the test target adds
`src/` to its include path. To add a new test file, create `test_<unit>.cpp` here and add it to
the `add_executable(sendspin_tests ...)` list in `tests/CMakeLists.txt`. New tests are held to
the standards in `docs/conventions.md` ("Testing"); the `test-standards` skill in
`.claude/skills/` applies them to a diff.
