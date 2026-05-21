# Unit tests

Host-only unit tests for the cross-platform logic in `src/`. They link against the `sendspin`
static library and run on macOS/Linux with [GoogleTest](https://github.com/google/googletest)
(fetched automatically via CMake `FetchContent`).

## Running

From the repository root:

```bash
cmake -B build-tests -DSENDSPIN_BUILD_TESTS=ON .
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
cmake -B build-tests-asan -DSENDSPIN_BUILD_TESTS=ON -DENABLE_SANITIZERS=ON .
cmake --build build-tests-asan --target sendspin_tests
ctest --test-dir build-tests-asan --output-on-failure
```

## Layout

Each `test_*.cpp` file covers one unit of cross-platform logic:

- `test_protocol.cpp` — wire-protocol parsing/formatting: enum round-trips, message dispatch, the
  tri-state metadata/color deltas, and the hand-rolled `client/time` formatter checked against
  `snprintf`.
- `test_time_filter.cpp` — `SendspinTimeFilter` invariants (monotonic-timestamp rejection, reset,
  offset round-trip, convergence).
- `test_audio_stream_info.cpp` — byte/frame/sample/duration conversions.

These are white-box tests: they include private headers from `src/`, so the test target adds
`src/` to its include path. To add a new test file, create `test_<unit>.cpp` here and add it to
the `add_executable(sendspin_tests ...)` list in `tests/CMakeLists.txt`.
