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
(the protocol task, the transport threads, the shared inbound ring, the sync task, the inbox
handoffs) the way ASan is for the parsers. The
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
  full-state metadata/color objects, and the hand-rolled `client/time` formatter checked against
  `snprintf`.
- `test_json_arena.cpp`: `SendspinArenaAllocator` wipes every byte its own buffer gives up
  when a block is freed, shrunk or moved (the wipe of a freed heap fallback block cannot be
  read back and is a named gap); a parse released through `ParsedJsonMessage` leaves only its
  stranded first key, and the peak over a parse and then its reply is the larger of the two,
  not their sum.
- `test_time_filter.cpp`: `SendspinTimeFilter` invariants (monotonic-timestamp rejection, reset,
  offset round-trip, convergence).
- `test_audio_stream_info.cpp`: byte/frame/sample/duration conversions.
- `test_network_info.cpp`: local interface MAC lookup is well-formed or absent.
- `test_thread_safe_queue.cpp`: `ThreadSafeQueue`'s `wake_receiver()` contract: a wake unblocks
  a parked receive, is held pending, is consumed once, and never drops a queued item.
- `test_inline_vector.cpp`: `InlineVector` order-preserving erase, element release at removal,
  and swap.
- `test_fixed_block_pool.cpp`: `FixedBlockPool` claims each block once until released, also
  under concurrent claims.
- `test_inbox.cpp`: `Inbox`/`InboxSlot` topic bits, event ring ordering, and slot binding.
- `test_shared_ring_buffer.cpp`: the host `SharedRingBuffer`: ring-order reclamation under
  out-of-order returns, no-split wrap placement, the full-ring acquire policies, completion
  order, and concurrent producers.
- `test_inbound_ring.cpp`: `InboundRing`, `InboundItemList`, `InboundQuota` and `InboundGate`:
  the wrapped-item hold-back, LOCAL items' two returns, quota accounting, the item list's
  append/take/recall/wake, the one-in-flight fallback hand-off, its release by a consume or a
  detach, the close rule, and the ring size derivation.
- `test_protocol_task.cpp`: `ProtocolTask`'s command queue (order, the consumer burst and the
  reserved accept slots), the latest-state slot, the lifecycle-request slot's wake and its
  hand-off at stop, the wakes, and stop/restart.
- `test_player_role.cpp`: the player's `client/state` timing parameters and the
  supported-format validation, driven through the role's `Impl` without a server, and its
  inbound ring hand-off: a chunk decoded in place, per-role quotas, the stream/clear marker,
  and the recall after a teardown.
- `test_decoder.cpp`: `SendspinDecoder` chunk decoding per codec (multi-frame FLAC, PCM at the
  spec maximum, an Opus packet longer than the estimate) and the sync task's whole-chunk decode.
- `test_visualizer_role.cpp`: `decode_visualizer_message()` and the visualizer role's
  negotiation and dispatch, the receive stamp a frame carries, and the recall after a teardown.
- `test_artwork_role.cpp`: the artwork role's `Impl` driven directly: announce/part/cancel
  transfers and the messages and sequences that close the connection, the per-channel image cap,
  decode thread, slot gating, `frame_done()` acks, and stream restart/clear.
- `test_connection_lifecycle.cpp`: the connection nursery (prove-then-admit) over real loopback
  sockets: junk probes, slow peers, capacity, and the liveness timeout (its derivation and
  expiry predicate as tables, and a silent peer dropped, or kept with the check disabled, end
  to end); admission and a cross-thread request acted on with no `loop()` call, and two peers
  at once settling on the preferred one.
- `test_encrypted_lifecycle.cpp`: the Noise transport end to end over loopback: re-handshake,
  pairing over the pairing PSK, `server/unpair`, pre-admission traffic, role dispatch by
  ownership, `client/leave` gating, the `client/state` role-object rules, the combined
  `['playback','pairing']` activate, the re-prove watchdog, the liveness tick and the arrival
  stamp it reads, persistence written from the main loop, and controller command validation.
- `test_client_lifecycle.cpp`: `start()`/`stop()`/restart: goodbyes, clear callbacks delivered
  inside `stop()`, re-entrancy from callbacks, role start rollback, accepts refused at `stop()`,
  the command queue's refusals and the lifecycle requests it never refuses, the protocol task's
  next deadline, the teardown reorder guarantee for every role with main-loop state, stream
  starts acknowledged by number, the high-performance grant, the time filter slot, and the
  inbound ring's size.
- `test_client_teardown.cpp`: destroying a running client joins every threaded role.
- `test_role_deactivation.cpp`: a later `server/activate` that removes a role: output stopped,
  buffers and state dropped, the roles it keeps left alone, and a removed role added back.
- `test_crypto.cpp`, `test_cpace.cpp`, `test_pairing_code.cpp`, `test_psk_wrap.cpp`,
  `test_pairing_token.cpp`, `test_noise_transport.cpp`, `test_noise_rehandshake.cpp`,
  `test_admission.cpp`, `test_record_store.cpp`, `test_dynamic_pairing_code.cpp`,
  `test_pairing_state_machine.cpp`, `test_pairing_offers.cpp`, `test_persistence_codec.cpp`: the
  encryption and pairing units, from the primitives up to the record store and the pairing
  state machine.

The loopback tests share `lifecycle_test_fixtures.h`: `FakeEncryptedServer` and
`FakeOutboundEncryptedServer` play a Sendspin server as the Noise initiator over a real socket,
and `PairedClientBundle` wires a client to a seeded record store. Every connection is encrypted,
so there is no cleartext fake; the fake sends its `server/hello` as soon as the handshake
completes, before any `client/hello`, so that ordering is exercised by every test.

`tests/wrap_test_helpers.h` holds the server side of pairing.md "Wrapping", so a test can open
what the client sealed without the library carrying an inverse it never calls.

`tests/inbound_test_helpers.h` stands in for a transport and the protocol task around the shared
inbound ring, so a role's protocol-task handlers can be driven on the test thread.

These are white-box tests: they include private headers from `src/`, so the test target adds
`src/` to its include path. To add a new test file, create `test_<unit>.cpp` here and add it to
the `add_executable(sendspin_tests ...)` list in `tests/CMakeLists.txt`. New tests are held to
the standards in `docs/conventions.md` ("Testing"); the `test-standards` skill in
`.claude/skills/` applies them to a diff.
