# Host unit tests for sendspin-cpp
#
# Enabled from the top-level CMakeLists.txt with -DSENDSPIN_BUILD_TESTS=ON.
# Tests link against the `sendspin` static library and exercise its internal
# logic directly (white-box: they include private headers from src/).

include(FetchContent)

# GoogleTest, fetched the same way as the library's other dependencies.
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)  # only gtest_main is used; skip building gmock
FetchContent_MakeAvailable(googletest)

# One executable aggregating every test_*.cpp file behind the main.cpp watchdog entry point.
# gtest_discover_tests still registers the individual TEST() cases with CTest so failures are
# reported per case.
add_executable(sendspin_tests
    main.cpp
    test_audio_stream_info.cpp
    test_decoder.cpp
    test_connection_lifecycle.cpp
    test_encrypted_lifecycle.cpp
    test_time_filter.cpp
    test_protocol.cpp
    test_network_info.cpp
    test_spsc_ring_buffer.cpp
    test_thread_safe_queue.cpp
    test_shared_ring_buffer.cpp
    test_inbound_ring.cpp
    test_protocol_task.cpp
    test_inbox.cpp
    test_player_role.cpp
    test_inline_vector.cpp
    test_fixed_block_pool.cpp
    test_visualizer_role.cpp
    test_artwork_role.cpp
    test_crypto.cpp
    test_cpace.cpp
    test_pairing_code.cpp
    test_psk_wrap.cpp
    test_pairing_token.cpp
    test_record_store.cpp
    test_noise_transport.cpp
    test_noise_rehandshake.cpp
    test_admission.cpp
    test_pairing_offers.cpp
    test_dynamic_pairing_code.cpp
    test_pairing_state_machine.cpp
    test_persistence_codec.cpp
    test_client_teardown.cpp
    test_client_lifecycle.cpp
    test_role_deactivation.cpp

    # FilePersistenceProvider is a host example helper (examples/common/), not part of the
    # library; compile it into the test target so the record-store tests can exercise it.
    ../examples/common/file_persistence_provider.cpp
)

# test_decoder.cpp calls SyncTask::decode_whole_chunk(), the sync task's chunk-resume loop, which
# is a protected static member: it grows the decode buffer, resumes the decoder and rolls a failed
# chunk back, and nothing on the public surface reaches it without the sync thread.
set_source_files_properties(test_decoder.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_client_lifecycle.cpp checks what a role's stop() left in its ring, which nothing on the
# public surface reports, and installs a stand-in connection in ConnectionManager's admitted slot
# (and drops it mid-publish) to pin publish_state()'s hold on it; it reads the private members
# directly instead of adding a seam. Reached: SendspinClient::connection_manager_, player_ and
# each role's impl_ (the sync task and the visualizer's drain ring); ConnectionManager's
# conn_ptr_mutex_, current_connection_, set_current_connection(), drop_connection() and
# flush_deferred_releases() (to install, swap out, and drop a stand-in connection) and accepting_
# (closed to take on_new_connection()'s admission-closed rejection).
set_source_files_properties(test_client_lifecycle.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_role_deactivation.cpp reads what a removed role left behind and drives the pieces the
# public surface does not expose: the sync task's run state and its encoded ring, the artwork
# transfer in flight and its drain-side slot buffers, the visualizer's stream flag and ring, a
# state role's held scheduled update and its teardown generation (including a direct
# handle_server_state() call with that generation), the controller's supported-commands mask
# (seeded so a command reaches the inactive-role send gate), plus the queued-event probe that proves
# ordering without a sleep (a role inbox's topic bits and the connection manager's pending-event
# flag).
set_source_files_properties(test_role_deactivation.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_player_role.cpp drives PlayerRole::Impl directly - no connected server, no sync-task
# thread - which is the only way to see the client/state player object and the only way to hand
# a handler a stale teardown generation. Reached: Impl's handle_stream_start(), handle_binary(),
# handle_stream_clear(), handle_server_command(), cleanup(), attach_inbox(), cleanup_generation
# and event_state's latest-wins slots; SyncTask's encoded_ring_buffer_, which is what says a
# refused handler buffered nothing.
set_source_files_properties(test_player_role.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_inbound_ring.cpp sets InboundGate's private CONSUMED bit directly to stage a consume bit
# that lands after the transport has published its next message, an interleaving of two threads
# no public call can produce on demand.
set_source_files_properties(test_inbound_ring.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_record_store.cpp reads records_ directly and calls the store's private locked-context
# lookups (record_by_psk_id, record_by_server_id); the store deliberately exposes no copying
# accessor for them, since nothing in the library needs one.
set_source_files_properties(test_record_store.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# Reach the library's private headers (protocol_messages.h, time_filter.h, ...) and
# the src/crypto/ headers.
# The public include/ dir and ArduinoJson propagate transitively from `sendspin`.
# Use CMAKE_CURRENT_SOURCE_DIR (not CMAKE_SOURCE_DIR) so the path stays correct even
# if sendspin is ever added as a subdirectory of a larger superproject.
target_include_directories(sendspin_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/../examples/common
)

target_link_libraries(sendspin_tests PRIVATE sendspin GTest::gtest)
# The watchdog in main.cpp prints a backtrace on a hang; glibc needs exported symbols to name
# the frames.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(sendspin_tests PRIVATE -rdynamic)
endif()

target_compile_features(sendspin_tests PRIVATE cxx_std_20)
target_compile_options(sendspin_tests PRIVATE -Wall -Wextra)

# test_pairing_state_machine.cpp is a white-box integration harness: its fixture injects fake
# connections into ConnectionManager's private state and drives private lifecycle methods
# directly. Disabling access checking for that one translation unit keeps every test seam
# out of the production headers (no friend declarations); access control is a compile-time
# check only, so this has no ABI effect. GCC and Clang both support the flag, and the test
# suite is host-only. The fixture's accessor methods document each seam and why it exists.
set_source_files_properties(test_pairing_state_machine.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_encrypted_lifecycle.cpp is a white-box integration harness: it drives the client's and the
# manager's private lifecycle, persistence and dispatch entry points against a real loopback server,
# none of which has a public surface to use instead. Reached:
#   - SendspinClient::connection_manager_ and record_store_, the two owners the rest of the file
#     works through: the store answers whether an unpaired record still resolves for this boot,
#     which is what "revoked" means. (The persisted half of the same removal is observable through
#     the test's persistence provider.)
#   - SendspinClient::process_json_message() and admit_connection(), to deliver traffic to a
#     stand-in connection and admit it on the test thread, which is how the hold/replay tests
#     place messages on either side of admission.
#   - ConnectionManager::conn_ptr_mutex_ and SendspinClient::json_processing_mutex_, taken and
#     probed directly by the lock-order test: holding the manager lock exactly where loop() holds
#     it is what makes an admission that reaches for the JSON lock hang the test instead of a
#     device.
#   - SendspinClient::request_persist(), note_last_played_server() and
#     flush_pending_persistence(), plus ConnectionManager::set_current_connection()/
#     flush_pending_admission() and handle_server_unpair()/flush_deferred_releases(): the RAM
#     change and its flush are separate steps on purpose, and only a test that takes them apart
#     can show what one tick coalesces.
#   - SendspinConnection::last_receive_time_us_, held_count_ and held_bytes_, the hold buffer's
#     accounting and the liveness stamp a stand-in connection has no transport to set (and, for
#     the stamp, one the liveness tick test ages directly instead of waiting). Likewise
#     time_frame_tag_ and time_frame_sent_us_, the client/time frame in flight that only a send
#     over a Noise transport records.
#   - ConnectionManager::nursery_ (read under conn_ptr_mutex_), swap_out_pending_events() and
#     DrainedEvents: the outbound open/close callbacks are reachable only through the connect_to()
#     connection that carries them, and whether an event about an already-released connection was
#     dropped or queued is visible only in the pending queues until loop() drains them.
#   - ConnectionManager::push_nursery_entry(), to hand loop() a stand-in connection to promote:
#     when the first client/state leaves relative to admission, and whether the liveness tick
#     drops the connection, are decided inside one tick. The liveness test also reads
#     liveness_timeout_us_, the timeout that tick compares against.
set_source_files_properties(test_encrypted_lifecycle.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_noise_transport.cpp uses it to read the transport ciphers after a loopback handshake and
# the reassembly buffer's capacity. The capacity is the
# only observable of the growth policy (the message that reaches the listener is the same either
# way) and which NoiseTransport exposes nowhere, deliberately: its size is an allocation
# decision, not protocol state. It also seeds SendspinConnection::time_frame_tag_ and
# time_frame_sent_us_ directly, for frame states a send cannot produce on demand: a leftover
# write hook's time earlier than the frame's own, and a write just past the low-32-bit wrap.
set_source_files_properties(test_noise_transport.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_cpace.cpp needs the same treatment for one reason: pinning CPace::derive()/tag()/isk()
# against the reference vectors requires a known scalar, and start() always samples a fresh one
# from the CSPRNG. The fixed-scalar KAT overwrites the private scalar_/public_share_ instead of
# production growing a test-only injection hook. See force_fixed_scalar() in that file.
set_source_files_properties(test_cpace.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# Match the library's sanitizer configuration so the test binary is instrumented too.
if(ENABLE_SANITIZERS)
    target_compile_options(sendspin_tests PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sendspin_tests PRIVATE -fsanitize=address,undefined)
endif()

# ThreadSanitizer, configured separately from ASan/UBSan (the two cannot be combined). The
# concurrency tests only report a data race when the binary is built this way; see
# RecordStoreConcurrency in test_record_store.cpp.
if(ENABLE_TSAN)
    target_compile_options(sendspin_tests PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(sendspin_tests PRIVATE -fsanitize=thread)
endif()

include(GoogleTest)
# Backstop above the 55 s watchdog in main.cpp, which fires first and prints the hung test's
# stack.
gtest_discover_tests(sendspin_tests PROPERTIES TIMEOUT 60)
