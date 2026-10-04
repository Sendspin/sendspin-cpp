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

# test_client_lifecycle.cpp checks what a role's stop() left on its item list, which nothing on
# the public surface reports, and plays the protocol task on the test thread to install a stand-in
# connection in ConnectionManager's admitted slot, to stage an accept or a full command queue at
# stop(), and to hand on_new_connection() a delivery; it reads the private members directly instead
# of adding a seam. Reached: SendspinClient::connection_manager_, protocol_task_, protocol_tick(),
# player_ and each role's impl_ (the sync task, which a feeder thread hands chunks to directly, and
# the visualizer's drain list, whose links it reads under the list's lock); ProtocolTask's
# command_mutex_ and command_count_ (how many commands wait); ConnectionManager's admitted_,
# nursery_, install_admitted(), refresh_published_state(), scan_nursery(), close_admission() and
# drop_connection() (to install, swap out, and drop a stand-in connection, and to run one scan);
# and SendspinConnection's noise_handshake_complete_ (a stand-in's finished handshake) and its
# transport side, begin_inbound_message() and end_inbound_message() (a stand-in's transport writing
# a ring item and a fallback message). The ring-size tables read SendspinClient::inbound_ring_ and
# InboundRing::storage_, the ring a start() created, whose size no public call reports. The
# next-deadline tables also stage each timer state against a fixed clock, which no public call can
# do: ConnectionManager's liveness_timeout_us_, pairing_window_open_until_us_,
# ws_server_start_retry_time_us_ and tick(); SendspinTimeBurst's burst_index_,
# last_burst_complete_time_, pending_embedded_, current_message_sent_time_, send_retry_after_ms_
# and pending_burst_completed_; and SendspinConnection's first_activate_received_ and
# last_receive_time_us_. The stale-command and refused-delivery tests reach the queue through
# protocol_task_ to push a command, or close accepts, the way a race or stop() would; the full
# queue test seeds the controller's supported_commands word (stamped with its cleanup_generation)
# so a send_command() reaches the queue. The teardown reorder table interleaves the protocol task
# (and, for artwork, the decode thread) with the main loop, which no public call does on demand:
# it calls each role's handler or teardown (the controller, metadata and color roles'
# handle_server_state(), the player's handle_stream_start() and handle_server_command(), the
# visualizer's handle_stream_start(), each role's cleanup()) and drain step (drain_events(), the
# visualizer's catch_up_teardown()), writes the generation-stamped slots (event_state, artwork's
# display_slot under its slot_epochs) and queues a STREAM_START (enqueue_stream_event()) with an
# old stamp, and reads cleanup_generation and the applied state (controller_state, metadata,
# color, the player's stream_active, current_stream_params and volume); its player runs with the
# sync thread stopped and the item list bound by hand (SyncTask's stop() and inbound_), so a
# STREAM_END never waits for a thread to go idle. The high-performance grant tables
# play the protocol task's run_time_sync() on a stand-in in the admitted slot (find_admitted(),
# its high_performance_held) and read the stand-in's time_frame_tag_, the one trace of a time
# frame written without a Noise session; the wake test restarts the protocol task
# (protocol_task_->start()) with liveness off (liveness_timeout_us_) so the grant is the only
# wake, and polls the client's Inbox through a role's impl_->inbox, which also lets the reorder
# table fill the event ring. The stream-events table drives the player's handle_stream_start()
# and handle_stream_end() as the task would, and stages one interleaving by waiting on the sync
# task's item list and the player's sync-idle topic bit, and its clear row calls
# handle_stream_clear() the same way. The next-stream header table plays the sync task itself on
# the test thread, because no public call holds the task between its ACTIVE load and its next
# IDLE wait: it calls SyncTask's wait_for_codec_header() and load_next_chunk() and returns items
# through its inbound_,
# resets the flags with event_flags_.clear_all() as start() would, sets and reads SyncContext's
# active_ordinal and next_header, and reads PlayerRole::Impl::stream_ordinal.
set_source_files_properties(test_client_lifecycle.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_role_deactivation.cpp reads what a removed role left behind and drives the pieces the
# public surface does not expose: the sync task's run state and its item list, the artwork
# transfer in flight and its drain-side slot buffers, the visualizer's stream flag and list, a
# state role's held scheduled update and its teardown generation (including a direct
# handle_server_state() call with that generation), the controller's supported-commands word
# (seeded, stamped with the role's generation, so a command reaches the inactive-role send gate),
# plus the queued-event probe that proves
# ordering without a sleep (a role inbox's topic bits).
set_source_files_properties(test_role_deactivation.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_player_role.cpp drives PlayerRole::Impl directly - no connected server, no sync-task
# thread - which is the only way to see the client/state player object and the only way to hand
# a handler a stale teardown generation. Reached: Impl's handle_stream_start(), handle_binary(),
# handle_stream_clear(), handle_server_command(), cleanup(), recall_stale_items(), attach_inbox(),
# drain_events(), volume, cleanup_generation and event_state's generation-stamped slots (one
# written with a stamp from before a teardown, the payload a drain on the far side of it would
# hold); SyncTask's inbound_ (and take_item()), bound to a test ring the way start() binds it but
# with no thread, so what a handler handed over (or, refused, did not) stays on the list to be
# read, and discard_to_clear_marker(), the sync thread's stream/clear step. The inbound tests
# also bind a VisualizerRole::Impl to the same ring, to show one holder's quota does not stop the
# other.
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
#   - SendspinClient::process_json_message(), process_binary_message(), protocol_tick() and
#     protocol_task_, to deliver traffic to a stand-in connection on the test thread. Those
#     fixtures stop the protocol task after start() and play it themselves, since a second thread
#     running the same entry points would race them.
#   - SendspinClient::request_persist(), note_last_played_server() and
#     flush_pending_persistence(), plus ConnectionManager::install_admitted(),
#     note_playback_activity() and handle_server_unpair(): the RAM change and its flush are
#     separate steps on purpose, and only a test that takes them apart can show what one drain
#     coalesces.
#   - SendspinConnection::last_receive_time_us_, the liveness stamp a stand-in connection has no
#     transport to set (and one the liveness tick test ages directly instead of waiting). Likewise
#     time_frame_tag_ and time_frame_sent_us_, the client/time frame in flight that only a send
#     over a Noise transport records.
#   - ConnectionManager::admitted_, primary(), nursery_, refresh_published_state() and
#     liveness_timeout_us_: a stand-in connection handed to the nursery is promoted by one
#     protocol tick, which decides when the first client/state leaves relative to admission and
#     whether the liveness scan drops the connection.
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
