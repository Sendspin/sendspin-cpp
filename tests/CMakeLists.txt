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

# One executable aggregating every test_*.cpp file but test_allocations.cpp behind the main.cpp
# watchdog entry point.
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
    test_json_arena.cpp
    test_network_info.cpp
    test_shared_ring_buffer.cpp
    test_inbound_ring.cpp
    test_outbound_ring.cpp
    test_protocol_task.cpp
    test_inbox.cpp
    test_player_role.cpp
    test_controller_role.cpp
    test_enum_set.cpp
    test_inline_text.cpp
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
    test_windows_header_macros.cpp
    test_connection_block.cpp
    test_yield_window.cpp

    # FilePersistenceProvider is a host example helper (examples/common/), not part of the
    # library; compile it into the test target so the record-store tests can exercise it.
    ../examples/common/file_persistence_provider.cpp
)

# test_decoder.cpp compiles with -fno-access-control and names the private members it reaches, and
# why, in its comments.
set_source_files_properties(test_decoder.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_inbox.cpp compiles with -fno-access-control and names the private members it reaches, and
# why, in its comments.
set_source_files_properties(test_inbox.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# Built only with the trace it tests.
if(SENDSPIN_ENABLE_MESSAGE_TRACE)
    target_sources(sendspin_tests PRIVATE test_message_trace.cpp)
endif()

# test_client_lifecycle.cpp compiles with -fno-access-control and names the private members it
# reaches, and why, in its comments.
set_source_files_properties(test_client_lifecycle.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_role_deactivation.cpp compiles with -fno-access-control and names the private members it
# reaches, and why, in its comments.
set_source_files_properties(test_role_deactivation.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_player_role.cpp compiles with -fno-access-control and names the private members it reaches,
# and why, in its comments.
set_source_files_properties(test_player_role.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# The source suite builds only with the role compiled in, so a SENDSPIN_ENABLE_SOURCE=OFF test build
# still links. test_source_role.cpp compiles with -fno-access-control and names the private members
# it reaches, and why, in its comments.
if(SENDSPIN_ENABLE_SOURCE)
    target_sources(sendspin_tests PRIVATE test_source_role.cpp)
    set_source_files_properties(test_source_role.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)
endif()

# test_json_arena.cpp compiles with -fno-access-control and names the private members it reaches,
# and why, in its comments.
set_source_files_properties(test_json_arena.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_inbound_ring.cpp compiles with -fno-access-control and names the private members it reaches,
# and why, in its comments.
set_source_files_properties(test_inbound_ring.cpp PROPERTIES COMPILE_OPTIONS -fno-access-control)

# test_record_store.cpp compiles with -fno-access-control and names the private members it reaches,
# and why, in its comments.
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

# test_allocations.cpp replaces the global operator new to count the library's allocations, so it
# gets a binary of its own: in sendspin_tests the replacement would take the place of the
# sanitizers' operator new and its mismatch checks. Building sendspin_tests builds it too, so the
# documented build and CTest commands cover it.
add_executable(sendspin_alloc_tests main.cpp test_allocations.cpp)
target_include_directories(sendspin_alloc_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto
)
# dladdr() lives in libdl before glibc 2.34; CMAKE_DL_LIBS names it on Linux and is empty on macOS.
target_link_libraries(sendspin_alloc_tests PRIVATE sendspin GTest::gtest ${CMAKE_DL_LIBS})
add_dependencies(sendspin_tests sendspin_alloc_tests)

foreach(test_target sendspin_tests sendspin_alloc_tests)
    # The watchdog in main.cpp prints a backtrace on a hang, and test_allocations.cpp names each
    # allocation's frames; glibc needs exported symbols for both.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(${test_target} PRIVATE -rdynamic)
    endif()
    target_compile_features(${test_target} PRIVATE cxx_std_20)
    target_compile_options(${test_target} PRIVATE -Wall -Wextra)
endforeach()

# test_pairing_state_machine.cpp compiles with -fno-access-control and names the private members it
# reaches, and why, in its comments.
set_source_files_properties(test_pairing_state_machine.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_encrypted_lifecycle.cpp compiles with -fno-access-control and names the private members it
# reaches, and why, in its comments.
set_source_files_properties(test_encrypted_lifecycle.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_noise_transport.cpp compiles with -fno-access-control and names the private members it
# reaches, and why, in its comments.
set_source_files_properties(test_noise_transport.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

# test_cpace.cpp compiles with -fno-access-control and names the private members it reaches, and
# why, in its comments.
set_source_files_properties(test_cpace.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-access-control")

include(GoogleTest)
foreach(test_target sendspin_tests sendspin_alloc_tests)
    # Match the library's sanitizer configuration so the test binaries are instrumented too.
    if(ENABLE_SANITIZERS)
        target_compile_options(${test_target} PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${test_target} PRIVATE -fsanitize=address,undefined)
    endif()

    # ThreadSanitizer, configured separately from ASan/UBSan (the two cannot be combined). The
    # concurrency tests only report a data race when the binary is built this way.
    if(ENABLE_TSAN)
        target_compile_options(${test_target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(${test_target} PRIVATE -fsanitize=thread)
    endif()

    # Backstop above the 55 s watchdog in main.cpp, which fires first and prints the hung test's
    # stack.
    gtest_discover_tests(${test_target} PROPERTIES TIMEOUT 60)
endforeach()
