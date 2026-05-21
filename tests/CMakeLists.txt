# Host unit tests for sendspin-cpp
#
# Enabled from the top-level CMakeLists.txt with -DSENDSPIN_BUILD_TESTS=ON.
# Tests link against the `sendspin` static library and exercise its internal
# logic directly (white-box: they include private headers from src/).

include(FetchContent)

# GoogleTest — fetched the same way as the library's other dependencies.
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)  # only gtest_main is used; skip building gmock
FetchContent_MakeAvailable(googletest)

# One executable aggregating every test_*.cpp file. gtest_discover_tests still
# registers the individual TEST() cases with CTest so failures are reported per case.
add_executable(sendspin_tests
    test_audio_stream_info.cpp
    test_time_filter.cpp
    test_protocol.cpp
)

# Reach the library's private headers (protocol_messages.h, time_filter.h, ...).
# The public include/ dir and ArduinoJson propagate transitively from `sendspin`.
# Use CMAKE_CURRENT_SOURCE_DIR (not CMAKE_SOURCE_DIR) so the path stays correct even
# if sendspin is ever added as a subdirectory of a larger superproject.
target_include_directories(sendspin_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

target_link_libraries(sendspin_tests PRIVATE sendspin GTest::gtest_main)

target_compile_features(sendspin_tests PRIVATE cxx_std_20)
target_compile_options(sendspin_tests PRIVATE -Wall -Wextra)

# Match the library's sanitizer configuration so the test binary is instrumented too.
if(ENABLE_SANITIZERS)
    target_compile_options(sendspin_tests PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sendspin_tests PRIVATE -fsanitize=address,undefined)
endif()

include(GoogleTest)
gtest_discover_tests(sendspin_tests)
