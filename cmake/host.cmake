# Host platform configuration for sendspin-cpp

include(FetchContent)

function(sendspin_configure_host TARGET_LIB SOURCE_DIR)
    # =========================================================================
    # Include paths:
    #   - src/host    — host networking headers (client_connection.h, etc.)
    #   - include     — public library headers
    #   - src         — private implementation headers
    # ESP networking headers live in src/esp/ (only added to ESP builds).
    # =========================================================================
    target_include_directories(${TARGET_LIB} PUBLIC ${SOURCE_DIR}/src/host)
    target_include_directories(${TARGET_LIB} PUBLIC ${SOURCE_DIR}/include)
    target_include_directories(${TARGET_LIB} PRIVATE ${SOURCE_DIR}/src)

    # =========================================================================
    # Platform abstraction layer — all host platform code is header-only
    # =========================================================================

    # =========================================================================
    # Host networking sources (IXWebSocket-based implementations)
    # =========================================================================
    target_sources(${TARGET_LIB} PRIVATE ${SENDSPIN_HOST_SOURCES})

    # =========================================================================
    # Compiler settings
    # =========================================================================
    target_compile_features(${TARGET_LIB} PUBLIC cxx_std_20)
    target_compile_options(${TARGET_LIB} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    if(ENABLE_WERROR)
        target_compile_options(${TARGET_LIB} PRIVATE -Werror)
    endif()
    if(ENABLE_SANITIZERS)
        target_compile_options(${TARGET_LIB} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${TARGET_LIB} PUBLIC -fsanitize=address,undefined)
    endif()

    # =========================================================================
    # External dependencies
    # =========================================================================

    # ArduinoJson (header-only)
    FetchContent_Declare(
        ArduinoJson
        GIT_REPOSITORY https://github.com/bblanchon/ArduinoJson.git
        GIT_TAG        v7.4.1
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(ArduinoJson)
    target_link_libraries(${TARGET_LIB} PUBLIC ArduinoJson)
    target_compile_definitions(${TARGET_LIB} PUBLIC
        ARDUINOJSON_ENABLE_STD_STRING=1
        ARDUINOJSON_USE_LONG_LONG=1
    )

    # micro-flac and micro-opus (audio codec libraries, required by decoder)
    FetchContent_Declare(
        micro_flac
        GIT_REPOSITORY https://github.com/esphome-libs/micro-flac.git
        GIT_TAG        v0.1.1
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES "lib/micro-ogg-demuxer"
    )
    FetchContent_MakeAvailable(micro_flac)
    target_link_libraries(${TARGET_LIB} PUBLIC micro_flac)

    FetchContent_Declare(
        micro_opus
        GIT_REPOSITORY https://github.com/esphome-libs/micro-opus.git
        GIT_TAG        v0.3.5
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES "lib/opus" "lib/micro-ogg-demuxer"
    )
    FetchContent_MakeAvailable(micro_opus)
    target_link_libraries(${TARGET_LIB} PUBLIC micro_opus)

    # IXWebSocket (WebSocket server/client for host networking)
    set(USE_TLS OFF CACHE BOOL "" FORCE)
    set(USE_ZLIB OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        IXWebSocket
        GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
        GIT_TAG        v11.4.5
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(IXWebSocket)
    target_link_libraries(${TARGET_LIB} PUBLIC ixwebsocket)

    # Threading support (for shim implementations)
    find_package(Threads REQUIRED)
    target_link_libraries(${TARGET_LIB} PRIVATE Threads::Threads)

    # =========================================================================
    # clang-tidy integration (opt-in via -DENABLE_CLANG_TIDY=ON)
    # Set only on this target so _deps are never analyzed.
    # =========================================================================
    option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
    if(ENABLE_CLANG_TIDY)
        find_program(CLANG_TIDY_EXE
            NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16
            HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
            REQUIRED
        )
        set_target_properties(${TARGET_LIB} PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
    endif()

endfunction()
