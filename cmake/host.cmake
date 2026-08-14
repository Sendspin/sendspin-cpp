# Host platform configuration for sendspin-cpp

include(FetchContent)

function(sendspin_configure_host TARGET_LIB SOURCE_DIR)
    # =========================================================================
    # Include paths:
    #   - src/host: host networking headers (client_connection.h, etc.)
    #   - include: public library headers
    #   - src: private implementation headers
    # ESP networking headers live in src/esp/ (only added to ESP builds).
    # =========================================================================
    target_include_directories(${TARGET_LIB} PUBLIC ${SOURCE_DIR}/src/host)
    target_include_directories(${TARGET_LIB} PUBLIC ${SOURCE_DIR}/include)
    target_include_directories(${TARGET_LIB} PRIVATE ${SOURCE_DIR}/src)

    # =========================================================================
    # Platform abstraction layer: all host platform code is header-only
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

    # micro-flac and micro-opus (audio codec libraries, required by player/decoder)
    # Only fetched and linked when the player role is enabled.
    if(SENDSPIN_ENABLE_PLAYER)
        FetchContent_Declare(
            micro_flac
            GIT_REPOSITORY https://github.com/esphome-libs/micro-flac.git
            GIT_TAG        v0.1.1
            GIT_SUBMODULES "lib/micro-ogg-demuxer"
        )
        FetchContent_MakeAvailable(micro_flac)
        target_link_libraries(${TARGET_LIB} PUBLIC micro_flac)

        FetchContent_Declare(
            micro_opus
            GIT_REPOSITORY https://github.com/esphome-libs/micro-opus.git
            GIT_TAG        v0.3.5
            GIT_SUBMODULES "lib/opus" "lib/micro-ogg-demuxer"
        )
        FetchContent_MakeAvailable(micro_opus)
        target_link_libraries(${TARGET_LIB} PUBLIC micro_opus)
    endif()

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
    # noise-c (Noise Protocol Framework implementation)
    #
    # The esphome-libs fork only ships an IDF CMakeLists.txt (idf_component_register),
    # so we cannot use FetchContent_MakeAvailable directly.  Instead we:
    #   1. Populate the esphome-libs fork into _deps/noise_c-src.
    #   2. Populate the rweather/noise-c upstream into _deps/noise_c_upstream-src
    #      to obtain the ghash (GCM authentication) source that the esphome-libs
    #      fork omits but that the reference AESGCM backend requires.
    #   3. Build a `noise_c` STATIC target manually from the exact file list that
    #      the IDF CMakeLists.txt uses (ref backend only, no libsodium, no OpenSSL),
    #      plus the ghash sources from upstream.
    #
    # Compile definitions:
    #   NOISE_USE_REFERENCE_BACKEND=1: use the pure-C reference backend
    #   NOISE_USE_AES=1:               enable AES-GCM (needs ghash)
    #   NOISE_USE_REFERENCE_AES=1:     route AES-GCM through the ref backend
    #   NOISE_USE_LIBSODIUM=0:         disable sodium backend on host
    #   NOISE_USE_CUSTOM_RAND=0:       use the OS RNG (rand_os.c)
    # =========================================================================
    # CMake 3.30+ deprecates calling FetchContent_Populate() directly (CMP0169).
    # We must use it here because the esphome-libs fork ships only an IDF
    # CMakeLists.txt, so FetchContent_MakeAvailable() cannot process it. Opt into
    # the old behavior to keep the manual populate quiet on newer CMake.
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()

    FetchContent_Declare(
        noise_c
        GIT_REPOSITORY https://github.com/esphome-libs/noise-c.git
        GIT_TAG        v0.1.13
        GIT_SHALLOW    TRUE
    )
    FetchContent_GetProperties(noise_c)
    if(NOT noise_c_POPULATED)
        FetchContent_Populate(noise_c)
    endif()

    # Obtain ghash sources from the rweather/noise-c upstream (not in the esphome-libs fork).
    # Pinned to a fixed commit (not master) for reproducible builds. A full SHA cannot be
    # fetched shallowly from GitHub, so GIT_SHALLOW is intentionally omitted here.
    FetchContent_Declare(
        noise_c_upstream
        GIT_REPOSITORY https://github.com/rweather/noise-c.git
        GIT_TAG        cfe25410979a87391bb9ac8d4d4bef64e9f268c6
    )
    FetchContent_GetProperties(noise_c_upstream)
    if(NOT noise_c_upstream_POPULATED)
        FetchContent_Populate(noise_c_upstream)
    endif()

    # Build the noise_c static library with the reference backend + ref AESGCM.
    # noise-c is a C library; suppress any pedantic/extra warnings so our own
    # -Wall -Wextra -Wpedantic flags don't bleed into it (it's a separate target).
    add_library(noise_c STATIC
        # Protocol state machine
        ${noise_c_SOURCE_DIR}/src/protocol/cipherstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/dhstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/errors.c
        ${noise_c_SOURCE_DIR}/src/protocol/handshakestate.c
        ${noise_c_SOURCE_DIR}/src/protocol/hashstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/internal.c
        ${noise_c_SOURCE_DIR}/src/protocol/names.c
        ${noise_c_SOURCE_DIR}/src/protocol/patterns.c
        ${noise_c_SOURCE_DIR}/src/protocol/rand_os.c
        ${noise_c_SOURCE_DIR}/src/protocol/randstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/signstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/symmetricstate.c
        ${noise_c_SOURCE_DIR}/src/protocol/util.c

        # Reference backend: ChaChaPoly + AES-GCM + Curve25519 + SHA-256
        ${noise_c_SOURCE_DIR}/src/backend/ref/cipher-chachapoly.c
        ${noise_c_SOURCE_DIR}/src/backend/ref/cipher-aesgcm.c
        ${noise_c_SOURCE_DIR}/src/backend/ref/dh-curve25519.c
        ${noise_c_SOURCE_DIR}/src/backend/ref/hash-sha256.c

        # Low-level crypto primitives
        ${noise_c_SOURCE_DIR}/src/crypto/chacha/chacha.c
        ${noise_c_SOURCE_DIR}/src/crypto/donna/poly1305-donna.c
        ${noise_c_SOURCE_DIR}/src/crypto/sha2/sha256.c
        ${noise_c_SOURCE_DIR}/src/crypto/aes/rijndael-alg-fst.c
        ${noise_c_SOURCE_DIR}/src/crypto/x25519/x25519.c

        # ghash (GF(2^128) multiply for AES-GCM), from rweather/noise-c upstream
        # (the esphome-libs fork omits this file)
        ${noise_c_upstream_SOURCE_DIR}/src/crypto/ghash/ghash.c
    )

    target_include_directories(noise_c PUBLIC
        ${noise_c_SOURCE_DIR}/include
        ${noise_c_SOURCE_DIR}/src
    )
    # Teach noise_c where to find the upstream ghash header.
    # cipher-aesgcm.c includes "crypto/ghash/ghash.h", so we add the upstream
    # src/ directory to the include path so that relative reference resolves.
    target_include_directories(noise_c PRIVATE
        ${noise_c_upstream_SOURCE_DIR}/src
    )

    target_compile_definitions(noise_c PUBLIC
        NOISE_USE_REFERENCE_BACKEND=1
        NOISE_USE_AES=1
        NOISE_USE_REFERENCE_AES=1
        NOISE_USE_LIBSODIUM=0
        NOISE_USE_CUSTOM_RAND=0
        NOISE_USE_REFERENCE_SHA512=1
    )

    # noise-c is a C library; don't apply sendspin's -Werror or pedantic flags.
    set_target_properties(noise_c PROPERTIES C_STANDARD 99)

    target_link_libraries(${TARGET_LIB} PUBLIC noise_c)

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
