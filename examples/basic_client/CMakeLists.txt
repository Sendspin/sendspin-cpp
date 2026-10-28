add_executable(basic_client main.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/file_persistence_provider.cpp)
target_link_libraries(basic_client PRIVATE sendspin)
target_compile_features(basic_client PRIVATE cxx_std_20)
target_include_directories(basic_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common)

# mDNS service advertisement via dns_sd.h (optional)
# macOS: built-in (no extra link flags needed; dns_sd is in libSystem)
# Linux: requires libavahi-compat-libdnssd-dev (provides dns_sd.h + libdns_sd)
if(APPLE)
    target_compile_definitions(basic_client PRIVATE SENDSPIN_HAS_MDNS=1)
    message(STATUS "mDNS advertisement enabled (Bonjour built-in)")
else()
    find_path(BASIC_CLIENT_DNS_SD_INCLUDE_DIR dns_sd.h)
    find_library(BASIC_CLIENT_DNS_SD_LIBRARY dns_sd)
    if(BASIC_CLIENT_DNS_SD_INCLUDE_DIR AND BASIC_CLIENT_DNS_SD_LIBRARY)
        target_include_directories(basic_client PRIVATE ${BASIC_CLIENT_DNS_SD_INCLUDE_DIR})
        target_link_libraries(basic_client PRIVATE ${BASIC_CLIENT_DNS_SD_LIBRARY})
        target_compile_definitions(basic_client PRIVATE SENDSPIN_HAS_MDNS=1)
        message(STATUS "mDNS advertisement enabled (${BASIC_CLIENT_DNS_SD_LIBRARY})")
    else()
        message(STATUS "mDNS advertisement disabled. Install libavahi-compat-libdnssd-dev "
                       "(Debian/Ubuntu) to enable; clients can still connect via -u ws://...")
    endif()
endif()

# PortAudio (optional; enables audio playback via PortAudioSink)
if(WIN32)
    # getenv() and _open() in the persistence provider, which the CRT deprecates for its _s variants
    target_compile_definitions(basic_client PRIVATE _CRT_SECURE_NO_WARNINGS)
    # Windows has no pkg-config or system PortAudio, so build it from source as a static library.
    include(FetchContent)
    FetchContent_Declare(
        portaudio
        GIT_REPOSITORY https://github.com/PortAudio/portaudio.git
        GIT_TAG        v19.7.0
        GIT_SHALLOW    TRUE
    )
    set(PA_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    # v19.7.0 declares cmake_minimum_required(VERSION 3.1), which CMake 4 rejects
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    FetchContent_MakeAvailable(portaudio)
    unset(CMAKE_POLICY_VERSION_MINIMUM)
    set(PORTAUDIO_FOUND TRUE)
    set(PORTAUDIO_LINK_LIBRARIES portaudio_static)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PORTAUDIO portaudio-2.0)
    endif()
endif()

if(PORTAUDIO_FOUND)
    target_sources(basic_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common/portaudio_sink.cpp)
    target_include_directories(basic_client PRIVATE ${PORTAUDIO_INCLUDE_DIRS})
    target_link_directories(basic_client PRIVATE ${PORTAUDIO_LIBRARY_DIRS})
    target_link_libraries(basic_client PRIVATE ${PORTAUDIO_LINK_LIBRARIES})
    target_compile_definitions(basic_client PRIVATE SENDSPIN_HAS_PORTAUDIO=1)
    message(STATUS "PortAudio found - PortAudioSink enabled")
else()
    message(STATUS "PortAudio not found - PortAudioSink will not be available")
endif()
