include(FetchContent)

FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG        v5.0.0
    GIT_SHALLOW    TRUE
)
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(ftxui)

add_executable(tui_client main.cpp tui.cpp)
target_link_libraries(tui_client PRIVATE
    sendspin
    ftxui::screen
    ftxui::dom
    ftxui::component
)
target_compile_features(tui_client PRIVATE cxx_std_20)

# mDNS service advertisement via dns_sd.h
# macOS: built-in (no extra link flags needed — dns_sd is in libSystem)
# Linux: requires libavahi-compat-libdnssd-dev (link with -ldns_sd)
if(NOT APPLE)
    target_link_libraries(tui_client PRIVATE dns_sd)
endif()

# PortAudio (optional — enables audio playback via PortAudioSink)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PORTAUDIO portaudio-2.0)
endif()

if(PORTAUDIO_FOUND)
    target_sources(tui_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common/portaudio_sink.cpp)
    target_include_directories(tui_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common ${PORTAUDIO_INCLUDE_DIRS})
    target_link_directories(tui_client PRIVATE ${PORTAUDIO_LIBRARY_DIRS})
    target_link_libraries(tui_client PRIVATE ${PORTAUDIO_LINK_LIBRARIES})
    target_compile_definitions(tui_client PRIVATE SENDSPIN_HAS_PORTAUDIO=1)
    message(STATUS "PortAudio found — PortAudioSink enabled for TUI")
else()
    message(STATUS "PortAudio not found — TUI will not have audio playback")
endif()
