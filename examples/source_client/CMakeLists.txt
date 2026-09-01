# PortAudio is required: this example captures the default input device, so without
# PortAudio there is nothing to stream and the target is skipped entirely.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PORTAUDIO portaudio-2.0)
endif()

if(NOT PORTAUDIO_FOUND)
    message(STATUS "Skipping source_client example (PortAudio not found). Install portaudio "
                   "(brew install portaudio / apt install portaudio19-dev) to enable it.")
    return()
endif()

add_executable(source_client main.cpp)
target_link_libraries(source_client PRIVATE sendspin)
target_compile_features(source_client PRIVATE cxx_std_20)

target_include_directories(source_client PRIVATE ${PORTAUDIO_INCLUDE_DIRS})
target_link_directories(source_client PRIVATE ${PORTAUDIO_LIBRARY_DIRS})
target_link_libraries(source_client PRIVATE ${PORTAUDIO_LINK_LIBRARIES})

# mDNS service advertisement via dns_sd.h (optional)
# macOS: built-in (no extra link flags needed — dns_sd is in libSystem)
# Linux: requires libavahi-compat-libdnssd-dev (provides dns_sd.h + libdns_sd)
if(APPLE)
    target_compile_definitions(source_client PRIVATE SENDSPIN_HAS_MDNS=1)
    message(STATUS "mDNS advertisement enabled (Bonjour built-in)")
else()
    find_path(SOURCE_CLIENT_DNS_SD_INCLUDE_DIR dns_sd.h)
    find_library(SOURCE_CLIENT_DNS_SD_LIBRARY dns_sd)
    if(SOURCE_CLIENT_DNS_SD_INCLUDE_DIR AND SOURCE_CLIENT_DNS_SD_LIBRARY)
        target_include_directories(source_client PRIVATE ${SOURCE_CLIENT_DNS_SD_INCLUDE_DIR})
        target_link_libraries(source_client PRIVATE ${SOURCE_CLIENT_DNS_SD_LIBRARY})
        target_compile_definitions(source_client PRIVATE SENDSPIN_HAS_MDNS=1)
        message(STATUS "mDNS advertisement enabled (${SOURCE_CLIENT_DNS_SD_LIBRARY})")
    else()
        message(STATUS "mDNS advertisement disabled. Install libavahi-compat-libdnssd-dev "
                       "(Debian/Ubuntu) to enable; clients can still connect via -u ws://...")
    endif()
endif()
