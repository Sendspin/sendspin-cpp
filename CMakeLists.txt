# CMakeLists.txt for sendspin-cpp
# Supports both ESP-IDF component builds and standalone host builds
#
# Structure:
#   cmake/sources.cmake   - Source file definitions
#   cmake/esp-idf.cmake   - ESP-IDF specific configuration
#   cmake/host.cmake      - Host platform configuration

cmake_minimum_required(VERSION 3.16)

# ==============================================================================
# Build type detection
# ==============================================================================

if(DEFINED IDF_TARGET)
    set(ESP_IDF_BUILD TRUE)
else()
    set(ESP_IDF_BUILD FALSE)
endif()

# Set source directory variable for consistent use
if(ESP_IDF_BUILD)
    set(SENDSPIN_COMPONENT_DIR ${COMPONENT_DIR})
else()
    set(SENDSPIN_COMPONENT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# ==============================================================================
# Include CMake modules
# ==============================================================================

include(${SENDSPIN_COMPONENT_DIR}/cmake/sources.cmake)

# ==============================================================================
# ESP-IDF Build
# ==============================================================================

if(ESP_IDF_BUILD)
    include(${SENDSPIN_COMPONENT_DIR}/cmake/esp-idf.cmake)

    # Collect sources
    sendspin_get_sources(${SENDSPIN_COMPONENT_DIR})

    set(SENDSPIN_REQUIRES esp_http_server esp_timer esp_ringbuf pthread mbedtls bblanchon__arduinojson micro-flac esphome__micro-opus)

    # Register the component — uses both common and ESP-specific sources
    idf_component_register(
        SRCS ${SENDSPIN_COMMON_SOURCES} ${SENDSPIN_ESP_SOURCES}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src" "src/esp"
        REQUIRES ${SENDSPIN_REQUIRES}
        PRIV_REQUIRES espressif__esp_websocket_client
    )

    # Apply ESP-IDF configuration
    sendspin_configure_esp_idf(${COMPONENT_LIB} ${COMPONENT_DIR})

# ==============================================================================
# Host Build
# ==============================================================================

else()
    project(sendspin VERSION 0.1.0 LANGUAGES CXX)

    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/host.cmake)

    # Get sources
    sendspin_get_sources(${CMAKE_CURRENT_SOURCE_DIR})

    # Create the library — common sources + host networking (added via host.cmake)
    add_library(sendspin STATIC ${SENDSPIN_COMMON_SOURCES})

    # Host build options
    option(ENABLE_WERROR "Treat warnings as errors" OFF)
    option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

    # Apply host configuration
    sendspin_configure_host(sendspin ${CMAKE_CURRENT_SOURCE_DIR})

    # Examples
    add_subdirectory(examples/basic_client)
    add_subdirectory(examples/tui_client)

endif()
