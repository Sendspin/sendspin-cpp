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

    # Assemble source list from core + enabled roles (driven by Kconfig)
    set(SENDSPIN_ALL_SOURCES ${SENDSPIN_CORE_SOURCES} ${SENDSPIN_ESP_SOURCES})

    set(SENDSPIN_REQUIRES esp_http_server esp_timer esp_ringbuf pthread mbedtls bblanchon__arduinojson)
    set(SENDSPIN_COMPILE_DEFS "")

    if(CONFIG_SENDSPIN_ENABLE_PLAYER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_PLAYER_SOURCES})
        list(APPEND SENDSPIN_REQUIRES esphome__micro-flac esphome__micro-opus)
        list(APPEND SENDSPIN_COMPILE_DEFS SENDSPIN_ENABLE_PLAYER)
    endif()

    if(CONFIG_SENDSPIN_ENABLE_CONTROLLER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_CONTROLLER_SOURCES})
        list(APPEND SENDSPIN_COMPILE_DEFS SENDSPIN_ENABLE_CONTROLLER)
    endif()

    if(CONFIG_SENDSPIN_ENABLE_METADATA)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_METADATA_SOURCES})
        list(APPEND SENDSPIN_COMPILE_DEFS SENDSPIN_ENABLE_METADATA)
    endif()

    if(CONFIG_SENDSPIN_ENABLE_ARTWORK)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_ARTWORK_SOURCES})
        list(APPEND SENDSPIN_COMPILE_DEFS SENDSPIN_ENABLE_ARTWORK)
    endif()

    if(CONFIG_SENDSPIN_ENABLE_VISUALIZER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_VISUALIZER_SOURCES})
        list(APPEND SENDSPIN_COMPILE_DEFS SENDSPIN_ENABLE_VISUALIZER)
    endif()

    # Register the component — uses assembled source list
    idf_component_register(
        SRCS ${SENDSPIN_ALL_SOURCES}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src" "src/esp"
        REQUIRES ${SENDSPIN_REQUIRES}
        PRIV_REQUIRES espressif__esp_websocket_client
    )

    # Apply compile definitions for enabled roles
    foreach(DEF ${SENDSPIN_COMPILE_DEFS})
        target_compile_definitions(${COMPONENT_LIB} PUBLIC ${DEF})
    endforeach()

    # Apply ESP-IDF configuration
    sendspin_configure_esp_idf(${COMPONENT_LIB} ${COMPONENT_DIR})

# ==============================================================================
# Host Build
# ==============================================================================

else()
    project(sendspin VERSION 0.1.0 LANGUAGES CXX)

    # Role selection options
    option(SENDSPIN_ENABLE_PLAYER "Enable player role (audio decoding)" ON)
    option(SENDSPIN_ENABLE_CONTROLLER "Enable controller role" ON)
    option(SENDSPIN_ENABLE_METADATA "Enable metadata role" ON)
    option(SENDSPIN_ENABLE_ARTWORK "Enable artwork role" ON)
    option(SENDSPIN_ENABLE_VISUALIZER "Enable visualizer role" ON)

    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/host.cmake)

    # Get sources
    sendspin_get_sources(${CMAKE_CURRENT_SOURCE_DIR})

    # Assemble source list from core + enabled roles
    set(SENDSPIN_ALL_SOURCES ${SENDSPIN_CORE_SOURCES})

    if(SENDSPIN_ENABLE_PLAYER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_PLAYER_SOURCES})
    endif()
    if(SENDSPIN_ENABLE_CONTROLLER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_CONTROLLER_SOURCES})
    endif()
    if(SENDSPIN_ENABLE_METADATA)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_METADATA_SOURCES})
    endif()
    if(SENDSPIN_ENABLE_ARTWORK)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_ARTWORK_SOURCES})
    endif()
    if(SENDSPIN_ENABLE_VISUALIZER)
        list(APPEND SENDSPIN_ALL_SOURCES ${SENDSPIN_VISUALIZER_SOURCES})
    endif()

    # Create the library — core sources + enabled role sources + host networking (added via host.cmake)
    add_library(sendspin STATIC ${SENDSPIN_ALL_SOURCES})

    # Add compile definitions for enabled roles
    if(SENDSPIN_ENABLE_PLAYER)
        target_compile_definitions(sendspin PUBLIC SENDSPIN_ENABLE_PLAYER)
    endif()
    if(SENDSPIN_ENABLE_CONTROLLER)
        target_compile_definitions(sendspin PUBLIC SENDSPIN_ENABLE_CONTROLLER)
    endif()
    if(SENDSPIN_ENABLE_METADATA)
        target_compile_definitions(sendspin PUBLIC SENDSPIN_ENABLE_METADATA)
    endif()
    if(SENDSPIN_ENABLE_ARTWORK)
        target_compile_definitions(sendspin PUBLIC SENDSPIN_ENABLE_ARTWORK)
    endif()
    if(SENDSPIN_ENABLE_VISUALIZER)
        target_compile_definitions(sendspin PUBLIC SENDSPIN_ENABLE_VISUALIZER)
    endif()

    # Host build options
    option(ENABLE_WERROR "Treat warnings as errors" OFF)
    option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

    # Apply host configuration
    sendspin_configure_host(sendspin ${CMAKE_CURRENT_SOURCE_DIR})

    # Examples
    add_subdirectory(examples/basic_client)
    add_subdirectory(examples/tui_client)

endif()
