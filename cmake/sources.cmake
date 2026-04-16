# Source file definitions for sendspin-cpp

function(sendspin_get_sources BASE_DIR)
    # Core sources — always compiled on both ESP-IDF and host
    set(SENDSPIN_CORE_SOURCES
        # Audio utilities
        ${BASE_DIR}/src/audio_stream_info.cpp
        ${BASE_DIR}/src/transfer_buffer.cpp

        # Protocol
        ${BASE_DIR}/src/protocol.cpp

        # Time synchronization
        ${BASE_DIR}/src/time_filter.cpp
        ${BASE_DIR}/src/time_burst.cpp

        # Connection base class
        ${BASE_DIR}/src/connection.cpp

        # Connection management
        ${BASE_DIR}/src/connection_manager.cpp

        # Client orchestration
        ${BASE_DIR}/src/client.cpp

        PARENT_SCOPE
    )

    # Per-role source sets — conditionally compiled based on SENDSPIN_ENABLE_* options
    set(SENDSPIN_PLAYER_SOURCES
        ${BASE_DIR}/src/player_role.cpp
        ${BASE_DIR}/src/audio_ring_buffer.cpp
        ${BASE_DIR}/src/decoder.cpp
        ${BASE_DIR}/src/sync_task.cpp

        PARENT_SCOPE
    )

    set(SENDSPIN_CONTROLLER_SOURCES
        ${BASE_DIR}/src/controller_role.cpp

        PARENT_SCOPE
    )

    set(SENDSPIN_METADATA_SOURCES
        ${BASE_DIR}/src/metadata_role.cpp

        PARENT_SCOPE
    )

    set(SENDSPIN_ARTWORK_SOURCES
        ${BASE_DIR}/src/artwork_role.cpp

        PARENT_SCOPE
    )

    set(SENDSPIN_VISUALIZER_SOURCES
        ${BASE_DIR}/src/visualizer_role.cpp

        PARENT_SCOPE
    )

    # ESP-IDF only sources — networking layer deeply coupled to ESP-IDF APIs
    set(SENDSPIN_ESP_SOURCES
        ${BASE_DIR}/src/esp/server_connection.cpp
        ${BASE_DIR}/src/esp/client_connection.cpp
        ${BASE_DIR}/src/esp/ws_server.cpp

        PARENT_SCOPE
    )

    # Host only sources — IXWebSocket-based networking
    set(SENDSPIN_HOST_SOURCES
        ${BASE_DIR}/src/host/ws_server.cpp
        ${BASE_DIR}/src/host/server_connection.cpp
        ${BASE_DIR}/src/host/client_connection.cpp

        PARENT_SCOPE
    )
endfunction()
