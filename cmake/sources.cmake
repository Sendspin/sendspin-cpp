# Source file definitions for sendspin-cpp

function(sendspin_get_sources BASE_DIR)
    # Common sources — build on both ESP-IDF and host
    set(SENDSPIN_COMMON_SOURCES
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

        # Audio pipeline
        ${BASE_DIR}/src/audio_ring_buffer.cpp
        ${BASE_DIR}/src/decoder.cpp
        ${BASE_DIR}/src/sync_task.cpp

        # Client orchestration
        ${BASE_DIR}/src/client.cpp

        PARENT_SCOPE
    )

    # ESP-IDF only sources — networking layer deeply coupled to ESP-IDF APIs
    set(SENDSPIN_ESP_SOURCES
        ${BASE_DIR}/src/esp/server_connection.cpp
        ${BASE_DIR}/src/esp/client_connection.cpp
        ${BASE_DIR}/src/esp/ws_server.cpp

        PARENT_SCOPE
    )
endfunction()
