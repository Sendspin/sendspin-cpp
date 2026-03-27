# ESP-IDF specific configuration for sendspin-cpp

function(sendspin_configure_esp_idf TARGET_LIB COMPONENT_DIR)
    target_compile_features(${TARGET_LIB} PUBLIC cxx_std_20)
    target_compile_options(${TARGET_LIB} PRIVATE
        -Wall
        -Wextra
        -Wno-sign-conversion
        -Wno-conversion
    )

    # ArduinoJson configuration - must be set before ArduinoJson.h is included
    target_compile_definitions(${TARGET_LIB} PUBLIC
        ARDUINOJSON_ENABLE_STD_STRING=1
        ARDUINOJSON_USE_LONG_LONG=1
    )

    # Enable debug-level logging for this library regardless of ESP-IDF's global default.
    # ESP-IDF defaults to ERROR in ESPHome, which compiles out all INFO/DEBUG/WARN logs.
    # LOG_LOCAL_LEVEL overrides the compile-time maximum for this component only.
    target_compile_definitions(${TARGET_LIB} PRIVATE
        LOG_LOCAL_LEVEL=ESP_LOG_DEBUG
    )
endfunction()
