# sendspin-cpp

[![CI](https://github.com/Sendspin/sendspin-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/Sendspin/sendspin-cpp/actions/workflows/ci.yml)
[![Component Registry](https://components.espressif.com/components/sendspin/sendspin-cpp/badge.svg)](https://components.espressif.com/components/sendspin/sendspin-cpp)

Standalone C++ library implementing the [Sendspin synchronized audio streaming protocol](https://www.sendspin-audio.com/). Builds on both ESP-IDF (ESP32) and host platforms (macOS/Linux). Designed to be consumed by ESPHome but has no ESPHome dependencies.

[![A project from the Open Home Foundation](https://www.openhomefoundation.org/badges/ohf-project.png)](https://www.openhomefoundation.org/)

## Features

- WebSocket-based audio streaming with server time synchronization
- FLAC, Opus, and PCM audio decoding
- Cross-platform: ESP-IDF (ESP32) and host (macOS/Linux)

## Documentation

- **[Integration Guide](docs/integration-guide.md)** -- How to integrate sendspin-cpp into your application, including required callbacks, role composition, and platform setup
- **[Internals](docs/internals.md)** -- Internal architecture, threading model, and inter-class communication

## Build

### Host (macOS/Linux)

```bash
cmake -B build
cmake --build build
```

Dependencies (fetched automatically via CMake FetchContent): ArduinoJson, micro-flac, micro-opus, IXWebSocket.

### ESP-IDF

Used as an IDF component. Add to your project's `idf_component.yml`.

## Examples

- **`examples/basic_client/`** -- Standalone host example with PortAudio audio output
- **`examples/tui_client/`** -- Terminal UI host example with PortAudio audio output

## License

Apache 2.0
