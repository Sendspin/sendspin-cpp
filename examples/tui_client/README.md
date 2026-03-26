# TUI Client Example

Runs the sendspin-cpp client with a terminal user interface showing playback info, volume, progress, and keyboard controls. Requires PortAudio for audio playback.

## Build

From the repository root:

```sh
cmake -B build
cmake --build build
```

The binary is at `build/examples/tui_client/tui_client`.

### Linux prerequisites

```sh
sudo apt install libavahi-compat-libdnssd-dev portaudio19-dev
```

macOS has mDNS support built in. Install PortAudio via Homebrew:

```sh
brew install portaudio
```

## Run

```sh
./build/examples/tui_client/tui_client                        # default name "TUI Client"
./build/examples/tui_client/tui_client "My Player"            # custom name
./build/examples/tui_client/tui_client -u ws://192.168.1.10:8928/sendspin  # connect to a specific server
./build/examples/tui_client/tui_client -V                     # disable visualizer
```

Press `q` to quit.
