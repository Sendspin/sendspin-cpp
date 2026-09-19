# TUI Client Example

Runs the sendspin-cpp client with a terminal user interface showing playback info, volume, progress, and keyboard controls. Requires PortAudio for audio playback.

The client takes the player, controller, metadata, artwork, color and visualizer roles. Artwork images are reported by channel and size rather than drawn, and the audio-derived palette is shown as its RGB values, so a terminal can still show that both roles are being served.

## Build

From the repository root:

```sh
cmake -B build
cmake --build build
```

The binary is at `build/examples/tui_client/tui_client`.

### Linux prerequisites

PortAudio enables audio playback:

```sh
sudo apt install portaudio19-dev
```

mDNS server discovery is optional. Install Avahi's Bonjour-compatible headers to enable it:

```sh
sudo apt install libavahi-compat-libdnssd-dev
```

Without it the in-TUI server picker stays empty and you must use `-u ws://server-host:port/path` to connect.

macOS has mDNS support built in. Install PortAudio via Homebrew:

```sh
brew install portaudio
```

## Run

```sh
./build/examples/tui_client/tui_client                        # default name "TUI Client"
./build/examples/tui_client/tui_client "My Player"            # custom name
./build/examples/tui_client/tui_client -u ws://192.168.1.10:8928/sendspin  # connect to a specific server
./build/examples/tui_client/tui_client -p 8930                # listen on a custom port
./build/examples/tui_client/tui_client -V                     # disable visualizer
```

Press `q` to quit.

## Pairing

Every connection is encrypted, so a server has to pair with the client before it can stream. The Server panel shows the connection's trust and, when a server pairs with a code, the six-digit code to enter there. A Pairing Token panel holds the Pairing PSK token to paste into a server that pairs via `pairing_psk`, and disappears once the connection is paired.

Identity and pairing records are stored in `~/.sendspin_tui.json`, separate from basic_client's file; delete it to re-provision the client from scratch.
