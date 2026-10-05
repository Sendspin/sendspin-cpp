# Source Client Example

Runs the sendspin-cpp client with the source role on a host computer (macOS/Linux), capturing the default PortAudio input device and streaming it to a Sendspin server. The server gates streaming: capture starts on its start command and stops on its stop. When built with mDNS support, it advertises via mDNS so Sendspin servers discover and connect automatically; otherwise connect to a server manually with `-u ws://<server-host>:<port>/<path>`.

## Build

From the repository root:

```sh
cmake -B build
cmake --build build
```

The binary is at `build/examples/source_client/source_client`.

PortAudio is required (the example is skipped without it):

```sh
brew install portaudio               # macOS
sudo apt install portaudio19-dev    # Debian/Ubuntu
```

The example builds only when the source role is enabled (`SENDSPIN_ENABLE_SOURCE`, on by default). `-o` needs `SENDSPIN_ENABLE_OPUS` (also on by default).

### Linux prerequisites

mDNS service advertisement is optional. Install Avahi's Bonjour-compatible headers to enable it:

```sh
sudo apt install libavahi-compat-libdnssd-dev
```

macOS has mDNS support built in; no extra dependencies needed.

## Run

```sh
./build/examples/source_client/source_client              # default name "Source Client"
./build/examples/source_client/source_client "Line In"    # custom name
./build/examples/source_client/source_client -o           # stream Opus instead of PCM
./build/examples/source_client/source_client -p 8930      # listen on a custom port
```

The client listens on port 8928 by default. When mDNS is enabled it advertises `_sendspin._tcp` with the configured port so Sendspin servers on the local network discover and connect automatically; otherwise tell the server to connect with `ws://<this-host>:8928/sendspin`, replacing `8928` if you passed `-p`.

Audio is captured at 48 kHz / 16-bit from the default input device (mono or stereo, following the device), in 20 ms chunks. Chunks are raw PCM by default; with `-o` they are Opus-encoded when the server accepts Opus, and PCM otherwise.

Press Ctrl+C to stop.

## Pairing

Unpaired access stays off, so only a server this client has paired with can start the stream. On startup the example prints its pairing token; paste it into a server that asks for one, or start pairing from the server and enter the code the example prints. The keypair and pairing records persist in `~/.sendspin-source.json`, separate from the basic client's.
