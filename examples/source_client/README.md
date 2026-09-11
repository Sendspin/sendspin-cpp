# Source Client Example

Runs the sendspin-cpp client with the source role on a host computer (macOS/Linux), capturing the default PortAudio input device and streaming it to the Sendspin server. Streaming is server-gated: the client advertises the source role and waits; capture starts when the server commands the stream to start and stops when it commands stop. When built with mDNS support, advertises via mDNS so Sendspin servers discover and connect automatically; otherwise connect to a server manually with `-u ws://<server-host>:<port>/<path>`.

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

The example builds only when the source role is enabled (`SENDSPIN_ENABLE_SOURCE`, on by default).

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

Audio is captured at 48 kHz / 16-bit from the default input device (mono or stereo, following the device). By default chunks are sent as raw PCM; with `-o` each 20 ms chunk is Opus-encoded before sending.

Press Ctrl+C to stop.
