# Basic Client Example

Runs the sendspin-cpp client on a host computer (macOS/Linux). When built with mDNS support, advertises via mDNS so Sendspin servers discover and connect automatically; otherwise connect to a server manually with `-u ws://<server-host>:<port>/<path>`.

## Build

From the repository root:

```sh
cmake -B build
cmake --build build
```

The binary is at `build/examples/basic_client/basic_client`.

### Linux prerequisites

mDNS service advertisement is optional. Install Avahi's Bonjour-compatible headers to enable it:

```sh
sudo apt install libavahi-compat-libdnssd-dev
```

macOS has mDNS support built in; no extra dependencies needed.

## Run

```sh
./build/examples/basic_client/basic_client            # default name "Basic Client"
./build/examples/basic_client/basic_client "My Player" # custom name
```

The client listens on port 8928. When mDNS is enabled it advertises `_sendspin._tcp` so Sendspin servers on the local network discover and connect automatically; otherwise tell the server to connect with `ws://<this-host>:8928/sendspin`.

If PortAudio is available, audio is played through the default output device. Otherwise, audio is discarded (NullAudioSink).

Press Ctrl+C to stop.
