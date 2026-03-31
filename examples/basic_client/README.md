# Basic Client Example

Runs the sendspin-cpp client on a host computer (macOS/Linux). Advertises via mDNS so Sendspin servers discover and connect automatically.

## Build

From the repository root:

```sh
cmake -B build
cmake --build build
```

The binary is at `build/examples/basic_client/basic_client`.

### Linux prerequisites

```sh
sudo apt install libavahi-compat-libdnssd-dev
```

macOS has mDNS support built in; no extra dependencies needed.

## Run

```sh
./build/examples/basic_client/basic_client            # default name "Basic Client"
./build/examples/basic_client/basic_client "My Player" # custom name
```

The client listens on port 8928 and advertises `_sendspin._tcp` via mDNS. Sendspin servers on the local network will discover and connect to it automatically.

If PortAudio is available, audio is played through the default output device. Otherwise, audio is discarded (NullAudioSink).

Press Ctrl+C to stop.
