# Basic Client Example

Runs the sendspin-cpp client on a host computer (macOS, Linux or Windows). When built with mDNS support, advertises via mDNS so Sendspin servers discover and connect automatically; otherwise connect to a server manually with `-u ws://<server-host>:<port>/<path>`.

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

### Windows

Build with clang-cl (for example `cmake -B build -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl` from a Visual Studio developer prompt). PortAudio is fetched and built from source, so audio plays with no extra install. The binary is `build\examples\basic_client\basic_client.exe`.

There is no mDNS on Windows, so a server cannot discover the client; dial the server with `-u`. The console keys `p` and `c` stand in for `SIGUSR1` and `SIGUSR2` (see [Pairing](#pairing)). The identity file falls back to `%USERPROFILE%` when `HOME` is unset, and inherits its directory's ACL rather than being created 0600.

## Run

```sh
./build/examples/basic_client/basic_client            # default name "Basic Client"
./build/examples/basic_client/basic_client "My Player" # custom name
./build/examples/basic_client/basic_client -p 8930     # listen on a custom port
./build/examples/basic_client/basic_client -s 12345678 # offer a static pairing code
./build/examples/basic_client/basic_client -a          # allow unpaired access
./build/examples/basic_client/basic_client -F -M       # server cannot set volume or mute
```

The client listens on port 8928 by default. When mDNS is enabled it advertises `_sendspin._tcp` with the configured port so Sendspin servers on the local network discover and connect automatically; otherwise tell the server to connect with `ws://<this-host>:8928/sendspin`, replacing `8928` if you passed `-p`.

If PortAudio is available, audio is played through the default output device. Otherwise, decoded audio is discarded (its byte count is tallied but nothing is played).

Press Ctrl+C to stop.

## Pairing

By default the example does not enable unpaired access, so a server has to pair with the client before it can stream; with `-a`, a server can stream without pairing once its operator approves the client. On startup the client prints its `client_id` and its Pairing PSK token to stderr; paste the token into a server that pairs via `pairing_psk`. A server that pairs with a code instead makes the client print a six-digit code to enter on the server. With `-s CODE` the client offers that 8-digit static code rather than a generated one.

The example has no physical pairing-window button, so `SIGUSR1` stands in for the gesture that opens the pairing window and `SIGUSR2` cancels it (on Windows, the console keys `p` and `c`).

Identity and pairing records are stored in `~/.sendspin.json`; delete it to re-provision the client from scratch.
