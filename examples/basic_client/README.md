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
./build/examples/basic_client/basic_client -p 8930     # listen on a custom port
./build/examples/basic_client/basic_client -s 12345678 # offer a static pairing code
```

The client listens on port 8928 by default. When mDNS is enabled it advertises `_sendspin._tcp` with the configured port so Sendspin servers on the local network discover and connect automatically; otherwise tell the server to connect with `ws://<this-host>:8928/sendspin`, replacing `8928` if you passed `-p`.

If PortAudio is available, audio is played through the default output device. Otherwise, decoded audio is discarded (its byte count is tallied but nothing is played).

Press Ctrl+C to stop.

## Pairing

Every connection is encrypted, so a server has to pair with the client before it can stream. On startup the client prints its `client_id` and its Pairing PSK token to stderr; paste the token into a server that pairs via `pairing_psk`. A server that pairs with a code instead makes the client print a six-digit code to enter on the server. With `-s CODE` the client offers that 8-digit static code rather than a generated one.

The example has no physical pairing-window button, so `SIGUSR1` stands in for the gesture that opens the pairing window and `SIGUSR2` cancels it.

Identity and pairing records are stored in `~/.sendspin.json`; delete it to re-provision the client from scratch.
