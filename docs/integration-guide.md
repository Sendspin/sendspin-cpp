# Integration Guide

This guide describes what you need to implement in order to integrate sendspin-cpp into your application. The library provides the Sendspin protocol, audio decoding, and time synchronization. You provide the audio output, network readiness, and optional persistence.

## Overview

Integration follows this pattern:

1. Create a `SendspinClient` with a configuration struct
2. Add roles (player, controller, metadata, artwork, visualizer, color, source) depending on what your application needs
3. Implement listener interfaces for the roles you added
4. Implement a network provider (required) and optionally a persistence provider
5. Wire listeners and providers to the client and roles
6. Start the server and run the main loop

The only role with a required callback is the player role (`on_audio_write`). All other listener methods have default no-op implementations.

## Headers

Include `sendspin/client.h` for the client class, config types, and shared types. Role headers must be included explicitly for any roles you use:

```cpp
#include "sendspin/client.h"          // SendspinClient, providers, listeners
#include "sendspin/player_role.h"     // PlayerRole, PlayerRoleListener
#include "sendspin/controller_role.h" // ControllerRole, ControllerRoleListener
#include "sendspin/metadata_role.h"   // MetadataRole, MetadataRoleListener
#include "sendspin/artwork_role.h"    // ArtworkRole, ArtworkRoleListener
#include "sendspin/visualizer_role.h" // VisualizerRole, VisualizerRoleListener
#include "sendspin/color_role.h"      // ColorRole, ColorRoleListener
#include "sendspin/source_role.h"     // SourceRole, SourceRoleListener
```

Only include the role headers you need. `client.h` includes `sendspin/config.h` (all configuration structs, including `SendspinClientConfig`) and `sendspin/types.h` transitively.

## Step 1: Configure and Create the Client

```cpp
using namespace sendspin;

// Optional: set log level before creating the client (host builds only, no-op on ESP-IDF)
SendspinClient::set_log_level(LogLevel::INFO);

SendspinClientConfig config;
config.name = "Living Room Speaker";            // Friendly display name
config.product_name = "My Speaker";             // Device product name (optional)
config.manufacturer = "My Company";             // Manufacturer name (optional)
config.software_version = "1.0.0";              // Software version string (optional)

SendspinClient client(std::move(config));
```

`client_id` is not a configuration field. The library derives it automatically from the
static X25519 keypair (`base64url(public_key)`, 43 characters). The keypair is generated
on first boot and, when a `SendspinPersistenceProvider` is set, persisted so that the same
identity survives reboots. After `start()` the derived `client_id` is available
via `client.client_id()`.

The `client_id` uniquely identifies this device to Sendspin servers and must be stable
across reboots for pairing and server-preference to work correctly. Without a persistence
provider the keypair is regenerated on every boot (development use only).

## Step 2: Add Roles

Add only the roles your application needs. All roles must be added before calling `start()`.

### Player Role (Audio Playback)

The player role handles audio decoding and synchronized playback. It requires a configuration struct that declares which audio formats your hardware supports.

```cpp
PlayerRoleConfig player_config;
player_config.audio_formats = {
    {SendspinCodecFormat::FLAC, 2, 44100, 16},
    {SendspinCodecFormat::FLAC, 2, 48000, 16},
#ifdef SENDSPIN_ENABLE_OPUS
    {SendspinCodecFormat::OPUS, 2, 48000, 16},
#endif
    {SendspinCodecFormat::PCM, 2, 44100, 16},
    {SendspinCodecFormat::PCM, 2, 48000, 16},
};
player_config.audio_buffer_capacity = 1000000;   // Encoded audio held, in bytes (default: 1000000)
player_config.fixed_delay_us = 0;                // Fixed delay offset in microseconds
player_config.initial_output_delay_ms = 0;       // Initial user-adjustable delay
player_config.extra_startup_silence_ms = 50;     // Extra startup silence for decode headroom (default: 50)
// player_config.required_lead_time_ms = 150;   // Startup lead requested from the server;
                                                 // unset derives it from the pipeline
player_config.min_buffer_ms = 500;               // Ongoing buffer requested from the server (default: 500)

auto& player = client.add_player(std::move(player_config));
```

Each `AudioSupportedFormatObject` declares a codec/channels/sample_rate/bit_depth combination. The server selects from these when establishing an audio stream. The list must include at least one `FLAC` or `PCM` entry, since those are the codecs every server supports; `client.start()` fails and logs if it does not. `OPUS` is optional and needs a build with the Opus decoder (`SENDSPIN_ENABLE_OPUS`, on by default); `client.start()` also fails on an `OPUS` entry without it.

The stream parameters negotiated by the server are available via `get_current_stream_params()`, which returns a `ServerPlayerStreamObject` with these fields:

| Field | Type | Description |
|---|---|---|
| `codec` | `std::optional<SendspinCodecFormat>` | Audio codec |
| `sample_rate` | `std::optional<uint32_t>` | Sample rate in Hz |
| `channels` | `std::optional<uint8_t>` | Number of channels |
| `bit_depth` | `std::optional<uint8_t>` | Bits per sample |
| `codec_header` | `std::optional<std::string>` | Codec-specific header data |

Call `is_complete()` on the object to check that `codec`, `sample_rate`, `channels`, and
`bit_depth` all have values. `codec_header` is not part of that check, so it can still be
`nullopt` when `is_complete()` returns true.

### Controller Role (Playback Commands)

Lets your application send transport commands (play, pause, next, etc.) and receive the server's controller state (volume, mute, repeat, shuffle, supported commands).

```cpp
auto& controller = client.add_controller();
```

### Metadata Role (Track Information)

Receives track metadata (title, artist, album, progress, etc.) from the server.

```cpp
auto& metadata = client.add_metadata();
```

### Artwork Role (Album Art)

Receives album artwork images from the server. Requires a configuration struct declaring preferred image formats per slot.

```cpp
ArtworkRoleConfig artwork_config;
artwork_config.preferred_formats = {
    {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 300, 300},
};

auto& artwork = client.add_artwork(std::move(artwork_config));
```

The slot/channel number for each entry is its position (index) in `preferred_formats`; the first entry is slot 0, the second slot 1, and so on. Up to `ARTWORK_MAX_SLOTS` (4) entries are supported. The client reports these channels to the server in its `client/state` artwork object, which is sent once the server activates the role.

Each image arrives as several binary messages that the role reassembles, so `on_image_decode()` fires once per complete image, never per message. `ImageSlotPreference::max_image_bytes` is the channel's memory budget: the role refuses an image the server announces as larger than that (the channel keeps what it was showing and the refusal is logged). While the client runs, the role holds one buffer of that size per configured channel, allocated by `start()` and released by `stop()`, which each image is copied into as its messages arrive; the messages themselves arrive in the client's shared inbound ring (placed by `SendspinClientConfig::inbound_ring_location`), which reserves room for one image of that size per channel in flight and returns each message as soon as it is copied. On a channel with `require_frame_done`, an image that completes while the channel's last delivery is un-acked waits in that buffer until `frame_done()` reopens the gate; a newer image replaces it there. The default, 128 KiB, suits the channel sizes a display client of this class asks for; raise it for a channel whose images are genuinely larger.

### Visualizer Role (Audio Visualization)

Receives real-time beat, loudness, dominant-frequency, onset, and spectrum data synchronized to playback.

```cpp
VisualizerSupportObject vis_support;
vis_support.buffer_capacity = 32768;  // Inbound ring bytes held; ~1/7 is advertised as wire data

VisualizerStreamConfig vis_stream;
vis_stream.types = {
    VisualizerDataType::BEAT,
    VisualizerDataType::LOUDNESS,
    VisualizerDataType::F_PEAK,
    VisualizerDataType::SPECTRUM,
    VisualizerDataType::PEAK,
};
vis_stream.rate_max = 30;  // Set to the display refresh rate
vis_stream.spectrum = VisualizerSpectrumConfig{
    .n_disp_bins = 32,
    .scale = VisualizerSpectrumScale::MEL,
    .f_min = 40,
    .f_max = 16000,
};

auto& visualizer = client.add_visualizer({.support = vis_support, .stream = vis_stream});
```

`support` is the capacity the client advertises once in `client/hello`; `stream` is the
configuration it reports in `client/state`, from which the server derives the stream it
sends. Both are set at construction time, so the stream configuration is reported as
configured and does not change while the client runs.

### Color Role (Audio-Derived Color Palette)

Receives an RGB color palette derived by the server from the currently playing audio (e.g., extracted from album artwork). Useful for LED matrices, status lights, or themed displays. Server-to-client only; no configuration.

```cpp
auto& color = client.add_color();
```

### Source Role (Audio Capture)

Streams audio captured on the device (a line input or a microphone) to the server. The server decides when: its `start` command opens the stream and its `stop` closes it (roles/source/v1.md "Source command semantics"). The `SourceRoleConfig` passed to `add_source()` is the format of every stream the role opens:

```cpp
SourceRoleConfig source_config;
source_config.sample_rate = 48000;
source_config.channels = 2;
source_config.bit_depth = 16;
source_config.codec = SendspinCodecFormat::PCM;  // or OPUS, in a build with SENDSPIN_ENABLE_OPUS
auto& source = client.add_source(source_config);
```

An invalid config (see [SourceRoleConfig](#sourceroleconfig)) leaves the role inert; a valid config whose buffers cannot be allocated fails `client.start()` instead. An `OPUS` role streams Opus only to a server whose `server/hello` lists it, and the same capture as PCM otherwise.

Feed the capture to `write_audio()` from one capture thread, with the capture time of each buffer's first sample on the client's clock (`std::chrono::steady_clock` on host, `esp_timer_get_time()` on ESP-IDF), or 0 to have the write stamped as ending now:

```cpp
source.write_audio(pcm_bytes, len, capture_time_us);
```

It never waits or allocates. It refuses audio while the stream is closed, a write that is not a whole number of frames, a write longer than the capture buffer takes at once (see `capture_buffer_ms` in [SourceRoleConfig](#sourceroleconfig)), and a write that finds the capture buffer full; after a stall the stream resumes from live capture rather than sending the stale backlog. Start capturing in `on_streaming_started()` and stop in `on_streaming_stopped()` (see [SourceRoleListener](#sourcerolelistener)); the client holds high-performance networking (`on_request_high_performance()`) between the two, as it does during playback. Stop calling `write_audio()` before destroying the client.

A role configured with `line_sense` reports the capture input's signal state from the main loop thread, which goes to the server in `client/state`:

```cpp
source.set_signal(SourceSignal::PRESENT);  // or ABSENT
```

`examples/source_client/` is a working reference: it captures the default PortAudio input device and feeds `write_audio()` from the capture callback with each buffer's capture time on the client's clock.

## Step 3: Implement Listener Interfaces

A role you add is configured and ready, but only the server decides which roles a session actually
uses, and it may change that set at any time. When an activation removes a role, the library tears
that role down on the spot: a stream role stops its output, drops its buffers, and reports the end
(`on_stream_end()`, `on_visualizer_stream_end()`, `on_image_clear()` for every slot; the source
closes its open input stream with `client-stream/end` and reports `on_streaming_stopped()`), and a
state role drops its state and reports the clear (`on_metadata_clear()`, `on_color_clear()`,
`on_controller_state_clear()`). The connection stays up and the other roles keep running. A clear
callback is therefore not proof that the server is gone; treat it as "this role has nothing to
show" and make it idempotent. Until the server adds the role back, anything it still sends for
that role is ignored rather than acted on, so a removed role stays quiet; when it is added back,
the role resumes normally.

### PlayerRoleListener (Required if Using Player Role)

The `on_audio_write` method is one of only two pure virtual (required) methods in the library;
the other is `SendspinNetworkProvider::is_network_ready()`.

```cpp
struct MyPlayerListener : PlayerRoleListener {
    // REQUIRED: Write decoded PCM audio to your audio output.
    // Called from a background thread. May block up to timeout_ms.
    // Must return the number of bytes actually written.
    size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) override {
        return my_audio_output.write(data, length, timeout_ms);
    }

    // Optional: Called when a new audio stream starts.
    // Use this to configure your audio output with the new stream parameters.
    void on_stream_start() override {
        auto& params = player_ref.get_current_stream_params();
        my_audio_output.configure(*params.sample_rate, *params.channels, *params.bit_depth);
    }

    // Optional: Called when the audio stream ends.
    void on_stream_end() override {
        my_audio_output.clear();
    }

    // Optional: Called when the server changes the volume.
    void on_volume_changed(uint8_t volume) override {
        my_audio_output.set_volume(volume);
    }

    // Optional: Called when the server changes the mute state.
    void on_mute_changed(bool muted) override {
        my_audio_output.set_muted(muted);
    }

    // Optional: Called when the server changes the output delay.
    void on_output_delay_changed(uint16_t delay_ms) override { }
};
```

### Audio Playback Feedback

Your audio output must report back when audio frames have been played. This feedback drives the library's synchronization. Call `notify_audio_played()` from your audio output callback:

```cpp
// In your audio output's playback callback (e.g., PortAudio callback):
player.notify_audio_played(frames_played, current_timestamp_us);
```

- `frames_played`: Number of audio frames (not bytes) just played
- `timestamp`: Client timestamp in microseconds when the audio will finish playing (e.g., from `std::chrono::steady_clock`)

This method is thread-safe and is expected to be called from an audio callback thread.

### MetadataRoleListener

```cpp
struct MyMetadataListener : MetadataRoleListener {
    void on_metadata(const ServerMetadataStateObject& md) override {
        // Overwrite display state on every call so server clears (nullopt) propagate.
        display_title(md.title.value_or(""));
        display_artist(md.artist.value_or(""));
        display_album(md.album.value_or(""));
        if (md.progress) {
            update_progress_bar(md.progress->track_progress, md.progress->track_duration);
        } else {
            clear_progress_bar();
        }
    }
};
```

The `ServerMetadataStateObject` contains these fields (all optional except `timestamp`):

| Field | Type | Description |
|---|---|---|
| `timestamp` | `int64_t` | Server clock µs at which this metadata becomes valid; delivery is held until the synced client clock reaches it |
| `title` | `std::optional<std::string>` | Track title |
| `artist` | `std::optional<std::string>` | Track artist |
| `album_artist` | `std::optional<std::string>` | Album artist |
| `album` | `std::optional<std::string>` | Album name |
| `artwork_url` | `std::optional<std::string>` | Artwork URL |
| `year` | `std::optional<uint16_t>` | Release year |
| `track` | `std::optional<uint16_t>` | Track number |
| `progress` | `std::optional<MetadataProgressObject>` | Playback progress (see below) |

`MetadataProgressObject` contains `track_progress` (ms), `track_duration` (ms), and `playback_speed`.

Every `on_metadata()` call carries the full state of the track being described, not a set of changes: a field the server left out of that update is `nullopt`, whatever an earlier update reported for it, and a state without `progress` means there is no position to show. Listeners that mirror metadata into display state should therefore overwrite every displayed value on each call (using e.g. `value_or("")`) rather than merging into what they already show.

You can also poll track progress at any time:

```cpp
uint32_t progress_ms = metadata.get_track_progress_ms();  // Interpolated
uint32_t duration_ms = metadata.get_track_duration_ms();   // 0 = unknown/live
```

### ControllerRoleListener

```cpp
struct MyControllerListener : ControllerRoleListener {
    void on_controller_state(const ServerStateControllerObject& state) override {
        // Update UI with server-side volume, mute, repeat, and shuffle state
        update_volume_slider(state.volume);
        update_mute_button(state.muted);
        update_repeat_icon(state.repeat);
        update_shuffle_icon(state.shuffle);
        // Enable/disable buttons based on supported commands
        enable_buttons(state.supported_commands);
    }
};
```

### ArtworkRoleListener

The artwork role uses a dedicated decode thread for the CPU-bound decode step and the main loop for scheduled display. `on_image_decode()` fires on the decode thread immediately when encoded image data arrives; once decode returns, the server display timestamp is handed off to the main loop, which fires `on_image_display()` once the timestamp is reached. If a newer frame for the same slot finishes decoding before its predecessor's display fires, only the newer one is delivered. Lifecycle callbacks also fire on the main loop thread.

`on_image_display()` reports `lateness_ms`: how far past the (offset-shifted) deadline it fired. Displays are best-effort, so an image that arrives or decodes after its deadline fires as soon as it is ready. Treat a small value as on time; a huge value is the cue to snap instantly. `lateness_ms` is `0` only when there is no connection (no deadline exists), so a connected on-time display always reports a small nonzero value.

```cpp
struct MyArtworkListener : ArtworkRoleListener {
    // THREAD SAFETY: Called from the dedicated decode thread.
    // Decode the encoded image synchronously (e.g., JPEG to bitmap).
    // The data pointer is valid for the duration of this call.
    void on_image_decode(uint8_t slot, const uint8_t* data, size_t length,
                         SendspinImageFormat format) override {
        decoded_images[slot] = decode_image(data, length, format);
    }

    // Called from the main loop thread once the server display timestamp is reached.
    // lateness_ms reports how late the display fired (0 = no connection).
    void on_image_display(uint8_t slot, uint32_t lateness_ms) override {
        display.show_image(slot, decoded_images[slot]);
    }

    // Called from the main loop thread when artwork should be cleared, either for this slot
    // alone or for every slot at the end of a stream.
    void on_image_clear(uint8_t slot) override {
        display.clear_slot(slot);
    }
};
```

**Knowing when there is no artwork.** Artwork stays valid until the server replaces or clears it, and the artwork role is independent of the metadata role, so a track change alone sends nothing: the next track of the same album keeps showing the image already delivered. When an item genuinely has no artwork, the server clears that channel and `on_image_clear()` fires for that slot alone, scheduled to its server timestamp like a display (`display_offset_ms` included) so it lands on the item boundary. `on_image_clear()` also fires for every configured slot on stream end, disconnect, and a `server/activate` that takes the artwork role out of the session's active roles.

| What happened | What the listener sees |
| --- | --- |
| Artwork unchanged (e.g. next track of the same album) | nothing; the current image stays valid |
| Item has no artwork | `on_image_clear(slot)` for that slot |
| Stream ended, connection lost, or the role deactivated | `on_image_clear(slot)` for every configured slot |

**Cross-fades with back-pressure (opt-in).** By default the role decodes and displays every frame as it arrives. A slot can instead opt into a back-pressure gate by setting `ImageSlotPreference::require_frame_done`. With the gate on, the role keeps at most one un-acked *delivery* (a frame or a clear) in flight for that slot. Call `ArtworkRole::frame_done(slot)` from the main loop exactly once for every `on_image_display()` and `on_image_clear()` that slot receives, e.g. once a cross-fade animation finishes. An extra call is a harmless no-op, but a missed one wedges the slot: there is no timeout, the acknowledgment is the contract.

Payloads and a stream end reach the gate differently:

- A **frame or per-channel clear** arriving while a delivery is un-acked is buffered latest-wins and delivered only after `frame_done(slot)`, and then owes its own `frame_done()`. It waits behind the outstanding delivery rather than replacing it, so a consumer presenting a delivery is never interrupted. The exception is a delivery that has not reached `on_image_display()` yet: the server announcing a newer image for the slot replaces it outright, its display never fires, and the gate reopens for the buffered payload.
- A **stream end** is a lifecycle event, not a payload, so it is never buffered: it fires `on_image_clear()` immediately for every configured slot, discards anything buffered, and replaces whatever delivery was outstanding. Exactly one `frame_done()` is owed afterward whatever was in flight.

Pair the gate with `ImageSlotPreference::display_offset_ms` to start a fade before the track boundary (positive fires the display early, mirroring `PlayerRoleConfig::fixed_delay_us`), and use `lateness_ms` to shorten the fade so it still ends on schedule:

```cpp
// Slot 0 has require_frame_done set, so on_image_display() starts a cross-fade and the gate
// stays held until on_fade_complete() acks it.
void on_image_display(uint8_t slot, uint32_t lateness_ms) override {
    display.start_fade(slot, decoded_images[slot], FADE_MS - std::min(lateness_ms, FADE_MS));
}
void on_image_clear(uint8_t slot) override {
    display.clear_slot(slot);
    artwork_role->frame_done(slot);  // a clear is a delivery; ack it
}
void on_fade_complete(uint8_t slot) {
    artwork_role->frame_done(slot);  // release the gate so the next frame can decode
}
```

Call `frame_done()` from the main loop thread. It is a safe no-op when the slot has nothing un-acked (including slots where `require_frame_done` is false), so calling it from inside `on_image_display()`/`on_image_clear()` for an instant, non-animated swap is fine.

### VisualizerRoleListener

```cpp
struct MyVisualizerListener : VisualizerRoleListener {
    // THREAD SAFETY: Data callbacks fire on a dedicated drain thread at each
    // frame's display timestamp, less VisualizerRoleConfig::display_offset_ms.
    // A frame that arrives after its display time is dropped, as is a backlog
    // more than 20 ms behind, so copy data quickly and defer heavy processing.
    void on_loudness(int64_t client_timestamp, uint16_t loudness) override {
        update_vu_meter(loudness);
    }

    void on_f_peak(int64_t client_timestamp, uint16_t frequency_hz, uint16_t amplitude) override {
        update_peak_display(frequency_hz, amplitude);
    }

    void on_spectrum(int64_t client_timestamp, const std::vector<uint16_t>& bins) override {
        update_spectrum_bars(bins);
    }

    // Musical beat events; downbeat marks a bar start when the server tracks downbeats.
    void on_beat(int64_t client_timestamp, bool downbeat) override {
        trigger_beat_animation(downbeat);
    }

    // Energy onset (transient) events, independent of musical timing.
    void on_peak(int64_t client_timestamp, uint8_t strength) override {
        trigger_flash(strength);
    }

    // Called from the main loop thread.
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& stream) override { }
    void on_visualizer_stream_end() override { }
    void on_visualizer_stream_clear() override { }
};
```

### ColorRoleListener

```cpp
struct MyColorListener : ColorRoleListener {
    void on_color(const ServerColorStateObject& c) override {
        if (c.background_dark) set_dark_bg(*c.background_dark);
        if (c.background_light) set_light_bg(*c.background_light);
        if (c.primary) set_primary((*c.primary)[0], (*c.primary)[1], (*c.primary)[2]);
        // accent, on_dark, on_light...
    }

    // Called when the cached colors are dropped: the connection was lost, or a
    // server/activate took the color role out of the session's active roles.
    // Reset any displayed colors to a neutral or default state.
    void on_color_clear() override {
        reset_to_defaults();
    }
};
```

The `ServerColorStateObject` contains a `timestamp` and six optional `RgbColor` fields (`std::array<uint8_t, 3>`, ordered `[R, G, B]`):

| Field | Description |
|---|---|
| `timestamp` | Server clock µs at which this color update becomes valid; delivery is held until the synced client clock reaches it, or fires immediately if there is no active connection |
| `background_dark` | Background suitable for dark mode; safe contrast with white text and `on_dark` |
| `background_light` | Background suitable for light mode; safe contrast with black text and `on_light` |
| `primary` | Dominant color, not adjusted for contrast |
| `accent` | Secondary or complementary color, not adjusted for contrast |
| `on_dark` | Light foreground for use on dark backgrounds |
| `on_light` | Dark foreground for use on light backgrounds |

Every `on_color()` call carries the full palette: a color the server left out of that update is `nullopt`, whatever an earlier update reported for it, so listeners render from the palette they are handed rather than merging it into the one they already hold.

### SourceRoleListener

Both callbacks are optional and fire on the main loop thread, in pairs:

```cpp
struct MySourceListener : SourceRoleListener {
    void on_streaming_started() override {
        // client-stream/start was sent; write_audio() accepts audio from here on
        capture.start();
    }
    void on_streaming_stopped() override {
        // A server stop, the role's removal, the client becoming unavailable, the connection
        // ending, or the client stopping; write_audio() refuses audio again
        capture.stop();
    }
};
```

## Step 4: Implement Providers

### SendspinNetworkProvider (Required)

The library needs to know when the network is available. This is the only required provider.

```cpp
struct MyNetworkProvider : SendspinNetworkProvider {
    bool is_network_ready() override {
        return wifi_is_connected();  // Your platform's network check
    }
};
```

On host platforms where the network is always available, return `true`:

```cpp
struct HostNetworkProvider : SendspinNetworkProvider {
    bool is_network_ready() override { return true; }
};
```

`is_network_ready()` is called from any thread: from `start()` on the main loop, then from the
library's protocol task, which polls it about once a second while the WebSocket server is down.
Keep it cheap and non-blocking (a read of a flag the platform keeps current), and do not call
back into the client from it.

### SendspinPersistenceProvider (Optional)

Allows the library to persist state across reboots. Required for stable identity and
pairing. On host platforms `examples/common/file_persistence_provider.h` provides
`FilePersistenceProvider`, which persists to a single JSON file (one document mapping each
key below to `base64url(bytes)`) -- use it directly or as a reference implementation.

The interface is a plain byte-blob store: a load, a save, and a commit, independent of what is
being stored:

```cpp
class SendspinPersistenceProvider {
public:
    virtual std::optional<std::vector<uint8_t>> load_blob(const std::string& key);
    virtual bool save_blob(const std::string& key, const uint8_t* data, size_t len);
    virtual bool commit();
};
```

The library owns all serialization. It calls these three methods with one of the fixed keys
below; a provider never needs to parse or interpret the bytes, only store and return them
byte-for-byte.

Every method is invoked on the main loop thread, for every key, so a provider needs no locking
of its own. (A persisted change decided on the protocol task, such as the pairing record
committed when a pairing finalizes, an unpair, or a playback handoff, is staged internally and
written from the next `loop()` call.)
No internal library lock is held across the call, so a slow write does not stall the audio path,
a Noise handshake or any other connection work -- but it does stop the main loop for its
duration, so the call must be one bounded storage operation, and it must not call back into the
client.
Provisioning writes from inside `start()` rather than in response to a runtime event:
`save_blob(persistence_keys::KEYPAIR, ...)` when no valid keypair is stored, and
`save_blob(persistence_keys::PAIRING_PSK, ...)` when no Pairing PSK is stored and none is
configured.

#### Keyspace

Every key comes from the `persistence_keys` namespace (`sendspin/persistence_keys.h`, which
`sendspin/client.h` includes), at most 12
characters (comfortably under a typical NVS key's 15-character limit). A provider must not invent its own keys; it only needs to
store and return whatever bytes the library gives it for each of these:

Every blob has a fixed size, published beside its key as a `*_SIZE` constant. The library
always writes exactly that many bytes and treats a stored blob of any other length as absent, so
a provider can store each key as a fixed-size value. `RECORD_ORDER` is the exception: it has no
size constant, is written as exactly `max_pairing_records` bytes, after the clamp to 5..255
described under Record capacity, and is read at any length. Integers are in the device's native
byte order: a blob is only ever read back by the device that wrote it.

| Key | Size | Contents |
|---|---|---|
| `persistence_keys::KEYPAIR` | `KEYPAIR_SIZE` (32) | The static X25519 private key. |
| `persistence_keys::record_slot_key(n)` | `RECORD_SLOT_SIZE` (64) | ONE `SendspinPairingRecord` as a codec blob (`encode_pairing_record()` / `decode_pairing_record()` in `sendspin/persistence_codec.h`), or 64 zero bytes when slot `n` is free. `n` runs from 0 to `max_pairing_records - 1`; the key is absent until that slot is first filled. |
| `persistence_keys::RECORD_ORDER` | `max_pairing_records` (12 by default) | The occupied slot numbers, least recently used first, one byte each, then `0xFF` in every remaining position. Decides which record a pairing at capacity evicts. |
| `persistence_keys::PAIRING_PSK` | `PAIRING_PSK_SIZE` (32) | The stored `SendspinPairingPsk` as a codec blob (`encode_pairing_psk()` / `decode_pairing_psk()`). Never written while `SendspinClientConfig::pairing_psk` is set, which outranks a stored one. |
| `persistence_keys::LAST_PLAYED` | `LAST_PLAYED_SIZE` (32) | The X25519 public key of the last-playback server, the key its base64url `server_id` encodes. |
| `persistence_keys::OUTPUT_DELAY` | `OUTPUT_DELAY_SIZE` (2) | A `uint16_t`: the player's output delay in milliseconds. |

`sendspin/persistence_codec.h` is public so a custom provider (or a test) can inspect or seed
the record slot / `PAIRING_PSK` content in exactly the format the library itself
produces -- it is not something a provider hand-rolls its own version of. A record is its PSK
and the server's public key; a Pairing PSK blob is the bare PSK. Neither stores its
`psk_id`, which decoding derives from the PSK.

Only the keys a change actually touches are written: a pairing writes one slot (and the order),
a revocation zeroes one slot (and writes the order), and a playback handoff that reorders
recency writes only the order.

#### Durability contract

- `save_blob()` returning `true` means the write was accepted: stored, or queued until the next
  `commit()`. That includes the zeroed write that frees a record slot. A `false` return is
  reported, not retried: the in-memory state
  stays authoritative for the current boot. What the rejection costs decides the level: a write
  that changes which records the next boot holds logs a warning naming the key and what will be lost (or come back) at the next reboot, while a
  write the next boot rebuilds by itself (the recency order in `RECORD_ORDER`) reports at debug.
  For a record slot specifically: a rejected
  write of a just-paired record leaves the pairing working for this boot only
  (`on_pairing_succeeded` still fires; the record is gone after a reboot), and a rejected write
  of a removal means the store still holds the old record and will hand it back at the next boot,
  silently making the revoked PSK valid again (the revoked record is always dropped from RAM
  regardless of the return value). A supersede and an eviction both write the new record over the
  old one's slot, so a rejected write there leaves the OLD record in storage: after a reboot the
  client is paired to the server it evicted, or holds the pre-supersede PSK for a server that has
  already discarded it, which then falls back to unpaired (Sentinel) access.
- `commit()` makes every accepted write durable. The library calls it once after a batch of
  accepted writes that holds pairing material (`KEYPAIR`, `PAIRING_PSK`, or a record slot) and,
  for a pairing, does so before `on_pairing_succeeded` fires. Writes to `RECORD_ORDER`,
  `LAST_PLAYED` and `OUTPUT_DELAY` never trigger it, so a provider that queues its writes may
  batch those on its own schedule. A provider that writes through in `save_blob()` keeps the
  default, which returns `true`. A `false` return is logged like a rejected write and not
  retried.
- The library never erases a key: every blob it owns is rewritten in place or left alone (a
  removal zeroes its slot). An application that wipes the keyspace, for example on a factory
  reset, does so against its own store.

#### Record capacity

The library's built-in `RecordStore` caps the number of long-term records it will hold at
`SendspinClientConfig::max_pairing_records`, which defaults to
`SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS` (12). The cap is also the number of record
slot keys the store may use, one per record. A pairing at the cap evicts the least recently used
record that no open connection is resolving against, since a pairing never fails for lack of
record storage. A record counts as recently used when a server takes playback on it, not when
it merely connects, and a new record starts as the most recently used. Replacing a record already held for
a given `psk_id` or `server_id` evicts nothing, because that never grows the store. Recency survives a reboot: it is what
`persistence_keys::RECORD_ORDER` holds. An evicted server's next handshake lands in the Sentinel
fallback, where it can offer its operator re-pairing. The protocol requires room for at least 5
records, so a smaller configured cap is raised to that floor, and a cap above 255 is lowered to
that ceiling (so the highest slot is 254, leaving byte value 255 free as the order blob's
padding). Raise or lower the cap by setting `max_pairing_records` before calling `start()`:

```cpp
SendspinClientConfig config;
config.max_pairing_records = 32;
```

Every method has a default no-op / `nullopt` implementation, so you can implement only the
keys your deployment actually needs. The minimum useful set for a deployed device is
`persistence_keys::KEYPAIR` (for stable identity) and the record slot keys (for pairing to
survive reboots).

```cpp
struct MyPersistenceProvider : SendspinPersistenceProvider {
    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        std::vector<uint8_t> bytes;
        if (nvs_read_bytes(key.c_str(), bytes)) return bytes;
        return std::nullopt;
    }
    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        return nvs_write_bytes(key.c_str(), data, len);
    }
};
```

A provider backed by a single flat NVS namespace (as above) can often implement the whole
interface generically, since every key is already sized to fit and the library handles
serialization. A provider on a store of fixed-size values (such as ESPHome's preferences) can
size each key from its `*_SIZE` constant, and `RECORD_ORDER` from the clamped
`max_pairing_records`; a provider that needs different backing per key (e.g. a plaintext-secrets
file plus separate flash-wear-optimized storage for `OUTPUT_DELAY`) can switch on `key` instead.

### SendspinClientListener (Optional)

Receives client-level events. All callbacks fire on the main loop thread.

```cpp
struct MyClientListener : SendspinClientListener {
    // Called when group state changes (playback state, group name, etc.)
    void on_group_update(const GroupUpdateObject& group) override {
        if (group.playback_state) update_playback_indicator(*group.playback_state);
        if (group.group_name) update_group_display(*group.group_name);
    }

    // Called after a time sync burst completes.
    void on_time_sync_updated(float error) override {
        log_sync_quality(error);
    }

    // Called when the library needs low-latency networking (e.g., during active streaming).
    // Use this to disable WiFi power saving on ESP32.
    void on_request_high_performance() override {
        esp_wifi_set_ps(WIFI_PS_NONE);
    }

    // Called when the library no longer needs low-latency networking.
    void on_release_high_performance() override {
        esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    }

    // Called when a server begins a pairing exchange, once per attempt and whatever
    // the method (Pairing PSK, dynamic pairing code, or static pairing code).
    // server_id is the base64url public key of the server initiating pairing.
    void on_pairing_started(const std::string& server_id) override {
        printf("Pairing started with server %s\n", server_id.c_str());
    }

    // Called when pairing completes successfully and the long-term record is stored.
    // Subsequent connections from this server will report ConnectionTrust::USER.
    void on_pairing_succeeded(const std::string& server_id) override {
        printf("Pairing succeeded with server %s\n", server_id.c_str());
    }

    // Called when a pairing exchange is aborted. Most server-sent abort reasons leave the
    // connection open so the server can retry or resume normal operation; CONCURRENT_ATTEMPT
    // and protocol errors (reported as UNKNOWN) close it.
    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        printf("Pairing failed with server %s\n", server_id.c_str());
    }

    // Called after the Noise handshake completes, and again after each successful
    // re-handshake (notably the post-pairing rekey).
    // trust reflects the PSK category used:
    //   ConnectionTrust::USER  -- long-term record: a paired server
    //   ConnectionTrust::NONE  -- Sentinel or Pairing PSK (unpaired access)
    void on_trust_changed(ConnectionTrust trust) override {
        bool paired = (trust == ConnectionTrust::USER);
        update_trust_indicator(paired);
    }

    // Dynamic pairing code: emit/withdraw the code the device derived. Only invoked when
    // SendspinClientConfig::pairing_code_out_channels and pairing_code_formats are both
    // non-empty. `format` says what `code` is: six decimal digits, or a pairing token to
    // render as a QR code.
    void on_display_pairing_code(const std::string& code,
                                 SendspinPairingCodeFormat format) override {
        show_pairing_code_on_display(code, format);
    }
    void on_clear_pairing_code() override {
        clear_pairing_code_from_display();
    }

    // Prompt/dismiss the operator pairing-window gesture for a gesture-gated attempt (every
    // static pairing code attempt, and a dynamic one held back by the round limit). Confirm the
    // gesture by calling client.confirm_pairing_window() (thread-safe) once the operator
    // performs it; calling it with no attempt waiting opens a standing 5-minute pairing window
    // that admits the next attempt without a further gesture.
    // client.cancel_pairing_window() closes an open window again.
    void on_open_pairing_window() override {
        prompt_pairing_button_press();
    }
    void on_close_pairing_window() override {
        dismiss_pairing_prompt();
    }
};
```

## Step 5: Wire Everything Together

Listeners and providers are set as raw pointers. They must stay alive for as long as the client can call them: until `stop()` returns, or until the client is destroyed if `stop()` is never called. The destructor's only listener call is `on_release_high_performance()` for a hold still outstanding (see [Stopping and Restarting](#stopping-and-restarting)).

```cpp
MyPlayerListener player_listener;
MyMetadataListener metadata_listener;
MyControllerListener controller_listener;
MyClientListener client_listener;
MyNetworkProvider network_provider;
MyPersistenceProvider persistence_provider;

player.set_listener(&player_listener);
metadata.set_listener(&metadata_listener);
controller.set_listener(&controller_listener);
client.set_listener(&client_listener);
client.set_network_provider(&network_provider);         // Required
client.set_persistence_provider(&persistence_provider); // Optional
```

## Step 6: Start and Run

```cpp
// Start the role threads and the protocol task, and arm the WebSocket server (it listens before
// start() returns when the network provider already reports ready, otherwise as soon as it does).
// Task priorities and PSRAM settings are taken from SendspinClientConfig.
if (!client.start()) {
    // Handle failure
    return 1;
}

// Optionally initiate a client-side connection to a known server URL.
// Without this, the client waits for incoming server connections.
client.connect_to("ws://192.168.1.10:8928/sendspin");

// Main loop: call loop() periodically to deliver callbacks. Connection work runs on the library's
// protocol task and does not wait for it.
while (running) {
    client.loop();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// Clean shutdown: goodbye every peer, tear everything down, deliver the clear callbacks.
client.stop();
```

## Stopping and Restarting

`stop()` is synchronous: when it returns the client is fully stopped. It sends a `client/goodbye` (reason `shutdown`) to every peer and closes each connection right behind its goodbye (a peer whose WebSocket upgrade completes after `stop()` has begun is closed without one). It does not wait for a queued goodbye to be written: the host transports and the ESP outbound connection send synchronously, and the ESP server writes each queued goodbye before the close queued behind it. It then closes the server and every connection still open, joins the role threads, resets every role, and delivers the roles' clear callbacks (`on_stream_end()`, `on_image_clear()`, `on_visualizer_stream_end()`, `on_metadata_clear()`, `on_controller_state_clear()`, `on_color_clear()`, `on_streaming_stopped()`) before returning. An open source stream is ended with `client-stream/end` ahead of its connection's goodbye, except inside a re-handshake's quiet window (connection.md "Re-handshake"): there the end waits for a `server/activate` a stopping client never receives, so the goodbye alone ends the stream. It is a no-op on a stopped client. `is_started()` reports the state, and `loop()` is a no-op while stopped.

Restarting is `start()` again; start, stop, and start again can be repeated indefinitely, and a restarted client begins with no connection, no group state, and no role state from before the stop.

`stop()` may block, but the wait is bounded. It includes:

- The transports' own close. The host server joins every accepted connection thread; a WebSocket peer completes its close handshake within about 300 ms, but a raw socket that connected and never completed the upgrade holds the join for the full 3 s handshake timeout. The ESP server waits for the httpd task to exit, which polls at 100 ms and first finishes any queued send, which can take up to httpd's send timeout for a peer that has stopped reading.
- An outbound `connect_to()` connection's transport stop, which is synchronous (`esp_websocket_client_stop()` / `ix::WebSocket::stop()`) and, for a connection whose upgrade is still in flight, can last up to the transport's connect and handshake timeout: 30 s on host (`SendspinClientConnection::HANDSHAKE_TIMEOUT_SECS`, the nursery's establish window), and on ESP esp_websocket_client's `network_timeout_ms` (10 s, `SendspinClientConnection::NETWORK_TIMEOUT_MS`) for each of the connect's three steps (TCP connect, upgrade request, its response), plus the DNS lookup before them, which lwIP's resolver bounds at 7 s per configured DNS server (3 servers by default, so about 21 s). That includes an attempt released earlier by `disconnect()` or a replacing `connect_to()` whose transport has not finished yet.
- A listener callback already running on a role thread: the join cannot interrupt it. `on_audio_write()` is bounded by its `timeout_ms`; `on_image_decode()` has no bound.

A pairing attempt in flight is cut short the same way: `on_clear_pairing_code()` and `on_close_pairing_window()` fire from inside `stop()` for a prompt that was still showing, and every provider write still owed (a long-term record a `server/pair-finalize` had just committed, for example) is performed before `stop()` returns. The identity and record store survive the stop, so a restarted client keeps its `client_id`, its pairing token, and every record.

Listener callbacks fire from inside `stop()`, after every role and the group state have been reset, so a callback that reads the client through its getters sees the stopped state. One that calls `start()` gets `false` and starts nothing; one that calls `stop()`, `connect_to()`, or `disconnect()` is ignored. `is_started()` reads `false` throughout and is safe to call from any thread. Call `stop()` only from the main loop thread: from a role-thread callback it would join the calling thread.

`on_request_high_performance()` and `on_release_high_performance()` fire from the main loop with no internal lock held, and their bodies should only toggle the platform networking mode rather than calling back into the client or a role. A time burst waits for the request to have been delivered before it sends its first time message, so a main loop that stalls delays the next clock measurement rather than measuring it in power-save mode; a release is never delayed that way.

Destroying a running client performs the transport half of `stop()` (goodbye, close, join) and dispatches no role teardown or clear callback; the only listener call is `on_release_high_performance()`, once for each hold the main loop granted and has not released. A request the main loop never delivered is dropped unheard, so the listener never sees a release without its request. Role-thread callbacks (`on_audio_write()`, `on_image_decode()`, visualizer deliveries) can still run until the destructor joins their role, so listeners must outlive the client as described in Step 5. Call `stop()` first when the clear callbacks matter.

## Encryption and Pairing

All connections are encrypted with Noise KKpsk2 (X25519 + ChaChaPoly). This
requires no application-level configuration beyond providing a `SendspinPersistenceProvider`
(so the static keypair survives reboots). Encryption is mandatory; there is no cleartext
fallback.

### Client Identity

The library derives `client_id` from the static X25519 keypair: `base64url(public_key)`
(43 characters, URL-safe, no padding). This string identifies the device to servers. It is
fixed for the lifetime of the keypair.

Without a persistence provider the keypair is regenerated on every boot. Pairing records
and server preferences will not survive reboots in that case.

```cpp
client.start();
printf("client_id: %s\n", client.client_id().c_str());
```

### Pairing

Pairing creates a long-term trust record for a specific server. After pairing, connections
from that server resolve via the long-term PSK and report `ConnectionTrust::USER`.

Pairing is server-initiated. The server includes `pairing` in the `activities` of its
`server/activate` message; the library handles the exchange automatically. The application
observes pairing via `SendspinClientListener` callbacks:

1. `on_pairing_started(server_id)` -- the exchange has begun.
2. `on_pairing_succeeded(server_id)` -- the record is stored; the server will
   re-handshake immediately on the new long-term PSK.
3. `on_pairing_failed(server_id, reason)` -- the exchange failed. See
   `SendspinPairAbortReason` below for the possible reasons.

   Whether the connection survives depends on the reason. Most reasons the server sends in a
   `pair/abort` leave it open, so the server can re-activate pairing or resume normal operation
   on it. `CONCURRENT_ATTEMPT` closes it, as do protocol errors (a malformed pairing frame or a
   bad CPace share), which are reported as `UNKNOWN` and close the transport without sending a
   `client/goodbye`.

   A persistence provider that rejects the durable write does not fail the pairing:
   `on_pairing_succeeded` fires, the record is authoritative for the rest of this boot, and a
   warning says it will not survive a reboot. Surface that failure from the provider itself if
   the application needs to act on it. The record is dropped outright, with neither callback
   firing, only when the store is at capacity with nothing evictable, which the connection budget
   rules out (`MAX_OPEN_CONNECTIONS` is below the records floor).

   Either way, do not treat this callback as a disconnect notification; poll `is_connected()`
   if the application needs to track that.

#### Pairing PSK

`pairing_psk` is the pairing method every client must implement, so it is always offered and a
Pairing PSK always backs it. Unless the application supplies one, the library generates a random
Pairing PSK on first boot and persists it as a `persistence_keys::PAIRING_PSK` blob. A stored blob
holding an all-zero key or the Sentinel PSK is ignored and replaced the same way. Nothing is
required of the application to enable the method.

To pair, the server must learn that PSK out of band. Surface it as a **pairing token** -- one
`"SP:"`-prefixed string carrying the `client_id` and the PSK together, for the operator to
paste (or scan) into the server:

```cpp
auto token = client.pairing_token();  // e.g. "SP:0AAAQ..." (107 chars), nullopt before start()
```

The token is stable for the lifetime of the PSK, so it can be printed at startup, shown in a UI,
or rendered as a QR code.

To ship a device with a factory-provisioned Pairing PSK instead (for example one read from a
factory partition, with its token printed on a label), set it in the config. `pairing.md`
"Pairing PSK Flow" requires it to be drawn from a CSPRNG per device, never shared across devices:

```cpp
std::array<uint8_t, 32> factory_psk = read_factory_psk();  // the device's own 32 random bytes
config.pairing_psk = SendspinPsk(factory_psk);
```

A configured Pairing PSK outranks a stored one and is never written to the persistence provider;
the library derives its `psk_id`. An all-zero key or the published Sentinel PSK is rejected:
`start()` logs an error and returns `false`, so a factory partition that was never written cannot
ship a key every peer knows. `SendspinPsk` wipes its bytes when destroyed, and so does every copy
the client makes; a source buffer such as `factory_psk` above is the application's to wipe.

`client.format_pairing_token(factory_psk)` builds the token for any 32-byte PSK rather than the
one in use, which is what a provisioning tool needs to print the token for a key it provisions.
It returns `nullopt` before `start()`, since the token also carries the client's identity.

After pairing completes, `on_pairing_succeeded` fires and the long-term record is stored
by the library in the first free record slot. Subsequent boots load that same slot; no further
provisioning is needed.

#### Pairing-code pairing

The library also supports the two pairing-code methods, gated by
`SendspinClientConfig::pairing_code_out_channels` / `pairing_code_formats` /
`pairing_window_supported` and the `SendspinClientListener::on_display_pairing_code` /
`on_clear_pairing_code` / `on_open_pairing_window` / `on_close_pairing_window` callbacks
documented in Step 3 above. A method is advertised only when the platform can carry it: a client
that names no out-channel and no format never offers `dynamic_pairing_code`, and the server is
then limited to the remaining methods.

A client offers at most one pairing-code method, and one with an out-channel offers the dynamic
code, so a device that means to offer `static_pairing_code` leaves `pairing_code_out_channels`
empty.

A **dynamic pairing code** is derived per attempt from the Noise handshake hash and both sides'
nonces, and emitted through `on_display_pairing_code` as either six decimal digits or a pairing
token to render as a QR code, whichever format the server selected from those advertised. If the
operator types a code the device did not emit, the client asks for another round
(`client/pair-retry`) and keeps the same code on screen. After 20 rounds without a successful
verification the attempt ends and further attempts are held back until an operator gesture.

A **static pairing code** is the fixed 8-digit value the device shipped with, set in
`SendspinClientConfig::static_pairing_code` and drawn from a CSPRNG per device (`pairing.md` "Static
Pairing Code Flow"). A value that is not exactly 8 decimal digits makes `start()` log an error and
return `false`. Every attempt is **gesture-gated**: the client answers the pairing activation with
`client/pair-pending` and withholds `client/pair-init` until a pairing window is open. The window
opens on the operator gesture (`confirm_pairing_window()`) and lives for 5 minutes. It keeps
admitting attempts on the connection that carried its first, and closes on a completed pairing (the
server's `server/pair-finalize` ack, the point at which the record is stored), on the fifth attempt
whose verification failed, when that connection drops, on `cancel_pairing_window()`, or on expiry. A
gesture performed before the activation arrives leaves the window standing open, so the next attempt
within its lifetime proceeds without a prompt.

A device that leaves `pairing_window_supported` false cannot show the `on_open_pairing_window`
prompt, so a gated attempt sends `client/pair-pending`, logs a warning, and waits for the
server's own timeout to cancel it. For a `dynamic_pairing_code` device that also means a standing
round limit can never be cleared: `pairing.md` "Rounds" has only a deliberate operator action
clear it, and the gesture is that action, so every later attempt sits at `client/pair-pending`
until the server gives up. A device that offers either pairing-code method should therefore set
`pairing_window_supported` and implement the gesture callbacks.

#### The locations hint

`SendspinClientConfig::pairing_psk_locations` and `static_pairing_code_locations` tell a server
where the operator can find each secret (`"device"`, `"leaflet"`, `"operator"`), and ride out as
the `locations` hint on the matching `client/hello` pair-method descriptor. Only the application
knows where its secrets were published, so an empty value omits the hint rather than guessing:
a code on the device label is `{"device"}`, a pairing token in the box is `{"leaflet"}`, and a
secret an operator provisioned out of band is `{"operator"}`.

The secrets themselves are `pairing_psk` (or the generated Pairing PSK) and
`static_pairing_code` in the same config, so an application that sets one sets its hint beside
it.

### Trust Levels

`ConnectionTrust` reflects which PSK resolved during the Noise handshake:

| Value | PSK used | Meaning |
|-------|---------|---------|
| `ConnectionTrust::USER` | Long-term record | Server holds a record minted for it during pairing |
| `ConnectionTrust::NONE` | Sentinel or Pairing PSK | Unpaired access |

`on_trust_changed` fires after `server/activate` is processed and the connection is promoted
to current, and again after each successful in-band re-handshake on that same connection.
Pairing an already-connected server therefore delivers the callback twice: once with
`ConnectionTrust::NONE` at admission, then again with `ConnectionTrust::USER` once the
post-pairing rekey completes. Connections that are rejected (e.g., an unpaired server
declaring playback or active roles while unpaired access is disabled) do not fire this
callback. The last reported trust describes the connection only while `is_connected()` is
true: a disconnect fires no `on_trust_changed`.

### Unpaired Access

Paired servers (long-term record) may declare playback and activate roles at any time. Unpaired
servers, those connecting with the Pairing PSK or the Sentinel PSK, are always admitted idle
(activities `[]`) or declaring `pairing`, but may declare playback or activate roles only while
unpaired access is enabled. `pairing.md` "Unpaired Access" makes the default the
manufacturer's choice and a change a local action on the device, so the application owns the
setting. It is off until `set_unpaired_access_enabled()` turns it on:

```cpp
client.set_unpaired_access_enabled(true);
bool on = client.is_unpaired_access_enabled();
```

The call may be made from any thread and works at any time, before the first `start()` and while
stopped included; the next `start()` advertises and admits against the value it left.

The library never persists the setting. An application that keeps it across reboots stores it
and restores it by calling `set_unpaired_access_enabled()` before `start()`, so the first
`client/hello` and admission already use it. If that stored value is lost, restore off rather
than the out-of-box default unless the application's own record shows the device has never been
set up, or a damaged store reopens unauthenticated access an operator turned off.

A call on a running client applies the new value to the live connections as `pairing.md`
"Unpaired Access" describes:

- Turning it off closes every connection that only unpaired access was admitting (an unpaired
  server with playback or active roles) with `client/goodbye` reason `pairing_required`. Paired
  connections, and unpaired ones with neither playback nor active roles, stay open.
- Turning it on closes each unpaired connection a server opened that is not declaring pairing
  with reason `restart`, so the server reconnects and reads the new value in the `client/hello`.
  Paired connections and `connect_to()` connections stay open; the latter keep advertising the
  old value until they are reopened. A connection on the Pairing PSK still awaiting its first
  `server/activate` also stays open: it is most likely about to declare pairing, and a restart
  would cost that pairing attempt. If it activates idle instead, it keeps the `client/hello` it
  already read until it reconnects.

Connections admitted with the Sentinel PSK report `ConnectionTrust::NONE`. Disabling
unpaired access after the device is paired is the typical production configuration.

## Sending Commands

If you added the controller role, use it to send playback commands. `send_command` takes a `ClientCommandControllerObject`, built with designated initializers - set only the field the command uses:

```cpp
controller.send_command({.command = SendspinControllerCommand::PLAY});
controller.send_command({.command = SendspinControllerCommand::PAUSE});
controller.send_command({.command = SendspinControllerCommand::NEXT});
controller.send_command({.command = SendspinControllerCommand::PREVIOUS});
controller.send_command({.command = SendspinControllerCommand::STOP});
controller.send_command({.command = SendspinControllerCommand::SHUFFLE});
controller.send_command({.command = SendspinControllerCommand::UNSHUFFLE});
controller.send_command({.command = SendspinControllerCommand::REPEAT_OFF});
controller.send_command({.command = SendspinControllerCommand::REPEAT_ONE});
controller.send_command({.command = SendspinControllerCommand::REPEAT_ALL});

// Commands that carry a parameter set the matching field:
controller.send_command({.command = SendspinControllerCommand::VOLUME, .volume = 75});
controller.send_command({.command = SendspinControllerCommand::MUTE, .muted = true});
controller.send_command({.command = SendspinControllerCommand::MUTE, .muted = false});

// Seek to an absolute position (0 to the controller state's seek_max_ms):
controller.send_command({.command = SendspinControllerCommand::SEEK, .position_ms = 30000});

// Seek by a signed offset from the current position (negative seeks backward):
controller.send_command({.command = SendspinControllerCommand::SEEK_RELATIVE, .offset_ms = -10000});
```

Fields that do not match the command are ignored when the message is serialized. The client drops, with a warning, a command missing from the latest controller state's `supported_commands`, and one without the field it requires (`volume` in 0-100, `muted`, `position_ms`, `offset_ms`); gate your UI on `supported_commands` so such calls are not made. The server clamps seeks to the seekable range.

A command is sent only to the admitted connection that owns the controller role, and only while the server has `controller@v1` among that connection's active roles. Calls made before the first `server/activate`, or after one that removes the role, are dropped rather than queued. `send_command()` checks the command against `supported_commands` and its parameter on the calling thread, then queues the command itself to the protocol task, which formats the `client/command`, applies the gate and sends it. A command validated against an owner that was replaced before the protocol task handled it is dropped there, since the new owner never offered it. It returns `false` for a command it drops itself (not in `supported_commands`, or a missing parameter) and when the request never reached the task: the client is not running, or the request queue is full. The queue holds a small fixed burst of controller commands (eight; `connect_to()`, `disconnect()`, `leave()`, the pairing-window gestures and unpaired-access changes never take a slot and are never refused), so a control that fires faster than the protocol task drains it, such as a rotary encoder sending a volume step per detent, sees `send_command()` return `false` and should coalesce and retry. A `false` for an unsupported command or a missing parameter is not one a retry can fix: retry only on a full queue, and gate the UI on `supported_commands` for the rest. `true` means queued, not sent.

## Accessing Roles

In addition to the references returned by `add_*()`, you can access roles at any time through the client's accessor methods. These return `nullptr` if the role was not added.

```cpp
if (auto* p = client.player()) {
    p->update_volume(75);
}
if (auto* c = client.controller()) {
    c->send_command({.command = SendspinControllerCommand::NEXT});
}
if (auto* m = client.metadata()) {
    uint32_t progress = m->get_track_progress_ms();
}
if (auto* a = client.artwork()) { /* ... */ }
if (auto* v = client.visualizer()) { /* ... */ }
if (auto* col = client.color()) { /* ... */ }
if (auto* s = client.source()) { /* ... */ }
```

Use these accessors when the role reference from `add_*()` is out of scope.

> **Note:** Role registration methods (`add_player()`, etc.), accessor methods (`player()`, etc.), and their backing members are conditionally compiled based on `SENDSPIN_ENABLE_*` flags. When a role is disabled at build time, calling `add_player()` or `client.player()` is a compile error, not a runtime nullptr. See [Compile-Time Role Selection](#compile-time-role-selection) below.

## Updating Player State

Report local state changes back to the server:

```cpp
player.update_volume(75);
player.update_muted(false);
player.update_output_delay(50);  // User-adjustable delay in ms

// Enable/disable output delay adjustment by the server. When disabled, the stored delay
// is not applied to sync timing and is reported as 0 in client state.
player.set_output_delay_adjustable(true);
```

## External Sources

A device can be taken over by something other than Sendspin: a local source, another protocol,
an HDMI input. How it tells the server depends on whether Sendspin may take it back (messaging.md
"External Source Handling").

### Leaving the Group

A device that plays a local source it can be interrupted out of stays available and leaves its
group:

```cpp
client.leave();  // Sends client/leave
```

The server treats this as it treats a client becoming unavailable: the client ends up alone in a
stopped group and rejoins only when an operator switches it back. Availability is unchanged, so
the server may still take the client over for new playback.

Leaving is only meaningful while the group is playing; a client in a stopped group keeps its
grouping by staying. The call needs an admitted connection that has received its first
`server/activate`, and is ignored (with a log) otherwise. It may be called from any thread: the
request is posted to the protocol task, which never refuses it, and calls before the task takes
it send one `client/leave`.

### Reporting Unavailability

A device that will not yield to Sendspin while the other activity runs reports itself
unavailable, and available again as soon as it would yield:

```cpp
client.set_available(false);  // client/state with available: false
client.set_available(true);   // Sendspin may take the device over again
bool available = client.is_available();
```

The server moves an unavailable client into a stopped group of its own and does not take it over
until it is available again. Until the server ends the stream, the player discards the audio
that still arrives. An open source stream closes with `client-stream/end` before the
`client/state` reporting `available: false`, and a start received while unavailable is ignored.
Availability is kept across disconnects and `stop()`/`start()`, and only a change publishes a
`client/state`. Call it from the main loop thread.

## Querying State

The client and roles expose query methods for polling state in your main loop or UI update cycle:

```cpp
// Client state
bool connected = client.is_connected();       // Active connection with completed handshake
bool synced = client.is_time_synced();         // Time filter has received at least one measurement
const GroupUpdateObject& group = client.get_group_state();   // Group id, name, playback state (all optional)

// Player state
uint8_t vol = player.get_volume();
bool muted = player.get_muted();
uint16_t delay = player.get_output_delay_ms();
auto& stream = player.get_current_stream_params();

// Controller state
auto& ctrl = controller.get_controller_state();  // volume, muted, repeat, shuffle, supported_commands, seek_max_ms

// Metadata
uint32_t progress = metadata.get_track_progress_ms();  // Interpolated
uint32_t duration = metadata.get_track_duration_ms();

// Timestamp conversion
int64_t client_ts = client.get_client_time(server_timestamp);
```

## Thread Safety Summary

The library runs its connection work on its own protocol task (`SsProto`): every handshake,
admission, pairing exchange, time sync, watchdog and send. `loop()` only delivers what that task
and the role threads produced, so a slow main loop delays callbacks but not connections.

Most listener callbacks fire on the main loop thread (the thread calling `client.loop()`). The exceptions are:

| Callback | Thread |
|---|---|
| `PlayerRoleListener::on_audio_write()` | Sync task background thread |
| `ArtworkRoleListener::on_image_decode()` | Dedicated artwork decode thread |
| `ArtworkRoleListener::on_image_display()` | Main loop thread |
| `VisualizerRoleListener` data callbacks (`on_loudness()`, `on_beat()`, `on_f_peak()`, `on_spectrum()`, `on_peak()`) | Dedicated visualizer drain thread |
| All other listener methods | Main loop thread |

`PlayerRole::notify_audio_played()` is thread-safe and is designed to be called from an audio output callback thread.

`ControllerRole::send_command()` is callable from any thread.

`SourceRole::write_audio()` is for exactly one capture thread; the library does not serialize concurrent writers. `SourceRole::set_signal()` and `is_streaming()` are main loop only.

`ArtworkRole::frame_done()` must be called from the main loop thread (typically from inside `on_image_display()`/`on_image_clear()` or when a cross-fade animation completes).

`SendspinPersistenceProvider` calls are on the main loop thread for every key (see the
`SendspinPersistenceProvider` section above). `SendspinNetworkProvider::is_network_ready()` is
called from any thread and must be cheap and non-blocking.

Callable from any thread: `connect_to()`, `disconnect()`, `leave()`,
`confirm_pairing_window()`, `cancel_pairing_window()`, `set_unpaired_access_enabled()` and the
getters `is_started()`, `is_connected()`, `is_time_synced()`, `get_client_time()`,
`get_server_information()` and `is_unpaired_access_enabled()`. The
requests take effect on the protocol task's next tick; the getters read what that task last
published. Controller commands are queued, so a burst of them can fill the
queue (see [Sending Commands](#sending-commands)); `connect_to()`, `disconnect()`, `leave()`,
the pairing-window gestures and `set_unpaired_access_enabled()` are posted instead, never
refused, and each holds only its latest call (the latest URL, the latest disconnect reason, the
later of a confirm and a cancel). A `connect_to()` and a `disconnect()` resolve by call order: a
`connect_to()` after a `disconnect()` opens the new attempt once the goodbyes are sent, and a
`disconnect()` after a `connect_to()` the task has not acted on cancels it. Posted requests are
applied ahead of the sends queued in the same window, so a send queued before a `disconnect()`
is dropped rather than sent after the goodbye, while a server connection that arrived before it
still goes through admission: a disconnect addresses the current connections, not a newcomer.
Releasing an outbound attempt that is still connecting (a
`disconnect()`, or a `connect_to()` that replaces it) does not wait for its transport either:
the attempt is closed without blocking and freed once its transport has finished, at the latest
once its connect bound has passed (30 s on host; on ESP-IDF three connect steps of 10 s each,
plus the DNS lookup, which lwIP's resolver bounds at 7 s per configured DNS server), so the
requests behind it are not held up, except that on ESP-IDF an attempt dropped at that bound
while its DNS lookup is still running holds the protocol task until the lookup gives up. Everything else (`start()`, `stop()`, `loop()`, the listener, provider and role setters, and role registration) belongs
to the main loop.

The pairing exchange (CPace and SHA-512) runs on the protocol task with the Noise handshakes, so
`protocol_task_stack_size` has to carry the deepest crypto frame.

## Minimal Example

A minimal integration that receives and discards audio:

```cpp
#include "sendspin/client.h"
#include "sendspin/player_role.h"

#include <chrono>
#include <thread>

using namespace sendspin;

struct MinimalPlayer : PlayerRoleListener {
    size_t on_audio_write(uint8_t* data, size_t length, uint32_t timeout_ms) override {
        return length;  // Discard audio
    }
};

struct AlwaysReady : SendspinNetworkProvider {
    bool is_network_ready() override { return true; }
};

int main() {
    SendspinClientConfig config;
    config.name = "Minimal Client";

    SendspinClient client(std::move(config));

    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    auto& player = client.add_player(std::move(player_config));

    MinimalPlayer player_listener;
    AlwaysReady network;
    player.set_listener(&player_listener);
    client.set_network_provider(&network);

    client.start();

    while (true) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
```

## Compile-Time Role Selection

By default all roles are enabled. You can disable roles at build time to exclude their code (and dependencies like audio decoders) from the binary. This is useful on constrained targets where flash space matters.

### CMake (Host Builds)

Pass `-D` options to cmake:

```bash
# Disable the player role (excludes decoder and sync task)
cmake -B build -DSENDSPIN_ENABLE_PLAYER=OFF

# Disable all optional roles, keep only the player
cmake -B build -DSENDSPIN_ENABLE_CONTROLLER=OFF \
               -DSENDSPIN_ENABLE_METADATA=OFF \
               -DSENDSPIN_ENABLE_ARTWORK=OFF \
               -DSENDSPIN_ENABLE_VISUALIZER=OFF \
               -DSENDSPIN_ENABLE_COLOR=OFF \
               -DSENDSPIN_ENABLE_SOURCE=OFF
```

Available options (all `ON` by default):

| Option | Controls |
|---|---|
| `SENDSPIN_ENABLE_PLAYER` | Player role, audio decoders (micro-flac, and micro-opus with `SENDSPIN_ENABLE_OPUS`), sync task |
| `SENDSPIN_ENABLE_OPUS` | Opus (micro-opus): the player's decoder and the source's encoder; no effect when both roles are `OFF` |
| `SENDSPIN_ENABLE_CONTROLLER` | Controller role |
| `SENDSPIN_ENABLE_METADATA` | Metadata role |
| `SENDSPIN_ENABLE_ARTWORK` | Artwork role |
| `SENDSPIN_ENABLE_VISUALIZER` | Visualizer role |
| `SENDSPIN_ENABLE_COLOR` | Color role |
| `SENDSPIN_ENABLE_SOURCE` | Source role (audio capture streamed to the server), source task |

When `SENDSPIN_ENABLE_PLAYER` is `OFF`, micro-flac is not fetched, and micro-opus is fetched only for the source role. `SENDSPIN_ENABLE_OPUS=OFF` drops micro-opus alone, for products that cannot ship Opus (see the patent note in the player and source role specs); the player then refuses `OPUS` entries in `audio_formats`, and the source refuses an `OPUS` codec in its config.

### ESP-IDF (Kconfig)

Role flags are exposed via Kconfig under `Component config → sendspin-cpp`:

```kconfig
CONFIG_SENDSPIN_ENABLE_PLAYER=y
CONFIG_SENDSPIN_ENABLE_OPUS=y
CONFIG_SENDSPIN_ENABLE_CONTROLLER=y
CONFIG_SENDSPIN_ENABLE_METADATA=y
CONFIG_SENDSPIN_ENABLE_ARTWORK=y
CONFIG_SENDSPIN_ENABLE_VISUALIZER=y
CONFIG_SENDSPIN_ENABLE_COLOR=y
CONFIG_SENDSPIN_ENABLE_SOURCE=y
```

The component also selects esp_websocket_client's `ESP_WS_CLIENT_SEPARATE_TX_LOCK`, so sends on an outbound connection (`connect_to()`) take their own lock rather than the one the client task holds while the receive handler waits for inbound ring space. With the source role and Opus enabled, micro-opus must stay in its thread-safe pseudostack allocation mode (the default); the build fails otherwise.

### Effect on the API

When a role is disabled, its `add_*()` method, accessor method, and backing member are removed from `client.h` via `#ifdef` guards. Attempting to call `client.add_player()` when `SENDSPIN_ENABLE_PLAYER` is `OFF` produces a compile error. The corresponding role header can still be included (it defines protocol types and the listener interface), but the role class cannot be instantiated.

---

## Configuration Reference

### SendspinClientConfig

Main client configuration passed to the `SendspinClient` constructor.

`client_id` is not a field in `SendspinClientConfig`. It is derived from the static
X25519 keypair and read back via `client.client_id()` after `start()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `std::string` | (none) | Friendly display name shown in the Sendspin UI |
| `product_name` | `std::optional<std::string>` | unset | Device product name; sent in `client/hello` only when set |
| `manufacturer` | `std::optional<std::string>` | unset | Manufacturer name (e.g., `"ESPHome"`); sent in `client/hello` only when set |
| `software_version` | `std::optional<std::string>` | unset | Software version string; sent in `client/hello` only when set |
| `mac_address` | `std::optional<std::string>` | auto-detected | MAC address of the network interface, lowercase colon-separated (e.g., `"aa:bb:cc:dd:ee:ff"`), sent in `client/hello`. Left unset, the library auto-detects it. ESP-IDF uses the default network interface (Wi-Fi or Ethernet). Host uses a best-effort from the active routable interface. Set explicitly to override (recommended on multi-homed hosts). |
| `pairing_code_out_channels` | `std::vector<SendspinPairingCodeChannel>` | `{}` | Where the device can emit a dynamic pairing code: `DISPLAY`, `SPEAKER`. Advertised as the descriptor's `out_channels`. Empty (or an empty `pairing_code_formats`) means the device cannot emit one, so `dynamic_pairing_code` is not advertised. |
| `pairing_code_formats` | `std::vector<SendspinPairingCodeFormat>` | `{}` | How the device can render a dynamic pairing code: `DIGITS` (six decimal digits), `QR_CODE` (a pairing token to render). Advertised as the descriptor's `formats`; the server picks one from this list. |
| `pairing_window_supported` | `bool` | `false` | Set to `true` when the application implements `on_open_pairing_window` / `on_close_pairing_window` on its `SendspinClientListener`. When `false`, the `static_pairing_code` method is not advertised even if `static_pairing_code` is set. Dynamic-pairing-code devices should also set it: an attempt held back by the round limit is gesture-gated through the same callbacks, and without them such an attempt stalls until the server cancels it. |
| `max_pairing_records` | `size_t` | `12` | Maximum number of long-term pairing records `RecordStore` retains. See [Record capacity](#record-capacity). |
| `httpd_psram_stack` | `bool` | `false` | Allocate HTTP server task stack in PSRAM (ESP-IDF only) |
| `httpd_priority` | `unsigned` | `5` | FreeRTOS priority for the HTTP server task (ESP-IDF only) |
| `httpd_stack_size` | `size_t` | `4608` | HTTP server task stack size in bytes (ESP-IDF only). The task runs esp_http_server, receives frames into the inbound ring and runs queued sends. Like every task stack default here, it is derived in `tools/stack_usage/README.md`. Values below the default are clamped up to it with a warning. Raising it is allowed. |
| `websocket_priority` | `unsigned` | `5` | FreeRTOS priority for the WebSocket client task (ESP-IDF only) |
| `websocket_stack_size` | `size_t` | `4608` | esp_websocket_client task stack size in bytes (ESP-IDF only), the outbound connection's transport task. Derived as for `httpd_stack_size`. Values below the default are clamped up to it with a warning. Raising it is allowed. |
| `protocol_task_psram_stack` | `bool` | `false` | Allocate the protocol task (`SsProto`) stack in PSRAM (ESP-IDF only). The task never writes flash (the persistence provider runs on the main loop), so its stack may live in PSRAM; a consumer that already exposes `httpd_psram_stack` (ESPHome does) should pass this through beside it, which moves the largest library task stack out of internal RAM on a device with PSRAM. |
| `protocol_task_priority` | `unsigned` | `5` | FreeRTOS priority for the protocol task (ESP-IDF only). Defaults to the httpd task's priority, below the player's sync task. |
| `protocol_task_stack_size` | `size_t` | `7168` | Protocol task stack size in bytes (ESP-IDF only). Every Noise handshake (including the in-band re-handshake after pairing, with its X25519 crypto), the pairing exchange (CPace and SHA-512), the JSON parse, the role handlers and every send run on this task. Derived as for `httpd_stack_size`. Values below the default are clamped up to it with a warning. |
| `server_port` | `uint16_t` | `8928` | WebSocket server port |
| `server_max_connections` | `uint8_t` | `4` | Maximum simultaneous WebSocket connections (one established, two unproven, and one spare so a surplus peer can be rejected with a goodbye) |
| `httpd_ctrl_port` | `uint16_t` | `0` | ESP-IDF httpd control port; `0` uses `ESP_HTTPD_DEF_CTRL_PORT + 1` to avoid conflict with the web_server component |
| `time_burst_size` | `uint8_t` | `8` | Number of messages per time sync burst |
| `time_burst_interval_ms` | `int64_t` | `10000` | Milliseconds between time sync bursts |
| `time_burst_response_timeout_ms` | `int64_t` | `10000` | Milliseconds before a burst message times out |
| `liveness_timeout_ms` | `std::optional<int64_t>` | unset (`60000` with default burst settings) | Milliseconds of inbound silence before the established connection is dropped as dead, with a `restart` goodbye so a server that was only slow reconnects. Unset derives it from the time burst settings, tolerating two consecutive unanswered time messages. An explicit value below `time_burst_interval_ms + time_burst_response_timeout_ms` drops healthy connections. Set or derived, it is capped at `SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS` (30 minutes). `0` disables the check. |
| `inbound_ring_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Memory placement for the shared inbound ring every admitted connection receives into (sized from the player's `audio_buffer_capacity`, the visualizer's `buffer_capacity`, one image per artwork channel in flight plus the artwork images that arrive behind a held audio chunk, and a baseline every configuration pays, which is also its floor, of two of the longest messages the enabled roles need in one piece: 131,152 bytes with the artwork role or a player whose advertised buffer reaches a Noise frame, 32,880 with neither and no larger visualizer message, two of the player's longest chunks in between; audio is decoded straight out of it) and each connection's fallback buffer, which holds a pre-admission message or a message longer than the ring takes. The sizing budgets the control messages and time replies that arrive while the oldest held audio chunk or visualizer frame, or an artwork part waiting for the decode thread to copy it, is out; an exhausted ring closes the connection ([The Inbound Ring](internals.md#the-inbound-ring)). `PREFER_EXTERNAL` tries SPIRAM first and falls back to internal RAM; `PREFER_INTERNAL` does the reverse. Use `PREFER_INTERNAL` on devices with slow PSRAM (e.g., plain ESP32) to avoid stuttering. ESP-IDF only; ignored on host. |
| `noise_buffer_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Memory placement for the Noise transport's fragment reassembly buffer and the ~64 KB fragmentation frame buffer. The reassembly buffer grows with the largest fragmented message received (e.g. album artwork) and retains its capacity for the life of the connection, so keeping it in SPIRAM protects internal RAM. Independent of `inbound_ring_location` (which covers the inbound ring). ESP-IDF only; ignored on host. |
| `pairing_psk` | `std::optional<SendspinPsk>` | unset | A factory-provisioned Pairing PSK (32 bytes). Outranks a stored one and is never persisted; an all-zero key or the Sentinel PSK makes `start()` fail. Unset loads the stored one or generates and persists one on first boot. See [Pairing PSK](#pairing-psk). |
| `static_pairing_code` | `std::optional<std::string>` | unset | The device's static pairing code, exactly 8 decimal digits. The `static_pairing_code` method is advertised only when this is set, `pairing_window_supported` is true, and `dynamic_pairing_code` is not advertised. An invalid value makes `start()` fail. |
| `pairing_psk_locations` | `std::vector<std::string>` | `{}` | Where the operator can find the pairing token the device shipped with: any of `"device"`, `"leaflet"`, `"operator"`. Advertised as the informational `locations` hint on the `pairing_psk` descriptor in `client/hello`; empty omits the hint, see [The locations hint](#the-locations-hint). |
| `static_pairing_code_locations` | `std::vector<std::string>` | `{}` | Where the operator can find the static pairing code the device shipped with, same values as above. Advertised on the `static_pairing_code` descriptor in `client/hello`; empty omits the hint. |
| `json_arena_size` | `size_t` | `2048` | Size in bytes of a fixed internal-RAM scratch buffer that backs every JSON document the protocol task works with: the parse of each incoming protocol message and every message it builds, instead of PSRAM. Costs this many bytes of internal RAM permanently but removes PSRAM traffic from the protocol task on every message. The arena holds one document at a time: a parsed message is released before the reply it triggers (the `client/state` after a `server/activate`, a pairing reply, a re-handshake's second message) is built. The default covers one steady-state protocol message, including the FLAC stream-start header; a document larger than the budget on its own, such as a large track-metadata message, falls back to PSRAM (those arrive only once per song). That holds on a 32-bit target, where ArduinoJson allocates each variant pool as one 1,024-byte block. Every freed block is wiped, so a document that held key material leaves none behind. Set to `0` to send every document to PSRAM. On host there is no PSRAM distinction, so the arena is just a fixed scratch buffer, and since a variant pool alone is 4 KB there, the default fits no document's pool on host. |

---

### PlayerRoleConfig

Configuration passed to `client.add_player()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `audio_formats` | `std::vector<AudioSupportedFormatObject>` | `{}` | Audio formats the player supports, in priority order; advertised to the server during the hello handshake. The server selects one when establishing a stream. Must list at least one `FLAC` or `PCM` entry, the codecs every server supports; `OPUS` may be listed in addition when the build has the Opus decoder (`SENDSPIN_ENABLE_OPUS`). `start()` fails and logs otherwise. |
| `audio_buffer_capacity` | `size_t` | `1000000` | Bytes of the shared inbound ring the player may hold as encoded audio (its quota; the ring is sized to include it). Each chunk is charged its stored size, so the client advertises the share that holds encoded frames at the smallest chunk size (2/3 of it) to the server; a server filling that share with frames under 144 bytes overruns the quota, and the excess is dropped with a warning. The advertised value is at most the ring's largest item so that any single chunk the server may send fits (621,312 bytes with the default ring, below the 666,666-byte share). The ring also holds the traffic that arrives while the oldest chunk is held (`derive_inbound_ring_bytes()` in `src/inbound_ring.h`), so the default quota yields a 1,242,704-byte ring; a visualizer's frame rate and the artwork channels' images add to it (1,641,776 bytes with one 128 KB artwork channel). Larger buffers absorb more jitter at the cost of memory. While the oldest chunk is held, the control messages and time replies have only that pass-through allowance; a sync task stalled in `on_audio_write()` or a server far over the advertised buffer can exhaust it, and an exhausted ring closes the connection with "ring pinned behind held items" ([The Inbound Ring](internals.md#the-inbound-ring)). |
| `fixed_delay_us` | `int32_t` | `0` | Fixed platform-level delay offset in microseconds (e.g., a known I2S pipeline delay). Applied on top of the user-adjustable output delay. |
| `initial_output_delay_ms` | `uint16_t` | `0` | Initial value for the user-adjustable output delay in milliseconds. Overridden by the persisted value if a `SendspinPersistenceProvider` is set. |
| `extra_startup_silence_ms` | `uint16_t` | `50` | Extra silence inserted at stream start, after the first playback notification and before the first decoded chunk reaches the sink. Added on top of the initial-sync priming silence to give the decode pipeline more slack to stay ahead of the sink, preventing the initial-playback stutter caused by the decoder briefly falling behind. Larger values trade a longer startup delay for more underflow protection; set to `0` to disable. |
| `required_lead_time_ms` | `std::optional<uint16_t>` | unset (`150` with the default startup silence) | Startup lead in milliseconds reported to the server as `required_lead_time_ms`, measured from the server's transmission of a `stream/start` or `stream/clear` to the playback timestamp of the first chunk that can be played in full. Unset reports what the pipeline itself spends: the sync task's 25 ms priming silence, the configured `extra_startup_silence_ms`, and a 75 ms allowance for codec init, the first decode and the audio backend. Set it for an output with more startup latency than that allowance; a value below what the pipeline spends is raised to it. The server treats it as a hint and may give less lead. |
| `min_buffer_ms` | `uint16_t` | `500` | Ongoing buffer duration in milliseconds reported to the server as `min_buffer_ms`: how much audio the player wants held ahead of playback during a stream to absorb network jitter and decode timing variance. Mostly relevant for live streams. The audio it represents must fit `audio_buffer_capacity` at the highest-bitrate entry in `audio_formats`. |
| `psram_stack` | `bool` | `false` | Allocate sync/decode task stack in PSRAM (ESP-IDF only) |
| `priority` | `unsigned` | `6` | FreeRTOS priority for the sync/decode task (ESP-IDF only). The default value, `6`, is one above the default `httpd_priority` (`5`). If you customize priorities, keep this above `httpd_priority` so the HTTP server task cannot starve the decoder during the initial burst of encoded audio that fills the buffer at stream start. |
| `decode_buffer_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Memory placement preference for the decode transfer buffer. `PREFER_EXTERNAL` tries SPIRAM first and falls back to internal RAM; `PREFER_INTERNAL` does the reverse. ESP-IDF only; ignored on host. |

Each entry in `audio_formats` is an `AudioSupportedFormatObject`:

| Field | Type | Description |
|---|---|---|
| `codec` | `SendspinCodecFormat` | Audio codec (`FLAC`, `OPUS`, or `PCM`) |
| `channels` | `uint8_t` | Number of audio channels |
| `sample_rate` | `uint32_t` | Sample rate in Hz |
| `bit_depth` | `uint8_t` | Bits per sample |

---

### ArtworkRoleConfig

Configuration passed to `client.add_artwork()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `preferred_formats` | `std::vector<ImageSlotPreference>` | `{}` | Image slot preferences advertised to the server during the hello handshake. Each entry declares an image source, format, and resolution; the slot/channel number is the entry's index in this vector. |
| `psram_stack` | `bool` | `false` | Allocate decode thread stack in PSRAM (ESP-IDF only) |
| `priority` | `unsigned` | `2` | FreeRTOS priority for the decode thread (ESP-IDF only) |

Each entry in `preferred_formats` is an `ImageSlotPreference`. The slot/channel number is the entry's index in `preferred_formats` (first entry is slot 0), so entries are declared in slot order:

| Field | Type | Description |
|---|---|---|
| `source` | `SendspinImageSource` | Image source (`ALBUM` or `ARTIST`) |
| `format` | `SendspinImageFormat` | Image format (`JPEG` or `PNG`) |
| `width` | `uint16_t` | Desired image width in pixels |
| `height` | `uint16_t` | Desired image height in pixels |
| `require_frame_done` | `bool` | Opt-in back-pressure gate (default `false`). When set, the role delivers at most one un-acked frame or clear at a time for this slot; the consumer must call `ArtworkRole::frame_done(slot)` to release the gate. See [ArtworkRoleListener](#artworkrolelistener). |
| `display_offset_ms` | `int32_t` | Shifts the display deadline (default `0`). Positive fires `on_image_display()` earlier (mirroring `PlayerRoleConfig::fixed_delay_us`), negative delays it; lets a cross-fade straddle the track boundary. |
| `max_image_bytes` | `uint32_t` | Largest encoded image this channel holds, in bytes (default 128 KiB). A larger image is refused: the transfer is followed to its end with its bytes dropped and the channel keeps what it was showing. The role holds one assembly buffer of this size per configured channel from `start()` to `stop()`, which an image waits in while a `require_frame_done` channel's last delivery is un-acked, and the inbound ring reserves one image of this size per channel in flight, sent in parts of at least 4,096 bytes (the reference server sends maximal parts of 65,517 bytes): the quota charges each part its stored size, so an image split into smaller parts can exceed it and is dropped while the decode thread is busy. That quota is one image: a second image for the channel arriving behind a complete one still queued while the decode thread is inside a long `on_image_decode()` is dropped, and the channel keeps its current image until the server's next one. A third image arriving while `on_image_decode()` is still inside the first one is dropped the same way, but with no hold window of 30 s or more (artwork alone, or a visualizer holding under 30 s) its refused parts stay pinned behind the queued image, so a stall long enough for time replies and state to arrive behind them can exhaust the ring and close the connection; that takes a callback blocked for about two image cadences or track skips faster than the ring's budget. `0` holds nothing at all. |

---

### VisualizerRoleConfig

Configuration passed to `client.add_visualizer()`.

| Field | Type | Default | Description |
|---|---|--|---|
| `support` | `VisualizerSupportObject` | - | Visualizer capabilities advertised to the server during the hello handshake |
| `stream` | `VisualizerStreamConfig` | - | Stream configuration reported to the server in `client/state` |
| `psram_stack` | `bool` | `false` | Allocate drain thread stack in PSRAM (ESP-IDF only) |
| `display_offset_ms` | `int32_t` | `0` | Fires the data callbacks this far ahead of each frame's display time (negative delays them), for a consumer's own render latency. The callbacks' `client_timestamp` stays the display time. |
| `priority` | `unsigned` | `2` | FreeRTOS priority for the drain thread (ESP-IDF only) |

`VisualizerSupportObject` fields:

| Field | Type | Description |
|---|---|---|
| `buffer_capacity` | `size_t` | Bytes of the shared inbound ring the visualizer may hold (its quota; the ring is sized to include it). Per-item overhead means only ~1/7 holds wire data at the smallest frame size; the client advertises that effective capacity to the server. The advertised value is at most the ring's largest item so that any single chunk the server may send fits, which a seventh of the quota always is. Below 70 bytes (the smallest budget that advertises one frame) the role refuses to start. The ring's pass-through budget assumes the server fills this quota at `rate_max`, the shortest the oldest frame is held; a sparser stream (a few beats a second) holds it longer and pins more traffic behind it than budgeted, which exhausts the ring and closes the connection with "ring pinned behind held items" ([The Inbound Ring](internals.md#the-inbound-ring)) |

`VisualizerStreamConfig` fields:

| Field | Type | Description |
|---|---|---|
| `types` | `std::vector<VisualizerDataType>` | Data stream types to receive (`BEAT`, `LOUDNESS`, `F_PEAK`, `SPECTRUM`, `PEAK`); may be empty to request none |
| `rate_max` | `uint16_t` | Maximum periodic frames per second; set to the display refresh rate. Must be positive when `types` is non-empty, or `SendspinClient::start()` fails |
| `spectrum` | `std::optional<VisualizerSpectrumConfig>` | Spectrum analysis parameters; required when `SPECTRUM` is in `types`, or `SendspinClient::start()` fails |

`VisualizerSpectrumConfig` fields:

| Field | Type | Description |
|---|---|---|
| `n_disp_bins` | `uint8_t` | Number of frequency bins to receive |
| `scale` | `VisualizerSpectrumScale` | Frequency scale (`MEL`, `LOG`, or `LIN`) |
| `f_min` | `uint16_t` | Minimum frequency in Hz |
| `f_max` | `uint16_t` | Maximum frequency in Hz |

### SourceRoleConfig

Configuration passed to `client.add_source()`. A value that breaks any rule below logs at ERROR and leaves the role inert, neither advertised nor streaming; values are never clamped.

| Field | Type | Default | Description |
|---|---|---|---|
| `codec` | `SendspinCodecFormat` | `PCM` | `PCM` sends the capture bytes untouched; `OPUS` encodes each chunk into one CELT-only Opus packet (needs `SENDSPIN_ENABLE_OPUS`). `FLAC` is not accepted. `OPUS` costs the encoder state plus a micro-opus scratch arena for the source task (about 120 KB, PSRAM-preferring, allocated before the first Opus chunk is encoded), separate from the one the player's sync task holds. |
| `sample_rate` | `uint32_t` | `48000` | Capture rate in Hz, more than 0. `OPUS` takes 8000, 12000, 16000, 24000, or 48000. |
| `channels` | `uint8_t` | `2` | Capture channel count, at least 1 (1 or 2 for `OPUS`) |
| `bit_depth` | `uint8_t` | `16` | 16, 24 (3 packed bytes), or 32; `OPUS` takes 16 |
| `chunk_duration_ms` | `uint32_t` | `20` | Audio per chunk, 5 to 150 ms; one chunk with its header must fit one Noise transport message. `OPUS` takes 5, 10, 20, 40, or 60. |
| `capture_buffer_ms` | `uint32_t` | `500` | More than 0 ms; about the longest network stall the stream rides out without a gap; a longer one resumes from live capture. A single write must fit in just under 5/8 of it. |
| `opus_bitrate` | `uint32_t` | `128000` | Opus bitrate in bit/s, 500 to 512000; ignored for `PCM` |
| `opus_complexity` | `uint8_t` | `2` | Opus encoder complexity, at most 10; ignored for `PCM` |
| `line_sense` | `bool` | `false` | Advertise signal sensing; see `SourceRole::set_signal()` |
| `buffer_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Placement of the capture buffer and the chunk buffer (ESP-IDF only) |
| `priority` | `unsigned` | `3` | FreeRTOS priority for the source task, below the protocol and httpd tasks (ESP-IDF only) |
| `psram_stack` | `bool` | `false` | Allocate the source task stack in PSRAM (ESP-IDF only) |

The capture buffer is allocated by the first `start()` and kept until the client is destroyed, since the capture thread may write at any time; the chunk buffer, which holds a few chunks for the protocol task to send, lives from each `start()` to its `stop()`.

---

## Enums Reference

### ConnectionTrust

| Value | Description |
|---|---|
| `NONE` | Sentinel or Pairing PSK was used; this server has not been paired |
| `USER` | Long-term record matched; the server is paired |

Reported via `SendspinClientListener::on_trust_changed` on admission and again after each
successful in-band re-handshake. See [Trust Levels](#trust-levels).

### SendspinPairAbortReason

| Value | Description |
|---|---|
| `ATTEMPT_TIMEOUT` | Pairing timed out waiting for the next step |
| `CONCURRENT_ATTEMPT` | The server rejected pairing because another pairing is in progress |
| `METHOD_NOT_SUPPORTED` | The proposed pairing method is not supported by the client |
| `PAIRING_CODE_MISMATCH` | The pairing code entered does not match the one this client emitted |
| `USER_CANCELLED` | The pairing was cancelled by the user: by the server, or locally by `cancel_pairing_window()` while an attempt was waiting for the gesture |
| `UNKNOWN` | Unrecognized abort reason from the server, or a client-local protocol error (which also closes the connection) |

Delivered via `SendspinClientListener::on_pairing_failed`. An activation naming a pairing
method or format the client does not offer is answered with a `pair/abort` carrying
`method_not_supported` and no listener callback at all; the connection stays open.

### SendspinPairingCodeChannel

| Value | Description |
|---|---|
| `DISPLAY` | The code is shown on a display |
| `SPEAKER` | The code is spoken, not tone-encoded |

Listed in `SendspinClientConfig::pairing_code_out_channels` and advertised as the
`dynamic_pairing_code` descriptor's `out_channels`.

### SendspinPairingCodeFormat

| Value | Description |
|---|---|
| `DIGITS` | Six decimal digits the operator types into the server |
| `QR_CODE` | A pairing token the operator scans from a rendered QR code |

Listed in `SendspinClientConfig::pairing_code_formats` and advertised as the
`dynamic_pairing_code` descriptor's `formats`; the server picks one of them and the chosen
format arrives as the `format` argument of `on_display_pairing_code`.

### SendspinCodecFormat

| Value | Description |
|---|---|
| `FLAC` | FLAC lossless audio |
| `OPUS` | Opus lossy audio; decodable, and encodable by the source role, only in a build with `SENDSPIN_ENABLE_OPUS` |
| `PCM` | Raw PCM audio |
| `UNSUPPORTED` | Unsupported codec |

### SendspinControllerCommand

| Value | Description |
|---|---|
| `PLAY` | Start playback |
| `PAUSE` | Pause playback |
| `STOP` | Stop playback |
| `NEXT` | Skip to next track |
| `PREVIOUS` | Skip to previous track |
| `VOLUME` | Set volume (pass value via the `volume` field) |
| `MUTE` | Set mute state (pass value via the `muted` field) |
| `REPEAT_OFF` | Disable repeat |
| `REPEAT_ONE` | Repeat current track |
| `REPEAT_ALL` | Repeat all tracks |
| `SHUFFLE` | Enable shuffle |
| `UNSHUFFLE` | Disable shuffle |
| `SWITCH` | Switch source |
| `SEEK` | Seek to an absolute position (pass value via the `position_ms` field) |
| `SEEK_RELATIVE` | Seek by a signed offset from the current position (pass value via the `offset_ms` field) |

### SendspinPlayerCommand

| Value | Description |
|---|---|
| `VOLUME` | Volume adjustment from the server |
| `MUTE` | Mute state change from the server |
| `SET_OUTPUT_DELAY` | Output delay adjustment from the server |

These represent commands the server can send to the player. The player advertises which commands it supports. Enable `SET_OUTPUT_DELAY` with `player.set_output_delay_adjustable(true)`.

### SendspinGoodbyeReason

| Value | Description |
|---|---|
| `ANOTHER_SERVER` | Disconnecting to connect to another server |
| `SHUTDOWN` | Device is shutting down |
| `RESTART` | Device is restarting |
| `USER_REQUEST` | User requested disconnect |
| `UNAUTHORIZED` | Server requested an activity its trust level does not permit |
| `PAIRING_REQUIRED` | Server requested playback but the client requires pairing first |
| `CONCURRENT_ATTEMPT` | Incoming connection rejected because another is already admitted. Distinct from the same-named `SendspinPairAbortReason`, which is specific to pairing |
| `UNPAIRED` | Server unpaired this device via `server/unpair` |

### SendspinPlaybackState

| Value | Description |
|---|---|
| `PLAYING` | Audio is playing |
| `STOPPED` | Audio is stopped |

### SendspinRepeatMode

| Value | Description |
|---|---|
| `OFF` | Repeat disabled |
| `ONE` | Repeat current track |
| `ALL` | Repeat all tracks |

### SendspinImageFormat

| Value | Description |
|---|---|
| `JPEG` | JPEG image |
| `PNG` | PNG image |

### SendspinImageSource

| Value | Description |
|---|---|
| `ALBUM` | Album artwork |
| `ARTIST` | Artist image |
| `NONE` | No image source |

### VisualizerDataType

| Value | Description |
|---|---|
| `BEAT` | Musical beat events from tempo/beat tracking |
| `LOUDNESS` | Overall loudness level |
| `F_PEAK` | Dominant frequency and its amplitude |
| `SPECTRUM` | Full frequency spectrum bins |
| `PEAK` | Energy onset (transient) events |

### VisualizerSpectrumScale

| Value | Description |
|---|---|
| `MEL` | Mel scale (perceptual) |
| `LOG` | Logarithmic scale |
| `LIN` | Linear scale |

### SourceSignal

| Value | Description |
|---|---|
| `PRESENT` | Audio signal detected on the capture input |
| `ABSENT` | No audio signal on the capture input |

Reported with `SourceRole::set_signal()`; meaningful only with `SourceRoleConfig::line_sense` set.

### LogLevel

| Value | Description |
|---|---|
| `NONE` | No logging |
| `ERROR` | Errors only |
| `WARN` | Warnings and above |
| `INFO` | Informational and above (default) |
| `DEBUG` | Debug and above |
| `VERBOSE` | All messages |

Set with `SendspinClient::set_log_level()`. Only affects host builds; ESP-IDF builds use the ESP log level system.

### MemoryLocation

| Value | Description |
|---|---|
| `PREFER_EXTERNAL` | Prefer SPIRAM, fall back to internal RAM (ESP-IDF only) |
| `PREFER_INTERNAL` | Prefer internal RAM, fall back to SPIRAM (ESP-IDF only) |

Used by `SendspinClientConfig::inbound_ring_location` to control where the shared inbound ring and the per-connection fallback buffers are allocated, by `SendspinClientConfig::noise_buffer_location` to control where the Noise transport's fragment reassembly and fragmentation buffers are allocated, by `PlayerRoleConfig::decode_buffer_location` to control where the player's decode transfer buffer is allocated, and by `SourceRoleConfig::buffer_location` to control where the source's capture and chunk buffers are allocated. Ignored on host platforms (no internal/external distinction).
