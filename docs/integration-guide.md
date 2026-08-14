# Integration Guide

This guide describes what you need to implement in order to integrate sendspin-cpp into your application. The library provides the Sendspin protocol, audio decoding, and time synchronization. You provide the audio output, network readiness, and optional persistence.

## Overview

Integration follows this pattern:

1. Create a `SendspinClient` with a configuration struct
2. Add roles (player, controller, metadata, artwork, visualizer, color) depending on what your application needs
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
identity survives reboots. After `start_server()` the derived `client_id` is available
via `client.client_id()`.

The `client_id` uniquely identifies this device to Sendspin servers and must be stable
across reboots for pairing and server-preference to work correctly. Without a persistence
provider the keypair is regenerated on every boot (development use only).

## Step 2: Add Roles

Add only the roles your application needs. All roles must be added before calling `start_server()`.

### Player Role (Audio Playback)

The player role handles audio decoding and synchronized playback. It requires a configuration struct that declares which audio formats your hardware supports.

```cpp
PlayerRoleConfig player_config;
player_config.audio_formats = {
    {SendspinCodecFormat::FLAC, 2, 44100, 16},
    {SendspinCodecFormat::FLAC, 2, 48000, 16},
    {SendspinCodecFormat::OPUS, 2, 48000, 16},
    {SendspinCodecFormat::PCM, 2, 44100, 16},
    {SendspinCodecFormat::PCM, 2, 48000, 16},
};
player_config.audio_buffer_capacity = 1000000;   // Ring buffer size in bytes (default: 1000000)
player_config.fixed_delay_us = 0;                // Fixed delay offset in microseconds
player_config.initial_static_delay_ms = 0;       // Initial user-adjustable delay
player_config.extra_startup_silence_ms = 50;     // Extra startup silence for decode headroom (default: 50)

auto& player = client.add_player(std::move(player_config));
```

Each `AudioSupportedFormatObject` declares a codec/channels/sample_rate/bit_depth combination. The server selects from these when establishing an audio stream.

The stream parameters negotiated by the server are available via `get_current_stream_params()`, which returns a `ServerPlayerStreamObject` with these fields:

| Field | Type | Description |
|---|---|---|
| `codec` | `std::optional<SendspinCodecFormat>` | Audio codec |
| `sample_rate` | `std::optional<uint32_t>` | Sample rate in Hz |
| `channels` | `std::optional<uint8_t>` | Number of channels |
| `bit_depth` | `std::optional<uint8_t>` | Bits per sample |
| `codec_header` | `std::optional<std::string>` | Codec-specific header data |

Call `is_complete()` on the object to check if all fields have values.

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

The slot/channel number for each entry is its position (index) in `preferred_formats`; the first entry is slot 0, the second slot 1, and so on. Up to `ARTWORK_MAX_SLOTS` (4) entries are supported.

### Visualizer Role (Audio Visualization)

Receives real-time beat, loudness, peak frequency, onset, and spectrum data synchronized to playback.

```cpp
VisualizerSupportObject vis_support;
vis_support.types = {
    VisualizerDataType::BEAT,
    VisualizerDataType::LOUDNESS,
    VisualizerDataType::F_PEAK,
    VisualizerDataType::SPECTRUM,
    VisualizerDataType::PEAK,
};
vis_support.buffer_capacity = 32768;  // Total ring buffer bytes; ~1/3 holds wire data
vis_support.rate_max = 30;  // Set to the display refresh rate
vis_support.spectrum = VisualizerSpectrumConfig{
    .n_disp_bins = 32,
    .scale = VisualizerSpectrumScale::MEL,
    .f_min = 40,
    .f_max = 16000,
};

auto& visualizer = client.add_visualizer({.support = vis_support});
```

### Color Role (Audio-Derived Color Palette)

Receives an RGB color palette derived by the server from the currently playing audio (e.g., extracted from album artwork). Useful for LED matrices, status lights, or themed displays. Server-to-client only; no configuration.

```cpp
auto& color = client.add_color();
```

## Step 3: Implement Listener Interfaces

### PlayerRoleListener (Required if Using Player Role)

The `on_audio_write` method is the only pure virtual (required) method in the entire library.

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

    // Optional: Called when the server changes the static delay.
    void on_static_delay_changed(uint16_t delay_ms) override { }
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

A field is `nullopt` when the server has not provided it or has explicitly cleared it. Listeners that mirror metadata into display state should overwrite the displayed value on every `on_metadata()` call (using e.g. `value_or("")`) so that server clears propagate.

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

**Knowing when there is no artwork.** Artwork stays valid until the server replaces or clears it, and the artwork role is independent of the metadata role, so a track change alone sends nothing: the next track of the same album keeps showing the image already delivered. When an item genuinely has no artwork, the server clears that channel and `on_image_clear()` fires for that slot alone, scheduled to its server timestamp like a display (`display_offset_ms` included) so it lands on the item boundary. `on_image_clear()` also fires for every configured slot on stream end, stream clear, and disconnect.

| What happened | What the listener sees |
| --- | --- |
| Artwork unchanged (e.g. next track of the same album) | nothing; the current image stays valid |
| Item has no artwork | `on_image_clear(slot)` for that slot |
| Stream ended, cleared, or connection lost | `on_image_clear(slot)` for every configured slot |

**Cross-fades with back-pressure (opt-in).** By default the role decodes and displays every frame as it arrives. A slot can instead opt into a back-pressure gate by setting `ImageSlotPreference::require_frame_done`. With the gate on, the role keeps at most one un-acked *delivery* (a frame or a clear) in flight for that slot. Call `ArtworkRole::frame_done(slot)` from the main loop exactly once for every `on_image_display()` and `on_image_clear()` that slot receives -- e.g. once a cross-fade animation finishes. An extra call is a harmless no-op, but a missed one wedges the slot: there is no timeout, the acknowledgment is the contract.

Payloads and stream-level clears reach the gate differently:

- A **frame or per-channel clear** arriving while a delivery is un-acked is buffered latest-wins and delivered only after `frame_done(slot)`, and then owes its own `frame_done()`. It waits behind the outstanding delivery rather than replacing it, so a consumer is never interrupted mid-fade.
- A **stream end or stream clear** is a lifecycle event, not a payload, so it is never buffered: it fires `on_image_clear()` immediately for every configured slot, discards anything buffered, and replaces whatever delivery was outstanding. Exactly one `frame_done()` is owed afterward whatever was in flight.

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
    // frame's display timestamp. Copy data quickly and defer heavy processing.
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

    // Called when the connection is lost and cached colors are dropped.
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

A field is `nullopt` when the server has not provided it or has explicitly cleared it; listeners do not need to distinguish those cases.

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

### SendspinPersistenceProvider (Optional)

Allows the library to persist state across reboots. Required for stable identity and
pairing. On host platforms `examples/common/file_persistence_provider.h` provides
`FilePersistenceProvider`, which persists to a single JSON file (one document mapping each
key below to `base64url(bytes)`) -- use it directly or as a reference implementation.

The interface is a plain byte-blob store -- three methods, independent of what is being
stored:

```cpp
class SendspinPersistenceProvider {
public:
    virtual std::optional<std::vector<uint8_t>> load_blob(const std::string& key);
    virtual bool save_blob(const std::string& key, const uint8_t* data, size_t len);
    virtual bool erase_blob(const std::string& key);
};
```

The library owns all serialization. It calls these three methods with one of the fixed keys
below; a provider never needs to parse or interpret the bytes, only store and return them
byte-for-byte.

Most keys are only ever touched from the main loop thread. Two exceptions:

- `save_blob(persistence_keys::RECORDS, ...)` is also called on the network thread when a
  pairing finalizes (the record must be durable before the server's immediate re-handshake
  resolves it). This can therefore overlap a main-loop call to another key, so an
  implementation that shares state across keys (a file, a handle) must serialize its own
  access. `FilePersistenceProvider` guards every call with a mutex.
- `save_blob(persistence_keys::KEYPAIR, ...)` fires once, during `start_server()` (main loop),
  called out only because it is a startup-time write rather than a response to a runtime event.

#### Keyspace

Every key is a fixed constant from the `persistence_keys` namespace (`sendspin/client.h`), at
most 12 characters (comfortably under a typical NVS key's 15-character limit). A provider must
not invent its own keys; it only needs to store and return whatever bytes the library gives it
for each of these:

| Key | Contents |
|---|---|
| `persistence_keys::KEYPAIR` | 32 raw bytes: the static X25519 private key. No codec. |
| `persistence_keys::RECORDS` | The WHOLE `SendspinPairingRecord` array as one codec blob (`encode_pairing_records()` / `decode_pairing_records()` in `sendspin/persistence_codec.h`). Stays present (possibly as an empty array) once any record has ever existed. |
| `persistence_keys::PAIRING_PSK` | The accepted `SendspinPairingPsk` as one codec blob (`encode_pairing_psk()` / `decode_pairing_psk()`). |
| `persistence_keys::STATIC_PIN` | Raw UTF-8 bytes: the configured static PIN string. |
| `persistence_keys::PAIR_CONFIG` | The `SendspinPairingConfig` as one codec blob (`encode_pairing_config()` / `decode_pairing_config()`). |
| `persistence_keys::LAST_PLAYED` | Raw UTF-8 bytes: the `server_id` (base64url public key) of the last server that played audio. |
| `persistence_keys::STATIC_DELAY` | ASCII decimal string (e.g. `"150"`): the player's static delay in milliseconds. Chosen over raw `uint16_t` bytes for debuggability and to avoid an endianness dependency. |

`sendspin/persistence_codec.h` is public so a custom provider (or a test) can inspect or seed
the `RECORDS` / `PAIRING_PSK` / `PAIR_CONFIG` content in exactly the format the library itself
produces -- it is not something a provider hand-rolls its own version of.

#### Durability contract

- `save_blob()` returning `true` means DURABLY stored. This matters most for
  `persistence_keys::RECORDS`: the library gates pairing completion on it (a `false` return
  during pairing fails the exchange closed -- the client reports
  `SendspinPairAbortReason::STORAGE_FAILED` via `on_pairing_failed` and drops the connection
  rather than complete a pairing that could not survive a reboot) and gates revocation
  durability on it for removals (a revoked record is always dropped from RAM regardless of the
  return value, but a `false` return means the store still holds the old array and will hand
  the revoked record back at the next boot, silently making the revoked PSK valid again -- the
  library logs a warning saying exactly that).
- `erase_blob()` is only ever called for `persistence_keys::PAIRING_PSK` and
  `persistence_keys::STATIC_PIN` (a removal from `RECORDS` re-saves the shrunken array instead,
  so that key stays present). Absent counts as success. Same durability contract as a rejected
  save: the in-memory effect of the clear always happens regardless of the return value, but a
  `false` return means the cleared PSK/PIN may still be in the store and will resume
  authenticating pairing attempts / admitting the static PIN after a reboot.

Every method has a default no-op / `nullopt` implementation, so you can implement only the
keys your deployment actually needs. The minimum useful set for a deployed device is
`persistence_keys::KEYPAIR` (for stable identity) and `persistence_keys::RECORDS` (for pairing
to survive reboots).

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
    bool erase_blob(const std::string& key) override {
        return nvs_erase(key.c_str());  // Return true if the key is already absent, too.
    }
};
```

A provider backed by a single flat NVS namespace (as above) can often implement the whole
interface generically, since every key is already sized to fit and the library handles
serialization; a provider that needs different backing per key (e.g. a plaintext-secrets file
plus separate flash-wear-optimized storage for `STATIC_DELAY`) can switch on `key` instead.

#### Migrating from a Pre-Blob-Store Release

If your `SendspinPersistenceProvider` implementation predates the blob-store interface, it
implemented up to 17 typed methods (`save_static_keypair`, `load_pairing_records`,
`save_pairing_psk`, etc.) instead of the three generic ones above. There is no compatibility
shim: override `load_blob` / `save_blob` / `erase_blob` instead, using the keyspace table above
to know which key replaces which old method, and `sendspin/persistence_codec.h` to encode/decode
the struct types the old typed methods took directly. A provider carrying old typed `override`s
will fail to compile after upgrading (they no longer override anything); that is intentional
rather than silently no-op-ing.

The on-disk format is not preserved across this migration either: `examples/common/
file_persistence_provider.h`'s `FilePersistenceProvider` now stores one JSON document mapping
key to `base64url(bytes)`, replacing the old per-struct JSON layout. A file written by the old
provider is not read by the new one; delete it and let the device re-provision (a fresh keypair,
a fresh Pairing PSK) rather than trying to hand-migrate the old format.

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

    // Called when a server starts a Pairing-PSK pairing exchange.
    // server_id is the base64url public key of the server initiating pairing.
    void on_pairing_started(const std::string& server_id) override {
        printf("Pairing started with server %s\n", server_id.c_str());
    }

    // Called when pairing completes successfully and the long-term record is stored.
    // Subsequent connections from this server will report ConnectionTrust::USER.
    void on_pairing_succeeded(const std::string& server_id) override {
        printf("Pairing succeeded with server %s\n", server_id.c_str());
    }

    // Called when a pairing exchange is aborted. The connection is closed immediately
    // after this callback.
    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        printf("Pairing failed with server %s\n", server_id.c_str());
    }

    // Called once per admitted connection after the Noise handshake completes.
    // trust reflects the PSK category used:
    //   ConnectionTrust::USER  -- long-term pairing record (paired server)
    //   ConnectionTrust::NONE  -- Sentinel or Pairing PSK (unpaired access)
    void on_trust_changed(ConnectionTrust trust) override {
        bool paired = (trust == ConnectionTrust::USER);
        update_trust_indicator(paired);
    }

    // Dynamic-PIN pairing: display/clear a server-issued PIN. Only invoked when
    // SendspinClientConfig::pin_display_supported is true.
    void on_display_pairing_pin(const std::string& pin) override {
        show_pin_on_display(pin);
    }
    void on_clear_pairing_pin() override {
        clear_pin_from_display();
    }

    // PIN pairing: prompt/dismiss the operator pairing-window gesture for a gesture-gated
    // attempt (static PIN: every attempt; dynamic PIN: when the method is escalated by its
    // failure counter or the session PIN is shorter than 6 digits). Confirm the gesture by
    // calling client.confirm_pairing_window() (thread-safe) once the operator performs it;
    // calling it with no attempt waiting opens a standing 5-minute pairing window that admits
    // the next attempt without a further gesture.
    void on_open_pairing_window() override {
        prompt_pairing_button_press();
    }
    void on_close_pairing_window() override {
        dismiss_pairing_prompt();
    }
};
```

## Step 5: Wire Everything Together

Listeners and providers are set as raw pointers. They must outlive the client.

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
// Start the WebSocket server and sync task.
// Task priorities and PSRAM settings are taken from SendspinClientConfig.
if (!client.start_server()) {
    // Handle failure
    return 1;
}

// Optionally initiate a client-side connection to a known server URL.
// Without this, the client waits for incoming server connections.
client.connect_to("ws://192.168.1.10:8928/sendspin");

// Main loop: call loop() periodically to process events.
while (running) {
    client.loop();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// Clean shutdown
client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
```

## Encryption and Pairing

All connections are encrypted with Noise KKpsk2 (X25519 + ChaChaPoly or AES-GCM). This
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
client.start_server();
printf("client_id: %s\n", client.client_id().c_str());
```

### Cipher Suite

The default cipher suite is `ChaChaPoly` (lower CPU on bare-metal). On host targets AES-GCM
may be faster; set the preference in `SendspinClientConfig`:

```cpp
config.cipher_suite = NoiseCipherSuitePreference::AESGCM;
```

Both suites are always supported on host; this field only sets the preference sent to the
server. On ESP-IDF, `AESGCM` is not usable (see the `NoiseCipherSuitePreference` reference
below) and the library falls back to `ChaChaPoly` regardless of this setting.

### Pairing

Pairing creates a long-term trust record for a specific server. After pairing, connections
from that server resolve via the long-term PSK and report `ConnectionTrust::USER`.

Pairing is server-initiated. The server includes `pairing` in the `activities` of its
`server/activate` message; the library handles the exchange automatically. The application
observes pairing via `SendspinClientListener` callbacks:

1. `on_pairing_started(server_id)` -- the exchange has begun.
2. `on_pairing_succeeded(server_id)` -- the record is stored; the server will
   re-handshake immediately on the new long-term PSK.
3. `on_pairing_failed(server_id, reason)` -- the exchange failed; connection closed. See
   `SendspinPairAbortReason` below for the possible reasons, including the client-local
   `STORAGE_FAILED` case (the persistence provider rejected the record).

#### Pairing PSK

`pairing_psk` is the pairing method every client must implement, so the library provisions a
random Pairing PSK on first boot and persists it as a `persistence_keys::PAIRING_PSK` blob.
Nothing is required of the application to enable the method.

To pair, the server must learn that PSK out of band. Surface it as a **pairing token** -- one
`"SP:"`-prefixed string carrying the `client_id` and the PSK together, for the operator to
paste (or scan) into the server:

```cpp
auto token = client.pairing_token();  // e.g. "SP:0AAAQ..." (107 chars), nullopt before start_server()
```

The token is stable for the lifetime of the stored PSK, so it can be printed at startup, shown
in a UI, or rendered as a QR code.

To pin a specific PSK instead (for factory provisioning, where the same key is baked into a
setup tool), write one through the persistence provider before `start_server()`, encoded with
the codec so it round-trips through the library's own loader:

```cpp
SendspinPairingPsk psk;
// 32 raw bytes distributed out-of-band during provisioning
psk.psk = { /* ... */ };
psk.psk_id = "";  // derived from psk by the library; any value here is ignored
std::string blob = encode_pairing_psk(psk);  // sendspin/persistence_codec.h
persistence_provider.save_blob(persistence_keys::PAIRING_PSK,
                                reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
```

After pairing completes, `on_pairing_succeeded` fires and the long-term record is stored
by the library as a `persistence_keys::RECORDS` blob. Subsequent boots load that same blob;
no further provisioning is needed.

#### PIN pairing

The library also supports PIN-based pairing (dynamic and static), gated by
`SendspinClientConfig::pin_display_supported` / `pairing_window_supported` and the
`SendspinClientListener::on_display_pairing_pin` / `on_clear_pairing_pin` /
`on_open_pairing_window` / `on_close_pairing_window` callbacks documented in Step 3 above.
A method is advertised only when the platform capability flag is set: a client that leaves
`pin_display_supported` false never offers `dynamic_pin`, whatever the stored pairing config
says, and the server is then limited to the pairing-token flow.

Some PIN attempts are **gesture-gated**: the client answers the pairing activation with
`client/pair-pending` and withholds `client/pair-init` until a pairing window is open. Static
PIN gates every attempt; dynamic PIN gates an attempt only when the method is *escalated* or
the session's PIN length is below 6 digits. The window opens on the operator gesture
(`confirm_pairing_window()`) or via `management/open-pairing-window` from a paired server, it
lives for 5 minutes, and it admits exactly one attempt. A gesture performed before the
activation arrives leaves the window standing open, so the next attempt within its lifetime
proceeds without a prompt.

The gating rules apply to dynamic PIN even on a device that leaves
`pairing_window_supported` false. On such a device the `on_open_pairing_window` prompt cannot
fire, so a gated attempt sends `client/pair-pending`, logs a warning, and waits for either a
window opened remotely via `management/open-pairing-window` or the server's own timeout. To
keep escalated recovery in the operator's hands, a device that offers `dynamic_pin` should
set `pairing_window_supported` and implement the gesture callbacks.

Repeated dynamic-PIN failures escalate the method rather than locking it out: the client
keeps a single failure counter (persisted across reboots) that increments only when its own
verification of the server's key-confirmation tag fails, and resets when that verification
succeeds. At 10 failures the method becomes escalated -- every attempt is gesture-gated --
but it stays offered; there is no lockout state and no management command to clear the
counter.

### Trust Levels

`ConnectionTrust` reflects which PSK resolved during the Noise handshake:

| Value | PSK used | Meaning |
|-------|---------|---------|
| `ConnectionTrust::USER` | Long-term pairing record | Server has been paired with this client |
| `ConnectionTrust::NONE` | Sentinel or Pairing PSK | Unpaired access |

`on_trust_changed` fires once per admitted connection, after `server/activate` is
processed and the connection is promoted to current. Connections that are rejected
(e.g., missing record when unpaired access is disabled) do not fire this callback.

### Unpaired Access

By default only paired servers (long-term record) and servers holding the accepted Pairing
PSK are admitted. Servers that only know the Sentinel PSK (no pairing required) are admitted
when unpaired access is enabled, and the setting lives in the persisted
`SendspinPairingConfig`.

To ship a device that allows unpaired access out of the box, set the first-boot default in
`SendspinClientConfig`:

```cpp
SendspinClientConfig config;
config.initial_unpaired_access_enabled = true;
```

The seed applies only on a genuine first boot, and the seeded value is written through the
persistence provider during first-boot provisioning. On every later start the stored config
wins, so a server that turns unpaired access off through `management/set-pairing-config` keeps
it off across reboots. With no persistence provider there is no stored config, so the seed
applies on every start.

A config that fails to load is not treated as a first boot. The library's internal load of the
`persistence_keys::PAIR_CONFIG` blob is treated as "nothing stored" both when the key is truly
absent and when the stored blob fails to decode, and the interface gives a provider no way to
tell the client which happened. If any provisioned material survives -- a pairing record or the
Pairing PSK -- the seed is skipped and unpaired access stays disabled, so a damaged config on a
paired device fails closed rather than silently reopening unauthenticated access. A store that
lost everything is indistinguishable from a factory-fresh device, so the seed does apply there.

An application that manages the persisted pairing config itself can write the flag directly,
but it must read-modify-write the stored blob rather than save a fresh one:

```cpp
auto blob = persistence_provider.load_blob(persistence_keys::PAIR_CONFIG);
if (blob.has_value()) {
    std::string text(blob->begin(), blob->end());
    auto cfg = decode_pairing_config(text);  // sendspin/persistence_codec.h
    if (cfg.has_value()) {
        cfg->unpaired_access_enabled = true;
        std::string encoded = encode_pairing_config(*cfg);
        persistence_provider.save_blob(persistence_keys::PAIR_CONFIG,
                                        reinterpret_cast<const uint8_t*>(encoded.data()),
                                        encoded.size());
    }
}
```

This is why the read-modify-write step matters: the provider is a byte store and does not
validate what it is handed, so saving a bare, default-constructed `SendspinPairingConfig`
*will* be written and *will* take effect on the next boot -- silently resetting every policy
field (`pairing_psk_enabled`, `dynamic_pin_enabled`, and in particular the empty
`record_mode_psk_id`, which drops the client's reference to its shared-PSK fallback record) to
the struct's compiled-in defaults rather than merely failing to change `unpaired_access_enabled`.
`RecordStore` does notice the empty `record_mode_psk_id` and re-provisions a fresh shared-PSK
fallback record for it, but that repair does not restore the OTHER policy fields the bare write
clobbered, and it does not count as a first boot (the config blob still decoded successfully),
so `initial_unpaired_access_enabled` is not reapplied either. Before the first `start_server()`
there is no stored config to modify, so use the seed instead.

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

Fields that do not match the command are ignored when the message is serialized. The server clamps seeks to the seekable range and ignores any command not present in the controller state's `supported_commands`.

> **Deprecated:** the earlier positional overload `send_command(cmd, volume, mute)` still works but cannot carry seek parameters and will be removed in v0.8.0. Migrate to the struct form above.

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
```

Use these accessors when the role reference from `add_*()` is out of scope.

> **Note:** Role registration methods (`add_player()`, etc.), accessor methods (`player()`, etc.), and their backing members are conditionally compiled based on `SENDSPIN_ENABLE_*` flags. When a role is disabled at build time, calling `add_player()` or `client.player()` is a compile error, not a runtime nullptr. See [Compile-Time Role Selection](#compile-time-role-selection) below.

## Updating Player State

Report local state changes back to the server:

```cpp
player.update_volume(75);
player.update_muted(false);
player.update_static_delay(50);  // User-adjustable delay in ms

// Enable/disable static delay adjustment by the server. When disabled, the stored delay
// is not applied to sync timing and is reported as 0 in client state.
player.set_static_delay_adjustable(true);
```

## Updating Client State

Report the client's overall state to the server. Use this when your device switches to an external audio source or encounters an error:

```cpp
client.update_state(SendspinClientState::EXTERNAL_SOURCE);  // Playing from another source
client.update_state(SendspinClientState::ERROR);             // Error condition
client.update_state(SendspinClientState::SYNCHRONIZED);      // Back to normal
```

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
uint16_t delay = player.get_static_delay_ms();
int32_t fixed = player.get_fixed_delay_us();
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

Most listener callbacks fire on the main loop thread (the thread calling `client.loop()`). The exceptions are:

| Callback | Thread |
|---|---|
| `PlayerRoleListener::on_audio_write()` | Sync task background thread |
| `ArtworkRoleListener::on_image_decode()` | Dedicated artwork decode thread |
| `ArtworkRoleListener::on_image_display()` | Main loop thread |
| `VisualizerRoleListener` data callbacks (`on_loudness()`, `on_beat()`, `on_f_peak()`, `on_spectrum()`, `on_peak()`) | Dedicated visualizer drain thread |
| All other listener methods | Main loop thread |

`PlayerRole::notify_audio_played()` is thread-safe and is designed to be called from an audio output callback thread.

`ArtworkRole::frame_done()` must be called from the main loop thread (typically from inside `on_image_display()`/`on_image_clear()` or when a cross-fade animation completes).

`SendspinPersistenceProvider` calls are on the main loop thread for every key except
`persistence_keys::RECORDS`, whose `save_blob()` is also called on the network thread when a
pairing finalizes (see the `SendspinPersistenceProvider` section above).

## Minimal Example

A minimal integration that receives and discards audio:

```cpp
#include "sendspin/client.h"
#include "sendspin/player_role.h"

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

    client.start_server();

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
# Disable the player role (excludes decoder, sync task, audio ring buffer)
cmake -B build -DSENDSPIN_ENABLE_PLAYER=OFF

# Disable all optional roles, keep only the player
cmake -B build -DSENDSPIN_ENABLE_CONTROLLER=OFF \
               -DSENDSPIN_ENABLE_METADATA=OFF \
               -DSENDSPIN_ENABLE_ARTWORK=OFF \
               -DSENDSPIN_ENABLE_VISUALIZER=OFF \
               -DSENDSPIN_ENABLE_COLOR=OFF
```

Available options (all `ON` by default):

| Option | Controls |
|---|---|
| `SENDSPIN_ENABLE_PLAYER` | Player role, audio decoders (micro-flac, micro-opus), sync task |
| `SENDSPIN_ENABLE_CONTROLLER` | Controller role |
| `SENDSPIN_ENABLE_METADATA` | Metadata role |
| `SENDSPIN_ENABLE_ARTWORK` | Artwork role |
| `SENDSPIN_ENABLE_VISUALIZER` | Visualizer role |
| `SENDSPIN_ENABLE_COLOR` | Color role |

When `SENDSPIN_ENABLE_PLAYER` is `OFF`, the micro-flac and micro-opus dependencies are not fetched.

### ESP-IDF (Kconfig)

Role flags are exposed via Kconfig under `Component config → sendspin-cpp`:

```kconfig
CONFIG_SENDSPIN_ENABLE_PLAYER=y
CONFIG_SENDSPIN_ENABLE_CONTROLLER=y
CONFIG_SENDSPIN_ENABLE_METADATA=y
CONFIG_SENDSPIN_ENABLE_ARTWORK=y
CONFIG_SENDSPIN_ENABLE_VISUALIZER=y
CONFIG_SENDSPIN_ENABLE_COLOR=y
```

### Effect on the API

When a role is disabled, its `add_*()` method, accessor method, and backing member are removed from `client.h` via `#ifdef` guards. Attempting to call `client.add_player()` when `SENDSPIN_ENABLE_PLAYER` is `OFF` produces a compile error. The corresponding role header can still be included (it defines protocol types and the listener interface), but the role class cannot be instantiated.

---

## Configuration Reference

### SendspinClientConfig

Main client configuration passed to the `SendspinClient` constructor.

`client_id` is not a field in `SendspinClientConfig`. It is derived from the static
X25519 keypair and read back via `client.client_id()` after `start_server()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `std::string` | — | Friendly display name shown in the Sendspin UI |
| `cipher_suite` | `NoiseCipherSuitePreference` | `CHACHAPOLY` | Preferred Noise cipher suite advertised to the server. `CHACHAPOLY` (default) is lower CPU on bare-metal; `AESGCM` is host-only (see the enum reference below). Both suites are always supported; the server selects the actual cipher used. |
| `product_name` | `std::optional<std::string>` | unset | Device product name; sent in `client/hello` only when set |
| `manufacturer` | `std::optional<std::string>` | unset | Manufacturer name (e.g., `"ESPHome"`); sent in `client/hello` only when set |
| `software_version` | `std::optional<std::string>` | unset | Software version string; sent in `client/hello` only when set |
| `mac_address` | `std::optional<std::string>` | auto-detected | MAC address of the network interface, lowercase colon-separated (e.g., `"aa:bb:cc:dd:ee:ff"`), sent in `client/hello`. Left unset, the library auto-detects it. ESP-IDF uses the default network interface (Wi-Fi or Ethernet). Host uses a best-effort from the active routable interface. Set explicitly to override (recommended on multi-homed hosts). |
| `pin_display_supported` | `bool` | `false` | Set to `true` when the application implements `on_display_pairing_pin` / `on_clear_pairing_pin` on its `SendspinClientListener`. When `false`, dynamic-PIN pairing is not advertised even if enabled in `SendspinPairingConfig`. |
| `pairing_window_supported` | `bool` | `false` | Set to `true` when the application implements `on_open_pairing_window` / `on_close_pairing_window` on its `SendspinClientListener`. When `false`, static-PIN pairing is not advertised even if a static PIN is configured. Dynamic-PIN devices should also set it: escalated or short-PIN dynamic attempts are gesture-gated through the same callbacks, and without them such an attempt can only proceed via `management/open-pairing-window` (or stalls until the server cancels it). |
| `httpd_psram_stack` | `bool` | `false` | Allocate HTTP server task stack in PSRAM (ESP-IDF only) |
| `httpd_priority` | `unsigned` | `5` | FreeRTOS priority for the HTTP server task (ESP-IDF only) |
| `httpd_stack_size` | `size_t` | `8192` | HTTP server task stack size in bytes (ESP-IDF only). The Noise handshake (and especially the in-band re-handshake after pairing) runs its X25519 crypto on this task; values below the default are clamped up to it with a warning, since a smaller stack overflows during the post-pairing re-handshake. Raising it is allowed. |
| `websocket_priority` | `unsigned` | `5` | FreeRTOS priority for the WebSocket client task (ESP-IDF only) |
| `server_port` | `uint16_t` | `8928` | WebSocket server port |
| `server_max_connections` | `uint8_t` | `4` | Maximum simultaneous WebSocket connections (one established, two unproven, and one spare so a surplus peer can be rejected with a goodbye) |
| `httpd_ctrl_port` | `uint16_t` | `0` | ESP-IDF httpd control port; `0` uses `ESP_HTTPD_DEF_CTRL_PORT + 1` to avoid conflict with the web_server component |
| `time_burst_size` | `uint8_t` | `8` | Number of messages per time sync burst |
| `time_burst_interval_ms` | `int64_t` | `10000` | Milliseconds between time sync bursts |
| `time_burst_response_timeout_ms` | `int64_t` | `10000` | Milliseconds before a burst message times out |
| `websocket_payload_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Memory placement for the per-connection WebSocket payload reassembly buffer (sized to the largest incoming frame, holds raw audio chunks delivered by httpd). `PREFER_EXTERNAL` tries SPIRAM first and falls back to internal RAM; `PREFER_INTERNAL` does the reverse. Use `PREFER_INTERNAL` on devices with slow PSRAM (e.g., plain ESP32) to avoid stuttering. ESP-IDF only; ignored on host. |
| `noise_buffer_location` | `MemoryLocation` | `PREFER_EXTERNAL` | Memory placement for the Noise transport's fragment reassembly buffer and the ~64 KB fragmentation frame buffer. The reassembly buffer grows with the largest fragmented message received (e.g. album artwork) and retains its capacity for the life of the connection, so keeping it in SPIRAM protects internal RAM. Independent of `websocket_payload_location` (which covers the raw WebSocket frame buffer). ESP-IDF only; ignored on host. |
| `json_arena_size` | `size_t` | `2048` | Size in bytes of a fixed internal-RAM scratch buffer used to parse incoming JSON protocol messages, instead of the default PSRAM. Costs this many bytes of internal RAM permanently but removes PSRAM traffic from the network task on every message. Messages too large for the budget fall back to PSRAM; the default covers steady-state traffic (including the FLAC stream-start header), while large track-metadata messages may spill over (but those arrive only once per song). Set to `0` to disable and keep PSRAM-only behaviour. On host there is no PSRAM distinction, so the arena is just a fixed scratch buffer for the parse (still used, harmless). |

---

### PlayerRoleConfig

Configuration passed to `client.add_player()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `audio_formats` | `std::vector<AudioSupportedFormatObject>` | `{}` | Audio formats the player supports; advertised to the server during the hello handshake. The server selects one when establishing a stream. |
| `audio_buffer_capacity` | `size_t` | `1000000` | Internal ring buffer size in bytes. Larger buffers absorb more jitter at the cost of memory. |
| `fixed_delay_us` | `int32_t` | `0` | Fixed platform-level delay offset in microseconds (e.g., a known I2S pipeline delay). Applied on top of the user-adjustable static delay. |
| `initial_static_delay_ms` | `uint16_t` | `0` | Initial value for the user-adjustable static delay in milliseconds. Overridden by the persisted value if a `SendspinPersistenceProvider` is set. |
| `extra_startup_silence_ms` | `uint16_t` | `50` | Extra silence inserted at stream start, after the first playback notification and before the first decoded chunk reaches the sink. Added on top of the initial-sync priming silence to give the decode pipeline more slack to stay ahead of the sink, preventing the initial-playback stutter caused by the decoder briefly falling behind. Larger values trade a longer startup delay for more underflow protection; set to `0` to disable. |
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
| `format` | `SendspinImageFormat` | Image format (`JPEG`, `PNG`, or `BMP`) |
| `width` | `uint16_t` | Desired image width in pixels |
| `height` | `uint16_t` | Desired image height in pixels |
| `require_frame_done` | `bool` | Opt-in back-pressure gate (default `false`). When set, the role delivers at most one un-acked frame or clear at a time for this slot; the consumer must call `ArtworkRole::frame_done(slot)` to release the gate. See [ArtworkRoleListener](#artworkrolelistener). |
| `display_offset_ms` | `int32_t` | Shifts the display deadline (default `0`). Positive fires `on_image_display()` earlier (mirroring `PlayerRoleConfig::fixed_delay_us`), negative delays it; lets a cross-fade straddle the track boundary. |

---

### VisualizerRoleConfig

Configuration passed to `client.add_visualizer()`.

| Field | Type | Default | Description |
|---|---|--|---|
| `support` | `VisualizerSupportObject` | - | Visualizer capabilities advertised to the server during the hello handshake |
| `psram_stack` | `bool` | `false` | Allocate drain thread stack in PSRAM (ESP-IDF only) |
| `priority` | `unsigned` | `2` | FreeRTOS priority for the drain thread (ESP-IDF only) |

`VisualizerSupportObject` fields:

| Field | Type | Description |
|---|---|---|
| `types` | `std::vector<VisualizerDataType>` | Data stream types to receive (`BEAT`, `LOUDNESS`, `F_PEAK`, `SPECTRUM`, `PEAK`) |
| `buffer_capacity` | `size_t` | Total RAM budget in bytes for the internal ring buffer. Per-entry overhead means only ~1/3 holds wire data; the client advertises that effective capacity to the server |
| `rate_max` | `uint16_t` | Maximum periodic frames per second; set to the display refresh rate |
| `spectrum` | `std::optional<VisualizerSpectrumConfig>` | Spectrum analysis parameters; required when `SPECTRUM` is in `types` |

`VisualizerSpectrumConfig` fields:

| Field | Type | Description |
|---|---|---|
| `n_disp_bins` | `uint8_t` | Number of frequency bins to receive |
| `scale` | `VisualizerSpectrumScale` | Frequency scale (`MEL`, `LOG`, or `LIN`) |
| `f_min` | `uint16_t` | Minimum frequency in Hz |
| `f_max` | `uint16_t` | Maximum frequency in Hz |

---

## Enums Reference

### NoiseCipherSuitePreference

| Value | Description |
|---|---|
| `CHACHAPOLY` | Prefer Noise_KKpsk2_25519_ChaChaPoly_SHA256 (default; lower CPU on bare-metal) |
| `AESGCM` | Prefer Noise_KKpsk2_25519_AESGCM_SHA256 (host only; on ESP-IDF the library ignores this preference and falls back to ChaChaPoly, since ESP-IDF's libsodium AES-GCM backend is a stub) |

Set in `SendspinClientConfig::cipher_suite`. The server selects the actual cipher; this is a preference only.

### ConnectionTrust

| Value | Description |
|---|---|
| `NONE` | Sentinel or Pairing PSK was used; this server has not been paired |
| `USER` | Long-term pairing record matched; this server is paired |

Reported via `SendspinClientListener::on_trust_changed` once per admitted connection.

### SendspinPairAbortReason

| Value | Description |
|---|---|
| `ATTEMPT_TIMEOUT` | Pairing timed out waiting for the next step |
| `CONCURRENT_ATTEMPT` | The server rejected pairing because another pairing is in progress |
| `METHOD_NOT_SUPPORTED` | The proposed pairing method is not supported by the client |
| `PIN_LENGTH_UNACCEPTABLE` | The PIN length requirement is out of the accepted range |
| `PIN_MISMATCH` | The PIN entered does not match |
| `USER_CANCELLED` | The pairing was cancelled by the user (on the server side) |
| `STORAGE_FAILED` | This device could not persist the pairing record (client-local; the wire carries `user_cancelled`) |
| `UNKNOWN` | Unrecognized abort reason from the server |

Delivered via `SendspinClientListener::on_pairing_failed`.

### SendspinCodecFormat

| Value | Description |
|---|---|
| `FLAC` | FLAC lossless audio |
| `OPUS` | Opus lossy audio |
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
| `SET_STATIC_DELAY` | Static delay adjustment from the server |

These represent commands the server can send to the player. The player advertises which commands it supports. Enable `SET_STATIC_DELAY` with `player.set_static_delay_adjustable(true)`.

### SendspinClientState

| Value | Description |
|---|---|
| `SYNCHRONIZED` | Normal synchronized state |
| `ERROR` | Error state |
| `EXTERNAL_SOURCE` | Playing from an external source |

### SendspinGoodbyeReason

| Value | Description |
|---|---|
| `ANOTHER_SERVER` | Disconnecting to connect to another server |
| `SHUTDOWN` | Device is shutting down |
| `RESTART` | Device is restarting |
| `USER_REQUEST` | User requested disconnect |

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
| `BMP` | BMP image |

### SendspinImageSource

| Value | Description |
|---|---|
| `ALBUM` | Album artwork |
| `ARTIST` | Artist image |
| `NONE` | No image source |

### VisualizerDataType

| Value | Description |
|---|---|
| `BEAT` | Beat detection events |
| `LOUDNESS` | Loudness level |
| `F_PEAK` | Peak frequency |
| `SPECTRUM` | Frequency spectrum bins |

### VisualizerSpectrumScale

| Value | Description |
|---|---|
| `MEL` | Mel scale (perceptual) |
| `LOG` | Logarithmic scale |
| `LIN` | Linear scale |

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

Used by `SendspinClientConfig::websocket_payload_location` to control where the per-connection WebSocket payload reassembly buffer is allocated, by `SendspinClientConfig::noise_buffer_location` to control where the Noise transport's fragment reassembly and fragmentation buffers are allocated, and by `PlayerRoleConfig::decode_buffer_location` to control where the player's decode transfer buffer is allocated. Ignored on host platforms (no internal/external distinction).
