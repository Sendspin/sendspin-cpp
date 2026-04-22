# Integration Guide

This guide describes what you need to implement in order to integrate sendspin-cpp into your application. The library provides the Sendspin protocol, audio decoding, and time synchronization. You provide the audio output, network readiness, and optional persistence.

## Overview

Integration follows this pattern:

1. Create a `SendspinClient` with a configuration struct
2. Add roles (player, controller, metadata, artwork, visualizer) depending on what your application needs
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
```

Only include the role headers you need. `client.h` includes `sendspin/config.h` (all configuration structs, including `SendspinClientConfig`) and `sendspin/types.h` transitively.

## Step 1: Configure and Create the Client

```cpp
using namespace sendspin;

// Optional: set log level before creating the client (host builds only, no-op on ESP-IDF)
SendspinClient::set_log_level(LogLevel::INFO);

SendspinClientConfig config;
config.client_id = "my-device-mac-addr";       // Unique identifier (e.g., MAC address)
config.name = "Living Room Speaker";            // Friendly display name
config.product_name = "My Speaker";             // Device product name
config.manufacturer = "My Company";             // Manufacturer name
config.software_version = "1.0.0";              // Software version string

SendspinClient client(std::move(config));
```

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

Lets your application send transport commands (play, pause, next, etc.) and receive the server's controller state (volume, mute, supported commands).

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
    {0, SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 300, 300},
};

auto& artwork = client.add_artwork(std::move(artwork_config));
```

### Visualizer Role (Audio Visualization)

Receives real-time beat, loudness, peak frequency, and spectrum data synchronized to playback.

```cpp
VisualizerSupportObject vis_support;
vis_support.types = {
    VisualizerDataType::BEAT,
    VisualizerDataType::LOUDNESS,
    VisualizerDataType::F_PEAK,
    VisualizerDataType::SPECTRUM,
};
vis_support.buffer_capacity = 8192;
vis_support.batch_max = 4;
vis_support.spectrum = VisualizerSpectrumConfig{
    .n_disp_bins = 32,
    .scale = VisualizerSpectrumScale::MEL,
    .f_min = 40,
    .f_max = 16000,
    .rate_max = 30,
};

auto& visualizer = client.add_visualizer({.support = vis_support});
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

    // Optional: Called when the audio stream is cleared (e.g., track skip).
    void on_stream_clear() override {
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
        if (md.title) display_title(*md.title);
        if (md.artist) display_artist(*md.artist);
        if (md.album) display_album(*md.album);
        if (md.progress) {
            update_progress_bar(md.progress->track_progress, md.progress->track_duration);
        }
        if (md.repeat) update_repeat_icon(*md.repeat);
        if (md.shuffle) update_shuffle_icon(*md.shuffle);
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
| `repeat` | `std::optional<SendspinRepeatMode>` | Repeat mode |
| `shuffle` | `std::optional<bool>` | Shuffle state |

`MetadataProgressObject` contains `track_progress` (ms), `track_duration` (ms), and `playback_speed`.

You can also poll track progress at any time:

```cpp
uint32_t progress_ms = metadata.get_track_progress_ms();  // Interpolated
uint32_t duration_ms = metadata.get_track_duration_ms();   // 0 = unknown/live
```

### ControllerRoleListener

```cpp
struct MyControllerListener : ControllerRoleListener {
    void on_controller_state(const ServerStateControllerObject& state) override {
        // Update UI with server-side volume and mute state
        update_volume_slider(state.volume);
        update_mute_button(state.muted);
        // Enable/disable buttons based on supported commands
        enable_buttons(state.supported_commands);
    }
};
```

### ArtworkRoleListener

The artwork role uses a dedicated decode thread for the CPU-bound decode step and the main loop for scheduled display. `on_image_decode()` fires on the decode thread immediately when encoded image data arrives; once decode returns, the server display timestamp is handed off to the main loop, which fires `on_image_display()` once the timestamp is reached. If a newer frame for the same slot finishes decoding before its predecessor's display fires, only the newer one is delivered. Lifecycle callbacks also fire on the main loop thread.

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
    // Swap the decoded image onto the display.
    void on_image_display(uint8_t slot) override {
        display.show_image(slot, decoded_images[slot]);
    }

    // Called from the main loop thread when artwork should be cleared.
    void on_image_clear(uint8_t slot) override {
        display.clear_slot(slot);
    }
};
```

### VisualizerRoleListener

```cpp
struct MyVisualizerListener : VisualizerRoleListener {
    // THREAD SAFETY: Called from a dedicated drain thread. Copy data quickly
    // and defer heavy processing.
    void on_visualizer_frame(const VisualizerFrame& frame) override {
        if (frame.loudness) update_vu_meter(*frame.loudness);
        if (frame.peak_freq) update_peak_display(*frame.peak_freq);
        if (!frame.spectrum.empty()) update_spectrum_bars(frame.spectrum);
    }

    // Called from the drain thread on beat events.
    void on_beat(int64_t client_timestamp) override {
        trigger_beat_animation();
    }

    // Called from the main loop thread.
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& stream) override { }
    void on_visualizer_stream_end() override { }
    void on_visualizer_stream_clear() override { }
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

### SendspinPersistenceProvider (Optional)

Allows the library to persist and restore state across reboots. Useful on embedded devices.

```cpp
struct MyPersistenceProvider : SendspinPersistenceProvider {
    // Save/load the hash of the last server that was playing audio.
    // Used to prioritize reconnection to the same server.
    bool save_last_server_hash(uint32_t hash) override {
        return nvs_write("last_server", hash);
    }
    std::optional<uint32_t> load_last_server_hash() override {
        uint32_t hash;
        if (nvs_read("last_server", &hash)) return hash;
        return std::nullopt;
    }

    // Save/load the player's user-adjustable static delay.
    bool save_static_delay(uint16_t delay_ms) override {
        return nvs_write("static_delay", delay_ms);
    }
    std::optional<uint16_t> load_static_delay() override {
        uint16_t delay;
        if (nvs_read("static_delay", &delay)) return delay;
        return std::nullopt;
    }
};
```

### SendspinClientListener (Optional)

Receives client-level events.

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

## Sending Commands

If you added the controller role, use it to send playback commands:

```cpp
controller.send_command(SendspinControllerCommand::PLAY);
controller.send_command(SendspinControllerCommand::PAUSE);
controller.send_command(SendspinControllerCommand::NEXT);
controller.send_command(SendspinControllerCommand::PREVIOUS);
controller.send_command(SendspinControllerCommand::STOP);
controller.send_command(SendspinControllerCommand::SHUFFLE);
controller.send_command(SendspinControllerCommand::UNSHUFFLE);
controller.send_command(SendspinControllerCommand::REPEAT_OFF);
controller.send_command(SendspinControllerCommand::REPEAT_ONE);
controller.send_command(SendspinControllerCommand::REPEAT_ALL);

// Volume and mute take additional arguments
controller.send_command(SendspinControllerCommand::VOLUME, 75);       // Volume 0-100
controller.send_command(SendspinControllerCommand::MUTE, {}, true);   // Mute on
controller.send_command(SendspinControllerCommand::MUTE, {}, false);  // Mute off
```

## Accessing Roles

In addition to the references returned by `add_*()`, you can access roles at any time through the client's accessor methods. These return `nullptr` if the role was not added.

```cpp
if (auto* p = client.player()) {
    p->update_volume(75);
}
if (auto* c = client.controller()) {
    c->send_command(SendspinControllerCommand::NEXT);
}
if (auto* m = client.metadata()) {
    uint32_t progress = m->get_track_progress_ms();
}
if (auto* a = client.artwork()) { /* ... */ }
if (auto* v = client.visualizer()) { /* ... */ }
```

Use these accessors when the role reference from `add_*()` is out of scope.

> **Note:** Role registration methods (`add_player()`, etc.), accessor methods (`player()`, etc.), and their backing members are conditionally compiled based on `SENDSPIN_ENABLE_*` flags. When a role is disabled at build time, calling `add_player()` or `client.player()` is a compile error, not a runtime nullptr. See [Compile-Time Role Selection](#compile-time-role-selection) below.

## Updating Player State

Report local state changes back to the server:

```cpp
player.update_volume(75);
player.update_muted(false);
player.update_static_delay(50);  // User-adjustable delay in ms

// Enable/disable static delay adjustment by the server
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
auto& ctrl = controller.get_controller_state();  // volume, muted, supported_commands

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
| `VisualizerRoleListener::on_visualizer_frame()` | Dedicated visualizer drain thread |
| `VisualizerRoleListener::on_beat()` | Dedicated visualizer drain thread |
| All other listener methods | Main loop thread |

`PlayerRole::notify_audio_played()` is thread-safe and is designed to be called from an audio output callback thread.

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
    config.client_id = "minimal-example";
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
               -DSENDSPIN_ENABLE_VISUALIZER=OFF
```

Available options (all `ON` by default):

| Option | Controls |
|---|---|
| `SENDSPIN_ENABLE_PLAYER` | Player role, audio decoders (micro-flac, micro-opus), sync task |
| `SENDSPIN_ENABLE_CONTROLLER` | Controller role |
| `SENDSPIN_ENABLE_METADATA` | Metadata role |
| `SENDSPIN_ENABLE_ARTWORK` | Artwork role |
| `SENDSPIN_ENABLE_VISUALIZER` | Visualizer role |

When `SENDSPIN_ENABLE_PLAYER` is `OFF`, the micro-flac and micro-opus dependencies are not fetched.

### ESP-IDF (Kconfig)

Role flags are exposed via Kconfig under `Component config → sendspin-cpp`:

```kconfig
CONFIG_SENDSPIN_ENABLE_PLAYER=y
CONFIG_SENDSPIN_ENABLE_CONTROLLER=y
CONFIG_SENDSPIN_ENABLE_METADATA=y
CONFIG_SENDSPIN_ENABLE_ARTWORK=y
CONFIG_SENDSPIN_ENABLE_VISUALIZER=y
```

### Effect on the API

When a role is disabled, its `add_*()` method, accessor method, and backing member are removed from `client.h` via `#ifdef` guards. Attempting to call `client.add_player()` when `SENDSPIN_ENABLE_PLAYER` is `OFF` produces a compile error. The corresponding role header can still be included (it defines protocol types and the listener interface), but the role class cannot be instantiated.

---

## Configuration Reference

### SendspinClientConfig

Main client configuration passed to the `SendspinClient` constructor.

| Field | Type | Default | Description |
|---|---|---|---|
| `client_id` | `std::string` | — | Unique client identifier (e.g., MAC address) |
| `name` | `std::string` | — | Friendly display name shown in the Sendspin UI |
| `product_name` | `std::string` | — | Device product name |
| `manufacturer` | `std::string` | — | Manufacturer name (e.g., `"ESPHome"`) |
| `software_version` | `std::string` | — | Software version string |
| `httpd_psram_stack` | `bool` | `false` | Allocate HTTP server task stack in PSRAM (ESP-IDF only) |
| `httpd_priority` | `unsigned` | `17` | FreeRTOS priority for the HTTP server task (ESP-IDF only) |
| `websocket_priority` | `unsigned` | `5` | FreeRTOS priority for the WebSocket client task (ESP-IDF only) |
| `server_max_connections` | `uint8_t` | `2` | Maximum simultaneous WebSocket connections (default supports the handoff protocol) |
| `httpd_ctrl_port` | `uint16_t` | `0` | ESP-IDF httpd control port; `0` uses `ESP_HTTPD_DEF_CTRL_PORT + 1` to avoid conflict with the web_server component |
| `time_burst_size` | `uint8_t` | `8` | Number of messages per time sync burst |
| `time_burst_interval_ms` | `int64_t` | `10000` | Milliseconds between time sync bursts |
| `time_burst_response_timeout_ms` | `int64_t` | `10000` | Milliseconds before a burst message times out |

---

### PlayerRoleConfig

Configuration passed to `client.add_player()`.

| Field | Type | Default | Description |
|---|---|---|---|
| `audio_formats` | `std::vector<AudioSupportedFormatObject>` | `{}` | Audio formats the player supports; advertised to the server during the hello handshake. The server selects one when establishing a stream. |
| `audio_buffer_capacity` | `size_t` | `1000000` | Internal ring buffer size in bytes. Larger buffers absorb more jitter at the cost of memory. |
| `fixed_delay_us` | `int32_t` | `0` | Fixed platform-level delay offset in microseconds (e.g., a known I2S pipeline delay). Applied on top of the user-adjustable static delay. |
| `initial_static_delay_ms` | `uint16_t` | `0` | Initial value for the user-adjustable static delay in milliseconds. Overridden by the persisted value if a `SendspinPersistenceProvider` is set. |
| `psram_stack` | `bool` | `false` | Allocate sync/decode task stack in PSRAM (ESP-IDF only) |
| `priority` | `unsigned` | `2` | FreeRTOS priority for the sync/decode task (ESP-IDF only) |

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
| `preferred_formats` | `std::vector<ImageSlotPreference>` | `{}` | Image slot preferences advertised to the server during the hello handshake. Each entry declares a slot index, image source, format, and resolution. |
| `psram_stack` | `bool` | `false` | Allocate decode thread stack in PSRAM (ESP-IDF only) |
| `priority` | `unsigned` | `2` | FreeRTOS priority for the decode thread (ESP-IDF only) |

Each entry in `preferred_formats` is an `ImageSlotPreference`:

| Field | Type | Description |
|---|---|---|
| `slot` | `uint8_t` | Artwork slot index (0–3) |
| `source` | `SendspinImageSource` | Image source (`ALBUM` or `ARTIST`) |
| `format` | `SendspinImageFormat` | Image format (`JPEG`, `PNG`, or `BMP`) |
| `width` | `uint16_t` | Desired image width in pixels |
| `height` | `uint16_t` | Desired image height in pixels |

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
| `types` | `std::vector<VisualizerDataType>` | Data stream types to receive (`BEAT`, `LOUDNESS`, `F_PEAK`, `SPECTRUM`) |
| `buffer_capacity` | `size_t` | Internal buffer size for incoming visualizer frames |
| `batch_max` | `uint8_t` | Maximum number of frames to process per drain cycle |
| `spectrum` | `std::optional<VisualizerSpectrumConfig>` | Spectrum analysis parameters; required when `SPECTRUM` is in `types` |

`VisualizerSpectrumConfig` fields:

| Field | Type | Description |
|---|---|---|
| `n_disp_bins` | `uint8_t` | Number of frequency bins to receive |
| `scale` | `VisualizerSpectrumScale` | Frequency scale (`MEL`, `LOG`, or `LIN`) |
| `f_min` | `uint16_t` | Minimum frequency in Hz |
| `f_max` | `uint16_t` | Maximum frequency in Hz |
| `rate_max` | `uint16_t` | Maximum spectrum update rate in Hz |

---

## Enums Reference

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
| `VOLUME` | Set volume (pass value via volume parameter) |
| `MUTE` | Set mute state (pass value via mute parameter) |
| `REPEAT_OFF` | Disable repeat |
| `REPEAT_ONE` | Repeat current track |
| `REPEAT_ALL` | Repeat all tracks |
| `SHUFFLE` | Enable shuffle |
| `UNSHUFFLE` | Disable shuffle |
| `SWITCH` | Switch source |

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
