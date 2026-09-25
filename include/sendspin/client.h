// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file client.h
/// @brief Main public API for the Sendspin synchronized audio streaming client

#pragma once

#include "sendspin/config.h"
#include "sendspin/types.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// Forward declarations for enabled roles
#ifdef SENDSPIN_ENABLE_ARTWORK
class ArtworkRole;
#endif
#ifdef SENDSPIN_ENABLE_COLOR
class ColorRole;
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
class ControllerRole;
#endif
#ifdef SENDSPIN_ENABLE_METADATA
class MetadataRole;
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
class PlayerRole;
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
class VisualizerRole;
#endif

// Forward declarations for listener types
struct GroupUpdateObject;

/// @brief Listener for SendspinClient events
/// All methods fire on the main loop thread
class SendspinClientListener {
public:
    virtual ~SendspinClientListener() = default;

    /// @brief Called when the group state is updated by the server
    virtual void on_group_update(const GroupUpdateObject& /*group*/) {}

    /// @brief Called after a time sync burst completes with the Kalman filter error
    virtual void on_time_sync_updated(float /*error*/) {}

    /// @brief Called when the library needs high-performance networking (e.g., disable WiFi
    /// power saving)
    ///
    /// Toggle the platform's networking mode and return; the body must not call any
    /// SendspinClient or role method.
    virtual void on_request_high_performance() {}

    /// @brief Called when the library no longer needs high-performance networking
    ///
    /// Same contract as on_request_high_performance(). Also fires from ~SendspinClient() for a
    /// hold still outstanding.
    virtual void on_release_high_performance() {}

    // ========================================
    // Encryption / pairing callbacks
    // ========================================

    /// @brief Called when a server begins a pairing exchange
    ///
    /// server_id is the base64url public key of the server entering pairing. Fires once per
    /// attempt whatever the method; the exchange ends at on_pairing_succeeded or
    /// on_pairing_failed.
    virtual void on_pairing_started(const std::string& /*server_id*/) {}

    /// @brief Called when a pairing exchange completes and a long-term record is stored
    ///
    /// server_id is the base64url public key of the newly paired server. After this
    /// callback the server re-handshakes on the new long-term PSK. Subsequent connections from
    /// this server will report ConnectionTrust::USER.
    virtual void on_pairing_succeeded(const std::string& /*server_id*/) {}

    /// @brief Called when a pairing exchange is aborted (by the server or by the protocol)
    ///
    /// The connection usually stays open after this callback, so the server can re-activate
    /// pairing or resume normal operation on it (pairing.md "pair/abort"). It is closed for
    /// CONCURRENT_ATTEMPT, and closed without any further message for the UNKNOWN reported on a
    /// pairing protocol error (a malformed or out-of-sequence pairing message).
    virtual void on_pairing_failed(const std::string& /*server_id*/,
                                   SendspinPairAbortReason /*reason*/) {}

    /// @brief Called when the active connection's trust level is known after handshake
    ///
    /// Fires on the initial handshake and after each successful re-handshake (for example, after
    /// pairing). trust reflects the PSK category matched during the Noise handshake:
    ///   ConnectionTrust::USER:  long-term record (paired server)
    ///   ConnectionTrust::NONE:  Sentinel or Pairing PSK (unpaired access)
    virtual void on_trust_changed(ConnectionTrust /*trust*/) {}

    /// @brief Called when a dynamic pairing code should be emitted to the operator.
    ///
    /// `code` carries the code in the format the server selected, and `format` names it:
    ///   DIGITS:  the six contiguous decimal digits (e.g. "042735"). pairing.md "Pairing Code
    ///            Presentation" asks for a `3-3` grouping when the code is shown or spoken; the
    ///            separator is the application's to add.
    ///   QR_CODE: the version-1 pairing token (e.g. "SP:14DQ..."), to be rendered verbatim as a
    ///            QR code with no URI scheme or wrapper around it.
    /// Fires at most once per pairing attempt: the code is unchanged across the attempt's rounds,
    /// and is always followed by on_clear_pairing_code.
    /// Only called when SendspinClientConfig::pairing_code_out_channels and
    /// ::pairing_code_formats are both non-empty.
    virtual void on_display_pairing_code(const std::string& /*code*/,
                                         SendspinPairingCodeFormat /*format*/) {}

    /// @brief Called to withdraw the emitted dynamic pairing code.
    ///
    /// Fires after every pairing attempt that triggered on_display_pairing_code, whatever its
    /// outcome.
    virtual void on_clear_pairing_code() {}

    /// @brief Called when the operator must perform the device pairing-window gesture to allow a
    /// gesture-gated pairing attempt (pairing.md "Pairing Window"): every static_pairing_code
    /// attempt, and a dynamic_pairing_code attempt held back by the round limit.
    ///
    /// Only called when SendspinClientConfig::pairing_window_supported is true; a device
    /// offering dynamic_pairing_code should therefore also implement this
    /// gesture UI, or such an attempt stalls until the server cancels it.
    /// Always followed by on_close_pairing_window when the attempt concludes. The application
    /// confirms the gesture by calling SendspinClient::confirm_pairing_window().
    virtual void on_open_pairing_window() {}

    /// @brief Called to dismiss the pairing-window prompt after every attempt that triggered
    /// on_open_pairing_window, regardless of outcome.
    virtual void on_close_pairing_window() {}
};

/// @brief Platform hook for network readiness
/// Must be set before start()
class SendspinNetworkProvider {
public:
    virtual ~SendspinNetworkProvider() = default;

    /// @brief Returns true if the network (WiFi/Ethernet) is ready for connections
    virtual bool is_network_ready() = 0;
};

/// @brief Optional persistence provider for saving/loading client state as opaque byte blobs.
///
/// The platform (e.g., ESPHome) provides a concrete implementation that stores blobs keyed by
/// the fixed key constants in `persistence_keys` below, backed by NVS/Preferences (ESP) or a
/// file (host). The library owns all serialization; see `persistence_keys` for which keys hold
/// raw bytes and which hold a codec blob (`sendspin/persistence_codec.h`); a provider is a pure
/// byte store and must not parse the codec blobs.
///
/// Every method has a default no-op / nullopt implementation so a platform can opt in
/// incrementally.
///
/// Threading: every method is invoked on the main loop thread, for every key, so a provider needs
/// no locking of its own. First-boot provisioning writes from inside `start()` rather than in
/// response to a runtime event: `KEYPAIR`, `PAIRING_PSK`, and `PAIR_CONFIG` when none is stored.
///
/// Re-entrancy: implementations must not call back into the library from inside
/// load_blob/save_blob/erase_blob. Every call is made from the middle of a library step that is
/// part-way through updating the state the call is about. No internal lock is held across the
/// call.
///
/// Blocking: perform one bounded storage operation and return. The main loop is stopped for the
/// duration, so audio scheduling, time sync and role callbacks wait with it. Report a failed
/// write by returning false rather than retrying inline.
class SendspinPersistenceProvider {
public:
    virtual ~SendspinPersistenceProvider() = default;

    /// @brief Load the blob stored under key.
    /// @return The bytes, or nullopt if absent.
    virtual std::optional<std::vector<uint8_t>> load_blob(const std::string& /*key*/) {
        return std::nullopt;
    }

    /// @brief Persist bytes under key. Returning true means durably stored (the library gates
    /// revocation durability on it for a cleared record slot). A zero-length write is a real
    /// write: it is how a record slot is emptied, and the key must read back as an empty blob
    /// afterwards.
    ///
    /// A rejected write is reported, not retried: the in-memory state stays authoritative for
    /// this boot and the library logs what will be lost at the next reboot. What a rejection
    /// costs decides the level: a write that changes which records the next boot holds warns;
    /// one the next boot rebuilds by itself (the recency order in `RECORD_ORDER`, a record's
    /// `"used"` flag) reports at debug. The case that matters is a rejected write of the empty
    /// blob that clears a revoked record's slot: the store still holds the old record and hands
    /// it back at the next boot, silently making the revoked PSK valid again (the record is dropped
    /// from RAM either way). A provider that queues writes should return true and surface its own
    /// failures.
    /// @return true on success, false on failure.
    virtual bool save_blob(const std::string& /*key*/, const uint8_t* /*data*/, size_t /*len*/) {
        return false;
    }

    /// @brief Remove key. Absent counts as success. A false return means the value may
    /// survive a reboot.
    ///
    /// The library never calls it: every blob it owns is rewritten in place or left alone. It is
    /// here for an application that wipes the library keyspace itself, for example on a factory
    /// reset.
    /// @return true if the key is gone from the store, false if it may still be there.
    virtual bool erase_blob(const std::string& /*key*/) {
        return false;
    }
};

/// @brief Fixed, library-owned keyspace for SendspinPersistenceProvider.
///
/// Every key is at most 12 characters, comfortably under the 15-character NVS key limit.
/// Providers are pure byte stores: they must not parse or reinterpret these values.
///
/// - A record slot key (`record_slot_key()`), `PAIRING_PSK`, and `PAIR_CONFIG` hold a versioned
///   JSON blob produced by the codec in `sendspin/persistence_codec.h`
///   (`encode_pairing_record()` / `decode_pairing_record()`, `encode_pairing_psk()` /
///   `decode_pairing_psk()`, `encode_pairing_config()` / `decode_pairing_config()`
///   respectively).
/// - `RECORD_ORDER`, `KEYPAIR`, `STATIC_PAIRING_CODE`, and `LAST_PLAYED` hold raw bytes: see
///   each constant's comment.
/// - `OUTPUT_DELAY` holds an ASCII decimal string rather than raw uint16_t bytes, for
///   debuggability and to avoid an endianness dependency; decode it with a bounds check and
///   treat an invalid value as absent.
namespace persistence_keys {

/// 32 raw bytes: the static X25519 private key. No codec, no encoding.
inline constexpr const char* KEYPAIR = "keypair";

/// Prefix of the per-slot record keys; see `record_slot_key()`.
inline constexpr const char* RECORD_SLOT_PREFIX = "rec_";

/// Raw bytes: the slot numbers of the occupied record slots, least recently used first, one byte
/// per slot. It decides which record is evicted when a pairing arrives at a full store, so it is
/// rewritten whenever that order changes. A slot number naming no stored record is ignored on
/// load, and a stored record this blob does not name sorts after the ones it does.
inline constexpr const char* RECORD_ORDER = "rec_order";

/// @brief Key of one long-term record slot: `RECORD_SLOT_PREFIX` followed by the decimal slot
/// number, for example `rec_0`.
///
/// Each slot holds one `SendspinPairingRecord` as a codec blob (`encode_pairing_record()` /
/// `decode_pairing_record()`), or an EMPTY blob when the slot is free. Only the slot that
/// changed is written, so a pairing or a revocation costs one record-sized write rather than a
/// rewrite of every record. Slot numbers run from 0 to `SendspinClientConfig::max_pairing_records
/// - 1`; a slot key is absent until that slot is first filled.
/// @param slot The slot number.
/// @return The storage key for that slot.
inline std::string record_slot_key(size_t slot) {
    return std::string(RECORD_SLOT_PREFIX) + std::to_string(slot);
}

/// Codec blob: the accepted `SendspinPairingPsk` (`encode_pairing_psk()` / `decode_pairing_psk()`).
inline constexpr const char* PAIRING_PSK = "pairing_psk";

/// Raw UTF-8 bytes: the configured static pairing code (8 decimal digits). The stored key string
/// is part of the storage format, fixed independently of the protocol field names.
inline constexpr const char* STATIC_PAIRING_CODE = "static_pin";

/// Codec blob: the `SendspinPairingConfig` (`encode_pairing_config()` / `decode_pairing_config()`).
inline constexpr const char* PAIR_CONFIG = "pair_config";

/// Raw UTF-8 bytes: the server_id (base64url public key) of the last server that played audio.
inline constexpr const char* LAST_PLAYED = "last_played";

/// ASCII decimal string (e.g. "150"): the player's output delay in milliseconds.
inline constexpr const char* OUTPUT_DELAY = "static_delay";

}  // namespace persistence_keys

/// @brief Log severity levels for host builds
/// Has no effect on ESP-IDF builds
enum class LogLevel : uint8_t {
    NONE = 0,
    ERROR = 1,
    WARN = 2,
    INFO = 3,
    DEBUG = 4,
    VERBOSE = 5,
};

// Forward declarations
class ConnectionManager;
struct PairingUiSnapshot;
class RecordStore;
class SendspinArenaAllocator;
class SendspinConnection;
class SendspinTimeBurst;
struct Identity;

/**
 * @brief Main orchestration class for the sendspin-cpp library
 *
 * Manages WebSocket connections, message routing, NTP-style time synchronization,
 * audio playback, and all Sendspin protocol interactions. Roles are added at runtime
 * and each receives events via a listener interface. Only roles that are added will
 * participate in the protocol.
 *
 * @code
 * struct MyPlayerListener : PlayerRoleListener {
 *     size_t on_audio_write(uint8_t* data, size_t len, uint32_t timeout_ms) override {
 *         return audio_output.write(data, len, timeout_ms);
 *     }
 * };
 *
 * struct MyNetworkProvider : SendspinNetworkProvider {
 *     bool is_network_ready() override { return true; }
 * };
 *
 * MyPlayerListener player_listener;
 * MyNetworkProvider network_provider;
 *
 * SendspinClientConfig config;
 * config.name = "My Device";
 * config.product_name = "Speaker";
 * config.manufacturer = "Acme";
 * config.software_version = "1.0.0";
 * SendspinClient client(config);
 * PlayerRoleConfig player_config;
 * player_config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
 * auto& player = client.add_player(player_config);
 * player.set_listener(&player_listener);
 * client.add_controller();
 * client.set_network_provider(&network_provider);
 * client.start();
 *
 * while (running) {
 *     client.loop();
 * }
 * client.stop();
 * @endcode
 */
class SendspinClient {
    friend class ConnectionManager;

public:
    explicit SendspinClient(SendspinClientConfig config);
    ~SendspinClient();

    /// @brief Sets the library-wide log level (host builds only, no-op on ESP-IDF)
    static void set_log_level(LogLevel level);

    /// @brief Returns the current log level (host builds only, INFO on ESP-IDF)
    static LogLevel get_log_level();

    // ========================================
    // Lifecycle
    // ========================================

    /// @brief Starts the role threads and arms the WebSocket server
    ///
    /// The server itself comes up on the first loop() tick after the network provider reports
    /// ready. If a role fails to start, the roles that did start are stopped again so a corrected
    /// retry begins from the stopped state. Main-loop thread only.
    /// @return true if the client is running (including when it already was), false on failure
    bool start();

    /// @brief Stops the client and returns only once it is fully stopped
    ///
    /// Sends a client/goodbye (reason shutdown) to every peer, waits a short bound for those
    /// sends to complete, then closes the server and every connection regardless, joins the role
    /// threads, resets every role, and delivers the roles' clear callbacks (on_stream_end(),
    /// on_image_clear(), on_metadata_clear(), ...) before returning. A pairing prompt still
    /// showing is dismissed the same way (on_clear_pairing_code() / on_close_pairing_window()),
    /// and a pairing record staged by a pair-finalize is persisted first. No-op when stopped.
    /// Calling start() afterwards restarts on the same identity and record store, unless the
    /// persistence provider changed in between. Start/stop cycles may be repeated indefinitely.
    ///
    /// Blocking is bounded by the goodbye wait, the transports' own close, and any listener
    /// callback already running on a role thread, which the join cannot interrupt. The
    /// per-transport bounds are described in docs/integration-guide.md (Stopping and
    /// Restarting).
    ///
    /// Listener callbacks fire from inside this call, after every role has been reset, so the
    /// state they observe through the getters is the stopped state. One that calls start() has
    /// no effect and returns false; one that calls stop(), connect_to(), or disconnect() is
    /// ignored. Main-loop thread only: calling it from a role-thread callback would join the
    /// calling thread.
    void stop();

    /// @brief Returns true between a successful start() and stop()
    ///
    /// Running means the role threads are up and the server is armed, not that the server is
    /// listening yet (that waits for the network provider). Reads false for the whole duration
    /// of stop(), including from the clear callbacks it fires. Safe to call from any thread.
    bool is_started() const {
        return this->lifecycle_.load(std::memory_order_acquire) == LifecycleState::RUNNING;
    }

    /// @brief Starts the client
    /// @deprecated Use start(). Kept as an alias for existing consumers; removal is planned for
    /// v0.9.0.
    /// @return See start().
    [[deprecated("Use start()")]] bool start_server() {
        return this->start();
    }

    /// @brief Initiates a client connection to a Sendspin server at the given URL
    ///
    /// Ignored (with a warning) unless the client is running, including from a callback fired
    /// inside stop(). start() is where the identity and record store the Noise handshake needs
    /// are created. Must be called from the main loop
    /// thread: it tears down and replaces connection state (time filter, dispatch, client state)
    /// directly rather than deferring to loop(), so calling it concurrently with loop() would
    /// race those mutations.
    /// @param url WebSocket server URL (e.g., "ws://server.local:8927/sendspin")
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server with the given reason
    ///
    /// Ignored unless the client is running, including from a callback fired inside stop().
    /// Must be called from the main loop thread: the blocking transport close runs outside the
    /// manager lock, so another thread could race loop()'s own release of the same connection.
    /// @param reason The goodbye reason to send
    void disconnect(SendspinGoodbyeReason reason);

    /// @brief Processes events, drives time sync, checks network. Call from main loop
    /// A no-op while the client is stopped.
    void loop();

    // ========================================
    // Role registration (call before start())
    // ========================================

#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Adds the player role. Returns a reference for setting callbacks
    PlayerRole& add_player(PlayerRoleConfig config);
#endif

#ifdef SENDSPIN_ENABLE_COLOR
    /// @brief Adds the color role. Returns a reference for setting callbacks
    ColorRole& add_color();
#endif

#ifdef SENDSPIN_ENABLE_CONTROLLER
    /// @brief Adds the controller role. Returns a reference for setting callbacks
    ControllerRole& add_controller();
#endif

#ifdef SENDSPIN_ENABLE_METADATA
    /// @brief Adds the metadata role. Returns a reference for setting callbacks
    MetadataRole& add_metadata();
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
    /// @brief Adds the artwork role. Returns a reference for setting callbacks
    ArtworkRole& add_artwork(ArtworkRoleConfig config);
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    /// @brief Adds the visualizer role. Returns a reference for setting callbacks
    VisualizerRole& add_visualizer(VisualizerRoleConfig config);
#endif

    // ========================================
    // Role access (nullptr if not added)
    // ========================================

#ifdef SENDSPIN_ENABLE_ARTWORK
    /// @brief Returns the artwork role, or nullptr if not added
    // cppcheck-suppress unusedFunction
    // Public API: live entry point the reference examples don't happen to exercise, not dead code.
    ArtworkRole* artwork() {
        return this->artwork_.get();
    }
    /// @brief Returns the artwork role (const), or nullptr if not added
    const ArtworkRole* artwork() const {
        return this->artwork_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    /// @brief Returns the color role, or nullptr if not added
    ColorRole* color() {
        return this->color_.get();
    }
    /// @brief Returns the color role (const), or nullptr if not added
    const ColorRole* color() const {
        return this->color_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    /// @brief Returns the controller role, or nullptr if not added
    ControllerRole* controller() {
        return this->controller_.get();
    }
    /// @brief Returns the controller role (const), or nullptr if not added
    const ControllerRole* controller() const {
        return this->controller_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    /// @brief Returns the metadata role, or nullptr if not added
    MetadataRole* metadata() {
        return this->metadata_.get();
    }
    /// @brief Returns the metadata role (const), or nullptr if not added
    const MetadataRole* metadata() const {
        return this->metadata_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Returns the player role, or nullptr if not added
    PlayerRole* player() {
        return this->player_.get();
    }
    /// @brief Returns the player role (const), or nullptr if not added
    const PlayerRole* player() const {
        return this->player_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    /// @brief Returns the visualizer role, or nullptr if not added
    // cppcheck-suppress unusedFunction
    // Public API, not dead code.
    VisualizerRole* visualizer() {
        return this->visualizer_.get();
    }
    /// @brief Returns the visualizer role (const), or nullptr if not added
    const VisualizerRole* visualizer() const {
        return this->visualizer_.get();
    }
#endif

    // ========================================
    // Queries
    // ========================================

    /// @brief Returns the client's cryptographic identity string.
    /// This is base64url(X25519 public key), 43 chars: the Sendspin client_id.
    /// Generated on first boot and persisted via the persistence provider.
    /// Empty until start() is called.
    /// Main loop only. start() rewrites the value, so do not cache a c_str() across a restart.
    [[nodiscard]] const std::string& client_id() const {
        return this->client_id_;
    }

    /// @brief Builds the pairing token (pairing.md "Pairing Token") for a Sendspin Pairing
    /// PSK: the single "SP:"-prefixed, base32 string that carries this client's static public key
    /// alongside `pairing_psk`, for an operator to transfer into a server via copy/paste or QR
    /// code to begin the Pairing PSK flow. Clients offering `pairing_psk` SHOULD surface this
    /// token rather than the bare PSK.
    /// Main loop only.
    /// @param pairing_psk The 32-byte Sendspin Pairing PSK.
    /// @return The 107-character token string, or nullopt if no identity has been initialized
    ///         yet (before start() is called).
    [[nodiscard]] std::optional<std::string> format_pairing_token(
        const std::array<uint8_t, 32>& pairing_psk) const;

    /// @brief Builds the pairing token for the client's own Sendspin Pairing PSK.
    /// The Pairing PSK is provisioned automatically on first boot and persisted, so this token
    /// is stable for the lifetime of the stored key: display it (or its QR code) for the
    /// operator to transfer into a server that is setting this client up.
    /// Main loop only.
    /// @return The 107-character token string, or nullopt before start() or when no
    ///         Pairing PSK is configured.
    [[nodiscard]] std::optional<std::string> pairing_token() const;

    /// @brief Returns true if there is an active connection whose handshake completed and whose
    /// first server/activate has arrived
    bool is_connected() const;

    /// @brief Returns the server information from the active connection's hello handshake, or
    /// nullopt when no handshake has completed
    std::optional<ServerInformationObject> get_server_information() const;

    /// @brief Returns true if the time filter has received at least one measurement
    bool is_time_synced() const;

    /// @brief Converts a server timestamp to the equivalent client timestamp
    /// @param server_time Server-side timestamp in microseconds
    /// @return Equivalent client-side timestamp in microseconds
    int64_t get_client_time(int64_t server_time) const;

    /// @brief Returns the current group state; fields are optional and may be unset
    const GroupUpdateObject& get_group_state() const {
        return this->group_state_;
    }

    /// @brief Returns the trust level of the active connection. Main loop only.
    /// The same value SendspinClientListener::on_trust_changed reports, queryable at any time.
    /// @return The active connection's ConnectionTrust; ConnectionTrust::NONE when no
    ///         connection is active or the handshake has not completed
    ConnectionTrust get_current_trust() const {
        return this->current_trust_;
    }

    // ========================================
    // State updates
    // ========================================

    /// @brief Sets whether the client is available for Sendspin playback; publishes on a change
    ///
    /// messaging.md "External Source Handling": false only while the device will not yield to
    /// Sendspin, which moves it to a stopped group of its own. An activity Sendspin may interrupt
    /// calls leave() instead. Kept across disconnects and stop()/start(). Main loop only.
    /// @param available false while the device will not yield to Sendspin.
    void set_available(bool available);

    /// @brief Whether the client reports itself available; see set_available(). Main loop only.
    bool is_available() const {
        return this->available_;
    }

    /// @brief Leaves the current group with messaging.md "client/leave". Main loop only.
    ///
    /// The client no longer wants to take part in its group's playback, for example while
    /// playing a local source. The
    /// server treats it as it treats a client becoming unavailable: this client ends up alone in
    /// a stopped group, and rejoins only when an operator switches it back. Leaving does not
    /// change availability, so the server may still take the client over for new playback; a
    /// client that will not yield calls set_available(false) instead.
    ///
    /// Only meaningful while the group is playing: a client in a stopped group keeps its
    /// grouping by staying. Ignored, with a log, unless a connection is admitted and its latest
    /// server/activate has arrived.
    void leave();

    // ========================================
    // Pairing
    // ========================================

    /// @brief Signals that the operator performed the device pairing-window gesture.
    /// Thread-safe. Opens a pairing window (pairing.md "Pairing Window"): a gesture-gated attempt
    /// already waiting proceeds immediately; otherwise the window stands open for 5 minutes and
    /// admits pairing attempts on one connection without a further gesture. It closes before
    /// those 5 minutes are up when a pairing under it succeeds, when the connection it is bound
    /// to is lost, after five attempts fail verification, or on cancel_pairing_window(). The
    /// gesture also clears a standing dynamic-pairing-code round limit.
    void confirm_pairing_window();

    /// @brief Signals that the operator cancelled the pairing window.
    /// Thread-safe. Closes any open window, one of the closing events pairing.md "Pairing Window"
    /// defines, so the next gesture-gated attempt waits for a fresh gesture. An attempt still
    /// withheld for that gesture ends with pair/abort reason user_cancelled; one already under
    /// way runs to its own end.
    void cancel_pairing_window();

    // ========================================
    // Listener and provider setters
    // ========================================

    /// @brief Sets the listener for client events. The listener must outlive this client
    void set_listener(SendspinClientListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Sets the network provider (required before start())
    /// The provider must outlive this client
    void set_network_provider(SendspinNetworkProvider* provider) {
        this->network_provider_ = provider;
    }

    /// @brief Sets the optional persistence provider. The provider must outlive this client
    void set_persistence_provider(SendspinPersistenceProvider* provider) {
        this->persistence_provider_ = provider;
    }

    // ========================================
    // Role services (called by roles via SendspinClient pointer)
    // ========================================

    /// @brief Publishes the current client state to the active connection
    ///
    /// Main loop only, like the role setters that call it: the client state and the role fields
    /// it serializes are main-loop state. The connection itself is resolved as a shared_ptr, so
    /// the publish cannot outlive the slot even when a caller ignores that contract.
    void publish_state();

    /// @brief Sends a role-originated text message over the active connection
    ///
    /// Every message sent on a role's behalf carries the role it belongs to, so the activation
    /// gate cannot be forgotten at a call site. The client's own messages do not come through
    /// here.
    ///
    /// Dropped unless that role is active on the connection: messaging.md "server/activate"
    /// tolerates inactive-role objects server-side because a client that received the role
    /// removal stops sending them. The activation test is on the versioned name, the same test
    /// the receive path applies. Also held, like client/state, while a re-handshake awaits the
    /// server/activate that follows it.
    ///
    /// Callable from any thread: the gate reads the connection's published role mask, not the
    /// main-loop-only role set.
    /// @param text The text message to send
    /// @param role_family Role family the message belongs to, without the version suffix
    ///                    (e.g. "controller")
    void send_text(const std::string& text, const std::string& role_family);

    /// @brief Acquires a ref-counted high-performance networking request
    void acquire_high_performance();

    /// @brief Releases a ref-counted high-performance networking request
    ///
    /// The last release calls the listener inline, so only call this where no ConnectionManager
    /// lock is held; locked teardown paths use release_high_performance_deferred().
    void release_high_performance();

    /// @brief Hands a high-performance release to the next drain instead of performing it here
    ///
    /// The reference stays held until flush_high_performance_releases() runs, so a release
    /// deferred out of a locked teardown can never be reordered against an acquire that follows
    /// it. Main loop only.
    void release_high_performance_deferred();

private:
    /// @brief Cleans up playback state when the active streaming connection is removed
    void cleanup_connection_state();

    /// @brief Persists a pairing record the network thread staged, if one is pending.
    ///
    /// The store may be null here: the destructor calls this on a client whose start() never
    /// succeeded.
    void flush_pending_records();

    /// @brief Drains the inbox: lifecycle events, role slots, and group updates, dispatching
    /// listener callbacks on the calling (main-loop) thread. Shared by loop() and stop().
    void drain_inbox();

    /// @brief Performs the releases release_high_performance_deferred() handed over
    ///
    /// Runs at the head of drain_inbox(), with no ConnectionManager lock held, so a last
    /// release's listener callback may call back into the client.
    void flush_high_performance_releases();

    /// @brief Signals the drain roles, then goodbyes and closes every transport, joining the
    /// network threads. The shared first half of stop() and the destructor's teardown.
    /// @return The pairing prompts the dropped connections left showing; stop() dismisses them
    ///         after cleanup_connection_state(), the destructor dispatches nothing.
    PairingUiSnapshot close_transports();

    /// @brief Asks the artwork and visualizer threads to exit without joining them, so their
    /// exit overlaps the transport teardown. The player is excluded: its ring must keep a
    /// consumer until the network threads are gone (see stop()).
    void signal_drain_role_stops();

    /// @brief Stops and joins every threaded role; each is a no-op if not running
    void stop_role_threads();

    /// @brief Builds the formatted client hello message from config
    std::string build_hello_message();

    // ========================================
    // Message processing
    // ========================================

    /// @brief Processes a JSON message from a connection
    ///
    /// Called on the connection's network thread. Takes the JSON processing mutex and hands off
    /// to dispatch_json_message(). `data` is not null-terminated and is valid for the duration
    /// of the call only.
    void process_json_message(SendspinConnection* conn, const char* data, size_t len,
                              int64_t timestamp);

    /// @brief Where a dispatched JSON message came from.
    enum class JsonMessageOrigin : uint8_t {
        NETWORK,           ///< Live traffic, subject to the admission gate
        ADMISSION_REPLAY,  ///< A message held until admission, whose gate has already been passed
    };

    /// @brief Defers a pairing message that failed to parse to the main loop.
    ///
    /// Shared by the pair-init, pair-auth and pair-confirm arms of dispatch_json_message(), which
    /// differ only in the payload they parse.
    void schedule_malformed_pairing_message(SendspinConnection* conn, const char* type_name);

    /// @brief Parses and routes one JSON message. The caller holds json_processing_mutex_.
    /// @param origin Whether the admission gate still applies to this message
    void dispatch_json_message(SendspinConnection* conn, const char* data, size_t len,
                               int64_t timestamp,
                               JsonMessageOrigin origin = JsonMessageOrigin::NETWORK);

    /// @brief Replays the connection's held role messages and marks it admitted.
    ///
    /// Main loop only; ConnectionManager::flush_pending_admission() is the only caller. The
    /// replay and the flag happen under one hold of json_processing_mutex_ so the role traffic a
    /// server sent between its server/activate and this admission is applied exactly once, in
    /// arrival order, ahead of anything that arrives afterwards.
    ///
    /// THREADING: takes json_processing_mutex_, so the caller must hold no ConnectionManager
    /// lock. That is the library-wide lock order (docs/conventions.md, "Threading and
    /// cross-thread state"): json_processing_mutex_ outside conn_ptr_mutex_.
    void admit_connection(SendspinConnection* conn);

    /// @brief Processes a binary message from a connection
    /// Every binary message is role-bound, so this is dropped unless `conn` holds the admitted
    /// slot.
    void process_binary_message(SendspinConnection* conn, const uint8_t* payload, size_t len);

    // ========================================
    // State publishing
    // ========================================

    /// @brief Publishes the current client state to the specified connection
    ///
    /// Held while an available, active player has no clock sync yet (see client_state_held_).
    /// Takes no lock of its own: its main-loop callers already hold conn_ptr_mutex_ or a
    /// shared_ptr, which is what keeps `conn` alive for the call.
    void publish_client_state(SendspinConnection* conn);

    // ========================================
    // Persistence & identity
    // ========================================

    /// @brief Loads or generates the static X25519 identity keypair via the persistence
    /// provider. Sets identity_ on success. Called once from start(), before the
    /// connection manager can hand the identity out to any connection.
    /// @return false only if key generation failed (e.g. noise-c allocation failure); a corrupt
    /// or wrong-length stored key is discarded and a fresh identity generated in its place (the
    /// device must then re-pair). identity_ is left null on false and the caller (start()) must
    /// not proceed.
    bool load_or_generate_identity();

    /// @brief Loads the last played server_id from persistence
    void load_last_played_server();

    /// @brief Persists the server_id as the last played server, RAM half and write together.
    /// For a caller that holds no manager lock (the group-update drain); the connection manager
    /// uses note_last_played_server() / write_last_played_server() separately.
    void persist_last_played_server(const std::string& server_id);

    /// @brief Applies the handoff preference in RAM, the half a caller holding
    /// ConnectionManager::conn_ptr_mutex_ may run: arbitration reads last_played_server_id_
    /// later in that same locked block, so the RAM update must not be deferred with the write.
    /// @return true when the value actually changed, so the caller owes a
    ///         write_last_played_server() once its locks are dropped.
    bool note_last_played_server(const std::string& server_id);

    /// @brief Writes the last-played server_id through the persistence provider. No library lock
    /// may be held: on ESP this is a flash write.
    void write_last_played_server(const std::string& server_id);

    // ========================================
    // Connection event handlers (called by ConnectionManager via friend access)
    // ========================================

    /// @brief Publishes the initial client state after handshake completes
    /// @param conn The connection that completed the handshake
    void on_handshake_complete(SendspinConnection* conn);

    /// @brief Tears down every role the activation just took out of active_roles
    ///
    /// messaging.md "server/activate" has the client stop a removed stream role's output and clear
    /// its buffers, and discard a removed state role's current state and pending scheduled update,
    /// as part of applying the activation. Roles that stay active at the same version are
    /// untouched.
    ///
    /// Called by ConnectionManager on the main loop while conn_ptr_mutex_ is held, for the
    /// admitted connection only, so the teardown obeys the same rule as the disconnect path: it
    /// queues its listener callbacks on the inbox instead of calling them here.
    /// @param roles_before The active roles the activation replaces
    /// @param roles_after The active roles the activation established
    void apply_role_removals(const std::vector<std::string>& roles_before,
                             const std::vector<std::string>& roles_after);

    // Pairing and trust notifications. Each is called by ConnectionManager on the main loop,
    // most while conn_ptr_mutex_ is held, and queues the listener callback for delivery from
    // loop() so it fires unlocked. note_pairing_succeeded() runs after the network thread's
    // schedule_pairing_succeeded() event has been drained (ConnectionManager::loop()).

    /// @brief Queue an on_pairing_started notification
    void note_pairing_started(const std::string& server_id);

    /// @brief Queue an on_pairing_succeeded notification
    void note_pairing_succeeded(const std::string& server_id);

    /// @brief Queue an on_pairing_failed notification
    void note_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason);

    /// @brief Queue an on_display_pairing_code notification
    void note_display_pairing_code(const std::string& code, SendspinPairingCodeFormat format);

    /// @brief Queue an on_clear_pairing_code notification
    void note_clear_pairing_code();

    /// @brief Queue an on_open_pairing_window notification
    void note_open_pairing_window();

    /// @brief Queue an on_close_pairing_window notification
    void note_close_pairing_window();

    /// @brief Queue an on_trust_changed notification
    void note_trust_changed(ConnectionTrust trust);

    struct EventState;

    // Struct fields
    SendspinClientConfig config_;
    GroupUpdateObject group_state_{};

    // String fields
    std::string client_id_;  ///< Derived from the static keypair: base64url(public_key).

    // Pointer fields
#ifdef SENDSPIN_ENABLE_ARTWORK
    std::unique_ptr<ArtworkRole> artwork_;
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    std::unique_ptr<ColorRole> color_;
#endif
    std::unique_ptr<ConnectionManager> connection_manager_;
#ifdef SENDSPIN_ENABLE_CONTROLLER
    std::unique_ptr<ControllerRole> controller_;
#endif
    std::unique_ptr<EventState> event_state_;
    /// Static X25519 identity (generated on first boot, persisted via the persistence
    /// provider). Set by load_or_generate_identity() in start(); outlives every
    /// connection the manager hands it out to.
    std::unique_ptr<Identity> identity_;
    /// Internal-RAM scratch arena for parsing incoming JSON; null unless config_.json_arena_size >
    /// 0
    std::unique_ptr<SendspinArenaAllocator> json_arena_;
    /// Serializes process_json_message() (and its use of json_arena_) across the network threads
    /// of concurrently live connections (current + pending during a handoff).
    std::mutex json_processing_mutex_;
    SendspinClientListener* listener_{nullptr};
#ifdef SENDSPIN_ENABLE_METADATA
    std::unique_ptr<MetadataRole> metadata_;
#endif
    /// The provider identity_ and record_store_ were built from; start() rebuilds both when
    /// persistence_provider_ no longer matches it.
    SendspinPersistenceProvider* identity_provider_{nullptr};
    SendspinNetworkProvider* network_provider_{nullptr};
    SendspinPersistenceProvider* persistence_provider_{nullptr};
#ifdef SENDSPIN_ENABLE_PLAYER
    std::unique_ptr<PlayerRole> player_;
#endif
    /// In-memory pairing record store (PSK resolution, trust config). Set in start();
    /// outlives every connection the manager hands it out to.
    std::unique_ptr<RecordStore> record_store_;
    std::unique_ptr<SendspinTimeBurst> time_burst_;
#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::unique_ptr<VisualizerRole> visualizer_;
#endif

    // 8-bit fields
    /// Consumer-owned availability; see set_available(). Main loop only.
    bool available_{true};
    /// A client/state held for clock sync, which loop() sends once synced. Main loop only.
    bool client_state_held_{false};
    /// Trust level of the active connection; written by on_handshake_complete() and reset by
    /// cleanup_connection_state(), both main loop only, so get_current_trust() needs no lock.
    ConnectionTrust current_trust_{ConnectionTrust::NONE};
    bool high_performance_held_for_time_{false};
    std::atomic<uint8_t> high_performance_ref_count_{0};
    /// Releases handed over by release_high_performance_deferred() and performed by the next
    /// flush_high_performance_releases(). Main loop only.
    uint8_t high_performance_releases_pending_{0};
    /// Where the client is in its lifecycle. Written only by start()/stop() on the main loop;
    /// atomic so is_started() can be read from any thread. STOPPING covers the whole of stop():
    /// start() is refused and stop()/connect_to()/disconnect() are ignored while it is set, so a
    /// listener callback fired from inside the teardown cannot recurse into it.
    enum class LifecycleState : uint8_t { STOPPED, RUNNING, STOPPING };
    std::atomic<LifecycleState> lifecycle_{LifecycleState::STOPPED};
};

}  // namespace sendspin
