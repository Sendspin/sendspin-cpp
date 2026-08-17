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
    virtual void on_request_high_performance() {}

    /// @brief Called when the library no longer needs high-performance networking
    virtual void on_release_high_performance() {}

    // ========================================
    // Encryption / pairing callbacks
    // ========================================

    /// @brief Called when a server begins a pairing exchange
    ///
    /// server_id is the base64url public key of the server entering pairing. Fires once per
    /// attempt regardless of the selected method (Pairing-PSK, dynamic PIN, or static PIN);
    /// the exchange completes when on_pairing_succeeded or on_pairing_failed fires.
    /// Fires on the main loop.
    virtual void on_pairing_started(const std::string& /*server_id*/) {}

    /// @brief Called when a pairing exchange completes and a long-term record is stored
    ///
    /// server_id is the base64url public key of the newly paired server. After this
    /// callback the server re-handshakes on the new long-term PSK. Subsequent
    /// connections from this server will report ConnectionTrust::USER.
    /// Fires on the main loop.
    virtual void on_pairing_succeeded(const std::string& /*server_id*/) {}

    /// @brief Called when a pairing exchange is aborted (by the server or by the protocol)
    ///
    /// server_id identifies the server whose pairing was aborted. reason explains why.
    /// The connection is closed immediately after this callback.
    /// Fires on the main loop.
    virtual void on_pairing_failed(const std::string& /*server_id*/,
                                   SendspinPairAbortReason /*reason*/) {}

    /// @brief Called when the active connection's trust level is known after handshake
    ///
    /// Fires on the main loop when the active connection's trust level becomes known: on the
    /// initial handshake and after each successful re-handshake (for example, after pairing).
    /// trust reflects the PSK category matched during the Noise handshake:
    ///   ConnectionTrust::USER:  long-term record (paired server)
    ///   ConnectionTrust::NONE:  Sentinel or Pairing PSK (unpaired access)
    virtual void on_trust_changed(ConnectionTrust /*trust*/) {}

    /// @brief Called when a dynamic-PIN should be displayed to the user.
    ///
    /// pin is the zero-padded decimal PIN string (e.g., "042735").  Fires on the main loop.
    /// Called at most once per pairing attempt; always followed by on_clear_pairing_pin when
    /// the attempt concludes (success, failure, or abort).
    /// Only called when SendspinClientConfig::pin_display_supported is true.
    virtual void on_display_pairing_pin(const std::string& /*pin*/) {}

    /// @brief Called to clear the dynamic PIN from the display.
    ///
    /// Fires on the main loop after every pairing attempt that triggered on_display_pairing_pin,
    /// regardless of outcome.  Always called after on_display_pairing_pin, never before it.
    virtual void on_clear_pairing_pin() {}

    /// @brief Called when the operator must perform the device pairing-window gesture to allow
    /// a gesture-gated PIN pairing attempt (static PIN: every attempt; dynamic PIN: when the
    /// method is escalated by its failure counter or the session PIN is shorter than 6 digits).
    ///
    /// Fires on the main loop. Only called when SendspinClientConfig::pairing_window_supported
    /// is true; a device offering dynamic_pin should therefore also implement this gesture UI,
    /// or an escalated/short-PIN attempt can only proceed via management/open-pairing-window
    /// (or stall until the server cancels it). Always followed by on_close_pairing_window when
    /// the attempt concludes. The application confirms the gesture by calling
    /// SendspinClient::confirm_pairing_window().
    virtual void on_open_pairing_window() {}

    /// @brief Called to dismiss the pairing-window prompt after every attempt that triggered
    /// on_open_pairing_window, regardless of outcome.
    virtual void on_close_pairing_window() {}
};

/// @brief Platform hook for network readiness
/// Must be set before start_server()
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
/// Threading: every method is invoked on the main loop thread, for every key. A provider
/// therefore needs no locking of its own. (The one library write that originates on the network
/// thread, the pairing record committed at server/pair-finalize, is staged internally and
/// flushed to `save_blob(persistence_keys::RECORDS, ...)` from the next `loop()` tick.)
/// `save_blob(persistence_keys::KEYPAIR, ...)` is the one write that happens exactly once, at
/// startup during `start_server()`, rather than in response to a runtime event.
///
/// Re-entrancy: implementations must NOT call back into the library (SendspinClient or any of
/// its objects) from inside load_blob/save_blob/erase_blob. The library invokes these methods
/// while holding internal locks (e.g. the record store's mutex around a `RECORDS` save), so a
/// callback into the library from a provider method can deadlock.
///
/// Blocking: for the same reason, an implementation must perform one bounded storage operation
/// and return, not add blocking of its own (a synchronous retry loop, a multi-second fsync
/// chain). Held locks are on the call stack for the duration. A failed write should be reported
/// by returning false rather than retried inline; the library already handles that (durability
/// warnings, fail-closed management add-record) as described below on save_blob/erase_blob.
class SendspinPersistenceProvider {
public:
    virtual ~SendspinPersistenceProvider() = default;

    /// @brief Load the blob stored under key.
    /// @return The bytes, or nullopt if absent.
    virtual std::optional<std::vector<uint8_t>> load_blob(const std::string& /*key*/) {
        return std::nullopt;
    }

    /// @brief Persist bytes under key. Returning true means DURABLY stored (the library
    /// gates management/add-record results on this for the "records" key, and revocation
    /// durability on it for removals).
    ///
    /// A rejected write is reported, not retried: the in-memory state it was meant to capture
    /// stays authoritative for the current boot, and the library logs a warning naming what will
    /// be lost (or come back) at the next reboot. Specifically, for
    /// `persistence_keys::RECORDS`: a rejected write of a just-paired record leaves the pairing
    /// working for this boot only (`on_pairing_succeeded` still fires); a rejected write of a
    /// removal means the store still holds the old array and will hand the revoked record back
    /// at the next boot, silently making the revoked PSK valid again (the revoked record is
    /// always dropped from RAM regardless of this return value, so a `false` does not undo
    /// that). The one fail-closed consumer is `management/add-record`, which reports a rejected
    /// write to the requesting server as storage_exhausted rather than promising a credential
    /// the device does not durably hold.
    /// A provider that cannot report durability synchronously (one that queues the write) should
    /// return true and surface its own write failures; the library's warnings are only as
    /// accurate as this return value, so report failure honestly rather than swallowing it.
    /// @return true on success, false on failure.
    virtual bool save_blob(const std::string& /*key*/, const uint8_t* /*data*/, size_t /*len*/) {
        return false;
    }

    /// @brief Remove key. Absent counts as success. A false return means the value may
    /// survive a reboot.
    ///
    /// Only `persistence_keys::PAIRING_PSK` and `persistence_keys::STATIC_PIN` are ever erased
    /// this way; `persistence_keys::RECORDS` is never erased (a removal re-saves the shrunken
    /// array instead, so the key stays present with an empty array). The in-memory effect of a
    /// clear always takes place regardless of the return value (the PSK/PIN stops working for
    /// the current boot either way); a `false` return means the value the library just cleared
    /// may still be sitting in the store and will resume authenticating pairing attempts /
    /// admitting the static PIN again after a reboot.
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
/// - `RECORDS`, `PAIRING_PSK`, and `PAIR_CONFIG` hold a versioned JSON blob produced by the
///   codec in `sendspin/persistence_codec.h` (`encode_pairing_records()` /
///   `decode_pairing_records()`, `encode_pairing_psk()` / `decode_pairing_psk()`,
///   `encode_pairing_config()` / `decode_pairing_config()` respectively).
/// - `KEYPAIR`, `STATIC_PIN`, and `LAST_PLAYED` hold raw bytes: see each constant's comment.
/// - `STATIC_DELAY` holds an ASCII decimal string rather than raw uint16_t bytes, for
///   debuggability and to avoid an endianness dependency; decode it with a bounds check and
///   treat an invalid value as absent.
namespace persistence_keys {

/// 32 raw bytes: the static X25519 private key. No codec, no encoding.
inline constexpr const char* KEYPAIR = "keypair";

/// Codec blob: the WHOLE `SendspinPairingRecord` array (`encode_pairing_records()` /
/// `decode_pairing_records()`). Stays present once any record exists, including an empty array
/// after the last record is removed; see `persistence_keys` doc above.
inline constexpr const char* RECORDS = "records";

/// Codec blob: the accepted `SendspinPairingPsk` (`encode_pairing_psk()` / `decode_pairing_psk()`).
inline constexpr const char* PAIRING_PSK = "pairing_psk";

/// Raw UTF-8 bytes: the configured static PIN string.
inline constexpr const char* STATIC_PIN = "static_pin";

/// Codec blob: the `SendspinPairingConfig` (`encode_pairing_config()` / `decode_pairing_config()`).
inline constexpr const char* PAIR_CONFIG = "pair_config";

/// Raw UTF-8 bytes: the server_id (base64url public key) of the last server that played audio.
inline constexpr const char* LAST_PLAYED = "last_played";

/// ASCII decimal string (e.g. "150"): the player's static delay in milliseconds.
inline constexpr const char* STATIC_DELAY = "static_delay";

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
 * Usage:
 * 1. Fill in a SendspinClientConfig with the device identity fields
 * 2. Construct a SendspinClient with that config
 * 3. Add roles via add_player(), add_controller(), add_metadata(), etc.
 * 4. Set listeners on each role and set the network provider on the client
 * 5. Call start_server() to start the WebSocket server and background tasks
 * 6. Call loop() periodically from the platform main loop
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
 * auto& player = client.add_player(PlayerRoleConfig{});
 * player.set_listener(&player_listener);
 * client.add_controller();
 * client.set_network_provider(&network_provider);
 * client.start_server();
 *
 * while (true) {
 *     client.loop();
 * }
 * @endcode
 */
class SendspinClient {
    friend class ConnectionManager;

public:
    explicit SendspinClient(SendspinClientConfig config);
    ~SendspinClient();

    /// @brief Sets the library-wide log level (host builds only, no-op on ESP-IDF)
    /// @param level The desired log level
    static void set_log_level(LogLevel level);

    /// @brief Returns the current log level (host builds only, INFO on ESP-IDF)
    /// @return The current log level
    static LogLevel get_log_level();

    // ========================================
    // Lifecycle
    // ========================================

    /// @brief Starts the WebSocket server and initializes the sync task (if audio is configured)
    /// @return true on success, false on failure
    bool start_server();

    /// @brief Initiates a client connection to a Sendspin server at the given URL
    ///
    /// Must be called from the main loop thread: it tears down and replaces connection state
    /// (time filter, dispatch, client state) directly rather than deferring to loop(), so calling
    /// it concurrently with loop() would race those mutations.
    ///
    /// Requires a successful start_server() first: the static identity and record store the Noise
    /// handshake needs are created there. Calling this earlier (or after start_server() returned
    /// false) logs an error and does nothing rather than building a connection that would fault
    /// once its WebSocket upgrade completed.
    /// @param url WebSocket server URL (e.g., "ws://server.local:8927/sendspin")
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server with the given reason
    ///
    /// Must be called from the main loop thread: the blocking transport close runs outside the
    /// manager lock, so a call from another thread could race loop()'s own release of the same
    /// connection (two concurrent transport stops).
    /// @param reason The goodbye reason to send
    void disconnect(SendspinGoodbyeReason reason);

    /// @brief Processes events, drives time sync, checks network. Call from main loop
    void loop();

    // ========================================
    // Role registration (call before start_server)
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
    /// @return Pointer to the artwork role, or nullptr
    // cppcheck-suppress unusedFunction
    // Public API: live entry point the reference examples don't happen to exercise, not dead code.
    ArtworkRole* artwork() {
        return this->artwork_.get();
    }
    /// @brief Returns the artwork role (const), or nullptr if not added
    /// @return Const pointer to the artwork role, or nullptr
    const ArtworkRole* artwork() const {
        return this->artwork_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    /// @brief Returns the color role, or nullptr if not added
    /// @return Pointer to the color role, or nullptr
    ColorRole* color() {
        return this->color_.get();
    }
    /// @brief Returns the color role (const), or nullptr if not added
    /// @return Const pointer to the color role, or nullptr
    const ColorRole* color() const {
        return this->color_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    /// @brief Returns the controller role, or nullptr if not added
    /// @return Pointer to the controller role, or nullptr
    ControllerRole* controller() {
        return this->controller_.get();
    }
    /// @brief Returns the controller role (const), or nullptr if not added
    /// @return Const pointer to the controller role, or nullptr
    const ControllerRole* controller() const {
        return this->controller_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    /// @brief Returns the metadata role, or nullptr if not added
    /// @return Pointer to the metadata role, or nullptr
    MetadataRole* metadata() {
        return this->metadata_.get();
    }
    /// @brief Returns the metadata role (const), or nullptr if not added
    /// @return Const pointer to the metadata role, or nullptr
    const MetadataRole* metadata() const {
        return this->metadata_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
    /// @brief Returns the player role, or nullptr if not added
    /// @return Pointer to the player role, or nullptr
    PlayerRole* player() {
        return this->player_.get();
    }
    /// @brief Returns the player role (const), or nullptr if not added
    /// @return Const pointer to the player role, or nullptr
    const PlayerRole* player() const {
        return this->player_.get();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    /// @brief Returns the visualizer role, or nullptr if not added
    /// @return Pointer to the visualizer role, or nullptr
    // cppcheck-suppress unusedFunction
    // Public API: live entry point the reference examples don't happen to exercise, not dead code.
    VisualizerRole* visualizer() {
        return this->visualizer_.get();
    }
    /// @brief Returns the visualizer role (const), or nullptr if not added
    /// @return Const pointer to the visualizer role, or nullptr
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
    /// Empty until start_server() is called.
    [[nodiscard]] const std::string& client_id() const {
        return this->client_id_;
    }

    /// @brief Builds the pairing token (spec's "Pairing Token" section) for a Sendspin Pairing
    /// PSK: the single "SP:"-prefixed, base32 string that carries this client's static public key
    /// alongside `pairing_psk`, for an operator to transfer into a server via copy/paste or QR
    /// code to begin the Pairing PSK flow. Clients offering `pairing_psk` SHOULD surface this
    /// token rather than the bare PSK.
    /// @param pairing_psk The 32-byte Sendspin Pairing PSK to encode alongside this client's
    ///                    identity.
    /// @return The 107-character token string, or nullopt if no identity has been initialized
    ///         yet (before start_server() is called).
    [[nodiscard]] std::optional<std::string> format_pairing_token(
        const std::array<uint8_t, 32>& pairing_psk) const;

    /// @brief Builds the pairing token for the client's own Sendspin Pairing PSK.
    /// The Pairing PSK is provisioned automatically on first boot and persisted, so this token
    /// is stable for the lifetime of the stored key: display it (or its QR code) for the
    /// operator to transfer into a server that is setting this client up.
    /// @return The 107-character token string, or nullopt before start_server() or when no
    ///         Pairing PSK is configured.
    [[nodiscard]] std::optional<std::string> pairing_token() const;

    /// @brief Returns true if there is an active connection with completed handshake
    /// @return true if connected with a completed handshake, false otherwise
    bool is_connected() const;

    /// @brief Returns the server information from the active connection's hello handshake
    /// @return ServerInformationObject if connected with a completed handshake, nullopt otherwise
    std::optional<ServerInformationObject> get_server_information() const;

    /// @brief Returns true if the time filter has received at least one measurement
    /// @return true if time synchronization has been established, false otherwise
    bool is_time_synced() const;

    /// @brief Converts a server timestamp to the equivalent client timestamp
    /// @param server_time Server-side timestamp in microseconds
    /// @return Equivalent client-side timestamp in microseconds
    int64_t get_client_time(int64_t server_time) const;

    /// @brief Returns the current group state
    /// @return The current GroupUpdateObject (fields are optional and may be unset)
    const GroupUpdateObject& get_group_state() const {
        return this->group_state_;
    }

    /// @brief Returns the trust level of the active connection. Main loop only.
    /// The same value SendspinClientListener::on_trust_changed reports, queryable at any
    /// time (e.g. for redrawing a UI without caching the callback's argument).
    /// @return The active connection's ConnectionTrust; ConnectionTrust::NONE when no
    ///         connection is active or the handshake has not completed
    ConnectionTrust get_current_trust() const {
        return this->current_trust_;
    }

    // ========================================
    // State updates
    // ========================================

    /// @brief Updates the client state (synchronized, error, external_source) and publishes
    /// @param state The new client state to publish
    void update_state(SendspinClientState state);

    // ========================================
    // Pairing
    // ========================================

    /// @brief Signals that the operator performed the device pairing-window gesture.
    /// Thread-safe. Opens a pairing window: a gesture-gated PIN attempt already waiting
    /// (static PIN always; dynamic PIN when escalated or the session PIN is short) proceeds
    /// immediately; otherwise the window stands open for 5 minutes and admits the next pairing
    /// attempt without a further gesture.
    void confirm_pairing_window();

    // ========================================
    // Listener and provider setters
    // ========================================

    /// @brief Sets the listener for client events. The listener must outlive this client
    void set_listener(SendspinClientListener* listener) {
        this->listener_ = listener;
    }

    /// @brief Sets the network provider (required before start_server())
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
    void publish_state();

    /// @brief Sends a text message over the active connection
    /// @param text The text message to send
    void send_text(const std::string& text);

    /// @brief Acquires a ref-counted high-performance networking request
    void acquire_high_performance();

    /// @brief Releases a ref-counted high-performance networking request
    void release_high_performance();

private:
    /// @brief Cleans up playback state when the active streaming connection is removed
    void cleanup_connection_state();

    /// @brief Builds the formatted client hello message from config
    /// @param conn The connection the hello will be sent on; used to derive trust_level from
    ///        the resolved PSK category. May be null (trust_level defaults to "none").
    std::string build_hello_message(const SendspinConnection* conn);

    // ========================================
    // Message processing
    // ========================================

    /// @brief Processes a JSON message from a connection
    /// @param conn The connection that received the message
    /// @param data Pointer to the raw JSON text (not null-terminated; valid for the duration of the
    /// call only)
    /// @param len Length of the JSON text in bytes
    /// @param timestamp Receive timestamp in microseconds
    void process_json_message(SendspinConnection* conn, const char* data, size_t len,
                              int64_t timestamp);

    /// @brief Processes a binary message from a connection
    /// Every binary message is role-bound, so this is dropped unless `conn` holds the admitted
    /// slot; see the admission gate in process_json_message() for why finishing the Noise
    /// handshake is not enough on its own.
    /// @param conn The connection the message arrived on
    /// @param payload Pointer to the raw binary data
    /// @param len Length of the binary data in bytes
    void process_binary_message(const SendspinConnection* conn, const uint8_t* payload, size_t len);

    // ========================================
    // State publishing
    // ========================================

    /// @brief Publishes the current client state to the specified connection
    /// @param conn The connection to publish to
    void publish_client_state(SendspinConnection* conn);

    // ========================================
    // Persistence & identity
    // ========================================

    /// @brief Loads or generates the static X25519 identity keypair via the persistence
    /// provider. Sets identity_ on success. Called once from start_server(), before the
    /// connection manager can hand the identity out to any connection.
    /// @return false if the stored key was corrupt/wrong-length or key generation failed (e.g.
    /// noise-c allocation failure); identity_ is left null in that case and the caller
    /// (start_server()) must not proceed. Never leaves identity_ set to an all-zero keypair.
    bool load_or_generate_identity();

    /// @brief Loads the last played server_id from persistence
    void load_last_played_server();

    /// @brief Persists the server_id as the last played server
    void persist_last_played_server(const std::string& server_id);

    // ========================================
    // Connection event handlers (called by ConnectionManager via friend access)
    // ========================================

    /// @brief Publishes the initial client state after handshake completes
    /// @param conn The connection that completed the handshake
    void on_handshake_complete(SendspinConnection* conn);

    /// @brief Queue an on_pairing_started notification for delivery from loop()
    /// Called by ConnectionManager while conn_ptr_mutex_ is held; the callback itself fires
    /// later from loop() so it runs unlocked. Main loop only.
    void note_pairing_started(const std::string& server_id);

    /// @brief Queue an on_pairing_succeeded notification for delivery from loop()
    /// Called by ConnectionManager on the main loop once the network thread's
    /// schedule_pairing_succeeded() event has been drained (see ConnectionManager::loop()).
    /// Main loop only.
    void note_pairing_succeeded(const std::string& server_id);

    /// @brief Queue an on_pairing_failed notification for delivery from loop()
    /// Same deferral as note_pairing_started. Main loop only.
    void note_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason);

    /// @brief Queue an on_display_pairing_pin notification for delivery from loop().
    /// Called by ConnectionManager while conn_ptr_mutex_ is held. Main loop only.
    void note_display_pin(const std::string& pin);

    /// @brief Queue an on_clear_pairing_pin notification for delivery from loop().
    /// Called by ConnectionManager while conn_ptr_mutex_ is held. Main loop only.
    void note_clear_pin();

    /// @brief Queue an on_open_pairing_window notification for delivery from loop().
    /// Called by ConnectionManager while conn_ptr_mutex_ is held. Main loop only.
    void note_open_pairing_window();

    /// @brief Queue an on_close_pairing_window notification for delivery from loop().
    /// Called by ConnectionManager while conn_ptr_mutex_ is held. Main loop only.
    void note_close_pairing_window();

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
    /// provider). Set by load_or_generate_identity() in start_server(); outlives every
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
    SendspinNetworkProvider* network_provider_{nullptr};
    SendspinPersistenceProvider* persistence_provider_{nullptr};
#ifdef SENDSPIN_ENABLE_PLAYER
    std::unique_ptr<PlayerRole> player_;
#endif
    /// In-memory pairing record store (PSK resolution, trust config). Set in start_server();
    /// outlives every connection the manager hands it out to.
    std::unique_ptr<RecordStore> record_store_;
    std::unique_ptr<SendspinTimeBurst> time_burst_;
#ifdef SENDSPIN_ENABLE_VISUALIZER
    std::unique_ptr<VisualizerRole> visualizer_;
#endif

    // 32-bit fields
    SendspinClientState state_{SendspinClientState::SYNCHRONIZED};

    // 8-bit fields
    /// Trust level of the active connection; written by on_handshake_complete() and reset by
    /// cleanup_connection_state(), both main loop only, so get_current_trust() needs no lock.
    ConnectionTrust current_trust_{ConnectionTrust::NONE};
    bool high_performance_held_for_time_{false};
    std::atomic<uint8_t> high_performance_ref_count_{0};
    bool started_{false};
};

}  // namespace sendspin
