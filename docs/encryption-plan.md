# Sendspin Encryption - Implementation Gameplan

Status: **implemented** (originally on branch `encryption`; re-implemented on this
branch as a state-port onto the nursery/inbox architecture - see the note below).

> **State-port status.** This document describes the plan as written on the original
> `encryption` branch. The current branch (`claude/encryption-rebase-strategy-*`) re-implements
> that same feature set as a state port onto `main` after main gained a substantially rewritten
> connection lifecycle (the Inbox/nursery rework, PRs #84-#97) that `encryption` predates.
> Completed so far, against the phase numbering below: Phase 1 (crypto and dependency
> foundation), Phase 2 (identity records and persistence-provider redesign), Phase 3 (Noise
> transport wired into the connection layer), Phase 4 (admission/trust/nursery lifecycle),
> Phase 5 (pairing flows, management suite, PIN state machine), and Phase 6 (public API
> surfacing, config completion, example polish, and this doc pass). What remains unported is
> scoped to hygiene-gate parity (the original branch's later `fix:`/`refactor:` commits, e.g.
> the include-what-you-use and cppcheck gates) and ESP-IDF hardware bring-up/validation.

This document is the master plan for bringing `sendspin-cpp` up to the merged
[Sendspin spec PR #84 "Add encryption support"](https://github.com/Sendspin/spec/pull/84).
It is meant to be executed across many sessions, one phase (or sub-phase) at a time. Each
phase below is written to be self-contained enough that a future session can pick it up,
read the linked spec sections, and implement it.

Breaking changes are explicitly acceptable. We are not maintaining wire compatibility with
the pre-encryption protocol.

---

## 1. Scope decisions (locked in this planning session)

| Area | Decision | Notes |
|---|---|---|
| **Core Noise encryption** | In scope | `KKpsk2`, both cipher suites, Sentinel + long-term PSK, re-handshake |
| **Pairing - Pairing PSK** | In scope | The only client-mandatory pairing method; no PAKE |
| **Pairing - PIN (dynamic/static)** | **Implemented** (Phases 8a-8d) | Uses CPace PAKE; see [Phase 8](#phase-8---pin-pairing-cpace) |
| **Management suite** | In scope | records, pairing-config, record-mode, storage accounting, `server/unpair` |
| **Pairing-record store + trust model** | In scope | Needed by both pairing and management |
| **Identity (Curve25519 keypair)** | In scope | `client_id` becomes base64url(pubkey) |
| **Persistence provider** | Expand to a **typed record API** | Platform owns storage; library calls typed methods |
| **Integration testing** | Against **aiosendspin** reference server | Plus unit tests / known-answer vectors written throughout |
| **Entangled protocol drift** | In scope | `server/activate`, activities/`active_roles`, role versioning, goodbye reasons - these are inseparable from the new handshake |
| **Non-entangled drift** (e.g. controller `seek`/`seek_relative`) | Opportunistic | Fold in where cheap; otherwise a small separate cleanup |

### Out of scope for this effort (deferred)

PIN pairing (dynamic + static), the CPace PAKE, the PIN-pairing lockout state machine,
the pairing-window operator-gesture flow, and out-channel (display/speaker) PIN emission.
Management's `static_pin` / `dynamic_pin` config branches simply return `invalid` (and are
omitted from `get-pairing-config`) until that phase lands - which is spec-compliant for a
client that does not implement those methods.

---

## 2. Dependency & crypto strategy

### noise-c covers the entire Noise layer

- **ESP32**: [`esphome-libs/noise-c`](https://github.com/esphome-libs/noise-c) - a PlatformIO/ESP-IDF
  port with `idf_component.yml`, `CMakeLists.txt`, `library.json`. MIT licensed.
- **Host**: same library (it has a plain CMake build) or upstream `rweather/noise-c`. Prefer the
  esphome-libs fork on both platforms for a single, patchable source of truth (we already keep
  local patches against esphome-libs forks - see the esp_peer ECDSA patch memory).

What noise-c gives us out of the box:

- Full handshake/cipher/symmetric/dh/hash state machines (`handshakestate.h`, etc.).
- The `KK` pattern + `pskN` modifiers → `Noise_KKpsk2_25519_ChaChaPoly_SHA256` and
  `Noise_KKpsk2_25519_AESGCM_SHA256` are both constructible via `noise_protocol_name_to_id`.
- Reference cipher backends: **ChaChaPoly**, **AES-GCM** (software rijndael), **Curve25519**,
  **SHA-256** - all bundled (`src/backend/ref/`, `src/crypto/`).
- Bundled **SHA-512** (`src/crypto/sha2/sha512.c`) and **X25519** (`src/crypto/x25519/`) - these
  are what an eventual CPace build reuses.
- `noise_handshakestate_set_prologue`, custom per-message payload read/write, and a randstate
  CSPRNG abstraction.

Optional later optimization: on ESP, route AES-GCM through mbedTLS hardware acceleration instead
of noise-c's software rijndael. Not required for correctness.

### The one genuinely hard piece (deferred): CPace

CPACE-X25519-SHA512 has **no clean embedded C library**. Correcting an early assumption in
this plan: CPACE-X25519-SHA512 **does require Elligator2**. The CPace generator is produced by
hashing the CPace transcript inputs and mapping the resulting digest onto the curve with the
Elligator2 map, which needs field arithmetic over GF(2^255-19); it is not merely a hashed
u-coordinate. So the build needs: SHA-512 + HMAC-SHA-512 (MCF tags) + X25519
scalar-mult-with-verify + Elligator2 field arithmetic (implemented in `src/crypto/field25519.h`).
Build it directly on **noise-c's bundled X25519 + SHA-512** (uniform across ESP/host, no new
dependency), validated byte-for-byte against the aiosendspin reference and the IETF draft test
vectors. mbedTLS is a
viable source of these primitives on ESP only (not on host); libsodium would be a new dependency
and is unnecessary.

### New small crypto/util primitives we must add (Phase 0)

- **base64url** encode **and** decode, no padding. Current `platform/base64.h` only *decodes*
  the standard alphabet - no encoder, no URL-safe (`-`/`_`) variant. Needed everywhere IDs/PSKs
  appear on the wire (43-char keys, 86-char MCF tags).
- **SHA-256 one-shot** helper (via noise-c hashstate or mbedTLS) for `psk_id` and PIN derivation.
- **Sentinel PSK** constant + its precomputed `psk_id` (both published constants in the spec).
- **CSPRNG** wrapper for generating ephemeral material, `long_term_psk`, and nonces.

---

## 3. Architecture deltas (what fundamentally changes)

1. **Framing inverts.** Today: text frame = JSON, binary frame = audio. New: after the Noise
   handshake, **every** WebSocket frame is a binary Noise transport ciphertext. After AEAD
   decryption the first plaintext byte is the message type; **type `0` = JSON body**. Cleartext
   text frames exist only for the three pre-transport handshake messages (`client/init`,
   `server/init`, `noise/handshake`).
2. **A binary send path must be created.** `SendspinConnection` currently has *no*
   `send_binary_message()` - all sends are text. This is the single biggest transport-layer gap.
3. **`client_id` / `server_id` become public keys.** base64url(Curve25519 pubkey), 43 chars.
   The library generates and persists its static keypair. `SendspinClientConfig::client_id` (a
   free-form string / MAC today) goes away as an input.
4. **`server/hello` shrinks; `server/activate` is new.** The old discovery/playback
   `connection_reason` is replaced by `activities` (`management`/`playback`/`pairing`) +
   `active_roles`. Admission between competing servers is decided by activity priority.
5. **Trust model.** `trust_level` (`user`/`none`) gates Management; which PSK matched during the
   handshake constrains the activity sets a server may legitimately declare.
6. **Persistence grows from 2 values to a record store.** Keypair + N pairing records + pairing
   config + (deferred) lockout counters. Provider becomes a typed API.

The transport layer has clean single choke points for in-place encrypt/decrypt on all four
connection variants (ESP/host × server-conn/client-conn). This codebase is the **Sendspin client
only** → it is **always the Noise responder**, regardless of who opened the WebSocket. See
[`docs/internals.md`](internals.md) and Phase 2 for the exact intercept locations.

---

## 4. Phase plan

Dependencies flow top-to-bottom. Phases 0-2 are strictly sequential. Phases 3-6 mostly build on
2 and can be interleaved but are listed in the recommended order. Phase 7 is finishing work.
Phase 8 is the deferred PIN/CPace effort.

### Phase 0 - Crypto & dependency foundation

**Goal:** noise-c linked into both builds; core crypto helpers + KATs in place; no protocol
changes yet.

- Add noise-c to host build (`cmake/host.cmake` FetchContent) and ESP build
  (`idf_component.yml` dependency + `cmake/sources.cmake`/`CMakeLists.txt` REQUIRES). Gate behind
  a single always-on switch initially; no per-role gating.
- Add `platform/crypto.h` (or extend `base64.h`): base64url encode/decode (no padding), SHA-256
  one-shot, HMAC stub (for later), CSPRNG wrapper.
- Add `src/crypto/` (new): Sendspin-specific constants - Sentinel PSK + `psk_id`, the
  `psk_id = base64url(SHA-256("sendspin-psk-id-v1" || PSK))` derivation, suite name strings.
- **Tests/KATs:** Sentinel PSK & its `psk_id` match the spec constants; `psk_id` derivation
  vector; base64url round-trips; an in-process `KKpsk2` handshake (noise-c as both initiator and
  responder) succeeds for **both** suites and produces matching transport keys.

**Done when:** both platforms build with noise-c; all Phase-0 KATs pass; `tests/` has a
`test_crypto.cpp`.

**Spec:** [Encryption](https://github.com/Sendspin/spec#encryption),
[Pre-Shared Key](https://github.com/Sendspin/spec#pre-shared-key),
[Cipher Suites](https://github.com/Sendspin/spec#cipher-suites).

---

### Phase 1 - Identity & persistence-provider redesign

**Goal:** the device has a persistent cryptographic identity and a working (host test) record
store, decoupled from any networking.

- Static keypair: generate-if-absent on first boot, persist, expose
  `client_id = base64url(public_key)`.
- Redesign `SendspinPersistenceProvider` into a **typed record API**:
  - keypair: `load_static_keypair()` / `save_static_keypair()`.
  - records: enumerate / add / remove by `psk_id`; each record = `{psk_id, server_id?, psk,
    used}`; distinguish stored-pubkey vs shared-PSK records.
  - pairing config: `pairing_psk` (enabled + secret), `record_mode.psk_id`, `unpaired_access`,
    (deferred) `static_pin`/`dynamic_pin`.
  - last-playback `server_id` (replaces today's FNV-1 hash in `connection_manager`).
- In-library record store object that holds the in-memory view and calls the provider; `psk_id`
  lookup over the set (used by the handshake to pick a PSK).
- `SendspinClientConfig` changes: drop `client_id` input; add cipher-suite preference; provision
  a default Pairing PSK / record_mode shared record.
- Provide a reference host persistence provider (file-backed) for examples/tests.

**Tests:** record store round-trips through a mock provider; `psk_id` lookup picks the right PSK
including Sentinel and shared-PSK fallback; keypair persists across "reboots."

**Done when:** a host harness boots, generates+persists a keypair, prints its `client_id`, and a
unit test exercises the record store + lookup.

**Spec:** [Identities](https://github.com/Sendspin/spec#identities),
[Records](https://github.com/Sendspin/spec#records),
[Pre-Shared Key](https://github.com/Sendspin/spec#pre-shared-key).

---

### Phase 2 - Noise transport integration (the core)

**Goal:** an encrypted channel exists end-to-end; against aiosendspin the client completes a
Sentinel-PSK handshake and exchanges encrypted `server/hello` ↔ `client/hello` and decodes
audio. **This is the keystone phase.**

- **Add `send_binary_message()`** to `SendspinConnection` + all four platform implementations
  (ESP server/client, host server/client). This is the missing path.
- **Cleartext handshake state machine** (responder):
  `client/init` (text) → `server/init` (text) → `noise/handshake` msg1 (text, server→client) →
  `noise/handshake` msg2 (text, client→server) → switch to transport mode.
  - **Prologue = exact wire bytes of `client/init` ‖ `server/init`.** Retain the *exact*
    serialized bytes (do not re-serialize) for both.
  - **PSK selection subtlety:** in `KKpsk2` the PSK is mixed only in msg2, so msg1's encrypted
    payload (the `psk_id`) is readable with static keys alone - but noise-c requires a PSK be set
    *before* `start`. Two viable approaches, decide during implementation:
    1. **Two-handshake trick (no patch):** read msg1 with a throwaway handshakestate (placeholder
       PSK) to extract `psk_id`; since msg1 is PSK-independent, discard it, build a second
       handshakestate with the real PSK, read the same msg1 bytes, then write msg2.
    2. **Small noise-c patch** allowing the PSK to be set after `start` but before msg2.
- **Framing switch:** post-handshake, outbound = `[type byte][payload]` → Noise encrypt → binary
  frame; inbound = binary frame → in-place Noise decrypt → first byte is type (`0` = JSON →
  dispatch as today's "text" path; others → binary role dispatch). Intercept at the choke points
  identified in the transport map (after `commit_receive_buffer`, before
  `dispatch_completed_message`; and in each platform's send method).
- **App-level fragmentation** (message types `2` fragment-more / `3` fragment-end) for
  transport plaintexts larger than `MAX_TRANSPORT_PLAINTEXT` = 65519 bytes (Noise's 65535 frame
  cap - 16-byte tag; the leading 1-byte message type is carried inside this plaintext budget,
  not subtracted from it). Receive-side reassembly is
  mandatory (artwork/large metadata); send-side only triggers for oversized client messages.
  Keep this distinct from WebSocket-level fragmentation already handled in `connection.cpp`.
- **Failure handling:** any handshake-phase failure closes the WebSocket silently; apply ~30 s
  per-step timeouts.
- Gate `client/hello` send on a new `noise_handshake_complete_` flag (analogous to
  `client_hello_sent_`).

**Tests:** against aiosendspin (Sentinel PSK) the handshake completes for both suites; encrypted
`server/hello`/`client/hello` round-trip; an audio frame decrypts and decodes. Unit test for
fragmentation reassembly.

**Done when:** encrypted playback works against the reference server on a Sentinel/unpaired or
pre-provisioned-PSK session.

**Spec:** [Communication](https://github.com/Sendspin/spec#communication),
[Binary Message ID Structure](https://github.com/Sendspin/spec#binary-message-id-structure),
[Fragmentation](https://github.com/Sendspin/spec#fragmentation),
[Prologue](https://github.com/Sendspin/spec#prologue),
[Failure Handling](https://github.com/Sendspin/spec#failure-handling).

---

### Phase 3 - New post-handshake protocol flow (entangled drift)

**Goal:** the client reaches the operational/playback state via the new message flow.

- New/changed messages: `server/hello` (now just `name`); `client/hello` (add `trust_level`,
  `unpaired_access`, `supported_pair_methods`; versioned support objects `player@v1_support`,
  etc.; `client_id` moves out of hello into `client/init`); `server/activate` (`activities`,
  `active_roles`, `selected_pair_method`).
- Replace `SendspinConnectionReason` (discovery/playback) everywhere with the activities +
  `active_roles` model. Consult `active_roles` before sending any role state/command.
- Role versioning fixes (`visualizer@_draft_r1` → `visualizer@v1`); confirm all role version
  strings match the spec.
- Gate the initial `client/state` + `client/time` on receipt of the first `server/activate`.
- Expand `SendspinGoodbyeReason` (add `unauthorized`, `pairing_required`, `concurrent_attempt`,
  `unpaired`).
- Opportunistically: controller `seek`/`seek_relative` + `seek_max_ms`, and any other small
  field drift noticed while in these files.

**Done when:** against aiosendspin the client progresses
handshake → `server/hello` → `client/hello` → `server/activate` → `client/state` → time sync →
playback on a paired (or unpaired-access) session.

**Spec:** [Server → Client: server/activate](https://github.com/Sendspin/spec#server--client-serveractivate),
[client/hello](https://github.com/Sendspin/spec#client--server-clienthello),
[Communication](https://github.com/Sendspin/spec#communication).

---

### Phase 4 - Admission, multi-server arbitration, trust, re-handshake

**Goal:** correct behavior with competing servers, trust enforcement, and in-band key rotation.

- Activity-priority admission (`management` > `playback` > `pairing` > empty); provisional
  connections until the first `server/activate`; 30 s provisional timeout; last-playback
  `server_id` matching for the empty-activities tiebreak; in-flight pairing is not displaced.
- Displacement / rejection paths emit the correct `client/goodbye` (`another_server`,
  `concurrent_attempt`) or `pair/abort` (`concurrent_attempt`) reasons.
- Trust enforcement: validate the matched-PSK category against the declared activity set (the
  spec's PSK→allowed-activities table); `management` requires a Sendspin (long-term) PSK match.
  Inadmissible `server/activate` → close with `unauthorized` / `pairing_required`.
- **In-band re-handshake:** the two `noise/handshake` messages travel as binary frames under the
  current transport keys; new prologue = prior handshake hash `h`; swap keys without closing the
  socket; then resume `server/hello` → `client/hello` → `server/activate`. Used for trust
  promotion after pairing and for session-key rotation.

**Tests:** arbitration decision-table unit tests; re-handshake (trust promotion) against
aiosendspin after a pairing exchange.

This phase reworks much of `connection_manager.{h,cpp}` (today's handoff logic is built around
the discovery/playback reason and an FNV hash).

**Spec:** [Multiple servers](https://github.com/Sendspin/spec#multiple-servers),
[Re-handshake](https://github.com/Sendspin/spec#re-handshake),
[server/activate admissibility](https://github.com/Sendspin/spec#server--client-serveractivate).

---

### Phase 5 - Pairing (Pairing-PSK method)

**Goal:** a Sentinel/unpaired session can be promoted to a trusted long-term pairing with no PAKE.

- Advertise `pairing_psk` in `supported_pair_methods`; handle the pairing `server/activate`
  (`activities=['pairing']`, `active_roles=[]`, `selected_pair_method=pairing_psk`).
- Flow: client generates a `long_term_psk` (CSPRNG) → `client/pair-finalize(long_term_psk)` →
  `server/pair-finalize` → persist the pairing record → server re-handshakes to the new PSK
  (Phase 4 machinery). Entering/leaving pairing quiesces the connection like an
  `external_source` transition.
- Unpaired-access toggle + Sentinel `['playback']` admission.
- `pair/abort` send/receive handling for the PSK flow.

**Done when:** end-to-end pairing via Pairing PSK against aiosendspin; a subsequent reconnect
authenticates with the long-term PSK and reaches `management`/`playback` trust.

**Spec:** [Pairing](https://github.com/Sendspin/spec#pairing),
[Pairing PSK Flow](https://github.com/Sendspin/spec#pairing-psk-flow),
[Unpaired Access](https://github.com/Sendspin/spec#unpaired-access).

---

### Phase 6 - Management suite + `server/unpair`

**Goal:** a paired (`user`-trust) server can administer the device.

- `management/*` request → single `management/result` (at-most-one-in-flight; order-matched).
- `list-records`, `add-record`, `remove-record` (incl. "can't remove a record referenced by
  `record_mode`" and "removing own record closes session" rules).
- `get-pairing-config` / `set-pairing-config` (patch semantics): `pairing_psk`, `record_mode`,
  `unpaired_access` implemented; `static_pin` / `dynamic_pin` objects **absent** and writes to
  them return `invalid` until Phase 8.
- `record_mode` fallback logic (stored-pubkey record by default; shared-PSK fallback on storage
  exhaustion).
- Storage accounting (`free`/`capacity`/`cost_*`) - emit if the provider reports bounded storage.
- `server/unpair` handling, including the shared-PSK record protection rule and the `trust_level
  == none` ignore rule.
- Trust gating: `management/*` outside a `management`-activity session → `permission_denied`.

**Done when:** a paired server can list/add/remove records and toggle config against the device;
`server/unpair` drops the record and disconnects with reason `unpaired`.

**Spec:** [Management](https://github.com/Sendspin/spec#management),
[Records](https://github.com/Sendspin/spec#records),
[Pairing Config](https://github.com/Sendspin/spec#pairing-config),
[server/unpair](https://github.com/Sendspin/spec#server--client-serverunpair).

---

### Phase 7 - Surfacing, examples, bindings, docs

**Goal:** the new capabilities are usable and documented.

- New `SendspinClientListener` callbacks: pairing lifecycle, unpaired-access state, trust changes.
- Examples (`basic_client`, `tui_client`): show `client_id`, drive Pairing-PSK pairing, use the
  file-backed persistence provider.
- Python bindings: surface identity, pairing, and the typed persistence hooks.
- Docs: rewrite the handshake/transport sections of `docs/internals.md` and
  `docs/integration-guide.md`; document the new persistence-provider contract.

---

### Phase 8 - PIN pairing (CPace)

**Status (update): implemented in Phases 8a-8d** (CPace primitive, dynamic PIN, static PIN +
management PIN config, and a state-machine integration test harness). The notes below are the
original plan; corrected where it diverged from what was built.

- Implement **CPACE-X25519-SHA512** on noise-c's bundled X25519 + SHA-512 (+ add HMAC-SHA-512).
  This **requires Elligator2** (the generator maps a hashed digest onto the curve). Validate
  against the aiosendspin reference and IETF draft vectors.
- Dynamic PIN: `commit_B`/`nonce_B`/`nonce_A`, PIN derivation from `h`, out-channel emission
  hooks (new listener callbacks for display/speaker).
- Static PIN: pairing-window operator-gesture flow, fixed PIN.
- PIN-pairing **lockout**: persisted per-method failure counter, terminal lockout at 10, exit via
  local action or `set-pairing-config`.
- Enable the `static_pin` / `dynamic_pin` branches of `get`/`set-pairing-config` (Phase 6 left
  them returning `invalid`).

**Spec:** [Dynamic PIN Pairing Flow](https://github.com/Sendspin/spec#dynamic-pin-pairing-flow),
[Static PIN Pairing Flow](https://github.com/Sendspin/spec#static-pin-pairing-flow),
[PAKE](https://github.com/Sendspin/spec#pake),
[PIN-Pairing Lockout](https://github.com/Sendspin/spec#pin-pairing-lockout).

---

## 5. Cross-cutting concerns (apply to every phase)

- **Threading:** the Noise handshake runs on the network thread (ESP httpd worker / IXWebSocket
  thread); record-store mutations and user callbacks must stay on the main loop, matching the
  existing deferred-event pattern in `client.cpp`/`connection_manager.cpp`.
- **Memory placement:** Noise transport buffers and the record store should honor the
  `MemoryLocation` (PSRAM vs internal) conventions; the existing `json_arena` interacts with the
  decrypt-then-parse path.
- **Exact-bytes prologue:** retain the literal serialized `client/init` and `server/init` bytes;
  do not reconstruct them.
- **Both suites always:** every handshake/transport test runs `ChaChaPoly` and `AESGCM`.
- **Keep `#ifdef` discipline:** per `CLAUDE.md`, role gating lives only in `cmake/sources.cmake`
  and the client dispatch points. Encryption is not role-gated - it's always on.
- **License headers** on all new files; run pre-commit (clang-format v18, markdownlint).

## 6. Key open questions / risks to revisit

1. **noise-c PSK-after-start:** confirm during Phase 2 whether the two-handshake trick is
   clean enough or a small noise-c patch is warranted (we maintain forks already).
2. **aiosendspin readiness:** confirm the reference server actually implements the merged
   encrypted spec before relying on it for Phase 2+ integration.
3. **AES-GCM performance on ESP:** noise-c's software rijndael may be slow; consider an mbedTLS
   hardware-accelerated backend if the AESGCM suite is preferred on-device.
4. **Storage budget on ESP:** the record store + keypair + pairing config must fit the platform's
   NVS/preferences budget; coordinate the typed provider API with ESPHome's storage limits.
