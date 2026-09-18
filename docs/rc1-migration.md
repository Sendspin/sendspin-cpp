# Spec 1.0.0-rc1 migration plan

Working tracker for bringing this branch into conformance with the Sendspin specification at tag
`1.0.0-rc1` (spec commit `671a34d`). The branch last tracked the spec near commit `1ad1b67`
(2026-08-18). This file is temporary: delete it when the migration is complete.

Item IDs (A = handshake/transport, B = pairing, C = core messages, D = player, E = other roles)
come from a requirement-by-requirement audit of the current spec text against the code. Verify an
item against the current code before acting on it; line numbers drift as phases land.

## Decisions

- The persisted blob shapes stay as they are. The `static_delay` persistence key is NOT renamed
  or migrated; only wire names and the public API move to `output_delay`.
- `min_buffer_ms` and `required_lead_time_ms` are fixed values set in `PlayerRoleConfig`. The
  `send_ahead` field is parsed past but not consumed. Measured values are later work.
- Artwork channel config and visualizer `types`/`rate_max`/`spectrum` stay construction-time
  config. They are sent once, in the role's `client/state` object, instead of in `client/hello`.
- `VisualizerRole::request_format()` and `VisualizerFormatRequest` are deleted with no
  replacement.
- The optional dual-connection hold (a pairing connection alongside a playback connection) is
  not implemented; the single-slot fallback the spec allows stays.
- Pairing configuration (which methods are enabled, the static code, unpaired access, and the
  secrets themselves) is construction-time only: `RecordStore` reads it from the persistence
  provider at `start()` and never writes it back. With the management namespace gone the library
  has no runtime mutators for any of it, so a device changes its pairing policy by writing the
  blobs and restarting. A public runtime API for it is possible later work. Until one exists,
  the `pairing.md` "Unpaired Access" rule that a client which stops admitting unpaired access
  closes the connections relying on it with `client/goodbye` reason `pairing_required` cannot
  fire, because the setting cannot change while the client runs.
- Record eviction order is least recently used, which the spec leaves to the implementation.
  Recency is the order of `RecordStore::records_`, which `mark_record_used()` moves a touched
  record to the back of; no new field or timestamp is stored, and the order persists with the
  records themselves.
- Operator cancellation of a pairing window arrives through a new
  `SendspinClient::cancel_pairing_window()`, the counterpart to the existing
  `confirm_pairing_window()`. It is a runtime action, not pairing configuration, so it does not
  cross the construction-time rule above.

## Conformance oracle

aiosendspin `main` is an RC1 server. It tolerates legacy clients by default and logs each tolerated
violation through `flag_noncompliance`; `SendspinServer(allow_noncompliant_clients=False)` rejects
them instead. Tolerant mode can therefore mask non-conformance. Each phase exits when its
noncompliance lines are gone; the final gate is a clean strict-mode playback and pairing session.
The harness lives on the aiosendspin branch `kahrendt-rc1-harness`
(`scripts/run_encrypted_server.py`).

The server does not see client-side parse errors (for example `send_ahead` bytes reaching the
decoder), so the audit items stand on their own. Where the server and the spec text disagree, the
spec text wins and the disagreement is reported upstream.

## Baseline (phase 0, 2026-09-17, client at `708ec1f`)

Tolerant mode: Pairing PSK pairing, re-handshake onto the long-term PSK, role activation, FLAC
playback, time sync and metadata all worked. Strict mode rejected the client at the first
`client/hello` check. The server logged:

1. `client/hello declared player supported_commands, superseded by client/state` (D5)
2. `client/hello sent supported_pair_methods as a list`: `pairing.md` "client/hello pair-method
   descriptor" makes it an object keyed by method identifier (new item B13)
3. `Pairing PSK client/pair-finalize sent without client/pair-init`: the Pairing PSK flow MUST
   send `client/pair-init` immediately before `client/pair-finalize` (new item B14)
4. `initial client/state omitted required player timing fields` (D2/D3)
5. `client/state used the pre-rename 'static_delay_ms' key` (D2)
6. `client/state declared the pre-rename 'set_static_delay' command` (D2)
7. INFO `unrecognized pairing methods: dynamic_pin` (B5): code pairing is never offered
8. Not logged while tolerated: a second `client/hello` after the re-handshake (A6)

Also found: role messages arriving between `server/activate` and the main loop marking the
connection admitted are dropped (`requires_admitted_connection` in `src/client.cpp`; new item
C9). A one-shot `server/state` sent in that window is lost. A 9 second connect-to-hello gap on a
first-boot client did not reproduce and could not be attributed because host client logs have no
timestamps; the harness docstring shows how to stamp them at capture.

With artwork, visualizer or color enabled the server would additionally flag
`artwork@v1_support` in the hello, the `media_width`/`media_height` keys, visualizer stream
config in the hello, `stream/request-format`, and a missing artwork `client/state` object.

### The legacy switch

The server picks legacy or RC1 handling for the whole session from the `client/hello`. Any of
these puts it in legacy mode: `player@v1_support.supported_commands`, `artwork@v1_support`,
visualizer stream config in the hello, `supported_pair_methods` as a list. Legacy mode means:
fragment IDs 2/3, audio chunks without `send_ahead`, `stream/end` instead of `stream/clear` on
stream replacement, role state cleared with a null role object, hellos repeated after a
re-handshake, pairing that quiesces playback, legacy pairing rounds, no playback on the pairing
PSK. Removing the hello triggers flips all of these at once, so the client changes that depend
on them must land together (phase 3). Until then the binary transport can only interoperate in
legacy mode.

## Phases

Each phase is a series of reviewable commits with a green host suite (ASan and TSan, never run
concurrently: they share ports).

### Phase 1: deletions

- A9/B1: the `management/*` message family, `SendspinActivity::MANAGEMENT`, `src/management.h`,
  `tests/test_management.cpp`. Keep the `server/unpair` handling (`handle_unpair`), relocated.
- A8: the shared-PSK / record-mode storage variant in `record_store`, and the
  "record without a `server_id`" acceptance paths.
- `trust_level` in `client/hello`.
- B8: the persisted failure-counter escalation model, replaced by the round limit.
- B12: whatever `SendspinPairingConfig` fields lose their meaning. Reading an old blob must not
  fail.

Exit: tolerant-mode run unchanged from the baseline.

### Phase 2: fixes that do not depend on the legacy switch

- D2: `static_delay_ms` / `set_static_delay` become `output_delay_ms` / `set_output_delay` on the
  wire (both directions) and in the public API. Persistence key unchanged.
- D3 (fixed form): `min_buffer_ms`, `required_lead_time_ms` config fields sent in `client/state`.
- D6: reject a player format list that is empty or lacks both `flac` and `pcm`.
- B14: `client/pair-init` before `client/pair-finalize` in the Pairing PSK flow.
- C9: do not drop role messages between `server/activate` and admission.
- A3: parse `psk_category` from Noise message 1, scope the PSK lookup by it, treat a category
  miss as a lookup miss (Sentinel fallback) and an unknown category as a silent failure.
- A10: the Sentinel fallback itself (`connection.md` "Sentinel Fallback"): a `psk_id` lookup miss
  in the initial handshake completes message 2 with the Sentinel PSK instead of failing, so the
  server learns its credential no longer matches. A miss in a re-handshake and a failed
  stored-`server_id` post-match check stay silent failures. Lands with A3, whose category rule
  creates a new way to miss.
- A7: recognize `server/error` during the init phase and surface its reason.
- C1: `client/leave` message and a public entry point.
- C4: controller commands are not sent while the controller role is inactive.

Exit: baseline lines 3-6 gone in tolerant mode.

### Phase 3: the flip

Lands as one reviewed series; interop is verified only at its end, in strict mode. Phase 3a (the
binary transport and the post-re-handshake and activation behavior) and phase 3b (the hello and
the role `client/state` objects) have both landed.

Done (3a):

- A6: no `server/hello` / `client/hello` after a re-handshake; the next message is
  `server/activate`, and the client starts no application message until it arrives.
- A4/A5: fragmentation is message ID `1` with a flags byte (bit 1 first, bit 0 last, bits 2-7
  zero), `orig_type` only on the first fragment. Malformed sequences close the connection: first
  while in flight, non-first with none in flight, non-fragment while in flight, nonzero reserved
  bit, `orig_type` of `1`. IDs 2-3 are reserved, and a fragmented message claiming one is
  discarded without buffering.
- D1: audio chunks carry `send_ahead` (big-endian uint32) at bytes 9-12; audio starts at byte 13.
  The value is parsed past, not consumed.
- A1/B11: `activities_allowed()` implements the category-to-activities table as written, so a
  long-term PSK no longer admits `['pairing']` and the Pairing PSK admits the empty set,
  `['playback']` and `['playback', 'pairing']` under unpaired access. A combined
  `['playback', 'pairing']` activate routes the pairing entry path with its playback side left
  running, and pairing no longer quiesces playback.

Done (3b):

- D5: `supported_commands` leaves `player@v1_support`; `client/state` always reports `volume`,
  `mute` and (when adjustable) `set_output_delay`.
- B13: `supported_pair_methods` as an object keyed by method identifier.
- C3: `ClientStateMessage` gains `artwork` and `visualizer` objects, built per role like the
  player's `build_state_fields`.
- E7/E8: artwork channels move from `artwork@v1_support` (deleted) to `client/state`, with the
  RC1 key names.
- E3/E4/C2: visualizer `types`/`rate_max`/`spectrum` move to `client/state`;
  `visualizer@v1_support` keeps only `buffer_capacity`; `stream/request-format`,
  `StreamRequestFormatMessage`, `request_format()` and `VisualizerFormatRequest` are deleted.
- E1/E2: metadata and color `server/state` objects are full state. Drop the tri-state delta types
  and cross-message merging; an included object replaces the current or pending state. An omitted
  `progress` clears the position.

Exit: strict-mode run pairs (Pairing PSK), plays and shows metadata with no rejection.

### Phase 4: artwork binary format

Done:

- E6: artwork announce / part / cancel transfers with `total_size`, one transfer in flight per
  role, the 65519 byte message cap, and the malformed-message and malformed-sequence closes. A
  zero `total_size` completes immediately and clears the image. An announce or a cancel discards
  the channel's pending image, which the per-channel slot epochs carry out.

Exit: strict-mode run with the TUI client (artwork, visualizer, color enabled).

### Phase 6: new behavior

- C5: when a later `server/activate` removes a role, stop its output, clear its buffers, discard
  its `server/state` and any pending scheduled update. Today `cleanup()` runs only on disconnect.
- D4: optional player `format` preference in `client/state`, if wanted.
- C7: `server_transmitted` on `stream/start` / `stream/clear`, only if something consumes it.

### After

- Rebase the `source-role` branch: `client-stream/*` names, announced formats, fresh `start`
  required after `client-stream/end`.
- Run the docs-sync, house-patterns, embedded-review and test-standards reviews, then update the
  ESPHome hub.

## Residual gaps

Known and accepted for now, recorded so they are not rediscovered as surprises:

- Binary messages (audio, artwork, visualizer frames) that arrive between `server/activate` and
  admission are still dropped; only the JSON half of that window is held and replayed. A player
  resynchronizes from the next chunk, so the cost is bounded, but a stream's first chunks can be
  lost this way. For artwork the window is now before the stream exists at all (the stream starts
  from the `client/state` the client sends once admitted), so no transfer can be torn by it.
- The artwork role refuses an image whose announced `total_size` exceeds the channel's configured
  `ImageSlotPreference::max_image_bytes` (128 KiB by default), tracking the transfer to its end
  with its bytes dropped. `roles/artwork/v1.md` "Artwork (Binary)" allows this (it is the
  "unavailable client" path) but sets no cap of its own, so a server that encodes an image larger
  than the channel's budget sees the channel keep its previous image rather than an error.
- A device that offers `dynamic_pairing_code` without implementing the pairing-window gesture
  (`pairing_window_supported` false) has no way to clear a standing round limit, which
  `pairing.md` "Rounds" says only a deliberate operator action clears. Its attempts then sit at
  `client/pair-pending` until the server cancels them. The library logs loudly when it reaches
  that state; the fix is for such a device to implement the gesture callbacks.
- `SendspinClient::send_text()` gained a required role-family argument when role-originated sends
  started gating on activation. It is a public method under "Role services", so a consumer calling
  it directly must pass the role the message belongs to.
- `SendspinImageFormat::BMP` is still offered by the public artwork config, but
  `roles/artwork/v1.md` "client/state artwork object" defines only `'jpeg' | 'png'`, and a server
  flags a client that declares it. The enumerator survives only so a consumer that names it still
  compiles; a client that configures a BMP channel is not conformant. Remove it with the next
  public API break.
- `PlayerRoleConfig::required_lead_time_ms` is `std::optional<uint16_t>`: unset reports the
  pipeline-derived lead, a value overrides it. A consumer that assigned a plain integer still
  compiles; one that read the field needs `value_or`.
- `VisualizerRoleConfig` splits into `support` (buffer capacity) and `stream` (types, rate cap,
  spectrum), so a consumer setting `config.support.types` moves to `config.stream.types`.
  `VisualizerRole::request_format()` and `VisualizerFormatRequest` are gone with no replacement.
- `MetadataRoleListener::on_metadata()` and `ColorRoleListener::on_color()` keep their signatures
  and state structs, but each call now carries the server's full state: a field the server left
  out of that message is absent rather than held over from an earlier one, and a metadata state
  without `progress` reports no position. A consumer that relied on the old carry-over sees
  fields it used to keep go empty.

## Verified conformant (no work)

The controller role, visualizer binary layouts (IDs 16-20), metadata progress math and
scheduled-update gating, the `client/goodbye` reason set, the 30 second provisional timeout, the
activity-rank arbitration and last-playback tiebreak, the stored-`server_id` post-match check,
arrival time taken after decrypt and reassembly, `available: true` gated on time-filter
convergence, `stream/clear` buffer discard, mid-stream format switches, and, since phase 3a, the
fragmentation wire format, the audio chunk header, the post-re-handshake sequence and the
category-to-activities table.
