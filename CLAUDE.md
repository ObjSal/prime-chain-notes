# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A Foundation **Passport Prime** app — a Rust binary crate with a **Slint** UI
on **KeyOS** — for **personal notes on the bitcoin blockchain**: compose text
on-device, seal it (XChaCha20-Poly1305, key derived from `GetAppSeed`) or
leave it public, embed it in OP_RETURN outputs of a transaction the app
builds and signs itself (P2TR key-path, BIP341/BIP340, pure Rust), and sync
via **bundles** — because Prime has no network, an online companion does all
scanning/broadcasting. Design + protocol: `../PLAN-chain-notes.md`; the
future chat sibling: `../FUTURE-chain-chat.md`.

A note tx spends from the app's own P2TR address back to itself; the address
history IS the notebook. Wipe recovery: everything re-derives from
`GetAppSeed` + a full chain rescan (proven in tests).

## Layout — two crates (wallet-core pattern)

```
notes-core/            # UI-free, host-testable: cargo test -p notes-core
  src/keys.rs          # FROZEN HKDF derivations: identity + encryption keys
  src/taproot.rs       # BIP341 tweak (ported from wallet-core)
  src/sign.rs          # BIP340 Schnorr (spec vectors), sighash.rs (BIP341)
  src/tx.rs            # tx model/serialization, fee estimator, coin selection
  src/envelope.rs      # PNTE || v1 || flags || note_id || seq/total (FROZEN)
  src/crypt.rs         # seal/open, SEAL_OVERHEAD=40 (cost estimator depends on it)
  src/bundle.rs        # SyncBundle JSON, extract_notes, compose_note, Identity
  examples/notes_cli.rs  # host CLI (device role) for the e2e scripts
src/main.rs            # app: screens, callbacks, state.json persistence
ui/{app.slint, callbacks.slint}
scripts/regtest-e2e.sh          # host-only e2e vs bitcoind -regtest
scripts/regtest-companion.sh    # companion-role helper (setup/bundle/broadcast/mine)
companion/index.html            # THE companion: sync-bundle builder + broadcaster
companion/viewer.html           # read-only on-chain notes viewer (?address=&network=; public text, private = placeholder)
companion/server.py             # static server + regtest via mempool-shaped /regtest/api/*
companion/tests/                # playwright: regtest (hermetic) + testnet4 (live)
vendor/{getrandom, security-api}  # KeyOS TRNG override + GetAppSeed API
```

## Invariants (do not break)

- **FROZEN strings**: HKDF salts `prime-chain-notes/key/v1`,
  `prime-chain-notes/enc/v1`, infos `identity/<attempt>`, `note-enc/v1`,
  and the PNTE envelope layout. Every confirmed note depends on them.
- **Pure-Rust only on device** (no C under armv7a-unknown-xous-elf).
  `rust-bitcoin` is a **dev-dependency only** — host tests cross-check our
  serialization/sighash/signatures against libsecp256k1.
- The estimator (`estimate_note_cost`/`estimate_vsize`) must stay
  byte-exact vs real signed txs — `cost_estimator_is_exact` enforces it.
- A payload counts as a note only if its tx **spends from the notes
  address** (spoof resistance) — companion sets `spends_from_self`.
- getrandom patch: after bumping deps re-run
  `cargo update getrandom@<ver> --precise 0.2.10` or the TRNG override
  silently drops out (check for "Patch … was not used" warnings).

## State & sync contract

- Compose fee tiers: 0 economy / 1 normal / 2 fast / **3 custom**. The
  rate field (`Compose.rate-text`) mirrors the selected tier's sat/vB;
  a manual edit flips the tier to 3 and `resolve_rate` parses the field
  (rejects non-finite/≤0/>100k). Rust never overwrites the field while
  tier == 3.
- Screens: 0 home · 1 notes · 2 note view · 3 compose · 4 confirm ·
  5 sync (ACTIONS only: import/export/scan + status) · 6 settings
  (network + chunk picker) — actions and preferences deliberately split.
- Networks: mainnet → testnet4 → signet → regtest (Settings cycle);
  testnet4/signet share the tb HRP. User-facing copy says "chain height",
  never "tip" (user decision — reads like a gratuity).
- QR transports (both verified optically via the sim's webcam): pending
  note renders its signed tx as a single QR (`set_view_qr`,
  ≤ MAX_QR_HEX_CHARS=4000; larger → file export) for the companion's
  camera; bundles come in via Sync "Scan bundle" → `open_qr_scanner` →
  `decode_scanned` (`CNB1 || deflate-raw(json)`, plain JSON tolerated) —
  the system scanner reassembles animated UR itself, and the companion's
  `ur.js` encoder is byte-identical to foundation-ur (cross-checked by
  `companion/tests/test_companion_qr.py` + the ur_encode/ur_decode
  examples).
- Chunk-size picker (Settings screen): Standard (DEFAULT_CHUNK=100000,
  Core v30 relay default) / 80 compat / Custom pills + bytes field
  (`Settings.chunk-*`). **Purely device-side** (user decision 2026-07-05):
  bundles carry no relay policy and any legacy `max_op_return_bytes`
  field is ignored on import. Custom validates to
  `[MIN_CHUNK=20, DEFAULT_CHUNK]` (inline label error). If an endpoint
  rejects an oversized note, the user picks 80 in Settings and
  recomposes. Changing it invokes `compose-changed` so a draft's cost
  line reprices immediately.
- `Location::User` `/.chain-notes/state.json` — notes (plaintext cache),
  UTXO ledger (updated on sign: inputs out, change in — unconfirmed
  chaining), fee tiers/tip/btc_usd from the last bundle, network.
- Import: first `*.json` (sorted) from `/chain-notes/inbox` on Internal,
  else Airlock (lazy mount, format-on-failed-mount, unmount after).
- Export: signed tx → `/chain-notes/outbox/<txid>.hex` on Internal +
  Airlock. `{"network":"regtest"}` seeded as state.json is enough to switch
  network for tests (serde defaults fill the rest).

## Log contract (grep targets for the UI test)

`cb: home balance=<sats> utxos=<n> tip=<h|none>` ·
`cb: refresh-notes n=<n>` ·
`cb: compose len=<n> private=<b> chunks=<c> fee=<f> vsize=<v> txid=<t> ok | err=<e>` (the UI test derives the applied sat/vB as fee/vsize) ·
`cb: sign-note id=<hex8> txid=<t> fee=<f> vsize=<v> internal=<ok|err> airlock=<ok|err>` ·
`cb: open-note id=<hex8> status=<s>` ·
`cb: import-bundle file=<f> loc=<l> notes=<n> new=<k> utxos=<m> tip=<h> ok | err=<e>` ·
`cb: export-pending n=<n> airlock=<ok|err>` ·
`cb: set-network <net>` ·
`cb: set-chunk-size <n|auto> ok | err=<msg>` ·
`cb: scan-bundle kind=<qr|ur> bytes=<n>` then `cb: import-bundle
src=scan-<kind> … ok` · `cb: scan-bundle cancelled | err=<e>`

## Build / test

```bash
nix develop ~/.foundation/sdk/current --command cargo test -p notes-core   # vectors + rust-bitcoin cross-check
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh # host e2e vs real bitcoind
nix develop ~/.foundation/sdk/current --command foundation sim              # run the app
../ui-automation/tests/chain-notes.sh   # full UI e2e (manages sim + bitcoind itself)
```

The UI test mirrors the sim's identity on the host: hosted `GetAppSeed` =
HMAC-SHA256(app-id bytes, master seed from `hosted_security_data.json`) —
see `../prime-bip85/NOTES.md` for provisioning. After editing
`[permissions]` in `app-config.toml`: `rm manifest.toml` first.

## Inherited gotchas

`ui/ui` and `resources/{fonts,images}` are symlinks into the SDK (+ copied
`resources/icons`) — required for `@ui/*` imports; the scaffold did not
create them. SDK `IconButton` drops taps (use TouchArea), overlays must
nest inside the root container, SDK TextArea can't scroll (compose uses the
text-editor's Flickable+TextInput pattern), keyboard-aware layout keeps all
compose controls in the top ~400px.
