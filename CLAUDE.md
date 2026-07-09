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
  src/dm.rs            # directed notes: static-static x-only ECDH + HKDF (FROZEN)
  src/bundle.rs        # SyncBundle JSON, extract_notes (+_watch, key-less), compose_note, Identity
  examples/notes_cli.rs  # host CLI (device role) for the e2e scripts
src/main.rs            # app: screens, callbacks, state.json persistence
ui/{app.slint, callbacks.slint}
scripts/regtest-e2e.sh          # host-only e2e vs bitcoind -regtest
scripts/regtest-companion.sh    # companion-role helper (setup/bundle/broadcast/mine)
companion/index.html            # THE companion: sync-bundle builder + broadcaster
companion/viewer.html           # read-only on-chain notes viewer (?address=&network=; public text, private = placeholder)
companion/note.html             # single-note permalink page (?address=&network=&note=<hex8>)
companion/chain-scan.js         # shared by viewer/note: esplora scan + PNTE envelope JS port + card renderer
companion/server.py             # static server + regtest via mempool-shaped /regtest/api/*
companion/tests/                # playwright: regtest (hermetic) + testnet4 (live)
vendor/{getrandom, security-api}  # KeyOS TRNG override + GetAppSeed API
```

## Invariants (do not break)

- **FROZEN strings**: HKDF salts `prime-chain-notes/key/v1`,
  `prime-chain-notes/enc/v1`, `prime-chain-notes/dm/v1`, infos
  `identity/<attempt>`, `note-enc/v1`, `dm-enc/v1`, the PNTE envelope
  layout (flags bit0 private, bit1 directed), and the directed-note AAD
  `sender_x(32) || recipient_x(32) || note_id(4)`. Every confirmed note
  depends on them. Directed-private key = HKDF(dm/v1,
  x(my_tweaked_seckey · lift_x(peer_output_x))) — symmetric both ways,
  frozen vector in `tests/vectors.rs`.
- **Pure-Rust only on device** (no C under armv7a-unknown-xous-elf).
  `rust-bitcoin` is a **dev-dependency only** — host tests cross-check our
  serialization/sighash/signatures against libsecp256k1.
- The estimator (`estimate_note_cost`/`estimate_vsize`) must stay
  byte-exact vs real signed txs — `cost_estimator_is_exact` enforces it.
- A payload counts as an **OWN** note only if its tx **spends from the
  notes address** (spoof resistance — companion sets `spends_from_self`).
  A PNTE tx that instead **pays** the address is a **RECEIVED** note,
  always shown `from <sender>` (first taproot input prevout — unforgeable),
  never as an own note; own and received chunk buckets never merge (keyed
  by note_id × origin/sender), so a pays-me tx reusing an own note_id
  cannot contaminate it. Directed-note txs: OP_RETURNs, then a
  DUST_LIMIT=330 output to the recipient, then change — the app's UTXO
  ledger takes change at vout `chunks + 1` for directed notes.
- **Gift amount (variable recipient value) — SHIPPED.** `notes-core`
  exposes variable-amount directed compose: `compose_directed_note_with_change_amount`
  / `compose_directed_note_exact_amount` (and the `build_note_tx_*` layer's
  `recipient_amount: u64` param), where the recipient output carries
  `recipient_amount` sats instead of a hardcoded dust — validated
  `>= DUST_LIMIT`. Both this Prime app and the chain-notes-app peer ship it
  end-to-end: a collapsible **"Gift · N sats"** panel on directed compose
  (default/min = dust 330, live cost). Here the wiring is: `Compose.gift-sats`
  / `Compose.gift-expanded` (callbacks.slint) → `resolve_gift(directed, text)`
  in `src/main.rs` (floors at DUST_LIMIT) → the cost line/fee sufficiency size
  off `gift`, and `compose_continue` calls
  `compose_directed_note_with_change_amount(…, gift, None, …)`. `note.sent`
  (= the gift) drives the cost line, the confirm summary, and the
  `gift=<n>` field on the `cb: compose` log line. Self-notes have no
  recipient output (`gift = 0`, unused). notes-core is a **local path
  crate** here (`members = [".", "notes-core"]`), so no pin bump was needed;
  the additive `_amount` variants were already present. Keep old callers
  byte-identical.
- getrandom patch: after bumping deps re-run
  `cargo update getrandom@<ver> --precise 0.2.10` or the TRNG override
  silently drops out (check for "Patch … was not used" warnings).

## State & sync contract

- Compose recipient: set ONLY by the contacts picker (`to-address` empty
  = self-note; a valid address = **directed note**: dust output + `to=`
  in the log; private requires a taproot recipient, sealed via dm.rs
  ECDH). A small `to-label` line under the header shows the target; the
  recipient clears after signing so it can't leak into the next note.
  Cost line appends "+ <gift> sats to recipient" (the gift amount, see
  the gift-amount invariant; default/min dust 330). compose-changed's
  Recipient::parse stays as a safety net (network switched mid-draft →
  Continue blocked).
- Compose fee tiers: 0 economy / 1 normal / 2 fast / **3 custom**. The
  sat/vB rate field is **revealed only when the Custom pill is selected**
  (`if Compose.tier == 3` in app.slint) — the preset tiers need no field.
  `Compose.rate-text` mirrors the selected tier's sat/vB; `resolve_rate`
  parses the field when tier == 3 (rejects non-finite/≤0/>100k). Rust never
  overwrites the field while tier == 3. (Same collapse-on-Custom UX ships
  in the chain-notes-app peer.)
- Screens: 0 home · 1 notes · 2 note view · 3 compose · 4 confirm ·
  5 sync (ACTIONS only: import/export/scan + status) · 6 settings
  (network + chunk picker) · 7 contacts (send-to picker) — actions and
  preferences deliberately split.
- Contacts (screen 7): home's "Compose note" opens the picker first —
  manual address input (Use), the prominent "To: Self" row, "Scan address
  QR" (system scanner; payload normalized: `bitcoin:` prefix + `?query`
  stripped, uppercase retried lowercased — our own home QR is uppercase),
  then recents. Recency = list order, front = latest use (NO clock
  on-device), cap 20; naming via each row's "name" zone (mode-switches
  the input; does not bump recency). Contacts live in state.json only —
  NOT chain-recoverable after a wipe. Picking sets `Compose.to-address`
  + `to-label`; compose has no address editing (its Back returns to the
  picker, preserving the draft text).
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
`cb: compose len=<n> private=<b> to=<addr|self> chunks=<c> fee=<f> vsize=<v> gift=<sats> txid=<t> ok | err=<e>` (the UI test derives the applied sat/vB as fee/vsize; `gift` = sats to the recipient output, 0 for self-notes) ·
`cb: sign-note id=<hex8> txid=<t> fee=<f> vsize=<v> internal=<ok|err> airlock=<ok|err>` ·
`cb: open-note id=<hex8> status=<s>[ from=<addr>]` ·
`cb: import-bundle file=<f> loc=<l> notes=<n> new=<k> received=<r> utxos=<m> tip=<h> ok | err=<e>` ·
`cb: export-pending n=<n> airlock=<ok|err>` ·
`cb: set-network <net>` ·
`cb: set-chunk-size <n|auto> ok | err=<msg>` ·
`cb: scan-bundle kind=<qr|ur> bytes=<n>` then `cb: import-bundle
src=scan-<kind> … ok` · `cb: scan-bundle cancelled | err=<e>` ·
`cb: refresh-contacts n=<n>` ·
`cb: pick-contact to=<addr|self> | err=<e>` ·
`cb: scan-contact ok addr=<a> | cancelled | err=<e>` ·
`cb: save-contact addr=<a> name-len=<n>`

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
