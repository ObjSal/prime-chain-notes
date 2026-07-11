# Development

Technical companion to the [README](README.md): how the protocol works, building, testing, and the companion's internals. The full design document is `../PLAN-chain-notes.md` in the workspace repo; the address-to-address messaging sibling is sketched in `../FUTURE-chain-chat.md`.

## How it works

- **Identity**: one P2TR address, key HKDF-derived from `GetAppSeed` (the PIN-gated per-app seed — never the wallet's own accounts). The note-encryption key derives from the same root. Derivation strings are frozen forever; the wipe-recovery story depends on them.
- **A note** = a transaction spending the app's own coins: `OP_RETURN` payload(s) + change back to the same address. Private notes are XChaCha20-Poly1305 sealed (nonce+tag once, then chunked); public notes are plaintext UTF-8. Envelope: `PNTE ‖ v1 ‖ flags ‖ note_id ‖ seq/total ‖ data`.
- **Directed notes**: the tx pays 330 sats of dust to the recipient so their scanner finds it, and private directed notes are sealed via **static-static x-only ECDH** against the recipient's taproot key — only the two devices can read them, both re-derivable from bare chain data after a wipe. Received notes are always attributed to their unforgeable input address and never mix with your own. A **gift amount** can raise the recipient output above dust (`compose_directed_note_*_amount`).
- **Sync bundle** (JSON via file, Airlock, or QR): UTXOs, fee tiers (mempool.space format), BTC price, tip height, and every OP_RETURN payload found in the address history. Only txs that *spend from* the notes address count as own notes — a third party paying the address with forged payloads is ignored, and private notes are additionally AEAD-authenticated.
- **Cost calculator**: the compose screen re-prices on every keystroke — pure arithmetic, no crypto runs (sealed size = text + 40 bytes, always). Fee tiers economy/normal/fast come from the bundle; a **Custom** tier engages when you edit the sat/vB field. The estimate is byte-exact: tests assert it equals the signed transaction's real vsize.
- **Chunk size** (Settings, purely device-side): Standard is 100000 — Bitcoin Core v30's relay default, verified live on mempool.space — so typical notes are a single OP_RETURN; "80 compat" targets pre-v30/strict relays. If an endpoint rejects a note, the reason shows in the companion's broadcast log; pick 80 on the device and recompose.
- **Unconfirmed chaining**: signing updates a local UTXO ledger, so several notes can queue between syncs, each spending the last one's change.
- **QR transports** run both directions: pending note → "Show tx QR" → companion camera → broadcast; and companion "Show as QR" (static or animated UR) → device "Scan bundle 📷" (the system scanner reassembles animated sequences itself). File/Airlock remains for restore-sized bundles and oversized txs.
- **Sweep / consolidate**: Settings → Coins (viewer-first, one consolidate button) and "Sweep funds…" through the contacts picker in sweep mode, both flowing through a shared compose-like screen → sign → outbox + broadcast QR. Deliberately no pay-fee-from-another-wallet option — a Prime holds its own keys.

## Layout

```
notes-core/     host-testable library: key derivation, envelope, AEAD,
                BIP341 sighash + BIP340 signing, tx assembly, sync bundles
src/ ui/        the KeyOS app (screens, persistence, log contract)
companion/      the online half (see below)
scripts/        regtest-e2e.sh (host e2e), regtest-companion.sh,
                publish-companion.sh (deploy mirror)
vendor/         KeyOS getrandom TRNG override + security-api (GetAppSeed)
```

## Build & test

```bash
nix develop ~/.foundation/sdk/current --command cargo test -p notes-core
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh
nix develop ~/.foundation/sdk/current --command foundation sim
../ui-automation/tests/chain-notes.sh    # full UI e2e (manages sim + bitcoind)
```

Fresh clone: recreate the SDK links the repo intentionally doesn't track (`ln -s ~/.foundation/sdk/current/ui/ui ui/ui`, plus `resources/{fonts,images}` symlinks + copied `icons/` — see NOTES.md), and run `foundation sim` once to generate `manifest.toml`.

## What's verified

- `cargo test -p notes-core`: BIP340/BIP341 official vectors; addresses, txids, sighashes and signatures cross-checked against rust-bitcoin/libsecp256k1; envelope/AEAD round-trips; byte-exact fee estimator; spoof/foreign-seed rejection; idempotent imports.
- `scripts/regtest-e2e.sh` against Bitcoin Core v30: multi-chunk and 323-byte single OP_RETURN notes relayed and mined; unconfirmed-change chaining; full-history wipe-restore; plaintext visible on-chain for public notes, ciphertext-only for private.
- `../ui-automation/tests/chain-notes.sh`: the same flow driven through the simulator UI with real taps/keystrokes — the tx signed on the "device" broadcasts on a real regtest node with the txid the device predicted, and a wiped app restores the note from bare chain data.
- **Relay policy, verified live (2026-07-05):** mempool.space/testnet4 accepted a 224-byte single OP_RETURN ([tx](https://mempool.space/testnet4/tx/9097778ec53b2b5b9f8270a7e404487643bdbdccaa81bf8af7aafb3b0404b8bc)) — Bitcoin Core v30 defaults — which is why the device's Standard chunk size is 100000.

## The companion (`companion/`)

**Hosted: https://objsal.github.io/chain-notes-companion/** (deploy mirror in the public `chain-notes-companion` repo, published via `scripts/publish-companion.sh` — this directory is canonical).

One static page + an optional local server:

```bash
python3 companion/server.py 8091            # static (mainnet/testnet4/signet)
python3 companion/server.py 8091 --regtest  # + managed local regtest node
```

`index.html` builds **sync bundles** (full address-history pagination, fee tiers, prices) shown as a downloadable file or as a **QR — static or animated UR** — for the device's scanner, and **broadcasts** the device's `.hex` exports or **scans the device's tx QR with the camera**; all against mempool.space — or against a local regtest node that `server.py` exposes through the *same mempool-shaped API*, so the page treats regtest as just another base URL. The regtest option only appears when the local server is detected.

`viewer.html` is a read-only sibling that renders an address's on-chain notes directly in the browser (deep-linkable via `viewer.html?address=…&network=…`): it ports the PNTE envelope decode/reassemble to JS, enforces the same spends-from-self rule, shows public notes as text and private ones as an encrypted placeholder. Every note card carries a **permalink** to `note.html?address=…&network=…&note=<id>`. The scanning/envelope/render core shared by both pages lives in `chain-scan.js`.

Playwright tests drive the real rendered page: `tests/test_companion_regtest.py` (hermetic, incl. a fake-camera scan), `tests/test_companion_qr.py` (bundle-QR round-trips cross-checked against foundation-ur) and `tests/test_companion_testnet4.py` (live), plus a no-network node unit test for the shared scan core (`node tests/test_chain_scan.js`).

## About

Scaffolded from `foundation new prime-chain-notes --template default-app`, then customized. Normally checked out as a git submodule of a `prime/` workspace; see **`CLAUDE.md`** for architecture detail, frozen protocol invariants, and the log contract, and **`NOTES.md`** for verified results and platform gotchas.
