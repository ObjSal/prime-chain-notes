#!/usr/bin/env node
// Unit test for companion/owner-probe.js — the shared history-probe used
// by index.html's spending-wallet watch-list flow (funding-unification
// companion gap-discovery, option (b), 2026-07-19). Covers:
//   - a live coin: utxos tagged owner_address, used=true (has history)
//   - a spent-then-emptied address: zero utxos but used=true (history
//     survives even with nothing left to spend) — the exact case the
//     device's `owner_used`-driven gap-advance (`spending-adopt … used-
//     only`) depends on
//   - a never-touched address: zero utxos, used=false
//   - a fetch failure propagates (per-address try/catch is the caller's
//     job, not this module's)
//
// No network, no DOM: owner-probe.js is plain CommonJS + a stubbed
// apiJson.  Run: node tests/test_owner_probe.js
"use strict";
const assert = require("assert/strict");
const { probeOwnerAddress } = require("../owner-probe.js");

const UTXO_ADDR = "bcrt1qhascoin";
const SPENT_ADDR = "bcrt1qspentempty";
const FRESH_ADDR = "bcrt1qneverused";
const ERR_ADDR = "bcrt1qerrors";

// Synthetic esplora-shaped responses keyed by path — mirrors the shim's
// real shape closely enough for this module (it only reads `.length` and
// spreads each utxo entry).
const FIXTURES = {
  [`/address/${UTXO_ADDR}/utxo`]: [{ txid: "aa".repeat(32), vout: 0, value: 50000 }],
  [`/address/${UTXO_ADDR}/txs`]: [{ txid: "aa".repeat(32) }],
  [`/address/${SPENT_ADDR}/utxo`]: [],
  [`/address/${SPENT_ADDR}/txs`]: [{ txid: "bb".repeat(32) }, { txid: "cc".repeat(32) }],
  [`/address/${FRESH_ADDR}/utxo`]: [],
  [`/address/${FRESH_ADDR}/txs`]: [],
};

async function apiJson(path) {
  if (path.startsWith(`/address/${ERR_ADDR}/`)) throw new Error("connection refused");
  if (!(path in FIXTURES)) throw new Error(`unstubbed path ${path}`);
  return FIXTURES[path];
}

(async () => {
  const withCoin = await probeOwnerAddress(apiJson, UTXO_ADDR);
  assert.equal(withCoin.used, true, "an address with a live coin must be used=true");
  assert.equal(withCoin.utxos.length, 1);
  assert.equal(withCoin.utxos[0].owner_address, UTXO_ADDR, "each utxo must be tagged owner_address");
  assert.equal(withCoin.utxos[0].value, 50000);
  console.log("PASS live coin: used=true, utxo tagged owner_address");

  const spentEmpty = await probeOwnerAddress(apiJson, SPENT_ADDR);
  assert.equal(spentEmpty.utxos.length, 0, "a spent address has no current utxos");
  assert.equal(spentEmpty.used, true,
    "a spent-then-emptied address must STILL report used=true — this is the exact fact " +
    "the device's gap-advance (spending-adopt … used-only) needs to converge past it");
  console.log("PASS spent-then-emptied: 0 utxos but used=true (history survives the spend)");

  const fresh = await probeOwnerAddress(apiJson, FRESH_ADDR);
  assert.equal(fresh.utxos.length, 0);
  assert.equal(fresh.used, false, "a never-touched address must be used=false");
  console.log("PASS never-touched address: used=false");

  await assert.rejects(
    () => probeOwnerAddress(apiJson, ERR_ADDR),
    /connection refused/,
    "a fetch failure must propagate — per-address recovery is the caller's job"
  );
  console.log("PASS fetch failure propagates (caller catches per-address, not this module)");

  console.log("OWNER-PROBE UNIT TESTS PASSED");
})().catch((e) => {
  console.error("FAIL " + e.message);
  process.exit(1);
});
