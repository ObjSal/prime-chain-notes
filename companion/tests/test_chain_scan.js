#!/usr/bin/env node
// Unit test for the shipped companion/chain-scan.js (the JS port of the
// FROZEN PNTE envelope + extract_notes): notes whose chunks are spread
// ACROSS DIFFERENT TRANSACTIONS must reassemble, list every carrying
// txid, take their height from the FIRST confirmation, dedup overlapping
// chunks, and surface missing chunks as partial instead of vanishing.
//
// No network, no browser: chain-scan.js runs in a vm context against a
// fetch stub serving synthetic esplora JSON.  Run: node tests/test_chain_scan.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const ADDR = "bcrt1ptestaddress";
const FLAG_PRIVATE = 0x01;

// OP_RETURN spk: PNTE || v1 || flags || note_id || seq || total || data
function chunkSpk(noteId, seq, total, flags, dataUtf8) {
  const payload = "504e544501" + flags.toString(16).padStart(2, "0") + noteId +
    seq.toString(16).padStart(2, "0") + total.toString(16).padStart(2, "0") +
    Buffer.from(dataUtf8, "utf8").toString("hex");
  return "6a" + (payload.length / 2).toString(16).padStart(2, "0") + payload;
}

function tx(txid, spks, height, fromSelf = true) {
  return {
    txid,
    vin: [{ prevout: { scriptpubkey_address: fromSelf ? ADDR : "bcrt1qsomeoneelse" } }],
    vout: [
      ...spks.map((spk) => ({ scriptpubkey_type: "op_return", scriptpubkey: spk })),
      { scriptpubkey_type: "v1_p2tr", scriptpubkey_address: ADDR, value: 5000 },
    ],
    status: { confirmed: height != null, block_height: height ?? undefined,
              block_time: height != null ? 1700000000 + height : undefined },
  };
}

// One history per scenario, routed by the fake API base URL.
const HISTORIES = {
  // "hello world" public note: seq 1 in the newer tx, seq 0 in the older.
  cross: [
    tx("tx_two", [chunkSpk("aabbccdd", 1, 2, 0, "world")], 102),
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
  ],
  // Same note, but the tx carrying seq=1 never made it on-chain.
  missing: [
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
  ],
  // Overlapping txs re-carry an identical chunk (must dedup, not error),
  // and a PRIVATE cross-tx note must reassemble but stay text:null.
  dedup: [
    tx("tx_dup", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 103),
    tx("tx_two", [chunkSpk("aabbccdd", 1, 2, 0, "world")], 102),
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
    tx("tx_priv2", [chunkSpk("11223344", 1, 2, FLAG_PRIVATE, "\x02\x03")], 105),
    tx("tx_priv1", [chunkSpk("11223344", 0, 2, FLAG_PRIVATE, "\x00\x01")], 104),
    // Spoof attempt: right note_id but does not spend from the address.
    tx("tx_spoof", [chunkSpk("aabbccdd", 0, 2, 0, "EVIL!!")], 106, false),
  ],
};

const ctx = {
  fetch: async (url) => {
    const scenario = url.match(/^stub:(\w+)/)[1];
    const body = url.includes("/txs/chain") ? [] : HISTORIES[scenario];
    return { ok: true, text: async () => JSON.stringify(body) };
  },
  TextDecoder, console, process,
};
vm.createContext(ctx);
vm.runInContext(src, ctx);

vm.runInContext(`
(async () => {
  const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

  const cross = await scanAddress("stub:cross", ${JSON.stringify(ADDR)});
  assert(cross.notes.length === 1, "cross: expected 1 note");
  const n = cross.notes[0];
  assert(n.text === "hello world", "cross: bad reassembly: " + n.text);
  assert(!n.partial, "cross: must not be partial");
  assert(n.txids.length === 2 && n.txids.includes("tx_one") && n.txids.includes("tx_two"),
         "cross: both carrying txids must be listed: " + n.txids);
  assert(n.height === 101, "cross: height must be FIRST confirmation, got " + n.height);
  console.log("PASS cross-tx note reassembled (both txids, first-confirmation height)");

  const missing = await scanAddress("stub:missing", ${JSON.stringify(ADDR)});
  const p = missing.notes[0];
  assert(p.partial && p.partial.have === 1 && p.partial.total === 2,
         "missing: expected partial 1/2, got " + JSON.stringify(p.partial));
  assert(p.text === null, "missing: partial note must have no text");
  console.log("PASS missing cross-tx chunk surfaces as partial 1/2");

  const dedup = await scanAddress("stub:dedup", ${JSON.stringify(ADDR)});
  assert(dedup.notes.length === 2, "dedup: expected 2 notes, got " + dedup.notes.length);
  const pub = dedup.notes.find((x) => !x.private);
  assert(pub.text === "hello world" && !pub.partial,
         "dedup: duplicate chunk must not break reassembly");
  // Like Rust extract_notes, a tx whose chunk is an exact duplicate is
  // skipped BEFORE its txid is recorded — only new-chunk contributors list.
  assert(pub.txids.length === 2 && !pub.txids.includes("tx_one"),
         "dedup: only new-chunk txids listed: " + pub.txids);
  const priv = dedup.notes.find((x) => x.private);
  assert(priv && !priv.partial && priv.text === null && priv.bodyLen === 4,
         "dedup: private cross-tx note must reassemble with text:null");
  assert(dedup.foreign === 1, "dedup: spoof tx (not spends-from-self) must be ignored");
  assert(dedup.notes[0] === priv, "dedup: newest-first ordering");
  console.log("PASS duplicate-chunk dedup, private cross-tx note, spoof rejection, ordering");

  console.log("CHAIN-SCAN UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
