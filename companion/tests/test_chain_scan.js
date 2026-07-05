#!/usr/bin/env node
// Unit test for the shipped companion/chain-scan.js (the JS port of the
// FROZEN PNTE envelope + extract_notes): cross-transaction reassembly,
// duplicate-chunk dedup, partial surfacing, and the directed-notes
// acceptance rules — own notes need spends-from-self (spoof resistance),
// pays-me PNTE txs surface as RECEIVED notes attributed to their taproot
// input, and own/received buckets never merge even on a note_id collision.
//
// No network, no browser: chain-scan.js runs in a vm context against a
// fetch stub serving synthetic esplora JSON.  Run: node tests/test_chain_scan.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const ADDR = "bcrt1ptestaddress";           // the scanned address (taproot-ish prefix)
const PEER = "bcrt1ppeeraddress";           // a taproot counterparty
const V0 = "bcrt1qsomeoneelse";             // a non-taproot address
const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;

// OP_RETURN spk: PNTE || v1 || flags || note_id || seq || total || data
function chunkSpk(noteId, seq, total, flags, dataUtf8) {
  const payload = "504e544501" + flags.toString(16).padStart(2, "0") + noteId +
    seq.toString(16).padStart(2, "0") + total.toString(16).padStart(2, "0") +
    Buffer.from(dataUtf8, "utf8").toString("hex");
  return "6a" + (payload.length / 2).toString(16).padStart(2, "0") + payload;
}

// A tx carrying `spks` OP_RETURNs. opts: vinAddr (prevout address),
// voutAddrs (non-OP_RETURN payment outputs, in order).
function tx(txid, spks, height, opts = {}) {
  const vinAddr = opts.vinAddr ?? ADDR;
  const voutAddrs = opts.voutAddrs ?? [ADDR];
  return {
    txid,
    vin: [{ prevout: { scriptpubkey_address: vinAddr } }],
    vout: [
      ...spks.map((spk) => ({ scriptpubkey_type: "op_return", scriptpubkey: spk })),
      ...voutAddrs.map((a) => ({
        scriptpubkey_type: /1p/.test(a) ? "v1_p2tr" : "v0_p2wpkh",
        scriptpubkey_address: a,
        value: 5000,
      })),
    ],
    status: { confirmed: height != null, block_height: height ?? undefined,
              block_time: height != null ? 1700000000 + height : undefined },
  };
}

const HISTORIES = {
  // "hello world" own public note: seq 1 in the newer tx, seq 0 in the older.
  cross: [
    tx("tx_two", [chunkSpk("aabbccdd", 1, 2, 0, "world")], 102),
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
  ],
  // Same note, but the tx carrying seq=1 never made it on-chain.
  missing: [
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
  ],
  // Overlapping txs re-carry an identical chunk (must dedup, not error),
  // a PRIVATE cross-tx note must reassemble but stay text:null, and a
  // pays-me tx from a non-taproot spender reusing an OWN note_id becomes a
  // RECEIVED note (from unknown) without contaminating the own bucket.
  dedup: [
    tx("tx_dup", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 103),
    tx("tx_two", [chunkSpk("aabbccdd", 1, 2, 0, "world")], 102),
    tx("tx_one", [chunkSpk("aabbccdd", 0, 2, 0, "hello ")], 101),
    tx("tx_priv2", [chunkSpk("11223344", 1, 2, FLAG_PRIVATE, "\x02\x03")], 105),
    tx("tx_priv1", [chunkSpk("11223344", 0, 2, FLAG_PRIVATE, "\x00\x01")], 104),
    // note_id collision from outside: pays ADDR, spends from a v0 address.
    tx("tx_collide", [chunkSpk("aabbccdd", 0, 1, 0, "EVIL!!")], 106, { vinAddr: V0 }),
  ],
  // Directed notes at the RECIPIENT (ADDR): a two-tx public note and a
  // private one from PEER; plus a non-PNTE pays-me tx and a tx that
  // neither spends from nor pays ADDR (pure foreign).
  directed: [
    tx("tx_dm2", [chunkSpk("cafebabe", 1, 2, FLAG_DIRECTED, "you!")], 202, { vinAddr: PEER }),
    tx("tx_dm1", [chunkSpk("cafebabe", 0, 2, FLAG_DIRECTED, "note for ")], 201, { vinAddr: PEER }),
    tx("tx_dmp", [chunkSpk("deadf00d", 0, 1, FLAG_DIRECTED | FLAG_PRIVATE, "\x10\x20\x30")], 203,
       { vinAddr: PEER }),
    tx("tx_junk", ["6a04deadbeef"], 204, { vinAddr: V0 }),
    tx("tx_foreign", [chunkSpk("00000001", 0, 1, 0, "not yours")], 205,
       { vinAddr: V0, voutAddrs: [V0] }),
  ],
  // Directed note at the SENDER (ADDR): own tx paying PEER + change to self.
  sent: [
    tx("tx_sent", [chunkSpk("beefbeef", 0, 1, FLAG_DIRECTED, "dear peer")], 301,
       { voutAddrs: [PEER, ADDR] }),
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
  assert(!n.received && !n.directed, "cross: plain own note");
  console.log("PASS cross-tx note reassembled (both txids, first-confirmation height)");

  const missing = await scanAddress("stub:missing", ${JSON.stringify(ADDR)});
  const p = missing.notes[0];
  assert(p.partial && p.partial.have === 1 && p.partial.total === 2,
         "missing: expected partial 1/2, got " + JSON.stringify(p.partial));
  assert(p.text === null, "missing: partial note must have no text");
  console.log("PASS missing cross-tx chunk surfaces as partial 1/2");

  const dedup = await scanAddress("stub:dedup", ${JSON.stringify(ADDR)});
  assert(dedup.notes.length === 3, "dedup: expected 3 notes, got " + dedup.notes.length);
  const own = dedup.notes.filter((x) => !x.received);
  const pub = own.find((x) => !x.private);
  assert(pub.text === "hello world" && !pub.partial,
         "dedup: duplicate chunk must not break reassembly");
  // Like Rust extract_notes, a tx whose chunk is an exact duplicate is
  // skipped BEFORE its txid is recorded — only new-chunk contributors list.
  assert(pub.txids.length === 2 && !pub.txids.includes("tx_one"),
         "dedup: only new-chunk txids listed: " + pub.txids);
  const priv = own.find((x) => x.private);
  assert(priv && !priv.partial && priv.text === null && priv.bodyLen === 4,
         "dedup: private cross-tx note must reassemble with text:null");
  // note_id collision: the pays-me tx lands in a SEPARATE received bucket.
  const collide = dedup.notes.find((x) => x.received);
  assert(collide && collide.noteId === "aabbccdd" && collide.text === "EVIL!!"
         && collide.from === null,
         "dedup: colliding pays-me tx must be a received note from unknown");
  assert(pub.text === "hello world", "dedup: own note must survive the collision intact");
  assert(dedup.receivedTxs === 1 && dedup.foreign === 0,
         "dedup: counters " + dedup.receivedTxs + "/" + dedup.foreign);
  console.log("PASS dedup, private cross-tx, collision isolation, ordering");

  const dir = await scanAddress("stub:directed", ${JSON.stringify(ADDR)});
  assert(dir.notes.length === 2, "directed: expected 2 notes, got " + dir.notes.length);
  const dpub = dir.notes.find((x) => !x.private);
  assert(dpub.received && dpub.directed && dpub.text === "note for you!"
         && dpub.from === ${JSON.stringify(PEER)},
         "directed: received public note with sender: " + JSON.stringify(dpub));
  assert(dpub.height === 201, "directed: first confirmation across txs");
  const dpriv = dir.notes.find((x) => x.private);
  assert(dpriv.received && dpriv.directed && dpriv.text === null,
         "directed: received private stays sealed");
  assert(dir.receivedTxs === 4 && dir.foreign === 1 && dir.nonPnte === 1,
         "directed: counters recv=" + dir.receivedTxs + " foreign=" + dir.foreign +
         " nonPnte=" + dir.nonPnte);
  console.log("PASS received directed notes (public text + from, private sealed, foreign ignored)");

  const sent = await scanAddress("stub:sent", ${JSON.stringify(ADDR)});
  const s = sent.notes[0];
  assert(!s.received && s.directed && s.to === ${JSON.stringify(PEER)}
         && s.text === "dear peer",
         "sent: own directed note carries to=PEER: " + JSON.stringify(s));
  console.log("PASS own directed note carries its recipient");

  console.log("CHAIN-SCAN UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
