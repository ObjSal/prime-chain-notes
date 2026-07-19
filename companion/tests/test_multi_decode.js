#!/usr/bin/env node
// Unit test for FLAG_MULTI (multi-recipient directed notes) decode in the
// shipped companion/chain-scan.js — the JS port of notes-core's PNTE
// envelope + bundle.rs scanner (branch multi-recipient).
//
// Wire spec (notes-core/src/envelope.rs FLAG_MULTI, frozen on this branch):
//   flags bit 2 (0x04), only ever set together with FLAG_DIRECTED (0x02).
//   public  (FLAG_PRIVATE clear): body = count(u8) || utf8 text
//   private (FLAG_PRIVATE set):   body = count(u8) || count*wrap(72B) || sealed_body
//   count is LIBERAL: 1..=255 accepted; count 0, or a body too short for
//   the declared framing, is undecodable — never a throw. Recipients are
//   the first `count` non-OP_RETURN outputs of the tx, ascending vout
//   order (they precede change by construction).
//
// Byte-parity cross-check against Rust (tests A/B/C below): the envelope
// bytes (flags/note_id/count/body) are taken verbatim from notes-core's
// notes-core/tests/multi_recipient.rs unit-test vectors —
// decode_liberal_count_one_accepted, decode_liberal_count_zero_rejected,
// decode_liberal_truncated_wraps_rejected — so this proves the JS decoder
// agrees with the Rust decoder byte-for-byte on those exact payloads, not
// just "the same logic re-implemented". (The full regtest e2e / notes_cli
// route was not used — hand-deriving from the frozen Rust vectors above is
// the option the task brief explicitly allows, and is hermetic/instant.)
//
// No network, no browser: chain-scan.js runs in a vm context against a
// fetch stub serving synthetic esplora JSON, same harness as
// tests/test_chain_scan.js.  Run: node tests/test_multi_decode.js
"use strict";
const assert = require("assert/strict");
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;
const FLAG_MULTI = 0x04;

const ADDR = "bcrt1ptestscannedaddr";  // the scanned address (also B, a recipient)
const SENDER = "bcrt1palicesender";    // the note's author (not `mine`)
const CAROL = "bcrt1pcarolrecipient";  // a second recipient
const CHANGE = "bcrt1qsenderchange";   // sender's change (non-taproot, non-recipient)

const noteIdHex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

// PNTE(4) || ver=1(1) || flags(1) || note_id(4) || seq(1) || total(1) || dataHex.
function envelopeHex(noteIdBytes, seq, total, flags, dataHex) {
  return (
    "504e544501" +
    flags.toString(16).padStart(2, "0") +
    noteIdHex(noteIdBytes) +
    seq.toString(16).padStart(2, "0") +
    total.toString(16).padStart(2, "0") +
    dataHex
  );
}

// OP_RETURN scriptPubKey around a hex payload, choosing the right push
// opcode (matches chain-scan.js's opReturnPayload decode: <=75 direct
// push, 76-255 OP_PUSHDATA1, else OP_PUSHDATA2).
function opReturnSpk(payloadHex) {
  const len = payloadHex.length / 2;
  let pushHex;
  if (len <= 75) pushHex = len.toString(16).padStart(2, "0");
  else if (len <= 255) pushHex = "4c" + len.toString(16).padStart(2, "0");
  else {
    const lo = len & 0xff, hi = (len >> 8) & 0xff;
    pushHex = "4d" + lo.toString(16).padStart(2, "0") + hi.toString(16).padStart(2, "0");
  }
  return "6a" + pushHex + payloadHex;
}

function chunkSpk(noteIdBytes, seq, total, flags, dataHex) {
  return opReturnSpk(envelopeHex(noteIdBytes, seq, total, flags, dataHex));
}

const hex = (s) => Buffer.from(s, "utf8").toString("hex");

// A single-OP_RETURN tx. `vinAddr` (default SENDER, not `mine`) drives
// spendsFromSelf; `voutAddrs` are the non-OP_RETURN outputs in vout order
// (index 0 = whatever chain-scan.js's `outputAddrs`/multi-recipient slice
// sees first).
function tx(txid, spkHex, height, { vinAddr = SENDER, voutAddrs = [ADDR] } = {}) {
  return {
    txid,
    vin: [{ prevout: { scriptpubkey_address: vinAddr } }],
    vout: [
      { scriptpubkey_type: "op_return", scriptpubkey: spkHex },
      ...voutAddrs.map((a) => ({
        scriptpubkey_type: /1p/.test(a) ? "v1_p2tr" : "v0_p2wpkh",
        scriptpubkey_address: a,
        value: 330,
      })),
    ],
    status: { confirmed: height != null, block_height: height ?? undefined,
              block_time: height != null ? 1700000000 + height : undefined },
  };
}

const HISTORIES = {
  // === A: cross-check vs multi_recipient.rs::decode_liberal_count_one_accepted ===
  // flags = FLAG_DIRECTED|FLAG_MULTI, note_id=[1,1,1,1], body = 0x01 ||
  // "solo via multi flag" — byte-identical to the Rust vector. Rust's
  // output_addrs there is [b.address(NET)] (one recipient = the scanned
  // address itself); mirrored here as voutAddrs:[ADDR].
  countOne: [
    tx("tx_a", chunkSpk([1, 1, 1, 1], 0, 1, FLAG_DIRECTED | FLAG_MULTI,
       hex("\x01") + hex("solo via multi flag")), 100, { voutAddrs: [ADDR] }),
  ],
  // === B: cross-check vs decode_liberal_count_zero_rejected ===
  // Same shape, count=0 — undecodable, not a crash.
  countZero: [
    tx("tx_b", chunkSpk([2, 2, 2, 2], 0, 1, FLAG_DIRECTED | FLAG_MULTI,
       hex("\x00") + hex("nobody")), 101, { voutAddrs: [ADDR] }),
  ],
  // === C: cross-check vs decode_liberal_truncated_wraps_rejected ===
  // flags = FLAG_DIRECTED|FLAG_MULTI|FLAG_PRIVATE, note_id=[3,3,3,3],
  // body = 0x02 || 10 zero bytes (claims 2*72=144 wrap bytes, has 10) —
  // text must stay undecodable (the browser never even attempts private
  // decrypt), but per notes-core's bundle.rs the recipient LIST is derived
  // from `count` alone, before any wrap-length check — so recipients must
  // still come back as both output addresses.
  truncated: [
    tx("tx_c", chunkSpk([3, 3, 3, 3], 0, 1, FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE,
       hex("\x02") + "00".repeat(10)), 102, { voutAddrs: [ADDR, CAROL] }),
  ],
  // === D: public, 2 recipients + a 3rd non-recipient output (change) ===
  // Proves recipients are SLICED to `count`, not "every non-OP_RETURN
  // output" — the trailing CHANGE output must be excluded.
  publicTwo: [
    tx("tx_d", chunkSpk([9, 9, 9, 9], 0, 1, FLAG_DIRECTED | FLAG_MULTI,
       hex("\x02") + hex("hi both of you")), 103,
       { voutAddrs: [ADDR, CAROL, CHANGE] }),
  ],
  // === E: private, 2 real-shaped 72-byte wraps + a sealed-body blob ===
  // The browser cannot decrypt — text must stay the placeholder (null),
  // but recipients still resolve from `count`.
  privateTwo: [
    tx("tx_e", chunkSpk([10, 10, 10, 10], 0, 1, FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE,
       hex("\x02") + "aa".repeat(144) + "bb".repeat(24)), 104,
       { voutAddrs: [ADDR, CAROL] }),
  ],
  // === F: single-recipient regression — FLAG_MULTI CLEAR ===
  // Plain directed note, own side (ADDR spends from itself to CAROL +
  // change to self) — must decode exactly as before this feature existed:
  // multi:false, recipients:[], `to` populated the old way.
  singleRegression: [
    tx("tx_f", chunkSpk([4, 4, 4, 4], 0, 1, FLAG_DIRECTED, hex("dear carol")), 105,
       { vinAddr: ADDR, voutAddrs: [CAROL, ADDR] }),
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

  // --- A: count=1 accepted (cross-check vs decode_liberal_count_one_accepted) ---
  const a = await scanAddress("stub:countOne", ${JSON.stringify(ADDR)});
  assert(a.notes.length === 1, "countOne: expected 1 note");
  const na = a.notes[0];
  assert(na.multi === true, "countOne: multi flag must be set");
  assert(na.text === "solo via multi flag",
         "countOne: text must match the Rust vector byte-for-byte, got " + JSON.stringify(na.text));
  assert(JSON.stringify(na.recipients) === JSON.stringify([${JSON.stringify(ADDR)}]),
         "countOne: recipients must be the single output address: " + JSON.stringify(na.recipients));
  console.log("PASS A: count=1 public multi note — text + recipients match Rust vector");

  // --- B: count=0 rejected (cross-check vs decode_liberal_count_zero_rejected) ---
  const b = await scanAddress("stub:countZero", ${JSON.stringify(ADDR)});
  assert(b.notes.length === 1, "countZero: expected 1 note (envelope still parses)");
  const nb = b.notes[0];
  assert(nb.multi === true, "countZero: multi flag must still be set");
  assert(nb.text === null, "countZero: count=0 must be undecodable, not a crash: " + JSON.stringify(nb.text));
  assert(Array.isArray(nb.recipients) && nb.recipients.length === 0,
         "countZero: recipients must be empty: " + JSON.stringify(nb.recipients));
  console.log("PASS B: count=0 is undecodable (liberal decode), does not throw");

  // --- C: truncated wraps (cross-check vs decode_liberal_truncated_wraps_rejected) ---
  const c = await scanAddress("stub:truncated", ${JSON.stringify(ADDR)});
  assert(c.notes.length === 1, "truncated: expected 1 note");
  const nc = c.notes[0];
  assert(nc.private === true && nc.multi === true, "truncated: private+multi flags");
  assert(nc.text === null, "truncated: private body is never attempted in-browser, must stay null");
  assert(JSON.stringify(nc.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "truncated: recipient list comes from count alone (before any wrap-length check): " +
         JSON.stringify(nc.recipients));
  console.log("PASS C: truncated private wraps — text stays sealed, recipients still resolve, no throw");

  // --- D: public, recipients sliced to count (change output excluded) ---
  const d = await scanAddress("stub:publicTwo", ${JSON.stringify(ADDR)});
  const nd = d.notes[0];
  assert(nd.text === "hi both of you", "publicTwo: bad text: " + JSON.stringify(nd.text));
  assert(JSON.stringify(nd.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "publicTwo: recipients must be sliced to count=2, excluding change: " + JSON.stringify(nd.recipients));
  console.log("PASS D: public 2-recipient note — recipients sliced from a 3-output list, change excluded");

  // --- E: private, real-shaped wraps — placeholder text, recipients resolve ---
  const e = await scanAddress("stub:privateTwo", ${JSON.stringify(ADDR)});
  const ne = e.notes[0];
  assert(ne.private === true && ne.multi === true, "privateTwo: private+multi flags");
  assert(ne.text === null, "privateTwo: private body must render as the placeholder (text:null)");
  assert(JSON.stringify(ne.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "privateTwo: recipients must resolve even though the body is sealed: " + JSON.stringify(ne.recipients));
  assert(!ne.partial, "privateTwo: a full single-chunk body must not be reported partial");
  console.log("PASS E: private 2-recipient note (72B wraps + sealed body) — placeholder text, recipients resolve");

  // --- F: single-recipient regression, FLAG_MULTI clear ---
  const f = await scanAddress("stub:singleRegression", ${JSON.stringify(ADDR)});
  const nf = f.notes[0];
  assert(nf.multi === false, "singleRegression: multi must be false");
  assert(Array.isArray(nf.recipients) && nf.recipients.length === 0,
         "singleRegression: recipients must be empty for a non-multi note: " + JSON.stringify(nf.recipients));
  assert(!nf.received && nf.directed && nf.to === ${JSON.stringify(CAROL)},
         "singleRegression: legacy 'to' field must still populate exactly as before: " + JSON.stringify(nf));
  assert(nf.text === "dear carol", "singleRegression: bad text: " + JSON.stringify(nf.text));
  console.log("PASS F: single-recipient directed note (FLAG_MULTI clear) decodes byte-identical to before");

  console.log("MULTI-DECODE UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
