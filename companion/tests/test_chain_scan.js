#!/usr/bin/env node
// Unit test for the shipped companion/chain-scan.js (the JS port of the
// FROZEN PNTE envelope + extract_notes): cross-transaction reassembly,
// duplicate-chunk dedup, partial surfacing, and the directed-notes
// acceptance rules — own notes need spends-from-self (spoof resistance),
// pays-me PNTE txs surface as RECEIVED notes attributed to their taproot
// input, and own/received buckets never merge even on a note_id collision.
// Also covers the funding-unification myAddresses extension (mirrors
// notes-core's extract_notes_multi self-spk-SET rule): additive-only, old
// 2-arg callers byte-identical, an unrelated address never falsely OWNs.
// And the 2026-07-18 DISPLAY-OWNER dedup (`notebookAddresses`, mirrors
// notes-core's extract_notes_multi_deduped): first-notebook-input-in-tx-
// order wins, order-flip flips the owner, a non-notebook input earlier in
// the tx never steals the anchor, dedup is opt-in (omitted/empty arg is a
// byte-identical no-op), and a note with no notebook input at all is
// unaffected.
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
const FUNDER = "bcrt1qfunderfunderfunder";  // a P2WPKH funding-wallet address (not taproot)
const NB2 = "bcrt1pnotebooktwoaddress";     // a SIBLING notebook address (also taproot)
const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;

// OP_RETURN spk: PNTE || v1 || flags || note_id || seq || total || data
function chunkSpk(noteId, seq, total, flags, dataUtf8) {
  const payload = "504e544501" + flags.toString(16).padStart(2, "0") + noteId +
    seq.toString(16).padStart(2, "0") + total.toString(16).padStart(2, "0") +
    Buffer.from(dataUtf8, "utf8").toString("hex");
  return "6a" + (payload.length / 2).toString(16).padStart(2, "0") + payload;
}

// A tx carrying `spks` OP_RETURNs. opts: vinAddr (single prevout address),
// vinAddrs (MULTIPLE prevout addresses, in tx order — overrides vinAddr;
// for the DISPLAY-OWNER dedup tests), voutAddrs (non-OP_RETURN payment
// outputs, in order).
function tx(txid, spks, height, opts = {}) {
  const vinAddrs = opts.vinAddrs ?? [opts.vinAddr ?? ADDR];
  const voutAddrs = opts.voutAddrs ?? [ADDR];
  return {
    txid,
    vin: vinAddrs.map((a) => (a == null ? {} : { prevout: { scriptpubkey_address: a } })),
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
  // funding-unification: a self-note funded by an external (non-taproot)
  // wallet — spends from FUNDER, dust-pays ADDR. Without myAddresses this
  // is indistinguishable from a stranger's pays-me note (today's behavior,
  // and no taproot input means no `from` attribution either); passing
  // myAddresses=[FUNDER] must classify it OWN — the self-spk-SET rule
  // mirrored from notes-core's extract_notes_multi.
  funded: [
    tx("tx_funded", [chunkSpk("f0f1f2f3", 0, 1, 0, "funded by external wallet")], 401,
       { vinAddr: FUNDER, voutAddrs: [ADDR] }),
  ],
  // DISPLAY-OWNER dedup (2026-07-18): a tx spending from TWO notebook
  // addresses, ADDR first then NB2. The stub `fetch` ignores which address
  // was actually requested (keyed by scenario name only), so scanning this
  // SAME history as both ADDR and NB2 mirrors two independent notebooks
  // scanning the identical tx.
  dual: [
    tx("tx_dual", [chunkSpk("d0d0d0d0", 0, 1, 0, "owned by two notebooks")], 500,
       { vinAddrs: [ADDR, NB2], voutAddrs: [ADDR] }),
  ],
  // Same shape, notebook inputs reversed (NB2 first) — the owner must flip.
  dualFlipped: [
    tx("tx_dual_flip", [chunkSpk("d1d1d1d1", 0, 1, 0, "owned by two notebooks, reversed")], 501,
       { vinAddrs: [NB2, ADDR], voutAddrs: [ADDR] }),
  ],
  // A non-notebook (funding-wallet) input at position 0, the notebook
  // (ADDR) input at position 1 — the refinement: FUNDER must not steal the
  // anchor away from ADDR.
  dualWpkhFirst: [
    tx("tx_dual_wpkh", [chunkSpk("d2d2d2d2", 0, 1, 0, "wallet-funded but notebook-anchored")],
       502, { vinAddrs: [FUNDER, ADDR], voutAddrs: [ADDR] }),
  ],
  // One input has no `prevout` data at all (esplora sometimes omits it) —
  // the anchor search must skip it without crashing, still finding the
  // real notebook input that follows.
  dualMissingPrevout: [
    tx("tx_dual_missing", [chunkSpk("d3d3d3d3", 0, 1, 0, "missing prevout data on input 0")],
       503, { vinAddrs: [null, ADDR], voutAddrs: [ADDR] }),
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

  // funding-unification: myAddresses is additive-only. Old callers passing
  // no 4th arg (every scanAddress() call above) must be byte-identical to
  // pre-change behavior — the funded-by-FUNDER tx stays RECEIVED (from
  // unattributable: no taproot input) exactly like an old bundle/caller
  // that never heard of myAddresses.
  const fundedDefault = await scanAddress("stub:funded", ${JSON.stringify(ADDR)});
  const fd = fundedDefault.notes[0];
  assert(fd.received && fd.from === null && fd.text === "funded by external wallet",
         "funded (no myAddresses): must render as received, unattributed: " + JSON.stringify(fd));
  console.log("PASS funded note without myAddresses renders as received (old behavior, unchanged)");

  // Passing myAddresses=[FUNDER] (e.g. viewer.html's optional &mine=)
  // extends OWN detection to that address — an OR, never a narrowing.
  const fundedOwn = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                       [${JSON.stringify(FUNDER)}]);
  const fo = fundedOwn.notes[0];
  assert(!fo.received && fo.text === "funded by external wallet",
         "funded (myAddresses=[FUNDER]): must classify OWN: " + JSON.stringify(fo));
  console.log("PASS funded note WITH myAddresses=[FUNDER] classifies OWN (self-spk-SET rule)");

  // A myAddresses entry that never appears as an input prevout changes
  // nothing (still an OR against the real inputs, not a wildcard).
  const fundedUnrelated = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                             [${JSON.stringify(PEER)}]);
  assert(fundedUnrelated.notes[0].received,
         "funded (myAddresses=[unrelated PEER]): must stay received: " +
         JSON.stringify(fundedUnrelated.notes[0]));
  console.log("PASS unrelated myAddresses entry does not falsely mark a note OWN");

  // --- DISPLAY-OWNER dedup (2026-07-18, mirrors extract_notes_multi_deduped) ---

  // (a) A tx spending from ADDR then NB2: scanning the SAME history as
  // both notebooks independently, exactly one keeps the note — the
  // first-notebook-input owner, ADDR. Never-zero across both scans.
  const dualAsAddr = await scanAddress("stub:dual", ${JSON.stringify(ADDR)}, undefined, [],
                                        [${JSON.stringify(NB2)}]);
  const dualAsNb2 = await scanAddress("stub:dual", ${JSON.stringify(NB2)}, undefined, [],
                                       [${JSON.stringify(ADDR)}]);
  assert(dualAsAddr.notes.length === 1, "dual: ADDR (first notebook input) must keep the note");
  assert(dualAsNb2.notes.length === 0, "dual: NB2 must not also display it");
  assert(dualAsAddr.notes.length + dualAsNb2.notes.length === 1,
         "dual: never-zero — exactly one scan keeps the note");
  console.log("PASS DISPLAY-OWNER dedup: first-notebook-input (in tx order) wins, never-zero");

  // (b) Same shape, inputs reversed — the owner flips to NB2.
  const flipAsAddr = await scanAddress("stub:dualFlipped", ${JSON.stringify(ADDR)}, undefined,
                                        [], [${JSON.stringify(NB2)}]);
  const flipAsNb2 = await scanAddress("stub:dualFlipped", ${JSON.stringify(NB2)}, undefined,
                                       [], [${JSON.stringify(ADDR)}]);
  assert(flipAsAddr.notes.length === 0, "dualFlipped: ADDR is no longer first, must not keep");
  assert(flipAsNb2.notes.length === 1, "dualFlipped: NB2 (now first) must keep the note");
  console.log("PASS DISPLAY-OWNER dedup: owner flips with input order");

  // (c) A funding-wallet (non-notebook) input at position 0 must not steal
  // the anchor from the real notebook input that follows.
  const wpkhFirst = await scanAddress("stub:dualWpkhFirst", ${JSON.stringify(ADDR)}, undefined,
                                       [], [${JSON.stringify(NB2)}]);
  assert(wpkhFirst.notes.length === 1 && !wpkhFirst.notes[0].received,
         "dualWpkhFirst: notebook input still anchors despite a non-notebook input first: " +
         JSON.stringify(wpkhFirst.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: non-notebook input at position 0 does not steal the anchor");

  // (d) A note with NO notebook input at all (pure funding-wallet shape,
  // reusing the "funded" fixture) is unaffected by dedup being enabled —
  // the anchor search finds nothing, so it's kept exactly as before.
  const fundedDeduped = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                           [${JSON.stringify(FUNDER)}], [${JSON.stringify(NB2)}]);
  assert(!fundedDeduped.notes[0].received,
         "funded + notebookAddresses set: no notebook input present, must stay kept/OWN: " +
         JSON.stringify(fundedDeduped.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: no-op when the tx has no notebook input at all");

  // (e) notebookAddresses omitted (old 2/4-arg calls) and an explicit empty
  // array must be byte-identical to each other — dedup is strictly opt-in.
  const dualOld = await scanAddress("stub:dual", ${JSON.stringify(ADDR)});
  const dualEmptyArr = await scanAddress("stub:dual", ${JSON.stringify(ADDR)}, undefined, [], []);
  assert(dualOld.notes.length === 1 && dualEmptyArr.notes.length === 1,
         "dual: omitted/empty notebookAddresses must both keep the note (dedup off)");
  console.log("PASS DISPLAY-OWNER dedup: omitted/empty notebookAddresses is a byte-identical no-op");

  // (f) A missing "prevout" field on one input (esplora sometimes omits
  // it) must not crash the anchor search — it's skipped, and the real
  // notebook input that follows still anchors correctly.
  const missingPrevout = await scanAddress("stub:dualMissingPrevout", ${JSON.stringify(ADDR)},
                                            undefined, [], [${JSON.stringify(NB2)}]);
  assert(missingPrevout.notes.length === 1 && !missingPrevout.notes[0].received,
         "dualMissingPrevout: a prevout-less input must not crash or block the real anchor: " +
         JSON.stringify(missingPrevout.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: a missing-prevout input is skipped, not fatal");

  console.log("CHAIN-SCAN UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
