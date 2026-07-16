// Shared chain-scanning core for viewer.html and note.html: esplora fetch
// + pagination, OP_RETURN parsing, the JS port of the FROZEN PNTE envelope
// (notes-core/src/envelope.rs), and the note-card renderer.
//
// Note text is arbitrary attacker-writable chain data — every renderer
// here builds DOM via textContent, never innerHTML.
"use strict";

const API = {
  mainnet:  { base: "https://mempool.space/api",          explorer: "https://mempool.space" },
  testnet4: { base: "https://mempool.space/testnet4/api", explorer: "https://mempool.space/testnet4" },
  signet:   { base: "https://mempool.space/signet/api",   explorer: "https://mempool.space/signet" },
  regtest:  { base: "/regtest/api",                       explorer: null },
};

const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;
const P2TR_RE = /^(bc|tb|bcrt)1p/;

const shortAddr = (a) => (a && a.length > 17 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a || "unknown");

const hexToBytes = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));

async function esploraText(base, path, opts) {
  const resp = await fetch(base + path, opts);
  const text = await resp.text();
  if (!resp.ok) throw new Error(text || resp.statusText);
  return text;
}
const esploraJson = async (base, path) => JSON.parse(await esploraText(base, path));

// scriptPubKey hex → pushed payload hex (single canonical push), or null.
function opReturnPayload(spkHex) {
  const b = spkHex.toLowerCase();
  if (!b.startsWith("6a")) return null;
  let rest = b.slice(2);
  const op = parseInt(rest.slice(0, 2), 16);
  let len, data;
  if (op >= 1 && op <= 75)      { len = op; data = rest.slice(2); }
  else if (op === 0x4c)         { len = parseInt(rest.slice(2, 4), 16); data = rest.slice(4); }
  else if (op === 0x4d)         { len = parseInt(rest.slice(4, 6) + rest.slice(2, 4), 16); data = rest.slice(6); }
  else return null;
  return data.length === len * 2 ? data : null;
}

async function fullHistory(base, address, onPage) {
  // First page: /txs = up to 50 mempool + first 25 confirmed.
  const txs = await esploraJson(base, `/address/${address}/txs`);
  let confirmed = txs.filter((t) => t.status.confirmed);
  let last = confirmed.length ? confirmed[confirmed.length - 1].txid : null;
  // Paginate the confirmed chain until a short page.
  while (last) {
    const page = await esploraJson(base, `/address/${address}/txs/chain?after_txid=${last}`);
    if (!page.length) break;
    txs.push(...page);
    if (onPage) onPage(page.length);
    last = page.length >= 25 ? page[page.length - 1].txid : null;
  }
  const seen = new Set();
  return txs.filter((t) => !seen.has(t.txid) && seen.add(t.txid));
}

// Mirrors notes-core/src/envelope.rs (FROZEN format):
// PNTE(0-3) || ver=1(4) || flags(5) || note_id(6-9) || seq(10) || total(11) || data(12..)
function decodeEnvelope(b) {
  if (b.length <= 12) return null;
  if (b[0] !== 0x50 || b[1] !== 0x4e || b[2] !== 0x54 || b[3] !== 0x45) return null; // "PNTE"
  if (b[4] !== 1) return null;
  const seq = b[10], total = b[11];
  if (total === 0 || seq >= total) return null;
  let noteId = "";
  for (let i = 6; i < 10; i++) noteId += b[i].toString(16).padStart(2, "0");
  return { flags: b[5], noteId, seq, total, dataHex: null, data: b.slice(12) };
}

// envelope.rs reassemble(), tolerant: instead of erroring on missing/
// inconsistent chunks it reports {partial:{have,total}} so partially-
// synced notes can be surfaced (the device silently drops them).
function reassemble(chunks) {
  const first = chunks[0];
  const total = first.total;
  const slots = new Array(total).fill(null);
  for (const c of chunks) {
    if (c.total !== total || c.flags !== first.flags) return { partial: { have: chunks.length, total } };
    if (c.seq >= total || slots[c.seq]) return { partial: { have: chunks.length, total } };
    slots[c.seq] = c;
  }
  const have = slots.filter(Boolean).length;
  if (have < total) return { partial: { have, total } };
  const body = new Uint8Array(slots.reduce((n, s) => n + s.data.length, 0));
  let off = 0;
  for (const s of slots) { body.set(s.data, off); off += s.data.length; }
  return { body };
}

// Port of notes-core extract_notes/extract_notes_multi (bundle.rs).
// Acceptance: a tx that SPENDS FROM the notebook address, OR from any
// address in the optional `myAddresses` set (funding-unification PLAN,
// "Attribution & scanner changes" — e.g. a separate spending wallet),
// carries OWN notes (spoof resistance — anyone can send OP_RETURNs *to* an
// address, so those never count as yours); a tx that only PAYS the address
// and carries PNTE is a RECEIVED note, attributed to its (unforgeable)
// taproot input address. Chunks bucket by (note_id, origin) so a pays-me tx
// reusing one of your note_ids can never contaminate your own note.
// `myAddresses` defaults to just [address], so every existing caller's
// behavior is byte-identical — this is a pure extension, never a narrowing,
// mirroring the Rust self-spk-SET rule exactly (OR, not replace).
// Returns { notes (newest-first), noteTxs, receivedTxs, txsScanned, foreign, nonPnte }.
async function scanAddress(base, address, onPage, myAddresses) {
  const mine = new Set([address, ...(myAddresses || [])]);
  const txs = await fullHistory(base, address, onPage);

  const byId = new Map();
  let foreign = 0, nonPnte = 0, noteTxs = 0, receivedTxs = 0;
  for (const t of txs) {
    const payloads = t.vout
      .filter((o) => o.scriptpubkey_type === "op_return")
      .map((o) => opReturnPayload(o.scriptpubkey))
      .filter(Boolean);
    if (!payloads.length) continue;
    const spendsFromSelf = t.vin.some(
      (i) => i.prevout && mine.has(i.prevout.scriptpubkey_address)
    );
    const paysSelf = t.vout.some((o) => o.scriptpubkey_address === address);
    let originKey, from = null, to = null;
    if (spendsFromSelf) {
      originKey = "own";
      const outs = t.vout.filter(
        (o) =>
          o.scriptpubkey_type !== "op_return" &&
          o.scriptpubkey_address &&
          o.scriptpubkey_address !== address
      );
      to = (outs.find((o) => P2TR_RE.test(o.scriptpubkey_address)) || outs[0])
        ?.scriptpubkey_address || null;
      noteTxs++;
    } else if (paysSelf) {
      from =
        t.vin
          .map((i) => i.prevout && i.prevout.scriptpubkey_address)
          .find((a) => a && P2TR_RE.test(a)) || null;
      originKey = `recv:${from || "unknown"}`;
      receivedTxs++;
    } else {
      foreign++; // neither from nor to this address — pure spoof
      continue;
    }
    const txHeight = t.status.confirmed ? t.status.block_height : null;
    const txTime = t.status.confirmed ? t.status.block_time : null;
    for (const payloadHex of payloads) {
      const chunk = decodeEnvelope(hexToBytes(payloadHex));
      if (!chunk) { nonPnte++; continue; }
      chunk.dataHex = payloadHex.slice(24);   // for dedup below
      const key = `${chunk.noteId}|${originKey}`;
      let entry = byId.get(key);
      if (!entry) {
        entry = { noteId: chunk.noteId, chunks: [], txids: [], height: null,
                  blocktime: null, received: originKey !== "own", from, to: null };
        byId.set(key, entry);
      }
      // Drop exact duplicates (same chunk seen in overlapping txs).
      if (entry.chunks.some((c) => c.seq === chunk.seq && c.dataHex === chunk.dataHex)) continue;
      entry.chunks.push(chunk);
      if (!entry.txids.includes(t.txid)) entry.txids.push(t.txid);
      if (!entry.to) entry.to = to;
      // A note's height is its FIRST confirmation.
      if (txHeight != null && (entry.height == null || txHeight < entry.height)) {
        entry.height = txHeight;
        entry.blocktime = txTime;
      }
    }
  }

  const notes = [];
  for (const entry of byId.values()) {
    const asm = reassemble(entry.chunks);
    const flags = entry.chunks[0].flags;
    const priv = (flags & FLAG_PRIVATE) !== 0;
    const directed = (flags & FLAG_DIRECTED) !== 0;
    let text = null;
    if (asm.body && !priv) {
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(asm.body); }
      catch { text = null; }
    }
    notes.push({
      noteId: entry.noteId,
      private: priv,
      directed,
      received: entry.received,
      from: entry.received ? entry.from : null,
      to: entry.received ? null : (directed ? entry.to : null),
      partial: asm.partial || null,
      bodyLen: asm.body ? asm.body.length : null,
      text,
      txids: entry.txids,
      height: entry.height,
      blocktime: entry.blocktime,
    });
  }
  // Newest first: unconfirmed on top, then height descending.
  const sortKey = (n) => (n.height == null ? Number.MAX_SAFE_INTEGER : n.height);
  notes.sort((a, b) => sortKey(b) - sortKey(a));

  return { notes, noteTxs, receivedTxs, txsScanned: txs.length, foreign, nonPnte };
}

// One note → a .note card element. permalinkHref (optional) adds a
// right-aligned link to the single-note page.
function buildNoteCard(n, explorer, permalinkHref) {
  const card = document.createElement("div");
  card.className = "note";

  const head = document.createElement("div");
  head.className = "note-head";
  const id = document.createElement("span");
  id.textContent = `note ${n.noteId}`;
  head.appendChild(id);
  const pill = (label) => {
    const s = document.createElement("span");
    s.className = "pill";
    s.textContent = label;
    head.appendChild(s);
  };
  pill(n.private ? "private" : "public");
  if (n.received) pill(`from ${shortAddr(n.from)}`);
  else if (n.directed && n.to) pill(`to ${shortAddr(n.to)}`);
  if (n.height == null) pill("unconfirmed");
  if (n.partial) pill(`partial ${n.partial.have}/${n.partial.total}`);
  if (permalinkHref) {
    const a = document.createElement("a");
    a.className = "permalink";
    a.href = permalinkHref;
    a.textContent = "permalink";
    head.appendChild(a);
  }
  card.appendChild(head);

  const body = document.createElement("div");
  body.className = "note-body";
  if (n.partial) {
    body.classList.add("dim");
    body.textContent = `Partial note — ${n.partial.have} of ${n.partial.total} chunks found on-chain.`;
  } else if (n.private) {
    body.classList.add("enc");
    body.textContent = n.directed
      ? "Encrypted (directed) — readable only on the sender's and recipient's devices."
      : "Encrypted (private) — readable only on the device.";
  } else if (n.text != null) {
    body.textContent = n.text;
  } else {
    body.classList.add("dim");
    body.textContent = `Public note but not valid UTF-8 (${n.bodyLen} bytes).`;
  }
  card.appendChild(body);

  const meta = document.createElement("div");
  meta.className = "note-meta";
  meta.textContent = n.height != null
    ? `height ${n.height} · ${new Date(n.blocktime * 1000).toLocaleString()} · `
    : "unconfirmed · ";
  n.txids.forEach((txid, i) => {
    if (i) meta.appendChild(document.createTextNode(", "));
    if (explorer) {
      const a = document.createElement("a");
      a.href = `${explorer}/tx/${txid}`;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = txid;
      meta.appendChild(a);
    } else {
      const c = document.createElement("code");
      c.textContent = txid;
      meta.appendChild(c);
    }
  });
  card.appendChild(meta);
  return card;
}
