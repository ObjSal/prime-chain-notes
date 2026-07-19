//! The PNTE on-chain envelope: `PNTE || ver || flags || note_id || seq ||
//! total || chunk_bytes`, one envelope per OP_RETURN output.
//!
//! Chunk size is POLICY, not protocol (PLAN-chain-notes.md): the caller
//! passes `max_payload` (what the broadcast endpoint relays) and the body
//! is split to fit. FROZEN FORMAT — every confirmed note is encoded this
//! way forever; only additive versioning is allowed.

use crate::Error;

pub const MAGIC: [u8; 4] = *b"PNTE";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 12;

/// flags bit 0: 1 = private (AEAD blob), 0 = public (plaintext UTF-8).
pub const FLAG_PRIVATE: u8 = 0x01;
/// flags bit 1: 1 = directed (note addressed to another taproot address via
/// a dust output; private bodies sealed under the dm.rs ECDH key, not the
/// self enc_key). Additive to the FROZEN v1 layout.
pub const FLAG_DIRECTED: u8 = 0x02;
/// flags bit 2: 1 = multi-recipient directed note (2..=255 recipients).
/// Valid only together with FLAG_DIRECTED — a single-recipient directed
/// note NEVER sets this bit (composers only emit it for count >= 2), so
/// every pre-existing directed-note wire byte is unchanged. FROZEN body
/// framing once this bit is set (see dm.rs for the multi-recipient crypto
/// that fills it in):
///   public  (FLAG_PRIVATE clear): `count(u8) || utf8 text`
///   private (FLAG_PRIVATE set):   `count(u8) || count × wrap(72B each) || sealed_body`
/// `count` is the number of recipients (the tx's recipient outputs,
/// `output_addrs[0..count]`, precede change by construction). Decoders are
/// LIBERAL: any count 1..=255 is accepted; count 0, or a body too short
/// for the declared framing, is undecodable (not a crash) — see
/// `bundle.rs`'s scanner.
pub const FLAG_MULTI: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub flags: u8,
    pub note_id: [u8; 4],
    pub seq: u8,
    pub total: u8,
    pub data: Vec<u8>,
}

impl Chunk {
    pub fn is_private(&self) -> bool {
        self.flags & FLAG_PRIVATE != 0
    }

    pub fn is_directed(&self) -> bool {
        self.flags & FLAG_DIRECTED != 0
    }

    pub fn is_multi(&self) -> bool {
        self.flags & FLAG_MULTI != 0
    }
}

/// Split `body` (already-sealed blob for private notes, UTF-8 for public)
/// into enveloped OP_RETURN payloads of at most `max_payload` bytes each.
pub fn encode_chunks(
    note_id: [u8; 4],
    flags: u8,
    body: &[u8],
    max_payload: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    if max_payload <= HEADER_LEN {
        return Err(Error::Envelope("max_payload smaller than header"));
    }
    if body.is_empty() {
        return Err(Error::Envelope("empty body"));
    }
    let chunk_size = max_payload - HEADER_LEN;
    let total = body.len().div_ceil(chunk_size);
    if total > u8::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let mut out = Vec::with_capacity(total);
    for (seq, piece) in body.chunks(chunk_size).enumerate() {
        let mut payload = Vec::with_capacity(HEADER_LEN + piece.len());
        payload.extend_from_slice(&MAGIC);
        payload.push(VERSION);
        payload.push(flags);
        payload.extend_from_slice(&note_id);
        payload.push(seq as u8);
        payload.push(total as u8);
        payload.extend_from_slice(piece);
        out.push(payload);
    }
    Ok(out)
}

/// Parse one OP_RETURN payload. `None` = not a PNTE envelope (foreign
/// OP_RETURN data — silently ignored by the scanner, not an error).
pub fn decode(payload: &[u8]) -> Option<Chunk> {
    if payload.len() <= HEADER_LEN || payload[..4] != MAGIC || payload[4] != VERSION {
        return None;
    }
    let mut note_id = [0u8; 4];
    note_id.copy_from_slice(&payload[6..10]);
    let (seq, total) = (payload[10], payload[11]);
    if total == 0 || seq >= total {
        return None;
    }
    Some(Chunk {
        flags: payload[5],
        note_id,
        seq,
        total,
        data: payload[HEADER_LEN..].to_vec(),
    })
}

/// Reassemble a full body from one note's chunks (any order). Fails if a
/// seq is missing/duplicated or the chunks disagree on total/flags.
pub fn reassemble(chunks: &[Chunk]) -> Result<Vec<u8>, Error> {
    let first = chunks.first().ok_or(Error::Envelope("no chunks"))?;
    let total = first.total as usize;
    if chunks.len() != total {
        return Err(Error::Envelope("missing chunks"));
    }
    let mut slots: Vec<Option<&Chunk>> = vec![None; total];
    for c in chunks {
        if c.total != first.total || c.flags != first.flags || c.note_id != first.note_id {
            return Err(Error::Envelope("inconsistent chunks"));
        }
        let slot = &mut slots[c.seq as usize];
        if slot.is_some() {
            return Err(Error::Envelope("duplicate seq"));
        }
        *slot = Some(c);
    }
    let mut body = Vec::new();
    for slot in slots {
        body.extend_from_slice(&slot.expect("len checked").data);
    }
    Ok(body)
}
