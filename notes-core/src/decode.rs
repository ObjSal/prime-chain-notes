//! Raw bitcoin transaction deserializer — the read side of `tx.rs`'s
//! BIP144 serializer, and the first link in the device's universal
//! "Confirm & sign" chain (`confirm.rs`): before signing-and-queuing, the
//! app must show the transaction decoded FROM THE ACTUAL RAW BYTES it just
//! produced, never from the builder's own intent structs. Strict and
//! total: adversarial input (truncated buffers, huge claimed varints, the
//! legacy/segwit marker ambiguity) always returns `Err`, never panics or
//! over-allocates.
//!
//! **`decode_transaction`'s inputs always carry `value: 0`.** A raw
//! transaction never serializes its inputs' prevout amounts — that's
//! exactly why BIP341/BIP143 sighashing needs an out-of-band prevout
//! lookup, and why `tx.rs`'s own serializer never writes `Utxo::value` to
//! the wire either. Any caller that needs input amounts (fee math,
//! sighash reconstruction) must supply them itself, e.g. from a UTXO set
//! or PSBT `witness_utxo` — see `confirm.rs`'s `ConfirmCtx::prevouts`.
//!
//! Round-trips against `tx.rs`'s own encoder: for any [`Transaction`] `t`
//! (with every input's `value` zeroed first, per the note above),
//! `decode_transaction(&t.serialize_segwit())` equals `t`, and
//! `decode_transaction(&t.serialize_legacy())` equals `t` with
//! `witnesses` cleared too (the legacy encoding carries no witness
//! section at all). See `tests/decode.rs`.

use crate::tx::{Transaction, TxOut, Utxo};
use crate::Error;

/// The BIP144 segwit flag our own encoder always writes
/// (`tx.rs::serialize_segwit`'s hardcoded marker/flag bytes); no other
/// flag value is a transaction this crate could have produced, so
/// anything else is rejected rather than guessed at.
const SEGWIT_FLAG: u8 = 0x01;

/// The RBF-signaling sequence every input in our [`Transaction`] model
/// carries — hardcoded by `tx.rs::serialize_in_outs` and
/// `wpkh::bip143_sighash` alike, and enforced the same way by
/// `psbt.rs::parse_unsigned_tx` on its embedded unsigned tx.
const RBF_SEQUENCE: u32 = 0xffff_fffd;

/// Decode a serialized bitcoin transaction: BIP144 segwit (marker `0x00`,
/// flag `0x01`, witness stacks after the outputs) or legacy (no marker,
/// no witness section — what [`Transaction::serialize_legacy`] emits).
///
/// Rejects anything this crate's own encoder could not have produced —
/// a scriptSig on any input (every note/sweep tx this app builds is
/// witness-only: P2TR key-path or P2WPKH), a non-RBF sequence, an
/// unsupported segwit flag, or trailing bytes after the locktime — in
/// addition to the ordinary truncated/malformed-varint failures. This
/// keeps the decoder narrowly scoped to "what could the signer honestly
/// have produced", exactly like `psbt.rs`'s parser, rather than becoming
/// a general-purpose bitcoin tx parser.
pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, Error> {
    let mut r = Reader::new(bytes);
    let version = r.i32_le()?;

    // A real transaction can never have zero inputs, so a first-varint
    // read of exactly 0 is unambiguously the BIP144 marker byte, never a
    // genuine "0 inputs" legacy count — the same convention every
    // consensus decoder relies on to tell the two encodings apart. The
    // very next byte must then be the flag.
    let first = r.varint()?;
    let (n_in, segwit) = if first == 0 {
        let flag = r.u8()?;
        if flag != SEGWIT_FLAG {
            return Err(Error::Decode("unsupported segwit flag"));
        }
        (checked_usize(r.varint()?)?, true)
    } else {
        (checked_usize(first)?, false)
    };

    // Every Vec below grows one successfully-read element at a time —
    // never pre-allocated by an attacker-controlled count — so a huge
    // claimed count errors out on the very first missing byte instead of
    // attempting a huge allocation.
    let mut inputs = Vec::new();
    for _ in 0..n_in {
        let txid: [u8; 32] = r.take(32)?.try_into().expect("take(32) yields 32 bytes");
        let vout = r.u32_le()?;
        let script_len = checked_usize(r.varint()?)?;
        if script_len != 0 {
            return Err(Error::Decode("input carries a scriptSig (not a witness-only tx)"));
        }
        let sequence = r.u32_le()?;
        if sequence != RBF_SEQUENCE {
            return Err(Error::Decode("unexpected input sequence (want 0xfffffffd)"));
        }
        inputs.push(Utxo { txid, vout, value: 0 });
    }

    let n_out = checked_usize(r.varint()?)?;
    let mut outputs = Vec::new();
    for _ in 0..n_out {
        let value = r.u64_le()?;
        let spk_len = checked_usize(r.varint()?)?;
        let script_pubkey = r.take(spk_len)?.to_vec();
        outputs.push(TxOut { value, script_pubkey });
    }

    let mut witnesses = Vec::new();
    if segwit {
        for _ in 0..n_in {
            let n_items = checked_usize(r.varint()?)?;
            let mut stack = Vec::new();
            for _ in 0..n_items {
                let len = checked_usize(r.varint()?)?;
                stack.push(r.take(len)?.to_vec());
            }
            witnesses.push(stack);
        }
    }

    let lock_time = r.u32_le()?;
    if r.remaining() != 0 {
        return Err(Error::Decode("trailing bytes after transaction"));
    }

    Ok(Transaction { version, lock_time, inputs, outputs, witnesses })
}

/// `u64` → `usize`, rejecting values that can't possibly index real bytes.
/// Guards 32-bit targets (the device is armv7a) from a silently
/// truncating `as usize` cast on an adversarial huge varint — without
/// this, a claimed count like `0x1_0000_0005` would wrap to `5` on a
/// 32-bit `usize` instead of erroring.
fn checked_usize(n: u64) -> Result<usize, Error> {
    usize::try_from(n).map_err(|_| Error::Decode("count too large"))
}

/// Bounds-checked byte cursor — every read either succeeds or returns
/// `Err`, never panics or reads out of bounds. Mirrors `psbt.rs`'s private
/// `Reader` (same pattern, kept separate per-module rather than shared —
/// neither module is large enough to justify a third crate-internal file
/// just for this).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::Decode("unexpected end of input"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32_le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i32_le(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64_le(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn varint(&mut self) -> Result<u64, Error> {
        Ok(match self.u8()? {
            0xff => self.u64_le()?,
            0xfe => self.u32_le()? as u64,
            0xfd => self.u16_le()? as u64,
            n => n as u64,
        })
    }
}
