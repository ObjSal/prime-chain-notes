//! Minimal pure-Rust BIP-174 (PSBT v0) codec — just the key-path subset the
//! Prime app needs to act as an EXTERNAL signer for the desktop peer:
//! parse an unsigned/partial PSBT, recognise the inputs that pay our own
//! taproot address, sign them (BIP341 key-path via `sighash`/`sign`), and
//! re-serialize a signed PSBT.
//!
//! The desktop app builds and finalizes PSBTs with rust-bitcoin (host); this
//! codec is the DEVICE side, so — like the rest of notes-core — it is pure
//! Rust with no `bitcoin`/secp256k1-sys dependency. `tests/psbt.rs`
//! cross-checks byte-level interop against rust-bitcoin in both directions.
//!
//! Fidelity: unknown key-value pairs (BIP32 derivations, tap key origins,
//! outputs, etc.) are preserved verbatim so a round-trip never drops the
//! fields a hardware wallet or the desktop finalizer relies on. We only need
//! to UNDERSTAND witness_utxo, tap_internal_key and tap_key_sig; everything
//! else rides along untouched.

use crate::sighash::taproot_key_spend_sighash;
use crate::sign::schnorr_sign;
use crate::tx::{write_varint, Transaction, TxOut, Utxo};
use crate::Error;

const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff]; // "psbt\xff"
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// The note-tx convention: every input signals RBF. Our `Transaction` model
/// hard-codes this sequence, so we require it on parse (the desktop builds
/// funding PSBTs the same way).
const RBF_SEQUENCE: u32 = 0xffff_fffd;

/// A per-input PSBT map. Only the fields we act on are typed; the rest are
/// kept verbatim as `(key, value)` for lossless round-trips.
#[derive(Debug, Clone, Default)]
pub struct PsbtInput {
    /// The spent output (value + scriptPubKey) — required to sign and to
    /// recognise our own inputs.
    pub witness_utxo: Option<TxOut>,
    /// x-only taproot internal key (PSBT_IN_TAP_INTERNAL_KEY).
    pub tap_internal_key: Option<[u8; 32]>,
    /// Schnorr signature for a key-path spend (PSBT_IN_TAP_KEY_SIG), 64 bytes
    /// for SIGHASH_DEFAULT (or 65 with an explicit sighash-type byte).
    pub tap_key_sig: Option<Vec<u8>>,
    /// Every other key-value pair, preserved verbatim (key includes its type
    /// byte and any key-data).
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A per-output PSBT map. We never need to interpret these — kept verbatim.
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A parsed PSBT. `unsigned_tx.inputs[i].value` is backfilled from the
/// matching `inputs[i].witness_utxo` so the BIP341 sighash (which needs the
/// input amounts) can be computed directly.
#[derive(Debug, Clone)]
pub struct Psbt {
    pub unsigned_tx: Transaction,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
    pub global_unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Psbt {
    /// Build an unsigned PSBT from a note/funding tx plus each input's spent
    /// output and (optional) taproot internal key. `tx.witnesses` is cleared;
    /// input amounts are taken from `witness_utxos`.
    pub fn from_unsigned(
        mut tx: Transaction,
        witness_utxos: Vec<TxOut>,
        tap_internal_keys: Vec<Option<[u8; 32]>>,
    ) -> Result<Self, Error> {
        if witness_utxos.len() != tx.inputs.len() || tap_internal_keys.len() != tx.inputs.len() {
            return Err(Error::Psbt("witness_utxo/internal_key count != inputs"));
        }
        tx.witnesses.clear();
        for (i, wu) in witness_utxos.iter().enumerate() {
            tx.inputs[i].value = wu.value;
        }
        let inputs = witness_utxos
            .into_iter()
            .zip(tap_internal_keys)
            .map(|(wu, ik)| PsbtInput {
                witness_utxo: Some(wu),
                tap_internal_key: ik,
                tap_key_sig: None,
                unknown: Vec::new(),
            })
            .collect();
        let outputs = (0..tx.outputs.len()).map(|_| PsbtOutput::default()).collect();
        Ok(Psbt { unsigned_tx: tx, inputs, outputs, global_unknown: Vec::new() })
    }

    /// Parse BIP-174 bytes into a `Psbt`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(5)? != MAGIC {
            return Err(Error::Psbt("bad magic"));
        }

        // --- global map ---
        let mut unsigned_tx: Option<Transaction> = None;
        let mut global_unknown = Vec::new();
        for (key, val) in r.read_map()? {
            if key[0] == PSBT_GLOBAL_UNSIGNED_TX && key.len() == 1 {
                if unsigned_tx.is_some() {
                    return Err(Error::Psbt("duplicate unsigned tx"));
                }
                unsigned_tx = Some(parse_unsigned_tx(&val)?);
            } else {
                global_unknown.push((key, val));
            }
        }
        let mut unsigned_tx = unsigned_tx.ok_or(Error::Psbt("missing unsigned tx"))?;

        // --- input maps (one per tx input) ---
        let mut inputs = Vec::with_capacity(unsigned_tx.inputs.len());
        for _ in 0..unsigned_tx.inputs.len() {
            let mut inp = PsbtInput::default();
            for (key, val) in r.read_map()? {
                match key[0] {
                    PSBT_IN_WITNESS_UTXO if key.len() == 1 => {
                        inp.witness_utxo = Some(parse_txout(&val)?);
                    }
                    PSBT_IN_TAP_INTERNAL_KEY if key.len() == 1 => {
                        inp.tap_internal_key =
                            Some(val.as_slice().try_into().map_err(|_| {
                                Error::Psbt("tap_internal_key not 32 bytes")
                            })?);
                    }
                    PSBT_IN_TAP_KEY_SIG if key.len() == 1 => {
                        if val.len() != 64 && val.len() != 65 {
                            return Err(Error::Psbt("tap_key_sig not 64/65 bytes"));
                        }
                        inp.tap_key_sig = Some(val);
                    }
                    _ => inp.unknown.push((key, val)),
                }
            }
            inputs.push(inp);
        }

        // --- output maps (one per tx output) ---
        let mut outputs = Vec::with_capacity(unsigned_tx.outputs.len());
        for _ in 0..unsigned_tx.outputs.len() {
            let mut outp = PsbtOutput::default();
            for kv in r.read_map()? {
                outp.unknown.push(kv);
            }
            outputs.push(outp);
        }

        if r.remaining() != 0 {
            return Err(Error::Psbt("trailing bytes after PSBT"));
        }

        // Backfill input amounts from witness_utxo so sighashing works.
        for (i, inp) in inputs.iter().enumerate() {
            if let Some(wu) = &inp.witness_utxo {
                unsigned_tx.inputs[i].value = wu.value;
            }
        }
        Ok(Psbt { unsigned_tx, inputs, outputs, global_unknown })
    }

    /// Serialize to BIP-174 bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();

        // global
        write_kv(&mut out, &[PSBT_GLOBAL_UNSIGNED_TX], &self.unsigned_tx.serialize_legacy());
        for (k, v) in &self.global_unknown {
            write_kv(&mut out, k, v);
        }
        out.push(0x00);

        // inputs
        for inp in &self.inputs {
            if let Some(wu) = &inp.witness_utxo {
                write_kv(&mut out, &[PSBT_IN_WITNESS_UTXO], &serialize_txout(wu));
            }
            if let Some(k) = &inp.tap_internal_key {
                write_kv(&mut out, &[PSBT_IN_TAP_INTERNAL_KEY], k);
            }
            if let Some(sig) = &inp.tap_key_sig {
                write_kv(&mut out, &[PSBT_IN_TAP_KEY_SIG], sig);
            }
            for (k, v) in &inp.unknown {
                write_kv(&mut out, k, v);
            }
            out.push(0x00);
        }

        // outputs
        for outp in &self.outputs {
            for (k, v) in &outp.unknown {
                write_kv(&mut out, k, v);
            }
            out.push(0x00);
        }
        out
    }

    /// scriptPubKeys of every input's spent output (needed for sighashing).
    /// Errors if any input is missing its `witness_utxo`.
    pub fn prevout_spks(&self) -> Result<Vec<Vec<u8>>, Error> {
        self.inputs
            .iter()
            .map(|i| {
                i.witness_utxo
                    .as_ref()
                    .map(|w| w.script_pubkey.clone())
                    .ok_or(Error::Psbt("input missing witness_utxo"))
            })
            .collect()
    }

    /// BIP341 key-path sighash (SIGHASH_DEFAULT) for input `index`.
    pub fn taproot_key_spend_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= self.inputs.len() {
            return Err(Error::Psbt("input index out of range"));
        }
        let spks = self.prevout_spks()?;
        Ok(taproot_key_spend_sighash(&self.unsigned_tx, &spks, index))
    }

    /// Sign input `index` as a taproot key-path spend with `tweaked_seckey`
    /// (already taproot-tweaked) and set its `tap_key_sig`. `aux` is 32 bytes
    /// of BIP340 auxiliary randomness (device TRNG).
    pub fn sign_taproot_key_path(
        &mut self,
        index: usize,
        tweaked_seckey: &[u8; 32],
        aux: &[u8; 32],
    ) -> Result<(), Error> {
        let sighash = self.taproot_key_spend_sighash(index)?;
        let sig = schnorr_sign(tweaked_seckey, &sighash, aux)?;
        self.inputs[index].tap_key_sig = Some(sig.to_vec());
        Ok(())
    }

    /// The x-only output key of input `index`'s spent output iff it is a P2TR
    /// scriptPubKey — used by a signer to recognise its own inputs by address.
    pub fn input_p2tr_output_x(&self, index: usize) -> Option<[u8; 32]> {
        let spk = &self.inputs.get(index)?.witness_utxo.as_ref()?.script_pubkey;
        crate::address::p2tr_x_of_spk(spk)
    }

    /// Sign every input whose spent output is OUR P2TR key-path address
    /// (`output_x`) with `tweaked_seckey`, leaving foreign inputs untouched.
    /// This is the external-signer entry point (the Prime app): recognise our
    /// own inputs by scriptPubKey and add a `tap_key_sig` to each. `aux`
    /// supplies fresh BIP340 randomness per input (device TRNG). Returns
    /// `(ours, newly_signed)`.
    pub fn sign_own_taproot(
        &mut self,
        output_x: &[u8; 32],
        tweaked_seckey: &[u8; 32],
        mut aux: impl FnMut() -> Result<[u8; 32], Error>,
    ) -> Result<(usize, usize), Error> {
        let our_spk = crate::address::p2tr_script_pubkey(output_x);
        let mut ours = 0;
        let mut signed = 0;
        for i in 0..self.inputs.len() {
            let is_ours = self.inputs[i]
                .witness_utxo
                .as_ref()
                .map(|w| w.script_pubkey == our_spk)
                .unwrap_or(false);
            if !is_ours {
                continue;
            }
            ours += 1;
            if self.inputs[i].tap_key_sig.is_some() {
                continue; // already signed
            }
            self.sign_taproot_key_path(i, tweaked_seckey, &aux()?)?;
            signed += 1;
        }
        Ok((ours, signed))
    }

    /// Finalize a fully-signed key-path taproot PSBT into a broadcastable
    /// transaction: each input's witness is its single `tap_key_sig`. Errors
    /// if any input is unsigned. (p2wpkh finalization is left to the desktop's
    /// rust-bitcoin finalizer; the device only ever signs taproot.)
    pub fn extract_final_tx(&self) -> Result<Transaction, Error> {
        let mut tx = self.unsigned_tx.clone();
        tx.witnesses = Vec::with_capacity(tx.inputs.len());
        for inp in &self.inputs {
            let sig = inp
                .tap_key_sig
                .as_ref()
                .ok_or(Error::Psbt("input not signed (no tap_key_sig)"))?;
            tx.witnesses.push(vec![sig.clone()]);
        }
        Ok(tx)
    }
}

// ---- helpers ----

fn write_kv(out: &mut Vec<u8>, key: &[u8], val: &[u8]) {
    write_varint(out, key.len() as u64);
    out.extend_from_slice(key);
    write_varint(out, val.len() as u64);
    out.extend_from_slice(val);
}

fn serialize_txout(o: &TxOut) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 1 + o.script_pubkey.len());
    v.extend_from_slice(&o.value.to_le_bytes());
    write_varint(&mut v, o.script_pubkey.len() as u64);
    v.extend_from_slice(&o.script_pubkey);
    v
}

fn parse_txout(bytes: &[u8]) -> Result<TxOut, Error> {
    let mut r = Reader::new(bytes);
    let value = r.u64_le()?;
    let spk_len = r.varint()? as usize;
    let script_pubkey = r.take(spk_len)?.to_vec();
    if r.remaining() != 0 {
        return Err(Error::Psbt("trailing bytes in witness_utxo"));
    }
    Ok(TxOut { value, script_pubkey })
}

/// Parse the legacy (no-witness) unsigned transaction embedded in the global
/// map. Enforces the PSBT invariants we rely on: empty scriptSigs and our
/// RBF sequence (the only sequence our `Transaction` model can represent).
fn parse_unsigned_tx(bytes: &[u8]) -> Result<Transaction, Error> {
    let mut r = Reader::new(bytes);
    let version = r.i32_le()?;
    let n_in = r.varint()? as usize;
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let txid: [u8; 32] =
            r.take(32)?.try_into().map_err(|_| Error::Psbt("short txid"))?;
        let vout = r.u32_le()?;
        let script_len = r.varint()? as usize;
        if script_len != 0 {
            return Err(Error::Psbt("unsigned tx input carries a scriptSig"));
        }
        let sequence = r.u32_le()?;
        if sequence != RBF_SEQUENCE {
            return Err(Error::Psbt("unexpected input sequence (want 0xfffffffd)"));
        }
        inputs.push(Utxo { txid, vout, value: 0 });
    }
    let n_out = r.varint()? as usize;
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let value = r.u64_le()?;
        let spk_len = r.varint()? as usize;
        let script_pubkey = r.take(spk_len)?.to_vec();
        outputs.push(TxOut { value, script_pubkey });
    }
    let lock_time = r.u32_le()?;
    if r.remaining() != 0 {
        return Err(Error::Psbt("trailing bytes in unsigned tx"));
    }
    Ok(Transaction { version, lock_time, inputs, outputs, witnesses: Vec::new() })
}

/// Bounds-checked byte cursor.
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
            return Err(Error::Psbt("unexpected end of input"));
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

    /// Read a PSBT key-value map up to its `0x00` separator. Each pair is
    /// `<keylen><key><vallen><val>`; a zero keylen ends the map.
    fn read_map(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let mut kvs = Vec::new();
        loop {
            let klen = self.varint()? as usize;
            if klen == 0 {
                break;
            }
            let key = self.take(klen)?.to_vec();
            let vlen = self.varint()? as usize;
            let val = self.take(vlen)?.to_vec();
            kvs.push((key, val));
        }
        Ok(kvs)
    }
}
