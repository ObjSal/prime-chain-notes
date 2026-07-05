//! Minimal bitcoin transaction model: exactly what a note tx needs —
//! P2TR key-path inputs, OP_RETURN outputs, one P2TR change output.
//! Segwit (BIP144) serialization, txid, weight/vsize, fee estimation,
//! coin selection and end-to-end note-tx construction.

use crate::address::p2tr_script_pubkey;
use crate::keys::double_sha256;
use crate::sighash::taproot_key_spend_sighash;
use crate::sign::schnorr_sign;
use crate::{Error, DUST_LIMIT};

/// An unspent output of OUR notes address (all inputs are ours by
/// construction). `txid` is internal byte order (reversed display hex).
#[derive(Debug, Clone)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<TxOut>,
    /// One witness stack per input; empty until signed.
    pub witnesses: Vec<Vec<Vec<u8>>>,
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// OP_RETURN script with a single canonical push of `payload`.
pub fn op_return_script(payload: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(payload.len() + 4);
    script.push(0x6a); // OP_RETURN
    match payload.len() {
        0..=75 => script.push(payload.len() as u8),
        76..=255 => {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(payload.len() as u8);
        }
        _ => {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        }
    }
    script.extend_from_slice(payload);
    script
}

/// Extract the pushed payload from an OP_RETURN scriptPubKey (the scanner
/// side of `op_return_script`). None for non-OP_RETURN or multi-push.
pub fn op_return_payload(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&0x6a) {
        return None;
    }
    let rest = &script[1..];
    let (len, data) = match rest.first()? {
        n @ 1..=75 => (*n as usize, &rest[1..]),
        0x4c => (*rest.get(1)? as usize, &rest[2..]),
        0x4d => (
            u16::from_le_bytes([*rest.get(1)?, *rest.get(2)?]) as usize,
            &rest[3..],
        ),
        _ => return None,
    };
    (data.len() == len).then_some(data)
}

impl Transaction {
    fn serialize_common_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
    }

    fn serialize_in_outs(&self, out: &mut Vec<u8>) {
        write_varint(out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_le_bytes());
            out.push(0); // empty scriptSig (segwit)
            out.extend_from_slice(&0xffff_fffdu32.to_le_bytes()); // RBF-signaling
        }
        write_varint(out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_varint(out, output.script_pubkey.len() as u64);
            out.extend_from_slice(&output.script_pubkey);
        }
    }

    /// Legacy (no-witness) serialization — this is what txid hashes.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_common_prefix(&mut out);
        self.serialize_in_outs(&mut out);
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Full BIP144 serialization with witnesses (what gets broadcast).
    pub fn serialize_segwit(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_common_prefix(&mut out);
        out.push(0x00); // marker
        out.push(0x01); // flag
        self.serialize_in_outs(&mut out);
        for witness in &self.witnesses {
            write_varint(&mut out, witness.len() as u64);
            for item in witness {
                write_varint(&mut out, item.len() as u64);
                out.extend_from_slice(item);
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// txid in internal byte order (reverse for display hex).
    pub fn txid(&self) -> [u8; 32] {
        double_sha256(&self.serialize_legacy())
    }

    /// Display txid: reversed hex, as explorers and bitcoin-cli show it.
    pub fn txid_hex(&self) -> String {
        let mut id = self.txid();
        id.reverse();
        hex::encode(id)
    }

    /// weight = base*3 + total (BIP141); vsize = ceil(weight/4).
    pub fn vsize(&self) -> usize {
        let base = self.serialize_legacy().len();
        let total = self.serialize_segwit().len();
        (base * 3 + total).div_ceil(4)
    }
}

/// Predicted vsize of a note tx BEFORE it exists — pure arithmetic for the
/// keystroke cost estimator. Key-path P2TR: 57.5 weight-units of input
/// witness (66 witness bytes + marker/flag amortized), matched by tests
/// against real signed transactions.
pub fn estimate_vsize(
    n_inputs: usize,
    payload_lens: &[usize],
    recipient_spk_len: Option<usize>,
    change: bool,
) -> usize {
    // Base (non-witness) bytes.
    let mut base = 4 + 4; // version + locktime
    base += varint_len(n_inputs) + n_inputs * (32 + 4 + 1 + 4);
    let n_outputs =
        payload_lens.len() + usize::from(recipient_spk_len.is_some()) + usize::from(change);
    base += varint_len(n_outputs);
    for &len in payload_lens {
        base += 8 + varint_len_script(len) + script_len(len);
    }
    if let Some(spk_len) = recipient_spk_len {
        base += 8 + varint_len(spk_len) + spk_len;
    }
    if change {
        base += 8 + 1 + 34;
    }
    // Witness bytes: marker+flag plus one 64-byte-sig stack per input.
    let witness = 2 + n_inputs * (1 + 1 + 64);
    (base * 4 + witness).div_ceil(4)
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

fn script_len(payload: usize) -> usize {
    op_return_script_len(payload)
}

fn op_return_script_len(payload: usize) -> usize {
    1 + match payload {
        0..=75 => 1,
        76..=255 => 2,
        _ => 3,
    } + payload
}

fn varint_len_script(payload: usize) -> usize {
    varint_len(op_return_script_len(payload))
}

/// A fully built, signed note transaction plus its accounting.
#[derive(Debug, Clone)]
pub struct NoteTx {
    pub tx: Transaction,
    pub fee: u64,
    pub change: u64,
    /// Sats delivered to a directed-note recipient (0 for self-notes and
    /// sweeps; DUST_LIMIT for directed notes).
    pub sent: u64,
    pub vsize: usize,
    pub txid_hex: String,
    pub raw_hex: String,
    pub spent_outpoints: Vec<([u8; 32], u32)>,
}

/// Build and sign a sweep: spend ALL `available` UTXOs (ours, key-path)
/// into a single external output `dest_spk`, everything minus fee. Used to
/// move funds off the notes address (e.g. returning testnet coins).
pub fn build_sweep_tx(
    available: &[Utxo],
    our_output_x: &[u8; 32],
    dest_spk: Vec<u8>,
    fee_rate: f64,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if available.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    let n = available.len();
    let in_value: u64 = available.iter().map(|u| u.value).sum();
    let base = 4 + varint_len(n) + n * 41 + 1 + (8 + varint_len(dest_spk.len()) + dest_spk.len()) + 4;
    let witness = 2 + n * 66;
    let vsize = (base * 4 + witness).div_ceil(4);
    let fee = (vsize as f64 * fee_rate).ceil() as u64;
    if in_value <= fee || in_value - fee < DUST_LIMIT {
        return Err(Error::InsufficientFunds);
    }

    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        inputs: available.to_vec(),
        outputs: vec![TxOut { value: in_value - fee, script_pubkey: dest_spk }],
        witnesses: Vec::new(),
    };
    let our_spk = p2tr_script_pubkey(our_output_x);
    let prevout_spks: Vec<Vec<u8>> = tx.inputs.iter().map(|_| our_spk.clone()).collect();
    for index in 0..tx.inputs.len() {
        let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
        let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
        tx.witnesses.push(vec![sig.to_vec()]);
    }
    Ok(NoteTx {
        fee,
        change: 0,
        sent: 0,
        vsize: tx.vsize(),
        txid_hex: tx.txid_hex(),
        raw_hex: hex::encode(tx.serialize_segwit()),
        spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
        tx,
    })
}

/// Build and sign a note tx: OP_RETURN outputs for `payloads`, then — for
/// directed notes — a DUST_LIMIT output to `recipient_spk`, then change
/// back to `output_x` (our own tweaked key). Inputs selected largest-first
/// from `available` until value covers fee (+ dust) at `fee_rate` sat/vB.
/// `tweaked_seckey` is the taproot-tweaked signing key; `aux` supplies
/// BIP340 aux randomness per input.
pub fn build_note_tx(
    available: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    fee_rate: f64,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let sent: u64 = if recipient_spk.is_some() { DUST_LIMIT } else { 0 };
    let mut candidates = available.to_vec();
    candidates.sort_by(|a, b| b.value.cmp(&a.value));

    let change_spk = p2tr_script_pubkey(output_x);
    let mut selected: Vec<Utxo> = Vec::new();
    let mut in_value: u64 = 0;

    for utxo in candidates {
        selected.push(utxo.clone());
        in_value += utxo.value;

        // Try with a change output first; fall back to no-change.
        for change in [true, false] {
            let vsize = estimate_vsize(
                selected.len(),
                &payload_lens,
                recipient_spk.map(<[u8]>::len),
                change,
            );
            let fee = (vsize as f64 * fee_rate).ceil() as u64;
            if in_value < fee + sent {
                continue;
            }
            let change_value = in_value - fee - sent;
            if change && change_value < DUST_LIMIT {
                continue;
            }
            if !change && change_value > DUST_LIMIT {
                // Overshoot without change would burn > dust into fees;
                // prefer adding the change output (previous iteration).
                continue;
            }

            let mut outputs: Vec<TxOut> = payloads
                .iter()
                .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
                .collect();
            if let Some(spk) = recipient_spk {
                outputs.push(TxOut { value: DUST_LIMIT, script_pubkey: spk.to_vec() });
            }
            if change {
                outputs.push(TxOut { value: change_value, script_pubkey: change_spk.clone() });
            }

            let mut tx = Transaction {
                version: 2,
                lock_time: 0,
                inputs: selected.clone(),
                outputs,
                witnesses: Vec::new(),
            };

            let prevout_spks: Vec<Vec<u8>> =
                tx.inputs.iter().map(|_| change_spk.clone()).collect();
            for index in 0..tx.inputs.len() {
                let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
                let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
                tx.witnesses.push(vec![sig.to_vec()]);
            }

            let actual_fee = in_value - sent - if change { change_value } else { 0 };
            return Ok(NoteTx {
                fee: actual_fee,
                change: if change { change_value } else { 0 },
                sent,
                vsize: tx.vsize(),
                txid_hex: tx.txid_hex(),
                raw_hex: hex::encode(tx.serialize_segwit()),
                spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
                tx,
            });
        }
    }
    Err(Error::InsufficientFunds)
}
