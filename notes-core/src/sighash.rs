//! BIP341 signature message for taproot key-path spends, SIGHASH_DEFAULT.
//! All our inputs spend the same P2TR scriptPubKey (the notes address).

use sha2::{Digest, Sha256};

use crate::taproot::tagged_hash;
use crate::tx::{write_varint, Transaction};

/// Sighash for key-path spending input `index` with SIGHASH_DEFAULT (0x00).
/// `prevout_spks[i]` is the scriptPubKey of the output input `i` spends.
pub fn taproot_key_spend_sighash(
    tx: &Transaction,
    prevout_spks: &[Vec<u8>],
    index: usize,
) -> [u8; 32] {
    let mut prevouts = Vec::new();
    let mut amounts = Vec::new();
    let mut spks = Vec::new();
    let mut sequences = Vec::new();
    for (input, spk) in tx.inputs.iter().zip(prevout_spks) {
        prevouts.extend_from_slice(&input.txid);
        prevouts.extend_from_slice(&input.vout.to_le_bytes());
        amounts.extend_from_slice(&input.value.to_le_bytes());
        write_varint(&mut spks, spk.len() as u64);
        spks.extend_from_slice(spk);
        sequences.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
    }
    let mut outputs = Vec::new();
    for output in &tx.outputs {
        outputs.extend_from_slice(&output.value.to_le_bytes());
        write_varint(&mut outputs, output.script_pubkey.len() as u64);
        outputs.extend_from_slice(&output.script_pubkey);
    }

    let mut msg = Vec::with_capacity(1 + 1 + 4 + 4 + 32 * 5 + 1 + 4);
    msg.push(0x00); // epoch
    msg.push(0x00); // hash_type: SIGHASH_DEFAULT
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    msg.extend_from_slice(&Sha256::digest(&prevouts));
    msg.extend_from_slice(&Sha256::digest(&amounts));
    msg.extend_from_slice(&Sha256::digest(&spks));
    msg.extend_from_slice(&Sha256::digest(&sequences));
    msg.extend_from_slice(&Sha256::digest(&outputs));
    msg.push(0x00); // spend_type: key path, no annex
    msg.extend_from_slice(&(index as u32).to_le_bytes());

    tagged_hash("TapSighash", &msg)
}
