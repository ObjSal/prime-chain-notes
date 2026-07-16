//! P2WPKH (BIP143) signing (`notes_core::wpkh`) — funding-unification M0.
//! Byte-for-byte sighash cross-checks and an end-to-end signed-tx interop
//! test against rust-bitcoin, mirroring the crate's existing rust-bitcoin
//! cross-tests (`psbt.rs`, `export_vectors.rs`).
//!
//! Lives in `tests/` rather than an inline `#[cfg(test)]` module in
//! `src/wpkh.rs`: `cargo test` compiles ALL of `src/` (incl. `export.rs`)
//! into one crate together with anything `#[cfg(test)]` pulls in, and
//! `bitcoin`'s blanket `AsRef<PushBytes>` impl for `[u8; N]` collides with
//! `hex::encode`'s type inference in `export.rs` once `bitcoin` is in
//! scope anywhere in that crate. Integration tests compile as separate
//! crates, so `bitcoin` never leaks into the lib build.

use notes_core::address::{p2tr_script_pubkey, p2wpkh_script_pubkey};
use notes_core::keys::hash160;
use notes_core::sighash::taproot_key_spend_sighash;
use notes_core::sign::schnorr_sign;
use notes_core::tx::{op_return_script, Transaction, TxOut, Utxo};
use notes_core::wpkh::{
    bip143_sighash, p2wpkh_script_code, sign_mixed_inputs, sign_p2wpkh_input, InputKey,
    SIGHASH_ALL,
};

use k256::ecdsa::{Signature, SigningKey};

fn seckey(byte: u8) -> [u8; 32] {
    let mut k = [0x11u8; 32];
    k[0] = byte;
    k
}

fn pubkey_and_hash(seckey: &[u8; 32]) -> ([u8; 33], [u8; 20]) {
    let sk = SigningKey::from_bytes(seckey.into()).unwrap();
    let pk: [u8; 33] = sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
    (pk, hash160(&pk))
}

/// Several fixtures — single input, multiple inputs, mixed
/// P2TR-looking/P2WPKH prevouts, small and large amounts — cross-check
/// byte-for-byte against rust-bitcoin's `SighashCache::p2wpkh_signature_hash`.
/// BIP143's `hashPrevouts`/`hashSequence` only commit outpoints and (fixed)
/// sequence, not amounts/scripts, so the non-signed inputs' placeholder
/// values below don't need to be realistic — only their outpoints matter,
/// and our `Transaction` model hardcodes RBF sequence on every input
/// (there is no per-input sequence to vary).
#[test]
fn bip143_sighash_matches_rust_bitcoin() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf};

    struct Case {
        n_inputs: usize,
        wpkh_index: usize,
        wpkh_value: u64,
        outputs: Vec<(u64, Vec<u8>)>,
    }
    let dummy_p2tr = || {
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);
        spk
    };
    let cases = [
        Case {
            n_inputs: 1,
            wpkh_index: 0,
            wpkh_value: 50_000,
            outputs: vec![(0, op_return_script(b"hi")), (1_000, dummy_p2tr())],
        },
        Case {
            n_inputs: 3,
            wpkh_index: 1,
            wpkh_value: 12_345,
            outputs: vec![
                (0, op_return_script(b"multi input mixed prevouts note")),
                (330, dummy_p2tr()),
                (4_000, dummy_p2tr()),
            ],
        },
        Case {
            n_inputs: 2,
            wpkh_index: 0,
            wpkh_value: 1,
            outputs: vec![(0, op_return_script(&[0x42u8; 200]))],
        },
        Case {
            n_inputs: 4,
            wpkh_index: 3,
            wpkh_value: 2_100_000_000_000_000, // max realistic sat amount
            outputs: vec![(546, dummy_p2tr()), (0, op_return_script(b"last input signs"))],
        },
    ];

    for (ci, case) in cases.iter().enumerate() {
        let mut inputs = Vec::new();
        for i in 0..case.n_inputs {
            inputs.push(Utxo {
                txid: [(ci as u8).wrapping_mul(17).wrapping_add(i as u8); 32],
                vout: i as u32,
                value: if i == case.wpkh_index { case.wpkh_value } else { 0 },
            });
        }
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            inputs,
            outputs: case
                .outputs
                .iter()
                .map(|(v, s)| TxOut { value: *v, script_pubkey: s.clone() })
                .collect(),
            witnesses: Vec::new(),
        };

        let (_pk, pubkey_hash) = pubkey_and_hash(&seckey(ci as u8 + 1));
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let ours = bip143_sighash(&tx, case.wpkh_index, &script_code);

        let btx: bitcoin::Transaction = btc_deser(&tx.serialize_legacy()).unwrap();
        let mut cache = SighashCache::new(&btx);
        let spk = ScriptBuf::from_bytes([vec![0x00, 0x14], pubkey_hash.to_vec()].concat());
        let theirs = cache
            .p2wpkh_signature_hash(
                case.wpkh_index,
                &spk,
                Amount::from_sat(case.wpkh_value),
                EcdsaSighashType::All,
            )
            .unwrap();
        assert_eq!(ours, theirs.to_byte_array(), "case {ci}");
    }
}

/// Signature validity: the produced DER signature verifies (via k256's
/// verifier) against the independently-recomputed sighash, and is already
/// low-S (no further normalization needed).
#[test]
fn sign_p2wpkh_input_is_valid_and_low_s() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    let sk = seckey(0x77);
    let notebook_spk = p2tr_script_pubkey(&[0x55; 32]);
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        inputs: vec![Utxo { txid: [9u8; 32], vout: 2, value: 77_000 }],
        outputs: vec![
            TxOut { value: 0, script_pubkey: op_return_script(b"validity check") },
            TxOut { value: 330, script_pubkey: notebook_spk },
        ],
        witnesses: Vec::new(),
    };

    let witness = sign_p2wpkh_input(&tx, 0, &sk).unwrap();
    assert_eq!(witness.len(), 2, "witness stack is [sig, pubkey]");
    let sig_with_type = &witness[0];
    let pubkey_bytes = &witness[1];
    assert_eq!(*sig_with_type.last().unwrap(), SIGHASH_ALL);

    let der = &sig_with_type[..sig_with_type.len() - 1];
    let sig = Signature::from_der(der).unwrap();
    assert!(sig.normalize_s().is_none(), "signature must already be low-S");

    let (expected_pubkey, pubkey_hash) = pubkey_and_hash(&sk);
    assert_eq!(pubkey_bytes.as_slice(), expected_pubkey.as_slice());
    let script_code = p2wpkh_script_code(&pubkey_hash);
    let sighash = bip143_sighash(&tx, 0, &script_code);

    let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes).unwrap();
    vk.verify_prehash(&sighash, &sig).expect("signature must verify against its sighash");
}

/// End-to-end: build a tx with a P2WPKH prevout, sign it, then check
/// rust-bitcoin can parse the fully-signed (segwit) bytes and that its own
/// recomputed BIP143 sighash validates our witness signature — standing in
/// for `.verify()` since bitcoinconsensus isn't available.
#[test]
fn signed_p2wpkh_tx_verifies_under_rust_bitcoin_sighash() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
    use bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf};

    let sk = seckey(0x33);
    let (pubkey, pubkey_hash) = pubkey_and_hash(&sk);
    let value = 80_000u64;
    let notebook_spk = p2tr_script_pubkey(&[0x99; 32]);
    let change_spk = p2wpkh_script_pubkey(&[0x22; 20]);

    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        inputs: vec![Utxo { txid: [7u8; 32], vout: 0, value }],
        outputs: vec![
            TxOut { value: 0, script_pubkey: op_return_script(b"funded note e2e") },
            TxOut { value: 330, script_pubkey: notebook_spk },
            TxOut { value: 40_000, script_pubkey: change_spk },
        ],
        witnesses: Vec::new(),
    };
    tx.witnesses = vec![sign_p2wpkh_input(&tx, 0, &sk).unwrap()];

    let btx: bitcoin::Transaction = btc_deser(&tx.serialize_segwit()).unwrap();
    assert_eq!(btx.compute_txid().to_string(), tx.txid_hex());

    let spk = ScriptBuf::from_bytes([vec![0x00, 0x14], pubkey_hash.to_vec()].concat());
    let mut cache = SighashCache::new(&btx);
    let sighash = cache
        .p2wpkh_signature_hash(0, &spk, Amount::from_sat(value), EcdsaSighashType::All)
        .unwrap();

    let witness = btx.input[0].witness.to_vec();
    let sig_bytes = &witness[0];
    let der = &sig_bytes[..sig_bytes.len() - 1];
    assert_eq!(sig_bytes[sig_bytes.len() - 1], EcdsaSighashType::All as u8);

    let secp_sig = SecpSignature::from_der(der).unwrap();
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(sighash.to_byte_array());
    let secp_pubkey = SecpPublicKey::from_slice(&pubkey).unwrap();
    secp.verify_ecdsa(&msg, &secp_sig, &secp_pubkey)
        .expect("witness signature must verify under rust-bitcoin's own sighash");
}

/// `sign_mixed_inputs`: one taproot input (schnorr) and one P2WPKH input
/// (ECDSA) in a single tx, signed in one pass — reproduces what
/// `sign_p2wpkh_input`/`schnorr_sign` produce standalone, per input.
#[test]
fn sign_mixed_inputs_matches_standalone_signing() {
    let taproot_seckey = [0x44u8; 32];
    let wpkh_seckey = seckey(0x55);
    let taproot_spk = p2tr_script_pubkey(&[0x11; 32]);
    let wpkh_prevout_spk = {
        let (_pk, hash) = pubkey_and_hash(&wpkh_seckey);
        p2wpkh_script_pubkey(&hash)
    };

    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        inputs: vec![
            Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
            Utxo { txid: [2u8; 32], vout: 1, value: 40_000 },
        ],
        outputs: vec![TxOut { value: 90_000, script_pubkey: p2tr_script_pubkey(&[0x66; 32]) }],
        witnesses: Vec::new(),
    };
    let prevout_spks = vec![taproot_spk.clone(), wpkh_prevout_spk];
    let keys = [
        InputKey::Taproot { tweaked_seckey: &taproot_seckey },
        InputKey::P2wpkh { seckey: &wpkh_seckey },
    ];
    let aux = [0x42u8; 32];
    sign_mixed_inputs(&mut tx, &prevout_spks, &keys, || Ok(aux)).unwrap();

    assert_eq!(tx.witnesses.len(), 2);
    assert_eq!(tx.witnesses[0].len(), 1, "taproot witness is [sig]");
    let expected_taproot_sighash = taproot_key_spend_sighash(&tx, &prevout_spks, 0);
    let expected_taproot_sig =
        schnorr_sign(&taproot_seckey, &expected_taproot_sighash, &aux).unwrap();
    assert_eq!(tx.witnesses[0][0], expected_taproot_sig.to_vec());

    // Re-derive the wpkh signature standalone with a pristine (unsigned)
    // copy of the tx — sighashing never reads `tx.witnesses`, so this must
    // match exactly.
    let mut unsigned = tx.clone();
    unsigned.witnesses = Vec::new();
    let expected_wpkh_witness = sign_p2wpkh_input(&unsigned, 1, &wpkh_seckey).unwrap();
    assert_eq!(tx.witnesses[1], expected_wpkh_witness);
}
