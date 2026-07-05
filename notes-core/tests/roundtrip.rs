//! Envelope/AEAD round-trips, fee-estimator exactness, full compose→scan
//! round-trips, and the rust-bitcoin cross-check of our transaction
//! serialization, sighash and signatures.

use notes_core::bundle::{
    compose_note, estimate_note_cost, extract_notes, Identity, OnchainTx, SyncBundle,
};
use notes_core::crypt::{self, SEAL_OVERHEAD};
use notes_core::envelope;
use notes_core::tx::{op_return_payload, Utxo};

const APP_SEED: [u8; 32] = [7u8; 32];
const AUX: [u8; 32] = [0x42; 32];

fn identity() -> Identity {
    Identity::from_app_seed(&APP_SEED).unwrap()
}

fn utxos() -> Vec<Utxo> {
    vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 1, value: 25_000 },
        Utxo { txid: [3u8; 32], vout: 0, value: 1_000 },
    ]
}

#[test]
fn envelope_roundtrip_boundaries() {
    // 80-byte policy → 68 data bytes per chunk. Exercise exact-fit, ±1.
    for len in [1usize, 67, 68, 69, 136, 137, 200] {
        let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let chunks_raw = envelope::encode_chunks([9, 9, 9, 9], 0, &body, 80).unwrap();
        assert!(chunks_raw.iter().all(|c| c.len() <= 80), "len {len}");
        let mut chunks: Vec<_> =
            chunks_raw.iter().map(|c| envelope::decode(c).unwrap()).collect();
        chunks.reverse(); // any order must reassemble
        assert_eq!(envelope::reassemble(&chunks).unwrap(), body, "len {len}");
    }
}

#[test]
fn envelope_rejects_bad_shapes() {
    assert!(envelope::encode_chunks([0; 4], 0, b"", 80).is_err());
    assert!(envelope::encode_chunks([0; 4], 0, b"x", 12).is_err());
    // > 255 chunks
    let big = vec![0u8; 68 * 256];
    assert!(envelope::encode_chunks([0; 4], 0, &big, 80).is_err());
    // foreign payloads
    assert!(envelope::decode(b"nonsense-not-pnte").is_none());
    assert!(envelope::decode(b"PNTE").is_none());
}

#[test]
fn seal_open_roundtrip_and_auth() {
    let key = [3u8; 32];
    let note_id = [1, 2, 3, 4];
    let blob = crypt::seal(&key, &note_id, "hola ₿".as_bytes()).unwrap();
    assert_eq!(blob.len(), "hola ₿".len() + SEAL_OVERHEAD);
    assert_eq!(crypt::open(&key, &note_id, &blob).unwrap(), "hola ₿".as_bytes());
    // wrong key / wrong note_id (AAD) / tampered byte all fail
    assert!(crypt::open(&[4u8; 32], &note_id, &blob).is_err());
    assert!(crypt::open(&key, &[9, 9, 9, 9], &blob).is_err());
    let mut bad = blob.clone();
    bad[30] ^= 1;
    assert!(crypt::open(&key, &note_id, &bad).is_err());
}

#[test]
fn identity_is_deterministic() {
    let a = identity();
    let b = identity();
    assert_eq!(a.output_x, b.output_x);
    assert_eq!(a.enc_key, b.enc_key);
    assert!(a.address(notes_core::Network::Regtest).starts_with("bcrt1p"));
    // different seed → different everything
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    assert_ne!(a.output_x, c.output_x);
    assert_ne!(a.enc_key, c.enc_key);
}

/// The keystroke estimator must match reality exactly: predicted vsize ==
/// actual vsize of the built+signed tx (change present).
#[test]
fn cost_estimator_is_exact() {
    let id = identity();
    for (text_len, private, max_or) in
        [(5usize, false, 80usize), (5, true, 80), (200, true, 80), (200, false, 10_000), (2_000, true, 10_000)]
    {
        let text: String = "x".repeat(text_len);
        let note = compose_note(
            &id,
            &utxos(),
            &text,
            private,
            [1, 1, 1, 1],
            max_or,
            2.0,
            || Ok(AUX),
        )
        .unwrap();
        assert!(note.change > 0, "fixture should produce change");
        let n_inputs = note.tx.inputs.len();
        let (_chunks, est_vsize) = estimate_note_cost(text_len, private, max_or, n_inputs).unwrap();
        assert_eq!(est_vsize, note.vsize, "text_len={text_len} private={private} max={max_or}");
    }
}

#[test]
fn insufficient_funds_is_reported() {
    let id = identity();
    let poor = vec![Utxo { txid: [1; 32], vout: 0, value: 50 }];
    let err = compose_note(&id, &poor, "hello", false, [0; 4], 80, 2.0, || Ok(AUX));
    assert!(err.is_err());
    // 200 sats CAN fund a minimal no-change note at 2 sat/vB (residue
    // below dust folds into the fee) — that's intended behavior.
    let tight = vec![Utxo { txid: [1; 32], vout: 0, value: 200 }];
    let note = compose_note(&id, &tight, "hello", false, [0; 4], 80, 2.0, || Ok(AUX)).unwrap();
    assert_eq!(note.change, 0);
    assert_eq!(note.fee, 200);
}

/// Build a bundle the way the companion would: one OnchainTx per note tx,
/// payloads pulled from the OP_RETURN outputs.
fn bundle_from_txs(txs: &[(&notes_core::tx::NoteTx, bool, Option<u64>)]) -> SyncBundle {
    SyncBundle {
        network: "regtest".into(),
        notes_onchain: txs
            .iter()
            .map(|(note, self_spend, height)| OnchainTx {
                txid: note.txid_hex.clone(),
                height: *height,
                blocktime: height.map(|h| 1_700_000_000 + h),
                spends_from_self: *self_spend,
                payloads: note
                    .tx
                    .outputs
                    .iter()
                    .filter_map(|o| op_return_payload(&o.script_pubkey))
                    .map(hex::encode)
                    .collect(),
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn compose_scan_roundtrip_public_private_chunked() {
    let id = identity();
    let long_text = "multi-chunk note ".repeat(20); // 340 bytes → 6 chunks at 80
    let pub_note =
        compose_note(&id, &utxos(), "public hello ₿", false, [1, 0, 0, 0], 80, 1.0, || Ok(AUX))
            .unwrap();
    let priv_note =
        compose_note(&id, &utxos(), "secret plans", true, [2, 0, 0, 0], 80, 1.0, || Ok(AUX))
            .unwrap();
    let chunked =
        compose_note(&id, &utxos(), &long_text, true, [3, 0, 0, 0], 80, 1.0, || Ok(AUX)).unwrap();
    assert!(
        chunked.tx.outputs.iter().filter(|o| o.script_pubkey.first() == Some(&0x6a)).count() > 1
    );

    let bundle = bundle_from_txs(&[
        (&pub_note, true, Some(100)),
        (&priv_note, true, Some(101)),
        (&chunked, true, Some(102)),
    ]);
    let notes = extract_notes(&bundle, &id.enc_key);
    assert_eq!(notes.len(), 3);
    assert_eq!(notes[0].text.as_deref(), Some("public hello ₿"));
    assert!(!notes[0].private);
    assert_eq!(notes[1].text.as_deref(), Some("secret plans"));
    assert!(notes[1].private);
    assert_eq!(notes[2].text.as_deref(), Some(long_text.as_str()));
}

#[test]
fn scan_ignores_foreign_and_spoofed() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "mine", true, [1, 2, 3, 4], 80, 1.0, || Ok(AUX)).unwrap();
    // Same payloads but spends_from_self=false → spoof attempt, ignored.
    let spoofed = bundle_from_txs(&[(&note, false, Some(50))]);
    assert!(extract_notes(&spoofed, &id.enc_key).is_empty());

    // A private note sealed under a DIFFERENT seed: envelope parses but
    // text must be None (foreign ciphertext).
    let other = Identity::from_app_seed(&[9u8; 32]).unwrap();
    let foreign =
        compose_note(&other, &utxos(), "not yours", true, [5, 5, 5, 5], 80, 1.0, || Ok(AUX))
            .unwrap();
    let bundle = bundle_from_txs(&[(&foreign, true, Some(60))]);
    let notes = extract_notes(&bundle, &id.enc_key);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none());
}

/// Idempotency: importing overlapping bundles converges (dedupe by chunk).
#[test]
fn scan_import_is_idempotent() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "once only", true, [7, 7, 7, 7], 80, 1.0, || Ok(AUX)).unwrap();
    let mut bundle = bundle_from_txs(&[(&note, true, Some(10))]);
    let dup = bundle.notes_onchain[0].clone();
    bundle.notes_onchain.push(dup); // overlapping incremental import
    let notes = extract_notes(&bundle, &id.enc_key);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text.as_deref(), Some("once only"));
}

/// The heavyweight cross-check: rust-bitcoin must (a) parse our raw tx,
/// (b) agree on txid and vsize, (c) recompute the identical BIP341 sighash
/// via its own implementation, and (d) accept our schnorr signature with
/// libsecp256k1 against the tweaked output key.
#[test]
fn rust_bitcoin_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let note = compose_note(
        &id,
        &utxos(),
        "cross-checked against rust-bitcoin",
        true,
        [0xAB, 0xCD, 0xEF, 0x01],
        80,
        3.0,
        || Ok(AUX),
    )
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);

    // Reconstruct the prevouts (every input spends our own P2TR output).
    let spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&id.output_x));
    let prevouts: Vec<TxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();

    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for (index, witness) in btx.input.iter().enumerate().map(|(i, _)| i).zip(&note.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = Signature::from_slice(&witness[0]).unwrap();
        secp.verify_schnorr(&sig, &msg, &output_key)
            .expect("libsecp256k1 must accept our BIP340 signature over rust-bitcoin's sighash");
    }
}
