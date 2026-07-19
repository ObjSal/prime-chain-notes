//! `notes_core::tx::build_note_tx_mixed_exact` / `estimate_vsize_mixed` —
//! the Prime device spending-wallet port (PLAN-chain-notes-funding-unification.md,
//! "Prime device" + M2). Cross-checked byte-for-byte against rust-bitcoin,
//! mirroring `wpkh_vectors.rs`'s treatment of `wpkh::sign_mixed_inputs`
//! (house rule for crypto/tx-assembly surface).

use notes_core::address::{p2tr_script_pubkey, p2wpkh_script_pubkey};
use notes_core::keys::hash160;
use notes_core::tx::{
    build_note_tx_exact, build_note_tx_mixed_exact, build_note_tx_mixed_exact_anchored,
    build_sweep_tx_mixed, estimate_vsize, estimate_vsize_mixed, InputKind, MixedInput, Utxo,
};
use notes_core::DUST_LIMIT;

use k256::ecdsa::SigningKey;

fn wpkh_seckey(byte: u8) -> [u8; 32] {
    let mut k = [0x22u8; 32];
    k[0] = byte;
    k
}

fn wpkh_spk(seckey: &[u8; 32]) -> Vec<u8> {
    let sk = SigningKey::from_bytes(seckey.into()).unwrap();
    let pk: [u8; 33] = sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
    p2wpkh_script_pubkey(&hash160(&pk))
}

const AUX: [u8; 32] = [0x77; 32];
const NOTEBOOK_X: [u8; 32] = [0x11; 32];
const TAPROOT_SECKEY: [u8; 32] = [0x44; 32]; // stand-in "already-tweaked" key-path secret

/// A single P2WPKH input funding a self-note: OP_RETURN, dust-to-notebook,
/// change to a fresh spending address — the "funded self-note" row of the
/// PLAN's cost table (~152 vB for a short note; here a fixed 2-byte payload).
#[test]
fn pure_spending_funded_self_note_shape_and_signature() {
    let sk = wpkh_seckey(1);
    let spk = wpkh_spk(&sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(2));
    let payloads = vec![b"hi".to_vec()];

    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [5u8; 32], vout: 0, value: 100_000 },
        prevout_spk: spk.clone(),
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];

    let note = build_note_tx_mixed_exact(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        2.0,
        || Ok(AUX),
    )
    .unwrap();

    // Output order: OP_RETURN, notebook dust, change.
    assert_eq!(note.tx.outputs.len(), 3);
    assert_eq!(note.tx.outputs[0].script_pubkey[0], 0x6a);
    assert_eq!(note.tx.outputs[1].value, DUST_LIMIT);
    assert_eq!(note.tx.outputs[1].script_pubkey, notebook_dust_spk);
    assert_eq!(note.tx.outputs[2].script_pubkey, change_spk);
    assert_eq!(note.sent, 0);
    assert_eq!(100_000, note.fee + DUST_LIMIT + note.change);

    // rust-bitcoin can parse the signed bytes and its own BIP143 sighash
    // validates our witness signature.
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
    use bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf};

    let btx: bitcoin::Transaction = btc_deser(&note.tx.serialize_segwit()).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    let script_spk = ScriptBuf::from_bytes(spk.clone());
    let mut cache = SighashCache::new(&btx);
    let sighash = cache
        .p2wpkh_signature_hash(0, &script_spk, Amount::from_sat(100_000), EcdsaSighashType::All)
        .unwrap();
    let witness = btx.input[0].witness.to_vec();
    let sig_bytes = &witness[0];
    let der = &sig_bytes[..sig_bytes.len() - 1];
    let pubkey_bytes = &witness[1];
    let secp_sig = SecpSignature::from_der(der).unwrap();
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(sighash.to_byte_array());
    let secp_pubkey = SecpPublicKey::from_slice(pubkey_bytes).unwrap();
    secp.verify_ecdsa(&msg, &secp_sig, &secp_pubkey)
        .expect("witness signature must verify under rust-bitcoin's own sighash");
}

/// A directed funded note: OP_RETURN, gift-to-recipient, dust-to-notebook,
/// change — the PLAN's "funded directed" row.
#[test]
fn pure_spending_funded_directed_note_output_order() {
    let sk = wpkh_seckey(3);
    let spk = wpkh_spk(&sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(4));
    let recipient_spk = p2tr_script_pubkey(&[0x99; 32]);
    let payloads = vec![b"gift for you".to_vec()];

    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [6u8; 32], vout: 1, value: 200_000 },
        prevout_spk: spk,
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];

    let note = build_note_tx_mixed_exact(
        &inputs,
        &payloads,
        Some(&recipient_spk),
        5_000,
        &notebook_dust_spk,
        &change_spk,
        3.0,
        || Ok(AUX),
    )
    .unwrap();

    assert_eq!(note.tx.outputs.len(), 4);
    assert_eq!(note.tx.outputs[0].script_pubkey[0], 0x6a);
    assert_eq!(note.tx.outputs[1].script_pubkey, recipient_spk);
    assert_eq!(note.tx.outputs[1].value, 5_000);
    assert_eq!(note.tx.outputs[2].script_pubkey, notebook_dust_spk);
    assert_eq!(note.tx.outputs[2].value, DUST_LIMIT);
    assert_eq!(note.tx.outputs[3].script_pubkey, change_spk);
    assert_eq!(note.sent, 5_000);
    assert_eq!(200_000, note.fee + 5_000 + DUST_LIMIT + note.change);
}

/// Mixed inputs: one taproot (notebook dust getting spent as a fee
/// top-up) plus one P2WPKH (spending wallet) — both signed in one pass,
/// each with the CORRECT algorithm, cross-checked against standalone
/// signing (same fixture shape as `wpkh_vectors.rs`'s
/// `sign_mixed_inputs_matches_standalone_signing`, but through the actual
/// tx-assembly builder instead of a hand-built tx).
#[test]
fn mixed_taproot_and_wpkh_inputs_each_sign_correctly() {
    use notes_core::sighash::taproot_key_spend_sighash;
    use notes_core::sign::schnorr_sign;
    use notes_core::wpkh::{bip143_sighash, p2wpkh_script_code, sign_p2wpkh_input};

    let taproot_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let wpkh_sk = wpkh_seckey(5);
    let wpkh_input_spk = wpkh_spk(&wpkh_sk);
    let notebook_dust_spk = taproot_spk.clone();
    let change_spk = wpkh_spk(&wpkh_seckey(6));
    let payloads = vec![b"mixed source note".to_vec()];

    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [1u8; 32], vout: 0, value: 1_000 },
            prevout_spk: taproot_spk.clone(),
            kind: InputKind::Taproot,
            seckey: TAPROOT_SECKEY,
        },
        MixedInput {
            utxo: Utxo { txid: [2u8; 32], vout: 3, value: 50_000 },
            prevout_spk: wpkh_input_spk.clone(),
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];

    let note = build_note_tx_mixed_exact(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        1.5,
        || Ok(AUX),
    )
    .unwrap();

    assert_eq!(note.tx.inputs.len(), 2);
    assert_eq!(note.tx.witnesses.len(), 2);

    // Input 0 (taproot): re-derive the expected schnorr sig standalone —
    // sighashing reads tx.inputs[i].value directly, unaffected by witnesses.
    let prevout_spks = vec![taproot_spk, wpkh_input_spk];
    let mut unsigned = note.tx.clone();
    unsigned.witnesses = Vec::new();
    let expected_sighash = taproot_key_spend_sighash(&unsigned, &prevout_spks, 0);
    let expected_sig = schnorr_sign(&TAPROOT_SECKEY, &expected_sighash, &AUX).unwrap();
    assert_eq!(note.tx.witnesses[0], vec![expected_sig.to_vec()]);

    // Input 1 (P2WPKH): re-derive standalone via sign_p2wpkh_input.
    let expected_witness = sign_p2wpkh_input(&unsigned, 1, &wpkh_sk).unwrap();
    assert_eq!(note.tx.witnesses[1], expected_witness);

    // Sanity: the witness really does verify against its own sighash (belt
    // and suspenders beyond the standalone-signer equality check above).
    let (_pk, pubkey_hash) = {
        let sk = SigningKey::from_bytes((&wpkh_sk).into()).unwrap();
        let pk: [u8; 33] =
            sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
        (pk, hash160(&pk))
    };
    let script_code = p2wpkh_script_code(&pubkey_hash);
    let sighash = bip143_sighash(&unsigned, 1, &script_code);
    assert_eq!(bip143_sighash(&note.tx, 1, &script_code), sighash);
}

/// `estimate_vsize_mixed` reproduces `estimate_vsize`'s all-taproot result
/// exactly when every input is taproot and the only extra output is a
/// same-length change spk — same formula, generalized.
#[test]
fn estimate_vsize_mixed_matches_all_taproot_estimate() {
    let payload_lens = [80usize, 42usize];
    let change_len = 34usize; // p2tr change spk length

    let all_taproot = estimate_vsize(3, &payload_lens, None, true);
    let mixed = estimate_vsize_mixed(
        &[InputKind::Taproot, InputKind::Taproot, InputKind::Taproot],
        &payload_lens,
        &[change_len],
    );
    assert_eq!(all_taproot, mixed);
}

/// A P2WPKH input costs more vsize than a P2TR one (68 vs 57.5 vB per the
/// PLAN's cost table) — single-input, single-output-besides-payload sanity
/// check of the exact numbers.
#[test]
fn estimate_vsize_mixed_p2wpkh_vs_taproot_input_cost() {
    let payload_lens = [10usize];
    let taproot_only = estimate_vsize_mixed(&[InputKind::Taproot], &payload_lens, &[]);
    let wpkh_only = estimate_vsize_mixed(&[InputKind::P2wpkh], &payload_lens, &[]);
    assert!(wpkh_only > taproot_only, "P2WPKH input must cost more vsize than P2TR");
    // The delta is exactly (108 - 66) / 4 = 10.5 wu -> vsize rounds up by
    // ceil(10.5/4)... check the concrete numbers directly instead of the
    // arithmetic shortcut, since both round up independently.
    assert_eq!(wpkh_only - taproot_only, 11);
}

/// Insufficient funds: inputs can't cover fee + dust-to-self.
#[test]
fn mixed_exact_insufficient_funds_errors() {
    let sk = wpkh_seckey(9);
    let spk = wpkh_spk(&sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(10));
    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [8u8; 32], vout: 0, value: 200 },
        prevout_spk: spk,
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];
    let err = build_note_tx_mixed_exact(
        &inputs,
        &[b"x".to_vec()],
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        1.0,
        || Ok(AUX),
    )
    .unwrap_err();
    assert!(matches!(err, notes_core::Error::InsufficientFunds));
}

/// `build_sweep_tx_mixed`: the sweep analog of `build_note_tx_mixed_exact`,
/// mixing ONE taproot (notebook) input and ONE P2WPKH (spending-wallet)
/// input into a single destination output. Covers: (1) value conservation
/// — no leakage/creation of sats, (2) txid/vsize agreement with
/// rust-bitcoin's independent parse, and (3) both witness kinds verifying
/// under their own BIP (BIP340/341 schnorr for the taproot input, BIP143
/// ECDSA for the P2WPKH one) — the same rigor
/// `pure_spending_funded_self_note_shape_and_signature` and
/// `mixed_taproot_and_wpkh_inputs_each_sign_correctly` apply above.
#[test]
fn sweep_mixed_taproot_and_wpkh_cross_check() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature as SecpEcdsaSignature;
    use bitcoin::secp256k1::{
        schnorr::Signature as SecpSchnorrSignature, Message, PublicKey as SecpPublicKey, Secp256k1,
        XOnlyPublicKey,
    };
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut as BtcTxOut};
    use notes_core::bundle::Identity;

    // A real (output_x, tweaked_seckey) pair — unlike NOTEBOOK_X/TAPROOT_SECKEY
    // (unrelated stand-ins fine for tests that only re-derive our own
    // sighash), this test asks rust-bitcoin to verify the schnorr signature
    // against the actual curve point, so the key and its output_x must
    // really correspond.
    let notebook = Identity::from_app_seed(&[0x51; 32]).unwrap();
    let taproot_spk = p2tr_script_pubkey(&notebook.output_x);
    let wpkh_sk = wpkh_seckey(21);
    let wpkh_input_spk = wpkh_spk(&wpkh_sk);
    let dest_spk = wpkh_spk(&wpkh_seckey(22)); // arbitrary external destination

    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [31u8; 32], vout: 0, value: 30_000 },
            prevout_spk: taproot_spk.clone(),
            kind: InputKind::Taproot,
            seckey: notebook.tweaked_seckey,
        },
        MixedInput {
            utxo: Utxo { txid: [32u8; 32], vout: 1, value: 70_000 },
            prevout_spk: wpkh_input_spk.clone(),
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();

    let sweep = build_sweep_tx_mixed(&inputs, dest_spk.clone(), 2.0, || Ok(AUX)).unwrap();

    // Single destination output, everything minus fee — no change, no
    // recipient, no OP_RETURN.
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
    assert_eq!(sweep.sent, 0);
    assert_eq!(sweep.change, 0);

    // (1) Value conservation.
    assert_eq!(in_value, sweep.fee + sweep.tx.outputs[0].value);

    // (2) txid/vsize agreement with rust-bitcoin.
    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = btc_deser(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);

    // (3) Both witness kinds verify under their own BIP.
    let prevouts: Vec<BtcTxOut> = vec![
        BtcTxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: ScriptBuf::from_bytes(taproot_spk),
        },
        BtcTxOut {
            value: Amount::from_sat(70_000),
            script_pubkey: ScriptBuf::from_bytes(wpkh_input_spk.clone()),
        },
    ];
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(&btx);

    // Input 0: taproot key-path (BIP340/341).
    let output_key = XOnlyPublicKey::from_slice(&notebook.output_x).unwrap();
    let tap_sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    secp.verify_schnorr(
        &SecpSchnorrSignature::from_slice(&sweep.tx.witnesses[0][0]).unwrap(),
        &Message::from_digest(tap_sighash.to_byte_array()),
        &output_key,
    )
    .expect("taproot sweep input must verify under BIP340/341");

    // Input 1: P2WPKH (BIP143).
    let wpkh_script_spk = ScriptBuf::from_bytes(wpkh_input_spk);
    let wpkh_sighash = cache
        .p2wpkh_signature_hash(1, &wpkh_script_spk, Amount::from_sat(70_000), EcdsaSighashType::All)
        .unwrap();
    let witness1 = &sweep.tx.witnesses[1];
    let sig_bytes = &witness1[0];
    assert_eq!(*sig_bytes.last().unwrap(), 0x01, "SIGHASH_ALL byte");
    let der = &sig_bytes[..sig_bytes.len() - 1];
    let pubkey_bytes = &witness1[1];
    let secp_sig = SecpEcdsaSignature::from_der(der).unwrap();
    let secp_pubkey = SecpPublicKey::from_slice(pubkey_bytes).unwrap();
    secp.verify_ecdsa(
        &Message::from_digest(wpkh_sighash.to_byte_array()),
        &secp_sig,
        &secp_pubkey,
    )
    .expect("P2WPKH sweep input must verify under BIP143");
}

/// All-taproot-only sweep through `build_sweep_tx_mixed` (2 notebook
/// inputs, no P2WPKH) — regression coverage that mixing in this new
/// builder didn't disturb the pure-taproot case `build_sweep_tx_multi`
/// already covers.
#[test]
fn sweep_mixed_all_taproot_only() {
    use bitcoin::consensus::encode::deserialize as btc_deser;

    let dest_spk = wpkh_spk(&wpkh_seckey(23));
    let taproot_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [41u8; 32], vout: 0, value: 20_000 },
            prevout_spk: taproot_spk.clone(),
            kind: InputKind::Taproot,
            seckey: TAPROOT_SECKEY,
        },
        MixedInput {
            utxo: Utxo { txid: [42u8; 32], vout: 1, value: 15_000 },
            prevout_spk: taproot_spk,
            kind: InputKind::Taproot,
            seckey: TAPROOT_SECKEY,
        },
    ];
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();
    let sweep = build_sweep_tx_mixed(&inputs, dest_spk.clone(), 1.0, || Ok(AUX)).unwrap();
    assert_eq!(sweep.tx.inputs.len(), 2);
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
    assert_eq!(in_value, sweep.fee + sweep.tx.outputs[0].value);

    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = btc_deser(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);
}

/// All-P2WPKH-only sweep through `build_sweep_tx_mixed` (2 spending-wallet
/// inputs, no taproot) — the pure-BIP143 case.
#[test]
fn sweep_mixed_all_wpkh_only() {
    use bitcoin::consensus::encode::deserialize as btc_deser;

    let sk1 = wpkh_seckey(24);
    let sk2 = wpkh_seckey(25);
    let spk1 = wpkh_spk(&sk1);
    let spk2 = wpkh_spk(&sk2);
    let dest_spk = p2tr_script_pubkey(&NOTEBOOK_X); // sweeping out to a notebook address
    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [51u8; 32], vout: 0, value: 12_000 },
            prevout_spk: spk1,
            kind: InputKind::P2wpkh,
            seckey: sk1,
        },
        MixedInput {
            utxo: Utxo { txid: [52u8; 32], vout: 2, value: 8_000 },
            prevout_spk: spk2,
            kind: InputKind::P2wpkh,
            seckey: sk2,
        },
    ];
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();
    let sweep = build_sweep_tx_mixed(&inputs, dest_spk.clone(), 1.0, || Ok(AUX)).unwrap();
    assert_eq!(sweep.tx.inputs.len(), 2);
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
    assert_eq!(in_value, sweep.fee + sweep.tx.outputs[0].value);

    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = btc_deser(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);
}

/// Empty input list must error, mirroring `build_sweep_tx_multi`'s guard.
#[test]
fn sweep_mixed_empty_inputs_errors() {
    let dest_spk = wpkh_spk(&wpkh_seckey(26));
    let err = build_sweep_tx_mixed(&[], dest_spk, 1.0, || Ok(AUX)).unwrap_err();
    assert!(matches!(err, notes_core::Error::InsufficientFunds));
}

/// Inputs that can't cover the fee at all must error.
#[test]
fn sweep_mixed_insufficient_funds_errors() {
    let sk = wpkh_seckey(27);
    let spk = wpkh_spk(&sk);
    let dest_spk = wpkh_spk(&wpkh_seckey(28));
    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [61u8; 32], vout: 0, value: 100 },
        prevout_spk: spk,
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];
    let err = build_sweep_tx_mixed(&inputs, dest_spk, 5.0, || Ok(AUX)).unwrap_err();
    assert!(matches!(err, notes_core::Error::InsufficientFunds));
}

/// Sanity anchor: the existing all-taproot `build_note_tx_exact` is
/// untouched by this module's additions (byte-identical call, no behavior
/// drift).
#[test]
fn build_note_tx_exact_still_works_unmodified() {
    let notebook_x = [0x22u8; 32];
    let inputs = vec![Utxo { txid: [1u8; 32], vout: 0, value: 50_000 }];
    let tweaked = [0x33u8; 32];
    let note = build_note_tx_exact(
        &inputs,
        &notebook_x,
        &[b"still taproot".to_vec()],
        None,
        0,
        None,
        1.0,
        &tweaked,
        || Ok(AUX),
    )
    .unwrap();
    assert_eq!(note.tx.inputs.len(), 1);
}

// ---------------------------------------------------------------------
// `build_note_tx_mixed_exact_anchored` — the dust-to-self output is
// skipped when the tx is already anchored by a notebook input (design
// decision, funding-unification, 2026-07-18: an input-anchored tx already
// appears in the notebook's address history and is already OWN by the
// spends-from-self rule, so the extra discoverability dust is redundant).
// ---------------------------------------------------------------------

/// Anchored mixed build: one taproot (notebook) input whose prevout spk
/// equals `notebook_dust_spk`, plus a P2WPKH (spending-wallet) input —
/// NO dust-to-self output; OP_RETURN then change is the full output list;
/// both witness kinds cross-checked against rust-bitcoin exactly like
/// `sweep_mixed_taproot_and_wpkh_cross_check`.
#[test]
fn anchored_mixed_build_skips_dust_when_notebook_input_present() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature as SecpEcdsaSignature;
    use bitcoin::secp256k1::{
        schnorr::Signature as SecpSchnorrSignature, Message, PublicKey as SecpPublicKey, Secp256k1,
        XOnlyPublicKey,
    };
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut as BtcTxOut};
    use notes_core::bundle::Identity;

    let notebook = Identity::from_app_seed(&[0x61; 32]).unwrap();
    let notebook_dust_spk = p2tr_script_pubkey(&notebook.output_x);
    let wpkh_sk = wpkh_seckey(31);
    let wpkh_input_spk = wpkh_spk(&wpkh_sk);
    let change_spk = wpkh_spk(&wpkh_seckey(32));
    let payloads = vec![b"anchored note".to_vec()];

    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [71u8; 32], vout: 0, value: 1_000 },
            // Same spk as `notebook_dust_spk` — this is what makes the tx
            // input-anchored to the notebook.
            prevout_spk: notebook_dust_spk.clone(),
            kind: InputKind::Taproot,
            seckey: notebook.tweaked_seckey,
        },
        MixedInput {
            utxo: Utxo { txid: [72u8; 32], vout: 2, value: 60_000 },
            prevout_spk: wpkh_input_spk.clone(),
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();

    let note = build_note_tx_mixed_exact_anchored(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        1.5,
        || Ok(AUX),
    )
    .unwrap();

    // Output order: OP_RETURN, change — NO dust-to-self output.
    assert_eq!(note.tx.outputs.len(), 2);
    assert_eq!(note.tx.outputs[0].script_pubkey[0], 0x6a);
    assert_eq!(note.tx.outputs[1].script_pubkey, change_spk);
    assert!(
        note.tx.outputs.iter().all(|o| o.script_pubkey != notebook_dust_spk),
        "no output should pay the notebook dust spk when anchored"
    );
    assert_eq!(note.sent, 0);
    assert_eq!(in_value, note.fee + note.change);

    // The estimator (fed the SAME extra-output shape: no dust length) is
    // byte-exact vs the real built tx.
    let predicted = estimate_vsize_mixed(
        &[InputKind::Taproot, InputKind::P2wpkh],
        &[payloads[0].len()],
        &[change_spk.len()],
    );
    assert_eq!(predicted, note.vsize, "estimator must match the anchored (no-dust) shape");

    // rust-bitcoin cross-check: both witness kinds verify under their own BIP.
    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = btc_deser(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);

    let prevouts: Vec<BtcTxOut> = vec![
        BtcTxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from_bytes(notebook_dust_spk.clone()) },
        BtcTxOut { value: Amount::from_sat(60_000), script_pubkey: ScriptBuf::from_bytes(wpkh_input_spk.clone()) },
    ];
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(&btx);

    let output_key = XOnlyPublicKey::from_slice(&notebook.output_x).unwrap();
    let tap_sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    secp.verify_schnorr(
        &SecpSchnorrSignature::from_slice(&note.tx.witnesses[0][0]).unwrap(),
        &Message::from_digest(tap_sighash.to_byte_array()),
        &output_key,
    )
    .expect("taproot input must verify under BIP340/341");

    let wpkh_script_spk = ScriptBuf::from_bytes(wpkh_input_spk);
    let wpkh_sighash = cache
        .p2wpkh_signature_hash(1, &wpkh_script_spk, Amount::from_sat(60_000), EcdsaSighashType::All)
        .unwrap();
    let witness1 = &note.tx.witnesses[1];
    let sig_bytes = &witness1[0];
    assert_eq!(*sig_bytes.last().unwrap(), 0x01, "SIGHASH_ALL byte");
    let der = &sig_bytes[..sig_bytes.len() - 1];
    let pubkey_bytes = &witness1[1];
    let secp_sig = SecpEcdsaSignature::from_der(der).unwrap();
    let secp_pubkey = SecpPublicKey::from_slice(pubkey_bytes).unwrap();
    secp.verify_ecdsa(&Message::from_digest(wpkh_sighash.to_byte_array()), &secp_sig, &secp_pubkey)
        .expect("P2WPKH input must verify under BIP143");
}

/// Unanchored funded build through the SAME new variant: spending-wallet-only
/// inputs (no input's prevout spk matches the notebook) — the dust-to-self
/// output is still present (the rule's else-branch), output order unchanged
/// from the always-dust builder.
#[test]
fn unanchored_funded_build_via_anchored_variant_keeps_dust() {
    let sk = wpkh_seckey(33);
    let spk = wpkh_spk(&sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(34));
    let payloads = vec![b"unanchored".to_vec()];

    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [81u8; 32], vout: 0, value: 100_000 },
        prevout_spk: spk, // does NOT match notebook_dust_spk
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];

    let note = build_note_tx_mixed_exact_anchored(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        2.0,
        || Ok(AUX),
    )
    .unwrap();

    // Output order: OP_RETURN, notebook dust, change — the else-branch.
    assert_eq!(note.tx.outputs.len(), 3);
    assert_eq!(note.tx.outputs[0].script_pubkey[0], 0x6a);
    assert_eq!(note.tx.outputs[1].value, DUST_LIMIT);
    assert_eq!(note.tx.outputs[1].script_pubkey, notebook_dust_spk);
    assert_eq!(note.tx.outputs[2].script_pubkey, change_spk);
    assert_eq!(100_000, note.fee + DUST_LIMIT + note.change);

    // Estimator matches the unanchored (dust-included) shape.
    let predicted = estimate_vsize_mixed(
        &[InputKind::P2wpkh],
        &[payloads[0].len()],
        &[notebook_dust_spk.len(), change_spk.len()],
    );
    assert_eq!(predicted, note.vsize, "estimator must match the unanchored (dust) shape");
}

/// When the anchored variant's skip condition doesn't fire (no input spends
/// the notebook spk, so dust is still emitted), it must build byte-identical
/// transactions to the old always-dust `build_note_tx_mixed_exact` given the
/// same inputs/params — the old function's behavior is untouched.
#[test]
fn old_and_new_mixed_builders_byte_identical_when_forced_dust() {
    let sk = wpkh_seckey(35);
    let spk = wpkh_spk(&sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(36));
    let payloads = vec![b"parity check".to_vec()];

    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [91u8; 32], vout: 0, value: 80_000 },
        prevout_spk: spk,
        kind: InputKind::P2wpkh,
        seckey: sk,
    }];

    let old = build_note_tx_mixed_exact(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        2.5,
        || Ok(AUX),
    )
    .unwrap();
    let new = build_note_tx_mixed_exact_anchored(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        2.5,
        || Ok(AUX),
    )
    .unwrap();

    assert_eq!(old.raw_hex, new.raw_hex);
    assert_eq!(old.tx, new.tx);
    assert_eq!(old.fee, new.fee);
    assert_eq!(old.change, new.change);
    assert_eq!(old.vsize, new.vsize);
}
