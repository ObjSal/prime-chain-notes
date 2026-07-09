//! Envelope/AEAD round-trips, fee-estimator exactness, full compose→scan
//! round-trips, and the rust-bitcoin cross-check of our transaction
//! serialization, sighash and signatures.

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note, compose_note, compose_note_exact, compose_note_with_change,
    estimate_note_cost,
    extract_notes, extract_notes_watch, Identity, OnchainTx, SyncBundle,
};
use notes_core::crypt::{self, SEAL_OVERHEAD};
use notes_core::envelope;
use notes_core::tx::{op_return_payload, Utxo};
use notes_core::Network;

const APP_SEED: [u8; 32] = [7u8; 32];
const AUX: [u8; 32] = [0x42; 32];
const NET: Network = Network::Regtest;

fn identity() -> Identity {
    Identity::from_app_seed(&APP_SEED).unwrap()
}

/// Second party for directed-note tests.
fn identity_b() -> Identity {
    Identity::from_app_seed(&[9u8; 32]).unwrap()
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
fn note_id_collision_guard_rerolls() {
    // Scripted generator: two ids that are taken, then a fresh one.
    let script = [[1u8; 4], [2u8; 4], [9u8; 4]];
    let mut i = 0;
    let gen = || {
        let id = script[i];
        i += 1;
        Ok(id)
    };
    let taken = |id: &[u8; 4]| *id == [1u8; 4] || *id == [2u8; 4];
    assert_eq!(notes_core::keys::pick_unique_note_id(gen, taken).unwrap(), [9u8; 4]);
    assert_eq!(i, 3, "must have rerolled past both collisions");

    // Everything taken (broken RNG stuck on one value) → error, not a spin.
    let stuck = || Ok([1u8; 4]);
    assert!(notes_core::keys::pick_unique_note_id(stuck, |_| true).is_err());
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
        let (_chunks, est_vsize) =
            estimate_note_cost(text_len, private, max_or, n_inputs, None).unwrap();
        assert_eq!(est_vsize, note.vsize, "text_len={text_len} private={private} max={max_or}");
    }

    // Directed notes: the recipient dust output (34-byte P2TR / 22-byte
    // P2WPKH spk) must be modeled byte-exactly too.
    let b = identity_b();
    let p2tr = Recipient::parse(NET, &b.address(NET)).unwrap();
    let p2wpkh = Recipient { address: String::new(), spk: vec![0x00, 0x14].into_iter().chain([0x11; 20]).collect(), p2tr_x: None };
    for (text_len, private, recipient) in
        [(5usize, true, &p2tr), (200, true, &p2tr), (40, false, &p2wpkh)]
    {
        let text: String = "y".repeat(text_len);
        let note = compose_directed_note(
            &id, &utxos(), &text, private, [2, 2, 2, 2], recipient, 80, 2.0, || Ok(AUX),
        )
        .unwrap();
        assert!(note.change > 0, "fixture should produce change");
        assert_eq!(note.sent, 330);
        let chunks = note
            .tx
            .outputs
            .iter()
            .filter(|o| o.script_pubkey.first() == Some(&0x6a))
            .count();
        // Output order: OP_RETURNs, dust to recipient, change.
        assert_eq!(note.tx.outputs[chunks].value, 330);
        assert_eq!(note.tx.outputs[chunks].script_pubkey, recipient.spk);
        assert_eq!(note.tx.outputs.len(), chunks + 2);
        let (_c, est_vsize) = estimate_note_cost(
            text_len,
            private,
            80,
            note.tx.inputs.len(),
            Some(recipient.spk.len()),
        )
        .unwrap();
        assert_eq!(est_vsize, note.vsize, "directed text_len={text_len} private={private}");
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
                pays_self: false,
                sender: None,
                author_candidates: Vec::new(),
                recipient: None,
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
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 3);
    assert_eq!(notes[0].text.as_deref(), Some("public hello ₿"));
    assert!(!notes[0].private);
    assert!(!notes[0].received && !notes[0].directed);
    assert_eq!(notes[1].text.as_deref(), Some("secret plans"));
    assert!(notes[1].private);
    assert_eq!(notes[2].text.as_deref(), Some(long_text.as_str()));
}

#[test]
fn scan_ignores_foreign_and_spoofed() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "mine", true, [1, 2, 3, 4], 80, 1.0, || Ok(AUX)).unwrap();
    // Same payloads, neither spending from nor paying us → pure spoof,
    // ignored entirely (the acceptance rule stays additive).
    let spoofed = bundle_from_txs(&[(&note, false, Some(50))]);
    assert!(extract_notes(&spoofed, &id, NET).is_empty());

    // A private note sealed under a DIFFERENT seed: envelope parses but
    // text must be None (foreign ciphertext).
    let other = identity_b();
    let foreign =
        compose_note(&other, &utxos(), "not yours", true, [5, 5, 5, 5], 80, 1.0, || Ok(AUX))
            .unwrap();
    let bundle = bundle_from_txs(&[(&foreign, true, Some(60))]);
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none());
}

#[test]
fn dm_shared_key_is_symmetric() {
    use notes_core::dm;
    let a = identity();
    let b = identity_b();
    let ab = dm::ecdh_shared_x(&a.tweaked_seckey, &b.output_x).unwrap();
    let ba = dm::ecdh_shared_x(&b.tweaked_seckey, &a.output_x).unwrap();
    // The tweaked scalars may be negated relative to their lifted points —
    // x-only must erase all four parity combinations.
    assert_eq!(ab, ba, "static-static ECDH must be symmetric over real tweaked keys");
    assert_eq!(dm::dm_key(&ab), dm::dm_key(&ba));

    // A third party derives something else entirely.
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    assert_ne!(dm::ecdh_shared_x(&c.tweaked_seckey, &b.output_x).unwrap(), ab);

    // AAD binds the note_id at the dm layer.
    let blob =
        dm::seal_directed(&a.tweaked_seckey, &a.output_x, &b.output_x, &[1, 2, 3, 4], b"psst")
            .unwrap();
    assert_eq!(
        dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &[1, 2, 3, 4], &blob)
            .unwrap(),
        b"psst"
    );
    assert!(dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &[9, 9, 9, 9], &blob)
        .is_err());
}

/// A → B, public: B sees a received note with text and sender; A's own
/// scan shows the same note as sent-to-B.
#[test]
fn compose_directed_public_roundtrip() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "hello bob, love alice", false, [1, 0, 0, 1], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    // B's bundle view: tx pays B but does not spend from B.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    let n = &notes[0];
    assert!(n.received && n.directed && !n.private);
    assert_eq!(n.text.as_deref(), Some("hello bob, love alice"));
    assert_eq!(n.sender.as_deref(), Some(a.address(NET).as_str()));

    // A's own view: spends from self, recipient recorded from the vout.
    let mut own = bundle_from_txs(&[(&note, true, Some(100))]);
    own.notes_onchain[0].recipient = Some(b.address(NET));
    let notes = extract_notes(&own, &a, NET);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received && notes[0].directed);
    assert_eq!(notes[0].recipient.as_deref(), Some(b.address(NET).as_str()));
    assert_eq!(notes[0].text.as_deref(), Some("hello bob, love alice"));
}

/// Watch-only scan: identical structure to the keyed scan — same notes,
/// origins, senders/recipients, public text — but every private body stays
/// sealed (text: None), including own self-notes.
#[test]
fn watch_scan_matches_keyed_scan_minus_private_text() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();

    let pub_note =
        compose_note(&a, &utxos(), "public hello", false, [1, 0, 0, 0], 80, 1.0, || Ok(AUX))
            .unwrap();
    let priv_note =
        compose_note(&a, &utxos(), "secret plans", true, [2, 0, 0, 0], 80, 1.0, || Ok(AUX))
            .unwrap();
    let sent_priv = compose_directed_note(
        &a, &utxos(), "for bob only", true, [3, 0, 0, 0], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();
    let from_b = compose_directed_note(
        &b, &utxos(), "hi alice", false, [4, 0, 0, 0], &Recipient::parse(NET, &a.address(NET)).unwrap(), 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    // A's address history as the companion would bundle it.
    let mut bundle = bundle_from_txs(&[
        (&pub_note, true, Some(100)),
        (&priv_note, true, Some(101)),
        (&sent_priv, true, Some(102)),
        (&from_b, false, Some(103)),
    ]);
    bundle.notes_onchain[2].recipient = Some(b.address(NET));
    bundle.notes_onchain[3].pays_self = true;
    bundle.notes_onchain[3].sender = Some(b.address(NET));

    let keyed = extract_notes(&bundle, &a, NET);
    let watch = extract_notes_watch(&bundle, NET);
    assert_eq!(keyed.len(), 4);
    assert_eq!(watch.len(), keyed.len());
    for (w, k) in watch.iter().zip(&keyed) {
        assert_eq!(w.note_id, k.note_id);
        assert_eq!(w.txids, k.txids);
        assert_eq!(w.height, k.height);
        assert_eq!(w.private, k.private);
        assert_eq!(w.directed, k.directed);
        assert_eq!(w.received, k.received);
        assert_eq!(w.sender, k.sender);
        assert_eq!(w.recipient, k.recipient);
        // The one permitted difference: private bodies never decrypt.
        if k.private {
            assert!(w.text.is_none(), "watch scan must not decrypt {:02x?}", w.note_id);
        } else {
            assert_eq!(w.text, k.text);
        }
    }
    // The keyed scan DID read the private ones — the comparison is real.
    assert_eq!(keyed[1].text.as_deref(), Some("secret plans"));
    assert_eq!(keyed[2].text.as_deref(), Some("for bob only"));
}

/// A → B, private: B decrypts via reciprocal ECDH; A re-derives the key
/// from the dust-output address (post-wipe recovery); a third identity
/// cannot read it.
#[test]
fn compose_directed_private_roundtrip() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "for bob's eyes only", true, [2, 0, 0, 2], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received && notes[0].directed && notes[0].private);
    assert_eq!(notes[0].text.as_deref(), Some("for bob's eyes only"));

    // Sender wipe-recovery: A reads its own sent note from bare chain data.
    let mut own = bundle_from_txs(&[(&note, true, Some(100))]);
    own.notes_onchain[0].recipient = Some(b.address(NET));
    let notes = extract_notes(&own, &a, NET);
    assert_eq!(notes[0].text.as_deref(), Some("for bob's eyes only"));

    // A third identity presented with the same tx gets ciphertext only.
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let mut leaked = bundle_from_txs(&[(&note, false, Some(100))]);
    leaked.notes_onchain[0].pays_self = true;
    leaked.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&leaked, &c, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "not addressed to C — must stay sealed");
}

/// Externally-funded directed-private note: the tx is funded and signed by a
/// third-party wallet (F), so the first taproot input is F, not the author A.
/// A's key rides along only as a dust-to-self output surfaced in
/// `author_candidates`. B must still decrypt by trying the candidate keys and
/// attribute the note to A — never to the funder F. A wrong candidate never
/// spuriously authenticates.
#[test]
fn externally_funded_directed_private_decodes_via_candidate() {
    let a = identity(); // author
    let b = identity_b(); // recipient
    let f = Identity::from_app_seed(&[0x11u8; 32]).unwrap(); // external funder
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "paid by cold storage", true, [7, 0, 0, 7], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    // B's view of an EXTERNALLY funded tx: pays B, does NOT spend from B, and
    // the first-input sender is the funder F. A's key is present only as a
    // candidate (the dust-to-self output the composer adds for discoverability).
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(f.address(NET));
    bundle.notes_onchain[0].author_candidates =
        vec![f.address(NET), a.address(NET), b.address(NET)];
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received && notes[0].directed && notes[0].private);
    assert_eq!(notes[0].text.as_deref(), Some("paid by cold storage"));
    // Attributed to the real author A, not the funder F.
    assert_eq!(notes[0].sender.as_deref(), Some(a.address(NET).as_str()));

    // Legacy bundle (only the funder as sender, no candidates) must NOT decrypt
    // — proving the candidate set is precisely what enables external funding.
    let mut legacy = bundle_from_txs(&[(&note, false, Some(100))]);
    legacy.notes_onchain[0].pays_self = true;
    legacy.notes_onchain[0].sender = Some(f.address(NET));
    let notes = extract_notes(&legacy, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "no candidate → funder key cannot decrypt");

    // Wrong-but-taproot candidates never spuriously authenticate (AAD/AEAD).
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let mut wrong = bundle_from_txs(&[(&note, false, Some(100))]);
    wrong.notes_onchain[0].pays_self = true;
    wrong.notes_onchain[0].sender = Some(f.address(NET));
    wrong.notes_onchain[0].author_candidates = vec![f.address(NET), c.address(NET)];
    let notes = extract_notes(&wrong, &b, NET);
    assert!(notes[0].text.is_none(), "wrong candidates must fail the AAD");
}

/// Author-side recovery of an EXTERNALLY-FUNDED directed-private note. The
/// author's tx does not spend from them (a funder paid), so a rescan sees it as
/// "received" — but open_sent with the recipient candidate (the note's dust
/// output) restores it to the author's own notebook: not received, recipient set.
#[test]
fn externally_funded_author_recovers_own_directed_private() {
    let a = identity(); // author
    let b = identity_b(); // recipient
    let f = Identity::from_app_seed(&[0x11u8; 32]).unwrap(); // funder
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "my own words, externally paid", true, [4, 2, 4, 2], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    // A's rescan of the externally-funded tx: it pays A (dust-to-self) but does
    // NOT spend from A; the input sender is the funder; candidates include B.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(f.address(NET));
    bundle.notes_onchain[0].author_candidates = vec![f.address(NET), b.address(NET)];
    let notes = extract_notes(&bundle, &a, NET);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received, "author's own note must not read as received");
    assert_eq!(notes[0].recipient.as_deref(), Some(b.address(NET).as_str()));
    assert_eq!(notes[0].text.as_deref(), Some("my own words, externally paid"));
}

/// The 68-byte AAD binds the sender: attributing the same sealed body to a
/// different sender address must fail decryption, not yield wrong text.
#[test]
fn directed_aad_binds_direction_and_sender() {
    let a = identity();
    let b = identity_b();
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "authentic", true, [3, 0, 0, 3], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    let mut spoofed = bundle_from_txs(&[(&note, false, Some(100))]);
    spoofed.notes_onchain[0].pays_self = true;
    spoofed.notes_onchain[0].sender = Some(c.address(NET)); // lie about the author
    let notes = extract_notes(&spoofed, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "spoofed sender must fail the AAD, not decrypt");
}

/// Received acceptance is additive: pays-me PNTE surfaces as received
/// (never own); neither-from-nor-paying stays ignored (covered again here
/// with a directed note for completeness).
#[test]
fn received_acceptance_is_additive() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "delivered", false, [4, 0, 0, 4], &to_b, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    // pays_self missing (old bundle) → tx contributes nothing at B.
    let old_style = bundle_from_txs(&[(&note, false, Some(100))]);
    assert!(extract_notes(&old_style, &b, NET).is_empty());

    // pays_self set → received, and never classified as own.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received);
}

/// An attacker reusing one of MY note_ids in a pays-me tx must not
/// contaminate my own note's chunk bucket.
#[test]
fn received_note_id_collision_does_not_contaminate() {
    let a = identity();
    let b = identity_b();
    let shared_id = [5, 0, 0, 5];
    let mine =
        compose_note(&a, &utxos(), "my own words", false, shared_id, 80, 1.0, || Ok(AUX)).unwrap();
    let to_a = Recipient::parse(NET, &a.address(NET)).unwrap();
    let attack = compose_directed_note(
        &b, &utxos(), "gotcha?", false, shared_id, &to_a, 80, 1.0, || Ok(AUX),
    )
    .unwrap();

    let mut bundle = bundle_from_txs(&[(&mine, true, Some(100)), (&attack, false, Some(101))]);
    bundle.notes_onchain[1].pays_self = true;
    bundle.notes_onchain[1].sender = Some(b.address(NET));
    let notes = extract_notes(&bundle, &a, NET);
    assert_eq!(notes.len(), 2, "own and received buckets must stay separate");
    let own = notes.iter().find(|n| !n.received).unwrap();
    assert_eq!(own.text.as_deref(), Some("my own words"), "own note must survive intact");
    let recv = notes.iter().find(|n| n.received).unwrap();
    assert_eq!(recv.text.as_deref(), Some("gotcha?"));
}

#[test]
fn private_directed_requires_p2tr_recipient() {
    let a = identity();
    let v0 = Recipient {
        address: "fake".into(),
        spk: {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[0x11; 20]);
            s
        },
        p2tr_x: None,
    };
    let err = compose_directed_note(
        &a, &utxos(), "secret", true, [6, 0, 0, 6], &v0, 80, 1.0, || Ok(AUX),
    );
    assert!(matches!(err, Err(notes_core::Error::RecipientNotTaproot)));
    // Public to a v0 address is fine.
    compose_directed_note(&a, &utxos(), "postcard", false, [6, 0, 0, 7], &v0, 80, 1.0, || Ok(AUX))
        .unwrap();
}

#[test]
fn decode_scanned_roundtrip() {
    use notes_core::bundle::{decode_scanned, SCAN_MAGIC};
    let json = r#"{"network":"regtest","tip_height":7}"#;
    // CNB1 + deflate-raw (what the companion's CompressionStream emits).
    let mut blob = SCAN_MAGIC.to_vec();
    blob.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(json.as_bytes(), 6));
    assert_eq!(decode_scanned(&blob).unwrap(), json);
    // Plain JSON QR tolerated.
    assert_eq!(decode_scanned(json.as_bytes()).unwrap(), json);
    // Garbage rejected.
    assert!(decode_scanned(b"CNB1notdeflate").is_err());
    assert!(decode_scanned(b"hello world").is_err());
    assert!(decode_scanned(b"").is_err());
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
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text.as_deref(), Some("once only"));

    // Same for a RECEIVED directed note duplicated across bundles.
    let b = identity_b();
    let to_me = Recipient::parse(NET, &id.address(NET)).unwrap();
    let sent = compose_directed_note(
        &b, &utxos(), "dm once", true, [8, 8, 8, 8], &to_me, 80, 1.0, || Ok(AUX),
    )
    .unwrap();
    let mut rb = bundle_from_txs(&[(&sent, false, Some(11))]);
    rb.notes_onchain[0].pays_self = true;
    rb.notes_onchain[0].sender = Some(b.address(NET));
    let dup = rb.notes_onchain[0].clone();
    rb.notes_onchain.push(dup);
    let received = extract_notes(&rb, &id, NET);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].text.as_deref(), Some("dm once"));
}

#[test]
fn directed_note_custom_gift_amount() {
    use notes_core::bundle::compose_directed_note_with_change_amount;
    use notes_core::DUST_LIMIT;

    let sender = identity_b();
    let recip = identity();
    let to_recip = Recipient::parse(NET, &recip.address(NET)).unwrap();

    // Default directed note sends exactly dust to the recipient.
    let dust_note = compose_directed_note(
        &sender, &utxos(), "hi", false, [1, 2, 3, 4], &to_recip, 80, 1.0, || Ok(AUX),
    )
    .unwrap();
    assert_eq!(dust_note.sent, DUST_LIMIT, "default gift is dust");

    // A custom gift amount lands verbatim in the recipient output, and the fee
    // math balances: inputs = fee + gift + change.
    let gift = 50_000u64;
    let gift_note = compose_directed_note_with_change_amount(
        &sender, &utxos(), "happy birthday", false, [1, 2, 3, 5], &to_recip, gift, None, 80, 1.0,
        || Ok(AUX),
    )
    .unwrap();
    assert_eq!(gift_note.sent, gift, "gift amount reaches the recipient output");
    let inputs_total: u64 = gift_note.tx.inputs.iter().map(|i| i.value).sum();
    assert_eq!(inputs_total, gift_note.fee + gift_note.sent + gift_note.change);

    // The recipient can still read the note (delivery/index unaffected).
    let mut rb = bundle_from_txs(&[(&gift_note, false, Some(20))]);
    rb.notes_onchain[0].pays_self = true;
    rb.notes_onchain[0].sender = Some(sender.address(NET));
    let received = extract_notes(&rb, &recip, NET);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].text.as_deref(), Some("happy birthday"));

    // Below dust is rejected.
    let err = compose_directed_note_with_change_amount(
        &sender, &utxos(), "too small", false, [1, 2, 3, 6], &to_recip, DUST_LIMIT - 1, None, 80,
        1.0, || Ok(AUX),
    );
    assert!(err.is_err(), "gift below dust must be rejected");
}

#[test]
fn address_decode_matches_rust_bitcoin() {
    use std::str::FromStr;
    // Any-network v0 + v1 decodes must equal rust-bitcoin's scriptPubKey.
    for (net, btc_net, addr) in [
        (
            notes_core::Network::Signet,
            bitcoin::Network::Signet,
            "tb1q2ylq48ne37ng9clds23xjcrxp8hmn707j5vpyk", // P2WPKH (testnet HRP)
        ),
        (
            notes_core::Network::Mainnet,
            bitcoin::Network::Bitcoin,
            "bc1p548gt356p9jrhr6p5hfvd83km5zus936hlcfyzl0xhmtg5av2arqtvrpme", // P2TR
        ),
    ] {
        let ours = notes_core::address::address_to_script_pubkey(net, addr).unwrap();
        let theirs = bitcoin::Address::from_str(addr)
            .unwrap()
            .require_network(btc_net)
            .unwrap()
            .script_pubkey();
        assert_eq!(ours, theirs.into_bytes(), "{addr}");
    }
    // Wrong network HRP must be rejected.
    assert!(notes_core::address::address_to_script_pubkey(
        notes_core::Network::Regtest,
        "bc1p548gt356p9jrhr6p5hfvd83km5zus936hlcfyzl0xhmtg5av2arqtvrpme"
    )
    .is_err());
}

/// Sweep: all inputs, one external output, rust-bitcoin cross-check.
#[test]
fn sweep_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let dest = notes_core::address::address_to_script_pubkey(
        notes_core::Network::Regtest,
        &Identity::from_app_seed(&[9u8; 32]).unwrap().address(notes_core::Network::Regtest),
    )
    .unwrap();
    let sweep = notes_core::tx::build_sweep_tx(
        &utxos(),
        &id.output_x,
        dest.clone(),
        2.0,
        &id.tweaked_seckey,
        || Ok(AUX),
    )
    .unwrap();
    assert_eq!(sweep.tx.inputs.len(), 3, "sweeps every utxo");
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].value, 86_000 - sweep.fee);

    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);

    let spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&id.output_x));
    let prevouts: Vec<TxOut> = sweep
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for (index, witness) in (0..btx.input.len()).zip(&sweep.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&witness[0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("sweep signature must verify");
    }
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

/// Same cross-check for a DIRECTED tx (self inputs + dust to recipient +
/// OP_RETURNs + change): rust-bitcoin must parse it, agree on txid/vsize,
/// recompute the sighash and accept our signature.
#[test]
fn directed_rust_bitcoin_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &id,
        &utxos(),
        "directed, cross-checked against rust-bitcoin",
        true,
        [0xDD, 0x11, 0x22, 0x33],
        &to_b,
        80,
        3.0,
        || Ok(AUX),
    )
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);
    // The dust output must land at B's address per rust-bitcoin's decoder.
    let dust = btx.output.iter().find(|o| o.value.to_sat() == 330).unwrap();
    assert_eq!(dust.script_pubkey.as_bytes(), to_b.spk.as_slice());

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
    for (index, witness) in (0..btx.input.len()).zip(&note.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&witness[0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("directed tx signature must verify");
    }
}

#[test]
fn change_can_go_to_a_custom_address() {
    let a = identity();
    let b = identity_b();
    // Custom change destination = identity B's own taproot spk.
    let b_spk = notes_core::address::address_to_script_pubkey(
        Network::Regtest,
        &b.address(Network::Regtest),
    )
    .unwrap();

    let default_tx =
        compose_note(&a, &utxos(), "hi", false, [1, 2, 3, 4], 80, 1.0, || Ok([0u8; 32])).unwrap();
    let custom_tx = compose_note_with_change(
        &a, &utxos(), "hi", false, [1, 2, 3, 4], Some(&b_spk), 80, 1.0, || Ok([0u8; 32]),
    )
    .unwrap();

    // Same inputs, same note; only the change output's script differs.
    assert_eq!(default_tx.spent_outpoints, custom_tx.spent_outpoints);
    assert_eq!(default_tx.change, custom_tx.change);
    let default_change = default_tx.tx.outputs.last().unwrap();
    let custom_change = custom_tx.tx.outputs.last().unwrap();
    assert_eq!(default_change.value, custom_change.value);
    assert_ne!(default_change.script_pubkey, custom_change.script_pubkey);
    assert_eq!(custom_change.script_pubkey, b_spk);
    // And it's a valid, different tx.
    assert_ne!(default_tx.txid_hex, custom_tx.txid_hex);
}

#[test]
fn exact_inputs_spends_all_given_coins() {
    let a = identity();
    // Two coins; auto-select would use only the first (largest).
    let coins = vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 0, value: 40_000 },
    ];
    let auto = compose_note(&a, &coins, "hi", false, [1, 2, 3, 4], 80, 1.0, || Ok([0u8; 32])).unwrap();
    // Auto used 1 input (60k covers it); exact-with-both spends both.
    assert_eq!(auto.spent_outpoints.len(), 1);
    let exact = compose_note_exact(&a, &coins, "hi", false, [1, 2, 3, 4], None, 80, 1.0, || Ok([0u8; 32])).unwrap();
    assert_eq!(exact.spent_outpoints.len(), 2, "exact spends every provided coin");
    assert!(exact.change > auto.change, "spending both leaves more change");

    // Exact with just the first coin == auto (both use that one coin).
    let one = compose_note_exact(&a, &coins[..1], "hi", false, [1, 2, 3, 4], None, 80, 1.0, || Ok([0u8; 32])).unwrap();
    assert_eq!(one.txid_hex, auto.txid_hex);

    // Not enough value → InsufficientFunds.
    let tiny = vec![Utxo { txid: [3u8; 32], vout: 0, value: 10 }];
    assert!(compose_note_exact(&a, &tiny, "hi", false, [1, 2, 3, 4], None, 80, 1.0, || Ok([0u8; 32])).is_err());
}
