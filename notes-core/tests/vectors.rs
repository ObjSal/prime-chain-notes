//! Published-vector tests: BIP340 signing/verification and the BIP341
//! taproot tweak, plus address encoding cross-checked against rust-bitcoin.

use notes_core::sign::{schnorr_sign, schnorr_verify};
use notes_core::taproot::taproot_tweak_pubkey;
use notes_core::{address, Network};

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap();
    out
}

// From the official BIP340 test vector CSV (index 0, 1, 2).
#[test]
fn bip340_sign_vectors() {
    let cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        ),
        (
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        ),
        (
            "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        ),
    ];
    for (seckey, aux, msg, want_sig) in cases {
        let sig = schnorr_sign(&h32(seckey), &h32(msg), &h32(aux)).unwrap();
        assert_eq!(hex::encode_upper(sig), want_sig, "seckey {seckey}");
    }
}

#[test]
fn bip340_verify_rejects_tampered() {
    let seckey = h32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let msg = h32("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let aux = h32("0000000000000000000000000000000000000000000000000000000000000001");
    let pubkey = h32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let sig = schnorr_sign(&seckey, &msg, &aux).unwrap();
    assert!(schnorr_verify(&pubkey, &msg, &sig));
    let mut bad = sig;
    bad[7] ^= 1;
    assert!(!schnorr_verify(&pubkey, &msg, &bad));
    let mut wrong_msg = msg;
    wrong_msg[0] ^= 1;
    assert!(!schnorr_verify(&pubkey, &wrong_msg, &sig));
}

// BIP341 scriptPubKey test vector #1: key-path-only (no script tree).
#[test]
fn bip341_tweak_vector() {
    let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (output_x, _) = taproot_tweak_pubkey(&internal, None).unwrap();
    assert_eq!(
        hex::encode(output_x),
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
}

#[test]
fn address_matches_rust_bitcoin() {
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::secp256k1::Secp256k1;

    let secp = Secp256k1::verification_only();
    let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (output_x, _) = taproot_tweak_pubkey(&internal, None).unwrap();

    for (network, btc_network) in [
        (Network::Mainnet, bitcoin::Network::Bitcoin),
        // rust-bitcoin's Testnet(3) shares the tb HRP with testnet4.
        (Network::Testnet4, bitcoin::Network::Testnet),
        (Network::Signet, bitcoin::Network::Signet),
        (Network::Regtest, bitcoin::Network::Regtest),
    ] {
        let ours = address::taproot_address(network, &output_x);
        let theirs = bitcoin::Address::p2tr(
            &secp,
            UntweakedPublicKey::from_slice(&internal).unwrap(),
            None,
            btc_network,
        );
        assert_eq!(ours, theirs.to_string(), "{network:?}");
    }
}
