//! BIP340 Schnorr signing/verification over secp256k1, implemented on
//! k256 scalar/point arithmetic exactly per the BIP340 reference:
//! https://github.com/bitcoin/bips/blob/master/bip-0340
//!
//! `aux_rand` is a parameter so test vectors are byte-reproducible; the
//! device passes fresh TRNG bytes per signature.

use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::ops::Reduce;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::PrimeField;
use k256::elliptic_curve;
use k256::{ProjectivePoint, Scalar, U256};

use crate::keys::scalar_from_bytes;
use crate::taproot::{lift_x, tagged_hash};
use crate::Error;

fn scalar_reduce(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&(*bytes).into())
}

/// BIP340 sign. `seckey` is the (already taproot-tweaked, when spending)
/// signing key; `msg` the 32-byte sighash; `aux` the auxiliary randomness.
pub fn schnorr_sign(seckey: &[u8; 32], msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    let d0 = scalar_from_bytes(seckey).ok_or(Error::InvalidPrivateKey)?;
    let p = (ProjectivePoint::GENERATOR * d0).to_affine();
    let d = if bool::from(p.y_is_odd()) { -d0 } else { d0 };
    let px: [u8; 32] = p.x().into();

    let t_mask = tagged_hash("BIP0340/aux", aux);
    let d_bytes: [u8; 32] = d.to_repr().into();
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = d_bytes[i] ^ t_mask[i];
    }

    let mut nonce_input = Vec::with_capacity(96);
    nonce_input.extend_from_slice(&t);
    nonce_input.extend_from_slice(&px);
    nonce_input.extend_from_slice(msg);
    let k0 = scalar_reduce(&tagged_hash("BIP0340/nonce", &nonce_input));
    if bool::from(k0.is_zero()) {
        return Err(Error::Entropy);
    }
    let r = (ProjectivePoint::GENERATOR * k0).to_affine();
    let k = if bool::from(r.y_is_odd()) { -k0 } else { k0 };
    let rx: [u8; 32] = r.x().into();

    let mut challenge_input = Vec::with_capacity(96);
    challenge_input.extend_from_slice(&rx);
    challenge_input.extend_from_slice(&px);
    challenge_input.extend_from_slice(msg);
    let e = scalar_reduce(&tagged_hash("BIP0340/challenge", &challenge_input));

    let s = k + e * d;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    let s_bytes: [u8; 32] = s.to_repr().into();
    sig[32..].copy_from_slice(&s_bytes);

    debug_assert!(schnorr_verify(&px, msg, &sig));
    Ok(sig)
}

/// BIP340 verify (used by tests and the debug_assert above).
pub fn schnorr_verify(pubkey_x: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(p) = lift_x(pubkey_x) else { return false };
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s_ct = Scalar::from_repr(s_bytes.into());
    if !bool::from(s_ct.is_some()) {
        return false;
    }
    let s = s_ct.unwrap();

    let mut challenge_input = Vec::with_capacity(96);
    challenge_input.extend_from_slice(&rx);
    challenge_input.extend_from_slice(pubkey_x);
    challenge_input.extend_from_slice(msg);
    let e = scalar_reduce(&tagged_hash("BIP0340/challenge", &challenge_input));

    let r_point =
        (ProjectivePoint::GENERATOR * s - ProjectivePoint::from(p) * e).to_affine();
    if bool::from(r_point.is_identity()) || bool::from(r_point.y_is_odd()) {
        return false;
    }
    let r_x: [u8; 32] = r_point.x().into();
    r_x == rx
}
