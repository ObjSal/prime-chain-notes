//! BIP341 taproot tweaking (key-path only — no script tree in this app).
//!
//! Ported verbatim from prime-paper-wallet's wallet-core `taproot.rs`,
//! which is pinned byte-identical to the bitcoin-gift-wallet reference
//! implementation and the BIP341 vectors.

use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use elliptic_curve::subtle::Choice;
use elliptic_curve::PrimeField;
use k256::elliptic_curve;
use k256::{AffinePoint, ProjectivePoint};
use sha2::{Digest, Sha256};

use crate::keys::scalar_from_bytes;
use crate::Error;

/// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// tweak = tagged_hash("TapTweak", pubkey_x [|| script_tree_hash]).
pub fn compute_taptweak(pubkey_x: &[u8; 32], script_tree_hash: Option<&[u8; 32]>) -> [u8; 32] {
    match script_tree_hash {
        Some(sth) => {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(pubkey_x);
            data[32..].copy_from_slice(sth);
            tagged_hash("TapTweak", &data)
        }
        None => tagged_hash("TapTweak", pubkey_x),
    }
}

/// BIP340 lift_x: decompress an x coordinate to the point with even y.
pub(crate) fn lift_x(x: &[u8; 32]) -> Result<AffinePoint, Error> {
    let ct = AffinePoint::decompress(&(*x).into(), Choice::from(0));
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(Error::InvalidPublicKey)
    }
}

/// Q = lift_x(internal) + t*G. Returns (output_x, parity_of_Q_y).
pub fn taproot_tweak_pubkey(
    internal_x: &[u8; 32],
    script_tree_hash: Option<&[u8; 32]>,
) -> Result<([u8; 32], u8), Error> {
    let p = lift_x(internal_x)?;
    let tweak = compute_taptweak(internal_x, script_tree_hash);
    let t = scalar_from_bytes(&tweak).ok_or(Error::TweakOutOfRange)?;
    let q = (ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * t).to_affine();
    if bool::from(q.is_identity()) {
        return Err(Error::PointAtInfinity);
    }
    let x: [u8; 32] = q.x().into();
    Ok((x, u8::from(bool::from(q.y_is_odd()))))
}

/// Tweaked private key: negate k if its pubkey has odd y, then k + t mod N.
pub fn taproot_tweak_seckey(
    privkey: &[u8; 32],
    script_tree_hash: Option<&[u8; 32]>,
) -> Result<[u8; 32], Error> {
    let k = scalar_from_bytes(privkey).ok_or(Error::InvalidPrivateKey)?;
    let point = (ProjectivePoint::GENERATOR * k).to_affine();
    let k = if bool::from(point.y_is_odd()) { -k } else { k };
    let x: [u8; 32] = point.x().into();
    let tweak = compute_taptweak(&x, script_tree_hash);
    let t = scalar_from_bytes(&tweak).ok_or(Error::TweakOutOfRange)?;
    let tweaked = k + t;
    if bool::from(tweaked.is_zero()) {
        return Err(Error::PointAtInfinity);
    }
    Ok(tweaked.to_repr().into())
}
