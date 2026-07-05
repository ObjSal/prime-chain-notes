//! Directed-note encryption: STATIC-STATIC x-only ECDH between two taproot
//! output keys, HKDF'd into an XChaCha20-Poly1305 key.
//!
//! CONSENSUS-CRITICAL FOR RE-DERIVATION — FROZEN like keys.rs: the salt and
//! info strings below, the x-only shared-secret definition, and the 68-byte
//! AAD layout are baked into every directed note ever sealed. NEVER change
//! them.
//!
//! Key agreement: `shared_x = x( my_tweaked_seckey · lift_x(peer_output_x) )`.
//! The taproot-tweaked scalar `a` satisfies `a·G = ±lift_x(my_output_x)`, so
//! the four parity combinations differ only in the sign of the shared point —
//! erased by taking the x coordinate. Both directions therefore derive the
//! same key from nothing but chain-visible data plus their own seed: the
//! sender re-reads sent notes after a wipe (peer = the tx's dust-output key),
//! the recipient reads received ones (peer = the tx's input key).
//!
//! AAD binds direction and note identity: `sender_x || recipient_x ||
//! note_id` — a sealed body replayed from a different sender address, to a
//! different recipient, or under another note_id fails authentication.

use hkdf::Hkdf;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::ProjectivePoint;
use sha2::Sha256;

use crate::keys::scalar_from_bytes;
use crate::taproot::lift_x;
use crate::{crypt, Error};

pub const DM_SALT: &[u8] = b"prime-chain-notes/dm/v1";
pub const DM_INFO: &[u8] = b"dm-enc/v1";

/// x coordinate of `tweaked_seckey · lift_x(peer_output_x)`.
pub fn ecdh_shared_x(
    tweaked_seckey: &[u8; 32],
    peer_output_x: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let a = scalar_from_bytes(tweaked_seckey).ok_or(Error::InvalidPrivateKey)?;
    let peer = lift_x(peer_output_x)?;
    let shared = (ProjectivePoint::from(peer) * a).to_affine();
    if bool::from(shared.is_identity()) {
        return Err(Error::PointAtInfinity);
    }
    Ok(shared.x().into())
}

/// FROZEN: HKDF-SHA256(DM_SALT, shared_x) expanded with DM_INFO.
pub fn dm_key(shared_x: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(DM_SALT), shared_x);
    let mut okm = [0u8; 32];
    hk.expand(DM_INFO, &mut okm).expect("32 bytes is a valid HKDF length");
    okm
}

/// FROZEN AAD layout: sender_output_x(32) || recipient_output_x(32) || note_id(4).
pub fn dm_aad(sender_x: &[u8; 32], recipient_x: &[u8; 32], note_id: &[u8; 4]) -> [u8; 68] {
    let mut aad = [0u8; 68];
    aad[..32].copy_from_slice(sender_x);
    aad[32..64].copy_from_slice(recipient_x);
    aad[64..].copy_from_slice(note_id);
    aad
}

fn key_for(my_tweaked_seckey: &[u8; 32], peer_output_x: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok(dm_key(&ecdh_shared_x(my_tweaked_seckey, peer_output_x)?))
}

/// Sender side: seal a directed-private body for `recipient_x`.
pub fn seal_directed(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipient_x: &[u8; 32],
    note_id: &[u8; 4],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, recipient_x)?;
    crypt::seal_aad(&key, &dm_aad(my_output_x, recipient_x, note_id), plaintext)
}

/// Recipient side: open a directed-private body sent to me by `sender_x`.
pub fn open_received(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    sender_x: &[u8; 32],
    note_id: &[u8; 4],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, sender_x)?;
    crypt::open_aad(&key, &dm_aad(sender_x, my_output_x, note_id), blob)
}

/// Sender re-reading their own sent note (wipe recovery: the recipient key
/// comes from the tx's dust output, visible in the sender's own history).
pub fn open_sent(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipient_x: &[u8; 32],
    note_id: &[u8; 4],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, recipient_x)?;
    crypt::open_aad(&key, &dm_aad(my_output_x, recipient_x, note_id), blob)
}
