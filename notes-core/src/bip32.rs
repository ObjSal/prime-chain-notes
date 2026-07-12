//! Minimal BIP-32: root-from-seed, hardened AND normal CKDpriv, key
//! fingerprint. Ported from the workspace sibling `bip85-core` (which is
//! hardened-only) and extended with normal derivation — the BIP-86 leaf
//! path `m/86'/{coin}'/{account}'/0/{index}` ends in two normal steps,
//! which need the parent's compressed public key in the HMAC input.
//!
//! No xprv/tprv serialization on purpose: the device never exports
//! extended keys, only 24-word phrases (see `seeds.rs`).

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

pub const HARDENED: u32 = 0x8000_0000;

/// A private extended key — just the derivation state, no serialization.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Xprv {
    pub depth: u8,
    pub chain_code: [u8; 32],
    pub key: [u8; 32],
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

impl Xprv {
    /// BIP-32 master key from a seed (`HMAC-SHA512("Bitcoin seed", seed)`).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let (il, ir) = i.split_at(32);
        let key: [u8; 32] = il.try_into().unwrap();
        nonzero_scalar(&key)?;
        Ok(Xprv { depth: 0, chain_code: ir.try_into().unwrap(), key })
    }

    /// Compressed SEC1 public key of this node (33 bytes).
    pub fn pubkey(&self) -> Result<[u8; 33], Error> {
        let k = nonzero_scalar(&self.key)?;
        let point = (ProjectivePoint::GENERATOR * k).to_affine();
        Ok(point.to_encoded_point(true).as_bytes().try_into().unwrap())
    }

    /// BIP-32 key fingerprint: first 4 bytes of HASH160 of the compressed
    /// public key — the "xfp" wallets display. Not a secret.
    pub fn fingerprint(&self) -> Result<[u8; 4], Error> {
        let h160 = Ripemd160::digest(Sha256::digest(self.pubkey()?));
        Ok(h160[..4].try_into().unwrap())
    }

    /// [`Self::fingerprint`] as the conventional 8-char lowercase hex.
    pub fn fingerprint_hex(&self) -> Result<String, Error> {
        Ok(self.fingerprint()?.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// CKDpriv. `index` carries the hardened bit already (use
    /// [`Self::derive_hardened`]/[`Self::derive_normal`] for clarity).
    pub fn derive(&self, index: u32) -> Result<Self, Error> {
        let mut data = Vec::with_capacity(37);
        if index & HARDENED != 0 {
            data.push(0);
            data.extend_from_slice(&self.key);
        } else {
            data.extend_from_slice(&self.pubkey()?);
        }
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(&self.chain_code, &data);
        data.zeroize();
        let (il, ir) = i.split_at(32);

        let il_scalar = nonzero_scalar_or_valid(il.try_into().unwrap())?;
        let parent = nonzero_scalar(&self.key)?;
        let child = il_scalar + parent;
        if bool::from(child.is_zero()) {
            return Err(Error::Derivation("derived zero key"));
        }
        Ok(Xprv {
            depth: self.depth + 1,
            chain_code: ir.try_into().unwrap(),
            key: child.to_repr().into(),
        })
    }

    /// Hardened CKDpriv (`index` WITHOUT the hardened bit).
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Error> {
        self.derive(index | HARDENED)
    }

    /// Normal (non-hardened) CKDpriv.
    pub fn derive_normal(&self, index: u32) -> Result<Self, Error> {
        if index & HARDENED != 0 {
            return Err(Error::Derivation("normal index has hardened bit"));
        }
        self.derive(index)
    }

    /// Derive along a path of raw child numbers (hardened bit included).
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Error> {
        let mut node = self.clone();
        for &index in path {
            node = node.derive(index)?;
        }
        Ok(node)
    }
}

fn nonzero_scalar(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    let s = nonzero_scalar_or_valid(bytes)?;
    if bool::from(s.is_zero()) {
        return Err(Error::Derivation("zero key"));
    }
    Ok(s)
}

/// Parse as scalar, rejecting only >= order (zero allowed — IL may be
/// anything below the order per BIP-32; the child sum is checked instead).
fn nonzero_scalar_or_valid(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or(Error::Derivation("scalar out of range"))
}
