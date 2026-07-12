//! BIP-39: entropy → English mnemonic, mnemonic → 64-byte seed.
//! Ported from the workspace sibling `bip85-core` (same pure-Rust deps).
//! English-only, which keeps normalization trivial: the wordlist is pure
//! ASCII, so NFKD is a no-op.

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};

use crate::Error;

/// Canonical English wordlist, checked in verbatim
/// (sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
pub const WORDS: &str = include_str!("english.txt");

pub fn wordlist() -> Vec<&'static str> {
    WORDS.lines().collect()
}

/// 11-bit wordlist indices for the given entropy (16/24/32 bytes).
pub fn entropy_to_indices(entropy: &[u8]) -> Result<Vec<u16>, Error> {
    if !matches!(entropy.len(), 16 | 24 | 32) {
        return Err(Error::Derivation("bad entropy length"));
    }
    let checksum_bits = entropy.len() * 8 / 32;
    let checksum = Sha256::digest(entropy)[0] >> (8 - checksum_bits);

    // Accumulate entropy || checksum bits, emitting an index every 11 bits.
    let mut indices = Vec::with_capacity((entropy.len() * 8 + checksum_bits) / 11);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut push_bits = |acc: &mut u32, bits: &mut usize, n: usize, value: u32| {
        *acc = (*acc << n) | value;
        *bits += n;
        while *bits >= 11 {
            indices.push(((*acc >> (*bits - 11)) & 0x7FF) as u16);
            *bits -= 11;
        }
    };
    for byte in entropy {
        push_bits(&mut acc, &mut bits, 8, *byte as u32);
    }
    push_bits(&mut acc, &mut bits, checksum_bits, checksum as u32);
    Ok(indices)
}

pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, Error> {
    let list = wordlist();
    let words: Vec<&str> =
        entropy_to_indices(entropy)?.into_iter().map(|i| list[i as usize]).collect();
    Ok(words.join(" "))
}

/// PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic" + passphrase`.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{passphrase}");
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}
