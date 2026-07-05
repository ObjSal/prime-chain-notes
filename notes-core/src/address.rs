//! bech32/bech32m segwit address encoding and decoding (BIP173/BIP350).

use bech32::segwit;

use crate::{Error, Network};

/// P2TR: witness v1 over the tweaked output x coordinate, bech32m.
pub fn taproot_address(network: Network, output_x: &[u8; 32]) -> String {
    segwit::encode_v1(network.hrp(), output_x).expect("32-byte program is always valid")
}

/// Decode any segwit address into its scriptPubKey, enforcing the
/// expected network's HRP. Used for sweep destinations (v0 P2WPKH/P2WSH
/// and v1 P2TR all reduce to `OP_n PUSH<program>`).
pub fn address_to_script_pubkey(network: Network, address: &str) -> Result<Vec<u8>, Error> {
    let (hrp, version, program) =
        segwit::decode(address).map_err(|_| Error::InvalidPublicKey)?;
    if hrp != network.hrp() {
        return Err(Error::InvalidPublicKey);
    }
    let mut spk = Vec::with_capacity(2 + program.len());
    spk.push(if version.to_u8() == 0 { 0x00 } else { 0x50 + version.to_u8() });
    spk.push(program.len() as u8);
    spk.extend_from_slice(&program);
    Ok(spk)
}

/// scriptPubKey for a P2TR output: OP_1 PUSH32 <output_x>.
pub fn p2tr_script_pubkey(output_x: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(output_x);
    spk
}

/// The x-only output key of a P2TR scriptPubKey, or None for any other kind.
pub fn p2tr_x_of_spk(spk: &[u8]) -> Option<[u8; 32]> {
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        let mut x = [0u8; 32];
        x.copy_from_slice(&spk[2..]);
        Some(x)
    } else {
        None
    }
}

/// The x-only output key of a P2TR address, or None (bad address, wrong
/// network, or non-taproot). Used by the scanner to run ECDH against a
/// sender/recipient address seen on-chain.
pub fn p2tr_x_of_address(network: Network, address: &str) -> Option<[u8; 32]> {
    address_to_script_pubkey(network, address).ok().and_then(|spk| p2tr_x_of_spk(&spk))
}

/// A validated directed-note recipient: any segwit address decodes; only
/// P2TR recipients have an x-only key to encrypt to.
pub struct Recipient {
    pub address: String,
    pub spk: Vec<u8>,
    pub p2tr_x: Option<[u8; 32]>,
}

impl Recipient {
    pub fn parse(network: Network, address: &str) -> Result<Self, Error> {
        let address = address.trim();
        let spk = address_to_script_pubkey(network, address)?;
        let p2tr_x = p2tr_x_of_spk(&spk);
        Ok(Recipient { address: address.to_string(), spk, p2tr_x })
    }
}
