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
