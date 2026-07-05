//! bech32m P2TR address encoding (BIP350) for the supported networks.

use bech32::segwit;

use crate::Network;

/// P2TR: witness v1 over the tweaked output x coordinate, bech32m.
pub fn taproot_address(network: Network, output_x: &[u8; 32]) -> String {
    segwit::encode_v1(network.hrp(), output_x).expect("32-byte program is always valid")
}

/// scriptPubKey for a P2TR output: OP_1 PUSH32 <output_x>.
pub fn p2tr_script_pubkey(output_x: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(output_x);
    spk
}
