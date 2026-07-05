//! Stateless CLI over notes-core for the regtest end-to-end test — plays
//! the DEVICE role from the host: derive address, compose+sign notes from
//! a sync bundle, scan a bundle back into notes. The e2e script
//! (../../scripts/regtest-e2e.sh) plays the companion with bitcoin-cli.
//!
//! App seed comes from NOTES_APP_SEED (64 hex chars), defaulting to a
//! fixed test seed. NOT part of the shipped app.

use std::io::Read;

use notes_core::bundle::{compose_note, extract_notes, Identity, SyncBundle};
use notes_core::keys::{generate_aux_rand, generate_note_id};
use notes_core::Network;

fn app_seed() -> [u8; 32] {
    let mut seed = [7u8; 32];
    if let Ok(hex_seed) = std::env::var("NOTES_APP_SEED") {
        hex::decode_to_slice(hex_seed.trim(), &mut seed).expect("NOTES_APP_SEED: 64 hex chars");
    }
    seed
}

fn read_bundle(path: &str) -> SyncBundle {
    let mut json = String::new();
    if path == "-" {
        std::io::stdin().read_to_string(&mut json).unwrap();
    } else {
        json = std::fs::read_to_string(path).unwrap();
    }
    SyncBundle::from_json(&json).expect("invalid sync bundle JSON")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let identity = Identity::from_app_seed(&app_seed()).unwrap();

    match args.get(1).map(String::as_str) {
        Some("address") => {
            let network = Network::from_str_opt(&args[2]).expect("network");
            println!("{}", identity.address(network));
        }
        Some("compose") => {
            // compose <bundle.json|-> <public|private> <fee_rate> <max_or> <text>
            let bundle = read_bundle(&args[2]);
            let private = match args[3].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[4].parse().unwrap();
            let max_or: usize = args[5].parse().unwrap();
            let text = &args[6];
            let note_id = generate_note_id().unwrap();
            let note = compose_note(
                &identity,
                &bundle.utxos(),
                text,
                private,
                note_id,
                max_or,
                fee_rate,
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "note_id": hex::encode(note_id),
                    "txid": note.txid_hex,
                    "raw_hex": note.raw_hex,
                    "fee": note.fee,
                    "vsize": note.vsize,
                    "change": note.change,
                    "op_returns": note.tx.outputs.iter()
                        .filter(|o| o.script_pubkey.first() == Some(&0x6a)).count(),
                })
            );
        }
        Some("sweep") => {
            // sweep <bundle.json|-> <network> <dest_address> <fee_rate>
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&args[3]).expect("network");
            let dest_spk =
                notes_core::address::address_to_script_pubkey(network, &args[4]).unwrap();
            let fee_rate: f64 = args[5].parse().unwrap();
            let sweep = notes_core::tx::build_sweep_tx(
                &bundle.utxos(),
                &identity.output_x,
                dest_spk,
                fee_rate,
                &identity.tweaked_seckey,
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "txid": sweep.txid_hex,
                    "raw_hex": sweep.raw_hex,
                    "fee": sweep.fee,
                    "vsize": sweep.vsize,
                    "value_out": sweep.tx.outputs[0].value,
                })
            );
        }
        Some("scan") => {
            let bundle = read_bundle(&args[2]);
            let notes = extract_notes(&bundle, &identity.enc_key);
            let out: Vec<_> = notes
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "note_id": hex::encode(n.note_id),
                        "txids": n.txids,
                        "height": n.height,
                        "blocktime": n.blocktime,
                        "private": n.private,
                        "text": n.text,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => {
            eprintln!("usage: notes_cli address <network> | compose <bundle> <public|private> <fee_rate> <max_or> <text> | scan <bundle> | sweep <bundle> <network> <dest_address> <fee_rate>");
            std::process::exit(2);
        }
    }
}
