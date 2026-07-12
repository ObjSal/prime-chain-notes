//! Stateless CLI over notes-core for the regtest end-to-end test — plays
//! the DEVICE role from the host: derive address, compose+sign notes from
//! a sync bundle, scan a bundle back into notes. The e2e script
//! (../../scripts/regtest-e2e.sh) plays the companion with bitcoin-cli.
//!
//! App seed comes from NOTES_APP_SEED (64 hex chars), defaulting to a
//! fixed test seed. NOT part of the shipped app.

use std::io::Read;

use notes_core::address::Recipient;
use notes_core::bundle::{compose_directed_note, compose_note, extract_notes, Identity, SyncBundle};
use notes_core::keys::{generate_aux_rand, generate_note_id, pick_unique_note_id};
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
        // Recovery seeds (PLAN-chain-notes-seed-rotation.md): mirror what
        // the device derives so the e2e can cross-check the sim UI and
        // feed the words to the chain-notes-app import.
        Some("seed-words") => {
            // seed-words <seed_index>
            let index: u32 = args[2].parse().expect("seed index");
            let words = notes_core::seeds::seed_mnemonic(&app_seed(), index).unwrap();
            println!("{}", &*words);
        }
        Some("seed-address") => {
            // seed-address <network> <seed_index> <account> <index>
            let network = Network::from_str_opt(&args[2]).expect("network");
            let seed: u32 = args[3].parse().expect("seed index");
            let account: u32 = args[4].parse().expect("account");
            let index: u32 = args[5].parse().expect("receive index");
            let id = Identity::from_bip86(&app_seed(), seed, network, account, index).unwrap();
            println!("{}", id.address(network));
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
            // Reroll against every note id already visible in the bundle
            // (self-collision guard; foreign ids included — a wider taken
            // set is harmless).
            let taken: std::collections::BTreeSet<[u8; 4]> = bundle
                .notes_onchain
                .iter()
                .flat_map(|t| t.payloads.iter())
                .filter_map(|p| hex::decode(p).ok())
                .filter_map(|p| notes_core::envelope::decode(&p))
                .map(|c| c.note_id)
                .collect();
            let note_id =
                pick_unique_note_id(generate_note_id, |id| taken.contains(id)).unwrap();
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
        Some("send") => {
            // send <bundle.json|-> <recipient_addr> <public|private> <fee_rate> <max_or> <text>
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&bundle.network).expect("bundle network");
            let recipient = Recipient::parse(network, &args[3]).unwrap();
            let private = match args[4].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[5].parse().unwrap();
            let max_or: usize = args[6].parse().unwrap();
            let text = &args[7];
            let taken: std::collections::BTreeSet<[u8; 4]> = bundle
                .notes_onchain
                .iter()
                .flat_map(|t| t.payloads.iter())
                .filter_map(|p| hex::decode(p).ok())
                .filter_map(|p| notes_core::envelope::decode(&p))
                .map(|c| c.note_id)
                .collect();
            let note_id =
                pick_unique_note_id(generate_note_id, |id| taken.contains(id)).unwrap();
            let note = compose_directed_note(
                &identity,
                &bundle.utxos(),
                text,
                private,
                note_id,
                &recipient,
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
                    "sent": note.sent,
                    "recipient": recipient.address,
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
            let network = Network::from_str_opt(&bundle.network).expect("bundle network");
            let notes = extract_notes(&bundle, &identity, network);
            let out: Vec<_> = notes
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "note_id": hex::encode(n.note_id),
                        "txids": n.txids,
                        "height": n.height,
                        "blocktime": n.blocktime,
                        "private": n.private,
                        "directed": n.directed,
                        "received": n.received,
                        "from": n.sender,
                        "to": n.recipient,
                        "text": n.text,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => {
            eprintln!("usage: notes_cli address <network> | compose <bundle> <public|private> <fee_rate> <max_or> <text> | send <bundle> <recipient_addr> <public|private> <fee_rate> <max_or> <text> | scan <bundle> | sweep <bundle> <network> <dest_address> <fee_rate>");
            std::process::exit(2);
        }
    }
}
