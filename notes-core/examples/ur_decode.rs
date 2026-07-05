//! Cross-check tool: feed UR part strings (one per line, stdin) into the
//! SAME decoder the KeyOS system QR scanner uses (foundation-ur), print
//! the reassembled payload as hex. The companion's JS UR encoder is
//! correct iff this accepts its parts and the payload round-trips.

use std::io::{BufRead, Write};

use foundation_ur::Decoder;

fn main() {
    let mut decoder: Decoder = Decoder::default();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let part = line.trim();
        if part.is_empty() {
            continue;
        }
        let lowered = part.to_lowercase();
        let ur = foundation_ur::UR::parse(lowered.as_str())
            .unwrap_or_else(|e| panic!("UR::parse failed on {part:?}: {e:?}"));
        decoder.receive(ur).expect("decoder.receive failed");
        if decoder.is_complete() {
            break;
        }
    }
    assert!(decoder.is_complete(), "UR sequence incomplete after stdin closed");
    let ur_type = decoder.ur_type().expect("no ur type").to_string();
    let message = decoder.message().expect("message error").expect("no message");
    eprintln!("ur_type={ur_type}");
    let mut out = std::io::stdout();
    out.write_all(hex::encode(&message).as_bytes()).unwrap();
    out.write_all(b"\n").unwrap();
}
