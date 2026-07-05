//! Reference UR-part generator (foundation-ur, the crate the device's
//! scanner runs). Prints the pure sequential parts 1..seqLen for a payload
//! — the companion's JS encoder must emit byte-identical strings.
//!
//! usage: ur_encode <payload-hex> <max-fragment-len>

use foundation_ur::Encoder;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let payload = hex::decode(&args[1]).expect("payload hex");
    let frag_len: usize = args[2].parse().expect("fragment len");

    let mut encoder = Encoder::new();
    encoder.start("bytes", &payload, frag_len);
    let count = encoder.sequence_count();
    for _ in 0..count {
        println!("{}", encoder.next_part());
    }
}
