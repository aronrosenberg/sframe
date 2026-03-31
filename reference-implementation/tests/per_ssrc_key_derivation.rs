// Test harness for SFrame per-SSRC stream key derivation vectors.
// Loads per-ssrc-key-derivation.json from the project's test-vectors directory
// and verifies that the Rust implementation produces identical keys.

use serde::Deserialize;
use sframe_reference::derive_ssrc_key;

#[derive(Deserialize)]
struct VectorEntry {
    cipher_suite: u16,
    base_key: String,
    ssrc_a: String,
    ssrc_b: String,
    stream_key_a: String,
    stream_key_b: String,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn parse_ssrc(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("invalid ssrc")
}

#[test]
fn per_ssrc_stream_key_vectors() {
    let json = include_str!("../../test-vectors/test-vectors-per-ssrc-key-derivation.json");
    let entries: Vec<VectorEntry> = serde_json::from_str(json).expect("failed to parse vectors");

    assert!(!entries.is_empty(), "Expected at least one vector entry");

    for entry in &entries {
        let base_key = hex_to_bytes(&entry.base_key);
        let ssrc_a = parse_ssrc(&entry.ssrc_a);
        let ssrc_b = parse_ssrc(&entry.ssrc_b);

        let computed_a = derive_ssrc_key(ssrc_a, &base_key, entry.cipher_suite);
        let computed_b = derive_ssrc_key(ssrc_b, &base_key, entry.cipher_suite);

        assert_eq!(
            computed_a,
            hex_to_bytes(&entry.stream_key_a),
            "stream_key_a mismatch for cipher_suite 0x{:04x}",
            entry.cipher_suite
        );
        assert_eq!(
            computed_b,
            hex_to_bytes(&entry.stream_key_b),
            "stream_key_b mismatch for cipher_suite 0x{:04x}",
            entry.cipher_suite
        );
    }
}
