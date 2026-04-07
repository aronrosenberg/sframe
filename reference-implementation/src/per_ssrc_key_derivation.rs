use hkdf::Hkdf;
use hmac::SimpleHmac;
use sha2::{Sha256, Sha512};

/// Derive the per-SSRC stream key for a given SFrame cipher suite as defined in Section 7 of draft-ietf-avtcore-rtp-sframe
///
/// This implements the RTP stream key derivation from the SFrame RTP payload format draft:
/// ```text
/// PRK          = HKDF-Extract(salt=SSRC_big_endian_4_bytes, ikm=base_key)
/// stream_key   = HKDF-Expand(PRK, info="SFrame 1.0 RTP Stream", L=Nh)
/// ```
///
/// Hash function and output length (Nh) are determined by cipher suite:
/// - Suites 0x0001–0x0004: SHA-256, Nh = 32
/// - Suites 0x0005–0x0008: SHA-512, Nh = 64
///
/// # Panics
/// Panics if `cipher_suite` is not in the range 0x0001–0x0008.
pub fn derive_ssrc_key(ssrc: u32, base_key: &[u8], cipher_suite: u16) -> Vec<u8> {
    static INFO: &[u8] = b"SFrame 1.0 RTP Stream";
    let ssrc_salt = ssrc.to_be_bytes();

    match cipher_suite {
        0x0001..=0x0004 => {
            let (_, h) = Hkdf::<Sha256>::extract(Some(&ssrc_salt), base_key);
            let mut key = vec![0u8; 32];
            h.expand(INFO, &mut key).expect("HKDF-Expand failed");
            key
        }
        0x0005..=0x0008 => {
            let (_, h) = Hkdf::<Sha512, SimpleHmac<Sha512>>::extract(Some(&ssrc_salt), base_key);
            let mut key = vec![0u8; 64];
            h.expand(INFO, &mut key).expect("HKDF-Expand failed");
            key
        }
        _ => panic!("Unsupported SFrame cipher suite: 0x{:04x}", cipher_suite),
    }
}
