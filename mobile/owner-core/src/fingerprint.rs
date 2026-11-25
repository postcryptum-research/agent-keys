//! Key fingerprints for humans to compare across devices
//! (docs/MOBILE_OWNER_DESIGN.md §6.3): the first 100 bits of
//! `sha256(x ‖ y)`, as four groups of five base32 characters.

use hw_signer::PublicKey;
use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `ABCDE-FGHIJ-KLMNO-PQRST`: 20 base32 characters = 100 bits.
pub fn fingerprint(pk: &PublicKey) -> String {
    let digest = Sha256::new().chain_update(pk.x).chain_update(pk.y).finalize();
    // 100 bits = 12.5 bytes; read 20 five-bit groups from the first 13 bytes.
    let mut bits: u128 = 0;
    for b in &digest[..13] {
        bits = (bits << 8) | *b as u128;
    }
    bits >>= 4; // keep the top 100 of the 104 bits
    let mut chars = Vec::with_capacity(20);
    // the shifts 95, 90, … 0, most significant group first
    for shift in (0u32..100).step_by(5).rev() {
        chars.push(ALPHABET[(bits.checked_shr(shift).unwrap_or(0) & 31) as usize]);
    }
    let s = String::from_utf8(chars).expect("ascii");
    format!("{}-{}-{}-{}", &s[..5], &s[5..10], &s[10..15], &s[15..20])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_determinism() {
        let pk = PublicKey { x: [1; 32], y: [2; 32] };
        let f = fingerprint(&pk);
        assert_eq!(f.len(), 23);
        assert!(f.split('-').all(|g| g.len() == 5 && g.bytes().all(|b| ALPHABET.contains(&b))));
        assert_eq!(f, fingerprint(&pk));
        assert_ne!(f, fingerprint(&PublicKey { x: [1; 32], y: [3; 32] }));
    }
}
