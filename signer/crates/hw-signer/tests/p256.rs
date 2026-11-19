//! The crate's P-256 helpers, on whichever `p256` line it is built with. They
//! moved from `p256` 0.13 to 0.14 for issue #16, where `normalize_s` changed
//! its return type and the point type its name; what they do must not change.
#![cfg(feature = "software")]

use hw_signer::software::SoftwareSigner;
use hw_signer::{normalize_low_s, valid_public_key, verify_p256, HardwareSigner, PublicKey, Signature};

/// The order of the curve, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
    0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `n - s`: the other `s` that verifies for the same `r`.
fn other_s(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        out[i] = (d + 256 * borrow) as u8;
    }
    out
}

/// The on-chain verifier refuses a high `s`, and a chip returns whichever it
/// computed: the high one comes back low, the low one comes back as it was.
#[test]
fn a_high_s_comes_back_low_and_both_forms_verify() {
    let signer = SoftwareSigner::from_bytes(&[7u8; 32]).unwrap();
    let pk = signer.public_key().unwrap();
    for n in 0..16u8 {
        let digest = [n; 32];
        let low = signer.sign_digest(&digest).unwrap();
        let high = Signature { r: low.r, s: other_s(&low.s) };
        assert!(high.s > low.s, "the signer returns the low s");
        assert_eq!(normalize_low_s(high), low);
        assert_eq!(normalize_low_s(low), low);
        assert!(verify_p256(&digest, &low, &pk) && verify_p256(&digest, &high, &pk));
        assert!(!verify_p256(&[n ^ 0x80; 32], &low, &pk), "another digest");
    }
}

/// A root handover refuses a key that is not a point on the curve.
#[test]
fn only_a_point_on_the_curve_is_a_key() {
    let pk = SoftwareSigner::from_bytes(&[7u8; 32]).unwrap().public_key().unwrap();
    assert!(valid_public_key(&pk));
    assert!(!valid_public_key(&PublicKey { x: pk.x, y: [2u8; 32] }));
    assert!(!valid_public_key(&PublicKey { x: [0u8; 32], y: [0u8; 32] }));
}
