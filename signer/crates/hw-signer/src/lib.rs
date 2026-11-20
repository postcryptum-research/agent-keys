//! Hardware-backed P-256 (secp256r1) signer abstraction.
//!
//! Every platform we care about exposes a hardware-protected ECDSA key on the
//! same curve: TPM 2.0 (Linux/Windows), Apple Secure Enclave (macOS/iOS) and
//! WebAuthn passkeys all speak NIST P-256. None of them can do secp256k1, which
//! is exactly why the on-chain side is an ERC-4337 smart account that verifies
//! P-256 — not an EOA.
//!
//! The trait is deliberately tiny: a 32-byte digest goes in, `(r, s)` comes
//! out. Everything above it (UserOperation building, signature packing,
//! bundler I/O) is platform-neutral; everything below it is one backend per
//! platform, selected by cargo feature.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::VerifyingKey;
use p256::{FieldBytes, Sec1Point};

/// The shape of a Secure Enclave key file (plain Rust; used by `secure_enclave`).
pub mod enclave_blob;
#[cfg(feature = "software")]
pub mod software;
#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(all(feature = "secure-enclave", target_os = "macos"))]
pub mod secure_enclave;
#[cfg(all(feature = "windows-tpm", target_os = "windows"))]
pub mod windows_tpm;
/// Tropic Square TROPIC01 over the USB DevKit (docs/TROPIC01.md).
#[cfg(feature = "tropic01")]
pub mod tropic01;
/// YubiKey 5 PIV slot over PC/SC (docs/YUBIKEY.md).
#[cfg(feature = "yubikey-piv")]
pub mod yubikey_piv;

/// Uncompressed P-256 public key coordinates — what the smart account enrolls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Raw ECDSA signature over P-256, normalized to low-s.
///
/// RIP-7212 accepts either `s`, but the Solady verifier (and most account
/// validators) reject `s > n/2` to kill malleability, so backends normalize
/// before returning. `(r, n - s)` is an equally valid signature, so this is
/// safe to do off-chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("key unavailable: {0}")]
    Key(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Flip a high `s` to `n - s`. Hardware returns whichever `s` it computed;
/// the on-chain verifier wants the canonical low one.
pub fn normalize_low_s(sig: Signature) -> Signature {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&sig.r);
    raw[32..].copy_from_slice(&sig.s);
    match p256::ecdsa::Signature::from_slice(&raw) {
        Ok(parsed) => {
            let (r, s) = parsed.normalize_s().split_bytes();
            Signature { r: r.into(), s: s.into() }
        }
        Err(_) => sig,
    }
}

/// What a signer gets to see about an ERC-4337 operation: its hash, and
/// for signers that must show a human what they sign (a phone), the whole
/// operation as the serialized sign request of `owner-core` — opaque here,
/// so this crate stays free of the wire format.
pub struct UserOpContext<'a> {
    pub user_op_hash: [u8; 32],
    pub request: Option<&'a [u8]>,
}

/// A key that lives in hardware and never leaves it.
pub trait HardwareSigner {
    /// Public key coordinates. The private key is never exposed.
    fn public_key(&self) -> Result<PublicKey, SignerError>;

    /// Sign a 32-byte digest. The caller decides what the digest commits to —
    /// for ERC-4337 it is the `userOpHash`. The hardware only ever sees `h`.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError>;

    /// Sign an ERC-4337 operation. Chips sign its hash; a phone decodes the
    /// request, shows it, and signs only what it has shown
    /// (docs/MOBILE_OWNER_DESIGN.md §8.3). The default is the hash.
    fn sign_user_op(&self, ctx: &UserOpContext<'_>) -> Result<Signature, SignerError> {
        self.sign_digest(&ctx.user_op_hash)
    }

    /// Whether `sign_user_op` needs `UserOpContext::request`. A chip signs
    /// the hash and never looks at it; a signer with a human behind it does.
    fn needs_request(&self) -> bool {
        false
    }
}

/// Whether `(x, y)` is a point on P-256 (not the identity). A key that is
/// not cannot have signed anything and must never become an account's root.
pub fn valid_public_key(pk: &PublicKey) -> bool {
    let point = Sec1Point::from_affine_coordinates(&FieldBytes::from(pk.x), &FieldBytes::from(pk.y), false);
    VerifyingKey::from_sec1_point(&point).is_ok()
}

/// Off-chain P-256 verification, mirroring what the on-chain validator checks:
/// `(h, r, s)` against `(x, y)`. Used by tests and the CLI self-check.
pub fn verify_p256(digest: &[u8; 32], sig: &Signature, pk: &PublicKey) -> bool {
    let point = Sec1Point::from_affine_coordinates(
        &FieldBytes::from(pk.x),
        &FieldBytes::from(pk.y),
        false,
    );
    let Ok(vk) = VerifyingKey::from_sec1_point(&point) else {
        return false;
    };
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&sig.r);
    raw[32..].copy_from_slice(&sig.s);
    let Ok(sig) = p256::ecdsa::Signature::from_slice(&raw) else {
        return false;
    };
    vk.verify_prehash(digest, &sig).is_ok()
}

#[cfg(all(test, feature = "software"))]
mod tests {
    use super::*;

    /// n/2 for P-256; a low-s signature has s <= this (big-endian compare).
    const N_HALF: &str = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";

    #[test]
    fn software_roundtrip_rejects_tamper_and_is_low_s() {
        let signer = software::SoftwareSigner::random();
        let digest = [7u8; 32];

        let sig = signer.sign_digest(&digest).unwrap();
        let pk = signer.public_key().unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));

        let n_half = hex::decode(N_HALF).unwrap();
        assert!(sig.s.as_slice() <= n_half.as_slice(), "s must be normalized to low-s");
    }
}
