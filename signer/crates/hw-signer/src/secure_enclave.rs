//! Apple Secure Enclave backend (macOS on Apple Silicon or a T2 Mac).
//!
//! The enclave holds a P-256 key addressed by a keychain label. Signing runs
//! inside the enclave over a host-supplied digest and returns an X9.62 DER
//! signature, which becomes the raw low-s `(r, s)` the smart account expects.
//! The private key never leaves the enclave: `external_representation` only
//! exists for the public half.
//!
//! Written against `security-framework` 3.x and type-checked for
//! `aarch64-apple-darwin` from Linux; it has not yet run on Apple hardware.
//! See docs/SECURE_ENCLAVE.md for the build and test procedure.

use p256::ecdsa::Signature as DerSignature;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

pub struct SecureEnclaveSigner {
    key: SecKey,
}

fn se(e: impl std::fmt::Display) -> SignerError {
    SignerError::Backend(e.to_string())
}

impl SecureEnclaveSigner {
    /// Generate a new P-256 key inside the enclave, persisted in the keychain
    /// under `label`. Usable only while the device is unlocked, and only on
    /// this device.
    pub fn create(label: &str) -> Result<Self, SignerError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(se)?;
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label)
            .set_access_control(access);
        let key = SecKey::new(&opts).map_err(se)?;
        Ok(Self { key })
    }

    /// Open the enclave key persisted under `label`.
    pub fn open(label: &str) -> Result<Self, SignerError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .label(label)
            .load_refs(true)
            .limit(1)
            .search()
            .map_err(se)?;
        for result in results {
            if let SearchResult::Ref(Reference::Key(key)) = result {
                return Ok(Self { key });
            }
        }
        Err(SignerError::Key(format!("no Secure Enclave key labelled {label}")))
    }

    /// Remove the key from the keychain (and thus from use).
    pub fn delete(self) -> Result<(), SignerError> {
        self.key.delete().map_err(se)
    }
}

impl HardwareSigner for SecureEnclaveSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        let public = self
            .key
            .public_key()
            .ok_or_else(|| SignerError::Key("enclave key has no public half".into()))?;
        let data = public
            .external_representation()
            .ok_or_else(|| SignerError::Key("public key is not exportable".into()))?;
        let bytes = data.bytes(); // X9.63 uncompressed: 0x04 ‖ x ‖ y
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(SignerError::Key(format!("unexpected public key encoding ({} bytes)", bytes.len())));
        }
        let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
        pk.x.copy_from_slice(&bytes[1..33]);
        pk.y.copy_from_slice(&bytes[33..65]);
        Ok(pk)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        // "DigestX962SHA256": the input is already the SHA-256-sized digest.
        let der = self
            .key
            .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest)
            .map_err(se)?;
        let sig = DerSignature::from_der(&der).map_err(|e| SignerError::Sign(e.to_string()))?;
        let (r, s) = sig.split_bytes();
        Ok(normalize_low_s(Signature { r: r.into(), s: s.into() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    /// Needs an Apple Secure Enclave and an ad-hoc signed test binary.
    /// Run: `cargo test -p hw-signer --features secure-enclave -- --ignored`
    #[test]
    #[ignore = "requires an Apple Secure Enclave"]
    fn enclave_key_signs_and_verifies() {
        let label = format!("tpm_sign-test-{}", std::process::id());
        let signer = SecureEnclaveSigner::create(&label).unwrap();
        let pk = signer.public_key().unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));

        let reopened = SecureEnclaveSigner::open(&label).unwrap();
        assert_eq!(reopened.public_key().unwrap(), pk);
        reopened.delete().unwrap();
    }
}
