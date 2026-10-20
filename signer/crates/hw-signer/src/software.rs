//! In-memory P-256 key. **Development and CI only.**
//!
//! This is the one backend that exists on every platform, so the pipeline
//! above [`HardwareSigner`] can be exercised without hardware. It must never
//! hold the key of a funded account: it is the exact thing the project exists
//! to avoid.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;

use crate::{HardwareSigner, PublicKey, Signature, SignerError};

pub struct SoftwareSigner {
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn random() -> Self {
        Self { key: SigningKey::random(&mut OsRng) }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, SignerError> {
        SigningKey::from_slice(secret)
            .map(|key| Self { key })
            .map_err(|e| SignerError::Key(e.to_string()))
    }
}

impl HardwareSigner for SoftwareSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            return Err(SignerError::Key("point at infinity".into()));
        };
        let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
        pk.x.copy_from_slice(x);
        pk.y.copy_from_slice(y);
        Ok(pk)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let sig: p256::ecdsa::Signature = self
            .key
            .sign_prehash(digest)
            .map_err(|e| SignerError::Sign(e.to_string()))?;
        // `normalize_s` returns Some only when it had to flip a high s.
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = sig.split_bytes();
        Ok(Signature { r: r.into(), s: s.into() })
    }
}
