//! Windows backend: the TPM 2.0 through CNG's Platform Crypto Provider.
//!
//! Every Windows 11 machine has a TPM 2.0 and ships the "Microsoft Platform
//! Crypto Provider", a key-storage provider that keeps keys inside the TPM.
//! A key is created and persisted by name (per user), exported only as its
//! public half, and `NCryptSignHash` signs a host digest inside the TPM. The
//! ECDSA signature comes back as the raw `r ‖ s` pair, which becomes the
//! low-s signature the smart account expects.
//!
//! Written on Linux and type-checked for `x86_64-pc-windows-msvc`; it has not
//! yet run on Windows. See docs/WINDOWS.md for the build and test procedure.

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

/// A P-256 key persisted in the TPM under a CNG key name.
pub struct CngSigner {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

fn win(e: windows::core::Error) -> SignerError {
    SignerError::Backend(format!("CNG: {e}"))
}

fn open_provider() -> Result<NCRYPT_PROV_HANDLE, SignerError> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    // SAFETY: out-pointer to a valid handle slot; the provider name is a
    // static null-terminated wide string from the Windows crate.
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.map_err(win)?;
    Ok(provider)
}

impl CngSigner {
    /// Generate a new P-256 key inside the TPM and persist it under `name`
    /// for the current user.
    pub fn create(name: &str) -> Result<Self, SignerError> {
        let provider = open_provider()?;
        let name_w = HSTRING::from(name);
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: valid provider handle, out-pointer, and null-terminated
        // wide strings that outlive the calls.
        let created = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                NCRYPT_ECDSA_P256_ALGORITHM,
                PCWSTR(name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .and_then(|()| NCryptFinalizeKey(key, NCRYPT_FLAGS(0)))
        };
        if let Err(e) = created {
            // SAFETY: handles obtained above; freeing on the error path.
            unsafe {
                if !key.is_invalid() {
                    let _ = NCryptFreeObject(NCRYPT_HANDLE(key.0));
                }
                let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
            }
            return Err(win(e));
        }
        Ok(Self { provider, key })
    }

    /// Open the key persisted under `name`.
    pub fn open(name: &str) -> Result<Self, SignerError> {
        let provider = open_provider()?;
        let name_w = HSTRING::from(name);
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: as in `create`.
        let opened = unsafe {
            NCryptOpenKey(provider, &mut key, PCWSTR(name_w.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))
        };
        if let Err(e) = opened {
            // SAFETY: provider handle obtained above.
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
            }
            return Err(win(e));
        }
        Ok(Self { provider, key })
    }

    /// Remove the key from the TPM's key store.
    pub fn delete(self) -> Result<(), SignerError> {
        // SAFETY: valid key handle; NCryptDeleteKey frees it on success, so
        // Drop must not free it again.
        let result = unsafe { NCryptDeleteKey(self.key, 0) }.map_err(win);
        let provider = self.provider;
        std::mem::forget(self);
        // SAFETY: provider handle still owned here.
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
        }
        result
    }
}

impl HardwareSigner for CngSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        // BCRYPT_ECCKEY_BLOB { dwMagic: u32, cbKey: u32 } ‖ X[cbKey] ‖ Y[cbKey]
        let mut needed = 0u32;
        // SAFETY: size query with no output buffer.
        unsafe { NCryptExportKey(self.key, None, BCRYPT_ECCPUBLIC_BLOB, None, None, &mut needed, NCRYPT_FLAGS(0)) }
            .map_err(win)?;
        let mut blob = vec![0u8; needed as usize];
        // SAFETY: buffer sized by the query above.
        unsafe {
            NCryptExportKey(self.key, None, BCRYPT_ECCPUBLIC_BLOB, None, Some(&mut blob), &mut needed, NCRYPT_FLAGS(0))
        }
        .map_err(win)?;
        let blob = &blob[..needed as usize];
        if blob.len() < 8 {
            return Err(SignerError::Key("public key blob too short".into()));
        }
        let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
        let len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || len != 32 || blob.len() < 8 + 2 * len {
            return Err(SignerError::Key(format!("not a P-256 public key blob (magic {magic:#x}, cbKey {len})")));
        }
        let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
        pk.x.copy_from_slice(&blob[8..40]);
        pk.y.copy_from_slice(&blob[40..72]);
        Ok(pk)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let mut needed = 0u32;
        // SAFETY: size query; the digest slice is valid for the call.
        unsafe { NCryptSignHash(self.key, None, digest, None, &mut needed, NCRYPT_FLAGS(0)) }.map_err(win)?;
        let mut sig = vec![0u8; needed as usize];
        // SAFETY: buffer sized by the query above.
        unsafe { NCryptSignHash(self.key, None, digest, Some(&mut sig), &mut needed, NCRYPT_FLAGS(0)) }
            .map_err(win)?;
        if needed != 64 {
            return Err(SignerError::Sign(format!("expected a 64-byte r‖s signature, got {needed}")));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..64]);
        Ok(normalize_low_s(Signature { r, s }))
    }
}

impl Drop for CngSigner {
    fn drop(&mut self) {
        // SAFETY: handles owned by this value and not freed elsewhere.
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    /// Needs a Windows machine with a TPM 2.0.
    /// Run: `cargo test -p hw-signer --features windows-tpm -- --ignored`
    #[test]
    #[ignore = "requires Windows with a TPM 2.0"]
    fn cng_key_signs_and_verifies() {
        let name = format!("tpm_sign-test-{}", std::process::id());
        let signer = CngSigner::create(&name).unwrap();
        let pk = signer.public_key().unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));

        drop(signer);
        let reopened = CngSigner::open(&name).unwrap();
        assert_eq!(reopened.public_key().unwrap(), pk);
        reopened.delete().unwrap();
    }
}
