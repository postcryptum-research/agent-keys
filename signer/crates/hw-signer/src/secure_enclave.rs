//! Apple Secure Enclave backend (macOS on Apple Silicon or a T2 Mac).
//!
//! The key is a CryptoKit `SecureEnclave.P256.Signing.PrivateKey`, reached
//! through a small Swift shim (`swift/SecureEnclaveShim.swift`, compiled by
//! build.rs). The enclave generates it and signs inside; what the host keeps
//! is CryptoKit's `dataRepresentation` — an opaque blob that only this
//! device's Secure Enclave can unwrap — in a file per label under
//! `~/Library/Application Support/tpm_sign/enclave/` (or `$TPM_SIGN_ENCLAVE_DIR`).
//!
//! Why not Security.framework keychain items: a Secure Enclave key can only
//! persist in the data-protection keychain, which requires keychain-access
//! entitlements that an ad-hoc signed command-line tool cannot have. The
//! CryptoKit blob needs no entitlements and no Apple developer account.
//!
//! Deleting the blob file destroys the key for good: nothing else refers to
//! it. Copying the file to another Mac is useless — its enclave cannot
//! unwrap it.
//!
//! See docs/SECURE_ENCLAVE.md for the build and test procedure.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::enclave_blob::{self, MAX_BLOB};
use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

// Status codes of the Swift shim.
const OK: i32 = 0;
const NOT_AVAILABLE: i32 = 1;
const BAD_KEY: i32 = 2;

const MSG_CAP: usize = 512;

extern "C" {
    fn tpmse_create(
        blob: *mut u8,
        blob_cap: usize,
        blob_len: *mut usize,
        public: *mut u8,
        msg: *mut u8,
        msg_cap: usize,
    ) -> i32;
    fn tpmse_public(blob: *const u8, blob_len: usize, public: *mut u8, msg: *mut u8, msg_cap: usize) -> i32;
    fn tpmse_sign(
        blob: *const u8,
        blob_len: usize,
        digest: *const u8,
        rs: *mut u8,
        msg: *mut u8,
        msg_cap: usize,
    ) -> i32;
}

/// Turn a shim status and its message into a `SignerError`.
fn check(code: i32, msg: &[u8; MSG_CAP]) -> Result<(), SignerError> {
    if code == OK {
        return Ok(());
    }
    let end = msg.iter().position(|&b| b == 0).unwrap_or(MSG_CAP);
    let text = String::from_utf8_lossy(&msg[..end]).into_owned();
    Err(match code {
        NOT_AVAILABLE => SignerError::Backend(text),
        BAD_KEY => SignerError::Key(text),
        _ => SignerError::Sign(text),
    })
}

pub struct SecureEnclaveSigner {
    path: PathBuf,
    blob: Vec<u8>,
    public: PublicKey,
}

fn key_dir() -> Result<PathBuf, SignerError> {
    if let Some(dir) = std::env::var_os("TPM_SIGN_ENCLAVE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| SignerError::Backend("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join("Library/Application Support/tpm_sign/enclave"))
}

fn key_path(label: &str) -> Result<PathBuf, SignerError> {
    let valid = !label.is_empty()
        && label.len() <= 64
        && label.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !label.starts_with('.');
    if !valid {
        return Err(SignerError::Key(format!("label {label:?}: use 1-64 of [A-Za-z0-9._-], not starting with '.'")));
    }
    Ok(key_dir()?.join(format!("{label}.se")))
}

fn io(path: &std::path::Path, e: std::io::Error) -> SignerError {
    SignerError::Backend(format!("{}: {e}", path.display()))
}

impl SecureEnclaveSigner {
    /// Generate a new P-256 key inside the enclave under `label`. Refuses to
    /// replace an existing key with that label.
    pub fn create(label: &str) -> Result<Self, SignerError> {
        let path = key_path(label)?;
        if path.exists() {
            return Err(SignerError::Key(format!("a key labelled {label} already exists ({})", path.display())));
        }
        let mut blob = vec![0u8; MAX_BLOB];
        let mut len = 0usize;
        let mut public = [0u8; 64];
        let mut msg = [0u8; MSG_CAP];
        // SAFETY: every pointer is valid for the capacity passed with it.
        let code = unsafe {
            tpmse_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr(), msg.as_mut_ptr(), MSG_CAP)
        };
        check(code, &msg)?;
        blob.truncate(len);
        // A system that writes another form of key file is noticed now, and
        // not when the key, by then enrolled somewhere, is needed (#78).
        enclave_blob::check(&blob).map_err(|why| {
            SignerError::Backend(format!("the enclave returned a key in a form this build does not know ({why}); nothing was stored: update agent-signer"))
        })?;

        let dir = path.parent().expect("key path has a directory");
        fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io(&path, e))?;
        file.write_all(&blob).map_err(|e| io(&path, e))?;

        Ok(Self { path, blob, public: split(&public) })
    }

    /// Open the enclave key stored under `label`.
    pub fn open(label: &str) -> Result<Self, SignerError> {
        let path = key_path(label)?;
        let blob = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => SignerError::Key(format!("no Secure Enclave key labelled {label} ({})", path.display())),
            _ => io(&path, e),
        })?;
        // A damaged file never reaches CryptoKit: damage in the stored public
        // key ends the process there with a fatal error and no message (#78).
        enclave_blob::check(&blob).map_err(|why| {
            SignerError::Key(format!(
                "{}: not a Secure Enclave key file ({why}): it is damaged or was altered. See docs/SECURE_ENCLAVE.md, troubleshooting",
                path.display()
            ))
        })?;
        let mut public = [0u8; 64];
        let mut msg = [0u8; MSG_CAP];
        // SAFETY: `blob` is valid for its length; the outputs for theirs.
        let code = unsafe { tpmse_public(blob.as_ptr(), blob.len(), public.as_mut_ptr(), msg.as_mut_ptr(), MSG_CAP) };
        check(code, &msg)?;
        Ok(Self { path, blob, public: split(&public) })
    }

    /// Destroy the key: its blob is the only handle to it.
    pub fn delete(self) -> Result<(), SignerError> {
        fs::remove_file(&self.path).map_err(|e| io(&self.path, e))
    }
}

fn split(xy: &[u8; 64]) -> PublicKey {
    let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
    pk.x.copy_from_slice(&xy[..32]);
    pk.y.copy_from_slice(&xy[32..]);
    pk
}

impl HardwareSigner for SecureEnclaveSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        Ok(self.public)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let mut rs = [0u8; 64];
        let mut msg = [0u8; MSG_CAP];
        // SAFETY: `blob` and `digest` are valid for their lengths, `rs` for 64 bytes.
        let code = unsafe {
            tpmse_sign(self.blob.as_ptr(), self.blob.len(), digest.as_ptr(), rs.as_mut_ptr(), msg.as_mut_ptr(), MSG_CAP)
        };
        check(code, &msg)?;
        let mut sig = Signature { r: [0; 32], s: [0; 32] };
        sig.r.copy_from_slice(&rs[..32]);
        sig.s.copy_from_slice(&rs[32..]);
        Ok(normalize_low_s(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    /// Run: `cargo test -p hw-signer --features secure-enclave -- --ignored`
    #[test]
    #[ignore = "requires an Apple Secure Enclave"]
    fn enclave_key_signs_and_verifies() {
        let label = format!("tpm_sign-test-{}", std::process::id());
        let signer = SecureEnclaveSigner::create(&label).unwrap();
        let pk = signer.public_key().unwrap();

        // a digest is signed as is: the signature verifies over these bytes
        let digest = [0x42u8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));

        // the stored blob reopens the same enclave key, which still signs
        let reopened = SecureEnclaveSigner::open(&label).unwrap();
        assert_eq!(reopened.public_key().unwrap(), pk);
        assert!(verify_p256(&digest, &reopened.sign_digest(&digest).unwrap(), &pk));

        // a second key under the same label is refused
        assert!(matches!(SecureEnclaveSigner::create(&label), Err(SignerError::Key(_))));

        reopened.delete().unwrap();
        assert!(matches!(SecureEnclaveSigner::open(&label), Err(SignerError::Key(_))));
    }
}
