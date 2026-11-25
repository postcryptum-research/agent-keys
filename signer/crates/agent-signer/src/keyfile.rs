//! An encrypted P-256 key file for an owner or recovery key on removable
//! media — the one exception to "no private key at rest" in
//! docs/KEY_POLICY.md (rule 5). Never for the agent.
//!
//! Format (JSON): the public key in clear (so `key show` and the account
//! setup need no passphrase), the scalar sealed with AES-256-GCM under a key
//! derived by scrypt from a passphrase typed at use. The public key is the
//! cipher's associated data, so a file whose public half was swapped does
//! not decrypt. The KDF cost in the file is checked against a floor, so a
//! tampered file cannot downgrade it.
//!
//! The weakness is the moment of use: the host that decrypts the file holds
//! the key itself while it signs. Use it on a machine that is not the
//! agent's host, plug the medium in only for the operation.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use hw_signer::{HardwareSigner, PublicKey, Signature, SignerError};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VERSION: u32 = 1;
const AAD_PREFIX: &[u8] = b"tpm_sign keyfile v1";
/// scrypt N = 2^18, r = 8 (256 MiB): the floor from KEY_POLICY.md rule 5.
const LOG_N: u8 = 18;
const MIN_LOG_N: u8 = 18;
/// The most a key file may ask of scrypt. Memory is `128 * r * 2^log_n`
/// bytes: 2^22 with r = 32 is 16 GiB, far above what this CLI writes
/// (256 MiB) and still a refusal with a reason; a tampered or corrupted
/// file asking for more would abort the process on the allocation (#178).
const MAX_LOG_N: u8 = 22;
const MAX_R: u32 = 32;
const MAX_P: u32 = 8;
const R: u32 = 8;
const P: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    version: u32,
    curve: String,
    public_key: Xy,
    kdf: Kdf,
    cipher: Cipher,
}

#[derive(Serialize, Deserialize)]
struct Xy {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kdf {
    name: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cipher {
    name: String,
    nonce: String,
    ciphertext: String,
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).context("bad hex in key file")
}

fn aad(pk: &PublicKey) -> Vec<u8> {
    [AAD_PREFIX, &pk.x[..], &pk.y[..]].concat()
}

fn derive(passphrase: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = scrypt::Params::new(log_n, r, p, 32).map_err(|e| anyhow::anyhow!("scrypt params: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase, salt, &params, key.as_mut()).map_err(|e| anyhow::anyhow!("scrypt: {e}"))?;
    Ok(key)
}

fn public_of(key: &SigningKey) -> PublicKey {
    let point = key.verifying_key().to_sec1_point(false);
    let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
    pk.x.copy_from_slice(point.x().expect("not the identity"));
    pk.y.copy_from_slice(point.y().expect("not the identity"));
    pk
}

/// Keep a secret out of swap while it lives (best effort).
fn lock(buf: &[u8]) {
    #[cfg(unix)]
    // SAFETY: mlock only pins the pages that hold `buf`; failure is harmless.
    unsafe {
        libc::mlock(buf.as_ptr().cast(), buf.len());
    }
    #[cfg(not(unix))]
    let _ = buf;
}

/// Generate a key and write it, encrypted under `passphrase`, to `path`.
/// Refuses to overwrite an existing file.
pub fn create(path: &Path, passphrase: &[u8]) -> Result<PublicKey> {
    if passphrase.is_empty() {
        bail!("empty passphrase: the file would decrypt for anyone");
    }
    let key = SigningKey::try_generate().context("the operating system's random source")?;
    let pk = public_of(&key);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kek = derive(passphrase, &salt, LOG_N, R, P)?;
    let scalar = Zeroizing::new(key.to_bytes());
    let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: &scalar[..], aad: &aad(&pk) })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let file = KeyFile {
        version: VERSION,
        curve: "P-256".into(),
        public_key: Xy { x: hex32(&pk.x), y: hex32(&pk.y) },
        kdf: Kdf { name: "scrypt".into(), log_n: LOG_N, r: R, p: P, salt: format!("0x{}", hex::encode(salt)) },
        cipher: Cipher {
            name: "aes-256-gcm".into(),
            nonce: format!("0x{}", hex::encode(nonce)),
            ciphertext: format!("0x{}", hex::encode(ciphertext)),
        },
    };
    let json = serde_json::to_vec_pretty(&file)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut out = opts.open(path).with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    out.write_all(&json)?;
    out.sync_all()?;
    Ok(pk)
}

fn read(path: &Path) -> Result<(KeyFile, PublicKey)> {
    let file: KeyFile = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
        .context("not a tpm_sign key file")?;
    if file.version != VERSION || file.curve != "P-256" {
        bail!("unsupported key file (version {}, curve {})", file.version, file.curve);
    }
    let x: [u8; 32] = unhex(&file.public_key.x)?.try_into().map_err(|_| anyhow::anyhow!("bad x"))?;
    let y: [u8; 32] = unhex(&file.public_key.y)?.try_into().map_err(|_| anyhow::anyhow!("bad y"))?;
    Ok((file, PublicKey { x, y }))
}

/// The public key, without the passphrase.
pub fn public_key(path: &Path) -> Result<PublicKey> {
    Ok(read(path)?.1)
}

/// Decrypt the key in `path` with `passphrase`.
pub fn open(path: &Path, passphrase: &[u8]) -> Result<KeyFileSigner> {
    let (file, pk) = read(path)?;
    if file.kdf.name != "scrypt" || file.kdf.log_n < MIN_LOG_N || file.kdf.r < R || file.kdf.p < 1 {
        bail!("key file KDF below the required strength (scrypt N >= 2^{MIN_LOG_N}, r >= {R})");
    }
    if file.kdf.log_n > MAX_LOG_N || file.kdf.r > MAX_R || file.kdf.p > MAX_P {
        bail!(
            "key file KDF asks for more than this CLI computes (scrypt N <= 2^{MAX_LOG_N}, r <= {MAX_R}, p <= {MAX_P}): \
             N = 2^{}, r = {}, p = {}. The file is damaged or was not written by this CLI",
            file.kdf.log_n,
            file.kdf.r,
            file.kdf.p
        );
    }
    if file.cipher.name != "aes-256-gcm" {
        bail!("unsupported cipher {}", file.cipher.name);
    }
    let kek = derive(passphrase, &unhex(&file.kdf.salt)?, file.kdf.log_n, file.kdf.r, file.kdf.p)?;
    let nonce: [u8; 12] = unhex(&file.cipher.nonce)?.try_into().map_err(|_| anyhow::anyhow!("bad nonce length"))?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).expect("32-byte key");
    let scalar = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(nonce), Payload { msg: &unhex(&file.cipher.ciphertext)?, aad: &aad(&pk) })
            .map_err(|_| anyhow::anyhow!("wrong passphrase, or the key file was altered"))?,
    );
    lock(&scalar);
    let key = SigningKey::from_slice(&scalar).context("key file holds an invalid scalar")?;
    if public_of(&key) != pk {
        bail!("key file's public key does not match its secret");
    }
    Ok(KeyFileSigner { key, public: pk })
}

/// Read a passphrase from the terminal (twice when creating).
pub fn prompt(confirm: bool) -> Result<Zeroizing<String>> {
    let first = prompt_secret("key file passphrase: ")?;
    if confirm {
        let again = prompt_secret("repeat passphrase: ")?;
        if *first != *again {
            bail!("passphrases differ");
        }
    }
    Ok(first)
}

/// Read a secret from the terminal without echo (a passphrase, a PIN).
pub fn prompt_secret(label: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}

/// A decrypted key file. The scalar lives in the `SigningKey`, which wipes
/// itself on drop.
pub struct KeyFileSigner {
    key: SigningKey,
    public: PublicKey,
}

impl HardwareSigner for KeyFileSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        Ok(self.public)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let sig: p256::ecdsa::Signature =
            self.key.sign_prehash(digest).map_err(|e| SignerError::Sign(e.to_string()))?;
        let (r, s) = sig.normalize_s().split_bytes();
        Ok(Signature { r: r.into(), s: s.into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_wrong_passphrase_and_tamper() {
        let dir = std::env::temp_dir().join(format!("tpm_sign-keyfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owner.json");
        let _ = std::fs::remove_file(&path);

        let pk = create(&path, b"correct horse battery staple").unwrap();
        assert_eq!(public_key(&path).unwrap(), pk);
        assert!(create(&path, b"correct horse battery staple").is_err(), "never overwrites");

        let signer = open(&path, b"correct horse battery staple").unwrap();
        let digest = [9u8; 32];
        assert!(hw_signer::verify_p256(&digest, &signer.sign_digest(&digest).unwrap(), &pk));

        assert!(open(&path, b"wrong passphrase!!").is_err());

        // swapping the public half breaks decryption (it is the AAD)
        let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["publicKey"]["x"] = serde_json::json!(hex32(&[1u8; 32]));
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(open(&path, b"correct horse battery staple").is_err());

        // a downgraded KDF is refused
        let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["publicKey"]["x"] = serde_json::json!(hex32(&pk.x));
        file["kdf"]["logN"] = serde_json::json!(10);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(open(&path, b"correct horse battery staple").is_err());

        // a KDF that asks for more than this CLI computes is refused before any memory is asked for:
        // logN 30 would be about 1 TiB, and the failed allocation would abort the process
        for (field, value) in [("logN", 30), ("logN", 23), ("r", 33), ("p", 9)] {
            let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            file["kdf"]["logN"] = serde_json::json!(18);
            file["kdf"][field] = serde_json::json!(value);
            std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            let refused = open(&path, b"correct horse battery staple").err().expect("refused").to_string();
            assert!(refused.contains("asks for more than this CLI computes"), "{field} {value}: {refused}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
