//! Proof of possession for a root handover to a key that is not a phone's
//! (issue #51).
//!
//! `owner set-root` gives the account's root to a new key in one on-chain
//! step, and the new key has no accept step. A key nobody can sign with — the
//! private key lost, never made, or on a device that no longer works — takes
//! the account with it, and a fingerprint only shows which *public* key was
//! pasted. So before anything is signed or sent, the new key signs a fresh
//! challenge and the CLI verifies it against the public key the root is going
//! to. The phone path has the same step as a session
//! (`phone::prove_possession`).
//!
//! Two lines of text, made to be copied between machines:
//!
//! ```text
//! challenge  tpmsign-handover-challenge:1:<chain id>:<account>:<x>:<y>:<nonce>:<expires>
//! proof      tpmsign-handover-proof:1:<key nonce>:<r>:<s>
//! ```
//!
//! The key signs `sha256(DOMAIN ‖ challenge line ‖ key nonce)`.
//!
//! - **Bound to the chain, the account and the key:** the challenge line names
//!   all three and is hashed as it stands.
//! - **Fresh:** the line carries the verifier's nonce and an expiry (unix
//!   seconds). The verifier keeps its challenge in memory and checks the proof
//!   against that line only, so a proof for another account, chain, key or
//!   run of the command does not verify, and neither does a late one.
//! - **Neither side chooses the digest:** the key adds a nonce of its own
//!   under a domain separator of this proof alone. The line cannot be made to
//!   pass for an operation's hash, which the same key signs as 32 raw bytes.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use hw_signer::{verify_p256, HardwareSigner, PublicKey, Signature};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// Not the health check's separator: the two messages differ, and a signature
/// for one must never count as the other.
const DOMAIN: &[u8] = b"TPM_sign/v1/handover-possession";
const CHALLENGE: &str = "tpmsign-handover-challenge";
const PROOF: &str = "tpmsign-handover-proof";
const VERSION: &str = "1";

/// Unix seconds, now.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn parse32(field: &str, what: &str) -> Result<[u8; 32]> {
    let raw = field.strip_prefix("0x").with_context(|| format!("{what}: 0x and 64 hex digits expected"))?;
    let bytes = hex::decode(raw).with_context(|| format!("{what}: not hex"))?;
    bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("{what}: 32 bytes expected, got {}", bytes.len()))
}

/// A pasted line may pick up spaces or line breaks on the way.
fn unspaced(line: &str) -> String {
    line.chars().filter(|c| !c.is_whitespace()).collect()
}

fn random32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// What the new key is asked to answer, and the verifier's record of it.
pub struct Challenge {
    line: String,
    pub chain_id: u64,
    pub account: Address,
    pub key: PublicKey,
    pub expires: u64,
}

fn render(chain_id: u64, account: Address, key: &PublicKey, nonce: &[u8; 32], expires: u64) -> String {
    format!("{CHALLENGE}:{VERSION}:{chain_id}:{account:#x}:{}:{}:{}:{expires}", hex32(&key.x), hex32(&key.y), hex32(nonce))
}

impl Challenge {
    /// A fresh challenge for `key` to become the root of `account` on `chain_id`.
    pub fn new(chain_id: u64, account: Address, key: &PublicKey, lifetime: Duration) -> Self {
        let expires = now().saturating_add(lifetime.as_secs());
        Self { line: render(chain_id, account, key, &random32(), expires), chain_id, account, key: *key, expires }
    }

    /// The challenge as the key's machine received it. Only the canonical
    /// form is accepted, so what is shown to the person at that machine is
    /// what the key signs.
    pub fn parse(pasted: &str) -> Result<Self> {
        let line = unspaced(pasted);
        let fields: Vec<&str> = line.split(':').collect();
        let [tag, version, chain_id, account, x, y, nonce, expires] = fields[..] else {
            bail!("not a handover challenge: 8 fields separated by ':' expected, as `owner set-root` prints it");
        };
        if tag != CHALLENGE {
            bail!("not a handover challenge: it does not begin with {CHALLENGE}");
        }
        if version != VERSION {
            bail!("handover challenge version {version}: this build knows version {VERSION}");
        }
        let chain_id: u64 = chain_id.parse().context("handover challenge: chain id")?;
        let account = Address::from_str(account).context("handover challenge: account")?;
        let key = PublicKey { x: parse32(x, "handover challenge: x")?, y: parse32(y, "handover challenge: y")? };
        let nonce = parse32(nonce, "handover challenge: nonce")?;
        let expires: u64 = expires.parse().context("handover challenge: expiry")?;
        if render(chain_id, account, &key, &nonce, expires) != line {
            bail!("handover challenge: not in the form `owner set-root` prints (lower-case hex, plain decimal numbers)");
        }
        if !hw_signer::valid_public_key(&key) {
            bail!("handover challenge: its key is not a point on P-256");
        }
        Ok(Self { line, chain_id, account, key, expires })
    }

    /// The one line to carry to the key's machine.
    pub fn line(&self) -> &str {
        &self.line
    }

    fn digest(&self, key_nonce: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.line.as_bytes());
        h.update(key_nonce);
        h.finalize().into()
    }

    /// The key's half: sign, and return the proof line. A key other than the
    /// one the challenge names is refused here, before it signs anything.
    pub fn prove(&self, signer: &dyn HardwareSigner) -> Result<String> {
        let held = signer.public_key()?;
        if held != self.key {
            bail!(
                "this key is {}, and the challenge is for {}: not the key the root is going to; nothing signed",
                owner_core::fingerprint::fingerprint(&held),
                owner_core::fingerprint::fingerprint(&self.key)
            );
        }
        let key_nonce = random32();
        let sig = signer.sign_digest(&self.digest(&key_nonce))?;
        Ok(format!("{PROOF}:{VERSION}:{}:{}:{}", hex32(&key_nonce), hex32(&sig.r), hex32(&sig.s)))
    }

    /// The verifier's half, at unix time `at`: the proof must be by the key
    /// this challenge names, over this very challenge, and in time.
    pub fn verify(&self, pasted: &str, at: u64) -> Result<()> {
        let line = unspaced(pasted);
        let fields: Vec<&str> = line.split(':').collect();
        let [tag, version, key_nonce, r, s] = fields[..] else {
            bail!("not a proof of possession: the one line `key prove` prints is expected");
        };
        if tag != PROOF {
            bail!("not a proof of possession: it does not begin with {PROOF}");
        }
        if version != VERSION {
            bail!("proof of possession version {version}: this build knows version {VERSION}");
        }
        let key_nonce = parse32(key_nonce, "proof of possession: key nonce")?;
        let sig = Signature { r: parse32(r, "proof of possession: r")?, s: parse32(s, "proof of possession: s")? };
        if !verify_p256(&self.digest(&key_nonce), &sig, &self.key) {
            bail!(
                "the proof does not verify for key {} and this challenge: it was made by another key, or for another \
                 challenge (another account, chain, or run of this command)",
                owner_core::fingerprint::fingerprint(&self.key)
            );
        }
        if at > self.expires {
            bail!("the proof arrived {} s after the challenge expired: run the command again", at - self.expires);
        }
        Ok(())
    }
}
