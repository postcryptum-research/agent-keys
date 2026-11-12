//! The `uniffi` surface for the phone apps (docs/MOBILE_OWNER_DESIGN.md §7.2):
//! the QR, the review, the response. Thin: every rule lives in the other
//! modules; this file converts types and nothing else. Built with
//! `--features ffi`; the Kotlin and Swift bindings are generated from the
//! compiled library (`mobile/android/build-core.sh`).

use std::sync::Arc;

use alloy_primitives::Address;
use hw_signer::{normalize_low_s, verify_p256, PublicKey, Signature};

use crate::request::{AppInfo, QrPayload, SignResponse};
use crate::review::{self, EnrolledAccount, Facts, Review, Verdict};

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    Failed(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Failed(m) => f.write_str(m),
        }
    }
}

fn failed(e: impl std::fmt::Display) -> CoreError {
    CoreError::Failed(e.to_string())
}

#[derive(uniffi::Record)]
pub struct FfiQr {
    pub url: String,
    pub commitment: String,
}

/// §5.4, the part the review needs. Addresses as 0x-hex; the cap in wei as
/// a decimal string (Kotlin has no u128).
#[derive(uniffi::Record)]
pub struct FfiEnrolledAccount {
    pub chain_id: u64,
    pub entry_point: String,
    pub account: String,
    pub validator: Option<String>,
    pub gas_cap_wei: String,
    pub expert_mode: bool,
}

#[derive(uniffi::Record)]
pub struct FfiRow {
    pub label: String,
    pub value: String,
    pub emphasis: bool,
}

#[derive(uniffi::Record)]
pub struct FfiSection {
    pub title: String,
    pub rows: Vec<FfiRow>,
}

#[derive(uniffi::Enum)]
pub enum FfiVerdict {
    Sign,
    SignWithWarnings { warnings: Vec<String> },
    Refuse { reason: String },
}

#[derive(uniffi::Record)]
pub struct FfiApp {
    pub platform: String,
    pub version: String,
}

/// A parsed request: the screen, the verdict and the digest, from one parse.
#[derive(uniffi::Object)]
pub struct ReviewHandle {
    review: Review,
    request_bytes: Vec<u8>,
}

#[uniffi::export]
impl ReviewHandle {
    pub fn verdict(&self) -> FfiVerdict {
        match &self.review.verdict {
            Verdict::Sign => FfiVerdict::Sign,
            Verdict::SignWithWarnings(w) => FfiVerdict::SignWithWarnings { warnings: w.clone() },
            Verdict::Refuse(r) => FfiVerdict::Refuse { reason: r.clone() },
        }
    }

    pub fn sections(&self) -> Vec<FfiSection> {
        self.review
            .sections
            .iter()
            .map(|s| FfiSection {
                title: s.title.clone(),
                rows: s.rows.iter().map(|r| FfiRow { label: r.label.clone(), value: r.value.clone(), emphasis: r.emphasis }).collect(),
            })
            .collect()
    }

    /// The screen as one text.
    pub fn text(&self) -> String {
        self.review.text()
    }

    pub fn needs_second_confirmation(&self) -> bool {
        self.review.needs_second_confirmation()
    }

    /// The bold rows, for the second confirmation (§6.6).
    pub fn effects(&self) -> Vec<String> {
        self.review
            .sections
            .iter()
            .flat_map(|s| s.rows.iter().filter(|r| r.emphasis).map(|r| format!("{}: {}", r.label, r.value)))
            .collect()
    }

    pub fn account(&self) -> String {
        self.review.account.to_checksum(None)
    }

    pub fn chain_id(&self) -> u64 {
        self.review.chain_id
    }

    /// The `userOpHash` this review recomputed — the only thing the key signs.
    pub fn digest_to_sign(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self.review.digest_to_sign().map_err(failed)?.to_vec())
    }

    /// The signed response (§4.2) from the key's DER signature over
    /// `digest_to_sign()` and the 64-byte public key `x ‖ y`: converts to
    /// `r ‖ s`, normalizes low-s, verifies, and refuses anything else.
    pub fn finish(&self, der_signature: Vec<u8>, public_key: Vec<u8>, app: FfiApp) -> Result<Vec<u8>, CoreError> {
        let digest = self.review.digest_to_sign().map_err(failed)?;
        let pk = parse_key(&public_key)?;
        let (r, s) = der_to_rs(&der_signature).ok_or_else(|| CoreError::Failed("the signature is not DER ECDSA".into()))?;
        let sig = normalize_low_s(Signature { r, s });
        if !verify_p256(&digest.0, &sig, &pk) {
            return Err(CoreError::Failed("the signature does not verify against the key over the reviewed digest".into()));
        }
        Ok(SignResponse::signed(&self.review.request_commitment, digest, &sig, &pk, app_info(app)).to_bytes())
    }

    /// The refusal response (§4.2).
    pub fn refuse(&self, reason: String, detail: Option<String>, app: FfiApp) -> Vec<u8> {
        SignResponse::refused(&self.review.request_commitment, &reason, detail, app_info(app)).to_bytes()
    }

    /// The exact bytes the review was made from, for records.
    pub fn request_bytes(&self) -> Vec<u8> {
        self.request_bytes.clone()
    }
}

/// `tpmsign:1?u=…&h=…`; refuses a non-local host (§3.2).
#[uniffi::export]
pub fn parse_qr(uri: String) -> Result<FfiQr, CoreError> {
    let q = QrPayload::parse(&uri).map_err(failed)?;
    Ok(FfiQr { url: q.url, commitment: q.commitment })
}

/// §6.1. `facts` are empty on the phone until the build-embedded table
/// (§6.7): addresses show in full without names, and no paymaster is accepted.
#[uniffi::export]
pub fn open_request(
    bytes: Vec<u8>,
    commitment: String,
    now: u64,
    enrolled: Vec<FfiEnrolledAccount>,
) -> Result<Arc<ReviewHandle>, CoreError> {
    let mut accounts = Vec::with_capacity(enrolled.len());
    for e in enrolled {
        let mut a = EnrolledAccount::new(e.chain_id, parse_address(&e.entry_point)?, parse_address(&e.account)?);
        a.validator = e.validator.as_deref().map(parse_address).transpose()?;
        a.gas_cap_wei = e.gas_cap_wei.parse().map_err(|_| CoreError::Failed("gasCapWei: not a decimal integer".into()))?;
        a.expert_mode = e.expert_mode;
        accounts.push(a);
    }
    let review = review::open_request(&bytes, &commitment, now, &accounts, &Facts::default());
    Ok(Arc::new(ReviewHandle { review, request_bytes: bytes }))
}

/// `sha256(x ‖ y)`, 100 bits, four groups of five (§6.3).
#[uniffi::export]
pub fn fingerprint_of(public_key: Vec<u8>) -> Result<String, CoreError> {
    Ok(crate::fingerprint::fingerprint(&parse_key(&public_key)?))
}

/// The key-attestation challenge for an enrollment request (§5.2).
#[uniffi::export]
pub fn attestation_challenge(request_bytes: Vec<u8>) -> Vec<u8> {
    crate::enroll::attestation_challenge(&request_bytes).to_vec()
}

#[uniffi::export]
pub fn default_gas_cap_wei() -> String {
    review::DEFAULT_GAS_CAP_WEI.to_string()
}

#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn app_info(app: FfiApp) -> AppInfo {
    AppInfo { platform: app.platform, version: app.version, core: env!("CARGO_PKG_VERSION").to_string() }
}

fn parse_address(s: &str) -> Result<Address, CoreError> {
    s.parse().map_err(|_| CoreError::Failed(format!("not an address: {s}")))
}

fn parse_key(xy: &[u8]) -> Result<PublicKey, CoreError> {
    if xy.len() != 64 {
        return Err(CoreError::Failed(format!("the public key is {} bytes, not 64", xy.len())));
    }
    let pk = PublicKey { x: xy[..32].try_into().expect("32"), y: xy[32..].try_into().expect("32") };
    if !hw_signer::valid_public_key(&pk) {
        return Err(CoreError::Failed("the public key is not a point on P-256".into()));
    }
    Ok(pk)
}

/// `SEQUENCE { INTEGER r, INTEGER s }` as the platforms emit it, each integer
/// at most 33 bytes (a leading zero for a high bit), into two 32-byte words.
fn der_to_rs(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut i = 0;
    if der.get(i)? != &0x30 {
        return None;
    }
    i += 1;
    let seq_len = der_len(der, &mut i)?;
    if i + seq_len != der.len() {
        return None;
    }
    let r = der_int(der, &mut i)?;
    let s = der_int(der, &mut i)?;
    (i == der.len()).then_some((r, s))
}

fn der_len(der: &[u8], i: &mut usize) -> Option<usize> {
    let b = *der.get(*i)?;
    *i += 1;
    if b < 0x80 {
        return Some(b as usize);
    }
    if b == 0x81 {
        let l = *der.get(*i)? as usize;
        *i += 1;
        return Some(l);
    }
    None
}

fn der_int(der: &[u8], i: &mut usize) -> Option<[u8; 32]> {
    if der.get(*i)? != &0x02 {
        return None;
    }
    *i += 1;
    let len = der_len(der, i)?;
    let bytes = der.get(*i..*i + len)?;
    *i += len;
    let bytes = match bytes {
        [0x00, rest @ ..] if rest.len() == 32 => rest,
        b if b.len() <= 32 => b,
        _ => return None,
    };
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_signatures_become_r_s() {
        // r with a high bit (33-byte integer), s short (31 bytes)
        let mut der = vec![0x30, 0x44, 0x02, 0x21, 0x00];
        der.extend_from_slice(&[0x80; 32]);
        der.extend_from_slice(&[0x02, 0x1f]);
        der.extend_from_slice(&[0x11; 31]);
        let (r, s) = der_to_rs(&der).unwrap();
        assert_eq!(r, [0x80; 32]);
        assert_eq!(s[0], 0);
        assert_eq!(&s[1..], &[0x11; 31]);
        assert!(der_to_rs(&der[..der.len() - 1]).is_none(), "truncated");
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(der_to_rs(&trailing).is_none(), "trailing byte");
        assert!(der_to_rs(&[0x31, 0x00]).is_none(), "not a sequence");
    }

    #[test]
    fn finish_round_trips_a_real_signature() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let p = sk.verifying_key().to_encoded_point(false);
        let xy = [p.x().unwrap().as_slice(), p.y().unwrap().as_slice()].concat();
        let digest = [7u8; 32];
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        let (r, s) = der_to_rs(sig.to_der().as_bytes()).unwrap();
        let (er, es) = sig.split_bytes();
        assert_eq!(&r[..], er.as_slice());
        assert_eq!(&s[..], es.as_slice());
        assert_eq!(fingerprint_of(xy.clone()).unwrap().len(), 23);
        assert!(fingerprint_of(vec![1; 64]).is_err(), "off the curve");
    }
}
