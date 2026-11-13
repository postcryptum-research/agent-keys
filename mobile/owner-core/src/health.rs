//! The health check, which is also the proof of possession a handover waits
//! for (docs/MOBILE_OWNER_DESIGN.md §2.2, §2.4): the laptop asks the phone to
//! show that it holds a key, without any transaction. The phone signs
//! `sha256("TPM_sign/v1/health" ‖ laptopNonce ‖ phoneNonce)`. It contributes
//! `phoneNonce`, so the laptop cannot choose the digest, and a SHA-256 output
//! under this prefix is not a `userOpHash` or any other message the key
//! could be asked to sign (§6.5). The same QR → LAN transport as a sign
//! request; the same commitment.

use alloy_primitives::{Address, Bytes, B256};
use hw_signer::{normalize_low_s, valid_public_key, verify_p256, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::request::{commitment, AppInfo, PublicKeyJson, RequestError, PROTOCOL_VERSION};

pub const HEALTH_REQUEST: &str = "health-request";
pub const HEALTH_RESPONSE: &str = "health-response";

/// Domain prefix of the digest the phone signs.
pub const HEALTH_PREFIX: &[u8] = b"TPM_sign/v1/health";

/// The phone's reasons for refusing, beyond the owner's own no (`user`).
pub const REASON_NO_KEY: &str = "no-key";
pub const REASON_OTHER_KEY: &str = "other-key";

pub fn health_digest(laptop_nonce: &B256, phone_nonce: &B256) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HEALTH_PREFIX);
    h.update(laptop_nonce);
    h.update(phone_nonce);
    h.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthRequest {
    pub tpm_sign: String,
    pub version: u32,
    /// unix seconds
    pub expires: u64,
    /// decimal
    pub chain_id: String,
    pub account: Address,
    /// The key to prove. The laptop names it, so a phone that holds another
    /// key for the account, or none, says so instead of answering for the
    /// wrong one.
    pub public_key: PublicKeyJson,
    /// 32 random bytes: the laptop's half of the digest.
    pub nonce: B256,
}

impl HealthRequest {
    pub fn new(chain_id: u64, account: Address, key: &PublicKey, nonce: B256, expires: u64) -> Self {
        Self {
            tpm_sign: HEALTH_REQUEST.into(),
            version: PROTOCOL_VERSION,
            expires,
            chain_id: chain_id.to_string(),
            account,
            public_key: PublicKeyJson::from(key),
            nonce,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// The phone's checks before anything is shown: type, version, expiry,
    /// a key on the curve.
    pub fn parse(bytes: &[u8], now: u64, clock_tolerance: u64) -> Result<Self, RequestError> {
        let req: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if req.tpm_sign != HEALTH_REQUEST {
            return Err(RequestError::Malformed(format!("not a health request: {:?}", req.tpm_sign)));
        }
        if req.version != PROTOCOL_VERSION {
            return Err(RequestError::Version { got: req.version, supported: PROTOCOL_VERSION });
        }
        if now > req.expires.saturating_add(clock_tolerance) {
            return Err(RequestError::Expired);
        }
        if !valid_public_key(&req.public_key.to_key()) {
            return Err(RequestError::Malformed("the public key is not a point on P-256".into()));
        }
        req.chain_id()?;
        Ok(req)
    }

    pub fn chain_id(&self) -> Result<u64, RequestError> {
        self.chain_id.parse().map_err(|_| RequestError::Malformed("chainId is not a decimal integer".into()))
    }

    /// What a phone holding `held` for this request's chain and account
    /// does: `Ok` to prove the key, or the reason and detail of its refusal.
    pub fn held(&self, held: Option<&PublicKey>) -> Result<(), (&'static str, String)> {
        let asked = self.public_key.to_key();
        match held {
            Some(k) if *k == asked => Ok(()),
            Some(k) => Err((
                REASON_OTHER_KEY,
                format!(
                    "this phone's key for the account is {}, not {}",
                    crate::fingerprint::fingerprint(k),
                    crate::fingerprint::fingerprint(&asked)
                ),
            )),
            None => Err((REASON_NO_KEY, "this phone holds no key for the account".into())),
        }
    }
}

/// `result` is `signed` or `refused`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub tpm_sign: String,
    pub version: u32,
    /// the commitment of the request this answers
    pub request: String,
    pub result: String,
    /// 32 random bytes: the phone's half of the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_nonce: Option<B256>,
    /// `r ‖ s`, 64 bytes, low-s
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
}

impl HealthResponse {
    pub fn signed(request_commitment: &str, phone_nonce: B256, sig: &Signature, app: AppInfo) -> Self {
        let sig = normalize_low_s(*sig);
        Self {
            tpm_sign: HEALTH_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "signed".into(),
            phone_nonce: Some(phone_nonce),
            signature: Some(Bytes::copy_from_slice(&[&sig.r[..], &sig.s[..]].concat())),
            reason: None,
            detail: None,
            app: Some(app),
        }
    }

    pub fn refused(request_commitment: &str, reason: &str, detail: Option<String>, app: AppInfo) -> Self {
        Self {
            tpm_sign: HEALTH_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "refused".into(),
            phone_nonce: None,
            signature: None,
            reason: Some(reason.into()),
            detail,
            app: Some(app),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// The laptop's check: the response answers *this* request, and its
    /// signature is by the key the request named, over the digest of the
    /// request's nonce and the phone's. Nothing else proves that the phone
    /// holds the key.
    pub fn verify(bytes: &[u8], request_bytes: &[u8]) -> Result<(), RequestError> {
        let request: HealthRequest = serde_json::from_slice(request_bytes).map_err(|e| RequestError::Malformed(format!("the request: {e}")))?;
        let resp: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if resp.tpm_sign != HEALTH_RESPONSE {
            return Err(RequestError::Malformed(format!("not a health response: {:?}", resp.tpm_sign)));
        }
        if resp.version != PROTOCOL_VERSION {
            return Err(RequestError::Version { got: resp.version, supported: PROTOCOL_VERSION });
        }
        if resp.request != commitment(request_bytes) {
            return Err(RequestError::Malformed("the response answers a different request".into()));
        }
        match resp.result.as_str() {
            "signed" => {}
            "refused" => {
                return Err(RequestError::Refused {
                    reason: resp.reason.unwrap_or_else(|| "unspecified".into()),
                    detail: resp.detail,
                })
            }
            other => return Err(RequestError::Malformed(format!("result {other:?}"))),
        }
        let phone_nonce = resp.phone_nonce.ok_or_else(|| RequestError::Malformed("no phoneNonce".into()))?;
        let raw = resp.signature.ok_or_else(|| RequestError::Malformed("no signature".into()))?;
        if raw.len() != 64 {
            return Err(RequestError::Malformed(format!("signature is {} bytes, not 64", raw.len())));
        }
        let mut sig = Signature { r: [0; 32], s: [0; 32] };
        sig.r.copy_from_slice(&raw[..32]);
        sig.s.copy_from_slice(&raw[32..]);
        if !verify_p256(&health_digest(&request.nonce, &phone_nonce), &sig, &request.public_key.to_key()) {
            return Err(RequestError::NotHeld);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    fn key(n: u8) -> (p256::ecdsa::SigningKey, PublicKey) {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[n; 32].into()).unwrap();
        let p = sk.verifying_key().to_encoded_point(false);
        let pk = PublicKey { x: (*p.x().unwrap()).into(), y: (*p.y().unwrap()).into() };
        (sk, pk)
    }

    fn sign(sk: &p256::ecdsa::SigningKey, digest: &[u8; 32]) -> Signature {
        let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).unwrap();
        let (r, s) = sig.split_bytes();
        Signature { r: r.into(), s: s.into() }
    }

    fn app() -> AppInfo {
        AppInfo { platform: "test".into(), version: "0".into(), core: "0".into() }
    }

    #[test]
    fn the_digest_is_the_designs() {
        let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
        let mut bytes = b"TPM_sign/v1/health".to_vec();
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(health_digest(&a, &b), expected);
        assert_ne!(health_digest(&a, &b), health_digest(&b, &a), "each side's nonce has its place");
    }

    #[test]
    fn only_the_named_key_proves_itself() {
        let account = address!("D62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628");
        let (sk, pk) = key(5);
        let (other_sk, other_pk) = key(6);
        let request = HealthRequest::new(31337, account, &pk, B256::repeat_byte(7), 2_000_000_000);
        let bytes = request.to_bytes();
        assert_eq!(HealthRequest::parse(&bytes, 1_999_999_000, 300).unwrap(), request);
        assert!(matches!(HealthRequest::parse(&bytes, 2_000_000_301, 300), Err(RequestError::Expired)));
        let c = commitment(&bytes);
        let phone_nonce = B256::repeat_byte(9);
        let digest = health_digest(&request.nonce, &phone_nonce);

        // the phone's side: the key it holds for the account decides
        assert_eq!(request.held(Some(&pk)), Ok(()));
        let (reason, detail) = request.held(Some(&other_pk)).unwrap_err();
        assert_eq!(reason, REASON_OTHER_KEY);
        assert!(detail.contains(&crate::fingerprint::fingerprint(&other_pk)) && detail.contains(&crate::fingerprint::fingerprint(&pk)), "{detail}");
        assert_eq!(request.held(None).unwrap_err().0, REASON_NO_KEY);

        // the laptop's side
        let good = HealthResponse::signed(&c, phone_nonce, &sign(&sk, &digest), app()).to_bytes();
        assert!(HealthResponse::verify(&good, &bytes).is_ok());
        // another key: the phone does not hold the one named
        let other = HealthResponse::signed(&c, phone_nonce, &sign(&other_sk, &digest), app()).to_bytes();
        assert!(matches!(HealthResponse::verify(&other, &bytes), Err(RequestError::NotHeld)));
        // the right key over another nonce pair: a signature from another session proves nothing here
        let stale = HealthResponse::signed(&c, phone_nonce, &sign(&sk, &health_digest(&B256::repeat_byte(8), &phone_nonce)), app()).to_bytes();
        assert!(matches!(HealthResponse::verify(&stale, &bytes), Err(RequestError::NotHeld)));
        // an answer to another request
        let elsewhere = HealthResponse::signed("x", phone_nonce, &sign(&sk, &digest), app()).to_bytes();
        assert!(HealthResponse::verify(&elsewhere, &bytes).is_err());
        // a refusal carries its reason
        let refused = HealthResponse::refused(&c, REASON_NO_KEY, Some("this phone holds no key for the account".into()), app()).to_bytes();
        assert!(matches!(HealthResponse::verify(&refused, &bytes), Err(RequestError::Refused { reason, .. }) if reason == REASON_NO_KEY));
        // a response without its halves
        let mut bare: serde_json::Value = serde_json::from_slice(&good).unwrap();
        bare.as_object_mut().unwrap().remove("phoneNonce");
        assert!(HealthResponse::verify(&serde_json::to_vec(&bare).unwrap(), &bytes).is_err());
    }

    #[test]
    fn a_request_must_name_a_real_key_and_be_what_it_says() {
        let account = address!("D62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628");
        let off_curve = PublicKey { x: [1; 32], y: [1; 32] };
        let bytes = HealthRequest::new(31337, account, &off_curve, B256::ZERO, 2_000_000_000).to_bytes();
        assert!(HealthRequest::parse(&bytes, 0, 0).is_err());
        let (_, pk) = key(5);
        let mut v: serde_json::Value = serde_json::from_slice(&HealthRequest::new(31337, account, &pk, B256::ZERO, 2_000_000_000).to_bytes()).unwrap();
        v["tpmSign"] = "sign-request".into();
        assert!(HealthRequest::parse(&serde_json::to_vec(&v).unwrap(), 0, 0).is_err());
        v["tpmSign"] = HEALTH_REQUEST.into();
        v["chainId"] = "0x7a69".into();
        assert!(HealthRequest::parse(&serde_json::to_vec(&v).unwrap(), 0, 0).is_err());
    }

    /// §6.5: the health digest is a SHA-256 output under its own prefix, and
    /// the key's other signatures are over keccak `userOpHash`es. A health
    /// signature is not a signature over the laptop's nonce itself.
    #[test]
    fn the_laptop_does_not_choose_what_is_signed() {
        let chosen = B256::repeat_byte(0xAB);
        assert_ne!(health_digest(&chosen, &B256::ZERO), chosen.0);
        assert_ne!(health_digest(&chosen, &B256::repeat_byte(1)), health_digest(&chosen, &B256::repeat_byte(2)), "the phone's nonce moves the digest");
    }
}
