//! Enrollment (docs/MOBILE_OWNER_DESIGN.md §2.1, §4.3): the laptop asks the
//! phone to create an owner key for one account; the phone answers with the
//! public key, the security tier it got, and attestation evidence. The same
//! QR → LAN transport as a sign request; the same commitment. Nothing here is
//! on-chain: the handover to the new key is a separate `set-root`, and the
//! laptop checks that key's fingerprint against this enrollment.

use alloy_primitives::{Address, B256};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hw_signer::{valid_public_key, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::request::{commitment, AppInfo, PublicKeyJson, RequestError, PROTOCOL_VERSION};

pub const ENROLL_REQUEST: &str = "enroll-request";
pub const ENROLL_RESPONSE: &str = "enroll-response";

/// Domain prefix of the key-attestation challenge (§5.2).
pub const ATTESTATION_CHALLENGE_PREFIX: &[u8] = b"TPM_sign/v1/enroll";

/// The challenge the phone must put into the key's attestation: it binds
/// the attested key to this exact request, so evidence cannot be replayed
/// from another enrollment. `sha256("TPM_sign/v1/enroll" ‖ commitment)`,
/// with the commitment as its base64url text.
pub fn attestation_challenge(request_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ATTESTATION_CHALLENGE_PREFIX);
    h.update(commitment(request_bytes).as_bytes());
    h.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    pub tpm_sign: String,
    pub version: u32,
    /// unix seconds
    pub expires: u64,
    /// decimal
    pub chain_id: String,
    pub entry_point: Address,
    /// The existing account the key is for (§5.5: no counterfactual accounts in v1).
    pub account: Address,
    /// The owner's name for this key; shown on the phone, kept in the config.
    pub label: String,
    /// 32 random bytes, so two enrollments never share a commitment.
    pub challenge: B256,
}

impl EnrollRequest {
    pub fn new(chain_id: u64, entry_point: Address, account: Address, label: &str, challenge: B256, expires: u64) -> Self {
        Self {
            tpm_sign: ENROLL_REQUEST.into(),
            version: PROTOCOL_VERSION,
            expires,
            chain_id: chain_id.to_string(),
            entry_point,
            account,
            label: label.into(),
            challenge,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// The phone's checks before anything is shown: type, version, expiry.
    pub fn parse(bytes: &[u8], now: u64, clock_tolerance: u64) -> Result<Self, RequestError> {
        let req: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if req.tpm_sign != ENROLL_REQUEST {
            return Err(RequestError::Malformed(format!("not an enroll request: {:?}", req.tpm_sign)));
        }
        if req.version != PROTOCOL_VERSION {
            return Err(RequestError::Version { got: req.version, supported: PROTOCOL_VERSION });
        }
        if now > req.expires.saturating_add(clock_tolerance) {
            return Err(RequestError::Expired);
        }
        if req.label.is_empty() || req.label.len() > 64 {
            return Err(RequestError::Malformed("label must be 1 to 64 characters".into()));
        }
        req.chain_id()?;
        Ok(req)
    }

    pub fn chain_id(&self) -> Result<u64, RequestError> {
        self.chain_id.parse().map_err(|_| RequestError::Malformed("chainId: not a decimal integer".into()))
    }
}

/// §4.3. `result` is `enrolled` or `refused`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub tpm_sign: String,
    pub version: u32,
    /// the commitment of the request this answers
    pub request: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyJson>,
    /// The tier as the phone sees it: `strongbox`, `tee` or `secure-enclave`.
    /// Display only until the attestation says the same (§5.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_level: Option<String>,
    /// Whether the device PIN may also unlock the key (§5.4 opt-in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_credential: Option<bool>,
    /// Attestation evidence, each entry base64 DER, the key's certificate
    /// first (Android). Empty when the platform gives none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestation: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
}

/// What the laptop keeps from a verified response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub public_key: PublicKey,
    pub security_level: String,
    pub device_credential: bool,
    /// DER certificates, the key's first.
    pub attestation: Vec<Vec<u8>>,
    pub app: Option<AppInfo>,
}

impl EnrollResponse {
    pub fn enrolled(
        request_commitment: &str,
        pk: &PublicKey,
        security_level: &str,
        device_credential: bool,
        attestation_der: &[Vec<u8>],
        app: AppInfo,
    ) -> Self {
        Self {
            tpm_sign: ENROLL_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "enrolled".into(),
            public_key: Some(PublicKeyJson::from(pk)),
            security_level: Some(security_level.into()),
            device_credential: Some(device_credential),
            attestation: attestation_der.iter().map(|c| B64.encode(c)).collect(),
            reason: None,
            detail: None,
            app: Some(app),
        }
    }

    pub fn refused(request_commitment: &str, reason: &str, detail: Option<String>, app: AppInfo) -> Self {
        Self {
            tpm_sign: ENROLL_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "refused".into(),
            public_key: None,
            security_level: None,
            device_credential: None,
            attestation: Vec::new(),
            reason: Some(reason.into()),
            detail,
            app: Some(app),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// The laptop's checks (§2.1 step 5, the transport part): the response
    /// answers *this* request and carries a key on the curve. Whether the
    /// attestation proves anything is the caller's step (P3); this only
    /// decodes it and refuses an empty chain unless `allow_no_attestation`.
    pub fn verify(bytes: &[u8], request_bytes: &[u8], allow_no_attestation: bool) -> Result<Enrollment, RequestError> {
        let resp: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if resp.tpm_sign != ENROLL_RESPONSE {
            return Err(RequestError::Malformed(format!("not an enroll response: {:?}", resp.tpm_sign)));
        }
        if resp.version != PROTOCOL_VERSION {
            return Err(RequestError::Version { got: resp.version, supported: PROTOCOL_VERSION });
        }
        if resp.request != commitment(request_bytes) {
            return Err(RequestError::Malformed("the response answers a different request".into()));
        }
        match resp.result.as_str() {
            "enrolled" => {}
            "refused" => {
                return Err(RequestError::Refused {
                    reason: resp.reason.unwrap_or_else(|| "unspecified".into()),
                    detail: resp.detail,
                })
            }
            other => return Err(RequestError::Malformed(format!("result {other:?}"))),
        }
        let public_key = resp.public_key.ok_or_else(|| RequestError::Malformed("no public key".into()))?.to_key();
        if !valid_public_key(&public_key) {
            return Err(RequestError::Malformed("the public key is not a point on P-256".into()));
        }
        let security_level = resp.security_level.ok_or_else(|| RequestError::Malformed("no securityLevel".into()))?;
        if !matches!(security_level.as_str(), "strongbox" | "tee" | "secure-enclave" | "simulator") {
            return Err(RequestError::Malformed(format!("securityLevel {security_level:?} is not one this side knows")));
        }
        let mut attestation = Vec::with_capacity(resp.attestation.len());
        for (i, cert) in resp.attestation.iter().enumerate() {
            let der = B64.decode(cert).map_err(|e| RequestError::Malformed(format!("attestation[{i}]: not base64: {e}")))?;
            if der.first() != Some(&0x30) {
                return Err(RequestError::Malformed(format!("attestation[{i}]: not a DER certificate")));
            }
            attestation.push(der);
        }
        if attestation.is_empty() && !allow_no_attestation {
            return Err(RequestError::NoAttestation);
        }
        Ok(Enrollment {
            public_key,
            security_level,
            device_credential: resp.device_credential.unwrap_or(false),
            attestation,
            app: resp.app,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn request() -> Vec<u8> {
        EnrollRequest::new(
            31337,
            address!("0000000071727De22E5E9d8BAf0edAc6f37da032"),
            address!("D62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628"),
            "owner-phone",
            B256::repeat_byte(7),
            2_000_000_000,
        )
        .to_bytes()
    }

    /// A P-256 generator-multiple point: on the curve, so it passes as a key.
    fn some_key() -> PublicKey {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let p = sk.verifying_key().to_encoded_point(false);
        PublicKey { x: p.x().unwrap().as_slice().try_into().unwrap(), y: p.y().unwrap().as_slice().try_into().unwrap() }
    }

    fn app() -> AppInfo {
        AppInfo { platform: "test".into(), version: "0".into(), core: "0".into() }
    }

    #[test]
    fn request_round_trip_and_checks() {
        let bytes = request();
        let req = EnrollRequest::parse(&bytes, 1_999_999_000, 300).unwrap();
        assert_eq!(req.chain_id().unwrap(), 31337);
        assert_eq!(req.label, "owner-phone");
        assert!(matches!(EnrollRequest::parse(&bytes, 2_000_001_000, 300), Err(RequestError::Expired)));
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["tpmSign"] = "sign-request".into();
        assert!(EnrollRequest::parse(&serde_json::to_vec(&v).unwrap(), 0, 0).is_err());
        // the challenge binds to the exact bytes
        let mut other = bytes.clone();
        other.push(b' ');
        assert_ne!(attestation_challenge(&bytes), attestation_challenge(&other));
    }

    #[test]
    fn response_is_verified_against_its_request() {
        let bytes = request();
        let c = commitment(&bytes);
        let pk = some_key();
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let ok = EnrollResponse::enrolled(&c, &pk, "tee", false, &[der.clone()], app()).to_bytes();
        let e = EnrollResponse::verify(&ok, &bytes, false).unwrap();
        assert_eq!(e.public_key, pk);
        assert_eq!(e.security_level, "tee");
        assert_eq!(e.attestation, vec![der]);
        // another request
        assert!(EnrollResponse::verify(&ok, b"{}", false).is_err());
        // no evidence: refused unless allowed
        let bare = EnrollResponse::enrolled(&c, &pk, "simulator", false, &[], app()).to_bytes();
        assert!(matches!(EnrollResponse::verify(&bare, &bytes, false), Err(RequestError::NoAttestation)));
        assert!(EnrollResponse::verify(&bare, &bytes, true).is_ok());
        // a point off the curve is not a key
        let off = EnrollResponse::enrolled(&c, &PublicKey { x: [1; 32], y: [2; 32] }, "tee", false, &[], app()).to_bytes();
        assert!(EnrollResponse::verify(&off, &bytes, true).is_err());
        // the phone said no
        let no = EnrollResponse::refused(&c, "user", Some("declined".into()), app()).to_bytes();
        assert!(matches!(EnrollResponse::verify(&no, &bytes, true), Err(RequestError::Refused { .. })));
        // an unknown tier
        let odd = EnrollResponse::enrolled(&c, &pk, "cloud", false, &[], app()).to_bytes();
        assert!(EnrollResponse::verify(&odd, &bytes, true).is_err());
    }
}
