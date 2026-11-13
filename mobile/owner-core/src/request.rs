//! The wire format between the laptop and the phone
//! (docs/MOBILE_OWNER_DESIGN.md §3.2, §4): the sign request the laptop
//! serves, the response the phone posts, the QR payload that commits to the
//! request bytes and carries the session's secret, the MAC that secret puts
//! on every answer, and the checks each side runs. JSON, UTF-8; byte strings
//! as 0x-hex; integers that can exceed 2^53 as decimal strings.

use alloy_primitives::{Address, Bytes, B256, U256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use hw_signer::{normalize_low_s, verify_p256, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::user_op::{user_op_hash, PackedUserOp};

pub const PROTOCOL_VERSION: u32 = 1;
pub const SIGN_REQUEST: &str = "sign-request";
pub const SIGN_RESPONSE: &str = "sign-response";

/// SHA-256 of the exact request bytes, base64url without padding: what the
/// QR carries and what the response echoes.
pub fn commitment(request_bytes: &[u8]) -> String {
    B64URL.encode(Sha256::digest(request_bytes))
}

/// The HTTP header that carries [`answer_mac`] on every POST of a session.
pub const MAC_HEADER: &str = "X-TpmSign-Mac";
/// The session secret is 128 random bits, base64url (22 characters).
pub const SESSION_SECRET_BYTES: usize = 16;

/// `HMAC-SHA256(secret, body)`, base64url. The secret travels only in the QR
/// — from the laptop's screen to the phone's camera — and never over the
/// network, so an answer that carries this MAC comes from the device that
/// scanned the QR. A host on the LAN sees the session URL and its token in
/// the phone's cleartext GET; it does not see this.
pub fn answer_mac(secret: &str, body: &[u8]) -> Result<String, RequestError> {
    Ok(B64URL.encode(mac_over(secret, body)?.finalize().into_bytes()))
}

/// Constant-time check of [`answer_mac`].
pub fn verify_answer_mac(secret: &str, body: &[u8], mac: &str) -> bool {
    let (Ok(expected), Ok(given)) = (mac_over(secret, body), B64URL.decode(mac)) else {
        return false;
    };
    expected.verify_slice(&given).is_ok()
}

/// What the laptop answers when it accepts an answer, base64url:
/// `HMAC-SHA256(secret, "TPM_sign/v1/accepted" ‖ HMAC-SHA256(secret, body))`.
/// The phone takes only this as "the laptop has it": a bare `200` can be
/// written by any host in the path that dropped the real POST, and a phone
/// that believed it would keep a key the laptop never saw.
pub fn confirmation_mac(secret: &str, answer_body: &[u8]) -> Result<String, RequestError> {
    Ok(B64URL.encode(confirmation_over(secret, answer_body)?.finalize().into_bytes()))
}

/// Constant-time check of [`confirmation_mac`].
pub fn verify_confirmation_mac(secret: &str, answer_body: &[u8], confirmation: &str) -> bool {
    let (Ok(expected), Ok(given)) = (confirmation_over(secret, answer_body), B64URL.decode(confirmation.trim())) else {
        return false;
    };
    expected.verify_slice(&given).is_ok()
}

fn keyed(secret: &str) -> Result<Hmac<Sha256>, RequestError> {
    let key = B64URL.decode(secret).ok().filter(|k| k.len() == SESSION_SECRET_BYTES);
    let key = key.ok_or_else(|| RequestError::Malformed("the session secret is not 16 bytes of base64url".into()))?;
    Ok(Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes a key of any length"))
}

/// The body alone is enough to cover: the key is fresh for each session
/// and used for nothing else, and the body names the request it answers by
/// its commitment, so a MAC cannot be replayed into another session or
/// onto another request.
fn mac_over(secret: &str, body: &[u8]) -> Result<Hmac<Sha256>, RequestError> {
    let mut mac = keyed(secret)?;
    mac.update(body);
    Ok(mac)
}

/// A different input shape from an answer's (a JSON body), so one can never
/// stand in for the other.
fn confirmation_over(secret: &str, answer_body: &[u8]) -> Result<Hmac<Sha256>, RequestError> {
    let answer = mac_over(secret, answer_body)?.finalize().into_bytes();
    let mut mac = keyed(secret)?;
    mac.update(b"TPM_sign/v1/accepted");
    mac.update(&answer);
    Ok(mac)
}

/// The packed v0.7 operation without its signature, as JSON (§4.1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserOpJson {
    pub sender: Address,
    /// decimal
    pub nonce: String,
    pub init_code: Bytes,
    pub call_data: Bytes,
    pub account_gas_limits: B256,
    /// decimal
    pub pre_verification_gas: String,
    pub gas_fees: B256,
    pub paymaster_and_data: Bytes,
}

impl UserOpJson {
    pub fn from_packed(op: &PackedUserOp) -> Self {
        Self {
            sender: op.sender,
            nonce: op.nonce.to_string(),
            init_code: op.init_code.clone(),
            call_data: op.call_data.clone(),
            account_gas_limits: op.account_gas_limits,
            pre_verification_gas: op.pre_verification_gas.to_string(),
            gas_fees: op.gas_fees,
            paymaster_and_data: op.paymaster_and_data.clone(),
        }
    }

    pub fn to_packed(&self) -> Result<PackedUserOp, RequestError> {
        let dec = |s: &str, what: &str| {
            U256::from_str_radix(s, 10).map_err(|_| RequestError::Malformed(format!("{what}: not a decimal integer")))
        };
        Ok(PackedUserOp {
            sender: self.sender,
            nonce: dec(&self.nonce, "nonce")?,
            init_code: self.init_code.clone(),
            call_data: self.call_data.clone(),
            account_gas_limits: self.account_gas_limits,
            pre_verification_gas: dec(&self.pre_verification_gas, "preVerificationGas")?,
            gas_fees: self.gas_fees,
            paymaster_and_data: self.paymaster_and_data.clone(),
        })
    }
}

/// Advisory hints from the laptop (§4.1 `laptop.*`): never trusted, only
/// displayed as "the laptop says".
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LaptopHints {
    pub user_op_hash: B256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<Address, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub tpm_sign: String,
    pub version: u32,
    /// unix seconds
    pub expires: u64,
    /// decimal
    pub chain_id: String,
    pub entry_point: Address,
    pub user_op: UserOpJson,
    pub laptop: LaptopHints,
}

impl SignRequest {
    pub fn new(
        op: &PackedUserOp,
        entry_point: Address,
        chain_id: u64,
        expires: u64,
        command: Option<String>,
        labels: BTreeMap<Address, String>,
        agent_version: Option<String>,
    ) -> Self {
        Self {
            tpm_sign: SIGN_REQUEST.to_string(),
            version: PROTOCOL_VERSION,
            expires,
            chain_id: chain_id.to_string(),
            entry_point,
            user_op: UserOpJson::from_packed(op),
            laptop: LaptopHints { user_op_hash: user_op_hash(op, entry_point, chain_id), command, labels, agent_version },
        }
    }

    /// The bytes the laptop serves and the QR commits to.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// Parse and run the checks that need no enrollment context: the type and
    /// version, the expiry (with `clock_tolerance` seconds for a drifting
    /// phone), and that the laptop's hash equals the one recomputed here.
    pub fn parse(bytes: &[u8], now: u64, clock_tolerance: u64) -> Result<Self, RequestError> {
        let req: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if req.tpm_sign != SIGN_REQUEST {
            return Err(RequestError::Malformed(format!("not a sign request: {:?}", req.tpm_sign)));
        }
        if req.version != PROTOCOL_VERSION {
            return Err(RequestError::Version { got: req.version, supported: PROTOCOL_VERSION });
        }
        if now > req.expires.saturating_add(clock_tolerance) {
            return Err(RequestError::Expired);
        }
        let recomputed = req.user_op_hash()?;
        if recomputed != req.laptop.user_op_hash {
            return Err(RequestError::HashMismatch { laptop: req.laptop.user_op_hash, recomputed });
        }
        Ok(req)
    }

    pub fn chain_id(&self) -> Result<u64, RequestError> {
        self.chain_id.parse().map_err(|_| RequestError::Malformed("chainId: not a decimal integer".into()))
    }

    /// Recomputed from the operation, never taken from `laptop`.
    pub fn user_op_hash(&self) -> Result<B256, RequestError> {
        Ok(user_op_hash(&self.user_op.to_packed()?, self.entry_point, self.chain_id()?))
    }

    /// The upper 192 bits of the nonce: 0 is the root path (§6.2 check 5).
    pub fn nonce_key(&self) -> Result<U256, RequestError> {
        Ok(self.user_op.to_packed()?.nonce >> 64)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyJson {
    pub x: B256,
    pub y: B256,
}

impl From<&PublicKey> for PublicKeyJson {
    fn from(pk: &PublicKey) -> Self {
        Self { x: B256::from(pk.x), y: B256::from(pk.y) }
    }
}

impl PublicKeyJson {
    pub fn to_key(&self) -> PublicKey {
        PublicKey { x: self.x.0, y: self.y.0 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppInfo {
    pub platform: String,
    pub version: String,
    pub core: String,
}

/// §4.2. `result` is `signed` or `refused`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub tpm_sign: String,
    pub version: u32,
    /// the commitment of the request this answers
    pub request: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_op_hash: Option<B256>,
    /// `r ‖ s`, 64 bytes, low-s
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
}

impl SignResponse {
    pub fn signed(request_commitment: &str, hash: B256, sig: &Signature, pk: &PublicKey, app: AppInfo) -> Self {
        let sig = normalize_low_s(*sig);
        Self {
            tpm_sign: SIGN_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "signed".into(),
            user_op_hash: Some(hash),
            signature: Some(Bytes::copy_from_slice(&[&sig.r[..], &sig.s[..]].concat())),
            public_key: Some(PublicKeyJson::from(pk)),
            reason: None,
            detail: None,
            app: Some(app),
        }
    }

    pub fn refused(request_commitment: &str, reason: &str, detail: Option<String>, app: AppInfo) -> Self {
        Self {
            tpm_sign: SIGN_RESPONSE.into(),
            version: PROTOCOL_VERSION,
            request: request_commitment.into(),
            result: "refused".into(),
            user_op_hash: None,
            signature: None,
            public_key: None,
            reason: Some(reason.into()),
            detail,
            app: Some(app),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("serializable")
    }

    /// The laptop's checks (§2.3 step 4): the response answers *this*
    /// request, carries a 64-byte low-s signature by `expected_key` over
    /// `expected_hash`. Returns the signature, or why the phone refused.
    pub fn verify(
        bytes: &[u8],
        request_bytes: &[u8],
        expected_key: &PublicKey,
        expected_hash: B256,
    ) -> Result<Signature, RequestError> {
        let resp: Self = serde_json::from_slice(bytes).map_err(|e| RequestError::Malformed(e.to_string()))?;
        if resp.tpm_sign != SIGN_RESPONSE {
            return Err(RequestError::Malformed(format!("not a sign response: {:?}", resp.tpm_sign)));
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
        if resp.user_op_hash != Some(expected_hash) {
            return Err(RequestError::Malformed("the response names a different userOpHash".into()));
        }
        if let Some(pk) = &resp.public_key {
            if pk.to_key() != *expected_key {
                return Err(RequestError::WrongKey);
            }
        }
        let raw = resp.signature.ok_or_else(|| RequestError::Malformed("no signature".into()))?;
        if raw.len() != 64 {
            return Err(RequestError::Malformed(format!("signature is {} bytes, not 64", raw.len())));
        }
        let mut sig = Signature { r: [0; 32], s: [0; 32] };
        sig.r.copy_from_slice(&raw[..32]);
        sig.s.copy_from_slice(&raw[32..]);
        if normalize_low_s(sig) != sig {
            return Err(RequestError::Malformed("signature is not low-s".into()));
        }
        if !verify_p256(&expected_hash.0, &sig, expected_key) {
            return Err(RequestError::BadSignature);
        }
        Ok(sig)
    }
}

/// `tpmsign:1?u=<session url>&h=<commitment>&k=<secret>` (§3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrPayload {
    pub url: String,
    pub commitment: String,
    /// The key of [`answer_mac`]; in the QR only.
    pub secret: String,
}

impl QrPayload {
    pub fn to_uri(&self) -> String {
        format!("tpmsign:{PROTOCOL_VERSION}?u={}&h={}&k={}", self.url, self.commitment, self.secret)
    }

    /// Parse; the URL's host must be a private, link-local or unique-local
    /// address, or the phone refuses (§3.2).
    pub fn parse(uri: &str) -> Result<Self, RequestError> {
        let rest = uri
            .strip_prefix(&format!("tpmsign:{PROTOCOL_VERSION}?"))
            .ok_or_else(|| RequestError::Malformed("not a tpmsign:1 URI".into()))?;
        let (mut url, mut h, mut k) = (None, None, None);
        for part in rest.split('&') {
            match part.split_once('=') {
                Some(("u", v)) => url = Some(v.to_string()),
                Some(("h", v)) => h = Some(v.to_string()),
                Some(("k", v)) => k = Some(v.to_string()),
                _ => {}
            }
        }
        let (url, commitment, secret) = (
            url.ok_or_else(|| RequestError::Malformed("no u= in the QR".into()))?,
            h.ok_or_else(|| RequestError::Malformed("no h= in the QR".into()))?,
            k.ok_or_else(|| RequestError::Malformed("no k= in the QR (an older agent-signer?)".into()))?,
        );
        if B64URL.decode(&secret).map(|b| b.len()).ok() != Some(SESSION_SECRET_BYTES) {
            return Err(RequestError::Malformed("k= is not 16 bytes of base64url".into()));
        }
        if commitment.len() != 43 || !commitment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(RequestError::Malformed("h= is not a base64url SHA-256".into()));
        }
        let host = session_host(&url)?;
        if !is_local_host(&host) {
            return Err(RequestError::NotLocal(host));
        }
        Ok(Self { url, commitment, secret })
    }
}

/// The host of a session URL (§3.2): `http://`, then an authority that is an
/// IP literal — dotted IPv4 or a bracketed IPv6 — with an optional port that
/// fits a `u16`, then a path. No userinfo (`user@host` would let the checked
/// host differ from the one a client connects to), no names (no DNS, so no
/// rebinding). Returns the host without brackets.
pub fn session_host(url: &str) -> Result<String, RequestError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| RequestError::Malformed("u= is not an http:// URL".into()))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return Err(RequestError::Malformed("u= carries a userinfo part; refusing".into()));
    }
    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, rest) = after_bracket
            .split_once(']')
            .ok_or_else(|| RequestError::Malformed("u= has an unterminated IPv6 literal".into()))?;
        let port = match rest {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| RequestError::Malformed("u= has text after the IPv6 literal".into()))?),
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(RequestError::Malformed(format!("u= host {host:?} is not an IPv6 address")));
        }
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if host.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(RequestError::Malformed(format!("u= host {host:?} is not an IP address (names are not allowed)")));
        }
        (host, port)
    };
    if let Some(p) = port {
        if p.is_empty() || p.parse::<u16>().is_err() {
            return Err(RequestError::Malformed(format!("u= port {p:?} is not a port number")));
        }
    }
    Ok(host.to_string())
}

/// Private (RFC 1918), link-local, loopback, or IPv6 ULA / link-local.
/// Loopback is for the laptop's own tests (`--listen 127.0.0.1:0` with a
/// simulated phone); on a phone it names the phone itself.
pub fn is_local_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_private() || v4.is_link_local() || v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let seg = v6.segments()[0];
        return v6.is_loopback() || (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80;
    }
    false
}

#[derive(Debug)]
pub enum RequestError {
    Malformed(String),
    Version { got: u32, supported: u32 },
    Expired,
    HashMismatch { laptop: B256, recomputed: B256 },
    Refused { reason: String, detail: Option<String> },
    WrongKey,
    BadSignature,
    NotLocal(String),
    /// An enrollment without attestation evidence (`enroll.rs`).
    NoAttestation,
    /// A health answer whose signature is not by the key the request named
    /// (`health.rs`).
    NotHeld,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Malformed(m) => write!(f, "malformed: {m}"),
            RequestError::Version { got, supported } => {
                write!(f, "protocol version {got} is not supported (this side speaks {supported})")
            }
            RequestError::Expired => write!(f, "the request has expired"),
            RequestError::HashMismatch { laptop, recomputed } => {
                write!(f, "the laptop's userOpHash {laptop} differs from the recomputed {recomputed}")
            }
            RequestError::Refused { reason, detail } => match detail {
                Some(d) => write!(f, "the phone refused: {reason} ({d})"),
                None => write!(f, "the phone refused: {reason}"),
            },
            RequestError::WrongKey => write!(f, "the response's public key is not the expected owner key"),
            RequestError::BadSignature => {
                write!(f, "the signature does not verify against the owner key over the userOpHash")
            }
            RequestError::NotLocal(h) => write!(f, "the session host {h} is not a local address"),
            RequestError::NotHeld => write!(f, "the answer's signature is not by the key the laptop named: the phone has not shown that it holds that key"),
            RequestError::NoAttestation => write!(
                f,
                "the phone sent no attestation evidence; pass --allow-no-attestation to enroll a key the laptop cannot place in hardware"
            ),
        }
    }
}
impl std::error::Error for RequestError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, hex};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as P256Sig, SigningKey};

    fn op() -> PackedUserOp {
        PackedUserOp {
            sender: address!("1111111111111111111111111111111111111111"),
            nonce: U256::from(0x10),
            init_code: Bytes::new(),
            call_data: Bytes::from(hex!("d09de08a")),
            account_gas_limits: b256!("00000000000000000000000000049d4000000000000000000000000000007530"),
            pre_verification_gas: U256::from(100_000),
            gas_fees: b256!("000000000000000000000000000f424000000000000000000000000005f5e100"),
            paymaster_and_data: Bytes::new(),
        }
    }
    const EP: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

    fn software_key() -> (SigningKey, PublicKey) {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let p = sk.verifying_key().to_encoded_point(false);
        let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
        pk.x.copy_from_slice(p.x().unwrap());
        pk.y.copy_from_slice(p.y().unwrap());
        (sk, pk)
    }

    fn sign(sk: &SigningKey, h: &B256) -> Signature {
        let s: P256Sig = sk.sign_prehash(&h.0).unwrap();
        let (r, s) = s.split_bytes();
        Signature { r: r.into(), s: s.into() }
    }

    #[test]
    fn request_round_trip_and_hash_check() {
        let req = SignRequest::new(&op(), EP, 31337, 2_000_000_000, Some("op send --root".into()), Default::default(), None);
        let bytes = req.to_bytes();
        let parsed = SignRequest::parse(&bytes, 1_900_000_000, 300).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(
            parsed.user_op_hash().unwrap(),
            b256!("48e286b71f896beef7a0b4d23fd82d6afae60a64e7976118de492a2fba4c1947")
        );
        assert_eq!(parsed.nonce_key().unwrap(), U256::ZERO);
        // expiry and tolerance
        assert!(matches!(SignRequest::parse(&bytes, 2_000_000_301, 300), Err(RequestError::Expired)));
        assert!(SignRequest::parse(&bytes, 2_000_000_299, 300).is_ok());
        // a tampered hint is caught: the phone recomputes
        let mut tampered = req.clone();
        tampered.laptop.user_op_hash = B256::ZERO;
        assert!(matches!(
            SignRequest::parse(&tampered.to_bytes(), 0, 0),
            Err(RequestError::HashMismatch { .. })
        ));
        // a tampered field changes the hash and so the commitment
        let mut other = req.clone();
        other.user_op.call_data = Bytes::from(hex!("d09de08b"));
        assert_ne!(commitment(&other.to_bytes()), commitment(&bytes));
    }

    #[test]
    fn response_is_verified_against_key_hash_and_request() {
        let req = SignRequest::new(&op(), EP, 31337, u64::MAX, None, Default::default(), None);
        let bytes = req.to_bytes();
        let hash = req.user_op_hash().unwrap();
        let (sk, pk) = software_key();
        let app = AppInfo { platform: "test".into(), version: "0".into(), core: "0".into() };
        let ok = SignResponse::signed(&commitment(&bytes), hash, &sign(&sk, &hash), &pk, app.clone()).to_bytes();
        assert!(SignResponse::verify(&ok, &bytes, &pk, hash).is_ok());
        // wrong key expected
        let (_, other_pk) = software_key();
        assert!(matches!(SignResponse::verify(&ok, &bytes, &other_pk, hash), Err(RequestError::WrongKey)));
        // a different request
        assert!(matches!(SignResponse::verify(&ok, b"other", &pk, hash), Err(RequestError::Malformed(_))));
        // signed over another hash
        let wrong = SignResponse::signed(&commitment(&bytes), hash, &sign(&sk, &B256::repeat_byte(7)), &pk, app.clone()).to_bytes();
        assert!(matches!(SignResponse::verify(&wrong, &bytes, &pk, hash), Err(RequestError::BadSignature)));
        // refused
        let no = SignResponse::refused(&commitment(&bytes), "user", None, app).to_bytes();
        assert!(matches!(SignResponse::verify(&no, &bytes, &pk, hash), Err(RequestError::Refused { .. })));
    }

    #[test]
    fn qr_payload() {
        let k = B64URL.encode([7u8; SESSION_SECRET_BYTES]);
        let h = "A".repeat(43);
        let q = QrPayload { url: "http://192.168.1.23:49731/s/abc".into(), commitment: h.clone(), secret: k.clone() };
        assert_eq!(QrPayload::parse(&q.to_uri()).unwrap(), q);
        let uri = |url: &str| format!("tpmsign:1?u={url}&h={h}&k={k}");
        assert!(matches!(QrPayload::parse(&format!("tpmsign:1?u=http://10.0.0.1:1/s/x&h=short&k={k}")), Err(RequestError::Malformed(_))));
        assert!(matches!(QrPayload::parse(&uri("http://93.184.216.34:80/s/x")), Err(RequestError::NotLocal(_))));
        // the session secret is required, and is 16 bytes
        assert!(matches!(QrPayload::parse(&format!("tpmsign:1?u=http://10.0.0.1:1/s/x&h={h}")), Err(RequestError::Malformed(m)) if m.contains("k=")));
        assert!(matches!(QrPayload::parse(&format!("tpmsign:1?u=http://10.0.0.1:1/s/x&h={h}&k=AAAA")), Err(RequestError::Malformed(m)) if m.contains("16 bytes")));
        // the authority must be an IP literal and nothing else (per review of PR #27)
        assert!(matches!(QrPayload::parse(&uri("http://10.0.0.1:80@93.184.216.34/s/x")), Err(RequestError::Malformed(m)) if m.contains("userinfo")));
        assert!(QrPayload::parse(&uri("http://[fe80::1]/s/x")).is_ok(), "a bracketed IPv6 literal without a port is a valid local host");
        assert!(QrPayload::parse(&uri("http://[fd00::1]:8080/s/x")).is_ok());
        assert!(matches!(QrPayload::parse(&uri("http://[2001:db8::1]:80/s/x")), Err(RequestError::NotLocal(_))));
        assert!(matches!(QrPayload::parse(&uri("http://10.0.0.1:99999999/s/x")), Err(RequestError::Malformed(m)) if m.contains("port")));
        assert!(matches!(QrPayload::parse(&uri("http://laptop.local:80/s/x")), Err(RequestError::Malformed(m)) if m.contains("not an IP address")));
        assert!(QrPayload::parse(&uri("http://[fe80::1/s/x")).is_err());
        assert!(QrPayload::parse(&uri("http://[fe80::1]x/s/x")).is_err());
        assert_eq!(session_host("http://192.168.1.2/s/x").unwrap(), "192.168.1.2");
        assert_eq!(session_host("http://[fe80::1]:1/s/x").unwrap(), "fe80::1");
        assert!(is_local_host("10.0.0.1") && is_local_host("172.16.5.5") && is_local_host("fe80::1") && is_local_host("fd00::1"));
        assert!(!is_local_host("8.8.8.8") && !is_local_host("example.com"));
    }

    /// The answer MAC: HMAC-SHA256 under the QR's secret (RFC 4231's test
    /// case 2 pins the primitive; the rest pins our use of it).
    #[test]
    fn answers_are_authenticated_by_the_qr_secret() {
        // RFC 4231, test case 2: key "Jefe", data "what do ya want for nothing?"
        let mut rfc = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        rfc.update(b"what do ya want for nothing?");
        assert_eq!(
            alloy_primitives::hex::encode(rfc.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let secret = B64URL.encode([7u8; SESSION_SECRET_BYTES]);
        let other = B64URL.encode([8u8; SESSION_SECRET_BYTES]);
        let mac = answer_mac(&secret, b"answer").unwrap();
        assert_eq!(mac.len(), 43);
        assert!(verify_answer_mac(&secret, b"answer", &mac));
        assert!(!verify_answer_mac(&secret, b"another answer", &mac), "the body is covered");
        assert!(!verify_answer_mac(&other, b"answer", &mac), "another session's secret does not verify");
        assert!(!verify_answer_mac(&secret, b"answer", ""), "no MAC is not a MAC");
        assert!(!verify_answer_mac(&secret, b"answer", &mac[..42]));
        assert!(answer_mac("AAAA", b"answer").is_err() && !verify_answer_mac("AAAA", b"answer", &mac), "a short secret is refused");
        // the laptop's confirmation: bound to the secret and to the answer, and not an answer's MAC
        let confirmation = confirmation_mac(&secret, b"answer").unwrap();
        assert!(verify_confirmation_mac(&secret, b"answer", &confirmation));
        assert!(verify_confirmation_mac(&secret, b"answer", &format!("{confirmation}\n")), "a trailing newline from the transport is not part of it");
        assert!(!verify_confirmation_mac(&secret, b"another answer", &confirmation));
        assert!(!verify_confirmation_mac(&other, b"answer", &confirmation));
        assert!(!verify_confirmation_mac(&secret, b"answer", "ok") && !verify_confirmation_mac(&secret, b"answer", ""), "a bare ok is not a confirmation");
        assert!(!verify_confirmation_mac(&secret, b"answer", &mac) && !verify_answer_mac(&secret, b"answer", &confirmation), "the two MACs do not stand in for each other");
    }
}
