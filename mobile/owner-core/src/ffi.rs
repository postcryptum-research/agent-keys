//! The `uniffi` surface for the phone apps (docs/MOBILE_OWNER_DESIGN.md §7.2):
//! the QR, the review, the response. Thin: every rule lives in the other
//! modules; this file converts types and nothing else. Built with
//! `--features ffi`; the Kotlin and Swift bindings are generated from the
//! compiled library (`mobile/android/build-core.sh`).

use std::sync::Arc;

use alloy_primitives::Address;
use hw_signer::{normalize_low_s, verify_p256, PublicKey, Signature};

use crate::enroll::{EnrollRequest, EnrollResponse};
use crate::request::{AppInfo, QrPayload, SignResponse};
use crate::review::{self, EnrolledAccount, Review, Verdict, CLOCK_TOLERANCE_SECS};

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
    /// The session's secret, for [`answer_mac`]: never sent anywhere.
    pub secret: String,
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
    /// The laptop's pins kept at enrollment (`open_enrollment`).
    pub pins: Vec<FfiPin>,
}

/// A name the laptop gave to an address the build does not know (§4.3).
#[derive(uniffi::Record)]
pub struct FfiPin {
    pub address: String,
    pub label: String,
}

/// An enrollment request, checked (§2.1 step 3): what the phone shows before
/// the owner confirms, and what it keeps.
#[derive(uniffi::Record)]
pub struct FfiEnrollment {
    pub chain_id: u64,
    pub entry_point: String,
    pub account: String,
    pub label: String,
    /// To store with the enrollment and to show as "from the laptop — unverified".
    pub pins: Vec<FfiPin>,
    /// Pins not taken because this build names the address itself; one line each, to show.
    pub ignored_pins: Vec<String>,
    /// Whether this build has facts for the chain; if not, reviews name nothing.
    pub chain_known: bool,
    /// The key-attestation challenge bound to this request (§5.2).
    pub attestation_challenge: Vec<u8>,
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

/// `tpmsign:1?u=…&h=…`; refuses a non-local host (§3.2). Loopback, which
/// `is_local_host` keeps for the laptop's own tests, is the phone itself here.
#[uniffi::export]
pub fn parse_qr(uri: String) -> Result<FfiQr, CoreError> {
    let q = QrPayload::parse(&uri).map_err(failed)?;
    let host = crate::request::session_host(&q.url).map_err(failed)?;
    let loopback = host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
    if loopback {
        return Err(CoreError::Failed("the session host is this phone itself; refused".into()));
    }
    Ok(FfiQr { url: q.url, commitment: q.commitment, secret: q.secret })
}

/// The value of the [`answer_mac_header`] header for a POST body (§3.3):
/// `HMAC-SHA256` under the secret the QR carried, so the laptop knows the
/// answer comes from the device that scanned it.
#[uniffi::export]
pub fn answer_mac(secret: String, body: Vec<u8>) -> Result<String, CoreError> {
    crate::request::answer_mac(&secret, &body).map_err(failed)
}

#[uniffi::export]
pub fn answer_mac_header() -> String {
    crate::request::MAC_HEADER.to_string()
}

/// Whether the laptop's reply to a POST is its confirmation of that answer
/// (§3.3). Only this means the laptop has the answer: any host in the path
/// can write a bare `200`.
#[uniffi::export]
pub fn verify_confirmation(secret: String, answer_body: Vec<u8>, reply: String) -> bool {
    crate::request::verify_confirmation_mac(&secret, &answer_body, &reply)
}

/// §2.1 step 3: the commitment, the type, the version, the expiry with the
/// clock tolerance, the label and the pins; the pins split by what this
/// build knows.
#[uniffi::export]
pub fn open_enrollment(bytes: Vec<u8>, commitment: String, now: u64) -> Result<FfiEnrollment, CoreError> {
    if crate::request::commitment(&bytes) != commitment {
        return Err(CoreError::Failed("the served request does not match the QR's commitment".into()));
    }
    let req = EnrollRequest::parse(&bytes, now, CLOCK_TOLERANCE_SECS).map_err(failed)?;
    let chain_id = req.chain_id().map_err(failed)?;
    let facts = crate::facts::for_chain(chain_id);
    if facts.entry_point.is_some_and(|known| known != req.entry_point) {
        return Err(CoreError::Failed(format!(
            "EntryPoint {} is not the one this build knows for chain {chain_id}; refusing the enrollment",
            req.entry_point.to_checksum(None)
        )));
    }
    let (kept, ignored) = req.split_pins(&facts);
    Ok(FfiEnrollment {
        chain_id,
        entry_point: req.entry_point.to_checksum(None),
        account: req.account.to_checksum(None),
        label: req.label.clone(),
        pins: kept.iter().map(|(a, l)| FfiPin { address: a.to_checksum(None), label: l.clone() }).collect(),
        ignored_pins: ignored
            .iter()
            .map(|p| format!("{}: the laptop says \"{}\" — {}", p.address.to_checksum(None), p.laptop_label, p.why))
            .collect(),
        chain_known: crate::facts::chains().contains(&chain_id),
        attestation_challenge: crate::enroll::attestation_challenge(&bytes).to_vec(),
    })
}

/// The phone's answer to an enrollment request (§4.3): the new key `x ‖ y`,
/// the tier the phone gave it, and the platform's evidence as DER
/// certificates, the key's first (empty where the platform has none).
#[uniffi::export]
pub fn enroll_answer(
    commitment: String,
    public_key: Vec<u8>,
    security_level: String,
    device_credential: bool,
    attestation: Vec<Vec<u8>>,
    app: FfiApp,
) -> Result<Vec<u8>, CoreError> {
    let pk = parse_key(&public_key)?;
    Ok(EnrollResponse::enrolled(&commitment, &pk, &security_level, device_credential, &attestation, app_info(app)).to_bytes())
}

/// The refusal of an enrollment request (§4.3).
#[uniffi::export]
pub fn enroll_refusal(commitment: String, reason: String, detail: Option<String>, app: FfiApp) -> Vec<u8> {
    EnrollResponse::refused(&commitment, &reason, detail, app_info(app)).to_bytes()
}

/// §6.1, with the facts this build embeds for the request's chain (§6.7).
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
        for pin in e.pins {
            a.pins.insert(parse_address(&pin.address)?, pin.label);
        }
        accounts.push(a);
    }
    let review = review::open_request_with_build_facts(&bytes, &commitment, now, &accounts);
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

/// The crate's version; a development build that knows the test chain says so.
#[uniffi::export]
pub fn core_version() -> String {
    crate::version().to_string()
}

fn app_info(app: FfiApp) -> AppInfo {
    AppInfo { platform: app.platform, version: app.version, core: crate::version().to_string() }
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

/// Strict: the short form below 128, the one-byte long form at or above it.
fn der_len(der: &[u8], i: &mut usize) -> Option<usize> {
    let b = *der.get(*i)?;
    *i += 1;
    if b < 0x80 {
        return Some(b as usize);
    }
    if b == 0x81 {
        let l = *der.get(*i)? as usize;
        *i += 1;
        return (l >= 0x80).then_some(l);
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
    // minimal: no leading zero unless the next byte needs it, never empty or negative
    let bytes = match bytes {
        [] => return None,
        [0x00, rest @ ..] if rest.first().map_or(false, |b| *b & 0x80 != 0) && rest.len() <= 32 => rest,
        [0x00, ..] => return None,
        [first, ..] if *first & 0x80 != 0 => return None,
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
        // non-minimal encodings are refused
        assert!(der_to_rs(&[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_none(), "long form for a short length");
        assert!(der_to_rs(&[0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01]).is_none(), "a needless leading zero");
        assert!(der_to_rs(&[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01]).is_none(), "a negative integer");
        assert_eq!(der_to_rs(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x7f]).unwrap().1[31], 0x7f);
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

    #[test]
    fn enrollment_is_opened_with_the_builds_view_of_its_pins() {
        use alloy_primitives::{address, B256};
        let known = address!("dd544A6F0220778Fff16F51B468656e73E32ae85");
        let unknown = address!("05a97329397200dF8795A882da0b5b1aD894EB97");
        let pins = [(known, "MyPolicy".to_string()), (unknown, "test paymaster".to_string())].into_iter().collect();
        let entry = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
        let pins2 = [(known, "MyPolicy".to_string())].into_iter().collect();
        // an enrollment for an EntryPoint other than the build's is refused
        let wrong_entry = EnrollRequest::new(84532, known, unknown, "owner-phone", B256::ZERO, 2_000_000_000).to_bytes();
        assert!(open_enrollment(wrong_entry.clone(), crate::request::commitment(&wrong_entry), 0).is_err());
        let bytes = EnrollRequest::new(84532, entry, unknown, "owner-phone", B256::ZERO, 2_000_000_000).with_pins(pins).to_bytes();
        let e = open_enrollment(bytes.clone(), crate::request::commitment(&bytes), 1_999_999_000).unwrap();
        assert!(e.chain_known && e.chain_id == 84532 && e.label == "owner-phone");
        assert_eq!(e.pins.len(), 1);
        assert_eq!((e.pins[0].address.as_str(), e.pins[0].label.as_str()), ("0x05a97329397200dF8795A882da0b5b1aD894EB97", "test paymaster"));
        assert_eq!(e.ignored_pins.len(), 1);
        assert!(e.ignored_pins[0].contains("the laptop says \"MyPolicy\" — this build knows the address as AgentPolicy"), "{}", e.ignored_pins[0]);
        assert_eq!(e.attestation_challenge, crate::enroll::attestation_challenge(&bytes).to_vec());
        // the answers the phone builds for this request are the ones the laptop reads
        let c = crate::request::commitment(&bytes);
        let app = || FfiApp { platform: "ios".into(), version: "0".into() };
        let sk = p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let p = sk.verifying_key().to_encoded_point(false);
        let xy = [p.x().unwrap().as_slice(), p.y().unwrap().as_slice()].concat();
        let answer = enroll_answer(c.clone(), xy.clone(), "secure-enclave".into(), false, vec![], app()).unwrap();
        let got = EnrollResponse::verify(&answer, &bytes, true).unwrap();
        assert_eq!([got.public_key.x, got.public_key.y].concat(), xy);
        assert_eq!((got.security_level.as_str(), got.device_credential, got.attestation.len()), ("secure-enclave", false, 0));
        assert_eq!(got.app.unwrap().platform, "ios");
        assert!(EnrollResponse::verify(&answer, &bytes, false).is_err(), "no evidence: only where the laptop allows that");
        assert!(enroll_answer(c.clone(), vec![1; 64], "secure-enclave".into(), false, vec![], app()).is_err(), "off the curve");
        let refusal = enroll_refusal(c, "user".into(), Some("declined on the phone".into()), app());
        assert!(matches!(EnrollResponse::verify(&refusal, &bytes, true), Err(crate::request::RequestError::Refused { .. })));
        // the commitment and the expiry are checked here, not in the app
        assert!(open_enrollment(bytes.clone(), "x".into(), 1_999_999_000).is_err());
        assert!(open_enrollment(bytes.clone(), crate::request::commitment(&bytes), 2_000_000_301).is_err());
        // a chain the build does not know: every pin is kept, and the phone can say so
        let other = EnrollRequest::new(1, known, unknown, "p", B256::ZERO, 2_000_000_000).with_pins(pins2).to_bytes();
        let e = open_enrollment(other.clone(), crate::request::commitment(&other), 0).unwrap();
        assert!(!e.chain_known && e.pins.len() == 1 && e.ignored_pins.is_empty());
    }

    /// `finish` over a reviewed request: a good signature becomes a verified
    /// response; one over another digest, or by another key, is refused.
    #[test]
    fn finish_builds_a_verified_response_or_refuses() {
        use crate::kernel;
        use crate::request::{SignRequest, SignResponse};
        use crate::user_op::PackedUserOp;
        use alloy_primitives::{address, Bytes, U256};
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let entry = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
        let account = address!("D62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628");
        let other = address!("7000000000000000000000000000000000000007");
        let op = PackedUserOp {
            sender: account,
            nonce: U256::from(1),
            init_code: Bytes::new(),
            call_data: kernel::execute_calldata(other, U256::from(1), &[]),
            account_gas_limits: kernel::pack_gas(300_000, 150_000),
            pre_verification_gas: U256::from(60_000),
            gas_fees: kernel::pack_gas(1, 1),
            paymaster_and_data: Bytes::new(),
        };
        let bytes = SignRequest::new(&op, entry, 31337, 2_000_000_000, None, Default::default(), None).to_bytes();
        let commitment = crate::request::commitment(&bytes);
        let enrolled = vec![FfiEnrolledAccount {
            chain_id: 31337,
            entry_point: format!("{entry}"),
            account: format!("{account}"),
            validator: None,
            gas_cap_wei: default_gas_cap_wei(),
            expert_mode: false,
            pins: vec![],
        }];
        let review = open_request(bytes.clone(), commitment, 1_999_999_000, enrolled).unwrap();
        assert!(matches!(review.verdict(), FfiVerdict::Sign));
        assert!(review.needs_second_confirmation(), "value to an unknown address is an effect");
        let digest = review.digest_to_sign().unwrap();
        let key = |n: u8| {
            let sk = p256::ecdsa::SigningKey::from_bytes(&[n; 32].into()).unwrap();
            let p = sk.verifying_key().to_encoded_point(false);
            (sk, [p.x().unwrap().as_slice(), p.y().unwrap().as_slice()].concat())
        };
        let (sk, xy) = key(5);
        let app = || FfiApp { platform: "test".into(), version: "0".into() };
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        let resp = review.finish(sig.to_der().as_bytes().to_vec(), xy.clone(), app()).unwrap();
        let pk = parse_key(&xy).unwrap();
        let expected = alloy_primitives::B256::from_slice(&digest);
        assert!(SignResponse::verify(&resp, &bytes, &pk, expected).is_ok(), "the laptop accepts what finish built");
        // a signature over another digest
        let wrong: p256::ecdsa::Signature = sk.sign_prehash(&[9u8; 32]).unwrap();
        assert!(review.finish(wrong.to_der().as_bytes().to_vec(), xy.clone(), app()).is_err());
        // the right digest, another key
        let (_, xy2) = key(6);
        assert!(review.finish(sig.to_der().as_bytes().to_vec(), xy2, app()).is_err());
        // a refusal names the request
        let refused = review.refuse("user".into(), None, app());
        assert!(matches!(SignResponse::verify(&refused, &bytes, &pk, expected), Err(crate::request::RequestError::Refused { .. })));
        // loopback is this phone
        let k = "BwcHBwcHBwcHBwcHBwcHBw"; // 16 bytes, base64url
        assert!(parse_qr(format!("tpmsign:1?u=http://127.0.0.1:1/s/x&h=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&k={k}")).is_err());
        let qr = parse_qr(format!("tpmsign:1?u=http://10.0.0.1:1/s/x&h=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&k={k}")).unwrap();
        // the phone's MAC over an answer is what the laptop verifies
        let mac = answer_mac(qr.secret.clone(), refused.clone()).unwrap();
        assert!(crate::request::verify_answer_mac(&qr.secret, &refused, &mac));
        assert_eq!(answer_mac_header(), "X-TpmSign-Mac");
        let confirmation = crate::request::confirmation_mac(&qr.secret, &refused).unwrap();
        assert!(verify_confirmation(qr.secret.clone(), refused.clone(), confirmation));
        assert!(!verify_confirmation(qr.secret.clone(), refused.clone(), "ok".into()));
    }
}
