//! Android key attestation, verified on the laptop at enrollment
//! (docs/MOBILE_OWNER_DESIGN.md §5.2, §5.6): the certificate chain the
//! phone returns must end at one of Google's hardware attestation roots,
//! and the record inside the key's certificate must describe the key the
//! design asks for — made in secure hardware for this very enrollment
//! request, by our app, usable only after a biometric check.
//!
//! What this is evidence of: where the key lives and which app made it. Not
//! whose phone it is — that is the session secret's job (`phone.rs`), since
//! anyone can hold a genuine phone with the published app.
//!
//! Signatures are checked by `aws-lc-rs` over the exact bytes parsed by
//! `der.rs`. The rules that matter beyond "the signatures verify": every
//! issuer is a CA, and only the first certificate may carry the attestation
//! record — otherwise an attested key, which signs whatever its owner asks,
//! could issue a certificate with a record of its owner's choosing.

use std::collections::HashMap;

use alloy::primitives::U256;
use aws_lc_rs::signature::{self as sig, UnparsedPublicKey, VerificationAlgorithm};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hw_signer::PublicKey;

use crate::der::{self, Tlv};

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// Android's `KeyDescription`, 1.3.6.1.4.1.11129.2.1.17.
const OID_KEY_DESCRIPTION: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];

/// Google's hardware attestation roots as published at
/// `https://android.googleapis.com/attestation/root` (fetched 2026-11-12):
/// the RSA-4096 root of keys provisioned at the factory, and the P-384 root
/// of remotely provisioned keys. A chain is accepted by the root's public
/// key, not its certificate: Google has reissued the RSA certificate.
const GOOGLE_ROOTS: &[(&str, &str)] = &[
    ("Google's factory-provisioning root (RSA-4096)", include_str!("attestation/google-root-rsa.pem")),
    ("Google's remote-provisioning root (P-384)", include_str!("attestation/google-root-p384.pem")),
];

/// Where Google publishes revoked attestation certificates.
pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";

/// The owner app's package names this CLI accepts. Provisional: the
/// application id is fixed by the owner before distribution
/// (docs/APP_ATTEST_ORG.md §8).
pub const ANDROID_PACKAGES: &[&str] = &["dev.tpmsign.owner.spike"];

/// T14: the first `versionCode` whose answers carry the session MAC and that
/// keeps a key only on the laptop's authenticated confirmation.
pub const MIN_ANDROID_VERSION_CODE: u64 = 10;

/// SHA-256 digests of the signing certificates of distributed builds, per
/// channel (§5.2, docs/MOBILE_DEV_MODE.md §2.2). Empty until the project
/// has a signing key: a developer's own build is accepted with
/// `--android-app-digest`, naming their own certificate.
pub const PINNED_SIGNING_DIGESTS: &[[u8; 32]] = &[];

/// Chains seen in practice have four or five certificates.
const MAX_CHAIN: usize = 10;

/// A trust anchor: a name for messages and the root's SubjectPublicKeyInfo.
#[derive(Clone, Debug)]
pub struct Root {
    pub name: String,
    pub spki: Vec<u8>,
}

pub fn google_roots() -> Vec<Root> {
    GOOGLE_ROOTS
        .iter()
        .map(|(name, pem)| {
            let der = pem_to_der(pem).expect("an embedded root certificate");
            let cert = Cert::parse(&der).expect("an embedded root certificate");
            Root { name: name.to_string(), spki: cert.spki.to_vec() }
        })
        .collect()
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    B64.decode(body.trim()).map_err(|e| format!("PEM: {e}"))
}

/// Where the key lives, as the attestation says (§5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    StrongBox,
    Tee,
}

impl Tier {
    /// The word used in the enrollment answer and the config.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::StrongBox => "strongbox",
            Tier::Tee => "tee",
        }
    }
}

/// What the enrollment must match.
pub struct Expect<'a> {
    /// `owner_core::enroll::attestation_challenge(request_bytes)`.
    pub challenge: [u8; 32],
    /// The key the enrollment answer names.
    pub public_key: PublicKey,
    /// Whether the enrollment chose the device-PIN opt-in (§5.4).
    pub device_credential: bool,
    /// Unix seconds: certificates must be valid now.
    pub now: u64,
    /// The app's package names this CLI accepts.
    pub packages: &'a [&'a str],
    /// SHA-256 digests of the signing certificates accepted for the app's
    /// channel (§5.2, T6).
    pub signing_digests: &'a [[u8; 32]],
    /// T14: the lowest `versionCode` accepted.
    pub min_version_code: u64,
}

/// A verified attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    pub tier: Tier,
    /// The trust anchor the chain ended at.
    pub root: String,
    pub chain_len: usize,
    pub attestation_version: u64,
    pub package: String,
    pub version_code: u64,
    pub signing_digest: [u8; 32],
    /// Shown, not refused: a boot state other than Verified, for example.
    pub warnings: Vec<String>,
    /// Each certificate's serial number, for the revocation list.
    pub serials: Vec<Vec<u8>>,
}

enum Key<'a> {
    P256(&'a [u8]),
    P384(&'a [u8]),
    Rsa(&'a [u8]),
}

struct Cert<'a> {
    /// The signed part, exactly as it stands in the certificate.
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: u64,
    not_after: u64,
    spki: &'a [u8],
    key: Key<'a>,
    is_ca: bool,
    key_description: Option<&'a [u8]>,
}

impl<'a> Cert<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, String> {
        let outer = der::read_only(der)?.sequence("certificate")?;
        let [tbs, alg, signature] = outer[..] else {
            return Err("certificate: not tbsCertificate, signatureAlgorithm, signatureValue".into());
        };
        let sig_alg = algorithm(alg, "signatureAlgorithm")?.0;
        let signature = signature.bit_string("signatureValue")?;
        let mut fields = tbs.sequence("tbsCertificate")?.into_iter().peekable();
        if fields.peek().is_some_and(|t| t.is_context(0)) {
            fields.next(); // version
        }
        let mut next = |what: &str| fields.next().ok_or(format!("tbsCertificate: no {what}"));
        // a serial number is compared, never computed with: take its content as it stands
        let serial = next("serialNumber")?;
        if serial.class != der::UNIVERSAL || serial.number != der::INTEGER || serial.value.is_empty() {
            return Err("tbsCertificate: serialNumber is not an integer".into());
        }
        if algorithm(next("signature")?, "tbsCertificate.signature")?.0 != sig_alg {
            return Err("certificate: the signed and the outer signature algorithm differ".into());
        }
        let issuer = next("issuer")?;
        issuer.sequence("issuer")?;
        let validity = next("validity")?.sequence("validity")?;
        let [not_before, not_after] = validity[..] else {
            return Err("validity: not two times".into());
        };
        let subject = next("subject")?;
        subject.sequence("subject")?;
        let spki = next("subjectPublicKeyInfo")?;
        let spki_fields = spki.sequence("subjectPublicKeyInfo")?;
        let [key_alg, key_bits] = spki_fields[..] else {
            return Err("subjectPublicKeyInfo: not algorithm and key".into());
        };
        let (key_oid, key_params) = algorithm(key_alg, "subjectPublicKeyInfo.algorithm")?;
        let key_bytes = key_bits.bit_string("subjectPublicKey")?;
        let key = if key_oid == OID_EC_PUBLIC_KEY {
            let curve = key_params.ok_or("an EC key without a named curve")?.oid("the EC key's curve")?;
            match (curve, key_bytes.len(), key_bytes.first()) {
                (c, 65, Some(4)) if c == OID_P256 => Key::P256(key_bytes),
                (c, 97, Some(4)) if c == OID_P384 => Key::P384(key_bytes),
                _ => return Err("an EC key that is not an uncompressed P-256 or P-384 point".into()),
            }
        } else if key_oid == OID_RSA {
            Key::Rsa(key_bytes)
        } else {
            return Err("a public key that is neither EC nor RSA".into());
        };
        let (mut is_ca, mut key_description) = (false, None);
        let mut seen: Vec<&[u8]> = Vec::new();
        for field in fields {
            if !field.is_context(3) {
                if field.is_context(1) || field.is_context(2) {
                    continue; // issuer and subject unique ids
                }
                return Err("tbsCertificate: an unexpected field".into());
            }
            for ext in field.explicit("extensions")?.sequence("extensions")? {
                let parts = ext.sequence("extension")?;
                let (oid, value) = match parts[..] {
                    [oid, value] => (oid, value),
                    [oid, critical, value] => {
                        critical.boolean("extension.critical")?;
                        (oid, value)
                    }
                    _ => return Err("extension: not an id, an optional flag and a value".into()),
                };
                let (oid, value) = (oid.oid("extension id")?, value.octets("extension value")?);
                if seen.contains(&oid) {
                    return Err("certificate: the same extension twice".into());
                }
                seen.push(oid);
                if oid == OID_BASIC_CONSTRAINTS {
                    let fields = der::read_only(value)?.sequence("basicConstraints")?;
                    is_ca = match fields.first() {
                        Some(f) if f.class == der::UNIVERSAL && f.number == der::BOOLEAN => f.boolean("basicConstraints.cA")?,
                        _ => false,
                    };
                } else if oid == OID_KEY_DESCRIPTION {
                    key_description = Some(value);
                }
            }
        }
        Ok(Cert {
            tbs: tbs.raw,
            sig_alg,
            signature,
            serial: serial.value,
            issuer: issuer.raw,
            subject: subject.raw,
            not_before: time(not_before)?,
            not_after: time(not_after)?,
            spki: spki.raw,
            key,
            is_ca,
            key_description,
        })
    }

    /// `self` is signed by the holder of `issuer_key`.
    fn signed_by(&self, issuer_key: &Key<'_>) -> Result<(), String> {
        let (alg, key): (&dyn VerificationAlgorithm, &[u8]) = match (self.sig_alg, issuer_key) {
            (a, Key::P256(k)) if a == OID_ECDSA_SHA256 => (&sig::ECDSA_P256_SHA256_ASN1, k),
            (a, Key::P256(k)) if a == OID_ECDSA_SHA384 => (&sig::ECDSA_P256_SHA384_ASN1, k),
            (a, Key::P384(k)) if a == OID_ECDSA_SHA256 => (&sig::ECDSA_P384_SHA256_ASN1, k),
            (a, Key::P384(k)) if a == OID_ECDSA_SHA384 => (&sig::ECDSA_P384_SHA384_ASN1, k),
            (a, Key::Rsa(k)) if a == OID_RSA_SHA256 => (&sig::RSA_PKCS1_2048_8192_SHA256, k),
            (a, Key::Rsa(k)) if a == OID_RSA_SHA384 => (&sig::RSA_PKCS1_2048_8192_SHA384, k),
            (a, Key::Rsa(k)) if a == OID_RSA_SHA512 => (&sig::RSA_PKCS1_2048_8192_SHA512, k),
            _ => return Err("a signature algorithm this verifier does not accept for the issuer's key".into()),
        };
        UnparsedPublicKey::new(alg, key).verify(self.tbs, self.signature).map_err(|_| "the signature does not verify".to_string())
    }
}

/// `AlgorithmIdentifier`: the OID's content and the parameters, if any.
fn algorithm<'a>(t: Tlv<'a>, what: &str) -> Result<(&'a [u8], Option<Tlv<'a>>), String> {
    let fields = t.sequence(what)?;
    match fields[..] {
        [oid] => Ok((oid.oid(what)?, None)),
        [oid, params] => Ok((oid.oid(what)?, Some(params))),
        _ => Err(format!("{what}: not an algorithm identifier")),
    }
}

/// UTCTime or GeneralizedTime, in the `…Z` form X.509 requires, as unix seconds.
fn time(t: Tlv<'_>) -> Result<u64, String> {
    let bad = || "certificate: a time that is not YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ".to_string();
    let text = std::str::from_utf8(t.value).map_err(|_| bad())?;
    let digits = text.strip_suffix('Z').filter(|d| d.bytes().all(|b| b.is_ascii_digit())).ok_or_else(bad)?;
    let n = |range: std::ops::Range<usize>| digits[range].parse::<i64>().map_err(|_| bad());
    let (year, rest) = match (t.class, t.number, digits.len()) {
        (der::UNIVERSAL, der::UTC_TIME, 12) => {
            let yy = n(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        (der::UNIVERSAL, der::GENERALIZED_TIME, 14) => (n(0..4)?, 4),
        _ => return Err(bad()),
    };
    let (month, day, hour, minute, second) = (n(rest..rest + 2)?, n(rest + 2..rest + 4)?, n(rest + 4..rest + 6)?, n(rest + 6..rest + 8)?, n(rest + 8..rest + 10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return Err(bad());
    }
    // days from the civil date (Howard Hinnant's algorithm)
    let y = if month <= 2 { year - 1 } else { year };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).map_err(|_| "certificate: a time before 1970".to_string())
}

/// One authorization list of the key description: the tags the checks read.
#[derive(Default)]
struct AuthList<'a> {
    purposes: Option<Vec<u64>>,
    algorithm: Option<u64>,
    key_size: Option<u64>,
    digests: Option<Vec<u64>>,
    ec_curve: Option<u64>,
    no_auth_required: bool,
    user_auth_type: Option<u64>,
    auth_timeout: Option<u64>,
    origin: Option<u64>,
    root_of_trust: Option<Tlv<'a>>,
    application_id: Option<&'a [u8]>,
}

impl<'a> AuthList<'a> {
    fn parse(list: Tlv<'a>, what: &str) -> Result<Self, String> {
        let mut out = AuthList::default();
        let ints = |t: Tlv<'a>, what: &str| t.set(what)?.into_iter().map(|i| i.uint(what)).collect::<Result<Vec<_>, _>>();
        let mut seen = Vec::new();
        for field in list.sequence(what)? {
            if field.class != der::CONTEXT {
                return Err(format!("{what}: a field without a context tag"));
            }
            if seen.contains(&field.number) {
                return Err(format!("{what}: tag {} twice", field.number));
            }
            seen.push(field.number);
            let inner = field.explicit(what)?;
            match field.number {
                1 => out.purposes = Some(ints(inner, "purpose")?),
                2 => out.algorithm = Some(inner.uint("algorithm")?),
                3 => out.key_size = Some(inner.uint("keySize")?),
                5 => out.digests = Some(ints(inner, "digest")?),
                10 => out.ec_curve = Some(inner.uint("ecCurve")?),
                503 => out.no_auth_required = true,
                504 => out.user_auth_type = Some(inner.uint("userAuthType")?),
                505 => out.auth_timeout = Some(inner.uint("authTimeout")?),
                702 => out.origin = Some(inner.uint("origin")?),
                704 => out.root_of_trust = Some(inner),
                709 => out.application_id = Some(inner.octets("attestationApplicationId")?),
                _ => {} // dates, patch levels, device ids: not part of what the key may do
            }
        }
        Ok(out)
    }
}

/// Verify the chain and the key's attestation record against `expect`.
/// `chain` is DER, the key's certificate first, as the phone returns it.
pub fn verify_android(chain: &[Vec<u8>], roots: &[Root], expect: &Expect<'_>) -> Result<Attested, String> {
    if chain.len() < 2 || chain.len() > MAX_CHAIN {
        return Err(format!("a chain of {} certificates", chain.len()));
    }
    let certs = chain
        .iter()
        .enumerate()
        .map(|(i, der)| Cert::parse(der).map_err(|e| format!("certificate {i}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    // the chain: each certificate signed by the next, which must be a CA and valid now
    for (i, cert) in certs.iter().enumerate() {
        if expect.now < cert.not_before || expect.now > cert.not_after {
            return Err(format!("certificate {i} is not valid now (expired, or not yet valid: check this machine's clock)"));
        }
        if i > 0 && cert.key_description.is_some() {
            return Err(format!("certificate {i} carries an attestation record; only the key's own certificate may"));
        }
        let Some(issuer) = certs.get(i + 1) else { break };
        if cert.issuer != issuer.subject {
            return Err(format!("certificate {i} was not issued by certificate {}", i + 1));
        }
        if !issuer.is_ca {
            return Err(format!("certificate {} issued certificate {i} but is not a CA", i + 1));
        }
        cert.signed_by(&issuer.key).map_err(|e| format!("certificate {i}: {e}"))?;
    }
    let top = certs.last().expect("at least two");
    if top.issuer != top.subject || !top.is_ca {
        return Err("the chain does not end in a self-signed CA certificate".into());
    }
    top.signed_by(&top.key).map_err(|e| format!("the root certificate: {e}"))?;
    let root = roots.iter().find(|r| r.spki == top.spki).ok_or("the chain does not end at a hardware attestation root this CLI trusts")?;

    // the key
    let leaf = &certs[0];
    let Key::P256(point) = leaf.key else {
        return Err("the attested key is not a P-256 key".into());
    };
    if point[1..33] != expect.public_key.x || point[33..] != expect.public_key.y {
        return Err("the attested key is not the key the phone's answer names".into());
    }

    // the record
    let record = leaf.key_description.ok_or("the key's certificate carries no attestation record")?;
    let fields = der::read_only(record)?.sequence("KeyDescription")?;
    let [version, att_level, _keymint_version, km_level, challenge, _unique_id, software, hardware] = fields[..] else {
        return Err("KeyDescription: not the eight fields of the schema".into());
    };
    let attestation_version = version.uint("attestationVersion")?;
    if attestation_version < 3 {
        return Err(format!("attestation version {attestation_version} is older than Keymaster 4"));
    }
    let tier = match (att_level.enumerated("attestationSecurityLevel")?, km_level.enumerated("keyMintSecurityLevel")?) {
        (1, 1) => Tier::Tee,
        (2, 2) => Tier::StrongBox,
        (0, _) | (_, 0) => return Err("the key or its attestation is software-backed".into()),
        (a, k) => return Err(format!("the attestation's security level ({a}) and the key's ({k}) differ")),
    };
    if challenge.octets("attestationChallenge")? != expect.challenge {
        return Err("the attestation was not made for this enrollment request (challenge mismatch)".into());
    }
    let software = AuthList::parse(software, "softwareEnforced")?;
    let hw = AuthList::parse(hardware, "hardwareEnforced")?;

    // what the hardware enforces about the key (§5.2)
    if hw.algorithm != Some(3) || !(hw.ec_curve == Some(1) || (hw.ec_curve.is_none() && hw.key_size == Some(256))) {
        return Err("the hardware does not attest an EC P-256 key".into());
    }
    if hw.purposes.as_deref() != Some(&[2]) {
        return Err("the key's purposes are not exactly: sign".into());
    }
    if !hw.digests.as_deref().is_some_and(|d| d.contains(&0)) {
        return Err("the key does not allow DIGEST_NONE, which the account's validator needs".into());
    }
    if hw.origin != Some(0) {
        return Err("the key was not generated in the secure hardware (imported or unknown origin)".into());
    }
    if hw.no_auth_required || software.no_auth_required {
        return Err("the key can be used without user authentication".into());
    }
    if hw.auth_timeout.is_some_and(|t| t != 0) {
        return Err("the key stays unlocked for a time window instead of asking on every use".into());
    }
    // HardwareAuthenticatorType: 1 = the device credential, 2 = biometric
    let wanted_auth = if expect.device_credential { 3 } else { 2 };
    if hw.user_auth_type != Some(wanted_auth) {
        return Err(format!(
            "the key's user authentication type is {:?}, not {wanted_auth} ({})",
            hw.user_auth_type,
            if expect.device_credential { "biometric or the device PIN, as this enrollment chose" } else { "biometric only" }
        ));
    }

    // the device's state
    let mut warnings = Vec::new();
    let rot = hw.root_of_trust.ok_or("the hardware attests no root of trust")?.sequence("rootOfTrust")?;
    let (locked, state) = match rot[..] {
        [_key, locked, state] | [_key, locked, state, _] => (locked.boolean("deviceLocked")?, state.enumerated("verifiedBootState")?),
        _ => return Err("rootOfTrust: not the fields of the schema".into()),
    };
    if !locked {
        return Err("the phone's bootloader is unlocked".into());
    }
    // shown, not refused (§5.2): the locked bootloader is the rule, the state is information
    match state {
        0 => {}
        1 => warnings.push("verified boot state: SelfSigned — a custom operating system on a locked bootloader".to_string()),
        2 => warnings.push("verified boot state: Unverified".to_string()),
        s => warnings.push(format!("verified boot state: Failed ({s})")),
    }

    // which app made the key: asserted by the phone's operating system, hence the boot state above
    let app = software.application_id.or(hw.application_id).ok_or("the attestation names no application")?;
    let app = der::read_only(app)?.sequence("attestationApplicationId")?;
    let [packages, digests] = app[..] else {
        return Err("attestationApplicationId: not packages and signature digests".into());
    };
    let packages = packages.set("package infos")?;
    let [package] = packages[..] else {
        return Err(format!("the key was made by {} packages sharing a user id; exactly one is expected", packages.len()));
    };
    let package = package.sequence("package info")?;
    let [name, version_code] = package[..] else {
        return Err("package info: not a name and a version".into());
    };
    let name = String::from_utf8_lossy(name.octets("package name")?).into_owned();
    let version_code = version_code.uint("package version")?;
    if !expect.packages.contains(&name.as_str()) {
        return Err(format!("the key was made by the app {name:?}, not by the owner app"));
    }
    if version_code < expect.min_version_code {
        return Err(format!("the app's version code {version_code} is below the minimum {}; update the app", expect.min_version_code));
    }
    let digests = digests.set("signature digests")?;
    let [digest] = digests[..] else {
        return Err(format!("the app has {} signing certificates; exactly one is expected", digests.len()));
    };
    let signing_digest: [u8; 32] = digest.octets("signature digest")?.try_into().map_err(|_| "a signing digest that is not SHA-256")?;
    if !expect.signing_digests.contains(&signing_digest) {
        return Err(format!(
            "the app is signed by a certificate this CLI does not pin (SHA-256 {}). If this is your own build of the app, \
             pass --android-app-digest {}",
            hex::encode(signing_digest),
            hex::encode(signing_digest)
        ));
    }

    Ok(Attested {
        tier,
        root: root.name.clone(),
        chain_len: certs.len(),
        attestation_version,
        package: name,
        version_code,
        signing_digest,
        warnings,
        serials: certs.iter().map(|c| c.serial.to_vec()).collect(),
    })
}

/// Google's status list, fetched now. `Err` says why it could not be: the
/// caller reports that the revocation check was skipped (§5.2: "checked when
/// online, and the result says so").
pub fn fetch_status_list() -> Result<StatusList, String> {
    use alloy::transports::http::reqwest;
    let fetch = async {
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8)).build().map_err(|e| e.to_string())?;
        let resp = client.get(STATUS_URL).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        StatusList::parse(&resp.bytes().await.map_err(|e| e.to_string())?)
    };
    // the caller is synchronous code inside the CLI's runtime
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fetch)),
        Err(_) => Err("no network runtime".into()),
    }
}

/// The SHA-256 digest of a signing certificate, as `apksigner verify
/// --print-certs` prints it and `--android-app-digest` takes it.
pub fn parse_digest(text: &str) -> Result<[u8; 32], String> {
    let clean: String = text.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    hex::decode(clean.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| "a signing-certificate digest is 32 bytes of hex (SHA-256)".to_string())
}

/// Google's list of revoked attestation certificates
/// (`{"entries": {"<serial>": {"status": "REVOKED", "reason": "…"}}}`).
pub struct StatusList(HashMap<String, String>);

impl StatusList {
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_slice(json).map_err(|e| format!("the status list: {e}"))?;
        let entries = v.get("entries").and_then(|e| e.as_object()).ok_or("the status list has no entries")?;
        Ok(Self(
            entries
                .iter()
                .map(|(serial, e)| {
                    let field = |k: &str| e.get(k).and_then(|s| s.as_str()).unwrap_or("?").to_string();
                    (serial.to_ascii_lowercase(), format!("{} ({})", field("status"), field("reason")))
                })
                .collect(),
        ))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The first of `serials` the list names, with its status. The list
    /// writes a serial in hexadecimal or in decimal; both are looked up.
    pub fn listed(&self, serials: &[Vec<u8>]) -> Option<(String, String)> {
        serials.iter().find_map(|serial| {
            let n = U256::try_from_be_slice(serial)?;
            [format!("{n:x}"), n.to_string()].into_iter().find_map(|form| self.0.get(&form).map(|status| (form, status.clone())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::write::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, RSA_PKCS1_SHA256};
    use sha2::{Digest, Sha256};

    const NOW: u64 = 1_800_000_000; // 2027-01-15
    const PACKAGE: &str = "dev.tpmsign.owner.spike";
    const SIGNER_DIGEST: [u8; 32] = [0xc3; 32];

    /// A key that signs test certificates.
    enum TestKey {
        P256(EcdsaKeyPair),
        P384(EcdsaKeyPair),
        Rsa(aws_lc_rs::rsa::KeyPair),
    }

    impl TestKey {
        fn p256() -> Self {
            TestKey::P256(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap())
        }
        fn p384() -> Self {
            TestKey::P384(EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).unwrap())
        }
        fn rsa() -> Self {
            TestKey::Rsa(aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap())
        }
        fn spki(&self) -> Vec<u8> {
            match self {
                TestKey::P256(k) => seq(&[seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_P256)]), bit_string(k.public_key().as_ref())]),
                TestKey::P384(k) => seq(&[seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_P384)]), bit_string(k.public_key().as_ref())]),
                TestKey::Rsa(k) => seq(&[seq(&[oid(OID_RSA), vec![0x05, 0x00]]), bit_string(k.public_key().as_ref())]),
            }
        }
        fn sig_alg(&self) -> Vec<u8> {
            match self {
                TestKey::P256(_) => seq(&[oid(OID_ECDSA_SHA256)]),
                TestKey::P384(_) => seq(&[oid(OID_ECDSA_SHA384)]),
                TestKey::Rsa(_) => seq(&[oid(OID_RSA_SHA256), vec![0x05, 0x00]]),
            }
        }
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                TestKey::P256(k) | TestKey::P384(k) => k.sign(&rng, message).unwrap().as_ref().to_vec(),
                TestKey::Rsa(k) => {
                    let mut out = vec![0u8; k.public_modulus_len()];
                    k.sign(&RSA_PKCS1_SHA256, &rng, message, &mut out).unwrap();
                    out
                }
            }
        }
        fn public_key(&self) -> PublicKey {
            let TestKey::P256(k) = self else { panic!("the phone's key is P-256") };
            let p = k.public_key().as_ref();
            PublicKey { x: p[1..33].try_into().unwrap(), y: p[33..].try_into().unwrap() }
        }
    }

    fn name(cn: &str) -> Vec<u8> {
        seq(&[set(&[seq(&[oid(&[0x55, 0x04, 0x03]), tlv(der::UNIVERSAL, false, 12, cn.as_bytes())])])])
    }

    struct CertSpec<'a> {
        subject: &'a str,
        issuer: &'a str,
        key: &'a TestKey,
        signer: &'a TestKey,
        ca: bool,
        not_after: &'a str,
        key_description: Option<Vec<u8>>,
    }

    fn cert(spec: CertSpec<'_>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if spec.ca {
            extensions.push(seq(&[oid(OID_BASIC_CONSTRAINTS), boolean(true), octets(&seq(&[boolean(true)]))]));
        }
        if let Some(record) = &spec.key_description {
            extensions.push(seq(&[oid(OID_KEY_DESCRIPTION), octets(record)]));
        }
        let tbs = seq(&[
            explicit(0, &uint(2)),
            uint(0x0102_0304),
            spec.signer.sig_alg(),
            name(spec.issuer),
            seq(&[utc_time("250101000000Z"), utc_time(spec.not_after)]),
            name(spec.subject),
            spec.key.spki(),
            explicit(3, &seq(&extensions)),
        ]);
        seq(&[tbs.clone(), spec.signer.sig_alg(), bit_string(&spec.signer.sign(&tbs))])
    }

    /// What the tests vary in the key's record.
    #[derive(Clone)]
    struct Record {
        levels: (u64, u64),
        challenge: [u8; 32],
        purposes: Vec<u64>,
        digests: Vec<u64>,
        user_auth_type: Option<u64>,
        auth_timeout: Option<u64>,
        no_auth: bool,
        origin: u64,
        locked: bool,
        boot_state: u64,
        package: String,
        version_code: u64,
        signer_digest: [u8; 32],
    }

    impl Record {
        fn good(challenge: [u8; 32]) -> Self {
            Record {
                levels: (1, 1),
                challenge,
                purposes: vec![2],
                digests: vec![0, 4],
                user_auth_type: Some(2),
                auth_timeout: None,
                no_auth: false,
                origin: 0,
                locked: true,
                boot_state: 0,
                package: PACKAGE.into(),
                version_code: 10,
                signer_digest: SIGNER_DIGEST,
            }
        }

        /// The layout of a real record: versions 400, the app in the
        /// software list, the key and the root of trust in the hardware list.
        fn der(&self) -> Vec<u8> {
            let app = seq(&[
                set(&[seq(&[octets(self.package.as_bytes()), uint(self.version_code)])]),
                set(&[octets(&self.signer_digest)]),
            ]);
            let software = seq(&[explicit(701, &uint(1_800_000_000_000)), explicit(709, &octets(&app))]);
            let ints = |v: &[u64]| set(&v.iter().map(|i| uint(*i)).collect::<Vec<_>>());
            let mut hw = vec![explicit(1, &ints(&self.purposes)), explicit(2, &uint(3)), explicit(3, &uint(256)), explicit(5, &ints(&self.digests)), explicit(10, &uint(1))];
            if self.no_auth {
                hw.push(explicit(503, &[0x05, 0x00]));
            }
            if let Some(t) = self.user_auth_type {
                hw.push(explicit(504, &uint(t)));
            }
            if let Some(t) = self.auth_timeout {
                hw.push(explicit(505, &uint(t)));
            }
            hw.push(explicit(509, &[0x05, 0x00]));
            hw.push(explicit(702, &uint(self.origin)));
            hw.push(explicit(704, &seq(&[octets(&[1; 32]), boolean(self.locked), enumerated(self.boot_state), octets(&[2; 32])])));
            hw.push(explicit(706, &uint(202_611)));
            seq(&[uint(400), enumerated(self.levels.0), uint(400), enumerated(self.levels.1), octets(&self.challenge), octets(&[]), software, seq(&hw)])
        }
    }

    /// root → intermediate → the hardware's attestation key → the phone's key.
    struct Pki {
        root: TestKey,
        mid: TestKey,
        tee: TestKey,
        phone: TestKey,
    }

    impl Pki {
        fn new(root: TestKey) -> Self {
            Pki { root, mid: TestKey::p384(), tee: TestKey::p256(), phone: TestKey::p256() }
        }
        fn roots(&self) -> Vec<Root> {
            vec![Root { name: "a test root".into(), spki: self.root.spki() }]
        }
        fn upper(&self) -> Vec<Vec<u8>> {
            let c = |subject, issuer, key, signer| cert(CertSpec { subject, issuer, key, signer, ca: true, not_after: "350101000000Z", key_description: None });
            vec![c("tee", "mid", &self.tee, &self.mid), c("mid", "root", &self.mid, &self.root), c("root", "root", &self.root, &self.root)]
        }
        fn leaf(&self, record: &Record) -> Vec<u8> {
            cert(CertSpec {
                subject: "Android Keystore Key",
                issuer: "tee",
                key: &self.phone,
                signer: &self.tee,
                ca: false,
                not_after: "480101000000Z",
                key_description: Some(record.der()),
            })
        }
        fn chain(&self, record: &Record) -> Vec<Vec<u8>> {
            [vec![self.leaf(record)], self.upper()].concat()
        }
        fn expect(&self) -> (PublicKey, [u8; 32]) {
            (self.phone.public_key(), [0x5a; 32])
        }
    }

    fn expect(public_key: PublicKey, challenge: [u8; 32]) -> Expect<'static> {
        Expect {
            challenge,
            public_key,
            device_credential: false,
            now: NOW,
            packages: &[PACKAGE],
            signing_digests: &[SIGNER_DIGEST],
            min_version_code: 10,
        }
    }

    #[test]
    fn a_good_chain_is_verified_for_both_kinds_of_root() {
        for root in [TestKey::p384(), TestKey::rsa()] {
            let pki = Pki::new(root);
            let (key, challenge) = pki.expect();
            let a = verify_android(&pki.chain(&Record::good(challenge)), &pki.roots(), &expect(key, challenge)).unwrap();
            assert_eq!((a.tier, a.chain_len, a.attestation_version), (Tier::Tee, 4, 400));
            assert_eq!((a.package.as_str(), a.version_code, a.signing_digest), (PACKAGE, 10, SIGNER_DIGEST));
            assert!(a.warnings.is_empty() && a.serials.len() == 4);
        }
        // StrongBox is read from the record, and both levels must say it
        let pki = Pki::new(TestKey::p384());
        let (key, challenge) = pki.expect();
        let strongbox = Record { levels: (2, 2), ..Record::good(challenge) };
        assert_eq!(verify_android(&pki.chain(&strongbox), &pki.roots(), &expect(key, challenge)).unwrap().tier, Tier::StrongBox);
    }

    #[test]
    fn the_chain_must_hold() {
        let pki = Pki::new(TestKey::p384());
        let (key, challenge) = pki.expect();
        let good = Record::good(challenge);
        let check = |chain: &[Vec<u8>], roots: &[Root], now: u64| verify_android(chain, roots, &Expect { now, ..expect(key, challenge) });
        let refused = |r: Result<Attested, String>, why: &str| {
            let e = r.expect_err(why);
            assert!(e.contains(why), "expected {why:?}, got {e:?}");
        };
        // another root than the trusted one
        let other = Pki::new(TestKey::p384());
        refused(check(&pki.chain(&good), &other.roots(), NOW), "does not end at a hardware attestation root");
        // a byte of the signed part changed
        let mut chain = pki.chain(&good);
        let at = chain[0].len() / 2;
        chain[0][at] ^= 1;
        assert!(check(&chain, &pki.roots(), NOW).is_err());
        // expired, and not yet valid
        refused(check(&pki.chain(&good), &pki.roots(), 2_100_000_000), "not valid now");
        refused(check(&pki.chain(&good), &pki.roots(), 1_600_000_000), "not valid now");
        // the chain cut short, or out of order
        let chain = pki.chain(&good);
        refused(check(&chain[..1], &pki.roots(), NOW), "a chain of 1");
        refused(check(&[chain[0].clone(), chain[2].clone(), chain[3].clone()], &pki.roots(), NOW), "was not issued by");
        // without its root: the last certificate is not self-signed
        refused(check(&chain[..3], &pki.roots(), NOW), "does not end in a self-signed CA");
    }

    /// The attack the CA rule exists for: a genuine attested key signs a
    /// certificate for another key, with a record of the attacker's choosing.
    #[test]
    fn an_attested_key_cannot_issue_attestations() {
        let pki = Pki::new(TestKey::p384());
        let (_, challenge) = pki.expect();
        let attacker_key = TestKey::p256();
        let forged = cert(CertSpec {
            subject: "Android Keystore Key",
            issuer: "Android Keystore Key",
            key: &attacker_key,
            signer: &pki.phone, // the genuine key, which signs anything its owner asks
            ca: false,
            not_after: "480101000000Z",
            key_description: Some(Record { levels: (2, 2), ..Record::good(challenge) }.der()),
        });
        let chain = [vec![forged], pki.chain(&Record::good(challenge))].concat();
        let e = verify_android(&chain, &pki.roots(), &expect(attacker_key.public_key(), challenge)).unwrap_err();
        assert!(e.contains("carries an attestation record") || e.contains("is not a CA"), "{e}");
        // the same with the genuine certificate's record stripped is stopped by the CA rule alone
        let genuine_no_record = cert(CertSpec {
            subject: "Android Keystore Key",
            issuer: "tee",
            key: &pki.phone,
            signer: &pki.tee,
            ca: false,
            not_after: "480101000000Z",
            key_description: None,
        });
        let forged = cert(CertSpec {
            subject: "Android Keystore Key",
            issuer: "Android Keystore Key",
            key: &attacker_key,
            signer: &pki.phone,
            ca: false,
            not_after: "480101000000Z",
            key_description: Some(Record::good(challenge).der()),
        });
        let chain = [vec![forged, genuine_no_record], pki.upper()].concat();
        let e = verify_android(&chain, &pki.roots(), &expect(attacker_key.public_key(), challenge)).unwrap_err();
        assert!(e.contains("is not a CA"), "{e}");
    }

    #[test]
    fn the_record_must_describe_the_key_the_design_asks_for() {
        let pki = Pki::new(TestKey::p384());
        let (key, challenge) = pki.expect();
        let good = Record::good(challenge);
        let verify = |r: &Record, e: &Expect<'_>| verify_android(&pki.chain(r), &pki.roots(), e);
        let refused = |r: Record, why: &str| {
            let e = verify(&r, &expect(key, challenge)).expect_err(why);
            assert!(e.contains(why), "expected {why:?}, got {e:?}");
        };
        refused(Record { challenge: [1; 32], ..good.clone() }, "challenge mismatch");
        refused(Record { levels: (0, 0), ..good.clone() }, "software-backed");
        refused(Record { levels: (1, 0), ..good.clone() }, "software-backed");
        refused(Record { levels: (2, 1), ..good.clone() }, "differ");
        refused(Record { purposes: vec![2, 3], ..good.clone() }, "purposes are not exactly: sign");
        refused(Record { digests: vec![4], ..good.clone() }, "DIGEST_NONE");
        refused(Record { origin: 2, ..good.clone() }, "not generated in the secure hardware");
        refused(Record { no_auth: true, ..good.clone() }, "without user authentication");
        refused(Record { auth_timeout: Some(30), ..good.clone() }, "time window");
        refused(Record { user_auth_type: None, ..good.clone() }, "user authentication type");
        refused(Record { user_auth_type: Some(3), ..good.clone() }, "biometric only");
        refused(Record { locked: false, ..good.clone() }, "bootloader is unlocked");
        refused(Record { package: "com.example.other".into(), ..good.clone() }, "not by the owner app");
        refused(Record { version_code: 9, ..good.clone() }, "below the minimum");
        refused(Record { signer_digest: [9; 32], ..good.clone() }, "--android-app-digest 0909");
        // the PIN opt-in is accepted exactly when the enrollment chose it
        let with_pin = Record { user_auth_type: Some(3), ..good.clone() };
        assert!(verify(&with_pin, &Expect { device_credential: true, ..expect(key, challenge) }).is_ok());
        assert!(verify(&good, &Expect { device_credential: true, ..expect(key, challenge) }).is_err());
        // a boot state other than Verified is shown, not refused: a custom OS on a locked bootloader
        let a = verify(&Record { boot_state: 1, ..good.clone() }, &expect(key, challenge)).unwrap();
        assert!(a.warnings[0].contains("SelfSigned"));
        assert!(verify(&Record { boot_state: 2, ..good.clone() }, &expect(key, challenge)).unwrap().warnings[0].contains("Unverified"));
        // the attested key must be the one the answer names
        let other = TestKey::p256().public_key();
        assert!(verify(&good, &expect(other, challenge)).unwrap_err().contains("not the key the phone's answer names"));
    }

    /// The embedded roots are Google's: they parse, they are self-signed CAs
    /// under their own keys — an RSA-4096 and a P-384 signature from the wild.
    #[test]
    fn googles_roots() {
        let roots = google_roots();
        assert_eq!(roots.len(), 2);
        for ((_, pem), root) in GOOGLE_ROOTS.iter().zip(&roots) {
            let der = pem_to_der(pem).unwrap();
            let cert = Cert::parse(&der).unwrap();
            assert!(cert.is_ca && cert.issuer == cert.subject);
            cert.signed_by(&cert.key).unwrap();
            assert_eq!(cert.spki, &root.spki[..]);
        }
        let spki_hash = |r: &Root| hex::encode(Sha256::digest(&r.spki));
        assert_eq!(spki_hash(&roots[0]), "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae");
        assert_eq!(spki_hash(&roots[1]), "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec");
    }

    #[test]
    fn times_and_digests() {
        let t = |text: &str| time(der::read_only(&utc_time(text)).unwrap());
        assert_eq!(t("700101000000Z").unwrap(), 0);
        assert_eq!(t("270115080000Z").unwrap(), 1_800_000_000);
        assert_eq!(t("491231235959Z").unwrap(), 2_524_607_999);
        assert!(t("2701150800Z").is_err() && t("270115080000+0100").is_err() && t("271315080000Z").is_err());
        let generalized = tlv(der::UNIVERSAL, false, der::GENERALIZED_TIME, b"20270115080000Z");
        assert_eq!(time(der::read_only(&generalized).unwrap()).unwrap(), 1_800_000_000);
        // the form `apksigner verify --print-certs` prints, and plain hex
        let colons = (0..32).map(|i| format!("{:02X}", 0xa0 + i)).collect::<Vec<_>>().join(":");
        assert_eq!(parse_digest(&colons).unwrap()[31], 0xbf);
        assert_eq!(parse_digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_digest("c390").is_err());
    }

    #[test]
    fn the_status_list_is_read_in_both_notations() {
        let list = StatusList::parse(
            br#"{"entries": {"c35747a084470c31": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
                             "6681152659205225093": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"}}}"#,
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        let serial = |hex_text: &str| hex::decode(hex_text).unwrap();
        // a serial the list writes in hexadecimal
        assert_eq!(list.listed(&[serial("01"), serial("00c35747a084470c31")]).unwrap().1, "REVOKED (KEY_COMPROMISE)");
        // and one it writes in decimal
        let decimal = 6681152659205225093u64.to_be_bytes().to_vec();
        assert_eq!(list.listed(&[decimal]).unwrap(), ("6681152659205225093".to_string(), "SUSPENDED (SOFTWARE_FLAW)".to_string()));
        assert!(list.listed(&[serial("02"), serial("0102030405")]).is_none());
        assert!(StatusList::parse(b"{}").is_err());
    }

    /// The live list, as the enrollment fetches it.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the network"]
    async fn the_live_status_list() {
        let list = fetch_status_list().unwrap();
        assert!(list.len() > 1000, "{} entries", list.len());
        assert!(list.listed(&[vec![1], vec![2, 3]]).is_none());
        eprintln!("{} entries", list.len());
    }

    /// A real chain, kept out of the repository: point `TPMSIGN_ATTESTATION_DIR`
    /// at a directory written by `key create --phone --out` (`enroll-request.json`,
    /// `enroll-response.json`, `attest-*.der`) and give the app's signing
    /// digest in `TPMSIGN_ANDROID_APP_DIGEST`.
    #[test]
    #[ignore = "needs a real enrollment's evidence in TPMSIGN_ATTESTATION_DIR"]
    fn a_real_enrollment() {
        let dir = std::path::PathBuf::from(std::env::var("TPMSIGN_ATTESTATION_DIR").expect("TPMSIGN_ATTESTATION_DIR"));
        let digest = parse_digest(&std::env::var("TPMSIGN_ANDROID_APP_DIGEST").expect("TPMSIGN_ANDROID_APP_DIGEST")).unwrap();
        let request = std::fs::read(dir.join("enroll-request.json")).unwrap();
        let answer = std::fs::read(dir.join("enroll-response.json")).unwrap();
        let e = owner_core::enroll::EnrollResponse::verify(&answer, &request, false).unwrap();
        // the certificate of the hardware's key is short-lived: check at the time of the enrollment
        let expires = serde_json::from_slice::<serde_json::Value>(&request).unwrap()["expires"].as_u64().unwrap();
        let a = verify_android(
            &e.attestation,
            &google_roots(),
            &Expect {
                challenge: owner_core::enroll::attestation_challenge(&request),
                public_key: e.public_key,
                device_credential: e.device_credential,
                now: expires,
                packages: &[PACKAGE],
                signing_digests: &[digest],
                min_version_code: 1,
            },
        )
        .unwrap();
        eprintln!("{a:?}");
        assert_eq!(a.tier.as_str(), e.security_level, "the attested tier is the one the phone reported");
        // and a different request is not what this attestation was made for
        let mut other = request.clone();
        other.push(b' ');
        let wrong = Expect {
            challenge: owner_core::enroll::attestation_challenge(&other),
            public_key: e.public_key,
            device_credential: false,
            now: expires,
            packages: &[PACKAGE],
            signing_digests: &[digest],
            min_version_code: 1,
        };
        assert!(verify_android(&e.attestation, &google_roots(), &wrong).unwrap_err().contains("challenge mismatch"));
    }
}
