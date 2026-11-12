//! The phone owner: an operation goes to the owner's phone over the local
//! network behind a QR code and comes back signed by the phone's secure
//! hardware (docs/MOBILE_OWNER_DESIGN.md §3, §4, §8).
//!
//! The QR is the trusted channel: it carries a SHA-256 commitment to the
//! exact request bytes and a secret that never travels over the network.
//! Plain HTTP on the LAN is then enough: the phone checks the request
//! against the commitment, and every answer carries a MAC under the secret,
//! so it comes from the device that scanned the QR — an attacker on the
//! network can only make the session fail. Every signature that comes back
//! is also verified here against the enrolled key over our own `userOpHash`
//! before it is used.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use alloy::primitives::B256;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use alloy::primitives::Address;
use hw_signer::{HardwareSigner, PublicKey, Signature, SignerError, UserOpContext};

use crate::attestation::{self, Attested};
use owner_core::enroll::{EnrollRequest, EnrollResponse, Enrollment};
use owner_core::fingerprint::fingerprint;
use owner_core::request::{commitment, confirmation_mac, verify_answer_mac, QrPayload, RequestError, SignResponse, MAC_HEADER, SESSION_SECRET_BYTES};
use rand_core::{OsRng, RngCore};

/// Session settings, set once from the command line.
#[derive(Clone, Debug)]
pub struct PhoneOptions {
    pub listen: Option<SocketAddr>,
    pub timeout: Duration,
    pub qr_file: Option<PathBuf>,
}

static OPTIONS: OnceLock<PhoneOptions> = OnceLock::new();

pub fn configure(opts: PhoneOptions) {
    let _ = OPTIONS.set(opts);
}

pub fn options() -> PhoneOptions {
    OPTIONS.get().cloned().unwrap_or(PhoneOptions { listen: None, timeout: Duration::from_secs(120), qr_file: None })
}

/// The enrolled phone key: signs operations, never bare digests.
pub struct PhoneSigner {
    label: String,
    public_key: PublicKey,
}

impl PhoneSigner {
    pub fn new(label: String, public_key: PublicKey) -> Self {
        Self { label, public_key }
    }
}

const MAX_WRONG_TOKENS: u32 = 20;
/// Answers without the session's MAC are ignored at no cost beyond reading
/// them, so they get their own, larger cap: a host on the network cannot
/// close the session by sending twenty of them.
const MAX_UNAUTHENTICATED: u32 = 200;
/// A sign response is well under 4 KiB (§3.3); an enrollment answer carries
/// an attestation chain of a few certificates, so the cap is 64 KiB.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

impl HardwareSigner for PhoneSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        Ok(self.public_key)
    }

    fn sign_digest(&self, _digest: &[u8; 32]) -> Result<Signature, SignerError> {
        Err(SignerError::Key(format!(
            "phone key {:?} signs operations, not bare digests: the phone must see what it signs",
            self.label
        )))
    }

    fn needs_request(&self) -> bool {
        true
    }

    fn sign_user_op(&self, ctx: &UserOpContext<'_>) -> Result<Signature, SignerError> {
        let request = ctx.request.ok_or_else(|| SignerError::Key("no sign request attached for the phone".into()))?;
        let hash = B256::from(ctx.user_op_hash);
        let headline = format!(
            "phone owner {:?}: scan this with the owner app, review the operation, confirm.\nkey fingerprint: {}   userOpHash: {hash}",
            self.label,
            fingerprint(&self.public_key)
        );
        let sig = lan_session(request, &headline, |body| Ok(SignResponse::verify(body, request, &self.public_key, hash)?))
            .map_err(|e| match e {
                SessionError::Refused(e) => SignerError::Key(format!("phone {:?}: {e}", self.label)),
                SessionError::Rejected(m) => SignerError::Key(format!("phone {:?}: {m}", self.label)),
                SessionError::Backend(m) => SignerError::Backend(m),
            })?;
        eprintln!("phone:          signed, signature verified against the owner key");
        Ok(sig)
    }
}

/// The owner's check of the fingerprint the phone shows at enrollment. The
/// answer is already authenticated by the session's secret (the MAC in
/// `lan_session`), which a host on the network does not have. Someone who
/// could read the QR — off the laptop's screen, a camera, a shared screen —
/// and is on the network within the session has it too; the comparison with
/// the phone's own screen is what stops that case. An enrollment is followed
/// by a root handover, so the check is the default.
pub enum FingerprintSource {
    /// Ask on the terminal when the answer arrives: the default.
    Prompt,
    /// Given up front (`--phone-fingerprint`): the answer must carry this key.
    Given(String),
    /// Not checked (`--phone-skip-fingerprint`): the session secret alone
    /// authenticates the answer.
    Skipped,
}

/// What the laptop asks of the phone's key attestation (design §5.2, §5.6).
pub struct AttestationPolicy {
    /// Accept an answer without evidence: a simulator, or a platform without it.
    pub allow_none: bool,
    /// The app's signing-certificate digests accepted here, beyond the pinned ones.
    pub signing_digests: Vec<[u8; 32]>,
    /// Refuse a key the attestation places in the TEE.
    pub require_strongbox: bool,
}

/// What the laptop learned about the key from its attestation.
pub struct Evidence {
    pub attested: Attested,
    /// The revocation list: how many entries were checked, or why it was not.
    pub revocation: Result<usize, String>,
}

/// An enrolled key: the request served, the phone's answer as posted, its
/// parsed content, and the verified evidence when the answer carried any.
pub struct Enrolled {
    pub request: Vec<u8>,
    pub answer: Vec<u8>,
    pub enrollment: Enrollment,
    pub evidence: Option<Evidence>,
}

/// Enrollment (design §2.1): ask the phone to create a new owner key for
/// `account` and return it with its evidence, which is verified before the
/// answer is accepted. Nothing on-chain; the caller prints the fingerprint
/// and the config snippet, and the handover is the owner's next, separate
/// step.
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    label: &str,
    chain_id: u64,
    entry_point: Address,
    account: Address,
    pins: std::collections::BTreeMap<Address, String>,
    policy: &AttestationPolicy,
    confirm: FingerprintSource,
) -> Result<Enrolled, SignerError> {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| SignerError::Backend(e.to_string()))?;
    let expires = now.as_secs() + options().timeout.as_secs();
    let request = EnrollRequest::new(chain_id, entry_point, account, label, B256::from(challenge), expires).with_pins(pins).to_bytes();
    let headline = format!(
        "enrolling phone owner key {label:?} for account {account} on chain {chain_id}: scan this with the owner app, \
         read the notice about this phone's key hardware, confirm. The phone then shows the new key's fingerprint{}",
        if matches!(confirm, FingerprintSource::Prompt) { "; you will be asked to type it here." } else { ", and so will this terminal." }
    );
    let mut typed: Option<String> = match &confirm {
        FingerprintSource::Given(fp) => Some(normalize_fingerprint(fp)?),
        FingerprintSource::Prompt | FingerprintSource::Skipped => None,
    };
    let roots = attestation::google_roots();
    let mut digests = attestation::PINNED_SIGNING_DIGESTS.to_vec();
    digests.extend(&policy.signing_digests);
    let (body, enrollment, evidence) = lan_session(&request, &headline, |body| {
        let e = EnrollResponse::verify(body, &request, policy.allow_none)?;
        // the evidence: where the key lives and which app made it (§5.2). The answer is the
        // phone's own (the session MAC), so a failure here ends the session with its reason.
        let evidence = if e.attestation.is_empty() {
            if policy.require_strongbox {
                return Err(Rejection::End("--require-strongbox needs a key attestation, and the answer carries none".into()));
            }
            None
        } else {
            let attested = attestation::verify_android(
                &e.attestation,
                &roots,
                &attestation::Expect {
                    challenge: owner_core::enroll::attestation_challenge(&request),
                    public_key: e.public_key,
                    device_credential: e.device_credential,
                    now: now.as_secs(),
                    packages: attestation::ANDROID_PACKAGES,
                    signing_digests: &digests,
                    min_version_code: attestation::MIN_ANDROID_VERSION_CODE,
                },
            )
            .map_err(|why| Rejection::End(format!("the key attestation was not accepted: {why}")))?;
            if attested.tier.as_str() != e.security_level {
                return Err(Rejection::End(format!(
                    "the phone reports the key's security level as {:?}, its attestation says {:?}",
                    e.security_level,
                    attested.tier.as_str()
                )));
            }
            if policy.require_strongbox && attested.tier != attestation::Tier::StrongBox {
                return Err(Rejection::End(
                    "--require-strongbox: the attestation places this key in the processor's trusted mode (TEE), not in a StrongBox".into(),
                ));
            }
            let revocation = attestation::fetch_status_list().map(|list| (list.len(), list.listed(&attested.serials)));
            let revocation = match revocation {
                Ok((_, Some((serial, status)))) => {
                    return Err(Rejection::End(format!("a certificate of the attestation chain (serial {serial}) is on Google's revocation list: {status}")));
                }
                Ok((entries, None)) => Ok(entries),
                Err(why) => Err(why),
            };
            Some(Evidence { attested, revocation })
        };
        let actual = fingerprint(&e.public_key);
        let matches = match &typed {
            Some(t) => fingerprint_matches(t, &actual),
            None if matches!(confirm, FingerprintSource::Skipped) => true,
            None => {
                let mut t = prompt_fingerprint()?;
                // a typo and a foreign key look the same; one more try tells them apart before the value is kept
                if !fingerprint_matches(&t, &actual) {
                    eprintln!("that does not match the key in this answer. If you mistyped, type the fingerprint once more; otherwise press Enter to reject this answer.");
                    if let Ok(again) = prompt_fingerprint() {
                        t = again;
                    }
                }
                let ok = fingerprint_matches(&t, &actual);
                typed = Some(t);
                ok
            }
        };
        if !matches {
            eprintln!(
                "an answer arrived with a key whose fingerprint ({actual}) is not the one on the phone's screen; \
                 it is not the phone's key — refused, still waiting for the phone"
            );
            return Err(RequestError::Malformed("the key is not the one on the phone's screen".into()).into());
        }
        Ok((body.to_vec(), e, evidence))
    })
    .map_err(|e| match e {
        SessionError::Refused(e) => SignerError::Key(format!("enrollment of {label:?}: {e}")),
        SessionError::Rejected(m) => SignerError::Key(format!("enrollment of {label:?}: {m}")),
        SessionError::Backend(m) => SignerError::Backend(m),
    })?;
    Ok(Enrolled { request, answer: body, enrollment, evidence })
}

/// Names from the laptop's deployments file for the addresses the phone's
/// build does not know (design §4.3, §6.7): a variant's paymaster, a chain
/// without embedded facts. The phone shows them as unverified labels and
/// reports any that its build names itself, so none are sent for those. The
/// labels say what the config uses an address for; they are never the names
/// the build gives to what it verifies, which the phone refuses in a pin.
pub fn laptop_pins(dep: &crate::agent::Deployments) -> std::collections::BTreeMap<Address, String> {
    let known = owner_core::facts::for_chain(dep.chain_id).names;
    [
        (Some(dep.p256_validator), "owner validator (config)"),
        (Some(dep.p256_signer), "signer module (config)"),
        (Some(dep.agent_policy), "policy module (config)"),
        (Some(dep.demo_counter), "counter (config)"),
        (dep.whitelist_paymaster, "paymaster (config)"),
        (dep.p256_recovery_validator, "recovery validator (config)"),
        (dep.p256_validator_v1, "old owner validator (config)"),
        (dep.p256_recovery_validator_v1, "old recovery validator (config)"),
        (dep.safe_nonce_assert, "safe nonce guard (config)"),
    ]
    .into_iter()
    .filter_map(|(a, name)| a.map(|a| (a, name.to_string())))
    .filter(|(a, _)| !known.contains_key(a))
    .collect()
}

/// `ABCDE-FGHIJ-KLMNO-PQRST` as the phone shows it, or at least its first
/// two groups; case and dashes do not matter. Why two: the phone's answer
/// travels in cleartext, so a host in the network path can hold it, read
/// the phone's key, and grind a key whose fingerprint starts the same way.
/// One group (25 bits) falls to that in minutes; two (50 bits) do not
/// within a session. All four is what to type when in doubt.
fn normalize_fingerprint(typed: &str) -> Result<String, SignerError> {
    let t: String = typed.trim().chars().filter(|c| *c != '-' && !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    if t.len() < 10 || t.len() > 20 || !t.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)) {
        return Err(SignerError::Key(
            "the fingerprint has four groups of five characters (A–Z, 2–7); type at least the first two groups".into(),
        ));
    }
    Ok(t)
}

fn fingerprint_matches(typed_normalized: &str, actual: &str) -> bool {
    let a: String = actual.chars().filter(|c| *c != '-').collect();
    a.starts_with(typed_normalized)
}

fn prompt_fingerprint() -> Result<String, RequestError> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(RequestError::Malformed(
            "an answer arrived but there is no terminal to confirm the phone's fingerprint on; run interactively, or pass --phone-fingerprint or --phone-skip-fingerprint".into(),
        ));
    }
    eprint!("\nthe phone shows the new key's fingerprint. Type at least its first two groups (all four when in doubt): ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| RequestError::Malformed(format!("reading the fingerprint: {e}")))?;
    normalize_fingerprint(&line).map_err(|e| RequestError::Malformed(e.to_string()))
}

enum SessionError {
    /// The phone said no, or its answer was not accepted.
    Refused(RequestError),
    /// The phone's authenticated answer fails a check no retry can fix.
    Rejected(String),
    Backend(String),
}

/// Why a verifier turns an authenticated answer down.
enum Rejection {
    /// Answer 400 and keep waiting: another answer may be the right one.
    Wait(RequestError),
    /// Answer 400 with this reason and end the session: the phone's answer
    /// itself is unacceptable (its attestation, say), so waiting is pointless.
    End(String),
}

impl From<RequestError> for Rejection {
    fn from(e: RequestError) -> Self {
        Rejection::Wait(e)
    }
}

/// One session: a random token and a random secret, the QR on the terminal
/// (and in the QR file, if configured), the request served to the phone, and
/// the first answer that carries the secret's MAC and that `verify` accepts.
/// The token travels in the phone's cleartext GET, so a host on the LAN can
/// post in the phone's place; the secret travels only in the QR, so such a
/// post has no valid MAC: it gets a 401 and the session keeps waiting,
/// whatever it says — a forged refusal included. An authenticated answer
/// that `verify` rejects gets a 400 and the session waits on; the phone's
/// own refusal ends it. Wrong tokens and rejected answers count against one
/// cap, unauthenticated answers against a larger one of their own. An
/// accepted answer is answered with `confirmation_mac`, which only the
/// laptop can produce: the phone takes nothing else as "the laptop has it".
fn lan_session<T>(
    request: &[u8],
    headline: &str,
    mut verify: impl FnMut(&[u8]) -> Result<T, Rejection>,
) -> Result<T, SessionError> {
    let opts = options();
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let token = B64URL.encode(token);
    let mut secret = [0u8; SESSION_SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    let secret = B64URL.encode(secret);
    let bind = match opts.listen {
        Some(addr) => addr,
        None => SocketAddr::new(default_route_ip().ok_or_else(no_network)?, 0),
    };
    let server = tiny_http::Server::http(bind).map_err(|e| SessionError::Backend(format!("LAN session on {bind}: {e}")))?;
    let local = server.server_addr().to_ip().ok_or_else(|| SessionError::Backend("no socket address".into()))?;
    let host = if local.ip().is_unspecified() { default_route_ip().ok_or_else(no_network)? } else { local.ip() };
    let url = match host {
        IpAddr::V4(ip) => format!("http://{ip}:{}/s/{token}", local.port()),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}/s/{token}", local.port()),
    };
    let qr = QrPayload { url: url.clone(), commitment: commitment(request), secret: secret.clone() };
    let uri = qr.to_uri();

    eprintln!();
    eprintln!("{headline}");
    eprintln!("{}", render_qr(&uri).map_err(|e| SessionError::Backend(e.to_string()))?);
    // the secret is in the QR, not in text: a terminal log or a pasted transcript travels further than a screen
    eprintln!("{}", uri.replace(&secret, "<in the QR only>"));
    eprintln!("waiting up to {}s for the phone…", opts.timeout.as_secs());
    if let Some(path) = &opts.qr_file {
        std::fs::write(path, &uri).map_err(|e| SessionError::Backend(format!("writing {}: {e}", path.display())))?;
    }

    let started = Instant::now();
    let path = format!("/s/{token}");
    let mut strikes = 0u32;
    let mut unauthenticated = 0u32;
    let strike = |strikes: &mut u32| -> Result<(), SessionError> {
        *strikes += 1;
        if *strikes >= MAX_WRONG_TOKENS {
            return Err(SessionError::Backend("too many wrong or rejected requests; session closed".into()));
        }
        Ok(())
    };
    let remaining = || opts.timeout.checked_sub(started.elapsed());
    loop {
        let Some(left) = remaining() else {
            return Err(SessionError::Backend(format!("no answer from the phone within {}s", opts.timeout.as_secs())));
        };
        let Some(req) = server.recv_timeout(left).map_err(|e| SessionError::Backend(format!("session: {e}")))? else {
            continue;
        };
        if !eq_ct(req.url().as_bytes(), path.as_bytes()) {
            let _ = req.respond(tiny_http::Response::empty(404));
            strike(&mut strikes)?;
            continue;
        }
        match req.method() {
            tiny_http::Method::Get => {
                let r = tiny_http::Response::from_data(request.to_vec())
                    .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").expect("header"));
                let _ = req.respond(r);
            }
            tiny_http::Method::Post => {
                let Some(left) = remaining() else { continue };
                let mac = req.headers().iter().find(|h| h.field.equiv(MAC_HEADER)).map(|h| h.value.as_str().to_string());
                let Some((req, body)) = read_body(req, left) else {
                    eprintln!("a client opened an answer and stalled past the session's deadline; dropped");
                    continue;
                };
                let body = match body {
                    Ok(b) => b,
                    Err(why) => {
                        let _ = req.respond(tiny_http::Response::from_string(why).with_status_code(400));
                        strike(&mut strikes)?;
                        continue;
                    }
                };
                // not from the device that scanned the QR: whatever it says, it is not the phone's answer
                if !mac.is_some_and(|m| verify_answer_mac(&secret, &body, &m)) {
                    eprintln!("an answer without this session's secret was ignored (not the phone that scanned the QR); still waiting for the phone");
                    let _ = req.respond(tiny_http::Response::from_string("no valid MAC for this session").with_status_code(401));
                    unauthenticated += 1;
                    if unauthenticated >= MAX_UNAUTHENTICATED {
                        return Err(SessionError::Backend("too many answers without this session's secret; session closed".into()));
                    }
                    continue;
                }
                match verify(&body) {
                    Ok(t) => {
                        // the phone keeps its key only on this: a bare 200 could come from anyone in the path
                        let confirmation = confirmation_mac(&secret, &body).map_err(|e| SessionError::Backend(e.to_string()))?;
                        let _ = req.respond(tiny_http::Response::from_string(confirmation));
                        drop(server); // the port closes; later requests get nothing
                        return Ok(t);
                    }
                    Err(Rejection::Wait(e @ RequestError::Refused { .. })) => {
                        let _ = req.respond(tiny_http::Response::from_string("ok"));
                        return Err(SessionError::Refused(e));
                    }
                    Err(Rejection::Wait(e)) => {
                        eprintln!("an answer was rejected ({e}); still waiting for the phone");
                        let _ = req.respond(tiny_http::Response::from_string(e.to_string()).with_status_code(400));
                        strike(&mut strikes)?;
                    }
                    Err(Rejection::End(why)) => {
                        let _ = req.respond(tiny_http::Response::from_string(why.clone()).with_status_code(400));
                        return Err(SessionError::Rejected(why));
                    }
                }
            }
            _ => {
                let _ = req.respond(tiny_http::Response::empty(405));
            }
        }
    }
}

fn no_network() -> SessionError {
    SessionError::Backend("no network interface for the LAN session (no default route); give one with --listen <ip:port>".into())
}

/// The POST body, at most `MAX_RESPONSE_BYTES`, within `deadline`. The read
/// runs on its own thread: a client that opens the POST and stalls must not
/// hold the session past its timeout. `None` on the deadline; the thread
/// then ends with the connection, and the request is answered by nobody.
fn read_body(mut req: tiny_http::Request, deadline: Duration) -> Option<(tiny_http::Request, Result<Vec<u8>, String>)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let result = req
            .as_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading the answer: {e}"))
            .and_then(|n| {
                if n > MAX_RESPONSE_BYTES {
                    Err(format!("the answer exceeds {} KiB", MAX_RESPONSE_BYTES / 1024))
                } else {
                    Ok(buf)
                }
            });
        let _ = tx.send((req, result));
    });
    rx.recv_timeout(deadline).ok()
}

/// The address of the interface that carries the default route — where a
/// phone on the same network reaches us. No packet is sent. `None` when
/// there is no route: a QR pointing at loopback would be accepted by the
/// phone and never reach us.
fn default_route_ip() -> Option<IpAddr> {
    let ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip())
        .ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

fn render_qr(uri: &str) -> Result<String, SignerError> {
    use qrcode::render::unicode;
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| SignerError::Backend(format!("QR: {e}")))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_key_never_signs_a_bare_digest() {
        let s = PhoneSigner::new("p".into(), PublicKey { x: [1; 32], y: [2; 32] });
        assert!(s.sign_digest(&[0; 32]).is_err());
        assert!(s.sign_user_op(&UserOpContext { user_op_hash: [0; 32], request: None }).is_err());
    }

    #[test]
    fn fingerprints_are_typed_loosely_and_matched_as_a_prefix() {
        let fp = "ZOLH5-D2DIS-66ZBB-4T6NL";
        assert!(fingerprint_matches(&normalize_fingerprint("zolh5-d2dis").unwrap(), fp));
        assert!(fingerprint_matches(&normalize_fingerprint(" ZOLH5 D2DIS 66ZBB 4T6NL ").unwrap(), fp));
        assert!(!fingerprint_matches(&normalize_fingerprint("ZOLH5-D2DIT").unwrap(), fp));
        assert!(normalize_fingerprint("zolh5").is_err(), "one group can be ground by a host that read the phone's key");
        assert!(normalize_fingerprint("ZOLH5-D2DI").is_err(), "nine characters are not two groups");
        assert!(normalize_fingerprint("ZOLH5-D2DI1").is_err(), "1 is not base32");
        assert!(normalize_fingerprint("ZOLH5-D2DIS-66ZBB-4T6NL-X").is_err());
    }

    #[test]
    fn constant_time_compare() {
        assert!(eq_ct(b"abc", b"abc"));
        assert!(!eq_ct(b"abc", b"abd"));
        assert!(!eq_ct(b"abc", b"ab"));
    }
}
