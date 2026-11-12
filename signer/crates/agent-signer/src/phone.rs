//! The phone owner: an operation goes to the owner's phone over the local
//! network behind a QR code and comes back signed by the phone's secure
//! hardware (docs/MOBILE_OWNER_DESIGN.md §3, §4, §8).
//!
//! The QR is the trusted channel: it carries a SHA-256 commitment to the
//! exact request bytes, so plain HTTP on the LAN is enough — an attacker
//! there can only make the session fail. Every signature that comes back is
//! verified here against the enrolled key over our own `userOpHash` before
//! it is used.

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
use owner_core::enroll::{EnrollRequest, EnrollResponse, Enrollment};
use owner_core::fingerprint::fingerprint;
use owner_core::request::{commitment, QrPayload, RequestError, SignResponse};
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
        let sig = lan_session(request, &headline, |body| SignResponse::verify(body, request, &self.public_key, hash))
            .map_err(|e| match e {
                SessionError::Refused(e) => SignerError::Key(format!("phone {:?}: {e}", self.label)),
                SessionError::Backend(m) => SignerError::Backend(m),
            })?;
        eprintln!("phone:          signed, signature verified against the owner key");
        Ok(sig)
    }
}

/// How the owner confirms the fingerprint the phone shows at enrollment.
/// An enrollment answer is the one message nothing authenticates, so
/// whoever posts first with the session token could name their own key;
/// the owner's comparison with the phone's screen is the whole defence
/// until P3 verifies the attestation. The CLI therefore asks for it and
/// refuses an answer that does not carry the fingerprint typed in.
pub enum FingerprintSource {
    /// Ask on the terminal when the first answer arrives (the phone shows
    /// its fingerprint once the key exists).
    Prompt,
    /// Given up front (`--phone-fingerprint`): tests and scripts.
    Given(String),
    /// A shell command run when the first answer arrives, repeated every
    /// second until its output holds a fingerprint (`--phone-fingerprint-cmd`):
    /// for a development phone on USB, where `adb` can read what the phone
    /// shows — a channel a host on the LAN does not have.
    Command(String),
}

/// Enrollment (design §2.1): ask the phone to create a new owner key for
/// `account` and return it with its evidence. Nothing on-chain; the caller
/// prints the fingerprint and the config snippet, and the handover is the
/// owner's next, separate step.
pub fn enroll(
    label: &str,
    chain_id: u64,
    entry_point: Address,
    account: Address,
    pins: std::collections::BTreeMap<Address, String>,
    allow_no_attestation: bool,
    confirm: FingerprintSource,
) -> Result<(Vec<u8>, Vec<u8>, Enrollment), SignerError> {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| SignerError::Backend(e.to_string()))?;
    let expires = now.as_secs() + options().timeout.as_secs();
    let request = EnrollRequest::new(chain_id, entry_point, account, label, B256::from(challenge), expires).with_pins(pins).to_bytes();
    let headline = format!(
        "enrolling phone owner key {label:?} for account {account} on chain {chain_id}: scan this with the owner app, \
         read the notice about this phone's key hardware, confirm. The phone then shows the new key's fingerprint; \
         you will be asked to type it here."
    );
    let mut typed: Option<String> = match &confirm {
        FingerprintSource::Given(fp) => Some(normalize_fingerprint(fp)?),
        FingerprintSource::Prompt | FingerprintSource::Command(_) => None,
    };
    let (body, enrollment) = lan_session(&request, &headline, |body| {
        let e = EnrollResponse::verify(body, &request, allow_no_attestation)?;
        let actual = fingerprint(&e.public_key);
        let matches = match &typed {
            Some(t) => fingerprint_matches(t, &actual),
            None => {
                let mut t = match &confirm {
                    FingerprintSource::Command(cmd) => fingerprint_from_command(cmd, options().timeout)?,
                    _ => prompt_fingerprint()?,
                };
                // a typo and a foreign key look the same; one more try tells them apart before the value is kept
                if !fingerprint_matches(&t, &actual) && matches!(confirm, FingerprintSource::Prompt) {
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
            return Err(RequestError::Malformed("the key is not the one on the phone's screen".into()));
        }
        Ok((body.to_vec(), e))
    })
    .map_err(|e| match e {
        SessionError::Refused(e) => SignerError::Key(format!("enrollment of {label:?}: {e}")),
        SessionError::Backend(m) => SignerError::Backend(m),
    })?;
    Ok((request, body, enrollment))
}

/// Names from the laptop's deployments file for the addresses the phone's
/// build does not know (design §4.3, §6.7): a variant's paymaster, a chain
/// without embedded facts. The phone shows them as unverified labels and
/// reports any that its build names itself, so none are sent for those.
pub fn laptop_pins(dep: &crate::agent::Deployments) -> std::collections::BTreeMap<Address, String> {
    let known = owner_core::facts::for_chain(dep.chain_id).names;
    [
        (Some(dep.p256_validator), "P256Validator"),
        (Some(dep.p256_signer), "P256Signer"),
        (Some(dep.agent_policy), "AgentPolicy"),
        (Some(dep.demo_counter), "demo counter"),
        (dep.whitelist_paymaster, "WhitelistPaymaster"),
        (dep.p256_recovery_validator, "P256RecoveryValidator"),
        (dep.p256_validator_v1, "P256Validator v1"),
        (dep.p256_recovery_validator_v1, "P256RecoveryValidator v1"),
        (dep.safe_nonce_assert, "SafeNonceAssert"),
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

/// Runs `sh -c <cmd>` every second until its stdout holds a fingerprint or
/// `deadline` passes.
fn fingerprint_from_command(cmd: &str, deadline: Duration) -> Result<String, RequestError> {
    let started = Instant::now();
    eprintln!("an answer arrived; reading the fingerprint the phone shows through `{cmd}`…");
    loop {
        let out = std::process::Command::new("sh").arg("-c").arg(cmd).output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty()) {
                if let Ok(fp) = normalize_fingerprint(line) {
                    eprintln!("fingerprint from the command: {line}");
                    return Ok(fp);
                }
            }
        }
        if started.elapsed() > deadline {
            return Err(RequestError::Malformed(format!("`{cmd}` produced no fingerprint within {}s", deadline.as_secs())));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn fingerprint_matches(typed_normalized: &str, actual: &str) -> bool {
    let a: String = actual.chars().filter(|c| *c != '-').collect();
    a.starts_with(typed_normalized)
}

fn prompt_fingerprint() -> Result<String, RequestError> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(RequestError::Malformed(
            "an answer arrived but there is no terminal to confirm the phone's fingerprint on; run interactively or pass --phone-fingerprint".into(),
        ));
    }
    eprint!("\nthe phone shows the new key's fingerprint. Type at least its first two groups (all four when in doubt): ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| RequestError::Malformed(format!("reading the fingerprint: {e}")))?;
    normalize_fingerprint(&line).map_err(|e| RequestError::Malformed(e.to_string()))
}

enum SessionError {
    /// The phone said no, or the session ended without a usable answer.
    Refused(RequestError),
    Backend(String),
}

impl From<RequestError> for SessionError {
    fn from(e: RequestError) -> Self {
        SessionError::Refused(e)
    }
}

/// One session: a random token, the QR on the terminal (and in the QR file,
/// if configured), the request served to the phone, and the first answer
/// that `verify` accepts. An answer it rejects gets a 400 and the session
/// keeps waiting — the token travels in the phone's cleartext GET, so a
/// host on the LAN can post garbage first — unless the phone itself
/// refused, which ends the session. Rejected answers and wrong tokens count
/// against one cap.
fn lan_session<T>(
    request: &[u8],
    headline: &str,
    mut verify: impl FnMut(&[u8]) -> Result<T, RequestError>,
) -> Result<T, SessionError> {
    let opts = options();
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let token = B64URL.encode(token);
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
    let qr = QrPayload { url: url.clone(), commitment: commitment(request) };
    let uri = qr.to_uri();

    eprintln!();
    eprintln!("{headline}");
    eprintln!("{}", render_qr(&uri).map_err(|e| SessionError::Backend(e.to_string()))?);
    eprintln!("{uri}");
    eprintln!("waiting up to {}s for the phone…", opts.timeout.as_secs());
    if let Some(path) = &opts.qr_file {
        std::fs::write(path, &uri).map_err(|e| SessionError::Backend(format!("writing {}: {e}", path.display())))?;
    }

    let started = Instant::now();
    let path = format!("/s/{token}");
    let mut strikes = 0u32;
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
                match verify(&body) {
                    Ok(t) => {
                        let _ = req.respond(tiny_http::Response::from_string("ok"));
                        drop(server); // the port closes; later requests get nothing
                        return Ok(t);
                    }
                    Err(e @ RequestError::Refused { .. }) => {
                        let _ = req.respond(tiny_http::Response::from_string("ok"));
                        return Err(SessionError::Refused(e));
                    }
                    Err(e) => {
                        eprintln!("an answer was rejected ({e}); still waiting for the phone");
                        let _ = req.respond(tiny_http::Response::from_string(e.to_string()).with_status_code(400));
                        strike(&mut strikes)?;
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
