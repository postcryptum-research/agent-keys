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
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use alloy::primitives::B256;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use hw_signer::{HardwareSigner, PublicKey, Signature, SignerError, UserOpContext};
use owner_core::fingerprint::fingerprint;
use owner_core::request::{commitment, QrPayload, SignResponse};
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
const MAX_RESPONSE_BYTES: usize = 4096;

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

    fn sign_user_op(&self, ctx: &UserOpContext<'_>) -> Result<Signature, SignerError> {
        let request = ctx.request.ok_or_else(|| SignerError::Key("no sign request attached for the phone".into()))?;
        let opts = options();
        let hash = B256::from(ctx.user_op_hash);

        // the session: one token, one request, one answer
        let mut token = [0u8; 16];
        OsRng.fill_bytes(&mut token);
        let token = B64URL.encode(token);
        let bind = opts.listen.unwrap_or_else(|| SocketAddr::new(default_route_ip(), 0));
        let server = tiny_http::Server::http(bind).map_err(|e| SignerError::Backend(format!("LAN session on {bind}: {e}")))?;
        let local = server.server_addr().to_ip().ok_or_else(|| SignerError::Backend("no socket address".into()))?;
        let host = match local.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => default_route_ip(),
            ip => ip,
        };
        let url = format!("http://{host}:{}/s/{token}", local.port());
        let qr = QrPayload { url: url.clone(), commitment: commitment(request) };
        let uri = qr.to_uri();

        eprintln!();
        eprintln!("phone owner {:?}: scan this with the owner app, review the operation, confirm.", self.label);
        eprintln!("key fingerprint: {}   userOpHash: {hash}", fingerprint(&self.public_key));
        eprintln!("{}", render_qr(&uri)?);
        eprintln!("{uri}");
        eprintln!("waiting up to {}s for the phone…", opts.timeout.as_secs());
        if let Some(path) = &opts.qr_file {
            std::fs::write(path, &uri).map_err(|e| SignerError::Backend(format!("writing {}: {e}", path.display())))?;
        }

        let started = Instant::now();
        let path = format!("/s/{token}");
        let mut wrong = 0u32;
        let body = loop {
            let remaining = opts.timeout.checked_sub(started.elapsed()).ok_or_else(|| {
                SignerError::Backend(format!("no answer from the phone within {}s", opts.timeout.as_secs()))
            })?;
            let Some(mut req) = server.recv_timeout(remaining).map_err(|e| SignerError::Backend(format!("session: {e}")))? else {
                continue;
            };
            if !eq_ct(req.url().as_bytes(), path.as_bytes()) {
                wrong += 1;
                let _ = req.respond(tiny_http::Response::empty(404));
                if wrong >= MAX_WRONG_TOKENS {
                    return Err(SignerError::Backend("too many requests with a wrong session token; session closed".into()));
                }
                continue;
            }
            match req.method() {
                tiny_http::Method::Get => {
                    let r = tiny_http::Response::from_data(request.to_vec()).with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").expect("header"),
                    );
                    let _ = req.respond(r);
                }
                tiny_http::Method::Post => {
                    let mut buf = Vec::new();
                    let n = req
                        .as_reader()
                        .take(MAX_RESPONSE_BYTES as u64 + 1)
                        .read_to_end(&mut buf)
                        .map_err(|e| SignerError::Backend(format!("reading the phone's answer: {e}")))?;
                    if n > MAX_RESPONSE_BYTES {
                        let _ = req.respond(tiny_http::Response::from_string("too large").with_status_code(413));
                        return Err(SignerError::Backend("the phone's answer exceeds 4 KiB".into()));
                    }
                    let _ = req.respond(tiny_http::Response::from_string("ok"));
                    break buf;
                }
                _ => {
                    let _ = req.respond(tiny_http::Response::empty(405));
                }
            }
        };
        drop(server); // the port closes; later requests get nothing

        match SignResponse::verify(&body, request, &self.public_key, hash) {
            Ok(sig) => {
                eprintln!("phone:          signed, signature verified against the owner key");
                Ok(sig)
            }
            Err(e) => Err(SignerError::Key(format!("phone {:?}: {e}", self.label))),
        }
    }
}

/// The address of the interface that carries the default route — where a
/// phone on the same network reaches us. No packet is sent.
fn default_route_ip() -> IpAddr {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
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
    fn constant_time_compare() {
        assert!(eq_ct(b"abc", b"abc"));
        assert!(!eq_ct(b"abc", b"abd"));
        assert!(!eq_ct(b"abc", b"ab"));
    }
}
