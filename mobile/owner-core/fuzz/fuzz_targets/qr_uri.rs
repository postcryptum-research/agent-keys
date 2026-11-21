// The text of a scanned QR code, and the two helpers that decide whether its
// address is on the local network.
#![no_main]
use libfuzzer_sys::fuzz_target;
use owner_core::request::{is_local_host, session_host, QrPayload};

/// The local ranges, written out by hand: 10/8, 172.16/12, 192.168/16,
/// 169.254/16, 127/8; ::1, fc00::/7, fe80::/10.
fn local(host: &str) -> bool {
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        let [a, b, _, _] = v4.octets();
        return a == 10 || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254) || a == 127;
    }
    match host.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => {
            let first = v6.octets()[0];
            v6.octets() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] || first & 0xfe == 0xfc || (first == 0xfe && v6.octets()[1] & 0xc0 == 0x80)
        }
        Err(_) => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(host) = session_host(text) {
        let _ = is_local_host(&host);
    }
    let _ = is_local_host(text);
    if let Ok(payload) = QrPayload::parse(text) {
        // an accepted payload names a local host, and reads back as itself
        let host = session_host(&payload.url).expect("an accepted payload whose address has no host");
        assert!(is_local_host(&host), "an accepted payload that is not local: {host:?}");
        assert!(local(&host), "an accepted payload whose host is outside the local ranges: {host:?}");
        assert!(payload.url.starts_with("http://") && !payload.url[7..].split('/').next().unwrap().contains('@'));
        assert_eq!(QrPayload::parse(&payload.to_uri()).ok().as_ref(), Some(&payload));
    }
});
