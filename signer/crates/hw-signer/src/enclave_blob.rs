//! The shape of a Secure Enclave key file, checked before the file goes to
//! CryptoKit (issue #78).
//!
//! CryptoKit's `dataRepresentation` is DER: an OCTET STRING that holds a SET
//! of `SEQUENCE { UTF8String name, value }` entries, a value being a SET of
//! more such entries, an OCTET STRING, an INTEGER or a BOOLEAN. The entry
//! `rk` holds, among others, `pub`: the key's public point, uncompressed and
//! in the clear.
//!
//! A file damaged in that point makes CryptoKit end the process with a Swift
//! fatal error, which no `do`/`catch` in the shim can turn into a message; a
//! file damaged in its structure is malformed input to system code. So a
//! file that is not a well-formed blob with a valid point is refused here,
//! with the reason, and never reaches CryptoKit.
//!
//! **What this does not see:** a change inside a value (the wrapped key, an
//! identifier, a flag) or a name changed into another printable one. Such a
//! file is well-formed; the enclave refuses it when it is asked to sign.
//!
//! The format is Apple's and not documented. The check holds to what the
//! files look like today and names no entry but `rk` and `pub`; `create`
//! runs it on the fresh key, so a system that writes another form is noticed
//! when a key is made and not when it is needed.
//!
//! Plain Rust with no platform code, so that its tests run anywhere.

use crate::{valid_public_key, PublicKey};

/// The largest key file accepted (they are about 320 bytes today).
pub const MAX_BLOB: usize = 4096;

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const UTF8_STRING: u8 = 0x0c;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
/// Deeper nesting than any file has (they have three levels of entries).
const MAX_DEPTH: usize = 8;

/// One DER element at the start of `bytes`: its tag, its content and what
/// follows it. Definite lengths in their shortest form only, as DER has them.
fn element(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let [tag, first, rest @ ..] = bytes else {
        return Err("it ends in the middle of an element".into());
    };
    let (len, rest) = match *first {
        n if n < 0x80 => (n as usize, rest),
        0x81 => match rest {
            [n, rest @ ..] if *n >= 0x80 => (*n as usize, rest),
            _ => return Err("an element's length is not in its shortest form".into()),
        },
        0x82 => match rest {
            [hi, lo, rest @ ..] if *hi != 0 => ((*hi as usize) << 8 | *lo as usize, rest),
            _ => return Err("an element's length is not in its shortest form".into()),
        },
        _ => return Err("an element's length is in a form these files do not use".into()),
    };
    if len > rest.len() {
        return Err("an element is longer than what holds it".into());
    }
    let (content, rest) = rest.split_at(len);
    Ok((*tag, content, rest))
}

/// The entries of a SET. Returns the public point if this SET is `rk`'s (the
/// caller says so with `in_rk`) or, at the top, if its `rk` has one.
fn entries(mut bytes: &[u8], depth: usize, in_rk: bool) -> Result<Option<PublicKey>, String> {
    if depth > MAX_DEPTH {
        return Err("it is nested deeper than these files are".into());
    }
    let mut found = None;
    while !bytes.is_empty() {
        let (tag, entry, rest) = element(bytes)?;
        if tag != SEQUENCE {
            return Err("an entry is not a SEQUENCE".into());
        }
        let (tag, name, value) = element(entry)?;
        if tag != UTF8_STRING || name.is_empty() || !name.iter().all(|b| b.is_ascii_graphic()) {
            return Err("an entry does not begin with a printable name".into());
        }
        let (tag, content, nothing) = element(value)?;
        if !nothing.is_empty() {
            return Err("an entry holds more than a name and one value".into());
        }
        match tag {
            SET => {
                let inside = entries(content, depth.saturating_add(1), depth == 0 && name == b"rk")?;
                if depth == 0 && name == b"rk" {
                    let key = inside.ok_or("its `rk` entry has no public key (`pub`)")?;
                    if found.replace(key).is_some() {
                        return Err("it has two `rk` entries".into());
                    }
                }
            }
            OCTET_STRING if in_rk && name == b"pub" => {
                let [0x04, xy @ ..] = content else {
                    return Err("its public key is not an uncompressed point".into());
                };
                if xy.len() != 64 {
                    return Err("its public key is not 65 bytes".into());
                }
                let mut key = PublicKey { x: [0; 32], y: [0; 32] };
                key.x.copy_from_slice(&xy[..32]);
                key.y.copy_from_slice(&xy[32..]);
                if !valid_public_key(&key) {
                    return Err("its public key is not a point on P-256".into());
                }
                if found.replace(key).is_some() {
                    return Err("it has two public keys".into());
                }
            }
            OCTET_STRING => {}
            INTEGER if !content.is_empty() && content.len() <= 8 => {}
            BOOLEAN if content.len() == 1 => {}
            _ => return Err("a value is of a kind these files do not hold".into()),
        }
        bytes = rest;
    }
    Ok(found)
}

/// Whether `blob` has the shape of a Secure Enclave key file: well-formed
/// from the first byte to the last, with a valid public point in `rk`.
/// Returns that point, or what is wrong.
pub fn check(blob: &[u8]) -> Result<PublicKey, String> {
    if blob.is_empty() {
        return Err("it is empty".into());
    }
    if blob.len() > MAX_BLOB {
        return Err(format!("it is {} bytes, more than a key file has", blob.len()));
    }
    let (tag, content, rest) = element(blob)?;
    if tag != OCTET_STRING || !rest.is_empty() {
        return Err("it is not one OCTET STRING from the first byte to the last".into());
    }
    let (tag, set, rest) = element(content)?;
    if tag != SET || !rest.is_empty() {
        return Err("it does not hold exactly one SET".into());
    }
    entries(set, 0, false)?.ok_or_else(|| "it has no `rk` entry with a public key".to_string())
}
