//! A strict reader for the DER that key attestation needs
//! (docs/MOBILE_OWNER_DESIGN.md §5.2): X.509 certificates and Android's
//! `KeyDescription` extension, whose context tags go up to `[724]` — beyond
//! what the `der` crate's tag numbers hold. Definite, minimal lengths only;
//! every element is a slice of the input, so a signature is checked over the
//! exact bytes that were parsed. No allocation except the lists of children.

pub const UNIVERSAL: u8 = 0;
pub const CONTEXT: u8 = 2;

pub const BOOLEAN: u32 = 1;
pub const INTEGER: u32 = 2;
pub const BIT_STRING: u32 = 3;
pub const OCTET_STRING: u32 = 4;
pub const OID: u32 = 6;
pub const ENUMERATED: u32 = 10;
pub const SEQUENCE: u32 = 16;
pub const SET: u32 = 17;
pub const UTC_TIME: u32 = 23;
pub const GENERALIZED_TIME: u32 = 24;

/// One element: tag, value, and the whole element as it stood in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

/// The first element of `input` and what follows it.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let first = *input.first().ok_or("DER: empty input")?;
    let (class, constructed) = (first >> 6, first & 0x20 != 0);
    let mut i = 1;
    let mut number = (first & 0x1f) as u32;
    if number == 0x1f {
        // high-tag-number form: base 128, most significant first, minimal
        number = 0;
        loop {
            let b = *input.get(i).ok_or("DER: truncated tag")?;
            if number == 0 && b == 0x80 {
                return Err("DER: tag number with a leading zero".into());
            }
            if number > (u32::MAX >> 7) {
                return Err("DER: tag number too large".into());
            }
            number = (number << 7) | (b & 0x7f) as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        if number < 0x1f {
            return Err("DER: a low tag number in the long form".into());
        }
    }
    let l = *input.get(i).ok_or("DER: truncated length")?;
    i += 1;
    let len = if l < 0x80 {
        l as usize
    } else {
        let n = (l & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("DER: indefinite or oversized length".into());
        }
        let bytes = input.get(i..i + n).ok_or("DER: truncated length")?;
        i += n;
        let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        if bytes[0] == 0 || len < 0x80 {
            return Err("DER: a length that is not minimal".into());
        }
        len
    };
    let end = i.checked_add(len).filter(|e| *e <= input.len()).ok_or("DER: a value longer than its input")?;
    Ok((Tlv { class, constructed, number, value: &input[i..end], raw: &input[..end] }, &input[end..]))
}

/// `input` as exactly one element.
pub fn read_only(input: &[u8]) -> Result<Tlv<'_>, String> {
    let (tlv, rest) = read(input)?;
    if !rest.is_empty() {
        return Err("DER: bytes after the element".into());
    }
    Ok(tlv)
}

/// Every element in `value`, in order.
pub fn children(mut value: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    while !value.is_empty() {
        let (tlv, rest) = read(value)?;
        out.push(tlv);
        value = rest;
    }
    Ok(out)
}

impl<'a> Tlv<'a> {
    fn universal(self, number: u32, constructed: bool, what: &str) -> Result<Self, String> {
        if self.class != UNIVERSAL || self.number != number || self.constructed != constructed {
            return Err(format!("DER: {what} has an unexpected tag"));
        }
        Ok(self)
    }

    pub fn is_context(self, number: u32) -> bool {
        self.class == CONTEXT && self.number == number
    }

    pub fn sequence(self, what: &str) -> Result<Vec<Tlv<'a>>, String> {
        children(self.universal(SEQUENCE, true, what)?.value)
    }

    pub fn set(self, what: &str) -> Result<Vec<Tlv<'a>>, String> {
        children(self.universal(SET, true, what)?.value)
    }

    /// The single element inside an EXPLICIT context tag.
    pub fn explicit(self, what: &str) -> Result<Tlv<'a>, String> {
        if self.class != CONTEXT || !self.constructed {
            return Err(format!("DER: {what} is not an explicit context tag"));
        }
        read_only(self.value).map_err(|e| format!("{what}: {e}"))
    }

    pub fn octets(self, what: &str) -> Result<&'a [u8], String> {
        Ok(self.universal(OCTET_STRING, false, what)?.value)
    }

    pub fn oid(self, what: &str) -> Result<&'a [u8], String> {
        Ok(self.universal(OID, false, what)?.value)
    }

    /// A BIT STRING with no unused bits: its bytes.
    pub fn bit_string(self, what: &str) -> Result<&'a [u8], String> {
        match self.universal(BIT_STRING, false, what)?.value {
            [0, bytes @ ..] => Ok(bytes),
            _ => Err(format!("DER: {what} is a bit string with unused bits")),
        }
    }

    /// DER BOOLEAN: `0x00` or `0xff`, nothing else.
    pub fn boolean(self, what: &str) -> Result<bool, String> {
        match self.universal(BOOLEAN, false, what)?.value {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(format!("DER: {what} is not a DER boolean")),
        }
    }

    /// The content of a non-negative INTEGER, without the sign byte; minimal.
    pub fn unsigned_bytes(self, what: &str) -> Result<&'a [u8], String> {
        unsigned(self.universal(INTEGER, false, what)?.value, what)
    }

    pub fn uint(self, what: &str) -> Result<u64, String> {
        to_u64(self.unsigned_bytes(what)?, what)
    }

    pub fn enumerated(self, what: &str) -> Result<u64, String> {
        to_u64(unsigned(self.universal(ENUMERATED, false, what)?.value, what)?, what)
    }
}

fn unsigned<'a>(v: &'a [u8], what: &str) -> Result<&'a [u8], String> {
    match v {
        [] => Err(format!("DER: {what} is an empty integer")),
        [0] => Ok(v),
        [0, next, ..] if next & 0x80 != 0 => Ok(&v[1..]),
        [0, ..] => Err(format!("DER: {what} has a needless leading zero")),
        [first, ..] if first & 0x80 != 0 => Err(format!("DER: {what} is negative")),
        _ => Ok(v),
    }
}

fn to_u64(bytes: &[u8], what: &str) -> Result<u64, String> {
    if bytes.len() > 8 {
        return Err(format!("DER: {what} does not fit 64 bits"));
    }
    Ok(bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

/// A minimal DER writer for the tests that build certificates and
/// attestation records.
#[cfg(test)]
pub mod write {
    use super::*;

    /// One element with the given tag around `value`.
    pub fn tlv(class: u8, constructed: bool, number: u32, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(value.len() + 8);
        let lead = (class << 6) | if constructed { 0x20 } else { 0 };
        if number < 0x1f {
            out.push(lead | number as u8);
        } else {
            out.push(lead | 0x1f);
            let mut groups = vec![(number & 0x7f) as u8];
            let mut n = number >> 7;
            while n > 0 {
                groups.push((n & 0x7f) as u8 | 0x80);
                n >>= 7;
            }
            out.extend(groups.iter().rev());
        }
        match value.len() {
            l if l < 0x80 => out.push(l as u8),
            l if l < 0x100 => out.extend([0x81, l as u8]),
            l if l < 0x1_0000 => out.extend([0x82, (l >> 8) as u8, l as u8]),
            l => out.extend([0x83, (l >> 16) as u8, (l >> 8) as u8, l as u8]),
        }
        out.extend_from_slice(value);
        out
    }

    pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(UNIVERSAL, true, SEQUENCE, &items.concat())
    }

    pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(UNIVERSAL, true, SET, &items.concat())
    }

    /// `[number] EXPLICIT inner`.
    pub fn explicit(number: u32, inner: &[u8]) -> Vec<u8> {
        tlv(CONTEXT, true, number, inner)
    }

    pub fn octets(bytes: &[u8]) -> Vec<u8> {
        tlv(UNIVERSAL, false, OCTET_STRING, bytes)
    }

    pub fn oid(content: &[u8]) -> Vec<u8> {
        tlv(UNIVERSAL, false, OID, content)
    }

    pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
        tlv(UNIVERSAL, false, BIT_STRING, &[&[0u8][..], bytes].concat())
    }

    pub fn boolean(b: bool) -> Vec<u8> {
        tlv(UNIVERSAL, false, BOOLEAN, &[if b { 0xff } else { 0 }])
    }

    fn int_content(v: u64) -> Vec<u8> {
        let bytes = v.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let mut out = bytes[start..].to_vec();
        if out[0] & 0x80 != 0 {
            out.insert(0, 0);
        }
        out
    }

    pub fn uint(v: u64) -> Vec<u8> {
        tlv(UNIVERSAL, false, INTEGER, &int_content(v))
    }

    pub fn enumerated(v: u64) -> Vec<u8> {
        tlv(UNIVERSAL, false, ENUMERATED, &int_content(v))
    }

    pub fn utc_time(text: &str) -> Vec<u8> {
        tlv(UNIVERSAL, false, UTC_TIME, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_lengths_and_values() {
        // SEQUENCE { INTEGER 5, [704] EXPLICIT { BOOLEAN TRUE } }
        let inner = write::explicit(704, &write::boolean(true));
        assert_eq!(&inner[..3], &[0xbf, 0x85, 0x40], "704 = 5·128 + 64 in the long tag form");
        let der = write::seq(&[write::uint(5), inner]);
        let items = read_only(&der).unwrap().sequence("test").unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].uint("n").unwrap(), 5);
        assert!(items[1].is_context(704) && items[1].explicit("x").unwrap().boolean("b").unwrap());
        // every element is a slice of the input
        assert_eq!(items[0].raw, &der[2..5]);
        // long lengths
        let big = write::octets(&[7u8; 300]);
        assert_eq!(&big[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(read_only(&big).unwrap().octets("o").unwrap().len(), 300);
    }

    #[test]
    fn what_is_not_der_is_refused() {
        assert!(read(&[]).is_err());
        assert!(read(&[0x30, 0x80, 0x00, 0x00]).is_err(), "indefinite length");
        assert!(read(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_err(), "long form for a short length");
        assert!(read(&[0x04, 0x82, 0x00, 0x90]).is_err(), "a leading zero in the length");
        assert!(read(&[0x04, 0x05, 1, 2]).is_err(), "a value longer than its input");
        assert!(read(&[0xbf, 0x80, 0x01, 0x00]).is_err(), "a tag number with a leading zero");
        assert!(read(&[0xbf, 0x1e, 0x00]).is_err(), "a low tag number in the long form");
        assert!(read_only(&[0x05, 0x00, 0x00]).is_err(), "trailing bytes");
        // integers and booleans
        let int = |content: &[u8]| read_only(&write::tlv(UNIVERSAL, false, INTEGER, content)).unwrap().uint("n");
        assert_eq!(int(&[0x00, 0x80]).unwrap(), 128);
        assert!(int(&[0x00, 0x01]).is_err(), "a needless leading zero");
        assert!(int(&[0x80]).is_err(), "negative");
        assert!(int(&[]).is_err());
        assert!(int(&[1; 9]).is_err(), "more than 64 bits");
        assert!(read_only(&[0x01, 0x01, 0x01]).unwrap().boolean("b").is_err(), "0x01 is not a DER TRUE");
        assert!(read_only(&[0x03, 0x02, 0x03, 0xf8]).unwrap().bit_string("b").is_err(), "unused bits");
        // the wrong kind of element
        assert!(read_only(&write::uint(1)).unwrap().octets("o").is_err());
        assert!(read_only(&write::uint(1)).unwrap().explicit("e").is_err());
    }
}
