// The DER reader in front of key attestation (agent-signer's, taken by path:
// that crate is a binary). Whatever it accepts must be the one canonical
// encoding of what it says it read, written here by a second hand.
#![no_main]
#![allow(dead_code)]
#[path = "../../../../signer/crates/agent-signer/src/der.rs"]
mod der;

use libfuzzer_sys::fuzz_target;

fn canonical(class: u8, constructed: bool, number: u32, value: &[u8]) -> Vec<u8> {
    let mut out = vec![(class << 6) | if constructed { 0x20 } else { 0 }];
    if number < 31 {
        out[0] |= number as u8;
    } else {
        out[0] |= 31;
        let mut groups = Vec::new();
        let mut n = number;
        loop {
            groups.push((n & 0x7f) as u8);
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        for (i, g) in groups.iter().rev().enumerate() {
            out.push(if i + 1 < groups.len() { g | 0x80 } else { *g });
        }
    }
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let len = value.len().to_be_bytes();
        let len = &len[len.iter().position(|b| *b != 0).unwrap()..];
        out.push(0x80 | len.len() as u8);
        out.extend_from_slice(len);
    }
    out.extend_from_slice(value);
    out
}

fn walk(input: &[u8], depth: usize) {
    let Ok((tlv, rest)) = der::read(input) else { return };
    assert_eq!(tlv.raw.len() + rest.len(), input.len());
    assert_eq!(tlv.raw, &input[..tlv.raw.len()]);
    assert_eq!(tlv.raw, canonical(tlv.class, tlv.constructed, tlv.number, tlv.value).as_slice(), "accepted, but not the canonical encoding");
    // every reader of a value, on any element
    let _ = (tlv.octets("x"), tlv.oid("x"), tlv.bit_string("x"), tlv.boolean("x"), tlv.unsigned_bytes("x"), tlv.uint("x"), tlv.enumerated("x"));
    let _ = (tlv.sequence("x"), tlv.set("x"), tlv.explicit("x"));
    if let Ok(v) = tlv.uint("x") {
        // a number that was read is the shortest form of itself
        let bytes = v.to_be_bytes();
        let short = &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(7)..];
        let want: Vec<u8> = if short[0] & 0x80 != 0 { [&[0u8][..], short].concat() } else { short.to_vec() };
        assert_eq!(tlv.value, want.as_slice());
    }
    if tlv.constructed && depth < 16 {
        if let Ok(children) = der::children(tlv.value) {
            assert_eq!(children.iter().map(|c| c.raw.len()).sum::<usize>(), tlv.value.len());
            let mut at = tlv.value;
            for child in children {
                walk(at, depth + 1);
                at = &at[child.raw.len()..];
            }
        }
    }
    walk(rest, depth);
}

fuzz_target!(|data: &[u8]| {
    walk(data, 0);
    if let Ok(only) = der::read_only(data) {
        assert_eq!(only.raw, data);
    }
});
