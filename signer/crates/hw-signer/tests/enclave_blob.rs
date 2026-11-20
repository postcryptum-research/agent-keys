//! The shape check of a Secure Enclave key file (issue #78), on a blob built
//! here in the form of a real one: the same entries, lengths and nesting,
//! with the curve's base point as its public key and filler for the rest. No
//! enclave is involved: a damaged file must be refused before CryptoKit, and
//! that is plain Rust, tested on any platform.

use hw_signer::enclave_blob::{check, MAX_BLOB};

/// What a byte of the blob is, for the tests that damage it.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Role {
    /// A tag or a length.
    Structure,
    /// The public point.
    Point,
    /// A letter of `rk` or `pub`.
    NeededName,
    /// A letter of another entry's name.
    Name,
    /// The content of any other value.
    Value,
}

type Bytes = Vec<(u8, Role)>;

fn tagged(tag: u8, content: Bytes) -> Bytes {
    let n = content.len();
    let mut header = vec![tag];
    match n {
        0..=0x7f => header.push(n as u8),
        0x80..=0xff => header.extend([0x81, n as u8]),
        _ => header.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    header.into_iter().map(|b| (b, Role::Structure)).chain(content).collect()
}

fn entry(name: &str, value: Bytes) -> Bytes {
    let role = if name == "rk" || name == "pub" { Role::NeededName } else { Role::Name };
    let name = tagged(0x0c, name.bytes().map(|b| (b, role)).collect());
    tagged(0x30, name.into_iter().chain(value).collect())
}

fn set(entries: Vec<Bytes>) -> Bytes {
    tagged(0x31, entries.concat())
}

fn octets(len: usize, role: Role) -> Bytes {
    tagged(0x04, (0..len).map(|i| ((0xa5 ^ i as u8), role)).collect())
}

fn integer(n: u8) -> Bytes {
    tagged(0x02, vec![(n, Role::Value)])
}

fn boolean() -> Bytes {
    tagged(0x01, vec![(0xff, Role::Value)])
}

/// The base point of P-256, uncompressed.
const POINT: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

fn point() -> Bytes {
    tagged(0x04, POINT.iter().map(|&b| (b, Role::Point)).collect())
}

/// A blob in the form of a key file, with what each byte is.
fn blob_with(rk: Vec<Bytes>) -> Bytes {
    let acl = ["ock", "odel", "osgn", "oa", "okd"].iter().map(|name| entry(name, boolean())).collect();
    tagged(0x04, set(vec![entry("rk", set(rk)), entry("ed", set(vec![entry("acl", set(acl))]))]))
}

fn rk() -> Vec<Bytes> {
    vec![
        entry("bid", octets(4, Role::Value)),
        entry("pub", point()),
        entry("rko", integer(0)),
        entry("kt", integer(4)),
        entry("wk", octets(40, Role::Value)),
        entry("bc", integer(9)),
        entry("kv", integer(2)),
        entry("kid", octets(16, Role::Value)),
        entry("rkm", octets(32, Role::Value)),
    ]
}

fn bytes(labelled: &Bytes) -> Vec<u8> {
    labelled.iter().map(|(b, _)| *b).collect()
}

#[test]
fn a_well_formed_blob_passes_and_gives_its_public_key() {
    let blob = bytes(&blob_with(rk()));
    assert_eq!(blob.len(), 324, "the fixture has the length of a real key file");
    let key = check(&blob).expect("the fixture is well-formed");
    assert_eq!((&key.x[..], &key.y[..]), (&POINT[1..33], &POINT[33..]));
}

/// Every single-bit change in a tag, a length, the public point or the names
/// `rk` and `pub` is refused: none of these reaches CryptoKit.
#[test]
fn every_bit_of_the_structure_and_of_the_public_key_is_held() {
    let labelled = blob_with(rk());
    let blob = bytes(&labelled);
    let (mut held, mut passed) = (0, Vec::new());
    for (i, (_, role)) in labelled.iter().enumerate() {
        if !matches!(role, Role::Structure | Role::Point | Role::NeededName) {
            continue;
        }
        for bit in 0..8 {
            let mut damaged = blob.clone();
            damaged[i] ^= 1 << bit;
            match check(&damaged) {
                Err(_) => held += 1,
                Ok(_) => passed.push((i, bit, *role)),
            }
        }
    }
    assert!(passed.is_empty(), "accepted with a bit changed at {passed:?}");
    assert!(held > 8 * 65, "{held} changes tried");
}

/// What the check cannot see, stated as a test so that it is not mistaken for
/// more: a change inside another value, or a name changed into another
/// printable one, leaves a well-formed file. A name that stops being printable
/// is refused.
#[test]
fn a_change_inside_a_value_is_not_seen() {
    let labelled = blob_with(rk());
    let blob = bytes(&labelled);
    for (i, (byte, role)) in labelled.iter().enumerate() {
        for bit in 0..8 {
            let mut damaged = blob.clone();
            damaged[i] ^= 1 << bit;
            match role {
                Role::Value => assert!(check(&damaged).is_ok(), "a value byte at {i}, bit {bit}"),
                Role::Name => {
                    assert_eq!(
                        check(&damaged).is_ok(),
                        (byte ^ (1 << bit)).is_ascii_graphic(),
                        "a name byte at {i}, bit {bit}"
                    )
                }
                _ => {}
            }
        }
    }
}

#[test]
fn a_cut_or_padded_file_is_refused() {
    let blob = bytes(&blob_with(rk()));
    for len in 0..blob.len() {
        assert!(check(&blob[..len]).is_err(), "the first {len} bytes");
    }
    assert!(check(&[]).unwrap_err().contains("empty"));
    let mut padded = blob.clone();
    padded.push(0);
    assert!(check(&padded).is_err(), "a byte after the end");
    assert!(check(&vec![0u8; MAX_BLOB + 1]).unwrap_err().contains("more than a key file has"));
    // nothing but zeros, and nothing but ones, of a key file's length
    assert!(check(&[0u8; 324]).is_err());
    assert!(check(&[0xffu8; 324]).is_err());
}

#[test]
fn a_blob_without_one_valid_public_key_is_refused() {
    let without: Vec<Bytes> = rk().into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, e)| e).collect();
    assert!(check(&bytes(&blob_with(without.clone()))).unwrap_err().contains("no public key"));

    let mut twice = rk();
    twice.push(entry("pub", point()));
    assert!(check(&bytes(&blob_with(twice))).unwrap_err().contains("two public keys"));

    // a point of the wrong length, a compressed one, and one that is not on the curve
    for (wrong, why) in [
        (octets(64, Role::Point), "uncompressed point"),
        (tagged(0x04, POINT[..33].iter().map(|&b| (b, Role::Point)).collect()), "65 bytes"),
        (
            tagged(0x04, std::iter::once(0x04).chain([7u8; 64]).map(|b| (b, Role::Point)).collect()),
            "not a point on P-256",
        ),
    ] {
        let mut entries = without.clone();
        entries.push(entry("pub", wrong));
        let refused = check(&bytes(&blob_with(entries))).unwrap_err();
        assert!(refused.contains(why), "{refused}");
    }

    // a public key outside `rk` is not the key's
    let acl = vec![entry("pub", point())];
    let elsewhere = tagged(0x04, set(vec![entry("rk", set(without)), entry("ed", set(acl))]));
    assert!(check(&bytes(&elsewhere)).unwrap_err().contains("no public key"));
}

#[test]
fn other_kinds_of_value_and_deep_nesting_are_refused() {
    // a NULL, a UTF8String and a SEQUENCE where a value is expected
    for value in [tagged(0x05, vec![]), tagged(0x0c, vec![(b'x', Role::Value)]), tagged(0x30, vec![])] {
        let mut entries = rk();
        entries.push(entry("new", value));
        assert!(check(&bytes(&blob_with(entries))).unwrap_err().contains("a kind these files do not hold"));
    }
    // a BOOLEAN of two bytes, an INTEGER of none
    for value in [tagged(0x01, vec![(0, Role::Value); 2]), tagged(0x02, vec![])] {
        let mut entries = rk();
        entries.push(entry("new", value));
        assert!(check(&bytes(&blob_with(entries))).is_err());
    }
    // sets inside sets, far deeper than a key file
    let mut deep = set(vec![]);
    for _ in 0..12 {
        deep = set(vec![entry("in", deep)]);
    }
    let mut entries = rk();
    entries.push(entry("deep", deep));
    assert!(check(&bytes(&blob_with(entries))).unwrap_err().contains("nested deeper"));
    // a length in a longer form than it needs
    let mut long_form = bytes(&blob_with(rk()));
    assert_eq!(&long_form[..4], [0x04, 0x82, 0x01, 0x40]);
    long_form.splice(4..6, [0x31, 0x83, 0x00]);
    assert!(check(&long_form).is_err());
}
