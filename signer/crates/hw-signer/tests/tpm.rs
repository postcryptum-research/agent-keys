//! The TPM backend against a real TPM 2.0, or a software one named by
//! `TPM2TOOLS_TCTI`. Each test opens one connection at a time, which is all a
//! software TPM's socket takes.
//!
//! Run: `cargo test -p hw-signer --features tpm -- --ignored --test-threads=1`
//! (`scripts/tpm-check.sh` does).
#![cfg(feature = "tpm")]

use std::str::FromStr;

use hw_signer::tpm::{TpmSigner, DEFAULT_PARENT};
use hw_signer::SignerError;
use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};
use tss_esapi::structures::Public;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

/// A handle the tests persist a key at and evict again.
const HANDLE: u32 = 0x8101_ff11;

/// Whether the key persisted at `handle` is exempt from the dictionary-attack
/// lockout, read back from the TPM.
fn no_da(handle: u32) -> bool {
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0"))
        .unwrap();
    let mut ctx = Context::new(tcti).unwrap();
    let object = ctx
        .tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(handle).unwrap()))
        .unwrap();
    let (public, _, _) = ctx.read_public(object.into()).unwrap();
    let Public::Ecc { object_attributes, .. } = public else {
        panic!("not an ECC key");
    };
    object_attributes.no_da()
}

/// #43: a key without an authValue has no secret to guess, and under the
/// lockout it would stop signing whenever another key's authValue was
/// mistyped three times. Only a key with an authValue stays under it.
#[test]
#[ignore = "requires a TPM"]
fn only_a_key_with_an_auth_value_is_under_the_lockout() {
    type Create = fn() -> Result<TpmSigner, SignerError>;
    let cases: [(&str, Create, bool); 3] = [
        ("plain", || TpmSigner::create_under(DEFAULT_PARENT), true),
        ("sealed to a PCR", || TpmSigner::create_sealed_under(DEFAULT_PARENT, &[16]), true),
        ("behind an authValue", || TpmSigner::create_protected_under(DEFAULT_PARENT, b"a secret"), false),
    ];
    for (name, create, exempt) in cases {
        let mut signer = create().unwrap();
        signer.persist(HANDLE).unwrap();
        drop(signer);
        let got = no_da(HANDLE);
        TpmSigner::evict(HANDLE).unwrap();
        assert_eq!(got, exempt, "a key {name}");
    }
}

/// #178: `TPM2_EvictControl` on a persistent object removes it. A second
/// `persist`, on the signer that persisted the key or on one that opened it,
/// is refused and the key is still there.
#[test]
#[ignore = "requires a TPM"]
fn persisting_twice_is_refused_and_the_key_stays() {
    let mut signer = TpmSigner::create_under(DEFAULT_PARENT).unwrap();
    signer.persist(HANDLE).unwrap();
    let key = hw_signer::HardwareSigner::public_key(&signer).unwrap();

    let again = signer.persist(HANDLE).unwrap_err().to_string();
    assert!(again.contains("already persistent"), "{again}");
    drop(signer);

    let mut opened = TpmSigner::open_persistent(HANDLE).expect("the key is still at its handle");
    let again = opened.persist(HANDLE).unwrap_err().to_string();
    assert!(again.contains("already persistent"), "{again}");
    drop(opened);

    let still = TpmSigner::open_persistent(HANDLE).expect("the key is still at its handle");
    let same = hw_signer::HardwareSigner::public_key(&still).unwrap();
    drop(still);
    TpmSigner::evict(HANDLE).unwrap();
    assert!(key.x == same.x && key.y == same.y, "the same key");
}

/// #43: the TPM's words for an empty handle are "the handle is not correct
/// for the use". The error has to say what is missing, where, and what to do.
#[test]
#[ignore = "requires a TPM"]
fn an_empty_handle_is_named() {
    let Err(no_parent) = TpmSigner::create_under(0x81ff_ff7e) else {
        panic!("created a key under a parent that is not there");
    };
    let text = no_parent.to_string();
    assert!(text.contains("no storage parent at 0x81ffff7e"), "{text}");
    assert!(text.contains("docs/FAQ.md"), "{text}");

    let Err(no_key) = TpmSigner::open_persistent(HANDLE) else {
        panic!("opened a key that is not there");
    };
    assert!(no_key.to_string().contains("no key at 0x8101ff11"), "{no_key}");
    let Err(nothing_to_evict) = TpmSigner::evict(HANDLE) else {
        panic!("evicted a key that is not there");
    };
    assert!(nothing_to_evict.to_string().contains("no key at 0x8101ff11"), "{nothing_to_evict}");
}
