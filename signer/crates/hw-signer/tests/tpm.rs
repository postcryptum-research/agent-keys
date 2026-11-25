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

/// A handle for an object that is not one of this crate's keys.
const OTHER: u32 = 0x8101_ff15;

fn raw_context() -> Context {
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0"))
        .unwrap();
    Context::new(tcti).unwrap()
}

/// A restricted decryption key (what a storage parent is), persisted at
/// `OTHER` with the TPM's own commands.
fn persist_a_storage_key() {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::interface_types::dynamic_handles::Persistent;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
    use tss_esapi::structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
    };
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .unwrap();
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .unwrap();
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap();
    let mut ctx = raw_context();
    ctx.execute_with_nullauth_session(|ctx| {
        let key = ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)?.key_handle;
        ctx.evict_control(Provision::Owner, key.into(), Persistent::Persistent(PersistentTpmHandle::new(OTHER)?))?;
        ctx.flush_context(key.into())
    })
    .unwrap();
}

/// Whether something is persisted at `handle`; with `remove`, takes it away
/// with the TPM's own command, whatever it is.
fn other_object(remove: bool) -> bool {
    use tss_esapi::interface_types::dynamic_handles::Persistent;
    use tss_esapi::interface_types::resource_handles::Provision;
    let mut ctx = raw_context();
    let handle = PersistentTpmHandle::new(OTHER).unwrap();
    let Ok(object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)) else { return false };
    if remove {
        ctx.execute_with_nullauth_session(|ctx| ctx.evict_control(Provision::Owner, object, Persistent::Persistent(handle)))
            .unwrap();
    }
    true
}

/// #178: `evict` removes a key of the kind this crate makes and nothing
/// else. A storage parent at a handle one digit away from a key's is the
/// costly mistake: every key under it goes with it.
#[test]
#[ignore = "requires a TPM"]
fn evict_refuses_what_is_not_a_signing_key() {
    if other_object(false) {
        other_object(true);
    }
    persist_a_storage_key();
    let refused = TpmSigner::evict(OTHER);
    let still = other_object(true);
    let refused = refused.unwrap_err().to_string();
    assert!(refused.contains("not an unrestricted ECC signing key") && refused.contains("not evicted"), "{refused}");
    assert!(still, "the object was still at its handle");
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
