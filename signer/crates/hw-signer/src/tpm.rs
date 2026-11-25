//! Linux TPM 2.0 backend via `tss-esapi` (Enhanced System API).
//!
//! Keys are created under a storage parent — by default the SRK that
//! distributions (systemd) persist at `0x81000001`, the same handle the Python
//! prototype used — and never leave the chip: `create` hands back the private
//! part wrapped by the parent, and `sign` runs inside the TPM.
//!
//! The key is an *unrestricted* P-256 signing key. That matters: a restricted
//! key only signs digests the TPM hashed itself (proved by a hash-check
//! ticket), while we need it to sign a host-computed `userOpHash`.
//!
//! A key can instead be *protected by an authValue*: the TPM then signs only
//! for a caller presenting it. That is how an owner key shares the chip with
//! the agent key (docs/KEY_POLICY.md, rule 3): the secret lives in a file
//! only root can read, so the agent's ordinary user cannot use the key. The
//! authValue is SHA-256 of the file's contents (trailing whitespace trimmed),
//! so any passphrase length fits the TPM's 32-byte limit.
//!
//! A key can additionally be *sealed to PCRs*: its auth policy is
//! `TPM2_PolicyPCR` over a set of platform configuration registers, so the
//! chip only signs while the measured boot state equals the one the key was
//! created under. After a firmware or bootloader change the key goes silent
//! and the owner rotates the agent permission to a fresh one.
//!
//! A key *without* an authValue is exempt from the dictionary-attack lockout
//! (`noDA`): see [`p256_signing_template`].

use std::str::FromStr;
use std::sync::Mutex;

use sha2::{Digest as Sha2Digest, Sha256};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme,
    PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder,
    PublicEccParametersBuilder, Signature as TpmSignature, SignatureScheme, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::Context;

use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

/// Storage parent for new keys: the owner-hierarchy SRK as persisted by systemd.
pub const DEFAULT_PARENT: u32 = 0x8100_0001;

/// The kernel resource manager, not the raw `/dev/tpm0`: it is group `tss`
/// rather than root-only, and it multiplexes handles between clients.
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// A P-256 key living in the TPM, either transient (flushed on drop) or
/// persistent (survives reboots at a `0x81xxxxxx` handle), optionally sealed
/// to a PCR selection.
pub struct TpmSigner {
    ctx: Mutex<Context>,
    key: KeyHandle,
    persistent: bool,
    sealed_to: Option<PcrSelectionList>,
    /// The authValue the key was created with, if any; re-applied whenever
    /// the key's ESYS handle changes (persisting).
    auth: Option<Auth>,
}

/// The authValue for a secret (a passphrase file's contents).
fn auth_from_secret(secret: &[u8]) -> Result<Auth, SignerError> {
    let trimmed = secret.trim_ascii_end();
    if trimmed.is_empty() {
        return Err(SignerError::Key("empty auth secret".into()));
    }
    Auth::try_from(Sha256::digest(trimmed).to_vec()).map_err(tss)
}

fn tss(e: tss_esapi::Error) -> SignerError {
    SignerError::Backend(e.to_string())
}

/// TPM2B_ECC_PARAMETER values are curve-sized, but left-pad defensively.
fn pad32(bytes: &[u8]) -> Result<[u8; 32], SignerError> {
    if bytes.len() > 32 {
        return Err(SignerError::Backend(format!("field element of {} bytes", bytes.len())));
    }
    let mut out = [0u8; 32];
    // the length was checked above: the start is within the word
    out[32usize.saturating_sub(bytes.len())..].copy_from_slice(bytes);
    Ok(out)
}

fn connect() -> Result<Context, SignerError> {
    // Honour TPM2TOOLS_TCTI / TCTI if set (e.g. a simulator), else the RM device.
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str(DEFAULT_TCTI))
        .map_err(tss)?;
    let mut ctx = Context::new(tcti).map_err(tss)?;
    // Password session with an empty auth value: the SRK and our keys carry no
    // password. Sealed keys authorize through a policy session instead.
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    Ok(ctx)
}

/// `auth_policy` makes the key usable only through a session that satisfies
/// that policy; `user_with_auth` is then cleared so the (empty) password
/// cannot bypass it.
///
/// `auth_value` is the authValue the key is created with, if any, and it
/// decides `noDA` here and nowhere else (#43, #52): **a key is exempt from
/// the dictionary-attack lockout exactly when it has no authValue.** A plain
/// key and a PCR-sealed key have no secret to guess, and without the
/// exemption they stop signing whenever the TPM is in lockout: another key's
/// wrong authValues cause that, and so do unclean stops of the TPM after a
/// signature; a virtual TPM allows three (docs/SERVER_KEY_STORES.md §8.2).
/// A key with an authValue stays under the lockout, which is the only limit
/// on guesses at it: the two must never be combined, so the template takes
/// the authValue and not a flag. The exemption is a fix for availability,
/// not a strengthening of custody.
///
/// The attribute is part of the key's public area, so it changes the key's
/// name and not its public point: a config that references the handle is
/// unaffected. Attributes are fixed at creation, so a key made before #43
/// keeps the old behaviour.
fn p256_signing_template(auth_policy: Option<Digest>, auth_value: Option<&Auth>) -> Result<Public, SignerError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_no_da(auth_value.is_none())
        .with_user_with_auth(auth_policy.is_none())
        .with_sign_encrypt(true)
        .with_restricted(false)
        .with_decrypt(false)
        .build()
        .map_err(tss)?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(tss)?;
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default());
    if let Some(policy) = auth_policy {
        builder = builder.with_auth_policy(policy);
    }
    builder.build().map_err(tss)
}

// --- PCR policy helpers ---

fn pcr_slot(index: u8) -> Result<PcrSlot, SignerError> {
    use PcrSlot::*;
    Ok(match index {
        0 => Slot0,
        1 => Slot1,
        2 => Slot2,
        3 => Slot3,
        4 => Slot4,
        5 => Slot5,
        6 => Slot6,
        7 => Slot7,
        8 => Slot8,
        9 => Slot9,
        10 => Slot10,
        11 => Slot11,
        12 => Slot12,
        13 => Slot13,
        14 => Slot14,
        15 => Slot15,
        16 => Slot16,
        17 => Slot17,
        18 => Slot18,
        19 => Slot19,
        20 => Slot20,
        21 => Slot21,
        22 => Slot22,
        23 => Slot23,
        _ => return Err(SignerError::Backend(format!("PCR index {index} out of range"))),
    })
}

/// Sorted, de-duplicated PCR indices: `TPM2_PolicyPCR` digests the selected
/// registers in ascending order, so the caller's order must not matter.
fn normalize_pcrs(pcrs: &[u8]) -> Result<Vec<u8>, SignerError> {
    if pcrs.is_empty() {
        return Err(SignerError::Backend("sealing needs at least one PCR".into()));
    }
    let mut v = pcrs.to_vec();
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

fn pcr_selection(pcrs: &[u8]) -> Result<PcrSelectionList, SignerError> {
    let slots = pcrs.iter().map(|&i| pcr_slot(i)).collect::<Result<Vec<_>, _>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(tss)
}

/// SHA-256 over the concatenated current values of the selected PCRs — the
/// `pcrDigest` that `TPM2_PolicyPCR` commits a trial session to. `pcr_read`
/// returns the digests in selection order (ascending index), which is also
/// the order PolicyPCR hashes them in.
fn current_pcr_digest(ctx: &mut Context, selection: &PcrSelectionList, pcrs: &[u8]) -> Result<Digest, SignerError> {
    let (_, _, digests) = ctx
        .execute_without_session(|ctx| ctx.pcr_read(selection.clone()))
        .map_err(tss)?;
    let values = digests.value();
    if values.len() != pcrs.len() {
        return Err(SignerError::Backend(format!(
            "asked for {} PCRs, the TPM returned {} (at most 8 per read)",
            pcrs.len(),
            values.len()
        )));
    }
    let mut concat = Vec::with_capacity(values.len().saturating_mul(32));
    for value in values {
        concat.extend_from_slice(value.value());
    }
    Digest::try_from(Sha256::digest(&concat).to_vec()).map_err(tss)
}

fn start_policy_session(ctx: &mut Context, kind: SessionType) -> Result<AuthSession, SignerError> {
    let session = ctx
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                None,
                None,
                None,
                kind,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(tss)?
        .ok_or_else(|| SignerError::Backend("TPM returned no session handle".into()))?;
    let (attributes, mask) = SessionAttributesBuilder::new().with_decrypt(true).with_encrypt(true).build();
    ctx.tr_sess_set_attributes(session, attributes, mask).map_err(tss)?;
    Ok(session)
}

fn flush_session(ctx: &mut Context, session: AuthSession) {
    let _ = ctx.flush_context(ObjectHandle::from(SessionHandle::from(session)));
}

/// The policy digest a key must carry to be bound to the current values of
/// `pcrs`: computed in a trial session, exactly as the real session will
/// recompute it at signing time.
fn pcr_policy_digest(ctx: &mut Context, selection: &PcrSelectionList, pcrs: &[u8]) -> Result<Digest, SignerError> {
    let pcr_digest = current_pcr_digest(ctx, selection, pcrs)?;
    let trial = start_policy_session(ctx, SessionType::Trial)?;
    let policy = ctx.execute_without_session(|ctx| -> Result<Digest, SignerError> {
        let session = PolicySession::try_from(trial).map_err(tss)?;
        ctx.policy_pcr(session, pcr_digest, selection.clone()).map_err(tss)?;
        ctx.policy_get_digest(session).map_err(tss)
    });
    flush_session(ctx, trial);
    policy
}

impl TpmSigner {
    /// `what` is expected at `handle`; `hint` is what to do when nothing is
    /// there. The TPM's own words for an empty handle are "the handle is not
    /// correct for the use", which names neither (#43).
    fn resolve(ctx: &mut Context, handle: u32, what: &str, hint: &str) -> Result<KeyHandle, SignerError> {
        let persistent = PersistentTpmHandle::new(handle).map_err(tss)?;
        // ReadPublic takes no authorization, so resolve outside the password
        // session (tss-esapi's documented usage). With the session set this
        // crashed inside Esys_TR_FromTPMPublic_Finish on tpm2-tss 4.0.1.
        let object = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)))
            .map_err(|e| match e {
                tss_esapi::Error::Tss2Error(rc) if rc.kind() == Some(Tss2ResponseCodeKind::Handle) => {
                    SignerError::Key(format!("no {what} at 0x{handle:08x}{hint}"))
                }
                other => tss(other),
            })?;
        Ok(object.into())
    }

    fn resolve_key(ctx: &mut Context, handle: u32) -> Result<KeyHandle, SignerError> {
        Self::resolve(ctx, handle, "key", "")
    }

    fn create(parent: u32, sealed_to: Option<&[u8]>, secret: Option<&[u8]>) -> Result<Self, SignerError> {
        if sealed_to.is_some() && secret.is_some() {
            return Err(SignerError::Key("a key is either sealed to PCRs or protected by an authValue, not both".into()));
        }
        let auth = secret.map(auth_from_secret).transpose()?;
        let mut ctx = connect()?;
        let (policy, selection) = match sealed_to {
            None => (None, None),
            Some(pcrs) => {
                let pcrs = normalize_pcrs(pcrs)?;
                let selection = pcr_selection(&pcrs)?;
                let policy = pcr_policy_digest(&mut ctx, &selection, &pcrs)?;
                (Some(policy), Some(selection))
            }
        };
        let parent = Self::resolve(
            &mut ctx,
            parent,
            "storage parent",
            ": persist one there first (docs/FAQ.md, \"Create the keys\"), or name another parent",
        )?;
        let created = ctx
            .create(parent, p256_signing_template(policy, auth.as_ref())?, auth.clone(), None, None, None)
            .map_err(tss)?;
        let key = ctx
            .load(parent, created.out_private, created.out_public)
            .map_err(tss)?;
        if let Some(auth) = &auth {
            ctx.tr_set_auth(key.into(), auth.clone()).map_err(tss)?;
        }
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: false, sealed_to: selection, auth })
    }

    /// Generate a fresh P-256 key inside the TPM under `parent` and load it.
    /// The key is transient: it is flushed when the signer is dropped unless
    /// [`persist`](Self::persist) is called.
    pub fn create_under(parent: u32) -> Result<Self, SignerError> {
        Self::create(parent, None, None)
    }

    /// Like [`create_under`](Self::create_under), but the TPM signs only for
    /// a caller presenting the authValue derived from `secret`.
    pub fn create_protected_under(parent: u32, secret: &[u8]) -> Result<Self, SignerError> {
        Self::create(parent, None, Some(secret))
    }

    /// Like [`create_under`](Self::create_under), but the key only signs
    /// while the SHA-256 values of `pcrs` equal their values right now.
    pub fn create_sealed_under(parent: u32, pcrs: &[u8]) -> Result<Self, SignerError> {
        Self::create(parent, Some(pcrs), None)
    }

    /// Use a key previously persisted at `handle`.
    pub fn open_persistent(handle: u32) -> Result<Self, SignerError> {
        let mut ctx = connect()?;
        let key = Self::resolve_key(&mut ctx, handle)?;
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: true, sealed_to: None, auth: None })
    }

    /// Use a persisted key protected by an authValue, presenting the one
    /// derived from `secret`. A wrong secret is not detected here: the TPM
    /// refuses to sign (and counts the failure against its lockout).
    pub fn open_persistent_protected(handle: u32, secret: &[u8]) -> Result<Self, SignerError> {
        let auth = auth_from_secret(secret)?;
        let mut ctx = connect()?;
        let key = Self::resolve_key(&mut ctx, handle)?;
        ctx.tr_set_auth(key.into(), auth.clone()).map_err(tss)?;
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: true, sealed_to: None, auth: Some(auth) })
    }

    /// Use a persisted key that was sealed to `pcrs` (the TPM does not record
    /// the selection with the key, so the caller supplies it).
    pub fn open_persistent_sealed(handle: u32, pcrs: &[u8]) -> Result<Self, SignerError> {
        let mut ctx = connect()?;
        let key = Self::resolve_key(&mut ctx, handle)?;
        let selection = pcr_selection(&normalize_pcrs(pcrs)?)?;
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: true, sealed_to: Some(selection), auth: None })
    }

    /// Persist the loaded key at `handle` (owner hierarchy) so it survives
    /// reboots and process restarts. Once only: a key that is already
    /// persistent (after this call, or opened with `open_persistent*`) is
    /// refused. `TPM2_EvictControl` on a persistent object **removes** it, so
    /// a second call, made to be sure or as a retry, would delete the key
    /// and report success (#178).
    pub fn persist(&mut self, handle: u32) -> Result<(), SignerError> {
        if self.persistent {
            return Err(SignerError::Backend(format!(
                "this key is already persistent: persisting it again at {handle:#010x} would evict it from the TPM"
            )));
        }
        let target = PersistentTpmHandle::new(handle).map_err(tss)?;
        let key = self.key;
        let persisted = {
            let mut ctx = self.ctx.lock().map_err(|_| SignerError::Backend("poisoned lock".into()))?;
            let persisted = ctx
                .evict_control(Provision::Owner, key.into(), Persistent::Persistent(target))
                .map_err(tss)?;
            let _ = ctx.flush_context(key.into());
            // The persistent handle is a new ESYS object: give it the auth too.
            if let Some(auth) = &self.auth {
                ctx.tr_set_auth(persisted, auth.clone()).map_err(tss)?;
            }
            persisted
        };
        self.key = persisted.into();
        self.persistent = true;
        Ok(())
    }

    /// Remove a persisted key from the TPM. Only an unrestricted ECC signing
    /// key, the kind this crate makes: anything else at the handle (a storage
    /// parent, another tool's object) is refused and left where it is.
    pub fn evict(handle: u32) -> Result<(), SignerError> {
        let mut ctx = connect()?;
        let target = PersistentTpmHandle::new(handle).map_err(tss)?;
        let object = Self::resolve_key(&mut ctx, handle)?;
        // Only a key of the kind this crate makes. A handle is typed by hand,
        // and one digit away from a key may be the storage parent every key
        // on the machine hangs from: evicting that is not undone (#178).
        let (public, _, _) = ctx.execute_without_session(|ctx| ctx.read_public(object)).map_err(tss)?;
        let ours = match &public {
            Public::Ecc { object_attributes, .. } => {
                object_attributes.sign_encrypt() && !object_attributes.restricted() && !object_attributes.decrypt()
            }
            _ => false,
        };
        if !ours {
            return Err(SignerError::Key(format!(
                "the object at {handle:#010x} is not an unrestricted ECC signing key (it is a storage parent, or another \
                 tool's object): not evicted. `tpm2_evictcontrol` removes such an object, if that is what you mean"
            )));
        }
        ctx.evict_control(Provision::Owner, object.into(), Persistent::Persistent(target))
            .map_err(tss)?;
        Ok(())
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed_to.is_some()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Context>, SignerError> {
        self.ctx.lock().map_err(|_| SignerError::Backend("poisoned lock".into()))
    }

    /// Run a raw ESAPI call on this signer's context (tests: PCR extend/reset).
    #[cfg(test)]
    fn with_ctx<T>(&self, f: impl FnOnce(&mut Context) -> tss_esapi::Result<T>) -> Result<T, SignerError> {
        let mut ctx = self.lock()?;
        f(&mut ctx).map_err(tss)
    }
}

impl HardwareSigner for TpmSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        let mut ctx = self.lock()?;
        let key = self.key;
        // ReadPublic has no auth area: run it outside the password session.
        let (public, _, _) = ctx
            .execute_without_session(|ctx| ctx.read_public(key))
            .map_err(tss)?;
        let Public::Ecc { unique, .. } = public else {
            return Err(SignerError::Key("not an ECC key".into()));
        };
        Ok(PublicKey { x: pad32(unique.x().value())?, y: pad32(unique.y().value())? })
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let mut ctx = self.lock()?;
        let digest = Digest::try_from(digest.to_vec()).map_err(tss)?;
        // Null ticket: accepted for unrestricted keys signing host digests.
        let validation = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        })
        .map_err(tss)?;
        let scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        let key = self.key;

        let signed = match &self.sealed_to {
            None => ctx.sign(key, digest, scheme, validation).map_err(|e| match e {
                // The TPM's words are "authValue or authPolicy is not available
                // for selected entity": the key answers to a policy only, and
                // it was opened without one. Every other refusal (a wrong
                // authValue, a lockout) keeps the TPM's own words (#49).
                tss_esapi::Error::Tss2Error(rc) if rc.kind() == Some(Tss2ResponseCodeKind::AuthUnavailable) => SignerError::Key(
                    "this key is sealed to PCRs and was opened without them: give the selection it was created with \
                     (--pcrs, or \"pcrs\" in the config)"
                        .into(),
                ),
                other => tss(other),
            }),
            Some(selection) => {
                let selection = selection.clone();
                let session = start_policy_session(&mut ctx, SessionType::Policy)?;
                // An empty pcrDigest tells TPM2_PolicyPCR to use the registers'
                // current values; the session then satisfies the key's policy
                // only if those equal the values the key was sealed to, and
                // the TPM refuses to sign otherwise.
                let armed = ctx.execute_without_session(|ctx| {
                    let policy = PolicySession::try_from(session).map_err(tss)?;
                    ctx.policy_pcr(policy, Digest::default(), selection).map_err(tss)
                });
                let signed = match armed {
                    Ok(()) => ctx
                        .execute_with_session(Some(session), |ctx| ctx.sign(key, digest, scheme, validation))
                        .map_err(tss),
                    Err(e) => Err(e),
                };
                flush_session(&mut ctx, session);
                signed
            }
        };
        let TpmSignature::EcDsa(sig) = signed? else {
            return Err(SignerError::Sign("TPM returned a non-ECDSA signature".into()));
        };
        let r = pad32(sig.signature_r().value())?;
        let s = pad32(sig.signature_s().value())?;
        Ok(normalize_low_s(Signature { r, s }))
    }
}

impl Drop for TpmSigner {
    fn drop(&mut self) {
        if !self.persistent {
            if let Ok(mut ctx) = self.ctx.lock() {
                let _ = ctx.flush_context(ObjectHandle::from(self.key));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;
    use tss_esapi::handles::PcrHandle;
    use tss_esapi::structures::DigestValues;

    /// Needs a real TPM (`/dev/tpmrm0`, `tss` group).
    /// Run: `cargo test --features tpm -- --ignored`
    #[test]
    #[ignore = "requires TPM hardware"]
    fn tpm_key_signs_and_verifies() {
        let signer = TpmSigner::create_under(DEFAULT_PARENT).unwrap();
        let pk = signer.public_key().unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));
    }

    /// PCR 16 is the resettable debug register, so a key sealed to it can be
    /// locked out and restored within one test: extend → the TPM refuses to
    /// sign; reset → it signs again.
    #[test]
    #[ignore = "requires TPM hardware"]
    fn sealed_key_follows_pcr16() {
        let signer = TpmSigner::create_sealed_under(DEFAULT_PARENT, &[16]).unwrap();
        assert!(signer.is_sealed());
        let pk = signer.public_key().unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        // "Boot state changed": extend PCR 16 with an arbitrary measurement.
        let mut tamper = DigestValues::new();
        tamper.set(HashingAlgorithm::Sha256, Digest::try_from(Sha256::digest(b"tamper").to_vec()).unwrap());
        signer.with_ctx(|ctx| ctx.pcr_extend(PcrHandle::Pcr16, tamper)).unwrap();
        assert!(signer.sign_digest(&digest).is_err(), "a sealed key must refuse to sign after a PCR change");

        signer.with_ctx(|ctx| ctx.pcr_reset(PcrHandle::Pcr16)).unwrap();
        let again = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &again, &pk));
    }

    /// An authValue-protected key (the owner key sharing a chip with the
    /// agent, docs/KEY_POLICY.md rule 3): the TPM signs with the right
    /// secret and refuses without it. Each refusal counts against the TPM's
    /// dictionary-attack lockout (31 failures, one recovered every 10 min
    /// on Intel PTT), so the test spends exactly two.
    #[test]
    #[ignore = "requires TPM hardware"]
    fn protected_key_signs_only_with_its_auth() {
        let signer = TpmSigner::create_protected_under(DEFAULT_PARENT, b"correct horse battery\n").unwrap();
        let pk = signer.public_key().unwrap();
        let digest = [0x5au8; 32];
        let sig = signer.sign_digest(&digest).unwrap();
        assert!(verify_p256(&digest, &sig, &pk));

        // a wrong secret: the TPM must refuse
        let wrong = auth_from_secret(b"wrong horse").unwrap();
        signer.with_ctx(|ctx| ctx.tr_set_auth(signer.key.into(), wrong)).unwrap();
        assert!(signer.sign_digest(&digest).is_err(), "signed with a wrong authValue");

        // no secret at all (the empty authValue an unprotected key uses)
        signer.with_ctx(|ctx| ctx.tr_set_auth(signer.key.into(), Auth::default())).unwrap();
        let refused = signer.sign_digest(&digest).expect_err("signed with an empty authValue");
        assert!(!refused.to_string().contains("sealed to PCRs"), "a wrong authValue is not a missing policy (#49): {refused}");

        // trailing whitespace is not part of the secret
        let right = auth_from_secret(b"correct horse battery").unwrap();
        signer.with_ctx(|ctx| ctx.tr_set_auth(signer.key.into(), right)).unwrap();
        assert!(verify_p256(&digest, &signer.sign_digest(&digest).unwrap(), &pk));
    }
}
