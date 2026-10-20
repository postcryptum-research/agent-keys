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

use std::str::FromStr;
use std::sync::Mutex;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme,
    Public, PublicBuilder, PublicEccParametersBuilder, Signature as TpmSignature,
    SignatureScheme, SymmetricDefinitionObject,
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
/// persistent (survives reboots at a `0x81xxxxxx` handle).
pub struct TpmSigner {
    ctx: Mutex<Context>,
    key: KeyHandle,
    persistent: bool,
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
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn connect() -> Result<Context, SignerError> {
    // Honour TPM2TOOLS_TCTI / TCTI if set (e.g. a simulator), else the RM device.
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str(DEFAULT_TCTI))
        .map_err(tss)?;
    let mut ctx = Context::new(tcti).map_err(tss)?;
    // Password session with an empty auth value: the SRK and our keys carry no
    // password. PCR / policy binding is a later phase.
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    Ok(ctx)
}

fn p256_signing_template() -> Result<Public, SignerError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
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
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(tss)
}

impl TpmSigner {
    fn resolve(ctx: &mut Context, handle: u32) -> Result<KeyHandle, SignerError> {
        let handle = PersistentTpmHandle::new(handle).map_err(tss)?;
        // ReadPublic takes no authorization, so resolve outside the password
        // session (tss-esapi's documented usage). With the session set this
        // crashed inside Esys_TR_FromTPMPublic_Finish on tpm2-tss 4.0.1.
        let object = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))
            .map_err(tss)?;
        Ok(object.into())
    }

    /// Generate a fresh P-256 key inside the TPM under `parent` and load it.
    /// The key is transient: it is flushed when the signer is dropped unless
    /// [`persist`](Self::persist) is called.
    pub fn create_under(parent: u32) -> Result<Self, SignerError> {
        let mut ctx = connect()?;
        let parent = Self::resolve(&mut ctx, parent)?;
        let created = ctx
            .create(parent, p256_signing_template()?, None, None, None, None)
            .map_err(tss)?;
        let key = ctx
            .load(parent, created.out_private, created.out_public)
            .map_err(tss)?;
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: false })
    }

    /// Use a key previously persisted at `handle`.
    pub fn open_persistent(handle: u32) -> Result<Self, SignerError> {
        let mut ctx = connect()?;
        let key = Self::resolve(&mut ctx, handle)?;
        Ok(Self { ctx: Mutex::new(ctx), key, persistent: true })
    }

    /// Persist the loaded key at `handle` (owner hierarchy) so it survives
    /// reboots and process restarts.
    pub fn persist(&mut self, handle: u32) -> Result<(), SignerError> {
        let target = PersistentTpmHandle::new(handle).map_err(tss)?;
        let mut ctx = self.ctx.lock().map_err(|_| SignerError::Backend("poisoned lock".into()))?;
        let persisted = ctx
            .evict_control(Provision::Owner, self.key.into(), Persistent::Persistent(target))
            .map_err(tss)?;
        let _ = ctx.flush_context(self.key.into());
        self.key = persisted.into();
        self.persistent = true;
        Ok(())
    }

    /// Remove a persisted key from the TPM.
    pub fn evict(handle: u32) -> Result<(), SignerError> {
        let mut ctx = connect()?;
        let target = PersistentTpmHandle::new(handle).map_err(tss)?;
        let object = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(target)))
            .map_err(tss)?;
        ctx.evict_control(Provision::Owner, object, Persistent::Persistent(target))
            .map_err(tss)?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Context>, SignerError> {
        self.ctx.lock().map_err(|_| SignerError::Backend("poisoned lock".into()))
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
        let TpmSignature::EcDsa(sig) =
            ctx.sign(self.key, digest, scheme, validation).map_err(tss)?
        else {
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
}
