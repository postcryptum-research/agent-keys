//! YubiKey 5 PIV backend: a P-256 key in a PIV slot, reached over PC/SC.
//!
//! The key is generated on the device by `ykman piv keys generate`, which
//! also fixes the slot's PIN and touch policies for the life of the key
//! (docs/YUBIKEY.md). This backend never holds the management key: it reads
//! the slot's metadata, sends the 32-byte digest through GENERAL AUTHENTICATE
//! and returns `(r, s)` normalized to low-s.
//!
//! Every operation opens the device anew, bound to the serial number seen at
//! `open`, like the TROPIC01 backend: the signer stays a plain value usable
//! through `&self`, and a pulled key is reported as an error, not a hang.
//!
//! The PIN, when the slot's policy needs one, is handed in by the caller and
//! kept zeroized in memory; this crate never prompts. A touch policy of
//! `Always` or `Cached` blocks the sign call until the user touches the key,
//! so callers can register a notice to print before that happens.

use std::fmt;
use std::sync::Mutex;

use yubikey::piv::{self, AlgorithmId, SlotAlgorithmId, SlotId};
use yubikey::{PinPolicy, Serial, TouchPolicy, YubiKey};
use zeroize::Zeroizing;

use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

pub use yubikey::piv::SlotId as PivSlot;
pub use yubikey::{PinPolicy as PivPinPolicy, TouchPolicy as PivTouchPolicy};

/// Called right before a signature that the device will wait on a touch for.
pub type TouchNotice = Box<dyn Fn() + Send + Sync>;

/// Asked for the PIN the first time a signature needs it.
pub type PinProvider = Box<dyn Fn() -> Result<Zeroizing<Vec<u8>>, SignerError> + Send + Sync>;

/// A P-256 key in PIV `slot` of the YubiKey with `serial`.
pub struct YubiKeyPivSigner {
    serial: u32,
    slot: SlotId,
    public_key: PublicKey,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    /// The PIN once known: given up front or obtained from the provider at
    /// the first signature, then kept for this signer's life (a bundler path
    /// signs again when the fee floor moves). Cleared again when the device rejects it.
    pin: Mutex<Option<Zeroizing<Vec<u8>>>>,
    pin_provider: Option<PinProvider>,
    touch_notice: Option<TouchNotice>,
}

impl YubiKeyPivSigner {
    /// Open the key in `slot`: with `serial`, that YubiKey; without, the one
    /// YubiKey plugged in (two or more is an error). Reads the public key and
    /// the policies from the slot's metadata (firmware 5.3+) and refuses a
    /// slot that holds anything but a P-256 key.
    pub fn open(serial: Option<u32>, slot: SlotId) -> Result<Self, SignerError> {
        let mut yk = open_device(serial)?;
        let name = slot_name(slot);
        let md = piv::metadata(&mut yk, slot).map_err(|e| SignerError::Key(format!("slot {name}: {e}")))?;
        match md.algorithm {
            SlotAlgorithmId::Asymmetric(AlgorithmId::EccP256) => {}
            other => return Err(SignerError::Key(format!("slot {name} holds {other:?}, not a P-256 key"))),
        }
        let spki = md.public.ok_or_else(|| SignerError::Key(format!("slot {name}: metadata carries no public key")))?;
        let public_key = parse_point(spki.subject_public_key.raw_bytes())?;
        let (pin_policy, touch_policy) = md.policy.unwrap_or((PinPolicy::Default, TouchPolicy::Default));
        Ok(Self {
            serial: yk.serial().0,
            slot,
            public_key,
            pin_policy,
            touch_policy,
            pin: Mutex::new(None),
            pin_provider: None,
            touch_notice: None,
        })
    }

    /// Supply the PIN for a slot whose policy asks for one.
    pub fn with_pin(mut self, pin: Zeroizing<Vec<u8>>) -> Self {
        self.pin = Mutex::new(Some(pin));
        self
    }

    /// Ask for the PIN only when a signature needs it. The caller can then
    /// check the key against the chain before the user types anything.
    pub fn with_pin_provider(
        mut self,
        provider: impl Fn() -> Result<Zeroizing<Vec<u8>>, SignerError> + Send + Sync + 'static,
    ) -> Self {
        self.pin_provider = Some(Box::new(provider));
        self
    }

    /// Register what to do right before the device waits for a touch.
    pub fn with_touch_notice(mut self, notice: impl Fn() + Send + Sync + 'static) -> Self {
        self.touch_notice = Some(Box::new(notice));
        self
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn slot(&self) -> SlotId {
        self.slot
    }

    pub fn pin_policy(&self) -> PinPolicy {
        self.pin_policy
    }

    pub fn touch_policy(&self) -> TouchPolicy {
        self.touch_policy
    }

    /// Whether signing needs the PIN (`Once` and `Always`; `Default` is
    /// `Once` for every slot but 9c, where it is `Always`, so it counts).
    pub fn needs_pin(&self) -> bool {
        !matches!(self.pin_policy, PinPolicy::Never)
    }

    /// Whether signing waits for a touch (`Always` or `Cached`).
    pub fn needs_touch(&self) -> bool {
        matches!(self.touch_policy, TouchPolicy::Always | TouchPolicy::Cached)
    }

    /// The slot's attestation certificate, DER, signed by the device's
    /// attestation key (slot f9). It names the firmware, the PIN and touch
    /// policies and the serial number; verify it against the f9 certificate
    /// and Yubico's roots off the device (docs/YUBIKEY.md). Needs no PIN.
    pub fn attestation(&self) -> Result<Vec<u8>, SignerError> {
        let mut yk = open_device(Some(self.serial))?;
        let der = piv::attest(&mut yk, self.slot)
            .map_err(|e| SignerError::Backend(format!("attest slot {}: {e}", slot_name(self.slot))))?;
        Ok(der.to_vec())
    }
}

impl fmt::Debug for YubiKeyPivSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YubiKeyPivSigner")
            .field("serial", &self.serial)
            .field("slot", &slot_name(self.slot))
            .field("pin_policy", &self.pin_policy)
            .field("touch_policy", &self.touch_policy)
            .finish_non_exhaustive()
    }
}

impl HardwareSigner for YubiKeyPivSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        Ok(self.public_key)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let name = slot_name(self.slot);
        let mut yk = open_device(Some(self.serial))?;
        if self.needs_pin() {
            let mut cached = self.pin.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if cached.is_none() {
                let provider = self.pin_provider.as_ref().ok_or_else(|| {
                    SignerError::Key(format!("slot {name}: PIN policy {:?} needs a PIN and none was given", self.pin_policy))
                })?;
                *cached = Some(provider()?);
            }
            let verified = yk.verify_pin(cached.as_ref().expect("filled above"));
            if verified.is_err() {
                *cached = None;
            }
            verified.map_err(|e| match e {
                yubikey::Error::WrongPin { tries } => {
                    SignerError::Key(format!("wrong PIN; {tries} tries left before only the PUK can unblock it"))
                }
                yubikey::Error::PinLocked => SignerError::Key("PIN blocked: unblock it with the PUK (ykman piv access unblock-pin)".into()),
                other => SignerError::Backend(format!("verify PIN: {other}")),
            })?;
        }
        if self.needs_touch() {
            if let Some(notice) = &self.touch_notice {
                notice();
            }
        }
        let der = piv::sign_data(&mut yk, digest, AlgorithmId::EccP256, self.slot)
            .map_err(|e| SignerError::Sign(format!("slot {name}: {e}")))?;
        let (r, s) = der_ecdsa_rs(&der).ok_or_else(|| SignerError::Sign("malformed DER signature from the device".into()))?;
        Ok(normalize_low_s(Signature { r, s }))
    }
}

/// `9a`, `9c`, …, `82`–`95`, `f9`: the slot as ykman names it.
pub fn slot_name(slot: SlotId) -> String {
    format!("{:02x}", u8::from(slot))
}

fn open_device(serial: Option<u32>) -> Result<YubiKey, SignerError> {
    match serial {
        Some(s) => YubiKey::open_by_serial(Serial(s)).map_err(|e| SignerError::Backend(format!("YubiKey {s}: {e}"))),
        None => YubiKey::open().map_err(|e| {
            SignerError::Backend(format!("YubiKey: {e} (one YubiKey must be plugged in; with several, give its serial)"))
        }),
    }
}

fn parse_point(bytes: &[u8]) -> Result<PublicKey, SignerError> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(SignerError::Key(format!("unexpected public key encoding ({} bytes)", bytes.len())));
    }
    let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
    pk.x.copy_from_slice(&bytes[1..33]);
    pk.y.copy_from_slice(&bytes[33..65]);
    Ok(pk)
}

/// `SEQUENCE { INTEGER r, INTEGER s }` → fixed 32-byte `r` and `s`. The device
/// emits minimal DER: a leading `0x00` when the top bit is set, fewer bytes
/// when the integer is short.
pub fn der_ecdsa_rs(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (body, rest) = der_tlv(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, body) = der_tlv(body, 0x02)?;
    let (s, body) = der_tlv(body, 0x02)?;
    if !body.is_empty() {
        return None;
    }
    Some((der_int32(r)?, der_int32(s)?))
}

fn der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 || input[0] != tag {
        return None;
    }
    let (len, off): (usize, usize) = match input[1] {
        l if l < 0x80 => (l as usize, 2),
        0x81 => (*input.get(2)? as usize, 3),
        0x82 => (u16::from_be_bytes([*input.get(2)?, *input.get(3)?]) as usize, 4),
        _ => return None,
    };
    let end = off.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((&input[off..end], &input[end..]))
}

fn der_int32(mut v: &[u8]) -> Option<[u8; 32]> {
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    if v.is_empty() || v.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32usize.saturating_sub(v.len())..].copy_from_slice(v);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_parsing_handles_sign_bytes_and_short_integers() {
        // r with its top bit set (0x00 prefix, 33 bytes), s short (31 bytes).
        let mut der = vec![0x30, 0x44, 0x02, 0x21, 0x00];
        let r = [0x80u8; 32];
        der.extend_from_slice(&r);
        der.extend_from_slice(&[0x02, 0x1f]);
        let s_short = [0x7fu8; 31];
        der.extend_from_slice(&s_short);
        let (pr, ps) = der_ecdsa_rs(&der).expect("valid DER");
        assert_eq!(pr, r);
        assert_eq!(ps[0], 0);
        assert_eq!(&ps[1..], &s_short[..]);

        // trailing garbage, a wrong tag and an oversized integer are refused
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(der_ecdsa_rs(&trailing).is_none());
        let mut wrong_tag = der.clone();
        wrong_tag[2] = 0x04;
        assert!(der_ecdsa_rs(&wrong_tag).is_none());
        let mut oversized = vec![0x30, 0x46, 0x02, 0x22, 0x01];
        oversized.extend_from_slice(&[0u8; 33]);
        oversized.extend_from_slice(&[0x02, 0x20]);
        oversized.extend_from_slice(&[1u8; 32]);
        assert!(der_ecdsa_rs(&oversized).is_none());
    }

    #[test]
    fn slot_names_match_ykman() {
        assert_eq!(slot_name(SlotId::Signature), "9c");
        assert_eq!(slot_name(SlotId::Authentication), "9a");
        assert_eq!(slot_name(SlotId::Attestation), "f9");
        assert_eq!(slot_name("9c".parse().unwrap()), "9c");
    }

    /// Signs with the key in `YUBIKEY_PIV_SLOT` (default 9c) of the one
    /// YubiKey plugged in; the PIN comes from `YUBIKEY_PIV_PIN` when the
    /// slot's policy needs it. Run:
    /// `read -s YUBIKEY_PIV_PIN && export YUBIKEY_PIV_PIN && cargo test -p hw-signer --features yubikey-piv yubikey -- --ignored --nocapture`
    /// `--nocapture` matters: the touch cue is printed from the test, and
    /// without it the runner swallows it, the 15-second touch window closes
    /// unseen, and the device answers "authentication error". The key's
    /// light blinks while it waits for the touch.
    #[test]
    #[ignore = "requires a YubiKey with a P-256 key in the slot"]
    fn yubikey_signs_and_verifies() {
        let slot: SlotId = std::env::var("YUBIKEY_PIV_SLOT").unwrap_or_else(|_| "9c".into()).parse().unwrap();
        let mut signer = YubiKeyPivSigner::open(None, slot).expect("open the slot");
        if signer.needs_pin() {
            let pin = std::env::var("YUBIKEY_PIV_PIN").expect("YUBIKEY_PIV_PIN for a slot whose policy needs the PIN");
            signer = signer.with_pin(Zeroizing::new(pin.into_bytes()));
        }
        if signer.needs_touch() {
            signer = signer.with_touch_notice(|| eprintln!("touch the YubiKey…"));
        }
        let digest = [0x5au8; 32];
        let sig = signer.sign_digest(&digest).expect("sign");
        let pk = signer.public_key().unwrap();
        assert!(crate::verify_p256(&digest, &sig, &pk));
        let mut tampered = digest;
        tampered[31] ^= 1;
        assert!(!crate::verify_p256(&tampered, &sig, &pk));
    }
}
