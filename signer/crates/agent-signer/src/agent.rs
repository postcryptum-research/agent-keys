//! The agent account as configuration: which hardware keys, which mandate,
//! which deployment. Nothing here is secret — handles and public addresses.

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, FixedBytes, B256, U256};
use anyhow::{Context, Result};
#[cfg(feature = "insecure-software-keys")]
use hw_signer::software::SoftwareSigner;
use hw_signer::{HardwareSigner, PublicKey};
use serde::Deserialize;

use crate::kernel::{PermissionId, PolicyParams};

/// `contracts/deployments/<chainid>.json`, as written by `script/Deploy.s.sol`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployments {
    pub chain_id: u64,
    pub entry_point: Address,
    pub kernel: Address,
    pub kernel_factory: Address,
    pub p256_validator: Address,
    pub p256_signer: Address,
    pub agent_policy: Address,
    pub demo_counter: Address,
    /// Present once `Deploy.s.sol` has deployed the paymaster for this chain.
    #[serde(default)]
    pub whitelist_paymaster: Option<Address>,
    #[serde(default)]
    pub paymaster_owner: Option<Address>,
    /// The SafeNonceAssert AgentPolicy pairs every Safe transaction with.
    #[serde(default)]
    pub safe_nonce_assert: Option<Address>,
    /// The P256Validator instance that holds a cold recovery key.
    #[serde(default)]
    pub p256_recovery_validator: Option<Address>,
}

/// A TPM key: `"0x81010010"`; `{"handle": "0x81010011", "pcrs": [0, 2, 4, 7]}`
/// for a key sealed to those PCRs (the selection is not stored in the TPM);
/// or `{"handle": "0x81010013", "authFile": "/etc/tpm_sign/owner.auth"}` for a
/// key protected by an authValue whose secret is that file — for the owner
/// key on the agent's chip, a file only root can read (docs/KEY_POLICY.md).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TpmKey {
    Handle(String),
    Sealed { handle: String, pcrs: Vec<u8> },
    Protected {
        handle: String,
        #[serde(rename = "authFile")]
        auth_file: PathBuf,
    },
}

/// Where a key lives.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySpec {
    /// Persistent TPM handle, optionally sealed to PCRs.
    Tpm(TpmKey),
    /// Apple Secure Enclave key, addressed by its label (macOS).
    #[serde(rename = "secure-enclave")]
    SecureEnclave(String),
    /// TPM 2.0 key through CNG's Platform Crypto Provider, by key name (Windows).
    #[serde(rename = "windows-tpm")]
    WindowsTpm(String),
    /// Tropic Square TROPIC01 on its USB DevKit: serial port and ECC key slot.
    Tropic01 { port: String, slot: u16 },
    /// YubiKey 5 PIV slot (`"9c"`, `"9a"`, …, `"82"`–`"95"`); `serial` picks
    /// one of several YubiKeys. The PIN and touch policies are the slot's
    /// (docs/YUBIKEY.md); the PIN is asked at use.
    #[serde(rename = "yubikey")]
    YubiKey { slot: String, serial: Option<u32> },
    /// 32-byte hex scalar in this file. **Insecure**: refused in every role
    /// unless built with `--features insecure-software-keys` (tests only;
    /// docs/KEY_POLICY.md rule 5).
    Software(String),
    /// An encrypted key file on removable media (`crate::keyfile`), for the
    /// owner or the recovery key only; the passphrase is asked at use.
    Keyfile(PathBuf),
}

/// Which role a key plays. The owner's key is never needed for the agent's
/// operations and never opened by them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Agent,
    /// The cold recovery key (P256RecoveryValidator): may only take over root.
    Recovery,
}

/// Public key coordinates in a config (`{"x": "0x…", "y": "0x…"}`), as
/// `key show` prints them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyJson {
    pub x: String,
    pub y: String,
}

impl PublicKeyJson {
    pub fn parse(&self) -> Result<PublicKey> {
        Ok(PublicKey { x: parse32(&self.x)?, y: parse32(&self.y)? })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyConfig {
    pub allow: Vec<AllowEntry>,
    /// wei, decimal string
    pub max_value_per_op: String,
    /// wei, decimal string
    pub budget: String,
    /// unix seconds
    pub valid_until: u64,
    /// unix seconds; the mandate takes effect only from then (0 = at once).
    /// Several permissions with their own windows make a schedule.
    #[serde(default)]
    pub valid_after: u64,
    /// Per-token limits for ERC-20 `transfer` / `transferFrom` / `approve` /
    /// `increaseAllowance`; an allow-listed token selector needs one.
    #[serde(default)]
    pub tokens: Vec<TokenEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenEntry {
    pub token: Address,
    /// token units, decimal string
    pub max_per_op: String,
    /// token units, decimal string
    pub budget: String,
    /// Allow x402 / EIP-3009 payments in this token (the CLI reads the
    /// token's EIP-712 domain separator when installing the mandate).
    #[serde(default)]
    pub x402: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub target: Address,
    /// 4-byte hex; `0x00000000` allows a plain value transfer
    pub selector: String,
}

#[derive(Debug, Deserialize)]
/// The agent config file (docs/AGENT_CONFIG.md). Unknown fields are an
/// error: a misspelled `validAfter` must not silently become 0.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentConfig {
    /// Relative to this file.
    pub deployments: PathBuf,
    pub owner: KeySpec,
    pub agent: KeySpec,
    /// 4-byte hex, a clean literal (see docs/ARCHITECTURE.md).
    pub permission_id: String,
    #[serde(default)]
    pub salt: Option<String>,
    /// Pin the deployed account. Once set, keys and mandate in this file
    /// describe the *next* permission (rotation), not the account's address.
    #[serde(default)]
    pub account: Option<Address>,
    /// The owner's public key, to derive the account address and its
    /// initCode without opening the owner's key: the agent's operations must
    /// work on a host that cannot reach it (docs/KEY_POLICY.md rule 3).
    #[serde(default)]
    pub owner_public_key: Option<PublicKeyJson>,
    /// The agent's public key, so the owner can rotate to it from a host that
    /// cannot reach the agent's chip. Without it the agent key is opened for
    /// its public half.
    #[serde(default)]
    pub agent_public_key: Option<PublicKeyJson>,
    /// The cold recovery key (docs/RESILIENCE.md), usually
    /// `{"keyfile": "/media/…/recovery.json"}` on a USB drive.
    #[serde(default)]
    pub recovery: Option<KeySpec>,
    pub policy: PolicyConfig,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<(Self, PathBuf)> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Self = serde_json::from_slice(&bytes).context("parsing agent config")?;
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok((cfg, base))
    }

    pub fn load_deployments(&self, base: &Path) -> Result<Deployments> {
        let path = base.join(&self.deployments);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).context("parsing deployments")
    }

    pub fn permission_id(&self) -> Result<PermissionId> {
        let raw = hex::decode(self.permission_id.trim_start_matches("0x")).context("permissionId")?;
        let arr: [u8; 4] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("permissionId must be 4 bytes"))?;
        Ok(PermissionId::from(arr))
    }

    /// Hex number (`0x0`, `0x1`, …), right-aligned into 32 bytes.
    pub fn salt(&self) -> Result<B256> {
        match &self.salt {
            None => Ok(B256::ZERO),
            Some(s) => {
                let n = U256::from_str_radix(s.trim_start_matches("0x"), 16)
                    .with_context(|| format!("salt: {s}"))?;
                Ok(B256::from(n.to_be_bytes::<32>()))
            }
        }
    }

    /// Tokens whose x402 payments this mandate allows.
    pub fn x402_tokens(&self) -> Vec<Address> {
        self.policy.tokens.iter().filter(|t| t.x402).map(|t| t.token).collect()
    }

    /// The mandate as install parameters. `domains` holds the EIP-712 domain
    /// separators of the `x402` tokens (read from the chain by the caller).
    pub fn policy_params(&self, domains: &std::collections::HashMap<Address, alloy::primitives::B256>) -> Result<PolicyParams> {
        let mut targets = Vec::with_capacity(self.policy.allow.len());
        let mut selectors = Vec::with_capacity(self.policy.allow.len());
        for entry in &self.policy.allow {
            let raw = hex::decode(entry.selector.trim_start_matches("0x")).context("selector")?;
            let arr: [u8; 4] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("selector must be 4 bytes: {}", entry.selector))?;
            targets.push(entry.target);
            selectors.push(FixedBytes::from(arr));
        }
        Ok(PolicyParams {
            targets,
            selectors,
            max_value_per_op: self.policy.max_value_per_op.parse().context("maxValuePerOp")?,
            budget: self.policy.budget.parse().context("budget")?,
            valid_until: self.policy.valid_until,
            valid_after: self.policy.valid_after,
            tokens: self
                .policy
                .tokens
                .iter()
                .map(|t| -> Result<(Address, u128, u128, alloy::primitives::B256)> {
                    let domain = if t.x402 {
                        *domains.get(&t.token).with_context(|| format!("no domain separator read for x402 token {}", t.token))?
                    } else {
                        alloy::primitives::B256::ZERO
                    };
                    Ok((
                        t.token,
                        t.max_per_op.parse().context("tokens.maxPerOp")?,
                        t.budget.parse().context("tokens.budget")?,
                        domain,
                    ))
                })
                .collect::<Result<_>>()?,
        })
    }
}

pub fn parse_hex_u32(s: &str) -> Result<u32> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("bad u32 hex: {s}"))
}

pub fn parse32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("bad hex")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", raw.len()))
}

/// Open the signer a [`KeySpec`] points at, for `role`. The TPM variant needs
/// the `tpm` feature. A software key is refused in every role unless the
/// build opted into `insecure-software-keys` (tests only).
pub fn open_signer(spec: &KeySpec, role: Role) -> Result<Box<dyn HardwareSigner>> {
    match spec {
        KeySpec::Tpm(key) => {
            #[cfg(feature = "tpm")]
            {
                use hw_signer::tpm::TpmSigner;
                Ok(match key {
                    TpmKey::Handle(handle) => Box::new(TpmSigner::open_persistent(parse_hex_u32(handle)?)?),
                    TpmKey::Sealed { handle, pcrs } => {
                        Box::new(TpmSigner::open_persistent_sealed(parse_hex_u32(handle)?, pcrs)?)
                    }
                    TpmKey::Protected { handle, auth_file } => {
                        let secret = std::fs::read(auth_file).with_context(|| {
                            format!("reading the authValue secret {} (owner operations run as root)", auth_file.display())
                        })?;
                        Box::new(TpmSigner::open_persistent_protected(parse_hex_u32(handle)?, &secret)?)
                    }
                })
            }
            #[cfg(not(feature = "tpm"))]
            {
                anyhow::bail!("key {key:?} is a TPM key but this build has no `tpm` feature")
            }
        }
        KeySpec::SecureEnclave(label) => {
            #[cfg(all(feature = "secure-enclave", target_os = "macos"))]
            {
                Ok(Box::new(hw_signer::secure_enclave::SecureEnclaveSigner::open(label)?))
            }
            #[cfg(not(all(feature = "secure-enclave", target_os = "macos")))]
            {
                anyhow::bail!("key {label} is a Secure Enclave key: needs macOS and `--features secure-enclave`")
            }
        }
        KeySpec::WindowsTpm(name) => {
            #[cfg(all(feature = "windows-tpm", target_os = "windows"))]
            {
                Ok(Box::new(hw_signer::windows_tpm::CngSigner::open(name)?))
            }
            #[cfg(not(all(feature = "windows-tpm", target_os = "windows")))]
            {
                anyhow::bail!("key {name} is a Windows TPM key: needs Windows and `--features windows-tpm`")
            }
        }
        KeySpec::Tropic01 { port, slot } => {
            #[cfg(feature = "tropic01")]
            {
                Ok(Box::new(hw_signer::tropic01::Tropic01Signer::open(port, *slot)?))
            }
            #[cfg(not(feature = "tropic01"))]
            {
                anyhow::bail!("key in TROPIC01 slot {slot} on {port}: needs `--features tropic01`")
            }
        }
        KeySpec::YubiKey { slot, serial } => {
            #[cfg(feature = "yubikey")]
            {
                Ok(Box::new(open_yubikey(*serial, slot, role, true)?))
            }
            #[cfg(not(feature = "yubikey"))]
            {
                let _ = serial;
                anyhow::bail!("key in YubiKey PIV slot {slot}: needs `--features yubikey`")
            }
        }
        KeySpec::Keyfile(path) => {
            if role == Role::Agent {
                anyhow::bail!(
                    "refusing a key file for the agent: an encrypted file is allowed for the owner and \
                     recovery keys only (docs/KEY_POLICY.md rule 5)"
                );
            }
            eprintln!("opening the key file {} (decrypted in memory for this operation only)", path.display());
            let passphrase = crate::keyfile::prompt(false)?;
            Ok(Box::new(crate::keyfile::open(path, passphrase.as_bytes())?))
        }
        KeySpec::Software(hex) => {
            // A test build (`insecure-software-keys`, never a release) may use
            // software keys in every role -- the integration tests drive owner
            // and recovery operations on a local chain. Any other build refuses.
            #[cfg(feature = "insecure-software-keys")]
            {
                eprintln!("WARNING: using a software {role:?} key — insecure, tests only");
                Ok(Box::new(SoftwareSigner::from_bytes(&parse32(hex)?)?))
            }
            #[cfg(not(feature = "insecure-software-keys"))]
            {
                let _ = hex;
                if role != Role::Agent {
                    anyhow::bail!("refusing a software {role:?} key: the root of the account would be a plaintext file");
                }
                anyhow::bail!(
                    "refusing a software agent key: a plaintext key file defeats the hardware \
                     (tests only: build with --features insecure-software-keys)"
                )
            }
        }
    }
}

/// Open a YubiKey PIV slot for `role`. An agent key signs unattended, so a
/// slot whose policy needs a PIN or a touch is refused for that role. With
/// `ask_pin`, the PIN is prompted when the slot's policy needs one; without,
/// the signer can show its public key but not sign.
#[cfg(feature = "yubikey")]
pub fn open_yubikey(
    serial: Option<u32>,
    slot: &str,
    role: Role,
    ask_pin: bool,
) -> Result<hw_signer::yubikey_piv::YubiKeyPivSigner> {
    use hw_signer::yubikey_piv::{slot_name, PivSlot, YubiKeyPivSigner};
    use zeroize::Zeroizing;

    let slot_id: PivSlot = slot
        .parse()
        .map_err(|e| anyhow::anyhow!("YubiKey slot {slot:?}: {e} (9a, 9c, 9d, 9e or 82..95)"))?;
    let signer = YubiKeyPivSigner::open(serial, slot_id)?;
    let name = slot_name(slot_id);
    if role == Role::Agent && (signer.needs_pin() || signer.needs_touch()) {
        anyhow::bail!(
            "refusing YubiKey slot {name} as the agent key: PIN policy {:?} and touch policy {:?} need a human at \
             every signature. An unattended agent key needs PIN never and touch never (docs/YUBIKEY.md)",
            signer.pin_policy(),
            signer.touch_policy()
        );
    }
    let mut signer = signer.with_touch_notice(|| eprintln!("touch the YubiKey to sign…"));
    if ask_pin && signer.needs_pin() {
        // Asked at the first signature, not now: by then the CLI has checked
        // the key against the account's root (chain.rs), so a wrong device
        // or slot costs no PIN try and no touch.
        let label = format!("YubiKey PIV PIN (slot {name}): ");
        signer = signer.with_pin_provider(move || {
            crate::keyfile::prompt_secret(&label)
                .map(|pin| Zeroizing::new(pin.as_bytes().to_vec()))
                .map_err(|e| hw_signer::SignerError::Key(format!("PIN: {e}")))
        });
    }
    Ok(signer)
}
