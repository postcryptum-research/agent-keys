//! The agent account as configuration: which hardware keys, which mandate,
//! which deployment. Nothing here is secret — handles and public addresses.

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, FixedBytes, B256, U256};
use anyhow::{Context, Result};
use hw_signer::{software::SoftwareSigner, HardwareSigner};
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
}

/// A TPM key: `"0x81010010"`, or `{"handle": "0x81010011", "pcrs": [0, 2, 4, 7]}`
/// for a key sealed to those PCRs (the selection is not stored in the TPM).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TpmKey {
    Handle(String),
    Sealed { handle: String, pcrs: Vec<u8> },
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
    /// 32-byte hex scalar. **Insecure** — for CI and machines without a
    /// supported secure element only; never for a funded account.
    Software(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    pub allow: Vec<AllowEntry>,
    /// wei, decimal string
    pub max_value_per_op: String,
    /// wei, decimal string
    pub budget: String,
    /// unix seconds
    pub valid_until: u64,
}

#[derive(Debug, Deserialize)]
pub struct AllowEntry {
    pub target: Address,
    /// 4-byte hex; `0x00000000` allows a plain value transfer
    pub selector: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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

    pub fn policy_params(&self) -> Result<PolicyParams> {
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

/// Open the signer a [`KeySpec`] points at. The TPM variant needs the `tpm`
/// feature; the software variant warns loudly.
pub fn open_signer(spec: &KeySpec) -> Result<Box<dyn HardwareSigner>> {
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
        KeySpec::Software(hex) => {
            eprintln!("WARNING: using a software key — insecure, dev/CI only");
            Ok(Box::new(SoftwareSigner::from_bytes(&parse32(hex)?)?))
        }
    }
}
