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
    /// ZeroDev's staked `FactoryStaker`, through which an account's first
    /// operation creates it (issue #102). Absent: Kernel's factory is named
    /// directly, which a bundler that enforces ERC-7562 refuses.
    #[serde(default)]
    pub kernel_factory_staker: Option<Address>,
    pub p256_validator: Address,
    pub p256_signer: Address,
    pub agent_policy: Address,
    pub demo_counter: Address,
    /// The chain's CoW Swap decoder, where CoW Protocol runs.
    #[serde(default)]
    pub cow_swap_decoder: Option<Address>,
    /// The chain's decoder of plain 1inch limit orders, where 1inch's router is.
    #[serde(default)]
    pub one_inch_limit_order_decoder: Option<Address>,
    /// The chain's decoder of swaps at Uniswap's SwapRouter02, where that router is.
    #[serde(default)]
    pub swap_router02_decoder: Option<Address>,
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
    /// The keys not named above: the compiler settings and the earlier
    /// instances a redeploy keeps as `<name>V<n>` (`p256ValidatorV2`, …),
    /// still in use on accounts until the owner moves them. Read through
    /// [`Deployments::superseded`].
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Deployments {
    /// Every earlier instance of `name` the file keeps (`<name>V<n>`): the
    /// CLI reads their keys for the pre-signature checks and refuses them as
    /// targets, but installs nothing new on them.
    pub fn superseded(&self, name: &str) -> Vec<Address> {
        self.other
            .iter()
            .filter(|(key, _)| version_of(key).is_some_and(|(base, _)| base == name))
            .filter_map(|(_, v)| v.as_str()?.parse().ok())
            .collect()
    }

    /// A versioned key whose value is not an address would drop an earlier
    /// instance from the checks without a word: refused when the file is read.
    pub(crate) fn check_superseded(&self) -> Result<()> {
        for (key, value) in &self.other {
            if version_of(key).is_some() && value.as_str().and_then(|s| s.parse::<Address>().ok()).is_none() {
                anyhow::bail!("deployments: {key} is not an address");
            }
        }
        Ok(())
    }
}

/// `<name>V<n>` as the deploy script writes a superseded key: a name, `V`,
/// and a number without a leading zero (`Deploy.s.sol`, `versionOf`).
fn version_of(key: &str) -> Option<(&str, &str)> {
    let (base, n) = key.rsplit_once('V')?;
    (!base.is_empty() && !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit())).then_some((base, n))
}

/// A TPM key: `"0x81010010"`; `{"handle": "0x81010011", "pcrs": [0, 2, 4, 7]}`
/// for a key sealed to those PCRs (the selection is not stored in the TPM);
/// or `{"handle": "0x81010013", "authFile": "/etc/tpm_sign/owner.auth"}` for a
/// key protected by an authValue whose secret is that file — for the owner
/// key on the agent's chip, a file only root can read (docs/KEY_POLICY.md).
/// Unknown fields are an error: with `pcrs` and `authFile` both given, the
/// key would otherwise load as sealed and the `authFile` go unread (#154).
#[derive(Debug, Deserialize)]
#[serde(
    untagged,
    deny_unknown_fields,
    expecting = "a TPM key: a handle string, {\"handle\", \"pcrs\"} or {\"handle\", \"authFile\"} \
                 (pcrs and authFile do not combine; no other fields)"
)]
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
    /// The owner's phone (docs/MOBILE_OWNER_DESIGN.md): its key never leaves
    /// the phone's secure hardware; an operation goes to it over the local
    /// network behind a QR code, and comes back signed. `publicKey` is the
    /// enrolled key, so read-only commands and the pre-signature root check
    /// need no session; `fingerprint` is the one the owner read on the
    /// phone's screen at enrollment (`key create --phone`), and the key is
    /// refused before any prompt when the two disagree. `attestation` is
    /// what the enrollment verified about the key's hardware (`strongbox`,
    /// `tee`, or `none`): a record for the reader, shown by `key show`.
    /// Owner role only.
    #[serde(rename = "phone")]
    Phone {
        label: String,
        #[serde(rename = "publicKey")]
        public_key: PublicKeyJson,
        fingerprint: String,
        #[serde(default)]
        attestation: Option<String>,
        /// Whether the attestation chain was checked against Google's
        /// revocation list at enrollment: `checked` or `not checked`.
        #[serde(default)]
        revocation: Option<String>,
        /// What the phone's verified boot said of its operating system at
        /// enrollment: `verified`, `self-signed`, `unverified`, or `none`
        /// without evidence.
        #[serde(default, rename = "bootState")]
        boot_state: Option<String>,
        /// Records of the enrollment, as `attestation`: the phone's platform,
        /// and whether the device PIN may unlock the key besides a biometric.
        #[serde(default)]
        platform: Option<String>,
        #[serde(default, rename = "deviceCredential")]
        device_credential: Option<bool>,
    },
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
    /// Seconds after which every budget starts afresh (86400: each UTC
    /// day); 0 or absent, a budget is for the mandate's whole life. Needs an
    /// `AgentPolicy` that knows periods.
    #[serde(default)]
    pub period: u32,
    /// Where the agent may place orders (issue #80), and on what terms.
    #[serde(default)]
    pub venues: Vec<VenueEntry>,
    /// Limits per token id of an ERC-6909 contract (issue #186), for its
    /// `transfer`, `transferFrom` and `approve`; an allow-listed one of the
    /// three needs a limit on its target, and that target may list nothing
    /// else. Needs an `AgentPolicy` that knows them.
    #[serde(default)]
    pub token_ids: Vec<TokenIdEntry>,
}

/// A limit for one id of an ERC-6909 contract. An id has no payee list and
/// no x402: the agent picks who receives it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenIdEntry {
    /// The ERC-6909 contract.
    pub token: Address,
    /// The token id: a decimal string, or hex with `0x`.
    pub id: String,
    /// The id's units, decimal string
    pub max_per_op: String,
    /// The id's units, decimal string
    pub budget: String,
}

/// A trading venue of the mandate: its decoder contract and the terms the
/// decoder holds every order to.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VenueEntry {
    pub kind: VenueKind,
    /// The venue's decoder (`CowSwapDecoder`, `OneInchLimitOrderDecoder`,
    /// `SwapRouter02Decoder`), as deployed.
    pub decoder: Address,
    /// The decoder's code hash. Absent, the CLI pins what the chain has
    /// there now; present, the chain must agree.
    #[serde(default)]
    pub code_hash: Option<alloy::primitives::B256>,
    /// CoW Swap: the only `appData` an order may carry. No other kind has one.
    #[serde(default)]
    pub app_data: Option<alloy::primitives::B256>,
    /// The longest an order may live, seconds. A venue of swaps has none: a
    /// swap is made at once.
    #[serde(default)]
    pub max_life: u32,
    pub pairs: Vec<PairEntry>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VenueKind {
    /// CoW Protocol's orders (`CowSwapDecoder`).
    Cowswap,
    /// A plain order of 1inch's Limit Order Protocol (`OneInchLimitOrderDecoder`).
    #[serde(rename = "1inch")]
    OneInch,
    /// A swap the account makes itself at Uniswap's SwapRouter02
    /// (`SwapRouter02Decoder`): a call, not an order.
    Uniswap,
}

impl VenueKind {
    /// The deployments key of this kind's decoder.
    pub fn deployments_key(self) -> &'static str {
        match self {
            VenueKind::Cowswap => "cowSwapDecoder",
            VenueKind::OneInch => "oneInchLimitOrderDecoder",
            VenueKind::Uniswap => "swapRouter02Decoder",
        }
    }
}

/// A pair the agent may trade one way, and its lowest price: never less
/// than `minBuy` of the buy token for each `perSell` of the sell token.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairEntry {
    pub sell_token: Address,
    pub buy_token: Address,
    /// base units, decimal string
    pub min_buy: String,
    /// base units, decimal string
    pub per_sell: String,
}

impl VenueEntry {
    /// The config as the decoder reads it; the mandate pins its hash.
    pub fn config(&self) -> Result<alloy::primitives::Bytes> {
        let pairs = self
            .pairs
            .iter()
            .map(|p| -> Result<_> {
                Ok((
                    p.sell_token,
                    p.buy_token,
                    p.min_buy.parse::<U256>().context("venues.pairs.minBuy")?,
                    p.per_sell.parse::<U256>().context("venues.pairs.perSell")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        match (self.kind, self.app_data) {
            (VenueKind::Cowswap | VenueKind::OneInch, _) if self.max_life == 0 => {
                anyhow::bail!("the venue {} names no `maxLife`: the longest an order may live, in seconds", self.decoder)
            }
            (VenueKind::Uniswap, None) if self.max_life == 0 => Ok(owner_core::kernel::swap_config(&pairs)),
            (VenueKind::Uniswap, _) => {
                anyhow::bail!("the swap venue {} names a `maxLife` or an `appData`: a swap is made at once and has neither", self.decoder)
            }
            (VenueKind::Cowswap, Some(app_data)) => Ok(owner_core::kernel::cow_config(app_data, self.max_life, &pairs)),
            (VenueKind::Cowswap, None) => anyhow::bail!("the CoW Swap venue {} names no `appData`: the one `appData` its orders carry", self.decoder),
            (VenueKind::OneInch, None) => Ok(owner_core::kernel::one_inch_config(self.max_life, &pairs)),
            (VenueKind::OneInch, Some(_)) => anyhow::bail!("the 1inch venue {} names an `appData`: a 1inch order has none", self.decoder),
        }
    }

    /// The decoder the deployments file names for this kind of venue, if any.
    pub fn listed(&self, dep: &Deployments) -> Option<Address> {
        match self.kind {
            VenueKind::Cowswap => dep.cow_swap_decoder,
            VenueKind::OneInch => dep.one_inch_limit_order_decoder,
            VenueKind::Uniswap => dep.swap_router02_decoder,
        }
    }
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
    /// Who this token may go to: a list of the only addresses it may be
    /// transferred to, approved for, or pay through x402 (needs an
    /// `AgentPolicy` that knows payee lists), or the word `"anyone"` — the
    /// agent picks. Absent, the config still loads, but no mandate is
    /// installed from it: the owner has to say which.
    #[serde(default)]
    pub payees: Option<Payees>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Payees {
    Anyone(Anyone),
    Only(Vec<Address>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Anyone {
    Anyone,
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
    /// Widens the one bound on a bundler's `preVerificationGas` by this whole
    /// factor, for a chain whose bundlers fold the L1 data fee into that
    /// figure, for the agent's operations only. Absent is 1; see
    /// [`AgentConfig::pre_verification_factor`].
    #[serde(default)]
    pub bundler_pre_verification_factor: Option<u64>,
    pub policy: PolicyConfig,
}

/// The largest `bundlerPreVerificationFactor` the CLI takes. With it a
/// bundler may be paid up to this many times the ordinary ceiling for an
/// operation's bytes, from the mandate's budget.
pub const MAX_PRE_VERIFICATION_FACTOR: u64 = 64;

impl AgentConfig {
    pub fn load(path: &Path) -> Result<(Self, PathBuf)> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Self = serde_json::from_slice(&bytes).context("parsing agent config")?;
        cfg.check_listed_once()?;
        cfg.pre_verification_factor()?;
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok((cfg, base))
    }

    /// A token or a venue listed twice is refused here. The phone's review
    /// refuses such a mandate and the policy reverts on it, so nothing wrong
    /// could be installed; without this the CLI read the first entry, sent
    /// both, and the mistake showed only at the install (#178).
    pub fn check_listed_once(&self) -> Result<()> {
        let mut tokens = std::collections::BTreeSet::new();
        for t in &self.policy.tokens {
            if !tokens.insert(t.token) {
                anyhow::bail!("policy.tokens lists {} twice: one entry per token", t.token);
            }
        }
        let mut venues = std::collections::BTreeSet::new();
        for v in &self.policy.venues {
            if !venues.insert(v.decoder) {
                anyhow::bail!("policy.venues lists the decoder {} twice: one entry per venue", v.decoder);
            }
        }
        Ok(())
    }

    /// `bundlerPreVerificationFactor`, 1 when the file does not set it.
    /// Refused outside 1..=[`MAX_PRE_VERIFICATION_FACTOR`]: zero would refuse
    /// every operation, and there is no fraction, since a factor below 1
    /// would only tighten a bound that honest bundlers already sit near.
    pub fn pre_verification_factor(&self) -> Result<u128> {
        match self.bundler_pre_verification_factor {
            None => Ok(1),
            Some(f) if (1..=MAX_PRE_VERIFICATION_FACTOR).contains(&f) => Ok(u128::from(f)),
            Some(f) => anyhow::bail!(
                "bundlerPreVerificationFactor is {f}: it is a whole number from 1 to {MAX_PRE_VERIFICATION_FACTOR} \
                 (docs/AGENT_CONFIG.md)"
            ),
        }
    }

    pub fn load_deployments(&self, base: &Path) -> Result<Deployments> {
        let path = base.join(&self.deployments);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let dep: Deployments = serde_json::from_slice(&bytes).context("parsing deployments")?;
        dep.check_superseded()?;
        Ok(dep)
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

    /// The period and the venues as the policy takes them. `codes` holds
    /// each decoder's code hash, read from the chain by the caller.
    pub fn trading(&self, codes: &std::collections::HashMap<Address, alloy::primitives::B256>) -> Result<owner_core::kernel::Trading> {
        if self.policy.period == 0 && !self.policy.venues.is_empty() {
            anyhow::bail!(
                "the config names venues and no budget period (`policy.period`): the policy refuses such a mandate. \
                 An order's charge is not given back, so the period is what returns an unfilled order's part of the budget"
            );
        }
        let venues = self
            .policy
            .venues
            .iter()
            .map(|v| -> Result<_> {
                let code = *codes.get(&v.decoder).with_context(|| format!("no code hash read for the venue decoder {}", v.decoder))?;
                Ok((v.decoder, code, alloy::primitives::keccak256(v.config()?)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(owner_core::kernel::Trading { period: self.policy.period, venues, ids: self.token_ids()? })
    }

    /// The limits per token id as the policy takes them: `(contract, id,
    /// maxPerOp, budget)`.
    pub fn token_ids(&self) -> Result<Vec<(Address, U256, u128, u128)>> {
        self.policy
            .token_ids
            .iter()
            .map(|t| -> Result<_> {
                let id: U256 = t.id.parse().with_context(|| format!("tokenIds.id: {}", t.id))?;
                Ok((t.token, id, t.max_per_op.parse().context("tokenIds.maxPerOp")?, t.budget.parse().context("tokenIds.budget")?))
            })
            .collect()
    }

    /// The venues' configs, for the phone: the mandate carries their hashes.
    pub fn venue_configs(&self) -> Result<Vec<alloy::primitives::Bytes>> {
        self.policy.venues.iter().map(|v| v.config()).collect()
    }

    /// The token budget the config gives `token`, if it limits it.
    pub fn token_budget(&self, token: Address) -> Result<Option<U256>> {
        self.policy.tokens.iter().find(|t| t.token == token).map(|t| t.budget.parse::<U256>().context("tokens.budget")).transpose()
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
            payees: self.payees()?,
        })
    }

    /// The tokens bound to a payee list, as the policy takes them.
    pub fn payees(&self) -> Result<Vec<(Address, Vec<Address>)>> {
        let mut lists = Vec::new();
        for t in &self.policy.tokens {
            let Some(Payees::Only(list)) = &t.payees else { continue };
            if list.is_empty() {
                anyhow::bail!("tokens: the payee list of {} is empty; name the payees, or write \"payees\": \"anyone\"", t.token);
            }
            for (i, payee) in list.iter().enumerate() {
                if payee.is_zero() || list[..i].contains(payee) {
                    anyhow::bail!("tokens: the payee list of {} has the zero address or {payee} twice", t.token);
                }
            }
            lists.push((t.token, list.clone()));
        }
        Ok(lists)
    }

    /// Before a mandate is installed: every token in it must say who may be
    /// paid. A cap without that reads as a bound and is not one.
    pub fn check_payees_stated(&self) -> Result<()> {
        if let Some(t) = self.policy.tokens.iter().find(|t| t.payees.is_none()) {
            anyhow::bail!(
                "tokens: {} has limits but does not say who may be paid; add \"payees\": [\"0x…\"] (only these addresses) or \"payees\": \"anyone\" (the agent picks) to its entry",
                t.token
            );
        }
        // transfer, approve, increaseAllowance, transferFrom: what a token's
        // limits and payee list are checked on. Anything else on that token
        // would pass neither, and AgentPolicy refuses the mandate at install.
        const METERED: [&str; 4] = ["a9059cbb", "095ea7b3", "39509351", "23b872dd"];
        // ERC-777's authorizeOperator: AgentPolicy refuses a mandate that lists it
        if let Some(a) = self.policy.allow.iter().find(|a| a.selector.trim_start_matches("0x").eq_ignore_ascii_case("959b8c3f")) {
            anyhow::bail!(
                "allow: {} {} is refused: authorizeOperator (ERC-777) makes an address the operator of all the account's tokens there, \
                 and nothing makes the agent withdraw it; AgentPolicy refuses the mandate at install. If the grant is needed, it is the owner's to make",
                a.target,
                a.selector
            );
        }
        // and the mirror: one of the four on a target with no limit here is
        // refused at every operation, and AgentPolicy refuses it at install (#175)
        if let Some(a) = self.policy.allow.iter().find(|a| {
            METERED.contains(&a.selector.trim_start_matches("0x").to_lowercase().as_str())
                && !self.policy.tokens.iter().any(|t| t.token == a.target)
        }) {
            anyhow::bail!(
                "allow: {} {} is refused: transfer, transferFrom, approve and increaseAllowance are checked against a token's limits, and {} has none in `tokens`; add its limits, or remove the entry",
                a.target,
                a.selector,
                a.target
            );
        }
        // The same for an ERC-6909 contract with limits per id (#186), and its
        // transfer, transferFrom and approve
        const ID_METERED: [&str; 3] = ["095bcdb6", "fe99049a", "426a8493"];
        let ids = self.token_ids()?;
        for (i, id) in ids.iter().enumerate() {
            if id.0.is_zero() || ids.iter().take(i).any(|other| (other.0, other.1) == (id.0, id.1)) {
                anyhow::bail!("tokenIds: {} id {} is listed twice, or its contract is the zero address", id.0, id.1);
            }
            if self.policy.tokens.iter().any(|t| t.token == id.0) {
                anyhow::bail!("tokenIds: {} also has limits in `tokens`; a contract has a token limit or limits per id, not both", id.0);
            }
        }
        for a in self.policy.allow.iter() {
            let has_ids = ids.iter().any(|id| id.0 == a.target);
            let metered = ID_METERED.contains(&a.selector.trim_start_matches("0x").to_lowercase().as_str());
            if has_ids && !metered {
                anyhow::bail!(
                    "allow: {} {} is refused: {} has limits per id in `tokenIds`, and such a contract is callable only through ERC-6909's transfer, transferFrom and approve — \
                     anything else (setOperator among them) would move its tokens past the limits; AgentPolicy refuses the mandate at install",
                    a.target,
                    a.selector,
                    a.target
                );
            }
            if !has_ids && metered {
                anyhow::bail!(
                    "allow: {} {} is refused: ERC-6909's transfer, transferFrom and approve are checked against a limit per token id, and {} has none in `tokenIds`; \
                     add its limits, or remove the entry",
                    a.target,
                    a.selector,
                    a.target
                );
            }
        }
        for t in self.policy.tokens.iter() {
            if let Some(a) = self.policy.allow.iter().find(|a| {
                a.target == t.token && !METERED.contains(&a.selector.trim_start_matches("0x").to_lowercase().as_str())
            }) {
                anyhow::bail!(
                    "allow: {} {} is refused: {} has limits in `tokens`, and such a token is callable only through transfer, transferFrom, approve and increaseAllowance — through any other function it would move past its limits. Remove the entry",
                    a.target,
                    a.selector,
                    t.token
                );
            }
        }
        Ok(())
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

/// Read a TPM key's authValue secret (`authFile`, `--auth-file`). On Unix a
/// file that group or others may use is refused: the owner key behind it is
/// out of the agent's reach only while root alone reads it (docs/KEY_POLICY.md
/// rule 3, mode 0600).
#[cfg_attr(not(feature = "tpm"), allow(dead_code))] // its callers are the TPM backend's
pub fn read_auth_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata().with_context(|| format!("reading {}", path.display()))?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} has mode {mode:03o}: an auth file must be readable by its owner only (docs/KEY_POLICY.md rule 3); \
                 run `chmod 600 {}`",
                path.display(),
                path.display()
            );
        }
    }
    let mut secret = Vec::new();
    file.read_to_end(&mut secret).with_context(|| format!("reading {}", path.display()))?;
    Ok(secret)
}

/// Write a record that names a device (an enrollment, an attestation
/// certificate with its serial number) readable by its owner only: mode 0600
/// on Unix, a file already there included.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // the mode above applies to a new file only
        file.set_permissions(std::fs::Permissions::from_mode(0o600)).with_context(|| format!("writing {}", path.display()))?;
    }
    file.write_all(bytes).with_context(|| format!("writing {}", path.display()))
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
                        let secret = read_auth_file(auth_file).with_context(|| {
                            format!("the authValue secret {} (owner operations run as root)", auth_file.display())
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
        KeySpec::Phone { label, public_key, fingerprint, .. } => {
            if role != Role::Owner {
                anyhow::bail!(
                    "phone key {label:?}: a phone signs only owner operations (a human confirms each one); \
                     it cannot be the agent key, and recovery on a phone is not supported yet"
                );
            }
            let pk = public_key.parse()?;
            let actual = owner_core::fingerprint::fingerprint(&pk);
            if !fingerprint.eq_ignore_ascii_case(&actual) {
                anyhow::bail!(
                    "phone key {label:?}: the config's fingerprint {fingerprint} is not the fingerprint of its publicKey ({actual}); \
                     the key the phone showed at enrollment and the key in this file differ — fix the config before anything is signed"
                );
            }
            Ok(Box::new(crate::phone::PhoneSigner::new(label.clone(), pk)))
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

#[cfg(test)]
mod payee_tests {
    use super::*;

    /// The tracked x402 config with a transfer entry on its token, and the
    /// token moved to a payee list or left to anyone.
    fn config_with(listed: bool, extra_allow: Option<&str>) -> AgentConfig {
        let text = include_str!("../../../agent.x402.base-sepolia.json");
        let mut v: serde_json::Value = serde_json::from_str(text).unwrap();
        let token = v["policy"]["tokens"][0]["token"].clone();
        if listed {
            v["policy"]["tokens"][0]["payees"] = serde_json::json!(["0x00000000000000000000000000000000000000d1"]);
        }
        let allow = v["policy"]["allow"].as_array_mut().unwrap();
        allow.push(serde_json::json!({"target": token, "selector": "0xA9059CBB"}));
        if let Some(selector) = extra_allow {
            allow.push(serde_json::json!({"target": token, "selector": selector}));
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_token_or_a_venue_listed_twice_is_refused_at_load() {
        let text = include_str!("../../../agent.x402.base-sepolia.json");
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        serde_json::from_value::<AgentConfig>(v.clone()).unwrap().check_listed_once().unwrap();

        let mut twice = v.clone();
        let token = twice["policy"]["tokens"][0].clone();
        twice["policy"]["tokens"].as_array_mut().unwrap().push(token);
        let refused = serde_json::from_value::<AgentConfig>(twice).unwrap().check_listed_once().unwrap_err().to_string();
        assert!(refused.contains("policy.tokens lists") && refused.contains("twice"), "{refused}");

        let venue = serde_json::json!({
            "kind": "cowswap", "decoder": "0x00000000000000000000000000000000000000c0",
            "appData": "0x0000000000000000000000000000000000000000000000000000000000000000", "maxLife": 600, "pairs": []
        });
        let mut twice = v;
        twice["policy"]["period"] = serde_json::json!(86400);
        twice["policy"]["venues"] = serde_json::json!([venue.clone(), venue]);
        match serde_json::from_value::<AgentConfig>(twice) {
            Ok(cfg) => {
                let refused = cfg.check_listed_once().unwrap_err().to_string();
                assert!(refused.contains("policy.venues lists the decoder") && refused.contains("twice"), "{refused}");
            }
            Err(e) => panic!("the venue of this test does not parse: {e}"),
        }
    }

    /// A venue's terms are encoded for its kind's decoder: CoW Swap's with the
    /// one `appData`, 1inch's without any, a swap venue's without a lifetime
    /// either. The other way round is refused, and so is a kind the CLI does
    /// not know.
    #[test]
    fn a_venues_terms_are_encoded_for_its_kind() {
        let pair = serde_json::json!({"sellToken": "0x00000000000000000000000000000000000000a1", "buyToken": "0x00000000000000000000000000000000000000b2", "minBuy": "3", "perSell": "1"});
        let venue = |kind: &str, app_data: bool| {
            let mut v = serde_json::json!({"kind": kind, "decoder": "0x00000000000000000000000000000000000000c0", "maxLife": 600, "pairs": [pair.clone()]});
            if app_data {
                v["appData"] = serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000");
            }
            serde_json::from_value::<VenueEntry>(v)
        };
        let pairs = [(
            "0x00000000000000000000000000000000000000a1".parse().unwrap(),
            "0x00000000000000000000000000000000000000b2".parse().unwrap(),
            U256::from(3u8),
            U256::from(1u8),
        )];
        let cow = venue("cowswap", true).unwrap();
        assert_eq!(cow.kind.deployments_key(), "cowSwapDecoder");
        assert_eq!(cow.config().unwrap(), owner_core::kernel::cow_config(alloy::primitives::B256::ZERO, 600, &pairs));
        let limit = venue("1inch", false).unwrap();
        assert_eq!(limit.kind.deployments_key(), "oneInchLimitOrderDecoder");
        assert_eq!(limit.config().unwrap(), owner_core::kernel::one_inch_config(600, &pairs));
        // the two encodings are not each other's
        assert_ne!(cow.config().unwrap(), limit.config().unwrap());
        let refused = venue("cowswap", false).unwrap().config().unwrap_err().to_string();
        assert!(refused.contains("names no `appData`"), "{refused}");
        let refused = venue("1inch", true).unwrap().config().unwrap_err().to_string();
        assert!(refused.contains("a 1inch order has none"), "{refused}");
        assert!(venue("uniswapx", false).is_err());

        // a venue of swaps: the pairs alone
        let swaps = |max_life: Option<u32>, app_data: bool| {
            let mut v = serde_json::json!({"kind": "uniswap", "decoder": "0x00000000000000000000000000000000000000c0", "pairs": [pair.clone()]});
            if let Some(l) = max_life {
                v["maxLife"] = serde_json::json!(l);
            }
            if app_data {
                v["appData"] = serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000");
            }
            serde_json::from_value::<VenueEntry>(v).unwrap()
        };
        let swap = swaps(None, false);
        assert_eq!(swap.kind.deployments_key(), "swapRouter02Decoder");
        assert_eq!(swap.config().unwrap(), owner_core::kernel::swap_config(&pairs));
        assert_ne!(swap.config().unwrap(), limit.config().unwrap());
        assert_eq!(swaps(Some(0), false).config().unwrap(), swap.config().unwrap());
        for (max_life, app_data) in [(Some(600), false), (None, true), (Some(600), true)] {
            let refused = swaps(max_life, app_data).config().unwrap_err().to_string();
            assert!(refused.contains("a swap is made at once and has neither"), "{refused}");
        }
        // a venue of orders without a lifetime, left out or zero
        for kind in ["cowswap", "1inch"] {
            for max_life in [None, Some(0u32)] {
                let mut v = serde_json::json!({"kind": kind, "decoder": "0x00000000000000000000000000000000000000c0", "pairs": [pair.clone()]});
                if let Some(l) = max_life {
                    v["maxLife"] = serde_json::json!(l);
                }
                if kind == "cowswap" {
                    v["appData"] = serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000");
                }
                let refused = serde_json::from_value::<VenueEntry>(v).unwrap().config().unwrap_err().to_string();
                assert!(refused.contains("names no `maxLife`"), "{kind} {max_life:?}: {refused}");
            }
        }
    }

    #[test]
    fn a_capped_token_takes_only_the_four_functions() {
        for listed in [true, false] {
            config_with(listed, None).check_payees_stated().unwrap();
            config_with(listed, Some("0x23b872dd")).check_payees_stated().unwrap();
            // mint, permit, a plain transfer to the token
            for other in ["0x40c10f19", "0xd505accf", "0x00000000"] {
                let refused = config_with(listed, Some(other)).check_payees_stated().unwrap_err().to_string();
                assert!(refused.contains("callable only through"), "{refused}");
            }
        }
    }

    /// ERC-777's `authorizeOperator` in the allow-list is refused, as the
    /// policy refuses it at install.
    #[test]
    fn an_erc777_operator_grant_is_not_listed() {
        for selector in ["0x959b8c3f", "0x959B8C3F"] {
            let mut v: serde_json::Value = serde_json::from_str(include_str!("../../../agent.x402.base-sepolia.json")).unwrap();
            v["policy"]["allow"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"target": "0x00000000000000000000000000000000000000e7", "selector": selector}));
            let cfg: AgentConfig = serde_json::from_value(v).unwrap();
            let refused = cfg.check_payees_stated().unwrap_err().to_string();
            assert!(refused.contains("authorizeOperator (ERC-777)"), "{selector}: {refused}");
        }
    }

    /// #186: limits per id of an ERC-6909 contract. The config gives them to
    /// the mandate, and is refused where the policy would refuse the install.
    #[test]
    fn limits_per_token_id_follow_the_policys_rules() {
        let pool = "0x0000000000000000000000000000000000006909";
        let with = |allow: &[&str], ids: serde_json::Value| -> AgentConfig {
            let mut v: serde_json::Value = serde_json::from_str(include_str!("../../../agent.x402.base-sepolia.json")).unwrap();
            for selector in allow {
                v["policy"]["allow"].as_array_mut().unwrap().push(serde_json::json!({"target": pool, "selector": selector}));
            }
            v["policy"]["tokenIds"] = ids;
            serde_json::from_value(v).unwrap()
        };
        let seven = serde_json::json!([{"token": pool, "id": "7", "maxPerOp": "5", "budget": "8"}, {"token": pool, "id": "0x10", "maxPerOp": "1", "budget": "2"}]);
        let cfg = with(&["0x095bcdb6", "0xfe99049a", "0x426a8493"], seven.clone());
        cfg.check_payees_stated().unwrap();
        let pool_address: Address = pool.parse().unwrap();
        assert_eq!(cfg.token_ids().unwrap(), vec![(pool_address, U256::from(7), 5, 8), (pool_address, U256::from(16), 1, 2)]);
        assert_eq!(cfg.trading(&Default::default()).unwrap().ids.len(), 2);
        let refused = |cfg: AgentConfig, why: &str| {
            let said = cfg.check_payees_stated().unwrap_err().to_string();
            assert!(said.contains(why), "{said}");
        };
        // anything else on the contract, an operator among them
        refused(with(&["0x095bcdb6", "0x558a7297"], seven.clone()), "callable only through ERC-6909's transfer, transferFrom and approve");
        // one of the three without a limit per id
        for selector in ["0x095bcdb6", "0xFE99049A", "0x426a8493"] {
            refused(with(&[selector], serde_json::json!([])), "has none in `tokenIds`");
        }
        // the same id twice, in two spellings
        let twice = serde_json::json!([{"token": pool, "id": "16", "maxPerOp": "5", "budget": "8"}, {"token": pool, "id": "0x10", "maxPerOp": "1", "budget": "2"}]);
        refused(with(&["0x095bcdb6"], twice), "listed twice");
        // a contract with a token limit too
        let usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        refused(with(&[], serde_json::json!([{"token": usdc, "id": "7", "maxPerOp": "5", "budget": "8"}])), "not both");
        // an id that is not a number
        assert!(with(&[], serde_json::json!([{"token": pool, "id": "seven", "maxPerOp": "5", "budget": "8"}])).check_payees_stated().is_err());
    }

    /// #175: one of the four metered functions on a target without a limit
    /// would be refused at every operation; the config is refused.
    #[test]
    fn a_metered_function_needs_a_limit_for_its_target() {
        for selector in ["0xa9059cbb", "0x095ea7b3", "0x39509351", "0x23b872dd"] {
            let mut v: serde_json::Value = serde_json::from_str(include_str!("../../../agent.x402.base-sepolia.json")).unwrap();
            v["policy"]["allow"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"target": "0x00000000000000000000000000000000000000e1", "selector": selector}));
            let cfg: AgentConfig = serde_json::from_value(v).unwrap();
            let refused = cfg.check_payees_stated().unwrap_err().to_string();
            assert!(refused.contains("has none in `tokens`"), "{selector}: {refused}");
        }
        // the control: the same entry on the config's limited token
        config_with(false, Some("0x095ea7b3")).check_payees_stated().unwrap();
    }
}

#[cfg(all(test, unix))]
mod file_mode_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// #154: an auth file is read only when group and others have no access
    /// to it (docs/KEY_POLICY.md rule 3); otherwise the refusal says how to fix it.
    #[test]
    fn an_auth_file_others_may_read_is_refused() {
        let dir = std::env::temp_dir().join(format!("agent-signer-authfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owner.auth");
        std::fs::write(&path, b"a secret only root reads").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_auth_file(&path).unwrap(), b"a secret only root reads");

        for mode in [0o644, 0o640, 0o604, 0o620] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let refused = read_auth_file(&path).unwrap_err().to_string();
            assert!(refused.contains(&format!("mode {mode:03o}")) && refused.contains("chmod 600"), "{mode:o}: {refused}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #154: an enrollment record (it carries the device's serial number) is
    /// written 0600, also over a file that was there with a wider mode.
    #[test]
    fn an_enrollment_record_is_written_owner_only() {
        let dir = std::env::temp_dir().join(format!("agent-signer-record-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enroll-response.json");
        let _ = std::fs::remove_file(&path);
        write_private(&path, b"{}").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"{\"again\": true}").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"again\": true}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
