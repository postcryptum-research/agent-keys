//! What the phone shows, and what it refuses (docs/MOBILE_OWNER_DESIGN.md
//! §6): one parse of a sign request into a [`Review`] — the verdict, the
//! sections the screen renders, and the digest to sign, all from the same
//! object, so nothing is signed that was not shown. The native side renders
//! `sections` generically; every word comes from here.
//!
//! Facts come from the caller: which accounts this phone is enrolled for,
//! and which contracts the build knows (§6.7; `facts.rs` holds the embedded
//! table, and [`open_request_with_build_facts`] is what the phone and the
//! laptop's preview run). Nothing here touches the network.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use hw_signer::PublicKey;

use crate::abi::IKernel;
use crate::fingerprint::fingerprint;
use crate::request::{commitment, RequestError, SignRequest};

/// The phone's clock gets this much tolerance on `expires` (§6.2).
pub const CLOCK_TOLERANCE_SECS: u64 = 300;
/// D8: the default cap on the maximum gas cost the account may be charged.
pub const DEFAULT_GAS_CAP_WEI: u128 = 5_000_000_000_000_000; // 0.005 ETH

const VALIDATION_TYPE_VALIDATOR: u8 = 0x01;
const VALIDATION_TYPE_PERMISSION: u8 = 0x02;
const SELECTOR_INCREMENT: [u8; 4] = [0xd0, 0x9d, 0xe0, 0x8a];
const SELECTOR_ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SELECTOR_ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// One account this phone holds a key for (§5.4), with the options chosen
/// at enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledAccount {
    pub chain_id: u64,
    pub entry_point: Address,
    pub account: Address,
    /// The validator this phone's key is installed on, once root was handed
    /// to it; removing that validator means this phone loses control.
    pub validator: Option<Address>,
    pub gas_cap_wei: u128,
    /// D4: unknown external calls are refused unless this is on.
    pub expert_mode: bool,
    /// Names the laptop gave at enrollment to addresses the build does not
    /// know (§4.3, §6.7). Labels only: shown as unverified, never a reason
    /// to accept, emphasise less or decode anything.
    pub pins: BTreeMap<Address, String>,
}

impl EnrolledAccount {
    pub fn new(chain_id: u64, entry_point: Address, account: Address) -> Self {
        Self {
            chain_id,
            entry_point,
            account,
            validator: None,
            gas_cap_wei: DEFAULT_GAS_CAP_WEI,
            expert_mode: false,
            pins: BTreeMap::new(),
        }
    }
}

/// A token the build knows (§6.7): amounts are scaled only with these
/// decimals, and an x402 mandate must carry this signing domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub symbol: String,
    pub decimals: u8,
    /// The token's EIP-712 domain separator on its chain.
    pub domain: B256,
}

/// What the build knows (§6.7): names for the project's contracts, the
/// paymasters known to charge nothing, the recovery validators, the tokens.
/// `facts::for_chain` builds it from the embedded table; tests build their own.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub names: BTreeMap<Address, String>,
    /// Paymasters without a `postOp` (§6.4): the only ones accepted.
    pub sponsoring_paymasters: Vec<Address>,
    pub recovery_validators: Vec<Address>,
    /// The project's demo counter: `increment()` is recognised there only.
    pub demo_counter: Option<Address>,
    /// Policy modules whose init data this build can read, and signer
    /// modules likewise. Kept apart: an address is readable in its own slot
    /// only, never a signer where a policy belongs.
    pub policy_modules: Vec<Address>,
    /// The policy modules among them that enforce per-token payee lists.
    pub payee_policy_modules: Vec<Address>,
    pub signer_modules: Vec<Address>,
    pub tokens: BTreeMap<Address, Token>,
    /// The chain's EntryPoint, when the build knows it: a request or an
    /// enrollment naming another one is refused.
    pub entry_point: Option<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Sign,
    SignWithWarnings(Vec<String>),
    Refuse(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub value: String,
    /// Bold on the screen: an effect that needs the second confirmation (§6.6).
    pub emphasis: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub verdict: Verdict,
    pub sections: Vec<Section>,
    /// The request's commitment, echoed in the response.
    pub request_commitment: String,
    /// The account and chain the request names (zero until parsed).
    pub account: Address,
    pub chain_id: u64,
    digest: Option<B256>,
}

impl Review {
    /// The `userOpHash` this review recomputed — never the laptop's number.
    /// `Err` when the verdict is a refusal: there is nothing to sign.
    pub fn digest_to_sign(&self) -> Result<B256, RequestError> {
        match (&self.verdict, self.digest) {
            (Verdict::Refuse(why), _) => Err(RequestError::Malformed(format!("refused: {why}"))),
            (_, None) => Err(RequestError::Malformed("refused: no digest".into())),
            (_, Some(d)) => Ok(d),
        }
    }

    pub fn needs_second_confirmation(&self) -> bool {
        self.sections.iter().any(|s| s.rows.iter().any(|r| r.emphasis))
    }

    /// The screen as one text, for tests and the CLI's dry run.
    pub fn text(&self) -> String {
        self.render(true)
    }

    /// The screen without the `userOpHash` row: what the tamper test
    /// compares, since that row changes with every mutation by definition.
    pub fn text_without_hash(&self) -> String {
        self.render(false)
    }

    fn render(&self, with_hash: bool) -> String {
        let mut out = String::new();
        for s in &self.sections {
            out.push_str(&format!("## {}\n", s.title));
            for r in &s.rows {
                if !with_hash && r.label == "userOpHash" {
                    continue;
                }
                out.push_str(&format!("{}{}: {}\n", if r.emphasis { "! " } else { "" }, r.label, r.value));
            }
        }
        out
    }

    /// A refusal. Its reason is shown on the owner's screen and can quote the
    /// laptop's bytes (a parser's error names the field it met), so it is
    /// held to the rule of everything else there: what is not printable
    /// ASCII or one of the marks the review writes itself becomes `?`. A
    /// line break or a direction mark in it could make the screen read as
    /// something else after "REFUSED".
    fn refused(request_commitment: String, sections: Vec<Section>, why: impl Into<String>) -> Self {
        let why: String = why
            .into()
            .chars()
            .map(|c| if (' '..='~').contains(&c) || ['\u{2014}', '\u{b7}', '\u{2192}', '\u{2016}'].contains(&c) { c } else { '?' })
            .collect();
        Self { verdict: Verdict::Refuse(why), sections, request_commitment, account: Address::ZERO, chain_id: 0, digest: None }
    }
}

struct Builder<'a> {
    facts: &'a Facts,
    pins: &'a BTreeMap<Address, String>,
    sections: Vec<Section>,
    warnings: Vec<String>,
}

impl Builder<'_> {
    /// The address in full, with the build's name, or else the laptop's pin
    /// marked as such. A pin never replaces a build name (§6.7).
    fn name(&self, a: Address) -> String {
        match (self.facts.names.get(&a), self.pins.get(&a)) {
            (Some(n), _) => format!("{} — {n} (verified in this build)", a.to_checksum(None)),
            (None, Some(p)) => format!("{} \"{p}\" (pinned by the laptop at enrollment — unverified)", a.to_checksum(None)),
            (None, None) => a.to_checksum(None),
        }
    }
    /// Scaled with the build's decimals, or raw units (§6.3).
    fn token_amount(&self, token: Address, amount: U256) -> String {
        match self.facts.tokens.get(&token) {
            Some(t) => format!("{} {}", format_units(amount, t.decimals), t.symbol),
            None => format!("{amount} (raw units, unverified decimals)"),
        }
    }
    fn section(&mut self, title: impl Into<String>) -> usize {
        self.sections.push(Section { title: title.into(), rows: Vec::new() });
        self.sections.len() - 1
    }
    fn row(&mut self, s: usize, label: impl Into<String>, value: impl Into<String>) {
        self.sections[s].rows.push(Row { label: label.into(), value: value.into(), emphasis: false });
    }
    fn bold(&mut self, s: usize, label: impl Into<String>, value: impl Into<String>) {
        self.sections[s].rows.push(Row { label: label.into(), value: value.into(), emphasis: true });
    }
}

/// §6.1: the one parse. `expected_commitment` is what the QR carried.
pub fn open_request(
    bytes: &[u8],
    expected_commitment: &str,
    now: u64,
    enrolled: &[EnrolledAccount],
    facts: &Facts,
) -> Review {
    open_with(bytes, expected_commitment, now, enrolled, |_| facts.clone())
}

/// The same parse with the facts this build embeds for the request's chain
/// (§6.7): what the phone runs, and what the laptop previews.
pub fn open_request_with_build_facts(bytes: &[u8], expected_commitment: &str, now: u64, enrolled: &[EnrolledAccount]) -> Review {
    open_with(bytes, expected_commitment, now, enrolled, crate::facts::for_chain)
}

fn open_with(
    bytes: &[u8],
    expected_commitment: &str,
    now: u64,
    enrolled: &[EnrolledAccount],
    facts_for: impl FnOnce(u64) -> Facts,
) -> Review {
    let c = commitment(bytes);
    if c != expected_commitment {
        return Review::refused(c, vec![], "the served request does not match the QR's commitment");
    }
    let req = match SignRequest::parse(bytes, now, CLOCK_TOLERANCE_SECS) {
        Ok(r) => r,
        Err(e) => return Review::refused(c, vec![], e.to_string()),
    };
    let op = match req.user_op.to_packed() {
        Ok(op) => op,
        Err(e) => return Review::refused(c, vec![], e.to_string()),
    };
    let chain_id = match req.chain_id() {
        Ok(id) => id,
        Err(e) => return Review::refused(c, vec![], e.to_string()),
    };
    let Some(acct) = enrolled
        .iter()
        .find(|e| e.chain_id == chain_id && e.entry_point == req.entry_point && e.account == op.sender)
    else {
        return Review::refused(
            c,
            vec![],
            format!(
                "this phone is not enrolled for account {} on chain {chain_id} with EntryPoint {}",
                op.sender.to_checksum(None),
                req.entry_point.to_checksum(None)
            ),
        );
    };
    let refused = |c: String, sections: Vec<Section>, why: String| Review { account: op.sender, chain_id, ..Review::refused(c, sections, why) };
    if !op.init_code.is_empty() {
        return refused(c, vec![], "the operation carries initCode; v1 signs for existing accounts only".into());
    }
    if op.nonce >> 64 != U256::ZERO {
        return Review::refused(c, vec![], "the nonce key is not the root key; this phone signs root operations only");
    }
    // 6: SignRequest::parse refused a hint that differs; the digest is still the recomputed value
    let digest = match req.user_op_hash() {
        Ok(h) => h,
        Err(e) => return Review::refused(c, vec![], e.to_string()),
    };

    let facts = &facts_for(chain_id);
    if facts.entry_point.is_some_and(|known| known != req.entry_point) {
        return refused(
            c,
            vec![],
            format!("EntryPoint {} is not the one this build knows for chain {chain_id}", req.entry_point.to_checksum(None)),
        );
    }
    let mut b = Builder { facts, pins: &acct.pins, sections: Vec::new(), warnings: Vec::new() };
    let s = b.section("Operation");
    b.row(s, "Account", op.sender.to_checksum(None));
    b.row(s, "Chain", chain_id.to_string());
    if let Some(cmd) = &req.laptop.command {
        match clean_label(cmd) {
            Some(l) => b.row(s, "The laptop says", format!("\"{l}\" (from the laptop — unverified)")),
            None => return Review::refused(c, b.sections, "the laptop's command label is not plain text"),
        }
    }
    let mut labels = BTreeMap::new();
    for (a, l) in &req.laptop.labels {
        match clean_label(l) {
            Some(l) => {
                labels.insert(*a, l);
            }
            None => return Review::refused(c, b.sections, "a laptop label is not plain text"),
        }
    }

    // the calldata (§6.3)
    let calls = match top_level(&op.call_data, op.sender) {
        Ok(calls) => calls,
        Err(why) => return Review::refused(c, b.sections, why),
    };
    let installed_keys = keys_installed_in(&calls, op.sender);
    for (i, (target, value, data)) in calls.iter().enumerate() {
        let title = if calls.len() == 1 { "Call".to_string() } else { format!("Call {} of {}", i + 1, calls.len()) };
        let s = b.section(title);
        let outcome = if *target == op.sender {
            if !value.is_zero() {
                Err("a self-call with value; refused".to_string())
            } else {
                self_call(&mut b, s, data, acct, &installed_keys)
            }
        } else {
            external_call(&mut b, s, *target, *value, data, acct, &labels)
        };
        if let Err(why) = outcome {
            return Review::refused(c, b.sections, why);
        }
    }

    // cost and sponsorship (§6.4)
    let (verification_gas, call_gas) = split(op.account_gas_limits);
    let (max_priority, max_fee) = split(op.gas_fees);
    let mut pm_gas: u128 = 0;
    let s = b.section("Cost");
    if !op.paymaster_and_data.is_empty() {
        if op.paymaster_and_data.len() < 52 {
            return Review::refused(c, b.sections, "paymasterAndData is too short to name a paymaster");
        }
        let pm = Address::from_slice(&op.paymaster_and_data[..20]);
        let pm_verification = u128::from_be_bytes(op.paymaster_and_data[20..36].try_into().expect("16"));
        let pm_post_op = u128::from_be_bytes(op.paymaster_and_data[36..52].try_into().expect("16"));
        if !facts.sponsoring_paymasters.contains(&pm) {
            return Review::refused(
                c,
                b.sections,
                format!("paymaster {} is not one this build knows to charge nothing (T20)", pm.to_checksum(None)),
            );
        }
        pm_gas = pm_verification + pm_post_op;
        b.row(s, "Gas", format!("sponsored by {}", b.name(pm)));
        b.row(s, "Paymaster gas limits", format!("verification {pm_verification}, postOp {pm_post_op}"));
    }
    let total_gas = U256::from(verification_gas) + U256::from(call_gas) + op.pre_verification_gas + U256::from(pm_gas);
    let max_cost = total_gas * U256::from(max_fee);
    b.row(s, "Maximum gas cost", format!("{} ETH", format_ether(max_cost)));
    if op.paymaster_and_data.is_empty() && max_cost > U256::from(acct.gas_cap_wei) {
        return Review::refused(
            c,
            b.sections,
            format!(
                "the maximum gas cost {} ETH exceeds this enrollment's cap of {} ETH",
                format_ether(max_cost),
                format_ether(U256::from(acct.gas_cap_wei))
            ),
        );
    }

    // every field the hash covers (§6.4)
    let s = b.section("Details");
    b.row(s, "nonce", format!("key 0 (root), sequence {}", op.nonce));
    b.row(s, "verificationGasLimit", verification_gas.to_string());
    b.row(s, "callGasLimit", call_gas.to_string());
    b.row(s, "preVerificationGas", op.pre_verification_gas.to_string());
    b.row(s, "maxFeePerGas", format!("{max_fee} wei"));
    b.row(s, "maxPriorityFeePerGas", format!("{max_priority} wei"));
    b.row(s, "EntryPoint", req.entry_point.to_checksum(None));
    b.row(s, "expires", format!("{} UTC ({})", utc(req.expires), req.expires));
    b.row(s, "userOpHash", format!("{digest}"));

    let verdict = if b.warnings.is_empty() { Verdict::Sign } else { Verdict::SignWithWarnings(b.warnings) };
    Review { verdict, sections: b.sections, request_commitment: c, account: op.sender, chain_id, digest: Some(digest) }
}

/// §6.3 top level: `execute` (single or batch, default exec type) or a direct
/// `uninstallValidation`. Returns the inner calls as (target, value, data).
fn top_level(call_data: &[u8], account: Address) -> Result<Vec<(Address, U256, Bytes)>, String> {
    if call_data.len() < 4 {
        return Err("callData has no selector".into());
    }
    let selector: [u8; 4] = call_data[..4].try_into().expect("4");
    if selector == IKernel::executeCall::SELECTOR {
        let exec = IKernel::executeCall::abi_decode_validate(call_data).map_err(|e| format!("execute: {e}"))?;
        if exec.abi_encode() != call_data {
            return Err("execute calldata is not canonical (trailing or misplaced bytes); refused".into());
        }
        let mode = exec.execMode.0;
        if mode[2..] != [0u8; 30] {
            return Err("execMode carries a selector or payload this version does not show; refused".into());
        }
        if mode[1] != 0x00 {
            return Err(format!("execute exec type 0x{:02x} (not revert-on-failure); refused", mode[1]));
        }
        match mode[0] {
            0x00 => {
                let d = &exec.executionCalldata;
                if d.len() < 52 {
                    return Err("single execution calldata is shorter than target ‖ value".into());
                }
                let target = Address::from_slice(&d[..20]);
                let value = U256::from_be_slice(&d[20..52]);
                Ok(vec![(target, value, Bytes::copy_from_slice(&d[52..]))])
            }
            0x01 => {
                let executions = Vec::<IKernel::Execution>::abi_decode_validate(&exec.executionCalldata)
                    .map_err(|e| format!("batch executions: {e}"))?;
                if executions.abi_encode() != exec.executionCalldata.as_ref() {
                    return Err("batch calldata is not canonical; refused".into());
                }
                if executions.is_empty() {
                    return Err("an empty batch".into());
                }
                Ok(executions.into_iter().map(|e| (e.target, e.value, e.callData)).collect())
            }
            0xff => Err("delegatecall is refused".into()),
            other => Err(format!("execute call type 0x{other:02x} is refused")),
        }
    } else if selector == IKernel::uninstallValidationCall::SELECTOR {
        Ok(vec![(account, U256::ZERO, Bytes::copy_from_slice(call_data))])
    } else {
        Err(format!("top-level call 0x{} is not execute or uninstallValidation; refused", hex(&selector)))
    }
}

/// Keys installed in this batch by validator id, so a `changeRootValidator`
/// to a validator installed in the same batch can name the key (§2.2).
fn keys_installed_in(calls: &[(Address, U256, Bytes)], account: Address) -> BTreeMap<FixedBytes<21>, PublicKey> {
    let mut keys = BTreeMap::new();
    for (target, _, data) in calls {
        if *target != account {
            continue;
        }
        if let Ok(c) = IKernel::installValidationsCall::abi_decode_validate(data) {
            for (vid, vdata) in c.vIds.iter().zip(&c.validationData) {
                if vid.0[0] == VALIDATION_TYPE_VALIDATOR {
                    if let Some(pk) = decode_pubkey(vdata) {
                        keys.insert(*vid, pk);
                    }
                }
            }
        }
    }
    keys
}

fn self_call(
    b: &mut Builder<'_>,
    s: usize,
    data: &[u8],
    acct: &EnrolledAccount,
    installed_keys: &BTreeMap<FixedBytes<21>, PublicKey>,
) -> Result<(), String> {
    if data.len() < 4 {
        return Err("a self-call without a selector; refused".into());
    }
    let selector: [u8; 4] = data[..4].try_into().expect("4");
    // the hook Kernel means by "none" (address(1)); any other hook runs code around the validator
    let no_hook = Address::with_last_byte(1);
    if selector == IKernel::installValidationsCall::SELECTOR {
        let c = IKernel::installValidationsCall::abi_decode_validate(data).map_err(|e| format!("installValidations: {e}"))?;
        if c.abi_encode() != data {
            return Err("installValidations calldata is not canonical; refused".into());
        }
        if c.vIds.len() != c.configs.len() || c.vIds.len() != c.validationData.len() || c.vIds.len() != c.hookData.len() {
            return Err("installValidations with mismatched arrays; refused".into());
        }
        for (((vid, cfg), vdata), hdata) in c.vIds.iter().zip(&c.configs).zip(&c.validationData).zip(&c.hookData) {
            clean_permission_vid(*vid)?;
            if cfg.hook != no_hook {
                return Err(format!("installValidations with hook {}; this version installs validations without hooks", cfg.hook.to_checksum(None)));
            }
            if !hdata.is_empty() {
                return Err("installValidations with hook data; refused".into());
            }
            match vid.0[0] {
                VALIDATION_TYPE_PERMISSION => {
                    let id = FixedBytes::<4>::from_slice(&vid.0[1..5]);
                    b.row(s, "Install agent permission", format!("0x{}", hex(id.as_slice())));
                    permission_rows(b, s, vdata, acct)?;
                    b.row(s, "Validation nonce", cfg.nonce.to_string());
                }
                VALIDATION_TYPE_VALIDATOR => {
                    let v = Address::from_slice(&vid.0[1..21]);
                    let pk = decode_pubkey(vdata).ok_or("installValidations: validator data is not a P-256 key")?;
                    if b.facts.recovery_validators.contains(&v) {
                        b.bold(
                            s,
                            "Install a recovery key",
                            format!("{} — it will be able to take over this account", fingerprint(&pk)),
                        );
                        b.row(s, "Recovery validator", b.name(v));
                    } else if b.facts.names.contains_key(&v) {
                        // v1 does not know which validators the account uses: a key on any of them is an
                        // owner-grade key, whether the validator is current or superseded
                        b.bold(
                            s,
                            "Install a key on a validator",
                            format!("{} — it controls this account once it is root or is granted access", fingerprint(&pk)),
                        );
                        b.row(s, "Validator", b.name(v));
                    } else {
                        // a validator the build cannot classify may be a recovery validator: say so
                        b.bold(s, "Install a key on a validator this build cannot classify", format!("{} — it may be able to take over this account", fingerprint(&pk)));
                        b.row(s, "Validator", v.to_checksum(None));
                    }
                    b.row(s, "Validation nonce", cfg.nonce.to_string());
                }
                other => return Err(format!("installValidations of validation type 0x{other:02x}; refused")),
            }
        }
        Ok(())
    } else if selector == IKernel::grantAccessCall::SELECTOR {
        let c = IKernel::grantAccessCall::abi_decode_validate(data).map_err(|e| format!("grantAccess: {e}"))?;
        if c.abi_encode() != data {
            return Err("grantAccess calldata is not canonical; refused".into());
        }
        clean_permission_vid(c.vId)?;
        let who = vid_text(c.vId);
        let what = selector_name(c.selector.0);
        let (is_validator, is_permission) = (c.vId.0[0] == VALIDATION_TYPE_VALIDATOR, c.vId.0[0] == VALIDATION_TYPE_PERMISSION);
        let (execute, change_root) = (c.selector.0 == IKernel::executeCall::SELECTOR, c.selector.0 == IKernel::changeRootValidatorCall::SELECTOR);
        // Kernel lets a non-root validation call a top-level selector only when it is granted
        // here. A permission's `execute` is bounded by its policy; nothing bounds a validator,
        // and nothing bounds anyone on Kernel's admin selectors.
        if !c.allow {
            b.row(s, format!("Forbid {who} to call"), what);
        } else if is_permission && execute {
            b.row(s, format!("Allow {who} to call"), what);
        } else if is_validator && change_root {
            b.bold(s, format!("Allow {who} to call"), format!("{what} — may take over this account"));
        } else if is_validator && execute {
            b.bold(s, format!("Allow {who} to call"), format!("{what} — this key will be able to do anything with this account"));
        } else if acct.expert_mode && (is_validator || is_permission) {
            b.bold(s, format!("Allow {who} to call"), format!("{what} — nothing bounds what this grant lets it do to the account"));
            b.warnings.push(format!("a grant of {what} to {who}, allowed by expert mode"));
        } else {
            return Err(format!(
                "a grant of {what} to {who}: this version signs a permission's execute, and a validator's execute or \
                 changeRootValidator, and no other grant (expert mode is off)"
            ));
        }
        Ok(())
    } else if selector == IKernel::changeRootValidatorCall::SELECTOR {
        let c = IKernel::changeRootValidatorCall::abi_decode_validate(data).map_err(|e| format!("changeRootValidator: {e}"))?;
        if c.abi_encode() != data {
            return Err("changeRootValidator calldata is not canonical; refused".into());
        }
        if c.rootValidator.0[0] != VALIDATION_TYPE_VALIDATOR {
            return Err("changeRootValidator to a non-validator id; refused".into());
        }
        if c.hook != no_hook || !c.hookData.is_empty() {
            return Err("changeRootValidator with a hook; refused".into());
        }
        if !c.validatorData.is_empty() && decode_pubkey(&c.validatorData).is_none() {
            return Err("changeRootValidator: validator data is not a P-256 key; refused".into());
        }
        let v = Address::from_slice(&c.rootValidator.0[1..21]);
        let key = decode_pubkey(&c.validatorData).or_else(|| installed_keys.get(&c.rootValidator).copied());
        match key {
            Some(pk) => b.bold(s, "Hand control of this account to key", fingerprint(&pk)),
            None => b.bold(s, "Hand control of this account to validator", b.name(v)),
        }
        b.row(s, "Root validator", b.name(v));
        Ok(())
    } else if selector == IKernel::uninstallValidationCall::SELECTOR {
        let c = IKernel::uninstallValidationCall::abi_decode_validate(data).map_err(|e| format!("uninstallValidation: {e}"))?;
        if c.abi_encode() != data {
            return Err("uninstallValidation calldata is not canonical; refused".into());
        }
        if !c.hookDeinitData.is_empty() {
            return Err("uninstallValidation with hook data; refused".into());
        }
        clean_permission_vid(c.vId)?;
        match c.vId.0[0] {
            VALIDATION_TYPE_PERMISSION => {
                // Kernel's PermissionDisableDataFormat: one entry per module; ours carry nothing
                let entries = Vec::<Bytes>::abi_decode_validate(&c.deinitData).map_err(|e| format!("permission deinit data: {e}"))?;
                if entries.abi_encode() != c.deinitData.as_ref() || entries.iter().any(|e| !e.is_empty()) {
                    return Err("uninstallValidation of a permission with module data; refused".into());
                }
                b.row(s, "Remove permission", format!("0x{}", hex(&c.vId.0[1..5])));
            }
            VALIDATION_TYPE_VALIDATOR => {
                if !c.deinitData.is_empty() {
                    return Err("uninstallValidation of a validator with data; refused".into());
                }
                let v = Address::from_slice(&c.vId.0[1..21]);
                match acct.validator {
                    Some(mine) if mine == v => {
                        b.bold(s, "Remove validator", format!("{} — this phone will no longer control the account", b.name(v)))
                    }
                    Some(_) => b.row(s, "Remove validator", b.name(v)),
                    // not knowing which validator holds this phone's key, every removal may be that one
                    None => b.bold(s, "Remove validator", format!("{} — this may be the validator holding this phone's key", b.name(v))),
                }
            }
            other => return Err(format!("uninstallValidation of validation type 0x{other:02x}; refused")),
        }
        Ok(())
    } else {
        Err(format!("self-call 0x{} is not a Kernel admin call this version knows; refused", hex(&selector)))
    }
}

/// Kernel's `PermissionEnableDataFormat` as `permission_data` builds it:
/// policies first, the signer last; each entry `flag(2) ‖ module(20) ‖ init`.
fn permission_rows(b: &mut Builder<'_>, s: usize, vdata: &[u8], acct: &EnrolledAccount) -> Result<(), String> {
    let entries = Vec::<Bytes>::abi_decode_validate(vdata).map_err(|e| format!("permission data: {e}"))?;
    if entries.abi_encode() != vdata {
        return Err("permission data is not canonical; refused".into());
    }
    if entries.len() < 2 {
        return Err("permission data without a policy and a signer; refused".into());
    }
    let (signer, policies) = entries.split_last().expect("at least two");
    // the module the build can read, or expert mode: the mandate rows are this build's reading
    // of init data that the module interprets its own way
    let module_known = |b: &mut Builder<'_>, what: &str, module: Address| -> Result<(), String> {
        let readable = if what == "policy" { &b.facts.policy_modules } else { &b.facts.signer_modules };
        if readable.contains(&module) {
            return Ok(());
        }
        if !acct.expert_mode {
            return Err(format!(
                "{what} module {} is not known to this build, so the mandate shown could mean anything there (expert mode is off)",
                module.to_checksum(None)
            ));
        }
        b.bold(s, format!("Unknown {what} module"), format!("{} — this build cannot read what it enforces", module.to_checksum(None)));
        b.warnings.push(format!("{what} module {} is not known to this build", module.to_checksum(None)));
        Ok(())
    };
    for p in policies {
        if p.len() < 22 {
            return Err("a policy entry shorter than flag ‖ module; refused".into());
        }
        // Kernel's PassFlag: a set bit skips the policy for user operations or the signature
        if p[..2] != [0, 0] {
            return Err(format!("a policy entry with flag 0x{}; a permission that skips its policy is refused", hex(&p[..2])));
        }
        let module = Address::from_slice(&p[2..22]);
        b.row(s, "Policy module", b.name(module));
        module_known(b, "policy", module)?;
        type PolicyInit = (Vec<Address>, Vec<FixedBytes<4>>, U256, U256, U256, Vec<(Address, U256, U256, B256)>, U256);
        type PolicyInitPayees =
            (Vec<Address>, Vec<FixedBytes<4>>, U256, U256, U256, Vec<(Address, U256, U256, B256)>, U256, Vec<(Address, Vec<Address>)>);
        // Two forms, told apart as the policy tells them: by the first head
        // word, the offset of `targets` behind seven or eight head words.
        let init = &p[22..];
        let head = init.get(..32).map(U256::from_be_slice).ok_or("policy parameters shorter than a word; refused")?;
        let (targets, selectors, max_value, budget, until, tokens, after, payees) = if head == U256::from(8 * 32) {
            let d = PolicyInitPayees::abi_decode_params_validate(init).map_err(|e| format!("policy parameters: {e}"))?;
            if d.abi_encode_params() != init {
                return Err("policy parameters are not canonical; refused".into());
            }
            d
        } else {
            let d = PolicyInit::abi_decode_params_validate(init).map_err(|e| format!("policy parameters: {e}"))?;
            if d.abi_encode_params() != init {
                return Err("policy parameters are not canonical; refused".into());
            }
            (d.0, d.1, d.2, d.3, d.4, d.5, d.6, Vec::new())
        };
        if head == U256::from(8 * 32) {
            // an older policy would decode the first seven and ignore the lists:
            // the owner would see payees that nothing enforces
            if !b.facts.payee_policy_modules.contains(&module) {
                return Err("this mandate carries payee lists, and the policy module it goes to is not known to enforce them; refused".into());
            }
            if payees.is_empty() {
                return Err("policy parameters in the payee form without a payee list; refused".into());
            }
        }
        for (i, (token, list)) in payees.iter().enumerate() {
            if list.is_empty() || !tokens.iter().any(|t| t.0 == *token) || payees[..i].iter().any(|p| p.0 == *token) {
                return Err("a payee list that is empty, repeated or for a token without a cap; refused".into());
            }
            if list.iter().any(|a| a.is_zero()) || (1..list.len()).any(|j| list[..j].contains(&list[j])) {
                return Err("a payee list with the zero address or the same address twice; refused".into());
            }
        }
        if targets.len() != selectors.len() {
            return Err("policy targets and selectors differ in length; refused".into());
        }
        // A token with a limit is callable through the four functions the
        // limit is checked on. Any other entry on it would move the token
        // past its caps and its payee list: AgentPolicy refuses such a
        // mandate at install, and an earlier AgentPolicy would let the
        // entry through unmetered, so it is refused here for either.
        const METERED: [[u8; 4]; 4] = [[0xa9, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3], [0x39, 0x50, 0x93, 0x51], [0x23, 0xb8, 0x72, 0xdd]];
        for (t, sel) in targets.iter().zip(&selectors) {
            // Permit2 at its usual address (the constant AgentPolicy carries): its own
            // `approve` names who may pull a token, and no policy reads that call
            if *t == alloy_primitives::address!("000000000022D473030F116dDEE9F6B43aC78BA3") {
                return Err("this mandate lets the agent call Permit2, through which a token's allowance can be handed to any address, past its limits and payee list; refused".into());
            }
            if tokens.iter().any(|token| token.0 == *t) && !METERED.contains(&sel.0) {
                return Err(format!(
                    "this mandate limits the token {} and also allows {} on it; a limited token may only be called through transfer, transferFrom, approve and increaseAllowance, anything else would move it past its limits; refused",
                    b.name(*t),
                    selector_name(sel.0)
                ));
            }
        }
        let secs = |v: U256, what: &str| u64::try_from(v).map_err(|_| format!("{what} does not fit a timestamp; refused"));
        let (until, after) = (secs(until, "validUntil")?, secs(after, "validAfter")?);
        for (t, sel) in targets.iter().zip(&selectors) {
            b.row(s, "Allow", format!("{} · {}", b.name(*t), selector_name(sel.0)));
        }
        b.row(s, "Max value per operation", format!("{} ETH", format_ether(max_value)));
        b.row(s, "Budget", format!("{} ETH", format_ether(budget)));
        b.row(s, "Valid from", if after == 0 { "now".to_string() } else { format!("{} UTC ({after})", utc(after)) });
        b.row(s, "Valid until", format!("{} UTC ({until})", utc(until)));
        for (token, max, budget, domain) in &tokens {
            let known = b.facts.tokens.get(token);
            let caps = match known {
                Some(t) => format!(
                    "max {} {sym} per operation, budget {} {sym}",
                    format_units(*max, t.decimals),
                    format_units(*budget, t.decimals),
                    sym = t.symbol
                ),
                None => format!("max {max} per operation, budget {budget} (raw units, unverified decimals)"),
            };
            let x402 = match (domain.is_zero(), known) {
                (true, _) => String::new(),
                // the policy checks payment signatures against this domain: for a token the
                // build knows it must be that token's own, or the cap would guard another contract
                (false, Some(t)) if t.domain == *domain => ", x402 payments allowed (the token's own signing domain)".to_string(),
                (false, Some(t)) => {
                    return Err(format!("the x402 signing domain in this mandate is not {}'s own; refused", t.symbol));
                }
                (false, None) => format!(", x402 payments allowed (domain {domain})"),
            };
            b.row(s, "Token cap", format!("{}: {caps}{x402}", b.name(*token)));
            match payees.iter().find(|p| p.0 == *token) {
                Some((_, list)) => {
                    for payee in list {
                        b.row(s, "Token payee", format!("{}: only to {}", b.name(*token), b.name(*payee)));
                    }
                }
                None => b.row(s, "Token payee", format!("{}: anyone — the agent picks the recipient and the spender", b.name(*token))),
            }
        }
    }
    if signer.len() < 22 {
        return Err("a signer entry shorter than flag ‖ module; refused".into());
    }
    if signer[..2] != [0, 0] {
        return Err(format!("a signer entry with flag 0x{}; a permission that skips its signature is refused", hex(&signer[..2])));
    }
    let module = Address::from_slice(&signer[2..22]);
    b.row(s, "Signer module", b.name(module));
    module_known(b, "signer", module)?;
    let pk = decode_pubkey(&signer[22..]).ok_or("signer data is not a P-256 key; refused")?;
    b.row(s, "Agent key", fingerprint(&pk));
    Ok(())
}

fn external_call(
    b: &mut Builder<'_>,
    s: usize,
    target: Address,
    value: U256,
    data: &[u8],
    acct: &EnrolledAccount,
    labels: &BTreeMap<Address, String>,
) -> Result<(), String> {
    let mut to = b.name(target);
    if let Some(l) = labels.get(&target) {
        to.push_str(&format!(" \"{l}\" (from the laptop — unverified)"));
    }
    b.row(s, "To", to);
    if !value.is_zero() {
        // value to a contract the build knows is a parameter; to anything else it is a payment
        if b.facts.names.contains_key(&target) {
            b.row(s, "Send", format!("{} ETH", format_ether(value)));
        } else {
            b.bold(s, "Send", format!("{} ETH to an address this build does not know", format_ether(value)));
        }
    }
    if data.is_empty() {
        if value.is_zero() {
            b.row(s, "Call", "empty (no value, no data)");
        }
        return Ok(());
    }
    if data.len() < 4 {
        return Err("an external call with data shorter than a selector; refused".into());
    }
    let selector: [u8; 4] = data[..4].try_into().expect("4");
    if selector == SELECTOR_INCREMENT && data.len() == 4 && b.facts.demo_counter == Some(target) {
        b.row(s, "Call", "increment()");
        return Ok(());
    }
    if (selector == SELECTOR_ERC20_TRANSFER || selector == SELECTOR_ERC20_APPROVE) && data.len() == 68 {
        if data[4..16] != [0u8; 12] {
            return Err("an ERC-20 call with a non-canonical address word; refused".into());
        }
        let who = Address::from_slice(&data[16..36]);
        let amount = U256::from_be_slice(&data[36..68]);
        let amount = match (amount == U256::MAX, b.facts.tokens.get(&target)) {
            (true, Some(t)) => format!("unlimited {}", t.symbol),
            (true, None) => "unlimited".to_string(),
            (false, _) => b.token_amount(target, amount),
        };
        if selector == SELECTOR_ERC20_TRANSFER {
            // tokens are payments too: plain only to a contract the build knows
            if b.facts.names.contains_key(&who) {
                b.row(s, "Call", format!("ERC-20 transfer to {}: {amount}", b.name(who)));
            } else {
                b.bold(s, "ERC-20 transfer", format!("{amount} to {}, an address this build does not know", who.to_checksum(None)));
            }
        } else {
            // an approval hands spending rights to a third party
            b.bold(s, "ERC-20 approve", format!("{} may spend {amount} of this token", who.to_checksum(None)));
        }
        return Ok(());
    }
    if !acct.expert_mode {
        return Err(format!(
            "a call to {} with function 0x{} this version cannot decode; from the root key it can move everything the account holds (expert mode is off)",
            target.to_checksum(None),
            hex(&selector)
        ));
    }
    b.bold(
        s,
        "Unknown call",
        format!("function 0x{}, {} bytes — this calls an unknown contract that can move everything this account holds", hex(&selector), data.len()),
    );
    b.warnings.push("an unknown external call, allowed by expert mode".into());
    Ok(())
}

fn decode_pubkey(data: &[u8]) -> Option<PublicKey> {
    if data.len() != 64 {
        return None;
    }
    let pk = PublicKey { x: data[..32].try_into().ok()?, y: data[32..].try_into().ok()? };
    hw_signer::valid_public_key(&pk).then_some(pk)
}

/// `0x02 ‖ id ‖ 0×16`: the tail is not shown, so it must be zero.
fn clean_permission_vid(vid: FixedBytes<21>) -> Result<(), String> {
    if vid.0[0] == VALIDATION_TYPE_PERMISSION && vid.0[5..] != [0u8; 16] {
        return Err("a permission id with non-zero trailing bytes; refused".into());
    }
    Ok(())
}

fn vid_text(vid: FixedBytes<21>) -> String {
    match vid.0[0] {
        VALIDATION_TYPE_PERMISSION => format!("permission 0x{}", hex(&vid.0[1..5])),
        VALIDATION_TYPE_VALIDATOR => format!("validator {}", Address::from_slice(&vid.0[1..21]).to_checksum(None)),
        other => format!("validation type 0x{other:02x}"),
    }
}

fn selector_name(sel: [u8; 4]) -> String {
    let name = match sel {
        s if s == IKernel::executeCall::SELECTOR => Some("execute"),
        s if s == IKernel::changeRootValidatorCall::SELECTOR => Some("changeRootValidator"),
        s if s == IKernel::installValidationsCall::SELECTOR => Some("installValidations"),
        s if s == IKernel::uninstallValidationCall::SELECTOR => Some("uninstallValidation"),
        s if s == IKernel::grantAccessCall::SELECTOR => Some("grantAccess"),
        SELECTOR_INCREMENT => Some("increment"),
        SELECTOR_ERC20_TRANSFER => Some("transfer"),
        SELECTOR_ERC20_APPROVE => Some("approve"),
        [0, 0, 0, 0] => Some("plain value transfer"),
        _ => None,
    };
    match name {
        Some(n) => format!("{n} (0x{})", hex(&sel)),
        None => format!("0x{}", hex(&sel)),
    }
}

/// §6.3 text rules: printable ASCII plus spaces, at most 32 characters.
pub(crate) fn clean_label(l: &str) -> Option<String> {
    (l.len() <= 32 && plain_text(l)).then(|| l.to_string())
}

/// Printable ASCII, not empty: no homoglyphs, no bidirectional controls.
pub(crate) fn plain_text(l: &str) -> bool {
    !l.is_empty() && l.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Wei as ETH, without trailing zeros: `0.00102 ETH`, `1 ETH`.
fn format_ether(wei: U256) -> String {
    format_units(wei, 18)
}

/// An integer amount with `decimals` decimal places, without trailing zeros.
fn format_units(amount: U256, decimals: u8) -> String {
    let d = decimals as usize;
    let digits = amount.to_string();
    let digits = if digits.len() <= d { format!("{}{digits}", "0".repeat(d + 1 - digits.len())) } else { digits };
    let (int, frac) = digits.split_at(digits.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { int.to_string() } else { format!("{int}.{frac}") }
}

fn split(word: B256) -> (u128, u128) {
    (u128::from_be_bytes(word.0[..16].try_into().expect("16")), u128::from_be_bytes(word.0[16..].try_into().expect("16")))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `YYYY-MM-DD HH:MM:SS` from unix seconds (proleptic Gregorian, no leap seconds).
fn utc(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel;
    use crate::request::SignRequest;
    use crate::user_op::PackedUserOp;
    use alloy_primitives::address;

    type ValidationIdBytes = FixedBytes<21>;

    const ENTRY: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
    const ACCOUNT: Address = address!("D62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628");
    const COUNTER: Address = address!("1000000000000000000000000000000000000001");
    const VALIDATOR: Address = address!("2000000000000000000000000000000000000002");
    const RECOVERY: Address = address!("3000000000000000000000000000000000000003");
    const POLICY: Address = address!("4000000000000000000000000000000000000004");
    const SIGNER: Address = address!("5000000000000000000000000000000000000005");
    const PAYMASTER: Address = address!("6000000000000000000000000000000000000006");
    const NOW: u64 = 1_800_000_000;

    fn key(n: u8) -> PublicKey {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[n; 32].into()).unwrap();
        let p = sk.verifying_key().to_sec1_point(false);
        PublicKey { x: p.x().unwrap().as_slice().try_into().unwrap(), y: p.y().unwrap().as_slice().try_into().unwrap() }
    }

    fn facts() -> Facts {
        let mut names = BTreeMap::new();
        names.insert(COUNTER, "demo counter".to_string());
        names.insert(VALIDATOR, "P256Validator".to_string());
        names.insert(RECOVERY, "P256RecoveryValidator".to_string());
        names.insert(POLICY, "AgentPolicy".to_string());
        names.insert(SIGNER, "P256Signer".to_string());
        names.insert(PAYMASTER, "WhitelistPaymaster".to_string());
        Facts {
            names,
            sponsoring_paymasters: vec![PAYMASTER],
            recovery_validators: vec![RECOVERY],
            demo_counter: Some(COUNTER),
            policy_modules: vec![POLICY],
            payee_policy_modules: vec![POLICY],
            signer_modules: vec![SIGNER],
            tokens: BTreeMap::new(),
            entry_point: None,
        }
    }

    fn enrolled() -> Vec<EnrolledAccount> {
        let mut e = EnrolledAccount::new(31337, ENTRY, ACCOUNT);
        e.validator = Some(VALIDATOR);
        vec![e]
    }

    fn op(call_data: Bytes) -> PackedUserOp {
        PackedUserOp {
            sender: ACCOUNT,
            nonce: U256::from(7),
            init_code: Bytes::new(),
            call_data,
            account_gas_limits: kernel::pack_gas(300_000, 150_000),
            pre_verification_gas: U256::from(60_000),
            gas_fees: kernel::pack_gas(1_000_000, 20_000_000_000), // 20 gwei max fee → 0.0102 ETH max cost
            paymaster_and_data: Bytes::new(),
        }
    }

    fn request(op: &PackedUserOp) -> (Vec<u8>, String) {
        let mut labels = BTreeMap::new();
        labels.insert(COUNTER, "demo counter".to_string());
        let bytes = SignRequest::new(op, ENTRY, 31337, NOW + 120, Some("owner operation (root)".into()), labels, None).to_bytes();
        let c = commitment(&bytes);
        (bytes, c)
    }

    fn open(op: &PackedUserOp) -> Review {
        let (bytes, c) = request(op);
        open_request(&bytes, &c, NOW, &enrolled(), &facts())
    }

    fn clone_params(p: &kernel::PolicyParams) -> kernel::PolicyParams {
        kernel::PolicyParams {
            targets: p.targets.clone(),
            selectors: p.selectors.clone(),
            max_value_per_op: p.max_value_per_op,
            budget: p.budget,
            valid_until: p.valid_until,
            tokens: p.tokens.clone(),
            valid_after: p.valid_after,
            payees: p.payees.clone(),
        }
    }

    fn increment() -> PackedUserOp {
        let mut o = op(kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT));
        o.gas_fees = kernel::pack_gas(1_000_000, 2_000_000_000); // 2 gwei → 0.00102 ETH, under the cap
        o
    }

    #[test]
    fn a_counter_increment_is_shown_and_signable() {
        let r = open(&increment());
        assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        let t = r.text();
        assert!(t.contains("increment()"), "{t}");
        assert!(t.contains("demo counter (verified in this build)"), "{t}");
        assert!(t.contains("\"demo counter\" (from the laptop — unverified)"), "{t}");
        assert!(t.contains("Maximum gas cost: 0.00102 ETH"), "{t}");
        assert!(t.contains("key 0 (root), sequence 7"), "{t}");
        assert!(!r.needs_second_confirmation());
        assert_eq!(r.digest_to_sign().unwrap(), SignRequest::parse(&request(&increment()).0, NOW, 0).unwrap().user_op_hash().unwrap());
    }

    #[test]
    fn the_checks_of_6_2() {
        let o = increment();
        let (bytes, c) = request(&o);
        let f = facts();
        // 1 commitment
        assert!(matches!(open_request(&bytes, "x", NOW, &enrolled(), &f).verdict, Verdict::Refuse(ref m) if m.contains("commitment")));
        // 2 expiry, with the 5-minute tolerance
        assert_eq!(open_request(&bytes, &c, NOW + 120 + 299, &enrolled(), &f).verdict, Verdict::Sign);
        assert!(matches!(open_request(&bytes, &c, NOW + 120 + 301, &enrolled(), &f).verdict, Verdict::Refuse(_)));
        // 3 enrollment
        assert!(matches!(open_request(&bytes, &c, NOW, &[], &f).verdict, Verdict::Refuse(ref m) if m.contains("not enrolled")));
        let other_chain = vec![EnrolledAccount::new(1, ENTRY, ACCOUNT)];
        assert!(matches!(open_request(&bytes, &c, NOW, &other_chain, &f).verdict, Verdict::Refuse(_)));
        // 4 initCode
        let mut o2 = o.clone();
        o2.init_code = Bytes::from(vec![1, 2, 3]);
        assert!(matches!(open(&o2).verdict, Verdict::Refuse(ref m) if m.contains("initCode")));
        // 5 nonce key
        let mut o3 = o.clone();
        o3.nonce = U256::from(1) << 64;
        assert!(matches!(open(&o3).verdict, Verdict::Refuse(ref m) if m.contains("nonce key")));
        // 6 hash: a request whose laptop hint lies is refused by the parser
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["laptop"]["userOpHash"] = serde_json::json!(format!("{}", B256::repeat_byte(9)));
        let lying = serde_json::to_vec(&v).unwrap();
        let r = open_request(&lying, &commitment(&lying), NOW, &enrolled(), &f);
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("differs from the recomputed")), "{:?}", r.verdict);
        assert!(r.digest_to_sign().is_err());
    }

    #[test]
    fn gas_cap_and_paymasters() {
        // 20 gwei × 510k gas = 0.0102 ETH > 0.005 ETH cap
        let r = open(&op(kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT)));
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("exceeds this enrollment's cap")), "{:?}", r.verdict);
        // the known no-charge paymaster: shown, and the cap does not apply to the account
        let mut sponsored = op(kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT));
        let mut pm = PAYMASTER.to_vec();
        pm.extend_from_slice(&100_000u128.to_be_bytes());
        pm.extend_from_slice(&0u128.to_be_bytes());
        sponsored.paymaster_and_data = pm.into();
        let r = open(&sponsored);
        assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        assert!(r.text().contains("sponsored by"), "{}", r.text());
        // any other paymaster is refused
        let mut other = sponsored.clone();
        let mut pm = SIGNER.to_vec();
        pm.extend_from_slice(&[0u8; 32]);
        other.paymaster_and_data = pm.into();
        assert!(matches!(open(&other).verdict, Verdict::Refuse(ref m) if m.contains("paymaster")));
    }

    #[test]
    fn admin_calls_are_decoded_with_their_effects() {
        let me = ACCOUNT;
        let phone_key = key(9);
        // the handover batch set_root builds with the recovery pivot
        let batch = kernel::execute_batch_calldata(vec![
            (me, U256::ZERO, kernel::change_root_calldata(RECOVERY, None)),
            (me, U256::ZERO, kernel::uninstall_validator_call(VALIDATOR)),
            (me, U256::ZERO, kernel::install_validator_call(kernel::validator_id(VALIDATOR), &phone_key, 3)),
            (me, U256::ZERO, kernel::change_root_calldata(VALIDATOR, None)),
        ]);
        let mut o = op(batch);
        o.gas_fees = kernel::pack_gas(1, 1);
        let r = open(&o);
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(r.needs_second_confirmation());
        assert!(t.contains("! Hand control of this account to validator"), "{t}");
        assert!(t.contains("this phone will no longer control the account"), "{t}");
        assert!(t.contains(&format!("! Hand control of this account to key: {}", fingerprint(&phone_key))), "{t}");
        assert!(t.contains("Call 4 of 4"), "{t}");

        // add-recovery: install + grant changeRootValidator
        let mut o = op(kernel::add_recovery_calldata(me, RECOVERY, &key(4), 2));
        o.gas_fees = kernel::pack_gas(1, 1);
        let r = open(&o);
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(t.contains("! Install a recovery key"), "{t}");
        assert!(t.contains("may take over this account"), "{t}");

        // an agent permission with its mandate, then the revoke
        let params = kernel::PolicyParams {
            targets: vec![COUNTER],
            selectors: vec![FixedBytes::from(SELECTOR_INCREMENT)],
            max_value_per_op: 1000,
            budget: 10u128.pow(18),
            valid_until: NOW + 86_400,
            tokens: vec![(SIGNER, 5, 50, B256::repeat_byte(1))],
            valid_after: 0, payees: vec![],
        };
        let perm = FixedBytes::from([0x74, 0x65, 0x73, 0x31]);
        let pdata = kernel::permission_data(POLICY, &params, SIGNER, &key(2));
        let mut o = op(kernel::execute_batch_calldata(vec![
            (me, U256::ZERO, kernel::install_permission_calldata(perm, pdata, 1)),
            (me, U256::ZERO, kernel::grant_execute_calldata(perm)),
        ]));
        o.gas_fees = kernel::pack_gas(1, 1);
        let r = open(&o);
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(t.contains("Install agent permission: 0x74657331"), "{t}");
        assert!(t.contains(&format!("Agent key: {}", fingerprint(&key(2)))), "{t}");
        assert!(t.contains("increment (0xd09de08a)"), "{t}");
        assert!(t.contains("Budget: 1 ETH"), "{t}");
        assert!(t.contains("x402 payments allowed"), "{t}");
        assert!(t.contains("Allow permission 0x74657331 to call: execute"), "{t}");
        assert!(!r.needs_second_confirmation(), "{t}");
        // no payee list: the screen says who may be paid
        assert!(t.contains("anyone — the agent picks the recipient and the spender"), "{t}");

        // the same mandate with a payee list for its token
        let listed = kernel::PolicyParams { payees: vec![(SIGNER, vec![COUNTER, RECOVERY])], ..params };
        let install = |p: &kernel::PolicyParams, module_facts: &Facts| {
            let pdata = kernel::permission_data(POLICY, p, SIGNER, &key(2));
            let mut o = op(kernel::execute_batch_calldata(vec![
                (me, U256::ZERO, kernel::install_permission_calldata(perm, pdata, 1)),
                (me, U256::ZERO, kernel::grant_execute_calldata(perm)),
            ]));
            o.gas_fees = kernel::pack_gas(1, 1);
            let (bytes, c) = request(&o);
            open_request(&bytes, &c, NOW, &enrolled(), module_facts)
        };
        let r = install(&listed, &facts());
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert_eq!(t.matches("Token payee: ").count(), 2, "{t}");
        assert!(t.contains(&format!("only to {}", COUNTER.to_checksum(None))), "{t}");
        assert!(!t.contains("anyone — the agent picks"), "{t}");
        // a policy module that would ignore the lists: nothing is shown as if enforced
        let mut older = facts();
        older.payee_policy_modules.clear();
        assert!(matches!(install(&listed, &older).verdict, Verdict::Refuse(ref m) if m.contains("not known to enforce")));
        // lists the policy itself would refuse
        for bad in [
            vec![(SIGNER, vec![])],
            vec![(SIGNER, vec![COUNTER, COUNTER])],
            vec![(SIGNER, vec![Address::ZERO])],
            vec![(COUNTER, vec![RECOVERY])],
            vec![(SIGNER, vec![COUNTER]), (SIGNER, vec![RECOVERY])],
        ] {
            let p = kernel::PolicyParams { payees: bad, ..kernel::PolicyParams { payees: vec![], ..clone_params(&listed) } };
            assert!(matches!(install(&p, &facts()).verdict, Verdict::Refuse(_)));
        }
        // a limited token with an entry its limits are not checked on (permit, a plain
        // transfer to it): refused, with a payee list and without; `transfer` is fine
        for payees in [vec![], vec![(SIGNER, vec![COUNTER])]] {
            let with = |selector: [u8; 4]| kernel::PolicyParams {
                targets: vec![COUNTER, SIGNER],
                selectors: vec![FixedBytes::from(SELECTOR_INCREMENT), FixedBytes::from(selector)],
                payees: payees.clone(),
                ..clone_params(&listed)
            };
            for other in [[0xd5, 0x05, 0xac, 0xcf], [0, 0, 0, 0]] {
                let r = install(&with(other), &facts());
                assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("past its limits")), "{}", r.text());
            }
            let r = install(&with([0xa9, 0x05, 0x9c, 0xbb]), &facts());
            assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        }
        // Permit2 as a target, whatever the function
        let permit2 = kernel::PolicyParams {
            targets: vec![COUNTER, alloy_primitives::address!("000000000022D473030F116dDEE9F6B43aC78BA3")],
            selectors: vec![FixedBytes::from(SELECTOR_INCREMENT), FixedBytes::from([0x87, 0x51, 0x7c, 0x45])],
            payees: vec![],
            ..clone_params(&listed)
        };
        let r = install(&permit2, &facts());
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("Permit2")), "{}", r.text());
        let mut o = op(kernel::uninstall_permission_calldata(perm));
        o.gas_fees = kernel::pack_gas(1, 1);
        let r = open(&o);
        assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        assert!(r.text().contains("Remove permission: 0x74657331"));
    }

    #[test]
    fn what_is_never_signed_6_5() {
        let me = ACCOUNT;
        let mut o = op(kernel::execute_calldata(COUNTER, U256::ZERO, &[0xde, 0xad, 0xbe, 0xef]));
        o.gas_fees = kernel::pack_gas(1, 1);
        // an unknown external call: refused, allowed in expert mode with the bold warning
        assert!(matches!(open(&o).verdict, Verdict::Refuse(ref m) if m.contains("cannot decode")));
        // increment() is a selector, not a contract: on an unknown target it is an unknown call
        let mut inc_elsewhere = op(kernel::execute_calldata(PAYMASTER, U256::ZERO, &SELECTOR_INCREMENT));
        inc_elsewhere.gas_fees = kernel::pack_gas(1, 1);
        assert!(matches!(open(&inc_elsewhere).verdict, Verdict::Refuse(ref m) if m.contains("cannot decode")));
        let mut expert = enrolled();
        expert[0].expert_mode = true;
        let (bytes, c) = request(&o);
        let r = open_request(&bytes, &c, NOW, &expert, &facts());
        assert!(matches!(r.verdict, Verdict::SignWithWarnings(_)), "{:?}", r.verdict);
        assert!(r.needs_second_confirmation());
        // delegatecall
        let mut dc = kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT).to_vec();
        dc[4] = 0xff; // execMode's first byte
        let mut o = op(dc.into());
        o.gas_fees = kernel::pack_gas(1, 1);
        assert!(matches!(open(&o).verdict, Verdict::Refuse(ref m) if m.contains("delegatecall")));
        // an unknown self-call
        let mut o = op(kernel::execute_calldata(me, U256::ZERO, &[1, 2, 3, 4]));
        o.gas_fees = kernel::pack_gas(1, 1);
        assert!(matches!(open(&o).verdict, Verdict::Refuse(ref m) if m.contains("not a Kernel admin call")));
        // a top-level call that is neither execute nor uninstallValidation
        let mut o = op(Bytes::from(vec![9, 9, 9, 9]));
        o.gas_fees = kernel::pack_gas(1, 1);
        assert!(matches!(open(&o).verdict, Verdict::Refuse(_)));
        // a label that is not plain text
        let (bytes, _) = request(&increment());
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["laptop"]["command"] = serde_json::json!("owner\u{202e}noitarepo");
        let b = serde_json::to_vec(&v).unwrap();
        assert!(matches!(open_request(&b, &commitment(&b), NOW, &enrolled(), &facts()).verdict, Verdict::Refuse(ref m) if m.contains("plain text")));
    }

    /// §9.2: every change that changes the hash must change the screen or be
    /// refused — the request's fields one by one, and every byte of the
    /// calldata.
    #[test]
    fn tamper_every_hash_covered_field() {
        // every decoder in one batch: an external call with value, an ERC-20 transfer, a
        // permission install with its mandate, a validator install, a grant, a root change
        let golden = {
            let me = ACCOUNT;
            let perm = FixedBytes::from([0x74, 0x65, 0x73, 0x31]);
            let params = kernel::PolicyParams {
                targets: vec![COUNTER], selectors: vec![FixedBytes::from(SELECTOR_INCREMENT)], max_value_per_op: 1000,
                budget: 10u128.pow(18), valid_until: NOW + 86_400, tokens: vec![(SIGNER, 5, 50, B256::repeat_byte(1))], valid_after: 0, payees: vec![],
            };
            let mut transfer = SELECTOR_ERC20_TRANSFER.to_vec();
            transfer.extend_from_slice(&[0u8; 12]);
            transfer.extend_from_slice(PAYMASTER.as_slice());
            transfer.extend_from_slice(&U256::from(5).to_be_bytes::<32>());
            let mut o = op(kernel::execute_batch_calldata(vec![
                (COUNTER, U256::from(5), Bytes::copy_from_slice(&SELECTOR_INCREMENT)),
                (SIGNER, U256::ZERO, transfer.into()),
                (me, U256::ZERO, kernel::install_permission_calldata(perm, kernel::permission_data(POLICY, &params, SIGNER, &key(2)), 1)),
                (me, U256::ZERO, kernel::grant_execute_calldata(perm)),
                (me, U256::ZERO, kernel::install_validator_call(kernel::validator_id(RECOVERY), &key(4), 2)),
                (me, U256::ZERO, kernel::change_root_calldata(RECOVERY, None)),
            ]));
            o.gas_fees = kernel::pack_gas(1, 1);
            o
        };
        let base = open(&golden);
        assert_eq!(base.verdict, Verdict::Sign, "{}", base.text());
        let base_text = base.text_without_hash();
        let base_hash = base.digest_to_sign().unwrap();
        let mut refused = 0usize;
        let mut shown = 0usize;
        let mut check = |what: &str, o: &PackedUserOp| {
            let r = open(o);
            let hash = crate::user_op::user_op_hash(o, ENTRY, 31337);
            assert_ne!(hash, base_hash, "{what}: the mutation did not change the hash");
            if r.verdict != Verdict::Sign && !matches!(r.verdict, Verdict::SignWithWarnings(_)) {
                refused += 1;
                return;
            }
            // the hash row is excluded: it changes by definition and proves nothing
            assert_ne!(r.text_without_hash(), base_text, "{what}: the hash changed but the screen did not");
            shown += 1;
        };
        let mut o = golden.clone();
        o.nonce = U256::from(8);
        check("nonce", &o);
        let mut o = golden.clone();
        o.account_gas_limits = kernel::pack_gas(150_000, 300_000);
        check("swapped verification and call gas", &o);
        let mut o = golden.clone();
        o.pre_verification_gas = U256::from(60_001);
        check("preVerificationGas", &o);
        let mut o = golden.clone();
        o.gas_fees = kernel::pack_gas(2, 1);
        check("maxPriorityFeePerGas", &o);
        let mut o = golden.clone();
        o.gas_fees = kernel::pack_gas(1, 2);
        check("maxFeePerGas", &o);
        let mut o = golden.clone();
        let mut pm = PAYMASTER.to_vec();
        pm.extend_from_slice(&[0u8; 32]);
        o.paymaster_and_data = pm.into();
        check("paymasterAndData", &o);
        // every byte of the calldata, with two flips: the low bit and the high bit
        for i in 0..golden.call_data.len() {
            for mask in [0x01u8, 0x80] {
                let mut cd = golden.call_data.to_vec();
                cd[i] ^= mask;
                let mut o = golden.clone();
                o.call_data = cd.into();
                check(&format!("callData byte {i} ^ {mask:#04x}"), &o);
            }
        }
        assert!(shown > 100 && refused > 100, "both outcomes occur: shown {shown}, refused {refused}");
    }

    /// The review of PR #30: hash-covered fields the screen did not show must be
    /// refused — the permission's pass flags, hooks and hook data, deinit data,
    /// ERC-20 padding, trailing bytes — and an unknown module is not a warning.
    #[test]
    fn hidden_fields_are_refused() {
        let me = ACCOUNT;
        let quiet = |cd: Bytes| {
            let mut o = op(cd);
            o.gas_fees = kernel::pack_gas(1, 1);
            o
        };
        let perm = FixedBytes::from([0x74, 0x65, 0x73, 0x31]);
        let params = kernel::PolicyParams {
            targets: vec![COUNTER], selectors: vec![FixedBytes::from(SELECTOR_INCREMENT)], max_value_per_op: 1, budget: 2,
            valid_until: NOW + 10, tokens: vec![], valid_after: 0, payees: vec![],
        };
        let pdata = kernel::permission_data(POLICY, &params, SIGNER, &key(2));
        let install = |pdata: Bytes| quiet(kernel::execute_calldata(me, U256::ZERO, &kernel::install_permission_calldata(perm, pdata, 1)));
        assert_eq!(open(&install(pdata.clone())).verdict, Verdict::Sign);
        // the policy entry's flag: SKIP_USEROP means the mandate on screen is not enforced
        let entries = Vec::<Bytes>::abi_decode(&pdata).unwrap();
        let flip_flag = |i: usize, flag: [u8; 2]| {
            let mut e = entries.clone();
            let mut raw = e[i].to_vec();
            raw[..2].copy_from_slice(&flag);
            e[i] = raw.into();
            Bytes::from(e.abi_encode())
        };
        assert!(matches!(open(&install(flip_flag(0, [0, 1]))).verdict, Verdict::Refuse(ref m) if m.contains("skips its policy")));
        assert!(matches!(open(&install(flip_flag(1, [0, 2]))).verdict, Verdict::Refuse(ref m) if m.contains("skips its signature")));
        // a hook on an install
        let mut c = IKernel::installValidationsCall::abi_decode(&kernel::install_permission_calldata(perm, pdata.clone(), 1)).unwrap();
        c.configs[0].hook = PAYMASTER;
        assert!(matches!(open(&quiet(kernel::execute_calldata(me, U256::ZERO, &c.abi_encode()))).verdict, Verdict::Refuse(ref m) if m.contains("hook")));
        let mut c = IKernel::installValidationsCall::abi_decode(&kernel::install_permission_calldata(perm, pdata.clone(), 1)).unwrap();
        c.hookData[0] = Bytes::from(vec![1]);
        assert!(matches!(open(&quiet(kernel::execute_calldata(me, U256::ZERO, &c.abi_encode()))).verdict, Verdict::Refuse(ref m) if m.contains("hook data")));
        // a self-call with value, and a permission id with a dirty tail
        let r = open(&quiet(kernel::execute_batch_calldata(vec![(me, U256::from(1), kernel::grant_execute_calldata(perm))])));
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("self-call with value")));
        let mut g = IKernel::grantAccessCall::abi_decode(&kernel::grant_execute_calldata(perm)).unwrap();
        g.vId.0[20] = 1;
        let r = open(&quiet(kernel::execute_calldata(me, U256::ZERO, &g.abi_encode())));
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("trailing bytes")));
        // a hook on a root change
        let mut c = IKernel::changeRootValidatorCall::abi_decode(&kernel::change_root_calldata(VALIDATOR, None)).unwrap();
        c.hook = PAYMASTER;
        assert!(matches!(open(&quiet(kernel::execute_calldata(me, U256::ZERO, &c.abi_encode()))).verdict, Verdict::Refuse(ref m) if m.contains("hook")));
        // deinit data on an uninstall
        let mut c = IKernel::uninstallValidationCall::abi_decode(&kernel::uninstall_validator_call(VALIDATOR)).unwrap();
        c.deinitData = Bytes::from(vec![1]);
        assert!(matches!(open(&quiet(kernel::execute_calldata(me, U256::ZERO, &c.abi_encode()))).verdict, Verdict::Refuse(ref m) if m.contains("with data")));
        let mut c = IKernel::uninstallValidationCall::abi_decode(&kernel::uninstall_permission_calldata(perm)).unwrap();
        c.hookDeinitData = Bytes::from(vec![1]);
        assert!(matches!(open(&quiet(c.abi_encode().into())).verdict, Verdict::Refuse(ref m) if m.contains("hook data")));
        // trailing bytes after execute's calldata
        let mut cd = kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT).to_vec();
        cd.push(0);
        assert!(matches!(open(&quiet(cd.into())).verdict, Verdict::Refuse(ref m) if m.contains("canonical")));
        // ERC-20 padding bytes
        let mut transfer = SELECTOR_ERC20_TRANSFER.to_vec();
        transfer.extend_from_slice(&[0u8; 12]);
        transfer.extend_from_slice(PAYMASTER.as_slice());
        transfer.extend_from_slice(&U256::from(5).to_be_bytes::<32>());
        let r = open(&quiet(kernel::execute_calldata(SIGNER, U256::ZERO, &transfer)));
        assert_eq!(r.verdict, Verdict::Sign);
        assert!(r.text().contains("Call: ERC-20 transfer to 0x6000000000000000000000000000000000000006 — WhitelistPaymaster (verified in this build): 5"), "a known recipient stays plain: {}", r.text());
        let mut to_unknown = transfer.clone();
        to_unknown[16..36].copy_from_slice(address!("7000000000000000000000000000000000000007").as_slice());
        let r = open(&quiet(kernel::execute_calldata(SIGNER, U256::ZERO, &to_unknown)));
        assert!(r.needs_second_confirmation() && r.text().contains("! ERC-20 transfer: 5 (raw units, unverified decimals) to 0x7000000000000000000000000000000000000007, an address this build does not know"), "{}", r.text());
        let mut padded = transfer.clone();
        padded[4] = 1;
        assert!(matches!(open(&quiet(kernel::execute_calldata(SIGNER, U256::ZERO, &padded))).verdict, Verdict::Refuse(ref m) if m.contains("address word")));
        // approve is an effect; unlimited is named
        let mut approve = SELECTOR_ERC20_APPROVE.to_vec();
        approve.extend_from_slice(&transfer[4..36]);
        approve.extend_from_slice(&U256::MAX.to_be_bytes::<32>());
        let r = open(&quiet(kernel::execute_calldata(SIGNER, U256::ZERO, &approve)));
        assert_eq!(r.verdict, Verdict::Sign);
        assert!(r.needs_second_confirmation() && r.text().contains("may spend unlimited"), "{}", r.text());
        // value to an unknown address is an effect too
        let r = open(&quiet(kernel::execute_calldata(address!("7000000000000000000000000000000000000007"), U256::from(10u128.pow(18)), &[])));
        assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        assert!(r.text().contains("! Send: 1 ETH to an address this build does not know"), "{}", r.text());
        // an unknown policy module: refused, bold in expert mode
        let foreign = kernel::permission_data(PAYMASTER, &params, SIGNER, &key(2));
        assert!(matches!(open(&install(foreign.clone())).verdict, Verdict::Refuse(ref m) if m.contains("not known to this build")));
        let (bytes, c) = request(&install(foreign));
        let mut expert = enrolled();
        expert[0].expert_mode = true;
        let r = open_request(&bytes, &c, NOW, &expert, &facts());
        assert!(matches!(r.verdict, Verdict::SignWithWarnings(_)) && r.text().contains("! Unknown policy module"), "{}", r.text());
    }

    /// The review of PR #31: on the phone the facts are empty and the enrollment
    /// does not know its validator until slice 3. When the review cannot tell,
    /// it emphasises.
    #[test]
    fn empty_facts_emphasise_what_cannot_be_classified() {
        let me = ACCOUNT;
        let bare = [EnrolledAccount::new(31337, ENTRY, ACCOUNT)];
        let quiet = |cd: Bytes| {
            let mut o = op(cd);
            o.gas_fees = kernel::pack_gas(1, 1);
            o
        };
        let open_bare = |o: &PackedUserOp| {
            let (bytes, c) = request(o);
            open_request(&bytes, &c, NOW, &bare, &Facts::default())
        };
        // the handover batch: the removal of the old validator and the root change are bold
        let r = open_bare(&quiet(kernel::execute_batch_calldata(vec![
            (me, U256::ZERO, kernel::change_root_calldata(RECOVERY, None)),
            (me, U256::ZERO, kernel::uninstall_validator_call(VALIDATOR)),
            (me, U256::ZERO, kernel::install_validator_call(kernel::validator_id(VALIDATOR), &key(9), 3)),
            (me, U256::ZERO, kernel::change_root_calldata(VALIDATOR, None)),
        ])));
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(t.contains("! Remove validator: 0x2000000000000000000000000000000000000002 — this may be the validator holding this phone's key"), "{t}");
        assert!(t.contains("! Install a key on a validator this build cannot classify"), "{t}");
        assert!(t.contains("! Hand control of this account to key"), "{t}");
        // add-recovery: the install is bold even without knowing the recovery validator
        let r = open_bare(&quiet(kernel::add_recovery_calldata(me, RECOVERY, &key(4), 2)));
        assert!(r.text().contains("! Install a key on a validator this build cannot classify") && r.text().contains("may take over this account"), "{}", r.text());
        // a permission install is unsignable without known modules (expert mode off)
        let params = kernel::PolicyParams { targets: vec![], selectors: vec![], max_value_per_op: 0, budget: 0, valid_until: NOW + 1, tokens: vec![], valid_after: 0, payees: vec![] };
        let pdata = kernel::permission_data(POLICY, &params, SIGNER, &key(2));
        let r = open_bare(&quiet(kernel::execute_calldata(me, U256::ZERO, &kernel::install_permission_calldata(FixedBytes::from([1, 2, 3, 4]), pdata, 1))));
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("not known to this build")), "{:?}", r.verdict);
        // and a plain increment on an unknown counter is refused: the phone knows no contracts yet
        assert!(matches!(open_bare(&quiet(kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT))).verdict, Verdict::Refuse(_)));
    }

    /// §6.7: a token the build knows is scaled with the build's decimals and
    /// named; its x402 domain in a mandate must be the token's own.
    #[test]
    fn known_tokens_are_scaled_and_their_x402_domain_is_checked() {
        let me = ACCOUNT;
        let token = address!("8000000000000000000000000000000000000008");
        let domain = B256::repeat_byte(0xd0);
        let mut f = facts();
        f.names.insert(token, "USDC".into());
        f.tokens.insert(token, Token { symbol: "USDC".into(), decimals: 6, domain });
        let open_f = |cd: Bytes| {
            let mut o = op(cd);
            o.gas_fees = kernel::pack_gas(1, 1);
            let (bytes, c) = request(&o);
            open_request(&bytes, &c, NOW, &enrolled(), &f)
        };
        let erc20 = |on: Address, selector: [u8; 4], who: Address, amount: U256| {
            let mut d = selector.to_vec();
            d.extend_from_slice(&[0u8; 12]);
            d.extend_from_slice(who.as_slice());
            d.extend_from_slice(&amount.to_be_bytes::<32>());
            kernel::execute_calldata(on, U256::ZERO, &d)
        };
        let t = open_f(erc20(token, SELECTOR_ERC20_TRANSFER, PAYMASTER, U256::from(20_500_000))).text();
        assert!(t.contains("USDC (verified in this build)") && t.contains(": 20.5 USDC"), "{t}");
        let t = open_f(erc20(token, SELECTOR_ERC20_APPROVE, PAYMASTER, U256::MAX)).text();
        assert!(t.contains("may spend unlimited USDC of this token"), "{t}");
        // the same amount on a token the build does not know stays raw
        let t = open_f(erc20(SIGNER, SELECTOR_ERC20_TRANSFER, PAYMASTER, U256::from(20_500_000))).text();
        assert!(t.contains("20500000 (raw units, unverified decimals)"), "{t}");

        let mandate = |token_domain: B256| {
            let params = kernel::PolicyParams {
                targets: vec![COUNTER],
                selectors: vec![FixedBytes::from(SELECTOR_INCREMENT)],
                max_value_per_op: 0,
                budget: 0,
                valid_until: NOW + 10,
                tokens: vec![(token, 20_000_000, 100_000_000, token_domain)],
                valid_after: 0, payees: vec![],
            };
            let pdata = kernel::permission_data(POLICY, &params, SIGNER, &key(2));
            open_f(kernel::execute_calldata(me, U256::ZERO, &kernel::install_permission_calldata(FixedBytes::from([1, 2, 3, 4]), pdata, 1)))
        };
        let r = mandate(domain);
        assert_eq!(r.verdict, Verdict::Sign, "{}", r.text());
        assert!(
            r.text().contains("max 20 USDC per operation, budget 100 USDC, x402 payments allowed (the token's own signing domain)"),
            "{}",
            r.text()
        );
        let r = mandate(B256::ZERO);
        assert!(r.text().contains("budget 100 USDC\n"), "no x402 without a domain: {}", r.text());
        // a mandate whose x402 domain is another contract's would guard the wrong thing
        assert!(matches!(mandate(B256::repeat_byte(1)).verdict, Verdict::Refuse(ref m) if m.contains("not USDC's own")));
    }

    /// §4.3, §6.7: a laptop pin is a label, marked as such; it changes no verdict
    /// and no emphasis, and it never replaces a name the build has.
    #[test]
    fn laptop_pins_are_labels_only() {
        let vault = address!("7000000000000000000000000000000000000007");
        let fake_counter = address!("9000000000000000000000000000000000000009");
        let mut pinned = enrolled();
        pinned[0].pins.insert(vault, "my vault".into());
        pinned[0].pins.insert(fake_counter, "demo counter".into());
        pinned[0].pins.insert(COUNTER, "not the counter".into());
        let open_p = |cd: Bytes| {
            let mut o = op(cd);
            o.gas_fees = kernel::pack_gas(1, 1);
            let (bytes, c) = request(&o);
            open_request(&bytes, &c, NOW, &pinned, &facts())
        };
        let r = open_p(kernel::execute_calldata(vault, U256::from(10u128.pow(18)), &[]));
        let t = r.text();
        assert!(t.contains("To: 0x7000000000000000000000000000000000000007 \"my vault\" (pinned by the laptop at enrollment — unverified)"), "{t}");
        assert!(t.contains("! Send: 1 ETH to an address this build does not know") && r.needs_second_confirmation(), "a pin does not make a payment plain: {t}");
        // a pin named like a known contract does not make its calls known
        assert!(matches!(open_p(kernel::execute_calldata(fake_counter, U256::ZERO, &SELECTOR_INCREMENT)).verdict, Verdict::Refuse(ref m) if m.contains("cannot decode")));
        // and the build's name wins over a pin
        let t = open_p(kernel::execute_calldata(COUNTER, U256::ZERO, &SELECTOR_INCREMENT)).text();
        assert!(t.contains("demo counter (verified in this build)") && !t.contains("not the counter"), "{t}");
    }

    /// The phone's path: the facts embedded for the request's chain. On Base
    /// Sepolia the project's own contracts are known, a variant's paymaster is not.
    /// A refusal's reason is on the screen too: a request whose field name
    /// carries a line break and a right-to-left override is refused, and the
    /// reason shows neither.
    #[test]
    fn a_refusal_does_not_carry_the_laptops_control_characters() {
        let bytes = "{\"userOp\":{\"zz\\n\u{202e}SIGNED OK\":1}}".as_bytes();
        let r = open_request_with_build_facts(bytes, &commitment(bytes), NOW, &[]);
        let Verdict::Refuse(why) = &r.verdict else { panic!("{:?}", r.verdict) };
        assert!(why.chars().all(|c| (' '..='~').contains(&c)), "{why:?}");
        assert!(why.contains("SIGNED OK") && why.contains('?'), "{why:?}");
    }

    #[test]
    fn build_facts_drive_the_review() {
        let me = ACCOUNT;
        let f = crate::facts::for_chain(84532);
        let (policy, signer) = (f.policy_modules[0], f.signer_modules[0]);
        let usdc = *f.tokens.keys().next().unwrap();
        let open_84532 = |o: &PackedUserOp| {
            let bytes = SignRequest::new(o, ENTRY, 84532, NOW + 120, None, BTreeMap::new(), None).to_bytes();
            open_request_with_build_facts(&bytes, &commitment(&bytes), NOW, &[EnrolledAccount::new(84532, ENTRY, ACCOUNT)])
        };
        let params = kernel::PolicyParams {
            targets: vec![f.demo_counter.unwrap()],
            selectors: vec![FixedBytes::from(SELECTOR_INCREMENT)],
            max_value_per_op: 0,
            budget: 0,
            valid_until: NOW + 10,
            tokens: vec![(usdc, 20_000_000, 100_000_000, f.tokens[&usdc].domain)],
            valid_after: 0, payees: vec![],
        };
        let pdata = kernel::permission_data(policy, &params, signer, &key(2));
        let mut o = op(kernel::execute_calldata(me, U256::ZERO, &kernel::install_permission_calldata(FixedBytes::from([1, 2, 3, 4]), pdata, 1)));
        o.gas_fees = kernel::pack_gas(1, 1);
        let r = open_84532(&o);
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(t.contains("AgentPolicy (verified in this build)") && t.contains("P256Signer (verified in this build)"), "{t}");
        assert!(t.contains("demo counter (verified in this build) · increment") && t.contains("max 20 USDC per operation"), "{t}");
        // sponsored by the canonical paymaster: accepted; by a variant's paymaster: refused
        let sponsored_by = |pm: Address| {
            let mut s = o.clone();
            let mut pd = pm.to_vec();
            pd.extend_from_slice(&[0u8; 32]);
            s.paymaster_and_data = pd.into();
            open_84532(&s)
        };
        assert!(sponsored_by(f.sponsoring_paymasters[0]).text().contains("sponsored by") );
        let enclave_paymaster = address!("05a97329397200dF8795A882da0b5b1aD894EB97");
        assert!(matches!(sponsored_by(enclave_paymaster).verdict, Verdict::Refuse(ref m) if m.contains("paymaster")));
        // the EntryPoint is a build fact: an enrollment made for another one signs nothing
        let other_entry = address!("0000000000000000000000000000000000000Ee1");
        let bytes = SignRequest::new(&o, other_entry, 84532, NOW + 120, None, BTreeMap::new(), None).to_bytes();
        let r = open_request_with_build_facts(&bytes, &commitment(&bytes), NOW, &[EnrolledAccount::new(84532, other_entry, ACCOUNT)]);
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("EntryPoint")), "{:?}", r.verdict);
        // a chain the build does not know: the same request names nothing and is refused
        let bytes = SignRequest::new(&o, ENTRY, 1, NOW + 120, None, BTreeMap::new(), None).to_bytes();
        let r = open_request_with_build_facts(&bytes, &commitment(&bytes), NOW, &[EnrolledAccount::new(1, ENTRY, ACCOUNT)]);
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("not known to this build")), "{:?}", r.verdict);
    }

    #[test]
    fn amounts_are_formatted_without_trailing_zeros() {
        assert_eq!(format_units(U256::ZERO, 6), "0");
        assert_eq!(format_units(U256::from(1), 18), "0.000000000000000001");
        assert_eq!(format_units(U256::from(1_500_000), 6), "1.5");
        assert_eq!(format_units(U256::from(20_000_000), 6), "20");
        assert_eq!(format_units(U256::from(5), 0), "5");
        assert_eq!(format_ether(U256::from(10u128.pow(18))), "1");
    }

    /// The review of PR #32: `grantAccess` is what lets a non-root key call a
    /// top-level selector, so a grant is an effect unless something bounds it,
    /// and a key on any validator is an owner-grade key.
    #[test]
    fn grants_and_validator_installs_are_effects() {
        let me = ACCOUNT;
        let perm = FixedBytes::from([0x74, 0x65, 0x73, 0x31]);
        let v1 = address!("a000000000000000000000000000000000000001");
        let mut f = facts();
        f.names.insert(v1, "P256Validator v1 (superseded)".into());
        let open_as = |calls: Vec<Bytes>, accounts: &[EnrolledAccount]| {
            let mut o = op(kernel::execute_batch_calldata(calls.into_iter().map(|c| (me, U256::ZERO, c)).collect()));
            o.gas_fees = kernel::pack_gas(1, 1);
            let (bytes, c) = request(&o);
            open_request(&bytes, &c, NOW, accounts, &f)
        };
        let open_calls = |calls: Vec<Bytes>| open_as(calls, &enrolled());
        let grant = |vid: ValidationIdBytes, selector: [u8; 4], allow: bool| -> Bytes {
            IKernel::grantAccessCall { vId: vid, selector: FixedBytes::from(selector), allow }.abi_encode().into()
        };
        let (execute, change_root) = (IKernel::executeCall::SELECTOR, IKernel::changeRootValidatorCall::SELECTOR);
        let (install, grant_sel) = (IKernel::installValidationsCall::SELECTOR, IKernel::grantAccessCall::SELECTOR);
        let validator = kernel::validator_id(v1);
        let permission = kernel::permission_vid(perm);

        // a second owner in two plain-looking steps: a key on a superseded validator, then execute for it
        let r = open_calls(vec![kernel::install_validator_call(validator, &key(6), 3), grant(validator, execute, true)]);
        let t = r.text();
        assert_eq!(r.verdict, Verdict::Sign, "{t}");
        assert!(r.needs_second_confirmation());
        assert!(t.contains("! Install a key on a validator:") && t.contains("P256Validator v1 (superseded)"), "{t}");
        assert!(t.contains("to call: execute (0xe9ae5c53) — this key will be able to do anything with this account"), "{t}");
        // the grant alone
        let r = open_calls(vec![grant(validator, execute, true)]);
        assert!(r.verdict == Verdict::Sign && r.needs_second_confirmation(), "{}", r.text());
        // the recovery grant stays as it was
        assert!(open_calls(vec![grant(validator, change_root, true)]).text().contains("changeRootValidator (0x") );
        assert!(open_calls(vec![grant(validator, change_root, true)]).needs_second_confirmation());
        // a permission's execute is bounded by its policy: plain
        let r = open_calls(vec![grant(permission, execute, true)]);
        assert!(r.verdict == Verdict::Sign && !r.needs_second_confirmation(), "{}", r.text());
        // every other grant is refused: admin selectors to a permission or a validator, a selector nobody can name
        for (vid, selector) in [(permission, install), (permission, grant_sel), (permission, change_root), (permission, [0xde, 0xad, 0xbe, 0xef]), (validator, install), (validator, grant_sel)] {
            let r = open_calls(vec![grant(vid, selector, true)]);
            assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("no other grant")), "{:?}: {:?}", selector, r.verdict);
        }
        // taking access away is never a takeover
        for (vid, selector) in [(permission, execute), (validator, execute), (validator, change_root), (permission, install)] {
            let r = open_calls(vec![grant(vid, selector, false)]);
            assert!(r.verdict == Verdict::Sign && !r.needs_second_confirmation() && r.text().contains("Forbid"), "{}", r.text());
        }
        // expert mode turns the refusal into a bold row with a warning
        let mut expert = enrolled();
        expert[0].expert_mode = true;
        let r = open_as(vec![grant(permission, install, true)], &expert);
        assert!(matches!(r.verdict, Verdict::SignWithWarnings(_)) && r.needs_second_confirmation(), "{:?}", r.verdict);
        assert!(r.text().contains("nothing bounds what this grant"), "{}", r.text());
        // a signer module is readable as a signer only: in the policy's slot it is unknown
        let params = kernel::PolicyParams { targets: vec![], selectors: vec![], max_value_per_op: 0, budget: 0, valid_until: NOW + 1, tokens: vec![], valid_after: 0, payees: vec![] };
        let swapped = kernel::permission_data(SIGNER, &params, SIGNER, &key(2));
        let r = open_calls(vec![kernel::install_permission_calldata(perm, swapped, 1)]);
        assert!(matches!(r.verdict, Verdict::Refuse(ref m) if m.contains("policy module") && m.contains("not known to this build")), "{:?}", r.verdict);
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_800_000_000), "2027-01-15 08:00:00");
    }
}
