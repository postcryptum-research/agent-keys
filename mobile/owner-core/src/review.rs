//! What the phone shows, and what it refuses (docs/MOBILE_OWNER_DESIGN.md
//! §6): one parse of a sign request into a [`Review`] — the verdict, the
//! sections the screen renders, and the digest to sign, all from the same
//! object, so nothing is signed that was not shown. The native side renders
//! `sections` generically; every word comes from here.
//!
//! Facts come from the caller: which accounts this phone is enrolled for,
//! and which contracts the build knows (§6.7). Nothing here touches the
//! network.

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
}

impl EnrolledAccount {
    pub fn new(chain_id: u64, entry_point: Address, account: Address) -> Self {
        Self { chain_id, entry_point, account, validator: None, gas_cap_wei: DEFAULT_GAS_CAP_WEI, expert_mode: false }
    }
}

/// What the build knows (§6.7): names for the project's contracts, the
/// paymasters known to charge nothing, the recovery validators. Slice 1
/// takes them from the caller; the build-embedded table follows.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub names: BTreeMap<Address, String>,
    /// Paymasters without a `postOp` (§6.4): the only ones accepted.
    pub sponsoring_paymasters: Vec<Address>,
    pub recovery_validators: Vec<Address>,
}

impl Facts {
    fn name(&self, a: Address) -> String {
        match self.names.get(&a) {
            Some(n) => format!("{} — {n} (verified in this build)", a.to_checksum(None)),
            None => a.to_checksum(None),
        }
    }
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
        let mut out = String::new();
        for s in &self.sections {
            out.push_str(&format!("## {}\n", s.title));
            for r in &s.rows {
                out.push_str(&format!("{}{}: {}\n", if r.emphasis { "! " } else { "" }, r.label, r.value));
            }
        }
        out
    }

    fn refused(request_commitment: String, sections: Vec<Section>, why: impl Into<String>) -> Self {
        Self { verdict: Verdict::Refuse(why.into()), sections, request_commitment, digest: None }
    }
}

struct Builder<'a> {
    facts: &'a Facts,
    sections: Vec<Section>,
    warnings: Vec<String>,
}

impl Builder<'_> {
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
    let chain_id = req.chain_id().unwrap_or(0);
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
    if !op.init_code.is_empty() {
        return Review::refused(c, vec![], "the operation carries initCode; v1 signs for existing accounts only");
    }
    if op.nonce >> 64 != U256::ZERO {
        return Review::refused(c, vec![], "the nonce key is not the root key; this phone signs root operations only");
    }
    // 6: the recomputed hash equals the laptop's hint — SignRequest::parse checked it
    let digest = req.laptop.user_op_hash;

    let mut b = Builder { facts, sections: Vec::new(), warnings: Vec::new() };
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
            self_call(&mut b, s, data, acct, &installed_keys)
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
        b.row(s, "Gas", format!("sponsored by {}", facts.name(pm)));
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
    Review { verdict, sections: b.sections, request_commitment: c, digest: Some(digest) }
}

/// §6.3 top level: `execute` (single or batch, default exec type) or a direct
/// `uninstallValidation`. Returns the inner calls as (target, value, data).
fn top_level(call_data: &[u8], account: Address) -> Result<Vec<(Address, U256, Bytes)>, String> {
    if call_data.len() < 4 {
        return Err("callData has no selector".into());
    }
    let selector: [u8; 4] = call_data[..4].try_into().expect("4");
    if selector == IKernel::executeCall::SELECTOR {
        let exec = IKernel::executeCall::abi_decode(call_data).map_err(|e| format!("execute: {e}"))?;
        let mode = exec.execMode.0;
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
                let executions = Vec::<IKernel::Execution>::abi_decode(&exec.executionCalldata)
                    .map_err(|e| format!("batch executions: {e}"))?;
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
        if let Ok(c) = IKernel::installValidationsCall::abi_decode(data) {
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
    if selector == IKernel::installValidationsCall::SELECTOR {
        let c = IKernel::installValidationsCall::abi_decode(data).map_err(|e| format!("installValidations: {e}"))?;
        if c.vIds.len() != c.configs.len() || c.vIds.len() != c.validationData.len() {
            return Err("installValidations with mismatched arrays; refused".into());
        }
        for ((vid, cfg), vdata) in c.vIds.iter().zip(&c.configs).zip(&c.validationData) {
            match vid.0[0] {
                VALIDATION_TYPE_PERMISSION => {
                    let id = FixedBytes::<4>::from_slice(&vid.0[1..5]);
                    b.row(s, "Install agent permission", format!("0x{}", hex(id.as_slice())));
                    permission_rows(b, s, vdata)?;
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
                        b.row(s, "Recovery validator", b.facts.name(v));
                    } else {
                        b.row(s, "Install validator", b.facts.name(v));
                        b.row(s, "With key", fingerprint(&pk));
                    }
                    b.row(s, "Validation nonce", cfg.nonce.to_string());
                }
                other => return Err(format!("installValidations of validation type 0x{other:02x}; refused")),
            }
        }
        Ok(())
    } else if selector == IKernel::grantAccessCall::SELECTOR {
        let c = IKernel::grantAccessCall::abi_decode(data).map_err(|e| format!("grantAccess: {e}"))?;
        let who = vid_text(c.vId);
        let what = selector_name(c.selector.0);
        let verb = if c.allow { "Allow" } else { "Forbid" };
        if c.selector.0 == IKernel::changeRootValidatorCall::SELECTOR {
            b.bold(s, format!("{verb} {who} to call"), format!("{what} — may take over this account"));
        } else {
            b.row(s, format!("{verb} {who} to call"), what);
        }
        Ok(())
    } else if selector == IKernel::changeRootValidatorCall::SELECTOR {
        let c = IKernel::changeRootValidatorCall::abi_decode(data).map_err(|e| format!("changeRootValidator: {e}"))?;
        if c.rootValidator.0[0] != VALIDATION_TYPE_VALIDATOR {
            return Err("changeRootValidator to a non-validator id; refused".into());
        }
        let v = Address::from_slice(&c.rootValidator.0[1..21]);
        let key = decode_pubkey(&c.validatorData).or_else(|| installed_keys.get(&c.rootValidator).copied());
        match key {
            Some(pk) => b.bold(s, "Hand control of this account to key", fingerprint(&pk)),
            None => b.bold(s, "Hand control of this account to validator", b.facts.name(v)),
        }
        b.row(s, "Root validator", b.facts.name(v));
        Ok(())
    } else if selector == IKernel::uninstallValidationCall::SELECTOR {
        let c = IKernel::uninstallValidationCall::abi_decode(data).map_err(|e| format!("uninstallValidation: {e}"))?;
        match c.vId.0[0] {
            VALIDATION_TYPE_PERMISSION => {
                b.row(s, "Remove permission", format!("0x{}", hex(&c.vId.0[1..5])));
            }
            VALIDATION_TYPE_VALIDATOR => {
                let v = Address::from_slice(&c.vId.0[1..21]);
                if acct.validator == Some(v) {
                    b.bold(s, "Remove validator", format!("{} — this phone will no longer control the account", b.facts.name(v)));
                } else {
                    b.row(s, "Remove validator", b.facts.name(v));
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
fn permission_rows(b: &mut Builder<'_>, s: usize, vdata: &[u8]) -> Result<(), String> {
    let entries = Vec::<Bytes>::abi_decode(vdata).map_err(|e| format!("permission data: {e}"))?;
    if entries.len() < 2 {
        return Err("permission data without a policy and a signer; refused".into());
    }
    let (signer, policies) = entries.split_last().expect("at least two");
    for p in policies {
        if p.len() < 22 {
            return Err("a policy entry shorter than flag ‖ module; refused".into());
        }
        let module = Address::from_slice(&p[2..22]);
        b.row(s, "Policy module", b.facts.name(module));
        if !b.facts.names.contains_key(&module) {
            b.warnings.push(format!("policy module {} is not known to this build", module.to_checksum(None)));
        }
        type PolicyInit = (Vec<Address>, Vec<FixedBytes<4>>, U256, U256, U256, Vec<(Address, U256, U256, B256)>, U256);
        let (targets, selectors, max_value, budget, until, tokens, after) =
            PolicyInit::abi_decode_params(&p[22..]).map_err(|e| format!("policy parameters: {e}"))?;
        if targets.len() != selectors.len() {
            return Err("policy targets and selectors differ in length; refused".into());
        }
        for (t, sel) in targets.iter().zip(&selectors) {
            b.row(s, "Allow", format!("{} · {}", b.facts.name(*t), selector_name(sel.0)));
        }
        b.row(s, "Max value per operation", format!("{} ETH", format_ether(max_value)));
        b.row(s, "Budget", format!("{} ETH", format_ether(budget)));
        b.row(s, "Valid from", if after.is_zero() { "now".to_string() } else { format!("{} UTC ({after})", utc(after.to::<u64>())) });
        b.row(s, "Valid until", format!("{} UTC ({until})", utc(until.saturating_to::<u64>())));
        for (token, max, budget, domain) in &tokens {
            b.row(
                s,
                "Token cap",
                format!(
                    "{}: max {max} per operation, budget {budget} (raw units, unverified decimals){}",
                    b.facts.name(*token),
                    if domain.is_zero() { "" } else { ", x402 payments allowed" }
                ),
            );
        }
    }
    if signer.len() < 22 {
        return Err("a signer entry shorter than flag ‖ module; refused".into());
    }
    let module = Address::from_slice(&signer[2..22]);
    b.row(s, "Signer module", b.facts.name(module));
    if !b.facts.names.contains_key(&module) {
        b.warnings.push(format!("signer module {} is not known to this build", module.to_checksum(None)));
    }
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
    let mut to = b.facts.name(target);
    if let Some(l) = labels.get(&target) {
        to.push_str(&format!(" \"{l}\" (from the laptop — unverified)"));
    }
    b.row(s, "To", to);
    if !value.is_zero() {
        b.row(s, "Send", format!("{} ETH", format_ether(value)));
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
    if selector == SELECTOR_INCREMENT && data.len() == 4 {
        b.row(s, "Call", "increment()");
        return Ok(());
    }
    if (selector == SELECTOR_ERC20_TRANSFER || selector == SELECTOR_ERC20_APPROVE) && data.len() == 68 {
        let who = Address::from_slice(&data[16..36]);
        let amount = U256::from_be_slice(&data[36..68]);
        let what = if selector == SELECTOR_ERC20_TRANSFER { "transfer" } else { "approve" };
        b.row(
            s,
            "Call",
            format!("ERC-20 {what}({}, {amount}) — raw units, unverified decimals", who.to_checksum(None)),
        );
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
fn clean_label(l: &str) -> Option<String> {
    let ok = !l.is_empty() && l.len() <= 32 && l.bytes().all(|b| (0x20..=0x7e).contains(&b));
    ok.then(|| l.to_string())
}

/// Wei as ETH, without trailing zeros: `0.00102 ETH`, `1 ETH`.
fn format_ether(wei: U256) -> String {
    let s = alloy_primitives::utils::format_ether(wei);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() { "0".into() } else { s.to_string() }
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
        let p = sk.verifying_key().to_encoded_point(false);
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
        Facts { names, sponsoring_paymasters: vec![PAYMASTER], recovery_validators: vec![RECOVERY] }
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
            valid_after: 0,
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
        let golden = {
            let me = ACCOUNT;
            let mut o = op(kernel::execute_batch_calldata(vec![
                (COUNTER, U256::from(5), Bytes::copy_from_slice(&SELECTOR_INCREMENT)),
                (me, U256::ZERO, kernel::change_root_calldata(RECOVERY, None)),
            ]));
            o.gas_fees = kernel::pack_gas(1, 1);
            o
        };
        let base = open(&golden);
        assert_eq!(base.verdict, Verdict::Sign, "{}", base.text());
        let base_text = base.text();
        let base_hash = base.digest_to_sign().unwrap();
        let check = |what: &str, o: &PackedUserOp| {
            let r = open(o);
            let hash = crate::user_op::user_op_hash(o, ENTRY, 31337);
            assert_ne!(hash, base_hash, "{what}: the mutation did not change the hash");
            if r.verdict != Verdict::Sign && !matches!(r.verdict, Verdict::SignWithWarnings(_)) {
                return; // refused is fine
            }
            assert_ne!(r.text(), base_text, "{what}: the hash changed but the screen did not");
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
        // every byte of the calldata
        for i in 0..golden.call_data.len() {
            let mut cd = golden.call_data.to_vec();
            cd[i] ^= 0x01;
            let mut o = golden.clone();
            o.call_data = cd.into();
            check(&format!("callData byte {i}"), &o);
        }
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_800_000_000), "2027-01-15 08:00:00");
    }
}
