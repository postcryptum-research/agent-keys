//! ERC-4337 bundler RPC (v0.7): the alternative to bundling ourselves.
//!
//! A bundler takes the signed UserOperation over JSON-RPC, submits
//! `handleOps` from its own wallet and is paid from the account's (or the
//! paymaster's) EntryPoint deposit. It is untrusted infrastructure in our
//! model: it can delay or drop an operation, and it cannot change what the
//! operation calls or where its value goes, since the signature covers every
//! field. It does propose the gas figures the hardware signs, and
//! `preVerificationGas` and the fees are what pays it: a hostile bundler
//! would turn the account's gas budget into its own revenue (issue #148). So
//! its estimate is taken only up to [`FACTOR`] times the CLI's own, its fees
//! only up to [`FACTOR`] times the node's `maxFeePerGas`, and anything beyond
//! is refused before the hardware signs.
//!
//! The RPC carries the operation *unpacked*: `initCode` as `factory` +
//! `factoryData`, `accountGasLimits` as two limits, `paymasterAndData` as
//! four fields. Quantities are hex strings.

use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::sol_types::SolValue;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::abi::IEntryPoint::PackedUserOperation;

/// Split a packed `(hi, lo)` word: `accountGasLimits` into (verification,
/// call), `gasFees` into (maxPriorityFee, maxFee).
pub fn split_gas(word: B256) -> (u128, u128) {
    let b = word.0;
    (
        u128::from_be_bytes(b[..16].try_into().expect("16 bytes")),
        u128::from_be_bytes(b[16..].try_into().expect("16 bytes")),
    )
}

fn hi_lo(word: B256) -> (u128, u128) {
    split_gas(word)
}

/// How far a bundler's figures may go: each gas figure at most twice the
/// CLI's own, each fee at most twice the node's `maxFeePerGas` (which already
/// holds twice the base fee). Honest bundlers sit well inside: Pimlico's
/// estimates on Base Sepolia were under the CLI's own (`docs/SECURE_ENCLAVE.md`
/// §13), and its fees on Base Sepolia, Base, Ethereum and Arbitrum were
/// 0.67 to 0.82 times the node's `maxFeePerGas` (2026-11-25). Twice bounds what
/// a hostile one can take to a small multiple of an honest bill, where the
/// review measured 72 times with no bound.
pub const FACTOR: u128 = 2;

/// `theirs` if it is at most `ceiling`, refused otherwise. A value too wide
/// for 128 bits is above any ceiling: a refusal, never a panic (issue #150).
pub fn bounded(name: &str, theirs: U256, ceiling: u128, of: &str) -> Result<u128> {
    match u128::try_from(theirs) {
        Ok(v) if v <= ceiling => Ok(v),
        _ => bail!(
            "the bundler's {name} {theirs} is above {ceiling}, {FACTOR} times {of}: refusing to sign it \
             (docs/FAQ.md, \"Do I need a bundler or a gas wallet?\")"
        ),
    }
}

/// The most a bundler's `preVerificationGas` may be: [`FACTOR`] times the
/// larger of ours and what the operation's bytes cost a bundler on L1 — the
/// reference bundler's overheads (21000 per bundle, 18300 per operation, 4 per
/// word) with each byte at EIP-7623's floor rate (10 gas zero, 40 other), the
/// dearer of the two calldata schedules — so a large first operation is not
/// refused.
pub fn pre_verification_ceiling(op: &PackedUserOperation, ours: u128) -> u128 {
    // saturating: these are ceilings from our own figures, and the largest value is a right bound (rule 10)
    let packed = op.abi_encode();
    let bytes = packed.iter().fold(0u128, |sum, &b| sum.saturating_add(if b == 0 { 10 } else { 40 }));
    let words = u128::try_from(packed.len().div_ceil(32)).unwrap_or(u128::MAX);
    let l1 = 39_300u128.saturating_add(words.saturating_mul(4)).saturating_add(bytes); // 21000 + 18300
    FACTOR.saturating_mul(ours.max(l1))
}

/// Write a bundler's estimate into `op`, whose gas fields still hold the
/// CLI's own figures: each one is the bound for the bundler's. Refused, and
/// `op` left as it was, if any figure goes beyond its bound.
pub fn apply_estimate(op: &mut PackedUserOperation, est: &GasEstimate) -> Result<()> {
    const OURS: &str = "the CLI's own estimate";
    let (our_verification, our_call) = split_gas(op.accountGasLimits);
    let our_pre_verification = op.preVerificationGas.saturating_to::<u128>();
    let pre_verification = bounded(
        "preVerificationGas",
        est.pre_verification_gas,
        pre_verification_ceiling(op, our_pre_verification),
        "the larger of the CLI's own figure and the operation's calldata cost",
    )?;
    let verification =
        bounded("verificationGasLimit", est.verification_gas_limit, FACTOR.saturating_mul(our_verification), OURS)?;
    let call = bounded("callGasLimit", est.call_gas_limit, FACTOR.saturating_mul(our_call), OURS)?;
    let paymaster_and_data = if op.paymasterAndData.len() >= 52 {
        let pm = &op.paymasterAndData;
        let our_verification = u128::from_be_bytes(pm[20..36].try_into().expect("16 bytes"));
        let our_post_op = u128::from_be_bytes(pm[36..52].try_into().expect("16 bytes"));
        // Our paymaster runs no postOp (ours is 0, a bundler may say 1): its
        // two limits share one bound, twice the paymaster gas we set.
        let ceiling = FACTOR.saturating_mul(our_verification.saturating_add(our_post_op));
        let paymaster = |name, theirs: Option<U256>, ours| match theirs {
            Some(v) => bounded(name, v, ceiling, "the paymaster gas the CLI sets"),
            None => Ok(ours),
        };
        let verification =
            paymaster("paymasterVerificationGasLimit", est.paymaster_verification_gas_limit, our_verification)?;
        let post_op = paymaster("paymasterPostOpGasLimit", est.paymaster_post_op_gas_limit, our_post_op)?;
        let mut repacked = Vec::with_capacity(pm.len());
        repacked.extend_from_slice(&pm[..20]);
        repacked.extend_from_slice(&verification.to_be_bytes());
        repacked.extend_from_slice(&post_op.to_be_bytes());
        repacked.extend_from_slice(&pm[52..]);
        Some(Bytes::from(repacked))
    } else {
        None
    };
    op.accountGasLimits = crate::kernel::pack_gas(verification, call);
    op.preVerificationGas = U256::from(pre_verification);
    if let Some(pm) = paymaster_and_data {
        op.paymasterAndData = pm;
    }
    Ok(())
}

/// The floor a bundler names when it refuses an operation as underpriced,
/// e.g. Pimlico's `maxPriorityFeePerGas must be at least 1000000 (current
/// maxPriorityFeePerGas: 100000)`. Returns the floor in wei.
pub fn min_priority_fee_from_error(message: &str) -> Option<u128> {
    let idx = message.find("maxPriorityFeePerGas must be at least")?;
    let rest = &message[idx + "maxPriorityFeePerGas must be at least".len()..];
    let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// One tier of `pimlico_getUserOperationGasPrice`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasPrice {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

#[derive(Debug, Deserialize)]
struct GasPriceTiers {
    standard: GasPrice,
}

fn quantity(n: u128) -> Value {
    Value::String(format!("0x{n:x}"))
}

/// The v0.7 wire form of a packed operation.
pub fn to_rpc(op: &PackedUserOperation) -> Value {
    let (verification_gas, call_gas) = hi_lo(op.accountGasLimits);
    let (max_priority, max_fee) = hi_lo(op.gasFees);
    let mut v = json!({
        "sender": op.sender,
        "nonce": op.nonce,
        "callData": op.callData,
        "callGasLimit": quantity(call_gas),
        "verificationGasLimit": quantity(verification_gas),
        "preVerificationGas": op.preVerificationGas,
        "maxFeePerGas": quantity(max_fee),
        "maxPriorityFeePerGas": quantity(max_priority),
        "signature": op.signature,
    });
    if op.initCode.len() >= 20 {
        v["factory"] = json!(Address::from_slice(&op.initCode[..20]));
        v["factoryData"] = json!(Bytes::from(op.initCode[20..].to_vec()));
    }
    if op.paymasterAndData.len() >= 52 {
        let pm = &op.paymasterAndData;
        v["paymaster"] = json!(Address::from_slice(&pm[..20]));
        v["paymasterVerificationGasLimit"] =
            quantity(u128::from_be_bytes(pm[20..36].try_into().expect("16 bytes")));
        v["paymasterPostOpGasLimit"] = quantity(u128::from_be_bytes(pm[36..52].try_into().expect("16 bytes")));
        v["paymasterData"] = json!(Bytes::from(pm[52..].to_vec()));
    }
    v
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    pub pre_verification_gas: U256,
    pub verification_gas_limit: U256,
    pub call_gas_limit: U256,
    #[serde(default)]
    pub paymaster_verification_gas_limit: Option<U256>,
    #[serde(default)]
    pub paymaster_post_op_gas_limit: Option<U256>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOpReceipt {
    pub success: bool,
    pub actual_gas_used: U256,
    #[serde(default)]
    pub reason: Option<String>,
    pub receipt: InnerReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InnerReceipt {
    pub transaction_hash: B256,
    pub block_number: U256,
}

pub struct Bundler {
    rpc: DynProvider,
    entry_point: Address,
}

impl Bundler {
    pub fn new(rpc: DynProvider, entry_point: Address) -> Self {
        Self { rpc, entry_point }
    }

    /// Refuse early if the bundler does not serve our EntryPoint.
    pub async fn check_entry_point(&self) -> Result<()> {
        // `()` would serialize to `null`; bundlers want an (empty) array.
        let supported: Vec<Address> = self
            .rpc
            .raw_request("eth_supportedEntryPoints".into(), json!([]))
            .await
            .context("eth_supportedEntryPoints")?;
        if !supported.contains(&self.entry_point) {
            bail!("bundler does not support EntryPoint {}; it offers {supported:?}", self.entry_point);
        }
        Ok(())
    }

    /// The bundler's own gas prices, when it publishes them
    /// (`pimlico_getUserOperationGasPrice`): the only way to know the floor
    /// it will enforce at `eth_sendUserOperation`. `None` when the method is
    /// not offered; the caller falls back to the node's estimate.
    pub async fn gas_price(&self) -> Option<GasPrice> {
        let tiers: Result<GasPriceTiers, _> =
            self.rpc.raw_request("pimlico_getUserOperationGasPrice".into(), json!([])).await;
        tiers.ok().map(|t| t.standard)
    }

    /// Apply the bundler's gas estimate to `op`, within the bounds of
    /// [`apply_estimate`]. The operation carries a placeholder signature of
    /// the real one's length: bundlers simulate without checking it, and the
    /// hash covers the gas fields, so the hardware signs once, after this.
    pub async fn estimate(&self, op: &mut PackedUserOperation) -> Result<GasEstimate> {
        let est: GasEstimate = self
            .rpc
            .raw_request("eth_estimateUserOperationGas".into(), (to_rpc(op), self.entry_point))
            .await
            .context("eth_estimateUserOperationGas")?;
        apply_estimate(op, &est)?;
        Ok(est)
    }

    /// Submit and return the bundler's userOpHash.
    pub async fn send(&self, op: &PackedUserOperation) -> Result<B256> {
        self.rpc
            .raw_request("eth_sendUserOperation".into(), (to_rpc(op), self.entry_point))
            .await
            .context("eth_sendUserOperation")
    }

    /// Whether a refusal came from the bundler's priority-fee floor, and
    /// what the floor is.
    pub fn fee_floor(error: &anyhow::Error) -> Option<u128> {
        min_priority_fee_from_error(&format!("{error:#}"))
    }

    /// Poll until the operation is included (or `timeout` passes).
    pub async fn wait(&self, user_op_hash: B256, timeout: Duration) -> Result<UserOpReceipt> {
        let started = std::time::Instant::now();
        loop {
            let receipt: Option<UserOpReceipt> = self
                .rpc
                .raw_request("eth_getUserOperationReceipt".into(), (user_op_hash,))
                .await
                .context("eth_getUserOperationReceipt")?;
            if let Some(r) = receipt {
                return Ok(r);
            }
            if started.elapsed() > timeout {
                bail!("operation {user_op_hash} not included within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pimlico_fee_floor() {
        let msg = "eth_sendUserOperation\n\nCaused by:\n    server returned an error response: error code -32602: \
                   maxPriorityFeePerGas must be at least 1000000 (current maxPriorityFeePerGas: 100000) - use \
                   pimlico_getUserOperationGasPrice to get the current gas price";
        assert_eq!(min_priority_fee_from_error(msg), Some(1_000_000));
        assert_eq!(min_priority_fee_from_error("AA24 signature error"), None);
        assert_eq!(min_priority_fee_from_error("maxPriorityFeePerGas must be at least"), None);
    }

    #[test]
    fn gas_price_tiers_parse() {
        let v: GasPriceTiers = serde_json::from_value(json!({
            "slow": {"maxFeePerGas": "0x829b42b5", "maxPriorityFeePerGas": "0x829b42b5"},
            "standard": {"maxFeePerGas": "0x88d36a75", "maxPriorityFeePerGas": "0xf4240"},
            "fast": {"maxFeePerGas": "0x8f0b9234", "maxPriorityFeePerGas": "0x8f0b9234"}
        }))
        .unwrap();
        assert_eq!(v.standard.max_priority_fee_per_gas, U256::from(1_000_000u64));
        assert_eq!(v.standard.max_fee_per_gas, U256::from(0x88d36a75u64));
    }

    /// A sponsored operation for a deployed account as the CLI builds it:
    /// verification 300000, call 150000, preVerification 100000, paymaster
    /// verification 100000 and no postOp, a 65-byte placeholder signature.
    fn ours(init_code: usize) -> PackedUserOperation {
        let mut pm = vec![0x05u8; 20];
        pm.extend_from_slice(&100_000u128.to_be_bytes());
        pm.extend_from_slice(&0u128.to_be_bytes());
        PackedUserOperation {
            sender: Address::repeat_byte(0xd6),
            nonce: U256::from(7u64),
            initCode: Bytes::from(vec![0xabu8; init_code]),
            callData: Bytes::from(vec![0xe9u8; 228]),
            accountGasLimits: crate::kernel::pack_gas(300_000, 150_000),
            preVerificationGas: U256::from(100_000u64),
            gasFees: crate::kernel::pack_gas(1_000_000, 11_000_000),
            paymasterAndData: Bytes::from(pm),
            signature: Bytes::from(vec![0xffu8; 65]),
        }
    }

    /// Pimlico's answer for such an operation on Base Sepolia (the sponsored
    /// run of `docs/SECURE_ENCLAVE.md` §13, read back from its transaction).
    fn honest() -> GasEstimate {
        GasEstimate {
            pre_verification_gas: U256::from(49_175u64),
            verification_gas_limit: U256::from(109_000u64),
            call_gas_limit: U256::from(17_955u64),
            paymaster_verification_gas_limit: Some(U256::from(24_484u64)),
            paymaster_post_op_gas_limit: Some(U256::from(1u64)),
        }
    }

    fn paymaster_limits(op: &PackedUserOperation) -> (u128, u128) {
        let pm = &op.paymasterAndData;
        (u128::from_be_bytes(pm[20..36].try_into().unwrap()), u128::from_be_bytes(pm[36..52].try_into().unwrap()))
    }

    #[test]
    fn an_honest_estimate_is_taken_as_given() {
        let mut op = ours(0);
        apply_estimate(&mut op, &honest()).unwrap();
        assert_eq!(split_gas(op.accountGasLimits), (109_000, 17_955));
        assert_eq!(op.preVerificationGas, U256::from(49_175u64));
        assert_eq!(paymaster_limits(&op), (24_484, 1));
        assert_eq!(op.paymasterAndData[..20], [0x05u8; 20]);

        // up to twice ours, each figure, is still taken
        let mut op = ours(0);
        let est = GasEstimate {
            pre_verification_gas: U256::from(200_000u64),
            verification_gas_limit: U256::from(600_000u64),
            call_gas_limit: U256::from(300_000u64),
            paymaster_verification_gas_limit: Some(U256::from(200_000u64)),
            paymaster_post_op_gas_limit: None,
        };
        apply_estimate(&mut op, &est).unwrap();
        assert_eq!(split_gas(op.accountGasLimits), (600_000, 300_000));
        assert_eq!(paymaster_limits(&op), (200_000, 0));
    }

    #[test]
    fn a_figure_beyond_twice_ours_is_refused_and_nothing_changes() {
        let inflate: [(&str, fn(&mut GasEstimate)); 5] = [
            // the review's figure: a 72-fold bill
            ("preVerificationGas 50000000", |e| e.pre_verification_gas = U256::from(50_000_000u64)),
            ("preVerificationGas 200001", |e| e.pre_verification_gas = U256::from(200_001u64)),
            ("verificationGasLimit 600001", |e| e.verification_gas_limit = U256::from(600_001u64)),
            ("callGasLimit 300001", |e| e.call_gas_limit = U256::from(300_001u64)),
            ("paymasterPostOpGasLimit 200001", |e| e.paymaster_post_op_gas_limit = Some(U256::from(200_001u64))),
        ];
        for (named, f) in inflate {
            let mut est = honest();
            f(&mut est);
            let mut op = ours(0);
            let before = op.clone();
            let err = apply_estimate(&mut op, &est).unwrap_err().to_string();
            assert!(err.contains(&format!("the bundler's {named} is above")), "{err}");
            assert!(err.contains("refusing to sign it"), "{err}");
            assert_eq!(op.abi_encode(), before.abi_encode());
        }
    }

    #[test]
    fn a_quantity_wider_than_128_bits_is_refused_not_a_panic() {
        let wide = U256::from(1u8) << 128;
        let oversize: [fn(&mut GasEstimate, U256); 5] = [
            |e, v| e.pre_verification_gas = v,
            |e, v| e.verification_gas_limit = v,
            |e, v| e.call_gas_limit = v,
            |e, v| e.paymaster_verification_gas_limit = Some(v),
            |e, v| e.paymaster_post_op_gas_limit = Some(v),
        ];
        for f in oversize {
            for v in [wide, U256::MAX] {
                let mut est = honest();
                f(&mut est, v);
                let err = apply_estimate(&mut ours(0), &est).unwrap_err().to_string();
                assert!(err.contains(&v.to_string()), "{err}");
            }
        }
        // the same check bounds the fees against the node's
        let fee = |v| bounded("maxFeePerGas", v, 2 * 11_000_000, "the node's maxFeePerGas");
        assert_eq!(fee(U256::from(7_350_000u64)).unwrap(), 7_350_000); // Pimlico's on Base Sepolia
        assert!(fee(U256::from(22_000_001u64)).is_err());
        assert!(fee(wide).is_err());
    }

    #[test]
    fn a_large_first_operation_raises_the_pre_verification_ceiling() {
        // a small operation: our own figure is the larger one
        assert_eq!(pre_verification_ceiling(&ours(0), 100_000), 200_000);
        // 8 KiB of factory data costs a bundler more than 100000 on L1
        let big = ours(8192);
        let ceiling = pre_verification_ceiling(&big, 100_000);
        assert!(ceiling > 2 * (39_300 + 40 * 8192), "{ceiling}");
        let mut est = honest();
        est.pre_verification_gas = U256::from(400_000u64);
        apply_estimate(&mut big.clone(), &est).unwrap();
        assert!(apply_estimate(&mut ours(0), &est).is_err());
    }
}
