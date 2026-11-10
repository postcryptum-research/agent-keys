//! ERC-4337 bundler RPC (v0.7): the alternative to bundling ourselves.
//!
//! A bundler takes the signed UserOperation over JSON-RPC, submits
//! `handleOps` from its own wallet and is paid from the account's (or the
//! paymaster's) EntryPoint deposit. It is untrusted infrastructure in our
//! model: it can delay or drop an operation, it cannot forge or redirect one.
//!
//! The RPC carries the operation *unpacked*: `initCode` as `factory` +
//! `factoryData`, `accountGasLimits` as two limits, `paymasterAndData` as
//! four fields. Quantities are hex strings.

use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider};
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

    /// Apply the bundler's gas estimate to `op`. The operation carries a
    /// placeholder signature of the real one's length: bundlers simulate
    /// without checking it, and the hash covers the gas fields, so the
    /// hardware signs once, after this.
    pub async fn estimate(&self, op: &mut PackedUserOperation) -> Result<GasEstimate> {
        let est: GasEstimate = self
            .rpc
            .raw_request("eth_estimateUserOperationGas".into(), (to_rpc(op), self.entry_point))
            .await
            .context("eth_estimateUserOperationGas")?;
        op.accountGasLimits =
            crate::kernel::pack_gas(est.verification_gas_limit.to::<u128>(), est.call_gas_limit.to::<u128>());
        op.preVerificationGas = est.pre_verification_gas;
        if op.paymasterAndData.len() >= 52 {
            let pm = op.paymasterAndData.to_vec();
            let verification = est.paymaster_verification_gas_limit.map(|v| v.to::<u128>()).unwrap_or_else(|| {
                u128::from_be_bytes(pm[20..36].try_into().expect("16 bytes"))
            });
            let post_op = est.paymaster_post_op_gas_limit.map(|v| v.to::<u128>()).unwrap_or_else(|| {
                u128::from_be_bytes(pm[36..52].try_into().expect("16 bytes"))
            });
            let mut repacked = Vec::with_capacity(pm.len());
            repacked.extend_from_slice(&pm[..20]);
            repacked.extend_from_slice(&verification.to_be_bytes());
            repacked.extend_from_slice(&post_op.to_be_bytes());
            repacked.extend_from_slice(&pm[52..]);
            op.paymasterAndData = Bytes::from(repacked);
        }
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
}
