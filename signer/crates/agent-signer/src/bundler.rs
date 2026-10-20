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

fn hi_lo(word: B256) -> (u128, u128) {
    let b = word.0;
    (
        u128::from_be_bytes(b[..16].try_into().expect("16 bytes")),
        u128::from_be_bytes(b[16..].try_into().expect("16 bytes")),
    )
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

    /// Apply the bundler's gas estimate to `op`. The operation must carry a
    /// signature that validates, since the bundler simulates it; the caller
    /// re-signs afterwards because the hash covers the gas fields.
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
