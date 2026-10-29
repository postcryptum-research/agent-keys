//! The ERC-4337 v0.7 `userOpHash`, computed locally. The phone recomputes
//! it from the operation it was shown (docs/MOBILE_OWNER_DESIGN.md §6.2),
//! and the CLI checks its own value against `EntryPoint.getUserOpHash` on
//! every operation (§8.3), so the formula is tested against the chain on
//! every run of the anvil suite.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;

/// The fields of a `PackedUserOperation` that the hash covers — everything
/// but the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedUserOp {
    pub sender: Address,
    pub nonce: U256,
    pub init_code: Bytes,
    pub call_data: Bytes,
    pub account_gas_limits: B256,
    pub pre_verification_gas: U256,
    pub gas_fees: B256,
    pub paymaster_and_data: Bytes,
}

/// `keccak256(abi.encode(keccak256(pack(op)), entryPoint, chainId))`, where
/// `pack(op)` is `abi.encode(sender, nonce, keccak256(initCode),
/// keccak256(callData), accountGasLimits, preVerificationGas, gasFees,
/// keccak256(paymasterAndData))` — EntryPoint v0.7's `UserOperationLib`.
pub fn user_op_hash(op: &PackedUserOp, entry_point: Address, chain_id: u64) -> B256 {
    let packed = (
        op.sender,
        op.nonce,
        keccak256(&op.init_code),
        keccak256(&op.call_data),
        op.account_gas_limits,
        op.pre_verification_gas,
        op.gas_fees,
        keccak256(&op.paymaster_and_data),
    )
        .abi_encode_params();
    keccak256((keccak256(packed), entry_point, U256::from(chain_id)).abi_encode_params())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, hex};

    // Reference values computed independently with `cast abi-encode` and
    // `cast keccak` (2026-10-29) for this operation.
    fn op() -> PackedUserOp {
        PackedUserOp {
            sender: address!("1111111111111111111111111111111111111111"),
            nonce: U256::from(0x10),
            init_code: Bytes::new(),
            call_data: Bytes::from(hex!("d09de08a")),
            account_gas_limits: b256!("00000000000000000000000000049d4000000000000000000000000000007530"),
            pre_verification_gas: U256::from(100_000),
            gas_fees: b256!("000000000000000000000000000f424000000000000000000000000005f5e100"),
            paymaster_and_data: Bytes::new(),
        }
    }
    const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

    #[test]
    fn matches_cast_on_two_chains() {
        assert_eq!(
            user_op_hash(&op(), ENTRY_POINT, 84532),
            b256!("245bc355436dba4c60b81598339e5e8e45a3f9a63ed3ac00e7b22c3fa7f87dbb")
        );
        assert_eq!(
            user_op_hash(&op(), ENTRY_POINT, 31337),
            b256!("48e286b71f896beef7a0b4d23fd82d6afae60a64e7976118de492a2fba4c1947")
        );
    }

    #[test]
    fn every_field_changes_the_hash() {
        let base = user_op_hash(&op(), ENTRY_POINT, 84532);
        let mut variants = Vec::new();
        let mut o = op(); o.sender = address!("2222222222222222222222222222222222222222"); variants.push(o);
        let mut o = op(); o.nonce = U256::from(0x11); variants.push(o);
        let mut o = op(); o.init_code = Bytes::from(vec![1]); variants.push(o);
        let mut o = op(); o.call_data = Bytes::from(hex!("d09de08b")); variants.push(o);
        // swap verification / call gas limits: same sum, different hash
        let mut o = op(); o.account_gas_limits = b256!("00000000000000000000000000007530000000000000000000000000000049d4"); variants.push(o);
        let mut o = op(); o.pre_verification_gas = U256::from(100_001); variants.push(o);
        let mut o = op(); o.gas_fees = b256!("000000000000000000000000000f424100000000000000000000000005f5e100"); variants.push(o);
        let mut o = op(); o.paymaster_and_data = Bytes::from(vec![0]); variants.push(o);
        for v in &variants {
            assert_ne!(user_op_hash(v, ENTRY_POINT, 84532), base);
        }
        assert_ne!(user_op_hash(&op(), address!("0000000000000000000000000000000000000001"), 84532), base);
    }
}
