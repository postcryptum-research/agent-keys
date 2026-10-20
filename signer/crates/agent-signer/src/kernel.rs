//! Byte-exact encodings for a Kernel v3.3 account owned by hardware keys.
//! Every layout here is the one exercised by `contracts/test/*.t.sol`.

use alloy::primitives::{aliases::U192, Address, Bytes, FixedBytes, B256, U256};
use alloy::sol_types::{SolCall, SolValue};
use hw_signer::{PublicKey, Signature};

use crate::abi::{IKernel, IKernelFactory};

pub type ValidationId = FixedBytes<21>;
pub type PermissionId = FixedBytes<4>;

const VALIDATION_TYPE_VALIDATOR: u8 = 0x01;
const VALIDATION_TYPE_PERMISSION: u8 = 0x02;

/// `0x01 ‖ validator address`
pub fn validator_id(validator: Address) -> ValidationId {
    let mut b = [0u8; 21];
    b[0] = VALIDATION_TYPE_VALIDATOR;
    b[1..].copy_from_slice(validator.as_slice());
    ValidationId::from(b)
}

/// `0x02 ‖ permission id ‖ 0×16` — the id must be a clean 4-byte value.
pub fn permission_vid(id: PermissionId) -> ValidationId {
    let mut b = [0u8; 21];
    b[0] = VALIDATION_TYPE_PERMISSION;
    b[1..5].copy_from_slice(id.as_slice());
    ValidationId::from(b)
}

/// EntryPoint nonce key (uint192): `mode ‖ vType ‖ vIdWithoutType(20) ‖ nonceKey(2)`.
pub fn permission_nonce_key(id: PermissionId) -> U192 {
    let mut b = [0u8; 24];
    b[1] = VALIDATION_TYPE_PERMISSION;
    b[2..6].copy_from_slice(id.as_slice());
    U192::from_be_slice(&b)
}

/// Key 0 routes to the root validator.
pub fn root_nonce_key() -> U192 {
    U192::ZERO
}

/// `abi.encode(bytes32 x, bytes32 y)` — what both P256 modules expect on install.
pub fn encode_pubkey(pk: &PublicKey) -> Bytes {
    (B256::from(pk.x), B256::from(pk.y)).abi_encode().into()
}

pub struct PolicyParams {
    pub targets: Vec<Address>,
    pub selectors: Vec<FixedBytes<4>>,
    pub max_value_per_op: u128,
    pub budget: u128,
    pub valid_until: u64,
}

/// Kernel's `PermissionEnableDataFormat`: `abi.encode(bytes[] entries)` where
/// each entry is `flag(2) ‖ module(20) ‖ initData`; policies first, signer last.
/// The numeric policy fields are encoded as full words, which is byte-identical
/// to `abi.encode(uint128, uint128, uint48)` for in-range values.
pub fn permission_data(
    policy: Address,
    params: &PolicyParams,
    signer: Address,
    agent_key: &PublicKey,
) -> Bytes {
    // `abi.encode(targets, selectors, max, budget, until)`: a parameter
    // sequence, not one tuple value — `abi_encode()` on a dynamic tuple would
    // prepend an offset word and the policy's `abi.decode` would reject it.
    let policy_init = (
        params.targets.clone(),
        params.selectors.clone(),
        U256::from(params.max_value_per_op),
        U256::from(params.budget),
        U256::from(params.valid_until),
    )
        .abi_encode_params();
    let flag = FixedBytes::<2>::ZERO;
    let entries: Vec<Bytes> = vec![
        (flag, policy, Bytes::from(policy_init)).abi_encode_packed().into(),
        (flag, signer, encode_pubkey(agent_key)).abi_encode_packed().into(),
    ];
    entries.abi_encode().into()
}

/// `Kernel.initialize(...)` calldata: the owner key as root, the agent
/// permission installed and granted `execute` through `initConfig`.
pub fn init_data(
    validator: Address,
    owner_key: &PublicKey,
    perm: PermissionId,
    permission_data: Bytes,
) -> Bytes {
    let install = IKernel::installValidationsCall {
        vIds: vec![permission_vid(perm)],
        configs: vec![IKernel::ValidationConfig { nonce: 1, hook: Address::with_last_byte(1) }],
        validationData: vec![permission_data],
        hookData: vec![Bytes::new()],
    }
    .abi_encode();
    let grant = IKernel::grantAccessCall {
        vId: permission_vid(perm),
        selector: FixedBytes::from(IKernel::executeCall::SELECTOR),
        allow: true,
    }
    .abi_encode();
    IKernel::initializeCall {
        rootValidator: validator_id(validator),
        hook: Address::ZERO,
        validatorData: encode_pubkey(owner_key),
        hookData: Bytes::new(),
        initConfig: vec![install.into(), grant.into()],
    }
    .abi_encode()
    .into()
}

/// ERC-4337 `initCode`: `factory ‖ createAccount(initData, salt)`.
pub fn init_code(factory: Address, init_data: &Bytes, salt: B256) -> Bytes {
    let call = IKernelFactory::createAccountCall { data: init_data.clone(), salt }.abi_encode();
    [factory.as_slice(), &call].concat().into()
}

/// `execute(single/default, target ‖ value ‖ data)`.
pub fn execute_calldata(target: Address, value: U256, data: &[u8]) -> Bytes {
    let exec = [target.as_slice(), &value.to_be_bytes::<32>(), data].concat();
    IKernel::executeCall { execMode: B256::ZERO, executionCalldata: exec.into() }
        .abi_encode()
        .into()
}

/// `accountGasLimits` / `gasFees` packing: high 16 bytes ‖ low 16 bytes.
pub fn pack_gas(high: u128, low: u128) -> B256 {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&high.to_be_bytes());
    b[16..].copy_from_slice(&low.to_be_bytes());
    B256::from(b)
}

/// Permission path: no policy segments, `0xff` introduces the signer bytes.
pub fn permission_signature(sig: &Signature) -> Bytes {
    [&[0xffu8][..], &sig.r, &sig.s].concat().into()
}

/// Root path: the bare pair.
pub fn root_signature(sig: &Signature) -> Bytes {
    [&sig.r[..], &sig.s[..]].concat().into()
}
