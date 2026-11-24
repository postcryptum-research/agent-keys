// SPDX-License-Identifier: Apache-2.0
// Moved from signer/crates/agent-signer (Apache-2.0); the licence of the rest
// of this crate is not decided yet — see README.md.
//! Byte-exact encodings for a Kernel v3.3 account owned by hardware keys.
//! Every layout here is the one exercised by `contracts/test/*.t.sol`.

use alloy_primitives::{aliases::U192, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use hw_signer::{PublicKey, Signature};

use crate::abi::{IFactoryStaker, IKernel, IKernelFactory};

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

/// A plain validator's nonce key: `0x00 ‖ 0x01 ‖ validator ‖ 0x0000`.
pub fn validator_nonce_key(validator: Address) -> U192 {
    let mut b = [0u8; 24];
    b[1] = VALIDATION_TYPE_VALIDATOR;
    b[2..22].copy_from_slice(validator.as_slice());
    U192::from_be_slice(&b)
}

/// Owner (root) batch installing `validator` with `key` and granting it only
/// `changeRootValidator` — the cold recovery key. `nonce` as for
/// `install_permission_calldata`.
pub fn add_recovery_calldata(account: Address, validator: Address, key: &PublicKey, nonce: u32) -> Bytes {
    let vid = validator_id(validator);
    let install = IKernel::installValidationsCall {
        vIds: vec![vid],
        configs: vec![IKernel::ValidationConfig { nonce, hook: Address::with_last_byte(1) }],
        validationData: vec![encode_pubkey(key)],
        hookData: vec![Bytes::new()],
    }
    .abi_encode();
    let grant = IKernel::grantAccessCall {
        vId: vid,
        selector: IKernel::changeRootValidatorCall::SELECTOR.into(),
        allow: true,
    }
    .abi_encode();
    execute_batch_calldata(vec![(account, U256::ZERO, install.into()), (account, U256::ZERO, grant.into())])
}

/// `installValidations([validator], [{nonce, hook = address(1)}], [abi.encode(x, y)], [""])`.
pub fn install_validator_call(vid: ValidationId, key: &PublicKey, nonce: u32) -> Bytes {
    IKernel::installValidationsCall {
        vIds: vec![vid],
        configs: vec![IKernel::ValidationConfig { nonce, hook: Address::with_last_byte(1) }],
        validationData: vec![encode_pubkey(key)],
        hookData: vec![Bytes::new()],
    }
    .abi_encode()
    .into()
}

/// `uninstallValidation(validatorId(validator), "", "")` — `onUninstall`
/// clears the key the validator held for this account.
pub fn uninstall_validator_call(validator: Address) -> Bytes {
    IKernel::uninstallValidationCall { vId: validator_id(validator), deinitData: Bytes::new(), hookDeinitData: Bytes::new() }
        .abi_encode()
        .into()
}

/// `changeRootValidator(vId, hook = address(1), abi.encode(x, y), "")`.
/// `key` is installed only if `validator` is not installed yet — callers
/// must check that, or the old key silently stays.
pub fn change_root_calldata(validator: Address, key: Option<&PublicKey>) -> Bytes {
    IKernel::changeRootValidatorCall {
        rootValidator: validator_id(validator),
        hook: Address::with_last_byte(1),
        validatorData: key.map(encode_pubkey).unwrap_or_default(),
        hookData: Bytes::new(),
    }
    .abi_encode()
    .into()
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
    /// `(token, maxPerOp, budget, EIP-712 domain separator or 0)`
    pub tokens: Vec<(Address, u128, u128, B256)>,
    pub valid_after: u64,
    /// `(token, payees)`: the only addresses that token's transfers,
    /// allowances and x402 payments may name. Empty: no token is bound, and
    /// the mandate is encoded as it was before payee lists existed.
    pub payees: Vec<(Address, Vec<Address>)>,
}

/// What a mandate for trading adds (issue #80): the budgets' window and the
/// venues. `period` in seconds, 0 for one budget for the mandate's life;
/// `venues` as `(decoder, code hash, config hash)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trading {
    pub period: u32,
    pub venues: Vec<(Address, B256, B256)>,
}

impl Trading {
    pub fn is_none(&self) -> bool {
        self.period == 0 && self.venues.is_empty()
    }
}

/// A CoW Swap venue's config, as `CowSwapDecoder` reads it:
/// `abi.encode((bytes32 appData, uint32 maxLife, (address sellToken, address
/// buyToken, uint256 minBuy, uint256 perSell)[] pairs))`.
pub fn cow_config(app_data: B256, max_life: u32, pairs: &[(Address, Address, U256, U256)]) -> Bytes {
    (app_data, max_life, pairs.to_vec()).abi_encode().into()
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
    permission_data_with_trading(policy, params, &Trading::default(), signer, agent_key)
}

/// The same with a budget period, venues or both: then the policy's
/// parameters take their ten-word form, payee lists included even when
/// empty. Without either, the bytes are those of `permission_data`.
pub fn permission_data_with_trading(
    policy: Address,
    params: &PolicyParams,
    trading: &Trading,
    signer: Address,
    agent_key: &PublicKey,
) -> Bytes {
    // `abi.encode(targets, selectors, max, budget, until, tokens, after)`: a parameter
    // sequence, not one tuple value — `abi_encode()` on a dynamic tuple would
    // prepend an offset word and the policy's `abi.decode` would reject it.
    let seven = (
        params.targets.clone(),
        params.selectors.clone(),
        U256::from(params.max_value_per_op),
        U256::from(params.budget),
        U256::from(params.valid_until),
        params
            .tokens
            .iter()
            .map(|&(token, max, budget, domain)| (token, U256::from(max), U256::from(budget), domain))
            .collect::<Vec<_>>(),
        U256::from(params.valid_after),
    );
    // Payee lists travel as an eighth parameter, and only when there is one:
    // without them the bytes, and so a counterfactual account's address, are
    // what they were before lists existed. The policy tells the two forms
    // apart by the first head word.
    let policy_init = if !trading.is_none() {
        let (a, b, c, d, e, f, g) = seven;
        (a, b, c, d, e, f, g, params.payees.clone(), trading.period, trading.venues.clone()).abi_encode_params()
    } else if params.payees.is_empty() {
        seven.abi_encode_params()
    } else {
        let (a, b, c, d, e, f, g) = seven;
        (a, b, c, d, e, f, g, params.payees.clone()).abi_encode_params()
    };
    let flag = FixedBytes::<2>::ZERO;
    let entries: Vec<Bytes> = vec![
        (flag, policy, Bytes::from(policy_init)).abi_encode_packed().into(),
        (flag, signer, encode_pubkey(agent_key)).abi_encode_packed().into(),
    ];
    entries.abi_encode().into()
}

/// `installValidations([perm], [{nonce, hook = address(1)}], [data], [""])`.
/// `nonce` must equal the account's validation nonce at execution time:
/// `currentNonce()`, or one more if this id was installed before.
pub fn install_permission_calldata(perm: PermissionId, permission_data: Bytes, nonce: u32) -> Bytes {
    IKernel::installValidationsCall {
        vIds: vec![permission_vid(perm)],
        configs: vec![IKernel::ValidationConfig { nonce, hook: Address::with_last_byte(1) }],
        validationData: vec![permission_data],
        hookData: vec![Bytes::new()],
    }
    .abi_encode()
    .into()
}

/// `grantAccess(perm, execute.selector, true)` — a permission may only use
/// the selectors it was granted.
pub fn grant_execute_calldata(perm: PermissionId) -> Bytes {
    IKernel::grantAccessCall {
        vId: permission_vid(perm),
        selector: FixedBytes::from(IKernel::executeCall::SELECTOR),
        allow: true,
    }
    .abi_encode()
    .into()
}

/// `uninstallValidation(perm, disableData, "")` where `disableData` is
/// Kernel's PermissionDisableDataFormat: one entry per policy, then the
/// signer. Our modules need nothing beyond the id Kernel prepends.
pub fn uninstall_permission_calldata(perm: PermissionId) -> Bytes {
    let entries: Vec<Bytes> = vec![Bytes::new(), Bytes::new()];
    IKernel::uninstallValidationCall {
        vId: permission_vid(perm),
        deinitData: entries.abi_encode().into(),
        hookDeinitData: Bytes::new(),
    }
    .abi_encode()
    .into()
}

/// `Kernel.initialize(...)` calldata: the owner key as root, the agent
/// permission installed and granted `execute` through `initConfig`.
pub fn init_data(
    validator: Address,
    owner_key: &PublicKey,
    perm: PermissionId,
    permission_data: Bytes,
) -> Bytes {
    IKernel::initializeCall {
        rootValidator: validator_id(validator),
        hook: Address::ZERO,
        validatorData: encode_pubkey(owner_key),
        hookData: Bytes::new(),
        // initialize() sets the validation nonce to 1 before running initConfig
        initConfig: vec![install_permission_calldata(perm, permission_data, 1), grant_execute_calldata(perm)],
    }
    .abi_encode()
    .into()
}

/// `execute(batch/default, abi.encode(Execution[]))` — several calls in one
/// operation; self-calls let a root operation reconfigure the account.
pub fn execute_batch_calldata(calls: Vec<(Address, U256, Bytes)>) -> Bytes {
    let executions: Vec<IKernel::Execution> = calls
        .into_iter()
        .map(|(target, value, call_data)| IKernel::Execution { target, value, callData: call_data })
        .collect();
    let mut mode = [0u8; 32];
    mode[0] = 0x01; // CALLTYPE_BATCH, EXECTYPE_DEFAULT
    IKernel::executeCall { execMode: B256::from(mode), executionCalldata: executions.abi_encode().into() }
        .abi_encode()
        .into()
}

/// The calls inside `execute` calldata built by [`execute_calldata`] /
/// [`execute_batch_calldata`]; `None` for anything else.
pub fn decode_execute(call_data: &[u8]) -> Option<Vec<(Address, U256, Bytes)>> {
    let exec = IKernel::executeCall::abi_decode(call_data).ok()?;
    match exec.execMode.0[0] {
        0x00 => {
            let raw = exec.executionCalldata;
            if raw.len() < 52 {
                return None;
            }
            let target = Address::from_slice(&raw[..20]);
            let value = U256::from_be_slice(&raw[20..52]);
            Some(vec![(target, value, Bytes::copy_from_slice(&raw[52..]))])
        }
        0x01 => {
            let calls = <Vec<IKernel::Execution>>::abi_decode(&exec.executionCalldata).ok()?;
            Some(calls.into_iter().map(|c| (c.target, c.value, c.callData)).collect())
        }
        _ => None,
    }
}

/// ERC-4337 `initCode`: `factory ‖ createAccount(initData, salt)`.
pub fn init_code(factory: Address, init_data: &Bytes, salt: B256) -> Bytes {
    let call = IKernelFactory::createAccountCall { data: init_data.clone(), salt }.abi_encode();
    [factory.as_slice(), &call].concat().into()
}

/// ERC-4337 `initCode` through a staked factory:
/// `staker ‖ deployWithFactory(factory, initData, salt)`.
///
/// Creating an account writes the modules' slots for it, and during an
/// operation with `initCode` ERC-7562 allows those only when the factory
/// the operation names is staked (STO-022). Kernel's factory holds no
/// stake; ZeroDev's `FactoryStaker` does, and calls `createAccount` on the
/// factory with the same data and salt, so the account is the same one at
/// the same address.
pub fn init_code_staked(staker: Address, factory: Address, init_data: &Bytes, salt: B256) -> Bytes {
    let call = IFactoryStaker::deployWithFactoryCall { factory, createData: init_data.clone(), salt }.abi_encode();
    [staker.as_slice(), &call].concat().into()
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

/// Kernel's ERC-1271 wrapper: what the signer actually signs for a hash a
/// verifier passes to `isValidSignature` — EIP-712 in the account's own
/// domain ("Kernel", "0.3.3"), struct `Kernel(bytes32 hash)`.
pub fn kernel_wrapped_hash(account: Address, chain_id: u64, hash: B256) -> B256 {
    use alloy_primitives::keccak256;
    let domain_typehash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    let domain = keccak256(
        (domain_typehash, keccak256("Kernel"), keccak256("0.3.3"), U256::from(chain_id), account).abi_encode(),
    );
    let wrapper_typehash = keccak256("Kernel(bytes32 hash)");
    let struct_hash = keccak256((wrapper_typehash, hash).abi_encode());
    keccak256([&[0x19u8, 0x01][..], domain.as_slice(), struct_hash.as_slice()].concat())
}

/// An ERC-1271 signature under a permission: `0x02 ‖ permission id ‖ 0xff ‖ r ‖ s`.
pub fn permission_1271_signature(perm: PermissionId, sig: &Signature) -> Bytes {
    [&[0x02u8][..], perm.as_slice(), &[0xffu8][..], &sig.r[..], &sig.s[..]].concat().into()
}

/// EIP-3009 `TransferWithAuthorization` digest in a token's domain.
pub fn transfer_with_authorization_digest(
    domain_separator: B256,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    use alloy_primitives::keccak256;
    let typehash = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );
    let struct_hash = keccak256((typehash, from, to, value, valid_after, valid_before, nonce).abi_encode());
    keccak256([&[0x19u8, 0x01][..], domain_separator.as_slice(), struct_hash.as_slice()].concat())
}

/// Permission path: no policy segments, `0xff` introduces the signer bytes.
pub fn permission_signature(sig: &Signature) -> Bytes {
    [&[0xffu8][..], &sig.r, &sig.s].concat().into()
}

/// Permission path under a mandate with a budget per period: the policy's
/// part of the signature (Kernel: index 0, an 8-byte length, the bytes) is
/// the six-byte index of the period the operation is for, `now / period`.
pub fn permission_signature_in_period(period_index: u64, sig: &Signature) -> Bytes {
    let index = period_index.to_be_bytes();
    [&[0u8][..], &6u64.to_be_bytes(), &index[2..], &[0xff], &sig.r, &sig.s].concat().into()
}

/// A CoW Protocol sell order as `CowSwapDecoder` takes it: the twelve words
/// of `GPv2Order.Data`, filled whole, plain ERC-20 balances, no fee, the
/// proceeds to the order's owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CowSellOrder {
    pub sell_token: Address,
    pub buy_token: Address,
    pub sell_amount: U256,
    pub buy_amount: U256,
    pub valid_to: u32,
    pub app_data: B256,
}

impl CowSellOrder {
    /// `abi.encode(GPv2Order.Data)`.
    pub fn encode(&self) -> Bytes {
        use alloy_primitives::keccak256;
        (
            self.sell_token,
            self.buy_token,
            Address::ZERO, // receiver: the owner
            self.sell_amount,
            self.buy_amount,
            U256::from(self.valid_to),
            self.app_data,
            U256::ZERO, // feeAmount
            keccak256("sell"),
            false,
            keccak256("erc20"),
            keccak256("erc20"),
        )
            .abi_encode()
            .into()
    }

    /// The EIP-712 digest the settlement asks the owner to vouch for.
    pub fn digest(&self, domain_separator: B256) -> B256 {
        use alloy_primitives::keccak256;
        let type_hash = keccak256(
            "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)",
        );
        let struct_hash = keccak256([type_hash.as_slice(), &self.encode()].concat());
        keccak256([&[0x19u8, 0x01][..], domain_separator.as_slice(), struct_hash.as_slice()].concat())
    }
}

/// The EIP-712 domain separator of CoW's settlement on a chain.
pub fn cow_domain_separator(chain_id: u64, settlement: Address) -> B256 {
    use alloy_primitives::keccak256;
    keccak256(
        (
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Gnosis Protocol"),
            keccak256("v2"),
            U256::from(chain_id),
            settlement,
        )
            .abi_encode(),
    )
}

/// `AgentPolicy.orderRegister(decoder, config, order)`.
pub fn order_register_calldata(decoder: Address, config: &[u8], order: &[u8]) -> Bytes {
    let args = (decoder, Bytes::copy_from_slice(config), Bytes::copy_from_slice(order)).abi_encode_params();
    [&[0x27u8, 0xdd, 0xae, 0x76][..], &args].concat().into()
}

/// `AgentPolicy.orderReclaim(id, decoder, config, order)`.
pub fn order_reclaim_calldata(id: B256, decoder: Address, config: &[u8], order: &[u8]) -> Bytes {
    let args = (id, decoder, Bytes::copy_from_slice(config), Bytes::copy_from_slice(order)).abi_encode_params();
    [&[0x43u8, 0x44, 0xb7, 0x33][..], &args].concat().into()
}

/// Root path: the bare pair.
pub fn root_signature(sig: &Signature) -> Bytes {
    [&sig.r[..], &sig.s[..]].concat().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    // Reference values computed independently with `cast` (abi-encode + keccak).
    const A: Address = address!("1111111111111111111111111111111111111111");
    const B: Address = address!("2222222222222222222222222222222222222222");
    const N: B256 = b256!("3333333333333333333333333333333333333333333333333333333333333333");

    /// The policy's install parameters in both forms, against `cast abi-encode`
    /// of the Solidity types `AgentPolicy.onInstall` decodes.
    #[test]
    fn policy_parameters_with_and_without_payees() {
        let token = address!("00000000000000000000000000000000000000c1");
        let init = |payees| {
            let params = PolicyParams {
                targets: vec![token],
                selectors: vec![FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])],
                max_value_per_op: 7,
                budget: 9,
                valid_until: 1000,
                tokens: vec![(token, 5, 50, B256::ZERO)],
                valid_after: 3,
                payees,
            };
            let data = permission_data(A, &params, B, &PublicKey { x: [1; 32], y: [2; 32] });
            let entries = Vec::<Bytes>::abi_decode(&data).unwrap();
            alloy_primitives::keccak256(&entries[0][22..])
        };
        // seven parameters, as before payee lists existed
        assert_eq!(init(vec![]), b256!("6af2f27ba0bcd1851dc4161b2e4a9ff02f3b02f4d5bb1b48c9a5691d77ad0d6a"));
        let payees = vec![(
            token,
            vec![address!("00000000000000000000000000000000000000d1"), address!("00000000000000000000000000000000000000d2")],
        )];
        assert_eq!(init(payees), b256!("00f7275b78b049a3af82e32d41654173b4e2da115082c3e049c8e7f629da723f"));
    }

    /// The ten-word form, the venue's config and the two order calls, against
    /// `cast abi-encode` / `cast calldata` of the Solidity types.
    #[test]
    fn trading_parameters_and_order_calls() {
        let token = address!("00000000000000000000000000000000000000c1");
        let decoder = address!("00000000000000000000000000000000000000e1");
        let (h1, h2) = (B256::repeat_byte(0x44), B256::repeat_byte(0x55));
        let init = |payees, trading: &Trading| {
            let params = PolicyParams {
                targets: vec![token],
                selectors: vec![FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])],
                max_value_per_op: 7,
                budget: 9,
                valid_until: 1000,
                tokens: vec![(token, 5, 50, B256::ZERO)],
                valid_after: 3,
                payees,
            };
            let data = permission_data_with_trading(A, &params, trading, B, &PublicKey { x: [1; 32], y: [2; 32] });
            let entries = Vec::<Bytes>::abi_decode(&data).unwrap();
            alloy_primitives::keccak256(&entries[0][22..])
        };
        let venue = Trading { period: 86_400, venues: vec![(decoder, h1, h2)] };
        assert_eq!(init(vec![], &venue), b256!("ba3c12e045cea07ebf5cfc7acdaff2f76915c3e30222ae34034753d9e41e2307"));
        let payees = vec![(token, vec![address!("00000000000000000000000000000000000000d1")])];
        let period_only = Trading { period: 3_600, venues: vec![] };
        assert_eq!(init(payees, &period_only), b256!("f93f7ce6c4f1c164c7b5679505e3cfa19809b46a575654ea843af386bb408144"));
        // neither: the bytes of the seven-word form
        assert_eq!(init(vec![], &Trading::default()), b256!("6af2f27ba0bcd1851dc4161b2e4a9ff02f3b02f4d5bb1b48c9a5691d77ad0d6a"));

        let config = cow_config(h1, 1800, &[(token, decoder, U256::from(99), U256::from(100))]);
        assert_eq!(alloy_primitives::keccak256(&config), b256!("bd17f342cd26c2da70ee8c0fe56447cb04075240b14936e9ae45470bbdc7f737"));
        assert_eq!(
            alloy_primitives::keccak256(order_register_calldata(decoder, &[0x12, 0x34], &[0xab, 0xcd, 0xef])),
            b256!("08453e4f1e3e9495f734e5698aaf154c96a6e22c0b20ed67a2523cd9ce67f174")
        );
        assert_eq!(
            alloy_primitives::keccak256(order_reclaim_calldata(h1, decoder, &[0x12, 0x34], &[0xab, 0xcd, 0xef])),
            b256!("b2dd9870883ef1040f6adcd0e9dd5609857462ad16bf32f73f737d2f29e31a3b")
        );
    }

    /// The order's digest against CoW's own: an order from the public
    /// mainnet order book (2026-11-21), whose uid begins with its digest.
    #[test]
    fn cow_order_digest_is_the_order_books() {
        let settlement = address!("9008D19f58AAbD9eD0D60971565AA8510560ab41");
        let order = CowSellOrder {
            sell_token: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            buy_token: address!("dAC17F958D2ee523a2206206994597C13D831ec7"),
            sell_amount: U256::from(100_000_000u64),
            buy_amount: U256::from(100_215_097u64),
            valid_to: 1_795_270_546,
            app_data: B256::ZERO,
        };
        assert_eq!(order.encode().len(), 12 * 32);
        assert_eq!(
            order.digest(cow_domain_separator(1, settlement)),
            b256!("ef9a1f96802a5a751d7a34427a773d18e7089c42b20346e5d1817ccc4249bcbc")
        );
        // Base Sepolia's separator, as the settlement there returns it
        assert_eq!(
            cow_domain_separator(84532, settlement),
            b256!("75e06a5fc9670d3e53c52ba9d3ff16ef1f1c671964aa68ad94588ee7462d0338")
        );
    }

    #[test]
    fn the_period_travels_in_the_policys_part_of_the_signature() {
        let sig = Signature { r: [0xaa; 32], s: [0xbb; 32] };
        let bytes = permission_signature_in_period(20_833, &sig);
        assert_eq!(bytes.len(), 1 + 8 + 6 + 1 + 64);
        assert_eq!(&bytes[..16], &[0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x51, 0x61, 0xff][..]);
        assert_eq!(&bytes[16..], &permission_signature(&sig)[1..]);
    }

    #[test]
    fn usdc_authorization_digest() {
        let usdc_domain = b256!("71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818");
        let d = transfer_with_authorization_digest(
            usdc_domain,
            A,
            B,
            U256::from(1000),
            U256::ZERO,
            U256::from(1_800_000_000u64),
            N,
        );
        assert_eq!(d, b256!("ef65c4162bdc50eebf36f55ef5535cbe66f39950f41dff21d9cde9d02e02ce2b"));
    }

    #[test]
    fn kernel_1271_wrapper() {
        assert_eq!(
            kernel_wrapped_hash(A, 84532, N),
            b256!("a0c4e2fb6da7cfeb16f6f22278e127d1577af46d75234d79702d760db9922994")
        );
    }

    /// `cast calldata 'deployWithFactory(address,bytes,bytes32)'` for the
    /// same arguments, behind the staker's address.
    #[test]
    fn init_code_through_the_staker_matches_cast() {
        let staker = address!("d703aaE79538628d27099B8c4f621bE4CCd142d5");
        let factory = address!("2577507b78c2008Ff367261CB6285d44ba5eF2E9");
        let data = Bytes::from(vec![1u8, 2, 3, 4, 5]);
        let mut salt = [0u8; 32];
        salt[31] = 0xaa;
        let got = init_code_staked(staker, factory, &data, B256::from(salt));
        let cast = "c5265d5d0000000000000000000000002577507b78c2008ff367261cb6285d44ba5ef2e9000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000aa00000000000000000000000000000000000000000000000000000000000000050102030405000000000000000000000000000000000000000000000000000000";
        assert_eq!(&got[..20], staker.as_slice());
        assert_eq!(Bytes::from(got[20..].to_vec()).to_string(), format!("0x{cast}"));
        // and the direct form still names the factory
        assert_eq!(&init_code(factory, &data, B256::from(salt))[..20], factory.as_slice());
    }

    #[test]
    fn execute_round_trips() {
        let single = execute_calldata(A, U256::from(7), &[1, 2, 3]);
        assert_eq!(decode_execute(&single), Some(vec![(A, U256::from(7), Bytes::from(vec![1, 2, 3]))]));
        let calls = vec![(A, U256::ZERO, Bytes::from(vec![9])), (B, U256::from(1), Bytes::new())];
        assert_eq!(decode_execute(&execute_batch_calldata(calls.clone())), Some(calls));
        assert_eq!(decode_execute(&[0xde, 0xad]), None);
    }

    #[test]
    fn permission_1271_layout() {
        let sig = Signature { r: [0xaa; 32], s: [0xbb; 32] };
        let b = permission_1271_signature(FixedBytes([1, 2, 3, 4]), &sig);
        assert_eq!(b.len(), 1 + 4 + 1 + 64);
        assert_eq!(&b[..6], &[0x02, 1, 2, 3, 4, 0xff]);
    }
}
