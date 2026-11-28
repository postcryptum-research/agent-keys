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

/// Owner (root) batch that replaces the recovery key (issue #114): the
/// recovery validator is uninstalled, which clears the key it held for the
/// account, and installed again with `key` and the one grant it has. One
/// operation: there is no moment with the old key gone and no new one.
/// `nonce` as for `install_permission_calldata`.
pub fn replace_recovery_calldata(account: Address, validator: Address, key: &PublicKey, nonce: u32) -> Bytes {
    let vid = validator_id(validator);
    let grant = IKernel::grantAccessCall { vId: vid, selector: IKernel::changeRootValidatorCall::SELECTOR.into(), allow: true }.abi_encode();
    execute_batch_calldata(vec![
        (account, U256::ZERO, uninstall_validator_call(validator)),
        (account, U256::ZERO, install_validator_call(vid, key, nonce)),
        (account, U256::ZERO, grant.into()),
    ])
}

/// Owner (root) batch that removes the recovery key: its grant of
/// `changeRootValidator` is withdrawn and the validator uninstalled.
pub fn remove_recovery_calldata(account: Address, validator: Address) -> Bytes {
    let vid = validator_id(validator);
    let forbid = IKernel::grantAccessCall { vId: vid, selector: IKernel::changeRootValidatorCall::SELECTOR.into(), allow: false }.abi_encode();
    execute_batch_calldata(vec![(account, U256::ZERO, forbid.into()), (account, U256::ZERO, uninstall_validator_call(validator))])
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
/// must check that, or the old key silently stays. The phone's review
/// refuses a root change with a key (issue #147).
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

/// What the longer forms of a mandate add: the budgets' window and the
/// venues (issue #80), and limits per id of an ERC-6909 contract (issue
/// #186). `period` in seconds, 0 for one budget for the mandate's life;
/// `venues` as `(decoder, code hash, config hash)`; `ids` as `(contract,
/// token id, maxPerOp, budget)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trading {
    pub period: u32,
    pub venues: Vec<(Address, B256, B256)>,
    pub ids: Vec<(Address, U256, u128, u128)>,
}

impl Trading {
    pub fn is_none(&self) -> bool {
        self.period == 0 && self.venues.is_empty() && self.ids.is_empty()
    }
}

/// A CoW Swap venue's config, as `CowSwapDecoder` reads it:
/// `abi.encode((bytes32 appData, uint32 maxLife, (address sellToken, address
/// buyToken, uint256 minBuy, uint256 perSell)[] pairs))`.
pub fn cow_config(app_data: B256, max_life: u32, pairs: &[(Address, Address, U256, U256)]) -> Bytes {
    (app_data, max_life, pairs.to_vec()).abi_encode().into()
}

/// A 1inch limit-order venue's config, as `OneInchLimitOrderDecoder` reads
/// it: `abi.encode((uint32 maxLife, (address sellToken, address buyToken,
/// uint256 minBuy, uint256 perSell)[] pairs))`.
pub fn one_inch_config(max_life: u32, pairs: &[(Address, Address, U256, U256)]) -> Bytes {
    (max_life, pairs.to_vec()).abi_encode().into()
}

/// A swap venue's config, as `SwapRouter02Decoder` reads it:
/// `abi.encode(((address sellToken, address buyToken, uint256 minBuy,
/// uint256 perSell)[] pairs))`: a struct of one list.
pub fn swap_config(pairs: &[(Address, Address, U256, U256)]) -> Bytes {
    (pairs.to_vec(),).abi_encode().into()
}

/// The rule for one argument word of a call, as `CallRulesDecoder` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordRule {
    /// The word is the address of the account that makes the call.
    IsAccount,
    /// The word is exactly this value.
    IsValue(U256),
    /// The word, as an unsigned number, is at most this bound.
    AtMost(U256),
    /// The word is an amount, charged in this token.
    Charged(Address),
    /// The word is the agent's to choose.
    Any,
}

impl WordRule {
    /// The decoder's `(kind, value)` for the rule. The kind is a `uint8`
    /// there, one word like any other: a number here.
    pub fn encode(&self) -> (U256, U256) {
        let (kind, value) = match self {
            WordRule::IsAccount => (0u8, U256::ZERO),
            WordRule::IsValue(v) => (1, *v),
            WordRule::AtMost(v) => (2, *v),
            WordRule::Charged(token) => (3, U256::from_be_slice(token.as_slice())),
            WordRule::Any => (4, U256::ZERO),
        };
        (U256::from(kind), value)
    }
}

/// A function the agent may call at a venue of rules: its selector and the
/// rule for each of its argument words, in order.
pub type RuledFunction = (FixedBytes<4>, Vec<WordRule>);

/// A venue of rules' config, as `CallRulesDecoder` reads it:
/// `abi.encode(((bytes4 selector, (uint8 kind, uint256 value)[] words)[]
/// functions))`: a struct of one list.
pub fn call_rules_config(functions: &[RuledFunction]) -> Bytes {
    let raw: Vec<(FixedBytes<4>, Vec<(U256, U256)>)> =
        functions.iter().map(|(selector, words)| (*selector, words.iter().map(WordRule::encode).collect())).collect();
    (raw,).abi_encode().into()
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
/// empty. With limits per id, their eleven-word form: the ten, then the
/// limits. Without any of the three, the bytes are those of `permission_data`.
pub fn permission_data_with_trading(
    policy: Address,
    params: &PolicyParams,
    trading: &Trading,
    signer: Address,
    agent_key: &PublicKey,
) -> Bytes {
    permission_data_shaped(policy, params, trading, &[], signer, agent_key)
}

/// The same with shape judges pinned (#251): `(judge, code hash)` each,
/// which a mandate with a Safe transaction or a batch on its allow-list
/// needs. With any, the twelve-word form: the eleven, the limits per id
/// possibly empty, then the judges. Without, the bytes of
/// `permission_data_with_trading`.
pub fn permission_data_shaped(
    policy: Address,
    params: &PolicyParams,
    trading: &Trading,
    shapes: &[(Address, B256)],
    signer: Address,
    agent_key: &PublicKey,
) -> Bytes {
    permission_data_faced(policy, params, trading, shapes, None, signer, agent_key)
}

/// The same with the native token's ERC-20 face named (#251): `(token,
/// decimals)`, Arc's USDC, whose movements under its token limit count
/// against the native limits too. With it, the fourteen-word form: the
/// twelve, the judges possibly none, then the face. Without, the bytes of
/// `permission_data_shaped`.
pub fn permission_data_faced(
    policy: Address,
    params: &PolicyParams,
    trading: &Trading,
    shapes: &[(Address, B256)],
    face: Option<(Address, u8)>,
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
    let policy_init = if let Some(face) = face {
        let (a, b, c, d, e, f, g) = seven;
        let ids: Vec<_> =
            trading.ids.iter().map(|&(token, id, max, budget)| (token, id, U256::from(max), U256::from(budget))).collect();
        let twelve =
            (a, b, c, d, e, f, g, params.payees.clone(), trading.period, trading.venues.clone(), ids, shapes.to_vec())
                .abi_encode_params();
        with_face(&twelve, face)
    } else if !shapes.is_empty() {
        let (a, b, c, d, e, f, g) = seven;
        let ids: Vec<_> =
            trading.ids.iter().map(|&(token, id, max, budget)| (token, id, U256::from(max), U256::from(budget))).collect();
        (a, b, c, d, e, f, g, params.payees.clone(), trading.period, trading.venues.clone(), ids, shapes.to_vec())
            .abi_encode_params()
    } else if !trading.ids.is_empty() {
        let (a, b, c, d, e, f, g) = seven;
        let ids: Vec<_> =
            trading.ids.iter().map(|&(token, id, max, budget)| (token, id, U256::from(max), U256::from(budget))).collect();
        (a, b, c, d, e, f, g, params.payees.clone(), trading.period, trading.venues.clone(), ids).abi_encode_params()
    } else if !trading.is_none() {
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

/// The head words of the twelve-word form that are offsets of dynamic
/// parameters: targets, selectors, tokens, payees, venues, ids, shapes.
pub(crate) const TWELVE_OFFSETS: [usize; 7] = [0, 1, 5, 7, 9, 10, 11];

/// The fourteen-word form from the twelve-word encoding: the face's two
/// words after the twelfth head word, and each offset of a dynamic parameter
/// 64 bytes further on. (The ABI encoders this crate uses take twelve
/// parameters at most.)
fn with_face(twelve: &[u8], face: (Address, u8)) -> Vec<u8> {
    let mut out = Vec::with_capacity(twelve.len().saturating_add(64));
    for (i, word) in twelve[..384].chunks(32).enumerate() {
        let w = U256::from_be_slice(word);
        let w = if TWELVE_OFFSETS.contains(&i) { w.checked_add(U256::from(64)).expect("an offset within the encoding") } else { w };
        out.extend_from_slice(&w.to_be_bytes::<32>());
    }
    out.extend_from_slice(&B256::left_padding_from(face.0.as_slice()).0);
    out.extend_from_slice(&U256::from(face.1).to_be_bytes::<32>());
    out.extend_from_slice(&twelve[384..]);
    out
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

/// A plain order of 1inch's Limit Order Protocol v4 as
/// `OneInchLimitOrderDecoder` takes it: the eight words of the router's
/// order, the proceeds to the maker, filled whole and once, with an
/// expiration and no other trait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneInchOrder {
    /// Any number: with no extension the router gives it no meaning.
    pub salt: U256,
    /// The account.
    pub maker: Address,
    pub maker_asset: Address,
    pub taker_asset: Address,
    pub making_amount: U256,
    pub taking_amount: U256,
    /// The last second the order can be filled; forty bits, never zero.
    pub expiration: u64,
    /// The order's place among the maker's one-fill bits; forty bits.
    pub nonce: u64,
}

impl OneInchOrder {
    /// The order's `makerTraits`: bit 255 (no partial fills), the expiration
    /// in bits 80 to 119, the nonce in bits 120 to 159, and nothing else.
    /// `None` if the expiration is zero (the router reads it as "never") or
    /// either number is wider than forty bits.
    pub fn traits(&self) -> Option<U256> {
        let (expiration, nonce) = (self.expiration.to_be_bytes(), self.nonce.to_be_bytes());
        if self.expiration == 0 || expiration[..3] != [0u8; 3] || nonce[..3] != [0u8; 3] {
            return None;
        }
        // big-endian: bit 255 is the first byte's top bit; bits 120-159 are
        // bytes 12 to 16, bits 80-119 bytes 17 to 21
        let mut word = [0u8; 32];
        word[0] = 0x80;
        word[12..17].copy_from_slice(&nonce[3..]);
        word[17..22].copy_from_slice(&expiration[3..]);
        Some(U256::from_be_bytes(word))
    }

    /// `abi.encode` of the router's order: eight words.
    pub fn encode(&self) -> Option<Bytes> {
        Some(
            (
                self.salt,
                self.maker,
                Address::ZERO, // receiver: the maker
                self.maker_asset,
                self.taker_asset,
                self.making_amount,
                self.taking_amount,
                self.traits()?,
            )
                .abi_encode()
                .into(),
        )
    }

    /// The EIP-712 digest the router asks the maker to vouch for.
    pub fn digest(&self, domain_separator: B256) -> Option<B256> {
        use alloy_primitives::keccak256;
        let type_hash = keccak256(
            "Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)",
        );
        let struct_hash = keccak256([type_hash.as_slice(), &self.encode()?].concat());
        Some(keccak256([&[0x19u8, 0x01][..], domain_separator.as_slice(), struct_hash.as_slice()].concat()))
    }
}

/// The EIP-712 domain separator of 1inch's router (AggregationRouterV6) on a chain.
pub fn one_inch_domain_separator(chain_id: u64, router: Address) -> B256 {
    use alloy_primitives::keccak256;
    keccak256(
        (
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("1inch Aggregation Router"),
            keccak256("6"),
            U256::from(chain_id),
            router,
        )
            .abi_encode(),
    )
}

/// A swap of an exact amount through one Uniswap v3 pool, as
/// `SwapRouter02Decoder` takes it: what the agent names. The decoder writes
/// the rest of the router call itself: the bought token to the account, no
/// native value, no price limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrder {
    pub token_in: Address,
    pub token_out: Address,
    /// The pool's fee tier; twenty-four bits.
    pub fee: u32,
    /// The exact amount sold; never zero (to the router that is its own balance).
    pub amount_in: U256,
    /// The least amount bought.
    pub amount_out_minimum: U256,
}

impl SwapOrder {
    /// The widest fee tier the router's `uint24` holds.
    const MAX_FEE: u32 = 0x00ff_ffff;

    /// `abi.encode(Swap)`: the five words the decoder is handed. `None` if
    /// the fee tier is wider than twenty-four bits.
    pub fn encode(&self) -> Option<Bytes> {
        if self.fee > Self::MAX_FEE {
            return None;
        }
        Some((self.token_in, self.token_out, U256::from(self.fee), self.amount_in, self.amount_out_minimum).abi_encode().into())
    }

    /// The router call the decoder builds for `account`
    /// (`SwapRouter02Decoder.swapCall`): `exactInputSingle((tokenIn,
    /// tokenOut, fee, recipient, amountIn, amountOutMinimum,
    /// sqrtPriceLimitX96))` with the account as recipient and no price limit.
    /// The account sends exactly these bytes to the router, with no value,
    /// in the leg after the swap's registration.
    pub fn call(&self, account: Address) -> Option<Bytes> {
        if self.fee > Self::MAX_FEE {
            return None;
        }
        let args = (self.token_in, self.token_out, U256::from(self.fee), account, self.amount_in, self.amount_out_minimum, U256::ZERO)
            .abi_encode();
        Some([&[0x04u8, 0xe4, 0x5a, 0xaf][..], &args].concat().into())
    }

    /// The call's hash, as the decoder answers the policy with
    /// (`VenueCalls.digest(0, call)`): `keccak256(abi.encode(uint256 value,
    /// keccak256(calldata)))` with no value.
    pub fn digest(&self, account: Address) -> Option<B256> {
        use alloy_primitives::keccak256;
        Some(keccak256((U256::ZERO, keccak256(self.call(account)?)).abi_encode()))
    }
}

/// `AgentPolicy.orderRegister(decoder, config, order)`.
pub fn order_register_calldata(decoder: Address, config: &[u8], order: &[u8]) -> Bytes {
    let args = (decoder, Bytes::copy_from_slice(config), Bytes::copy_from_slice(order)).abi_encode_params();
    [&[0x27u8, 0xdd, 0xae, 0x76][..], &args].concat().into()
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
        let venue = Trading { period: 86_400, venues: vec![(decoder, h1, h2)], ids: vec![] };
        assert_eq!(init(vec![], &venue), b256!("ba3c12e045cea07ebf5cfc7acdaff2f76915c3e30222ae34034753d9e41e2307"));
        let payees = vec![(token, vec![address!("00000000000000000000000000000000000000d1")])];
        let period_only = Trading { period: 3_600, venues: vec![], ids: vec![] };
        assert_eq!(init(payees, &period_only), b256!("f93f7ce6c4f1c164c7b5679505e3cfa19809b46a575654ea843af386bb408144"));
        // neither: the bytes of the seven-word form
        assert_eq!(init(vec![], &Trading::default()), b256!("6af2f27ba0bcd1851dc4161b2e4a9ff02f3b02f4d5bb1b48c9a5691d77ad0d6a"));

        let config = cow_config(h1, 1800, &[(token, decoder, U256::from(99), U256::from(100))]);
        assert_eq!(alloy_primitives::keccak256(&config), b256!("bd17f342cd26c2da70ee8c0fe56447cb04075240b14936e9ae45470bbdc7f737"));
        assert_eq!(
            alloy_primitives::keccak256(order_register_calldata(decoder, &[0x12, 0x34], &[0xab, 0xcd, 0xef])),
            b256!("08453e4f1e3e9495f734e5698aaf154c96a6e22c0b20ed67a2523cd9ce67f174")
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

    /// The 1inch order's digest against the router's own: `hashOrder` of the
    /// router at 0x111111125421cA6dc452d289314280a0f8842A65 was asked for
    /// this order on four chains (2026-11-26, `eth_call`), the same order
    /// `OneInchLimitOrderDecoder.t.sol` holds the decoder to.
    #[test]
    fn one_inch_order_digest_is_the_routers() {
        let router = address!("111111125421cA6dc452d289314280a0f8842A65");
        let order = OneInchOrder {
            salt: U256::from(42u64),
            maker: A,
            maker_asset: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            taker_asset: address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            making_amount: U256::from(1_000_000_000u64),
            taking_amount: U256::from(250_000_000_000_000_000u64),
            expiration: 1_900_000_000,
            nonce: 7,
        };
        assert_eq!(order.encode().unwrap().len(), 8 * 32);
        // no partial fills, the expiration and the nonce, and no other bit
        assert_eq!(
            order.traits().unwrap(),
            "57896044618658097711785492504343953926644299225749833698634550595112927232000".parse::<U256>().unwrap()
        );
        for (chain, given) in [
            (1u64, b256!("0a6c594bc65692afed072afc8ffbcbac664384f0d521624b63f396edfcbbb48d")),
            (8453, b256!("fbcef6ee1646af7a95c2d774d1f7e7168b46dc7a79e5e58e1c310c91ef8b961f")),
            (11155111, b256!("a776b6c7b9c9e0a40a83221072e354a444b8fd94c6dcf5f4ec56c2e764c9e598")),
            (84532, b256!("a64c698dddd4f1ece332d81be16df5c432a378ed04f9eff991f366cb23fb96cf")),
        ] {
            assert_eq!(order.digest(one_inch_domain_separator(chain, router)), Some(given), "chain {chain}");
        }
        // mainnet's separator, as the decoder's test has it
        assert_eq!(
            one_inch_domain_separator(1, router),
            b256!("d999e213f11c7bfa3e796c3409e316f25e02aa3e25e5c207a92e381c7d22b6de")
        );
        // an order that never expires, or a number wider than forty bits, is no order
        assert_eq!(OneInchOrder { expiration: 0, ..order.clone() }.encode(), None);
        assert_eq!(OneInchOrder { expiration: 1 << 40, ..order.clone() }.traits(), None);
        assert_eq!(OneInchOrder { nonce: 1 << 40, ..order.clone() }.digest(B256::ZERO), None);
        // the widest of both fit, and stay in their own bits
        let widest = OneInchOrder { expiration: (1 << 40) - 1, nonce: (1 << 40) - 1, ..order }.traits().unwrap();
        assert_eq!(widest, (U256::from(1u8) << 255) | (((U256::from(1u8) << 80) - U256::from(1u8)) << 80));
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
    /// A swap as `SwapRouter02Decoder` reads and builds it: the config, the
    /// five words, the router call and the call's hash, against the bytes
    /// the decoder's own test records
    /// (`contracts/test/SwapRouter02.t.sol`, `test_decoder_theRecordedSwap`).
    #[test]
    fn a_swap_is_the_decoders() {
        use alloy_primitives::hex;
        let account = address!("1111111111111111111111111111111111111111");
        let (sell, buy) = (address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"));
        let (sold, least) = (U256::from(1_000_000_000u64), U256::from(250_000_000_000_000_000u64));
        assert_eq!(
            swap_config(&[(sell, buy, least, sold)]).as_ref(),
            hex!("000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000003782dace9d90000000000000000000000000000000000000000000000000000000000003b9aca00")
        );
        let swap = SwapOrder { token_in: sell, token_out: buy, fee: 500, amount_in: sold, amount_out_minimum: least };
        assert_eq!(
            swap.encode().unwrap().as_ref(),
            hex!("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000003782dace9d90000")
        );
        assert_eq!(
            swap.call(account).unwrap().as_ref(),
            hex!("04e45aaf000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f40000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000003782dace9d900000000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(swap.digest(account).unwrap(), b256!("b870325779145b133ddd23f0edfe40ef291a53b1b456ddae332f89a8489be208"));
        // another account, another call; a fee tier wider than the router's 24 bits is no swap
        assert_ne!(swap.digest(address!("2222222222222222222222222222222222222222")), swap.digest(account));
        let wide = SwapOrder { fee: 0x0100_0000, ..swap.clone() };
        assert!(wide.encode().is_none() && wide.call(account).is_none() && wide.digest(account).is_none());
        assert!(SwapOrder { fee: 0x00ff_ffff, ..swap }.encode().is_some());
    }

    /// A venue of rules' config as `CallRulesDecoder` reads it, and the hash
    /// of a call there, against the bytes the decoder's own test records
    /// (`contracts/test/CallRules.t.sol`, `test_rules_theRecordedConfig`):
    /// Aave's `supply` and `withdraw`, for one asset and the account.
    #[test]
    fn a_rules_config_is_the_decoders() {
        use alloy_primitives::{hex, keccak256};
        let asset = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let value = U256::from_be_slice(asset.as_slice());
        let functions = [
            (FixedBytes::from([0x61, 0x7b, 0xa0, 0x37]), vec![WordRule::IsValue(value), WordRule::Charged(asset), WordRule::IsAccount, WordRule::IsValue(U256::ZERO)]),
            (FixedBytes::from([0x69, 0x32, 0x8d, 0xec]), vec![WordRule::IsValue(value), WordRule::Any, WordRule::IsAccount]),
        ];
        assert_eq!(
            call_rules_config(&functions).as_ref(),
            hex!("000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001a0617ba03700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000003000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000069328dec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        // the call's hash is of no value and the calldata as it is sent
        let call = hex!("617ba037000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f5e10000000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(keccak256((U256::ZERO, keccak256(call)).abi_encode()), b256!("607f2975b8dddb42774a6aedddf7168667808e32e98f70f542b9c8ff6405d295"));
        // the five kinds, as the decoder numbers them
        let kinds: Vec<U256> = [WordRule::IsAccount, WordRule::IsValue(U256::from(7u8)), WordRule::AtMost(U256::from(7u8)), WordRule::Charged(asset), WordRule::Any]
            .iter()
            .map(|r| r.encode().0)
            .collect();
        assert_eq!(kinds, (0u8..5).map(U256::from).collect::<Vec<_>>());
    }

}
