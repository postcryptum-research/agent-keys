// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPolicy} from "kernel/src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {CallType, ExecMode, ExecType, ValidAfter, ValidUntil, packValidationData} from "kernel/src/types/Types.sol";
import {
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT,
    MODULE_TYPE_POLICY,
    SIG_VALIDATION_FAILED_UINT
} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
// The decoder Kernel itself executes with: the policy must read a call
// exactly the way the account will run it.
import {LibERC7579} from "kernel/lib/solady/src/accounts/LibERC7579.sol";

import {SafeNonceAssert} from "./SafeNonceAssert.sol";

/// The one Kernel view the policy reads at install time: which EntryPoint
/// the account answers to, so that it can never become an agent's target.
interface IKernelEntryPoint {
    function entrypoint() external view returns (address);
}

/// @title AgentPolicy
/// @notice Kernel permission policy that bounds what an agent's key may do.
///
/// Installed next to `P256Signer` under one permission id, it turns the
/// hardware key from "owner" into "operator with a mandate":
///  - only `execute` (single call or batch, revert-on-failure); no
///    delegatecall;
///  - every call on the (target, selector) allow-list; selector `0x00000000`
///    stands for a plain value transfer and admits empty calldata only
///    (1 to 3 bytes, or a longer body that starts with four zero bytes,
///    would run the target's fallback);
///  - `value` capped per operation and, with the gas the account pays for
///    itself, by a total budget;
///  - ERC-20 `transfer` / `transferFrom` / `approve` / `increaseAllowance`
///    amounts capped per operation and by a budget per token; an
///    allow-listed token selector without a token limit is refused, and a
///    token with a limit is callable through these four functions only: a
///    mandate with another entry on it (`permit`, a `mint`, a vault's
///    `withdraw`) would move the token past its limit and is refused at
///    install;
///  - a time window `[validAfter, validUntil]` that the EntryPoint enforces:
///    several permissions for the same agent key, each with its own window,
///    budget and allow-list, make a schedule ("weekdays: up to X on these
///    contracts; the 1st: payroll up to Y");
///  - the account itself, its EntryPoint, this policy (except its two
///    x402 entry points) and Permit2 are never valid targets: all are
///    refused at install, and all but the EntryPoint again at validation
///    (it is not re-checked there, see `_judge`). No mandate, however
///    written, lets the agent widen its own permission, replace the root key
///    or drain the deposit.
///
///  - optionally, per token, a list of payees: with one, `transfer` and
///    `transferFrom` may only pay a listed address, `approve` and
///    `increaseAllowance` may only name a listed spender, and an x402
///    authorization may only pay a listed address. A token without a list
///    is bound in amount only, as before: the agent picks the recipient.
///    A listed spender can move what it was approved for wherever it likes;
///    list a spender only if you would list everyone it pays.
///
/// Safe pass-through: an allow-list entry `(safe, execTransaction)` lets the
/// agent drive a Safe that this account owns (Olas / Jinn service Safes),
/// with a pre-validated `v = 1` signature — no ERC-1271 needed. The policy
/// judges the call *inside* the Safe transaction against the same mandate.
/// `gasPrice` must be 0 (otherwise the Safe pays a refund out of its own
/// funds to a receiver the agent picks) and Safes do not nest. `operation`
/// must be CALL, or DELEGATECALL into an allow-listed
/// `(multiSendCallOnly, multiSend)` batch whose every leg is a CALL that
/// passes the mandate. Each Safe transaction must come as a Kernel batch
/// `[SafeNonceAssert.check(safe, n), safe.execTransaction(...)]`: a `v = 1`
/// signature does not commit to the Safe nonce, and the assertion makes a
/// replay revert on-chain.
///
/// One allow-list entry admits its call directly, through a Safe and as a
/// batch leg alike; curate it with that in mind.
///
/// ERC-1271 signatures are refused — with one exception that keeps the
/// mandate in charge: x402 payments. The agent first *registers* an EIP-3009
/// `TransferWithAuthorization` with an ordinary operation calling
/// `x402Authorize(...)`; the mandate judges it like a token transfer (per-op
/// cap, the token's budget, shared with direct transfers) and records its
/// EIP-712 digest. Afterwards `checkSignaturePolicy` vouches for exactly
/// that digest — the hash USDC hands to `isValidSignature` — within the
/// mandate's window and the authorization's `validBefore`. Every other hash
/// (permits, Permit2, orders, other authorizations) is still refused. The
/// token itself enforces one use per nonce; `x402Reclaim` returns the budget
/// of an authorization that expired unused. docs/ERC1271.md.
///
/// The chip guarantees nobody else can be this agent; this policy guarantees
/// that even this agent, compromised, cannot exceed what it was allowed to do.
interface IERC3009State {
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}

contract AgentPolicy is IPolicy {
    struct Config {
        uint48 validUntil; // 0 = not installed
        uint32 epoch; // bumps on uninstall so stale entries die
        uint128 maxValuePerOp;
        uint128 budget;
        uint128 spent;
        uint48 validAfter; // 0 = from installation on
    }

    /// Install-time limit for one ERC-20 token. `domainSeparator` is the
    /// token's EIP-712 domain (read off-chain at install), non-zero to allow
    /// x402 / EIP-3009 payments in it — the policy cannot read the token's
    /// storage during validation.
    struct TokenCap {
        address token;
        uint128 maxPerOp;
        uint128 budget;
        bytes32 domainSeparator;
    }

    /// Install-time list of the only addresses a token's transfers,
    /// allowances and x402 payments may name. The token needs a `TokenCap`.
    struct TokenPayees {
        address token;
        address[] payees;
    }

    struct TokenLimit {
        uint128 maxPerOp;
        uint128 budget;
        uint128 spent;
        bool set;
        // true: only `Mandate.payees[token]` may be paid or approved.
        // It sits before `domainSeparator`, so `tokenLimit()` returns the
        // separator as its sixth word (the fifth before payee lists).
        bool payeesOnly;
        bytes32 domainSeparator;
    }

    /// A registered x402 authorization, keyed by its EIP-712 digest.
    struct Pending {
        uint128 value;
        uint48 validBefore;
        address token;
    }

    struct Mandate {
        mapping(address target => mapping(bytes4 selector => bool)) allowed;
        mapping(address token => TokenLimit) tokens;
        mapping(bytes32 digest => Pending) x402;
        mapping(address token => mapping(address payee => bool)) payees;
    }

    error InvalidConfig();
    /// An allow-list entry the agent must never have (the account, its
    /// EntryPoint, this policy outside x402).
    error ForbiddenTarget(address target, bytes4 selector);
    /// The account did not say which EntryPoint it uses, so the policy
    /// cannot keep that EntryPoint out of the allow-list.
    error UnknownEntryPoint();
    error X402NotRegistered();
    error X402StillLive();
    error X402Settled();

    event X402Authorized(
        address indexed account,
        address indexed token,
        address indexed to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    );
    event X402Reclaimed(address indexed account, bytes32 indexed id, bytes32 digest, uint256 value);

    event AgentPolicySet(
        address indexed account, bytes32 indexed id, uint48 validUntil, uint128 maxValuePerOp, uint128 budget
    );

    /// `Safe.execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
    bytes4 public constant SAFE_EXEC_TRANSACTION = 0x6a761202;
    /// `MultiSend(CallOnly).multiSend(bytes)`
    bytes4 public constant MULTI_SEND = 0x8d80ff0a;
    /// `SafeNonceAssert.check(address,uint256)`
    bytes4 public constant NONCE_CHECK = SafeNonceAssert.check.selector;

    bytes4 internal constant ERC20_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    bytes4 internal constant ERC20_TRANSFER_FROM = 0x23b872dd; // transferFrom(address,address,uint256)
    bytes4 internal constant ERC20_APPROVE = 0x095ea7b3; // approve(address,uint256)
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = 0x39509351; // increaseAllowance(address,uint256)

    /// EIP-3009 `TransferWithAuthorization(address from,address to,uint256 value,
    /// uint256 validAfter,uint256 validBefore,bytes32 nonce)` (== USDC's).
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    /// Where a call sits: issued by the account, by the account right after
    /// a matching nonce assertion, by a Safe, or as a Safe batch leg.
    uint8 internal constant FROM_ACCOUNT = 0;
    uint8 internal constant FROM_ACCOUNT_GUARDED = 1;
    uint8 internal constant FROM_SAFE = 2;
    uint8 internal constant FROM_BATCH = 3;

    /// The SafeNonceAssert every Safe transaction must be paired with.
    address public immutable NONCE_ASSERT;

    mapping(address account => mapping(bytes32 id => Config)) public configs;
    mapping(address account => uint256) public usedIds;
    mapping(address account => mapping(bytes32 id => mapping(uint32 epoch => Mandate))) internal _mandates;

    constructor(address nonceAssert) {
        NONCE_ASSERT = nonceAssert;
    }

    /// The install data's first word — the offset of `targets` — tells the
    /// two encodings apart: seven head words, or eight with `payees`.
    /// Data whose first word is neither is refused, and so is data whose
    /// word does not match its body, so no install drops a list. That the
    /// owner sees exactly what is installed rests on the reviewing app,
    /// which accepts canonical encodings only; this contract decodes as
    /// loosely as `abi.decode` does.
    uint256 internal constant HEAD_WITHOUT_PAYEES = 7 * 32;
    uint256 internal constant HEAD_WITH_PAYEES = 8 * 32;

    /// @param data `bytes32 id ++ abi.encode(address[] targets, bytes4[] selectors,
    ///              uint128 maxValuePerOp, uint128 budget, uint48 validUntil, TokenCap[] tokens,
    ///              uint48 validAfter)`, optionally with one more parameter
    ///              `TokenPayees[] payees`. A mandate without payee lists is
    ///              encoded as before this parameter existed.
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = configs[msg.sender][id];
        if (c.validUntil != 0) revert AlreadyInitialized(msg.sender);
        (
            address[] memory targets,
            bytes4[] memory selectors,
            uint128 maxValuePerOp,
            uint128 budget,
            uint48 validUntil,
            TokenCap[] memory tokens,
            uint48 validAfter
        ) = abi.decode(data[32:], (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48));
        if (targets.length == 0 || targets.length != selectors.length || validUntil == 0 || validAfter >= validUntil) {
            revert InvalidConfig();
        }

        Mandate storage m = _mandates[msg.sender][id][c.epoch];
        address entryPoint = _entryPointOf(msg.sender);
        if (entryPoint == address(0)) revert UnknownEntryPoint();
        for (uint256 i; i < targets.length; i++) {
            if (!_targetAllowed(targets[i], selectors[i]) || targets[i] == entryPoint) {
                revert ForbiddenTarget(targets[i], selectors[i]);
            }
            m.allowed[targets[i]][selectors[i]] = true;
        }
        for (uint256 i; i < tokens.length; i++) {
            if (tokens[i].token == address(0) || m.tokens[tokens[i].token].set) revert InvalidConfig();
            m.tokens[tokens[i].token] =
                TokenLimit(tokens[i].maxPerOp, tokens[i].budget, 0, true, false, tokens[i].domainSeparator);
        }
        _installPayees(m, data[32:]);
        // A token with a limit is callable through the four metered
        // functions only (`_chargeToken`). Any other entry on it would pass
        // neither its caps nor its payee list, so the limit the owner wrote
        // down would not be one: such a mandate is refused whole.
        for (uint256 i; i < targets.length; i++) {
            if (m.tokens[targets[i]].set && !_isMetered(selectors[i])) revert InvalidConfig();
        }
        c.validUntil = validUntil;
        c.validAfter = validAfter;
        c.maxValuePerOp = maxValuePerOp;
        c.budget = budget;
        c.spent = 0;
        usedIds[msg.sender]++;
        emit AgentPolicySet(msg.sender, id, validUntil, maxValuePerOp, budget);
    }

    function _isMetered(bytes4 selector) internal pure returns (bool) {
        return selector == ERC20_TRANSFER || selector == ERC20_APPROVE || selector == ERC20_INCREASE_ALLOWANCE
            || selector == ERC20_TRANSFER_FROM;
    }

    /// @dev The optional eighth parameter. Each entry needs a capped token
    /// that has no list yet, and at least one payee; no zero address, no
    /// payee twice.
    function _installPayees(Mandate storage m, bytes calldata params) internal {
        if (params.length < 32) revert InvalidConfig();
        uint256 head = uint256(bytes32(params[0:32]));
        if (head == HEAD_WITHOUT_PAYEES) return;
        if (head != HEAD_WITH_PAYEES) revert InvalidConfig();
        (,,,,,,, TokenPayees[] memory lists) =
            abi.decode(params, (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48, TokenPayees[]));
        // the eight-word form exists to carry a list: without one, use the other
        if (lists.length == 0) revert InvalidConfig();
        for (uint256 i; i < lists.length; i++) {
            TokenLimit storage t = m.tokens[lists[i].token];
            address[] memory payees = lists[i].payees;
            if (!t.set || t.payeesOnly || payees.length == 0) revert InvalidConfig();
            t.payeesOnly = true;
            mapping(address => bool) storage listed = m.payees[lists[i].token];
            for (uint256 j; j < payees.length; j++) {
                if (payees[j] == address(0) || listed[payees[j]]) revert InvalidConfig();
                listed[payees[j]] = true;
            }
        }
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = configs[msg.sender][id];
        if (c.validUntil == 0) revert NotInitialized(msg.sender);
        c.validUntil = 0;
        c.validAfter = 0;
        c.epoch++;
        usedIds[msg.sender]--;
    }

    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address account) external view override returns (bool) {
        return usedIds[account] > 0;
    }

    function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool) {
        return _mandates[account][id][configs[account][id].epoch].allowed[target][selector];
    }

    function tokenLimit(address account, bytes32 id, address token) external view returns (TokenLimit memory) {
        return _mandates[account][id][configs[account][id].epoch].tokens[token];
    }

    /// @notice Whether the mandate lets `token` reach `payee`: true for any
    /// address when the token has no payee list.
    function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool) {
        Mandate storage m = _mandates[account][id][configs[account][id].epoch];
        return !m.tokens[token].payeesOnly || m.payees[token][payee];
    }

    /// @dev Returns `packValidationData(validAfter, validUntil)` on success so
    /// the EntryPoint enforces the window, `SIG_VALIDATION_FAILED_UINT` otherwise
    /// (which Kernel turns into a `PolicyFailed` revert, undoing any token
    /// accounting done on the way).
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        Config storage c = configs[msg.sender][id];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;

        _beginOperation();
        (bool ok, uint256 value) = _judgeExecute(_mandates[msg.sender][id][c.epoch], userOp.callData);
        if (!ok || value > c.maxValuePerOp) return SIG_VALIDATION_FAILED_UINT;

        // Without a paymaster the account pays for gas out of its own
        // deposit: count the most it can be charged against the budget.
        uint256 charged = value;
        if (userOp.paymasterAndData.length == 0) charged += _maxGasCost(userOp);
        uint256 spent = c.spent + charged;
        if (spent > c.budget) return SIG_VALIDATION_FAILED_UINT;
        c.spent = uint128(spent);

        return packValidationData(ValidAfter.wrap(c.validAfter), ValidUntil.wrap(c.validUntil));
    }

    /// @dev The only message an agent may "sign": a registered x402
    /// authorization's digest — the hash the token passes to
    /// `isValidSignature` (Kernel hands policies the unwrapped hash). The
    /// caller is not checked: facilitators verify with `eth_call` from their
    /// own address, and the digest is bound to the token's domain anyway.
    function checkSignaturePolicy(bytes32 id, address, bytes32 hash, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        Config storage c = configs[msg.sender][id];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;
        Pending storage p = _mandates[msg.sender][id][c.epoch].x402[hash];
        if (p.value == 0) return SIG_VALIDATION_FAILED_UINT;
        uint48 until = p.validBefore < c.validUntil ? p.validBefore : c.validUntil;
        return packValidationData(ValidAfter.wrap(c.validAfter), ValidUntil.wrap(until));
    }

    /// @notice Executed after validation registered the authorization: only
    /// leaves a record for wallets and `x402 reclaim`.
    function x402Authorize(
        address token,
        address, /* from: the account itself, checked in validation */
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) external {
        emit X402Authorized(msg.sender, token, to, value, validAfter, validBefore, nonce);
    }

    /// @notice Return to the budget an authorization that can never settle
    /// any more: past `validBefore` and unused at the token. Only the account
    /// can, for its own records.
    function x402Reclaim(
        bytes32 id,
        address token,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) external {
        Config storage c = configs[msg.sender][id];
        Mandate storage m = _mandates[msg.sender][id][c.epoch];
        TokenLimit storage t = m.tokens[token];
        bytes32 digest = _x402Digest(t.domainSeparator, msg.sender, to, value, validAfter, validBefore, nonce);
        Pending storage p = m.x402[digest];
        if (p.value == 0) revert X402NotRegistered();
        if (block.timestamp < validBefore) revert X402StillLive();
        if (IERC3009State(token).authorizationState(msg.sender, nonce)) revert X402Settled();
        t.spent -= p.value;
        emit X402Reclaimed(msg.sender, id, digest, p.value);
        delete m.x402[digest];
    }

    function x402Pending(address account, bytes32 id, bytes32 digest) external view returns (Pending memory) {
        return _mandates[account][id][configs[account][id].epoch].x402[digest];
    }

    function _x402Digest(
        bytes32 domainSeparator,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @dev Validation of `x402Authorize(...)`: judged like a transfer of the
    /// token (per-op cap, shared budget), then the digest is recorded.
    function _registerX402(Mandate storage m, bytes calldata d) internal returns (bool) {
        if (d.length != 4 + 7 * 32) return false;
        (address token, address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce) =
            abi.decode(d[4:], (address, address, address, uint256, uint256, uint256, bytes32));
        if (from != msg.sender) return false; // the account checkUserOpPolicy runs for
        TokenLimit storage t = m.tokens[token];
        if (!t.set || t.domainSeparator == bytes32(0)) return false;
        if (value == 0 || validBefore > type(uint48).max) return false;
        if (_movedThisOperation(token, value) > t.maxPerOp) return false;
        if (t.payeesOnly && !m.payees[token][to]) return false;
        uint256 spent = t.spent + value;
        if (spent > t.budget) return false;
        bytes32 digest = _x402Digest(t.domainSeparator, from, to, value, validAfter, validBefore, nonce);
        Pending storage p = m.x402[digest];
        if (p.value != 0) return false;
        t.spent = uint128(spent);
        m.x402[digest] = Pending(uint128(value), uint48(validBefore), token);
        return true;
    }

    /// @dev Transient slot of the per-account operation counter; laid out as
    /// a mapping keyed by the account (`keccak256(account ‖ slot)`), the
    /// form ERC-7562 lets a module touch during validation.
    uint256 internal constant OPERATION_SEQ = uint256(keccak256("agent-keys.AgentPolicy.operationSeq"));

    /// @dev Starts the per-operation token totals afresh. Transient storage
    /// lives for the whole transaction and a bundle validates many
    /// operations in one, so the totals are keyed by a counter that moves
    /// on with every `checkUserOpPolicy` call for the account.
    function _beginOperation() internal {
        uint256 seqSlot = uint256(keccak256(abi.encode(msg.sender, OPERATION_SEQ)));
        assembly ("memory-safe") {
            tstore(seqSlot, add(tload(seqSlot), 1))
        }
    }

    /// @dev Adds `amount` to what this operation has moved of `token` so far
    /// (transfers, approvals and x402 registrations alike, in every leg) and
    /// returns the total, for the caller to hold against `maxPerOp`: the cap
    /// is per operation, as `maxValuePerOp` is for native value.
    function _movedThisOperation(address token, uint256 amount) internal returns (uint256 total) {
        uint256 seqSlot = uint256(keccak256(abi.encode(msg.sender, OPERATION_SEQ)));
        uint256 seq;
        assembly ("memory-safe") {
            seq := tload(seqSlot)
        }
        uint256 slot = uint256(keccak256(abi.encode(msg.sender, keccak256(abi.encode(seq, token)))));
        uint256 before;
        assembly ("memory-safe") {
            before := tload(slot)
        }
        total = before + amount;
        assembly ("memory-safe") {
            tstore(slot, total)
        }
    }

    /// @dev `(verificationGasLimit + callGasLimit + preVerificationGas) *
    /// maxFeePerGas` — the EntryPoint's required prefund without a paymaster.
    function _maxGasCost(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        uint256 limits = uint256(userOp.accountGasLimits);
        uint256 gas = (limits >> 128) + uint128(limits) + userOp.preVerificationGas;
        return gas * uint128(uint256(userOp.gasFees));
    }

    /// @dev Accepts `execute(mode, executionCalldata)` with a single call or a
    /// batch, default exec type, and judges every call; returns the native
    /// value the operation moves.
    function _judgeExecute(Mandate storage m, bytes calldata callData) internal returns (bool, uint256) {
        // selector + mode + offset + length is the smallest well-formed call
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Account.execute.selector) return (false, 0);
        (CallType callType, ExecType execType,,) = ExecLib.decode(ExecMode.wrap(bytes32(callData[4:36])));
        // A "try" batch would let a failed nonce assertion pass silently.
        if (!(execType == EXECTYPE_DEFAULT)) return (false, 0);

        uint256 start = 4 + uint256(bytes32(callData[36:68]));
        if (callData.length < start + 32) return (false, 0);
        uint256 length = uint256(bytes32(callData[start:start + 32]));
        if (callData.length < start + 32 + length) return (false, 0);
        bytes calldata executionData = callData[start + 32:start + 32 + length];

        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
            return _judge(m, target, value, data, FROM_ACCOUNT);
        }
        if (callType == CALLTYPE_BATCH) return _judgeAccountBatch(m, LibERC7579.decodeBatch(executionData));
        return (false, 0);
    }

    /// @dev The account's own batch. A Safe transaction is admitted only as
    /// the leg right after `SafeNonceAssert.check(thatSafe, n)`.
    function _judgeAccountBatch(Mandate storage m, bytes32[] calldata pointers) internal returns (bool, uint256 moved) {
        if (pointers.length == 0) return (false, 0);
        uint256 i;
        while (i < pointers.length) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
            bool ok;
            uint256 legMoved;
            if (target == NONCE_ASSERT) {
                (ok, legMoved) = _judgeGuarded(m, pointers, i, value, data);
                i += 2;
            } else {
                (ok, legMoved) = _judge(m, target, value, data, FROM_ACCOUNT);
                i += 1;
            }
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Leg `i` is a nonce assertion; leg `i + 1` must be the Safe
    /// transaction it guards.
    function _judgeGuarded(Mandate storage m, bytes32[] calldata pointers, uint256 i, uint256 value, bytes calldata data)
        internal
        returns (bool, uint256)
    {
        if (value != 0 || data.length != 68 || bytes4(data[0:4]) != NONCE_CHECK || i + 1 >= pointers.length) {
            return (false, 0);
        }
        address guarded = address(uint160(uint256(bytes32(data[4:36]))));
        (address safe, uint256 safeValue, bytes calldata safeData) = LibERC7579.getExecution(pointers, i + 1);
        if (safe != guarded || _selector(safeData) != SAFE_EXEC_TRANSACTION) return (false, 0);
        return _judge(m, safe, safeValue, safeData, FROM_ACCOUNT_GUARDED);
    }

    /// @dev Decides one call and returns the total value it moves, including
    /// what moves inside it (a Safe transaction, a batch's legs). Token
    /// amounts are charged to their budgets on the way.
    function _judge(Mandate storage m, address target, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        bytes4 selector = _selector(data);
        // The zero selector stands for a plain transfer, which carries no
        // calldata. 1–3 bytes would run the target's fallback, and so would
        // a longer body that happens to start with four zero bytes.
        if (selector == bytes4(0) && data.length != 0) return (false, 0);
        if (!m.allowed[target][selector]) return (false, 0);
        // Install refuses these; refused again here so that no mandate, in
        // any version's storage, can reach the account or the policy itself.
        // The EntryPoint is refused at install only, on purpose: checking it
        // here would cost a staticcall per operation, and every mandate this
        // version holds went through that install-time filter.
        if (!_targetAllowed(target, selector)) return (false, 0);
        // A batch is only meaningful delegatecalled by a Safe (below); called
        // any other way its legs would run as the batch contract.
        if (selector == MULTI_SEND) return (false, 0);
        if (selector == SAFE_EXEC_TRANSACTION) return _judgeSafe(m, value, data, from);
        // x402: registering an authorization is the account's own call only
        if (target == address(this) && selector == this.x402Authorize.selector) {
            return (from == FROM_ACCOUNT && value == 0 && _registerX402(m, data)) ? (true, 0) : (false, 0);
        }
        if (!_chargeToken(m, target, selector, data)) return (false, 0);
        return (true, value);
    }

    /// @dev Uniswap's Permit2 where it is deployed by the usual CREATE2
    /// factory: Ethereum, Base and their testnets among others. Not every
    /// chain: on zkSync-style chains it sits elsewhere. Check it before this
    /// policy is deployed to a chain it has not been on.
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// @dev Targets no agent may ever have, whatever the allow-list says: the
    /// account itself (Kernel's own `grantAccess`, `installValidations`,
    /// `changeRootValidator`, `execute`: the mandate would widen or replace
    /// itself) and this policy, except the two x402 entry points the account
    /// calls on purpose. `msg.sender` is the account in both callers.
    /// And Permit2: it holds one allowance per token and its own `approve`
    /// names who may pull it, a call this policy does not read, so through
    /// it a token would leave past its cap and its payee list. Refused until
    /// the policy meters Permit2's calls. This closes the one well-known
    /// contract of that shape, not the shape: any allow-listed contract
    /// that holds an allowance from the account can move it.
    function _targetAllowed(address target, bytes4 selector) internal view returns (bool) {
        if (target == msg.sender || target == PERMIT2) return false;
        if (target == address(this)) {
            return selector == this.x402Authorize.selector || selector == this.x402Reclaim.selector;
        }
        return true;
    }

    /// @dev The account's EntryPoint, read from Kernel at install so that
    /// `withdrawTo` and friends on the account's deposit can never be
    /// allow-listed. Zero when the account does not answer (not a Kernel):
    /// the install is then refused, since the check could not be made.
    function _entryPointOf(address account) internal view returns (address) {
        (bool ok, bytes memory ret) = account.staticcall(abi.encodeWithSelector(IKernelEntryPoint.entrypoint.selector));
        if (!ok || ret.length < 32) return address(0);
        return abi.decode(ret, (address));
    }

    /// @dev An allow-listed Safe: the call that matters is the inner one.
    function _judgeSafe(Mandate storage m, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        // Only the account's own nonce-guarded call; Safes do not nest.
        if (from != FROM_ACCOUNT_GUARDED) return (false, 0);
        (bool decoded, address to, uint256 innerValue, uint256 operation, bytes calldata inner) = _decodeSafeExec(data);
        if (!decoded) return (false, 0);
        if (operation == 0) {
            (ok, moved) = _judge(m, to, innerValue, inner, FROM_SAFE);
        } else if (operation == 1 && innerValue == 0 && _selector(inner) == MULTI_SEND && m.allowed[to][MULTI_SEND]) {
            (ok, moved) = _judgeBatch(m, inner);
        }
        return ok ? (true, value + moved) : (false, 0);
    }

    /// @dev ERC-20 accounting: `transfer` / `approve` / `increaseAllowance`
    /// carry the amount in argument 1 and who gets it (the recipient, the
    /// spender) in argument 0; `transferFrom` carries them in arguments 2
    /// and 1. Any other selector passes untouched — unless the target is a
    /// token with a limit: such a token moves only through the four
    /// functions metered here, so that `permit`, `transferWithAuthorization`,
    /// a vault's `withdraw` or anything else allow-listed on it cannot move
    /// it past its caps or pay an address its payee list does not name.
    /// Install refuses such a mandate; this is the same rule at validation.
    function _chargeToken(Mandate storage m, address token, bytes4 selector, bytes calldata data)
        internal
        returns (bool)
    {
        uint256 arg;
        if (selector == ERC20_TRANSFER || selector == ERC20_APPROVE || selector == ERC20_INCREASE_ALLOWANCE) arg = 1;
        else if (selector == ERC20_TRANSFER_FROM) arg = 2;

        TokenLimit storage t = m.tokens[token];
        if (arg == 0) return !t.set;
        if (!t.set) return false;
        uint256 end = 4 + 32 * (arg + 1);
        if (data.length < end) return false;
        uint256 amount = uint256(bytes32(data[end - 32:end]));
        if (t.payeesOnly) {
            // the word before the amount; a token reads its low 160 bits, so
            // anything above them would name one address here and pay another
            uint256 payee = uint256(bytes32(data[end - 64:end - 32]));
            if (payee >> 160 != 0 || !m.payees[token][address(uint160(payee))]) return false;
        }
        if (_movedThisOperation(token, amount) > t.maxPerOp) return false;
        uint256 spent = t.spent + amount;
        if (spent > t.budget) return false;
        t.spent = uint128(spent);
        return true;
    }

    /// @dev `multiSend(bytes transactions)`, each transaction packed as
    /// `operation (1) ‖ to (20) ‖ value (32) ‖ dataLength (32) ‖ data`.
    /// Every leg must be a CALL the mandate accepts.
    function _judgeBatch(Mandate storage m, bytes calldata d) internal returns (bool, uint256 moved) {
        (bool ok, bytes calldata txs) = _batchTransactions(d);
        if (!ok || txs.length == 0) return (false, 0);
        uint256 i;
        while (i < txs.length) {
            uint256 legMoved;
            (ok, legMoved, i) = _judgeLeg(m, txs, i);
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Judges the batch leg at `i` and returns where the next one starts.
    function _judgeLeg(Mandate storage m, bytes calldata txs, uint256 i)
        internal
        returns (bool ok, uint256 moved, uint256 next)
    {
        (bool parsed, address to, uint256 value, bytes calldata data) = _leg(txs, i);
        if (!parsed) return (false, 0, 0);
        (ok, moved) = _judge(m, to, value, data, FROM_BATCH);
        next = i + 85 + data.length;
    }

    /// @dev The `bytes transactions` argument of a `multiSend` call.
    function _batchTransactions(bytes calldata d) internal pure returns (bool ok, bytes calldata txs) {
        txs = d[0:0];
        if (d.length < 68) return (false, txs);
        uint256 offset = uint256(bytes32(d[4:36]));
        if (offset > d.length) return (false, txs);
        uint256 start = 4 + offset;
        if (d.length < start + 32) return (false, txs);
        uint256 length = uint256(bytes32(d[start:start + 32]));
        if (length > d.length || d.length < start + 32 + length) return (false, txs);
        return (true, d[start + 32:start + 32 + length]);
    }

    /// @dev The batch leg starting at `i`; CALL legs only.
    function _leg(bytes calldata txs, uint256 i)
        internal
        pure
        returns (bool ok, address to, uint256 value, bytes calldata data)
    {
        data = txs[0:0];
        if (txs.length < i + 85 || uint8(txs[i]) != 0) return (false, address(0), 0, data);
        to = address(bytes20(txs[i + 1:i + 21]));
        value = uint256(bytes32(txs[i + 21:i + 53]));
        uint256 length = uint256(bytes32(txs[i + 53:i + 85]));
        if (length > txs.length || txs.length < i + 85 + length) return (false, address(0), 0, data);
        data = txs[i + 85:i + 85 + length];
        ok = true;
    }

    /// @dev Reads the parts of a `Safe.execTransaction` call the policy rules
    /// on, straight from the ABI head (the Safe decodes the same words), and
    /// refuses gas refunds.
    function _decodeSafeExec(bytes calldata d)
        internal
        pure
        returns (bool ok, address to, uint256 value, uint256 operation, bytes calldata inner)
    {
        inner = d[0:0];
        // selector + ten head words
        if (d.length < 324) return (false, address(0), 0, 0, inner);
        to = address(uint160(uint256(bytes32(d[4:36]))));
        value = uint256(bytes32(d[36:68]));
        uint256 dataOffset = uint256(bytes32(d[68:100]));
        operation = uint256(bytes32(d[100:132]));
        if (uint256(bytes32(d[196:228])) != 0) return (false, address(0), 0, 0, inner); // gasPrice: no refunds

        if (dataOffset > d.length) return (false, address(0), 0, 0, inner);
        uint256 start = 4 + dataOffset;
        if (d.length < start + 32) return (false, address(0), 0, 0, inner);
        uint256 length = uint256(bytes32(d[start:start + 32]));
        if (length > d.length || d.length < start + 32 + length) return (false, address(0), 0, 0, inner);
        inner = d[start + 32:start + 32 + length];
        ok = true;
    }

    /// @dev `0x00000000` stands for "no calldata": a plain value transfer.
    function _selector(bytes calldata data) internal pure returns (bytes4) {
        return data.length >= 4 ? bytes4(data[0:4]) : bytes4(0);
    }
}
