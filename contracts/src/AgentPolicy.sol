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
import {IVenueDecoder} from "./venues/IVenueDecoder.sol";

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
        // The budgets' window in seconds; 0 = one budget for the mandate's
        // whole life. Windows are counted from the Unix epoch: with 86400,
        // a day from midnight UTC.
        uint32 period;
        // The window `spent` counts for, plus one; 0 before the first.
        uint48 periodSeen;
    }

    /// A trading venue of a mandate (issue #80): the decoder the policy asks
    /// about the venue's orders, bound by its code, and the hash of the
    /// owner's config for it.
    struct Venue {
        address decoder;
        bytes32 codeHash;
        bytes32 configHash;
    }

    /// A decoder's answer about an order; `ok` false when there is none.
    struct Judged {
        bool ok;
        address token;
        uint256 mostSold;
        uint48 notBefore;
        uint48 validTo;
        bytes32 digest;
    }

    struct VenuePin {
        bytes32 codeHash;
        bytes32 configHash;
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
        // true: only the payees listed for the token may be paid or approved.
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
    error OrderNotRegistered();
    error OrderStillLive();
    error OrderTouched();
    error NotTheVenue();

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
    event OrderRegistered(address indexed account, address indexed decoder, bytes order);
    event OrderReclaimed(address indexed account, bytes32 indexed id, bytes32 digest, uint256 value);

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

    /// Storage layout. Validation reads and writes this contract's storage
    /// on the account's behalf, and ERC-7562 lets a bundler admit that only
    /// for slots that belong to the account: `keccak256(account ‖ x) + n`
    /// with a small `n`. So the account is the innermost key of every
    /// mapping, and everything else that names an entry (the permission id,
    /// its epoch, a target and selector, a token, a payee, a digest) is
    /// hashed into the outer key first. A nested mapping with the account
    /// outermost holds the same data in slots a rule-enforcing bundler
    /// refuses (issue #83).
    mapping(bytes32 id => mapping(address account => Config)) internal _configs;
    mapping(address account => uint256) public usedIds;
    /// key: `keccak256(mandate, target, selector)`
    mapping(bytes32 key => mapping(address account => bool)) internal _allowed;
    /// key: `keccak256(mandate, token)`
    mapping(bytes32 key => mapping(address account => TokenLimit)) internal _tokens;
    /// key: `keccak256(mandate, digest)`
    mapping(bytes32 key => mapping(address account => Pending)) internal _x402;
    /// key: `keccak256(mandate, token, payee)`
    mapping(bytes32 key => mapping(address account => bool)) internal _payees;
    /// key: `keccak256(mandate, token)`. The window the token's `spent`
    /// counts for, plus one. Beside `TokenLimit` and not in it, so that what
    /// `tokenLimit()` returns keeps its shape.
    mapping(bytes32 key => mapping(address account => uint48)) internal _tokenPeriod;
    /// key: `keccak256(mandate, digest)`. The window a registered
    /// authorization or order was charged in, plus one.
    mapping(bytes32 key => mapping(address account => uint48)) internal _chargedIn;
    /// key: `keccak256(mandate, decoder)`
    mapping(bytes32 key => mapping(address account => VenuePin)) internal _venues;
    /// The venues an account has ever pinned in a mandate: each venue's own
    /// contract and its decoder. None of them is a target for the agent
    /// under any mandate of the account, whichever was installed first:
    /// at the venue itself an order could be signed past the decoder
    /// (CoW: `setPreSignature`), and the venue holds the owner's allowance.
    /// Never cleared: an address that was a venue stays out of reach.
    mapping(address place => mapping(address account => bool)) internal _venuePlaces;

    constructor(address nonceAssert) {
        NONCE_ASSERT = nonceAssert;
    }

    /// @dev One installation of a permission: the id and its epoch, which
    /// moves on at uninstall so that nothing of an earlier installation is
    /// found again. Part of every outer key below.
    function _mandate(bytes32 id, uint32 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, epoch));
    }

    function _allowedKey(bytes32 m, address target, bytes4 selector) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, target, selector));
    }

    function _payeeKey(bytes32 m, address token, address payee) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, token, payee));
    }

    function _token(address account, bytes32 m, address token) internal view returns (TokenLimit storage) {
        return _tokens[keccak256(abi.encode(m, token))][account];
    }

    function _venue(address account, bytes32 m, address decoder) internal view returns (VenuePin storage) {
        return _venues[keccak256(abi.encode(m, decoder))][account];
    }

    function _pending(address account, bytes32 m, bytes32 digest) internal view returns (Pending storage) {
        return _x402[keccak256(abi.encode(m, digest))][account];
    }

    /// @notice The permission's limits and counters, in the order of `Config`.
    function configs(address account, bytes32 id)
        external
        view
        returns (uint48 validUntil, uint32 epoch, uint128 maxValuePerOp, uint128 budget, uint128 spent, uint48 validAfter)
    {
        Config storage c = _configs[id][account];
        return (c.validUntil, c.epoch, c.maxValuePerOp, c.budget, c.spent, c.validAfter);
    }

    /// @notice The budgets' window of a permission in seconds (0: none) and
    /// the window its native `spent` counts for, plus one.
    function period(address account, bytes32 id) external view returns (uint32 seconds_, uint48 seen) {
        Config storage c = _configs[id][account];
        return (c.period, c.periodSeen);
    }

    /// @notice The pinned code hash and config hash of a venue's decoder
    /// under the permission; zeros when it is not one of its venues.
    /// @notice Whether `place` is, or ever was, a venue's own contract or a
    /// venue's decoder in a mandate of `account`: then no mandate of the
    /// account may name it as a target.
    function venuePlace(address account, address place) external view returns (bool) {
        return _venuePlaces[place][account];
    }

    function venue(address account, bytes32 id, address decoder) external view returns (VenuePin memory) {
        return _venue(account, _mandate(id, _configs[id][account].epoch), decoder);
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
    /// Ten words: `payees` (which may then be empty), `uint32 period` and
    /// `Venue[] venues`. For a mandate with a budget per period, with
    /// venues, or both; one with neither is encoded in a shorter form.
    uint256 internal constant HEAD_WITH_TRADING = 10 * 32;

    /// @param data `bytes32 id ++ abi.encode(address[] targets, bytes4[] selectors,
    ///              uint128 maxValuePerOp, uint128 budget, uint48 validUntil, TokenCap[] tokens,
    ///              uint48 validAfter)`, optionally with one more parameter
    ///              `TokenPayees[] payees`, or with three more:
    ///              `TokenPayees[] payees, uint32 period, Venue[] venues`. A
    ///              mandate is encoded in the shortest form that holds it.
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = _configs[id][msg.sender];
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

        bytes32 m = _mandate(id, c.epoch);
        address entryPoint = _entryPointOf(msg.sender);
        if (entryPoint == address(0)) revert UnknownEntryPoint();
        for (uint256 i; i < targets.length; i++) {
            if (!_targetAllowed(targets[i], selectors[i]) || targets[i] == entryPoint) {
                revert ForbiddenTarget(targets[i], selectors[i]);
            }
            _allowed[_allowedKey(m, targets[i], selectors[i])][msg.sender] = true;
        }
        for (uint256 i; i < tokens.length; i++) {
            if (tokens[i].token == address(0) || _token(msg.sender, m, tokens[i].token).set) revert InvalidConfig();
            _tokens[keccak256(abi.encode(m, tokens[i].token))][msg.sender] =
                TokenLimit(tokens[i].maxPerOp, tokens[i].budget, 0, true, false, tokens[i].domainSeparator);
        }
        _installPayees(m, data[32:]);
        c.period = _installTrading(m, data[32:], targets);
        // A token with a limit is callable through the four metered
        // functions only (`_chargeToken`). Any other entry on it would pass
        // neither its caps nor its payee list, so the limit the owner wrote
        // down would not be one: such a mandate is refused whole.
        for (uint256 i; i < targets.length; i++) {
            if (_token(msg.sender, m, targets[i]).set && !_isMetered(selectors[i])) revert InvalidConfig();
        }
        c.validUntil = validUntil;
        c.validAfter = validAfter;
        c.maxValuePerOp = maxValuePerOp;
        c.budget = budget;
        c.spent = 0;
        c.periodSeen = 0;
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
    function _installPayees(bytes32 m, bytes calldata params) internal {
        if (params.length < 32) revert InvalidConfig();
        uint256 head = uint256(bytes32(params[0:32]));
        if (head == HEAD_WITHOUT_PAYEES) return;
        TokenPayees[] memory lists;
        if (head == HEAD_WITH_PAYEES) {
            (,,,,,,, lists) =
                abi.decode(params, (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48, TokenPayees[]));
            // the eight-word form exists to carry a list: without one, use the other
            if (lists.length == 0) revert InvalidConfig();
        } else if (head == HEAD_WITH_TRADING) {
            (,,,,,,, lists,,) = abi.decode(
                params,
                (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48, TokenPayees[], uint32, Venue[])
            );
        } else {
            revert InvalidConfig();
        }
        for (uint256 i; i < lists.length; i++) {
            TokenLimit storage t = _token(msg.sender, m, lists[i].token);
            address[] memory payees = lists[i].payees;
            if (!t.set || t.payeesOnly || payees.length == 0) revert InvalidConfig();
            t.payeesOnly = true;
            for (uint256 j; j < payees.length; j++) {
                bytes32 key = _payeeKey(m, lists[i].token, payees[j]);
                if (payees[j] == address(0) || _payees[key][msg.sender]) revert InvalidConfig();
                _payees[key][msg.sender] = true;
            }
        }
    }

    /// @dev The ten-word form's last two parameters. A venue's decoder must
    /// be the code the owner pinned, once per mandate; the venue's own
    /// contract (CoW's settlement, with `setPreSignature` on it) may not be
    /// among the mandate's targets: only orders the decoder judged reach it.
    function _installTrading(bytes32 m, bytes calldata params, address[] memory targets)
        internal
        returns (uint32 period_)
    {
        if (uint256(bytes32(params[0:32])) != HEAD_WITH_TRADING) return 0;
        Venue[] memory venues;
        (,,,,,,,, period_, venues) = abi.decode(
            params, (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48, TokenPayees[], uint32, Venue[])
        );
        // the ten-word form exists to carry one of the two
        if (period_ == 0 && venues.length == 0) revert InvalidConfig();
        for (uint256 i; i < venues.length; i++) {
            address decoder = venues[i].decoder;
            VenuePin storage v = _venue(msg.sender, m, decoder);
            if (
                v.codeHash != bytes32(0) || venues[i].configHash == bytes32(0) || decoder.code.length == 0
                    || decoder.codehash != venues[i].codeHash
            ) revert InvalidConfig();
            (v.codeHash, v.configHash) = (venues[i].codeHash, venues[i].configHash);
            address place = IVenueDecoder(decoder).venue();
            // this mandate's own targets were judged before the venue was known
            for (uint256 j; j < targets.length; j++) {
                if (targets[j] == place || targets[j] == decoder) revert ForbiddenTarget(targets[j], bytes4(0));
            }
            // a venue that is the account or this policy would close the account's own paths
            if (place == msg.sender || place == address(this) || decoder == address(this)) revert InvalidConfig();
            (_venuePlaces[place][msg.sender], _venuePlaces[decoder][msg.sender]) = (true, true);
        }
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = _configs[id][msg.sender];
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
        return _allowed[_allowedKey(_mandate(id, _configs[id][account].epoch), target, selector)][account];
    }

    function tokenLimit(address account, bytes32 id, address token) external view returns (TokenLimit memory) {
        return _token(account, _mandate(id, _configs[id][account].epoch), token);
    }

    /// @notice Whether the mandate lets `token` reach `payee`: true for any
    /// address when the token has no payee list.
    function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool) {
        bytes32 m = _mandate(id, _configs[id][account].epoch);
        return !_token(account, m, token).payeesOnly || _payees[_payeeKey(m, token, payee)][account];
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
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;

        _beginOperation();
        (bool inWindow, uint48 from, uint48 until) = _enterPeriod(c, userOp.signature);
        if (!inWindow) return SIG_VALIDATION_FAILED_UINT;
        (bool ok, uint256 value) = _judgeExecute(_mandate(id, c.epoch), userOp.callData);
        if (!ok || value > c.maxValuePerOp) return SIG_VALIDATION_FAILED_UINT;

        // Without a paymaster the account pays for gas out of its own
        // deposit: count the most it can be charged against the budget.
        uint256 charged = value;
        if (userOp.paymasterAndData.length == 0) charged += _maxGasCost(userOp);
        uint256 spent = c.spent + charged;
        if (spent > c.budget) return SIG_VALIDATION_FAILED_UINT;
        c.spent = uint128(spent);

        // an order registered in this operation says "not before" and ends
        // at its `validTo`: an order that can no longer be filled is not
        // registered
        uint48 notBefore = uint48(_perOperation(NOT_BEFORE));
        if (notBefore > from) from = notBefore;
        uint256 notAfter = _perOperation(NOT_AFTER);
        if (notAfter != 0 && notAfter - 1 < until) until = uint48(notAfter - 1);
        if (from >= until) return SIG_VALIDATION_FAILED_UINT;
        return packValidationData(ValidAfter.wrap(from), ValidUntil.wrap(until));
    }

    /// @dev The window this operation is valid in and, for a mandate with a
    /// budget per period, the move into the period the operation names.
    ///
    /// Validation may not read the clock (ERC-7562), so the operation says
    /// which period it is for, in the six bytes Kernel hands this policy as
    /// its part of the signature, and the validity window returned is cut to
    /// that period: the EntryPoint, which may read the clock, refuses the
    /// operation at any other time. A period earlier than one already seen
    /// is refused; a later one starts its budgets afresh.
    ///
    /// Across a boundary an agent can spend one period's budget just before
    /// it and the next one's just after: up to twice the budget in a short
    /// time. That is the number an owner is to be shown, and it holds for
    /// what is registered as it does for what is transferred: under a period
    /// an x402 authorization or an order must end with the period it is
    /// charged in (`_endsWithThePeriod`), so nothing registered in one
    /// period can still be taken in a later one.
    ///
    /// Both ends are inclusive, as EntryPoint v0.7 reads them: an operation
    /// is in time from `validAfter` up to and at `validUntil`.
    function _enterPeriod(Config storage c, bytes calldata mine)
        internal
        returns (bool ok, uint48 from, uint48 until)
    {
        (from, until) = (c.validAfter, c.validUntil);
        uint256 seen;
        if (c.period != 0) {
            if (mine.length != 6) return (false, 0, 0);
            uint256 index = uint48(bytes6(mine));
            seen = index + 1;
            if (seen < c.periodSeen) return (false, 0, 0);
            uint256 start = index * c.period;
            uint256 end = start + c.period - 1;
            if (end > type(uint48).max) return (false, 0, 0);
            if (seen > c.periodSeen) {
                c.periodSeen = uint48(seen);
                c.spent = 0;
            }
            if (start > from) from = uint48(start);
            if (end < until) until = uint48(end);
            _setPerOperation(PERIOD_NEXT, end + 1);
        } else {
            _setPerOperation(PERIOD_NEXT, 0);
        }
        _setPerOperation(PERIOD_NOW, seen);
        _setPerOperation(NOT_BEFORE, 0);
        _setPerOperation(NOT_AFTER, 0);
        ok = true;
    }

    /// @dev What the token has spent in the period this operation is in,
    /// starting the token's count afresh when the period is new to it.
    function _tokenSpent(bytes32 m, address token, TokenLimit storage t) internal returns (uint256) {
        uint256 seen = _perOperation(PERIOD_NOW);
        if (seen != 0) {
            bytes32 key = keccak256(abi.encode(m, token));
            if (_tokenPeriod[key][msg.sender] != seen) {
                _tokenPeriod[key][msg.sender] = uint48(seen);
                t.spent = 0;
            }
        }
        return t.spent;
    }

    /// @dev Gives a registered charge back to the token's budget, if the
    /// budget still counts the period it was charged in. A charge of an
    /// earlier period is gone with that period.
    function _refund(bytes32 m, bytes32 digest, address token, TokenLimit storage t, uint128 value) internal {
        bytes32 key = keccak256(abi.encode(m, digest));
        if (_chargedIn[key][msg.sender] == _tokenPeriod[keccak256(abi.encode(m, token))][msg.sender]) {
            t.spent -= value;
        }
        delete _chargedIn[key][msg.sender];
        delete _x402[key][msg.sender];
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
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;
        Pending storage p = _pending(msg.sender, _mandate(id, c.epoch), hash);
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
        Config storage c = _configs[id][msg.sender];
        bytes32 m = _mandate(id, c.epoch);
        TokenLimit storage t = _token(msg.sender, m, token);
        bytes32 digest = _x402Digest(t.domainSeparator, msg.sender, to, value, validAfter, validBefore, nonce);
        Pending storage p = _pending(msg.sender, m, digest);
        if (p.value == 0) revert X402NotRegistered();
        if (block.timestamp < validBefore) revert X402StillLive();
        if (IERC3009State(token).authorizationState(msg.sender, nonce)) revert X402Settled();
        emit X402Reclaimed(msg.sender, id, digest, p.value);
        _refund(m, digest, token, t, p.value);
    }

    /// @notice Executed after validation registered the order: only leaves
    /// a record for wallets and `orderReclaim`.
    function orderRegister(address decoder, bytes calldata, /* config */ bytes calldata order) external {
        emit OrderRegistered(msg.sender, decoder, order);
    }

    /// @notice Return to the budget an order that can never be filled any
    /// more: past its `validTo` and untouched at the venue. Only the account
    /// can, for its own records. An order the owner cancelled at the venue
    /// counts there as filled, and its charge does not come back.
    function orderReclaim(bytes32 id, address decoder, bytes calldata config, bytes calldata order) external {
        bytes32 m = _mandate(id, _configs[id][msg.sender].epoch);
        Judged memory j = _askDecoder(m, decoder, config, order);
        if (!j.ok) revert NotTheVenue();
        Pending storage p = _pending(msg.sender, m, j.digest);
        if (p.value == 0 || p.token != j.token) revert OrderNotRegistered();
        // the venue fills an order up to and at `validTo`
        if (block.timestamp <= j.validTo) revert OrderStillLive();
        if (!IVenueDecoder(decoder).untouched{gas: JUDGE_GAS}(msg.sender, order)) revert OrderTouched();
        emit OrderReclaimed(msg.sender, id, j.digest, p.value);
        _refund(m, j.digest, j.token, _token(msg.sender, m, j.token), p.value);
    }

    /// The most gas a decoder gets to judge an order.
    uint256 internal constant JUDGE_GAS = 150_000;

    /// @dev Asks a venue's decoder about `order`, by `STATICCALL` with a gas
    /// bound. False unless the decoder is one of the mandate's venues, its
    /// code is the code the owner pinned, `config` is the owner's, and the
    /// answer is exactly the five words of `IVenueDecoder.judge`.
    function _askDecoder(bytes32 m, address decoder, bytes calldata config, bytes calldata order)
        internal
        view
        returns (Judged memory j)
    {
        VenuePin storage v = _venue(msg.sender, m, decoder);
        if (v.codeHash == bytes32(0) || decoder.codehash != v.codeHash || keccak256(config) != v.configHash) {
            return j;
        }
        (bool ok, bytes memory answer) =
            decoder.staticcall{gas: JUDGE_GAS}(abi.encodeCall(IVenueDecoder.judge, (msg.sender, config, order)));
        if (!ok || answer.length != 5 * 32) return j;
        (uint256 token, uint256 mostSold, uint256 notBefore, uint256 validTo, bytes32 digest) =
            abi.decode(answer, (uint256, uint256, uint256, uint256, bytes32));
        if (token >> 160 != 0 || notBefore > type(uint48).max || validTo > type(uint48).max) return j;
        return Judged(true, address(uint160(token)), mostSold, uint48(notBefore), uint48(validTo), digest);
    }

    /// @dev Validation of `orderRegister(...)`: the decoder says what the
    /// order sells and how much at most; that is judged like a transfer of
    /// the token (cap per operation, the shared budget) and the digest is
    /// recorded. A token with a payee list cannot be sold at a venue: what
    /// is sold goes to whoever fills the order, and the owner listed who may
    /// be paid.
    function _registerOrder(bytes32 m, bytes calldata d) internal returns (bool) {
        (bool ok, address decoder, bytes calldata config, bytes calldata order) = _orderArguments(d);
        if (!ok) return false;
        Judged memory j = _askDecoder(m, decoder, config, order);
        if (!j.ok || j.mostSold == 0) return false;
        if (!_endsWithThePeriod(uint256(j.validTo) + 1)) return false; // fillable up to and at `validTo`
        TokenLimit storage t = _token(msg.sender, m, j.token);
        if (!t.set || t.payeesOnly) return false;
        if (_movedThisOperation(j.token, j.mostSold) > t.maxPerOp) return false;
        uint256 spent = _tokenSpent(m, j.token, t) + j.mostSold;
        if (spent > t.budget) return false;
        if (!_recordX402(m, j.digest, j.mostSold, j.validTo, j.token)) return false;
        t.spent = uint128(spent);
        if (j.notBefore > _perOperation(NOT_BEFORE)) _setPerOperation(NOT_BEFORE, j.notBefore);
        uint256 notAfter = _perOperation(NOT_AFTER);
        if (notAfter == 0 || uint256(j.validTo) + 1 < notAfter) _setPerOperation(NOT_AFTER, uint256(j.validTo) + 1);
        return true;
    }

    /// @dev `orderRegister`'s arguments, where they sit in the calldata:
    /// the canonical encoding only, to the last byte. False otherwise.
    function _orderArguments(bytes calldata d)
        internal
        pure
        returns (bool, address decoder, bytes calldata config, bytes calldata order)
    {
        (config, order) = (d[0:0], d[0:0]);
        if (d.length < 4 + 5 * 32) return (false, address(0), config, order);
        bytes calldata a = d[4:];
        uint256 first = uint256(bytes32(a[0:32]));
        uint256 configLength = uint256(bytes32(a[96:128]));
        if (first >> 160 != 0 || uint256(bytes32(a[32:64])) != 96 || configLength > a.length) {
            return (false, address(0), config, order);
        }
        uint256 orderAt = 128 + ((configLength + 31) & ~uint256(31));
        if (uint256(bytes32(a[64:96])) != orderAt || orderAt + 32 > a.length) {
            return (false, address(0), config, order);
        }
        uint256 orderLength = uint256(bytes32(a[orderAt:orderAt + 32]));
        if (orderLength > a.length || a.length != orderAt + 32 + ((orderLength + 31) & ~uint256(31))) {
            return (false, address(0), config, order);
        }
        return (true, address(uint160(first)), a[128:128 + configLength], a[orderAt + 32:orderAt + 32 + orderLength]);
    }

    function x402Pending(address account, bytes32 id, bytes32 digest) external view returns (Pending memory) {
        return _pending(account, _mandate(id, _configs[id][account].epoch), digest);
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
    function _registerX402(bytes32 m, bytes calldata d) internal returns (bool) {
        if (d.length != 4 + 7 * 32) return false;
        (address token, address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce) =
            abi.decode(d[4:], (address, address, address, uint256, uint256, uint256, bytes32));
        if (from != msg.sender) return false; // the account checkUserOpPolicy runs for
        TokenLimit storage t = _token(msg.sender, m, token);
        if (!t.set || t.domainSeparator == bytes32(0)) return false;
        if (value == 0 || validBefore > type(uint48).max) return false;
        if (!_endsWithThePeriod(validBefore)) return false; // usable before `validBefore`
        if (_movedThisOperation(token, value) > t.maxPerOp) return false;
        if (t.payeesOnly && !_payees[_payeeKey(m, token, to)][msg.sender]) return false;
        uint256 spent = _tokenSpent(m, token, t) + value;
        if (spent > t.budget) return false;
        bytes32 digest = _x402Digest(t.domainSeparator, from, to, value, validAfter, validBefore, nonce);
        if (!_recordX402(m, digest, value, validBefore, token)) return false;
        t.spent = uint128(spent);
        return true;
    }

    /// @dev Under a budget per period, whether a registration that can be
    /// used before `notAfter` (exclusive) is over when the period it is
    /// charged in is. Without a period, always.
    function _endsWithThePeriod(uint256 notAfter) internal view returns (bool) {
        uint256 next = _perOperation(PERIOD_NEXT);
        return next == 0 || notAfter <= next;
    }

    /// @dev Records a registered authorization; false when its digest is
    /// already there.
    function _recordX402(bytes32 m, bytes32 digest, uint256 value, uint256 validBefore, address token)
        internal
        returns (bool)
    {
        Pending storage p = _pending(msg.sender, m, digest);
        if (p.value != 0) return false;
        if (value > type(uint128).max) return false;
        (p.value, p.validBefore, p.token) = (uint128(value), uint48(validBefore), token);
        _chargedIn[keccak256(abi.encode(m, digest))][msg.sender] = uint48(_perOperation(PERIOD_NOW));
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

    /// Per-operation notes, kept beside the token totals: the period the
    /// operation is in (plus one; 0 without periods), and the latest "not
    /// before" of the orders it registers.
    bytes32 internal constant PERIOD_NOW = keccak256("agent-keys.AgentPolicy.periodNow");
    /// The first second after that period; 0 without periods.
    bytes32 internal constant PERIOD_NEXT = keccak256("agent-keys.AgentPolicy.periodNext");
    bytes32 internal constant NOT_BEFORE = keccak256("agent-keys.AgentPolicy.notBefore");
    /// The earliest `validTo` of the orders it registers, plus one; 0 = none.
    bytes32 internal constant NOT_AFTER = keccak256("agent-keys.AgentPolicy.notAfter");

    function _perOperation(bytes32 what) internal view returns (uint256 value) {
        uint256 slot = uint256(keccak256(abi.encode(msg.sender, what)));
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }

    function _setPerOperation(bytes32 what, uint256 value) internal {
        uint256 slot = uint256(keccak256(abi.encode(msg.sender, what)));
        assembly ("memory-safe") {
            tstore(slot, value)
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
    function _judgeExecute(bytes32 m, bytes calldata callData) internal returns (bool, uint256) {
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
    function _judgeAccountBatch(bytes32 m, bytes32[] calldata pointers) internal returns (bool, uint256 moved) {
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
    function _judgeGuarded(bytes32 m, bytes32[] calldata pointers, uint256 i, uint256 value, bytes calldata data)
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
    function _judge(bytes32 m, address target, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        bytes4 selector = _selector(data);
        // The zero selector stands for a plain transfer, which carries no
        // calldata. 1–3 bytes would run the target's fallback, and so would
        // a longer body that happens to start with four zero bytes.
        if (selector == bytes4(0) && data.length != 0) return (false, 0);
        if (!_allowed[_allowedKey(m, target, selector)][msg.sender]) return (false, 0);
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
        // a venue's order: the same, through the venue's decoder
        if (target == address(this) && selector == this.orderRegister.selector) {
            return (from == FROM_ACCOUNT && value == 0 && _registerOrder(m, data)) ? (true, 0) : (false, 0);
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
        if (_venuePlaces[target][msg.sender]) return false;
        if (target == address(this)) {
            return selector == this.x402Authorize.selector || selector == this.x402Reclaim.selector
                || selector == this.orderRegister.selector || selector == this.orderReclaim.selector;
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
    function _judgeSafe(bytes32 m, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        // Only the account's own nonce-guarded call; Safes do not nest.
        if (from != FROM_ACCOUNT_GUARDED) return (false, 0);
        (bool decoded, address to, uint256 innerValue, uint256 operation, bytes calldata inner) = _decodeSafeExec(data);
        if (!decoded) return (false, 0);
        if (operation == 0) {
            (ok, moved) = _judge(m, to, innerValue, inner, FROM_SAFE);
        } else if (operation == 1 && innerValue == 0 && _selector(inner) == MULTI_SEND && _allowed[_allowedKey(m, to, MULTI_SEND)][msg.sender]) {
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
    function _chargeToken(bytes32 m, address token, bytes4 selector, bytes calldata data)
        internal
        returns (bool)
    {
        uint256 arg;
        if (selector == ERC20_TRANSFER || selector == ERC20_APPROVE || selector == ERC20_INCREASE_ALLOWANCE) arg = 1;
        else if (selector == ERC20_TRANSFER_FROM) arg = 2;

        TokenLimit storage t = _token(msg.sender, m, token);
        if (arg == 0) return !t.set;
        if (!t.set) return false;
        uint256 end = 4 + 32 * (arg + 1);
        if (data.length < end) return false;
        uint256 amount = uint256(bytes32(data[end - 32:end]));
        if (t.payeesOnly) {
            // the word before the amount; a token reads its low 160 bits, so
            // anything above them would name one address here and pay another
            uint256 payee = uint256(bytes32(data[end - 64:end - 32]));
            if (payee >> 160 != 0 || !_payees[_payeeKey(m, token, address(uint160(payee)))][msg.sender]) return false;
        }
        if (_movedThisOperation(token, amount) > t.maxPerOp) return false;
        uint256 spent = _tokenSpent(m, token, t) + amount;
        if (spent > t.budget) return false;
        t.spent = uint128(spent);
        return true;
    }

    /// @dev `multiSend(bytes transactions)`, each transaction packed as
    /// `operation (1) ‖ to (20) ‖ value (32) ‖ dataLength (32) ‖ data`.
    /// Every leg must be a CALL the mandate accepts.
    function _judgeBatch(bytes32 m, bytes calldata d) internal returns (bool, uint256 moved) {
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
    function _judgeLeg(bytes32 m, bytes calldata txs, uint256 i)
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
