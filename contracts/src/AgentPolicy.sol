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
    /// @dev Gets the EntryPoint the account answers to.
    /// @return The EntryPoint's address.
    function entrypoint() external view returns (address);
}

/// The one view of an EIP-3009 token (USDC) the policy reads: whether an
/// authorization's nonce is spent. `x402Reclaim` asks it, in the execution
/// phase, where the validation rules of ERC-7562 do not apply.
interface IERC3009State {
    /// @dev Gets the state of an authorization's nonce at the token.
    /// @param authorizer The address that signed the authorization: here, the account.
    /// @param nonce The authorization's nonce.
    /// @return True if the nonce was used, or cancelled (which marks it used).
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}

/// @title AgentPolicy - the agent's mandate, as a Kernel permission policy
/// @notice A Kernel permission policy: it bounds what an agent's key may do.
/// @dev Installed beside `P256Signer` under one permission id, this policy
/// turns the hardware key from "owner" into "operator with a mandate":
/// - `execute` only (a single call or a batch, revert-on-failure), and no
///   delegatecall;
/// - each call on the (target, selector) allow-list, where selector
///   `0x00000000` stands for a plain value transfer and admits empty
///   calldata only (1 to 3 bytes, or a longer body that starts with four
///   zero bytes, would run the target's fallback);
/// - `value` capped per operation and, together with the gas the account
///   pays for itself, by a total budget;
/// - ERC-20 `transfer` / `transferFrom` / `approve` / `increaseAllowance`
///   amounts capped per operation and by a budget per token. An allow-listed
///   token selector without a token limit is refused, and a token with a
///   limit is callable through these four functions only: a mandate with
///   another entry on it (`permit`, a `mint`, a vault's `withdraw`) would
///   move the token past its limit, and install refuses it;
/// - a time window `[validAfter, validUntil]`, enforced by the EntryPoint.
///   Several permissions for the same agent key, each with its own window,
///   budget and allow-list, make a schedule ("weekdays: up to X on these
///   contracts; the 1st: payroll up to Y");
/// - never a target: the account itself, its EntryPoint, this policy (but
///   for its two x402 entry points and its order entry point) and Permit2.
///   Install refuses all of them, and validation all but the EntryPoint
///   again (it is not re-checked there, see `_judge`). No mandate, however
///   written, lets the agent widen its own permission, replace the root key
///   or drain the deposit. Nor, under any mandate of the account, the
///   places of its trading venues (a venue's own contract, its decoder, its
///   spender);
/// - optionally, per token, a list of payees. With one, `transfer` and
///   `transferFrom` may pay a listed address only, `approve` and
///   `increaseAllowance` may name a listed spender only, and an x402
///   authorization may pay a listed address only. A token without a list is
///   bound in amount only, as before: the agent picks the recipient. A
///   listed spender can move what it was approved for wherever it likes, so
///   list a spender only if you would list everyone it pays;
/// - optionally, a budget per period: the native budget and every token's
///   start afresh in each window of `period` seconds, counted from the Unix
///   epoch. Validation may not read the clock (ERC-7562), so an operation
///   names its window and its validity is cut to it (`_enterPeriod`);
/// - optionally, with a period, trading venues (issue #80): the agent
///   registers an order with `orderRegister`, a decoder the owner pinned
///   says what the order sells and how much at most, and that is charged
///   like a transfer of the token (`_registerOrder`).
///
/// Safe pass-through: with an allow-list entry `(safe, execTransaction)`
/// the agent drives a Safe this account owns (Olas / Jinn service Safes)
/// with a pre-validated `v = 1` signature, no ERC-1271 needed, and the
/// policy judges the call *inside* the Safe transaction against the same
/// mandate. `gasPrice` must be 0, since otherwise the Safe pays a refund
/// out of its own funds to a receiver the agent picks, and Safes do not
/// nest. `operation` must be CALL, or DELEGATECALL into an allow-listed
/// `(multiSendCallOnly, multiSend)` batch each of whose legs is a CALL
/// that passes the mandate. Each Safe transaction must come as the Kernel
/// batch `[SafeNonceAssert.check(safe, n), safe.execTransaction(...)]`,
/// because a `v = 1` signature does not commit to the Safe nonce and the
/// assertion makes a replay revert on-chain. One allow-list entry admits
/// its call directly, through a Safe and as a batch leg alike: curate it
/// with that in mind.
///
/// ERC-1271 signatures are refused, with two exceptions that keep the
/// mandate in charge: x402 payments and a venue's orders. The agent first
/// *registers* an EIP-3009 `TransferWithAuthorization` with an ordinary
/// operation calling `x402Authorize(...)`. The mandate judges it like a
/// token transfer (per-op cap, the token's budget, shared with direct
/// transfers) and records its EIP-712 digest; afterwards
/// `checkSignaturePolicy` vouches for exactly that digest (the hash USDC
/// hands to `isValidSignature`) within the mandate's window and the
/// authorization's `validBefore`. An order is registered the same way, with
/// `orderRegister(...)`, and vouched for up to and at its `validTo`. Every
/// other hash (permits, Permit2, unregistered orders, other authorizations)
/// is still refused. The token itself enforces one use per nonce;
/// `x402Reclaim` returns the budget of an authorization that expired
/// unused, while an order's charge is never returned (`orderRegister`). See
/// docs/ERC1271.md. Kernel calls this module from the account, so
/// `msg.sender` is the account in every call it makes. The contract has no
/// owner and no admin function: one deployment serves every account, and
/// an account reaches its own mandates only.
///
/// The chip guarantees that nobody else can be this agent; this policy
/// guarantees that even this agent, compromised, cannot exceed what it was
/// allowed to do.
contract AgentPolicy is IPolicy {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    /// A permission's mandate as installed, and its native-value counters.
    /// Three storage slots: (`validUntil`, `epoch`, `maxValuePerOp`),
    /// (`budget`, `spent`), (`validAfter`, `period`, `periodSeen`).
    struct Config {
        // The mandate's last valid second, inclusive, as EntryPoint v0.7 reads it.
        // 2^48 - 1 seconds is about 8.9 million years
        uint48 validUntil; // 0 = not installed
        // Uninstalls of this id so far, part of every key of an installation
        // (`_mandate`); 2^32 - 1 uninstalls of one id is far past any use
        uint32 epoch; // bumps on uninstall so stale entries die
        // The most native value (wei) one operation may move, its Safe
        // transactions and batch legs included; 2^128 - 1 wei is about 3.4e20 ETH
        uint128 maxValuePerOp;
        // The most native value, plus the gas the account pays for itself, the
        // mandate may spend: over its whole life, or in each period. Same range
        uint128 budget;
        // What has been charged to `budget`, in the current period if there is
        // one; never above `budget`
        uint128 spent;
        // The mandate's first valid second, inclusive. Same range as `validUntil`
        uint48 validAfter; // 0 = from installation on
        // The budgets' window in seconds; 0 = one budget for the mandate's
        // whole life. Windows are counted from the Unix epoch: with 86400,
        // a day from midnight UTC. 2^32 - 1 seconds is over 136 years.
        uint32 period;
        // The window `spent` counts for, plus one; 0 before the first.
        // The operation names the window (`_enterPeriod`)
        uint48 periodSeen;
    }

    /// A trading venue of a mandate (issue #80): the decoder the policy asks
    /// about the venue's orders, bound by its code, and the hash of the
    /// owner's config for it. Install data; what is kept is a `VenuePin`.
    struct Venue {
        // The venue's decoder (`IVenueDecoder`); it must have code
        address decoder;
        // The decoder's code hash (`EXTCODEHASH`) as the owner reviewed it;
        // install and every order check the code against it
        bytes32 codeHash;
        // keccak256 of the owner's `config` for the venue, in the decoder's
        // encoding; never zero
        bytes32 configHash;
    }

    /// A decoder's answer about an order; `ok` false when there is none.
    /// Held in memory during one validation only.
    struct Judged {
        // True if the decoder allowed the order and answered in form
        bool ok;
        // The token the order sells
        address token;
        // The most of it the order can ever take, in its smallest units
        uint256 mostSold;
        // The earliest second the order may be registered in; the decoder's
        // word is refused if it does not fit 48 bits
        uint48 notBefore;
        // The last second the order can be filled in, inclusive; refused if it
        // does not fit 48 bits
        uint48 validTo;
        // The hash the venue will ask the account to vouch for (ERC-1271)
        bytes32 digest;
    }

    /// What a mandate keeps of one of its venues, per (mandate, decoder,
    /// account): two slots. A zero `codeHash` means the decoder is not one of
    /// the mandate's venues.
    struct VenuePin {
        // The decoder's code hash the owner pinned
        bytes32 codeHash;
        // keccak256 of the owner's config for the venue
        bytes32 configHash;
    }

    /// Install-time limit for one ERC-20 token. `domainSeparator` is the
    /// token's EIP-712 domain (read off-chain at install), non-zero to allow
    /// x402 / EIP-3009 payments in it — the policy cannot read the token's
    /// storage during validation.
    struct TokenCap {
        // The token contract; not zero, and one cap per token
        address token;
        // The most of the token one operation may move, in its smallest
        // units, summed over all its calls; 2^128 - 1 units is about 3.4e20
        // tokens of 18 decimals
        uint128 maxPerOp;
        // The most of the token the mandate may move: over its whole life,
        // or in each period. Same range
        uint128 budget;
        // The token's EIP-712 domain separator; zero for no x402 payments
        bytes32 domainSeparator;
    }

    /// Install-time list of the only addresses a token's transfers,
    /// allowances and x402 payments may name. The token needs a `TokenCap`.
    struct TokenPayees {
        // The token; one list per token
        address token;
        // The addresses it may reach: at least one, none zero, none twice
        address[] payees;
    }

    /// What a mandate keeps for one token, per (mandate, token, account):
    /// three slots, (`maxPerOp`, `budget`), (`spent`, `set`, `payeesOnly`),
    /// (`domainSeparator`). `tokenLimit()` returns it whole.
    struct TokenLimit {
        // As `TokenCap.maxPerOp`
        uint128 maxPerOp;
        // As `TokenCap.budget`
        uint128 budget;
        // What has been charged to `budget`, in the current period if there
        // is one; never above `budget`
        uint128 spent;
        // True once the token has a limit; a token without one is unset
        bool set;
        // true: only the payees listed for the token may be paid or approved.
        // It sits before `domainSeparator`, so `tokenLimit()` returns the
        // separator as its sixth word (the fifth before payee lists).
        bool payeesOnly;
        // As `TokenCap.domainSeparator`: non-zero to allow x402 payments
        bytes32 domainSeparator;
    }

    /// A registered x402 authorization, keyed by its EIP-712 digest. A
    /// registered order is kept the same way, under its digest. Two slots.
    struct Pending {
        // The amount charged to the token's budget; 0 marks no registration,
        // so nothing of value 0 is registered. Same range as `TokenCap.budget`
        uint128 value;
        // x402: the authorization's `validBefore` (the token takes it before
        // that second); an order: its `validTo` (fillable up to and at it).
        // `checkSignaturePolicy` vouches up to and at this second. 2^48 - 1
        // seconds is about 8.9 million years
        uint48 validBefore;
        // The token charged: the digest names it only through its domain
        address token;
    }

    /// @dev The install data is malformed, or breaks a rule of the mandate's
    /// form (`onInstall`, `_installPayees`, `_installTrading`).
    error InvalidConfig();
    /// @dev An allow-list entry the agent must never have (the account, its
    /// EntryPoint, this policy outside x402 and orders, Permit2, a place of
    /// one of the account's venues: its own contract, its decoder, its
    /// spender). Raised at install.
    /// @param target The refused target.
    /// @param selector Its selector in the allow-list; zero when the target is
    /// refused as a place of one of the mandate's own venues.
    error ForbiddenTarget(address target, bytes4 selector);
    /// @dev The account did not say which EntryPoint it uses, so the policy
    /// cannot keep that EntryPoint out of the allow-list.
    error UnknownEntryPoint();
    /// @dev `x402Reclaim`: no authorization with these terms is registered under
    /// the permission's current installation, or it was registered for
    /// another token.
    error X402NotRegistered();
    /// @dev `x402Reclaim`: the authorization can still settle (it is before its
    /// `validBefore`).
    error X402StillLive();
    /// @dev `x402Reclaim`: the token reports the authorization's nonce used, or
    /// cancelled; the charge stays.
    error X402Settled();

    /// @dev Emitted by `x402Authorize`, in the execution of the operation whose
    /// validation registered the authorization: a record for wallets and
    /// `x402 reclaim`. The event names `msg.sender`, so only an account can
    /// emit one for itself; what the policy acts on is the registration
    /// (`x402Pending`).
    /// @param account The account that pays.
    /// @param token The EIP-3009 token.
    /// @param to The payee.
    /// @param value The amount, in the token's smallest units.
    /// @param validAfter The authorization's `validAfter`.
    /// @param validBefore The authorization's `validBefore`.
    /// @param nonce The authorization's nonce.
    event X402Authorized(
        address indexed account,
        address indexed token,
        address indexed to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    );
    /// @dev Emitted when the account reclaims an authorization that expired
    /// unused (`x402Reclaim`).
    /// @param account The account.
    /// @param id The permission id the authorization was registered under.
    /// @param digest The authorization's EIP-712 digest.
    /// @param value The amount the registration charged. It returns to the
    /// token's budget only if that budget still counts the period it was
    /// charged in (`_refund`).
    event X402Reclaimed(address indexed account, bytes32 indexed id, bytes32 digest, uint256 value);
    /// @dev Emitted by `orderRegister`, in the execution of the operation whose
    /// validation registered the order: a record for wallets.
    /// @param account The account that sells.
    /// @param decoder The venue's decoder.
    /// @param order The order, in the decoder's encoding.
    event OrderRegistered(address indexed account, address indexed decoder, bytes order);

    /// @dev Emitted when an account installs a mandate under a permission.
    /// @param account The account.
    /// @param id The permission id, as Kernel passes it (the 4-byte id, left-aligned).
    /// @param validUntil The mandate's last valid second.
    /// @param maxValuePerOp The most native value one operation may move.
    /// @param budget The native budget, over the mandate's life or per period.
    event AgentPolicySet(
        address indexed account, bytes32 indexed id, uint48 validUntil, uint128 maxValuePerOp, uint128 budget
    );

    /// `Safe.execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
    bytes4 public constant SAFE_EXEC_TRANSACTION = 0x6a761202;
    /// `MultiSend(CallOnly).multiSend(bytes)`
    bytes4 public constant MULTI_SEND = 0x8d80ff0a;
    /// `SafeNonceAssert.check(address,uint256)`
    bytes4 public constant NONCE_CHECK = SafeNonceAssert.check.selector;

    // The four ERC-20 functions the policy meters (`_chargeToken`), the only
    // ones a token with a limit may be called through.
    /// The recipient in argument 0, the amount in argument 1
    bytes4 internal constant ERC20_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    /// The sender in argument 0, the recipient in argument 1, the amount in argument 2
    bytes4 internal constant ERC20_TRANSFER_FROM = 0x23b872dd; // transferFrom(address,address,uint256)
    /// The spender in argument 0, the amount in argument 1
    bytes4 internal constant ERC20_APPROVE = 0x095ea7b3; // approve(address,uint256)
    /// The spender in argument 0, the amount added in argument 1
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = 0x39509351; // increaseAllowance(address,uint256)

    /// EIP-3009 `TransferWithAuthorization(address from,address to,uint256 value,
    /// uint256 validAfter,uint256 validBefore,bytes32 nonce)` (== USDC's).
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // Where a call sits: issued by the account, by the account right after
    // a matching nonce assertion, by a Safe, or as a Safe batch leg.
    /// The account's own call: the single call, or a leg of its batch
    uint8 internal constant FROM_ACCOUNT = 0;
    /// The account's leg right after a matching `SafeNonceAssert.check`: the
    /// only place a Safe transaction is admitted
    uint8 internal constant FROM_ACCOUNT_GUARDED = 1;
    /// The call inside a Safe transaction (CALL)
    uint8 internal constant FROM_SAFE = 2;
    /// A leg of a MultiSend batch the Safe delegatecalls
    uint8 internal constant FROM_BATCH = 3;

    /// The SafeNonceAssert every Safe transaction must be paired with. Part of
    /// the code, so validation reads it without storage; as a constructor
    /// argument it is part of the policy's CREATE2 address too.
    address public immutable NONCE_ASSERT;

    // Storage layout. Validation reads and writes this contract's storage
    // on the account's behalf, and ERC-7562 lets a bundler admit that only
    // for slots that belong to the account: `keccak256(account ‖ x) + n`
    // with a small `n`. So the account is the innermost key of every
    // mapping, and everything else that names an entry (the permission id,
    // its epoch, a target and selector, a token, a payee, a digest) is
    // hashed into the outer key first. A nested mapping with the account
    // outermost holds the same data in slots a rule-enforcing bundler
    // refuses (issue #83). The `mandate` in the keys below is `_mandate(id,
    // epoch)`: one installation of a permission.

    // Map of permission id => account => the mandate's limits and counters.
    // One `Config` per id, kept across installations; its `epoch` names the
    // current one
    mapping(bytes32 id => mapping(address account => Config)) internal _configs;
    // Map of account => the number of its permissions with a mandate here; `isInitialized` reads it
    mapping(address account => uint256) public usedIds;
    // Map of key => account => whether the mandate allows the call.
    // key: `keccak256(mandate, target, selector)`
    mapping(bytes32 key => mapping(address account => bool)) internal _allowed;
    // Map of key => account => the token's limit and counter.
    // key: `keccak256(mandate, token)`
    mapping(bytes32 key => mapping(address account => TokenLimit)) internal _tokens;
    // Map of key => account => a registered x402 authorization or order.
    // key: `keccak256(mandate, digest)`
    mapping(bytes32 key => mapping(address account => Pending)) internal _x402;
    // Map of key => account => whether the token may reach the payee.
    // key: `keccak256(mandate, token, payee)`
    mapping(bytes32 key => mapping(address account => bool)) internal _payees;
    // key: `keccak256(mandate, token)`. The window the token's `spent`
    // counts for, plus one. Beside `TokenLimit` and not in it, so that what
    // `tokenLimit()` returns keeps its shape.
    mapping(bytes32 key => mapping(address account => uint48)) internal _tokenPeriod;
    // key: `keccak256(mandate, digest)`. The window a registered
    // authorization or order was charged in, plus one; 0 without periods.
    mapping(bytes32 key => mapping(address account => uint48)) internal _chargedIn;
    // Map of key => account => the venue's pinned code and config.
    // key: `keccak256(mandate, decoder)`
    mapping(bytes32 key => mapping(address account => VenuePin)) internal _venues;
    // The venues an account has ever pinned in a mandate: each venue's own
    // contract, its decoder and its spender. None of them is a target for
    // the agent under any mandate of the account, whichever was installed
    // first: at the venue itself an order could be signed past the decoder
    // (CoW: `setPreSignature`), and the spender holds the owner's allowance
    // of the sold tokens (CoW: the vault relayer), so through it they would
    // leave past their caps and payee lists. Never cleared: an address that
    // was a venue stays out of reach.
    mapping(address place => mapping(address account => bool)) internal _venuePlaces;

    /// @dev Policy constructor.
    /// @param nonceAssert The SafeNonceAssert on this chain, kept as `NONCE_ASSERT`.
    constructor(address nonceAssert) {
        NONCE_ASSERT = nonceAssert;
    }

    /// @dev One installation of a permission: the id and its epoch, which
    /// moves on at uninstall so that nothing of an earlier installation is
    /// found again. Part of every outer key below.
    /// @param id The permission id.
    /// @param epoch The id's epoch for the account.
    /// @return The mandate key.
    function _mandate(bytes32 id, uint32 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, epoch));
    }

    /// @dev The outer key of an allow-list entry.
    /// @param m The mandate key.
    /// @param target The call's target.
    /// @param selector The call's selector; zero for a plain value transfer.
    /// @return The key into `_allowed`.
    function _allowedKey(bytes32 m, address target, bytes4 selector) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, target, selector));
    }

    /// @dev The outer key of a payee-list entry.
    /// @param m The mandate key.
    /// @param token The token.
    /// @param payee The address the token may reach.
    /// @return The key into `_payees`.
    function _payeeKey(bytes32 m, address token, address payee) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, token, payee));
    }

    /// @dev The account's limit for a token under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param token The token.
    /// @return The `TokenLimit`; `set` is false if the token has none.
    function _token(address account, bytes32 m, address token) internal view returns (TokenLimit storage) {
        return _tokens[keccak256(abi.encode(m, token))][account];
    }

    /// @dev The account's pin of a venue's decoder under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param decoder The decoder.
    /// @return The `VenuePin`; a zero `codeHash` if the decoder is not a venue of the mandate.
    function _venue(address account, bytes32 m, address decoder) internal view returns (VenuePin storage) {
        return _venues[keccak256(abi.encode(m, decoder))][account];
    }

    /// @dev The account's registration of a digest under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param digest An x402 authorization's or an order's digest.
    /// @return The `Pending`; a zero `value` if the digest is not registered.
    function _pending(address account, bytes32 m, bytes32 digest) internal view returns (Pending storage) {
        return _x402[keccak256(abi.encode(m, digest))][account];
    }

    /// @notice The permission's limits and counters, in the order of `Config`.
    /// @dev The first six of its fields; `period()` returns the other two.
    /// @param account The account.
    /// @param id The permission id.
    /// @return validUntil The last valid second; 0 if the permission is not installed.
    /// @return epoch The number of times the id was uninstalled for the account.
    /// @return maxValuePerOp The most native value one operation may move.
    /// @return budget The native budget, over the mandate's life or per period.
    /// @return spent What has been charged to `budget`, in the period last seen if there are periods.
    /// @return validAfter The first valid second.
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
    /// @param account The account.
    /// @param id The permission id.
    /// @return seconds_ The window's length in seconds; 0 for one budget over the mandate's life.
    /// @return seen The window `spent` counts for, plus one; 0 before the first.
    function period(address account, bytes32 id) external view returns (uint32 seconds_, uint48 seen) {
        Config storage c = _configs[id][account];
        return (c.period, c.periodSeen);
    }

    /// @notice Whether `place` is, or ever was, a venue's own contract, its
    /// decoder or its spender in a mandate of `account`: then no mandate of
    /// the account may name it as a target.
    /// @param account The account.
    /// @param place The address asked about.
    /// @return True if the address is out of the agent's reach as a venue's place.
    function venuePlace(address account, address place) external view returns (bool) {
        return _venuePlaces[place][account];
    }

    /// @notice The pinned code hash and config hash of a venue's decoder
    /// under the permission; zeros when it is not one of its venues.
    /// @param account The account.
    /// @param id The permission id; its current installation is read.
    /// @param decoder The decoder.
    /// @return The `VenuePin`.
    function venue(address account, bytes32 id, address decoder) external view returns (VenuePin memory) {
        return _venue(account, _mandate(id, _configs[id][account].epoch), decoder);
    }

    // The install data's first word — the offset of `targets` — tells the
    // encodings apart: seven head words, eight with `payees`, or ten with
    // `payees`, `period` and `venues`. Data whose first word is none of
    // them is refused, and so is data whose word does not match its body,
    // so no install drops a list. That the
    // owner sees exactly what is installed rests on the reviewing app,
    // which accepts canonical encodings only; this contract decodes as
    // loosely as `abi.decode` does.
    /// Seven words: the plain mandate, without payee lists, period or venues
    uint256 internal constant HEAD_WITHOUT_PAYEES = 7 * 32;
    /// Eight words: with `TokenPayees[] payees`, which must not be empty then
    uint256 internal constant HEAD_WITH_PAYEES = 8 * 32;
    /// Ten words: `payees` (which may then be empty), `uint32 period` and
    /// `Venue[] venues`. For a mandate with a budget per period, with
    /// venues or without; one without a period is encoded in a shorter form
    /// and has no venues.
    uint256 internal constant HEAD_WITH_TRADING = 10 * 32;

    /// @dev Installs a mandate under a permission of the account. Kernel calls
    /// it when the account installs a permission with this policy (an
    /// owner's operation: `permission add`, `permission rotate`, or the
    /// account's creation with its first permission). Nothing of an earlier
    /// installation of the id is found again: entries are keyed by the
    /// mandate (`_mandate`), and the counters start at zero. `payable` for
    /// the interface; no value is used.
    /// @param data `bytes32 id ++ abi.encode(address[] targets, bytes4[] selectors,
    ///              uint128 maxValuePerOp, uint128 budget, uint48 validUntil, TokenCap[] tokens,
    ///              uint48 validAfter)`, optionally with one more parameter
    ///              `TokenPayees[] payees`, or with three more:
    ///              `TokenPayees[] payees, uint32 period, Venue[] venues`. A
    ///              mandate is encoded in the shortest form that holds it.
    function onInstall(bytes calldata data) external payable override {
        // The permission id comes first, as Kernel packs it
        bytes32 id = bytes32(data[0:32]);
        // One mandate per id at a time: an installed one is uninstalled first
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil != 0) revert AlreadyInitialized(msg.sender);
        // The seven head parameters every form starts with
        (
            address[] memory targets,
            bytes4[] memory selectors,
            uint128 maxValuePerOp,
            uint128 budget,
            uint48 validUntil,
            TokenCap[] memory tokens,
            uint48 validAfter
        ) = abi.decode(data[32:], (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48));
        // At least one entry, a selector for each target, and a window that is not empty
        if (targets.length == 0 || targets.length != selectors.length || validUntil == 0 || validAfter >= validUntil) {
            revert InvalidConfig();
        }

        // Every entry below is keyed by this installation
        bytes32 m = _mandate(id, c.epoch);
        // The EntryPoint holds the account's deposit: it must be known to be kept out
        address entryPoint = _entryPointOf(msg.sender);
        if (entryPoint == address(0)) revert UnknownEntryPoint();
        // Allow-list each (target, selector), refusing the targets no agent may have
        for (uint256 i; i < targets.length; i++) {
            if (!_targetAllowed(targets[i], selectors[i]) || targets[i] == entryPoint) {
                revert ForbiddenTarget(targets[i], selectors[i]);
            }
            _allowed[_allowedKey(m, targets[i], selectors[i])][msg.sender] = true;
        }
        // One limit per token, none for the zero address; nothing spent yet
        for (uint256 i; i < tokens.length; i++) {
            if (tokens[i].token == address(0) || _token(msg.sender, m, tokens[i].token).set) revert InvalidConfig();
            _tokens[keccak256(abi.encode(m, tokens[i].token))][msg.sender] =
                TokenLimit(tokens[i].maxPerOp, tokens[i].budget, 0, true, false, tokens[i].domainSeparator);
        }
        // The payee lists of the eight- and ten-word forms
        _installPayees(m, data[32:]);
        // The period and venues of the ten-word form; no period otherwise
        c.period = _installTrading(m, data[32:], targets);
        // A token with a limit is callable through the four metered
        // functions only (`_chargeToken`). Any other entry on it would pass
        // neither its caps nor its payee list, so the limit the owner wrote
        // down would not be one: such a mandate is refused whole.
        for (uint256 i; i < targets.length; i++) {
            if (_token(msg.sender, m, targets[i]).set && !_isMetered(selectors[i])) revert InvalidConfig();
        }
        // The window and the native limits; the counters from zero, since an
        // earlier installation of the id left its own in this `Config`
        c.validUntil = validUntil;
        c.validAfter = validAfter;
        c.maxValuePerOp = maxValuePerOp;
        c.budget = budget;
        c.spent = 0;
        c.periodSeen = 0;
        // Count the permission and record the install
        usedIds[msg.sender]++;
        emit AgentPolicySet(msg.sender, id, validUntil, maxValuePerOp, budget);
    }

    /// @dev Whether a selector is one of the four ERC-20 functions
    /// `_chargeToken` meters.
    /// @param selector The selector.
    /// @return True for `transfer`, `approve`, `increaseAllowance` and `transferFrom`.
    function _isMetered(bytes4 selector) internal pure returns (bool) {
        return selector == ERC20_TRANSFER || selector == ERC20_APPROVE || selector == ERC20_INCREASE_ALLOWANCE
            || selector == ERC20_TRANSFER_FROM;
    }

    /// @dev The optional eighth parameter. Each entry needs a capped token
    /// that has no list yet, and at least one payee; no zero address, no
    /// payee twice. Called by `onInstall` after the token limits are written.
    /// @param m The mandate key.
    /// @param params The install data after the permission id.
    function _installPayees(bytes32 m, bytes calldata params) internal {
        // The first word tells the form
        if (params.length < 32) revert InvalidConfig();
        uint256 head = uint256(bytes32(params[0:32]));
        // Seven words: no lists
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
        // Each list: a capped token without a list yet, then its payees, each once and none zero
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
    /// Nor may the decoder, or the venue's spender (CoW's vault relayer),
    /// which holds the owner's allowance of the sold tokens. The venue and
    /// the spender are asked of the decoder whose code was just pinned.
    /// @param m The mandate key.
    /// @param params The install data after the permission id.
    /// @param targets The mandate's targets, already allow-listed.
    /// @return period_ The budgets' window in seconds; 0 for the shorter forms.
    function _installTrading(bytes32 m, bytes calldata params, address[] memory targets)
        internal
        returns (uint32 period_)
    {
        // Only the ten-word form carries a period and venues
        if (uint256(bytes32(params[0:32])) != HEAD_WITH_TRADING) return 0;
        Venue[] memory venues;
        (,,,,,,,, period_, venues) = abi.decode(
            params, (address[], bytes4[], uint128, uint128, uint48, TokenCap[], uint48, TokenPayees[], uint32, Venue[])
        );
        // The ten-word form carries a period, with venues or without. A mandate
        // with venues needs one: an order's charge is never given back, so the
        // period is what returns an unfilled order's part of the budget.
        if (period_ == 0) revert InvalidConfig();
        for (uint256 i; i < venues.length; i++) {
            // Each decoder once, with a config, and with the code the owner pinned
            address decoder = venues[i].decoder;
            VenuePin storage v = _venue(msg.sender, m, decoder);
            if (
                v.codeHash != bytes32(0) || venues[i].configHash == bytes32(0) || decoder.code.length == 0
                    || decoder.codehash != venues[i].codeHash
            ) revert InvalidConfig();
            (v.codeHash, v.configHash) = (venues[i].codeHash, venues[i].configHash);
            // The venue's own contract and its spender, as the pinned code names them
            address place = IVenueDecoder(decoder).venue();
            address spender = IVenueDecoder(decoder).spender();
            // this mandate's own targets were judged before the venue was known
            for (uint256 j; j < targets.length; j++) {
                if (targets[j] == place || targets[j] == decoder || targets[j] == spender) {
                    revert ForbiddenTarget(targets[j], bytes4(0));
                }
            }
            // a venue that is the account or this policy would close the account's own paths
            if (
                place == msg.sender || place == address(this) || decoder == address(this) || spender == msg.sender
                    || spender == address(this)
            ) revert InvalidConfig();
            // Out of the agent's reach under every mandate of the account, for good
            _venuePlaces[place][msg.sender] = true;
            _venuePlaces[decoder][msg.sender] = true;
            _venuePlaces[spender][msg.sender] = true;
        }
    }

    /// @dev Ends a mandate. Kernel calls it when the account uninstalls the
    /// permission (an owner's operation: `permission revoke`, `permission
    /// rotate`), and goes on with the uninstall even if this call reverts
    /// (Kernel's `ModuleLib.uninstallModule`). Moving the epoch on leaves
    /// every entry of the installation (allow-list, token limits, payee
    /// lists, venues, registered authorizations and orders) under a key no
    /// lookup builds again: from this block on the policy vouches for none
    /// of its registered digests. The account's venue places stay. `payable`
    /// for the interface; no value is used.
    /// @param data `bytes32 id ++ ...`, as Kernel packs it; only the id is read.
    function onUninstall(bytes calldata data) external payable override {
        // The permission id comes first, as Kernel packs it
        bytes32 id = bytes32(data[0:32]);
        // It must be installed
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil == 0) revert NotInitialized(msg.sender);
        // Mark it uninstalled and move to a new epoch; the counters are reset at the next install
        c.validUntil = 0;
        c.validAfter = 0;
        c.epoch++;
        // Uncount the permission; every installed one was counted once
        usedIds[msg.sender]--;
    }

    /// @dev Tells Kernel which ERC-7579 module type this is.
    /// @param typeId An ERC-7579 module type id.
    /// @return True only for the policy type (`MODULE_TYPE_POLICY`).
    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_POLICY;
    }

    /// @dev Whether any permission of the account has a mandate here.
    /// @param account The account.
    /// @return True if at least one of the account's permissions is installed with this policy.
    function isInitialized(address account) external view override returns (bool) {
        return usedIds[account] > 0;
    }

    /// @notice Whether the permission's current mandate has `(target, selector)`
    /// on its allow-list.
    /// @param account The account.
    /// @param id The permission id.
    /// @param target The target.
    /// @param selector The selector; zero for a plain value transfer.
    /// @return True if the entry is on the allow-list.
    function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool) {
        return _allowed[_allowedKey(_mandate(id, _configs[id][account].epoch), target, selector)][account];
    }

    /// @notice The permission's current limit for `token`, and what it has spent.
    /// @param account The account.
    /// @param id The permission id.
    /// @param token The token.
    /// @return The `TokenLimit`; `set` is false if the token has no limit.
    function tokenLimit(address account, bytes32 id, address token) external view returns (TokenLimit memory) {
        return _token(account, _mandate(id, _configs[id][account].epoch), token);
    }

    /// @notice Whether the mandate lets `token` reach `payee`: true for any
    /// address when the token has no payee list.
    /// @param account The account.
    /// @param id The permission id.
    /// @param token The token.
    /// @param payee The address asked about.
    /// @return True if a transfer, allowance or x402 payment of the token may name the address.
    function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool) {
        bytes32 m = _mandate(id, _configs[id][account].epoch);
        return !_token(account, m, token).payeesOnly || _payees[_payeeKey(m, token, payee)][account];
    }

    /// @dev Returns `packValidationData(validAfter, validUntil)` on success so
    /// the EntryPoint enforces the window, `SIG_VALIDATION_FAILED_UINT` otherwise
    /// (which Kernel turns into a `PolicyFailed` revert, undoing any token
    /// accounting done on the way).
    /// The account calls it in the ERC-4337 validation phase, for an
    /// operation whose nonce selects the permission, before the permission's
    /// signer checks the signature. Of this contract's storage it touches
    /// the account's slots only, and it reads no clock (ERC-7562).
    /// @param id The permission id the operation's nonce selects.
    /// @param userOp The user operation. Its `signature` is this policy's part
    /// of the signature, as Kernel cut it out (empty when the operation gives
    /// none): under a period, the six bytes that name the period.
    /// @return The validity window cut to the period and to the operation's
    /// orders, or `SIG_VALIDATION_FAILED_UINT` (1).
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        // The permission must be installed
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;

        // Fresh per-operation totals, then the window and the period the operation names
        _beginOperation();
        (bool inWindow, uint48 from, uint48 until) = _enterPeriod(c, userOp.signature);
        if (!inWindow) return SIG_VALIDATION_FAILED_UINT;
        // Judge every call; token amounts are charged on the way
        (bool ok, uint256 value) = _judgeExecute(_mandate(id, c.epoch), userOp.callData);
        if (!ok || value > c.maxValuePerOp) return SIG_VALIDATION_FAILED_UINT;

        // Without a paymaster the account pays for gas out of its own
        // deposit: count the most it can be charged against the budget.
        uint256 charged = value;
        if (userOp.paymasterAndData.length == 0) charged += _maxGasCost(userOp);
        // The native budget; `spent` stays within it, so the cast cuts nothing
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
        // An empty window is refused, and with it an end of 0, which the
        // EntryPoint would read as no end at all
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
    ///
    /// It also writes the operation's notes (`PERIOD_NOW`, `PERIOD_NEXT`,
    /// `NOT_BEFORE`, `NOT_AFTER`) afresh, which the rest of the validation reads.
    /// @param c The permission's `Config`.
    /// @param mine This policy's part of the signature; read only under a period.
    /// @return ok False if the operation names no period, an earlier one, or one past the 48-bit clock.
    /// @return from The window's first second: the mandate's, or the period's start if later.
    /// @return until The window's last second: the mandate's, or the period's end if earlier.
    function _enterPeriod(Config storage c, bytes calldata mine)
        internal
        returns (bool ok, uint48 from, uint48 until)
    {
        // The mandate's own window, to be cut to the period
        (from, until) = (c.validAfter, c.validUntil);
        uint256 seen;
        if (c.period != 0) {
            // The period's index, big-endian, in exactly six bytes
            if (mine.length != 6) return (false, 0, 0);
            uint256 index = uint48(bytes6(mine));
            seen = index + 1;
            // Never back to an earlier period
            if (seen < c.periodSeen) return (false, 0, 0);
            // Its first and last second, which must fit the 48-bit window
            uint256 start = index * c.period;
            uint256 end = start + c.period - 1;
            if (end > type(uint48).max) return (false, 0, 0);
            // A new period starts the native budget afresh
            if (seen > c.periodSeen) {
                c.periodSeen = uint48(seen);
                c.spent = 0;
            }
            // Cut the window to the period, and note where the next one begins
            if (start > from) from = uint48(start);
            if (end < until) until = uint48(end);
            _setPerOperation(PERIOD_NEXT, end + 1);
        } else {
            _setPerOperation(PERIOD_NEXT, 0);
        }
        // The operation's other notes, from nothing
        _setPerOperation(PERIOD_NOW, seen);
        _setPerOperation(NOT_BEFORE, 0);
        _setPerOperation(NOT_AFTER, 0);
        ok = true;
    }

    /// @dev What the token has spent in the period this operation is in,
    /// starting the token's count afresh when the period is new to it.
    /// Each token keeps its own period marker (`_tokenPeriod`), since a
    /// token is touched only by the operations that move it.
    /// @param m The mandate key.
    /// @param token The token.
    /// @param t The token's `TokenLimit`.
    /// @return What has been charged to the token's budget in this period.
    function _tokenSpent(bytes32 m, address token, TokenLimit storage t) internal returns (uint256) {
        uint256 seen = _perOperation(PERIOD_NOW);
        // Under a period: a period new to the token resets its count
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
    /// earlier period is gone with that period. Without periods both markers
    /// are 0, so the charge always returns. Deletes the registration either
    /// way, so it is given back once.
    /// @param m The mandate key.
    /// @param digest The registration's digest.
    /// @param token The token it was charged to.
    /// @param t The token's `TokenLimit`.
    /// @param value The amount it charged.
    function _refund(bytes32 m, bytes32 digest, address token, TokenLimit storage t, uint128 value) internal {
        bytes32 key = keccak256(abi.encode(m, digest));
        // Charged in the period the token's count is in: that count includes it
        if (_chargedIn[key][msg.sender] == _tokenPeriod[keccak256(abi.encode(m, token))][msg.sender]) {
            t.spent -= value;
        }
        delete _chargedIn[key][msg.sender];
        delete _x402[key][msg.sender];
    }

    /// @dev The only messages an agent may "sign": a registered x402
    /// authorization's digest — the hash the token passes to
    /// `isValidSignature` (Kernel hands policies the unwrapped hash) — and a
    /// registered order's digest, which the venue passes the same way. The
    /// caller is not checked: facilitators verify with `eth_call` from their
    /// own address, and the digest is bound to the token's (or the venue's)
    /// domain anyway.
    /// Kernel calls it when anyone asks the account `isValidSignature` with a
    /// signature of this permission, and holds the window returned against
    /// the clock itself (`_checkPermissionSignature`). The second parameter
    /// (who asked the account) and the fourth (this policy's part of the
    /// signature) are not read.
    /// @param id The permission id.
    /// @param hash The hash to vouch for, as the asker handed it to the account.
    /// @return `packValidationData(validAfter, until)`, `until` being the earlier
    /// of the registration's end and the mandate's `validUntil`, if `hash` is
    /// registered under the permission's current installation;
    /// `SIG_VALIDATION_FAILED_UINT` otherwise (Kernel reverts `PolicyFailed`).
    function checkSignaturePolicy(bytes32 id, address, bytes32 hash, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        // The permission must be installed
        Config storage c = _configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;
        // The hash must be registered under the current installation
        Pending storage p = _pending(msg.sender, _mandate(id, c.epoch), hash);
        if (p.value == 0) return SIG_VALIDATION_FAILED_UINT;
        // Within the mandate's window, and no longer than the registration lives
        uint48 until = p.validBefore < c.validUntil ? p.validBefore : c.validUntil;
        return packValidationData(ValidAfter.wrap(c.validAfter), ValidUntil.wrap(until));
    }

    /// @notice Executed after validation registered the authorization: only
    /// leaves a record for wallets and `x402 reclaim`.
    /// @dev The registration was made by `_registerX402` in the operation's
    /// validation, from these same arguments. The second parameter, `from`,
    /// is the account itself, checked in validation, and is not read here.
    /// @param token The EIP-3009 token.
    /// @param to The payee.
    /// @param value The amount, in the token's smallest units.
    /// @param validAfter The authorization's `validAfter`.
    /// @param validBefore The authorization's `validBefore`.
    /// @param nonce The authorization's nonce.
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
    /// @dev The account calls it in the execution phase (the agent, with
    /// `(this policy, x402Reclaim)` on its allow-list, or the owner), so it
    /// may read the clock and the token. The charge returns only if the
    /// token's budget still counts the period it was charged in (`_refund`).
    /// @param id The permission id the authorization was registered under.
    /// @param token The EIP-3009 token.
    /// @param to The payee, as registered.
    /// @param value The amount, as registered.
    /// @param validAfter The authorization's `validAfter`, as registered.
    /// @param validBefore The authorization's `validBefore`, as registered.
    /// @param nonce The authorization's nonce, as registered.
    function x402Reclaim(
        bytes32 id,
        address token,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) external {
        // The permission's current installation, and the token's limit under it
        Config storage c = _configs[id][msg.sender];
        bytes32 m = _mandate(id, c.epoch);
        TokenLimit storage t = _token(msg.sender, m, token);
        // The digest of these terms, with the account as the payer
        bytes32 digest = _x402Digest(t.domainSeparator, msg.sender, to, value, validAfter, validBefore, nonce);
        Pending storage p = _pending(msg.sender, m, digest);
        // The digest names the token only through its domain separator; two
        // tokens that share one must not stand in for each other here.
        if (p.value == 0 || p.token != token) revert X402NotRegistered();
        // Still usable at the token: nothing to give back yet
        if (block.timestamp < validBefore) revert X402StillLive();
        // Used, or cancelled, at the token: the charge stays
        if (IERC3009State(token).authorizationState(msg.sender, nonce)) revert X402Settled();
        // Record it, then give the charge back and delete the registration
        emit X402Reclaimed(msg.sender, id, digest, p.value);
        _refund(m, digest, token, t, p.value);
    }

    /// @notice Executed after validation registered the order: only leaves
    /// a record for wallets. An order's charge is not given back: whether a
    /// venue filled an order cannot be read from the venue for good (CoW's
    /// settlement lets a solver clear the record of an expired order), so
    /// the budget rests on this policy's own counters alone. An unfilled
    /// order's part of the budget returns when the period turns.
    /// @dev The registration was made by `_registerOrder` in the operation's
    /// validation, from these same arguments. The second parameter, the
    /// owner's config for the venue, is not read here.
    /// @param decoder The venue's decoder.
    /// @param order The order, in the decoder's encoding.
    function orderRegister(address decoder, bytes calldata, /* config */ bytes calldata order) external {
        emit OrderRegistered(msg.sender, decoder, order);
    }

    /// The most gas a decoder gets to judge an order, so that it cannot spend
    /// the operation's whole verification gas
    uint256 internal constant JUDGE_GAS = 150_000;

    /// @dev Asks a venue's decoder about `order`, by `STATICCALL` with a gas
    /// bound. False unless the decoder is one of the mandate's venues, its
    /// code is the code the owner pinned, `config` is the owner's, and the
    /// answer is exactly the five words of `IVenueDecoder.judge`.
    /// @param m The mandate key.
    /// @param decoder The decoder the operation names.
    /// @param config The owner's config for the venue, as the operation carries it.
    /// @param order The order, in the decoder's encoding.
    /// @return j The decoder's answer; `ok` false if any check fails.
    function _askDecoder(bytes32 m, address decoder, bytes calldata config, bytes calldata order)
        internal
        view
        returns (Judged memory j)
    {
        // A venue of this mandate, its code still as pinned, and the owner's config
        VenuePin storage v = _venue(msg.sender, m, decoder);
        if (v.codeHash == bytes32(0) || decoder.codehash != v.codeHash || keccak256(config) != v.configHash) {
            return j;
        }
        // A static call cannot change state; a revert is the decoder's no
        (bool ok, bytes memory answer) =
            decoder.staticcall{gas: JUDGE_GAS}(abi.encodeCall(IVenueDecoder.judge, (msg.sender, config, order)));
        if (!ok || answer.length != 5 * 32) return j;
        // Read whole words, so that a value too wide for its type is refused, not cut
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
    /// @param m The mandate key.
    /// @param d The call's calldata, selector included.
    /// @return True if the order is registered and charged.
    function _registerOrder(bytes32 m, bytes calldata d) internal returns (bool) {
        // The arguments, in their canonical encoding only
        (bool ok, address decoder, bytes calldata config, bytes calldata order) = _orderArguments(d);
        if (!ok) return false;
        // The decoder's answer, for an order that sells something
        Judged memory j = _askDecoder(m, decoder, config, order);
        if (!j.ok || j.mostSold == 0) return false;
        // Under a period, the order ends with the period it is charged in
        if (!_endsWithThePeriod(uint256(j.validTo) + 1)) return false; // fillable up to and at `validTo`
        // A token with a limit, and without a payee list
        TokenLimit storage t = _token(msg.sender, m, j.token);
        if (!t.set || t.payeesOnly) return false;
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(j.token, j.mostSold) > t.maxPerOp) return false;
        // The token's budget, shared with transfers and x402
        uint256 spent = _tokenSpent(m, j.token, t) + j.mostSold;
        if (spent > t.budget) return false;
        // Record the digest for `checkSignaturePolicy`; the same order registers once
        if (!_recordX402(m, j.digest, j.mostSold, j.validTo, j.token)) return false;
        // Charge it
        t.spent = uint128(spent);
        // The operation is valid from the latest "not before" and up to the earliest `validTo`
        if (j.notBefore > _perOperation(NOT_BEFORE)) _setPerOperation(NOT_BEFORE, j.notBefore);
        uint256 notAfter = _perOperation(NOT_AFTER);
        if (notAfter == 0 || uint256(j.validTo) + 1 < notAfter) _setPerOperation(NOT_AFTER, uint256(j.validTo) + 1);
        return true;
    }

    /// @dev `orderRegister`'s arguments, where they sit in the calldata:
    /// the canonical encoding only, to the last byte. False otherwise.
    /// One encoding means one reading: what is judged here is what
    /// `orderRegister` decodes and records.
    /// @param d The call's calldata, selector included.
    /// @return True if the arguments are canonically encoded.
    /// @return decoder The decoder.
    /// @return config The owner's config, as carried.
    /// @return order The order.
    function _orderArguments(bytes calldata d)
        internal
        pure
        returns (bool, address decoder, bytes calldata config, bytes calldata order)
    {
        // Empty slices until the arguments are found
        (config, order) = (d[0:0], d[0:0]);
        // selector, three head words and two length words at the least
        if (d.length < 4 + 5 * 32) return (false, address(0), config, order);
        bytes calldata a = d[4:];
        // Word 0, the decoder, with nothing above its 160 bits; word 1, the
        // config's offset, right after the head; word 3, the config's length,
        // bounded by the calldata so that no sum below overflows
        uint256 first = uint256(bytes32(a[0:32]));
        uint256 configLength = uint256(bytes32(a[96:128]));
        if (first >> 160 != 0 || uint256(bytes32(a[32:64])) != 96 || configLength > a.length) {
            return (false, address(0), config, order);
        }
        // Word 2, the order's offset, right after the config padded to whole words
        uint256 orderAt = 128 + ((configLength + 31) & ~uint256(31));
        if (uint256(bytes32(a[64:96])) != orderAt || orderAt + 32 > a.length) {
            return (false, address(0), config, order);
        }
        // The order's length, and nothing after its padded bytes
        uint256 orderLength = uint256(bytes32(a[orderAt:orderAt + 32]));
        if (orderLength > a.length || a.length != orderAt + 32 + ((orderLength + 31) & ~uint256(31))) {
            return (false, address(0), config, order);
        }
        return (true, address(uint160(first)), a[128:128 + configLength], a[orderAt + 32:orderAt + 32 + orderLength]);
    }

    /// @notice A registration under the permission's current installation:
    /// an x402 authorization or an order, by its digest.
    /// @param account The account.
    /// @param id The permission id.
    /// @param digest The authorization's or the order's digest.
    /// @return The `Pending`; a zero `value` if the digest is not registered.
    function x402Pending(address account, bytes32 id, bytes32 digest) external view returns (Pending memory) {
        return _pending(account, _mandate(id, _configs[id][account].epoch), digest);
    }

    /// @dev The EIP-712 digest of an EIP-3009 `TransferWithAuthorization`:
    /// the hash the token hands to `isValidSignature`.
    /// @param domainSeparator The token's EIP-712 domain separator.
    /// @param from The payer.
    /// @param to The payee.
    /// @param value The amount.
    /// @param validAfter The authorization's `validAfter`.
    /// @param validBefore The authorization's `validBefore`.
    /// @param nonce The authorization's nonce.
    /// @return The digest.
    function _x402Digest(
        bytes32 domainSeparator,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal pure returns (bytes32) {
        // The struct hash: the type hash and the six fields
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        // The digest: "\x19\x01", the token's domain separator, the struct hash
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @dev Validation of `x402Authorize(...)`: judged like a transfer of the
    /// token (per-op cap, shared budget), then the digest is recorded.
    /// @param m The mandate key.
    /// @param d The call's calldata, selector included.
    /// @return True if the authorization is registered and charged.
    function _registerX402(bytes32 m, bytes calldata d) internal returns (bool) {
        // The seven static arguments, exactly
        if (d.length != 4 + 7 * 32) return false;
        (address token, address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce) =
            abi.decode(d[4:], (address, address, address, uint256, uint256, uint256, bytes32));
        if (from != msg.sender) return false; // the account checkUserOpPolicy runs for
        // A token with a limit and an EIP-712 domain
        TokenLimit storage t = _token(msg.sender, m, token);
        if (!t.set || t.domainSeparator == bytes32(0)) return false;
        // Something to pay (a zero value marks no registration), and an end that fits `Pending`
        if (value == 0 || validBefore > type(uint48).max) return false;
        // Under a period, the authorization ends with the period it is charged in
        if (!_endsWithThePeriod(validBefore)) return false; // usable before `validBefore`
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(token, value) > t.maxPerOp) return false;
        // The payee list, if the token has one
        if (t.payeesOnly && !_payees[_payeeKey(m, token, to)][msg.sender]) return false;
        // The token's budget, shared with transfers and orders
        uint256 spent = _tokenSpent(m, token, t) + value;
        if (spent > t.budget) return false;
        // Record the digest the token will ask about; the same authorization registers once
        bytes32 digest = _x402Digest(t.domainSeparator, from, to, value, validAfter, validBefore, nonce);
        if (!_recordX402(m, digest, value, validBefore, token)) return false;
        // Charge it
        t.spent = uint128(spent);
        return true;
    }

    /// @dev Under a budget per period, whether a registration that can be
    /// used before `notAfter` (exclusive) is over when the period it is
    /// charged in is. Without a period, always.
    /// @param notAfter The first second the registration can no longer be used in.
    /// @return True if the registration ends with the operation's period, or there are no periods.
    function _endsWithThePeriod(uint256 notAfter) internal view returns (bool) {
        uint256 next = _perOperation(PERIOD_NEXT);
        return next == 0 || notAfter <= next;
    }

    /// @dev Records a registered authorization; false when its digest is
    /// already there. Orders are recorded here too, their `validTo` as
    /// `validBefore`.
    /// @param m The mandate key.
    /// @param digest The digest `checkSignaturePolicy` will vouch for.
    /// @param value The amount charged; never 0 here.
    /// @param validBefore The last second it is vouched for.
    /// @param token The token charged.
    /// @return True if recorded.
    function _recordX402(bytes32 m, bytes32 digest, uint256 value, uint256 validBefore, address token)
        internal
        returns (bool)
    {
        // Once per digest
        Pending storage p = _pending(msg.sender, m, digest);
        if (p.value != 0) return false;
        // Never truncated
        if (value > type(uint128).max) return false;
        // The record, and the period it was charged in (0 without periods)
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

    // Per-operation notes, kept beside the token totals in transient
    // storage, at `keccak256(account ‖ name)`. Not keyed by the operation
    // counter: `_enterPeriod` writes all four afresh at the start of every
    // `checkUserOpPolicy`.
    /// The period the operation is in, plus one; 0 without periods.
    bytes32 internal constant PERIOD_NOW = keccak256("agent-keys.AgentPolicy.periodNow");
    /// The first second after that period; 0 without periods.
    bytes32 internal constant PERIOD_NEXT = keccak256("agent-keys.AgentPolicy.periodNext");
    /// The latest "not before" of the orders it registers; 0 = none.
    bytes32 internal constant NOT_BEFORE = keccak256("agent-keys.AgentPolicy.notBefore");
    /// The earliest `validTo` of the orders it registers, plus one; 0 = none.
    bytes32 internal constant NOT_AFTER = keccak256("agent-keys.AgentPolicy.notAfter");

    /// @dev Reads one of the operation's notes.
    /// @param what The note's name (`PERIOD_NOW`, ...).
    /// @return value The note; 0 if never written in this transaction.
    function _perOperation(bytes32 what) internal view returns (uint256 value) {
        uint256 slot = uint256(keccak256(abi.encode(msg.sender, what)));
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }

    /// @dev Writes one of the operation's notes.
    /// @param what The note's name.
    /// @param value The note.
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
    /// @param token The token.
    /// @param amount What the call moves, approves or registers.
    /// @return total What the operation has moved of the token, this call included.
    function _movedThisOperation(address token, uint256 amount) internal returns (uint256 total) {
        // The operation's counter
        uint256 seqSlot = uint256(keccak256(abi.encode(msg.sender, OPERATION_SEQ)));
        uint256 seq;
        assembly ("memory-safe") {
            seq := tload(seqSlot)
        }
        // The total of this operation and token, in the account's transient slots
        uint256 slot = uint256(keccak256(abi.encode(msg.sender, keccak256(abi.encode(seq, token)))));
        uint256 before;
        assembly ("memory-safe") {
            before := tload(slot)
        }
        // Add the amount; an overflow reverts, and the operation with it
        total = before + amount;
        assembly ("memory-safe") {
            tstore(slot, total)
        }
    }

    /// @dev `(verificationGasLimit + callGasLimit + preVerificationGas) *
    /// maxFeePerGas` — the EntryPoint's required prefund without a paymaster.
    /// @param userOp The user operation.
    /// @return The most the operation can charge the account's deposit, in wei.
    function _maxGasCost(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        // `accountGasLimits`: verificationGasLimit in the high 128 bits, callGasLimit in the low
        uint256 limits = uint256(userOp.accountGasLimits);
        uint256 gas = (limits >> 128) + uint128(limits) + userOp.preVerificationGas;
        // `gasFees`: maxFeePerGas in the low 128 bits
        return gas * uint128(uint256(userOp.gasFees));
    }

    /// @dev Accepts `execute(mode, executionCalldata)` with a single call or a
    /// batch, default exec type, and judges every call; returns the native
    /// value the operation moves.
    /// @param m The mandate key.
    /// @param callData The operation's `callData`.
    /// @return True if every call passes.
    /// @return The native value the operation moves, Safe transactions and batch legs included.
    function _judgeExecute(bytes32 m, bytes calldata callData) internal returns (bool, uint256) {
        // selector + mode + offset + length is the smallest well-formed call
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Account.execute.selector) return (false, 0);
        // The mode's first byte is the call type, its second the exec type
        (CallType callType, ExecType execType,,) = ExecLib.decode(ExecMode.wrap(bytes32(callData[4:36])));
        // A "try" batch would let a failed nonce assertion pass silently.
        if (!(execType == EXECTYPE_DEFAULT)) return (false, 0);

        // `executionCalldata`: its offset, its length word and its bytes, within the calldata
        uint256 start = 4 + uint256(bytes32(callData[36:68]));
        if (callData.length < start + 32) return (false, 0);
        uint256 length = uint256(bytes32(callData[start:start + 32]));
        if (callData.length < start + 32 + length) return (false, 0);
        bytes calldata executionData = callData[start + 32:start + 32 + length];

        // A single call is the account's own
        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
            return _judge(m, target, value, data, FROM_ACCOUNT);
        }
        // A batch, leg by leg; any other call type (delegatecall, static) is refused
        if (callType == CALLTYPE_BATCH) return _judgeAccountBatch(m, LibERC7579.decodeBatch(executionData));
        return (false, 0);
    }

    /// @dev The account's own batch. A Safe transaction is admitted only as
    /// the leg right after `SafeNonceAssert.check(thatSafe, n)`.
    /// @param m The mandate key.
    /// @param pointers The batch, as Solady's `decodeBatch` points into it.
    /// @return True if every leg passes; an empty batch is refused.
    /// @return moved The native value the legs move, together.
    function _judgeAccountBatch(bytes32 m, bytes32[] calldata pointers) internal returns (bool, uint256 moved) {
        if (pointers.length == 0) return (false, 0);
        uint256 i;
        while (i < pointers.length) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
            bool ok;
            uint256 legMoved;
            // A nonce assertion takes the Safe transaction after it along: two legs
            if (target == NONCE_ASSERT) {
                (ok, legMoved) = _judgeGuarded(m, pointers, i, value, data);
                i += 2;
            } else {
                (ok, legMoved) = _judge(m, target, value, data, FROM_ACCOUNT);
                i += 1;
            }
            // One refused leg refuses the operation
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Leg `i` is a nonce assertion; leg `i + 1` must be the Safe
    /// transaction it guards. The nonce itself is checked at execution, by
    /// `SafeNonceAssert`.
    /// @param m The mandate key.
    /// @param pointers The account's batch.
    /// @param i The index of the assertion leg.
    /// @param value The assertion leg's value.
    /// @param data The assertion leg's calldata.
    /// @return True if the pair passes.
    /// @return The native value the Safe transaction moves.
    function _judgeGuarded(bytes32 m, bytes32[] calldata pointers, uint256 i, uint256 value, bytes calldata data)
        internal
        returns (bool, uint256)
    {
        // The assertion: no value, exactly `check(address,uint256)`, and a leg after it
        if (value != 0 || data.length != 68 || bytes4(data[0:4]) != NONCE_CHECK || i + 1 >= pointers.length) {
            return (false, 0);
        }
        // The Safe it guards: the low 160 bits of its first argument
        // (`check` reverts at execution on anything above them)
        address guarded = address(uint160(uint256(bytes32(data[4:36]))));
        // The next leg must be that Safe's `execTransaction`
        (address safe, uint256 safeValue, bytes calldata safeData) = LibERC7579.getExecution(pointers, i + 1);
        if (safe != guarded || _selector(safeData) != SAFE_EXEC_TRANSACTION) return (false, 0);
        // Judged as guarded, the one form `_judgeSafe` admits
        return _judge(m, safe, safeValue, safeData, FROM_ACCOUNT_GUARDED);
    }

    /// @dev Decides one call and returns the total value it moves, including
    /// what moves inside it (a Safe transaction, a batch's legs). Token
    /// amounts are charged to their budgets on the way.
    /// @param m The mandate key.
    /// @param target The call's target.
    /// @param value The call's native value.
    /// @param data The call's calldata.
    /// @param from Where the call sits (`FROM_ACCOUNT`, ...).
    /// @return ok True if the call passes.
    /// @return moved The native value it moves; 0 when refused.
    function _judge(bytes32 m, address target, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        bytes4 selector = _selector(data);
        // The zero selector stands for a plain transfer, which carries no
        // calldata. 1–3 bytes would run the target's fallback, and so would
        // a longer body that happens to start with four zero bytes.
        if (selector == bytes4(0) && data.length != 0) return (false, 0);
        // On the allow-list
        if (!_allowed[_allowedKey(m, target, selector)][msg.sender]) return (false, 0);
        // Install refuses these; refused again here so that no mandate, in
        // any version's storage, can reach the account or the policy itself.
        // The EntryPoint is refused at install only, on purpose: checking it
        // here would cost a staticcall per operation, and every mandate this
        // version holds went through that install-time filter. The check here
        // also catches a venue's place pinned by a mandate installed after
        // this one.
        if (!_targetAllowed(target, selector)) return (false, 0);
        // A batch is only meaningful delegatecalled by a Safe (below); called
        // any other way its legs would run as the batch contract.
        if (selector == MULTI_SEND) return (false, 0);
        // A Safe transaction: the call inside it is what is judged
        if (selector == SAFE_EXEC_TRANSACTION) return _judgeSafe(m, value, data, from);
        // x402: registering an authorization is the account's own call only
        // (the records are kept for the account, not for a Safe)
        if (target == address(this) && selector == this.x402Authorize.selector) {
            return (from == FROM_ACCOUNT && value == 0 && _registerX402(m, data)) ? (true, 0) : (false, 0);
        }
        // a venue's order: the same, through the venue's decoder
        if (target == address(this) && selector == this.orderRegister.selector) {
            return (from == FROM_ACCOUNT && value == 0 && _registerOrder(m, data)) ? (true, 0) : (false, 0);
        }
        // Any other call: the ERC-20 rules, if the target is a token with a limit
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
    /// itself) and this policy, except the three entry points the account
    /// calls on purpose: `x402Authorize`, `x402Reclaim` and `orderRegister`.
    /// `msg.sender` is the account in both callers.
    /// And Permit2: it holds one allowance per token and its own `approve`
    /// names who may pull it, a call this policy does not read, so through
    /// it a token would leave past its cap and its payee list. Refused until
    /// the policy meters Permit2's calls. This closes the one well-known
    /// contract of that shape, not the shape: any allow-listed contract
    /// that holds an allowance from the account can move it.
    /// And every place of the account's venues (`_venuePlaces`).
    /// @param target The target.
    /// @param selector The selector, which matters only for this policy.
    /// @return True if the target may be on an allow-list.
    function _targetAllowed(address target, bytes4 selector) internal view returns (bool) {
        if (target == msg.sender || target == PERMIT2) return false;
        if (_venuePlaces[target][msg.sender]) return false;
        if (target == address(this)) {
            return selector == this.x402Authorize.selector || selector == this.x402Reclaim.selector
                || selector == this.orderRegister.selector;
        }
        return true;
    }

    /// @dev The account's EntryPoint, read from Kernel at install so that
    /// `withdrawTo` and friends on the account's deposit can never be
    /// allow-listed. Zero when the account does not answer (not a Kernel):
    /// the install is then refused, since the check could not be made.
    /// @param account The account.
    /// @return The EntryPoint's address; zero if the account does not answer.
    function _entryPointOf(address account) internal view returns (address) {
        (bool ok, bytes memory ret) = account.staticcall(abi.encodeWithSelector(IKernelEntryPoint.entrypoint.selector));
        if (!ok || ret.length < 32) return address(0);
        return abi.decode(ret, (address));
    }

    /// @dev An allow-listed Safe: the call that matters is the inner one.
    /// @param m The mandate key.
    /// @param value The native value the account sends the Safe.
    /// @param data The `execTransaction` calldata.
    /// @param from Where the call sits; only `FROM_ACCOUNT_GUARDED` passes.
    /// @return ok True if the Safe transaction passes.
    /// @return moved The value sent to the Safe plus what moves inside it; 0 when refused.
    function _judgeSafe(bytes32 m, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        // Only the account's own nonce-guarded call; Safes do not nest.
        if (from != FROM_ACCOUNT_GUARDED) return (false, 0);
        // The parts of the call the policy rules on
        (bool decoded, address to, uint256 innerValue, uint256 operation, bytes calldata inner) = _decodeSafeExec(data);
        if (!decoded) return (false, 0);
        // CALL (0): the inner call is judged like any other, from the Safe.
        // DELEGATECALL (1): only into an allow-listed MultiSend batch, with no
        // value named, and every leg judged. Any other operation is refused.
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
    /// An approval is charged like a transfer: what the spender later pulls
    /// is not seen.
    /// @param m The mandate key.
    /// @param token The call's target.
    /// @param selector The call's selector.
    /// @param data The call's calldata.
    /// @return True if the call passes.
    function _chargeToken(bytes32 m, address token, bytes4 selector, bytes calldata data)
        internal
        returns (bool)
    {
        // The argument that holds the amount; 0 for a function not metered
        uint256 arg;
        if (selector == ERC20_TRANSFER || selector == ERC20_APPROVE || selector == ERC20_INCREASE_ALLOWANCE) arg = 1;
        else if (selector == ERC20_TRANSFER_FROM) arg = 2;

        // A function not metered passes on a token without a limit only; a
        // metered one on a token with a limit only
        TokenLimit storage t = _token(msg.sender, m, token);
        if (arg == 0) return !t.set;
        if (!t.set) return false;
        // The amount, from calldata long enough to hold it
        uint256 end = 4 + 32 * (arg + 1);
        if (data.length < end) return false;
        uint256 amount = uint256(bytes32(data[end - 32:end]));
        if (t.payeesOnly) {
            // the word before the amount; a token reads its low 160 bits, so
            // anything above them would name one address here and pay another
            uint256 payee = uint256(bytes32(data[end - 64:end - 32]));
            if (payee >> 160 != 0 || !_payees[_payeeKey(m, token, address(uint160(payee)))][msg.sender]) return false;
        }
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(token, amount) > t.maxPerOp) return false;
        // The token's budget, in the current period if there is one
        uint256 spent = _tokenSpent(m, token, t) + amount;
        if (spent > t.budget) return false;
        // Charge it
        t.spent = uint128(spent);
        return true;
    }

    /// @dev `multiSend(bytes transactions)`, each transaction packed as
    /// `operation (1) ‖ to (20) ‖ value (32) ‖ dataLength (32) ‖ data`.
    /// Every leg must be a CALL the mandate accepts.
    /// @param m The mandate key.
    /// @param d The `multiSend` calldata, selector included.
    /// @return True if every leg passes; an empty batch is refused.
    /// @return moved The native value the legs move, together.
    function _judgeBatch(bytes32 m, bytes calldata d) internal returns (bool, uint256 moved) {
        // The packed transactions, at least one byte of them
        (bool ok, bytes calldata txs) = _batchTransactions(d);
        if (!ok || txs.length == 0) return (false, 0);
        uint256 i;
        // Leg by leg to the end; one refused leg refuses the batch
        while (i < txs.length) {
            uint256 legMoved;
            (ok, legMoved, i) = _judgeLeg(m, txs, i);
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Judges the batch leg at `i` and returns where the next one starts.
    /// @param m The mandate key.
    /// @param txs The packed transactions.
    /// @param i Where the leg starts.
    /// @return ok True if the leg passes.
    /// @return moved The native value it moves.
    /// @return next Where the next leg starts.
    function _judgeLeg(bytes32 m, bytes calldata txs, uint256 i)
        internal
        returns (bool ok, uint256 moved, uint256 next)
    {
        // A whole CALL leg
        (bool parsed, address to, uint256 value, bytes calldata data) = _leg(txs, i);
        if (!parsed) return (false, 0, 0);
        // Judged as a batch leg: it runs as the Safe
        (ok, moved) = _judge(m, to, value, data, FROM_BATCH);
        // After its 85-byte header and its data
        next = i + 85 + data.length;
    }

    /// @dev The `bytes transactions` argument of a `multiSend` call.
    /// @param d The `multiSend` calldata, selector included.
    /// @return ok True if the argument lies within the calldata.
    /// @return txs The packed transactions.
    function _batchTransactions(bytes calldata d) internal pure returns (bool ok, bytes calldata txs) {
        txs = d[0:0];
        // selector + offset + length
        if (d.length < 68) return (false, txs);
        // The offset, bounded by the calldata before any sum
        uint256 offset = uint256(bytes32(d[4:36]));
        if (offset > d.length) return (false, txs);
        // The length word, then the bytes, within the calldata
        uint256 start = 4 + offset;
        if (d.length < start + 32) return (false, txs);
        uint256 length = uint256(bytes32(d[start:start + 32]));
        if (length > d.length || d.length < start + 32 + length) return (false, txs);
        return (true, d[start + 32:start + 32 + length]);
    }

    /// @dev The batch leg starting at `i`; CALL legs only.
    /// @param txs The packed transactions.
    /// @param i Where the leg starts.
    /// @return ok True if the leg is a whole CALL leg.
    /// @return to The leg's target.
    /// @return value The leg's native value.
    /// @return data The leg's calldata.
    function _leg(bytes calldata txs, uint256 i)
        internal
        pure
        returns (bool ok, address to, uint256 value, bytes calldata data)
    {
        data = txs[0:0];
        // A whole header, and operation 0 (CALL)
        if (txs.length < i + 85 || uint8(txs[i]) != 0) return (false, address(0), 0, data);
        // to (20 bytes), value (32), the data's length (32)
        to = address(bytes20(txs[i + 1:i + 21]));
        value = uint256(bytes32(txs[i + 21:i + 53]));
        uint256 length = uint256(bytes32(txs[i + 53:i + 85]));
        // The data, within the packed bytes
        if (length > txs.length || txs.length < i + 85 + length) return (false, address(0), 0, data);
        data = txs[i + 85:i + 85 + length];
        ok = true;
    }

    /// @dev Reads the parts of a `Safe.execTransaction` call the policy rules
    /// on, straight from the ABI head (the Safe decodes the same words), and
    /// refuses gas refunds.
    /// @param d The `execTransaction` calldata, selector included.
    /// @return ok True if the call is well formed and asks for no refund.
    /// @return to The inner call's target.
    /// @return value The inner call's native value.
    /// @return operation 0 for CALL, 1 for DELEGATECALL.
    /// @return inner The inner call's calldata.
    function _decodeSafeExec(bytes calldata d)
        internal
        pure
        returns (bool ok, address to, uint256 value, uint256 operation, bytes calldata inner)
    {
        inner = d[0:0];
        // selector + ten head words
        if (d.length < 324) return (false, address(0), 0, 0, inner);
        // Head words 0 to 3: to, value, the data's offset, operation
        to = address(uint160(uint256(bytes32(d[4:36]))));
        value = uint256(bytes32(d[36:68]));
        uint256 dataOffset = uint256(bytes32(d[68:100]));
        operation = uint256(bytes32(d[100:132]));
        // Head word 6, gasPrice: non-zero, the Safe would pay a refund out of
        // its own funds to a receiver the agent picks
        if (uint256(bytes32(d[196:228])) != 0) return (false, address(0), 0, 0, inner); // gasPrice: no refunds

        // The data: its offset bounded before any sum, then its length and bytes within the calldata
        if (dataOffset > d.length) return (false, address(0), 0, 0, inner);
        uint256 start = 4 + dataOffset;
        if (d.length < start + 32) return (false, address(0), 0, 0, inner);
        uint256 length = uint256(bytes32(d[start:start + 32]));
        if (length > d.length || d.length < start + 32 + length) return (false, address(0), 0, 0, inner);
        inner = d[start + 32:start + 32 + length];
        ok = true;
    }

    /// @dev `0x00000000` stands for "no calldata": a plain value transfer.
    /// @param data The call's calldata.
    /// @return Its first four bytes; zero for calldata shorter than four bytes.
    function _selector(bytes calldata data) internal pure returns (bytes4) {
        return data.length >= 4 ? bytes4(data[0:4]) : bytes4(0);
    }
}
