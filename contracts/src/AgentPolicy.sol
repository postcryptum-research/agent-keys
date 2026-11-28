// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

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
import {IShapeJudge, SHAPE_BATCH, SHAPE_WALLET} from "./judges/IShapeJudge.sol";
import {Config, Pending, PolicyStorage, ShapePin, TokenLimit, VenuePin} from "./policy/PolicyStorage.sol";
import {PolicyInstall} from "./policy/PolicyInstall.sol";
import {
    AUTHORIZE_OPERATOR,
    ERC20_APPROVE,
    ERC20_INCREASE_ALLOWANCE,
    ERC20_TRANSFER,
    ERC20_TRANSFER_FROM,
    ERC6909_APPROVE,
    ERC6909_TRANSFER,
    ERC6909_TRANSFER_FROM,
    PERMIT2,
    PolicyRules
} from "./policy/PolicyRules.sol";
import {IVenueDecoder} from "./venues/IVenueDecoder.sol";
import {VenueCalls} from "./venues/VenueCalls.sol";

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

    /// Install-time pin of one shape judge (`IShapeJudge`, issue #251), in the
    /// twelve-word form. The judge's code names the selectors it reads and
    /// their roles; each selector has one judge per mandate.
    struct ShapeJudge {
        // The judge; it must have code
        address judge;
        // Its code hash (`EXTCODEHASH`) as the owner reviewed it; install checks
        // the code against it, and code at an address cannot change after
        // (EIP-6780)
        bytes32 codeHash;
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

    /// Install-time limit for one id of an ERC-6909 contract: what `TokenCap`
    /// is for an ERC-20 token, per `(token, id)`. No x402 and no payee list.
    struct IdCap {
        // The ERC-6909 contract; not zero, and not a token with a `TokenCap`
        address token;
        // The token id; one cap per `(token, id)`
        uint256 id;
        // The most of the id one operation may move, summed over its calls
        uint128 maxPerOp;
        // The most of the id the mandate may move: over its whole life, or
        // in each period
        uint128 budget;
    }

    /// Install-time list of the only addresses a token's transfers,
    /// allowances and x402 payments may name. The token needs a `TokenCap`.
    struct TokenPayees {
        // The token; one list per token
        address token;
        // The addresses it may reach: at least one, none zero, none twice
        address[] payees;
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

    /// @dev The owner named a guardian for the permission's mandate; zero for none.
    /// @param account The account.
    /// @param id The permission id.
    /// @param guardian The guardian.
    event GuardianSet(address indexed account, bytes32 indexed id, address guardian);

    /// @dev A module of the permission's mandate was paused, or the pause lifted.
    /// @param account The account.
    /// @param id The permission id.
    /// @param module The shape judge or venue decoder.
    /// @param paused True when paused, false when the pause was lifted.
    event ModulePaused(address indexed account, bytes32 indexed id, address indexed module, bool paused);

    /// @dev Only the mandate's guardian, or the account itself, pauses or lifts a pause.
    error NotTheGuardian();

    /// @dev The address is none of the mandate's shape judges or venue decoders.
    error NotAModule();

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
    /// `setApprovalForAll(address,bool)` of ERC-721 and ERC-1155: an operator
    /// grant over every token of the contract, withdrawn like an allowance.
    /// Each kind of grant has its own open flag (`_noteAllowance`), so one
    /// function cannot close what another opened; install also keeps this
    /// and `approve` on different targets (`approve` needs a limit on its
    /// target, and this is refused on a target with one).
    bytes4 internal constant SET_APPROVAL_FOR_ALL = 0xa22cb465;
    /// `setOperator(address,bool)` of ERC-6909: the same grant in the same
    /// shape, held the same way
    bytes4 internal constant SET_OPERATOR = 0x558a7297;
    /// `executeUserOp(PackedUserOperation,bytes32)`: the prefix Kernel requires
    /// of the `callData` of a permission that carries an execution hook
    bytes4 internal constant EXECUTE_USER_OP = 0x8dd7712f;

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

    /// The fixed code that installs a mandate (issue #251), created by this
    /// policy's constructor, so that it can never be paired with another
    /// policy. `onInstall` runs it by DELEGATECALL, on this storage.
    address public immutable INSTALL;


    /// @dev The policy's storage, one namespaced layout (`PolicyStorage`).
    /// @return The layout.
    function _store() internal pure returns (PolicyStorage.Layout storage) {
        return PolicyStorage.store();
    }

    /// @notice The number of the account's permissions with a mandate here.
    /// @param account The account.
    /// @return The count; `isInitialized` reads it.
    function usedIds(address account) external view returns (uint256) {
        return _store().usedIds[account];
    }

    /// @dev Policy constructor.
    /// @param nonceAssert The SafeNonceAssert on this chain, kept as `NONCE_ASSERT`.
    constructor(address nonceAssert) {
        NONCE_ASSERT = nonceAssert;
        INSTALL = address(new PolicyInstall());
    }

    /// @dev The account's registration of a digest under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param digest An x402 authorization's or an order's digest.
    /// @return The `Pending`; a zero `value` if the digest is not registered.
    function _pending(address account, bytes32 m, bytes32 digest) internal view returns (Pending storage) {
        return _store().x402[keccak256(abi.encode(m, digest))][account];
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
        Config storage c = _store().configs[id][account];
        return (c.validUntil, c.epoch, c.maxValuePerOp, c.budget, c.spent, c.validAfter);
    }

    /// @notice The budgets' window of a permission in seconds (0: none) and
    /// the window its native `spent` counts for, plus one.
    /// @param account The account.
    /// @param id The permission id.
    /// @return seconds_ The window's length in seconds; 0 for one budget over the mandate's life.
    /// @return seen The window `spent` counts for, plus one; 0 before the first.
    function period(address account, bytes32 id) external view returns (uint32 seconds_, uint48 seen) {
        Config storage c = _store().configs[id][account];
        return (c.period, c.periodSeen);
    }

    /// @notice Whether `place` is, or ever was, a venue's own contract, its
    /// decoder or its spender in a mandate of `account`: then no mandate of
    /// the account may name it as a target.
    /// @param account The account.
    /// @param place The address asked about.
    /// @return True if the address is a venue's place: on no allow-list of the account.
    function venuePlace(address account, address place) external view returns (bool) {
        return _store().venuePlaces[place][account];
    }

    /// @notice The pinned code hash and config hash of a venue's decoder
    /// under the permission; zeros when it is not one of its venues.
    /// @param account The account.
    /// @param id The permission id; its current installation is read.
    /// @param decoder The decoder.
    /// @return The `VenuePin`.
    function venue(address account, bytes32 id, address decoder) external view returns (VenuePin memory) {
        return PolicyRules.venue(account, PolicyRules.mandate(id, _store().configs[id][account].epoch), decoder);
    }


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
        // The install code is the fixed PolicyInstall's, run on this policy's
        // storage: under DELEGATECALL the account stays the caller
        (bool ok, bytes memory answer) = INSTALL.delegatecall(abi.encodeCall(PolicyInstall.onInstall, (data)));
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(answer, 0x20), mload(answer))
            }
        }
    }

    /// @notice The key an id's limit is kept under, in the place of a token's
    /// address: `tokenLimit(account, permissionId, idAsset(token, id))` is
    /// the id's limit and what it has spent.
    /// @dev The low 160 bits of a tagged hash of `(token, id)`. Everything a
    /// token's limit has (the sum per operation, the budget, its period) is
    /// then the id's too. To use a limit meant for another id, or a token's,
    /// takes a second preimage of 160 bits.
    /// @param token The ERC-6909 contract.
    /// @param id The token id.
    /// @return The key, as an address.
    function idAsset(address token, uint256 id) public pure returns (address) {
        return PolicyRules.idAsset(token, id);
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
        Config storage c = _store().configs[id][msg.sender];
        if (c.validUntil == 0) revert NotInitialized(msg.sender);
        // Mark it uninstalled and move to a new epoch; the counters are reset at the next install
        c.validUntil = 0;
        c.validAfter = 0;
        c.epoch++;
        // Uncount the permission; every installed one was counted once
        _store().usedIds[msg.sender]--;
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
        return _store().usedIds[account] > 0;
    }

    /// @notice Whether the permission's current mandate has `(target, selector)`
    /// on its allow-list.
    /// @param account The account.
    /// @param id The permission id.
    /// @param target The target.
    /// @param selector The selector; zero for a plain value transfer.
    /// @return True if the entry is on the allow-list.
    function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool) {
        return _store().allowed[PolicyRules.allowedKey(PolicyRules.mandate(id, _store().configs[id][account].epoch), target, selector)][account]
            != 0;
    }

    /// @notice The permission's current limit for `token`, and what it has spent.
    /// @param account The account.
    /// @param id The permission id.
    /// @param token The token.
    /// @return The `TokenLimit`; `set` is false if the token has no limit.
    function tokenLimit(address account, bytes32 id, address token) external view returns (TokenLimit memory) {
        return PolicyRules.token(account, PolicyRules.mandate(id, _store().configs[id][account].epoch), token);
    }

    /// @notice Whether the mandate lets `token` reach `payee`: true for any
    /// address when the token has no payee list.
    /// @param account The account.
    /// @param id The permission id.
    /// @param token The token.
    /// @param payee The address asked about.
    /// @return True if a transfer, allowance or x402 payment of the token may name the address.
    function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool) {
        bytes32 m = PolicyRules.mandate(id, _store().configs[id][account].epoch);
        return !PolicyRules.token(account, m, token).payeesOnly || _store().payees[PolicyRules.payeeKey(m, token, payee)][account];
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
        Config storage c = _store().configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;

        // Fresh per-operation totals, then the window and the period the operation names
        _beginOperation();
        (bool inWindow, uint48 from, uint48 until) = _enterPeriod(c, userOp.signature);
        if (!inWindow) return SIG_VALIDATION_FAILED_UINT;
        // Judge every call; token amounts are charged on the way
        (bool ok, uint256 value) = _judgeExecute(PolicyRules.mandate(id, c.epoch), userOp.callData);
        if (!ok || value > c.maxValuePerOp) return SIG_VALIDATION_FAILED_UINT;
        // No allowance the agent granted outlives the operation
        if (_tload(_thisOperation(OPEN_ALLOWANCES)) != 0) return SIG_VALIDATION_FAILED_UINT;
        // And no call a decoder judged is left unmade: its registration without it is refused
        if (_tload(_thisOperation(EXPECTED_CALL)) != 0) return SIG_VALIDATION_FAILED_UINT;

        // Who pays for gas is read as the EntryPoint reads it: by the
        // address in the paymaster field's first twenty bytes, not by the
        // field's length. An empty field: the account pays out of its own
        // deposit, and the most it can be charged counts against the budget.
        // A field that names no paymaster, shorter than its 52 fixed bytes
        // or with the zero address: refused. The EntryPoint takes such an
        // operation's prefund from the account, the field's two gas limits
        // included, and nothing here would have counted it (#244).
        uint256 charged = value;
        bytes calldata paymasterField = userOp.paymasterAndData;
        if (paymasterField.length == 0) charged += _maxGasCost(userOp);
        else {
            // the address the EntryPoint unpacks: the field's first twenty bytes
            uint256 paymaster;
            assembly ("memory-safe") {
                paymaster := shr(96, calldataload(paymasterField.offset))
            }
            if (paymasterField.length < 52 || paymaster == 0) return SIG_VALIDATION_FAILED_UINT;
        }
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
            // Strictly below the 48-bit maximum, so that `seen` (index + 1) and
            // the next period's start (end + 1) fit in 48 bits too
            if (end >= type(uint48).max) return (false, 0, 0);
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
            if (_store().tokenPeriod[key][msg.sender] != seen) {
                _store().tokenPeriod[key][msg.sender] = uint48(seen);
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
        if (_store().chargedIn[key][msg.sender] == _store().tokenPeriod[keccak256(abi.encode(m, token))][msg.sender]) {
            t.spent -= value;
        }
        delete _store().chargedIn[key][msg.sender];
        delete _store().x402[key][msg.sender];
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
        Config storage c = _store().configs[id][msg.sender];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;
        // The hash must be registered under the current installation
        Pending storage p = _pending(msg.sender, PolicyRules.mandate(id, c.epoch), hash);
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
        Config storage c = _store().configs[id][msg.sender];
        bytes32 m = PolicyRules.mandate(id, c.epoch);
        TokenLimit storage t = PolicyRules.token(msg.sender, m, token);
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

    /// @notice Names the guardian of the permission's current mandate (#251,
    /// decision 2), or zero for none: the owner's step, from the account. The
    /// code is the fixed `PolicyInstall`'s (`setGuardian` there).
    function setGuardian(bytes32, address) external {
        _install();
    }

    /// @notice Pauses one module of an account's mandate, a shape judge or a
    /// venue decoder, or lifts the pause: the mandate's guardian or the
    /// account. The code is the fixed `PolicyInstall`'s (`pause` there).
    function pause(address, bytes32, address, bool) external {
        _install();
    }

    /// @dev Runs this call in the fixed `PolicyInstall`, on this policy's
    /// storage: under DELEGATECALL the caller stays the caller.
    function _install() internal {
        (bool ok, bytes memory answer) = INSTALL.delegatecall(msg.data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(answer, 0x20), mload(answer))
            }
        }
    }

    /// @notice The guardian of the permission's current mandate; zero for none.
    /// @param account The account.
    /// @param id The permission id.
    /// @return The guardian.
    function guardian(address account, bytes32 id) external view returns (address) {
        return _store().guardians[keccak256(abi.encode(PolicyRules.mandate(id, _store().configs[id][account].epoch)))][account];
    }

    /// @notice Whether a module of the permission's current mandate, a shape
    /// judge or a venue decoder, is paused.
    /// @param account The account.
    /// @param id The permission id.
    /// @param module The shape judge or venue decoder.
    /// @return True when paused.
    function paused(address account, bytes32 id, address module) external view returns (bool) {
        return _store().modulePaused[keccak256(abi.encode(PolicyRules.mandate(id, _store().configs[id][account].epoch), module))][
            account
        ] != 0;
    }

    /// @notice Executed after validation registered the order: only leaves
    /// a record for wallets. An order's charge is not given back: whether a
    /// venue filled an order cannot be read from the venue for good (CoW's
    /// settlement lets a solver clear the record of an expired order), so
    /// the budget rests on this policy's own counters alone. An unfilled
    /// order's part of the budget returns when the period turns.
    /// A decoder may judge a call instead of an order (`VenueCalls`): the
    /// registration then admits that one call, at the decoder's own venue,
    /// as the operation's next leg, and keeps nothing of it but this record.
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
        VenuePin storage v = PolicyRules.venue(msg.sender, m, decoder);
        if (v.codeHash == bytes32(0) || decoder.codehash != v.codeHash || keccak256(config) != v.configHash) {
            return j;
        }
        // Paused by the mandate's guardian: refused, the rest of the mandate runs
        if (_store().modulePaused[keccak256(abi.encode(m, decoder))][msg.sender] != 0) return j;
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
    /// be paid. A decoder that answers without a `validTo` judged a call the
    /// account makes in the next leg: it is charged the same way when the
    /// decoder prices it, nothing is recorded, and its hash is kept, bound to
    /// the decoder's venue, for `_judgeVenueCall`.
    /// @param m The mandate key.
    /// @param d The call's calldata, selector included.
    /// @return True if the order, or the call, is registered and charged.
    function _registerOrder(bytes32 m, bytes calldata d) internal returns (bool) {
        // The arguments, in their canonical encoding only
        (bool ok, address decoder, bytes calldata config, bytes calldata order) = _orderArguments(d);
        if (!ok) return false;
        // The decoder's answer, for an order that sells something
        Judged memory j = _askDecoder(m, decoder, config, order);
        if (!j.ok) return false;
        // No `validTo`: the decoder judged a call the account makes now, in
        // the leg after this one, not an order a venue fills later
        bool call = j.validTo == 0;
        if (j.mostSold == 0) {
            // An order sells something. A call may take nothing through this
            // charge: what it takes through an allowance the agent gives in the
            // same operation is charged there
            if (!call) return false;
        } else {
            // Under a period, the order ends with the period it is charged in; a call is over at once
            if (!_endsWithThePeriod(uint256(j.validTo) + 1)) return false; // fillable up to and at `validTo`
            // A token with a limit, and without a payee list
            TokenLimit storage t = PolicyRules.token(msg.sender, m, j.token);
            if (!t.set || t.payeesOnly) return false;
            // The cap per operation, over all of the operation's calls
            if (_movedThisOperation(j.token, j.mostSold) > t.maxPerOp) return false;
            // The token's budget, shared with transfers and x402
            uint256 spent = _tokenSpent(m, j.token, t) + j.mostSold;
            if (spent > t.budget) return false;
            // An order's digest is recorded for `checkSignaturePolicy`; the same order registers once
            if (!call && !_recordX402(m, j.digest, j.mostSold, j.validTo, j.token)) return false;
            // Charge it
            t.spent = uint128(spent);
        }
        // The operation is valid from the latest "not before", a call's as an order's
        if (j.notBefore > _perOperation(NOT_BEFORE)) _setPerOperation(NOT_BEFORE, j.notBefore);
        if (call) {
            // The call's hash, bound to the decoder's own venue: a decoder speaks
            // for that contract only. Install took the venue from the same pinned
            // code and refused the account and this policy there. Kept for the leg
            // after this one and for this operation only, and vouched for to nobody
            _tstore(
                _thisOperation(EXPECTED_CALL), uint256(VenueCalls.bound(IVenueDecoder(decoder).venue(), j.digest))
            );
            return true;
        }
        // And, for an order, up to the earliest `validTo`
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
        return _pending(account, PolicyRules.mandate(id, _store().configs[id][account].epoch), digest);
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
        TokenLimit storage t = PolicyRules.token(msg.sender, m, token);
        if (!t.set || t.domainSeparator == bytes32(0)) return false;
        // Something to pay (a zero value marks no registration), and an end that fits `Pending`
        if (value == 0 || validBefore > type(uint48).max) return false;
        // Under a period, the authorization ends with the period it is charged in
        if (!_endsWithThePeriod(validBefore)) return false; // usable before `validBefore`
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(token, value) > t.maxPerOp) return false;
        // The payee list, if the token has one
        if (t.payeesOnly && !_store().payees[PolicyRules.payeeKey(m, token, to)][msg.sender]) return false;
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
    /// @param validBefore The last second it is vouched for; never 0, which
    /// `checkSignaturePolicy` would hand Kernel as "no end".
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
        // An end of 0 would be vouched for without end, past the mandate's own
        if (validBefore == 0) return false;
        // The record, and the period it was charged in (0 without periods)
        (p.value, p.validBefore, p.token) = (uint128(value), uint48(validBefore), token);
        _store().chargedIn[keccak256(abi.encode(m, digest))][msg.sender] = uint48(_perOperation(PERIOD_NOW));
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

    // No standing allowances: an allowance the agent grants (`approve` or
    // `increaseAllowance` of more than 0) must be withdrawn with
    // `approve(spender, 0)` later in the same operation, and an operator grant
    // (`setApprovalForAll(operator, true)` of ERC-721 and ERC-1155,
    // `setOperator(operator, true)` of ERC-6909) with the same function and
    // `false`, an ERC-6909 allowance of an id (`approve(spender, id, amount)`)
    // with the same function and 0, by the same holder
    // (the account, or the Safe whose transaction grants it). Otherwise it
    // would outlive a revoke of the mandate: the spender could pull from it
    // whenever it likes. Allowances the owner grants are not the agent's and
    // are not counted. Kept in transient slots of this operation.
    /// How many allowances the operation has granted and not withdrawn.
    bytes32 internal constant OPEN_ALLOWANCES = keccak256("agent-keys.AgentPolicy.openAllowances");
    /// One allowance granted and not withdrawn: under `(kind, holder, token, spender)`.
    bytes32 internal constant OPEN_ALLOWANCE = keccak256("agent-keys.AgentPolicy.openAllowance");
    /// The Safe whose transaction is being judged; 0 while it is the account's own call.
    bytes32 internal constant ALLOWANCE_HOLDER = keccak256("agent-keys.AgentPolicy.allowanceHolder");
    /// The hash of the call a decoder judged in the leg before, bound to that
    /// decoder's venue, until the leg after the registration is found to be
    /// that call.
    bytes32 internal constant EXPECTED_CALL = keccak256("agent-keys.AgentPolicy.expectedCall");

    /// @dev A transient slot of this operation of the account: keyed by the
    /// account and the operation counter (`keccak256(account ‖ x)`), so that
    /// nothing in it carries over to the account's next operation.
    /// @param what The note's name.
    /// @return slot The slot.
    function _thisOperation(bytes32 what) internal view returns (uint256 slot) {
        uint256 seq = _tload(uint256(keccak256(abi.encode(msg.sender, OPERATION_SEQ))));
        slot = uint256(keccak256(abi.encode(msg.sender, keccak256(abi.encode(seq, what)))));
    }

    /// @dev Reads a transient slot.
    /// @param slot The slot.
    /// @return value Its value; 0 if never written in this transaction.
    function _tload(uint256 slot) internal view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }

    /// @dev Writes a transient slot.
    /// @param slot The slot.
    /// @param value The value.
    function _tstore(uint256 slot, uint256 value) internal {
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }

    /// @dev Opens or withdraws one allowance of the current holder, and keeps
    /// the count of those open.
    /// @param kind What withdraws it: `approve` for an ERC-20 allowance, the
    /// grant's own selector for an operator grant, the selector with the
    /// token id for an ERC-6909 allowance. A grant is withdrawn only by its
    /// own kind.
    /// @param token The token.
    /// @param spender The spender.
    /// @param open True for a grant, false for its withdrawal.
    function _noteAllowance(bytes32 kind, address token, address spender, bool open) internal {
        uint256 holder = _tload(_thisOperation(ALLOWANCE_HOLDER));
        uint256 flag = _thisOperation(keccak256(abi.encode(OPEN_ALLOWANCE, kind, holder, token, spender)));
        uint256 count = _thisOperation(OPEN_ALLOWANCES);
        bool wasOpen = _tload(flag) != 0;
        if (open && !wasOpen) {
            _tstore(flag, 1);
            _tstore(count, _tload(count) + 1);
        } else if (!open && wasOpen) {
            // open, so counted: at least one
            _tstore(flag, 0);
            _tstore(count, _tload(count) - 1);
        }
    }

    /// @dev `_judgeSafe` with the Safe noted as the holder of the allowances
    /// its transaction grants.
    /// @param m The mandate key.
    /// @param safe The Safe.
    /// @param value The value the account sends with the transaction.
    /// @param data The `execTransaction` calldata.
    /// @param from Where the call comes from.
    /// @return ok True if the transaction passes.
    /// @return moved The native value it moves.
    function _judgeSafeAs(bytes32 m, address safe, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        uint256 holder = _thisOperation(ALLOWANCE_HOLDER);
        _tstore(holder, uint160(safe));
        (ok, moved) = _judgeSafe(m, value, data, from);
        _tstore(holder, 0);
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
    /// value the operation moves. Also in Kernel's form for a permission that
    /// carries an execution hook, `executeUserOp`'s selector before that call:
    /// Kernel requires it there and then runs the `execute(...)` after it as it
    /// is (Kernel.sol:264-271, 300), so the hook adds checks around the call
    /// and never takes the mandate's place.
    /// @param m The mandate key.
    /// @param callData The operation's `callData`.
    /// @return True if every call passes.
    /// @return The native value the operation moves, Safe transactions and batch legs included.
    function _judgeExecute(bytes32 m, bytes calldata callData) internal returns (bool, uint256) {
        // The hooked form: one `executeUserOp` selector, then the call itself
        if (callData.length >= 4 && bytes4(callData[0:4]) == EXECUTE_USER_OP) callData = callData[4:];
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
        if (callType == CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
            // The pointer array ends within `executionData`. Kernel's pinned
            // decoder bounds each leg and not the array, so a pointer could
            // be read past the end: zeros there for the account, the rest of
            // the operation for the policy (Solady's review, finding 5.3.7).
            bool within;
            assembly ("memory-safe") {
                let end := add(executionData.offset, executionData.length)
                within := iszero(or(gt(pointers.offset, end), gt(pointers.length, shr(5, sub(end, pointers.offset)))))
            }
            return within ? _judgeAccountBatch(m, pointers) : (false, 0);
        }
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
            // The leg before this one registered a call a decoder judged: this leg is that
            // call, or the operation is refused. A registration that is the last leg is
            // refused where validation ends
            if (_tload(_thisOperation(EXPECTED_CALL)) != 0) {
                // Its native value counts like any leg's
                (ok, legMoved) = (_judgeVenueCall(m, target, value, data), value);
                i += 1;
                // A nonce assertion takes the Safe transaction after it along: two legs
            } else if (target == NONCE_ASSERT) {
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

    /// @dev The leg after the registration of a call a decoder judged
    /// (`_registerOrder`): it must be that call, at that decoder's own venue.
    /// It is on no allow-list: the decoder's word is what admits it.
    /// @param m The mandate key.
    /// @param target The leg's target.
    /// @param value The leg's native value.
    /// @param data The leg's calldata.
    /// @return True if the leg is the call the decoder named.
    function _judgeVenueCall(bytes32 m, address target, uint256 value, bytes calldata data) internal returns (bool) {
        // Exactly the call the decoder named, at the decoder's own venue: the
        // registration bound the call's hash to it
        uint256 slot = _thisOperation(EXPECTED_CALL);
        if (uint256(VenueCalls.bound(target, VenueCalls.digest(value, data))) != _tload(slot)) return false;
        // Never Permit2 or a contract the mandate meters, even where a decoder
        // names one as its venue: a decoder's word does not open what the
        // mandate counts itself
        if (target == PERMIT2 || PolicyRules.token(msg.sender, m, target).set || PolicyRules.hasIds(m, target)) return false;
        _tstore(slot, 0);
        return true;
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
        // The Safe it guards: its first argument, a whole address word. With
        // anything above the low 160 bits `check` reverts at execution, after
        // validation has charged the operation: refused here, as a payee's
        // address word is (`_chargeToken`)
        if (uint256(bytes32(data[4:36])) >> 160 != 0) return (false, 0);
        address guarded = address(uint160(uint256(bytes32(data[4:36]))));
        // The next leg must be that Safe's `execTransaction`
        (address safe, uint256 safeValue, bytes calldata safeData) = LibERC7579.getExecution(pointers, i + 1);
        if (safe != guarded || _kindOf(m, safe, safeData) != SHAPE_WALLET) return (false, 0);
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
        // On the allow-list, with its kind
        uint8 kind = _store().allowed[PolicyRules.allowedKey(m, target, selector)][msg.sender];
        if (kind == 0) return (false, 0);
        // Install refuses these; refused again here so that no mandate, in
        // any version's storage, can reach the account or the policy itself.
        // The EntryPoint is refused at install only, on purpose: checking it
        // here would cost a staticcall per operation, and every mandate this
        // version holds went through that install-time filter. The check here
        // also catches a venue's place pinned by a mandate installed after
        // this one.
        if (!PolicyRules.targetAllowed(target, selector)) return (false, 0);
        // A batch is only meaningful delegatecalled by a wallet (below); called
        // any other way its legs would run as the batch contract.
        if (kind == SHAPE_BATCH) return (false, 0);
        // A wallet transaction (a Safe's): the calls inside it are what is judged
        if (kind == SHAPE_WALLET) return _judgeSafeAs(m, target, value, data, from);
        // A Safe transaction or a batch is never a plain call: a plain
        // `execTransaction` would run whatever the agent put in it. Install
        // refuses such an entry; refused again here
        if (selector == SAFE_EXEC_TRANSACTION || selector == MULTI_SEND) return (false, 0);
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
        // An operator grant (ERC-721 and ERC-1155 `setApprovalForAll`, ERC-6909
        // `setOperator`) is open until the same function with `false`, in the
        // same operation, withdraws it, as an allowance is
        if (selector == SET_APPROVAL_FOR_ALL || selector == SET_OPERATOR) {
            if (data.length < 68) return (false, 0);
            _noteAllowance(
                bytes32(selector), target, address(uint160(uint256(bytes32(data[4:36])))), uint256(bytes32(data[36:68])) != 0
            );
        }
        // An ERC-6909 allowance of one id: open until the same function, for
        // the same spender and id, sets it to 0 in the same operation
        if (selector == ERC6909_APPROVE) {
            if (data.length < 100) return (false, 0);
            _noteAllowance(
                keccak256(abi.encode(selector, bytes32(data[36:68]))),
                target,
                address(uint160(uint256(bytes32(data[4:36])))),
                uint256(bytes32(data[68:100])) != 0
            );
        }
        // Install refuses it; refused again here, as the account and the
        // policy are as targets
        if (selector == AUTHORIZE_OPERATOR) return (false, 0);
        // An ERC-6909 contract with id limits: its three metered functions,
        // each against the limit of the id it names, and nothing else
        if (PolicyRules.hasIds(m, target) || PolicyRules.isIdMetered(selector)) {
            return _chargeId(m, target, selector, data) ? (true, value) : (false, 0);
        }
        if (!_chargeToken(m, target, selector, data)) return (false, 0);
        return (true, value);
    }

    /// @dev Charges an ERC-6909 call to the limit of the id it names. The
    /// amount is the last argument and the id the one before it, in all
    /// three functions.
    /// @param m The mandate key.
    /// @param token The ERC-6909 contract.
    /// @param selector The call's selector.
    /// @param data The call's calldata.
    /// @return True if the call is one of the three and within the id's limits.
    function _chargeId(bytes32 m, address token, bytes4 selector, bytes calldata data) internal returns (bool) {
        // Not one of the three, or on a contract without id limits (a
        // mandate from before the install rule could list it): refused
        if (!PolicyRules.isIdMetered(selector) || !PolicyRules.hasIds(m, token)) return false;
        uint256 end = selector == ERC6909_TRANSFER_FROM ? 132 : 100;
        if (data.length < end) return false;
        uint256 amount = uint256(bytes32(data[end - 32:end]));
        address asset = idAsset(token, uint256(bytes32(data[end - 64:end - 32])));
        // The id's limit; an id without one is refused
        TokenLimit storage t = PolicyRules.token(msg.sender, m, asset);
        if (!t.set) return false;
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(asset, amount) > t.maxPerOp) return false;
        // The id's budget, in the current period if there is one
        uint256 spent = _tokenSpent(m, asset, t) + amount;
        if (spent > t.budget) return false;
        t.spent = uint128(spent);
        return true;
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
        TokenLimit storage t = PolicyRules.token(msg.sender, m, token);
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
            if (payee >> 160 != 0 || !_store().payees[PolicyRules.payeeKey(m, token, address(uint160(payee)))][msg.sender]) return false;
        }
        // The cap per operation, over all of the operation's calls
        if (_movedThisOperation(token, amount) > t.maxPerOp) return false;
        // The token's budget, in the current period if there is one
        uint256 spent = _tokenSpent(m, token, t) + amount;
        if (spent > t.budget) return false;
        // Charge it
        t.spent = uint128(spent);
        // An allowance granted is open until `approve(spender, 0)` in the same
        // operation withdraws it; the spender is the low 160 bits the token reads
        if (selector == ERC20_APPROVE || (selector == ERC20_INCREASE_ALLOWANCE && amount != 0)) {
            // `approve(spender, 0)` withdraws what either function granted: one kind
            _noteAllowance(bytes32(ERC20_APPROVE), token, address(uint160(uint256(bytes32(data[4:36])))), amount != 0);
        }
        return true;
    }

    /// @dev An allow-listed wallet transaction (a Safe's): the calls that
    /// matter are the ones inside it, as the shape judge the mandate pinned
    /// for its selector reads them (issue #251).
    /// @param m The mandate key.
    /// @param value The native value the account sends the wallet.
    /// @param data The wallet transaction's calldata (`execTransaction`).
    /// @param from Where the call sits; only `FROM_ACCOUNT_GUARDED` passes.
    /// @return ok True if the wallet transaction passes.
    /// @return moved The value sent to the wallet plus what moves inside it; 0 when refused.
    function _judgeSafe(bytes32 m, uint256 value, bytes calldata data, uint8 from)
        internal
        returns (bool ok, uint256 moved)
    {
        // Only the account's own guarded call; wallets do not nest.
        if (from != FROM_ACCOUNT_GUARDED) return (false, 0);
        // The calls inside, as the pinned judge reads them; at least one
        IShapeJudge.Inner[] memory calls;
        (ok, calls) = _read(m, data);
        if (!ok || calls.length == 0) return (false, 0);
        for (uint256 i; i < calls.length; i++) {
            uint256 innerMoved;
            (ok, innerMoved) = _judgeInner(m, data, calls[i]);
            if (!ok) return (false, 0);
            moved += innerMoved;
        }
        return ok ? (true, value + moved) : (false, 0);
    }

    /// @dev One call inside a wallet transaction, sliced from its calldata,
    /// within it. A CALL is judged like any other, as the wallet makes it. A
    /// DELEGATECALL only into a batch the mandate allows and its judge reads,
    /// still a target the agent may reach (not since made a venue place),
    /// with no value named, and every leg judged. Anything else is refused.
    /// @param m The mandate key.
    /// @param data The wallet transaction's calldata.
    /// @param c The inner call, as the judge read it.
    /// @return True if it passes.
    /// @return The native value it moves.
    function _judgeInner(bytes32 m, bytes calldata data, IShapeJudge.Inner memory c)
        internal
        returns (bool, uint256)
    {
        if (c.start > c.end || c.end > data.length) return (false, 0);
        bytes calldata inner = data[c.start:c.end];
        if (!c.delegate) return _judge(m, c.to, c.value, inner, FROM_SAFE);
        if (c.value != 0 || _kindOf(m, c.to, inner) != SHAPE_BATCH || !PolicyRules.targetAllowed(c.to, _selector(inner))) {
            return (false, 0);
        }
        return _judgeBatch(m, inner);
    }

    /// @dev The kind the mandate gives a call: 0 none, 1 plain, `SHAPE_WALLET`
    /// or `SHAPE_BATCH`.
    /// @param m The mandate key.
    /// @param target The call's target.
    /// @param data The call's calldata.
    /// @return The kind of its allow-list entry.
    function _kindOf(bytes32 m, address target, bytes calldata data) internal view returns (uint8) {
        return _store().allowed[PolicyRules.allowedKey(m, target, _selector(data))][msg.sender];
    }

    /// @dev A batch a wallet DELEGATECALLs (`multiSend`): every leg must be a
    /// CALL the mandate accepts, as the batch's pinned judge reads it.
    /// @param m The mandate key.
    /// @param d The batch's calldata, selector included.
    /// @return True if every leg passes; an empty batch is refused.
    /// @return moved The native value the legs move, together.
    function _judgeBatch(bytes32 m, bytes calldata d) internal returns (bool, uint256 moved) {
        // The legs, read by the judge: at least one
        (bool ok, IShapeJudge.Inner[] memory legs) = _read(m, d);
        if (!ok || legs.length == 0) return (false, 0);
        // Leg by leg; one refused leg refuses the batch. Each is a CALL,
        // sliced from this calldata, within it, and judged as a batch leg: it
        // runs as the wallet
        for (uint256 i; i < legs.length; i++) {
            IShapeJudge.Inner memory leg = legs[i];
            if (leg.delegate || leg.start > leg.end || leg.end > d.length) return (false, 0);
            uint256 legMoved;
            (ok, legMoved) = _judge(m, leg.to, leg.value, d[leg.start:leg.end], FROM_BATCH);
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Asks the shape judge the mandate pinned for the call's selector.
    /// Its code is the code the owner pinned at install: code at an address
    /// cannot change after (EIP-6780).
    /// @param m The mandate key.
    /// @param data The call's calldata, selector included.
    /// @return ok True if a judge is pinned and reads the call.
    /// @return calls The calls inside it.
    function _read(bytes32 m, bytes calldata data) internal view returns (bool ok, IShapeJudge.Inner[] memory calls) {
        bytes4 selector = _selector(data);
        ShapePin memory pin = _store().shapes[keccak256(abi.encode(m, selector))][msg.sender];
        // no judge, or one the mandate's guardian paused: refused
        if (pin.judge == address(0) || pin.paused != 0) return (false, calls);
        return IShapeJudge(pin.judge).read(selector, data);
    }

    /// @dev `0x00000000` stands for "no calldata": a plain value transfer.
    /// @param data The call's calldata.
    /// @return Its first four bytes; zero for calldata shorter than four bytes.
    function _selector(bytes calldata data) internal pure returns (bytes4) {
        return data.length >= 4 ? bytes4(data[0:4]) : bytes4(0);
    }
}
