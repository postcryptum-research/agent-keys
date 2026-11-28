// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AgentPolicy} from "../AgentPolicy.sol";
import {IVenueDecoder} from "../venues/IVenueDecoder.sol";
import {Config, NativeFacePin, PolicyStorage, ShapePin, TokenLimit, VenuePin} from "./PolicyStorage.sol";
import {IShapeJudge, SHAPE_BATCH, SHAPE_WALLET} from "../judges/IShapeJudge.sol";
import {
    AUTHORIZE_OPERATOR,
    ERC20_APPROVE,
    ERC20_INCREASE_ALLOWANCE,
    ERC20_TRANSFER,
    ERC20_TRANSFER_FROM,
    ERC6909_APPROVE,
    ERC6909_TRANSFER,
    ERC6909_TRANSFER_FROM,
    MULTI_SEND,
    ORDER_REGISTER,
    PolicyRules,
    SAFE_EXEC_TRANSACTION,
    X402_AUTHORIZE,
    X402_RECLAIM
} from "./PolicyRules.sol";

/// The one Kernel view the policy reads at install time: which EntryPoint
/// the account answers to, so that it can never become an agent's target.
interface IKernelEntryPoint {
    /// @dev Gets the EntryPoint the account answers to.
    /// @return The EntryPoint's address.
    function entrypoint() external view returns (address);
}

/// @title PolicyInstall - the install of a mandate, as fixed code of AgentPolicy
/// @notice The code that installs a mandate (issue #251). `AgentPolicy`
/// creates it in its constructor and runs it by DELEGATECALL from
/// `onInstall`, on the policy's own storage (`PolicyStorage`), with the
/// account as the caller. It runs in the execution phase of the owner's
/// operation, or in the validation of an account's first operation, whose
/// `initCode` installs its first mandate through a staked factory; there it
/// touches only the account's slots of the policy, and calls code by STATICCALL
/// alone. Called
/// directly, it writes its own storage, which nothing reads: a mandate is
/// what the policy's storage holds.
contract PolicyInstall {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    /// @dev Who paused a module: the account (the owner) and the mandate's guardian.
    uint8 internal constant PAUSED_BY_OWNER = 1;
    uint8 internal constant PAUSED_BY_GUARDIAN = 2;

    // The errors and the event of `AgentPolicy` that an install raises, with
    // the same signatures, so that the policy's callers see them as its own.
    /// @dev Kernel's: the permission id already has a mandate.
    /// @param smartAccount The account.
    error AlreadyInitialized(address smartAccount);
    /// @dev The install data is malformed, or breaks a rule of the mandate's form.
    error InvalidConfig();
    /// @dev A target no agent may have, whatever the allow-list says.
    /// @param target The target.
    /// @param selector The selector.
    error ForbiddenTarget(address target, bytes4 selector);
    /// @dev The account does not answer `entrypoint()`, so its EntryPoint cannot be kept out.
    error UnknownEntryPoint();

    /// @dev Kernel's: the permission id has no mandate.
    /// @param smartAccount The account.
    error NotInitialized(address smartAccount);
    /// @dev As `AgentPolicy.NotTheGuardian`.
    error NotTheGuardian();
    /// @dev As `AgentPolicy.NotAModule`.
    error NotAModule();

    /// @dev As `AgentPolicy.GuardianSet`.
    /// @param account The account.
    /// @param id The permission id.
    /// @param guardian The guardian.
    event GuardianSet(address indexed account, bytes32 indexed id, address guardian);

    /// @dev As `AgentPolicy.ModulePaused`.
    /// @param account The account.
    /// @param id The permission id.
    /// @param module The shape judge or venue decoder.
    /// @param paused True when paused, false when the pause was lifted.
    event ModulePaused(address indexed account, bytes32 indexed id, address indexed module, bool paused);

    /// @dev As `AgentPolicy.AgentPolicySet`: a mandate was installed.
    /// @param account The account.
    /// @param id The permission id, as Kernel passes it.
    /// @param validUntil The mandate's last valid second.
    /// @param maxValuePerOp The most native value one operation may move.
    /// @param budget The native budget, over the mandate's life or per period.
    event AgentPolicySet(
        address indexed account, bytes32 indexed id, uint48 validUntil, uint128 maxValuePerOp, uint128 budget
    );

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
    /// Eleven words: the ten, then `IdCap[] ids`, which must not be empty
    /// then. `payees` and `venues` may be empty and `period` may be 0 here
    /// (with no venues): the form exists to carry the id limits.
    uint256 internal constant HEAD_WITH_IDS = 11 * 32;
    /// Twelve words: the eleven, then `ShapeJudge[] shapes`, which must not
    /// be empty then; `ids` may be. For a mandate with a Safe transaction or a
    /// batch on its allow-list: each needs the shape judge for its selector.
    uint256 internal constant HEAD_WITH_SHAPES = 12 * 32;
    /// Fourteen words: the twelve (`shapes` may then be empty), then
    /// `NativeFace face`, two words inline: an ERC-20 that moves the native
    /// balance (Arc's USDC) and its decimals. What the mandate's limit of that
    /// token charges counts against the native limits too.
    uint256 internal constant HEAD_WITH_FACE = 14 * 32;

    /// @dev Installs a mandate under a permission of the account. Kernel calls
    /// it when the account installs a permission with this policy (an
    /// owner's operation: `permission add`, `permission rotate`, or the
    /// account's creation with its first permission). Nothing of an earlier
    /// installation of the id is found again: entries are keyed by the
    /// mandate (`_mandate`), and the counters start at zero. `payable` for
    /// the interface; no value is used.
    /// @param data `bytes32 id ++ abi.encode(address[] targets, bytes4[] selectors,
    ///              uint128 maxValuePerOp, uint128 budget, uint48 validUntil, AgentPolicy.TokenCap[] tokens,
    ///              uint48 validAfter)`, optionally with one more parameter
    ///              `AgentPolicy.TokenPayees[] payees`, or with three more:
    ///              `AgentPolicy.TokenPayees[] payees, uint32 period, AgentPolicy.Venue[] venues`. A
    ///              mandate is encoded in the shortest form that holds it.
    function onInstall(bytes calldata data) external payable {
        // The permission id comes first, as Kernel packs it
        bytes32 id = bytes32(data[0:32]);
        // One mandate per id at a time: an installed one is uninstalled first
        Config storage c = PolicyStorage.store().configs[id][msg.sender];
        if (c.validUntil != 0) revert AlreadyInitialized(msg.sender);
        // The seven head parameters every form starts with
        (
            address[] memory targets,
            bytes4[] memory selectors,
            uint128 maxValuePerOp,
            uint128 budget,
            uint48 validUntil,
            AgentPolicy.TokenCap[] memory tokens,
            uint48 validAfter
        ) = abi.decode(data[32:], (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48));
        // At least one entry, a selector for each target, and a window that is not empty
        if (targets.length == 0 || targets.length != selectors.length || validUntil == 0 || validAfter >= validUntil) {
            revert InvalidConfig();
        }

        // Every entry below is keyed by this installation
        bytes32 m = PolicyRules.mandate(id, c.epoch);
        // The EntryPoint holds the account's deposit: it must be known to be kept out
        address entryPoint = _entryPointOf(msg.sender);
        if (entryPoint == address(0)) revert UnknownEntryPoint();
        // The shape judges of the twelve-word form, before the allow-list that names their calls
        _installShapes(m, data[32:]);
        // Allow-list each (target, selector), refusing the targets no agent may have
        for (uint256 i; i < targets.length; i++) {
            if (!PolicyRules.targetAllowed(targets[i], selectors[i]) || targets[i] == entryPoint) {
                revert ForbiddenTarget(targets[i], selectors[i]);
            }
            PolicyStorage.store().allowed[PolicyRules.allowedKey(m, targets[i], selectors[i])][msg.sender] =
                _kindOf(m, selectors[i]);
        }
        // One limit per token, none for the zero address; nothing spent yet
        for (uint256 i; i < tokens.length; i++) {
            if (tokens[i].token == address(0) || PolicyRules.token(msg.sender, m, tokens[i].token).set) revert InvalidConfig();
            PolicyStorage.store().tokens[keccak256(abi.encode(m, tokens[i].token))][msg.sender] =
                TokenLimit(tokens[i].maxPerOp, tokens[i].budget, 0, true, false, tokens[i].domainSeparator);
        }
        // The payee lists of the eight- and ten-word forms
        _installPayees(m, data[32:]);
        // The period and venues of the ten-word form; no period otherwise
        c.period = _installTrading(m, data[32:], targets);
        // The id limits of the eleven-word form
        _installIds(m, data[32:]);
        // The native token's ERC-20 face of the fourteen-word form, one of the tokens above
        c.nativeFace = _installFace(m, data[32:]);
        // A token with a limit is callable through the four metered
        // functions only (`_chargeToken`). Any other entry on it would pass
        // neither its caps nor its payee list, so the limit the owner wrote
        // down would not be one. And a metered function is allowed on a token
        // with a limit only: on any other target validation refuses it every
        // time, a mandate that cannot do what it lists. Either is refused whole.
        // The same for an ERC-6909 contract with id limits and its three
        // metered functions. Any other entry on it is refused, `setOperator`
        // among them: an operator may move every id, which no limit bounds.
        for (uint256 i; i < targets.length; i++) {
            if (PolicyRules.token(msg.sender, m, targets[i]).set != _isMetered(selectors[i])) revert InvalidConfig();
            if (PolicyRules.hasIds(m, targets[i]) != PolicyRules.isIdMetered(selectors[i])) revert InvalidConfig();
            // An ERC-777 operator grant stands until `revokeOperator`, which
            // this policy does not pair with it: no mandate lists it
            if (selectors[i] == AUTHORIZE_OPERATOR) revert InvalidConfig();
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
        PolicyStorage.store().usedIds[msg.sender]++;
        emit AgentPolicySet(msg.sender, id, validUntil, maxValuePerOp, budget);
    }

    /// @dev The kind an allow-list entry gets: the role of the shape judge the
    /// mandate pinned for its selector, or a plain call. A Safe transaction
    /// or a batch without its judge is refused: allowed as a plain call, a
    /// Safe transaction would run whatever the agent puts in it.
    /// @param m The mandate key.
    /// @param selector The entry's selector.
    /// @return The kind: 1, `SHAPE_WALLET` or `SHAPE_BATCH`.
    function _kindOf(bytes32 m, bytes4 selector) internal view returns (uint8) {
        ShapePin storage pin = PolicyStorage.store().shapes[keccak256(abi.encode(m, selector))][msg.sender];
        if (pin.judge != address(0)) return pin.role;
        if (selector == SAFE_EXEC_TRANSACTION || selector == MULTI_SEND) revert InvalidConfig();
        return 1;
    }

    /// @dev The shape judges of the twelve-word form. Each judge once, with
    /// code, and with the code the owner pinned; each selector it names gets
    /// it, once per mandate, with its role.
    /// @param m The mandate key.
    /// @param params The mandate's parameters, after the permission id.
    function _installShapes(bytes32 m, bytes calldata params) internal {
        if (uint256(bytes32(params[0:32])) != HEAD_WITH_SHAPES && uint256(bytes32(params[0:32])) != HEAD_WITH_FACE) return;
        // The twelfth word: the offset of `ShapeJudge[]`, a dynamic array of
        // static tuples. Decoded on its own, as the eleventh is
        uint256 offset = uint256(bytes32(params[352:384]));
        if (offset > params.length || params.length - offset < 32) revert InvalidConfig();
        uint256 count = uint256(bytes32(params[offset:offset + 32]));
        // the twelve-word form exists to carry a judge: without one, use
        // another; in the fourteen-word form the list may be empty
        if ((count == 0 && uint256(bytes32(params[0:32])) == HEAD_WITH_SHAPES) || count > (params.length - offset - 32) / 64) {
            revert InvalidConfig();
        }
        for (uint256 i; i < count; i++) {
            // One `ShapeJudge`: two words, the address a whole word
            uint256 judgeWord = uint256(bytes32(params[offset + 32 + 64 * i:offset + 64 + 64 * i]));
            bytes32 codeHash = bytes32(params[offset + 64 + 64 * i:offset + 96 + 64 * i]);
            address judge = address(uint160(judgeWord));
            if (judgeWord >> 160 != 0 || judge.code.length == 0 || judge.codehash != codeHash) revert InvalidConfig();
            // a judge that is the account or this policy would close the account's own paths
            if (judge == msg.sender || judge == address(this)) revert InvalidConfig();
            (bytes4[] memory selectors, uint8[] memory roles) = IShapeJudge(judge).shapes();
            // eight at most: they are recorded in one word for `pause`
            if (selectors.length == 0 || selectors.length > 8 || selectors.length != roles.length) revert InvalidConfig();
            bytes32 packed;
            for (uint256 j; j < selectors.length; j++) {
                if (roles[j] != SHAPE_WALLET && roles[j] != SHAPE_BATCH) revert InvalidConfig();
                // never a selector the policy meters or answers itself
                if (_policyOwns(selectors[j])) revert InvalidConfig();
                packed |= bytes32(selectors[j]) >> (32 * j);
                ShapePin storage pin = PolicyStorage.store().shapes[keccak256(abi.encode(m, selectors[j]))][msg.sender];
                // one judge per selector: a second judge, or the same twice, is refused
                if (pin.judge != address(0)) revert InvalidConfig();
                (pin.judge, pin.role) = (judge, roles[j]);
            }
            PolicyStorage.store().judgeSelectors[keccak256(abi.encode(m, judge))][msg.sender] = packed;
        }
    }

    /// @dev The selectors the policy gives a meaning of its own: no data, the
    /// token functions it meters, and its own entry points. A judge never
    /// takes one of them over.
    /// @param s The selector.
    /// @return True if the policy owns it.
    function _policyOwns(bytes4 s) internal pure returns (bool) {
        return s == bytes4(0) || s == ERC20_TRANSFER || s == ERC20_TRANSFER_FROM || s == ERC20_APPROVE
            || s == ERC20_INCREASE_ALLOWANCE || s == ERC6909_TRANSFER || s == ERC6909_TRANSFER_FROM
            || s == ERC6909_APPROVE || s == AUTHORIZE_OPERATOR || s == X402_AUTHORIZE || s == X402_RECLAIM
            || s == ORDER_REGISTER;
    }

    /// @dev The native token's ERC-20 face of the fourteen-word form: a
    /// token with a limit in this mandate, of at most 18 decimals. Naming one
    /// only adds a limit: its movements count against the native limits too.
    /// @param m The mandate key.
    /// @param params The mandate's parameters, after the permission id.
    /// @return True if the mandate names one.
    function _installFace(bytes32 m, bytes calldata params) internal returns (bool) {
        if (uint256(bytes32(params[0:32])) != HEAD_WITH_FACE) return false;
        uint256 tokenWord = uint256(bytes32(params[384:416]));
        uint256 decimals = uint256(bytes32(params[416:448]));
        address token = address(uint160(tokenWord));
        if (tokenWord >> 160 != 0 || token == address(0) || decimals > 18) revert InvalidConfig();
        if (!PolicyRules.token(msg.sender, m, token).set) revert InvalidConfig();
        PolicyStorage.store().nativeFaces[m][msg.sender] = NativeFacePin(token, uint8(18 - decimals));
        return true;
    }

    /// @dev The id limits of the eleven-word form: one per `(token, id)`, on
    /// a contract that is not itself a token with a limit.
    /// @param m The mandate key.
    /// @param params The mandate's parameters, after the permission id.
    function _installIds(bytes32 m, bytes calldata params) internal {
        uint256 head = uint256(bytes32(params[0:32]));
        if (head != HEAD_WITH_IDS && head != HEAD_WITH_SHAPES && head != HEAD_WITH_FACE) return;
        // The eleventh word: the offset of `IdCap[]`, a dynamic array of static
        // tuples. Decoded on its own: eleven types at once do not fit the stack.
        uint256 offset = uint256(bytes32(params[320:352]));
        if (offset > params.length || params.length - offset < 32) revert InvalidConfig();
        uint256 count = uint256(bytes32(params[offset:offset + 32]));
        // the eleven-word form exists to carry a limit: without one, use
        // another; in the twelve-word form the list may be empty
        if ((count == 0 && head == HEAD_WITH_IDS) || count > (params.length - offset - 32) / 128) revert InvalidConfig();
        for (uint256 i; i < count; i++) {
            // One `IdCap`: four words, each within its type's width
            bytes calldata cap = params[offset + 32 + 128 * i:offset + 160 + 128 * i];
            uint256 token = uint256(bytes32(cap[0:32]));
            uint256 maxPerOp = uint256(bytes32(cap[64:96]));
            uint256 budget = uint256(bytes32(cap[96:128]));
            if (token == 0 || token >> 160 != 0 || (maxPerOp | budget) >> 128 != 0) revert InvalidConfig();
            TokenLimit storage t = PolicyRules.token(msg.sender, m, PolicyRules.idAsset(address(uint160(token)), uint256(bytes32(cap[32:64]))));
            if (t.set || PolicyRules.token(msg.sender, m, address(uint160(token))).set) revert InvalidConfig();
            (t.maxPerOp, t.budget, t.set) = (uint128(maxPerOp), uint128(budget), true);
            PolicyStorage.store().idContracts[keccak256(abi.encode(m, address(uint160(token))))][msg.sender] = true;
        }
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
        AgentPolicy.TokenPayees[] memory lists;
        if (head == HEAD_WITH_PAYEES) {
            (,,,,,,, lists) =
                abi.decode(params, (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48, AgentPolicy.TokenPayees[]));
            // the eight-word form exists to carry a list: without one, use the other
            if (lists.length == 0) revert InvalidConfig();
        } else if (head == HEAD_WITH_TRADING || head == HEAD_WITH_IDS || head == HEAD_WITH_SHAPES || head == HEAD_WITH_FACE) {
            // the eleven- and twelve-word forms' first ten words are the ten-word form's
            (,,,,,,, lists,,) = abi.decode(
                params,
                (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48, AgentPolicy.TokenPayees[], uint32, AgentPolicy.Venue[])
            );
        } else {
            revert InvalidConfig();
        }
        // Each list: a capped token without a list yet, then its payees, each once and none zero
        for (uint256 i; i < lists.length; i++) {
            TokenLimit storage t = PolicyRules.token(msg.sender, m, lists[i].token);
            address[] memory payees = lists[i].payees;
            if (!t.set || t.payeesOnly || payees.length == 0) revert InvalidConfig();
            t.payeesOnly = true;
            for (uint256 j; j < payees.length; j++) {
                bytes32 key = PolicyRules.payeeKey(m, lists[i].token, payees[j]);
                if (payees[j] == address(0) || PolicyStorage.store().payees[key][msg.sender]) revert InvalidConfig();
                PolicyStorage.store().payees[key][msg.sender] = true;
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
        // Only the ten- and eleven-word forms carry a period and venues
        uint256 head = uint256(bytes32(params[0:32]));
        if (head != HEAD_WITH_TRADING && head != HEAD_WITH_IDS && head != HEAD_WITH_SHAPES && head != HEAD_WITH_FACE) return 0;
        AgentPolicy.Venue[] memory venues;
        (,,,,,,,, period_, venues) = abi.decode(
            params, (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48, AgentPolicy.TokenPayees[], uint32, AgentPolicy.Venue[])
        );
        // The ten-word form carries a period, with venues or without. A mandate
        // with venues needs one: an order's charge is never given back, so the
        // period is what returns an unfilled order's part of the budget.
        // The eleven- and twelve-word forms may have neither: they are there for
        // the id limits and the shape judges.
        if (period_ == 0 && (head == HEAD_WITH_TRADING || venues.length != 0)) revert InvalidConfig();
        for (uint256 i; i < venues.length; i++) {
            // Each decoder once, with a config, and with the code the owner pinned
            address decoder = venues[i].decoder;
            VenuePin storage v = PolicyRules.venue(msg.sender, m, decoder);
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
            PolicyStorage.store().venuePlaces[place][msg.sender] = true;
            PolicyStorage.store().venuePlaces[decoder][msg.sender] = true;
            PolicyStorage.store().venuePlaces[spender][msg.sender] = true;
        }
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

    /// @notice Names the guardian of the permission's current mandate (#251,
    /// decision 2). The owner's step: the account calls it, in a root
    /// operation, usually in the one that installs the mandate. Zero names
    /// none. The guardian may pause a module of the mandate and lift the
    /// pause; it cannot widen anything. A new installation of the id starts
    /// with no guardian and nothing paused.
    /// @param id The permission id; its mandate must be installed.
    /// @param guardian The guardian, or zero.
    function setGuardian(bytes32 id, address guardian) external {
        Config storage c = PolicyStorage.store().configs[id][msg.sender];
        if (c.validUntil == 0) revert NotInitialized(msg.sender);
        PolicyStorage.store().guardians[keccak256(abi.encode(PolicyRules.mandate(id, c.epoch)))][msg.sender] = guardian;
        emit GuardianSet(msg.sender, id, guardian);
    }

    /// @notice Pauses one module of an account's mandate, or lifts the pause:
    /// a shape judge (every selector it reads under the mandate) or a venue
    /// decoder. While paused, validation refuses its calls and the rest of the
    /// mandate runs. The mandate's guardian, or the account itself (the
    /// owner), may do it. Outside validation: it reads the judge's `shapes()`
    /// and the guardian, which validation never does.
    /// @param account The account.
    /// @param id The permission id; its current mandate is the one paused.
    /// @param module The shape judge or venue decoder.
    /// @param paused True to pause, false to lift the pause.
    function pause(address account, bytes32 id, address module, bool paused) external {
        bytes32 m = PolicyRules.mandate(id, PolicyStorage.store().configs[id][account].epoch);
        // the owner's bit, or the guardian's
        uint8 bit = PAUSED_BY_OWNER;
        if (msg.sender != account) {
            if (msg.sender != PolicyStorage.store().guardians[keccak256(abi.encode(m))][account]) revert NotTheGuardian();
            bit = PAUSED_BY_GUARDIAN;
        }
        // A venue decoder of the mandate, or a shape judge it pinned: the
        // selectors recorded at install. The judge itself is not called, so a
        // judge cannot keep itself from being paused
        bytes32 reads = PolicyStorage.store().judgeSelectors[keccak256(abi.encode(m, module))][account];
        bool isVenue = PolicyRules.venue(account, m, module).codeHash != bytes32(0);
        if (reads == 0 && !isVenue) revert NotAModule();
        for (uint256 k; k < 8; k++) {
            bytes4 selector = bytes4(reads << (32 * k));
            if (selector == bytes4(0)) break;
            ShapePin storage pin = PolicyStorage.store().shapes[keccak256(abi.encode(m, selector))][account];
            if (pin.judge == module) pin.paused = _flags(pin.paused, bit, paused);
        }
        uint8 flags = _flags(PolicyStorage.store().modulePaused[keccak256(abi.encode(m, module))][account], bit, paused);
        PolicyStorage.store().modulePaused[keccak256(abi.encode(m, module))][account] = flags;
        // a venue's orders registered before the pause: their records name it by tag
        if (isVenue) PolicyStorage.store().venueTagPaused[PolicyRules.venueTag(m, module)][account] = flags;
        emit ModulePaused(account, id, module, paused);
    }

    /// @dev Who paused a module, after a pause or a lift: the owner's lift
    /// clears both bits, the guardian's its own only, so that the guardian
    /// never lifts what the owner paused.
    /// @param flags The bits before.
    /// @param bit The caller's bit.
    /// @param paused True for a pause, false for a lift.
    /// @return The bits after.
    function _flags(uint8 flags, uint8 bit, bool paused) internal pure returns (uint8) {
        if (paused) return flags | bit;
        return bit == PAUSED_BY_OWNER ? 0 : flags & ~bit;
    }
}
