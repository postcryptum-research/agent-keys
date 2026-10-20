// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPolicy} from "kernel/src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {CallType, ExecMode, ExecType, ValidAfter, ValidUntil, packValidationData} from "kernel/src/types/Types.sol";
import {
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT,
    MODULE_TYPE_POLICY,
    SIG_VALIDATION_FAILED_UINT
} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// @title AgentPolicy
/// @notice Kernel permission policy that bounds what an agent's key may do.
///
/// Installed next to `P256Signer` under one permission id, it turns the
/// hardware key from "owner" into "operator with a mandate":
///  - only `execute` with a single call — no batches, no delegatecall;
///  - only (target, selector) pairs on the allow-list; selector `0x00000000`
///    stands for a plain value transfer;
///  - `value` capped per operation and by a total budget;
///  - a hard expiry that the EntryPoint enforces through `validUntil`.
///
/// Safe pass-through: an allow-list entry `(safe, execTransaction)` lets the
/// agent drive a Safe that this account owns (Olas / Jinn service Safes),
/// with a pre-validated `v = 1` signature — no ERC-1271 needed. The policy
/// then looks *inside* the Safe transaction: its `(to, selector)` must be on
/// the same allow-list and its value counts against the same cap and budget.
/// `gasPrice` must be 0 (otherwise the Safe pays a refund out of its own
/// funds to a receiver the agent picks) and Safes do not nest. `operation`
/// must be CALL, with one exception: a DELEGATECALL into an allow-listed
/// `(multiSendCallOnly, multiSend)` batch (how Jinn settles), whose every leg
/// must itself be a CALL that passes the allow-list; leg values add up.
///
/// ERC-1271 signatures are refused outright: an agent must not be able to
/// sign off-chain approvals (permits, orders) that bypass the call allow-list.
/// docs/ERC1271.md describes the caller-scoped variant kept in reserve.
///
/// The chip guarantees nobody else can be this agent; this policy guarantees
/// that even this agent, compromised, cannot exceed what it was allowed to do.
contract AgentPolicy is IPolicy {
    struct Config {
        uint48 validUntil; // 0 = not installed
        uint32 epoch; // bumps on uninstall so stale allow-list entries die
        uint128 maxValuePerOp;
        uint128 budget;
        uint128 spent;
    }

    error InvalidConfig();

    /// `Safe.execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
    bytes4 public constant SAFE_EXEC_TRANSACTION = 0x6a761202;
    /// `MultiSend(CallOnly).multiSend(bytes)`
    bytes4 public constant MULTI_SEND = 0x8d80ff0a;

    /// Where a call sits: issued by the account, by a Safe, or as a batch leg.
    uint8 internal constant FROM_ACCOUNT = 0;
    uint8 internal constant FROM_SAFE = 1;
    uint8 internal constant FROM_BATCH = 2;

    event AgentPolicySet(
        address indexed account, bytes32 indexed id, uint48 validUntil, uint128 maxValuePerOp, uint128 budget
    );

    mapping(address account => mapping(bytes32 id => Config)) public configs;
    mapping(address account => uint256) public usedIds;
    mapping(
        address account
            => mapping(bytes32 id => mapping(uint32 epoch => mapping(address target => mapping(bytes4 selector => bool))))
    ) internal _allowed;

    /// @param data `bytes32 id ++ abi.encode(address[] targets, bytes4[] selectors,
    ///              uint128 maxValuePerOp, uint128 budget, uint48 validUntil)`
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = configs[msg.sender][id];
        if (c.validUntil != 0) revert AlreadyInitialized(msg.sender);
        (address[] memory targets, bytes4[] memory selectors, uint128 maxValuePerOp, uint128 budget, uint48 validUntil)
        = abi.decode(data[32:], (address[], bytes4[], uint128, uint128, uint48));
        if (targets.length == 0 || targets.length != selectors.length || validUntil == 0) revert InvalidConfig();

        uint32 epoch = c.epoch;
        for (uint256 i; i < targets.length; i++) {
            _allowed[msg.sender][id][epoch][targets[i]][selectors[i]] = true;
        }
        c.validUntil = validUntil;
        c.maxValuePerOp = maxValuePerOp;
        c.budget = budget;
        c.spent = 0;
        usedIds[msg.sender]++;
        emit AgentPolicySet(msg.sender, id, validUntil, maxValuePerOp, budget);
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        Config storage c = configs[msg.sender][id];
        if (c.validUntil == 0) revert NotInitialized(msg.sender);
        c.validUntil = 0;
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
        return _allowed[account][id][configs[account][id].epoch][target][selector];
    }

    /// @dev Returns `packValidationData(0, validUntil)` on success so the
    /// EntryPoint enforces the expiry, `SIG_VALIDATION_FAILED_UINT` otherwise
    /// (which Kernel turns into a `PolicyFailed` revert).
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        Config storage c = configs[msg.sender][id];
        if (c.validUntil == 0) return SIG_VALIDATION_FAILED_UINT;

        (bool ok, address target, uint256 value, bytes calldata data) = _decodeSingleExecute(userOp.callData);
        if (!ok) return SIG_VALIDATION_FAILED_UINT;
        (ok, value) = _judge(_allowed[msg.sender][id][c.epoch], target, value, data, FROM_ACCOUNT);
        if (!ok) return SIG_VALIDATION_FAILED_UINT;

        if (value > c.maxValuePerOp) return SIG_VALIDATION_FAILED_UINT;
        uint256 spent = c.spent + value;
        if (spent > c.budget) return SIG_VALIDATION_FAILED_UINT;
        c.spent = uint128(spent);

        return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(c.validUntil));
    }

    /// @dev Agents do not sign messages. See the contract notice.
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata)
        external
        pure
        override
        returns (uint256)
    {
        return SIG_VALIDATION_FAILED_UINT;
    }

    /// @dev Accepts exactly `execute(mode, executionCalldata)` with a single,
    /// default-type call and returns its (target, value, data).
    function _decodeSingleExecute(bytes calldata callData)
        internal
        pure
        returns (bool ok, address target, uint256 value, bytes calldata data)
    {
        data = callData[0:0];
        // selector + mode + offset + length is the smallest well-formed call
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Account.execute.selector) {
            return (false, address(0), 0, data);
        }
        (CallType callType, ExecType execType,,) = ExecLib.decode(ExecMode.wrap(bytes32(callData[4:36])));
        if (callType != CALLTYPE_SINGLE || !(execType == EXECTYPE_DEFAULT)) {
            return (false, address(0), 0, data);
        }
        uint256 start = 4 + uint256(bytes32(callData[36:68]));
        if (callData.length < start + 32) return (false, address(0), 0, data);
        uint256 length = uint256(bytes32(callData[start:start + 32]));
        if (callData.length < start + 32 + length || length < 52) return (false, address(0), 0, data);

        (target, value, data) = ExecLib.decodeSingle(callData[start + 32:start + 32 + length]);
        ok = true;
    }

    /// @dev Decides one call and returns the total value it moves, including
    /// what moves inside it (a Safe transaction, a batch's legs).
    function _judge(
        mapping(address => mapping(bytes4 => bool)) storage allowed,
        address target,
        uint256 value,
        bytes calldata data,
        uint8 from
    ) internal view returns (bool ok, uint256 moved) {
        bytes4 selector = _selector(data);
        if (!allowed[target][selector]) return (false, 0);
        // A batch is only meaningful delegatecalled by a Safe (below); called
        // any other way its legs would run as the batch contract.
        if (selector == MULTI_SEND) return (false, 0);
        if (selector != SAFE_EXEC_TRANSACTION) return (true, value);
        if (from != FROM_ACCOUNT) return (false, 0); // Safes do not nest

        // `target` is an allow-listed Safe: the call that matters is the inner one.
        (bool decoded, address to, uint256 innerValue, uint256 operation, bytes calldata inner) = _decodeSafeExec(data);
        if (!decoded) return (false, 0);
        if (operation == 0) {
            (ok, moved) = _judge(allowed, to, innerValue, inner, FROM_SAFE);
        } else if (operation == 1 && innerValue == 0 && _selector(inner) == MULTI_SEND && allowed[to][MULTI_SEND]) {
            (ok, moved) = _judgeBatch(allowed, inner);
        }
        return ok ? (true, value + moved) : (false, 0);
    }

    /// @dev `multiSend(bytes transactions)`, each transaction packed as
    /// `operation (1) ‖ to (20) ‖ value (32) ‖ dataLength (32) ‖ data`.
    /// Every leg must be a CALL the allow-list accepts.
    function _judgeBatch(mapping(address => mapping(bytes4 => bool)) storage allowed, bytes calldata d)
        internal
        view
        returns (bool, uint256 moved)
    {
        (bool ok, bytes calldata txs) = _batchTransactions(d);
        if (!ok || txs.length == 0) return (false, 0);
        uint256 i;
        while (i < txs.length) {
            uint256 legMoved;
            (ok, legMoved, i) = _judgeLeg(allowed, txs, i);
            if (!ok) return (false, 0);
            moved += legMoved;
        }
        return (true, moved);
    }

    /// @dev Judges the batch leg at `i` and returns where the next one starts.
    function _judgeLeg(mapping(address => mapping(bytes4 => bool)) storage allowed, bytes calldata txs, uint256 i)
        internal
        view
        returns (bool ok, uint256 moved, uint256 next)
    {
        (bool parsed, address to, uint256 value, bytes calldata data) = _leg(txs, i);
        if (!parsed) return (false, 0, 0);
        (ok, moved) = _judge(allowed, to, value, data, FROM_BATCH);
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
