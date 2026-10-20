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
/// ERC-1271 signatures are refused outright: an agent must not be able to
/// sign off-chain approvals (permits, orders) that bypass the call allow-list.
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

        (bool ok, address target, uint256 value, bytes4 selector) = _decodeSingleExecute(userOp.callData);
        if (!ok) return SIG_VALIDATION_FAILED_UINT;
        if (!_allowed[msg.sender][id][c.epoch][target][selector]) return SIG_VALIDATION_FAILED_UINT;
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
    /// default-type call and returns its (target, value, selector).
    function _decodeSingleExecute(bytes calldata callData)
        internal
        pure
        returns (bool ok, address target, uint256 value, bytes4 selector)
    {
        // selector + mode + offset + length is the smallest well-formed call
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Account.execute.selector) {
            return (false, address(0), 0, 0);
        }
        (CallType callType, ExecType execType,,) = ExecLib.decode(ExecMode.wrap(bytes32(callData[4:36])));
        if (callType != CALLTYPE_SINGLE || !(execType == EXECTYPE_DEFAULT)) {
            return (false, address(0), 0, 0);
        }
        uint256 start = 4 + uint256(bytes32(callData[36:68]));
        if (callData.length < start + 32) return (false, address(0), 0, 0);
        uint256 length = uint256(bytes32(callData[start:start + 32]));
        if (callData.length < start + 32 + length || length < 52) return (false, address(0), 0, 0);

        bytes calldata data;
        (target, value, data) = ExecLib.decodeSingle(callData[start + 32:start + 32 + length]);
        selector = data.length >= 4 ? bytes4(data[0:4]) : bytes4(0);
        ok = true;
    }
}
