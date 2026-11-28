// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

// The kind a mandate gives a call through a shape judge, kept as the value
// of its allow-list entry (issue #251). 0 is not allowed and 1 a plain
// call; these two are a judge's.
// A wallet transaction (`Safe.execTransaction`): it must come as the leg
// right after a guard naming its target (`SafeNonceAssert`), and the calls
// inside it run as the wallet.
uint8 constant SHAPE_WALLET = 2;
// A batch (`MultiSendCallOnly.multiSend`): reached only as a wallet's
// DELEGATECALL; its legs run as the wallet.
uint8 constant SHAPE_BATCH = 3;

/// @title IShapeJudge - what a shape judge is to AgentPolicy
/// @notice A contract without state that says where the calls inside one
/// call lie (issue #251), for the policy to judge each of them against the
/// same mandate. A mandate pins it by address and code hash; its code says
/// which selectors it reads and in which role. It reads no storage and no
/// clock (ERC-7562), and it does not revert on what it is given: what it
/// cannot read is answered `ok == false`.
interface IShapeJudge {
    /// One call inside the call read: its target, its value, where its data
    /// lies in the bytes given, and whether the wallet DELEGATECALLs it.
    struct Inner {
        // The inner call's target
        address to;
        // The inner call's native value
        uint256 value;
        // Where its data starts, in the bytes given
        uint256 start;
        // Where it ends, exclusive
        uint256 end;
        // true: the wallet DELEGATECALLs it, which the policy admits into a batch only
        bool delegate;
    }

    /// @notice The selectors this judge reads, each with its role.
    /// @return selectors The selectors.
    /// @return roles For each, `SHAPE_WALLET` or `SHAPE_BATCH`.
    function shapes() external view returns (bytes4[] memory selectors, uint8[] memory roles);

    /// @notice Reads a call of one of its selectors.
    /// @param selector The call's selector, one of `shapes()`.
    /// @param data The call's calldata, selector included.
    /// @return ok True if the call is one the judge can read and admits.
    /// @return calls The calls inside it, in order.
    function read(bytes4 selector, bytes calldata data) external view returns (bool ok, Inner[] memory calls);
}
