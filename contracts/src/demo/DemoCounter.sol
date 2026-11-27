// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

/// @title DemoCounter - a demo target for the agent
/// @notice Demo target for the agent: the paper's "logger". It records who
/// called — which is the agent's smart account, never the bundler.
/// @dev No owner and no access control: anyone may call it.
contract DemoCounter {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    // Number of increments so far
    uint256 public count;

    /// @dev Emitted on every increment.
    /// @param by The caller: the account that executed the operation.
    /// @param count The count after this increment.
    event Incremented(address indexed by, uint256 count);

    /// @dev Adds one to the count and records the caller.
    function increment() external {
        // Count the call
        count += 1;
        // Record who called: the smart account, not the bundler that sent the transaction
        emit Incremented(msg.sender, count);
    }

    /// @dev Accepts plain native transfers, so that a demo or a test can send
    /// value under a mandate (the `0x00000000` selector, the per-operation cap,
    /// the budget). The value stays here: the contract has no way to send it out.
    receive() external payable {}
}
