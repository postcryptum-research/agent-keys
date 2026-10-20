// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Demo target for the agent: the paper's "logger". It records who
/// called — which is the agent's smart account, never the bundler.
contract DemoCounter {
    uint256 public count;

    event Incremented(address indexed by, uint256 count);

    function increment() external {
        count += 1;
        emit Incremented(msg.sender, count);
    }

    receive() external payable {}
}
