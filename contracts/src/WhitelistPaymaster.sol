// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title WhitelistPaymaster
/// @notice Sponsors gas for enrolled agent accounts, as in the reference
/// design: the sponsor keeps a deposit in the EntryPoint and lists the
/// accounts it pays for. Authorization and sponsorship stay separate
/// checks — the paymaster never judges what an operation does, only who
/// sends it. With it, an agent account need not hold the native token.
contract WhitelistPaymaster is BasePaymaster {
    event Sponsored(address indexed account, bool sponsored);

    mapping(address account => bool) public sponsored;

    /// @param owner_ explicit, because deploying through the deterministic
    /// CREATE2 deployer would otherwise make that proxy the owner.
    constructor(IEntryPoint entryPoint_, address owner_) BasePaymaster(entryPoint_) {
        _transferOwnership(owner_);
    }

    function setSponsored(address account, bool allowed) external onlyOwner {
        sponsored[account] = allowed;
        emit Sponsored(account, allowed);
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256)
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        return ("", sponsored[userOp.sender] ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED);
    }
}
