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
///
/// Each account gets a gas budget and a per-operation cap, so one
/// compromised agent cannot drain the deposit shared by all. Every
/// operation is charged its maximum cost (`maxCost`, from its gas limits
/// and fee cap) at validation, with no refund afterwards: an upper bound
/// that needs no `postOp` and therefore no paymaster stake for bundlers.
contract WhitelistPaymaster is BasePaymaster {
    struct Sponsorship {
        uint128 remaining; // wei of gas this account may still be charged
        uint128 maxPerOp; // the most one operation may cost
    }

    event Sponsored(address indexed account, uint128 budget, uint128 maxPerOp);

    mapping(address account => Sponsorship) public sponsorships;

    /// @param owner_ explicit, because deploying through the deterministic
    /// CREATE2 deployer would otherwise make that proxy the owner.
    constructor(IEntryPoint entryPoint_, address owner_) BasePaymaster(entryPoint_) {
        _transferOwnership(owner_);
    }

    /// Set (replace) an account's sponsorship; a zero budget delists it.
    function setSponsored(address account, uint128 budget, uint128 maxPerOp) external onlyOwner {
        sponsorships[account] = Sponsorship(budget, maxPerOp);
        emit Sponsored(account, budget, maxPerOp);
    }

    function sponsored(address account) external view returns (bool) {
        return sponsorships[account].remaining > 0;
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        // Keyed by the sender: storage associated with it, which ERC-7562
        // lets even an unstaked paymaster read and write.
        Sponsorship storage s = sponsorships[userOp.sender];
        if (maxCost > s.maxPerOp || maxCost > s.remaining) return ("", SIG_VALIDATION_FAILED);
        s.remaining -= uint128(maxCost);
        return ("", SIG_VALIDATION_SUCCESS);
    }
}
