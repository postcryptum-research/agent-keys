// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title WhitelistPaymaster - sponsors gas for listed accounts, each with a budget and a cap
/// @notice Sponsors gas for enrolled agent accounts, as in the reference
/// design: the sponsor keeps a deposit in the EntryPoint and lists the
/// accounts it pays for. Authorization and sponsorship stay separate
/// checks — the paymaster never judges what an operation does, only who
/// sends it. With it, an agent account need not hold the native token.
/// @dev Each account gets a gas budget and a per-operation cap, so one
/// compromised agent cannot drain the deposit shared by all. Every
/// operation is charged its maximum cost (`maxCost`, from its gas limits
/// and fee cap) at validation, with no refund afterwards: an upper bound
/// that needs no `postOp` and therefore no paymaster stake for bundlers.
///
/// Unlike the modules, a paymaster has an owner, who decides whom it pays
/// for and how much; each sponsor deploys their own. The deposit and the
/// stake are handled by `BasePaymaster` (eth-infinitism, EntryPoint v0.7):
/// `deposit` is open to anyone, `withdrawTo`, `addStake`, `unlockStake` and
/// `withdrawStake` are the owner's.
contract WhitelistPaymaster is BasePaymaster {
    // An account's sponsorship, one storage slot
    struct Sponsorship {
        // 2^128 - 1 wei is about 3.4e20 ETH, more than will ever exist
        uint128 remaining; // wei of gas this account may still be charged
        // Same range as `remaining`
        uint128 maxPerOp; // the most one operation may cost
    }

    /// @dev Emitted when the owner sets an account's sponsorship.
    /// @param account The account.
    /// @param budget The wei of gas the account may be charged from now on.
    /// @param maxPerOp The most one operation may cost.
    event Sponsored(address indexed account, uint128 budget, uint128 maxPerOp);

    // Map of account => its sponsorship; a zero `remaining` means it is not sponsored.
    // The account is the mapping's key, so its slot is keccak256(account ‖ slot):
    // storage that ERC-7562 associates with the operation's sender.
    mapping(address account => Sponsorship) public sponsorships;

    /// @dev Paymaster constructor. `BasePaymaster` checks that `entryPoint_`
    /// is an EntryPoint (ERC-165) and makes the deployer the owner; ownership
    /// then goes to `owner_`.
    /// @param entryPoint_ The EntryPoint (v0.7) that holds the deposit and calls the paymaster.
    /// @param owner_ explicit, because deploying through the deterministic
    /// CREATE2 deployer would otherwise make that proxy the owner.
    constructor(IEntryPoint entryPoint_, address owner_) BasePaymaster(entryPoint_) {
        _transferOwnership(owner_);
    }

    /// @dev Set (replace) an account's sponsorship; a zero budget delists it.
    /// The new budget replaces what was left, it does not add to it. Owner only.
    /// @param account The account.
    /// @param budget The wei of gas the account may be charged from now on.
    /// @param maxPerOp The most one operation may cost.
    function setSponsored(address account, uint128 budget, uint128 maxPerOp) external onlyOwner {
        sponsorships[account] = Sponsorship(budget, maxPerOp);
        emit Sponsored(account, budget, maxPerOp);
    }

    /// @dev Whether an account has budget left. It says nothing of `maxPerOp`:
    /// a sponsored account whose cap is below an operation's cost is still refused.
    /// @param account The account.
    /// @return True if the account has budget left, false otherwise.
    function sponsored(address account) external view returns (bool) {
        return sponsorships[account].remaining > 0;
    }

    /// @dev Charges an operation's maximum cost to its sender's budget, or
    /// refuses it. `BasePaymaster.validatePaymasterUserOp` calls it in the
    /// validation phase, once it has checked that the EntryPoint is the caller.
    /// A refusal is a failure result, not a revert: the EntryPoint then
    /// refuses the operation. The operation's hash (the second parameter) is
    /// not read, nor anything the operation does.
    /// @param userOp The user operation; only its `sender` is read.
    /// @param maxCost The most the operation can cost, in wei, as the EntryPoint
    /// computes it from the operation's gas limits and fee cap.
    /// @return context Empty, so the EntryPoint calls no `postOp`.
    /// @return validationData `SIG_VALIDATION_SUCCESS` (0) if the operation is
    /// sponsored, `SIG_VALIDATION_FAILED` (1) if not; no time range.
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        // Keyed by the sender: storage associated with it, which ERC-7562
        // lets even an unstaked paymaster read and write.
        Sponsorship storage s = sponsorships[userOp.sender];
        // Refuse an operation above the per-operation cap or above what is left
        // (a delisted or unknown account has nothing left)
        if (maxCost > s.maxPerOp || maxCost > s.remaining) return ("", SIG_VALIDATION_FAILED);
        // Charge the maximum cost; the check above keeps it within uint128, so the cast does not truncate
        s.remaining -= uint128(maxCost);
        // Sponsor it, with an empty context and so no `postOp`
        return ("", SIG_VALIDATION_SUCCESS);
    }
}
