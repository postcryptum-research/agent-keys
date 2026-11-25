// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVenueDecoder - what a trading venue is to AgentPolicy
/// @notice What a trading venue is to `AgentPolicy`: a contract without
/// state that reads one of the venue's orders and says what it can cost
/// (issue #80). The mandate names a decoder by its address, its code hash and
/// the hash of the owner's `config`; the policy asks it with `STATICCALL`
/// and charges and records what it answers. A decoder reads no storage: it
/// runs inside the validation of an operation (ERC-7562).
interface IVenueDecoder {
    /// @notice Judges `order` for `account` under the owner's `config`.
    /// Reverts unless the order is one the config allows.
    /// @param account The account the order is for: the one that will vouch for it.
    /// @param config The owner's configuration for this venue, in the decoder's encoding.
    /// @param order The venue's order, in the decoder's encoding.
    /// @return sellToken the token the order spends
    /// @return mostSold  the most of it the order can ever take, fees included
    /// @return notBefore the earliest time the order may be registered
    ///                   (how a decoder bounds an order's lifetime without
    ///                   reading the clock)
    /// @return validTo   the last moment the order can be filled
    /// @return digest    the hash the venue will ask the account to vouch for
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        view
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest);

    /// @notice Whether the venue's storage shows nothing of `order` filled
    /// or cancelled now. Asked outside validation, after the order's
    /// `validTo`; it may read the venue's storage. It is the venue's present
    /// record and no proof of the past: where a venue lets that record be
    /// cleared (CoW does, after `validTo`), a filled order can read as
    /// untouched.
    /// @param account The account the order is for.
    /// @param order The venue's order, in the decoder's encoding.
    /// @return True if the venue's record shows nothing of the order filled or cancelled now.
    function untouched(address account, bytes calldata order) external view returns (bool);

    /// @notice The venue's own contract (CoW: the settlement). A mandate may
    /// not name it as a target: only orders this decoder judged reach it.
    /// @return The venue's contract address.
    function venue() external view returns (address);

    /// @notice Who takes the sell token from the account at this venue: the
    /// owner's tools approve it (the allowance). Like `venue()`, a mandate
    /// may not name it as a target: through it the allowance would move.
    /// @return The address the account approves to spend its sell token.
    function spender() external view returns (address);
}
