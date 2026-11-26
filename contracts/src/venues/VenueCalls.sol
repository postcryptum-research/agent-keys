// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VenueCalls - how a call the account is to make is named between a decoder and the policy
/// @notice A decoder may judge a call the account makes now (a swap at a
/// router, a deposit) instead of an order a venue fills later. It then
/// answers `judge` with a `validTo` of zero, and with the hash of that call
/// as `digest`: its value and its calldata. The call's target is not the
/// decoder's to name: it is the decoder's own `venue()`, which `AgentPolicy`
/// binds the hash to. The policy admits the call only as the leg right
/// after its registration, at that venue, and only if it hashes to what the
/// decoder answered (issue #80).
/// @dev Both hashes are of two words: neither is an EIP-712 digest (those
/// are of 66 bytes) nor an order of any venue. The policy keeps the bound
/// hash for the length of one operation and vouches for it to nobody.
library VenueCalls {
    /// @dev The hash a decoder answers with for one call of the account.
    /// @param value The native value sent with the call.
    /// @param data The call's calldata.
    /// @return The call's hash.
    function digest(uint256 value, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(value, keccak256(data)));
    }

    /// @dev A call's hash bound to the contract it is made at.
    /// @param place The contract called: the venue of the decoder that judged the call.
    /// @param callDigest The call's hash, as `digest` gives it.
    /// @return What the policy expects of the leg after the registration.
    function bound(address place, bytes32 callDigest) internal pure returns (bytes32) {
        return keccak256(abi.encode(place, callDigest));
    }
}
