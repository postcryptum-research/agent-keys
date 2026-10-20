// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISafeNonce {
    function nonce() external view returns (uint256);
}

/// @title SafeNonceAssert
/// @notice Binds a Safe transaction to the Safe nonce it was meant for.
///
/// A Safe accepts a pre-validated signature (`v = 1`) from `msg.sender ==
/// owner` whatever its nonce, so the same `execTransaction` sent twice runs
/// twice. AgentPolicy therefore admits an agent's Safe transaction only as a
/// Kernel batch `[check(safe, n), safe.execTransaction(...)]`: the first copy
/// moves the Safe to `n + 1`, and any replay fails here and reverts the batch.
contract SafeNonceAssert {
    error SafeNonceMismatch(address safe, uint256 expected, uint256 actual);

    function check(address safe, uint256 expected) external view {
        uint256 actual = ISafeNonce(safe).nonce();
        if (actual != expected) revert SafeNonceMismatch(safe, expected, actual);
    }
}
