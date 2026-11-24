// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// The one function of a Safe that SafeNonceAssert reads
interface ISafeNonce {
    /// @dev Gets the Safe's nonce: the one its next `execTransaction` is hashed with.
    /// @return The Safe's current nonce.
    function nonce() external view returns (uint256);
}

/// @title SafeNonceAssert - binds a Safe transaction to the Safe nonce it was meant for
/// @notice Binds a Safe transaction to the Safe nonce it was meant for.
/// @dev A Safe accepts a pre-validated signature (`v = 1`) from `msg.sender ==
/// owner` whatever its nonce, so the same `execTransaction` sent twice runs
/// twice. AgentPolicy therefore admits an agent's Safe transaction only as a
/// Kernel batch `[check(safe, n), safe.execTransaction(...)]`: the first copy
/// moves the Safe to `n + 1`, and any replay fails here and reverts the batch.
///
/// No state, no owner: one deployment serves every account. It runs in the
/// execution phase, as a call of the account's batch, so reading the Safe's
/// storage is outside the validation rules of ERC-7562.
contract SafeNonceAssert {
    /// @dev The Safe's nonce is not the one the transaction was meant for.
    /// @param safe The Safe.
    /// @param expected The nonce the transaction was meant for.
    /// @param actual The Safe's nonce at the check.
    error SafeNonceMismatch(address safe, uint256 expected, uint256 actual);

    /// @dev Reverts unless the Safe's nonce is `expected`. AgentPolicy admits it
    /// as the call right before the `execTransaction` it guards; its revert
    /// reverts the whole batch, that transaction included.
    /// @param safe The Safe the guarded transaction goes to.
    /// @param expected The Safe nonce the guarded transaction was meant for.
    function check(address safe, uint256 expected) external view {
        // Read the Safe's nonce now
        uint256 actual = ISafeNonce(safe).nonce();
        // A replay finds the nonce already moved on, and reverts
        if (actual != expected) revert SafeNonceMismatch(safe, expected, actual);
    }
}
