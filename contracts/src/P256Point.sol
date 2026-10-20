// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title P256Point
/// @notice Whether `(x, y)` is a point on NIST P-256 (secp256r1).
///
/// Modules check a public key at install: an off-curve key would make every
/// signature fail, silently bricking the account (or the permission).
library P256Point {
    uint256 internal constant P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 internal constant A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc; // p - 3
    uint256 internal constant B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    /// @dev y² ≡ x³ + a·x + b (mod p), with both coordinates reduced and not
    /// the point at infinity's (0, 0) encoding.
    function isOnCurve(bytes32 xb, bytes32 yb) internal pure returns (bool) {
        uint256 x = uint256(xb);
        uint256 y = uint256(yb);
        if (x >= P || y >= P || (x == 0 && y == 0)) return false;
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(addmod(mulmod(mulmod(x, x, P), x, P), mulmod(A, x, P), P), B, P);
        return lhs == rhs;
    }
}
