// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

/// @title P256Point - the check that a public key is a point on NIST P-256
/// @notice Whether `(x, y)` is a point on NIST P-256 (secp256r1).
/// @dev Modules check a public key at install: an off-curve key would make every
/// signature fail, silently bricking the account (or the permission).
library P256Point {
    // The prime p of the field the curve is defined over
    uint256 internal constant P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    // The curve's coefficient a, which for P-256 is p - 3
    uint256 internal constant A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc; // p - 3
    // The curve's coefficient b
    uint256 internal constant B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    /// @dev y² ≡ x³ + a·x + b (mod p), with both coordinates reduced and not
    /// the point at infinity's (0, 0) encoding.
    /// A coordinate of p or more is refused even if it satisfies the equation
    /// modulo p: the RIP-7212 precompile refuses such a key, so it would fail
    /// every signature just as an off-curve key does. (0, 0) does not satisfy
    /// the equation either, since b is not zero; the explicit test keeps the
    /// rule visible.
    /// @param xb The x coordinate, a big-endian 256-bit integer.
    /// @param yb The y coordinate, a big-endian 256-bit integer.
    /// @return True if `(xb, yb)` is a point on the curve, false otherwise.
    function isOnCurve(bytes32 xb, bytes32 yb) internal pure returns (bool) {
        // Read the coordinates as integers
        uint256 x = uint256(xb);
        uint256 y = uint256(yb);
        // Both coordinates must be reduced modulo p, and the point is not (0, 0)
        if (x >= P || y >= P || (x == 0 && y == 0)) return false;
        // Left side: y² mod p
        uint256 lhs = mulmod(y, y, P);
        // Right side: x³ + a·x + b mod p
        uint256 rhs = addmod(addmod(mulmod(mulmod(x, x, P), x, P), mulmod(A, x, P), P), B, P);
        // On the curve if the two sides agree
        return lhs == rhs;
    }
}
