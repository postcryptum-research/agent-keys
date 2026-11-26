// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VenuePairs - the pairs an owner lets an agent trade, and their lowest prices
/// @notice What a venue's decoder holds every order to, whatever the venue:
/// the order sells and buys a pair the owner listed, at no less than the
/// pair's lowest price. The rules are those of `CowSwapDecoder`, which
/// carries its own copy: a deployed decoder's code does not change when a
/// second venue arrives.
/// @dev Internal functions only: a decoder that uses them has them in its
/// own code, and calls no library at run time.
library VenuePairs {
    /// A pair the agent may trade, one way, and its lowest price: an order
    /// must ask for at least `minBuy` of `buyToken` per `perSell` of
    /// `sellToken`, both in the tokens' smallest units and neither zero.
    /// Without it a compromised agent could sell for nothing; with it the
    /// most it can lose on an order is the distance from this price to the
    /// market's. No oracle is asked: the owner sets the price and it stays
    /// until the mandate is replaced.
    struct Pair {
        /// The token the agent may sell.
        address sellToken;
        /// The token it may buy with it.
        address buyToken;
        /// The least of `buyToken` an order must ask for per `perSell` of `sellToken`.
        uint256 minBuy;
        /// The amount of `sellToken` that `minBuy` is the price of.
        uint256 perSell;
    }

    /// The most pairs a config may list: a decoder reads them all, inside a
    /// gas bound.
    uint256 internal constant MAX_PAIRS = 16;

    /// @dev The order's pair is not listed, or is listed with the same token on both sides or without a price.
    /// @param sellToken The order's sell token.
    /// @param buyToken The order's buy token.
    error PairNotListed(address sellToken, address buyToken);
    /// @dev The order asks for less than the pair's lowest price.
    error BelowTheLowestPrice();
    /// @dev The config lists the order's pair more than once.
    error PairListedTwice();
    /// @dev The config breaks a rule of `checkList`, or lists more than `MAX_PAIRS` pairs.
    error InvalidConfig();

    /// @dev Reverts unless the order's pair is listed exactly once, with a
    /// valid price, and the order asks for no less than that price. It does
    /// not rest on `checkList` having been asked: a list with too many
    /// pairs, a pair without a price or a pair listed twice (which of its two
    /// prices would hold?) allows nothing.
    /// @param pairs The pairs of the owner's config.
    /// @param sellToken The token the order sells.
    /// @param buyToken The token the order buys.
    /// @param sellAmount The amount the order sells.
    /// @param buyAmount The least the order buys for it.
    function check(Pair[] memory pairs, address sellToken, address buyToken, uint256 sellAmount, uint256 buyAmount)
        internal
        pure
    {
        // Bound the loop below
        if (pairs.length > MAX_PAIRS) revert InvalidConfig();
        bool found;
        // Read every pair, not only up to the first match, so that a pair listed twice is caught
        for (uint256 i; i < pairs.length; i++) {
            Pair memory p = pairs[i];
            if (p.sellToken != sellToken || p.buyToken != buyToken) continue;
            if (found) revert PairListedTwice();
            found = true;
            // The matching pair must be one `checkList` accepts: two tokens and a price
            if (p.sellToken == p.buyToken || p.minBuy == 0 || p.perSell == 0) {
                revert PairNotListed(sellToken, buyToken);
            }
            // buyAmount / sellAmount >= minBuy / perSell, in 512 bits
            (uint256 hi1, uint256 lo1) = mul(buyAmount, p.perSell);
            (uint256 hi2, uint256 lo2) = mul(sellAmount, p.minBuy);
            // Compare the two products high word first
            if (hi1 < hi2 || (hi1 == hi2 && lo1 < lo2)) revert BelowTheLowestPrice();
        }
        if (!found) revert PairNotListed(sellToken, buyToken);
    }

    /// @dev Reverts with `InvalidConfig` unless `pairs` is a list an owner
    /// can be shown: one to `MAX_PAIRS` pairs, no pair twice, no token at
    /// the zero address or paired with itself, a lowest price for every pair.
    /// @param pairs The pairs of the owner's config.
    function checkList(Pair[] memory pairs) internal pure {
        // One to `MAX_PAIRS` pairs
        if (pairs.length == 0 || pairs.length > MAX_PAIRS) revert InvalidConfig();
        for (uint256 i; i < pairs.length; i++) {
            Pair memory p = pairs[i];
            // Two non-zero token addresses, not the same one
            if (p.sellToken == address(0) || p.buyToken == address(0) || p.sellToken == p.buyToken) {
                revert InvalidConfig();
            }
            // A lowest price, neither of its terms zero
            if (p.minBuy == 0 || p.perSell == 0) revert InvalidConfig();
            // Not listed before (at most `MAX_PAIRS` pairs, so the quadratic scan stays small)
            for (uint256 j; j < i; j++) {
                if (pairs[j].sellToken == p.sellToken && pairs[j].buyToken == p.buyToken) revert InvalidConfig();
            }
        }
    }

    /// @dev The full 512-bit product. Both factors may be any uint256, so
    /// the product can need two words; the price check compares such
    /// products without overflow or rounding.
    /// @param a The first factor.
    /// @param b The second factor.
    /// @return hi The high 256 bits of `a * b`.
    /// @return lo The low 256 bits of `a * b`.
    function mul(uint256 a, uint256 b) internal pure returns (uint256 hi, uint256 lo) {
        assembly {
            // The product modulo 2^256 - 1
            let mm := mulmod(a, b, not(0))
            // The product modulo 2^256: its low word
            lo := mul(a, b)
            // By the Chinese remainder theorem, the high word is mm - lo, minus one
            // when that subtraction borrows (mm < lo)
            hi := sub(sub(mm, lo), lt(mm, lo))
        }
    }
}
