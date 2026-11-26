// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVenueDecoder} from "./IVenueDecoder.sol";
import {VenuePairs} from "./VenuePairs.sol";
import {VenueCalls} from "./VenueCalls.sol";

// The one function of Uniswap's SwapRouter02 that the decoder lets an agent call
interface ISwapRouter02 {
    /// The arguments of a swap of an exact amount through one pool.
    struct ExactInputSingleParams {
        /// The token sold.
        address tokenIn;
        /// The token bought.
        address tokenOut;
        /// The pool's fee tier: with the two tokens it names the pool.
        uint24 fee;
        /// Who receives the bought token.
        address recipient;
        /// The amount sold; zero means the router's own balance.
        uint256 amountIn;
        /// The least bought, or the swap reverts.
        uint256 amountOutMinimum;
        /// A price at which the swap stops early; zero is no limit.
        uint160 sqrtPriceLimitX96;
    }

    /// @dev Swaps `amountIn` of one token for as much as possible of another, through one pool.
    /// @param params The swap.
    /// @return amountOut The amount bought.
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

/// @title SwapRouter02Decoder - a swap through one Uniswap v3 pool, for `AgentPolicy` (issue #80)
/// @notice Judges a call, not an order: a swap the account makes itself, at
///         Uniswap's SwapRouter02, in the leg right after its registration.
///         The agent names five things: the two tokens, the pool's fee tier,
///         the amount sold and the least bought. The decoder builds the
///         router call from them and allows it only if:
///         - the pair is one the owner listed, at no less than the pair's
///           lowest price, which every pair has;
///         - something is sold.
///         Everything else in the call is written here and is not the
///         agent's to choose:
///         - the bought token goes to the account;
///         - no native value is sent;
///         - no price limit is set, so the router's check of the least
///           bought is the only one, and it is of the whole swap.
///         The amount sold is charged like an order's: against the sell
///         token's cap per operation and its budget, when the swap is
///         registered.
/// @dev No storage, no upgrade path, no `delegatecall`, no `selfdestruct`.
///
/// What each rule rests on in the router (SwapRouter02, verified source,
/// `V3SwapRouter.sol` and `PeripheryPaymentsExtended.sol`; the same
/// selector and struct in forks of it):
/// - `exactInputSingle` pays the pool from its caller (`payer = msg.sender`)
///   and has the pool pay `recipient`; it then requires the pool's output to
///   be at least `amountOutMinimum`. With the account as recipient the
///   account receives at least the least bought, or the swap reverts.
/// - The router takes the sold token from its caller only: an allowance of
///   the account to the router can be spent by the account's own calls and
///   by nobody else's. The account's calls reach the router through this
///   decoder alone (`AgentPolicy` keeps a venue's contract off every
///   allow-list), so each of them is charged here.
/// - `amountIn == 0` means "swap what the router holds" to the router; it is
///   refused.
/// - A recipient of `address(1)` or `address(2)` means the caller or the
///   router to the router. The recipient is the account's address, which is
///   neither.
/// - `multicall`, the sweeps and unwraps to any recipient, `pull`, the
///   position-manager calls and the permits are other functions of the
///   router; none of them is this call, so none of them is reachable.
///
/// A swap that reverts when the operation runs was still charged when it was
/// registered: the charge is of what was allowed, as for a transfer, and the
/// mandate's period gives it back.
contract SwapRouter02Decoder is IVenueDecoder {
    /// Semantic version of this contract (house rule 9).
    string public constant VERSION = "0.1.0";

    /// The owner's configuration for the venue, ABI-encoded, hash-pinned in the mandate.
    struct Config {
        /// The pairs the agent may swap, one way each, with their lowest prices.
        VenuePairs.Pair[] pairs;
    }

    /// What the agent names of a swap: the "order" this decoder is handed.
    struct Swap {
        /// The token sold.
        address tokenIn;
        /// The token bought.
        address tokenOut;
        /// The pool's fee tier.
        uint24 fee;
        /// The exact amount sold.
        uint256 amountIn;
        /// The least amount bought.
        uint256 amountOutMinimum;
    }

    /// @dev The swap is not exactly five words.
    error NotASwap();
    /// @dev The swap sells nothing: to the router that is its own balance.
    error NothingToSell();
    /// @dev There is no code at the router's address.
    error NotARouter();

    /// The length of an encoded swap: five words.
    uint256 internal constant SWAP_LENGTH = 5 * 32;
    /// The most pairs a config may list.
    uint256 public constant MAX_PAIRS = VenuePairs.MAX_PAIRS;

    /// The router: the venue's own contract, the one the judged call is made at.
    address public immutable override venue;
    /// The router again: it takes the sold token from its caller itself.
    address public immutable override spender;

    /// @dev Decoder constructor.
    /// @param router_ Uniswap's SwapRouter02 on this chain.
    constructor(address router_) {
        if (router_.code.length == 0) revert NotARouter();
        venue = router_;
        spender = router_;
    }

    /// @inheritdoc IVenueDecoder
    /// @dev Applies the rules listed for the contract. `notBefore` and
    /// `validTo` are zero: that is how a decoder says it judged a call the
    /// account makes now (`VenueCalls`). `digest` is that call's hash: no
    /// value, and the calldata `swapCall` builds. `mostSold` is `amountIn`:
    /// the router takes at most that.
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        pure
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        // Decode the swap (exactly five words) and the owner's config
        Swap memory s = _swap(order);
        Config memory c = abi.decode(config, (Config));

        // Something to sell: zero would be the router's own balance
        if (s.amountIn == 0) revert NothingToSell();
        // A listed pair, at no less than its lowest price
        VenuePairs.check(c.pairs, s.tokenIn, s.tokenOut, s.amountIn, s.amountOutMinimum);

        // What the swap can cost, and the one call it is
        sellToken = s.tokenIn;
        mostSold = s.amountIn;
        (notBefore, validTo) = (0, 0);
        digest = VenueCalls.digest(0, _call(account, s));
    }

    /// @notice The router call a swap is, for `account`: what the account
    /// must send to `venue`, with no value, in the leg after the swap's
    /// registration.
    /// @param account The account that swaps.
    /// @param order `abi.encode(Swap)`.
    /// @return The calldata of the router's `exactInputSingle`.
    function swapCall(address account, bytes calldata order) external pure returns (bytes memory) {
        return _call(account, _swap(order));
    }

    /// @inheritdoc IVenueDecoder
    /// @dev A swap is made in the operation that registers it or not at all:
    /// nothing of it is left to be filled later, and `AgentPolicy` keeps no
    /// record of it to give back. Always false.
    function untouched(address, bytes calldata) external pure override returns (bool) {
        return false;
    }

    /// @notice Whether `config` is a configuration the owner's tools can be
    /// shown: at least one pair, no pair twice, no token paired with itself,
    /// a lowest price for every pair, and code at every token's address.
    /// @dev The code is asked for because the router takes a transfer at an
    /// address without code for done. `judge` does not ask (it runs inside
    /// validation, where an address without code may not be touched), so
    /// the owner's tools ask here before the mandate is made. `judge` does
    /// not rely on this check having been asked for the rest.
    /// @param config `abi.encode(Config)`.
    /// @return True if the config passes; otherwise the call reverts, so it
    /// never returns false.
    function checkConfig(bytes calldata config) external view returns (bool) {
        // Decode the config
        Config memory c = abi.decode(config, (Config));
        // A list of pairs an owner can be shown
        VenuePairs.checkList(c.pairs);
        // Code at both tokens of every pair
        for (uint256 i; i < c.pairs.length; i++) {
            if (c.pairs[i].sellToken.code.length == 0 || c.pairs[i].buyToken.code.length == 0) {
                revert VenuePairs.InvalidConfig();
            }
        }
        return true;
    }

    /// @dev Decodes a swap. A word too wide for its type (an address, the
    /// fee tier) makes the decoding revert, so the call built from the swap
    /// is of exactly the values judged.
    /// @param order `abi.encode(Swap)`.
    /// @return The decoded swap.
    function _swap(bytes calldata order) internal pure returns (Swap memory) {
        // exactly the five words: nothing may ride along
        if (order.length != SWAP_LENGTH) revert NotASwap();
        return abi.decode(order, (Swap));
    }

    /// @dev The router call for a swap: the bought token to the account, no price limit.
    /// @param account The account that swaps and receives.
    /// @param s The swap.
    /// @return The calldata of the router's `exactInputSingle`.
    function _call(address account, Swap memory s) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(
                    s.tokenIn, s.tokenOut, s.fee, account, s.amountIn, s.amountOutMinimum, 0
                ))
        );
    }
}
