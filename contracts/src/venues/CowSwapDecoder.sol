// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVenueDecoder} from "./IVenueDecoder.sol";

interface IGPv2Settlement {
    function domainSeparator() external view returns (bytes32);
    function vaultRelayer() external view returns (address);
    function filledAmount(bytes calldata orderUid) external view returns (uint256);
}

/// @title  CowSwapDecoder — CoW Protocol's order, for `AgentPolicy` (issue #80)
/// @notice Reads a GPv2 order and allows it only if:
///         - its proceeds go to the account (`receiver` is zero or the account);
///         - it sells and buys a pair the owner listed, at no less than the
///           pair's lowest price, which every pair has;
///         - it is a sell order, filled whole or not at all, with both
///           balances plain ERC-20 (not Balancer's vault);
///         - its `appData` is the one the owner pinned.
///         The most it can take is `sellAmount + feeAmount`: the settlement
///         adds up what an order filled and caps it.
///
/// No storage, no upgrade path, no `delegatecall`, no `selfdestruct`: the
/// settlement's EIP-712 domain separator and its relayer are read once, in
/// the constructor, and are part of the code.
///
/// The order's hash is written here from CoW's type string (GPv2Order.sol)
/// and not taken from their library; the tests hold it to an independent
/// EIP-712 implementation. A decoder built for the wrong settlement fails
/// safe: its digests are ones that settlement never asks for.
contract CowSwapDecoder is IVenueDecoder {
    /// The owner's choice for this venue. `config` is `abi.encode(Config)`.
    struct Config {
        /// The one `appData` orders must carry.
        bytes32 appData;
        /// An order's `validTo` is at most this many seconds after the
        /// operation that registers it.
        uint32 maxLife;
        Pair[] pairs;
    }

    /// A pair the agent may trade, one way, and its lowest price: an order
    /// must ask for at least `minBuy` of `buyToken` per `perSell` of
    /// `sellToken`, both in the tokens' smallest units and neither zero.
    /// Without it a compromised agent could sell for nothing; with it the
    /// most it can lose on an order is the distance from this price to the
    /// market's. The policy has no oracle: the owner sets the price and it
    /// stays until the mandate is replaced.
    struct Pair {
        address sellToken;
        address buyToken;
        uint256 minBuy;
        uint256 perSell;
    }

    /// A GPv2 order as CoW's contracts lay it out. `order` is `abi.encode(Order)`.
    struct Order {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        bytes32 kind;
        bool partiallyFillable;
        bytes32 sellTokenBalance;
        bytes32 buyTokenBalance;
    }

    error NotAnOrder();
    error ProceedsLeaveTheAccount(address receiver);
    error PairNotListed(address sellToken, address buyToken);
    error BelowTheLowestPrice();
    error NotASellOrder();
    error PartiallyFillable();
    error NotPlainErc20();
    error OtherAppData(bytes32 appData);
    error NothingToSell();
    error InvalidConfig();

    bytes32 public constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );
    bytes32 public constant KIND_SELL = keccak256("sell");
    bytes32 public constant BALANCE_ERC20 = keccak256("erc20");
    uint256 internal constant ORDER_LENGTH = 12 * 32;

    address public immutable settlement;
    bytes32 public immutable domainSeparator;
    address public immutable override spender;

    constructor(address settlement_) {
        settlement = settlement_;
        domainSeparator = IGPv2Settlement(settlement_).domainSeparator();
        spender = IGPv2Settlement(settlement_).vaultRelayer();
    }

    /// @inheritdoc IVenueDecoder
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        view
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        Order memory o = _order(order);
        Config memory c = abi.decode(config, (Config));

        if (o.receiver != address(0) && o.receiver != account) revert ProceedsLeaveTheAccount(o.receiver);
        if (o.kind != KIND_SELL) revert NotASellOrder();
        if (o.partiallyFillable) revert PartiallyFillable();
        if (o.sellTokenBalance != BALANCE_ERC20 || o.buyTokenBalance != BALANCE_ERC20) revert NotPlainErc20();
        if (o.appData != c.appData) revert OtherAppData(o.appData);
        if (o.sellAmount == 0) revert NothingToSell();
        _checkPair(c.pairs, o);

        sellToken = o.sellToken;
        mostSold = o.sellAmount + o.feeAmount; // checked: an overflow is a refusal
        validTo = o.validTo;
        notBefore = o.validTo > c.maxLife ? uint48(o.validTo - c.maxLife) : 0;
        digest = _digest(order);
    }

    /// @inheritdoc IVenueDecoder
    function untouched(address account, bytes calldata order) external view override returns (bool) {
        Order memory o = _order(order);
        bytes memory uid = abi.encodePacked(_digest(order), account, o.validTo);
        return IGPv2Settlement(settlement).filledAmount(uid) == 0;
    }

    /// @notice Whether `config` is one `judge` can read and an owner can be
    /// shown: at least one pair, no pair twice, no token paired with itself,
    /// a lowest price for every pair.
    function checkConfig(bytes calldata config) external pure returns (bool) {
        Config memory c = abi.decode(config, (Config));
        if (c.pairs.length == 0 || c.maxLife == 0) revert InvalidConfig();
        for (uint256 i; i < c.pairs.length; i++) {
            Pair memory p = c.pairs[i];
            if (p.sellToken == address(0) || p.buyToken == address(0) || p.sellToken == p.buyToken) {
                revert InvalidConfig();
            }
            if (p.minBuy == 0 || p.perSell == 0) revert InvalidConfig();
            for (uint256 j; j < i; j++) {
                if (c.pairs[j].sellToken == p.sellToken && c.pairs[j].buyToken == p.buyToken) revert InvalidConfig();
            }
        }
        return true;
    }

    function _order(bytes calldata order) internal pure returns (Order memory) {
        // exactly the twelve words: nothing may ride along outside the hash
        if (order.length != ORDER_LENGTH) revert NotAnOrder();
        return abi.decode(order, (Order));
    }

    function _checkPair(Pair[] memory pairs, Order memory o) internal pure {
        for (uint256 i; i < pairs.length; i++) {
            Pair memory p = pairs[i];
            if (p.sellToken != o.sellToken || p.buyToken != o.buyToken) continue;
            if (p.sellToken == p.buyToken) break;
            // a pair without a price is not a pair: refused here too, whatever checkConfig said
            if (p.minBuy == 0 || p.perSell == 0) break;
            // buyAmount / sellAmount >= minBuy / perSell, in 512 bits
            (uint256 hi1, uint256 lo1) = _mul(o.buyAmount, p.perSell);
            (uint256 hi2, uint256 lo2) = _mul(o.sellAmount, p.minBuy);
            if (hi1 < hi2 || (hi1 == hi2 && lo1 < lo2)) revert BelowTheLowestPrice();
            return;
        }
        revert PairNotListed(o.sellToken, o.buyToken);
    }

    /// @dev The full 512-bit product.
    function _mul(uint256 a, uint256 b) internal pure returns (uint256 hi, uint256 lo) {
        assembly {
            let mm := mulmod(a, b, not(0))
            lo := mul(a, b)
            hi := sub(sub(mm, lo), lt(mm, lo))
        }
    }

    /// @dev EIP-712: the order's twelve words behind its type hash. `kind`
    /// and the two balances are strings in the type, so the words the order
    /// carries (their hashes) are what the struct hash takes.
    function _digest(bytes calldata order) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encodePacked(ORDER_TYPE_HASH, order));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }
}
