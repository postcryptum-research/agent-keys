// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVenueDecoder} from "./IVenueDecoder.sol";

// The three reads of CoW Protocol's settlement contract (GPv2Settlement) that the decoder needs
interface IGPv2Settlement {
    /// @dev Gets the settlement's EIP-712 domain separator, which every order digest is built on.
    /// @return The domain separator.
    function domainSeparator() external view returns (bytes32);
    /// @dev Gets the vault relayer: the contract that takes the sell token from an order's owner.
    /// @return The vault relayer's address.
    function vaultRelayer() external view returns (address);
    /// @dev Gets how much of an order has been filled; a cancelled order reads the maximum.
    /// @param orderUid The order's uid: its digest, its owner and its `validTo`, packed.
    /// @return The amount filled so far, in the order's sell or buy token by its kind.
    function filledAmount(bytes calldata orderUid) external view returns (uint256);
}

/// @title CowSwapDecoder - CoW Protocol's order, for `AgentPolicy` (issue #80)
/// @notice Reads a GPv2 order and allows it only if:
///         - its proceeds go to the account (`receiver` is zero or the account);
///         - it sells and buys a pair the owner listed, at no less than the
///           pair's lowest price, which every pair has;
///         - it is a sell order, filled whole or not at all, with both
///           balances plain ERC-20 (not Balancer's vault);
///         - its `appData` is the one the owner pinned;
///         - its `feeAmount` is zero, so that the lowest price is the price
///           of everything that leaves the account. (CoW takes its fee from
///           the surplus today and wants this field zero; the rule here does
///           not rest on that.)
///         The most it can take is then `sellAmount`: the settlement adds up
///         what an order filled and caps it.
/// @dev No storage, no upgrade path, no `delegatecall`, no `selfdestruct`: the
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
        /// operation that registers it. 2^32 - 1 seconds is over 136 years.
        uint32 maxLife;
        /// The pairs the agent may trade; at most `MAX_PAIRS`.
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
        /// The token the agent may sell.
        address sellToken;
        /// The token it may buy with it.
        address buyToken;
        /// The least of `buyToken` an order must ask for per `perSell` of `sellToken`.
        uint256 minBuy;
        /// The amount of `sellToken` that `minBuy` is the price of.
        uint256 perSell;
    }

    /// A GPv2 order as CoW's contracts lay it out. `order` is `abi.encode(Order)`.
    /// Every field is one ABI word, twelve in all.
    struct Order {
        /// The token the order sells.
        address sellToken;
        /// The token the order buys.
        address buyToken;
        /// Who receives the proceeds; zero means the order's owner.
        address receiver;
        /// For a sell order, the exact amount sold.
        uint256 sellAmount;
        /// For a sell order, the least amount bought.
        uint256 buyAmount;
        /// The last moment the order can be filled, in seconds; CoW's own
        /// width, enough until the year 2106.
        uint32 validTo;
        /// The hash of the order's off-chain metadata.
        bytes32 appData;
        /// The fee the order pays in the sell token, on top of `sellAmount`.
        uint256 feeAmount;
        /// `keccak256("sell")` or `keccak256("buy")`.
        bytes32 kind;
        /// Whether the order may be filled in parts.
        bool partiallyFillable;
        /// Where the sell token comes from: `keccak256("erc20")` for the plain
        /// token, other values for Balancer's vault.
        bytes32 sellTokenBalance;
        /// Where the bought token goes: `keccak256("erc20")` for the plain
        /// token, another value for Balancer's vault.
        bytes32 buyTokenBalance;
    }

    /// @dev The order is not exactly twelve words.
    error NotAnOrder();
    /// @dev The order's proceeds go to someone other than the account.
    /// @param receiver The order's receiver.
    error ProceedsLeaveTheAccount(address receiver);
    /// @dev The order's pair is not listed, or is listed with the same token on both sides or without a price.
    /// @param sellToken The order's sell token.
    /// @param buyToken The order's buy token.
    error PairNotListed(address sellToken, address buyToken);
    /// @dev The order asks for less than the pair's lowest price.
    error BelowTheLowestPrice();
    /// @dev The order is not a sell order.
    error NotASellOrder();
    /// @dev The order may be filled in parts.
    error PartiallyFillable();
    /// @dev A balance of the order is not the plain ERC-20 one.
    error NotPlainErc20();
    /// @dev The order carries another `appData` than the one the owner pinned.
    /// @param appData The order's `appData`.
    error OtherAppData(bytes32 appData);
    /// @dev The order sells nothing.
    error NothingToSell();
    /// @dev The order's `feeAmount` is not zero.
    error FeeNotZero();
    /// @dev The config lists the order's pair more than once.
    error PairListedTwice();
    /// @dev The config breaks a rule of `checkConfig`, or lists more than `MAX_PAIRS` pairs.
    error InvalidConfig();

    /// EIP-712 type hash of a GPv2 order, from CoW's type string.
    bytes32 public constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );
    /// The `kind` word of a sell order.
    bytes32 public constant KIND_SELL = keccak256("sell");
    /// The balance word of a plain ERC-20 balance.
    bytes32 public constant BALANCE_ERC20 = keccak256("erc20");
    /// The length of an encoded order: twelve words.
    uint256 internal constant ORDER_LENGTH = 12 * 32;
    /// The most pairs a config may list: `judge` reads them all, inside a
    /// gas bound.
    uint256 public constant MAX_PAIRS = 16;

    /// The settlement.
    address public immutable override venue;
    /// The settlement's EIP-712 domain separator, read at deployment.
    bytes32 public immutable domainSeparator;
    /// The settlement's vault relayer, read at deployment: who takes the sell token.
    address public immutable override spender;

    /// @dev Decoder constructor: reads the settlement's domain separator and
    /// vault relayer once, so that `judge` reads no storage.
    /// @param settlement_ CoW Protocol's settlement contract on this chain.
    constructor(address settlement_) {
        venue = settlement_;
        domainSeparator = IGPv2Settlement(settlement_).domainSeparator();
        spender = IGPv2Settlement(settlement_).vaultRelayer();
    }

    /// @inheritdoc IVenueDecoder
    /// @dev Applies the rules listed for the contract. `notBefore` is
    /// `validTo - maxLife` (zero when `validTo` is not above `maxLife`): an
    /// order registered no earlier than that has at most `maxLife` seconds
    /// left. `mostSold` is `sellAmount`, since the fee must be zero and the
    /// order is filled whole or not at all.
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        view
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        // Decode the order (exactly twelve words, each in canonical form) and the owner's config
        Order memory o = _order(order);
        Config memory c = abi.decode(config, (Config));

        // The proceeds go to the account: GPv2 reads a zero receiver as the order's owner
        if (o.receiver != address(0) && o.receiver != account) revert ProceedsLeaveTheAccount(o.receiver);
        // A sell order only
        if (o.kind != KIND_SELL) revert NotASellOrder();
        // Filled whole or not at all
        if (o.partiallyFillable) revert PartiallyFillable();
        // Both balances plain ERC-20, not Balancer's vault
        if (o.sellTokenBalance != BALANCE_ERC20 || o.buyTokenBalance != BALANCE_ERC20) revert NotPlainErc20();
        // The `appData` the owner pinned: the agent does not choose the order's metadata
        if (o.appData != c.appData) revert OtherAppData(o.appData);
        // Something to sell
        if (o.sellAmount == 0) revert NothingToSell();
        // No fee field, so the lowest price covers everything that leaves the account
        if (o.feeAmount != 0) revert FeeNotZero();
        // A listed pair, at no less than its lowest price
        _checkPair(c.pairs, o);

        // What the order can cost, when, and the digest the settlement will ask the account to vouch for
        sellToken = o.sellToken;
        mostSold = o.sellAmount;
        validTo = o.validTo;
        notBefore = o.validTo > c.maxLife ? uint48(o.validTo - c.maxLife) : 0;
        digest = _digest(order);
    }

    /// @inheritdoc IVenueDecoder
    /// @dev True means only that the settlement's `filledAmount` of the
    /// order reads zero now. It does not mean the order was never filled:
    /// after `validTo` an allowlisted solver may reset that word inside a
    /// settlement (`freeFilledAmountStorage`, made for a gas refund), and a
    /// filled order then reads as untouched. A caller that gives a charge
    /// back on this answer alone can give back what was spent.
    function untouched(address account, bytes calldata order) external view override returns (bool) {
        // Decode the order (exactly twelve words, each in canonical form)
        Order memory o = _order(order);
        // GPv2's order uid: the digest (32 bytes), the owner (20) and `validTo` (4), packed
        bytes memory uid = abi.encodePacked(_digest(order), account, o.validTo);
        // A fill adds to `filledAmount` and a cancellation sets it to the maximum, so zero means neither, now
        return IGPv2Settlement(venue).filledAmount(uid) == 0;
    }

    /// @notice Whether `config` is one `judge` can read and an owner can be
    /// shown: at least one pair, no pair twice, no token paired with itself,
    /// a lowest price for every pair.
    /// @dev Also: at most `MAX_PAIRS` pairs, a non-zero `maxLife`, and no
    /// token at the zero address. `judge` does not rely on this check having
    /// been asked (see `_checkPair`).
    /// @param config `abi.encode(Config)`.
    /// @return True if the config passes; otherwise the call reverts with
    /// `InvalidConfig`, so it never returns false.
    function checkConfig(bytes calldata config) external pure returns (bool) {
        // Decode the config
        Config memory c = abi.decode(config, (Config));
        // One to `MAX_PAIRS` pairs, and a lifetime for orders
        if (c.pairs.length == 0 || c.pairs.length > MAX_PAIRS || c.maxLife == 0) revert InvalidConfig();
        for (uint256 i; i < c.pairs.length; i++) {
            Pair memory p = c.pairs[i];
            // Two non-zero token addresses, not the same one
            if (p.sellToken == address(0) || p.buyToken == address(0) || p.sellToken == p.buyToken) {
                revert InvalidConfig();
            }
            // A lowest price, neither of its terms zero
            if (p.minBuy == 0 || p.perSell == 0) revert InvalidConfig();
            // Not listed before (at most `MAX_PAIRS` pairs, so the quadratic scan stays small)
            for (uint256 j; j < i; j++) {
                if (c.pairs[j].sellToken == p.sellToken && c.pairs[j].buyToken == p.buyToken) revert InvalidConfig();
            }
        }
        return true;
    }

    /// @dev Decodes an order. `abi.decode` reverts on a word not in canonical
    /// form (an address or a `validTo` with high bits set, a bool other than 0
    /// or 1), so the bytes `_digest` hashes are exactly the encoding of the
    /// order decoded here.
    /// @param order `abi.encode(Order)`.
    /// @return The decoded order.
    function _order(bytes calldata order) internal pure returns (Order memory) {
        // exactly the twelve words: nothing may ride along outside the hash
        if (order.length != ORDER_LENGTH) revert NotAnOrder();
        return abi.decode(order, (Order));
    }

    /// @dev `judge` does not rest on `checkConfig` having been asked: a
    /// config with too many pairs, a pair without a price or a pair listed
    /// twice (which of its two prices would hold?) allows nothing.
    /// It reverts unless the order's pair is listed exactly once, with a
    /// valid price, and the order asks for no less than that price.
    /// @param pairs The pairs of the owner's config.
    /// @param o The order.
    function _checkPair(Pair[] memory pairs, Order memory o) internal pure {
        // Bound the loop below
        if (pairs.length > MAX_PAIRS) revert InvalidConfig();
        bool found;
        // Read every pair, not only up to the first match, so that a pair listed twice is caught
        for (uint256 i; i < pairs.length; i++) {
            Pair memory p = pairs[i];
            if (p.sellToken != o.sellToken || p.buyToken != o.buyToken) continue;
            if (found) revert PairListedTwice();
            found = true;
            // The matching pair must be one `checkConfig` accepts: two tokens and a price
            if (p.sellToken == p.buyToken || p.minBuy == 0 || p.perSell == 0) {
                revert PairNotListed(o.sellToken, o.buyToken);
            }
            // buyAmount / sellAmount >= minBuy / perSell, in 512 bits
            (uint256 hi1, uint256 lo1) = _mul(o.buyAmount, p.perSell);
            (uint256 hi2, uint256 lo2) = _mul(o.sellAmount, p.minBuy);
            // Compare the two products high word first
            if (hi1 < hi2 || (hi1 == hi2 && lo1 < lo2)) revert BelowTheLowestPrice();
        }
        if (!found) revert PairNotListed(o.sellToken, o.buyToken);
    }

    /// @dev The full 512-bit product.
    /// Both factors may be any uint256, so the product can need two words; the
    /// price check compares such products without overflow or rounding.
    /// @param a The first factor.
    /// @param b The second factor.
    /// @return hi The high 256 bits of `a * b`.
    /// @return lo The low 256 bits of `a * b`.
    function _mul(uint256 a, uint256 b) internal pure returns (uint256 hi, uint256 lo) {
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

    /// @dev EIP-712: the order's twelve words behind its type hash. `kind`
    /// and the two balances are strings in the type, so the words the order
    /// carries (their hashes) are what the struct hash takes.
    /// @param order `abi.encode(Order)`, already checked by `_order`.
    /// @return The order's EIP-712 digest under the settlement's domain.
    function _digest(bytes calldata order) internal view returns (bytes32) {
        // The struct hash: the type hash, then the order's twelve words
        bytes32 structHash = keccak256(abi.encodePacked(ORDER_TYPE_HASH, order));
        // The digest: "\x19\x01", the settlement's domain separator, the struct hash
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }
}
