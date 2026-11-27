// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {IVenueDecoder} from "./IVenueDecoder.sol";
import {VenuePairs} from "./VenuePairs.sol";

// The three reads of 1inch's router (AggregationRouterV6, which carries Limit Order Protocol v4) that the decoder needs
interface IOneInchRouter {
    /// @dev ERC-5267: the fields of the router's EIP-712 domain, which every order digest is built on.
    /// @return fields Which of the domain's fields are used, one bit each.
    /// @return name The domain's name.
    /// @return version The domain's version.
    /// @return chainId The domain's chain id.
    /// @return verifyingContract The domain's contract: the router.
    /// @return salt The domain's salt, unused here.
    /// @return extensions The domain's extensions, none here.
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
    /// @dev Gets the digest the router builds for an order: what it asks a contract maker to vouch for.
    /// @param order The order.
    /// @return The order's EIP-712 digest under the router's domain.
    function hashOrder(OneInchLimitOrderDecoder.Order calldata order) external view returns (bytes32);
    /// @dev Gets the word of a maker's one-fill bits that holds `nonce`'s bit (the router shifts `nonce` by eight itself).
    /// @param maker The maker.
    /// @param nonce The order's nonce.
    /// @return The 256 bits of the word; bit `nonce & 0xff` is the order's.
    function bitInvalidatorForOrder(address maker, uint256 nonce) external view returns (uint256);
}

/// @title OneInchLimitOrderDecoder - a plain 1inch limit order, for `AgentPolicy` (issue #80)
/// @notice Reads an order of 1inch's Limit Order Protocol v4 and allows it
///         only if:
///         - the account is its maker, and its proceeds go to the account
///           (`receiver` is zero or the account);
///         - it sells and buys a pair the owner listed, at no less than the
///           pair's lowest price, which every pair has;
///         - it is filled whole, once, or not at all;
///         - it expires;
///         - it is plain: no extension, no interaction before or after the
///           fill, no Permit2, no unwrapping, no epoch series.
///         The most it can take is then `makingAmount`, and the least the
///         account gets for it is `takingAmount`: the protocol charges no fee
///         of its own on such an order.
/// @dev No storage, no upgrade path, no `delegatecall`, no `selfdestruct`: the
/// router's EIP-712 domain separator is read once, in the constructor, and
/// is part of the code.
///
/// What each rule rests on in the router (AggregationRouterV6 at
/// 0x111111125421cA6dc452d289314280a0f8842A65, verified source, with
/// limit-order-protocol 4.0.0-prerelease-19 and solidity-utils 3.7.1):
/// - The order's hash covers its eight words as the taker hands them over
///   (`OrderLib.hash` copies them from calldata), while the router reads an
///   address from a word's low 160 bits only. So the words are taken here
///   as numbers and held clean: the hash is of exactly what was judged.
/// - A contract maker is asked `isValidSignature(orderHash, signature)` when
///   nothing of the order has been filled yet (`_fillContractOrder`). An
///   order filled in parts is asked once and not again, so only an order
///   filled whole is allowed: every fill of it passes the account.
/// - An order that forbids partial fills is invalidated by a bit per maker
///   and nonce (`BitInvalidatorLib`): it fills once.
/// - Without the extension flag the router refuses any extension, so no
///   amount getter, predicate, transfer suffix or third-party interaction
///   can run. The two interaction flags would still call the maker itself;
///   they are refused with the rest.
/// - An expiration of zero means "never" to the router; it is refused.
/// - The router pulls the maker asset itself (`transferFrom`), so it is
///   both the venue and the spender. Its allowance is an allowance to the
///   whole router, as for every 1inch user.
///
/// The order's hash is written here from the router's type string and not
/// taken from its library; the constructor holds it to the router's own
/// `hashOrder`, so a decoder cannot be deployed for a router that hashes
/// otherwise.
contract OneInchLimitOrderDecoder is IVenueDecoder {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    /// The owner's choice for this venue. `config` is `abi.encode(Config)`.
    struct Config {
        /// An order's expiration is at most this many seconds after the
        /// operation that registers it. 2^32 - 1 seconds is over 136 years.
        uint32 maxLife;
        /// The pairs the agent may trade; at most `MAX_PAIRS`.
        VenuePairs.Pair[] pairs;
    }

    /// An order as the router lays it out. `order` is `abi.encode(Order)`.
    /// Every field is one ABI word, eight in all. The router's own types for
    /// the addresses and the traits are numbers underneath, and they are
    /// kept as numbers here: a word's high bits are part of the order's hash.
    struct Order {
        /// Any number: with no extension the router gives it no meaning.
        uint256 salt;
        /// The order's maker: the account, as a number.
        uint256 maker;
        /// Who receives the proceeds, as a number; zero means the maker.
        uint256 receiver;
        /// The token the order sells, as a number.
        uint256 makerAsset;
        /// The token the order buys, as a number.
        uint256 takerAsset;
        /// The exact amount sold.
        uint256 makingAmount;
        /// The least amount bought.
        uint256 takingAmount;
        /// The order's flags, expiration, nonce and allowed taker, packed (see the constants below).
        uint256 makerTraits;
    }

    /// @dev The order is not exactly eight words.
    error NotAnOrder();
    /// @dev The order's maker word is not the account's address.
    /// @param maker The order's maker word.
    error NotTheAccountsOrder(uint256 maker);
    /// @dev The order's proceeds go to someone other than the account.
    /// @param receiver The order's receiver word.
    error ProceedsLeaveTheAccount(uint256 receiver);
    /// @dev A token word of the order has bits above an address.
    error NotAnAddress();
    /// @dev The order may be filled in parts.
    error PartiallyFillable();
    /// @dev The order sets a flag or a field a plain order leaves at zero.
    /// @param bits The bits of `makerTraits` that are set and must not be.
    error NotAPlainOrder(uint256 bits);
    /// @dev The order has no expiration: the router would fill it at any time.
    error NeverExpires();
    /// @dev The order sells nothing.
    error NothingToSell();
    /// @dev An amount of the order does not fit 128 bits.
    error AmountTooLarge();
    /// @dev The router's EIP-712 domain is not one of name, version, chain and contract, for this chain and this router.
    error NotTheRoutersDomain();
    /// @dev The router's own hash of an order is not the one built here.
    error NotTheRoutersHash();

    /// EIP-712 type hash of the domain the router signs in.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// EIP-712 type hash of an order, from the router's type string.
    bytes32 public constant ORDER_TYPE_HASH = keccak256(
        "Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)"
    );
    /// The length of an encoded order: eight words.
    uint256 internal constant ORDER_LENGTH = 8 * 32;
    /// The most pairs a config may list.
    uint256 public constant MAX_PAIRS = VenuePairs.MAX_PAIRS;

    // `makerTraits`, low bits first (`MakerTraitsLib`):
    //   0-79    the only taker allowed, by the low 80 bits of its address; zero is anyone
    //   80-119  the expiration, in seconds; zero is never
    //   120-159 the nonce: with the one-fill bit, the order's place among the maker's one-fill bits
    //   160-199 the series, read only with the epoch flag
    //   200-246 no meaning
    //   247     unwrap WETH on the way to the receiver
    //   248     pull the maker asset through Permit2
    //   249     the order has an extension
    //   250     check the maker's epoch
    //   251     call the maker (or an extension's target) after the fill
    //   252     call the maker (or an extension's target) before the fill
    //   253     no meaning
    //   254     allow several fills
    //   255     no partial fills
    /// The flag that forbids partial fills: with it an order is filled whole, once.
    uint256 internal constant NO_PARTIAL_FILLS = 1 << 255;
    /// Bits 160 to 254: the series, the bits without a meaning and every
    /// flag but `NO_PARTIAL_FILLS`. A plain order leaves them all at zero.
    uint256 internal constant MUST_BE_ZERO = ((1 << 255) - 1) ^ ((1 << 160) - 1);
    /// Where the expiration sits, and its width.
    uint256 internal constant EXPIRATION_OFFSET = 80;
    /// Where the nonce sits; it is as wide as the expiration.
    uint256 internal constant NONCE_OFFSET = 120;
    /// Forty bits: the width of the expiration and of the nonce.
    uint256 internal constant FORTY_BITS = type(uint40).max;

    /// The router: the venue's own contract, and the one that takes the sell token.
    address public immutable override venue;
    /// The router again: it pulls the maker asset itself, so it is the spender.
    address public immutable override spender;
    /// The router's EIP-712 domain separator, built at deployment from the router's own domain fields.
    bytes32 public immutable domainSeparator;

    /// @dev Decoder constructor: builds the router's domain separator once,
    /// so that `judge` reads no storage, and holds the order hash built here
    /// to the router's own.
    /// @param router_ 1inch's router on this chain.
    constructor(address router_) {
        venue = router_;
        spender = router_;
        // The router's own domain fields: name, version, chain and contract, and nothing else
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IOneInchRouter(router_).eip712Domain();
        if (fields != 0x0f || chainId != block.chainid || verifyingContract != router_) revert NotTheRoutersDomain();
        bytes32 separator = keccak256(
            abi.encode(DOMAIN_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, router_)
        );
        domainSeparator = separator;
        // An order with a different number in every word: the router's hash of it must be the one built here
        Order memory probe = Order(1, 2, 3, 4, 5, 6, 7, 8);
        if (IOneInchRouter(router_).hashOrder(probe) != _digestUnder(separator, abi.encode(probe))) {
            revert NotTheRoutersHash();
        }
    }

    /// @inheritdoc IVenueDecoder
    /// @dev Applies the rules listed for the contract. `notBefore` is the
    /// expiration less `maxLife` (zero when the expiration is not above
    /// `maxLife`): an order registered no earlier than that has at most
    /// `maxLife` seconds left. `mostSold` is `makingAmount`: the order is
    /// filled whole or not at all, and the router adds no fee.
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        view
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        // Decode the order (exactly eight words, read as numbers) and the owner's config
        Order memory o = _order(order);
        Config memory c = abi.decode(config, (Config));

        // The account is the maker, in a word with nothing above the address
        if (o.maker != uint256(uint160(account))) revert NotTheAccountsOrder(o.maker);
        // The proceeds go to the account: the router reads a zero receiver as the maker
        if (o.receiver != 0 && o.receiver != o.maker) revert ProceedsLeaveTheAccount(o.receiver);
        // Both tokens in clean words: the pair below is compared by address
        if (o.makerAsset >> 160 != 0 || o.takerAsset >> 160 != 0) revert NotAnAddress();
        // Filled whole: the router then keeps one bit for the order, and asks the account on its one fill
        if (o.makerTraits & NO_PARTIAL_FILLS == 0) revert PartiallyFillable();
        // Plain: no extension, no interaction, no Permit2, no unwrapping, no epoch, no several fills
        if (o.makerTraits & MUST_BE_ZERO != 0) revert NotAPlainOrder(o.makerTraits & MUST_BE_ZERO);
        // An end: zero would be an order that never expires
        uint256 expiration = (o.makerTraits >> EXPIRATION_OFFSET) & FORTY_BITS;
        if (expiration == 0) revert NeverExpires();
        // Something to sell
        if (o.makingAmount == 0) revert NothingToSell();
        // Amounts inside the range the router's own arithmetic is written for
        if (o.makingAmount >> 128 != 0 || o.takingAmount >> 128 != 0) revert AmountTooLarge();
        // A listed pair, at no less than its lowest price
        VenuePairs.check(
            c.pairs, address(uint160(o.makerAsset)), address(uint160(o.takerAsset)), o.makingAmount, o.takingAmount
        );

        // What the order can cost, when, and the digest the router will ask the account to vouch for
        sellToken = address(uint160(o.makerAsset));
        mostSold = o.makingAmount;
        validTo = uint48(expiration);
        notBefore = expiration > c.maxLife ? uint48(expiration - c.maxLife) : 0;
        digest = _digestUnder(domainSeparator, order);
    }

    /// @inheritdoc IVenueDecoder
    /// @dev True means only that the order's one-fill bit at the router is
    /// clear now. The bit belongs to the maker and the nonce, not to the
    /// order: another order of the account with the same nonce sets it too,
    /// and a fill and a cancellation set it alike. So false does not mean
    /// that this order was filled, and true means that no order with its
    /// nonce was filled or cancelled.
    function untouched(address account, bytes calldata order) external view override returns (bool) {
        // Decode the order (exactly eight words)
        Order memory o = _order(order);
        // Only an order filled whole has a one-fill bit; `judge` allows no other
        if (o.makerTraits & NO_PARTIAL_FILLS == 0) revert PartiallyFillable();
        // The word of the maker's bits that holds this nonce, and the nonce's bit in it
        uint256 nonce = (o.makerTraits >> NONCE_OFFSET) & FORTY_BITS;
        uint256 word = IOneInchRouter(venue).bitInvalidatorForOrder(account, nonce);
        return word & (1 << (nonce & 0xff)) == 0;
    }

    /// @notice Whether `config` is one `judge` can read and an owner can be
    /// shown: a lifetime for orders, at least one pair, no pair twice, no
    /// token paired with itself, a lowest price for every pair, and code at
    /// every token's address.
    /// @dev The code is asked for because the router takes a transfer at an
    /// address without code for done: an order that buys such a "token"
    /// gives the sold amount away. `judge` does not ask (it runs inside
    /// validation, where an address without code may not be touched), so
    /// the owner's tools ask here before the mandate is made. `judge` does
    /// not rely on this check having been asked for the rest.
    /// @param config `abi.encode(Config)`.
    /// @return True if the config passes; otherwise the call reverts, so it
    /// never returns false.
    function checkConfig(bytes calldata config) external view returns (bool) {
        // Decode the config
        Config memory c = abi.decode(config, (Config));
        // A lifetime for orders, and a list of pairs an owner can be shown
        if (c.maxLife == 0) revert VenuePairs.InvalidConfig();
        VenuePairs.checkList(c.pairs);
        // Code at both tokens of every pair
        for (uint256 i; i < c.pairs.length; i++) {
            if (c.pairs[i].sellToken.code.length == 0 || c.pairs[i].buyToken.code.length == 0) {
                revert VenuePairs.InvalidConfig();
            }
        }
        return true;
    }

    /// @dev Decodes an order. Its eight words are numbers here, so no word
    /// is cut or cleaned on the way: the bytes `_digestUnder` hashes are
    /// exactly the words `judge` checks.
    /// @param order `abi.encode(Order)`.
    /// @return The decoded order.
    function _order(bytes calldata order) internal pure returns (Order memory) {
        // exactly the eight words: nothing may ride along outside the hash
        if (order.length != ORDER_LENGTH) revert NotAnOrder();
        return abi.decode(order, (Order));
    }

    /// @dev EIP-712: the order's eight words behind its type hash, as the
    /// router hashes them (`OrderLib.hash`).
    /// @param separator The router's domain separator.
    /// @param order `abi.encode(Order)`: the eight words.
    /// @return The order's EIP-712 digest under the router's domain.
    function _digestUnder(bytes32 separator, bytes memory order) internal pure returns (bytes32) {
        // The struct hash: the type hash, then the order's eight words
        bytes32 structHash = keccak256(abi.encodePacked(ORDER_TYPE_HASH, order));
        // The digest: "\x19\x01", the router's domain separator, the struct hash
        return keccak256(abi.encodePacked(hex"1901", separator, structHash));
    }
}
