// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {OneInchLimitOrderDecoder} from "../src/venues/OneInchLimitOrderDecoder.sol";
import {VenuePairs} from "../src/venues/VenuePairs.sol";

interface ITokenForRouter {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// 1inch's router as far as a plain limit order of a contract maker goes,
/// written from the verified source of AggregationRouterV6 (`OrderMixin`,
/// `OrderLib`, `MakerTraitsLib`, `BitInvalidatorLib`, `ECDSA`):
/// - the hash is of the order's eight words as they came in the calldata;
/// - the maker is asked `isValidSignature(orderHash, signature)`, the
///   signature's bytes passed on without padding;
/// - an order that forbids partial fills fills once, by a bit per maker and
///   nonce;
/// - the two interaction flags call the maker itself when no extension
///   names another target;
/// - an expiration of zero never expires.
/// What a plain order does not use (extensions, Permit2, unwrapping, epochs,
/// orders filled in parts) is not modelled: such an order reverts here.
/// `OneInchFork.t.sol` runs the same tests against the router itself.
contract RouterStandIn {
    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)"
    );

    mapping(address maker => mapping(uint256 slot => uint256 bits)) internal _bits;

    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (hex"0f", "1inch Aggregation Router", "6", block.chainid, address(this), bytes32(0), new uint256[](0));
    }

    function hashOrder(OneInchLimitOrderDecoder.Order calldata order) public view returns (bytes32 result) {
        bytes32 separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("1inch Aggregation Router"),
                keccak256("6"),
                block.chainid,
                address(this)
            )
        );
        bytes32 typeHash = ORDER_TYPE_HASH;
        // as `OrderLib.hash`: the eight words copied from the calldata, whatever their high bits
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            calldatacopy(add(ptr, 0x20), order, 0x100)
            result := keccak256(ptr, 0x120)
        }
        result = keccak256(abi.encodePacked(hex"1901", separator, result));
    }

    function bitInvalidatorForOrder(address maker, uint256 slot) external view returns (uint256) {
        return _bits[maker][slot >> 8];
    }

    /// `takerTraits`: bit 255 set means `amount` is the making amount, clear the taking amount.
    function fillContractOrder(
        OneInchLimitOrderDecoder.Order calldata order,
        bytes calldata signature,
        uint256 amount,
        uint256 takerTraits
    ) external returns (uint256 makingAmount, uint256 takingAmount, bytes32 orderHash) {
        uint256 traits = order.makerTraits;
        address maker = address(uint160(order.maker));
        require(traits >> 255 == 1, "stand-in: an order filled in parts is not modelled");
        require(traits & ((1 << 250) | (1 << 249) | (1 << 248) | (1 << 247)) == 0, "stand-in: not modelled");
        orderHash = hashOrder(order);
        // a one-fill order's remaining amount is always the whole of it, so the maker is asked on every fill
        require(_vouches(maker, orderHash, signature), "BadSignature");
        // the only taker allowed, by the low 80 bits of its address
        uint256 allowed = traits & type(uint80).max;
        require(allowed == 0 || allowed == uint160(msg.sender) & type(uint80).max, "PrivateOrder");
        // zero never expires
        uint256 expiration = (traits >> 80) & type(uint40).max;
        require(expiration == 0 || expiration >= block.timestamp, "OrderExpired");
        // the amounts, rounded in the maker's favour
        if (takerTraits >> 255 == 1) {
            makingAmount = amount < order.makingAmount ? amount : order.makingAmount;
            takingAmount = (makingAmount * order.takingAmount + order.makingAmount - 1) / order.makingAmount;
        } else {
            takingAmount = amount;
            makingAmount = takingAmount * order.makingAmount / order.takingAmount;
            if (makingAmount > order.makingAmount) {
                makingAmount = order.makingAmount;
                takingAmount = order.takingAmount;
                require(takingAmount <= amount, "TakingAmountExceeded");
            }
        }
        require(makingAmount == order.makingAmount, "PartialFillNotAllowed");
        require(makingAmount != 0 && takingAmount != 0, "SwapWithZeroAmount");
        // once: the nonce's bit among the maker's
        uint256 nonce = (traits >> 120) & type(uint40).max;
        uint256 bit = 1 << (nonce & 0xff);
        require(_bits[maker][nonce >> 8] & bit == 0, "BitInvalidatedOrder");
        _bits[maker][nonce >> 8] |= bit;
        // the interaction flags call the maker itself when there is no extension
        if (traits & (1 << 252) != 0) _interact(maker, 0x5a3e0d5c);
        require(ITokenForRouter(address(uint160(order.makerAsset))).transferFrom(maker, msg.sender, makingAmount));
        address receiver = address(uint160(order.receiver));
        require(
            ITokenForRouter(address(uint160(order.takerAsset)))
                .transferFrom(msg.sender, receiver == address(0) ? maker : receiver, takingAmount)
        );
        if (traits & (1 << 251) != 0) _interact(maker, 0x462ebde2);
    }

    /// The maker cancels its own order: sets the nonce's bit.
    function cancelOrder(uint256 makerTraits, bytes32) external {
        uint256 nonce = (makerTraits >> 120) & type(uint40).max;
        _bits[msg.sender][nonce >> 8] |= 1 << (nonce & 0xff);
    }

    function _interact(address maker, bytes4 selector) internal {
        (bool ok,) = maker.call(abi.encodeWithSelector(selector));
        require(ok, "interaction failed");
    }

    /// As `ECDSA.isValidSignature`: the signature's bytes follow their length without padding.
    function _vouches(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool success) {
        bytes4 selector = 0x1626ba7e;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, selector)
            mstore(add(ptr, 0x04), hash)
            mstore(add(ptr, 0x24), 0x40)
            mstore(add(ptr, 0x44), signature.length)
            calldatacopy(add(ptr, 0x64), signature.offset, signature.length)
            if staticcall(gas(), signer, ptr, add(0x64, signature.length), 0, 0x20) {
                success := and(eq(selector, mload(0)), eq(returndatasize(), 0x20))
            }
        }
    }
}

/// A router that names another domain, or hashes an order otherwise: the
/// decoder must not be deployable for it.
contract CrookedRouter {
    bytes1 internal immutable fields;
    uint256 internal immutable chain;
    address internal immutable verifying;
    bool internal immutable wrongHash;

    constructor(bytes1 fields_, uint256 chain_, address verifying_, bool wrongHash_) {
        (fields, chain, verifying, wrongHash) = (fields_, chain_, verifying_, wrongHash_);
    }

    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (
            fields,
            "1inch Aggregation Router",
            "6",
            chain == 0 ? block.chainid : chain,
            verifying == address(0) ? address(this) : verifying,
            bytes32(0),
            new uint256[](0)
        );
    }

    /// The hash a router with this contract's own domain would give, or that hash one bit off.
    function hashOrder(OneInchLimitOrderDecoder.Order calldata order) external view returns (bytes32 result) {
        bytes32 separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("1inch Aggregation Router"),
                keccak256("6"),
                block.chainid,
                address(this)
            )
        );
        bytes32 typeHash = keccak256(
            "Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)"
        );
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            calldatacopy(add(ptr, 0x20), order, 0x100)
            result := keccak256(ptr, 0x120)
        }
        result = keccak256(abi.encodePacked(hex"1901", separator, result));
        if (wrongHash) result = bytes32(uint256(result) ^ 1);
    }
}

/// The 1inch limit-order decoder (issue #80) on its own, without the policy:
/// what it lets through, what it refuses, and that its hash is the router's.
contract OneInchLimitOrderDecoderTest is Test {
    address constant ROUTER = 0x111111125421cA6dc452d289314280a0f8842A65;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    uint32 constant LIFE = 30 minutes;
    uint256 constant EXPIRATION = 1_800_000_000;
    uint256 constant NO_PARTIAL_FILLS = 1 << 255;

    address account = makeAddr("account");
    RouterStandIn router;
    OneInchLimitOrderDecoder decoder;

    function setUp() public {
        // the stand-in sits at the router's address, on mainnet's chain id
        vm.chainId(1);
        deployCodeTo("OneInchLimitOrderDecoder.t.sol:RouterStandIn", ROUTER);
        router = RouterStandIn(ROUTER);
        decoder = new OneInchLimitOrderDecoder(ROUTER);
        // `checkConfig` asks for code at a token's address
        vm.etch(USDC, hex"00");
        vm.etch(USDT, hex"00");
        vm.etch(WETH, hex"00");
    }

    function _config() internal pure returns (OneInchLimitOrderDecoder.Config memory c) {
        c.maxLife = LIFE;
        c.pairs = new VenuePairs.Pair[](2);
        // at least 0.0002 WETH for each USDC (5,000 USDC for one WETH at most)
        c.pairs[0] = VenuePairs.Pair(USDC, WETH, 0.0002 ether, 1e6);
        // at least 0.99 USDT for each USDC
        c.pairs[1] = VenuePairs.Pair(USDC, USDT, 99, 100);
    }

    /// The traits of a plain order: filled whole, with an expiration and a nonce.
    function _traits(uint256 expiration, uint256 nonce) internal pure returns (uint256) {
        return NO_PARTIAL_FILLS | (expiration << 80) | (nonce << 120);
    }

    function _order() internal view returns (OneInchLimitOrderDecoder.Order memory o) {
        o = OneInchLimitOrderDecoder.Order({
            salt: 42,
            maker: uint256(uint160(account)),
            receiver: 0,
            makerAsset: uint256(uint160(USDC)),
            takerAsset: uint256(uint160(WETH)),
            makingAmount: 200e6,
            takingAmount: 0.05 ether,
            makerTraits: _traits(EXPIRATION, 7)
        });
    }

    function _judge(OneInchLimitOrderDecoder.Order memory o)
        internal
        view
        returns (address, uint256, uint48, uint48, bytes32)
    {
        return decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function _refused(OneInchLimitOrderDecoder.Order memory o, bytes memory why) internal {
        vm.expectRevert(why);
        decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function test_constructor_takesTheRoutersFacts() public view {
        assertEq(decoder.venue(), ROUTER);
        assertEq(decoder.spender(), ROUTER, "the router pulls the sold token itself");
        // mainnet's separator: name "1inch Aggregation Router", version "6", chain 1, the router
        assertEq(decoder.domainSeparator(), 0xd999e213f11c7bfa3e796c3409e316f25e02aa3e25e5c207a92e381c7d22b6de);
        // the router's type hash, as `OrderLib` has it
        assertEq(decoder.ORDER_TYPE_HASH(), 0x3af21ec5a20011b88d3b7b4ed7c806cef05a5980cf34974bcd53566a131f7e4c);
        assertEq(decoder.MAX_PAIRS(), 16);
    }

    /// A deployment as a call of its own: an expected revert of a direct
    /// `new` would end the test where it stands, and what follows would not run.
    function build(address router_) external returns (OneInchLimitOrderDecoder) {
        return new OneInchLimitOrderDecoder(router_);
    }

    /// A router with another domain, or one that hashes an order otherwise,
    /// gets no decoder: the digests built here would be ones it never asks for.
    function test_constructor_refusesARouterItDoesNotHashLike() public {
        bytes memory domain = abi.encodeWithSelector(OneInchLimitOrderDecoder.NotTheRoutersDomain.selector);
        bytes memory hash = abi.encodeWithSelector(OneInchLimitOrderDecoder.NotTheRoutersHash.selector);
        // the control: an honest router elsewhere gets its decoder
        assertEq(this.build(address(new RouterStandIn())).spender().code.length > 0, true);
        // a domain with a salt field
        address crooked = address(new CrookedRouter(hex"1f", 0, address(0), false));
        vm.expectRevert(domain);
        this.build(crooked);
        // a domain without its version
        crooked = address(new CrookedRouter(hex"0d", 0, address(0), false));
        vm.expectRevert(domain);
        this.build(crooked);
        // another chain's domain
        crooked = address(new CrookedRouter(hex"0f", 8453, address(0), false));
        vm.expectRevert(domain);
        this.build(crooked);
        // another contract's domain
        crooked = address(new CrookedRouter(hex"0f", 0, ROUTER, false));
        vm.expectRevert(domain);
        this.build(crooked);
        // the right fields, and a hash one bit off
        crooked = address(new CrookedRouter(hex"0f", 0, address(0), true));
        vm.expectRevert(hash);
        this.build(crooked);
        // an address without code
        vm.expectRevert();
        this.build(makeAddr("nothing here"));
    }

    function test_judge_anAllowedOrder() public view {
        OneInchLimitOrderDecoder.Order memory o = _order();
        (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest) = _judge(o);
        assertEq(sellToken, USDC);
        assertEq(mostSold, 200e6);
        assertEq(validTo, EXPIRATION);
        assertEq(notBefore, EXPIRATION - LIFE, "registered no earlier than its lifetime before its end");
        assertEq(digest, router.hashOrder(o), "the hash the router asks the account for");
    }

    /// The maker is the account, and the word holds nothing above its
    /// address: the router would read the same maker from a word with high
    /// bits set, and hash another order.
    function test_judge_theMakerIsTheAccountInACleanWord() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.maker = uint256(uint160(makeAddr("someone else")));
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.NotTheAccountsOrder.selector, o.maker));
        for (uint256 bit = 160; bit < 256; bit++) {
            o.maker = uint256(uint160(account)) | (1 << bit);
            _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.NotTheAccountsOrder.selector, o.maker));
        }
        // what such a word is to the router: the same maker, another hash
        OneInchLimitOrderDecoder.Order memory clean = _order();
        assertEq(address(uint160(o.maker)), address(uint160(clean.maker)));
        assertTrue(router.hashOrder(o) != router.hashOrder(clean));
    }

    function test_judge_receiverIsTheAccountOrNobody() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.receiver = uint256(uint160(account));
        _judge(o);
        o.receiver = uint256(uint160(makeAddr("someone else")));
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.ProceedsLeaveTheAccount.selector, o.receiver));
        // the account's address under a high bit is not the account's word
        o.receiver = uint256(uint160(account)) | (1 << 200);
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.ProceedsLeaveTheAccount.selector, o.receiver));
        // nor is a word of high bits alone "nobody": the router reads its low bits as zero, the maker
        o.receiver = 1 << 255;
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.ProceedsLeaveTheAccount.selector, o.receiver));
    }

    function test_judge_onlyListedPairsOneWay() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.takerAsset = uint256(uint160(USDT));
        o.takingAmount = 199e6;
        _judge(o);
        // the listed pair the other way round
        o.makerAsset = uint256(uint160(WETH));
        o.takerAsset = uint256(uint160(USDC));
        _refused(o, abi.encodeWithSelector(VenuePairs.PairNotListed.selector, WETH, USDC));
        // a token that is not listed
        o = _order();
        o.takerAsset = uint256(uint160(makeAddr("another token")));
        _refused(o, abi.encodeWithSelector(VenuePairs.PairNotListed.selector, USDC, address(uint160(o.takerAsset))));
    }

    /// A token's word holds nothing above its address, for the same reason as the maker's.
    function test_judge_tokenWordsAreClean() public {
        bytes memory why = abi.encodeWithSelector(OneInchLimitOrderDecoder.NotAnAddress.selector);
        for (uint256 bit = 160; bit < 256; bit++) {
            OneInchLimitOrderDecoder.Order memory o = _order();
            o.makerAsset |= 1 << bit;
            _refused(o, why);
            o = _order();
            o.takerAsset |= 1 << bit;
            _refused(o, why);
        }
    }

    function test_judge_theLowestPrice() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        // 200 USDC at 0.0002 WETH each: 0.04 WETH is the least
        o.takingAmount = 0.04 ether;
        _judge(o);
        o.takingAmount = 0.04 ether - 1;
        _refused(o, abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        // nothing asked for is below every price
        o.takingAmount = 0;
        _refused(o, abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        // 0.99 USDT per USDC, in whole units: 198 for 200
        o.takerAsset = uint256(uint160(USDT));
        o.takingAmount = 198e6;
        _judge(o);
        o.takingAmount = 198e6 - 1;
        _refused(o, abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        // a price in whole units of the buy token: one unit below it is below it
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.pairs[0] = VenuePairs.Pair(USDC, WETH, 3, 1);
        o = _order();
        (o.makingAmount, o.takingAmount) = (100, 300);
        decoder.judge(account, abi.encode(c), abi.encode(o));
        o.takingAmount = 299;
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
    }

    /// The price at the widest amounts an order may carry and the widest a config may: no overflow.
    function test_judge_theLowestPriceAtTheWidestAmounts() public {
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.pairs[0] = VenuePairs.Pair(USDC, WETH, type(uint256).max, type(uint256).max);
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.makingAmount = type(uint128).max;
        o.takingAmount = type(uint128).max;
        decoder.judge(account, abi.encode(c), abi.encode(o));
        o.takingAmount = type(uint128).max - 1;
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
    }

    function testFuzz_judge_theLowestPriceAgainstAReference(uint128 buy, uint128 sell, uint256 minBuy, uint256 perSell)
        public
    {
        sell = uint128(bound(sell, 1, type(uint128).max));
        minBuy = bound(minBuy, 1, type(uint128).max);
        perSell = bound(perSell, 1, type(uint128).max);
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.pairs[0] = VenuePairs.Pair(USDC, WETH, minBuy, perSell);
        OneInchLimitOrderDecoder.Order memory o = _order();
        (o.makingAmount, o.takingAmount) = (sell, buy);
        // all four below 2^128: the products fit a word, and plain arithmetic is the reference
        bool enough = uint256(buy) * perSell >= uint256(sell) * minBuy;
        if (!enough) vm.expectRevert(abi.encodeWithSelector(VenuePairs.BelowTheLowestPrice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
    }

    /// Every bit of the traits a plain order leaves at zero, one at a time:
    /// the series, the bits without a meaning, and every flag but "no partial
    /// fills" (unwrap WETH 247, Permit2 248, an extension 249, the epoch 250,
    /// the call after 251 and before 252 the fill, several fills 254).
    function test_judge_everyOtherTraitIsRefused() public {
        for (uint256 bit = 160; bit < 255; bit++) {
            OneInchLimitOrderDecoder.Order memory o = _order();
            o.makerTraits |= 1 << bit;
            _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.NotAPlainOrder.selector, uint256(1) << bit));
        }
        // several at once are named together
        OneInchLimitOrderDecoder.Order memory both = _order();
        both.makerTraits |= (1 << 249) | (1 << 251);
        _refused(
            both, abi.encodeWithSelector(OneInchLimitOrderDecoder.NotAPlainOrder.selector, (1 << 249) | (1 << 251))
        );
    }

    /// An order that may be filled in parts: the router asks the maker on
    /// its first fill only.
    function test_judge_filledWholeOnly() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.makerTraits &= ~NO_PARTIAL_FILLS;
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.PartiallyFillable.selector));
        // with several fills allowed as well
        o.makerTraits |= 1 << 254;
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.PartiallyFillable.selector));
    }

    /// An order ends: an expiration of zero is "never" to the router.
    function test_judge_anOrderExpires() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.makerTraits = _traits(0, 7);
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.NeverExpires.selector));
        // the widest expiration the traits hold, and the lifetime before it
        o.makerTraits = _traits(type(uint40).max, 7);
        (,, uint48 notBefore, uint48 validTo,) = _judge(o);
        assertEq(validTo, type(uint40).max);
        assertEq(notBefore, uint256(type(uint40).max) - LIFE);
        // an expiration inside the lifetime: registered at any time
        o.makerTraits = _traits(LIFE, 7);
        (,, notBefore, validTo,) = _judge(o);
        assertEq(validTo, LIFE);
        assertEq(notBefore, 0);
    }

    /// What the agent picks freely: the salt, the nonce and the one taker
    /// allowed. Each makes another order of the same cost.
    function test_judge_theFreeFields() public view {
        OneInchLimitOrderDecoder.Order memory o = _order();
        (,,,, bytes32 first) = _judge(o);
        o.salt = type(uint256).max;
        (, uint256 mostSold,,, bytes32 salted) = _judge(o);
        assertEq(mostSold, 200e6);
        assertTrue(salted != first);
        o.makerTraits = _traits(EXPIRATION, type(uint40).max);
        (,,, uint48 validTo, bytes32 nonced) = _judge(o);
        assertEq(validTo, EXPIRATION);
        assertTrue(nonced != salted);
        o.makerTraits |= type(uint80).max;
        (,,, validTo,) = _judge(o);
        assertEq(validTo, EXPIRATION, "the taker's bits do not reach the expiration");
        assertEq(router.hashOrder(o), _digestOf(o));
    }

    function test_judge_theAmounts() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        o.makingAmount = 0;
        _refused(o, abi.encodeWithSelector(OneInchLimitOrderDecoder.NothingToSell.selector));
        bytes memory large = abi.encodeWithSelector(OneInchLimitOrderDecoder.AmountTooLarge.selector);
        o = _order();
        o.makingAmount = 1 << 128;
        _refused(o, large);
        o = _order();
        o.takingAmount = 1 << 128;
        _refused(o, large);
        o.takingAmount = type(uint256).max;
        _refused(o, large);
    }

    /// `judge` allows nothing under a config `checkConfig` refuses.
    function test_judge_doesNotRestOnCheckConfig() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        // the order's pair twice, with two prices
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.pairs[1] = VenuePairs.Pair(USDC, WETH, 1, 1e6);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairListedTwice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
        // the order's pair without a price
        c = _config();
        c.pairs[0].minBuy = 0;
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, USDC, WETH));
        decoder.judge(account, abi.encode(c), abi.encode(o));
        c = _config();
        c.pairs[0].perSell = 0;
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, USDC, WETH));
        decoder.judge(account, abi.encode(c), abi.encode(o));
        // more pairs than a config may list
        c.pairs = new VenuePairs.Pair[](17);
        for (uint256 i; i < 17; i++) {
            c.pairs[i] = VenuePairs.Pair(USDC, address(uint160(1000 + i)), 1, 1);
        }
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.InvalidConfig.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
        // no pairs at all
        c.pairs = new VenuePairs.Pair[](0);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, USDC, WETH));
        decoder.judge(account, abi.encode(c), abi.encode(o));
    }

    /// The sixteen pairs a config may list, the order's the last: inside the
    /// gas the policy gives a decoder (`AgentPolicy.JUDGE_GAS`, 150,000).
    function test_judge_fitsThePolicysGasWithTheMostPairs() public view {
        OneInchLimitOrderDecoder.Config memory c;
        c.maxLife = LIFE;
        c.pairs = new VenuePairs.Pair[](16);
        for (uint256 i; i < 15; i++) {
            c.pairs[i] = VenuePairs.Pair(USDC, address(uint160(1000 + i)), 1, 1);
        }
        c.pairs[15] = VenuePairs.Pair(USDC, WETH, 0.0002 ether, 1e6);
        bytes memory config = abi.encode(c);
        bytes memory order = abi.encode(_order());
        uint256 before = gasleft();
        decoder.judge{gas: 150_000}(account, config, order);
        assertLt(before - gasleft(), 150_000);
    }

    function test_judge_refusesAnythingButTheEightWords() public {
        bytes memory config = abi.encode(_config());
        bytes memory order = abi.encode(_order());
        bytes memory why = abi.encodeWithSelector(OneInchLimitOrderDecoder.NotAnOrder.selector);
        // a byte more, a word more, a word less, nothing
        vm.expectRevert(why);
        decoder.judge(account, config, bytes.concat(order, hex"00"));
        vm.expectRevert(why);
        decoder.judge(account, config, bytes.concat(order, bytes32(0)));
        bytes memory short = new bytes(7 * 32);
        for (uint256 i; i < short.length; i++) {
            short[i] = order[i];
        }
        vm.expectRevert(why);
        decoder.judge(account, config, short);
        vm.expectRevert(why);
        decoder.judge(account, config, "");
        // and the same for `untouched`
        vm.expectRevert(why);
        decoder.untouched(account, bytes.concat(order, hex"00"));
    }

    /// The digest against a second implementation of EIP-712 (forge's).
    function test_digest_agreesWithAnIndependentEip712() public view {
        OneInchLimitOrderDecoder.Order memory o = _order();
        (,,,, bytes32 digest) = _judge(o);
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"Order":[{"name":"salt","type":"uint256"},{"name":"maker","type":"address"},{"name":"receiver","type":"address"},{"name":"makerAsset","type":"address"},{"name":"takerAsset","type":"address"},{"name":"makingAmount","type":"uint256"},{"name":"takingAmount","type":"uint256"},{"name":"makerTraits","type":"uint256"}]},',
            '"primaryType":"Order","domain":{"name":"1inch Aggregation Router","version":"6","chainId":1,"verifyingContract":"',
            vm.toString(ROUTER),
            '"},"message":{"salt":"',
            vm.toString(o.salt),
            '","maker":"',
            vm.toString(address(uint160(o.maker)))
        );
        json = string.concat(
            json,
            '","receiver":"',
            vm.toString(address(uint160(o.receiver))),
            '","makerAsset":"',
            vm.toString(address(uint160(o.makerAsset))),
            '","takerAsset":"',
            vm.toString(address(uint160(o.takerAsset))),
            '","makingAmount":"',
            vm.toString(o.makingAmount),
            '","takingAmount":"',
            vm.toString(o.takingAmount),
            '","makerTraits":"',
            vm.toString(o.makerTraits),
            '"}}'
        );
        assertEq(digest, vm.eip712HashTypedData(json));
    }

    /// The digest against the router's own. `hashOrder` of the router at
    /// 0x111111125421cA6dc452d289314280a0f8842A65 was asked on four chains
    /// for this order (2026-11-26, `eth_call`); the decoder, built on the
    /// stand-in at that address under each chain id, gives the same. So does
    /// the stand-in, which is what makes it a stand-in.
    function test_digest_isTheOneTheRouterGave() public {
        OneInchLimitOrderDecoder.Order memory o = OneInchLimitOrderDecoder.Order({
            salt: 42,
            maker: uint256(uint160(0x1111111111111111111111111111111111111111)),
            receiver: 0,
            makerAsset: uint256(uint160(USDC)),
            takerAsset: uint256(uint160(WETH)),
            makingAmount: 1000e6,
            takingAmount: 0.25 ether,
            makerTraits: _traits(1_900_000_000, 7)
        });
        uint256[4] memory chains = [uint256(1), 8453, 11155111, 84532];
        bytes32[4] memory given = [
            bytes32(0x0a6c594bc65692afed072afc8ffbcbac664384f0d521624b63f396edfcbbb48d),
            0xfbcef6ee1646af7a95c2d774d1f7e7168b46dc7a79e5e58e1c310c91ef8b961f,
            0xa776b6c7b9c9e0a40a83221072e354a444b8fd94c6dcf5f4ec56c2e764c9e598,
            0xa64c698dddd4f1ece332d81be16df5c432a378ed04f9eff991f366cb23fb96cf
        ];
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.maxLife = type(uint32).max;
        for (uint256 i; i < chains.length; i++) {
            vm.chainId(chains[i]);
            OneInchLimitOrderDecoder d = new OneInchLimitOrderDecoder(ROUTER);
            (,,,, bytes32 digest) = d.judge(address(uint160(o.maker)), abi.encode(c), abi.encode(o));
            assertEq(digest, given[i], "the decoder's digest");
            assertEq(router.hashOrder(o), given[i], "the stand-in's hash");
        }
        // the order the constructor probes with, as mainnet's router hashes it
        vm.chainId(1);
        assertEq(
            router.hashOrder(OneInchLimitOrderDecoder.Order(1, 2, 3, 4, 5, 6, 7, 8)),
            0x414df8fabc5c7acecd1c823fc831f685b742e7b70f33e569be1710c1d57f0769
        );
    }

    /// EIP-712 by its definition, with the addresses as addresses: another
    /// way to the same digest than the one the decoder takes.
    function _digestOf(OneInchLimitOrderDecoder.Order memory o) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                decoder.ORDER_TYPE_HASH(),
                o.salt,
                address(uint160(o.maker)),
                address(uint160(o.receiver)),
                address(uint160(o.makerAsset)),
                address(uint160(o.takerAsset)),
                o.makingAmount,
                o.takingAmount,
                o.makerTraits
            )
        );
        return keccak256(abi.encodePacked(hex"1901", decoder.domainSeparator(), structHash));
    }

    /// `untouched` reads the order's one-fill bit: the maker's and the nonce's.
    function test_untouched_readsTheOrdersBit() public {
        OneInchLimitOrderDecoder.Order memory o = _order();
        bytes memory order = abi.encode(o);
        assertTrue(decoder.untouched(account, order));
        // the account cancels it at the router: the bit is set
        vm.prank(account);
        router.cancelOrder(o.makerTraits, bytes32(0));
        assertFalse(decoder.untouched(account, order));
        // the bit is the nonce's: another order with the same nonce reads the same, whatever else it says
        OneInchLimitOrderDecoder.Order memory twin = _order();
        twin.salt = 1;
        twin.makingAmount = 1;
        assertFalse(decoder.untouched(account, abi.encode(twin)));
        // the next nonce, in the same word of bits, is untouched; so is the same nonce of another maker
        OneInchLimitOrderDecoder.Order memory next = _order();
        next.makerTraits = _traits(EXPIRATION, 8);
        assertTrue(decoder.untouched(account, abi.encode(next)));
        assertTrue(decoder.untouched(makeAddr("another maker"), order));
        // a nonce in another word of bits: its own word is read
        OneInchLimitOrderDecoder.Order memory far = _order();
        far.makerTraits = _traits(EXPIRATION, 7 + 256);
        assertTrue(decoder.untouched(account, abi.encode(far)));
        vm.prank(account);
        router.cancelOrder(far.makerTraits, bytes32(0));
        assertFalse(decoder.untouched(account, abi.encode(far)));
        // an order filled in parts has no such bit
        o.makerTraits &= ~NO_PARTIAL_FILLS;
        vm.expectRevert(abi.encodeWithSelector(OneInchLimitOrderDecoder.PartiallyFillable.selector));
        decoder.untouched(account, abi.encode(o));
    }

    function test_checkConfig() public {
        assertTrue(decoder.checkConfig(abi.encode(_config())));
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.maxLife = 0;
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs = new VenuePairs.Pair[](0);
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[0].sellToken = address(0);
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[0].buyToken = address(0);
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[0].buyToken = USDC;
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[0].minBuy = 0;
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[0].perSell = 0;
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[1] = c.pairs[0];
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        // seventeen pairs, each of them fine: one too many (sixteen pass)
        c = _config();
        c.pairs = new VenuePairs.Pair[](17);
        for (uint256 i; i < 17; i++) {
            vm.etch(address(uint160(1000 + i)), hex"00");
            c.pairs[i] = VenuePairs.Pair(USDC, address(uint160(1000 + i)), 1, 1);
        }
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        OneInchLimitOrderDecoder.Config memory most = _config();
        most.pairs = new VenuePairs.Pair[](16);
        for (uint256 i; i < 16; i++) {
            most.pairs[i] = c.pairs[i];
        }
        assertTrue(decoder.checkConfig(abi.encode(most)));
    }

    /// The router takes a transfer at an address without code for done, so
    /// an order that buys such a "token" would give the sold amount away:
    /// a config that lists one is refused.
    function test_checkConfig_everyTokenHasCode() public {
        OneInchLimitOrderDecoder.Config memory c = _config();
        c.pairs[0].buyToken = makeAddr("no code to buy");
        _badConfig(c, VenuePairs.InvalidConfig.selector);
        c = _config();
        c.pairs[1].sellToken = makeAddr("no code to sell");
        _badConfig(c, VenuePairs.InvalidConfig.selector);
    }

    function _badConfig(OneInchLimitOrderDecoder.Config memory c, bytes4 why) internal {
        vm.expectRevert(abi.encodeWithSelector(why));
        decoder.checkConfig(abi.encode(c));
    }

    /// For any order: accepted means every rule holds; the sum and the
    /// window are as stated. (C7: every field is accounted for.)
    function testFuzz_judge_acceptedMeansEveryRuleHolds(OneInchLimitOrderDecoder.Order memory o, uint256 flips)
        public
        view
    {
        OneInchLimitOrderDecoder.Order memory good = _order();
        // one field at most is the fuzzer's; the rest are an acceptable order's
        uint256 broken = flips % 8;
        if (broken != 1) o.maker = good.maker;
        if (broken != 2) o.receiver = flips & 256 == 0 ? 0 : good.maker;
        if (broken != 3) o.makerAsset = good.makerAsset;
        if (broken != 4) o.takerAsset = uint256(uint160(flips & 512 == 0 ? WETH : USDT));
        if (broken != 5) {
            // a plain order's traits, with the fuzzer's taker, expiration and nonce
            o.makerTraits = (o.makerTraits & ((1 << 160) - 1)) | NO_PARTIAL_FILLS;
            if ((o.makerTraits >> 80) & type(uint40).max == 0) o.makerTraits |= 1 << 80;
        }
        if (broken != 6) o.makingAmount = bound(o.makingAmount, 0, 1e30);
        if (broken != 7) o.takingAmount = bound(o.takingAmount, 0, 1e30);

        try decoder.judge(account, abi.encode(_config()), abi.encode(o)) returns (
            address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest
        ) {
            assertEq(o.maker, uint256(uint160(account)), "maker");
            assertTrue(o.receiver == 0 || o.receiver == o.maker, "receiver");
            assertEq(o.makerAsset, uint256(uint160(USDC)), "sell token");
            assertTrue(o.takerAsset == uint256(uint160(WETH)) || o.takerAsset == uint256(uint160(USDT)), "buy token");
            assertLt(o.makingAmount, 1 << 128);
            assertLt(o.takingAmount, 1 << 128);
            if (o.takerAsset == uint256(uint160(USDT))) {
                assertGe(o.takingAmount * 100, o.makingAmount * 99, "lowest price");
            } else {
                assertGe(o.takingAmount * 1e6, o.makingAmount * 0.0002 ether, "lowest price");
            }
            assertEq(o.makerTraits >> 255, 1, "filled whole");
            assertEq((o.makerTraits >> 160) & ((1 << 95) - 1), 0, "plain");
            uint256 expiration = (o.makerTraits >> 80) & type(uint40).max;
            assertGt(expiration, 0, "expires");
            assertGt(o.makingAmount, 0);
            assertEq(sellToken, USDC);
            assertEq(mostSold, o.makingAmount);
            assertEq(validTo, expiration);
            assertEq(uint256(notBefore) + LIFE >= expiration, true);
            assertLe(notBefore, expiration);
            assertEq(digest, router.hashOrder(o), "the router's hash of the same words");
        } catch {}
    }
}
