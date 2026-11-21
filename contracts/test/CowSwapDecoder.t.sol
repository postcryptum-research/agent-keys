// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";

/// The settlement as far as the decoder asks it: the three views.
contract SettlementStandIn {
    bytes32 public immutable domainSeparator;
    address public constant vaultRelayer = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;
    mapping(bytes => uint256) public filledAmount;

    constructor(bytes32 separator) {
        domainSeparator = separator;
    }

    function fill(bytes calldata uid, uint256 amount) external {
        filledAmount[uid] = amount;
    }
}

/// The CoW Swap decoder (issue #80) on its own, without the policy: what it
/// lets through, what it refuses, and that its hash is CoW's.
contract CowSwapDecoderTest is Test {
    address constant SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    bytes32 constant APP_DATA = keccak256("the owner's appData");
    uint32 constant LIFE = 30 minutes;

    address account = makeAddr("account");
    SettlementStandIn settlement;
    CowSwapDecoder decoder;

    function setUp() public {
        // the stand-in sits at the settlement's address, with mainnet's separator
        bytes32 separator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Gnosis Protocol"),
                keccak256("v2"),
                uint256(1),
                SETTLEMENT
            )
        );
        deployCodeTo("CowSwapDecoder.t.sol:SettlementStandIn", abi.encode(separator), SETTLEMENT);
        settlement = SettlementStandIn(SETTLEMENT);
        decoder = new CowSwapDecoder(SETTLEMENT);
    }

    function _config() internal pure returns (CowSwapDecoder.Config memory c) {
        c.appData = APP_DATA;
        c.maxLife = LIFE;
        c.pairs = new CowSwapDecoder.Pair[](2);
        // at least 0.0002 WETH for each USDC (5,000 USDC for one WETH at most)
        c.pairs[0] = CowSwapDecoder.Pair(USDC, WETH, 0.0002 ether, 1e6);
        // at least 0.99 USDT for each USDC
        c.pairs[1] = CowSwapDecoder.Pair(USDC, USDT, 99, 100);
    }

    function _order() internal view returns (CowSwapDecoder.Order memory o) {
        o = CowSwapDecoder.Order({
            sellToken: USDC,
            buyToken: WETH,
            receiver: address(0),
            sellAmount: 200e6,
            buyAmount: 0.05 ether,
            validTo: 1_800_000_000,
            appData: APP_DATA,
            feeAmount: 1e6,
            kind: decoder.KIND_SELL(),
            partiallyFillable: false,
            sellTokenBalance: decoder.BALANCE_ERC20(),
            buyTokenBalance: decoder.BALANCE_ERC20()
        });
    }

    function _judge(CowSwapDecoder.Order memory o) internal view returns (address, uint256, uint48, uint48, bytes32) {
        return decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function _refused(CowSwapDecoder.Order memory o, bytes memory why) internal {
        vm.expectRevert(why);
        decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    function test_constructor_takesTheSettlementsFacts() public view {
        assertEq(decoder.settlement(), SETTLEMENT);
        assertEq(decoder.spender(), settlement.vaultRelayer());
        assertEq(decoder.domainSeparator(), settlement.domainSeparator());
        // CoW's constants, as GPv2Order.sol has them
        assertEq(decoder.ORDER_TYPE_HASH(), 0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489);
        assertEq(decoder.KIND_SELL(), 0xf3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775);
        assertEq(decoder.BALANCE_ERC20(), 0x5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9);
    }

    function test_judge_anAllowedOrder() public view {
        (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo,) = _judge(_order());
        assertEq(sellToken, USDC);
        assertEq(mostSold, 201e6, "the fee is part of what the order can take");
        assertEq(validTo, 1_800_000_000);
        assertEq(notBefore, 1_800_000_000 - LIFE, "registered no earlier than its lifetime before its end");
    }

    function test_judge_receiverIsTheAccountOrNobody() public {
        CowSwapDecoder.Order memory o = _order();
        o.receiver = account;
        _judge(o);
        o.receiver = makeAddr("the agent's own address");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.ProceedsLeaveTheAccount.selector, o.receiver));
    }

    function test_judge_onlyListedPairsOneWay() public {
        CowSwapDecoder.Order memory o = _order();
        o.buyToken = makeAddr("a token of the attacker's");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.PairNotListed.selector, USDC, o.buyToken));
        // the listed pair the other way round
        o.sellToken = WETH;
        o.buyToken = USDC;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.PairNotListed.selector, WETH, USDC));
        o.sellToken = USDC;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.PairNotListed.selector, USDC, USDC));
    }

    function test_judge_theLowestPrice() public {
        CowSwapDecoder.Order memory o = _order();
        o.buyToken = USDT;
        o.sellAmount = 200e6;
        o.buyAmount = 198e6; // exactly 0.99
        _judge(o);
        o.buyAmount = 198e6 - 1;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.BelowTheLowestPrice.selector));
        // selling for nothing is refused on every pair
        o.buyToken = WETH;
        o.buyAmount = 0;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.BelowTheLowestPrice.selector));
    }

    /// A config whose pair has no price never reached an owner's screen
    /// (`checkConfig` refuses it); if one is installed all the same, its
    /// pair is not a pair.
    function test_judge_aPairWithoutAPriceIsNotAPair() public {
        bytes memory order = abi.encode(_order());
        CowSwapDecoder.Config memory c = _config();
        c.pairs[0] = CowSwapDecoder.Pair(USDC, WETH, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.PairNotListed.selector, USDC, WETH));
        decoder.judge(account, abi.encode(c), order);
        c.pairs[0] = CowSwapDecoder.Pair(USDC, WETH, 1, 0);
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.PairNotListed.selector, USDC, WETH));
        decoder.judge(account, abi.encode(c), order);
    }

    function test_judge_theLowestPriceDoesNotOverflow() public {
        CowSwapDecoder.Config memory c = _config();
        c.pairs[1] = CowSwapDecoder.Pair(USDC, USDT, type(uint256).max, 1);
        CowSwapDecoder.Order memory o = _order();
        o.buyToken = USDT;
        o.sellAmount = 2;
        o.buyAmount = type(uint256).max; // max * 1 < 2 * max: refused, not wrapped into acceptance
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.BelowTheLowestPrice.selector));
        decoder.judge(account, abi.encode(c), abi.encode(o));
        o.sellAmount = 1;
        decoder.judge(account, abi.encode(c), abi.encode(o));
    }

    function test_judge_refusesEveryOtherShape() public {
        CowSwapDecoder.Order memory o = _order();
        o.kind = keccak256("buy");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.NotASellOrder.selector));

        o = _order();
        o.partiallyFillable = true;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.PartiallyFillable.selector));

        o = _order();
        o.sellTokenBalance = keccak256("external");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.NotPlainErc20.selector));
        o.sellTokenBalance = keccak256("internal");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.NotPlainErc20.selector));

        o = _order();
        o.buyTokenBalance = keccak256("internal");
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.NotPlainErc20.selector));

        o = _order();
        o.appData = bytes32(0);
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.OtherAppData.selector, bytes32(0)));

        o = _order();
        o.sellAmount = 0;
        _refused(o, abi.encodeWithSelector(CowSwapDecoder.NothingToSell.selector));

        // a fee that overflows the sum is a refusal (a panic), not a small charge
        o = _order();
        o.feeAmount = type(uint256).max;
        vm.expectRevert();
        decoder.judge(account, abi.encode(_config()), abi.encode(o));
    }

    /// Exactly twelve words, each in its canonical form: nothing rides along
    /// outside the hash, and no word reads as one thing here and another there.
    function test_judge_refusesAnythingButTheTwelveCanonicalWords() public {
        bytes memory order = abi.encode(_order());
        bytes memory config = abi.encode(_config());
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.NotAnOrder.selector));
        decoder.judge(account, config, bytes.concat(order, bytes32(0)));
        bytes memory short = new bytes(order.length - 32);
        for (uint256 i; i < short.length; i++) {
            short[i] = order[i];
        }
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.NotAnOrder.selector));
        decoder.judge(account, config, short);

        // dirty upper bits in an address (word 2, the receiver), in validTo (word 5), in the flag (word 9)
        uint256[3] memory words = [uint256(2), 5, 9];
        for (uint256 i; i < 3; i++) {
            bytes memory dirty = abi.encode(_order());
            dirty[words[i] * 32] = 0x01;
            vm.expectRevert();
            decoder.judge(account, config, dirty);
        }
    }

    /// The digest against a second implementation of EIP-712 (forge's).
    function test_digest_agreesWithAnIndependentEip712() public view {
        CowSwapDecoder.Order memory o = _order();
        (,,,, bytes32 digest) = _judge(o);
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"Order":[{"name":"sellToken","type":"address"},{"name":"buyToken","type":"address"},{"name":"receiver","type":"address"},{"name":"sellAmount","type":"uint256"},{"name":"buyAmount","type":"uint256"},{"name":"validTo","type":"uint32"},{"name":"appData","type":"bytes32"},{"name":"feeAmount","type":"uint256"},{"name":"kind","type":"string"},{"name":"partiallyFillable","type":"bool"},{"name":"sellTokenBalance","type":"string"},{"name":"buyTokenBalance","type":"string"}]},',
            '"primaryType":"Order","domain":{"name":"Gnosis Protocol","version":"v2","chainId":1,"verifyingContract":"',
            vm.toString(SETTLEMENT),
            '"},"message":{"sellToken":"',
            vm.toString(o.sellToken),
            '","buyToken":"',
            vm.toString(o.buyToken),
            '","receiver":"',
            vm.toString(o.receiver)
        );
        json = string.concat(
            json,
            '","sellAmount":"',
            vm.toString(o.sellAmount),
            '","buyAmount":"',
            vm.toString(o.buyAmount),
            '","validTo":',
            vm.toString(uint256(o.validTo)),
            ',"appData":"',
            vm.toString(o.appData),
            '","feeAmount":"',
            vm.toString(o.feeAmount),
            '","kind":"sell","partiallyFillable":false,"sellTokenBalance":"erc20","buyTokenBalance":"erc20"}}'
        );
        assertEq(digest, vm.eip712HashTypedData(json));
    }

    /// The digest against CoW's own: two orders from the public mainnet order
    /// book (2026-11-21). An order's uid begins with its digest.
    function test_digest_isTheOneCowsOrderBookGave() public view {
        CowSwapDecoder.Order memory o = _order();
        o.feeAmount = 0;

        o.sellToken = USDT;
        o.buyToken = USDC;
        o.receiver = 0x7249c6f7434dd3D884a2E1eb19b57076D5aF6F67;
        o.sellAmount = 2003001089;
        o.buyAmount = 2000000162;
        o.validTo = 1795270894;
        o.appData = 0xea94654d34c8a0375182d70519fe34d842dc87ead5a86790fe226e33d73c52a7;
        assertEq(_digestOf(o, o.receiver), 0xb33cd7a1966e9c426e6eea98fc16c5f50ecdff3f8f704cd9d65ee265056570c9);

        o.sellToken = USDC;
        o.buyToken = USDT;
        o.receiver = address(0);
        o.sellAmount = 100000000;
        o.buyAmount = 100215097;
        o.validTo = 1795270546;
        o.appData = bytes32(0);
        assertEq(
            _digestOf(o, 0xd35D7fB17Ee3061eE6EF5F6856A3CEf70d5a1Cf1),
            0xef9a1f96802a5a751d7a34427a773d18e7089c42b20346e5d1817ccc4249bcbc
        );
    }

    /// The digest of any order, through a config made to allow it.
    function _digestOf(CowSwapDecoder.Order memory o, address owner) internal view returns (bytes32 digest) {
        CowSwapDecoder.Config memory c;
        c.appData = o.appData;
        c.maxLife = LIFE;
        c.pairs = new CowSwapDecoder.Pair[](1);
        c.pairs[0] = CowSwapDecoder.Pair(o.sellToken, o.buyToken, 1, type(uint256).max);
        (,,,, digest) = decoder.judge(owner, abi.encode(c), abi.encode(o));
    }

    function test_untouched_readsTheSettlementsFilledAmount() public {
        CowSwapDecoder.Order memory o = _order();
        bytes memory order = abi.encode(o);
        (,,,, bytes32 digest) = _judge(o);
        assertTrue(decoder.untouched(account, order));
        // the uid is the digest, the owner and validTo: 56 bytes
        bytes memory uid = abi.encodePacked(digest, account, o.validTo);
        assertEq(uid.length, 56);
        settlement.fill(uid, 1);
        assertFalse(decoder.untouched(account, order), "a fill");
        settlement.fill(uid, type(uint256).max);
        assertFalse(decoder.untouched(account, order), "a cancellation by the owner looks like a fill");
        // another account's order with the same fields is another uid
        assertTrue(decoder.untouched(makeAddr("another account"), order));
    }

    function test_checkConfig() public {
        assertTrue(decoder.checkConfig(abi.encode(_config())));

        CowSwapDecoder.Config memory c = _config();
        c.pairs = new CowSwapDecoder.Pair[](0);
        _badConfig(c);

        c = _config();
        c.maxLife = 0;
        _badConfig(c);

        c = _config();
        c.pairs[1] = c.pairs[0]; // a pair twice
        _badConfig(c);

        c = _config();
        c.pairs[0].buyToken = USDC; // a token against itself
        _badConfig(c);

        c = _config();
        c.pairs[1].perSell = 0; // half a price
        _badConfig(c);

        c = _config();
        c.pairs[0].minBuy = 0; // no price
        c.pairs[0].perSell = 0;
        _badConfig(c);

        c = _config();
        c.pairs[0].sellToken = address(0);
        _badConfig(c);
    }

    function _badConfig(CowSwapDecoder.Config memory c) internal {
        vm.expectRevert(abi.encodeWithSelector(CowSwapDecoder.InvalidConfig.selector));
        decoder.checkConfig(abi.encode(c));
    }

    /// For any order: accepted means every rule holds; the sum and the
    /// window are as stated. (C7: every field is accounted for.)
    function testFuzz_judge_acceptedMeansEveryRuleHolds(CowSwapDecoder.Order memory o, uint256 flips) public view {
        CowSwapDecoder.Order memory good = _order();
        // one field at most is the fuzzer's; the rest are an acceptable order's
        uint256 broken = flips % 12;
        if (broken != 1) o.sellToken = good.sellToken;
        if (broken != 2) o.buyToken = flips & 256 == 0 ? WETH : USDT;
        if (broken != 3) o.receiver = flips & 512 == 0 ? address(0) : account;
        if (broken != 4) o.appData = good.appData;
        if (broken != 5) o.kind = good.kind;
        if (broken != 6) o.partiallyFillable = false;
        if (broken != 7) o.sellTokenBalance = good.sellTokenBalance;
        if (broken != 8) o.buyTokenBalance = good.buyTokenBalance;
        o.sellAmount = bound(o.sellAmount, 0, 1e30);
        o.buyAmount = bound(o.buyAmount, 0, 1e30);
        o.feeAmount = bound(o.feeAmount, 0, 1e30);

        try decoder.judge(account, abi.encode(_config()), abi.encode(o)) returns (
            address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32
        ) {
            assertTrue(o.receiver == address(0) || o.receiver == account, "receiver");
            assertEq(o.sellToken, USDC, "sell token");
            assertTrue(o.buyToken == WETH || o.buyToken == USDT, "buy token");
            if (o.buyToken == USDT) assertGe(o.buyAmount * 100, o.sellAmount * 99, "lowest price");
            if (o.buyToken == WETH) assertGe(o.buyAmount * 1e6, o.sellAmount * 0.0002 ether, "lowest price");
            assertEq(o.kind, good.kind);
            assertFalse(o.partiallyFillable);
            assertEq(o.sellTokenBalance, good.sellTokenBalance);
            assertEq(o.buyTokenBalance, good.buyTokenBalance);
            assertEq(o.appData, APP_DATA);
            assertGt(o.sellAmount, 0);
            assertEq(sellToken, o.sellToken);
            assertEq(mostSold, o.sellAmount + o.feeAmount);
            assertEq(validTo, o.validTo);
            assertEq(uint256(notBefore) + LIFE >= o.validTo, true);
            assertLe(notBefore, o.validTo);
        } catch {}
    }
}
