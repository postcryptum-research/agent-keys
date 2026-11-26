// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TradingTest} from "./Trading.t.sol";
import {MockToken, Counter} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {SwapRouter02Decoder, ISwapRouter02} from "../src/venues/SwapRouter02Decoder.sol";
import {VenuePairs} from "../src/venues/VenuePairs.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, CallType, PermissionId} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// What these tests need of a token that is not a mock.
interface IERC20ForSwaps {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// A router that swaps at a set price, with the three habits of SwapRouter02
/// the decoder's rules are about: it takes the sold token from its caller,
/// an amount of zero means its own balance, and the recipients `address(1)`
/// and `address(2)` mean its caller and itself. `SwapRouter02ForkTest` runs
/// against the router's own code.
contract SwapRouterStandIn {
    /// 0.3 ether for 1,000 dollars of six decimals: 3e8 wei for a dollar's smallest unit.
    uint256 public num = 3e8;
    uint256 public den = 1;
    uint256 public swaps;

    /// `out = amountIn * n / d`, in the tokens' smallest units.
    function setPrice(uint256 n, uint256 d) external {
        (num, den) = (n, d);
    }

    function exactInputSingle(ISwapRouter02.ExactInputSingleParams calldata p) external payable returns (uint256 out) {
        swaps++;
        address recipient =
            p.recipient == address(1) ? msg.sender : p.recipient == address(2) ? address(this) : p.recipient;
        uint256 amountIn = p.amountIn;
        if (amountIn == 0) {
            amountIn = MockToken(p.tokenIn).balanceOf(address(this));
        } else {
            MockToken(p.tokenIn).transferFrom(msg.sender, address(this), amountIn);
        }
        out = amountIn * num / den;
        MockToken(p.tokenOut).transfer(recipient, out);
        require(out >= p.amountOutMinimum, "Too little received");
    }

    /// Another function of the router: what it holds of a token, to anyone.
    function sweepToken(address token, uint256, address recipient) external payable {
        MockToken(token).transfer(recipient, MockToken(token).balanceOf(address(this)));
    }
}

/// The decoder alone: what it answers, and what it refuses.
contract SwapRouter02DecoderTest is Test {
    MockToken internal usd;
    MockToken internal weth;
    SwapRouterStandIn internal router;
    SwapRouter02Decoder internal decoder;
    address internal constant ACCOUNT = address(0xACC0);

    function setUp() public {
        usd = new MockToken();
        weth = new MockToken();
        router = new SwapRouterStandIn();
        decoder = new SwapRouter02Decoder(address(router));
    }

    /// One pair: dollars for wrapped ether, at no less than 0.25 ether per 1,000 dollars.
    function _config() internal view returns (bytes memory) {
        SwapRouter02Decoder.Config memory c;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.25 ether, 1_000e6);
        return abi.encode(c);
    }

    function _swap(uint256 sell, uint256 buy) internal view returns (SwapRouter02Decoder.Swap memory) {
        return SwapRouter02Decoder.Swap(address(usd), address(weth), 3000, sell, buy);
    }

    function _judge(SwapRouter02Decoder.Swap memory s) internal view returns (bytes32 digest) {
        (,,,, digest) = decoder.judge(ACCOUNT, _config(), abi.encode(s));
    }

    /// The call the decoder allows, written out here from the router's ABI:
    /// the selector, and seven words.
    function test_decoder_theCallItAllows() public view {
        SwapRouter02Decoder.Swap memory s = _swap(100e6, 0.025 ether);
        (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest) =
            decoder.judge(ACCOUNT, _config(), abi.encode(s));
        assertEq(sellToken, address(usd));
        assertEq(mostSold, 100e6, "the amount sold is what is charged");
        assertEq(notBefore, 0);
        assertEq(validTo, 0, "no end: a call, not an order");
        bytes memory expected = abi.encodeWithSelector(
            bytes4(0x04e45aaf),
            address(usd),
            address(weth),
            uint256(3000),
            ACCOUNT,
            uint256(100e6),
            uint256(0.025 ether),
            uint256(0)
        );
        assertEq(expected.length, 0xe4);
        assertEq(decoder.swapCall(ACCOUNT, abi.encode(s)), expected, "the call");
        // the call's hash: no value, and that calldata
        assertEq(digest, keccak256(abi.encode(uint256(0), keccak256(expected))), "the hash");
        assertEq(ISwapRouter02.exactInputSingle.selector, bytes4(0x04e45aaf));
    }

    /// One swap, with the bytes written out: the CLI and the phone's core
    /// build the same from their own code and are held to these bytes
    /// (`mobile/owner-core/src/kernel.rs`, `a_swap_is_the_decoders`).
    function test_decoder_theRecordedSwap() public view {
        address account = 0x1111111111111111111111111111111111111111;
        address sell = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        address buy = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        bytes memory order = abi.encode(SwapRouter02Decoder.Swap(sell, buy, 500, 1_000e6, 0.25 ether));
        SwapRouter02Decoder.Config memory c;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(sell, buy, 0.25 ether, 1_000e6);
        assertEq(
            abi.encode(c),
            hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000003782dace9d90000000000000000000000000000000000000000000000000000000000003b9aca00",
            "the config"
        );
        assertEq(
            order,
            hex"000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000003782dace9d90000",
            "the swap"
        );
        assertEq(
            decoder.swapCall(account, order),
            hex"04e45aaf000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f40000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000003782dace9d900000000000000000000000000000000000000000000000000000000000000000000",
            "the call"
        );
        (,,,, bytes32 digest) = decoder.judge(account, abi.encode(c), order);
        assertEq(digest, 0xb870325779145b133ddd23f0edfe40ef291a53b1b456ddae332f89a8489be208, "the call's hash");
    }

    /// The recipient is the account the swap is judged for, whoever that is.
    function test_decoder_theRecipientIsTheAccount() public view {
        bytes memory order = abi.encode(_swap(100e6, 0.025 ether));
        address other = address(0xBEEF);
        bytes memory forAccount = decoder.swapCall(ACCOUNT, order);
        bytes memory forOther = decoder.swapCall(other, order);
        // the fourth word of the struct, after the selector
        assertEq(abi.decode(_slice(forAccount, 0x64), (address)), ACCOUNT);
        assertEq(abi.decode(_slice(forOther, 0x64), (address)), other);
        (,,,, bytes32 a) = decoder.judge(ACCOUNT, _config(), order);
        (,,,, bytes32 b) = decoder.judge(other, _config(), order);
        assertTrue(a != b, "another account, another call");
        // the price limit, the last word: none
        assertEq(abi.decode(_slice(forAccount, 0xc4), (uint256)), 0);
        // the fee tier, the third word, is the swap's own: it names the pool
        assertEq(abi.decode(_slice(forAccount, 0x44), (uint256)), 3000);
        bytes memory inAnotherPool =
            abi.encode(SwapRouter02Decoder.Swap(address(usd), address(weth), 500, 100e6, 0.025 ether));
        assertEq(abi.decode(_slice(decoder.swapCall(ACCOUNT, inAnotherPool), 0x44), (uint256)), 500);
    }

    function _slice(bytes memory data, uint256 at) internal pure returns (bytes memory word) {
        word = new bytes(32);
        for (uint256 i; i < 32; i++) {
            word[i] = data[at + i];
        }
    }

    /// The lowest price is held exactly: at it, and one unit under it.
    function test_decoder_theLowestPrice() public {
        // 1,000 dollars for 0.25 ether is the price itself
        _judge(_swap(1_000e6, 0.25 ether));
        // one wei less of ether is under it
        vm.expectRevert(VenuePairs.BelowTheLowestPrice.selector);
        this.judgeExternal(_swap(1_000e6, 0.25 ether - 1));
        // one dollar unit more sold for the same is under it too
        vm.expectRevert(VenuePairs.BelowTheLowestPrice.selector);
        this.judgeExternal(_swap(1_000e6 + 1, 0.25 ether));
        // the least bought may be anything above
        _judge(_swap(1, type(uint256).max));
    }

    function judgeExternal(SwapRouter02Decoder.Swap memory s) external view returns (bytes32) {
        return _judge(s);
    }

    function test_decoder_refusals() public {
        // nothing sold: to the router that is its own balance
        vm.expectRevert(SwapRouter02Decoder.NothingToSell.selector);
        this.judgeExternal(_swap(0, 1 ether));
        // the pair the other way
        SwapRouter02Decoder.Swap memory back = SwapRouter02Decoder.Swap(address(weth), address(usd), 3000, 1 ether, 1);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(weth), address(usd)));
        this.judgeExternal(back);
        // a token that is not in the list, on either side
        MockToken other = new MockToken();
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(other), address(weth)));
        this.judgeExternal(SwapRouter02Decoder.Swap(address(other), address(weth), 3000, 100e6, 1 ether));
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(usd), address(other)));
        this.judgeExternal(SwapRouter02Decoder.Swap(address(usd), address(other), 3000, 100e6, 1 ether));
        // a token for itself
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(usd), address(usd)));
        this.judgeExternal(SwapRouter02Decoder.Swap(address(usd), address(usd), 3000, 100e6, 1 ether));
    }

    /// Exactly five words, each as wide as its type: nothing rides along.
    function test_decoder_aSwapIsFiveCleanWords() public {
        bytes memory order = abi.encode(_swap(100e6, 0.025 ether));
        decoder.judge(ACCOUNT, _config(), order);
        // a word more, a word less
        vm.expectRevert(SwapRouter02Decoder.NotASwap.selector);
        decoder.judge(ACCOUNT, _config(), bytes.concat(order, bytes32(0)));
        vm.expectRevert(SwapRouter02Decoder.NotASwap.selector);
        decoder.judge(ACCOUNT, _config(), abi.encode(address(usd), address(weth), uint24(3000), uint256(100e6)));
        vm.expectRevert(SwapRouter02Decoder.NotASwap.selector);
        decoder.judge(ACCOUNT, _config(), "");
        // a bit above the sold token's address
        bytes memory dirty =
            abi.encode(uint256(uint160(address(usd))) | (1 << 160), address(weth), 3000, 100e6, 1 ether);
        vm.expectRevert();
        decoder.judge(ACCOUNT, _config(), dirty);
        // above the bought token's
        dirty = abi.encode(address(usd), uint256(uint160(address(weth))) | (1 << 255), 3000, 100e6, 1 ether);
        vm.expectRevert();
        decoder.judge(ACCOUNT, _config(), dirty);
        // a fee tier wider than its 24 bits
        dirty = abi.encode(address(usd), address(weth), uint256(1 << 24), 100e6, 1 ether);
        vm.expectRevert();
        decoder.judge(ACCOUNT, _config(), dirty);
        // the widest fee tier there is passes: the pool it names is the router's matter
        decoder.judge(
            ACCOUNT, _config(), abi.encode(address(usd), address(weth), uint256(type(uint24).max), 100e6, 1 ether)
        );
    }

    /// A config that does not hold as a list allows nothing, whether or not `checkConfig` was asked.
    function test_decoder_aBrokenConfigAllowsNothing() public {
        bytes memory order = abi.encode(_swap(100e6, 0.025 ether));
        SwapRouter02Decoder.Config memory c;
        // the pair twice
        c.pairs = new VenuePairs.Pair[](2);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.25 ether, 1_000e6);
        c.pairs[1] = VenuePairs.Pair(address(usd), address(weth), 1, 1_000e6);
        vm.expectRevert(VenuePairs.PairListedTwice.selector);
        decoder.judge(ACCOUNT, abi.encode(c), order);
        // without a price
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0, 1_000e6);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(usd), address(weth)));
        decoder.judge(ACCOUNT, abi.encode(c), order);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.25 ether, 0);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(usd), address(weth)));
        decoder.judge(ACCOUNT, abi.encode(c), order);
        // seventeen pairs
        c.pairs = new VenuePairs.Pair[](17);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.25 ether, 1_000e6);
        for (uint256 i = 1; i < 17; i++) {
            c.pairs[i] = VenuePairs.Pair(address(uint160(0x1000 + i)), address(weth), 1, 1);
        }
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.judge(ACCOUNT, abi.encode(c), order);
        // no pairs
        c.pairs = new VenuePairs.Pair[](0);
        vm.expectRevert(abi.encodeWithSelector(VenuePairs.PairNotListed.selector, address(usd), address(weth)));
        decoder.judge(ACCOUNT, abi.encode(c), order);
    }

    function test_decoder_checkConfig() public {
        assertTrue(decoder.checkConfig(_config()));
        SwapRouter02Decoder.Config memory c;
        // no pairs
        c.pairs = new VenuePairs.Pair[](0);
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(c));
        // a token without code, on either side
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(0xDEAD), address(weth), 1, 1);
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(c));
        c.pairs[0] = VenuePairs.Pair(address(usd), address(0xDEAD), 1, 1);
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(c));
        // without a price
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0, 1);
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(c));
        // the pair twice
        c.pairs = new VenuePairs.Pair[](2);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 1, 1);
        c.pairs[1] = VenuePairs.Pair(address(usd), address(weth), 2, 1);
        vm.expectRevert(VenuePairs.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(c));
        // both ways is two pairs
        c.pairs[1] = VenuePairs.Pair(address(weth), address(usd), 2, 1);
        assertTrue(decoder.checkConfig(abi.encode(c)));
    }

    /// Deployed through a call of its own, so that the revert is the constructor's.
    function build(address at) external returns (SwapRouter02Decoder) {
        return new SwapRouter02Decoder(at);
    }

    function test_decoder_theRouterHasCode() public {
        vm.expectRevert(SwapRouter02Decoder.NotARouter.selector);
        this.build(address(0xDEAD));
        vm.expectRevert(SwapRouter02Decoder.NotARouter.selector);
        this.build(address(0));
        assertEq(this.build(address(usd)).venue(), address(usd));
    }

    function test_decoder_whatItIs() public view {
        assertEq(decoder.venue(), address(router));
        assertEq(decoder.spender(), address(router));
        assertEq(decoder.VERSION(), "0.1.0");
        assertEq(decoder.MAX_PAIRS(), 16);
        // nothing of a swap is left to be filled later
        assertFalse(decoder.untouched(ACCOUNT, abi.encode(_swap(100e6, 0.025 ether))));
    }
}

/// A swap under a mandate (issue #80): the agent registers the swap, the
/// policy asks `SwapRouter02Decoder`, and the leg after the registration is
/// the router call the decoder built, and no other. The mandate has two
/// venues, CoW Swap and the router, on one budget. The owner approved the
/// router for the sold token, as for CoW's relayer.
contract SwapRouter02TradingTest is TradingTest {
    SwapRouterStandIn internal router;
    SwapRouter02Decoder internal swaps;

    function _withSwaps() internal {
        _world();
        router = new SwapRouterStandIn();
        weth.mint(address(router), 100 ether);
        swaps = new SwapRouter02Decoder(address(router));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](2);
        v[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        v[1] = AgentPolicy.Venue(address(swaps), address(swaps).codehash, keccak256(_swapConfig()));
        _install(TRD_ID, _params(DAY, v));
        // the owner's allowance to the router, bounded by the budget
        vm.prank(acct);
        usd.approve(address(router), USD_BUDGET);
    }

    /// Dollars for wrapped ether, at no less than 0.25 ether per 1,000 dollars;
    /// the stand-in's price is 0.3 ether per 1,000.
    function _swapConfig() internal view returns (bytes memory) {
        SwapRouter02Decoder.Config memory c;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.25 ether, 1_000e6);
        return abi.encode(c);
    }

    /// A swap of `sell` dollars at the lowest price the owner allows.
    function _swap(uint256 sell) internal view returns (SwapRouter02Decoder.Swap memory) {
        return SwapRouter02Decoder.Swap(address(usd), address(weth), 3000, sell, sell * 0.00025 ether / 1e6);
    }

    function _reg(SwapRouter02Decoder.Swap memory s) internal view returns (Execution memory) {
        return Execution(
            address(policy),
            0,
            abi.encodeCall(AgentPolicy.orderRegister, (address(swaps), _swapConfig(), abi.encode(s)))
        );
    }

    function _call(SwapRouter02Decoder.Swap memory s) internal view returns (Execution memory) {
        return Execution(address(router), 0, swaps.swapCall(acct, abi.encode(s)));
    }

    function _legs(SwapRouter02Decoder.Swap memory s) internal view returns (Execution[] memory legs) {
        legs = new Execution[](2);
        (legs[0], legs[1]) = (_reg(s), _call(s));
    }

    function _two(Execution memory a, Execution memory b) internal pure returns (Execution[] memory legs) {
        legs = new Execution[](2);
        (legs[0], legs[1]) = (a, b);
    }

    /// An agent operation of several legs under the trading mandate, in today's period.
    function _batch(Execution[] memory legs) internal view returns (PackedUserOperation memory op) {
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(legs)
        );
        op = _op(_permissionNonce(TRD_ID), callData);
        op.signature = abi.encodePacked(
            bytes1(0), bytes8(uint64(6)), bytes6(_today()), bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op))
        );
    }

    function test_swap_registeredAndMade() public {
        _withSwaps();
        uint256 usdBefore = usd.balanceOf(acct);
        _send(_batch(_legs(_swap(100e6))));
        // sold, bought at the router's price, and to the account
        assertEq(usd.balanceOf(acct), usdBefore - 100e6);
        assertEq(weth.balanceOf(acct), 0.03 ether);
        assertEq(router.swaps(), 1);
        // charged like an order, and out of the owner's allowance
        assertEq(_usdSpent(), 100e6);
        assertEq(usd.allowance(acct, address(router)), USD_BUDGET - 100e6);
        // the same swap again: a call registers as often as it is made
        _send(_batch(_legs(_swap(100e6))));
        assertEq(_usdSpent(), 200e6);
        assertEq(weth.balanceOf(acct), 0.06 ether);
    }

    /// The router is reached by the call the decoder built and by nothing else.
    function test_swap_theRouterTakesNoOtherCall() public {
        _withSwaps();
        SwapRouter02Decoder.Swap memory s = _swap(100e6);
        Execution memory reg = _reg(s);
        Execution memory call = _call(s);
        // the call alone, without its registration
        _expectRefused(_tradeOp(_today(), call.target, 0, call.callData));
        // the bought token to somebody else
        address thief = makeAddr("thief");
        bytes memory toThief = abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(
                    address(usd), address(weth), 3000, thief, 100e6, s.amountOutMinimum, 0
                ))
        );
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, toThief))));
        // to the router itself, where anyone's sweep would take it
        bytes memory toRouter = abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(
                    address(usd), address(weth), 3000, address(2), 100e6, s.amountOutMinimum, 0
                ))
        );
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, toRouter))));
        // for less than the swap that was judged
        bytes memory forLess = abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(address(usd), address(weth), 3000, acct, 100e6, 0, 0))
        );
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, forLess))));
        // more sold than was judged and charged
        bytes memory more = abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(
                    address(usd), address(weth), 3000, acct, 101e6, s.amountOutMinimum, 0
                ))
        );
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, more))));
        // with a price limit
        bytes memory limited = abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(
                    address(usd), address(weth), 3000, acct, 100e6, s.amountOutMinimum, 1
                ))
        );
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, limited))));
        // with native value
        vm.deal(acct, 1 ether);
        _expectRefused(_batch(_two(reg, Execution(address(router), 1, call.callData))));
        // another function of the router
        bytes memory sweep = abi.encodeCall(SwapRouterStandIn.sweepToken, (address(weth), 0, thief));
        _expectRefused(_batch(_two(reg, Execution(address(router), 0, sweep))));
        // the call at another contract
        SwapRouterStandIn elsewhere = new SwapRouterStandIn();
        _expectRefused(_batch(_two(reg, Execution(address(elsewhere), 0, call.callData))));
        // nothing happened
        assertEq(router.swaps(), 0);
        assertEq(weth.balanceOf(thief), 0);
        assertEq(_usdSpent(), 0);
        // the control: the judged call passes
        _send(_batch(_two(reg, call)));
        assertEq(router.swaps(), 1);
    }

    function test_swap_whatTheDecoderRefusesIsNotRegistered() public {
        _withSwaps();
        // under the lowest price
        SwapRouter02Decoder.Swap memory cheap = _swap(100e6);
        cheap.amountOutMinimum -= 1;
        _expectRefused(_batch(_legs(cheap)));
        // the pair the other way
        weth.mint(acct, 1 ether);
        SwapRouter02Decoder.Swap memory back = SwapRouter02Decoder.Swap(address(weth), address(usd), 3000, 0.1 ether, 1);
        _expectRefused(_batch(_legs(back)));
        // the router's own balance
        SwapRouter02Decoder.Swap memory nothing = _swap(0);
        _expectRefused(_batch(_legs(nothing)));
        // under a config the owner did not pin: a lower price
        SwapRouter02Decoder.Config memory c;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 1, 1_000e6);
        Execution memory reg = Execution(
            address(policy),
            0,
            abi.encodeCall(AgentPolicy.orderRegister, (address(swaps), abi.encode(c), abi.encode(cheap)))
        );
        _expectRefused(_batch(_two(reg, _call(cheap))));
        assertEq(router.swaps(), 0);
        assertEq(_usdSpent(), 0);
    }

    /// The amount sold is held to the token's cap per operation and to its
    /// budget, which the two venues share.
    function test_swap_heldToTheCapAndTheBudget() public {
        _withSwaps();
        // over the cap per operation
        _expectRefused(_batch(_legs(_swap(USD_MAX + 1))));
        // two swaps in one operation: each with its registration, and their amounts add up
        Execution[] memory four = new Execution[](4);
        (four[0], four[1]) = (_reg(_swap(150e6)), _call(_swap(150e6)));
        (four[2], four[3]) = (_reg(_swap(51e6)), _call(_swap(51e6)));
        _expectRefused(_batch(four));
        (four[2], four[3]) = (_reg(_swap(50e6)), _call(_swap(50e6)));
        _send(_batch(four));
        assertEq(router.swaps(), 2);
        assertEq(_usdSpent(), 200e6);
        // a CoW order on the same budget
        _register(_order(200e6, _soon()));
        assertEq(_usdSpent(), 400e6);
        // the rest of the budget, and not a unit more
        _expectRefused(_batch(_legs(_swap(100e6 + 1))));
        _send(_batch(_legs(_swap(100e6))));
        assertEq(_usdSpent(), USD_BUDGET);
        _expectRefused(_batch(_legs(_swap(1e6))));
        // the next period gives the budget back
        vm.warp((uint256(_today()) + 1) * DAY + 1 hours);
        _send(_batch(_legs(_swap(1e6))));
    }

    /// A swap that reverts when the operation runs was charged when it was
    /// registered: the charge is of what was allowed.
    function test_swap_aSwapThatRevertsIsStillCharged() public {
        _withSwaps();
        // the market moved under the least bought: 0.2 ether per 1,000 dollars
        router.setPrice(2e8, 1);
        uint256 usdBefore = usd.balanceOf(acct);
        _send(_batch(_legs(_swap(100e6))));
        // nothing moved
        assertEq(usd.balanceOf(acct), usdBefore);
        assertEq(weth.balanceOf(acct), 0);
        assertEq(usd.allowance(acct, address(router)), USD_BUDGET);
        // and the budget is 100 dollars shorter until the period ends
        assertEq(_usdSpent(), 100e6);
    }

    /// The router is the venue's own contract and its spender: a mandate
    /// that names it as a target is refused, and so is one that names the decoder.
    function test_swap_theRouterIsNotATarget() public {
        _world();
        router = new SwapRouterStandIn();
        swaps = new SwapRouter02Decoder(address(router));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(address(swaps), address(swaps).codehash, keccak256(_swapConfig()));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        (targets[2], selectors[2]) = (address(router), ISwapRouter02.exactInputSingle.selector);
        _refusedInstall(_paramsFor(targets, selectors, DAY, v));
        (targets[2], selectors[2]) = (address(swaps), bytes4(0));
        _refusedInstall(_paramsFor(targets, selectors, DAY, v));
    }

    /// The decoder's code is pinned: other code at its address judges nothing.
    function test_swap_theDecodersCodeIsPinned() public {
        _withSwaps();
        vm.etch(address(swaps), address(new SwapRouter02Decoder(address(usd))).code);
        _expectRefused(_batch(_legs(_swap(100e6))));
    }
}

/// The same against Uniswap's SwapRouter02 as deployed on Base Sepolia, and a
/// pool with liquidity there: the call the decoder builds is the router's
/// own, and what the rules keep out is what the router does.
///
///     FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> \
///         forge test --evm-version osaka --match-contract SwapRouter02ForkTest
///
/// Skipped without the variable: CI has no RPC.
contract SwapRouter02ForkTest is TradingTest {
    address internal constant ROUTER = 0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4;
    IERC20ForSwaps internal constant WETH = IERC20ForSwaps(0x4200000000000000000000000000000000000006);
    IERC20ForSwaps internal constant USDC = IERC20ForSwaps(0x036CbD53842c5426634e7929541eC2318f3dCF7e);
    uint24 internal constant FEE = 3000;
    uint128 internal constant WETH_MAX = 0.01 ether;
    uint128 internal constant WETH_BUDGET = 0.03 ether;
    uint256 internal constant SELL = 0.001 ether;

    SwapRouter02Decoder internal swaps;
    /// What the pool pays for `SELL` now.
    uint256 internal quote;

    function _onBaseSepolia() internal returns (bool) {
        string memory rpc = vm.envOr("FORK_BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return false;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 84532, "not Base Sepolia");
        // the EntryPoint, the account and the policy of this build, on the fork
        setUp();
        _world();
        // wrapped ether for the account
        vm.deal(acct, 1 ether);
        vm.prank(acct);
        (bool wrapped,) = address(WETH).call{value: 0.1 ether}(abi.encodeWithSignature("deposit()"));
        require(wrapped, "WETH did not wrap");
        // what the pool pays now, asked of the router and undone
        uint256 snapshot = vm.snapshotState();
        vm.startPrank(acct);
        WETH.approve(ROUTER, SELL);
        uint256 paid = ISwapRouter02(ROUTER)
            .exactInputSingle(ISwapRouter02.ExactInputSingleParams(address(WETH), address(USDC), FEE, acct, SELL, 0, 0));
        vm.stopPrank();
        // undoing it undoes this contract's storage too: the answer is kept on the stack
        vm.revertToState(snapshot);
        quote = paid;
        assertGt(quote, 0, "the pool pays nothing");
        // the mandate: a cap on wrapped ether, and the router as a venue
        swaps = new SwapRouter02Decoder(ROUTER);
        assertTrue(swaps.checkConfig(_swapConfig()));
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(WETH), WETH_MAX, WETH_BUDGET, bytes32(0));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(address(swaps), address(swaps).codehash, keccak256(_swapConfig()));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        _install(
            TRD_ID,
            abi.encode(
                targets,
                selectors,
                MAX_VALUE,
                BUDGET,
                tradingExpiry,
                caps,
                uint48(0),
                new AgentPolicy.TokenPayees[](0),
                DAY,
                v
            )
        );
        // the owner's allowance to the router, bounded by the budget
        vm.prank(acct);
        WETH.approve(ROUTER, WETH_BUDGET);
        return true;
    }

    /// Wrapped ether for the test dollar, at no less than nine tenths of what the pool pays now.
    function _swapConfig() internal view returns (bytes memory) {
        SwapRouter02Decoder.Config memory c;
        c.pairs = new VenuePairs.Pair[](1);
        c.pairs[0] = VenuePairs.Pair(address(WETH), address(USDC), quote * 9 / 10, SELL);
        return abi.encode(c);
    }

    function _swap(uint256 sell) internal view returns (SwapRouter02Decoder.Swap memory) {
        return SwapRouter02Decoder.Swap(address(WETH), address(USDC), FEE, sell, quote * 9 / 10 * sell / SELL);
    }

    function _legs(SwapRouter02Decoder.Swap memory s, bytes memory routerCall)
        internal
        view
        returns (Execution[] memory legs)
    {
        legs = new Execution[](2);
        legs[0] = Execution(
            address(policy),
            0,
            abi.encodeCall(AgentPolicy.orderRegister, (address(swaps), _swapConfig(), abi.encode(s)))
        );
        legs[1] = Execution(ROUTER, 0, routerCall);
    }

    function _batch(Execution[] memory legs) internal view returns (PackedUserOperation memory op) {
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(legs)
        );
        op = _op(_permissionNonce(TRD_ID), callData);
        op.signature = abi.encodePacked(
            bytes1(0), bytes8(uint64(6)), bytes6(_today()), bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op))
        );
    }

    function _wethSpent() internal view returns (uint256) {
        return policy.tokenLimit(acct, TRD, address(WETH)).spent;
    }

    /// The agent swaps at the real router: the call the decoder builds is the router's own.
    function test_fork_theAgentSwaps() public {
        if (!_onBaseSepolia()) return;
        uint256 wethBefore = WETH.balanceOf(acct);
        uint256 usdcBefore = USDC.balanceOf(acct);
        SwapRouter02Decoder.Swap memory s = _swap(SELL);
        _send(_batch(_legs(s, swaps.swapCall(acct, abi.encode(s)))));
        // sold exactly, bought what the pool pays, to the account
        assertEq(WETH.balanceOf(acct), wethBefore - SELL, "sold");
        assertEq(USDC.balanceOf(acct), usdcBefore + quote, "bought");
        assertGe(quote, s.amountOutMinimum);
        // charged, and out of the owner's allowance
        assertEq(_wethSpent(), SELL);
        assertEq(WETH.allowance(acct, ROUTER), WETH_BUDGET - SELL);
    }

    /// What the rules keep out, at the real router.
    function test_fork_theRouterTakesNoOtherCall() public {
        if (!_onBaseSepolia()) return;
        SwapRouter02Decoder.Swap memory s = _swap(SELL);
        bytes memory call = swaps.swapCall(acct, abi.encode(s));
        address thief = makeAddr("thief");
        // the bought token to somebody else, and to the router itself
        _expectRefused(_batch(_legs(s, _routerCall(thief, SELL, s.amountOutMinimum))));
        _expectRefused(_batch(_legs(s, _routerCall(address(2), SELL, s.amountOutMinimum))));
        // for nothing
        _expectRefused(_batch(_legs(s, _routerCall(acct, SELL, 0))));
        // the same call inside the router's multicall
        bytes[] memory inner = new bytes[](1);
        inner[0] = call;
        _expectRefused(_batch(_legs(s, abi.encodeWithSignature("multicall(bytes[])", inner))));
        // the router's own balance
        SwapRouter02Decoder.Swap memory nothing = _swap(0);
        _expectRefused(_batch(_legs(nothing, swaps.swapCall(acct, abi.encode(nothing)))));
        // over the cap per operation
        SwapRouter02Decoder.Swap memory big = _swap(uint256(WETH_MAX) + 1);
        _expectRefused(_batch(_legs(big, swaps.swapCall(acct, abi.encode(big)))));
        // under the lowest price
        SwapRouter02Decoder.Swap memory cheap = _swap(SELL);
        cheap.amountOutMinimum -= 1;
        _expectRefused(_batch(_legs(cheap, swaps.swapCall(acct, abi.encode(cheap)))));
        assertEq(USDC.balanceOf(thief), 0);
        assertEq(_wethSpent(), 0);
        // the control
        _send(_batch(_legs(s, call)));
        assertEq(_wethSpent(), SELL);
    }

    function _routerCall(address recipient, uint256 sell, uint256 least) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(address(WETH), address(USDC), FEE, recipient, sell, least, 0))
        );
    }

    /// Why an amount of zero is refused: to the router it is the router's own
    /// balance, which whoever calls first swaps for themselves.
    function test_real_anAmountOfZeroIsTheRoutersBalance() public {
        if (!_onBaseSepolia()) return;
        // somebody's wrapped ether, left in the router
        vm.prank(acct);
        WETH.transfer(ROUTER, SELL);
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        uint256 out = ISwapRouter02(ROUTER)
            .exactInputSingle(
                ISwapRouter02.ExactInputSingleParams(address(WETH), address(USDC), FEE, stranger, 0, 0, 0)
            );
        assertEq(WETH.balanceOf(ROUTER), 0, "the router's balance was sold");
        assertEq(USDC.balanceOf(stranger), out);
        assertGt(out, 0);
    }

    /// Why the recipient is the account and nothing else: `address(2)` is the
    /// router to the router, and what the router holds anyone sweeps.
    function test_real_aRecipientOfTwoLeavesTheOutputToAnyone() public {
        if (!_onBaseSepolia()) return;
        vm.startPrank(acct);
        uint256 out = ISwapRouter02(ROUTER)
            .exactInputSingle(
                ISwapRouter02.ExactInputSingleParams(address(WETH), address(USDC), FEE, address(2), SELL, 0, 0)
            );
        vm.stopPrank();
        assertEq(USDC.balanceOf(ROUTER), out, "the output stayed in the router");
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        (bool swept,) = ROUTER.call(abi.encodeWithSignature("sweepToken(address,uint256)", address(USDC), 0));
        assertTrue(swept);
        assertEq(USDC.balanceOf(stranger), out, "and a stranger took it");
    }

    /// Why the allowance is safe to stand: the router takes the sold token
    /// from its caller only. A stranger's swap does not touch the account's.
    function test_real_theRouterTakesFromItsCallerOnly() public {
        if (!_onBaseSepolia()) return;
        address stranger = makeAddr("stranger");
        uint256 before = WETH.balanceOf(acct);
        vm.prank(stranger);
        vm.expectRevert();
        ISwapRouter02(ROUTER)
            .exactInputSingle(
                ISwapRouter02.ExactInputSingleParams(address(WETH), address(USDC), FEE, stranger, SELL, 0, 0)
            );
        assertEq(WETH.balanceOf(acct), before);
        assertEq(WETH.allowance(acct, ROUTER), WETH_BUDGET);
    }
}
