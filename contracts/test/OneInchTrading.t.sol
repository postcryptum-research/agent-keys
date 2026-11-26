// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TradingTest} from "./Trading.t.sol";
import {MockToken, Counter} from "./AgentPermission.t.sol";
import {RouterStandIn} from "./OneInchLimitOrderDecoder.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {OneInchLimitOrderDecoder} from "../src/venues/OneInchLimitOrderDecoder.sol";
import {VenuePairs} from "../src/venues/VenuePairs.sol";
import {PermissionId} from "kernel/src/types/Types.sol";

/// The router's functions these tests call, as the router has them.
interface IOneInchRouterForTests {
    function fillContractOrder(
        OneInchLimitOrderDecoder.Order calldata order,
        bytes calldata signature,
        uint256 amount,
        uint256 takerTraits
    ) external returns (uint256 makingAmount, uint256 takingAmount, bytes32 orderHash);
    function hashOrder(OneInchLimitOrderDecoder.Order calldata order) external view returns (bytes32);
    function cancelOrder(uint256 makerTraits, bytes32 orderHash) external;
}

/// A maker that vouches for anything, and counts the calls that reach it:
/// what an account without a policy would be to the router.
contract YesMaker {
    uint256 public calls;
    bool public silent;

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        return silent ? bytes4(0) : bytes4(0x1626ba7e);
    }

    function approve(MockToken token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }

    /// From now on it vouches for nothing.
    function fallSilent() external {
        silent = true;
    }

    /// The router's calls before and after a fill land here.
    fallback() external {
        calls++;
    }
}

/// 1inch limit orders under a mandate (issue #80): the agent registers a
/// plain order, the policy asks `OneInchLimitOrderDecoder`, and the account
/// vouches for exactly that order when the router fills it. The mandate has
/// two venues, CoW Swap and 1inch, on one budget.
/// The router is a stand-in here; `OneInchRealRouterTest` below runs every
/// test of this contract against the router's own code.
contract OneInchTradingTest is TradingTest {
    uint256 internal constant NO_PARTIAL_FILLS = 1 << 255;
    /// The taker's word for "the amount is the making amount".
    uint256 internal constant MAKING = 1 << 255;

    IOneInchRouterForTests internal router;
    OneInchLimitOrderDecoder internal oneInch;
    address internal taker = makeAddr("taker");

    /// The router these tests fill at.
    function _router() internal virtual returns (address) {
        return address(new RouterStandIn());
    }

    /// The trading world with a second venue: one mandate, CoW Swap and 1inch.
    function _both() internal {
        _world();
        router = IOneInchRouterForTests(_router());
        oneInch = new OneInchLimitOrderDecoder(address(router));
        _install(TRD_ID, _params(DAY, _twoVenues()));
        // the owner's allowance to the router, one budget of the token (the install gave CoW's)
        vm.prank(acct);
        usd.approve(address(router), USD_BUDGET);
        // the taker holds what it pays with
        weth.mint(taker, 100 ether);
        vm.prank(taker);
        weth.approve(address(router), type(uint256).max);
    }

    function _twoVenues() internal view returns (AgentPolicy.Venue[] memory v) {
        v = new AgentPolicy.Venue[](2);
        v[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        v[1] = AgentPolicy.Venue(address(oneInch), address(oneInch).codehash, keccak256(_oneInchConfig()));
    }

    function _oneInchConfig() internal view returns (bytes memory) {
        OneInchLimitOrderDecoder.Config memory c;
        c.maxLife = LIFE;
        c.pairs = new VenuePairs.Pair[](1);
        // at least 0.0002 WETH for each unit of the dollar token, as at CoW Swap
        c.pairs[0] = VenuePairs.Pair(address(usd), address(weth), 0.0002 ether, 1e6);
        return abi.encode(c);
    }

    function _traits(uint256 expiration, uint256 nonce) internal pure returns (uint256) {
        return NO_PARTIAL_FILLS | (expiration << 80) | (nonce << 120);
    }

    /// A plain order of the account: `sell` of the dollar token at 0.00025 WETH each.
    function _limit(uint256 sell, uint256 expiration, uint256 nonce)
        internal
        view
        returns (OneInchLimitOrderDecoder.Order memory o)
    {
        o = OneInchLimitOrderDecoder.Order({
            salt: 1,
            maker: uint256(uint160(acct)),
            receiver: 0,
            makerAsset: uint256(uint160(address(usd))),
            takerAsset: uint256(uint160(address(weth))),
            makingAmount: sell,
            takingAmount: sell * 0.00025 ether / 1e6,
            makerTraits: _traits(expiration, nonce)
        });
    }

    function _limitCall(OneInchLimitOrderDecoder.Order memory o) internal view returns (bytes memory) {
        return abi.encodeCall(AgentPolicy.orderRegister, (address(oneInch), _oneInchConfig(), abi.encode(o)));
    }

    function _registerLimit(OneInchLimitOrderDecoder.Order memory o) internal {
        _send(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
    }

    function _refusedLimit(OneInchLimitOrderDecoder.Order memory o) internal {
        uint256 spent = _usdSpent();
        _expectRefused(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
        assertEq(_usdSpent(), spent, "a refused order charges nothing");
        assertFalse(_vouched(router.hashOrder(o)), "and is not vouched for");
    }

    function _fill(OneInchLimitOrderDecoder.Order memory o) internal {
        bytes memory signature = _orderSignature(router.hashOrder(o));
        vm.prank(taker);
        router.fillContractOrder(o, signature, o.makingAmount, MAKING);
    }

    // --- the order's life ---

    function test_oneInch_registeredVouchedAndFilled() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        bytes32 digest = router.hashOrder(o);
        assertFalse(_vouched(digest), "nothing is vouched for before it is registered");
        assertTrue(oneInch.untouched(acct, abi.encode(o)));

        _registerLimit(o);
        assertEq(_usdSpent(), 150e6, "charged at registration");
        assertTrue(_vouched(digest));
        // an order one unit different is another digest
        OneInchLimitOrderDecoder.Order memory other = _limit(150e6, _soon(), 1);
        other.takingAmount -= 1;
        assertFalse(_vouched(router.hashOrder(other)));

        // the router fills it: it asks the account, pulls the sold token, pays the account
        uint256 before = weth.balanceOf(acct);
        _fill(o);
        assertEq(usd.balanceOf(acct), 10_000e6 - 150e6, "exactly the making amount left the account");
        assertEq(weth.balanceOf(acct) - before, o.takingAmount, "the proceeds are the account's");
        assertEq(usd.balanceOf(taker), 150e6);
        assertFalse(oneInch.untouched(acct, abi.encode(o)), "the router's bit for the order is set");

        // not twice: the account still vouches until the order's end, the router's bit says no
        assertTrue(_vouched(digest));
        bytes memory signature = _orderSignature(digest);
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.makingAmount, MAKING);
        assertEq(usd.balanceOf(acct), 10_000e6 - 150e6);
    }

    /// The taker may name the taking amount instead; it still fills whole, and
    /// a part is refused by the router.
    function test_oneInch_filledWholeOrNotAtAll() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        _registerLimit(o);
        bytes memory signature = _orderSignature(router.hashOrder(o));
        // a part, by the making amount and by the taking amount
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.makingAmount - 1, MAKING);
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.takingAmount - 1, 0);
        // the whole, by the taking amount
        uint256 before = weth.balanceOf(acct);
        vm.prank(taker);
        router.fillContractOrder(o, signature, o.takingAmount, 0);
        assertEq(usd.balanceOf(acct), 10_000e6 - 150e6);
        assertEq(weth.balanceOf(acct) - before, o.takingAmount);
    }

    function test_oneInch_vouchEndsWithTheOrder() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        _registerLimit(o);
        bytes32 digest = router.hashOrder(o);
        uint256 expiration = _soon();
        vm.warp(expiration);
        assertTrue(_vouched(digest), "at its expiration the router can still fill");
        vm.warp(expiration + 1);
        assertFalse(_vouched(digest));
        // and the router itself is past it
        bytes memory signature = _orderSignature(digest);
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.makingAmount, MAKING);
    }

    /// Without a signature of the agent's permission the router gets no
    /// answer: a registration alone does not fill an order.
    function test_oneInch_theRouterAsksTheAccount() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        // not registered: the agent's own signature is not enough
        bytes memory signature = _orderSignature(router.hashOrder(o));
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.makingAmount, MAKING);
        // registered, and no signature
        _registerLimit(o);
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, "", o.makingAmount, MAKING);
        assertEq(usd.balanceOf(acct), 10_000e6);
    }

    /// The same maker in a word with high bits set is another order to the
    /// router's hash: the account does not vouch for it, and it does not fill.
    function test_oneInch_aDirtyWordIsAnotherOrder() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        _registerLimit(o);
        OneInchLimitOrderDecoder.Order memory dirty = _limit(150e6, _soon(), 1);
        dirty.maker |= 1 << 200;
        assertTrue(router.hashOrder(dirty) != router.hashOrder(o));
        assertFalse(_vouched(router.hashOrder(dirty)));
        // it cannot be registered either
        _refusedLimit(dirty);
        // with the registered order's signature the router asks for the dirty hash, and gets a no
        bytes memory signature = _orderSignature(router.hashOrder(o));
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(dirty, signature, dirty.makingAmount, MAKING);
        // the same with the proceeds redirected under a dirty receiver word
        dirty = _limit(150e6, _soon(), 1);
        dirty.receiver = uint256(uint160(taker));
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(dirty, signature, dirty.makingAmount, MAKING);
        assertEq(usd.balanceOf(acct), 10_000e6);
    }

    // --- what is refused ---

    function test_oneInch_refusals() public {
        _both();
        // the proceeds to somebody else
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        o.receiver = uint256(uint160(makeAddr("the agent's own address")));
        _refusedLimit(o);
        // another maker
        o = _limit(150e6, _soon(), 1);
        o.maker = uint256(uint160(makeAddr("another account")));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
        // below the lowest price
        o = _limit(150e6, _soon(), 1);
        o.takingAmount = 150 * 0.0002 ether - 1;
        _refusedLimit(o);
        // the pair the other way round
        o = _limit(150e6, _soon(), 1);
        (o.makerAsset, o.takerAsset) = (o.takerAsset, o.makerAsset);
        _refusedLimit(o);
        // over the cap per operation
        _refusedLimit(_limit(USD_MAX + 1, _soon(), 1));
        // already past its end
        _refusedLimit(_limit(150e6, block.timestamp - 1, 1));
        // without an end
        _refusedLimit(_limit(150e6, 0, 1));
        // filled in parts
        o = _limit(150e6, _soon(), 1);
        o.makerTraits &= ~NO_PARTIAL_FILLS;
        _refusedLimit(o);
        // every flag a plain order leaves at zero: unwrap, Permit2, an extension, the epoch,
        // the calls after and before the fill, several fills
        uint8[7] memory flags = [247, 248, 249, 250, 251, 252, 254];
        for (uint256 i; i < flags.length; i++) {
            o = _limit(150e6, _soon(), 1);
            o.makerTraits |= uint256(1) << flags[i];
            _refusedLimit(o);
        }
        // a config of the agent's choosing
        o = _limit(150e6, _soon(), 1);
        OneInchLimitOrderDecoder.Config memory c = abi.decode(_oneInchConfig(), (OneInchLimitOrderDecoder.Config));
        c.pairs[0].minBuy = 1;
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(oneInch), abi.encode(c), abi.encode(o)))
            )
        );
        // the other venue's config, and the other venue's decoder with this order
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(oneInch), _cowConfig(), abi.encode(o)))
            )
        );
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), _oneInchConfig(), abi.encode(o)))
            )
        );
        // a decoder that is not the mandate's
        OneInchLimitOrderDecoder another = new OneInchLimitOrderDecoder(address(router));
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(another), _oneInchConfig(), abi.encode(o)))
            )
        );
        // the control, and then the same order a second time
        _registerLimit(o);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
        assertEq(_usdSpent(), 150e6);
    }

    /// An order registered no earlier than its lifetime before its end.
    function test_oneInch_notRegisteredEarlierThanItsLifetime() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, block.timestamp + LIFE + 1, 1);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
        vm.warp(block.timestamp + 1);
        _registerLimit(o);
        assertEq(_usdSpent(), 150e6);
    }

    // --- two venues, one mandate ---

    /// Orders at both venues are charged to the one budget of the token.
    function test_oneInch_bothVenuesShareTheBudget() public {
        _both();
        // CoW Swap: 150; 1inch: 150 and 150; the budget is 500
        _register(_order(150e6, _soon()));
        _registerLimit(_limit(150e6, _soon(), 1));
        _registerLimit(_limit(150e6, _soon(), 2));
        assertEq(_usdSpent(), 450e6);
        // 60 more would pass it, at either venue
        _refusedLimit(_limit(60e6, _soon(), 3));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(60e6, _soon()))));
        // 50 fits
        _registerLimit(_limit(50e6, _soon(), 3));
        assertEq(_usdSpent(), 500e6);
        // each venue fills its own
        _fill(_limit(150e6, _soon(), 1));
        CowSwapDecoder.Order memory cow = _order(150e6, _soon());
        settlement.settle(cow, acct, _orderSignature(settlement.digestOf(cow)));
        assertEq(usd.balanceOf(acct), 10_000e6 - 300e6);
    }

    /// Two orders of one nonce are two registrations and one fill: the
    /// router keeps one bit for the nonce.
    function test_oneInch_ordersOfOneNonceFillOnce() public {
        _both();
        OneInchLimitOrderDecoder.Order memory first = _limit(150e6, _soon(), 9);
        OneInchLimitOrderDecoder.Order memory second = _limit(100e6, _soon(), 9);
        _registerLimit(first);
        _registerLimit(second);
        assertEq(_usdSpent(), 250e6, "both are charged");
        _fill(second);
        assertFalse(oneInch.untouched(acct, abi.encode(first)), "the bit is the nonce's");
        bytes memory signature = _orderSignature(router.hashOrder(first));
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(first, signature, first.makingAmount, MAKING);
        assertEq(usd.balanceOf(acct), 10_000e6 - 100e6);
    }

    /// The owner cancels at the router; the agent cannot reach the router at all.
    function test_oneInch_theOwnerCancelsAtTheRouter() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        _registerLimit(o);
        // the agent: the router is a venue's place, no target of any mandate
        _expectRefused(
            _tradeOp(
                _today(),
                address(router),
                0,
                abi.encodeCall(IOneInchRouterForTests.cancelOrder, (o.makerTraits, router.hashOrder(o)))
            )
        );
        // the account itself, as the owner's operation would make it
        bytes32 digest = router.hashOrder(o);
        vm.prank(acct);
        router.cancelOrder(o.makerTraits, digest);
        assertFalse(oneInch.untouched(acct, abi.encode(o)));
        bytes memory signature = _orderSignature(digest);
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(o, signature, o.makingAmount, MAKING);
        assertEq(_usdSpent(), 150e6, "the charge stays: it returns when the budget renews");
    }

    // --- the router as a place ---

    /// The router is the venue's own contract and its spender: a mandate
    /// with it among its targets is refused, whatever the function.
    function test_oneInch_theRouterIsNotATarget() public {
        _world();
        router = IOneInchRouterForTests(_router());
        oneInch = new OneInchLimitOrderDecoder(address(router));
        assertEq(oneInch.venue(), address(router));
        assertEq(oneInch.spender(), address(router));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        (targets[2], selectors[2]) = (address(router), IOneInchRouterForTests.cancelOrder.selector);
        _refusedInstall(_paramsFor(targets, selectors, DAY, _twoVenues()));
        // nor the decoder
        (targets[2], selectors[2]) = (address(oneInch), bytes4(0));
        _refusedInstall(_paramsFor(targets, selectors, DAY, _twoVenues()));
    }

    /// Once a venue of the account, the router is out of the agent's reach
    /// under every mandate of the account.
    function test_oneInch_theRouterIsNoTargetUnderAnyMandate() public {
        _both();
        assertTrue(policy.venuePlace(acct, address(router)));
        assertTrue(policy.venuePlace(acct, address(oneInch)));
        // a later mandate without venues, naming the router: refused at install
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        (targets[2], selectors[2]) = (address(router), bytes4(0));
        _refusedInstall(_paramsFor(targets, selectors, DAY, new AgentPolicy.Venue[](0)));
    }

    /// The decoder's code is pinned: another decoder at the address the
    /// mandate names answers for nothing.
    function test_oneInch_theDecodersCodeIsPinned() public {
        _both();
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        bytes memory honest = address(oneInch).code;
        vm.etch(address(oneInch), address(decoder).code);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _limitCall(o)));
        vm.etch(address(oneInch), honest);
        _registerLimit(o);
    }
}

/// Every test above against the router's own code, and what the router does
/// with the orders the decoder refuses. The code is read from a chain when
/// the test runs and placed at the router's address, under that chain's id:
///
///   ONEINCH_RPC_URL=<an RPC of Ethereum, Base, Sepolia, ...> \
///     forge test --evm-version osaka --match-contract OneInchRealRouterTest
///
/// Without the variable the tests are skipped: CI has no RPC.
contract OneInchRealRouterTest is OneInchTradingTest {
    address internal constant ROUTER = 0x111111125421cA6dc452d289314280a0f8842A65;
    // The router's hash of the order (1, 2, 3, 4, 5, 6, 7, 8) on Base, Sepolia and Base Sepolia
    bytes32 internal constant PROBE_BASE = 0x9652befe1a3e3520f05150ad880f8b1a6a3ae709e33cf34f40099988c5cc348c;
    bytes32 internal constant PROBE_SEPOLIA = 0x4fcf8d8374635ca9bc214438eb9f4f23d99404a52940af7d4b10efa5b023940f;
    bytes32 internal constant PROBE_BASE_SEPOLIA = 0x9a7614c0abe9a44b132e0b7d3334238abd415fd87e4d4de5cac191649554d578;

    function _router() internal override returns (address) {
        string memory rpc = vm.envOr("ONEINCH_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            // a stand-in, so that the compiler has an address: a skipped test's world is never used
            return super._router();
        }
        bytes memory code = vm.rpc(rpc, "eth_getCode", string.concat('["', vm.toString(ROUTER), '","latest"]'));
        require(code.length > 0, "no router on this chain");
        // the chain's id, from the bytes of the RPC's answer
        bytes memory id = vm.rpc(rpc, "eth_chainId", "[]");
        uint256 chain;
        for (uint256 i; i < id.length; i++) {
            chain = (chain << 8) | uint8(id[i]);
        }
        // the router's domain is this chain's and this address's: both are in its code
        vm.chainId(chain);
        vm.etch(ROUTER, code);
        return ROUTER;
    }

    /// A maker that vouches for everything, with tokens and an allowance:
    /// the account without its policy.
    function _yesMaker() internal returns (YesMaker maker) {
        maker = new YesMaker();
        usd.mint(address(maker), 1_000e6);
        maker.approve(usd, address(router), type(uint256).max);
    }

    function _orderOf(YesMaker maker, uint256 traits) internal view returns (OneInchLimitOrderDecoder.Order memory o) {
        o = _limit(100e6, 0, 1);
        o.maker = uint256(uint160(address(maker)));
        o.makerTraits = traits;
    }

    /// Why an order must expire: an expiration of zero is "never".
    function test_real_anOrderWithoutAnExpirationNeverEnds() public {
        _both();
        YesMaker maker = _yesMaker();
        OneInchLimitOrderDecoder.Order memory o = _orderOf(maker, NO_PARTIAL_FILLS | (uint256(1) << 120));
        vm.warp(block.timestamp + 3650 days);
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount, MAKING);
        assertEq(usd.balanceOf(taker), 100e6, "filled ten years on");
    }

    /// Why the two interaction flags are refused although there is no
    /// extension: the router then calls the maker itself, before and after.
    function test_real_theInteractionFlagsCallTheMaker() public {
        _both();
        YesMaker maker = _yesMaker();
        OneInchLimitOrderDecoder.Order memory o = _orderOf(maker, _traits(_soon(), 1) | (1 << 251) | (1 << 252));
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount, MAKING);
        assertEq(maker.calls(), 2, "one call before the fill and one after");
    }

    /// Why an order is filled whole: of an order filled in parts the router
    /// asks the maker on the first fill only.
    function test_real_anOrderFilledInPartsIsAskedOnce() public {
        _both();
        YesMaker maker = _yesMaker();
        // several fills, parts allowed
        OneInchLimitOrderDecoder.Order memory o =
            _orderOf(maker, (uint256(1) << 254) | (_soon() << 80) | (uint256(1) << 120));
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount / 2, MAKING);
        assertEq(usd.balanceOf(taker), 50e6);
        // the maker stops vouching, as an account does when the registration ends: the rest still fills
        maker.fallSilent();
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount / 2, MAKING);
        assertEq(usd.balanceOf(taker), 100e6, "the second half was never put to the maker");
        // a whole order, by contrast, is put to it on its one fill
        OneInchLimitOrderDecoder.Order memory whole = _orderOf(maker, _traits(_soon(), 2));
        vm.prank(taker);
        vm.expectRevert();
        router.fillContractOrder(whole, "", whole.makingAmount, MAKING);
    }

    /// Why a config's tokens must have code: the router takes a transfer at
    /// an address without code for done.
    function test_real_aTokenWithoutCodeIsTakenForPaid() public {
        _both();
        YesMaker maker = _yesMaker();
        OneInchLimitOrderDecoder.Order memory o = _orderOf(maker, _traits(_soon(), 1));
        o.takerAsset = uint256(uint160(makeAddr("no token here")));
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount, MAKING);
        assertEq(usd.balanceOf(taker), 100e6, "the sold amount left the maker");
        assertEq(weth.balanceOf(address(maker)), 0, "and nothing came for it");
    }

    /// Why the words are held clean: the router reads the maker from the low
    /// bits of a word and hashes the whole word.
    function test_real_aDirtyMakerWordIsTheSameMakerUnderAnotherHash() public {
        _both();
        YesMaker maker = _yesMaker();
        OneInchLimitOrderDecoder.Order memory o = _orderOf(maker, _traits(_soon(), 1));
        bytes32 clean = router.hashOrder(o);
        o.maker |= 1 << 255;
        assertTrue(router.hashOrder(o) != clean);
        vm.prank(taker);
        router.fillContractOrder(o, "", o.makingAmount, MAKING);
        assertEq(usd.balanceOf(taker), 100e6, "filled from the maker in the word's low bits");
    }

    /// The decoder was built on the router's own facts: its constructor asked
    /// the router for its domain and for its hash of a probe order.
    function test_real_theDecoderIsBuiltOnTheRoutersOwnHash() public {
        _both();
        assertEq(oneInch.venue(), ROUTER);
        OneInchLimitOrderDecoder.Order memory o = _limit(150e6, _soon(), 1);
        (,,,, bytes32 digest) = oneInch.judge(acct, _oneInchConfig(), abi.encode(o));
        assertEq(digest, router.hashOrder(o));
        // and on the four chains where the router was asked for the probe order's hash
        // (2026-11-26, `eth_call`), this code gives what the chain gave
        bytes32 probe = router.hashOrder(OneInchLimitOrderDecoder.Order(1, 2, 3, 4, 5, 6, 7, 8));
        if (block.chainid == 1) assertEq(probe, 0x414df8fabc5c7acecd1c823fc831f685b742e7b70f33e569be1710c1d57f0769);
        if (block.chainid == 8453) assertEq(probe, PROBE_BASE);
        if (block.chainid == 11155111) assertEq(probe, PROBE_SEPOLIA);
        if (block.chainid == 84532) assertEq(probe, PROBE_BASE_SEPOLIA);
    }
}
