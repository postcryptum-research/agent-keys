// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TradingTest} from "./Trading.t.sol";
import {Counter, MockOperators} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {VenueCalls} from "../src/venues/VenueCalls.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, CallType, PermissionId} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// A decoder that judges nothing: its "order" says what to answer. With it
/// the tests hold what the policy keeps by itself, whatever a decoder says:
/// the pairing of a registered call with the leg after it, the one contract
/// a decoder speaks for, and what no decoder's word opens.
contract SayingDecoder {
    address public immutable venue;
    address public immutable spender;

    /// The spender is apart from the venue, so that a test can tell which of the two the policy binds.
    constructor(address place, address spender_) {
        (venue, spender) = (place, spender_);
    }

    /// `order` is `abi.encode(value, data, token, mostSold, validTo, digest)`: a
    /// call when `validTo` is zero (the digest is then the call's hash,
    /// unless `digest` is set to stand in for it). The call's target is not
    /// in it: the policy binds the hash to `venue`.
    function judge(address, bytes calldata, bytes calldata order)
        external
        pure
        returns (address, uint256, uint48, uint48, bytes32)
    {
        (uint256 value, bytes memory data, address token, uint256 mostSold, uint48 validTo, bytes32 digest) =
            abi.decode(order, (uint256, bytes, address, uint256, uint48, bytes32));
        if (digest == bytes32(0)) digest = VenueCalls.digest(value, data);
        return (token, mostSold, 0, validTo, digest);
    }
}

/// A place that takes a call with value and counts.
contract PayablePlace {
    uint256 public count;
    uint256 public received;

    function poke() external payable {
        count++;
        received += msg.value;
    }

    function other() external {
        count += 100;
    }
}

/// A call a decoder judged is admitted only as the leg right after its
/// registration, and only if it is exactly that call (issue #80). The
/// registration is the policy's `orderRegister`: a decoder that answers with
/// no `validTo` has judged a call, not an order.
contract VenueCallPairingTest is TradingTest {
    SayingDecoder internal saying;
    /// The decoder a registration goes through: `saying`, unless a test names another.
    SayingDecoder internal through;
    SayingDecoder internal atPermit2;
    SayingDecoder internal atTheToken;
    PayablePlace internal place;
    /// The saying decoder's spender: a contract like its venue, and not its venue.
    PayablePlace internal spenderPlace;
    bytes internal constant CONFIG = "the owner's config for the saying decoder";

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// The trading mandate with three more venues: the saying decoder at its
    /// place, and two that name as their place what no decoder may open,
    /// Permit2 and the token the mandate limits. An owner could pin those;
    /// the policy refuses a call there all the same.
    function _withCalls() internal {
        _world();
        (place, spenderPlace) = (new PayablePlace(), new PayablePlace());
        through = saying = new SayingDecoder(address(place), address(spenderPlace));
        atPermit2 = new SayingDecoder(PERMIT2, address(1));
        atTheToken = new SayingDecoder(address(usd), address(2));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](4);
        v[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        (v[1], v[2], v[3]) = (_pin(saying), _pin(atPermit2), _pin(atTheToken));
        _install(TRD_ID, _params(DAY, v));
        assertTrue(policy.venuePlace(acct, PERMIT2) && policy.venuePlace(acct, address(usd)), "pinned");
        vm.deal(acct, 10 ether);
    }

    function _pin(SayingDecoder d) internal view returns (AgentPolicy.Venue memory) {
        return AgentPolicy.Venue(address(d), address(d).codehash, keccak256(CONFIG));
    }

    function _poke() internal pure returns (bytes memory) {
        return abi.encodeCall(PayablePlace.poke, ());
    }

    /// The registration of a call with `value` and `data`, charged `mostSold` of `token`, through
    /// the decoder `through`: the call is then to be made at that decoder's venue.
    function _reg(uint256 value, bytes memory data, address token, uint256 mostSold)
        internal
        view
        returns (Execution memory)
    {
        return _regAs(value, data, token, mostSold, 0, bytes32(0));
    }

    function _regAs(uint256 value, bytes memory data, address token, uint256 mostSold, uint48 validTo, bytes32 digest)
        internal
        view
        returns (Execution memory)
    {
        bytes memory order = abi.encode(value, data, token, mostSold, validTo, digest);
        return
            Execution(address(policy), 0, abi.encodeCall(AgentPolicy.orderRegister, (address(through), CONFIG, order)));
    }

    /// An agent operation of several legs under the trading mandate, in today's period.
    function _batch(Execution[] memory calls) internal view returns (PackedUserOperation memory op) {
        return _batchAs(TRD_ID, calls);
    }

    /// The same under any permission with a period.
    function _batchAs(PermissionId id, Execution[] memory calls) internal view returns (PackedUserOperation memory op) {
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(calls)
        );
        op = _op(_permissionNonce(id), callData);
        op.signature = abi.encodePacked(
            bytes1(0), bytes8(uint64(6)), bytes6(_today()), bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op))
        );
    }

    function _two(Execution memory a, Execution memory b) internal pure returns (Execution[] memory calls) {
        calls = new Execution[](2);
        (calls[0], calls[1]) = (a, b);
    }

    /// A call registered through `through`, and the leg after it: the same call, made at `target`.
    function _pair(address target, uint256 value, bytes memory data) internal view returns (Execution[] memory) {
        return _two(_reg(value, data, address(0), 0), Execution(target, value, data));
    }

    // --- the pairing ---

    /// The place is a venue's own contract, on no allow-list and out of the
    /// agent's reach; the call the decoder judged reaches it, and only that.
    function test_call_theJudgedCallIsMadeAndNoOther() public {
        _withCalls();
        // by itself the place is refused, in a batch or alone
        _expectRefused(_tradeOp(_today(), address(place), 0, _poke()));
        // registered and made: two legs, one operation
        _send(_batch(_pair(address(place), 0, _poke())));
        assertEq(place.count(), 1);
        // the same call again: a call is not an order, and registers as often as it is made
        _send(_batch(_pair(address(place), 0, _poke())));
        assertEq(place.count(), 2);
        // nothing of it is vouched for: neither hash of the call is a signature of the account's
        bytes32 callDigest = VenueCalls.digest(0, _poke());
        assertFalse(_vouched(callDigest));
        assertFalse(_vouched(VenueCalls.bound(address(place), callDigest)));
    }

    function test_call_theLegAfterTheRegistrationMustBeThatCall() public {
        _withCalls();
        Execution memory reg = _reg(0, _poke(), address(0), 0);
        // another function of the same place
        _expectRefused(_batch(_two(reg, Execution(address(place), 0, abi.encodeCall(PayablePlace.other, ())))));
        // the same function with a value the decoder did not judge
        _expectRefused(_batch(_two(reg, Execution(address(place), 1, _poke()))));
        // the same call at another contract
        PayablePlace elsewhere = new PayablePlace();
        _expectRefused(_batch(_two(reg, Execution(address(elsewhere), 0, _poke()))));
        // a byte more of calldata
        _expectRefused(_batch(_two(reg, Execution(address(place), 0, bytes.concat(_poke(), hex"00")))));
        // an allow-listed call in between: the judged call is then not the next leg
        Execution[] memory between = new Execution[](3);
        between[0] = reg;
        between[1] = Execution(address(counter), 0, abi.encodeCall(Counter.increment, ()));
        between[2] = Execution(address(place), 0, _poke());
        _expectRefused(_batch(between));
        assertEq(place.count(), 0);
        assertEq(counter.count(), 0);
    }

    /// A registration without its call is refused: alone, or as the last leg.
    function test_call_aRegistrationWithoutItsCallIsRefused() public {
        _withCalls();
        Execution memory reg = _reg(0, _poke(), address(0), 0);
        // alone, as a single call of the account
        _expectRefused(_tradeOp(_today(), reg.target, 0, reg.callData));
        // as the last leg of a batch
        _expectRefused(_batch(_two(Execution(address(counter), 0, abi.encodeCall(Counter.increment, ())), reg)));
        // as the only leg of a batch
        Execution[] memory one = new Execution[](1);
        one[0] = reg;
        _expectRefused(_batch(one));
        // two registrations and then the two calls: the leg after the first is a registration
        Execution[] memory four = new Execution[](4);
        (four[0], four[1]) = (reg, reg);
        (four[2], four[3]) = (Execution(address(place), 0, _poke()), Execution(address(place), 0, _poke()));
        _expectRefused(_batch(four));
        // each registration with its call: passes
        (four[1], four[2]) = (four[2], four[1]);
        _send(_batch(four));
        assertEq(place.count(), 2);
    }

    /// A decoder speaks for its own venue's contract and for nothing else:
    /// not the account, not the policy, not a contract on the allow-list, not
    /// another venue's contract, not any other address.
    function test_call_onlyAtTheDecodersOwnVenue() public {
        _withCalls();
        // the account: a call to itself could install or change anything
        bytes memory grant = abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), ""));
        _expectRefused(_batch(_pair(acct, 0, grant)));
        // the policy
        _expectRefused(_batch(_pair(address(policy), 0, abi.encodeWithSignature("x402Reclaim()"))));
        // a contract on the mandate's allow-list: reached by the list, not by a decoder
        _expectRefused(_batch(_pair(address(counter), 0, abi.encodeCall(Counter.increment, ()))));
        // a contract nobody pinned
        PayablePlace elsewhere = new PayablePlace();
        _expectRefused(_batch(_pair(address(elsewhere), 0, _poke())));
        // another venue's contract, pinned in the same mandate: CoW's settlement, where a call
        // could sign an order past CoW's decoder
        assertTrue(policy.venuePlace(acct, address(settlement)), "a venue's place");
        bytes memory preSign = abi.encodeWithSignature("setPreSignature(bytes,bool)", hex"00", true);
        _expectRefused(_batch(_pair(address(settlement), 0, preSign)));
        // the decoder's spender: pinned with the venue, and not what the decoder speaks for
        assertTrue(policy.venuePlace(acct, address(spenderPlace)), "the spender is pinned");
        _expectRefused(_batch(_pair(address(spenderPlace), 0, _poke())));
        assertEq(counter.count(), 0);
        assertEq(elsewhere.count(), 0);
        assertEq(spenderPlace.count(), 0);
        // the control: the decoder's own venue, with the same decoder's word, passes
        _send(_batch(_pair(address(place), 0, _poke())));
        assertEq(place.count(), 1);
    }

    /// Nor what the mandate counts itself, even where an owner pinned a
    /// decoder that names it as its venue: Permit2, and a token with a limit.
    function test_call_whatNoDecoderOpens() public {
        _withCalls();
        // Permit2: it holds an allowance per token and moves it on a call the policy does not read
        vm.etch(PERMIT2, address(place).code);
        through = atPermit2;
        _expectRefused(_batch(_pair(PERMIT2, 0, _poke())));
        assertEq(PayablePlace(PERMIT2).count(), 0);
        // the limited token: its transfer would pass the cap and the budget, and nothing would count it
        through = atTheToken;
        bytes memory transfer = abi.encodeWithSignature("transfer(address,uint256)", makeAddr("anyone"), 5_000e6);
        _expectRefused(_batch(_pair(address(usd), 0, transfer)));
        assertEq(usd.balanceOf(makeAddr("anyone")), 0);
        // the control: a decoder whose venue is none of those
        through = saying;
        _send(_batch(_pair(address(place), 0, _poke())));
    }

    /// Nor a contract whose ids the mandate limits: the decoder's word would
    /// move an id past its cap with nothing counting it.
    function test_call_aDecoderDoesNotOpenAContractWithIdLimits() public {
        _world();
        (place, spenderPlace) = (new PayablePlace(), new PayablePlace());
        saying = new SayingDecoder(address(place), address(spenderPlace));
        MockOperators t = new MockOperators();
        SayingDecoder atTheIds = new SayingDecoder(address(t), address(3));
        t.mint(acct, 7, 100);
        PermissionId id = PermissionId.wrap(0x69643033); // "id03"
        // the registration alone: a venue's contract is on no allow-list
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.orderRegister.selector);
        AgentPolicy.IdCap[] memory caps = new AgentPolicy.IdCap[](1);
        caps[0] = AgentPolicy.IdCap(address(t), 7, 5, 5);
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](2);
        (v[0], v[1]) = (_pin(saying), _pin(atTheIds));
        _send(
            _installOp(
                id,
                abi.encode(
                    targets,
                    selectors,
                    MAX_VALUE,
                    BUDGET,
                    tradingExpiry,
                    new AgentPolicy.TokenCap[](0),
                    uint48(0),
                    new AgentPolicy.TokenPayees[](0),
                    DAY,
                    v,
                    caps
                )
            )
        );
        assertTrue(policy.venuePlace(acct, address(t)), "pinned");
        // by the word of the decoder whose venue it is, 50 of the id whose cap is 5: refused
        address to = makeAddr("receiver");
        Execution memory move = _idMove(t, to, 7, 50);
        through = atTheIds;
        _expectRefused(_batchAs(id, _pair(address(t), 0, move.callData)));
        assertEq(t.balanceOf(to, 7), 0);
        // the control: a decoder whose venue the mandate does not meter, under the same mandate
        through = saying;
        _send(_batchAs(id, _pair(address(place), 0, _poke())));
        assertEq(place.count(), 1);
    }

    // --- what a call is charged ---

    /// A call the decoder prices is charged like an order: to the token's cap
    /// per operation and its budget. One it does not price is charged nothing here.
    function test_call_chargedAsTheDecoderSays() public {
        _withCalls();
        _send(_batch(_two(_reg(0, _poke(), address(usd), 150e6), Execution(address(place), 0, _poke()))));
        assertEq(_usdSpent(), 150e6);
        // over the cap per operation
        _expectRefused(_batch(_two(_reg(0, _poke(), address(usd), USD_MAX + 1), Execution(address(place), 0, _poke()))));
        // up to the budget, and not past it
        _send(_batch(_two(_reg(0, _poke(), address(usd), 200e6), Execution(address(place), 0, _poke()))));
        _send(_batch(_two(_reg(0, _poke(), address(usd), 150e6), Execution(address(place), 0, _poke()))));
        assertEq(_usdSpent(), 500e6);
        _expectRefused(_batch(_two(_reg(0, _poke(), address(usd), 1), Execution(address(place), 0, _poke()))));
        // a token the mandate does not limit cannot be priced
        _expectRefused(_batch(_two(_reg(0, _poke(), address(weth), 1), Execution(address(place), 0, _poke()))));
        // unpriced: nothing more is charged, and the call is made
        uint256 before = place.count();
        _send(_batch(_pair(address(place), 0, _poke())));
        assertEq(place.count(), before + 1);
        assertEq(_usdSpent(), 500e6);
    }

    /// A token with a payee list cannot be charged by a call either: what the
    /// call takes goes to the venue's contract, and the owner listed who may be paid.
    function test_call_aTokenWithAPayeeListIsNotCharged() public {
        _world();
        (place, spenderPlace) = (new PayablePlace(), new PayablePlace());
        through = saying = new SayingDecoder(address(place), address(spenderPlace));
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usd), USD_MAX, USD_BUDGET, bytes32(0));
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0] = _list(address(usd), PAYEE, address(0));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = _pin(saying);
        _install(
            TRD_ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0), lists, DAY, v)
        );
        // priced in the listed token: refused
        _expectRefused(_batch(_two(_reg(0, _poke(), address(usd), 1e6), Execution(address(place), 0, _poke()))));
        assertEq(place.count(), 0);
        // the control: the same call unpriced
        _send(_batch(_pair(address(place), 0, _poke())));
        assertEq(place.count(), 1);
    }

    /// The call's native value counts toward the cap per operation and the budget, like any leg's.
    function test_call_itsNativeValueCounts() public {
        _withCalls();
        _send(_batch(_pair(address(place), MAX_VALUE, _poke())));
        assertEq(place.received(), MAX_VALUE);
        _expectRefused(_batch(_pair(address(place), MAX_VALUE + 1, _poke())));
        // two judged calls in one operation: their values add up
        Execution[] memory four = new Execution[](4);
        four[0] = _reg(MAX_VALUE, _poke(), address(0), 0);
        four[1] = Execution(address(place), MAX_VALUE, _poke());
        (four[2], four[3]) = (four[0], four[1]);
        _expectRefused(_batch(four));
        assertEq(place.received(), MAX_VALUE);
    }

    // --- an order is still an order ---

    /// A decoder that answers with a `validTo` has judged an order: it is
    /// recorded and vouched for, and it takes no leg along.
    function test_call_anAnswerWithAnEndIsAnOrder() public {
        _withCalls();
        bytes32 digest = keccak256("an order's digest");
        Execution memory order = _regAs(0, _poke(), address(usd), 100e6, _soon(), digest);
        // followed by the place's call: an order opens no call
        _expectRefused(_batch(_two(order, Execution(address(place), 0, _poke()))));
        // alone it registers, as before
        _send(_tradeOp(_today(), order.target, 0, order.callData));
        assertTrue(_vouched(digest));
        assertEq(_usdSpent(), 100e6);
        // and an order sells something: one that sells nothing is refused
        Execution memory nothing = _regAs(0, _poke(), address(usd), 0, _soon(), keccak256("another"));
        _expectRefused(_tradeOp(_today(), nothing.target, 0, nothing.callData));
    }

    /// A real order decoder that is handed an order ending at zero answers
    /// with no `validTo`: the policy takes that for a call, finds no leg that
    /// hashes to an order's digest, and refuses. Nothing is recorded.
    function test_call_anOrderEndingAtZeroIsNotACall() public {
        _withCalls();
        CowSwapDecoder.Order memory o = _order(150e6, 0);
        bytes32 digest = settlement.digestOf(o);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));
        Execution memory reg = Execution(address(policy), 0, _registerCall(o));
        _expectRefused(_batch(_two(reg, Execution(address(counter), 0, abi.encodeCall(Counter.increment, ())))));
        assertFalse(_vouched(digest));
        assertEq(_usdSpent(), 0);
    }
}
