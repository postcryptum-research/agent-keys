// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentPermissionTest, MockToken, MockUSDC, Counter} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {IVenueDecoder} from "../src/venues/IVenueDecoder.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, PermissionId, ValidationId} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {CallType} from "kernel/src/types/Types.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// CoW's settlement as far as these tests need it: the views the decoder
/// reads, and a `settle` that does what the real one does to an order's
/// owner: asks the owner's ERC-1271 for the order's digest, refuses a second
/// fill, pulls `sellAmount + feeAmount` and pays the proceeds. It is its own
/// relayer.
contract Settlement {
    bytes32 public immutable domainSeparator;
    mapping(bytes => uint256) public filledAmount;

    constructor() {
        domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Gnosis Protocol"),
                keccak256("v2"),
                block.chainid,
                address(this)
            )
        );
    }

    function vaultRelayer() external view returns (address) {
        return address(this);
    }

    function digestOf(CowSwapDecoder.Order memory o) public view returns (bytes32) {
        bytes32 typeHash = keccak256(
            "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
        );
        return keccak256(
            abi.encodePacked(hex"1901", domainSeparator, keccak256(abi.encodePacked(typeHash, abi.encode(o))))
        );
    }

    function settle(CowSwapDecoder.Order memory o, address owner, bytes calldata signature) external {
        require(o.validTo >= block.timestamp, "GPv2: order expired");
        bytes32 digest = digestOf(o);
        require(IERC1271(owner).isValidSignature(digest, signature) == 0x1626ba7e, "GPv2: invalid eip1271 signature");
        bytes memory uid = abi.encodePacked(digest, owner, o.validTo);
        require(filledAmount[uid] == 0, "GPv2: order filled");
        filledAmount[uid] = o.sellAmount;
        MockToken(o.sellToken).transferFrom(owner, address(this), o.sellAmount + o.feeAmount);
        MockToken(o.buyToken).transfer(o.receiver == address(0) ? owner : o.receiver, o.buyAmount);
    }

    function setPreSignature(bytes calldata, bool) external {}
}

/// A decoder that answers whatever it was built to answer.
contract CrookedDecoder {
    bytes internal answer;
    address public venue;

    constructor(bytes memory answer_) {
        answer = answer_;
    }

    fallback() external {
        bytes memory a = answer;
        assembly {
            return(add(a, 32), mload(a))
        }
    }
}

/// The core's side of trading (issue #80): a budget per period, and orders
/// registered through a venue's decoder, vouched for, settled and reclaimed.
contract TradingTest is AgentPermissionTest {
    PermissionId internal constant TRD_ID = PermissionId.wrap(0x74726164); // "trad"
    bytes32 internal constant TRD = bytes32(PermissionId.unwrap(TRD_ID));
    uint32 internal constant DAY = 1 days;
    uint32 internal constant LIFE = 30 minutes;
    uint128 internal constant USD_MAX = 200e6;
    uint128 internal constant USD_BUDGET = 500e6;
    bytes32 internal constant APP_DATA = keccak256("the owner's appData");
    uint256 internal constant T0 = 1_800_000_000;

    MockToken internal usd;
    MockToken internal weth;
    Settlement internal settlement;
    CowSwapDecoder internal decoder;
    uint48 internal tradingExpiry;

    function _world() internal {
        vm.warp(T0);
        tradingExpiry = uint48(T0 + 30 days);
        usd = new MockToken();
        weth = new MockToken();
        settlement = new Settlement();
        decoder = new CowSwapDecoder(address(settlement));
        usd.mint(acct, 10_000e6);
        weth.mint(address(settlement), 100 ether);
    }

    function _with(uint32 period_) internal {
        _world();
        _install(
            TRD_ID, _params(period_, _venues(address(decoder), address(decoder).codehash, keccak256(_cowConfig())))
        );
    }

    function _cowConfig() internal view returns (bytes memory) {
        CowSwapDecoder.Config memory c;
        c.appData = APP_DATA;
        c.maxLife = LIFE;
        c.pairs = new CowSwapDecoder.Pair[](1);
        // at least 0.0002 WETH for each unit of the dollar token
        c.pairs[0] = CowSwapDecoder.Pair(address(usd), address(weth), 0.0002 ether, 1e6);
        return abi.encode(c);
    }

    function _venues(address d, bytes32 codeHash, bytes32 configHash)
        internal
        pure
        returns (AgentPolicy.Venue[] memory v)
    {
        v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(d, codeHash, configHash);
    }

    function _targets() internal view returns (address[] memory targets, bytes4[] memory selectors) {
        targets = new address[](4);
        selectors = new bytes4[](4);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.orderRegister.selector);
        (targets[1], selectors[1]) = (address(policy), AgentPolicy.orderReclaim.selector);
        (targets[2], selectors[2]) = (address(counter), Counter.increment.selector);
        (targets[3], selectors[3]) = (address(counter), bytes4(0));
    }

    function _params(uint32 period_, AgentPolicy.Venue[] memory venues) internal view returns (bytes memory) {
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        return _paramsFor(targets, selectors, period_, venues);
    }

    function _paramsFor(
        address[] memory targets,
        bytes4[] memory selectors,
        uint32 period_,
        AgentPolicy.Venue[] memory venues
    ) internal view returns (bytes memory) {
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usd), USD_MAX, USD_BUDGET, bytes32(0));
        AgentPolicy.TokenPayees[] memory none = new AgentPolicy.TokenPayees[](0);
        return abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0), none, period_, venues);
    }

    /// The owner's install: the permission, its access to `execute`, and the
    /// allowance to the venue's relayer, bounded by the budget.
    function _installOp(PermissionId id, bytes memory params) internal view returns (PackedUserOperation memory) {
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(bytes2(0), address(policy), params);
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(id);
        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        batch[2] = Execution(address(usd), 0, abi.encodeCall(MockToken.approve, (address(settlement), USD_BUDGET)));
        return _rootOp(
            abi.encodeWithSelector(
                Kernel.execute.selector,
                ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
                ExecLib.encodeBatch(batch)
            )
        );
    }

    function _install(PermissionId id, bytes memory params) internal {
        _send(_installOp(id, params));
        assertTrue(
            policy.isAllowed(acct, bytes32(PermissionId.unwrap(id)), address(counter), Counter.increment.selector),
            "installed"
        );
    }

    /// An install the policy must refuse: the root operation goes through and
    /// leaves no permission behind.
    function _refusedInstall(bytes memory params) internal {
        PermissionId id = PermissionId.wrap(0x74726432); // "trd2"
        _send(_installOp(id, params));
        assertFalse(
            policy.isAllowed(acct, bytes32(PermissionId.unwrap(id)), address(counter), Counter.increment.selector)
        );
    }

    function _today() internal view returns (uint48) {
        return uint48(block.timestamp / DAY);
    }

    /// An agent operation that names its period in the policy's part of the signature.
    function _tradeOp(uint48 periodIndex, address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(_permissionNonce(TRD_ID), _singleCall(target, value, data));
        op.signature = abi.encodePacked(
            bytes1(0), bytes8(uint64(6)), bytes6(periodIndex), bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op))
        );
    }

    function _order(uint256 sell, uint32 validTo) internal view returns (CowSwapDecoder.Order memory o) {
        o = CowSwapDecoder.Order({
            sellToken: address(usd),
            buyToken: address(weth),
            receiver: address(0),
            sellAmount: sell,
            buyAmount: sell * 0.00025 ether / 1e6,
            validTo: validTo,
            appData: APP_DATA,
            feeAmount: 0,
            kind: keccak256("sell"),
            partiallyFillable: false,
            sellTokenBalance: keccak256("erc20"),
            buyTokenBalance: keccak256("erc20")
        });
    }

    /// The last second of the period the clock is in.
    function _periodEnd() internal view returns (uint32) {
        return uint32((uint256(_today()) + 1) * DAY - 1);
    }

    function _soon() internal view returns (uint32) {
        return uint32(block.timestamp + 10 minutes);
    }

    function _registerCall(CowSwapDecoder.Order memory o) internal view returns (bytes memory) {
        return abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), _cowConfig(), abi.encode(o)));
    }

    function _register(CowSwapDecoder.Order memory o) internal {
        _send(_tradeOp(_today(), address(policy), 0, _registerCall(o)));
    }

    function _usdSpent() internal view returns (uint256) {
        return policy.tokenLimit(acct, TRD, address(usd)).spent;
    }

    /// CoW's ERC-1271 signature of the account: Kernel's 0x02 ‖ permission id ‖ 0xff ‖ r ‖ s.
    function _orderSignature(bytes32 digest) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes1(0x02), PermissionId.unwrap(TRD_ID), bytes1(0xff), _sign(AGENT, _kernelWrapped(digest))
        );
    }

    function _vouched(bytes32 digest) internal view returns (bool) {
        try Kernel(payable(acct)).isValidSignature(digest, _orderSignature(digest)) returns (bytes4 r) {
            return r == 0x1626ba7e;
        } catch {
            return false;
        }
    }

    // --- install ---

    function test_trading_installPinsTheVenueAndThePeriod() public {
        _with(DAY);
        AgentPolicy.VenuePin memory pin = policy.venue(acct, TRD, address(decoder));
        assertEq(pin.codeHash, address(decoder).codehash);
        assertEq(pin.configHash, keccak256(_cowConfig()));
        (uint32 seconds_, uint48 seen) = policy.period(acct, TRD);
        assertEq(seconds_, DAY);
        assertEq(seen, 0);
        assertEq(policy.venue(acct, TRD, address(settlement)).codeHash, bytes32(0), "nothing else is a venue");
    }

    function test_trading_installRefusals() public {
        _with(DAY);
        bytes32 code = address(decoder).codehash;
        bytes32 config = keccak256(_cowConfig());
        // code other than the pinned
        _refusedInstall(_params(DAY, _venues(address(decoder), keccak256("other code"), config)));
        // an address without code, pinned to the hash of no code
        _refusedInstall(_params(DAY, _venues(makeAddr("nothing here"), keccak256(""), config)));
        // no config
        _refusedInstall(_params(DAY, _venues(address(decoder), code, bytes32(0))));
        // a venue twice
        AgentPolicy.Venue[] memory twice = new AgentPolicy.Venue[](2);
        twice[0] = AgentPolicy.Venue(address(decoder), code, config);
        twice[1] = twice[0];
        _refusedInstall(_params(DAY, twice));
        // the ten-word form with neither a period nor a venue
        _refusedInstall(_params(0, new AgentPolicy.Venue[](0)));
        // the control: the same data with a venue installs
        _install(PermissionId.wrap(0x74726433), _params(0, _venues(address(decoder), code, config)));
    }

    /// The settlement itself is never a target: `setPreSignature` on it
    /// would sign any order.
    function test_trading_theVenueItselfIsNotATarget() public {
        _with(DAY);
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        (targets[3], selectors[3]) = (address(settlement), Settlement.setPreSignature.selector);
        _refusedInstall(
            _paramsFor(
                targets, selectors, DAY, _venues(address(decoder), address(decoder).codehash, keccak256(_cowConfig()))
            )
        );
        (targets[3], selectors[3]) = (address(decoder), bytes4(0));
        _refusedInstall(
            _paramsFor(
                targets, selectors, DAY, _venues(address(decoder), address(decoder).codehash, keccak256(_cowConfig()))
            )
        );
    }

    // --- an order, end to end ---

    function test_order_registeredVouchedAndSettled() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        bytes32 digest = settlement.digestOf(o);
        assertFalse(_vouched(digest), "nothing is vouched for before it is registered");

        _register(o);
        assertEq(_usdSpent(), 150e6, "charged at registration");
        assertTrue(_vouched(digest));
        // an order one unit different is another digest
        CowSwapDecoder.Order memory other = _order(150e6, _soon());
        other.buyAmount -= 1;
        assertFalse(_vouched(settlement.digestOf(other)));

        uint256 before = weth.balanceOf(acct);
        settlement.settle(o, acct, _orderSignature(digest));
        assertEq(usd.balanceOf(acct), 10_000e6 - 150e6);
        assertEq(weth.balanceOf(acct) - before, o.buyAmount, "the proceeds are the account's");

        // not twice
        bytes memory signature = _orderSignature(digest);
        vm.expectRevert("GPv2: order filled");
        settlement.settle(o, acct, signature);
    }

    function test_order_vouchEndsWithTheOrder() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        _register(o);
        bytes32 digest = settlement.digestOf(o);
        vm.warp(o.validTo);
        assertTrue(_vouched(digest), "at validTo the venue can still fill");
        vm.warp(uint256(o.validTo) + 1);
        assertFalse(_vouched(digest));
    }

    function test_order_refusals() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());

        // the proceeds to somebody else
        o.receiver = makeAddr("the agent's own address");
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));

        // over the cap per operation
        o = _order(USD_MAX + 1, _soon());
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));

        // with a fee: outside the lowest price, the decoder's refusal
        o = _order(150e6, _soon());
        o.feeAmount = 1;
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));

        // already past its end
        o = _order(150e6, uint32(block.timestamp - 1));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));

        // a config of the agent's choosing
        o = _order(150e6, _soon());
        CowSwapDecoder.Config memory c = abi.decode(_cowConfig(), (CowSwapDecoder.Config));
        c.pairs[0].minBuy = 1;
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), abi.encode(c), abi.encode(o)))
            )
        );

        // a decoder that is not the mandate's
        CowSwapDecoder another = new CowSwapDecoder(address(settlement));
        _expectRefused(
            _tradeOp(
                _today(),
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(another), _cowConfig(), abi.encode(o)))
            )
        );

        // bytes after the arguments
        _expectRefused(_tradeOp(_today(), address(policy), 0, bytes.concat(_registerCall(o), bytes32(0))));

        // with value
        _expectRefused(_tradeOp(_today(), address(policy), 1, _registerCall(o)));

        // the control, and then the same order a second time
        _register(o);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));
        assertEq(_usdSpent(), 150e6);
    }

    /// An order may be registered only within its lifetime before its end:
    /// the policy cannot read the clock, so it says "not before" and the
    /// EntryPoint holds the operation to it.
    function test_order_notRegisteredEarlierThanItsLifetime() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, uint32(block.timestamp + LIFE + 60));
        PackedUserOperation memory op = _tradeOp(_today(), address(policy), 0, _registerCall(o));
        _expectRefused(op);
        vm.warp(block.timestamp + 60);
        _send(op);
        assertEq(_usdSpent(), 150e6);
    }

    function test_order_budgetHolds() public {
        _with(DAY);
        _register(_order(200e6, _soon()));
        _register(_order(200e6, _soon() + 1));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(101e6, _soon() + 2))));
        _register(_order(100e6, _soon() + 3));
        assertEq(_usdSpent(), USD_BUDGET);
    }

    /// The code at the decoder's address is the code the owner pinned, or
    /// nothing is registered.
    function test_order_decoderCodeIsPinned() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        bytes memory honest = address(decoder).code;
        // the same decoder built for another settlement: other immutables, other code
        CowSwapDecoder other = new CowSwapDecoder(address(new Settlement()));
        assertTrue(address(other).codehash != address(decoder).codehash);
        vm.etch(address(decoder), address(other).code);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(o)));
        vm.etch(address(decoder), honest);
        _register(o);
    }

    /// A decoder's answer is taken only in its exact form.
    function test_order_decoderAnswersAreHeldToTheirForm() public {
        _with(0);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        bytes32 digest = settlement.digestOf(o);
        bytes[5] memory answers = [
            bytes(""), // nothing, as an address without code answers
            abi.encode(address(usd), uint256(150e6), uint256(0), uint256(o.validTo)), // four words
            abi.encode(address(usd), uint256(150e6), uint256(0), uint256(o.validTo), digest, uint256(0)), // six
            abi.encode(uint256(1) << 160 | uint160(address(usd)), uint256(150e6), uint256(0), uint256(o.validTo), digest), // a dirty address
            abi.encode(address(usd), uint256(150e6), uint256(0), uint256(1) << 48, digest) // a time past 48 bits
        ];
        for (uint256 i; i < answers.length; i++) {
            CrookedDecoder crooked = new CrookedDecoder(answers[i]);
            PermissionId id = PermissionId.wrap(bytes4(uint32(0x74720000 + i)));
            _install(id, _params(0, _venues(address(crooked), address(crooked).codehash, keccak256("config"))));
            PackedUserOperation memory op = _op(
                _permissionNonce(id),
                _singleCall(
                    address(policy),
                    0,
                    abi.encodeCall(AgentPolicy.orderRegister, (address(crooked), bytes("config"), abi.encode(o)))
                )
            );
            op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
            _expectRefused(op);
        }
        // the control: the same decoder with a well-formed answer registers
        CrookedDecoder plain =
            new CrookedDecoder(abi.encode(address(usd), uint256(150e6), uint256(0), uint256(o.validTo), digest));
        PermissionId ok = PermissionId.wrap(0x74727878);
        _install(ok, _params(0, _venues(address(plain), address(plain).codehash, keccak256("config"))));
        PackedUserOperation memory good = _op(
            _permissionNonce(ok),
            _singleCall(
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.orderRegister, (address(plain), bytes("config"), abi.encode(o)))
            )
        );
        good.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(good)));
        _send(good);
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(ok)), address(usd)).spent, 150e6);
    }

    /// Only a token the mandate limits can be sold at a venue, and not one
    /// with a payee list: what is sold goes to whoever fills the order.
    function test_order_onlyALimitedTokenWithoutAPayeeList() public {
        _with(DAY);
        // a config that also lists selling WETH, which the mandate does not limit
        CowSwapDecoder.Config memory c = abi.decode(_cowConfig(), (CowSwapDecoder.Config));
        c.pairs[0] = CowSwapDecoder.Pair(address(weth), address(usd), 1, 1);
        bytes memory config = abi.encode(c);
        PermissionId id = PermissionId.wrap(0x74726434);
        _install(id, _params(0, _venues(address(decoder), address(decoder).codehash, keccak256(config))));
        CowSwapDecoder.Order memory o = _order(1 ether, _soon());
        (o.sellToken, o.buyToken, o.buyAmount) = (address(weth), address(usd), 1 ether);
        decoder.judge(acct, config, abi.encode(o)); // the decoder allows it
        _expectRefused(
            _plainOp(id, abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), config, abi.encode(o))))
        );

        // the dollar token with a payee list
        PermissionId listed = PermissionId.wrap(0x74726435);
        _install(listed, _paramsWithAPayeeList());
        _expectRefused(_plainOp(listed, _registerCall(_order(150e6, _soon()))));
    }

    function _paramsWithAPayeeList() internal view returns (bytes memory) {
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usd), USD_MAX, USD_BUDGET, bytes32(0));
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0] = _list(address(usd), PAYEE, address(0));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        AgentPolicy.Venue[] memory venues =
            _venues(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        return
            abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0), lists, uint32(0), venues);
    }

    /// An agent operation on the policy under a permission without a period.
    function _plainOp(PermissionId id, bytes memory data) internal view returns (PackedUserOperation memory op) {
        op = _op(_permissionNonce(id), _singleCall(address(policy), 0, data));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
    }

    /// The venue's own contract is out of the agent's reach under every
    /// mandate of the account, not only the one that trades there: at the
    /// settlement an order can be signed past the decoder
    /// (`setPreSignature`), and it holds the owner's allowance. A mandate
    /// that named it before it became a venue loses it, a later one is
    /// refused at install, and it stays so after the trading mandate is gone.
    function test_trading_theVenueIsNoTargetUnderAnyMandate() public {
        _world();
        PermissionId old = PermissionId.wrap(0x6f6c6431); // "old1"
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(settlement), Settlement.setPreSignature.selector);
        AgentPolicy.TokenCap[] memory noCaps = new AgentPolicy.TokenCap[](0);
        bytes memory plain = abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, noCaps, uint48(0));
        _install(old, plain);
        assertFalse(policy.venuePlace(acct, address(settlement)));

        bytes memory preSign = abi.encodeCall(Settlement.setPreSignature, (hex"01", true));
        PackedUserOperation memory op = _op(_permissionNonce(old), _singleCall(address(settlement), 0, preSign));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _send(op);

        // the account takes the settlement as a venue
        _install(
            TRD_ID, _params(DAY, _venues(address(decoder), address(decoder).codehash, keccak256(_cowConfig())))
        );
        assertTrue(policy.venuePlace(acct, address(settlement)));
        assertTrue(policy.venuePlace(acct, address(decoder)));
        assertFalse(policy.venuePlace(address(this), address(settlement)), "another account's venues are its own");

        // the older mandate still lists it, and the agent no longer reaches it
        op = _op(_permissionNonce(old), _singleCall(address(settlement), 0, preSign));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _expectRefused(op);
        // the rest of that mandate works as before
        op = _op(_permissionNonce(old), _singleCall(address(counter), 0, abi.encodeCall(Counter.increment, ())));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _send(op);

        // a new mandate that names it is refused whole
        _refusedInstall(plain);

        // and it stays out of reach when the trading mandate is revoked
        _send(_rootOp(_singleCall(acct, 0, _uninstallCall(ValidatorLib.permissionToIdentifier(TRD_ID)))));
        op = _op(_permissionNonce(old), _singleCall(address(settlement), 0, preSign));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _expectRefused(op);
    }

    function test_order_revokingEndsEveryVouch() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        _register(o);
        bytes32 digest = settlement.digestOf(o);
        assertTrue(_vouched(digest));
        _send(_rootOp(_singleCall(acct, 0, _uninstallCall(ValidatorLib.permissionToIdentifier(TRD_ID)))));
        assertFalse(_vouched(digest));
        bytes memory signature = _orderSignature(digest);
        vm.expectRevert();
        settlement.settle(o, acct, signature);
        assertEq(usd.balanceOf(acct), 10_000e6, "nothing left the account");
    }

    // --- the refund ---

    function _reclaimCall(CowSwapDecoder.Order memory o) internal view returns (bytes memory) {
        return abi.encodeCall(AgentPolicy.orderReclaim, (TRD, address(decoder), _cowConfig(), abi.encode(o)));
    }

    function test_reclaim_anUnfilledOrderAfterItsEnd() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        _register(o);

        // at validTo the venue can still fill: no refund yet
        vm.warp(o.validTo);
        vm.prank(acct);
        vm.expectRevert(AgentPolicy.OrderStillLive.selector);
        policy.orderReclaim(TRD, address(decoder), _cowConfig(), abi.encode(o));

        vm.warp(uint256(o.validTo) + 1);
        _send(_tradeOp(_today(), address(policy), 0, _reclaimCall(o)));
        assertEq(_usdSpent(), 0);
        assertEq(policy.x402Pending(acct, TRD, settlement.digestOf(o)).value, 0);

        // once
        vm.prank(acct);
        vm.expectRevert(AgentPolicy.OrderNotRegistered.selector);
        policy.orderReclaim(TRD, address(decoder), _cowConfig(), abi.encode(o));
    }

    function test_reclaim_notOfAFilledOrCancelledOrder() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        _register(o);
        settlement.settle(o, acct, _orderSignature(settlement.digestOf(o)));
        vm.warp(uint256(o.validTo) + 1);
        vm.prank(acct);
        vm.expectRevert(AgentPolicy.OrderTouched.selector);
        policy.orderReclaim(TRD, address(decoder), _cowConfig(), abi.encode(o));
        assertEq(_usdSpent(), 150e6);
    }

    function test_reclaim_onlyOfWhatWasRegistered() public {
        _with(DAY);
        CowSwapDecoder.Order memory o = _order(150e6, _soon());
        vm.warp(uint256(o.validTo) + 1);
        vm.startPrank(acct);
        vm.expectRevert(AgentPolicy.OrderNotRegistered.selector);
        policy.orderReclaim(TRD, address(decoder), _cowConfig(), abi.encode(o));
        vm.expectRevert(AgentPolicy.NotTheVenue.selector);
        policy.orderReclaim(TRD, address(settlement), _cowConfig(), abi.encode(o));
        vm.stopPrank();
    }

    // --- the budget per period ---

    function test_period_theOperationNamesItsPeriod() public {
        _with(DAY);
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // without the six bytes
        _expectRefused(_agentOpWith(AGENT, TRD_ID, address(counter), 0, inc));
        // yesterday's and tomorrow's: outside the window the EntryPoint enforces
        _expectRefused(_tradeOp(_today() - 1, address(counter), 0, inc));
        _expectRefused(_tradeOp(_today() + 1, address(counter), 0, inc));
        _send(_tradeOp(_today(), address(counter), 0, inc));
        assertEq(counter.count(), 1);
        (, uint48 seen) = policy.period(acct, TRD);
        assertEq(seen, _today() + 1);
    }

    /// The policy's own answers, asked as the account asks: a period before
    /// one already seen is refused whatever the clock, and so is anything
    /// but six bytes.
    function test_period_thePolicyRefusesAnEarlierPeriodAndOtherLengths() public {
        _with(DAY);
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        _send(_tradeOp(_today(), address(counter), 0, inc));
        PackedUserOperation memory op = _op(_permissionNonce(TRD_ID), _singleCall(address(counter), 0, inc));
        uint48 today = _today();
        vm.startPrank(acct);
        op.signature = abi.encodePacked(bytes6(today));
        assertTrue(policy.checkUserOpPolicy(TRD, op) != 1, "the control: this period");
        op.signature = abi.encodePacked(bytes6(today - 1));
        assertEq(policy.checkUserOpPolicy(TRD, op), 1, "an earlier period");
        op.signature = abi.encodePacked(bytes6(today), bytes1(0));
        assertEq(policy.checkUserOpPolicy(TRD, op), 1, "seven bytes");
        op.signature = abi.encodePacked(bytes5(0));
        assertEq(policy.checkUserOpPolicy(TRD, op), 1, "five bytes");
        op.signature = "";
        assertEq(policy.checkUserOpPolicy(TRD, op), 1, "none");
        vm.stopPrank();
    }

    function test_period_budgetsStartAfreshEachPeriod() public {
        _with(DAY);
        _register(_order(200e6, _soon()));
        _register(_order(200e6, _soon() + 1));
        _register(_order(100e6, _soon() + 2));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(1e6, _soon() + 3))));

        vm.warp((uint256(_today()) + 1) * DAY + 1 hours);
        _register(_order(200e6, _soon()));
        assertEq(_usdSpent(), 200e6, "the new period counts from nothing");

        // native value too
        vm.warp((uint256(_today()) + 1) * DAY + 1 hours);
        _send(_tradeOp(_today(), address(counter), 0.1 ether, ""));
        uint256 afterOne = _spentOf();
        vm.warp((uint256(_today()) + 1) * DAY + 1 hours);
        _send(_tradeOp(_today(), address(counter), 0.1 ether, ""));
        assertEq(_spentOf(), afterOne, "each period starts at zero");
    }

    function _spentOf() internal view returns (uint128 spent) {
        (,,,, spent,) = policy.configs(acct, TRD);
    }

    /// What an owner is told: across a boundary, up to twice the budget in a
    /// short time, and no more.
    function test_period_twiceTheBudgetAcrossABoundaryAndNoMore() public {
        _with(DAY);
        vm.warp((uint256(_today()) + 1) * DAY - 5 minutes);
        // an order ends with its period: these live for its last minutes
        _register(_order(200e6, _periodEnd()));
        _register(_order(200e6, _periodEnd() - 1));
        _register(_order(100e6, _periodEnd() - 2));
        vm.warp(block.timestamp + 6 minutes); // the next period
        _register(_order(200e6, _soon()));
        _register(_order(200e6, _soon() + 1));
        _register(_order(100e6, _soon() + 2));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(1e6, _soon() + 3))));
        // and the earlier period is closed for good
        _expectRefused(_tradeOp(_today() - 1, address(policy), 0, _registerCall(_order(1e6, _soon() + 4))));
    }

    /// What is registered under a period ends with that period. An order
    /// may be filled up to and at its `validTo`, so that is the period's last
    /// second at the latest; one second more and it could be taken in the
    /// next period, beside that period's own budget.
    function test_period_anOrderEndsWithThePeriodItIsChargedIn() public {
        _with(DAY);
        vm.warp((uint256(_today()) + 1) * DAY - 5 minutes);
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(100e6, _periodEnd() + 1))));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _registerCall(_order(100e6, _soon()))));
        _register(_order(100e6, _periodEnd()));
        assertEq(_usdSpent(), 100e6);
    }

    /// The same for x402: an authorization can be used before its
    /// `validBefore`, so that is the next period's first second at the
    /// latest. With a budget of one unit a day, a unit registered on each of
    /// three days cannot be taken together on the third: the earlier ones
    /// are over.
    function test_period_anAuthorizationEndsWithThePeriodItIsChargedIn() public {
        _world();
        usdc = new MockUSDC();
        usdc.mint(acct, 100e6);
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.x402Authorize.selector);
        (targets[1], selectors[1]) = (address(counter), Counter.increment.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usdc), 1e6, 1e6, usdc.DOMAIN_SEPARATOR());
        AgentPolicy.TokenPayees[] memory none = new AgentPolicy.TokenPayees[](0);
        AgentPolicy.Venue[] memory noVenues = new AgentPolicy.Venue[](0);
        _install(
            TRD_ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0), none, DAY, noVenues)
        );

        uint256 next = (uint256(_today()) + 1) * DAY;
        // past the period: refused, by a second and by ten days
        _expectRefused(_tradeOp(_today(), address(policy), 0, _authorizeCall(1e6, next + 1, bytes32(uint256(90)))));
        _expectRefused(_tradeOp(_today(), address(policy), 0, _authorizeCall(1e6, T0 + 10 days, bytes32(uint256(91)))));

        bytes32[3] memory digests;
        uint256[3] memory befores;
        for (uint256 day; day < 3; day++) {
            befores[day] = (uint256(_today()) + 1) * DAY; // usable to the period's last second
            digests[day] = usdc.digestOf(acct, PAYEE, 1e6, 0, befores[day], bytes32(day + 1));
            _send(_tradeOp(_today(), address(policy), 0, _authorizeCall(1e6, befores[day], bytes32(day + 1))));
            assertEq(policy.tokenLimit(acct, TRD, address(usdc)).spent, 1e6, "the day's budget is used up");
            if (day < 2) vm.warp(block.timestamp + 1 days);
        }
        uint256 taken;
        for (uint256 day; day < 3; day++) {
            bytes memory signature = abi.encodePacked(
                bytes1(0x02), PermissionId.unwrap(TRD_ID), bytes1(0xff), _sign(AGENT, _kernelWrapped(digests[day]))
            );
            try usdc.transferWithAuthorization(acct, PAYEE, 1e6, 0, befores[day], bytes32(day + 1), signature) {
                taken++;
            } catch {}
        }
        assertEq(taken, 1, "only the third day's authorization can still be used");
        assertEq(usdc.balanceOf(PAYEE), 1e6, "one day's budget left the account");
    }

    /// The period's end is noted per operation and does not leak into the
    /// next one. An operation under a mandate without a period, validated
    /// after one under a period in the same bundle, is not held to that
    /// period's end: its authorization may run for ten days.
    function test_period_theEndOfOneOperationsPeriodIsNotTheNextOperations() public {
        _world();
        usdc = new MockUSDC();
        usdc.mint(acct, 100e6);
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.x402Authorize.selector);
        (targets[1], selectors[1]) = (address(counter), Counter.increment.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usdc), 1e6, 1e6, usdc.DOMAIN_SEPARATOR());
        AgentPolicy.TokenPayees[] memory none = new AgentPolicy.TokenPayees[](0);
        AgentPolicy.Venue[] memory noVenues = new AgentPolicy.Venue[](0);
        _install(
            TRD_ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0), none, DAY, noVenues)
        );
        PermissionId plain = PermissionId.wrap(0x706c6e31); // "pln1"
        _install(plain, abi.encode(targets, selectors, MAX_VALUE, BUDGET, tradingExpiry, caps, uint48(0)));

        uint256 next = (uint256(_today()) + 1) * DAY;
        _send(_tradeOp(_today(), address(policy), 0, _authorizeCall(1e6, next, bytes32(uint256(1)))));
        _send(_plainOp(plain, _authorizeCall(1e6, T0 + 10 days, bytes32(uint256(2)))));
        assertEq(
            policy.tokenLimit(acct, bytes32(PermissionId.unwrap(plain)), address(usdc)).spent,
            1e6,
            "the mandate without a period registered its ten-day authorization"
        );
    }

    /// A refund belongs to the period of its charge: an order of yesterday,
    /// reclaimed today, gives today's budget nothing.
    function test_period_aRefundDoesNotCrossIntoTheNextPeriod() public {
        _with(DAY);
        vm.warp((uint256(_today()) + 1) * DAY - 5 minutes);
        CowSwapDecoder.Order memory old = _order(150e6, _periodEnd());
        _register(old);
        vm.warp(block.timestamp + 1 hours);
        _register(_order(200e6, _soon()));
        assertEq(_usdSpent(), 200e6);
        _send(_tradeOp(_today(), address(policy), 0, _reclaimCall(old)));
        assertEq(_usdSpent(), 200e6, "today's count is today's");
        assertEq(policy.x402Pending(acct, TRD, settlement.digestOf(old)).value, 0, "the record is gone");

        // within one period the refund does come back
        CowSwapDecoder.Order memory fresh = _order(100e6, _soon());
        _register(fresh);
        vm.warp(uint256(fresh.validTo) + 1);
        _send(_tradeOp(_today(), address(policy), 0, _reclaimCall(fresh)));
        assertEq(_usdSpent(), 200e6);
    }

    /// A mandate without a period is as before: one budget for its life, and
    /// no bytes of the policy's in the signature.
    function test_period_noneMeansOneBudgetForLife() public {
        _with(0);
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        _send(_agentOpWith(AGENT, TRD_ID, address(counter), 0, inc));
        PackedUserOperation memory op =
            _op(_permissionNonce(TRD_ID), _singleCall(address(policy), 0, _registerCall(_order(200e6, _soon()))));
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _send(op);
        vm.warp(block.timestamp + 3 days);
        assertEq(_usdSpent(), 200e6);
        (uint32 seconds_,) = policy.period(acct, TRD);
        assertEq(seconds_, 0);
    }
}
