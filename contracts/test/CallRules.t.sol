// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TradingTest} from "./Trading.t.sol";
import {MockToken} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, CallType} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// What these tests need of a token that is not a mock.
interface IERC20ForRules {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

/// A lending pool's two functions with a beneficiary argument, as Aave V3's
/// pool has them: a supply pulls from the caller and credits `onBehalfOf`; a
/// withdrawal takes from the caller's credit and pays `to`. `PoolForkTest`
/// runs against Aave's own pool.
contract PoolStandIn {
    mapping(address => mapping(address => uint256)) public credit;
    uint256 public limit;
    uint256 public claims;

    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        MockToken(asset).transferFrom(msg.sender, address(this), amount);
        credit[asset][onBehalfOf] += amount;
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        credit[asset][msg.sender] -= amount;
        MockToken(asset).transfer(to, amount);
        return amount;
    }

    function setLimit(uint256 limit_) external {
        limit = limit_;
    }

    function claim() external {
        claims++;
    }

    /// A function the owner did not list.
    function borrow(address asset, uint256 amount) external {
        MockToken(asset).transfer(msg.sender, amount);
    }
}

/// The rules these tests use, for a pool and one asset.
library PoolRules {
    bytes4 internal constant SUPPLY = 0x617ba037; // supply(address,uint256,address,uint16)
    bytes4 internal constant WITHDRAW = 0x69328dec; // withdraw(address,uint256,address)

    function word(uint8 kind, uint256 value) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(kind, value);
    }

    /// `supply(asset, amount, onBehalfOf, referral)`: this asset, the amount charged in it, for the account, no referral.
    function supply(address asset) internal pure returns (CallRulesDecoder.Function memory f) {
        f.selector = SUPPLY;
        f.words = new CallRulesDecoder.Word[](4);
        f.words[0] = word(1, uint256(uint160(asset)));
        f.words[1] = word(3, uint256(uint160(asset)));
        f.words[2] = word(0, 0);
        f.words[3] = word(1, 0);
    }

    /// `withdraw(asset, amount, to)`: this asset, any amount, to the account.
    function withdraw(address asset) internal pure returns (CallRulesDecoder.Function memory f) {
        f.selector = WITHDRAW;
        f.words = new CallRulesDecoder.Word[](3);
        f.words[0] = word(1, uint256(uint160(asset)));
        f.words[1] = word(4, 0);
        f.words[2] = word(0, 0);
    }
}

/// The decoder alone: what it answers, and what it refuses.
contract CallRulesDecoderTest is Test {
    MockToken internal usd;
    PoolStandIn internal pool;
    CallRulesDecoder internal decoder;
    address internal constant ACCOUNT = address(0xACC0);

    function setUp() public {
        usd = new MockToken();
        pool = new PoolStandIn();
        decoder = new CallRulesDecoder(address(pool), address(pool));
    }

    /// Four functions: the supply and the withdrawal, a bounded setter, and one without arguments.
    function _functions() internal view returns (CallRulesDecoder.Function[] memory fs) {
        fs = new CallRulesDecoder.Function[](4);
        fs[0] = PoolRules.supply(address(usd));
        fs[1] = PoolRules.withdraw(address(usd));
        fs[2].selector = PoolStandIn.setLimit.selector;
        fs[2].words = new CallRulesDecoder.Word[](1);
        fs[2].words[0] = PoolRules.word(2, 100);
        fs[3].selector = PoolStandIn.claim.selector;
    }

    function _config() internal view returns (bytes memory) {
        return abi.encode(CallRulesDecoder.Config(_functions()));
    }

    function _supply(address asset, uint256 amount, address onBehalfOf, uint256 referral)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(PoolRules.SUPPLY, asset, amount, onBehalfOf, referral);
    }

    /// Asked through a call of its own, so that an expected revert is the decoder's.
    function judge(bytes memory config, bytes memory call)
        external
        view
        returns (address token, uint256 amount, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        return decoder.judge(ACCOUNT, config, call);
    }

    function test_rules_aCallThatPassesEveryRule() public view {
        bytes memory call = _supply(address(usd), 100e6, ACCOUNT, 0);
        (address token, uint256 amount, uint48 notBefore, uint48 validTo, bytes32 digest) = this.judge(_config(), call);
        assertEq(token, address(usd), "the token charged");
        assertEq(amount, 100e6, "the amount charged is the charged word");
        assertEq(notBefore, 0);
        assertEq(validTo, 0, "no end: a call, not an order");
        // the call's hash: no value, and the calldata as it was handed over
        assertEq(digest, keccak256(abi.encode(uint256(0), keccak256(call))));
        // a function that charges nothing
        bytes memory out = abi.encodeWithSelector(PoolRules.WITHDRAW, address(usd), type(uint256).max, ACCOUNT);
        (token, amount,,, digest) = this.judge(_config(), out);
        assertEq(token, address(0));
        assertEq(amount, 0);
        assertEq(digest, keccak256(abi.encode(uint256(0), keccak256(out))));
        // a function without arguments is its selector alone
        (,,,, digest) = this.judge(_config(), abi.encodeCall(PoolStandIn.claim, ()));
        assertEq(digest, keccak256(abi.encode(uint256(0), keccak256(abi.encodeCall(PoolStandIn.claim, ())))));
    }

    /// One config and one call, with the bytes written out: the CLI and the
    /// phone's core build the config from their own code and are held to
    /// these bytes (`mobile/owner-core/src/kernel.rs`,
    /// `a_rules_config_is_the_decoders`).
    function test_rules_theRecordedConfig() public view {
        address asset = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](2);
        fs[0] = PoolRules.supply(asset);
        fs[1] = PoolRules.withdraw(asset);
        bytes memory config = abi.encode(CallRulesDecoder.Config(fs));
        assertEq(
            config,
            hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001a0617ba03700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000003000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000069328dec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "the config"
        );
        bytes memory call = _supply(asset, 100e6, 0x1111111111111111111111111111111111111111, 0);
        assertEq(
            call,
            hex"617ba037000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f5e10000000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000",
            "the call"
        );
        (,,,, bytes32 digest) = decoder.judge(0x1111111111111111111111111111111111111111, config, call);
        assertEq(digest, 0x607f2975b8dddb42774a6aedddf7168667808e32e98f70f542b9c8ff6405d295, "the call's hash");
    }

    /// Each kind of rule, at its boundary.
    function test_rules_eachWordIsHeldToItsRule() public {
        address other = address(0xBEEF);
        // the word is the account: anybody else, and the account's address with a bit above it
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 2));
        this.judge(_config(), _supply(address(usd), 100e6, other, 0));
        bytes memory dirty = abi.encodeWithSelector(
            PoolRules.SUPPLY, address(usd), uint256(100e6), uint256(uint160(ACCOUNT)) | (1 << 160), uint256(0)
        );
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 2));
        this.judge(_config(), dirty);
        // the word is a value the owner set: another asset, another referral
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 0));
        this.judge(_config(), _supply(other, 100e6, ACCOUNT, 0));
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 3));
        this.judge(_config(), _supply(address(usd), 100e6, ACCOUNT, 1));
        // the word is at most a bound: at it, and one over
        this.judge(_config(), abi.encodeCall(PoolStandIn.setLimit, (100)));
        this.judge(_config(), abi.encodeCall(PoolStandIn.setLimit, (0)));
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 0));
        this.judge(_config(), abi.encodeCall(PoolStandIn.setLimit, (101)));
        // the word is the agent's: anything
        this.judge(_config(), abi.encodeWithSelector(PoolRules.WITHDRAW, address(usd), 0, ACCOUNT));
        this.judge(_config(), abi.encodeWithSelector(PoolRules.WITHDRAW, address(usd), 12345, ACCOUNT));
        // and the withdrawal's beneficiary is the account
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.WordRefused.selector, 2));
        this.judge(_config(), abi.encodeWithSelector(PoolRules.WITHDRAW, address(usd), 1, other));
    }

    /// A listed selector, and exactly as many words as its rules.
    function test_rules_theCallIsItsFunctionsShape() public {
        bytes memory call = _supply(address(usd), 100e6, ACCOUNT, 0);
        // a function that is not listed
        vm.expectRevert(
            abi.encodeWithSelector(CallRulesDecoder.FunctionNotListed.selector, PoolStandIn.borrow.selector)
        );
        this.judge(_config(), abi.encodeCall(PoolStandIn.borrow, (address(usd), 1)));
        // a word more, a byte more, a word less
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.NotTheFunctionsLength.selector, call.length + 32));
        this.judge(_config(), bytes.concat(call, bytes32(0)));
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.NotTheFunctionsLength.selector, call.length + 1));
        this.judge(_config(), bytes.concat(call, hex"00"));
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.NotTheFunctionsLength.selector, call.length - 32));
        this.judge(_config(), abi.encodeWithSelector(PoolRules.SUPPLY, address(usd), uint256(100e6), ACCOUNT));
        // the selector alone, for a function with words; and words, for a function without
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.NotTheFunctionsLength.selector, 4));
        this.judge(_config(), abi.encodePacked(PoolRules.SUPPLY));
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.NotTheFunctionsLength.selector, 36));
        this.judge(_config(), abi.encodeWithSelector(PoolStandIn.claim.selector, uint256(1)));
        // less than a selector
        vm.expectRevert(CallRulesDecoder.NotACall.selector);
        this.judge(_config(), hex"617ba0");
        vm.expectRevert(CallRulesDecoder.NotACall.selector);
        this.judge(_config(), "");
    }

    /// A config that does not hold as a list of rules allows nothing, whether or not `checkConfig` was asked.
    function test_rules_aBrokenConfigAllowsNothing() public {
        bytes memory call = _supply(address(usd), 100e6, ACCOUNT, 0);
        CallRulesDecoder.Function[] memory fs = _functions();
        // the function listed twice, the second time with looser rules
        CallRulesDecoder.Function[] memory twice = new CallRulesDecoder.Function[](2);
        twice[0] = PoolRules.supply(address(usd));
        twice[1] = PoolRules.supply(address(usd));
        twice[1].words[2] = PoolRules.word(4, 0);
        vm.expectRevert(CallRulesDecoder.FunctionListedTwice.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(twice)), call);
        // a kind it does not know
        fs[0].words[3] = PoolRules.word(5, 0);
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        // a value where the kind reads none: on "the account", and on "anything"
        fs = _functions();
        fs[0].words[2] = PoolRules.word(0, 1);
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        fs = _functions();
        fs[0].words[3] = PoolRules.word(4, 7);
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        // two charged words, a charge in no token, a charge in a word wider than an address
        fs = _functions();
        fs[0].words[3] = PoolRules.word(3, uint256(uint160(address(usd))));
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        fs = _functions();
        fs[0].words[1] = PoolRules.word(3, 0);
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        fs = _functions();
        fs[0].words[1] = PoolRules.word(3, uint256(uint160(address(usd))) | (1 << 160));
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(fs)), call);
        // nine functions, and seventeen words
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(_many(9))), call);
        CallRulesDecoder.Function[] memory wide = new CallRulesDecoder.Function[](1);
        wide[0].selector = PoolRules.SUPPLY;
        wide[0].words = new CallRulesDecoder.Word[](17);
        for (uint256 i; i < 17; i++) {
            wide[0].words[i] = PoolRules.word(4, 0);
        }
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        this.judge(abi.encode(CallRulesDecoder.Config(wide)), abi.encodePacked(PoolRules.SUPPLY, new bytes(17 * 32)));
        // no functions
        vm.expectRevert(abi.encodeWithSelector(CallRulesDecoder.FunctionNotListed.selector, PoolRules.SUPPLY));
        this.judge(abi.encode(CallRulesDecoder.Config(new CallRulesDecoder.Function[](0))), call);
    }

    /// `n` functions, the supply first and the others with selectors of their own.
    function _many(uint256 n) internal view returns (CallRulesDecoder.Function[] memory fs) {
        fs = new CallRulesDecoder.Function[](n);
        fs[0] = PoolRules.supply(address(usd));
        for (uint256 i = 1; i < n; i++) {
            fs[i].selector = bytes4(uint32(0x1000 + i));
        }
    }

    function test_rules_checkConfig() public {
        assertTrue(decoder.checkConfig(_config()));
        assertTrue(decoder.checkConfig(abi.encode(CallRulesDecoder.Config(_many(8)))));
        // none, and nine
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(CallRulesDecoder.Config(new CallRulesDecoder.Function[](0))));
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(CallRulesDecoder.Config(_many(9))));
        // a function twice
        CallRulesDecoder.Function[] memory fs = _functions();
        fs[3].selector = PoolRules.SUPPLY;
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(CallRulesDecoder.Config(fs)));
        // seventeen words; sixteen pass
        fs = _functions();
        fs[3].words = new CallRulesDecoder.Word[](17);
        for (uint256 i; i < 17; i++) {
            fs[3].words[i] = PoolRules.word(4, 0);
        }
        vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
        decoder.checkConfig(abi.encode(CallRulesDecoder.Config(fs)));
        fs[3].words = new CallRulesDecoder.Word[](16);
        for (uint256 i; i < 16; i++) {
            fs[3].words[i] = PoolRules.word(4, 0);
        }
        assertTrue(decoder.checkConfig(abi.encode(CallRulesDecoder.Config(fs))));
        // an unknown kind; a value where none belongs, on each of the two kinds
        CallRulesDecoder.Word[3] memory bad = [PoolRules.word(5, 0), PoolRules.word(0, 1), PoolRules.word(4, 1)];
        for (uint256 i; i < bad.length; i++) {
            fs = _functions();
            fs[0].words[3] = bad[i];
            vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
            decoder.checkConfig(abi.encode(CallRulesDecoder.Config(fs)));
        }
        // a charge: twice, in no token, in a word wider than an address, in an address without code
        uint256[4] memory charges = [
            uint256(uint160(address(usd))),
            0,
            uint256(uint160(address(usd))) | (1 << 160),
            uint256(uint160(address(0xDEAD)))
        ];
        for (uint256 i; i < charges.length; i++) {
            fs = _functions();
            // the first case adds a second charged word; the others replace the one there is
            fs[0].words[i == 0 ? 3 : 1] = PoolRules.word(3, charges[i]);
            vm.expectRevert(CallRulesDecoder.InvalidConfig.selector);
            decoder.checkConfig(abi.encode(CallRulesDecoder.Config(fs)));
        }
    }

    /// Deployed through a call of its own, so that the revert is the constructor's.
    function build(address venue, address spender) external returns (CallRulesDecoder) {
        return new CallRulesDecoder(venue, spender);
    }

    function test_rules_theVenueAndTheSpenderHaveCode() public {
        vm.expectRevert(CallRulesDecoder.NotAContract.selector);
        this.build(address(0xDEAD), address(pool));
        vm.expectRevert(CallRulesDecoder.NotAContract.selector);
        this.build(address(pool), address(0xDEAD));
        vm.expectRevert(CallRulesDecoder.NotAContract.selector);
        this.build(address(0), address(0));
        CallRulesDecoder d = this.build(address(pool), address(usd));
        assertEq(d.venue(), address(pool));
        assertEq(d.spender(), address(usd));
    }

    function test_rules_whatItIs() public view {
        assertEq(decoder.venue(), address(pool));
        assertEq(decoder.spender(), address(pool));
        assertEq(decoder.VERSION(), "0.1.0");
        assertEq(decoder.MAX_FUNCTIONS(), 8);
        assertEq(decoder.MAX_WORDS(), 16);
        assertFalse(decoder.untouched(ACCOUNT, _supply(address(usd), 1, ACCOUNT, 0)));
    }

    /// The policy gives a decoder at most 150,000 gas: a config at both limits is judged within it.
    function test_rules_aConfigAtTheLimitsIsJudgedWithinTheGasBound() public {
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](8);
        bytes memory call;
        for (uint256 i; i < 8; i++) {
            fs[i].selector = bytes4(uint32(0x2000 + i));
            fs[i].words = new CallRulesDecoder.Word[](16);
            for (uint256 k; k < 16; k++) {
                fs[i].words[k] = PoolRules.word(1, k);
            }
        }
        // the last function, so that every entry is read before it is found
        for (uint256 k; k < 16; k++) {
            call = bytes.concat(call, bytes32(k));
        }
        call = bytes.concat(bytes4(uint32(0x2007)), call);
        bytes memory config = abi.encode(CallRulesDecoder.Config(fs));
        uint256 before = gasleft();
        decoder.judge(ACCOUNT, config, call);
        uint256 used = before - gasleft();
        emit log_named_uint("gas for a config at the limits", used);
        assertLt(used, 150_000, "over the policy's gas bound for a decoder");
    }

    /// For any four words: the supply passes exactly when its three fixed
    /// words are what the rules say, and it is then charged the second word.
    function testFuzz_rules_acceptedMeansEveryRuleHolds(uint256 w0, uint256 w1, uint256 w2, uint256 w3, uint8 fix)
        public
        view
    {
        // steer a share of the runs onto the accepted values, one word at a time
        if (fix & 1 != 0) w0 = uint256(uint160(address(usd)));
        if (fix & 2 != 0) w2 = uint256(uint160(ACCOUNT));
        if (fix & 4 != 0) w3 = 0;
        bytes memory call = abi.encodeWithSelector(PoolRules.SUPPLY, w0, w1, w2, w3);
        bool expected = w0 == uint256(uint160(address(usd))) && w2 == uint256(uint160(ACCOUNT)) && w3 == 0;
        try this.judge(_config(), call) returns (address token, uint256 amount, uint48, uint48, bytes32 digest) {
            assertTrue(expected, "a call that breaks a rule passes");
            assertEq(token, address(usd));
            assertEq(amount, w1);
            assertEq(digest, keccak256(abi.encode(uint256(0), keccak256(call))));
        } catch {
            assertFalse(expected, "a call within every rule is refused");
        }
    }
}

/// Calls at a pool under a mandate (issue #80): the agent registers a call,
/// the policy asks `CallRulesDecoder`, and the leg after the registration is
/// that call and no other. The owner approved the pool for the supplied
/// token; a supply is charged like an order.
contract CallRulesTradingTest is TradingTest {
    PoolStandIn internal pool;
    CallRulesDecoder internal rules;

    function _withRules() internal {
        _world();
        pool = new PoolStandIn();
        rules = new CallRulesDecoder(address(pool), address(pool));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](2);
        v[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(_cowConfig()));
        v[1] = AgentPolicy.Venue(address(rules), address(rules).codehash, keccak256(_rulesConfig()));
        _install(TRD_ID, _params(DAY, v));
        // the owner's allowance to the pool, bounded by the budget
        vm.prank(acct);
        usd.approve(address(pool), USD_BUDGET);
    }

    /// The supply and the withdrawal of the dollar token, for the account only.
    function _rulesConfig() internal view returns (bytes memory) {
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](2);
        fs[0] = PoolRules.supply(address(usd));
        fs[1] = PoolRules.withdraw(address(usd));
        return abi.encode(CallRulesDecoder.Config(fs));
    }

    function _supply(uint256 amount, address onBehalfOf) internal view returns (bytes memory) {
        return abi.encodeWithSelector(PoolRules.SUPPLY, address(usd), amount, onBehalfOf, uint256(0));
    }

    function _withdraw(uint256 amount, address to) internal view returns (bytes memory) {
        return abi.encodeWithSelector(PoolRules.WITHDRAW, address(usd), amount, to);
    }

    /// A call's registration and the call, as two legs.
    function _legs(bytes memory call) internal view returns (Execution[] memory legs) {
        return _legsOf(call, call);
    }

    /// The registration of one call, and another as the leg after it.
    function _legsOf(bytes memory registered, bytes memory made) internal view returns (Execution[] memory legs) {
        legs = new Execution[](2);
        legs[0] = Execution(
            address(policy), 0, abi.encodeCall(AgentPolicy.orderRegister, (address(rules), _rulesConfig(), registered))
        );
        legs[1] = Execution(address(pool), 0, made);
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

    function test_poolRules_suppliedForTheAccountAndWithdrawnToIt() public {
        _withRules();
        uint256 before = usd.balanceOf(acct);
        _send(_batch(_legs(_supply(100e6, acct))));
        assertEq(usd.balanceOf(acct), before - 100e6);
        assertEq(pool.credit(address(usd), acct), 100e6, "credited to the account");
        // charged like an order, and out of the owner's allowance
        assertEq(_usdSpent(), 100e6);
        assertEq(usd.allowance(acct, address(pool)), USD_BUDGET - 100e6);
        // a withdrawal to the account: nothing is charged, and nothing is given back
        _send(_batch(_legs(_withdraw(40e6, acct))));
        assertEq(usd.balanceOf(acct), before - 60e6);
        assertEq(pool.credit(address(usd), acct), 60e6);
        assertEq(_usdSpent(), 100e6);
    }

    /// The beneficiary is the account: a supply for somebody else and a
    /// withdrawal to somebody else are refused.
    function test_poolRules_theBeneficiaryIsTheAccount() public {
        _withRules();
        address thief = makeAddr("thief");
        _send(_batch(_legs(_supply(100e6, acct))));
        // for somebody else: refused at the registration
        _expectRefused(_batch(_legs(_supply(100e6, thief))));
        _expectRefused(_batch(_legs(_withdraw(40e6, thief))));
        // registered for the account and made for somebody else: refused at the pairing
        _expectRefused(_batch(_legsOf(_supply(100e6, acct), _supply(100e6, thief))));
        _expectRefused(_batch(_legsOf(_withdraw(40e6, acct), _withdraw(40e6, thief))));
        // registered as a small supply and made as a large one
        _expectRefused(_batch(_legsOf(_supply(1e6, acct), _supply(100e6, acct))));
        assertEq(pool.credit(address(usd), thief), 0);
        assertEq(usd.balanceOf(thief), 0);
        assertEq(pool.credit(address(usd), acct), 100e6);
        assertEq(_usdSpent(), 100e6);
    }

    function test_poolRules_whatIsNotListedIsRefused() public {
        _withRules();
        usd.mint(address(pool), 1_000e6);
        // a function the owner did not list
        _expectRefused(_batch(_legs(abi.encodeCall(PoolStandIn.borrow, (address(usd), 100e6)))));
        // another asset
        bytes memory other = abi.encodeWithSelector(PoolRules.SUPPLY, address(weth), uint256(1), acct, uint256(0));
        _expectRefused(_batch(_legs(other)));
        // a referral code
        bytes memory referred = abi.encodeWithSelector(PoolRules.SUPPLY, address(usd), uint256(1e6), acct, uint256(7));
        _expectRefused(_batch(_legs(referred)));
        // the pool by itself, without a registration
        _expectRefused(_tradeOp(_today(), address(pool), 0, _supply(100e6, acct)));
        // with native value
        vm.deal(acct, 1 ether);
        Execution[] memory legs = _legs(_withdraw(0, acct));
        legs[1].value = 1;
        _expectRefused(_batch(legs));
        assertEq(_usdSpent(), 0);
    }

    /// The amount supplied is held to the token's cap per operation and to
    /// its budget, which the venues share.
    function test_poolRules_heldToTheCapAndTheBudget() public {
        _withRules();
        _expectRefused(_batch(_legs(_supply(USD_MAX + 1, acct))));
        _send(_batch(_legs(_supply(USD_MAX, acct))));
        // a CoW order on the same budget
        _register(_order(200e6, _soon()));
        assertEq(_usdSpent(), 400e6);
        _expectRefused(_batch(_legs(_supply(100e6 + 1, acct))));
        _send(_batch(_legs(_supply(100e6, acct))));
        assertEq(_usdSpent(), USD_BUDGET);
        _expectRefused(_batch(_legs(_supply(1, acct))));
        // a withdrawal is charged nothing, so it still passes
        _send(_batch(_legs(_withdraw(300e6, acct))));
        assertEq(pool.credit(address(usd), acct), 0);
    }

    /// The pool is the venue's own contract and its spender: a mandate that names it as a target is refused.
    function test_poolRules_thePoolIsNotATarget() public {
        _world();
        pool = new PoolStandIn();
        rules = new CallRulesDecoder(address(pool), address(pool));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(address(rules), address(rules).codehash, keccak256(_rulesConfig()));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        (targets[2], selectors[2]) = (address(pool), PoolRules.SUPPLY);
        _refusedInstall(_paramsFor(targets, selectors, DAY, v));
    }
}

/// The same against Aave V3's pool on Base Sepolia, by the pool's functions
/// that name a beneficiary: what the allow-list cannot hold, the rules do.
///
///     FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> \
///         forge test --evm-version osaka --match-contract PoolForkTest
///
/// Skipped without the variable: CI has no RPC.
contract PoolForkTest is TradingTest {
    address internal constant POOL = 0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27;
    IERC20ForRules internal constant USDC = IERC20ForRules(0xba50Cd2A20f6DA35D788639E581bca8d0B5d4D5f);
    uint128 internal constant USDC_MAX = 100e6;
    uint128 internal constant USDC_BUDGET = 300e6;

    CallRulesDecoder internal rules;
    IERC20ForRules internal aUsdc;

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
        // the reserve's aToken, as the pool has it: word 8 of `getReserveData`
        (bool ok, bytes memory data) =
            POOL.staticcall(abi.encodeWithSignature("getReserveData(address)", address(USDC)));
        require(ok && data.length >= 15 * 32, "the pool does not answer getReserveData");
        uint256[15] memory words = abi.decode(data, (uint256[15]));
        aUsdc = IERC20ForRules(address(uint160(words[8])));
        // the mandate: a cap on the test dollar, and the pool as a venue of two functions
        rules = new CallRulesDecoder(POOL, POOL);
        assertTrue(rules.checkConfig(_rulesConfig()));
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(USDC), USDC_MAX, USDC_BUDGET, bytes32(0));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(address(rules), address(rules).codehash, keccak256(_rulesConfig()));
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
        deal(address(USDC), acct, 1_000e6);
        // the owner's allowance to the pool, bounded by the budget
        vm.prank(acct);
        USDC.approve(POOL, USDC_BUDGET);
        return true;
    }

    function _rulesConfig() internal pure returns (bytes memory) {
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](2);
        fs[0] = PoolRules.supply(address(USDC));
        fs[1] = PoolRules.withdraw(address(USDC));
        return abi.encode(CallRulesDecoder.Config(fs));
    }

    function _supply(uint256 amount, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(PoolRules.SUPPLY, address(USDC), amount, onBehalfOf, uint256(0));
    }

    function _withdraw(uint256 amount, address to) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(PoolRules.WITHDRAW, address(USDC), amount, to);
    }

    function _legs(bytes memory call) internal view returns (Execution[] memory legs) {
        legs = new Execution[](2);
        legs[0] = Execution(
            address(policy), 0, abi.encodeCall(AgentPolicy.orderRegister, (address(rules), _rulesConfig(), call))
        );
        legs[1] = Execution(POOL, 0, call);
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

    function _spent() internal view returns (uint256) {
        return policy.tokenLimit(acct, TRD, address(USDC)).spent;
    }

    /// The agent supplies by the form that names a beneficiary, and withdraws by the form that names a receiver.
    function test_fork_suppliedForTheAccountAndWithdrawnToIt() public {
        if (!_onBaseSepolia()) return;
        uint256 before = USDC.balanceOf(acct);
        _send(_batch(_legs(_supply(100e6, acct))));
        assertEq(USDC.balanceOf(acct), before - 100e6);
        assertApproxEqAbs(aUsdc.balanceOf(acct), 100e6, 2, "the aTokens are the account's");
        assertEq(_spent(), 100e6);
        assertEq(USDC.allowance(acct, POOL), USDC_BUDGET - 100e6);
        _send(_batch(_legs(_withdraw(40e6, acct))));
        assertEq(USDC.balanceOf(acct), before - 60e6);
        assertEq(_spent(), 100e6, "a withdrawal is charged nothing and gives nothing back");
    }

    /// What the allow-list could not hold: the same two functions, for anybody else.
    function test_fork_theBeneficiaryIsTheAccount() public {
        if (!_onBaseSepolia()) return;
        address thief = makeAddr("thief");
        _send(_batch(_legs(_supply(100e6, acct))));
        _expectRefused(_batch(_legs(_supply(100e6, thief))));
        _expectRefused(_batch(_legs(_withdraw(40e6, thief))));
        // a borrow, which is not listed
        bytes memory borrow =
            abi.encodeWithSignature("borrow(address,uint256,uint256,uint16,address)", address(USDC), 1e6, 2, 0, acct);
        _expectRefused(_batch(_legs(borrow)));
        // over the cap per operation
        _expectRefused(_batch(_legs(_supply(uint256(USDC_MAX) + 1, acct))));
        assertEq(aUsdc.balanceOf(thief), 0);
        assertEq(USDC.balanceOf(thief), 0);
        assertEq(_spent(), 100e6);
    }

    /// Why the beneficiary is held: the pool credits whoever the caller names.
    function test_real_thePoolCreditsWhoeverIsNamed() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("other");
        vm.prank(acct);
        (bool ok,) = POOL.call(_supply(10e6, other));
        assertTrue(ok);
        assertApproxEqAbs(aUsdc.balanceOf(other), 10e6, 2, "credited to the named address");
        assertEq(aUsdc.balanceOf(acct), 0);
    }

    /// Why the allowance may stand: the pool takes a supply from its caller only.
    function test_real_thePoolTakesFromItsCallerOnly() public {
        if (!_onBaseSepolia()) return;
        address stranger = makeAddr("stranger");
        uint256 before = USDC.balanceOf(acct);
        vm.prank(stranger);
        (bool ok,) = POOL.call(_supply(10e6, stranger));
        assertFalse(ok, "a stranger's supply does not spend the account's allowance");
        assertEq(USDC.balanceOf(acct), before);
        assertEq(USDC.allowance(acct, POOL), USDC_BUDGET);
    }
}
