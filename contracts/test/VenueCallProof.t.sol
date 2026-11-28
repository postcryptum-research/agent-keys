// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeShapes} from "../src/judges/SafeShapes.sol";
import {VenueCalls} from "../src/venues/VenueCalls.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {ExecMode} from "kernel/src/types/Types.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {Vm} from "forge-std/Vm.sol";
import {Acct, Recorder} from "./BudgetProof.t.sol";

/// A decoder that judges nothing: its "order" says what to answer. With it
/// the proofs below are of the policy's own rule, whatever a decoder says.
/// The call it names is always `CALL` (four fixed bytes); the order carries
/// the call's value and the price the decoder puts on it.
contract Answers {
    address public immutable venue;
    address public immutable spender;
    address internal immutable PRICED_IN;

    constructor(address place, address token) {
        (venue, spender, PRICED_IN) = (place, place, token);
    }

    /// `order` is `abi.encode(value, price)`: a call of `CALL` with `value`,
    /// charged `price` of the token. No end: a call, not an order.
    function judge(address, bytes calldata, bytes calldata order)
        external
        view
        returns (address, uint256, uint48, uint48, bytes32)
    {
        (uint256 value, uint256 price) = abi.decode(order, (uint256, uint256));
        return (PRICED_IN, price, 0, 0, VenueCalls.digest(value, hex"18178358"));
    }
}

/// Symbolic proofs of the rule that admits a call a venue's decoder judged
/// (issue #80, #225), proven with Kontrol like the budget's
/// (`BudgetProof.t.sol`, whose header says how to run them; this file goes
/// into `test/` beside that one).
///
/// What is proven, each for every value of its symbolic amounts:
///
/// - the native value of a call a decoder judged is counted like any leg's:
///   accepted only within the cap per operation, booked exactly;
/// - the price a decoder puts on a call is charged like an order's: accepted
///   only within the token's cap per operation, booked exactly;
/// - the leg after a registration is the registered call: with another
///   value than the one registered, the operation is refused;
/// - a registration without its call is refused: as the last leg of a
///   batch, and as a single call.
///
/// SCOPE. The decoder here answers what its order says, so nothing is proven
/// of any real decoder's judgment. The call's calldata and target are fixed;
/// its value and its price are symbolic. That the hash binds the target and
/// the calldata is held by the tests (`VenueCallPairing.t.sol`), not here:
/// those are of fixed shapes, not amounts. The third proof rests on the
/// prover's treatment of the hash as collision-free.
contract VenueCallProof {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    AgentPolicy internal policy;
    Acct internal acct;
    address internal token;
    address internal place;
    Answers internal decoder;

    address internal constant NONCE_ASSERT = 0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279;
    bytes32 internal constant ID = bytes32(bytes4(0x76656e75));
    bytes internal constant CONFIG = "the owner's config";
    bytes internal constant CALL = hex"18178358";
    // As in the budget's proofs: each budget is reachable within two operations.
    uint128 internal constant A_MAX = 100;
    uint128 internal constant A_BUDGET = 150;
    uint128 internal constant MAX_VALUE = 1 ether;
    uint128 internal constant BUDGET = 1.5 ether;
    uint48 internal constant UNTIL = type(uint48).max;
    // A mandate with venues has a budget period; every operation here names the same one.
    uint32 internal constant PERIOD = 1 days;
    uint48 internal constant INDEX = 20_000;

    function setUp() public {
        policy = new AgentPolicy(NONCE_ASSERT);
        acct = new Acct();
        token = address(new Recorder());
        place = address(new Recorder());
        decoder = new Answers(place, token);
        vm.deal(address(acct), 10 ether);
        // One mandate: the policy's registration on the allow-list, a token
        // with a cap and a budget, a native cap and budget, a period, and
        // one venue. The venue's own contract is on no allow-list.
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.orderRegister.selector);
        AgentPolicy.TokenCap[] memory tokens = new AgentPolicy.TokenCap[](1);
        tokens[0] = AgentPolicy.TokenCap(token, A_MAX, A_BUDGET, bytes32(0));
        AgentPolicy.Venue[] memory venues = new AgentPolicy.Venue[](1);
        venues[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(CONFIG));
        bytes memory data = abi.encodePacked(
            ID,
            abi.encode(
                targets,
                selectors,
                MAX_VALUE,
                BUDGET,
                UNTIL,
                tokens,
                uint48(0),
                new AgentPolicy.TokenPayees[](0),
                PERIOD,
                venues
            )
        );
        acct.install(policy, data);
    }

    // --- building one fixed-shape operation, symbolic leaves only ---

    function _op(ExecMode mode, bytes memory executionData) internal pure returns (PackedUserOperation memory op) {
        op.callData = abi.encodeWithSelector(Kernel.execute.selector, mode, executionData);
        // gas fields zero, as in the budget's proofs: only value and price are charged
        op.accountGasLimits = bytes32(0);
        op.gasFees = bytes32(0);
        // the policy's part of the signature: the period the operation names
        op.signature = abi.encodePacked(bytes6(INDEX));
    }

    function _batch(Execution[] memory legs) internal pure returns (PackedUserOperation memory) {
        return _op(ExecMode.wrap(bytes32(uint256(1) << 248)), ExecLib.encodeBatch(legs));
    }

    /// The registration of `CALL` with `value`, priced `price`.
    function _register(uint256 value, uint256 price) internal view returns (Execution memory) {
        return Execution(
            address(policy),
            0,
            abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), CONFIG, abi.encode(value, price)))
        );
    }

    /// A registration and the leg after it: `CALL` at the venue, with `made` as its value.
    function _pair(uint256 value, uint256 price, uint256 made) internal view returns (PackedUserOperation memory) {
        Execution[] memory legs = new Execution[](2);
        (legs[0], legs[1]) = (_register(value, price), Execution(place, made, CALL));
        return _batch(legs);
    }

    /// As the EntryPoint handles a refusal: the bundle reverts, and with it
    /// whatever the policy booked. Returns 1 for refused.
    function _validate(PackedUserOperation memory op) internal returns (uint256) {
        try this.validateAsEntryPoint(op) returns (uint256 r) {
            return r;
        } catch {
            return 1;
        }
    }

    function validateAsEntryPoint(PackedUserOperation calldata op) external returns (uint256 r) {
        r = acct.validate(policy, ID, op);
        require(r != 1, "AA24 signature error");
    }

    function _tokenSpent() internal view returns (uint128) {
        return policy.tokenLimit(address(acct), ID, token).spent;
    }

    function _nativeSpent() internal view returns (uint128) {
        (,,,, uint128 spent,) = policy.configs(address(acct), ID);
        return spent;
    }

    // --- the proofs ---

    /// The native value of a call a decoder judged: accepted only within the
    /// cap per operation, and booked exactly, like any leg's.
    function check_venueCall_valueCounted(uint256 value) public {
        uint256 r = _validate(_pair(value, 0, value));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(value <= MAX_VALUE);
            assert(_nativeSpent() == value);
            assert(_nativeSpent() <= BUDGET);
        }
    }

    /// The price a decoder puts on a call: accepted only within the token's
    /// cap per operation, and booked exactly, like an order's.
    function check_venueCall_priced(uint256 price) public {
        uint256 r = _validate(_pair(0, price, 0));
        if (r == 1) {
            assert(_tokenSpent() == 0);
        } else {
            assert(price <= A_MAX);
            assert(_tokenSpent() == price);
            assert(_tokenSpent() <= A_BUDGET);
        }
    }

    /// The leg after a registration is the call that was registered: made
    /// with another value, the operation is refused.
    function check_venueCall_onlyThatCall(uint256 value, uint256 made) public {
        uint256 r = _validate(_pair(value, 0, made));
        if (r != 1) {
            assert(made == value);
        }
    }

    /// A registration without its call is refused, whatever it registers: as
    /// the only leg of a batch, and as a single call.
    function check_venueCall_aRegistrationAlone(uint256 value, uint256 price) public {
        Execution[] memory legs = new Execution[](1);
        legs[0] = _register(value, price);
        assert(_validate(_batch(legs)) == 1);
        Execution memory alone = _register(value, price);
        PackedUserOperation memory single =
            _op(ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(alone.target, alone.value, alone.callData));
        assert(_validate(single) == 1);
        assert(_tokenSpent() == 0);
        assert(_nativeSpent() == 0);
    }
}
