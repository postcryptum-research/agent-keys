// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode} from "kernel/src/types/Types.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";

/// The account, as far as the policy is concerned, and the EntryPoint's
/// part of the judgment: the policy may not read the clock, so it answers
/// with a window and the EntryPoint holds the operation to it.
contract TradeAccount {
    error Refused();

    function entrypoint() external pure returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    function install(AgentPolicy policy, bytes calldata data) external {
        policy.onInstall(data);
    }

    /// Reverts unless the policy says yes and the clock is inside its
    /// window, both ends included, as EntryPoint v0.7 reads them. A revert
    /// undoes what the policy wrote, as a refused operation does on chain.
    function validate(AgentPolicy policy, bytes32 id, PackedUserOperation calldata op) external {
        uint256 r = policy.checkUserOpPolicy(id, op);
        if (uint160(r) != 0) revert Refused();
        uint256 until = uint48(r >> 160);
        uint256 from = uint48(r >> 208);
        if (until == 0) until = type(uint48).max;
        if (block.timestamp > until || block.timestamp < from) revert Refused();
    }

    /// Any call on the policy as the account, for what it no longer offers.
    function ask(AgentPolicy policy, bytes calldata data) external returns (bool ok) {
        (ok,) = address(policy).call(data);
    }

    /// Whether the account would vouch for `digest` now (ERC-1271 through
    /// the policy: its yes, and the clock inside the window it names).
    function vouches(AgentPolicy policy, bytes32 id, bytes32 digest) external view returns (bool) {
        uint256 r = policy.checkSignaturePolicy(id, address(0), digest, "");
        if (uint160(r) != 0) return false;
        uint256 until = uint48(r >> 160);
        if (until == 0) until = type(uint48).max;
        return block.timestamp <= until && block.timestamp >= uint48(r >> 208);
    }
}

/// What the decoder asks of CoW's settlement, with fills the test decides.
contract FuzzSettlement {
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

    function fill(bytes calldata uid, uint256 amount) external {
        filledAmount[uid] = amount;
    }
}

/// Fuzzing of the trading side of `AgentPolicy` (issue #80) at the policy's
/// own interface: a mandate with a budget per period and one venue, driven
/// by operations from a seed while the clock moves, against a second, plain
/// statement of the rules (the model below).
///
/// Beside agreement with the model, one rule is held that does not rest on
/// the model's counters: in no period does more of the token leave than its
/// budget, counting what the agent transferred in that period and every
/// order charged to it that the venue filled.
contract TradingFuzzModel is Test {
    address internal constant NONCE_ASSERT = 0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279;
    address internal constant COUNTER = address(0xC0);
    address internal constant SELL = address(0xA1);
    address internal constant BUY = address(0xB1);
    address internal constant OTHER = address(0xD1);

    bytes4 internal constant INCREMENT = 0xd09de08a;
    bytes4 internal constant TRANSFER = 0xa9059cbb;

    bytes32 internal constant ID = bytes32(bytes4(0x74726664)); // "trfd"
    uint128 internal constant MAX_VALUE = 1 ether;
    uint128 internal constant BUDGET = 5 ether;
    uint128 internal constant S_MAX = 100;
    uint128 internal constant S_BUDGET = 250;
    uint32 internal constant PERIOD = 1000;
    uint32 internal constant LIFE = 600;
    /// The lowest price: two of BUY for each one of SELL.
    uint256 internal constant MIN_BUY = 2;
    uint256 internal constant START = 1_000_000_500;
    uint48 internal constant VALID_UNTIL = uint48(START + 200 * uint256(PERIOD));

    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );
    bytes32 internal constant KIND_SELL = keccak256("sell");
    bytes32 internal constant KIND_BUY = keccak256("buy");
    bytes32 internal constant ERC20 = keccak256("erc20");

    AgentPolicy internal policy;
    CowSwapDecoder internal decoder;
    FuzzSettlement internal settlement;
    TradeAccount internal account;
    bytes internal config;
    uint256 internal rng;

    // --- the model's state ---

    /// The last period an accepted operation named, plus one.
    uint256 internal seen;
    uint256 internal spent;
    uint256 internal sSpent;
    /// The period (plus one) the token's counter stands for.
    uint256 internal sPeriod;

    struct Registered {
        CowSwapDecoder.Order order;
        bytes32 digest;
        uint256 chargedIn;
        bool filled;
    }

    Registered[] internal orders;
    mapping(bytes32 => bool) internal live;
    /// What left in each period (by its index plus one): transfers, and the
    /// filled orders charged to it.
    mapping(uint256 => uint256) internal outflow;
    mapping(uint256 => uint256) internal transferred;

    struct Leg {
        address target;
        uint256 value;
        bytes data;
        bool isOrder;
        CowSwapDecoder.Order order;
    }

    function setUp() public {
        vm.warp(START);
        policy = new AgentPolicy(NONCE_ASSERT);
        settlement = new FuzzSettlement();
        decoder = new CowSwapDecoder(address(settlement));
        account = new TradeAccount();

        CowSwapDecoder.Pair[] memory pairs = new CowSwapDecoder.Pair[](1);
        pairs[0] = CowSwapDecoder.Pair({sellToken: SELL, buyToken: BUY, minBuy: MIN_BUY, perSell: 1});
        config = abi.encode(CowSwapDecoder.Config({appData: bytes32(0), maxLife: LIFE, pairs: pairs}));

        address[] memory targets = new address[](4);
        bytes4[] memory selectors = new bytes4[](4);
        (targets[0], selectors[0]) = (COUNTER, INCREMENT);
        (targets[1], selectors[1]) = (COUNTER, bytes4(0));
        (targets[2], selectors[2]) = (SELL, TRANSFER);
        (targets[3], selectors[3]) = (address(policy), AgentPolicy.orderRegister.selector);
        AgentPolicy.TokenCap[] memory tokens = new AgentPolicy.TokenCap[](1);
        tokens[0] = AgentPolicy.TokenCap(SELL, S_MAX, S_BUDGET, bytes32(0));
        AgentPolicy.TokenPayees[] memory payees = new AgentPolicy.TokenPayees[](0);
        AgentPolicy.Venue[] memory venues = new AgentPolicy.Venue[](1);
        venues[0] = AgentPolicy.Venue(address(decoder), address(decoder).codehash, keccak256(config));
        account.install(
            policy,
            abi.encodePacked(
                ID,
                abi.encode(
                    targets, selectors, MAX_VALUE, BUDGET, VALID_UNTIL, tokens, uint48(0), payees, PERIOD, venues
                )
            )
        );
    }

    // --- the generator ---

    function _next() internal returns (uint256) {
        rng = uint256(keccak256(abi.encode(rng)));
        return rng;
    }

    function _below(uint256 n) internal returns (uint256) {
        return _next() % n;
    }

    /// An amount of the token: mostly small, with a share at the cap, one
    /// over it, at the budget's last unit and one past it.
    function _amount() internal returns (uint256) {
        uint256 left = sPeriod == block.timestamp / PERIOD + 1 ? S_BUDGET - sSpent : S_BUDGET;
        uint256 kind = _below(12);
        if (kind == 0) return S_MAX;
        if (kind == 1) return S_MAX + 1;
        if (kind == 2) return left;
        if (kind == 3) return left + 1;
        if (kind == 4) return 0;
        return 1 + _below(S_MAX / 2);
    }

    function _order() internal returns (CowSwapDecoder.Order memory o) {
        uint256 sell = _amount();
        uint256 lifetimes = _below(10);
        uint256 life = lifetimes == 0
            ? LIFE
            : lifetimes == 1 ? LIFE + 1 : lifetimes == 2 ? 0 : lifetimes == 3 ? LIFE - 1 : 1 + _below(LIFE);
        o = CowSwapDecoder.Order({
            sellToken: SELL,
            buyToken: BUY,
            receiver: address(0),
            sellAmount: sell,
            buyAmount: sell * MIN_BUY + _below(3),
            // also aimed at the period's last second and the first one after it
            validTo: lifetimes == 4
                ? uint32((block.timestamp / PERIOD + 1) * PERIOD - 1)
                : lifetimes == 5 ? uint32((block.timestamp / PERIOD + 1) * PERIOD) : uint32(block.timestamp + life),
            appData: bytes32(0),
            feeAmount: 0,
            kind: KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: ERC20,
            buyTokenBalance: ERC20
        });
        // one thing wrong, now and then
        uint256 wrong = _below(40);
        if (wrong == 0) o.receiver = address(0xBAD);
        if (wrong == 1) o.receiver = address(account);
        if (wrong == 2 && sell != 0) o.buyAmount = sell * MIN_BUY - 1;
        if (wrong == 3) o.feeAmount = 1;
        if (wrong == 4) o.kind = KIND_BUY;
        if (wrong == 5) o.partiallyFillable = true;
        if (wrong == 6) o.buyToken = OTHER;
        if (wrong == 7) o.appData = bytes32(uint256(1));
        if (wrong == 8) o.validTo = uint32(block.timestamp - 1);
        if (wrong == 9) (o.sellToken, o.buyToken) = (BUY, SELL);
        if (wrong == 10) o.sellTokenBalance = keccak256("internal");
    }

    function _leg() internal returns (Leg memory leg) {
        uint256 kind = _below(10);
        if (kind < 4) {
            leg.isOrder = true;
            leg.order = _order();
            leg.target = address(policy);
            leg.data = abi.encodeCall(AgentPolicy.orderRegister, (address(decoder), config, abi.encode(leg.order)));
            // an order registered with value attached is no registration
            if (_below(30) == 0) leg.value = 1;
        } else if (kind < 7) {
            leg.target = SELL;
            leg.data = abi.encodeWithSelector(TRANSFER, address(0x1001), _amount());
        } else if (kind < 9) {
            leg.target = COUNTER;
            leg.data = abi.encodeWithSelector(INCREMENT);
        } else {
            leg.target = COUNTER;
            uint256 values = _below(4);
            leg.value = values == 0 ? MAX_VALUE : values == 1 ? MAX_VALUE + 1 : _below(0.01 ether);
        }
    }

    function _execute(Leg[] memory legs, bool single) internal pure returns (bytes memory) {
        if (single && legs.length == 1) {
            return abi.encodeWithSelector(
                Kernel.execute.selector,
                ExecMode.wrap(bytes32(0)),
                ExecLib.encodeSingle(legs[0].target, legs[0].value, legs[0].data)
            );
        }
        Execution[] memory batch = new Execution[](legs.length);
        for (uint256 i; i < legs.length; i++) {
            batch[i] = Execution(legs[i].target, legs[i].value, legs[i].data);
        }
        return abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(uint256(1) << 248)), ExecLib.encodeBatch(batch)
        );
    }

    function _op(bytes memory callData, uint256 index) internal returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.callData = callData;
        op.accountGasLimits = bytes32((_below(1000) << 128) | _below(1000));
        op.preVerificationGas = _below(1000);
        op.gasFees = bytes32(_below(8) == 0 ? 0.0002 ether : _below(1e12));
        if (_below(2) == 0) op.paymasterAndData = abi.encodePacked(address(0xFA57), uint256(0));
        // what Kernel hands the policy as its part of the signature
        op.signature = abi.encodePacked(bytes6(uint48(index)));
        if (_below(60) == 0) op.signature = abi.encodePacked(bytes5(uint40(index)));
    }

    function _maxGasCost(PackedUserOperation memory op) internal pure returns (uint256) {
        uint256 limits = uint256(op.accountGasLimits);
        return ((limits >> 128) + uint128(limits) + op.preVerificationGas) * uint128(uint256(op.gasFees));
    }

    function _digest(CowSwapDecoder.Order memory o) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                hex"1901", settlement.domainSeparator(), keccak256(abi.encodePacked(ORDER_TYPE_HASH, abi.encode(o)))
            )
        );
    }

    // --- the model ---

    /// The owner's terms for an order, stated again.
    function _withinTerms(CowSwapDecoder.Order memory o) internal view returns (bool) {
        if (o.receiver != address(0) && o.receiver != address(account)) return false;
        if (o.kind != KIND_SELL || o.partiallyFillable) return false;
        if (o.sellTokenBalance != ERC20 || o.buyTokenBalance != ERC20) return false;
        if (o.appData != bytes32(0) || o.feeAmount != 0 || o.sellAmount == 0) return false;
        if (o.sellToken != SELL || o.buyToken != BUY) return false;
        return o.buyAmount >= o.sellAmount * MIN_BUY;
    }

    struct Tally {
        uint256 value;
        uint256 moved;
        uint256 token;
        uint256 transfers;
        bool touched;
        uint256 from;
        uint256 until;
        uint256 registered;
    }

    /// Whether the model lets the operation through, at this time and for
    /// the period `index`; on yes its state has moved on, on no it is as
    /// before.
    function _modelAccepts(Leg[] memory legs, PackedUserOperation memory op, uint256 index) internal returns (bool) {
        if (op.signature.length != 6) return false;
        uint256 s = index + 1;
        if (s < seen) return false;
        Tally memory t;
        // the operation is good in its period only, and while the mandate is
        t.from = index * PERIOD;
        t.until = t.from + PERIOD - 1;
        if (VALID_UNTIL < t.until) t.until = VALID_UNTIL;
        bytes32[] memory fresh = new bytes32[](legs.length);

        for (uint256 i; i < legs.length; i++) {
            Leg memory leg = legs[i];
            t.value += leg.value;
            if (leg.target == COUNTER) {
                if (leg.data.length != 0 && bytes4(leg.data) != INCREMENT) return false;
                continue;
            }
            uint256 amount;
            if (leg.isOrder) {
                if (leg.value != 0 || !_withinTerms(leg.order)) return false;
                // an order ends with the period it is charged in
                if (leg.order.validTo > index * PERIOD + PERIOD - 1) return false;
                amount = leg.order.sellAmount;
            } else {
                (, amount) = abi.decode(_tail(leg.data), (address, uint256));
            }
            // the token's cap is for the whole operation, its budget for the period
            if (!t.touched) {
                t.touched = true;
                t.token = sPeriod == s ? sSpent : 0;
            }
            t.moved += amount;
            if (t.moved > S_MAX) return false;
            t.token += amount;
            if (t.token > S_BUDGET) return false;
            if (!leg.isOrder) {
                t.transfers += amount;
                continue;
            }
            // an order is registered once
            bytes32 digest = _digest(leg.order);
            if (live[digest]) return false;
            for (uint256 k; k < t.registered; k++) {
                if (fresh[k] == digest) return false;
            }
            fresh[t.registered++] = digest;
            // not earlier than its longest life before its end, not after its end
            uint256 validTo = leg.order.validTo;
            uint256 notBefore = validTo > LIFE ? validTo - LIFE : 0;
            if (notBefore > t.from) t.from = notBefore;
            if (validTo < t.until) t.until = validTo;
        }
        if (t.value > MAX_VALUE) return false;
        uint256 native = s > seen ? 0 : spent;
        native += t.value + (op.paymasterAndData.length == 0 ? _maxGasCost(op) : 0);
        if (native > BUDGET) return false;
        // a window of a single second is refused: the policy keeps `until`
        // above `from`, so that it never names an empty or an endless one
        if (t.from >= t.until) return false;
        if (block.timestamp < t.from || block.timestamp > t.until) return false;

        seen = s;
        spent = native;
        if (t.touched) (sSpent, sPeriod) = (t.token, s);
        outflow[s] += t.transfers;
        transferred[s] += t.transfers;
        for (uint256 i; i < legs.length; i++) {
            if (!legs[i].isOrder) continue;
            bytes32 digest = _digest(legs[i].order);
            live[digest] = true;
            orders.push(Registered(legs[i].order, digest, s, false));
        }
        return true;
    }

    function _tail(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; i++) {
            out[i] = data[i + 4];
        }
    }

    // --- the steps ---

    function _moveTheClock() internal {
        uint256 kind = _below(12);
        uint256 nowIs = block.timestamp;
        uint256 boundary = (nowIs / PERIOD + 1) * PERIOD;
        if (kind < 4) return;
        if (kind < 7) vm.warp(nowIs + 1 + _below(60));
        else if (kind == 7) vm.warp(nowIs + LIFE / 2 + _below(LIFE));
        else if (kind == 8) vm.warp(boundary - 1);
        else if (kind == 9) vm.warp(boundary);
        else if (kind == 10) vm.warp(boundary + 1);
        else vm.warp(nowIs + PERIOD + _below(PERIOD));
    }

    function _operation() internal {
        Leg[] memory legs = new Leg[](1 + _below(3));
        for (uint256 i; i < legs.length; i++) {
            legs[i] = _leg();
        }
        // sometimes the same order twice in one operation
        if (legs.length > 1 && legs[0].isOrder && _below(20) == 0) legs[1] = legs[0];
        uint256 index = block.timestamp / PERIOD;
        uint256 which = _below(12);
        if (which == 0) index += 1;
        if (which == 1) index -= 1;
        PackedUserOperation memory op = _op(_execute(legs, _below(2) == 0), index);

        bool expected = _modelAccepts(legs, op, index);
        bool ok;
        try account.validate(policy, ID, op) {
            ok = true;
        } catch {}
        assertEq(ok, expected, "the policy and the model decide an operation differently");
    }

    /// The venue fills an order while the account vouches for it, or the
    /// account asks for one back and gets nothing: an order's charge stays
    /// until its period is over.
    function _orderStep() internal {
        if (orders.length == 0) return;
        Registered storage r = orders[_below(orders.length)];
        bytes memory uid = abi.encodePacked(r.digest, address(account), r.order.validTo);
        bool vouched = account.vouches(policy, ID, r.digest);
        assertEq(
            vouched,
            block.timestamp <= r.order.validTo,
            "the account vouches for an order exactly while it is not past its end"
        );

        if (_below(3) == 0) {
            // the venue settles only what the account vouches for
            if (!vouched || r.filled) return;
            settlement.fill(uid, r.order.sellAmount);
            r.filled = true;
            outflow[r.chargedIn] += r.order.sellAmount;
            return;
        }
        uint128 before = policy.tokenLimit(address(account), ID, SELL).spent;
        bool ok = account.ask(
            policy,
            abi.encodeWithSignature(
                "orderReclaim(bytes32,address,bytes,bytes)", ID, address(decoder), config, abi.encode(r.order)
            )
        );
        assertFalse(ok, "the policy gives an order's charge back");
        assertEq(policy.tokenLimit(address(account), ID, SELL).spent, before, "a refused refund moved the count");
    }

    /// Forty steps per seed. After each, the policy and the model count
    /// alike, no counter is past its limit, and no period has let more of
    /// the token out than its budget.
    function testFuzz_trading_modelDecisionsCountersAndOutflow(uint256 seed) public {
        rng = seed;
        for (uint256 n; n < 40; n++) {
            _moveTheClock();
            if (_below(4) == 0) _orderStep();
            else _operation();

            (,,,, uint128 native,) = policy.configs(address(account), ID);
            assertEq(native, spent, "native spent");
            AgentPolicy.TokenLimit memory s = policy.tokenLimit(address(account), ID, SELL);
            assertEq(s.spent, sSpent, "token spent");
            (, uint48 periodSeen) = policy.period(address(account), ID);
            assertEq(periodSeen, seen, "the period seen");
            assertLe(native, BUDGET);
            assertLe(s.spent, S_BUDGET);
        }
        // every period an operation ever named: what left in it is within the budget
        uint256 first = START / PERIOD;
        uint256 last = block.timestamp / PERIOD + 1;
        for (uint256 p = first; p <= last + 1; p++) {
            assertLe(outflow[p], S_BUDGET, "more of the token left in a period than its budget");
        }
    }

    /// Two periods' budgets is the most that can leave around a renewal:
    /// in any window of one period's length, whatever its start, no more
    /// than two budgets. Held here for transfers, which leave at once.
    function testFuzz_trading_noMoreThanTwoBudgetsAcrossARenewal(uint256 seed) public {
        rng = seed;
        for (uint256 n; n < 40; n++) {
            _moveTheClock();
            _operation();
        }
        uint256 first = START / PERIOD;
        uint256 last = block.timestamp / PERIOD + 1;
        for (uint256 p = first; p <= last; p++) {
            assertLe(transferred[p] + transferred[p + 1], 2 * uint256(S_BUDGET));
        }
    }
}
