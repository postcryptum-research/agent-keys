// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";

import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode} from "kernel/src/types/Types.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// Stands where the Kernel account stands for the policy: it is the caller
/// of `onInstall` and `checkUserOpPolicy`, it names its EntryPoint, and, as
/// Kernel does, it reverts when the policy refuses, so that nothing a
/// refused validation wrote on the way stays.
contract FuzzAccount {
    error Refused();

    function entrypoint() external pure returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    function install(AgentPolicy policy, bytes calldata data) external {
        policy.onInstall(data);
    }

    function uninstall(AgentPolicy policy, bytes32 id) external {
        policy.onUninstall(abi.encodePacked(id));
    }

    function validate(AgentPolicy policy, bytes32 id, PackedUserOperation calldata op) external returns (uint256 r) {
        r = policy.checkUserOpPolicy(id, op);
        if (r == 1) revert Refused();
    }

    function reclaim(
        AgentPolicy policy,
        bytes32 id,
        address token,
        address to,
        uint256 value,
        uint256 validBefore,
        bytes32 nonce
    ) external {
        policy.x402Reclaim(id, token, to, value, 0, validBefore, nonce);
    }

    function vouches(AgentPolicy policy, bytes32 id, bytes32 digest) external view returns (uint256) {
        return policy.checkSignaturePolicy(id, address(0), digest, "");
    }
}

/// What `x402Reclaim` asks of a token: whether an authorization's nonce was
/// used. The test says which were.
contract SettledNonces {
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    function settle(address authorizer, bytes32 nonce) external {
        authorizationState[authorizer][nonce] = true;
    }
}

/// Fuzzing of `AgentPolicy` at the policy's own interface, without Kernel,
/// keys or signatures, so that a run is cheap and many fit in a second.
/// Operations come from a seed: mostly well-formed and near the limits,
/// with a share of damaged ones.
///
/// - `testFuzz_model_*`: a second, plain statement of the rules (the model
///   below) decides each operation on its own, and the policy must decide
///   the same; the mandate's counters must never pass its limits.
/// - `testFuzz_differential_*`: the policy in the source and the instance
///   deployed to Base Sepolia on 2026-11-25 (its runtime code, in
///   `test/vectors`) get the same mandate and the same operations and must
///   agree on every decision and every view. That instance was built from
///   commit `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, so a difference is a
///   change to the source since, or a bug in one of the two.
///
/// More runs: `FOUNDRY_FUZZ_RUNS=20000 forge test --match-contract PolicyFuzz`.
abstract contract PolicyFuzzBase is Test {
    // the deployed instance was built with this SafeNonceAssert
    address internal constant NONCE_ASSERT = 0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219;
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    address internal constant COUNTER = address(0xC0);
    address internal constant TOKEN_A = address(0xA1); // limit, payee list {P1, P2}
    address internal constant TOKEN_B = address(0xB1); // limit, anyone, x402
    address internal constant VAULT = address(0xD1); // no limit
    address internal constant SAFE = address(0x5AFE);
    address internal constant MULTISEND = address(0x5E4D);
    address internal constant P1 = address(0x1001);
    address internal constant P2 = address(0x1002);
    address internal constant P3 = address(0x1003); // on no list

    bytes4 internal constant INCREMENT = 0xd09de08a;
    bytes4 internal constant DEPOSIT = 0xb6b55f25;
    bytes4 internal constant TRANSFER = 0xa9059cbb;
    bytes4 internal constant TRANSFER_FROM = 0x23b872dd;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant INCREASE = 0x39509351;
    bytes4 internal constant PERMIT = 0xd505accf;
    bytes4 internal constant SAFE_EXEC = 0x6a761202;
    bytes4 internal constant MULTI_SEND = 0x8d80ff0a;

    bytes32 internal constant ID = bytes32(bytes4(0x66757a7a)); // "fuzz"
    uint128 internal constant MAX_VALUE = 1 ether;
    uint128 internal constant BUDGET = 5 ether;
    uint128 internal constant A_MAX = 100;
    uint128 internal constant A_BUDGET = 250;
    uint128 internal constant B_MAX = 50;
    uint128 internal constant B_BUDGET = 120;
    bytes32 internal constant A_DOMAIN = keccak256("token a's domain");
    bytes32 internal constant B_DOMAIN = keccak256("token b's domain");

    /// What is left of each budget before the operation being built (the
    /// zero address: the native one), so that amounts can land exactly on
    /// a budget's last unit and one past it.
    mapping(address => uint256) internal left;

    FuzzAccount internal account;
    uint256 internal rng;
    /// Approvals carry an amount of 0 (see `PolicyFuzzDifferential.setUp`).

    function _next() internal returns (uint256) {
        rng = uint256(keccak256(abi.encode(rng)));
        return rng;
    }

    function _below(uint256 n) internal returns (uint256) {
        return _next() % n;
    }

    /// The mandate every test installs; the policy's own address is in it
    /// for the two x402 entry points, so it is built per policy.
    function _installData(AgentPolicy policy) internal pure returns (bytes memory) {
        address[] memory targets = new address[](12);
        bytes4[] memory selectors = new bytes4[](12);
        (targets[0], selectors[0]) = (COUNTER, INCREMENT);
        (targets[1], selectors[1]) = (COUNTER, bytes4(0));
        (targets[2], selectors[2]) = (TOKEN_A, TRANSFER);
        (targets[3], selectors[3]) = (TOKEN_A, APPROVE);
        (targets[4], selectors[4]) = (TOKEN_A, TRANSFER_FROM);
        (targets[5], selectors[5]) = (TOKEN_A, INCREASE);
        (targets[6], selectors[6]) = (TOKEN_B, TRANSFER);
        (targets[7], selectors[7]) = (VAULT, DEPOSIT);
        (targets[8], selectors[8]) = (SAFE, SAFE_EXEC);
        (targets[9], selectors[9]) = (MULTISEND, MULTI_SEND);
        (targets[10], selectors[10]) = (address(policy), AgentPolicy.x402Authorize.selector);
        (targets[11], selectors[11]) = (address(policy), AgentPolicy.x402Reclaim.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](2);
        caps[0] = AgentPolicy.TokenCap(TOKEN_A, A_MAX, A_BUDGET, A_DOMAIN);
        caps[1] = AgentPolicy.TokenCap(TOKEN_B, B_MAX, B_BUDGET, B_DOMAIN);
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0].token = TOKEN_A;
        lists[0].payees = new address[](2);
        (lists[0].payees[0], lists[0].payees[1]) = (P1, P2);
        return abi.encodePacked(
            ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, uint48(2_000_000_000), caps, uint48(0), lists)
        );
    }

    // --- operations from the seed ---

    struct Leg {
        address target;
        uint256 value;
        bytes data;
    }

    function _amount(uint256 cap, address token) internal returns (uint256) {
        uint256 k = _below(12);
        if (k == 10) return left[token];
        if (k == 11) return left[token] + 1;
        if (k == 0) return 0;
        if (k == 1) return cap;
        if (k == 2) return cap + 1;
        if (k == 3) return cap - 1;
        if (k == 4) return type(uint256).max;
        if (k == 5) return _below(3 * cap);
        return _below(cap / 2 + 1);
    }

    function _payee() internal returns (uint256) {
        uint256 k = _below(12);
        if (k < 5) return uint160(P1);
        if (k < 9) return uint160(P2);
        if (k < 11) return uint160(P3);
        // a listed address with something above its 160 bits
        return uint256(uint160(P1)) | (1 << 200);
    }

    function _value() internal returns (uint256) {
        uint256 k = _below(10);
        if (k == 8) return left[address(0)];
        if (k == 9) return left[address(0)] + 1;
        if (k < 4) return 0;
        if (k == 4) return MAX_VALUE;
        if (k == 5) return MAX_VALUE + 1;
        return _below(MAX_VALUE / 2);
    }


    /// A token call through one of the four metered functions, now and then
    /// cut short, or through `permit`.
    function _tokenLeg() internal returns (Leg memory leg) {
        uint256 t = _below(8);
        leg.target = t < 4 ? TOKEN_A : t < 7 ? TOKEN_B : VAULT;
        uint256 cap = leg.target == TOKEN_B ? B_MAX : A_MAX;
        uint256 s = _below(20);
        if (s < 8) leg.data = abi.encodeWithSelector(TRANSFER, _payee(), _amount(cap, leg.target));
        else if (s < 12) leg.data = abi.encodeWithSelector(APPROVE, _payee(), _amount(cap, leg.target));
        else if (s < 15) leg.data = abi.encodeWithSelector(INCREASE, _payee(), _amount(cap, leg.target));
        else if (s < 18) leg.data = abi.encodeWithSelector(TRANSFER_FROM, _payee(), _payee(), _amount(cap, leg.target));
        else if (s == 18) leg.data = abi.encodeWithSelector(PERMIT, _payee(), _payee(), _amount(cap, leg.target));
        else leg.data = abi.encodeWithSelector(DEPOSIT, _amount(cap, leg.target));
        if (_below(25) == 0) {
            bytes memory whole = leg.data;
            uint256 keep = _below(whole.length);
            assembly {
                mstore(whole, keep)
            }
        }
        if (_below(30) == 0) leg.value = _value();
    }

    /// A call the model knows: the counter, a plain transfer, a token call,
    /// or a target or function the mandate does not have.
    function _plainLeg() internal returns (Leg memory leg) {
        uint256 k = _below(20);
        if (k < 4) return Leg(COUNTER, _value(), abi.encodeWithSelector(INCREMENT));
        if (k < 6) return Leg(COUNTER, _value(), "");
        if (k == 6) return Leg(COUNTER, _value(), _below(2) == 0 ? bytes(hex"00") : bytes(hex"00000000aabb"));
        if (k == 7) return Leg(VAULT, 0, abi.encodeWithSelector(DEPOSIT, _below(1000)));
        if (k == 8) {
            address[4] memory outside = [address(account), PERMIT2, address(0xDEAD), COUNTER];
            return Leg(outside[_below(4)], 0, abi.encodeWithSelector(_below(2) == 0 ? TRANSFER : DEPOSIT, P1, 1));
        }
        return _tokenLeg();
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

    /// Small gas numbers, so that what the account would pay for gas moves
    /// the budget by amounts of the same order as the values do.
    function _op(bytes memory callData) internal returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.callData = callData;
        op.accountGasLimits = bytes32((_below(1000) << 128) | _below(1000));
        op.preVerificationGas = _below(1000);
        op.gasFees = bytes32(_below(4) == 0 ? 0.0002 ether : _below(1e12));
        if (_below(2) == 0) op.paymasterAndData = abi.encodePacked(address(0xFA57), uint256(0));
    }

    function _maxGasCost(PackedUserOperation memory op) internal pure returns (uint256) {
        uint256 limits = uint256(op.accountGasLimits);
        return ((limits >> 128) + uint128(limits) + op.preVerificationGas) * uint128(uint256(op.gasFees));
    }

    function _try(AgentPolicy policy, PackedUserOperation memory op) internal returns (bool ok, uint256 result) {
        try account.validate(policy, ID, op) returns (uint256 r) {
            return (true, r);
        } catch {
            return (false, 0);
        }
    }
}

/// The rules, stated a second time and as plainly as they can be, for
/// operations made of the account's own calls (no Safe, no x402).
contract PolicyFuzzModel is PolicyFuzzBase {
    AgentPolicy internal policy;

    // the model's state
    uint256 internal spent;
    mapping(address => uint256) internal tokenSpent;
    // one operation's working state
    mapping(address => uint256) internal movedA;
    uint256 internal movedSeq;

    function setUp() public {
        account = new FuzzAccount();
        policy = new AgentPolicy(NONCE_ASSERT);
        account.install(policy, _installData(policy));
    }

    function _allowed(address target, bytes4 selector) internal pure returns (bool) {
        if (target == COUNTER) return selector == INCREMENT || selector == bytes4(0);
        if (target == TOKEN_A) {
            return selector == TRANSFER || selector == APPROVE || selector == TRANSFER_FROM || selector == INCREASE;
        }
        if (target == TOKEN_B) return selector == TRANSFER;
        if (target == VAULT) return selector == DEPOSIT;
        return false;
    }

    function _word(bytes memory data, uint256 index) internal pure returns (uint256 w) {
        uint256 at = 4 + 32 * index;
        assembly {
            w := mload(add(add(data, 32), at))
        }
    }

    /// Whether the model lets the operation through; on yes, its state has
    /// moved on, on no it is as before.
    function _modelAccepts(Leg[] memory legs, PackedUserOperation memory op) internal returns (bool) {
        movedSeq++;
        uint256 value;
        uint256 open; // allowances granted in the operation and not withdrawn
        uint256 aSpent = tokenSpent[TOKEN_A];
        uint256 bSpent = tokenSpent[TOKEN_B];
        for (uint256 i; i < legs.length; i++) {
            Leg memory leg = legs[i];
            bytes4 selector = leg.data.length >= 4 ? bytes4(leg.data) : bytes4(0);
            if (selector == bytes4(0) && leg.data.length != 0) return false;
            if (!_allowed(leg.target, selector)) return false;
            value += leg.value;
            if (leg.target != TOKEN_A && leg.target != TOKEN_B) continue;
            // a token with a limit: the amount is the last word of the call, who gets it the word before
            uint256 words = selector == TRANSFER_FROM ? 3 : 2;
            if (leg.data.length < 4 + 32 * words) return false;
            uint256 amount = _word(leg.data, words - 1);
            if (leg.target == TOKEN_A) {
                uint256 payee = _word(leg.data, words - 2);
                if (payee != uint160(P1) && payee != uint160(P2)) return false;
            }
            bytes32 key = keccak256(abi.encode(movedSeq, leg.target));
            uint256 cap = leg.target == TOKEN_A ? A_MAX : B_MAX;
            if (amount > cap || _moved[key] + amount > cap) return false;
            _moved[key] += amount;
            if (leg.target == TOKEN_A) {
                aSpent += amount;
                if (aSpent > A_BUDGET) return false;
            } else {
                bSpent += amount;
                if (bSpent > B_BUDGET) return false;
            }
            // no standing allowances: a grant stays open until approve(spender, 0) in the same operation
            if (selector == APPROVE || (selector == INCREASE && amount != 0)) {
                bytes32 k = keccak256(abi.encode(movedSeq, leg.target, uint160(_word(leg.data, 0))));
                if (amount != 0 && !_open[k]) {
                    _open[k] = true;
                    open++;
                } else if (amount == 0 && _open[k]) {
                    _open[k] = false;
                    open--;
                }
            }
        }
        if (open != 0) return false;
        if (value > MAX_VALUE) return false;
        uint256 charged = value + (op.paymasterAndData.length == 0 ? _maxGasCost(op) : 0);
        if (spent + charged > BUDGET) return false;
        spent += charged;
        (tokenSpent[TOKEN_A], tokenSpent[TOKEN_B]) = (aSpent, bSpent);
        return true;
    }

    mapping(bytes32 => uint256) internal _moved;
    mapping(bytes32 => bool) internal _open;

    /// Now and then the withdrawal of an allowance a leg grants, at the end
    /// of the operation: with it the grant passes, without it it stands.
    function _withWithdrawals(Leg[] memory legs) internal returns (Leg[] memory out) {
        out = new Leg[](legs.length * 2);
        uint256 n;
        for (uint256 i; i < legs.length; i++) {
            out[n++] = legs[i];
        }
        for (uint256 i; i < legs.length; i++) {
            bytes memory d = legs[i].data;
            bool grants = d.length >= 68 && (bytes4(d) == APPROVE || bytes4(d) == INCREASE);
            if (grants && legs[i].target == TOKEN_A && _below(2) == 0) {
                out[n++] = Leg(TOKEN_A, 0, abi.encodeWithSelector(APPROVE, address(uint160(_word(d, 0))), uint256(0)));
            }
        }
        assembly {
            mstore(out, n)
        }
    }

    function _spentOnChain() internal view returns (uint256 s) {
        (,,,, s,) = policy.configs(address(account), ID);
    }

    /// Forty operations per seed; after each, the policy and the model must
    /// have decided alike and count alike.
    function testFuzz_model_decisionsAndCounters(uint256 seed) public {
        rng = seed;
        uint256 accepted;
        for (uint256 n; n < 40; n++) {
            left[address(0)] = BUDGET - spent;
            left[TOKEN_A] = A_BUDGET - tokenSpent[TOKEN_A];
            left[TOKEN_B] = B_BUDGET - tokenSpent[TOKEN_B];
            Leg[] memory legs = new Leg[](1 + _below(4));
            for (uint256 i; i < legs.length; i++) {
                legs[i] = _plainLeg();
            }
            legs = _withWithdrawals(legs);
            PackedUserOperation memory op = _op(_execute(legs, _below(2) == 0));
            bool expected = _modelAccepts(legs, op);
            (bool ok,) = _try(policy, op);
            assertEq(ok, expected, "the policy and the model decide differently");
            if (ok) accepted++;

            assertEq(_spentOnChain(), spent, "native spent");
            AgentPolicy.TokenLimit memory a = policy.tokenLimit(address(account), ID, TOKEN_A);
            AgentPolicy.TokenLimit memory b = policy.tokenLimit(address(account), ID, TOKEN_B);
            assertEq(a.spent, tokenSpent[TOKEN_A], "token A spent");
            assertEq(b.spent, tokenSpent[TOKEN_B], "token B spent");
            // the limits themselves, whatever the model says
            assertLe(_spentOnChain(), BUDGET);
            assertLe(a.spent, A_BUDGET);
            assertLe(b.spent, B_BUDGET);
        }
        // not a property of the policy: a guard that the generator still
        // produces operations of both kinds for most seeds
        emit log_named_uint("accepted of 40", accepted);
    }

    /// Bytes that are no `execute` call at all are never let through.
    function testFuzz_model_arbitraryCallDataIsRefused(bytes calldata callData, uint256 seed) public {
        rng = seed;
        vm.assume(callData.length < 4 || bytes4(callData[0:4]) != Kernel.execute.selector);
        (bool ok,) = _try(policy, _op(callData));
        assertFalse(ok);
        assertEq(_spentOnChain(), 0);
    }

    /// An `execute` call with arbitrary bytes behind the selector may be let
    /// through only within the limits: whatever it was, the counters hold.
    function testFuzz_model_arbitraryExecuteBodyStaysWithinLimits(bytes calldata body, uint256 seed) public {
        rng = seed;
        PackedUserOperation memory op = _op(abi.encodePacked(Kernel.execute.selector, body));
        _try(policy, op);
        assertLe(_spentOnChain(), uint256(MAX_VALUE) + _maxGasCost(op));
        assertLe(policy.tokenLimit(address(account), ID, TOKEN_A).spent, A_MAX);
        assertLe(policy.tokenLimit(address(account), ID, TOKEN_B).spent, B_MAX);
    }
}

/// The source against the deployed instance.
contract PolicyFuzzDifferential is PolicyFuzzBase {
    AgentPolicy internal fresh; // the source
    AgentPolicy internal deployed; // Base Sepolia's runtime code of 2026-11-25

    bytes32[] internal digests;

    /// Every authorization an operation tried to register, as the source's
    /// policy would know it.
    struct Authorization {
        address token;
        address from;
        address to;
        uint256 value;
        uint256 validBefore;
        bytes32 nonce;
        bytes32 digest;
    }

    Authorization[] internal tried;

    function setUp() public {
        account = new FuzzAccount();
        bytes memory nonces = address(new SettledNonces()).code;
        vm.etch(TOKEN_A, nonces);
        vm.etch(TOKEN_B, nonces);
        fresh = new AgentPolicy(NONCE_ASSERT);
        deployed = AgentPolicy(address(0xDE9107ED));
        vm.etch(address(deployed), vm.parseBytes(vm.readFile("test/vectors/agent-policy-84532-0xe52825D4.hex")));
        assertEq(deployed.NONCE_ASSERT(), NONCE_ASSERT, "the vector is not the instance it is taken for");
        account.install(fresh, _installData(fresh));
        account.install(deployed, _installData(deployed));
    }

    // --- legs the model does not cover ---

    function _x402Leg(AgentPolicy policy, uint256 salt) internal returns (Leg memory leg, bytes32 digest) {
        // the same draws for both policies: only the target differs
        uint256 saved = rng;
        rng = salt;
        address token = _below(3) == 0 ? TOKEN_A : TOKEN_B;
        address from = _below(8) == 0 ? P3 : address(account);
        address to = address(uint160(_payee()));
        uint256 value = _amount(B_MAX, token);
        uint256 validBefore = _below(12) == 0 ? type(uint256).max : 1_000_000 + 1000 * _below(4);
        bytes32 nonce = bytes32(_below(6));
        rng = saved;
        leg.target = address(policy);
        leg.data = abi.encodeCall(AgentPolicy.x402Authorize, (token, from, to, value, 0, validBefore, nonce));
        bytes32 structHash = keccak256(
            abi.encode(policy.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, uint256(0), validBefore, nonce)
        );
        digest = keccak256(abi.encodePacked(hex"1901", token == TOKEN_A ? A_DOMAIN : B_DOMAIN, structHash));
        if (policy == fresh) tried.push(Authorization(token, from, to, value, validBefore, nonce, digest));
    }

    function _reclaims(AgentPolicy policy, Authorization memory a) internal returns (bool) {
        try account.reclaim(policy, ID, a.token, a.to, a.value, a.validBefore, a.nonce) {
            return true;
        } catch {
            return false;
        }
    }

    /// The account asks for one of the authorizations back, as it was
    /// registered or with one field changed; before that, time may move on
    /// and the token may come to say the nonce was used. Both policies must
    /// answer alike, and as the rule says on its own: only what is
    /// registered, past its `validBefore` and not settled comes back, once,
    /// and the token's spent counter falls by exactly its value.
    function _reclaimStep(uint256 stepSeed) internal {
        if (tried.length == 0) return;
        rng = stepSeed;
        Authorization memory a = tried[_below(tried.length)];
        if (_below(3) == 0) vm.warp(block.timestamp + 1000 * _below(1200));
        if (_below(6) == 0) SettledNonces(a.token).settle(address(account), a.nonce);
        uint256 change = _below(12);
        unchecked {
            if (change == 0) a.value += 1;
        }
        if (change == 1) a.to = P3;
        if (change == 2) a.token = a.token == TOKEN_A ? TOKEN_B : TOKEN_A;
        if (change == 3) a.nonce = bytes32(uint256(a.nonce) + 100);

        // the rule on its own; the digest is of what is asked for, from the account
        uint256 registered = fresh.x402Pending(address(account), ID, _digestOf(a)).value;
        bool expected = registered != 0 && block.timestamp >= a.validBefore
            && !SettledNonces(a.token).authorizationState(address(account), a.nonce);
        uint256 before = fresh.tokenLimit(address(account), ID, a.token).spent;

        bool ok1 = _reclaims(fresh, a);
        bool ok2 = _reclaims(deployed, a);
        assertEq(ok1, ok2, "one gives back what the other keeps");
        assertEq(ok1, expected, "reclaim against the rule");
        if (ok1) {
            assertEq(registered, a.value, "registered with another value");
            assertEq(fresh.tokenLimit(address(account), ID, a.token).spent, before - a.value, "the budget got back another amount");
            assertFalse(_reclaims(fresh, a), "the same authorization came back twice");
            assertFalse(_reclaims(deployed, a));
            reclaimed++;
        }
        _sameViews();
        _sameAuthorizations();
    }

    uint256 internal reclaimed;

    function _digestOf(Authorization memory a) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(fresh.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), address(account), a.to, a.value, uint256(0), a.validBefore, a.nonce)
        );
        return keccak256(abi.encodePacked(hex"1901", a.token == TOKEN_A ? A_DOMAIN : B_DOMAIN, structHash));
    }

    /// The last operation drawn holds a Safe transaction with `safeTxGas`,
    /// `baseGas` or `gasPrice` other than 0. With any of them the Safe does
    /// not revert when its inner call fails, or pays a refund (#190): the
    /// policy must refuse the operation whatever else it holds.
    bool internal quietSafe;

    /// `gas` is `[safeTxGas, baseGas, gasPrice]`.
    function _safeExec(address to, uint256 value, bytes memory inner, uint256 operation, uint256[3] memory gas)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(SAFE_EXEC, to, value, inner, operation, gas[0], gas[1], gas[2], address(0), address(0), "");
    }

    function _multiSend(uint256 legs) internal returns (bytes memory) {
        bytes memory txs;
        for (uint256 i; i < legs; i++) {
            Leg memory leg = _plainLeg();
            uint8 operation = _below(15) == 0 ? 1 : 0;
            txs = abi.encodePacked(txs, operation, leg.target, leg.value, leg.data.length, leg.data);
        }
        if (_below(20) == 0) txs = abi.encodePacked(txs, hex"00");
        return abi.encodeWithSelector(MULTI_SEND, txs);
    }

    /// A nonce assertion and the Safe transaction it guards, with now and
    /// then one of the things that must get it refused.
    function _safePair() internal returns (Leg memory guard, Leg memory exec) {
        address guarded = _below(12) == 0 ? VAULT : SAFE;
        guard = Leg(NONCE_ASSERT, 0, abi.encodeCall(SafeNonceAssert.check, (guarded, _below(5))));
        // each of the three words now and then other than 0: 1, or any word at all
        uint256[3] memory gas;
        for (uint256 i; i < 3; i++) {
            if (_below(20) == 0) gas[i] = _below(2) == 0 ? 1 : _next() | 1;
            if (gas[i] != 0) quietSafe = true;
        }
        if (_below(2) == 0) {
            Leg memory inner = _plainLeg();
            exec = Leg(SAFE, _value(), _safeExec(inner.target, inner.value, inner.data, _below(15) == 0 ? 1 : 0, gas));
        } else {
            exec = Leg(SAFE, 0, _safeExec(MULTISEND, _below(20) == 0 ? 1 : 0, _multiSend(1 + _below(3)), _below(15) == 0 ? 0 : 1, gas));
        }
    }

    /// One operation, built twice: once per policy, alike but for the
    /// policy's own address in an x402 leg.
    function _operation(AgentPolicy policy, uint256 opSeed) internal returns (PackedUserOperation memory op) {
        rng = opSeed;
        quietSafe = false;
        uint256 shape = _below(40);
        if (shape == 0) {
            bytes memory junk = abi.encodePacked(_next(), _next(), _next());
            return _op(_below(2) == 0 ? junk : abi.encodePacked(Kernel.execute.selector, junk));
        }
        Leg[] memory legs = new Leg[](6);
        uint256 n;
        uint256 want = 1 + _below(4);
        while (n < want) {
            uint256 k = _below(10);
            if (k < 5) {
                legs[n++] = _plainLeg();
            } else if (k < 7) {
                bytes32 digest;
                (legs[n++], digest) = _x402Leg(policy, _next());
                if (policy == fresh) digests.push(digest);
            } else if (k < 9) {
                (legs[n], legs[n + 1]) = _safePair();
                // now and then the Safe transaction goes without its guard
                if (_below(12) == 0) legs[n] = legs[n + 1];
                else n++;
                n++;
            } else {
                legs[n++] = Leg(address(policy), 0, abi.encodeWithSelector(_below(2) == 0 ? TRANSFER : AgentPolicy.x402Reclaim.selector));
            }
        }
        assembly {
            mstore(legs, n)
        }
        bytes memory callData = _execute(legs, _below(2) == 0);
        if (shape == 1) {
            // a "try" batch: never accepted
            callData[5] = 0x01;
        }
        return _op(callData);
    }

    function _config(AgentPolicy policy) internal view returns (bytes memory) {
        (uint48 u, uint32 e, uint128 m, uint128 b, uint128 s, uint48 v) = policy.configs(address(account), ID);
        return abi.encode(u, e, m, b, s, v);
    }

    function _token(AgentPolicy policy, address token) internal view returns (bytes memory) {
        address a = address(account);
        return abi.encode(policy.tokenLimit(a, ID, token), policy.payeeAllowed(a, ID, token, P1), policy.payeeAllowed(a, ID, token, P3));
    }

    function _entries(AgentPolicy policy) internal view returns (bytes memory) {
        address a = address(account);
        return abi.encode(
            policy.isAllowed(a, ID, TOKEN_A, TRANSFER),
            policy.isAllowed(a, ID, VAULT, TRANSFER),
            policy.isAllowed(a, ID, COUNTER, bytes4(0)),
            policy.isInitialized(a)
        );
    }

    function _whatIsLeft() internal {
        (,,,, uint128 nativeSpent,) = fresh.configs(address(account), ID);
        left[address(0)] = BUDGET - nativeSpent;
        left[TOKEN_A] = A_BUDGET - fresh.tokenLimit(address(account), ID, TOKEN_A).spent;
        left[TOKEN_B] = B_BUDGET - fresh.tokenLimit(address(account), ID, TOKEN_B).spent;
    }

    function _sameViews() internal view {
        assertEq(_config(fresh), _config(deployed), "configs");
        assertEq(_token(fresh, TOKEN_A), _token(deployed, TOKEN_A), "token A");
        assertEq(_token(fresh, TOKEN_B), _token(deployed, TOKEN_B), "token B");
        assertEq(_entries(fresh), _entries(deployed), "entries");
    }

    /// Every authorization the run tried to register: registered in both or
    /// in neither, and vouched for alike.
    function _sameAuthorizations() internal view {
        address a = address(account);
        for (uint256 i; i < digests.length; i++) {
            assertEq(
                abi.encode(fresh.x402Pending(a, ID, digests[i])), abi.encode(deployed.x402Pending(a, ID, digests[i])), "x402Pending"
            );
            assertEq(account.vouches(fresh, ID, digests[i]), account.vouches(deployed, ID, digests[i]), "checkSignaturePolicy");
        }
    }

    function testFuzz_differential_sourceAgainstTheDeployedInstance(uint256 seed) public {
        uint256 accepted;
        uint256 quiet;
        for (uint256 n; n < 40; n++) {
            uint256 opSeed = uint256(keccak256(abi.encode(seed, n)));
            // now and then the permission is taken away and given back: a new epoch
            if (opSeed % 23 == 0) {
                account.uninstall(fresh, ID);
                account.uninstall(deployed, ID);
                _sameViews();
                _sameAuthorizations();
                account.install(fresh, _installData(fresh));
                account.install(deployed, _installData(deployed));
            }
            if (opSeed % 5 == 1) _reclaimStep(opSeed);
            _whatIsLeft();
            PackedUserOperation memory forFresh = _operation(fresh, opSeed);
            PackedUserOperation memory forDeployed = _operation(deployed, opSeed);
            (bool ok1, uint256 r1) = _try(fresh, forFresh);
            (bool ok2, uint256 r2) = _try(deployed, forDeployed);
            assertEq(ok1, ok2, "one accepts what the other refuses");
            assertEq(r1, r2, "validation data");
            // agreement is not enough here: both sides have the rule or both lack it
            if (quietSafe) {
                quiet++;
                assertFalse(ok1, "a Safe transaction that may fail quietly, or pays a refund, was accepted");
            }
            if (ok1) accepted++;
            _sameViews();
        }
        _sameAuthorizations();
        emit log_named_uint("accepted of 40", accepted);
        emit log_named_uint("with a Safe gas word other than 0", quiet);
        emit log_named_uint("reclaimed", reclaimed);
    }

    /// Arbitrary bytes as the whole call: the same answer from both.
    function testFuzz_differential_arbitraryCallData(bytes calldata callData, bool asExecute, uint256 seed) public {
        rng = seed;
        PackedUserOperation memory op =
            _op(asExecute ? abi.encodePacked(Kernel.execute.selector, callData) : bytes(callData));
        (bool ok1, uint256 r1) = _try(fresh, op);
        (bool ok2, uint256 r2) = _try(deployed, op);
        assertEq(ok1, ok2);
        assertEq(r1, r2);
        _sameViews();
    }

    /// Arbitrary bytes as install data: installed by both or refused by both.
    /// (Almost all such bytes fail to decode; the next test builds mandates.)
    function testFuzz_differential_arbitraryInstallData(bytes calldata params) public {
        bytes memory data = abi.encodePacked(OTHER, params);
        assertEq(_installs(fresh, data), _installs(deployed, data), "one installs what the other refuses");
    }

    bytes32 internal constant OTHER = bytes32(bytes4(0x6f746872)); // "othr"

    function _installs(AgentPolicy policy, bytes memory data) internal returns (bool) {
        try account.install(policy, data) {
            return true;
        } catch {
            return false;
        }
    }

    /// A mandate from the seed: entries, limits and payee lists drawn from a
    /// small set that holds everything install must refuse (the account, the
    /// policy, Permit2, the EntryPoint, a function outside the four on a
    /// token with a limit, a token twice, a zero address, a payee twice, a
    /// list for a token without a limit, an empty window).

    function _mandate(AgentPolicy policy, uint256 seed) internal returns (bytes memory) {
        rng = seed;
        address[9] memory places =
            [COUNTER, TOKEN_A, TOKEN_B, VAULT, COUNTER, address(account), address(policy), PERMIT2, account.entrypoint()];
        bytes4[8] memory functions = [
            TRANSFER, APPROVE, INCREMENT, bytes4(0), TRANSFER_FROM, PERMIT, AgentPolicy.x402Authorize.selector, DEPOSIT
        ];
        // mostly the ordinary places, now and then one install must refuse
        uint256 n = _below(5);
        address[] memory targets = new address[](n);
        bytes4[] memory selectors = new bytes4[](_below(12) == 0 ? n + 1 : n);
        for (uint256 i; i < n; i++) {
            targets[i] = places[_below(6) == 0 ? _below(9) : _below(5)];
        }
        for (uint256 i; i < selectors.length; i++) {
            selectors[i] = functions[_below(8)];
        }
        address[4] memory tokens = [TOKEN_A, TOKEN_B, VAULT, address(0)];
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](_below(4));
        for (uint256 i; i < caps.length; i++) {
            caps[i] = AgentPolicy.TokenCap(
                tokens[_below(8) == 0 ? 3 : _below(3)], uint128(_below(100)), uint128(_below(1000)), _below(2) == 0 ? bytes32(0) : B_DOMAIN
            );
        }
        uint48 validUntil = _below(10) == 0 ? 0 : uint48(1_900_000_000 + _below(100));
        uint48 validAfter = _below(10) == 0 ? validUntil : uint48(_below(2) * 1_800_000_000);
        if (_below(3) == 0) {
            return abi.encodePacked(
                OTHER, abi.encode(targets, selectors, uint128(_below(1e18)), uint128(_below(1e19)), validUntil, caps, validAfter)
            );
        }
        address[5] memory people = [P1, P2, P3, P1, address(0)];
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](_below(3));
        for (uint256 i; i < lists.length; i++) {
            lists[i].token = tokens[_below(3)];
            lists[i].payees = new address[](_below(4));
            for (uint256 j; j < lists[i].payees.length; j++) {
                lists[i].payees[j] = people[_below(8) == 0 ? 3 + _below(2) : _below(3)];
            }
        }
        return abi.encodePacked(
            OTHER, abi.encode(targets, selectors, uint128(_below(1e18)), uint128(_below(1e19)), validUntil, caps, validAfter, lists)
        );
    }

    function _mandateViews(AgentPolicy policy) internal view returns (bytes memory out) {
        address a = address(account);
        (uint48 u, uint32 e, uint128 m, uint128 b, uint128 s, uint48 v) = policy.configs(a, OTHER);
        out = abi.encode(u, e, m, b, s, v);
        address[5] memory places = [COUNTER, TOKEN_A, TOKEN_B, VAULT, PERMIT2];
        bytes4[8] memory functions = [
            TRANSFER, APPROVE, INCREMENT, bytes4(0), TRANSFER_FROM, PERMIT, AgentPolicy.x402Authorize.selector, DEPOSIT
        ];
        for (uint256 i; i < 5; i++) {
            for (uint256 j; j < 8; j++) {
                out = abi.encodePacked(out, policy.isAllowed(a, OTHER, places[i], functions[j]));
            }
        }
        address[3] memory tokens = [TOKEN_A, TOKEN_B, VAULT];
        for (uint256 i; i < 3; i++) {
            out = abi.encodePacked(out, abi.encode(policy.tokenLimit(a, OTHER, tokens[i])));
            out = abi.encodePacked(
                out,
                policy.payeeAllowed(a, OTHER, tokens[i], P1),
                policy.payeeAllowed(a, OTHER, tokens[i], P2),
                policy.payeeAllowed(a, OTHER, tokens[i], P3)
            );
        }
    }

    /// Three mandates in a row under one id, each uninstalled before the
    /// next: both install it or both refuse it, and what is then readable of
    /// it is the same, with nothing left of the one before.
    function testFuzz_differential_mandatesFromTheSeed(uint256 seed) public {
        uint256 installed;
        for (uint256 round; round < 3; round++) {
            uint256 roundSeed = uint256(keccak256(abi.encode(seed, round)));
            bool ok1 = _installs(fresh, _mandate(fresh, roundSeed));
            bool ok2 = _installs(deployed, _mandate(deployed, roundSeed));
            assertEq(ok1, ok2, "one installs what the other refuses");
            assertEq(_mandateViews(fresh), _mandateViews(deployed), "the installed mandate reads differently");
            if (ok1) {
                installed++;
                account.uninstall(fresh, OTHER);
                account.uninstall(deployed, OTHER);
                assertEq(_mandateViews(fresh), _mandateViews(deployed), "after uninstall");
            }
        }
        emit log_named_uint("installed of 3", installed);
    }
}
