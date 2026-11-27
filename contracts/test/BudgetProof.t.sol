// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeShapes} from "../src/judges/SafeShapes.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {ExecMode} from "kernel/src/types/Types.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {Vm} from "forge-std/Vm.sol";

/// Symbolic proofs of the budget invariant and of value-faithfulness,
/// proven with Kontrol (KEVM, https://github.com/runtimeverification/kontrol).
///
/// A prover treats each `check_` function's arguments as symbolic, so the
/// amounts below stand for *every* value at once, not a fuzzed sample. This
/// lifts the budget bound that `PolicyFuzz.t.sol` already asserts under
/// differential fuzzing (lines 390-392, 414-416) from "held on the seeds
/// tried" to "held on all inputs" — for the one path proven here.
///
/// To run it, from a copy of `contracts/` holding `src/`, `lib/`,
/// `foundry.toml` and this one file in `test/` (with the whole suite in
/// `test/` the build takes far longer), as `.github/workflows/kontrol.yml`
/// does:
///
///     docker run --rm -e KPROFILE_TELEMETRY_DISABLED=true \
///       -v "$PWD:/home/user/workspace" -w /home/user/workspace \
///       runtimeverificationinc/kontrol:ubuntu-jammy-1.0.255 \
///       bash -c 'kontrol build && kontrol prove --match-test "BudgetProof.check_" --workers 3'
///
/// What is proven, each for every value of its symbolic amounts (#124, #130):
///
/// - the accounting of a token `transfer` and of a plain native transfer, in
///   one operation and in two operations in a row: accepted only within the
///   cap per operation, booked exactly, never past the budget, never wrapped;
/// - the same summed over the legs of one operation, with the number of legs
///   fixed at two: an account batch (ERC-7579 `CALLTYPE_BATCH`), a Safe
///   transaction's inner value, and a Safe's delegatecalled multiSend;
/// - value-faithfulness on the account's own paths: the operation the policy
///   accepted is then executed the way Kernel v3.3 executes it
///   (`Kernel.execute` is `ExecLib.execute(mode, data)` behind its access
///   check), and what reaches the payee is exactly what was booked;
/// - no standing allowances: an approval is accepted only with its withdrawal
///   in the same operation, within the cap, and booked as a transfer is.
///
/// `.github/workflows/kontrol.yml` also breaks each rule alone, in a copy of
/// the policy, and requires its proof to fail. Timings are in
/// docs/FUZZING.md. Kontrol sends anonymous usage data unless
/// `KPROFILE_TELEMETRY_DISABLED=true` is set. Halmos 0.1.13 cannot run this
/// codebase: its symbolic EVM has no MCOPY, which our bytecode needs.
///
/// SCOPE. The number of legs is fixed (two); a loop over a length the caller
/// chooses stays with the fuzzing (`PolicyFuzz.t.sol`). The shapes are fixed
/// too: well-formed encodings with symbolic amounts, not symbolic offsets or
/// trailing bytes, which the parsers' own tests and the fuzzing hold.
/// Faithfulness is proven for the account's single and batch paths; a Safe
/// executing its transaction is not modelled here, and the differential
/// fuzzing stays the evidence for it. A refusal is modelled as the
/// EntryPoint handles it: `handleOps` reverts, so nothing stays booked, not
/// even the earlier legs of a refused batch, which the policy books before
/// it reaches the leg it refuses. A validation that reverts (an amount so
/// large that a sum would wrap) is a refusal too.
///
/// The run needs no network and changes no on-chain state. This file adds
/// nothing to `forge test`: `check_` is not a forge test prefix.
contract Acct {
    function entrypoint() external pure returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    function install(AgentPolicy p, bytes calldata d) external {
        p.onInstall(d);
    }

    function validate(AgentPolicy p, bytes32 id, PackedUserOperation calldata op) external returns (uint256) {
        return p.checkUserOpPolicy(id, op);
    }

    /// Kernel v3.3's `execute` (Kernel.sol:330-332) without its access check:
    /// the same selector, the same decoding, the same calls.
    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable {
        ExecLib.execute(execMode, executionCalldata);
    }

    receive() external payable {}
}

/// A token that only records what it was told to move.
contract Recorder {
    mapping(address => uint256) public received;

    function transfer(address to, uint256 amount) external returns (bool) {
        received[to] += amount;
        return true;
    }
}

contract BudgetProof {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    AgentPolicy internal policy;
    Acct internal acct;
    address internal token;

    address internal constant NONCE_ASSERT = 0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279;
    bytes32 internal constant ID = bytes32(bytes4(0x66757a7a));
    address internal constant PAYEE = address(0x1001);
    address internal constant SAFE = address(0x5AFE);
    address internal constant MULTISEND = address(0x3157);
    bytes4 internal constant TRANSFER = 0xa9059cbb;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    address internal constant SPENDER = address(0x5BE4);
    bytes4 internal constant SAFE_EXEC = 0x6a761202;
    bytes4 internal constant MULTI_SEND = 0x8d80ff0a;
    // Each budget is reachable within two operations: with a budget above
    // twice the cap, a broken budget check could never show (#130, item 3).
    uint128 internal constant A_MAX = 100;
    uint128 internal constant A_BUDGET = 150;
    uint128 internal constant MAX_VALUE = 1 ether;
    uint128 internal constant BUDGET = 1.5 ether;
    uint48 internal constant UNTIL = type(uint48).max;

    function setUp() public {
        policy = new AgentPolicy(NONCE_ASSERT, address(new SafeShapes()));
        acct = new Acct();
        token = address(new Recorder());
        vm.deal(address(acct), 10 ether);
        // One mandate: plain native transfers to PAYEE (value capped per op
        // and by the budget), token transfers (amount capped per op and by
        // the token budget), a Safe's transactions and its multiSend.
        address[] memory targets = new address[](5);
        bytes4[] memory selectors = new bytes4[](5);
        (targets[0], selectors[0]) = (PAYEE, bytes4(0)); // plain value transfer
        (targets[1], selectors[1]) = (token, TRANSFER);
        (targets[2], selectors[2]) = (SAFE, SAFE_EXEC);
        (targets[3], selectors[3]) = (MULTISEND, MULTI_SEND);
        (targets[4], selectors[4]) = (token, APPROVE);
        AgentPolicy.TokenCap[] memory tokens = new AgentPolicy.TokenCap[](1);
        tokens[0] = AgentPolicy.TokenCap(token, A_MAX, A_BUDGET, bytes32(0));
        bytes memory data = abi.encodePacked(
            ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, UNTIL, tokens, uint48(0))
        );
        acct.install(policy, data);
    }

    // --- building one fixed-shape operation, symbolic leaves only ---

    function _op(ExecMode mode, bytes memory executionData) internal pure returns (PackedUserOperation memory op) {
        op.callData = abi.encodeWithSelector(Kernel.execute.selector, mode, executionData);
        // gas fields zero: isolate the value/token accounting from the gas
        // charge (paymasterAndData is empty, so the account would pay gas, but
        // with zero gasFees the charge is zero, leaving only `value`).
        op.accountGasLimits = bytes32(0);
        op.gasFees = bytes32(0);
    }

    function _single(address target, uint256 value, bytes memory data) internal pure returns (PackedUserOperation memory) {
        return _op(ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(target, value, data));
    }

    function _batch(Execution[] memory legs) internal pure returns (PackedUserOperation memory) {
        // CALLTYPE_BATCH (0x01) in the mode's first byte, default exec type
        return _op(ExecMode.wrap(bytes32(uint256(1) << 248)), ExecLib.encodeBatch(legs));
    }

    function _transfer(uint256 amount) internal view returns (Execution memory) {
        return Execution(token, 0, abi.encodeWithSelector(TRANSFER, PAYEE, amount));
    }

    /// The account's nonce-guarded Safe transaction: the assertion, then the call.
    function _guardedSafe(address to, uint256 value, bytes memory inner, uint256 operation)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        Execution[] memory legs = new Execution[](2);
        legs[0] = Execution(NONCE_ASSERT, 0, abi.encodeWithSelector(SafeNonceAssert.check.selector, SAFE, uint256(0)));
        legs[1] = Execution(
            SAFE,
            0,
            abi.encodeWithSelector(
                SAFE_EXEC, to, value, inner, operation, uint256(0), uint256(0), uint256(0), address(0), address(0), ""
            )
        );
        return _batch(legs);
    }

    /// One validation as the EntryPoint (v0.7) runs it: a refusal reverts the
    /// whole `handleOps` (`FailedOp`, "AA24 signature error"), and with it
    /// whatever the policy booked for the earlier legs of a refused batch. A
    /// validation that reverts is a refusal too. Returns 1 for refused.
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

    // --- one call ---

    /// A single token transfer of a symbolic amount: whenever it is accepted,
    /// the token's spent is exactly the amount, within the per-op cap and the
    /// budget; whenever it is refused, nothing was booked.
    function check_tokenTransfer_oneOp(uint256 amount) public {
        uint256 r = _validate(_single(token, 0, abi.encodeWithSelector(TRANSFER, PAYEE, amount)));
        if (r == 1) {
            assert(_tokenSpent() == 0); // refused: nothing booked
        } else {
            assert(amount <= A_MAX); // accepted only within the per-op cap
            assert(_tokenSpent() == amount);
            assert(_tokenSpent() <= A_BUDGET);
        }
    }

    /// Two token transfers of symbolic amounts in sequence: if both are
    /// accepted, the cumulative spent is their sum, never over the budget, and
    /// never wrapped past uint128.
    function check_tokenTransfer_twoOps(uint256 a1, uint256 a2) public {
        uint256 r1 = _validate(_single(token, 0, abi.encodeWithSelector(TRANSFER, PAYEE, a1)));
        uint256 r2 = _validate(_single(token, 0, abi.encodeWithSelector(TRANSFER, PAYEE, a2)));
        if (r1 != 1 && r2 != 1) {
            assert(_tokenSpent() == a1 + a2); // no overflow: 0.8 would have reverted
            assert(_tokenSpent() <= A_BUDGET);
        }
    }

    /// A single plain native transfer of a symbolic value: accepted only within
    /// the per-op cap, and the native spent then never passes the budget.
    function check_nativeTransfer_oneOp(uint256 value) public {
        uint256 r = _validate(_single(PAYEE, value, ""));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(value <= MAX_VALUE);
            assert(_nativeSpent() == value);
            assert(_nativeSpent() <= BUDGET);
        }
    }

    /// Two plain native transfers in sequence: the native spent is their sum
    /// and never passes the budget.
    function check_nativeTransfer_twoOps(uint256 v1, uint256 v2) public {
        uint256 r1 = _validate(_single(PAYEE, v1, ""));
        uint256 r2 = _validate(_single(PAYEE, v2, ""));
        if (r1 != 1 && r2 != 1) {
            assert(_nativeSpent() == v1 + v2);
            assert(_nativeSpent() <= BUDGET);
        }
    }

    // --- the legs of one operation, summed ---

    /// Two token transfers in one account batch: the cap per operation holds
    /// for their sum, not for each leg (splitting does not escape it).
    function check_tokenBatch_twoLegs(uint256 a1, uint256 a2) public {
        Execution[] memory legs = new Execution[](2);
        (legs[0], legs[1]) = (_transfer(a1), _transfer(a2));
        uint256 r = _validate(_batch(legs));
        if (r == 1) {
            assert(_tokenSpent() == 0);
        } else {
            assert(a1 + a2 <= A_MAX);
            assert(_tokenSpent() == a1 + a2);
        }
    }

    /// Two native transfers in one account batch: their sum is what is capped
    /// and booked.
    function check_nativeBatch_twoLegs(uint256 v1, uint256 v2) public {
        Execution[] memory legs = new Execution[](2);
        (legs[0], legs[1]) = (Execution(PAYEE, v1, ""), Execution(PAYEE, v2, ""));
        uint256 r = _validate(_batch(legs));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(v1 + v2 <= MAX_VALUE);
            assert(_nativeSpent() == v1 + v2);
        }
    }

    /// The value a Safe transaction sends from the Safe counts as the
    /// account's: capped and booked like a transfer of its own.
    function check_safe_innerValue(uint256 value) public {
        uint256 r = _validate(_guardedSafe(PAYEE, value, "", 0));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(value <= MAX_VALUE);
            assert(_nativeSpent() == value);
        }
    }

    /// A Safe delegatecalling multiSend with two legs: their sum is capped and
    /// booked.
    function check_safe_multiSend_twoLegs(uint256 v1, uint256 v2) public {
        bytes memory txs = abi.encodePacked(uint8(0), PAYEE, v1, uint256(0), uint8(0), PAYEE, v2, uint256(0));
        uint256 r = _validate(_guardedSafe(MULTISEND, 0, abi.encodeWithSelector(MULTI_SEND, txs), 1));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(v1 + v2 <= MAX_VALUE);
            assert(_nativeSpent() == v1 + v2);
        }
    }

    // --- no standing allowances ---

    /// An approval of a limited token is accepted alone only if it grants
    /// nothing; with its withdrawal (`approve(spender, 0)`) later in the same
    /// operation it is accepted within the cap per operation and booked as a
    /// transfer is. Nothing the agent grants outlives the operation.
    function check_allowance_mustBeWithdrawn(uint256 amount) public {
        // alone: it would stand
        uint256 r1 = _validate(_single(token, 0, abi.encodeWithSelector(APPROVE, SPENDER, amount)));
        if (r1 != 1) assert(amount == 0);
        // granted and withdrawn in one batch
        uint256 before = _tokenSpent();
        Execution[] memory legs = new Execution[](2);
        legs[0] = Execution(token, 0, abi.encodeWithSelector(APPROVE, SPENDER, amount));
        legs[1] = Execution(token, 0, abi.encodeWithSelector(APPROVE, SPENDER, uint256(0)));
        uint256 r2 = _validate(_batch(legs));
        if (r2 == 1) {
            assert(_tokenSpent() == before);
        } else {
            assert(amount <= A_MAX);
            assert(_tokenSpent() == before + amount);
        }
    }

    // --- value-faithfulness: what the account then moves is what was booked ---

    /// A single token transfer, accepted, then executed as Kernel executes it:
    /// the payee receives exactly what the token's budget booked.
    function check_faithful_single(uint256 amount) public {
        PackedUserOperation memory op = _single(token, 0, abi.encodeWithSelector(TRANSFER, PAYEE, amount));
        if (_validate(op) == 1) return;
        (bool ok,) = address(acct).call(op.callData);
        assert(ok);
        assert(Recorder(token).received(PAYEE) == _tokenSpent());
    }

    /// A batch of a token transfer and a native transfer, accepted, then
    /// executed as Kernel executes it: the payee receives exactly the tokens
    /// and the value that were booked.
    function check_faithful_batch(uint256 amount, uint256 value) public {
        Execution[] memory legs = new Execution[](2);
        (legs[0], legs[1]) = (_transfer(amount), Execution(PAYEE, value, ""));
        PackedUserOperation memory op = _batch(legs);
        if (_validate(op) == 1) return;
        uint256 before = PAYEE.balance;
        (bool ok,) = address(acct).call(op.callData);
        assert(ok);
        assert(Recorder(token).received(PAYEE) == _tokenSpent());
        assert(PAYEE.balance - before == _nativeSpent());
    }
}
