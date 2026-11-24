// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentPolicy} from "../src/AgentPolicy.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {ExecMode} from "kernel/src/types/Types.sol";

/// Symbolic proof of the budget invariant for the single-call accounting path,
/// to run with Halmos (https://github.com/a16z/halmos):
///
///     halmos --contract BudgetProof
///
/// Halmos treats each `check_` function's arguments as symbolic, so the
/// amounts below stand for *every* value at once, not a fuzzed sample. This
/// lifts the budget bound that `PolicyFuzz.t.sol` already asserts under
/// differential fuzzing (lines 390-392, 414-416) from "held on the seeds
/// tried" to "held on all inputs" — for the one path proven here.
///
/// NOTE: Halmos 0.1.13 (the latest release) cannot yet execute this codebase —
/// its symbolic EVM does not implement the MCOPY opcode, which our bytecode
/// needs (transient storage forces cancun+, and the dependencies need a solc
/// that emits MCOPY). See issue #124. The harness is prover-agnostic and is
/// ready for a prover that handles MCOPY (Kontrol, Certora).
///
/// SCOPE, stated honestly. This proves the *accounting* invariant for a
/// fixed-shape single call (a token `transfer`, and a plain native transfer):
/// the meter the policy keeps never passes the budget and never wraps. It does
/// NOT cover the batch, Safe or multiSend decode paths (symbolic-length loops;
/// those stay fuzz-covered), and it does NOT prove *value-faithfulness* — that
/// what the executed call can move is at most what the policy counted, which
/// needs a model of Kernel's `execute` and is future work (the differential
/// fuzzing is the current evidence for it).
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
}

contract BudgetProof {
    AgentPolicy internal policy;
    Acct internal acct;

    address internal constant NONCE_ASSERT = 0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279;
    bytes32 internal constant ID = bytes32(bytes4(0x66757a7a));
    address internal constant TOKEN = address(0xA1);
    address internal constant PAYEE = address(0x1001);
    uint128 internal constant A_MAX = 100;
    uint128 internal constant A_BUDGET = 250;
    uint128 internal constant MAX_VALUE = 1 ether;
    uint128 internal constant BUDGET = 5 ether;
    uint48 internal constant UNTIL = type(uint48).max;

    function setUp() public {
        policy = new AgentPolicy(NONCE_ASSERT);
        acct = new Acct();
        // One mandate: a plain native transfer to PAYEE (value capped per op
        // and by the budget), and TOKEN transfers to PAYEE (amount capped per
        // op and by the token budget).
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (PAYEE, bytes4(0)); // plain value transfer
        (targets[1], selectors[1]) = (TOKEN, bytes4(0xa9059cbb)); // transfer(address,uint256)
        AgentPolicy.TokenCap[] memory tokens = new AgentPolicy.TokenCap[](1);
        tokens[0] = AgentPolicy.TokenCap(TOKEN, A_MAX, A_BUDGET, bytes32(0));
        bytes memory data = abi.encodePacked(
            ID, abi.encode(targets, selectors, MAX_VALUE, BUDGET, UNTIL, tokens, uint48(0))
        );
        acct.install(policy, data);
    }

    // --- building one fixed-shape operation, symbolic leaf only ---

    function _op(bytes memory executionData) internal pure returns (PackedUserOperation memory op) {
        // single call, default exec type — the shape PolicyFuzz._execute uses
        op.callData = abi.encodeWithSelector(Kernel.execute.selector, ExecMode.wrap(bytes32(0)), executionData);
        // gas fields zero: isolate the value/token accounting from the gas
        // charge (paymasterAndData is empty, so the account would pay gas, but
        // with zero gasFees the charge is zero, leaving only `value`).
        op.accountGasLimits = bytes32(0);
        op.gasFees = bytes32(0);
    }

    function _tokenSpent() internal view returns (uint128) {
        return policy.tokenLimit(address(acct), ID, TOKEN).spent;
    }

    function _nativeSpent() internal view returns (uint128) {
        (,,,, uint128 spent,) = policy.configs(address(acct), ID);
        return spent;
    }

    // --- the proofs ---

    /// A single token transfer of a symbolic amount: whenever it is accepted,
    /// the token's spent is exactly the amount, within the per-op cap and the
    /// budget; whenever it is refused, nothing was booked.
    function check_tokenTransfer_oneOp(uint256 amount) public {
        bytes memory inner = abi.encodeWithSelector(bytes4(0xa9059cbb), PAYEE, amount);
        bytes memory execData = ExecLib.encodeSingle(TOKEN, 0, inner);
        uint256 r = acct.validate(policy, ID, _op(execData));
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
        bytes memory i1 = abi.encodeWithSelector(bytes4(0xa9059cbb), PAYEE, a1);
        uint256 r1 = acct.validate(policy, ID, _op(ExecLib.encodeSingle(TOKEN, 0, i1)));
        bytes memory i2 = abi.encodeWithSelector(bytes4(0xa9059cbb), PAYEE, a2);
        uint256 r2 = acct.validate(policy, ID, _op(ExecLib.encodeSingle(TOKEN, 0, i2)));
        if (r1 != 1 && r2 != 1) {
            assert(_tokenSpent() == a1 + a2); // no overflow: 0.8 would have reverted
            assert(_tokenSpent() <= A_BUDGET);
        }
    }

    /// A single plain native transfer of a symbolic value: accepted only within
    /// the per-op cap, and the native spent then never passes the budget.
    function check_nativeTransfer_oneOp(uint256 value) public {
        bytes memory execData = ExecLib.encodeSingle(PAYEE, value, "");
        uint256 r = acct.validate(policy, ID, _op(execData));
        if (r == 1) {
            assert(_nativeSpent() == 0);
        } else {
            assert(value <= MAX_VALUE);
            assert(_nativeSpent() == value);
            assert(_nativeSpent() <= BUDGET);
        }
    }
}
