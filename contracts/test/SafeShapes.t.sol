// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {SafeShapes} from "../src/judges/SafeShapes.sol";

/// The ABI of the two calls the judge reads, for encoding them as a wallet does.
interface ISafeExec {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool);
}

interface IMultiSend {
    function multiSend(bytes calldata transactions) external payable;
}

/// `SafeShapes` (issue #251) says where the calls inside a Safe transaction
/// and a multiSend batch lie. What it points at must be exactly what the
/// Safe and MultiSendCallOnly decode, and what it cannot read is a plain
/// `false`, never a revert: the policy asks it inside validation.
contract SafeShapesTest is Test {
    SafeShapes internal shapes;

    function setUp() public {
        shapes = new SafeShapes();
    }

    /// The slice of `d` between two positions; an external call, so that `d` is calldata.
    function slice(bytes calldata d, uint256 start, uint256 end) external pure returns (bytes memory) {
        return d[start:end];
    }

    function _exec(address to, uint256 value, bytes memory data, uint8 operation) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ISafeExec.execTransaction, (to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), hex"01")
        );
    }

    /// Any Safe transaction a wallet encodes: the judge's positions slice
    /// out the inner call that Solidity's decoder reads, and the head words
    /// are the ones the Safe takes.
    function testFuzz_aSafeTransactionIsReadAsTheSafeDecodesIt(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation
    ) public view {
        bytes memory d = _exec(to, value, data, operation);
        (bool ok, address readTo, uint256 readValue, uint256 readOperation, uint256 start, uint256 end) =
            shapes.readSafeTransaction(d);
        assertTrue(ok);
        assertEq(readTo, to);
        assertEq(readValue, value);
        assertEq(readOperation, operation);
        assertEq(this.slice(d, start, end), data, "the inner call");
    }

    /// A refund, a gas figure for the Safe's own call, or an address word
    /// with bits above its 160: refused, each alone.
    function test_aSafeTransactionThatAsksForARefundOrHasADirtyAddressIsRefused() public view {
        bytes memory inc = abi.encodeWithSignature("increment()");
        bytes memory d = _exec(address(0xC0FFEE), 0, inc, 0);
        (bool ok,,,,,) = shapes.readSafeTransaction(d);
        assertTrue(ok, "the plain call");
        // head words 4, 5, 6: safeTxGas, baseGas, gasPrice; 0, 7, 8: to, gasToken, refundReceiver
        for (uint256 word = 4; word <= 6; word++) {
            assertFalse(_readsWith(d, word, bytes32(uint256(1))), "a gas word");
        }
        assertFalse(_readsWith(d, 0, bytes32(uint256(1) << 160)), "the target's word");
        assertFalse(_readsWith(d, 7, bytes32(uint256(1) << 160)), "the gas token's word");
        assertFalse(_readsWith(d, 8, bytes32(uint256(1) << 160)), "the refund receiver's word");
    }

    function _readsWith(bytes memory d, uint256 word, bytes32 bits) internal view returns (bool ok) {
        bytes memory changed = bytes.concat(d);
        uint256 place = 4 + 32 * word;
        bytes32 current;
        assembly ("memory-safe") {
            current := mload(add(add(changed, 0x20), place))
            mstore(add(add(changed, 0x20), place), or(current, bits))
        }
        (ok,,,,,) = shapes.readSafeTransaction(changed);
    }

    /// The data's offset or length pointing past the calldata: refused.
    function test_aSafeTransactionWhoseDataLiesOutsideIsRefused() public view {
        bytes memory d = _exec(address(0xC0FFEE), 0, hex"d09de08a", 0);
        // the data's offset (head word 2) far past the end
        bytes memory far = bytes.concat(d);
        assembly ("memory-safe") {
            mstore(add(add(far, 0x20), 68), 0xffffff)
        }
        (bool ok,,,,,) = shapes.readSafeTransaction(far);
        assertFalse(ok, "offset");
        // shorter than the head
        (ok,,,,,) = shapes.readSafeTransaction(this.slice(d, 0, 323));
        assertFalse(ok, "short");
    }

    function _leg(uint8 operation, address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(operation, to, value, data.length, data);
    }

    /// Any batch of up to four CALL legs: every leg found, in order, each
    /// with its target, its value and its data.
    function testFuzz_aBatchIsReadLegByLeg(address[4] memory tos, uint256[4] memory values, bytes[4] memory datas, uint8 count)
        public
        view
    {
        count = uint8(bound(count, 1, 4));
        bytes memory txs;
        for (uint256 i; i < count; i++) {
            txs = bytes.concat(txs, _leg(0, tos[i], values[i], datas[i]));
        }
        bytes memory d = abi.encodeCall(IMultiSend.multiSend, (txs));
        (bool ok, SafeShapes.Leg[] memory legs) = shapes.readMultiSend(d);
        assertTrue(ok);
        assertEq(legs.length, count);
        for (uint256 i; i < count; i++) {
            assertEq(legs[i].to, tos[i]);
            assertEq(legs[i].value, values[i]);
            assertEq(this.slice(d, legs[i].start, legs[i].end), datas[i]);
        }
    }

    /// A DELEGATECALL leg, a leg cut short, an empty batch: refused.
    function test_aBatchWithADelegatecallACutLegOrNoLegIsRefused() public view {
        bytes memory call = _leg(0, address(0xC0FFEE), 0, hex"d09de08a");
        bool ok;
        (ok,) = shapes.readMultiSend(abi.encodeCall(IMultiSend.multiSend, (bytes.concat(call, _leg(1, address(1), 0, "")))));
        assertFalse(ok, "a delegatecall leg");
        (ok,) = shapes.readMultiSend(abi.encodeCall(IMultiSend.multiSend, (this.slice(bytes.concat(call, call), 0, 2 * call.length - 1))));
        assertFalse(ok, "a cut leg");
        (ok,) = shapes.readMultiSend(abi.encodeCall(IMultiSend.multiSend, (bytes(""))));
        assertFalse(ok, "no leg");
        (ok,) = shapes.readMultiSend(abi.encodeCall(IMultiSend.multiSend, (call)));
        assertTrue(ok, "one whole leg");
    }

    /// Whatever bytes it is given, the judge answers and does not revert.
    function testFuzz_theJudgeDoesNotRevert(bytes calldata d) public view {
        shapes.readSafeTransaction(d);
        shapes.readMultiSend(d);
    }
}
