// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {IShapeJudge, SHAPE_BATCH, SHAPE_WALLET} from "./IShapeJudge.sol";

/// @title SafeShapes - where the calls lie inside a Safe transaction and a multiSend batch
/// @notice A judge without state for `AgentPolicy` (issue #251). It reads a
/// `Safe.execTransaction` call, and a `multiSend` batch, and says where the
/// calls inside them lie, as positions in the bytes it was given. The policy
/// slices its own calldata at those positions and judges each call itself,
/// so that what it judges is what the Safe will run.
/// @dev It reads the words the Safe and MultiSendCallOnly read, the way they
/// read them. It reads no storage and no clock (ERC-7562), and it does not
/// revert on what it is given: what it cannot read is answered `ok == false`.
contract SafeShapes is IShapeJudge {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    /// `Safe.execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
    bytes4 public constant EXEC_TRANSACTION = 0x6a761202;
    /// `MultiSendCallOnly.multiSend(bytes)`
    bytes4 public constant MULTI_SEND = 0x8d80ff0a;

    /// @inheritdoc IShapeJudge
    function shapes() external pure returns (bytes4[] memory selectors, uint8[] memory roles) {
        selectors = new bytes4[](2);
        roles = new uint8[](2);
        (selectors[0], roles[0]) = (EXEC_TRANSACTION, SHAPE_WALLET);
        (selectors[1], roles[1]) = (MULTI_SEND, SHAPE_BATCH);
    }

    /// @inheritdoc IShapeJudge
    /// @dev A Safe transaction holds one call: a CALL, or a DELEGATECALL (operation
    /// 1) that the policy admits into a batch only; any other operation is
    /// refused. A batch holds its CALL legs.
    function read(bytes4 selector, bytes calldata data) external pure returns (bool ok, Inner[] memory calls) {
        if (selector == EXEC_TRANSACTION) {
            (bool read_, address to, uint256 value, uint256 operation, uint256 start, uint256 end) =
                readSafeTransaction(data);
            if (!read_ || operation > 1) return (false, calls);
            calls = new Inner[](1);
            calls[0] = Inner(to, value, start, end, operation == 1);
            return (true, calls);
        }
        if (selector == MULTI_SEND) {
            Leg[] memory legs;
            (ok, legs) = readMultiSend(data);
            if (!ok) return (false, calls);
            calls = new Inner[](legs.length);
            for (uint256 i; i < legs.length; i++) {
                calls[i] = Inner(legs[i].to, legs[i].value, legs[i].start, legs[i].end, false);
            }
            return (true, calls);
        }
        return (false, calls);
    }

    /// One CALL leg of a batch: its target, its value, and where its data lies.
    struct Leg {
        // The leg's target
        address to;
        // The leg's native value
        uint256 value;
        // Where the leg's data starts, in the bytes given
        uint256 start;
        // Where it ends, exclusive
        uint256 end;
    }

    /// @notice Reads the parts of a `Safe.execTransaction` call the policy
    /// rules on, straight from the ABI head (the Safe decodes the same
    /// words), and refuses gas refunds.
    /// @param d The `execTransaction` calldata, selector included.
    /// @return ok True if the call is well formed and asks for no refund.
    /// @return to The inner call's target.
    /// @return value The inner call's native value.
    /// @return operation 0 for CALL, 1 for DELEGATECALL.
    /// @return start Where the inner call's data starts in `d`.
    /// @return end Where it ends in `d`, exclusive.
    function readSafeTransaction(bytes calldata d)
        public
        pure
        returns (bool ok, address to, uint256 value, uint256 operation, uint256 start, uint256 end)
    {
        // selector + ten head words
        if (d.length < 324) return (false, address(0), 0, 0, 0, 0);
        // Head words 0, 7 and 8 are addresses (to, gasToken, refundReceiver):
        // whole words only. A Safe built with a decoder that masks the word
        // would call the address judged here; one built with a decoder that
        // validates it reverts at execution, with the operation charged
        if ((uint256(bytes32(d[4:36])) | uint256(bytes32(d[228:260])) | uint256(bytes32(d[260:292]))) >> 160 != 0) {
            return (false, address(0), 0, 0, 0, 0);
        }
        // Head words 0 to 3: to, value, the data's offset, operation
        to = address(uint160(uint256(bytes32(d[4:36]))));
        value = uint256(bytes32(d[36:68]));
        uint256 dataOffset = uint256(bytes32(d[68:100]));
        operation = uint256(bytes32(d[100:132]));
        // Head words 4 to 6: safeTxGas, baseGas, gasPrice, all 0. With a
        // gasPrice the Safe would pay a refund out of its own funds to a
        // receiver the agent picks. With a safeTxGas (or a gasPrice) the Safe
        // does not revert when its inner call does, and validation would have
        // counted a call that was not made: a withdrawal of an allowance, say.
        // With all three 0 the Safe's transaction fails with its inner call.
        if ((uint256(bytes32(d[132:164])) | uint256(bytes32(d[164:196])) | uint256(bytes32(d[196:228]))) != 0) {
            return (false, address(0), 0, 0, 0, 0);
        }
        // The data: its offset bounded before any sum, then its length and bytes within the calldata
        if (dataOffset > d.length) return (false, address(0), 0, 0, 0, 0);
        uint256 head = 4 + dataOffset;
        if (d.length < head + 32) return (false, address(0), 0, 0, 0, 0);
        uint256 length = uint256(bytes32(d[head:head + 32]));
        if (length > d.length || d.length < head + 32 + length) return (false, address(0), 0, 0, 0, 0);
        return (true, to, value, operation, head + 32, head + 32 + length);
    }

    /// @notice Reads a `multiSend(bytes transactions)` call: each transaction
    /// packed as `operation (1) ‖ to (20) ‖ value (32) ‖ dataLength (32) ‖
    /// data`, CALL legs only.
    /// @param d The `multiSend` calldata, selector included.
    /// @return ok True if the batch holds at least one leg and every leg is a whole CALL leg.
    /// @return legs The legs, in order, with where each one's data lies in `d`.
    function readMultiSend(bytes calldata d) public pure returns (bool ok, Leg[] memory legs) {
        // The packed transactions, at least one byte of them
        (bool found, uint256 first, uint256 last) = _transactions(d);
        if (!found || first == last) return (false, legs);
        // Count the legs, each a whole CALL leg, to the end
        uint256 count;
        uint256 i = first;
        while (i < last) {
            (bool parsed,,, uint256 dataEnd) = _leg(d, i, last);
            if (!parsed) return (false, legs);
            count += 1;
            i = dataEnd;
        }
        // Then read them
        legs = new Leg[](count);
        i = first;
        for (uint256 k; k < count; k++) {
            (, address to, uint256 value, uint256 dataEnd) = _leg(d, i, last);
            legs[k] = Leg(to, value, i + 85, dataEnd);
            i = dataEnd;
        }
        return (true, legs);
    }

    /// @dev Where the `bytes transactions` argument of a `multiSend` call lies.
    /// @param d The `multiSend` calldata, selector included.
    /// @return ok True if the argument lies within the calldata.
    /// @return first Where the packed transactions start in `d`.
    /// @return last Where they end in `d`, exclusive.
    function _transactions(bytes calldata d) internal pure returns (bool ok, uint256 first, uint256 last) {
        // selector + offset + length
        if (d.length < 68) return (false, 0, 0);
        // The offset, bounded by the calldata before any sum
        uint256 offset = uint256(bytes32(d[4:36]));
        if (offset > d.length) return (false, 0, 0);
        // The length word, then the bytes, within the calldata
        uint256 head = 4 + offset;
        if (d.length < head + 32) return (false, 0, 0);
        uint256 length = uint256(bytes32(d[head:head + 32]));
        if (length > d.length || d.length < head + 32 + length) return (false, 0, 0);
        return (true, head + 32, head + 32 + length);
    }

    /// @dev The batch leg starting at `i`; CALL legs only.
    /// @param d The `multiSend` calldata.
    /// @param i Where the leg starts in `d`.
    /// @param last Where the packed transactions end in `d`.
    /// @return ok True if the leg is a whole CALL leg within the transactions.
    /// @return to The leg's target.
    /// @return value The leg's native value.
    /// @return dataEnd Where the leg's data ends, which is where the next leg starts.
    function _leg(bytes calldata d, uint256 i, uint256 last)
        internal
        pure
        returns (bool ok, address to, uint256 value, uint256 dataEnd)
    {
        // A whole header, and operation 0 (CALL)
        if (last < i + 85 || uint8(d[i]) != 0) return (false, address(0), 0, 0);
        // to (20 bytes), value (32), the data's length (32)
        to = address(bytes20(d[i + 1:i + 21]));
        value = uint256(bytes32(d[i + 21:i + 53]));
        uint256 length = uint256(bytes32(d[i + 53:i + 85]));
        // The data, within the packed bytes
        if (length > last || last < i + 85 + length) return (false, address(0), 0, 0);
        return (true, to, value, i + 85 + length);
    }
}
