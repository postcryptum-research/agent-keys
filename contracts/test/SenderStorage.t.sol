// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PayeeProbes2.t.sol";

/// Issue #83: during validation the policy may touch only storage that
/// belongs to the account under ERC-7562, i.e. slots of the form
/// `keccak256(account ‖ x) + n` with a small `n`. Forge records the
/// preimage of every mapping slot, so each test runs one operation and
/// asks, slot by slot, whether the account is the innermost key.
///
/// The policy's transient slots are built in the same form by hand
/// (`_beginOperation`, `_movedThisOperation`) and are not seen here.
contract SenderStorage is PayeeProbes2 {
    /// The widest struct the policy keeps (`Config`, `TokenLimit`) takes
    /// three slots; ERC-7562 allows offsets up to 127.
    uint256 internal constant WIDEST = 3;

    function _recordFrom() internal {
        vm.startMappingRecording();
        vm.record();
    }

    /// Every slot of the policy touched since `_recordFrom` is the account's.
    function _assertOnlyTheAccountsSlots(uint256 atLeast) internal {
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(policy));
        assertGe(reads.length, atLeast, "the operation did not reach the policy's storage");
        assertGt(writes.length, 0, "validation writes the spent counter at least");
        for (uint256 i; i < reads.length; i++) {
            // `reads` holds the written slots too
            assertTrue(_isTheAccounts(reads[i]), "a slot that is not keccak(account, x) + n");
        }
        vm.stopMappingRecording();
    }

    function _isTheAccounts(bytes32 slot) internal returns (bool) {
        for (uint256 n; n < WIDEST; n++) {
            (bool found, bytes32 key,) = vm.getMappingKeyAndParentOf(address(policy), bytes32(uint256(slot) - n));
            if (found && key == bytes32(uint256(uint160(acct)))) return true;
        }
        return false;
    }

    /// A plain call: the config, the allow-list entry, the target's (absent) token limit.
    function test_senderStorage_plainCall() public {
        PackedUserOperation memory op = _agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        _recordFrom();
        _send(op);
        _assertOnlyTheAccountsSlots(3);
        assertEq(counter.count(), 1);
    }

    /// A token transfer under a payee list: the token's limit and the payee entry as well.
    function test_senderStorage_tokenTransferToAListedPayee() public {
        _withPayees();
        PackedUserOperation memory op =
            _agentOpWith(AGENT, PYE_ID, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether)));
        _recordFrom();
        _send(op);
        _assertOnlyTheAccountsSlots(4);
        assertEq(token.balanceOf(PAYEE), 1 ether);
    }

    /// A batch of two tokens' transfers.
    function test_senderStorage_batchOfTwoTokens() public {
        _withPayees();
        Execution[] memory calls = new Execution[](2);
        calls[0] = _transferLeg(1 ether);
        calls[1] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1000)));
        PackedUserOperation memory op = _agentBatchWith(AGENT, PYE_ID, calls);
        _recordFrom();
        _send(op);
        _assertOnlyTheAccountsSlots(6);
    }

    /// An x402 registration: the pending authorization is written in validation.
    function test_senderStorage_x402Registration() public {
        _withX402();
        PackedUserOperation memory op = _agentOpWith(
            AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, block.timestamp + 1 hours, bytes32(uint256(1)))
        );
        _recordFrom();
        _send(op);
        _assertOnlyTheAccountsSlots(4);
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PAY_ID)), address(usdc)).spent, 500_000);
    }

    /// A token transfer out of a Safe, as a MultiSend leg.
    function test_senderStorage_safeBatchLeg() public {
        Safe safe = _probeSafe();
        PackedUserOperation memory op = _viaSafe(
            safe,
            _batch(
                safe,
                address(multiSend),
                _legOf(0, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether))),
                Enum.Operation.DelegateCall
            )
        );
        _recordFrom();
        _send(op);
        _assertOnlyTheAccountsSlots(5);
        assertEq(token.balanceOf(PAYEE), 1 ether);
    }

    /// The check itself tells the two layouts apart: a slot of the layout
    /// before #83, `keccak(id ‖ keccak(account ‖ p))`, is not the account's.
    function test_senderStorage_theEarlierLayoutWouldNotPass() public {
        _recordFrom();
        this.touchEarlierLayout();
        (bool found, bytes32 key,) = vm.getMappingKeyAndParentOf(address(this), earlierSlot);
        assertTrue(found && key != bytes32(uint256(uint160(acct))), "the earlier layout's last key is the id");
        vm.stopMappingRecording();
    }

    mapping(address => mapping(bytes32 => uint256)) internal _earlier;
    bytes32 internal earlierSlot;

    function touchEarlierLayout() external {
        _earlier[acct][bytes32(uint256(7))] = 1;
        uint256 p;
        assembly {
            p := _earlier.slot
        }
        bytes32 outer = keccak256(abi.encode(acct, p));
        earlierSlot = keccak256(abi.encode(bytes32(uint256(7)), outer));
    }
}
