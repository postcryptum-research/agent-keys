// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Further probes by the reviewer of #71: the per-operation token cap, the
// zero selector, the rule for limited tokens and the refusal of Permit2.
import "./PayeeProbes.t.sol";

contract PayeeProbes2 is PayeeProbes {
    function _signed(uint256 nonce, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = _op(nonce, callData);
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
    }

    /// Two operations in one bundle, each exactly at the cap: both run. A
    /// later bundle whose second operation is one unit over is refused.
    function test_probe2_twoOperationsEachExactlyAtTheCap() public {
        _withPayees();
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        uint256 nonce = _permissionNonce(PYE_ID);
        bytes memory atCap = _singleCall(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, TOKEN_MAX)));
        (ops[0], ops[1]) = (_signed(nonce, atCap), _signed(nonce + 1, atCap));
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(token.balanceOf(PAYEE), 2 * TOKEN_MAX);

        nonce = _permissionNonce(PYE_ID);
        ops[0] = _signed(nonce, _singleCall(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether))));
        ops[1] = _signed(nonce + 1, _singleCall(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, TOKEN_MAX + 1))));
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(token.balanceOf(PAYEE), 2 * TOKEN_MAX);
    }

    /// Two permissions of the same account in one bundle: the running sum of
    /// one is not held against the other.
    function test_probe2_twoPermissionsInOneBundleEachGetTheCap() public {
        _withPayees();
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _agentOpWith(AGENT, AGENT_ID, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, TOKEN_MAX)));
        ops[1] = _agentOpWith(AGENT, PYE_ID, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE_2, TOKEN_MAX)));
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(token.balanceOf(PAYEE), TOKEN_MAX);
        assertEq(token.balanceOf(PAYEE_2), TOKEN_MAX);
    }

    /// An amount that would overflow the running sum fails closed.
    function test_probe2_anAmountThatOverflowsTheSumIsRefused() public {
        _withPayees();
        Execution[] memory calls = new Execution[](2);
        calls[0] = _transferLeg(1);
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (PAYEE, type(uint256).max)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        (calls[0], calls[1]) = (calls[1], calls[0]);
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(token)), 0);
        assertEq(token.allowance(acct, PAYEE), 0);
    }

    /// transferFrom counts toward the same sum as transfer.
    function test_probe2_transferFromCountsTowardTheSum() public {
        _withPayees();
        token.mint(STRANGER, 20 ether);
        vm.prank(STRANGER);
        token.approve(acct, 20 ether);
        Execution[] memory calls = new Execution[](2);
        calls[0] = _transferLeg(6 ether);
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.transferFrom, (STRANGER, PAYEE_2, 6 ether)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.transferFrom, (STRANGER, PAYEE_2, 4 ether)));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE_2), 4 ether);
        assertEq(_tokenSpent(address(token)), 10 ether);
    }

    /// A transfer out of a Safe and a transfer out of the account, in one
    /// operation, are one sum.
    function test_probe2_safeLegAndAccountLegShareTheCap() public {
        Safe safe = _probeSafe();
        Execution[] memory calls = new Execution[](3);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(
            address(safe),
            0,
            _safeExec(safe, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 5 ether)), Enum.Operation.Call, 0)
        );
        calls[2] = Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 6 ether)));
        _expectRefused(_agentBatchWith(AGENT, PRB_ID, calls));
        assertEq(token.balanceOf(PAYEE), 0);
        calls[2] = Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 5 ether)));
        _send(_agentBatchWith(AGENT, PRB_ID, calls));
        assertEq(token.balanceOf(PAYEE), 10 ether);
    }

    /// The zero selector with a body, as a Safe's inner call, as a MultiSend
    /// leg and as a leg of the account's own batch.
    function test_probe2_zeroSelectorWithABodyIsRefusedOnEveryPath() public {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        calls[1] = Execution(address(counter), 0.01 ether, hex"00000000deadbeef");
        _expectRefused(_agentBatchWith(AGENT, AGENT_ID, calls));

        Safe safe = _withSafe();
        bytes memory body = hex"00000000deadbeef";
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.01 ether, body, Enum.Operation.Call, 0)));
        _expectRefused(
            _agentViaSafe(
                safe, _batch(safe, address(multiSend), _legOf(0, address(counter), 0.01 ether, body), Enum.Operation.DelegateCall)
            )
        );
        _expectRefused(
            _agentViaSafe(
                safe, _batch(safe, address(multiSend), _legOf(0, address(counter), 0, hex"00000000"), Enum.Operation.DelegateCall)
            )
        );
        assertEq(address(counter).balance, 0);
        assertEq(counter.count(), 0);
        // the plain transfer still goes through both ways
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.01 ether, "", Enum.Operation.Call, 0)));
        _send(
            _agentViaSafe(
                safe, _batch(safe, address(multiSend), _legOf(0, address(counter), 0.01 ether, ""), Enum.Operation.DelegateCall)
            )
        );
        assertEq(address(counter).balance, 0.02 ether);
    }

    /// Three operations at the cap in one bundle go past the budget: the
    /// per-operation sums start afresh, the budget does not.
    function test_probe2_theBudgetHoldsAcrossOperationsInOneBundle() public {
        _withPayees();
        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        uint256 nonce = _permissionNonce(PYE_ID);
        bytes memory atCap = _singleCall(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, TOKEN_MAX)));
        for (uint256 i; i < 3; i++) {
            ops[i] = _signed(nonce + i, atCap);
        }
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(token.balanceOf(PAYEE), 0);
        assertEq(_tokenSpent(address(token)), 0);
    }

    /// Legs that are each under the cap, and legs of zero, add up all the same.
    function test_probe2_smallLegsAndZeroLegsAddUp() public {
        _withPayees();
        Execution[] memory calls = new Execution[](3);
        (calls[0], calls[1], calls[2]) = (_transferLeg(4 ether), _transferLeg(4 ether), _transferLeg(4 ether));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        (calls[0], calls[1], calls[2]) = (_transferLeg(TOKEN_MAX), _transferLeg(0), _transferLeg(1));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(token)), 0);
        (calls[0], calls[1], calls[2]) = (_transferLeg(4 ether), _transferLeg(0), _transferLeg(6 ether));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE), TOKEN_MAX);
    }

    /// One token over its own cap spoils an operation whose other token is within its cap.
    function test_probe2_oneTokenOverItsCapSpoilsTheOperation() public {
        _withPayees();
        Execution[] memory calls = new Execution[](3);
        calls[0] = _transferLeg(1 ether);
        calls[1] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 600_000)));
        calls[2] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 400_001)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE), 0);
        assertEq(usdc.balanceOf(PAYEE), 0);
        calls[2] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 400_000)));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(usdc.balanceOf(PAYEE), 1e6);
    }

    /// One to three bytes of calldata, zero or not, on every path.
    function test_probe2_oneToThreeBytesAreRefusedOnEveryPath() public {
        bytes[] memory bodies = new bytes[](4);
        bodies[0] = hex"00";
        bodies[1] = hex"0000";
        bodies[2] = hex"000000";
        bodies[3] = hex"d09de0";
        Safe safe = _withSafe();
        for (uint256 i; i < bodies.length; i++) {
            _expectRefused(_agentOp(address(counter), 0.01 ether, bodies[i]));
            _expectRefused(
                _agentViaSafe(safe, _safeExec(safe, address(counter), 0.01 ether, bodies[i], Enum.Operation.Call, 0))
            );
            _expectRefused(
                _agentViaSafe(
                    safe,
                    _batch(safe, address(multiSend), _legOf(0, address(counter), 0.01 ether, bodies[i]), Enum.Operation.DelegateCall)
                )
            );
        }
        assertEq(address(counter).balance, 0);
        assertEq(counter.count(), 0);
    }

    function _installLimited(bytes32 id, address limited, bytes4 other, bool otherFirst, AgentPolicy.TokenCap[] memory caps)
        internal
    {
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (uint256 a, uint256 b) = otherFirst ? (0, 2) : (2, 0);
        (targets[a], selectors[a]) = (limited, other);
        (targets[1], selectors[1]) = (address(counter), Counter.increment.selector);
        (targets[b], selectors[b]) = (limited, MockToken.transfer.selector);
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));
    }

    /// Install: every function outside the four on a token with a limit,
    /// wherever it stands in the list, with and without x402 on the token.
    function test_probe2_installRefusesEveryUnmeteredFunctionOnALimitedToken() public {
        usdc = new MockUSDC();
        bytes4[6] memory unmetered = [
            bytes4(0xd505accf), // permit
            bytes4(0xe3ee160e), // transferWithAuthorization
            bytes4(0xa457c2d7), // decreaseAllowance
            bytes4(0x42966c68), // burn(uint256)
            MockToken.mint.selector,
            bytes4(0) // a plain transfer to the token
        ];
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](2);
        caps[0] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
        caps[1] = AgentPolicy.TokenCap(address(usdc), 1e6, 2_500_000, usdc.DOMAIN_SEPARATOR());
        uint256 n;
        for (uint256 k; k < unmetered.length; k++) {
            for (uint256 v; v < 4; v++) {
                vm.expectRevert(AgentPolicy.InvalidConfig.selector);
                this.installLimitedForProbe(
                    bytes32((0x6000 + n++) << 224), v < 2 ? address(token) : address(usdc), unmetered[k], v % 2 == 0, caps
                );
            }
            // the same function on a contract the mandate sets no limit for is an ordinary entry
            bytes32 ok = bytes32((0x7000 + k) << 224);
            this.installPlainForProbe(ok, address(forbidden), unmetered[k], true);
            assertTrue(policy.isAllowed(address(this), ok, address(forbidden), unmetered[k]));
        }
        assertEq(n, 24);
    }

    /// External, so that `vm.expectRevert` sees the policy's revert as the next call's.
    function installLimitedForProbe(bytes32 id, address limited, bytes4 other, bool otherFirst, AgentPolicy.TokenCap[] memory caps)
        external
    {
        _installLimited(id, limited, other, otherFirst, caps);
    }

    /// Install: a metered function on a target the mandate sets no limit for
    /// would be refused at every operation, a mandate that cannot do what it
    /// lists; it is refused at install (#175). With a limit it installs.
    function test_probe2_installRefusesAMeteredFunctionWithoutALimit() public {
        bytes4[4] memory metered = [
            MockToken.transfer.selector, MockToken.approve.selector, bytes4(0x39509351), MockToken.transferFrom.selector
        ];
        AgentPolicy.TokenCap[] memory none = new AgentPolicy.TokenCap[](0);
        AgentPolicy.TokenCap[] memory capped = new AgentPolicy.TokenCap[](1);
        capped[0] = AgentPolicy.TokenCap(address(forbidden), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
        for (uint256 k; k < metered.length; k++) {
            address[] memory targets = new address[](2);
            bytes4[] memory selectors = new bytes4[](2);
            (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
            (targets[1], selectors[1]) = (address(forbidden), metered[k]);
            vm.expectRevert(AgentPolicy.InvalidConfig.selector);
            this.installForProbe(
                abi.encodePacked(bytes32((0xa000 + k) << 224), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, none, uint48(0)))
            );
            // the control: the same entry with a limit for that target
            bytes32 ok = bytes32((0xb000 + k) << 224);
            this.installForProbe(abi.encodePacked(ok, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, capped, uint48(0))));
            assertTrue(policy.isAllowed(address(this), ok, address(forbidden), metered[k]));
        }
    }

    /// An operator grant and an ERC-20 approval on one target cannot both be
    /// listed, so a grant opened by one cannot be closed by the other: with a
    /// limit `setApprovalForAll` is refused, without one `approve` is.
    function test_probe2_anOperatorGrantAndAnApprovalNeverShareATarget() public {
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(forbidden), bytes4(0xa22cb465)); // setApprovalForAll(address,bool)
        (targets[1], selectors[1]) = (address(forbidden), MockToken.approve.selector);
        AgentPolicy.TokenCap[] memory capped = new AgentPolicy.TokenCap[](1);
        capped[0] = AgentPolicy.TokenCap(address(forbidden), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        this.installForProbe(abi.encodePacked(bytes32(uint256(0xc001) << 224), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, capped, uint48(0))));
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        this.installForProbe(
            abi.encodePacked(bytes32(uint256(0xc002) << 224), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0)))
        );
    }

    function installForProbe(bytes calldata data) external {
        policy.onInstall(data);
    }

    /// A reinstall under the same id starts clean: the earlier mandate's
    /// limit does not get an entry refused, and its entries are gone.
    function test_probe2_reinstallForgetsTheEarlierLimitsAndEntries() public {
        bytes32 id = bytes32(uint256(0x51) << 224);
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(token), MockToken.transfer.selector);
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _tokenCaps(), uint48(0))));
        assertTrue(policy.tokenLimit(address(this), id, address(token)).set);
        policy.onUninstall(abi.encodePacked(id));
        // the token has no limit now, and `mint` on it is an ordinary entry
        (targets[1], selectors[1]) = (address(token), MockToken.mint.selector);
        policy.onInstall(
            abi.encodePacked(
                id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0))
            )
        );
        assertFalse(policy.tokenLimit(address(this), id, address(token)).set);
        assertTrue(policy.isAllowed(address(this), id, address(token), MockToken.mint.selector));
        assertFalse(policy.isAllowed(address(this), id, address(token), MockToken.transfer.selector));
        // and with the limit back, the same entry is refused
        policy.onUninstall(abi.encodePacked(id));
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _tokenCaps(), uint48(0))));
    }

    /// The slot the policy reads for `allowed[target][selector]` of the account's mandate.
    function _allowedSlot(bytes32 id, address target, bytes4 selector) internal returns (bytes32) {
        vm.record();
        policy.isAllowed(acct, id, target, selector);
        (bytes32[] memory reads,) = vm.accesses(address(policy));
        return reads[reads.length - 1];
    }

    /// Validation holds the rule on its own: an entry written straight into
    /// the mandate's storage, as an earlier version of the policy could have
    /// left it, is refused for a token with a limit.
    function test_probe2_validationRefusesAnUnmeteredEntryPlantedInStorage() public {
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        vm.store(address(policy), _allowedSlot(id, address(token), MockToken.mint.selector), bytes32(uint256(1)));
        assertTrue(policy.isAllowed(acct, id, address(token), MockToken.mint.selector), "not planted where the policy reads");
        _expectRefused(_agentOp(address(token), 0, abi.encodeCall(MockToken.mint, (STRANGER, 1_000_000 ether))));
        assertEq(token.balanceOf(STRANGER), 0);
        // planted the same way for a contract without a limit, an entry is an ordinary call and runs
        vm.store(address(policy), _allowedSlot(id, address(counter), Counter.reset.selector), bytes32(uint256(1)));
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 1);
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.reset.selector)));
        assertEq(counter.count(), 0);
    }

    address internal constant PERMIT2_ADDR = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    bytes4 internal constant PERMIT2_APPROVE = bytes4(keccak256("approve(address,address,uint160,uint48)"));

    /// External, so that `vm.expectRevert` sees the policy's revert as the next call's.
    function installPlainForProbe(bytes32 id, address target, bytes4 selector, bool targetFirst) external {
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (uint256 a, uint256 b) = targetFirst ? (0, 1) : (1, 0);
        (targets[a], selectors[a]) = (target, selector);
        (targets[b], selectors[b]) = (address(counter), Counter.increment.selector);
        policy.onInstall(
            abi.encodePacked(
                id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0))
            )
        );
    }

    /// Install: Permit2 is refused whatever the function and wherever it
    /// stands in the list; the address next to it is an ordinary target.
    function test_probe2_installRefusesPermit2WhateverTheFunction() public {
        bytes4[4] memory fns = [
            PERMIT2_APPROVE,
            bytes4(keccak256("transferFrom(address,address,uint160,address)")),
            MockToken.transfer.selector,
            bytes4(0)
        ];
        address neighbour = address(uint160(PERMIT2_ADDR) ^ 1);
        for (uint256 k; k < fns.length; k++) {
            for (uint256 first; first < 2; first++) {
                vm.expectRevert(abi.encodeWithSelector(AgentPolicy.ForbiddenTarget.selector, PERMIT2_ADDR, fns[k]));
                this.installPlainForProbe(bytes32((0x8000 + 2 * k + first) << 224), PERMIT2_ADDR, fns[k], first == 1);
            }
            bytes32 ok = bytes32((0x9000 + k) << 224);
            if (fns[k] == MockToken.transfer.selector) {
                // a metered function needs a limit for its target (#175), the neighbour's too
                vm.expectRevert(AgentPolicy.InvalidConfig.selector);
                this.installPlainForProbe(ok, neighbour, fns[k], true);
                continue;
            }
            this.installPlainForProbe(ok, neighbour, fns[k], true);
            assertTrue(policy.isAllowed(address(this), ok, neighbour, fns[k]));
        }
    }

    /// Validation: Permit2 written straight into a mandate's storage is
    /// refused as the account's call, as a batch leg, as a Safe's inner call
    /// and as a MultiSend leg; the address next to it, planted the same way,
    /// passes.
    function test_probe2_permit2PlantedInStorageIsRefusedOnEveryPath() public {
        bytes memory call_ =
            abi.encodeWithSelector(PERMIT2_APPROVE, address(token), STRANGER, type(uint160).max, type(uint48).max);
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        vm.store(address(policy), _allowedSlot(id, PERMIT2_ADDR, PERMIT2_APPROVE), bytes32(uint256(1)));
        assertTrue(policy.isAllowed(acct, id, PERMIT2_ADDR, PERMIT2_APPROVE), "not planted where the policy reads");
        _expectRefused(_agentOp(PERMIT2_ADDR, 0, call_));
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        calls[1] = Execution(PERMIT2_ADDR, 0, call_);
        _expectRefused(_agentBatchWith(AGENT, AGENT_ID, calls));

        Safe safe = _withSafe();
        bytes32 safeId = bytes32(PermissionId.unwrap(SAFE_ID));
        vm.store(address(policy), _allowedSlot(safeId, PERMIT2_ADDR, PERMIT2_APPROVE), bytes32(uint256(1)));
        assertTrue(policy.isAllowed(acct, safeId, PERMIT2_ADDR, PERMIT2_APPROVE), "not planted for the Safe's mandate");
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, PERMIT2_ADDR, 0, call_, Enum.Operation.Call, 0)));
        _expectRefused(
            _agentViaSafe(safe, _batch(safe, address(multiSend), _legOf(0, PERMIT2_ADDR, 0, call_), Enum.Operation.DelegateCall))
        );
        assertEq(counter.count(), 0);

        address neighbour = address(uint160(PERMIT2_ADDR) ^ 1);
        vm.store(address(policy), _allowedSlot(id, neighbour, PERMIT2_APPROVE), bytes32(uint256(1)));
        _send(_agentOp(neighbour, 0, call_));
    }
}
