// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

// Two probes of the payee lists written by the reviewer of #71: a Safe that
// holds a bound token, and the first head word of the install data.
import "./AgentPermission.t.sol";
import {ShapedMandate} from "./ShapedMandate.sol";

contract PayeeProbes is AgentPermissionTest {
    PermissionId internal constant PRB_ID = PermissionId.wrap(0x70726231); // "prb1"

    function _probeSafe() internal returns (Safe safe) {
        Safe singleton = new Safe();
        SafeProxyFactory f = new SafeProxyFactory();
        address[] memory owners = new address[](1);
        owners[0] = acct;
        bytes memory setup =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));
        safe = Safe(payable(address(f.createProxyWithNonce(address(singleton), setup, 0))));
        token.mint(address(safe), 10 ether);
        multiSend = new MultiSendCallOnly();
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(multiSend), MultiSendCallOnly.multiSend.selector);
        (targets[2], selectors[2]) = (address(token), MockToken.transfer.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0] = _list(address(token), PAYEE, address(0));
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0),
            address(policy),
            ShapedMandate.shaped(abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0), lists), address(shapesJudge))
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(PRB_ID);
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
                    ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    function _viaSafe(Safe safe, bytes memory execData) internal view returns (PackedUserOperation memory) {
        Execution[] memory calls = new Execution[](2);
        calls[0] =
            Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, execData);
        return _agentBatchWith(AGENT, PRB_ID, calls);
    }

    /// A Safe's calls reach the same check as the account's own: a single
    /// transfer and every leg of a batch are held to the payee list.
    function test_probe_safeTransfersAreHeldToThePayeeList() public {
        Safe safe = _probeSafe();
        bytes memory toPayee = abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether));
        bytes memory toStranger = abi.encodeCall(MockToken.transfer, (STRANGER, 1 ether));
        _send(_viaSafe(safe, _safeExec(safe, address(token), 0, toPayee, Enum.Operation.Call, 0)));
        assertEq(token.balanceOf(PAYEE), 1 ether);
        _expectRefused(_viaSafe(safe, _safeExec(safe, address(token), 0, toStranger, Enum.Operation.Call, 0)));
        bytes memory good = _legOf(0, address(token), 0, toPayee);
        bytes memory bad = _legOf(0, address(token), 0, toStranger);
        _send(_viaSafe(safe, _batch(safe, address(multiSend), bytes.concat(good, good), Enum.Operation.DelegateCall)));
        assertEq(token.balanceOf(PAYEE), 3 ether);
        _expectRefused(
            _viaSafe(safe, _batch(safe, address(multiSend), bytes.concat(good, bad), Enum.Operation.DelegateCall))
        );
        _expectRefused(
            _viaSafe(safe, _batch(safe, address(multiSend), bytes.concat(bad, good), Enum.Operation.DelegateCall))
        );
        assertEq(token.balanceOf(STRANGER), 0);
        assertEq(token.balanceOf(PAYEE), 3 ether);
    }

    /// Audit #76 F-2 through a Safe: the legs of a MultiSend batch add up
    /// against the token's per-operation cap.
    function test_probe_safeBatchLegsShareTheTokenCap() public {
        Safe safe = _probeSafe();
        bytes memory atCap = _legOf(0, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, TOKEN_MAX)));
        bytes memory one = _legOf(0, address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1)));
        _expectRefused(
            _viaSafe(safe, _batch(safe, address(multiSend), bytes.concat(atCap, one), Enum.Operation.DelegateCall))
        );
        assertEq(token.balanceOf(PAYEE), 0);
        _send(_viaSafe(safe, _batch(safe, address(multiSend), atCap, Enum.Operation.DelegateCall)));
        assertEq(token.balanceOf(PAYEE), TOKEN_MAX);
    }

    function _params(bool withLists) internal view returns (bytes memory) {
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(token), MockToken.transfer.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
        if (!withLists) return abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0));
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0] = _list(address(token), PAYEE, address(0));
        return abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0), lists);
    }

    function _withHead(bytes memory params, uint256 head) internal pure returns (bytes memory) {
        assembly {
            mstore(add(params, 32), head)
        }
        return params;
    }

    function _installs(bytes32 id, bytes memory params) internal returns (bool ok) {
        (ok,) = address(policy).call(abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(id, params))));
    }

    /// The first head word chooses the form. Whatever a caller writes there,
    /// a mandate is never installed with the lists silently dropped.
    function test_probe_headWordCannotDropTheLists() public {
        bytes32 a = bytes32(uint256(0xa1) << 224);
        bytes32 b = bytes32(uint256(0xa2) << 224);
        bytes32 c = bytes32(uint256(0xa3) << 224);
        bytes32 d = bytes32(uint256(0xa4) << 224);
        // the honest forms
        assertTrue(_installs(a, _params(true)), "eight words with lists");
        assertFalse(policy.payeeAllowed(address(this), a, address(token), STRANGER));
        assertTrue(policy.payeeAllowed(address(this), a, address(token), PAYEE));
        assertTrue(_installs(b, _params(false)), "seven words");
        assertTrue(policy.payeeAllowed(address(this), b, address(token), STRANGER));
        // eight words with lists under a head that says "seven": installed, the lists would be gone
        assertFalse(_installs(c, _withHead(_params(true), 7 * 32)), "eight words under a seven-word head installed");
        // seven words under a head that says "eight", and heads that are neither
        assertFalse(_installs(d, _withHead(_params(false), 8 * 32)), "seven words under an eight-word head installed");
        assertFalse(_installs(d, _withHead(_params(true), 9 * 32)), "head 0x120 installed");
        assertFalse(_installs(d, _withHead(_params(true), 0)), "head 0 installed");
    }
}
