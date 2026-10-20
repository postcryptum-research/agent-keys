// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";

import {Kernel} from "kernel/src/Kernel.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";
import {ValidationManager} from "kernel/src/core/ValidationManager.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {IHook, IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {CallType, ExecMode, PermissionId, ValidationId} from "kernel/src/types/Types.sol";
import {
    CALLTYPE_BATCH,
    ERC1271_MAGICVALUE,
    SIG_VALIDATION_FAILED_UINT,
    VALIDATION_MODE_DEFAULT,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_TYPE_VALIDATOR,
    ValidationMode,
    ValidationType
} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

import {Safe} from "safe-smart-account/Safe.sol";
import {SafeProxyFactory} from "safe-smart-account/proxies/SafeProxyFactory.sol";
import {Enum} from "safe-smart-account/common/Enum.sol";
import {MultiSendCallOnly} from "safe-smart-account/libraries/MultiSendCallOnly.sol";

/// A minimal ERC-20 for the token-limit tests.
contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }

    function reset() external {
        count = 0;
    }

    receive() external payable {}
}

/// Phase 1b / 3.3: the agent's hardware key is a *permission*, not the root.
///
/// Account layout:
///   root       = P256Validator with the OWNER key
///   permission = AgentPolicy (allow-list, value cap, budget, expiry)
///                + P256Signer with the AGENT key
///
/// The agent may call `counter.increment()` and send small amounts to it,
/// and nothing else. The owner key can do anything — including revoking the
/// agent or rotating it to a new key.
contract AgentPermissionTest is Test {
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant OWNER = 0x0000000000000000000000000000000000000000000000000000000000000AA1;
    uint256 internal constant AGENT = 0x0000000000000000000000000000000000000000000000000000000000000BB2;
    uint256 internal constant AGENT2 = 0x0000000000000000000000000000000000000000000000000000000000000CC3;
    // A clean 4-byte literal, deliberately. `bytes4(keccak256(...))` leaves the
    // hash's remaining bytes as dirty low-order bits, and Kernel's
    // `ValidatorLib.permissionToIdentifier` ORs the raw word into the
    // ValidationId in assembly — the permission then installs under
    // `0x02 ++ id ++ <garbage>` while the nonce encodes `0x02 ++ id ++ 0…0`,
    // and every operation fails the allowed-selector check.
    PermissionId internal constant AGENT_ID = PermissionId.wrap(0x61676e74); // "agnt"
    PermissionId internal constant AGENT_ID2 = PermissionId.wrap(0x61676e32); // "agn2"

    uint128 internal constant MAX_VALUE = 0.1 ether;
    uint128 internal constant BUDGET = 0.25 ether;

    IEntryPoint internal entryPoint;
    P256Validator internal rootValidator;
    P256Signer internal signer;
    AgentPolicy internal policy;
    SafeNonceAssert internal nonceAssert;
    MockToken internal token;
    Counter internal counter;
    Counter internal forbidden;

    address internal acct;
    ValidationId internal permVId;
    uint48 internal expiry;
    bytes32 internal ownerX;
    bytes32 internal ownerY;
    bytes32 internal agentX;
    bytes32 internal agentY;

    function setUp() public {
        entryPoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));
        rootValidator = new P256Validator();
        signer = new P256Signer();
        nonceAssert = new SafeNonceAssert();
        policy = new AgentPolicy(address(nonceAssert));
        token = new MockToken();
        counter = new Counter();
        forbidden = new Counter();

        (uint256 x, uint256 y) = vm.publicKeyP256(OWNER);
        (ownerX, ownerY) = (bytes32(x), bytes32(y));
        (x, y) = vm.publicKeyP256(AGENT);
        (agentX, agentY) = (bytes32(x), bytes32(y));

        expiry = uint48(block.timestamp + 1 days);
        permVId = ValidatorLib.permissionToIdentifier(AGENT_ID);

        // --- install the permission during account initialization ---
        bytes[] memory initConfig = new bytes[](2);
        initConfig[0] = _installCall(permVId, 1, _permissionData(agentX, agentY));
        initConfig[1] = abi.encodeCall(Kernel.grantAccess, (permVId, Kernel.execute.selector, true));

        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(IValidator(address(rootValidator))),
            IHook(address(0)),
            abi.encode(ownerX, ownerY),
            hex"",
            initConfig
        );
        acct = KernelFactory(factory).createAccount(initData, bytes32(0));
        vm.deal(acct, 10 ether);
        token.mint(acct, 100 ether);
    }

    // --- helpers ---

    /// Token limits for the agent's mandate: at most 10 tokens per operation,
    /// 25 in total.
    uint128 internal constant TOKEN_MAX = 10 ether;
    uint128 internal constant TOKEN_BUDGET = 25 ether;
    /// Every test operation pays its own gas: (1M + 1M + 100k) gas at 1 gwei,
    /// charged to the budget at validation.
    uint256 internal constant GAS_PER_OP = 2_100_000 gwei;

    function _tokenCaps() internal view returns (AgentPolicy.TokenCap[] memory caps) {
        caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET);
    }

    function _policyEntry(address[] memory targets, bytes4[] memory selectors, AgentPolicy.TokenCap[] memory caps)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes2(0), address(policy), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps)
        );
    }

    /// The agent's mandate with a given signer key: increment the counter,
    /// send it small amounts, transfer and approve the token within limits.
    function _permissionData(bytes32 keyX, bytes32 keyY) internal view returns (bytes memory) {
        address[] memory targets = new address[](5);
        bytes4[] memory selectors = new bytes4[](5);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(counter), bytes4(0)); // plain value transfer
        (targets[2], selectors[2]) = (address(token), MockToken.transfer.selector);
        (targets[3], selectors[3]) = (address(token), MockToken.approve.selector);
        (targets[4], selectors[4]) = (address(forbidden), MockToken.transfer.selector); // no token limit
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, _tokenCaps());
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(keyX, keyY));
        return abi.encode(entries);
    }

    function _installCall(ValidationId vId, uint32 nonce, bytes memory permissionData)
        internal
        pure
        returns (bytes memory)
    {
        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = vId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: nonce, hook: IHook(address(1))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = permissionData;
        bytes[] memory hData = new bytes[](1);
        return abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData));
    }

    /// Kernel's PermissionDisableDataFormat: one entry per policy, then the
    /// signer. Our modules need nothing beyond the id Kernel prepends.
    function _uninstallCall(ValidationId vId) internal pure returns (bytes memory) {
        bytes[] memory entries = new bytes[](2);
        return abi.encodeCall(Kernel.uninstallValidation, (vId, abi.encode(entries), hex""));
    }

    /// Low-s normalized `abi.encodePacked(r, s)`, exactly what `agent-signer` emits.
    function _sign(uint256 priv, bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(priv, digest);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        return abi.encodePacked(r, s);
    }

    function _permissionNonce(PermissionId id) internal view returns (uint256) {
        uint192 key = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(PermissionId.unwrap(id)),
            0
        );
        return entryPoint.getNonce(acct, key);
    }

    function _op(uint256 nonce, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: acct,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | uint256(1_000_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _singleCall(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(target, value, data)
        );
    }

    /// An operation authorized by an agent key under its permission.
    function _agentOpWith(uint256 priv, PermissionId id, address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(_permissionNonce(id), _singleCall(target, value, data));
        // no policy signature segments; 0xff introduces the signer's bytes
        op.signature = abi.encodePacked(bytes1(0xff), _sign(priv, entryPoint.getUserOpHash(op)));
    }

    function _agentOp(address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return _agentOpWith(AGENT, AGENT_ID, target, value, data);
    }

    /// An agent operation that executes a Kernel batch.
    function _agentBatchWith(uint256 priv, PermissionId id, Execution[] memory calls)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(calls)
        );
        op = _op(_permissionNonce(id), callData);
        op.signature = abi.encodePacked(bytes1(0xff), _sign(priv, entryPoint.getUserOpHash(op)));
    }

    function _spent(PermissionId id) internal view returns (uint128 spent) {
        (,,,, spent) = policy.configs(acct, bytes32(PermissionId.unwrap(id)));
    }

    /// A root-path operation with arbitrary calldata, signed by the OWNER key.
    function _rootOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = _op(entryPoint.getNonce(acct, 0), callData);
        op.signature = _sign(OWNER, entryPoint.getUserOpHash(op));
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
    }

    // --- the mandate holds ---

    function test_setup_installedPermission() public view {
        (bytes32 x, bytes32 y) = signer.publicKeys(bytes32(PermissionId.unwrap(AGENT_ID)), acct);
        assertEq(x, agentX);
        assertEq(y, agentY);
        assertTrue(policy.isAllowed(acct, bytes32(PermissionId.unwrap(AGENT_ID)), address(counter), Counter.increment.selector));
        assertFalse(policy.isAllowed(acct, bytes32(PermissionId.unwrap(AGENT_ID)), address(counter), Counter.reset.selector));
    }

    function test_agent_callsAllowedTarget() public {
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 1);
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 2);
    }

    function test_agent_cannotCallOtherSelector() public {
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        PackedUserOperation memory op = _agentOp(address(counter), 0, abi.encodeWithSelector(Counter.reset.selector));
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 1, "reset must not run");
    }

    function test_agent_cannotCallOtherTarget() public {
        PackedUserOperation memory op =
            _agentOp(address(forbidden), 0, abi.encodeWithSelector(Counter.increment.selector));
        vm.expectRevert();
        _send(op);
        assertEq(forbidden.count(), 0);
    }

    function test_agent_valueCapAndBudget() public {
        _send(_agentOp(address(counter), 0.1 ether, ""));
        _send(_agentOp(address(counter), 0.1 ether, ""));
        assertEq(address(counter).balance, 0.2 ether);

        PackedUserOperation memory overCap = _agentOp(address(counter), 0.2 ether, "");
        vm.expectRevert();
        _send(overCap);

        PackedUserOperation memory overBudget = _agentOp(address(counter), 0.1 ether, "");
        vm.expectRevert();
        _send(overBudget);
        assertEq(address(counter).balance, 0.2 ether, "budget holds at 0.25 with 0.1 steps");
    }

    function test_agent_expires() public {
        vm.warp(uint256(expiry) + 1);
        PackedUserOperation memory op =
            _agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 0);
    }

    function test_agent_keyIsNotRoot() public {
        // root nonce (key 0) routes to P256Validator, which only knows the OWNER key
        PackedUserOperation memory op =
            _op(entryPoint.getNonce(acct, 0), _singleCall(address(counter), 0, abi.encodeWithSelector(Counter.reset.selector)));
        op.signature = _sign(AGENT, entryPoint.getUserOpHash(op));
        vm.expectRevert();
        _send(op);

        op.signature = _sign(OWNER, entryPoint.getUserOpHash(op));
        _send(op); // the owner is not bound by the agent's mandate
    }

    // --- the owner controls the mandate ---

    function test_owner_revokesAgent() public {
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 1);

        _send(_rootOp(_uninstallCall(permVId)));

        assertFalse(policy.isAllowed(acct, bytes32(PermissionId.unwrap(AGENT_ID)), address(counter), Counter.increment.selector));
        (bytes32 x,) = signer.publicKeys(bytes32(PermissionId.unwrap(AGENT_ID)), acct);
        assertEq(x, bytes32(0), "signer key removed");

        PackedUserOperation memory op = _agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 1, "the revoked agent cannot act");
    }

    function test_owner_rotatesAgentKey() public {
        (uint256 x2, uint256 y2) = vm.publicKeyP256(AGENT2);
        ValidationId permVId2 = ValidatorLib.permissionToIdentifier(AGENT_ID2);
        // a never-installed permission installs at the account's current nonce
        uint32 nonce = Kernel(payable(acct)).currentNonce();

        // one root operation: revoke the old permission, install the new one
        // (same mandate, new key), grant it execute()
        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution(acct, 0, _uninstallCall(permVId));
        batch[1] = Execution(acct, 0, _installCall(permVId2, nonce, _permissionData(bytes32(x2), bytes32(y2))));
        batch[2] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (permVId2, Kernel.execute.selector, true)));
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
        );
        _send(_rootOp(callData));

        // the old key under the old permission is dead
        PackedUserOperation memory stale = _agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        vm.expectRevert();
        _send(stale);

        // the new key under the new permission works, within the same mandate
        _send(_agentOpWith(AGENT2, AGENT_ID2, address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 1);
        PackedUserOperation memory outside =
            _agentOpWith(AGENT2, AGENT_ID2, address(counter), 0, abi.encodeWithSelector(Counter.reset.selector));
        vm.expectRevert();
        _send(outside);
    }

    // --- modules in isolation ---

    function test_signer_tpmVectorPasses() public {
        string memory json = vm.readFile("test/vectors/p256_tpm.json");
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        address a = makeAddr("account");
        vm.prank(a);
        signer.onInstall(
            abi.encodePacked(id, abi.encode(vm.parseJsonBytes32(json, ".x"), vm.parseJsonBytes32(json, ".y")))
        );
        bytes memory sig = abi.encodePacked(vm.parseJsonBytes32(json, ".r"), vm.parseJsonBytes32(json, ".s"));
        vm.prank(a);
        assertEq(signer.checkSignature(id, address(0), vm.parseJsonBytes32(json, ".digest"), sig), ERC1271_MAGICVALUE);
    }

    function test_policy_rejectsBatchAndMalformedCalls() public {
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        PackedUserOperation memory op;
        op.sender = acct;

        // batch mode with a single call's encoding: the same decoder Kernel
        // executes with rejects it (a revert in validation is a refusal)
        op.callData = abi.encodeWithSelector(
            IERC7579Account.execute.selector,
            ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
            ExecLib.encodeSingle(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
        );
        vm.prank(acct);
        vm.expectRevert();
        policy.checkUserOpPolicy(id, op);

        // "try" exec type, which would let a failed leg pass silently
        op.callData = abi.encodeWithSelector(
            IERC7579Account.execute.selector,
            ExecMode.wrap(bytes32(uint256(1) << 240)), // calltype single, exectype try
            ExecLib.encodeSingle(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
        );
        vm.prank(acct);
        assertEq(policy.checkUserOpPolicy(id, op), SIG_VALIDATION_FAILED_UINT);

        // not execute() at all
        op.callData = abi.encodeWithSelector(Kernel.grantAccess.selector, permVId, bytes4(0), true);
        vm.prank(acct);
        assertEq(policy.checkUserOpPolicy(id, op), SIG_VALIDATION_FAILED_UINT);

        // truncated
        op.callData = hex"e9ae5c53";
        vm.prank(acct);
        assertEq(policy.checkUserOpPolicy(id, op), SIG_VALIDATION_FAILED_UINT);
    }

    function test_policy_deniesErc1271() public view {
        assertEq(
            policy.checkSignaturePolicy(bytes32(PermissionId.unwrap(AGENT_ID)), address(0), keccak256("permit"), ""),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    // --- Safe pass-through: the agent drives a Safe this account owns ---

    PermissionId internal constant SAFE_ID = PermissionId.wrap(0x73616665); // "safe"

    MultiSendCallOnly internal multiSend;

    /// A 1/1 Safe owned by the Kernel account, holding 1 ether, and a second
    /// permission for the agent: drive that Safe, whose inner call may only
    /// be `counter.increment()` or a small transfer to the counter — alone or
    /// batched through MultiSendCallOnly.
    function _withSafe() internal returns (Safe safe) {
        Safe singleton = new Safe();
        SafeProxyFactory safeFactory = new SafeProxyFactory();
        address[] memory owners = new address[](1);
        owners[0] = acct;
        bytes memory setup = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = Safe(payable(address(safeFactory.createProxyWithNonce(address(singleton), setup, 0))));
        vm.deal(address(safe), 1 ether);

        multiSend = new MultiSendCallOnly();
        address[] memory targets = new address[](4);
        bytes4[] memory selectors = new bytes4[](4);
        (targets[3], selectors[3]) = (address(multiSend), MultiSendCallOnly.multiSend.selector);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(counter), Counter.increment.selector);
        (targets[2], selectors[2]) = (address(counter), bytes4(0));
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, new AgentPolicy.TokenCap[](0));
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));

        ValidationId vId = ValidatorLib.permissionToIdentifier(SAFE_ID);
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

    /// `execTransaction` with a pre-validated signature: v = 1 and r = the
    /// owner, accepted because the owner (the Kernel account) is msg.sender.
    function _safeExec(Safe, address to, uint256 value, bytes memory data, Enum.Operation op, uint256 gasPrice)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sig = abi.encodePacked(uint256(uint160(acct)), uint256(0), uint8(1));
        return abi.encodeCall(
            Safe.execTransaction, (to, value, data, op, 0, 0, gasPrice, address(0), payable(address(0)), sig)
        );
    }

    /// The only shape the policy admits for a Safe transaction: a batch that
    /// first asserts the Safe's current nonce.
    function _agentViaSafe(Safe safe, bytes memory execData) internal view returns (PackedUserOperation memory) {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, execData);
        return _agentBatchWith(AGENT, SAFE_ID, calls);
    }

    function _expectRefused(PackedUserOperation memory op) internal {
        vm.expectRevert();
        _send(op);
    }

    function test_safe_agentDrivesAllowedInnerCall() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0)));
        assertEq(counter.count(), 1);

        // a small transfer out of the Safe counts against cap and budget
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.1 ether, "", Enum.Operation.Call, 0)));
        assertEq(address(counter).balance, 0.1 ether);
        assertEq(address(safe).balance, 0.9 ether);
        assertEq(_spent(SAFE_ID), 0.1 ether + 2 * GAS_PER_OP);
    }

    function test_safe_innerCallIsHeldToTheAllowList() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // other target, other selector
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(forbidden), 0, inc, Enum.Operation.Call, 0)));
        _expectRefused(
            _agentViaSafe(
                safe,
                _safeExec(safe, address(counter), 0, abi.encodeWithSelector(Counter.reset.selector), Enum.Operation.Call, 0)
            )
        );
        // the Safe reconfiguring itself: add an owner the agent controls
        bytes memory addOwner = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", makeAddr("attacker"), 1);
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(safe), 0, addOwner, Enum.Operation.Call, 0)));
        assertEq(counter.count(), 0);
        assertFalse(safe.isOwner(makeAddr("attacker")));
    }

    function test_safe_refusesDelegatecallRefundsAndNesting() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // delegatecall would run the target's code as the Safe
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(counter), 0, inc, Enum.Operation.DelegateCall, 0)));
        // gasPrice > 0 makes the Safe pay a refund out of its own balance
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 1 gwei)));
        // execTransaction wrapping execTransaction
        bytes memory inner = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(safe), 0, inner, Enum.Operation.Call, 0)));
        assertEq(counter.count(), 0);
    }

    function test_safe_innerValueCapAndBudget() public {
        Safe safe = _withSafe();
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.2 ether, "", Enum.Operation.Call, 0)));
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.1 ether, "", Enum.Operation.Call, 0)));
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.1 ether, "", Enum.Operation.Call, 0)));
        // 0.2 spent of 0.25: another 0.1 would exceed the budget
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(counter), 0.1 ether, "", Enum.Operation.Call, 0)));
        assertEq(address(safe).balance, 0.8 ether);
    }

    function test_safe_otherSafeFunctionsAreNotAllowed() public {
        Safe safe = _withSafe();
        // calling the Safe directly with anything but execTransaction
        bytes memory addOwner = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", makeAddr("attacker"), 1);
        _expectRefused(_agentOpWith(AGENT, SAFE_ID, address(safe), 0, addOwner));
        // the original permission has no Safe entry at all
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        _expectRefused(_agentOp(address(safe), 0, _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0)));
    }

    // --- batches: DELEGATECALL into MultiSendCallOnly, every leg judged ---

    function _legOf(uint8 op, address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(op, to, value, data.length, data);
    }

    function _batch(Safe safe, address ms, bytes memory txs, Enum.Operation op) internal view returns (bytes memory) {
        return _safeExec(safe, ms, 0, abi.encodeCall(MultiSendCallOnly.multiSend, (txs)), op, 0);
    }

    function test_batch_allowedLegsRunAsTheSafe() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        bytes memory txs = bytes.concat(_legOf(0, address(counter), 0, inc), _legOf(0, address(counter), 0.05 ether, ""));
        _send(_agentViaSafe(safe, _batch(safe, address(multiSend), txs, Enum.Operation.DelegateCall)));
        assertEq(counter.count(), 1);
        assertEq(address(counter).balance, 0.05 ether);
        assertEq(_spent(SAFE_ID), 0.05 ether + GAS_PER_OP);
    }

    function test_batch_everyLegIsJudged() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        bytes memory ok = _legOf(0, address(counter), 0, inc);
        // one forbidden leg spoils the batch
        _expectRefused(
            _agentViaSafe(
                safe,
                _batch(safe, address(multiSend), bytes.concat(ok, _legOf(0, address(forbidden), 0, inc)), Enum.Operation.DelegateCall)
            )
        );
        // a delegatecall leg
        _expectRefused(
            _agentViaSafe(
                safe,
                _batch(safe, address(multiSend), bytes.concat(ok, _legOf(1, address(counter), 0, inc)), Enum.Operation.DelegateCall)
            )
        );
        // a leg that reconfigures the Safe
        bytes memory addOwner = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", makeAddr("attacker"), 1);
        _expectRefused(
            _agentViaSafe(
                safe,
                _batch(safe, address(multiSend), bytes.concat(ok, _legOf(0, address(safe), 0, addOwner)), Enum.Operation.DelegateCall)
            )
        );
        // a leg that is itself a Safe transaction
        bytes memory nested = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
        _expectRefused(
            _agentViaSafe(
                safe,
                _batch(safe, address(multiSend), bytes.concat(ok, _legOf(0, address(safe), 0, nested)), Enum.Operation.DelegateCall)
            )
        );
        assertEq(counter.count(), 0);
    }

    function test_batch_legValuesAddUp() public {
        Safe safe = _withSafe();
        // 0.06 + 0.06 > 0.1 per-operation cap, though each leg is under it
        bytes memory txs = bytes.concat(_legOf(0, address(counter), 0.06 ether, ""), _legOf(0, address(counter), 0.06 ether, ""));
        _expectRefused(_agentViaSafe(safe, _batch(safe, address(multiSend), txs, Enum.Operation.DelegateCall)));
    }

    function test_batch_onlyAnAllowListedBatcherAndOnlyByDelegatecall() public {
        Safe safe = _withSafe();
        bytes memory txs = _legOf(0, address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        // the same code at an address the owner did not allow-list
        MultiSendCallOnly other = new MultiSendCallOnly();
        _expectRefused(_agentViaSafe(safe, _batch(safe, address(other), txs, Enum.Operation.DelegateCall)));
        // CALLing the batcher would run the legs as the batcher, not the Safe
        _expectRefused(_agentViaSafe(safe, _batch(safe, address(multiSend), txs, Enum.Operation.Call)));
        // and the account itself cannot call it directly
        _expectRefused(
            _agentOpWith(AGENT, SAFE_ID, address(multiSend), 0, abi.encodeCall(MultiSendCallOnly.multiSend, (txs)))
        );
        assertEq(counter.count(), 0);
    }

    // --- audit 2026-10-20 fixes ---

    /// F2: token amounts are capped per operation and per budget; an
    /// allow-listed token selector without a token limit is refused.
    function test_token_amountsAreCapped() public {
        address to = makeAddr("recipient");
        _send(_agentOp(address(token), 0, abi.encodeCall(MockToken.transfer, (to, 10 ether))));
        assertEq(token.balanceOf(to), 10 ether);
        // over the per-operation cap
        _expectRefused(_agentOp(address(token), 0, abi.encodeCall(MockToken.transfer, (to, 11 ether))));
        _send(_agentOp(address(token), 0, abi.encodeCall(MockToken.transfer, (to, 10 ether))));
        // 20 of 25 spent: 10 more would exceed the token budget
        _expectRefused(_agentOp(address(token), 0, abi.encodeCall(MockToken.transfer, (to, 10 ether))));
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(AGENT_ID)), address(token)).spent, 20 ether);
    }

    function test_token_unlimitedApproveIsRefused() public {
        address spender = makeAddr("spender");
        _expectRefused(_agentOp(address(token), 0, abi.encodeCall(MockToken.approve, (spender, type(uint256).max))));
        _send(_agentOp(address(token), 0, abi.encodeCall(MockToken.approve, (spender, 5 ether))));
        assertEq(token.allowance(acct, spender), 5 ether);
    }

    function test_token_selectorWithoutLimitIsRefused() public {
        // (forbidden, transfer) is allow-listed, but no token limit exists for
        // it: refused even for a zero amount — without a limit the policy
        // does not know what that selector means on that contract
        _expectRefused(_agentOp(address(forbidden), 0, abi.encodeCall(MockToken.transfer, (address(1), 0))));
    }

    /// F3: when the account pays its own gas, the maximum charge counts
    /// against the budget.
    function test_gas_selfPaidCountsAgainstBudget() public {
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(_spent(AGENT_ID), GAS_PER_OP);
    }

    /// F4: a Safe transaction outside the nonce-guarded pair is refused, and
    /// a replay of a guarded one cannot execute twice.
    function test_safe_unguardedIsRefused() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        bytes memory exec = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
        // a single call, as before
        _expectRefused(_agentOpWith(AGENT, SAFE_ID, address(safe), 0, exec));
        // a batch without the assertion
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution(address(safe), 0, exec);
        _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        // an assertion about another address
        calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(counter), 0)));
        calls[1] = Execution(address(safe), 0, exec);
        _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        assertEq(counter.count(), 0);
    }

    function test_safe_replayCannotExecuteTwice() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        bytes memory exec = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, exec);
        _send(_agentBatchWith(AGENT, SAFE_ID, calls));
        assertEq(counter.count(), 1);
        // the same pair again, as a host retry would send it: valid
        // signature, admitted by the policy — and the assertion reverts it
        _send(_agentBatchWith(AGENT, SAFE_ID, calls));
        assertEq(counter.count(), 1);
        assertEq(safe.nonce(), 1);
    }

    /// F6: 1–3 bytes of calldata run the fallback; not a value transfer.
    function test_shortCalldataIsRefused() public {
        _expectRefused(_agentOp(address(counter), 0, hex"0102"));
        _send(_agentOp(address(counter), 0.01 ether, ""));
    }

    /// F7: a public key off the curve is rejected at install.
    function test_offCurveKeyIsRejected() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(AGENT2);
        bytes32 id = bytes32(PermissionId.unwrap(PermissionId.wrap(0x6f666663))); // "offc"
        vm.expectRevert();
        signer.onInstall(abi.encodePacked(id, bytes32(x), bytes32(y + 1)));
        P256Validator fresh = new P256Validator();
        vm.expectRevert();
        fresh.onInstall(abi.encode(bytes32(x), bytes32(y ^ 1)));
        // the real key installs
        signer.onInstall(abi.encodePacked(id, bytes32(x), bytes32(y)));
    }

    // --- cold recovery owner (docs/RESILIENCE.md, docs/KEY_POLICY.md rule 5) ---

    uint256 internal constant RECOVERY = 0x0000000000000000000000000000000000000000000000000000000000000DD4;
    uint256 internal constant NEW_OWNER = 0x0000000000000000000000000000000000000000000000000000000000000EE5;

    /// The owner installs a second validator holding the recovery key and
    /// grants it one selector: `changeRootValidator`.
    function _withRecovery() internal returns (P256Validator recovery, ValidationId rVId) {
        recovery = new P256RecoveryValidator();
        rVId = ValidatorLib.validatorToIdentifier(IValidator(address(recovery)));
        (uint256 x, uint256 y) = vm.publicKeyP256(RECOVERY);

        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = rVId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: Kernel(payable(acct)).currentNonce(), hook: IHook(address(1))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = abi.encode(bytes32(x), bytes32(y));
        bytes[] memory hData = new bytes[](1);

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (rVId, Kernel.changeRootValidator.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    /// An operation validated by the recovery validator (not root).
    function _recoveryOp(P256Validator recovery, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        uint192 key = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(recovery)),
            0
        );
        op = _op(entryPoint.getNonce(acct, key), callData);
        op.signature = _sign(RECOVERY, entryPoint.getUserOpHash(op));
    }

    /// A root operation signed by an arbitrary key (whoever is root now).
    function _rootOpWith(uint256 priv, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = _op(entryPoint.getNonce(acct, 0), callData);
        op.signature = _sign(priv, entryPoint.getUserOpHash(op));
    }

    function test_recovery_canOnlyTakeOverRoot() public {
        (P256Validator recovery,) = _withRecovery();
        // anything but changeRootValidator is refused for the recovery key
        bytes memory inc = _singleCall(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        _expectRefused(_recoveryOp(recovery, inc));
        assertEq(counter.count(), 0);
        // and the owner keeps working
        _send(_rootOp(inc));
        assertEq(counter.count(), 1);
    }

    function test_recovery_neverSignsMessages() public {
        (P256Validator recovery,) = _withRecovery();
        bytes32 h = keccak256("permit");
        // a perfectly valid signature by the recovery key: still refused,
        // because Kernel asks installed validators about ERC-1271 without
        // looking at the selectors granted to them (called as the account,
        // the way Kernel calls it)
        vm.prank(acct);
        assertEq(recovery.isValidSignatureWithSender(address(0), h, _sign(RECOVERY, h)), bytes4(0xffffffff));
    }

    function test_recovery_replacesALostOwner() public {
        (P256Validator recovery, ValidationId rVId) = _withRecovery();
        ValidationId ownerVId = ValidatorLib.validatorToIdentifier(IValidator(address(rootValidator)));

        // the owner key is lost: the recovery key makes itself root ...
        _send(_recoveryOp(recovery, abi.encodeCall(Kernel.changeRootValidator, (rVId, IHook(address(0)), "", ""))));
        assertEq(ValidationId.unwrap(Kernel(payable(acct)).rootValidator()), ValidationId.unwrap(rVId));

        // ... the old owner key no longer controls the account ...
        bytes memory inc = _singleCall(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        _expectRefused(_rootOpWith(OWNER, inc));

        // ... and, as root, retires the lost key and installs the new owner
        // key in the same validator, in one batch
        (uint256 x, uint256 y) = vm.publicKeyP256(NEW_OWNER);
        // Kernel refuses to reinstall a validator under the nonce it was
        // installed with before: use the current nonce, or one more
        uint32 current = Kernel(payable(acct)).currentNonce();
        uint32 nonce = Kernel(payable(acct)).validationConfig(ownerVId).nonce == current ? current + 1 : current;
        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = ownerVId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: nonce, hook: IHook(address(1))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = abi.encode(bytes32(x), bytes32(y));
        bytes[] memory hData = new bytes[](1);
        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution(acct, 0, abi.encodeCall(Kernel.uninstallValidation, (ownerVId, "", "")));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData)));
        batch[2] = Execution(acct, 0, abi.encodeCall(Kernel.changeRootValidator, (ownerVId, IHook(address(1)), "", "")));
        _send(
            _rootOpWith(
                RECOVERY,
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
        _send(_rootOpWith(NEW_OWNER, inc));
        assertEq(counter.count(), 1);

        // the lost key is gone for messages too: the validator holds the new key
        bytes32 h = keccak256("anything");
        vm.prank(acct);
        assertEq(rootValidator.isValidSignatureWithSender(address(0), h, _sign(OWNER, h)), bytes4(0xffffffff));
        vm.prank(acct);
        assertEq(rootValidator.isValidSignatureWithSender(address(0), h, _sign(NEW_OWNER, h)), bytes4(0x1626ba7e));

        // the recovery key is back to being recovery only
        _expectRefused(_recoveryOp(recovery, inc));
        // and the agent's mandate survived the whole exchange
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 2);
    }
}
