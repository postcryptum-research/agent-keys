// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";

import {Kernel} from "kernel/src/Kernel.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";
import {ValidationManager} from "kernel/src/core/ValidationManager.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {IHook, IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {CallType, ExecMode, PermissionId, ValidationId} from "kernel/src/types/Types.sol";
import {
    CALLTYPE_BATCH,
    ERC1271_MAGICVALUE,
    SIG_VALIDATION_FAILED_UINT,
    VALIDATION_MODE_DEFAULT,
    VALIDATION_TYPE_PERMISSION,
    ValidationMode,
    ValidationType
} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

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

/// Phase 1b: the agent's hardware key is a *permission*, not the root.
///
/// Account layout:
///   root       = P256Validator with the OWNER key
///   permission = AgentPolicy (allow-list, value cap, budget, expiry)
///                + P256Signer with the AGENT key
///
/// The agent may call `counter.increment()` and send small amounts to it,
/// and nothing else. The owner key can do anything.
contract AgentPermissionTest is Test {
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant OWNER = 0x0000000000000000000000000000000000000000000000000000000000000AA1;
    uint256 internal constant AGENT = 0x0000000000000000000000000000000000000000000000000000000000000BB2;
    // A clean 4-byte literal, deliberately. `bytes4(keccak256(...))` leaves the
    // hash's remaining bytes as dirty low-order bits, and Kernel's
    // `ValidatorLib.permissionToIdentifier` ORs the raw word into the
    // ValidationId in assembly — the permission then installs under
    // `0x02 ++ id ++ <garbage>` while the nonce encodes `0x02 ++ id ++ 0…0`,
    // and every operation fails the allowed-selector check.
    PermissionId internal constant AGENT_ID = PermissionId.wrap(0x61676e74); // "agnt"

    uint128 internal constant MAX_VALUE = 0.1 ether;
    uint128 internal constant BUDGET = 0.25 ether;

    IEntryPoint internal entryPoint;
    P256Validator internal rootValidator;
    P256Signer internal signer;
    AgentPolicy internal policy;
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
        policy = new AgentPolicy();
        counter = new Counter();
        forbidden = new Counter();

        (uint256 x, uint256 y) = vm.publicKeyP256(OWNER);
        (ownerX, ownerY) = (bytes32(x), bytes32(y));
        (x, y) = vm.publicKeyP256(AGENT);
        (agentX, agentY) = (bytes32(x), bytes32(y));

        expiry = uint48(block.timestamp + 1 days);
        permVId = ValidatorLib.permissionToIdentifier(AGENT_ID);

        // --- the agent's mandate ---
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        targets[0] = address(counter);
        selectors[0] = Counter.increment.selector;
        targets[1] = address(counter);
        selectors[1] = bytes4(0); // plain value transfer
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0), address(policy), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry)
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        bytes memory permissionData = abi.encode(entries);

        // --- install the permission during account initialization ---
        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = permVId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: 1, hook: IHook(address(1))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = permissionData;
        bytes[] memory hData = new bytes[](1);
        bytes[] memory initConfig = new bytes[](2);
        initConfig[0] = abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData));
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
    }

    // --- helpers ---

    function _sign(uint256 priv, bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(priv, digest);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        return abi.encodePacked(r, s);
    }

    function _permissionNonce() internal view returns (uint256) {
        uint192 key = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(PermissionId.unwrap(AGENT_ID)),
            0
        );
        return entryPoint.getNonce(acct, key);
    }

    function _op(uint256 nonce, address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = PackedUserOperation({
            sender: acct,
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(target, value, data)
            ),
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | uint256(1_000_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    /// An operation authorized by the agent key under its permission.
    function _agentOp(address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(_permissionNonce(), target, value, data);
        // no policy signature segments; 0xff introduces the signer's bytes
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
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
            _op(entryPoint.getNonce(acct, 0), address(counter), 0, abi.encodeWithSelector(Counter.reset.selector));
        op.signature = _sign(AGENT, entryPoint.getUserOpHash(op));
        vm.expectRevert();
        _send(op);

        op.signature = _sign(OWNER, entryPoint.getUserOpHash(op));
        _send(op); // the owner is not bound by the agent's mandate
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

        // batch mode
        op.callData = abi.encodeWithSelector(
            IERC7579Account.execute.selector,
            ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
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

}
