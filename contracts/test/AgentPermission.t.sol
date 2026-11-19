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

interface IERC1271Like {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// The EIP-3009 path of USDC FiatToken v2.2, reduced to what x402 uses:
/// an EIP-712 digest in the token's domain, ERC-1271 for contract wallets,
/// one use per (authorizer, nonce), the [validAfter, validBefore) window.
contract MockUSDC {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("USDC"),
                keccak256("2"),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(block.timestamp > validAfter && block.timestamp < validBefore, "FiatTokenV2: authorization window");
        require(!authorizationState[from][nonce], "FiatTokenV2: authorization is used or canceled");
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
        (bool ok, bytes memory ret) =
            from.staticcall(abi.encodeCall(IERC1271Like.isValidSignature, (digest, signature)));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e, "FiatTokenV2: invalid signature");
        authorizationState[from][nonce] = true;
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }

    function digestOf(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
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
        caps[0] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
    }

    function _policyEntry(address[] memory targets, bytes4[] memory selectors, AgentPolicy.TokenCap[] memory caps)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes2(0), address(policy), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))
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
        (,,,, spent,) = policy.configs(acct, bytes32(PermissionId.unwrap(id)));
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

    // --- schedule: permissions with their own time windows ---

    /// A second permission for the same agent key: only increments, only
    /// within [opensAt, closesAt].
    function _addWindowedPermission(PermissionId id, uint48 opensAt, uint48 closesAt) internal {
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0),
            address(policy),
            abi.encode(targets, selectors, MAX_VALUE, BUDGET, closesAt, new AgentPolicy.TokenCap[](0), opensAt)
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(id);
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    function test_schedule_windowIsEnforced() public {
        PermissionId friday = PermissionId.wrap(0x66726931); // "fri1"
        uint48 opens = uint48(block.timestamp + 2 days);
        uint48 closes = uint48(block.timestamp + 3 days);
        _addWindowedPermission(friday, opens, closes);
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);

        // before the window: refused
        _expectRefused(_agentOpWith(AGENT, friday, address(counter), 0, inc));
        // inside it: works
        vm.warp(opens + 1);
        _send(_agentOpWith(AGENT, friday, address(counter), 0, inc));
        assertEq(counter.count(), 1);
        // after it: refused
        vm.warp(closes + 1);
        _expectRefused(_agentOpWith(AGENT, friday, address(counter), 0, inc));
        assertEq(counter.count(), 1);
    }

    function test_schedule_windowsCoexist() public {
        // the everyday permission (no start) and a later window, side by side
        PermissionId later = PermissionId.wrap(0x6c617465); // "late"
        _addWindowedPermission(later, uint48(block.timestamp + 1 hours), uint48(block.timestamp + 2 hours));
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        _send(_agentOp(address(counter), 0, inc));
        _expectRefused(_agentOpWith(AGENT, later, address(counter), 0, inc));
        vm.warp(block.timestamp + 1 hours + 1);
        _send(_agentOpWith(AGENT, later, address(counter), 0, inc));
        _send(_agentOp(address(counter), 0, inc));
        assertEq(counter.count(), 3);
    }

    function test_schedule_emptyWindowIsRejected() public {
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        bytes memory install = abi.encodePacked(
            bytes32(uint256(0x77)),
            abi.encode(targets, selectors, MAX_VALUE, BUDGET, uint48(100), new AgentPolicy.TokenCap[](0), uint48(100))
        );
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        policy.onInstall(install);
    }

    // --- the agent is never let loose on its own account ---

    /// The account itself, its EntryPoint and the policy (outside x402) are
    /// refused as allow-list targets at install, whatever the selector; the
    /// x402 entry points on the policy stay allowed.
    function test_policy_install_refusesSelfTargets() public {
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](0);
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        bytes32 id = bytes32(uint256(0x5e1f));

        // the account: the agent could grant itself access or replace the root key
        (targets[0], selectors[0]) = (acct, Kernel.grantAccess.selector);
        vm.prank(acct);
        vm.expectRevert(abi.encodeWithSelector(AgentPolicy.ForbiddenTarget.selector, acct, Kernel.grantAccess.selector));
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));

        // the EntryPoint, read from the Kernel: the agent could withdraw the deposit
        bytes4 withdrawTo = bytes4(keccak256("withdrawTo(address,uint256)"));
        (targets[0], selectors[0]) = (address(entryPoint), withdrawTo);
        vm.prank(acct);
        vm.expectRevert(abi.encodeWithSelector(AgentPolicy.ForbiddenTarget.selector, address(entryPoint), withdrawTo));
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));

        // the policy itself, outside its x402 entry points
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.onInstall.selector);
        vm.prank(acct);
        vm.expectRevert(
            abi.encodeWithSelector(AgentPolicy.ForbiddenTarget.selector, address(policy), AgentPolicy.onInstall.selector)
        );
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));

        // the x402 entry points on the policy are what the account calls on purpose
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.x402Reclaim.selector);
        vm.prank(acct);
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));
        assertTrue(policy.isAllowed(acct, id, address(policy), AgentPolicy.x402Reclaim.selector));
        assertFalse(policy.isAllowed(acct, id, acct, Kernel.grantAccess.selector));
    }

    // --- x402: pre-registered EIP-3009 authorizations, scoped ERC-1271 ---

    PermissionId internal constant PAY_ID = PermissionId.wrap(0x70617931); // "pay1"
    MockUSDC internal usdc;
    address internal constant PAYEE = address(0xBEEF);

    /// A permission that may pay in mock USDC through x402: at most 1 USDC per
    /// payment, 2.5 USDC in total, direct transfers sharing the budget.
    function _withX402() internal {
        usdc = new MockUSDC();
        usdc.mint(acct, 100e6);
        _installX402();
    }

    /// Install (or reinstall) the x402 permission over the existing mock USDC.
    function _installX402() internal {
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.x402Authorize.selector);
        (targets[1], selectors[1]) = (address(policy), AgentPolicy.x402Reclaim.selector);
        (targets[2], selectors[2]) = (address(usdc), MockToken.transfer.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](2);
        caps[0] = AgentPolicy.TokenCap(address(usdc), 1e6, 2_500_000, usdc.DOMAIN_SEPARATOR());
        caps[1] = AgentPolicy.TokenCap(address(token), 1e6, 2_500_000, bytes32(0)); // limits, but no x402
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0), address(policy), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(PAY_ID);
        Execution[] memory batch = new Execution[](2);
        // Kernel's reinstall rule: an id whose stored nonce equals currentNonce needs currentNonce + 1
        uint32 current = Kernel(payable(acct)).currentNonce();
        uint32 nonce = Kernel(payable(acct)).validationConfig(vId).nonce == current ? current + 1 : current;
        batch[0] = Execution(acct, 0, _installCall(vId, nonce, abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    function _authorizeCall(uint256 value, uint256 validBefore, bytes32 nonce) internal view returns (bytes memory) {
        return abi.encodeCall(AgentPolicy.x402Authorize, (address(usdc), acct, PAYEE, value, 0, validBefore, nonce));
    }

    /// Kernel's ERC-1271 wrapper: the agent signs this for a raw `hash`.
    function _kernelWrapped(bytes32 hash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) =
            Kernel(payable(acct)).eip712Domain();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        bytes32 structHash = keccak256(abi.encode(bytes32(0x1547321c374afde8a591d972a084b071c594c275e36724931ff96c25f2999c83), hash));
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /// The agent's ERC-1271 signature: 0x02 ‖ permission id ‖ 0xff ‖ r ‖ s.
    function _agent1271(bytes32 hash) internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(0x02), PermissionId.unwrap(PAY_ID), bytes1(0xff), _sign(AGENT, _kernelWrapped(hash)));
    }

    function _isValid(bytes32 hash) internal view returns (bool) {
        try Kernel(payable(acct)).isValidSignature(hash, _agent1271(hash)) returns (bytes4 r) {
            return r == 0x1626ba7e;
        } catch {
            return false;
        }
    }

    function test_x402_registeredAuthorizationSettles() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        bytes32 digest = usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(1)));
        // not registered yet: no signature for it
        assertFalse(_isValid(digest));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(1)))));
        assertTrue(_isValid(digest));
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PAY_ID)), address(usdc)).spent, 500_000);

        // the facilitator (any EOA) settles it
        bytes memory sig = _agent1271(digest);
        vm.prank(makeAddr("facilitator"));
        usdc.transferWithAuthorization(acct, PAYEE, 500_000, 0, before, bytes32(uint256(1)), sig);
        assertEq(usdc.balanceOf(PAYEE), 500_000);
        // and cannot replay it: the token's nonce is used
        vm.expectRevert();
        usdc.transferWithAuthorization(acct, PAYEE, 500_000, 0, before, bytes32(uint256(1)), sig);
    }

    function test_x402_onlyRegisteredDigestsAreVouchedFor() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(1)))));
        // the same payment to another payee, another amount, another nonce: refused
        assertFalse(_isValid(usdc.digestOf(acct, address(0xBAD), 500_000, 0, before, bytes32(uint256(1)))));
        assertFalse(_isValid(usdc.digestOf(acct, PAYEE, 900_000, 0, before, bytes32(uint256(1)))));
        assertFalse(_isValid(usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(2)))));
        // any other message (a permit, an order): refused
        assertFalse(_isValid(keccak256("permit everything")));
    }

    function test_x402_registrationIsHeldToTheMandate() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        // over the per-payment cap
        _expectRefused(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(1_000_001, before, bytes32(uint256(1)))));
        // from someone else
        _expectRefused(
            _agentOpWith(
                AGENT,
                PAY_ID,
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.x402Authorize, (address(usdc), address(0xA11CE), PAYEE, 1, 0, before, bytes32(0)))
            )
        );
        // a token without x402 (the agent mandate's MockToken has no domain separator)
        _expectRefused(
            _agentOpWith(
                AGENT,
                PAY_ID,
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.x402Authorize, (address(token), acct, PAYEE, 1, 0, before, bytes32(0)))
            )
        );
        // the budget is shared with direct transfers: 1 + 1 transferred, 0.5 left
        _send(_agentOpWith(AGENT, PAY_ID, address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1e6))));
        _send(_agentOpWith(AGENT, PAY_ID, address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1e6))));
        _expectRefused(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(600_000, before, bytes32(uint256(3)))));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(3)))));
        // the same registration twice is refused
        _expectRefused(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(3)))));
    }

    function test_x402_windowAndRevocation() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        bytes32 digest = usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(7)));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(7)))));
        assertTrue(_isValid(digest));
        // past validBefore: no longer vouched for
        vm.warp(before + 1);
        assertFalse(_isValid(digest));
        vm.warp(before - 10);
        assertTrue(_isValid(digest));
        // the owner revokes the permission: every pending authorization dies
        _send(_rootOp(abi.encodeCall(Kernel.uninstallValidation, (ValidatorLib.permissionToIdentifier(PAY_ID), abi.encode(new bytes[](2)), ""))));
        assertFalse(_isValid(digest));
    }

    function test_x402_revokeKillsSignedAuthorizationsAndReinstallStartsClean() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        bytes32 id = bytes32(PermissionId.unwrap(PAY_ID));
        bytes32 digest = usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(11)));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(11)))));
        // a fully signed authorization, as the facilitator (or anyone who saw it) holds it
        bytes memory sig = _agent1271(digest);
        assertTrue(_isValid(digest));

        // the owner revokes the permission
        _send(_rootOp(abi.encodeCall(Kernel.uninstallValidation, (ValidatorLib.permissionToIdentifier(PAY_ID), abi.encode(new bytes[](2)), ""))));
        // settlement at the token itself now reverts: it asks the account, the policy no longer vouches
        vm.prank(makeAddr("facilitator"));
        vm.expectRevert();
        usdc.transferWithAuthorization(acct, PAYEE, 500_000, 0, before, bytes32(uint256(11)), sig);
        assertEq(usdc.balanceOf(PAYEE), 0);

        // the owner reinstalls the same permission: a new epoch, nothing carried over
        _installX402();
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 0);
        assertEq(policy.x402Pending(acct, id, digest).value, 0);
        assertFalse(_isValid(digest));
        vm.prank(makeAddr("facilitator"));
        vm.expectRevert();
        usdc.transferWithAuthorization(acct, PAYEE, 500_000, 0, before, bytes32(uint256(11)), sig);
        assertEq(usdc.balanceOf(PAYEE), 0);

        // and the reinstalled permission works on its own terms
        bytes32 fresh = usdc.digestOf(acct, PAYEE, 400_000, 0, before, bytes32(uint256(12)));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(400_000, before, bytes32(uint256(12)))));
        vm.prank(makeAddr("facilitator"));
        usdc.transferWithAuthorization(acct, PAYEE, 400_000, 0, before, bytes32(uint256(12)), _agent1271(fresh));
        assertEq(usdc.balanceOf(PAYEE), 400_000);
    }

    function test_x402_reclaimReturnsBudgetOfExpiredUnused() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        bytes32 id = bytes32(PermissionId.unwrap(PAY_ID));
        bytes memory auth = _authorizeCall(800_000, before, bytes32(uint256(9)));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, auth));
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 800_000);
        bytes memory reclaim =
            abi.encodeCall(AgentPolicy.x402Reclaim, (id, address(usdc), PAYEE, 800_000, 0, before, bytes32(uint256(9))));
        // still live: the reclaim reverts in execution, nothing changes
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, reclaim));
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 800_000);
        // expired and never settled: the budget comes back
        vm.warp(before + 1);
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, reclaim));
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 0);
    }

    function test_x402_settledCannotBeReclaimed() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        bytes32 id = bytes32(PermissionId.unwrap(PAY_ID));
        bytes32 digest = usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(5)));
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(5)))));
        bytes memory sig = _agent1271(digest);
        usdc.transferWithAuthorization(acct, PAYEE, 500_000, 0, before, bytes32(uint256(5)), sig);
        vm.warp(before + 1);
        vm.prank(acct);
        vm.expectRevert(AgentPolicy.X402Settled.selector);
        policy.x402Reclaim(id, address(usdc), PAYEE, 500_000, 0, before, bytes32(uint256(5)));
    }

    function test_x402_tokenWithoutDomainIsRefused() public {
        _withX402();
        // `token` has limits in this mandate but no domain separator: no x402
        _expectRefused(
            _agentOpWith(
                AGENT,
                PAY_ID,
                address(policy),
                0,
                abi.encodeCall(AgentPolicy.x402Authorize, (address(token), acct, PAYEE, 1, 0, block.timestamp + 1 hours, bytes32(0)))
            )
        );
    }

    function test_x402_sameAuthorizationRegistersOnce() public {
        _withX402();
        uint256 before = block.timestamp + 1 hours;
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(100_000, before, bytes32(uint256(4)))));
        _expectRefused(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(100_000, before, bytes32(uint256(4)))));
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PAY_ID)), address(usdc)).spent, 100_000);
    }

    function test_x402_notFromInsideASafe() public {
        Safe safe = _withSafe();
        _withX402();
        // a permission that may drive the Safe AND register x402 payments
        PermissionId both = PermissionId.wrap(0x62746831); // "bth1"
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(policy), AgentPolicy.x402Authorize.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(usdc), 1e6, 2_500_000, usdc.DOMAIN_SEPARATOR());
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0), address(policy), abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(both);
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
        // registering through the Safe (inner call) is refused
        bytes memory inner = _authorizeCall(100_000, block.timestamp + 1 hours, bytes32(uint256(8)));
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, _safeExec(safe, address(policy), 0, inner, Enum.Operation.Call, 0));
        _expectRefused(_agentBatchWith(AGENT, both, calls));
        // the same registration directly from the account works
        _send(_agentOpWith(AGENT, both, address(policy), 0, inner));
    }

    /// The tests below install mandates on the policy directly, as an
    /// account would: the policy asks its caller for its EntryPoint.
    function entrypoint() external view returns (address) {
        return address(entryPoint);
    }

    /// An account that does not name its EntryPoint gets no mandate: the
    /// policy could not keep that EntryPoint out of the allow-list.
    function test_install_refusedWithoutAnEntryPoint() public {
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        bytes memory data = abi.encodePacked(
            bytes32(uint256(9) << 224),
            abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0))
        );
        // an address with no code, and a contract without `entrypoint()`
        vm.prank(address(0x1234));
        vm.expectRevert(AgentPolicy.UnknownEntryPoint.selector);
        policy.onInstall(data);
        vm.prank(address(counter));
        vm.expectRevert(AgentPolicy.UnknownEntryPoint.selector);
        policy.onInstall(data);
        // the same data from a caller that answers is installed
        policy.onInstall(data);
        assertTrue(policy.isAllowed(address(this), bytes32(uint256(9) << 224), address(counter), Counter.increment.selector));
    }

    // --- payee lists (issue #66) ---

    PermissionId internal constant PYE_ID = PermissionId.wrap(0x70796531); // "pye1"
    address internal constant PAYEE_2 = address(0xCAFE);
    address internal constant STRANGER = address(0xDEAD);

    function _payeeTargets() internal view returns (address[] memory targets, bytes4[] memory selectors) {
        targets = new address[](7);
        selectors = new bytes4[](7);
        // allow-listed by a careless owner: ways to move the token that no list understands
        (targets[5], selectors[5]) = (address(token), MockToken.mint.selector);
        (targets[6], selectors[6]) = (address(token), bytes4(0));
        (targets[0], selectors[0]) = (address(policy), AgentPolicy.x402Authorize.selector);
        (targets[1], selectors[1]) = (address(usdc), MockToken.transfer.selector);
        (targets[2], selectors[2]) = (address(token), MockToken.transfer.selector);
        (targets[3], selectors[3]) = (address(token), MockToken.approve.selector);
        (targets[4], selectors[4]) = (address(token), MockToken.transferFrom.selector);
    }

    function _payeeCaps() internal view returns (AgentPolicy.TokenCap[] memory caps) {
        caps = new AgentPolicy.TokenCap[](2);
        caps[0] = AgentPolicy.TokenCap(address(usdc), 1e6, 2_500_000, usdc.DOMAIN_SEPARATOR());
        caps[1] = AgentPolicy.TokenCap(address(token), TOKEN_MAX, TOKEN_BUDGET, bytes32(0));
    }

    function _list(address tokenAddr, address a, address b) internal pure returns (AgentPolicy.TokenPayees memory l) {
        address[] memory payees = new address[](b == address(0) ? 1 : 2);
        payees[0] = a;
        if (b != address(0)) payees[1] = b;
        l = AgentPolicy.TokenPayees(tokenAddr, payees);
    }

    /// The policy's install parameters with payee lists: the eight-word form.
    function _payeeParams(AgentPolicy.TokenPayees[] memory lists) internal view returns (bytes memory) {
        (address[] memory targets, bytes4[] memory selectors) = _payeeTargets();
        return abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _payeeCaps(), uint48(0), lists);
    }

    /// A permission that may pay mock USDC to PAYEE only, and the mock token
    /// to PAYEE and PAYEE_2 only.
    function _withPayees() internal {
        usdc = new MockUSDC();
        usdc.mint(acct, 100e6);
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](2);
        lists[0] = _list(address(usdc), PAYEE, address(0));
        lists[1] = _list(address(token), PAYEE, PAYEE_2);
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(bytes2(0), address(policy), _payeeParams(lists));
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(PYE_ID);
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    function _payeeOp(address target, bytes memory data) internal view returns (PackedUserOperation memory) {
        return _agentOpWith(AGENT, PYE_ID, target, 0, data);
    }

    function test_payees_transferOnlyToAListedAddress() public {
        _withPayees();
        _send(_payeeOp(address(token), abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether))));
        _send(_payeeOp(address(token), abi.encodeCall(MockToken.transfer, (PAYEE_2, 1 ether))));
        assertEq(token.balanceOf(PAYEE), 1 ether);
        assertEq(token.balanceOf(PAYEE_2), 1 ether);
        // within every cap, to an address the owner did not list
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.transfer, (STRANGER, 1))));
        // a zero amount is no way around the list
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.transfer, (STRANGER, 0))));
        // each token has its own list: PAYEE_2 is listed for the mock token only
        _send(_payeeOp(address(usdc), abi.encodeCall(MockToken.transfer, (PAYEE, 1e6))));
        _expectRefused(_payeeOp(address(usdc), abi.encodeCall(MockToken.transfer, (PAYEE_2, 1e6))));
        assertEq(usdc.balanceOf(PAYEE), 1e6);
        // a refused operation charges nothing
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PYE_ID)), address(token)).spent, 2 ether);
    }

    function test_payees_spenderAndTransferFromAreBound() public {
        _withPayees();
        _send(_payeeOp(address(token), abi.encodeCall(MockToken.approve, (PAYEE, 2 ether))));
        assertEq(token.allowance(acct, PAYEE), 2 ether);
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.approve, (STRANGER, 1))));
        // transferFrom: the recipient is the second argument, whoever `from` is
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.transferFrom, (PAYEE, STRANGER, 1))));
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.transferFrom, (STRANGER, STRANGER, 1))));
        // a listed recipient passes the policy (the token's own allowance rule is not the policy's business)
        token.mint(STRANGER, 1 ether);
        vm.prank(STRANGER);
        token.approve(acct, 1 ether);
        _send(_payeeOp(address(token), abi.encodeCall(MockToken.transferFrom, (STRANGER, PAYEE_2, 1 ether))));
        assertEq(token.balanceOf(PAYEE_2), 1 ether);
    }

    /// A token reads the low 160 bits of an address word. The same word must
    /// not name a listed payee to one reader and a stranger to another.
    function test_payees_dirtyAddressWordIsRefused() public {
        _withPayees();
        bytes memory dirty =
            abi.encodePacked(MockToken.transfer.selector, bytes32(uint256(uint160(PAYEE)) | (1 << 160)), uint256(1));
        _expectRefused(_payeeOp(address(token), dirty));
        // a call cut short before the amount
        _expectRefused(_payeeOp(address(token), abi.encodePacked(MockToken.transfer.selector, bytes32(uint256(uint160(PAYEE))))));
    }

    /// A payee list is a promise about where the token goes. Any other
    /// function allow-listed on that token would be a way around it.
    function test_payees_otherFunctionsOfABoundTokenAreRefused() public {
        _withPayees();
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.mint, (STRANGER, 1))));
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.mint, (PAYEE, 1))));
        _expectRefused(_payeeOp(address(token), ""));
        // usdc is bound too; the first permission's token is not, and its other entries work as before
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(counter.count(), 1);
    }

    function test_payees_batchLegsAreBound() public {
        _withPayees();
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1 ether)));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (STRANGER, 1 ether)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE_2, 1 ether)));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE_2), 1 ether);
    }

    function test_payees_x402PaysOnlyAListedAddress() public {
        _withPayees();
        uint256 before = block.timestamp + 1 hours;
        _expectRefused(
            _payeeOp(
                address(policy),
                abi.encodeCall(AgentPolicy.x402Authorize, (address(usdc), acct, STRANGER, 100_000, 0, before, bytes32(uint256(1))))
            )
        );
        _send(_payeeOp(address(policy), _authorizeCall(100_000, before, bytes32(uint256(1)))));
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PYE_ID)), address(usdc)).spent, 100_000);
    }

    function test_payees_view() public {
        _withPayees();
        bytes32 id = bytes32(PermissionId.unwrap(PYE_ID));
        assertTrue(policy.payeeAllowed(acct, id, address(token), PAYEE_2));
        assertFalse(policy.payeeAllowed(acct, id, address(usdc), PAYEE_2));
        assertFalse(policy.payeeAllowed(acct, id, address(token), STRANGER));
        assertTrue(policy.tokenLimit(acct, id, address(token)).payeesOnly);
        // the first permission has no list for its token: anyone, as before
        bytes32 agentId = bytes32(PermissionId.unwrap(AGENT_ID));
        assertTrue(policy.payeeAllowed(acct, agentId, address(token), STRANGER));
        assertFalse(policy.tokenLimit(acct, agentId, address(token)).payeesOnly);
    }

    /// A mandate installed without lists is encoded as before lists existed,
    /// and a reinstall without them forgets the old ones.
    function test_payees_reinstallWithoutListsForgetsThem() public {
        usdc = new MockUSDC();
        bytes32 id = bytes32(uint256(1) << 224);
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        lists[0] = _list(address(token), PAYEE, address(0));
        policy.onInstall(abi.encodePacked(id, _payeeParams(lists)));
        assertFalse(policy.payeeAllowed(address(this), id, address(token), STRANGER));
        policy.onUninstall(abi.encodePacked(id));
        (address[] memory targets, bytes4[] memory selectors) = _payeeTargets();
        policy.onInstall(
            abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _payeeCaps(), uint48(0)))
        );
        assertTrue(policy.payeeAllowed(address(this), id, address(token), STRANGER));
        assertTrue(policy.tokenLimit(address(this), id, address(token)).set);
    }

    function _refusedInstall(bytes32 id, AgentPolicy.TokenPayees[] memory lists) internal {
        bytes memory data = abi.encodePacked(id, _payeeParams(lists));
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        policy.onInstall(data);
    }

    function test_payees_malformedListsAreRefusedAtInstall() public {
        usdc = new MockUSDC();
        bytes32 id = bytes32(uint256(2) << 224);
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        // a token the mandate has no cap for
        lists[0] = _list(address(forbidden), PAYEE, address(0));
        _refusedInstall(id, lists);
        // an empty list
        lists[0] = AgentPolicy.TokenPayees(address(token), new address[](0));
        _refusedInstall(id, lists);
        // the zero address
        lists[0] = _list(address(token), PAYEE, address(0));
        lists[0].payees[0] = address(0);
        _refusedInstall(id, lists);
        // a payee twice
        lists[0] = _list(address(token), PAYEE, PAYEE);
        _refusedInstall(id, lists);
        // a token twice
        AgentPolicy.TokenPayees[] memory twice = new AgentPolicy.TokenPayees[](2);
        twice[0] = _list(address(token), PAYEE, address(0));
        twice[1] = _list(address(token), PAYEE_2, address(0));
        _refusedInstall(id, twice);
        // the eight-word form carrying no list at all
        _refusedInstall(id, new AgentPolicy.TokenPayees[](0));
        // a head that is neither form: one more parameter still
        (address[] memory targets, bytes4[] memory selectors) = _payeeTargets();
        lists[0] = _list(address(token), PAYEE, address(0));
        bytes memory nine = abi.encodePacked(
            id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _payeeCaps(), uint48(0), lists, uint256(0))
        );
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        policy.onInstall(nine);
    }
}
