// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test, Vm} from "forge-std/Test.sol";

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
import {LibERC7579 as PinnedERC7579} from "kernel/lib/solady/src/accounts/LibERC7579.sol";
import {LibERC7579 as FixedERC7579} from "solady/accounts/LibERC7579.sol";
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

/// An execution hook that only counts: Kernel calls it around an operation
/// of the permission it is installed with.
/// A batch decoded as Kernel v3.3 decodes it: the same entry point and
/// selector as `Kernel.execute`, so the calldata is laid out as the account
/// sees it, and the Solady that Kernel pins, which `AgentPolicy` uses too.
/// `decodeFixed` is Solady v0.1.26, with the bounds check of PR 1244.
/// What Kernel's `execute(bytes32, bytes calldata)` reads of a batch: the
/// same ABI decoding of `executionData`'s offset and length, and the same
/// pinned decoder, with each leg's data returned as well.
contract KernelReads {
    function execute(bytes32, bytes calldata executionData)
        external
        pure
        returns (address[] memory targets, uint256[] memory values, bytes[] memory datas)
    {
        bytes32[] calldata pointers = PinnedERC7579.decodeBatch(executionData);
        targets = new address[](pointers.length);
        values = new uint256[](pointers.length);
        datas = new bytes[](pointers.length);
        for (uint256 i; i < pointers.length; i++) {
            (targets[i], values[i], datas[i]) = PinnedERC7579.getExecution(pointers, i);
        }
    }
}

contract KernelDecodes {
    function execute(bytes32, bytes calldata executionData)
        external
        pure
        returns (address[] memory targets, uint256[] memory values)
    {
        bytes32[] calldata pointers = PinnedERC7579.decodeBatch(executionData);
        targets = new address[](pointers.length);
        values = new uint256[](pointers.length);
        for (uint256 i; i < pointers.length; i++) {
            (targets[i], values[i],) = PinnedERC7579.getExecution(pointers, i);
        }
    }

    function decodeFixed(bytes calldata executionData) external pure returns (uint256) {
        return FixedERC7579.decodeBatch(executionData).length;
    }
}

contract CountingHook is IHook {
    uint256 public pre;
    uint256 public post;
    mapping(address => bool) internal installed;

    function onInstall(bytes calldata) external payable {
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external payable {
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 4;
    }

    function isInitialized(address account) external view returns (bool) {
        return installed[account];
    }

    function preCheck(address, uint256, bytes calldata) external payable returns (bytes memory) {
        pre++;
        return "";
    }

    function postCheck(bytes calldata) external payable {
        post++;
    }
}

/// An ERC-721/1155-style operator registry: `setApprovalForAll` only.
contract MockOperators {
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    /// ERC-6909
    mapping(address => mapping(address => bool)) public isOperator;

    function setOperator(address operator, bool approved) external returns (bool) {
        isOperator[msg.sender][operator] = approved;
        return true;
    }

    mapping(address => mapping(address => mapping(uint256 => uint256))) public allowance;

    function approve(address spender, uint256 id, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender][id] = amount;
        return true;
    }

    mapping(address => mapping(uint256 => uint256)) public balanceOf;

    function mint(address to, uint256 id, uint256 amount) external {
        balanceOf[to][id] += amount;
    }

    function transfer(address receiver, uint256 id, uint256 amount) external returns (bool) {
        balanceOf[msg.sender][id] -= amount;
        balanceOf[receiver][id] += amount;
        return true;
    }

    function transferFrom(address sender, address receiver, uint256 id, uint256 amount) external returns (bool) {
        require(sender == msg.sender, "this mock moves the caller's own");
        balanceOf[sender][id] -= amount;
        balanceOf[receiver][id] += amount;
        return true;
    }

    /// ERC-777
    mapping(address => mapping(address => bool)) public authorized;

    function authorizeOperator(address operator) external {
        authorized[msg.sender][operator] = true;
    }

    function revokeOperator(address operator) external {
        authorized[msg.sender][operator] = false;
    }
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
        address[] memory targets = new address[](4);
        bytes4[] memory selectors = new bytes4[](4);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(counter), bytes4(0)); // plain value transfer
        (targets[2], selectors[2]) = (address(token), MockToken.transfer.selector);
        (targets[3], selectors[3]) = (address(token), MockToken.approve.selector);
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
        // a capped approval passes, withdrawn in the same operation (no standing allowances)
        _send(_agentBatchWith(AGENT, AGENT_ID, _grantAndWithdraw(spender, 5 ether)));
        assertEq(token.allowance(acct, spender), 0);
    }

    /// `approve(spender, amount)` and then `approve(spender, 0)`, on the mock token.
    function _grantAndWithdraw(address spender, uint256 amount) internal view returns (Execution[] memory calls) {
        calls = new Execution[](2);
        calls[0] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (spender, amount)));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (spender, 0)));
    }

    // --- no standing allowances: what the agent grants, it withdraws in the same operation ---

    /// An allowance outlives a revoke of the mandate: the spender pulls from
    /// it whenever it likes. So an allowance the agent grants must be
    /// withdrawn with `approve(spender, 0)` later in the same operation.
    function test_allowances_noneOutlivesTheOperation() public {
        address spender = makeAddr("spender");
        address other = makeAddr("other spender");
        bytes memory grant = abi.encodeCall(MockToken.approve, (spender, 5 ether));
        // alone, it would stand: refused
        _expectRefused(_agentOp(address(token), 0, grant));
        // withdrawn: passes, and nothing stands after it
        _send(_agentBatchWith(AGENT, AGENT_ID, _grantAndWithdraw(spender, 5 ether)));
        assertEq(token.allowance(acct, spender), 0);
        // withdrawn for another spender only: refused
        Execution[] memory calls = _grantAndWithdraw(spender, 5 ether);
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (other, 0)));
        _expectRefused(_agentBatchWith(AGENT, AGENT_ID, calls));
        // granted again after the withdrawal: refused
        Execution[] memory three = new Execution[](3);
        (three[0], three[1]) = (calls[0], Execution(address(token), 0, abi.encodeCall(MockToken.approve, (spender, 0))));
        three[2] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (spender, 3 ether)));
        _expectRefused(_agentBatchWith(AGENT, AGENT_ID, three));
        // withdrawing an allowance granted earlier (by the owner, say) passes on its own
        vm.prank(acct);
        token.approve(other, 1 ether);
        _send(_agentOp(address(token), 0, abi.encodeCall(MockToken.approve, (other, 0))));
        assertEq(token.allowance(acct, other), 0);
    }

    /// An operator grant (`setApprovalForAll` of ERC-721 and ERC-1155) is an
    /// allowance over every token of the contract: withdrawn in the same
    /// operation, or refused (#176).
    /// A mandate without token limits, installed by the owner under `id`.
    function _installOperatorMandate(PermissionId id, address[] memory targets, bytes4[] memory selectors) internal {
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, new AgentPolicy.TokenCap[](0));
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(id);
        Execution[] memory install = new Execution[](2);
        install[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        install[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(install)
                )
            )
        );
    }

    /// The eleven-word form: a mandate with limits per id of an ERC-6909
    /// contract, installed by the owner under `id`.
    function _installIdMandate(
        PermissionId id,
        address[] memory targets,
        bytes4[] memory selectors,
        AgentPolicy.IdCap[] memory caps,
        uint32 period
    ) internal {
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(bytes2(0), address(policy), _idParams(targets, selectors, caps, period));
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(id);
        Execution[] memory install = new Execution[](2);
        install[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        install[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(install)
                )
            )
        );
    }

    function _idParams(address[] memory targets, bytes4[] memory selectors, AgentPolicy.IdCap[] memory caps, uint32 period)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(
            targets,
            selectors,
            MAX_VALUE,
            BUDGET,
            expiry,
            new AgentPolicy.TokenCap[](0),
            uint48(0),
            new AgentPolicy.TokenPayees[](0),
            period,
            new AgentPolicy.Venue[](0),
            caps
        );
    }

    function _idTargets(address t) internal pure returns (address[] memory targets, bytes4[] memory selectors) {
        targets = new address[](3);
        selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (t, bytes4(0x095bcdb6)); // transfer(address,uint256,uint256)
        (targets[1], selectors[1]) = (t, bytes4(0xfe99049a)); // transferFrom(address,address,uint256,uint256)
        (targets[2], selectors[2]) = (t, bytes4(0x426a8493)); // approve(address,uint256,uint256)
    }

    function _idMove(MockOperators t, address to, uint256 tokenId, uint256 amount) internal pure returns (Execution memory) {
        return Execution(address(t), 0, abi.encodeWithSelector(bytes4(0x095bcdb6), to, tokenId, amount));
    }

    /// #186: an id of an ERC-6909 contract is held to its cap per operation
    /// and its budget; an id without a limit is not moved at all.
    function test_ids_anIdIsHeldToItsLimits() public {
        MockOperators t = new MockOperators();
        t.mint(acct, 7, 100);
        t.mint(acct, 8, 100);
        PermissionId id = PermissionId.wrap(0x69643031); // "id01"
        (address[] memory targets, bytes4[] memory selectors) = _idTargets(address(t));
        AgentPolicy.IdCap[] memory caps = new AgentPolicy.IdCap[](1);
        caps[0] = AgentPolicy.IdCap(address(t), 7, 5, 8);
        _installIdMandate(id, targets, selectors, caps, 0);
        address to = makeAddr("receiver");
        // above the cap per operation, in one call and summed over two
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, _idMove(t, to, 7, 6).callData));
        Execution[] memory calls = new Execution[](2);
        (calls[0], calls[1]) = (_idMove(t, to, 7, 3), _idMove(t, to, 7, 3));
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        // an id without a limit
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, _idMove(t, to, 8, 1).callData));
        // within both: 3, then 5 by transferFrom, which is the whole budget
        _send(_agentOpWith(AGENT, id, address(t), 0, _idMove(t, to, 7, 3).callData));
        _send(_agentOpWith(AGENT, id, address(t), 0, abi.encodeWithSelector(bytes4(0xfe99049a), acct, to, 7, 5)));
        assertEq(t.balanceOf(to, 7), 8);
        // the id's limit is read as a token's, under the id's key
        AgentPolicy.TokenLimit memory limit =
            policy.tokenLimit(acct, bytes32(PermissionId.unwrap(id)), policy.idAsset(address(t), 7));
        assertEq(limit.spent, 8);
        assertEq(limit.budget, 8);
        assertTrue(limit.set);
        assertFalse(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(id)), policy.idAsset(address(t), 8)).set);
        // the budget is spent
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, _idMove(t, to, 7, 1).callData));
        // a short call is refused
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, abi.encodePacked(bytes4(0x095bcdb6), bytes32(uint256(uint160(to))), uint256(7))));
        assertEq(t.balanceOf(to, 7), 8);
        assertEq(t.balanceOf(to, 8), 0);
    }

    /// The same limits one call deeper: ids a Safe holds, moved by its
    /// `execTransaction` and by the legs of a MultiSend batch. The cap per
    /// operation sums the legs.
    function test_ids_heldThroughASafeAndItsBatch() public {
        (Safe safe, MockOperators t) = _safeWithIds();
        address to = makeAddr("receiver");
        // one inner call above the cap, and an id without a limit
        _expectRefused(_idViaSafe(safe, _safeExec(safe, address(t), 0, _idMove(t, to, 7, 6).callData, Enum.Operation.Call, 0)));
        _expectRefused(_idViaSafe(safe, _safeExec(safe, address(t), 0, _idMove(t, to, 8, 1).callData, Enum.Operation.Call, 0)));
        // two legs of a batch that are above the cap together
        bytes memory three = _legOf(0, address(t), 0, _idMove(t, to, 7, 3).callData);
        _expectRefused(_idViaSafe(safe, _batch(safe, address(multiSend), bytes.concat(three, three), Enum.Operation.DelegateCall)));
        // a leg for an id without a limit, beside one that is fine
        bytes memory other = _legOf(0, address(t), 0, _idMove(t, to, 8, 1).callData);
        _expectRefused(_idViaSafe(safe, _batch(safe, address(multiSend), bytes.concat(three, other), Enum.Operation.DelegateCall)));
        assertEq(t.balanceOf(to, 7), 0);
        // within the cap: 3 and 2 in a batch, then 3 alone, which is the whole budget
        bytes memory two = _legOf(0, address(t), 0, _idMove(t, to, 7, 2).callData);
        _send(_idViaSafe(safe, _batch(safe, address(multiSend), bytes.concat(three, two), Enum.Operation.DelegateCall)));
        _send(_idViaSafe(safe, _safeExec(safe, address(t), 0, _idMove(t, to, 7, 3).callData, Enum.Operation.Call, 0)));
        assertEq(t.balanceOf(to, 7), 8);
        _expectRefused(_idViaSafe(safe, _safeExec(safe, address(t), 0, _idMove(t, to, 7, 1).callData, Enum.Operation.Call, 0)));
        assertEq(t.balanceOf(to, 8), 0);
    }

    PermissionId internal constant SAFE_IDS = PermissionId.wrap(0x69643033); // "id03"

    /// A Safe of the account's that holds ids 7 and 8, and a mandate with a
    /// limit for id 7: 5 per operation, 8 in all.
    function _safeWithIds() internal returns (Safe safe, MockOperators t) {
        bytes memory setup =
            abi.encodeCall(Safe.setup, (_one(acct), 1, address(0), "", address(0), address(0), 0, payable(address(0))));
        safe = Safe(payable(address(new SafeProxyFactory().createProxyWithNonce(address(new Safe()), setup, 0))));
        multiSend = new MultiSendCallOnly();
        t = new MockOperators();
        t.mint(address(safe), 7, 100);
        t.mint(address(safe), 8, 100);
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(multiSend), MultiSendCallOnly.multiSend.selector);
        (targets[2], selectors[2]) = (address(t), bytes4(0x095bcdb6));
        AgentPolicy.IdCap[] memory caps = new AgentPolicy.IdCap[](1);
        caps[0] = AgentPolicy.IdCap(address(t), 7, 5, 8);
        _installIdMandate(SAFE_IDS, targets, selectors, caps, 0);
    }

    function _one(address a) internal pure returns (address[] memory list) {
        list = new address[](1);
        list[0] = a;
    }

    function _idViaSafe(Safe safe, bytes memory execData) internal view returns (PackedUserOperation memory) {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, execData);
        return _agentBatchWith(AGENT, SAFE_IDS, calls);
    }

    /// What install refuses in the eleven-word form, and around it.
    function test_ids_installRules() public {
        MockOperators t = new MockOperators();
        (address[] memory targets, bytes4[] memory selectors) = _idTargets(address(t));
        AgentPolicy.IdCap[] memory caps = new AgentPolicy.IdCap[](1);
        caps[0] = AgentPolicy.IdCap(address(t), 7, 5, 8);
        // the control installs
        this.installAsAccount(1, _idParams(targets, selectors, caps, 0));
        // no id limit in the form that exists to carry one
        _installRefused(2, _idParams(targets, selectors, new AgentPolicy.IdCap[](0), 0));
        // the same id twice
        AgentPolicy.IdCap[] memory twice = new AgentPolicy.IdCap[](2);
        (twice[0], twice[1]) = (caps[0], caps[0]);
        _installRefused(3, _idParams(targets, selectors, twice, 0));
        // the zero address
        AgentPolicy.IdCap[] memory zero = new AgentPolicy.IdCap[](1);
        zero[0] = AgentPolicy.IdCap(address(0), 7, 5, 8);
        _installRefused(4, _idParams(targets, selectors, zero, 0));
        // any other function on a contract with id limits: an operator moves every id
        address[] memory more = new address[](4);
        bytes4[] memory moreSelectors = new bytes4[](4);
        for (uint256 i; i < 3; i++) {
            (more[i], moreSelectors[i]) = (targets[i], selectors[i]);
        }
        (more[3], moreSelectors[3]) = (address(t), MockOperators.setOperator.selector);
        _installRefused(5, _idParams(more, moreSelectors, caps, 0));
        // one of the three on a contract without an id limit, in a mandate that has none
        _installRefused(
            6,
            abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0))
        );
        // and in one whose limits are another contract's
        AgentPolicy.IdCap[] memory other = new AgentPolicy.IdCap[](1);
        other[0] = AgentPolicy.IdCap(address(counter), 7, 5, 8);
        _installRefused(7, _idParams(targets, selectors, other, 0));
        // a cap wider than its type
        bytes memory wide = _idParams(targets, selectors, caps, 0);
        uint256 at = wide.length - 32; // the last word: the one cap's budget
        assembly {
            mstore(add(add(wide, 32), at), shl(128, 1))
        }
        _installRefused(8, wide);
    }

    function installAsAccount(uint256 n, bytes calldata params) external {
        vm.prank(acct);
        policy.onInstall(abi.encodePacked(bytes32((uint256(0x69640000) + n) << 224), params));
    }

    function _installRefused(uint256 n, bytes memory params) internal {
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        this.installAsAccount(n, params);
    }

    function test_allowances_anOperatorGrantIsWithdrawnInTheSameOperation() public {
        MockOperators nft = new MockOperators();
        PermissionId id = PermissionId.wrap(0x6f707273); // "oprs"
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(nft), MockOperators.setApprovalForAll.selector);
        _installOperatorMandate(id, targets, selectors);
        address op = makeAddr("operator");
        Execution memory grant = Execution(address(nft), 0, abi.encodeCall(MockOperators.setApprovalForAll, (op, true)));
        Execution memory withdraw = Execution(address(nft), 0, abi.encodeCall(MockOperators.setApprovalForAll, (op, false)));
        // alone, it would stand: refused
        _expectRefused(_agentOpWith(AGENT, id, address(nft), 0, grant.callData));
        // withdrawn in the same operation: passes, and nothing stands
        Execution[] memory calls = new Execution[](2);
        (calls[0], calls[1]) = (grant, withdraw);
        _send(_agentBatchWith(AGENT, id, calls));
        assertFalse(nft.isApprovedForAll(acct, op));
        // withdrawn for another operator only: refused
        calls[1] = Execution(address(nft), 0, abi.encodeCall(MockOperators.setApprovalForAll, (makeAddr("other"), false)));
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        // withdrawing a grant made earlier passes on its own; a short call is refused
        vm.prank(acct);
        nft.setApprovalForAll(op, true);
        _send(_agentOpWith(AGENT, id, address(nft), 0, withdraw.callData));
        assertFalse(nft.isApprovedForAll(acct, op));
        _expectRefused(_agentOpWith(AGENT, id, address(nft), 0, abi.encodePacked(MockOperators.setApprovalForAll.selector, bytes32(uint256(uint160(op))))));
    }

    /// ERC-6909's `setOperator(operator, bool)` is held as `setApprovalForAll`
    /// is, and a grant is withdrawn by its own function only: on a contract
    /// that has both, one does not close what the other opened.
    function test_allowances_anERC6909OperatorIsWithdrawnByItsOwnFunction() public {
        MockOperators nft = new MockOperators();
        PermissionId id = PermissionId.wrap(0x6f707236); // "opr6"
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(nft), MockOperators.setOperator.selector);
        (targets[1], selectors[1]) = (address(nft), MockOperators.setApprovalForAll.selector);
        _installOperatorMandate(id, targets, selectors);
        address op = makeAddr("operator");
        Execution memory grant = Execution(address(nft), 0, abi.encodeCall(MockOperators.setOperator, (op, true)));
        Execution memory withdraw = Execution(address(nft), 0, abi.encodeCall(MockOperators.setOperator, (op, false)));
        // alone, it would stand: refused
        _expectRefused(_agentOpWith(AGENT, id, address(nft), 0, grant.callData));
        // withdrawn in the same operation: passes, and nothing stands
        Execution[] memory calls = new Execution[](2);
        (calls[0], calls[1]) = (grant, withdraw);
        _send(_agentBatchWith(AGENT, id, calls));
        assertFalse(nft.isOperator(acct, op));
        // "withdrawn" with the other function: the ERC-6909 grant would stand, refused
        calls[1] = Execution(address(nft), 0, abi.encodeCall(MockOperators.setApprovalForAll, (op, false)));
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        // and the other way round
        calls[0] = Execution(address(nft), 0, abi.encodeCall(MockOperators.setApprovalForAll, (op, true)));
        calls[1] = withdraw;
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        // a short call is refused
        _expectRefused(_agentOpWith(AGENT, id, address(nft), 0, abi.encodePacked(MockOperators.setOperator.selector, bytes32(uint256(uint160(op))))));
        assertFalse(nft.isOperator(acct, op));
        assertFalse(nft.isApprovedForAll(acct, op));
    }

    /// An ERC-6909 allowance of one id, `approve(spender, id, amount)`, is
    /// withdrawn with amount 0 for the same spender and the same id.
    function test_allowances_anERC6909AllowanceIsWithdrawnForItsId() public {
        MockOperators t = new MockOperators();
        PermissionId id = PermissionId.wrap(0x61703639); // "ap69"
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(t), bytes4(0x426a8493)); // approve(address,uint256,uint256)
        AgentPolicy.IdCap[] memory caps = new AgentPolicy.IdCap[](3);
        for (uint256 i; i < 3; i++) {
            caps[i] = AgentPolicy.IdCap(address(t), 7 + i, 10 ether, 100 ether);
        }
        _installIdMandate(id, targets, selectors, caps, 0);
        address spender = makeAddr("spender");
        bytes4 approve3 = bytes4(0x426a8493);
        Execution memory grant = Execution(address(t), 0, abi.encodeWithSelector(approve3, spender, 7, 5 ether));
        // alone, it would stand: refused
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, grant.callData));
        // withdrawn for the same id: passes, nothing stands
        Execution[] memory calls = new Execution[](2);
        calls[0] = grant;
        calls[1] = Execution(address(t), 0, abi.encodeWithSelector(approve3, spender, 7, 0));
        _send(_agentBatchWith(AGENT, id, calls));
        assertEq(t.allowance(acct, spender, 7), 0);
        // withdrawn for another id, or for another spender: refused
        calls[1] = Execution(address(t), 0, abi.encodeWithSelector(approve3, spender, 8, 0));
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        calls[1] = Execution(address(t), 0, abi.encodeWithSelector(approve3, makeAddr("other"), 7, 0));
        _expectRefused(_agentBatchWith(AGENT, id, calls));
        // an allowance the owner made is withdrawn on its own; a short call is refused
        vm.prank(acct);
        t.approve(spender, 9, 1 ether);
        _send(_agentOpWith(AGENT, id, address(t), 0, abi.encodeWithSelector(approve3, spender, 9, 0)));
        assertEq(t.allowance(acct, spender, 9), 0);
        _expectRefused(_agentOpWith(AGENT, id, address(t), 0, abi.encodePacked(approve3, bytes32(uint256(uint160(spender))), uint256(7))));
        assertEq(t.allowance(acct, spender, 7), 0);
    }

    /// ERC-777's `authorizeOperator(operator)` is withdrawn by another
    /// function, which the policy does not pair with it: no mandate lists it.
    /// `revokeOperator` alone only takes a grant away and may be listed.
    function test_allowances_noMandateListsAnERC777OperatorGrant() public {
        MockOperators t777 = new MockOperators();
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(t777), MockOperators.authorizeOperator.selector);
        vm.prank(acct);
        vm.expectRevert(AgentPolicy.InvalidConfig.selector);
        policy.onInstall(
            abi.encodePacked(
                bytes32(uint256(0x6f703737) << 224),
                abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, new AgentPolicy.TokenCap[](0), uint48(0))
            )
        );
        // the control: the same mandate with the withdrawing function installs
        selectors[0] = MockOperators.revokeOperator.selector;
        PermissionId id = PermissionId.wrap(0x6f703738); // "op78"
        _installOperatorMandate(id, targets, selectors);
        address op = makeAddr("operator");
        vm.prank(acct);
        t777.authorizeOperator(op);
        _send(_agentOpWith(AGENT, id, address(t777), 0, abi.encodeCall(MockOperators.revokeOperator, (op))));
        assertFalse(t777.authorized(acct, op));
    }

    /// A Safe's allowances are the Safe's: one the account grants is not
    /// withdrawn by the Safe's `approve(spender, 0)`, nor the other way round;
    /// inside a Safe's batch a grant and its withdrawal pass together.
    function test_allowances_theHolderWithdrawsWhatItGranted() public {
        Safe safe = _withSafeApprovals();
        address spender = makeAddr("spender");
        bytes memory grant = abi.encodeCall(MockToken.approve, (spender, 5 ether));
        bytes memory withdraw = abi.encodeCall(MockToken.approve, (spender, 0));
        // the Safe grants and leaves it standing: refused
        _expectRefused(_agentViaSafe(safe, _safeExec(safe, address(token), 0, grant, Enum.Operation.Call, 0)));
        // granted and withdrawn in the Safe's batch: passes
        bytes memory txs = bytes.concat(_legOf(0, address(token), 0, grant), _legOf(0, address(token), 0, withdraw));
        _send(_agentViaSafe(safe, _batch(safe, address(multiSend), txs, Enum.Operation.DelegateCall)));
        assertEq(token.allowance(address(safe), spender), 0);
        // the account grants, the Safe withdraws: refused
        Execution[] memory calls = new Execution[](3);
        calls[0] = Execution(address(token), 0, grant);
        calls[1] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[2] = Execution(address(safe), 0, _safeExec(safe, address(token), 0, withdraw, Enum.Operation.Call, 0));
        _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        // the Safe grants, the account withdraws: refused
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, _safeExec(safe, address(token), 0, grant, Enum.Operation.Call, 0));
        calls[2] = Execution(address(token), 0, withdraw);
        _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        // increaseAllowance grants as approve does
        bytes memory increase = abi.encodeWithSelector(bytes4(0x39509351), spender, uint256(1 ether));
        _expectRefused(_agentOpWith(AGENT, SAFE_ID, address(token), 0, increase));
        assertEq(token.allowance(acct, spender), 0);
        assertEq(token.allowance(address(safe), spender), 0);
    }

    /// A Safe transaction with a `safeTxGas` does not revert when its inner
    /// call does: the Safe notes the failure and goes on. Validation counted
    /// the inner call as made. So a withdrawal of an allowance that fails
    /// inside such a transaction (here: a spender word with a bit above 160,
    /// which the policy reads as the spender and the token's decoder
    /// refuses) left the allowance standing after an operation that passed.
    /// The policy admits a Safe transaction only with `safeTxGas` and
    /// `baseGas` of 0, where the Safe reverts with its inner call.
    function test_safe_aTransactionThatMayFailQuietlyIsRefused() public {
        Safe safe = _withSafeApprovals();
        address spender = makeAddr("spender");
        bytes memory grant = abi.encodeCall(MockToken.approve, (spender, 5 ether));
        bytes memory dirtyWithdraw =
            abi.encodeWithSelector(MockToken.approve.selector, uint256(uint160(spender)) | (1 << 200), uint256(0));
        uint256 nonce = safe.nonce();
        Execution[] memory calls = new Execution[](4);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), nonce)));
        calls[1] = Execution(address(safe), 0, _safeExecGas(address(token), grant, 0, 0));
        calls[2] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), nonce + 1)));
        calls[3] = Execution(address(safe), 0, _safeExecGas(address(token), dirtyWithdraw, 1, 0));
        _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        assertEq(token.allowance(address(safe), spender), 0, "no allowance stands");
        // either gas field alone, on a call that would succeed
        bytes memory withdraw = abi.encodeCall(MockToken.approve, (spender, 0));
        _expectRefused(_agentViaSafe(safe, _safeExecGas(address(token), withdraw, 1, 0)));
        _expectRefused(_agentViaSafe(safe, _safeExecGas(address(token), withdraw, 0, 1)));
        // the control: both 0
        _send(_agentViaSafe(safe, _safeExecGas(address(token), withdraw, 0, 0)));
        assertEq(safe.nonce(), nonce + 1);
    }

    /// #193, item 3: with the three gas words at 0, an inner call that fails
    /// at execution fails the operation. The shape of #190 with `safeTxGas`
    /// at 0: validation accepts it, having seen the withdrawal; the
    /// withdrawal reverts at execution (the token refuses the word); the Safe
    /// reverts with it (`GS013`: `require(success || safeTxGas != 0 ||
    /// gasPrice != 0)`); and the EntryPoint reverts the operation's whole
    /// execution. The grant goes with it, so no allowance stands, and the
    /// Safe's nonce does not move. Run through the EntryPoint, Kernel's
    /// batch, the Safe and the token.
    function test_safe_aFailingInnerCallFailsTheOperation() public {
        Safe safe = _withSafeApprovals();
        address spender = makeAddr("spender");
        bytes memory grant = abi.encodeCall(MockToken.approve, (spender, 5 ether));
        bytes memory dirtyWithdraw =
            abi.encodeWithSelector(MockToken.approve.selector, uint256(uint160(spender)) | (1 << 200), uint256(0));
        uint256 nonce = safe.nonce();
        Execution[] memory calls = new Execution[](4);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), nonce)));
        calls[1] = Execution(address(safe), 0, _safeExecGas(address(token), grant, 0, 0));
        calls[2] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), nonce + 1)));
        calls[3] = Execution(address(safe), 0, _safeExecGas(address(token), dirtyWithdraw, 0, 0));
        vm.recordLogs();
        // validation accepts it: handleOps does not revert
        _send(_agentBatchWith(AGENT, SAFE_ID, calls));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
        uint256 seen;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter != address(entryPoint) || logs[i].topics[0] != topic) continue;
            (, bool success,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            assertFalse(success, "the operation's execution failed");
            seen++;
        }
        assertEq(seen, 1, "one operation, reported once");
        assertEq(token.allowance(address(safe), spender), 0, "the grant was undone with the failed withdrawal");
        assertEq(safe.nonce(), nonce, "the Safe ran neither transaction");
    }

    /// #201, item 2: finding 5.3.7 of Solady's Cantina/Spearbit review, its
    /// proof of concept (`testDecodeBatchEdgeCase2`, fixed in PR 1244). The
    /// batch's `executionData` declares five words while its pointer array
    /// claims four entries, so the last pointer word lies past the declared
    /// end, in the call's trailing bytes. Kernel decodes it with the Solady it
    /// pins and so does `AgentPolicy`: both read the same four calls, to
    /// address 0, and the policy refuses them, whatever follows `callData` in
    /// the operation. Solady v0.1.26 refuses the batch itself, so moving the
    /// policy alone to it would make the policy and the deployed Kernel differ.
    function test_batch_theSoladyReviewsBatchIsReadAsKernelReadsIt() public {
        bytes memory callData = abi.encodePacked(
            Kernel.execute.selector,
            ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
            uint256(0x40), // the offset of executionData
            uint256(32 * 5), // its declared length: five words
            uint256(0x20), // the offset of the pointer array
            uint256(4), // its length: four pointers
            uint256(0),
            uint256(0),
            uint256(0), // pointers[0] to [2]
            uint256(0) // pointers[3]: past the declared end, in the trailing bytes
        );
        // Kernel's reading: four calls to address 0
        _kernelReadsFourCallsToZero(callData);
        // The fixed decoder refuses the batch outright
        KernelDecodes decoder = new KernelDecodes();
        bytes memory executionData = new bytes(32 * 5);
        for (uint256 i; i < executionData.length; i++) {
            executionData[i] = callData[100 + i];
        }
        vm.expectRevert(FixedERC7579.DecodingError.selector);
        decoder.decodeFixed(executionData);
        // The policy's reading: the same calls, refused (address 0 is no
        // target of the mandate), with or without bytes after `callData`.
        // The control: a well-formed batch of one allowed call passes (a
        // verdict other than 1 is the window it is valid in).
        Execution[] memory one = new Execution[](1);
        one[0] = Execution(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        bytes memory wellFormed = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(one)
        );
        assertTrue(_policyVerdict(wellFormed, "") != 1, "the control passes");
        assertEq(_policyVerdict(callData, ""), 1, "refused, as read");
        assertEq(_policyVerdict(callData, abi.encodePacked(address(0xbeef), uint128(1), uint128(1))), 1);
        // and through the EntryPoint, refused
        PackedUserOperation memory op = _op(_permissionNonce(AGENT_ID), callData);
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
        _expectRefused(op);
    }

    /// The same batch shifted so that `executionData` ends where `callData`
    /// ends, its last pointer word wholly past both. Kernel reads zeros past
    /// its calldata and takes the four calls to address 0. The policy reads
    /// what follows `callData` in the encoded operation: with no
    /// `paymasterAndData`, zeros too, and it refuses the calls as Kernel reads
    /// them; with a `paymasterAndData`, its length word (52) as the pointer,
    /// past the batch's bounds, and the pinned decoder refuses the batch. The
    /// two readings differ there, and the policy's is the refusal.
    function test_batch_pastTheEndOfTheCallThePolicyRefuses() public {
        bytes memory callData = abi.encodePacked(
            Kernel.execute.selector,
            ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
            uint256(0x40 + 28), // executionData starts 28 bytes later
            new bytes(28), // so that callData's length is a whole number of words
            uint256(32 * 5),
            uint256(0x20),
            uint256(4),
            uint256(0),
            uint256(0),
            uint256(0) // pointers[0] to [2]; pointers[3] would be the next word
        );
        assertEq(callData.length % 32, 0);
        _kernelReadsFourCallsToZero(callData);
        assertEq(_policyVerdict(callData, ""), 1, "no bytes after callData: zeros, refused as Kernel reads it");
        bytes memory paymasterAndData = abi.encodePacked(address(0xbeef), uint128(1), uint128(1));
        assertEq(paymasterAndData.length, 52);
        PackedUserOperation memory op = _opWith(callData, paymasterAndData);
        vm.prank(acct);
        vm.expectRevert(PinnedERC7579.DecodingError.selector);
        policy.checkUserOpPolicy(bytes32(PermissionId.unwrap(AGENT_ID)), op);
    }

    function _kernelReadsFourCallsToZero(bytes memory callData) internal {
        (bool ok, bytes memory ret) = address(new KernelDecodes()).call(callData);
        assertTrue(ok, "the pinned decoder takes the batch");
        (address[] memory targets, uint256[] memory values) = abi.decode(ret, (address[], uint256[]));
        assertEq(targets.length, 4);
        for (uint256 i; i < 4; i++) {
            assertEq(targets[i], address(0));
            assertEq(values[i], 0);
        }
    }

    function _opWith(bytes memory callData, bytes memory paymasterAndData)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(_permissionNonce(AGENT_ID), callData);
        op.paymasterAndData = paymasterAndData;
    }

    /// The policy asked directly, as Kernel asks it for the agent's permission.
    /// The policy refuses a batch whose pointer array does not end within
    /// `executionData`, whatever its legs are. The batch of Solady's review
    /// reads as four plain calls to address 0. Here the mandate is made to
    /// allow exactly that (written into storage), so that nothing but the
    /// rule on the array refuses it: without the rule this batch passes.
    /// The same four calls in a batch whose array ends inside pass.
    function test_batch_aPointerArrayPastTheEndIsRefused() public {
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        vm.record();
        policy.isAllowed(acct, id, address(0), bytes4(0));
        (bytes32[] memory reads,) = vm.accesses(address(policy));
        vm.store(address(policy), reads[reads.length - 1], bytes32(uint256(1)));
        assertTrue(policy.isAllowed(acct, id, address(0), bytes4(0)), "not planted where the policy reads");

        bytes memory head = abi.encodePacked(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), uint256(0x40)
        );
        // four pointers of 0, all inside: each leg is the array's first three words
        bytes memory inside =
            abi.encodePacked(head, uint256(32 * 6), uint256(0x20), uint256(4), uint256(0), uint256(0), uint256(0), uint256(0));
        assertTrue(_policyVerdict(inside, "") != 1, "the control: four calls to address 0 pass when the array is inside");
        // the same bytes with executionData declared one word shorter: pointers[3] is past its end
        bytes memory past =
            abi.encodePacked(head, uint256(32 * 5), uint256(0x20), uint256(4), uint256(0), uint256(0), uint256(0), uint256(0));
        _kernelReadsFourCallsToZero(past);
        assertEq(_policyVerdict(past, ""), 1, "a pointer past the end of executionData");
        // and with the array starting past the end altogether
        bytes memory beyond = abi.encodePacked(head, uint256(32), uint256(0x40), uint256(0), uint256(0));
        assertEq(_policyVerdict(beyond, ""), 1, "an array that starts past the end");
    }

    /// `executionData`'s own offset and length, read alike by the policy and
    /// by Kernel. The policy slices `executionData` out of `callData` by
    /// hand; Kernel's `execute` takes it through Solidity's ABI decoder. A
    /// well-formed batch of allowed legs is laid out with an offset other
    /// than 0x40, a declared length shorter or longer than the bytes, bytes
    /// between and after, and now and then one byte changed. Whenever the
    /// policy accepts: Kernel reads the call too, every leg Kernel reads is
    /// on the mandate's allow-list, and the value the policy charged is the
    /// sum of the values Kernel would send. So nothing runs that was not
    /// judged, and nothing judged with a value goes unmade.
    function testFuzz_batch_executionDataIsReadAsKernelReadsIt(uint256 seed) public {
        KernelReads kernel = new KernelReads();
        uint256 accepted;
        uint256 odd;
        for (uint256 n; n < 16; n++) {
            uint256 r = uint256(keccak256(abi.encode(seed, n))) & ((1 << 255) - 1);
            // the first is always the plain layout, so that every run has one accepted
            (bool ok, bool plain) = _oneLayout(kernel, r, n == 0);
            if (plain) assertTrue(ok, "the plain layout of allowed legs passes");
            else odd++;
            if (ok) accepted++;
        }
        // The seventeenth: a pointer array that runs one word past the end
        // of `callData`. Both sides read it as four plain calls to address
        // 0, and the mandate is made to allow exactly that (written into
        // storage, as in `test_batch_aPointerArrayPastTheEndIsRefused`), so
        // that only the rule on the array can refuse it.
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        vm.record();
        policy.isAllowed(acct, id, address(0), bytes4(0));
        (bytes32[] memory reads,) = vm.accesses(address(policy));
        vm.store(address(policy), reads[reads.length - 1], bytes32(uint256(1)));
        (bool past,) = _oneLayout(kernel, 1 << 255, false);
        assertFalse(past, "a pointer array past the end of callData was accepted");
        // not a property of the policy: the generator still reaches both kinds
        assertGt(accepted, 0, "none accepted");
        assertGt(odd, 2, "too few odd layouts");
    }

    function _oneLayout(KernelReads kernel, uint256 r, bool asEncoded) internal returns (bool ok, bool plain) {
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        bytes memory callData;
        (callData, plain) = _batchLaidOut(r, asEncoded);
        bytes memory paymasterAndData =
            (r >> 200) % 3 == 0 ? abi.encodePacked(address(0xbeef), uint128(1), uint128(1), r) : bytes("");
        uint256 snap = vm.snapshotState();
        // what the policy charges for the operation's gas alone, with the same fields
        uint256 gasOnly = _charged(id, _opWith(_singleCall(address(counter), 0, ""), paymasterAndData));
        vm.revertToState(snap);
        uint256 charged;
        (ok, charged) = _judged(id, _opWith(callData, paymasterAndData));
        vm.revertToState(snap);
        if (ok) assertEq(charged, gasOnly + _kernelWouldSend(kernel, id, callData), "charged: the values Kernel would send");
    }

    function _judged(bytes32 id, PackedUserOperation memory op) internal returns (bool ok, uint256 charged) {
        (,,,, uint128 before,) = policy.configs(acct, id);
        vm.prank(acct);
        // with a limit on the gas: a read that uses it up is a refusal (see `READ_GAS`)
        (bool answered, bytes memory verdict) =
            address(policy).call{gas: READ_GAS}(abi.encodeCall(policy.checkUserOpPolicy, (id, op)));
        ok = answered && abi.decode(verdict, (uint256)) != 1;
        (,,,, uint128 afterwards,) = policy.configs(acct, id);
        charged = afterwards - before;
    }

    /// The gas one reading of a call gets in these tests, some thirty times
    /// what a batch of three legs takes. Kernel's pinned `decodeBatch`
    /// checks the pointers in a loop from the last one down, and a pointer
    /// past the end of the calldata reads as zeros and passes: with an
    /// enormous array length the loop ends only when the gas does ("Does an
    /// out-of-gas revert", in the library's words). The policy calls the same
    /// decoder first, so it stops the same way, and an operation whose
    /// validation runs out of gas is not included. Without a limit one such
    /// layout takes nearly all the gas the test has.
    uint256 internal constant READ_GAS = 10_000_000;

    /// A batch whose array length is enormous is read by neither side:
    /// Kernel's decoder runs out of gas, the policy does not accept, and
    /// nothing is charged.
    function test_batch_anEnormousPointerArrayIsReadByNeither() public {
        bytes32 id = bytes32(PermissionId.unwrap(AGENT_ID));
        Execution[] memory legs = new Execution[](1);
        legs[0] = Execution(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        bytes memory body = ExecLib.encodeBatch(legs);
        bytes memory honest = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), body
        );
        (bool ok,) = _judged(id, _opWith(honest, ""));
        assertTrue(ok, "the batch as encoded passes");
        // the same bytes with the array's length word changed: 4 + 32 (mode)
        // + 32 (offset) + 32 (length) + 32 (the array's offset), then the word
        bytes memory enormous = bytes.concat(honest);
        enormous[4 + 32 * 4 + 24] = 0x10; // one leg becomes 2^60 + 1
        KernelReads kernel = new KernelReads();
        (bool read,) = address(kernel).call{gas: READ_GAS}(enormous);
        assertFalse(read, "Kernel's decoder read an enormous array");
        uint256 charged;
        (ok, charged) = _judged(id, _opWith(enormous, ""));
        assertFalse(ok, "the policy accepted an enormous array");
        assertEq(charged, 0, "nothing charged");
    }

    /// Kernel's reading of a call the policy accepted: every leg on the
    /// allow-list; the values together.
    function _kernelWouldSend(KernelReads kernel, bytes32 id, bytes memory callData) internal returns (uint256 sum) {
        (bool read, bytes memory ret) = address(kernel).call{gas: READ_GAS}(callData);
        assertTrue(read, "the policy accepted a call Kernel cannot read");
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            abi.decode(ret, (address[], uint256[], bytes[]));
        assertGt(targets.length, 0, "the policy accepted a batch Kernel reads as empty");
        for (uint256 i; i < targets.length; i++) {
            bytes memory d = datas[i];
            assertTrue(d.length == 0 || d.length >= 4, "a leg of one to three bytes");
            assertTrue(
                policy.isAllowed(acct, id, targets[i], d.length == 0 ? bytes4(0) : bytes4(d)),
                "Kernel would run a call the mandate does not list"
            );
            sum += values[i];
        }
    }

    function _charged(bytes32 id, PackedUserOperation memory op) internal returns (uint256) {
        (,,,, uint128 before,) = policy.configs(acct, id);
        vm.prank(acct);
        assertTrue(policy.checkUserOpPolicy(id, op) != 1, "the control passes");
        (,,,, uint128 afterwards,) = policy.configs(acct, id);
        return afterwards - before;
    }

    /// A batch of one to three allowed legs (an increment, or a few wei to
    /// the counter) as `execute` calldata; `plain` when laid out as
    /// `abi.encode` would.
    function _batchLaidOut(uint256 r, bool asEncoded) internal view returns (bytes memory callData, bool plain) {
        Execution[] memory legs = new Execution[](1 + r % 3);
        for (uint256 i; i < legs.length; i++) {
            uint256 k = (r >> (8 + 8 * i)) % 4;
            legs[i] = k == 0
                ? Execution(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
                : Execution(address(counter), k, "");
        }
        bytes memory body = ExecLib.encodeBatch(legs);
        if (r >> 255 == 1 && !asEncoded) {
            // four pointers of 0, the last one word past the end of callData
            return (
                abi.encodePacked(
                    Kernel.execute.selector,
                    ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
                    uint256(0x40),
                    uint256(32 * 5),
                    uint256(0x20),
                    uint256(4),
                    uint256(0),
                    uint256(0),
                    uint256(0)
                ),
                false
            );
        }
        if (asEncoded) {
            return (
                abi.encodeWithSelector(Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), body),
                true
            );
        }
        uint256 between = (r >> 40) % 4 == 0 ? (r >> 48) % 4 : 0; // words between the offset and the length
        uint256 offset = 0x40 + 32 * between;
        uint256 length = body.length;
        uint256 how = (r >> 56) % 12;
        if (how == 0) offset += 1 + (r >> 64) % 31; // not on a word
        if (how == 1) offset -= 32; // onto the offset word itself
        if (how == 2) offset = (r >> 64) % 0x200;
        if (how == 3) length -= 32 * (1 + (r >> 72) % 3);
        if (how == 4) length += 32 * (1 + (r >> 72) % 3);
        if (how == 5) length = (r >> 72) % 2 == 0 ? length - 1 : length + 1;
        if (how == 6) length = r >> 80;
        if (how == 7) length = 0;
        bytes memory gap;
        for (uint256 i; i < between; i++) {
            // zeros, a small number, or any word
            uint256 w = uint256(keccak256(abi.encode(r, "gap", i)));
            gap = abi.encodePacked(gap, w % 3 == 0 ? uint256(0) : w % 3 == 1 ? (w >> 8) % 0x200 : w);
        }
        bytes memory tail;
        for (uint256 i; i < (r >> 100) % 4; i++) {
            uint256 w = uint256(keccak256(abi.encode(r, "tail", i)));
            tail = abi.encodePacked(tail, w % 2 == 0 ? (w >> 8) % 0x200 : w);
        }
        callData = abi.encodePacked(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), offset, gap, length, body, tail
        );
        bool changed = (r >> 110) % 6 == 0;
        if (changed) {
            uint256 at = 36 + (r >> 120) % (callData.length - 36);
            callData[at] = bytes1(uint8(uint8(callData[at]) ^ uint8(1 << ((r >> 140) % 8))));
        }
        plain = between == 0 && how > 7 && !changed;
    }

    function _policyVerdict(bytes memory callData, bytes memory paymasterAndData) internal returns (uint256) {
        // built first: a prank goes to the next call, and building the
        // operation makes calls of its own
        PackedUserOperation memory op = _opWith(callData, paymasterAndData);
        vm.prank(acct);
        return policy.checkUserOpPolicy(bytes32(PermissionId.unwrap(AGENT_ID)), op);
    }

    function _safeExecGas(address to, bytes memory data, uint256 safeTxGas, uint256 baseGas)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sig = abi.encodePacked(uint256(uint160(acct)), uint256(0), uint8(1));
        return abi.encodeCall(
            Safe.execTransaction,
            (to, 0, data, Enum.Operation.Call, safeTxGas, baseGas, 0, address(0), payable(address(0)), sig)
        );
    }

    /// The Safe mandate of `_withSafe`, with approvals of the mock token
    /// (approve, increaseAllowance) within its limits.
    function _withSafeApprovals() internal returns (Safe safe) {
        Safe singleton = new Safe();
        SafeProxyFactory safeFactory = new SafeProxyFactory();
        address[] memory owners = new address[](1);
        owners[0] = acct;
        bytes memory setup = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = Safe(payable(address(safeFactory.createProxyWithNonce(address(singleton), setup, 0))));
        multiSend = new MultiSendCallOnly();
        address[] memory targets = new address[](4);
        bytes4[] memory selectors = new bytes4[](4);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(multiSend), MultiSendCallOnly.multiSend.selector);
        (targets[2], selectors[2]) = (address(token), MockToken.approve.selector);
        (targets[3], selectors[3]) = (address(token), bytes4(0x39509351)); // increaseAllowance(address,uint256)
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, _tokenCaps());
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(SAFE_ID);
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

    /// A metered function on a contract without a token limit: refused at
    /// install (#175; `test_probe2_installRefusesAMeteredFunctionWithoutALimit`),
    /// and, for a mandate an earlier instance installed, at every operation.
    /// Here the entry is not on the mandate at all.
    function test_token_selectorWithoutLimitIsRefused() public {
        _expectRefused(_agentOp(address(forbidden), 0, abi.encodeCall(MockToken.transfer, (address(1), 0))));
    }

    /// F3: when the account pays its own gas, the maximum charge counts
    /// against the budget.
    function test_gas_selfPaidCountsAgainstBudget() public {
        _send(_agentOp(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)));
        assertEq(_spent(AGENT_ID), GAS_PER_OP);
    }

    /// The EntryPoint takes the paymaster from the field's first twenty
    /// bytes, not from the field's length. A field of 52 bytes that names the
    /// zero address is "no paymaster" to it: the account pays, the field's
    /// two gas limits included. The policy used to count gas for an empty
    /// field only, so such an operation ran uncounted: with a large
    /// `preVerificationGas` the account paid more than its whole native
    /// budget to the beneficiary that the caller of `handleOps` named, and
    /// `spent` stayed 0 (#244, the internal audit of 2026-11-28, finding
    /// AK-2026-11-28-01). Refused now, with nothing paid.
    function test_gas_aPaymasterFieldThatNamesNoPaymasterIsRefused() public {
        address payable beneficiary = payable(makeAddr("beneficiary"));
        // the account can pay it: a refusal below is the policy's, not a lack of funds
        vm.deal(acct, 10 ether);
        // 300,000,000 gas at 1 gwei is 0.3 ether, over the budget of 0.25
        uint256 preVerificationGas = 300_000_000;
        assertGt(preVerificationGas * 1 gwei, BUDGET);

        // the control: an empty field, the account pays, the gas is counted and is over the budget
        _expectRefusedPaying(_agentOpPaying(preVerificationGas, ""), beneficiary);

        uint256 funds = acct.balance + entryPoint.balanceOf(acct);
        bytes[3] memory fields = [
            // the zero address and no paymaster gas
            abi.encodePacked(address(0), uint128(0), uint128(0)),
            // the zero address with paymaster gas limits, which the EntryPoint adds to the account's prefund
            abi.encodePacked(address(0), uint128(500_000), uint128(500_000)),
            // and with data after the fixed part
            abi.encodePacked(address(0), uint128(0), uint128(0), bytes32(uint256(1)))
        ];
        for (uint256 i; i < fields.length; i++) {
            _expectRefusedPaying(_agentOpPaying(preVerificationGas, fields[i]), beneficiary);
            // with an ordinary gas figure too: the field is refused, not the amount
            _expectRefusedPaying(_agentOpPaying(100_000, fields[i]), beneficiary);
            assertEq(_policyVerdict(_incrementCall(), fields[i]), 1, "the refusal is the policy's");
        }
        assertEq(counter.count(), 0, "nothing ran");
        assertEq(_spent(AGENT_ID), 0);
        assertEq(acct.balance + entryPoint.balanceOf(acct), funds, "the account paid nothing");
        assertEq(beneficiary.balance, 0, "and the beneficiary received nothing");
    }

    /// A field shorter than a paymaster's 52 fixed bytes names no paymaster
    /// either. The EntryPoint refuses such an operation itself; the policy
    /// does not rest on that.
    function test_gas_aPaymasterFieldShorterThanItsFixedPartIsRefused() public {
        bytes memory whole = abi.encodePacked(address(0xbeef), uint128(1), uint128(1));
        for (uint256 length = 1; length < 52; length++) {
            bytes memory field = new bytes(length);
            for (uint256 i; i < length; i++) field[i] = whole[i];
            uint256 snap = vm.snapshotState();
            assertEq(_policyVerdict(_incrementCall(), field), 1, "a cut field");
            vm.revertToState(snap);
        }
        // the whole field names a paymaster: the policy passes the operation and counts no gas for the account
        assertTrue(_policyVerdict(_incrementCall(), whole) != 1, "a paymaster's field");
        assertEq(_spent(AGENT_ID), 0);
    }

    /// For any paymaster field. An operation the policy passes has an empty
    /// field, and then its gas is counted for the account; or it names a
    /// paymaster as the EntryPoint unpacks one (52 bytes or more, an address
    /// that is not zero), and then nothing is counted because the account
    /// pays nothing. Every other field is refused.
    function testFuzz_gas_whoPaysIsWhatTheEntryPointReads(bytes memory field, bool zeroed) public {
        // random bytes seldom start with twenty zeros: make half of the runs do
        if (zeroed) for (uint256 i; i < field.length && i < 20; i++) field[i] = 0;
        address paymaster;
        if (field.length >= 20) {
            assembly ("memory-safe") {
                paymaster := shr(96, mload(add(field, 32)))
            }
        }
        bool namesAPaymaster = field.length >= 52 && paymaster != address(0);
        uint256 verdict = _policyVerdict(_incrementCall(), field);
        if (field.length == 0) {
            assertTrue(verdict != 1, "an empty field passes");
            assertEq(_spent(AGENT_ID), GAS_PER_OP, "and the account's gas is counted");
        } else if (namesAPaymaster) {
            assertTrue(verdict != 1, "a paymaster's field passes");
            assertEq(_spent(AGENT_ID), 0, "and nothing is counted for the account");
        } else {
            assertEq(verdict, 1, "a field that names no paymaster is refused");
        }
    }

    function _incrementCall() internal view returns (bytes memory) {
        return _singleCall(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
    }

    /// An agent's call of the counter with the gas figure and the paymaster field under test.
    function _agentOpPaying(uint256 preVerificationGas, bytes memory paymasterAndData)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(_permissionNonce(AGENT_ID), _incrementCall());
        op.preVerificationGas = preVerificationGas;
        op.paymasterAndData = paymasterAndData;
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
    }

    function _expectRefusedPaying(PackedUserOperation memory op, address payable beneficiary) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
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

    /// The assertion's address is a whole word. With a bit above the low 160
    /// the policy used to judge the low 160 bits and pass the operation;
    /// `check` then reverted at execution, and the operation was charged its
    /// gas for nothing. Refused in validation now.
    function test_safe_theGuardedAddressIsAWholeWord() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        bytes memory exec = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
        Execution[] memory calls = new Execution[](2);
        calls[1] = Execution(address(safe), 0, exec);
        for (uint256 bit = 160; bit < 256; bit += 19) {
            calls[0] = Execution(
                address(nonceAssert),
                0,
                abi.encodeWithSelector(SafeNonceAssert.check.selector, uint256(uint160(address(safe))) | (1 << bit), safe.nonce())
            );
            _expectRefused(_agentBatchWith(AGENT, SAFE_ID, calls));
        }
        assertEq(_spent(SAFE_ID), 0, "a refused operation is charged nothing");
        // the control: the same pair with the plain address
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        _send(_agentBatchWith(AGENT, SAFE_ID, calls));
        assertEq(counter.count(), 1);
    }

    /// The same one call deeper: the address words of `execTransaction`
    /// itself (`to`, `gasToken`, `refundReceiver`). The policy judged the low
    /// 160 bits of `to`; this Safe, built with a decoder that validates the
    /// word, reverted at execution with the operation charged.
    function test_safe_theTransactionsAddressesAreWholeWords() public {
        Safe safe = _withSafe();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // head words 0, 7 and 8, after the selector
        uint256[3] memory words = [uint256(0), 7, 8];
        for (uint256 w; w < words.length; w++) {
            for (uint256 bit = 160; bit < 256; bit += 31) {
                bytes memory exec = _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0);
                uint256 at = 32 + 4 + 32 * words[w];
                uint256 mask = 1 << bit;
                assembly {
                    mstore(add(exec, at), or(mload(add(exec, at)), mask))
                }
                _expectRefused(_agentViaSafe(safe, exec));
            }
        }
        assertEq(_spent(SAFE_ID), 0, "a refused operation is charged nothing");
        assertEq(counter.count(), 0);
        // the control
        _send(_agentViaSafe(safe, _safeExec(safe, address(counter), 0, inc, Enum.Operation.Call, 0)));
        assertEq(counter.count(), 1);
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

    /// Audit #76 F-1: the plain-transfer entry admits empty calldata only. A
    /// body that starts with four zero bytes has the zero selector too, and
    /// would run the target's fallback with data the agent chose.
    function test_zeroSelectorWithABodyIsRefused() public {
        _expectRefused(_agentOp(address(counter), 0, hex"00000000"));
        _expectRefused(_agentOp(address(counter), 0, hex"00000000deadbeef"));
        _expectRefused(_agentOp(address(counter), 0.01 ether, abi.encodePacked(bytes4(0), uint256(1), uint256(2))));
        assertEq(address(counter).balance, 0);
        _send(_agentOp(address(counter), 0.01 ether, ""));
        assertEq(address(counter).balance, 0.01 ether);
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

    /// Issue #154: install data is exactly the key, 64 bytes, for the validator
    /// and the recovery validator; a word short or anything after it is refused.
    function test_validatorInstallDataIsExactlyTheKey() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(AGENT2);
        bytes memory key = abi.encode(bytes32(x), bytes32(y));
        P256Validator[2] memory validators = [new P256Validator(), P256Validator(new P256RecoveryValidator())];
        for (uint256 i; i < validators.length; i++) {
            vm.expectRevert(P256Validator.InvalidPublicKey.selector);
            validators[i].onInstall(abi.encodePacked(key, bytes1(0))); // 65 bytes
            vm.expectRevert(P256Validator.InvalidPublicKey.selector);
            validators[i].onInstall(abi.encodePacked(key, bytes32(0))); // 96 bytes
            vm.expectRevert(P256Validator.InvalidPublicKey.selector);
            validators[i].onInstall(abi.encodePacked(bytes32(x), bytes31(bytes32(y)))); // 63 bytes
            validators[i].onInstall(key);
            assertTrue(validators[i].isInitialized(address(this)));
        }
    }

    /// Issue #154: the signer's install data is exactly the id and the key, 96
    /// bytes; a byte short or anything after the key is refused.
    function test_signerInstallDataIsExactlyTheIdAndTheKey() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(AGENT2);
        bytes32 id = bytes32(PermissionId.unwrap(PermissionId.wrap(0x6c656e67))); // "leng"
        bytes memory key = abi.encode(bytes32(x), bytes32(y));
        vm.expectRevert(P256Signer.InvalidPublicKey.selector);
        signer.onInstall(abi.encodePacked(id, key, bytes1(0))); // 97 bytes
        vm.expectRevert(P256Signer.InvalidPublicKey.selector);
        signer.onInstall(abi.encodePacked(id, key, bytes32(0))); // 128 bytes
        vm.expectRevert(P256Signer.InvalidPublicKey.selector);
        signer.onInstall(abi.encodePacked(id, bytes32(x), bytes31(bytes32(y)))); // 95 bytes
        signer.onInstall(abi.encodePacked(id, key));
        (bytes32 storedX,) = signer.publicKeys(id, address(this));
        assertEq(storedX, bytes32(x));
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

        // Permit2: its own `approve` would hand a token's allowance to any address, unread
        address permit2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
        bytes4[2] memory onPermit2 = [bytes4(keccak256("approve(address,address,uint160,uint48)")), bytes4(0x12345678)];
        for (uint256 k; k < onPermit2.length; k++) {
            (targets[0], selectors[0]) = (permit2, onPermit2[k]);
            vm.prank(acct);
            vm.expectRevert(abi.encodeWithSelector(AgentPolicy.ForbiddenTarget.selector, permit2, onPermit2[k]));
            policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));
        }

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

    // --- a permission with an execution hook ---

    PermissionId internal constant HOOK_ID = PermissionId.wrap(0x686f6f6b); // "hook"

    /// The agent's mandate (the counter, and value to it) on a permission that
    /// carries `hook`.
    function _withHook(CountingHook hook) internal {
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(counter), Counter.increment.selector);
        (targets[1], selectors[1]) = (address(counter), bytes4(0));
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, new AgentPolicy.TokenCap[](0));
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(HOOK_ID);
        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = vId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: Kernel(payable(acct)).currentNonce(), hook: IHook(address(hook))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = abi.encode(entries);
        bytes[] memory hData = new bytes[](1);
        hData[0] = hex"ff"; // Kernel's flag: call the hook's onInstall
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(acct, 0, abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData)));
        batch[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(batch)
                )
            )
        );
    }

    /// An agent operation on the hooked permission, its `callData` prefixed
    /// `times` times with `executeUserOp`'s selector.
    function _hookedOp(uint256 times, address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        bytes memory callData = _singleCall(target, value, data);
        for (uint256 i; i < times; i++) {
            callData = abi.encodePacked(Kernel.executeUserOp.selector, callData);
        }
        op = _op(_permissionNonce(HOOK_ID), callData);
        op.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op)));
    }

    /// A permission with an execution hook runs under the same mandate:
    /// Kernel requires `executeUserOp ‖ execute(...)` of it, the policy judges
    /// the `execute(...)` inside, and the hook runs around the call.
    function test_hook_aHookedPermissionIsHeldToTheMandate() public {
        CountingHook hook = new CountingHook();
        _withHook(hook);
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // Kernel refuses the plain form for a hooked permission
        PackedUserOperation memory plain = _op(_permissionNonce(HOOK_ID), _singleCall(address(counter), 0, inc));
        plain.signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(plain)));
        _expectRefused(plain);
        // the hooked form passes the mandate, and the hook runs around it
        _send(_hookedOp(1, address(counter), 0, inc));
        assertEq(counter.count(), 1);
        assertEq(hook.pre(), 1);
        assertEq(hook.post(), 1);
        // held to the mandate in that form: a target outside it, a value over the cap
        _expectRefused(_hookedOp(1, address(forbidden), 0, inc));
        _expectRefused(_hookedOp(1, address(counter), MAX_VALUE + 1, ""));
        // one prefix only
        _expectRefused(_hookedOp(2, address(counter), 0, inc));
        assertEq(counter.count(), 1);
        assertEq(hook.pre(), 1);
    }

    /// The selector the policy strips is Kernel's.
    function test_hook_thePrefixIsKernelsExecuteUserOp() public pure {
        assertEq(Kernel.executeUserOp.selector, bytes4(0x8dd7712f));
    }

    /// An authorization without an end is refused: its `validBefore` of 0
    /// would be vouched for as Kernel reads a `validUntil` of 0, without end,
    /// past the mandate's own `validUntil`.
    function test_x402_anAuthorizationWithoutAnEndIsRefused() public {
        _withX402();
        bytes32 id = bytes32(PermissionId.unwrap(PAY_ID));
        bytes32 digest = usdc.digestOf(acct, PAYEE, 500_000, 0, 0, bytes32(uint256(9)));
        _expectRefused(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, 0, bytes32(uint256(9)))));
        assertFalse(_isValid(digest));
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 0);
        // the control: the same authorization with an end registers
        uint256 before = block.timestamp + 1 hours;
        _send(_agentOpWith(AGENT, PAY_ID, address(policy), 0, _authorizeCall(500_000, before, bytes32(uint256(9)))));
        assertTrue(_isValid(usdc.digestOf(acct, PAYEE, 500_000, 0, before, bytes32(uint256(9)))));
        assertEq(policy.tokenLimit(acct, id, address(usdc)).spent, 500_000);
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
        targets = new address[](5);
        selectors = new bytes4[](5);
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

    // --- audit #76 F-2: a token's `maxPerOp` holds for the whole operation ---

    function _transferLeg(uint256 amount) internal view returns (Execution memory) {
        return Execution(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE, amount)));
    }

    function _tokenSpent(address tokenAddr) internal view returns (uint256) {
        return policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PYE_ID)), tokenAddr).spent;
    }

    function test_tokenCapPerOperation_legsAddUp() public {
        _withPayees();
        Execution[] memory calls = new Execution[](2);
        // each leg is at the cap, the operation is at twice the cap
        (calls[0], calls[1]) = (_transferLeg(TOKEN_MAX), _transferLeg(TOKEN_MAX));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        (calls[0], calls[1]) = (_transferLeg(TOKEN_MAX - 1 ether), _transferLeg(1 ether + 1));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE), 0);
        assertEq(_tokenSpent(address(token)), 0);
        // exactly the cap in two legs
        (calls[0], calls[1]) = (_transferLeg(TOKEN_MAX - 1 ether), _transferLeg(1 ether));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE), TOKEN_MAX);
        assertEq(_tokenSpent(address(token)), TOKEN_MAX);
    }

    /// An approval and a transfer of one token in one operation share the cap.
    function test_tokenCapPerOperation_approveAndTransferShareIt() public {
        _withPayees();
        Execution[] memory calls = new Execution[](3);
        calls[0] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (PAYEE, 6 ether)));
        calls[1] = _transferLeg(6 ether);
        calls[2] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (PAYEE, 0))); // no standing allowance
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        calls[1] = _transferLeg(4 ether);
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(token)), 10 ether);
    }

    /// Each token has its own total, and a new operation starts from zero —
    /// also when two operations are validated in one bundle transaction.
    function test_tokenCapPerOperation_perTokenAndPerOperation() public {
        _withPayees();
        Execution[] memory calls = new Execution[](2);
        calls[0] = _transferLeg(TOKEN_MAX);
        calls[1] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 1e6)));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(token.balanceOf(PAYEE), TOKEN_MAX);
        assertEq(usdc.balanceOf(PAYEE), 1e6);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        uint256 nonce = _permissionNonce(PYE_ID);
        for (uint256 i; i < 2; i++) {
            ops[i] = _op(nonce + i, _singleCall(address(token), 0, abi.encodeCall(MockToken.transfer, (PAYEE_2, 7 ether))));
            ops[i].signature = abi.encodePacked(bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(ops[i])));
        }
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(token.balanceOf(PAYEE_2), 14 ether);
        assertEq(_tokenSpent(address(token)), TOKEN_MAX + 14 ether);
    }

    /// x402 registrations count toward the same per-operation total.
    function test_tokenCapPerOperation_x402RegistrationsAddUp() public {
        _withPayees();
        uint256 before = block.timestamp + 1 hours;
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(policy), 0, _authorizeCall(600_000, before, bytes32(uint256(1))));
        calls[1] = Execution(address(policy), 0, _authorizeCall(600_000, before, bytes32(uint256(2))));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        // a transfer and a registration of the same token
        calls[1] = Execution(address(usdc), 0, abi.encodeCall(MockToken.transfer, (PAYEE, 400_001)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(usdc)), 0);
        calls[1] = Execution(address(policy), 0, _authorizeCall(400_000, before, bytes32(uint256(2))));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(usdc)), 1e6);
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
        // to a listed spender (withdrawn in the same operation: no standing allowances)
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (PAYEE, 2 ether)));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (PAYEE, 0)));
        _send(_agentBatchWith(AGENT, PYE_ID, calls));
        assertEq(_tokenSpent(address(token)), 2 ether);
        // to a spender not listed: refused, withdrawn or not
        calls[0] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (STRANGER, 1)));
        calls[1] = Execution(address(token), 0, abi.encodeCall(MockToken.approve, (STRANGER, 0)));
        _expectRefused(_agentBatchWith(AGENT, PYE_ID, calls));
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

    // --- `transferFrom` and its source (#247: the internal audit of 2026-11-28, finding AK-2026-11-28-04) ---

    PermissionId internal constant PULL_ID = PermissionId.wrap(0x70756c6c); // "pull"

    /// A Safe of the account's, and a mandate that lists `transferFrom` on
    /// the token, for a direct call and for a call inside a Safe transaction:
    /// with PAYEE as the token's only payee, or with no payee list.
    function _withTransferFrom(bool listed) internal returns (Safe safe) {
        address[] memory owners = new address[](1);
        owners[0] = acct;
        bytes memory setup =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));
        safe = Safe(payable(address(new SafeProxyFactory().createProxyWithNonce(address(new Safe()), setup, 0))));
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (address(safe), Safe.execTransaction.selector);
        (targets[1], selectors[1]) = (address(token), MockToken.transferFrom.selector);
        bytes memory params;
        if (listed) {
            AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
            lists[0] = _list(address(token), PAYEE, address(0));
            params = abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _tokenCaps(), uint48(0), lists);
        } else {
            params = abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, _tokenCaps(), uint48(0));
        }
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(bytes2(0), address(policy), params);
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(PULL_ID);
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

    /// `transferFrom(from, to, amount)` by a direct call of the account.
    function _pull(address from, address to, uint256 amount) internal view returns (PackedUserOperation memory) {
        return _agentOpWith(AGENT, PULL_ID, address(token), 0, abi.encodeCall(MockToken.transferFrom, (from, to, amount)));
    }

    /// The same call inside a Safe transaction, after the nonce assertion.
    function _pullViaSafe(Safe safe, address from, address to, uint256 amount)
        internal
        view
        returns (PackedUserOperation memory)
    {
        bytes memory inner = abi.encodeCall(MockToken.transferFrom, (from, to, amount));
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(nonceAssert), 0, abi.encodeCall(SafeNonceAssert.check, (address(safe), safe.nonce())));
        calls[1] = Execution(address(safe), 0, _safeExec(safe, address(token), 0, inner, Enum.Operation.Call, 0));
        return _agentBatchWith(AGENT, PULL_ID, calls);
    }

    /// The policy holds `transferFrom` by its amount and its recipient, and
    /// does not judge its source. A mandate that lists it hands the agent
    /// what others approved to the account, and inside a Safe transaction
    /// what others approved to the Safe: within the token's cap and budget,
    /// and to its payees where it has a list. An owner reads this in
    /// docs/AGENT_CONFIG.md and docs/CONTRACTS.md. Held here for both
    /// contexts and both kinds of payee list.
    function test_token_transferFromMovesWhatOthersApproved() public {
        for (uint256 listed; listed < 2; listed++) {
            uint256 snap = vm.snapshotState();
            _transferFromInBothContexts(listed == 1);
            vm.revertToState(snap);
        }
    }

    function _transferFromInBothContexts(bool listed) internal {
        Safe safe = _withTransferFrom(listed);
        address third = makeAddr("a third party");
        token.mint(third, 100 ether);
        vm.startPrank(third);
        token.approve(acct, 50 ether);
        token.approve(address(safe), 50 ether);
        vm.stopPrank();
        uint256 own = token.balanceOf(acct);
        uint256 spentBefore = policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PULL_ID)), address(token)).spent;

        // by a direct call: what the third party approved to the account
        _send(_pull(third, PAYEE, 2 ether));
        // inside a Safe transaction: what it approved to the Safe
        _send(_pullViaSafe(safe, third, PAYEE, 3 ether));
        assertEq(token.balanceOf(PAYEE), 5 ether);
        assertEq(token.balanceOf(third), 95 ether, "the third party's tokens moved");
        assertEq(token.balanceOf(acct), own, "not the account's");
        assertEq(token.balanceOf(address(safe)), 0, "and not the Safe's");
        // each is charged to the token's budget like a transfer
        assertEq(
            policy.tokenLimit(acct, bytes32(PermissionId.unwrap(PULL_ID)), address(token)).spent, spentBefore + 5 ether
        );

        // the cap per operation holds in both contexts
        _expectRefused(_pull(third, PAYEE, TOKEN_MAX + 1));
        _expectRefused(_pullViaSafe(safe, third, PAYEE, TOKEN_MAX + 1));

        // the recipient: a listed payee only, where the token has a list
        if (listed) {
            _expectRefused(_pull(third, STRANGER, 1 ether));
            _expectRefused(_pullViaSafe(safe, third, STRANGER, 1 ether));
            assertEq(token.balanceOf(STRANGER), 0);
        } else {
            _send(_pull(third, STRANGER, 1 ether));
            _send(_pullViaSafe(safe, third, STRANGER, 1 ether));
            assertEq(token.balanceOf(STRANGER), 2 ether);
        }
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
    /// Audit #79. A careless owner allow-lists a way to move a capped token
    /// that the caps do not meter (`mint` here; `permit` or a vault's
    /// `withdraw` elsewhere): the mandate is refused whole at install, with
    /// a payee list on the token and without one, since through that entry
    /// the token would pass neither its caps nor its list. The same entry on
    /// a token the mandate sets no limit for installs.
    /// The payee mandate's x402 and USDC entries, `fn` on the mock token, and a
    /// limit for USDC only.
    function _installWithoutTheTokensLimit(bytes32 id, bytes4 fn, AgentPolicy.TokenCap memory usdcCap) internal {
        (address[] memory payeeTargets, bytes4[] memory payeeSelectors) = _payeeTargets();
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        for (uint256 i; i < 2; i++) {
            (targets[i], selectors[i]) = (payeeTargets[i], payeeSelectors[i]);
        }
        (targets[2], selectors[2]) = (address(token), fn);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = usdcCap;
        policy.onInstall(abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0))));
    }

    function test_token_otherFunctionsOfACappedTokenAreRefusedAtInstall() public {
        usdc = new MockUSDC();
        bytes4[2] memory careless = [MockToken.mint.selector, bytes4(0)];
        for (uint256 k; k < careless.length; k++) {
            (address[] memory targets, bytes4[] memory selectors) = _payeeTargets();
            (targets[3], selectors[3]) = (address(token), careless[k]);
            AgentPolicy.TokenCap[] memory caps = _payeeCaps();
            bytes32 id = bytes32((uint256(0x30) + k) << 224);
            // capped, with a payee list on it
            AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
            lists[0] = _list(address(token), PAYEE, address(0));
            bytes memory data =
                abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0), lists));
            vm.expectRevert(AgentPolicy.InvalidConfig.selector);
            policy.onInstall(data);
            // capped, the list on the other token
            lists[0] = _list(address(usdc), PAYEE, address(0));
            data = abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0), lists));
            vm.expectRevert(AgentPolicy.InvalidConfig.selector);
            policy.onInstall(data);
            // capped, no lists at all
            data = abi.encodePacked(id, abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0)));
            vm.expectRevert(AgentPolicy.InvalidConfig.selector);
            policy.onInstall(data);
            // no limit for that token in this mandate: the entry is an ordinary call
            // (the token's metered entries go with its limit, #175)
            _installWithoutTheTokensLimit(id, careless[k], caps[0]);
            assertTrue(policy.isAllowed(address(this), id, address(token), careless[k]));
        }
        // and on an installed mandate nothing but the four functions reaches a capped token
        _withPayees();
        _expectRefused(_payeeOp(address(token), abi.encodeCall(MockToken.mint, (PAYEE, 1))));
        _expectRefused(_payeeOp(address(token), ""));
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
