// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test, console} from "forge-std/Test.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {Logger} from "../src/demo/Logger.sol";

import {IEntryPoint as IAAEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";
import {ValidationManager} from "kernel/src/core/ValidationManager.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {IHook, IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecMode, PermissionId, ValidationId} from "kernel/src/types/Types.sol";
import {
    VALIDATION_MODE_DEFAULT, VALIDATION_TYPE_PERMISSION, ValidationMode, ValidationType
} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

/// Reproduces the reference paper's measurement — one logging event, payload
/// sizes from 10 bytes to 100 kB, local execution gas — for its three
/// EOA-submitted methods and for this project's agent path: a real EntryPoint
/// v0.7, Kernel v3.3, P256Signer + AgentPolicy as the agent permission, and
/// the whitelist paymaster. The paper's fourth bar was secp256k1 AA against a
/// mock EntryPoint; ours is P-256 against the real one.
///
/// Numbers are the gas consumed by the call as seen from the test contract
/// (execution only). `intrinsic` adds the 21,000 base and calldata cost of
/// the outer transaction so the two can be summed into a transaction total.
///
///   forge test --match-contract GasBenchmark -vv
///
/// Writes benchmarks/gas.json.
contract GasBenchmarkTest is Test {
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant K1_PRIV = 0xBEEF;
    uint256 internal constant R1_PRIV = 0x0000000000000000000000000000000000000000000000000000000000000AA1;
    uint256 internal constant OWNER = 0x0000000000000000000000000000000000000000000000000000000000000AA2;
    uint256 internal constant AGENT = 0x0000000000000000000000000000000000000000000000000000000000000BB2;
    PermissionId internal constant AGENT_ID = PermissionId.wrap(0x61676e74);

    uint256[] internal sizes = [10, 100, 1_000, 10_000, 100_000];

    address internal eoa = makeAddr("eoa");
    address internal k1Signer;
    bytes32 internal r1X;
    bytes32 internal r1Y;

    Logger internal logger;
    IEntryPoint internal entryPoint;
    WhitelistPaymaster internal paymaster;
    address internal acct;

    function setUp() public {
        k1Signer = vm.addr(K1_PRIV);
        (uint256 x, uint256 y) = vm.publicKeyP256(R1_PRIV);
        (r1X, r1Y) = (bytes32(x), bytes32(y));
        logger = new Logger(eoa, k1Signer, r1X, r1Y);

        // --- the agent account, as in production ---
        entryPoint = IEntryPoint(EntryPointLib.deploy());
        paymaster = new WhitelistPaymaster(IAAEntryPoint(address(entryPoint)), address(this));
        paymaster.deposit{value: 10 ether}();
        acct = _deployAgentAccount();
        paymaster.setSponsored(acct, 1 ether, 0.1 ether);

        // warm up every path once, as the paper does, so storage-slot and
        // nonce initialization costs do not land on the first measurement
        _addressOnly(10);
        _k1(10);
        _r1(10);
        _agent(10);
    }

    function _deployAgentAccount() internal returns (address) {
        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));
        P256Validator rootValidator = new P256Validator();
        (uint256 ox, uint256 oy) = vm.publicKeyP256(OWNER);
        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(IValidator(address(rootValidator))),
            IHook(address(0)),
            abi.encode(bytes32(ox), bytes32(oy)),
            hex"",
            _initConfig(_permissionData())
        );
        return factory.createAccount(initData, bytes32(0));
    }

    /// The agent's mandate: `Logger.log` only, no value.
    function _permissionData() internal returns (bytes memory) {
        P256Signer signer = new P256Signer();
        AgentPolicy policy = new AgentPolicy(address(new SafeNonceAssert()));
        (uint256 ax, uint256 ay) = vm.publicKeyP256(AGENT);
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        targets[0] = address(logger);
        selectors[0] = Logger.log.selector;
        bytes[] memory entries = new bytes[](2);
        entries[0] = abi.encodePacked(
            bytes2(0),
            address(policy),
            abi.encode(
                targets, selectors, uint128(0), uint128(0), uint48(block.timestamp + 365 days), new AgentPolicy.TokenCap[](0), uint48(0)
            )
        );
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(bytes32(ax), bytes32(ay)));
        return abi.encode(entries);
    }

    function _initConfig(bytes memory permissionData) internal pure returns (bytes[] memory initConfig) {
        ValidationId permVId = ValidatorLib.permissionToIdentifier(AGENT_ID);
        ValidationId[] memory vIds = new ValidationId[](1);
        vIds[0] = permVId;
        ValidationManager.ValidationConfig[] memory cfgs = new ValidationManager.ValidationConfig[](1);
        cfgs[0] = ValidationManager.ValidationConfig({nonce: 1, hook: IHook(address(1))});
        bytes[] memory vData = new bytes[](1);
        vData[0] = permissionData;
        bytes[] memory hData = new bytes[](1);
        initConfig = new bytes[](2);
        initConfig[0] = abi.encodeCall(Kernel.installValidations, (vIds, cfgs, vData, hData));
        initConfig[1] = abi.encodeCall(Kernel.grantAccess, (permVId, Kernel.execute.selector, true));
    }

    // --- the four methods ---

    function _payload(uint256 size) internal pure returns (bytes memory p) {
        p = new bytes(size);
        for (uint256 i; i < size; i++) {
            p[i] = bytes1(uint8(0x41 + (i % 26)));
        }
    }

    function _addressOnly(uint256 size) internal returns (uint256 gas) {
        bytes memory payload = _payload(size);
        vm.prank(eoa);
        uint256 before = gasleft();
        logger.logAddressOnly(payload);
        gas = before - gasleft();
    }

    function _k1(uint256 size) internal returns (uint256 gas) {
        bytes memory payload = _payload(size);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(K1_PRIV, keccak256(payload));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.prank(eoa);
        uint256 before = gasleft();
        logger.logK1(payload, sig);
        gas = before - gasleft();
    }

    function _r1(uint256 size) internal returns (uint256 gas) {
        bytes memory payload = _payload(size);
        (bytes32 r, bytes32 s) = vm.signP256(R1_PRIV, keccak256(payload));
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        vm.prank(eoa);
        uint256 before = gasleft();
        logger.logR1(payload, r, s);
        gas = before - gasleft();
    }

    /// The agent path: permission-validated UserOperation, paymaster-sponsored,
    /// submitted through handleOps. Measured as the whole handleOps call,
    /// which is what a self-bundling agent pays for.
    function _agent(uint256 size) internal returns (uint256 gas) {
        bytes memory payload = _payload(size);
        uint192 key = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(PermissionId.unwrap(AGENT_ID)),
            0
        );
        PackedUserOperation memory op = PackedUserOperation({
            sender: acct,
            nonce: entryPoint.getNonce(acct, key),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                ExecMode.wrap(bytes32(0)),
                ExecLib.encodeSingle(address(logger), 0, abi.encodeCall(Logger.log, (payload)))
            ),
            accountGasLimits: bytes32((uint256(300_000) << 128) | uint256(3_000_000)),
            preVerificationGas: 0,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            paymasterAndData: abi.encodePacked(address(paymaster), uint128(100_000), uint128(0)),
            signature: hex""
        });
        (bytes32 r, bytes32 s) = vm.signP256(AGENT, entryPoint.getUserOpHash(op));
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        op.signature = abi.encodePacked(bytes1(0xff), r, s);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 before = gasleft();
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        gas = before - gasleft();
    }

    /// 21,000 base plus post-Pectra calldata pricing (EIP-7623: 10 gas per
    /// token, a zero byte is 1 token and a non-zero byte 4; the standard
    /// execution-plus-calldata price is 4/16 per byte) — reported so the
    /// execution numbers can be turned into transaction totals.
    function _intrinsic(uint256 calldataBytes, bool nonZero) internal pure returns (uint256) {
        return 21_000 + calldataBytes * (nonZero ? 16 : 4);
    }

    // --- the benchmark ---

    function test_benchmark() public {
        // Access lists reset per transaction, and setUp ran in a different one:
        // warm every path again here so no row pays cold-access costs that the
        // others don't (the paper warms up before recording, too).
        _addressOnly(10);
        _k1(10);
        _r1(10);
        _agent(10);

        string memory root = "benchmark";
        string memory out;
        console.log("payload  address-only  k1-signature  p256-signature  p256-AA+paymaster");
        for (uint256 i; i < sizes.length; i++) {
            uint256 size = sizes[i];
            uint256 a = _addressOnly(size);
            uint256 k = _k1(size);
            uint256 r = _r1(size);
            uint256 g = _agent(size);
            console.log("%d  %d  %d", size, a, k);
            console.log("        %d  %d", r, g);

            string memory row = vm.toString(size);
            vm.serializeUint(row, "payloadBytes", size);
            vm.serializeUint(row, "addressOnly", a);
            vm.serializeUint(row, "k1Signature", k);
            vm.serializeUint(row, "p256Signature", r);
            vm.serializeUint(row, "p256AgentAccountPaymaster", g);
            string memory rowJson = vm.serializeUint(row, "intrinsicCalldataEstimate", _intrinsic(size + 100, true));
            out = vm.serializeString(root, vm.toString(size), rowJson);
        }
        vm.writeJson(out, "benchmarks/gas.json");
    }
}
