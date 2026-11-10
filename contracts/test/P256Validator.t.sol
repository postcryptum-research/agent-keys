// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {P256Validator} from "../src/P256Validator.sol";

import {Kernel} from "kernel/src/Kernel.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {IHook, IModule, IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecMode, ValidationId} from "kernel/src/types/Types.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }
}

/// Phase 1: a raw P-256 key owns an ERC-7579 account.
///  - unit: the validator against a cheatcode key (`vm.signP256`)
///  - hardware: the committed TPM-signed vector passes the validator
///  - e2e: EntryPoint → Kernel v3 → P256Validator → execute(), signed by P-256
contract P256ValidatorTest is Test {
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant PRIV = 0xA11CE000000000000000000000000000000000000000000000000000000000AA;
    uint256 internal constant OTHER = 0xB0B0000000000000000000000000000000000000000000000000000000000BB;

    P256Validator internal validator;
    address internal account = makeAddr("account");
    bytes32 internal pkX;
    bytes32 internal pkY;

    function setUp() public {
        validator = new P256Validator();
        (uint256 x, uint256 y) = vm.publicKeyP256(PRIV);
        pkX = bytes32(x);
        pkY = bytes32(y);
    }

    // --- helpers ---

    /// Low-s normalized `abi.encodePacked(r, s)`, exactly what `agent-signer` emits.
    function _sign(uint256 priv, bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(priv, digest);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        return abi.encodePacked(r, s);
    }

    function _install(address acct, bytes32 x, bytes32 y) internal {
        vm.prank(acct);
        validator.onInstall(abi.encode(x, y));
    }

    function _validate(address acct, bytes32 hash, bytes memory sig) internal returns (uint256) {
        PackedUserOperation memory op;
        op.sender = acct;
        op.signature = sig;
        vm.prank(acct);
        return validator.validateUserOp(op, hash);
    }

    // --- install ---

    function test_install_storesKey() public {
        _install(account, pkX, pkY);
        (bytes32 x, bytes32 y) = validator.publicKeys(account);
        assertEq(x, pkX);
        assertEq(y, pkY);
        assertTrue(validator.isInitialized(account));
    }

    function test_install_rejectsZeroKey() public {
        vm.prank(account);
        vm.expectRevert(P256Validator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(bytes32(0), pkY));
    }

    function test_install_twiceReverts() public {
        _install(account, pkX, pkY);
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, account));
        validator.onInstall(abi.encode(pkX, pkY));
    }

    function test_uninstall_clearsKey() public {
        _install(account, pkX, pkY);
        vm.prank(account);
        validator.onUninstall("");
        assertFalse(validator.isInitialized(account));
    }

    // --- validateUserOp ---

    function test_validateUserOp_acceptsValidSignature() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("userOp");
        assertEq(_validate(account, h, _sign(PRIV, h)), SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_validateUserOp_rejectsWrongHash() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("userOp");
        assertEq(_validate(account, keccak256("other"), _sign(PRIV, h)), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_rejectsOtherKey() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("userOp");
        assertEq(_validate(account, h, _sign(OTHER, h)), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_rejectsHighS() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("userOp");
        bytes memory sig = _sign(PRIV, h);
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        bytes memory malleated = abi.encodePacked(r, bytes32(N - uint256(s)));
        assertEq(_validate(account, h, malleated), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_rejectsBadLength() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("userOp");
        assertEq(_validate(account, h, abi.encodePacked(h)), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_rejectsUninstalledAccount() public {
        bytes32 h = keccak256("userOp");
        assertEq(_validate(account, h, _sign(PRIV, h)), SIG_VALIDATION_FAILED_UINT);
    }

    // --- ERC-1271 ---

    function test_erc1271_withSender() public {
        _install(account, pkX, pkY);
        bytes32 h = keccak256("message");
        vm.prank(account);
        assertEq(validator.isValidSignatureWithSender(address(0), h, _sign(PRIV, h)), ERC1271_MAGICVALUE);
        vm.prank(account);
        assertEq(validator.isValidSignatureWithSender(address(0), h, _sign(OTHER, h)), ERC1271_INVALID);
    }

    // --- hardware vector ---

    function test_tpmVector_passesValidator() public {
        string memory json = vm.readFile("test/vectors/p256_tpm.json");
        bytes32 digest = vm.parseJsonBytes32(json, ".digest");
        bytes32 r = vm.parseJsonBytes32(json, ".r");
        bytes32 s = vm.parseJsonBytes32(json, ".s");
        _install(account, vm.parseJsonBytes32(json, ".x"), vm.parseJsonBytes32(json, ".y"));

        assertEq(_validate(account, digest, abi.encodePacked(r, s)), SIG_VALIDATION_SUCCESS_UINT);
        assertEq(
            _validate(account, digest ^ bytes32(uint256(1)), abi.encodePacked(r, s)),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    /// A phone's Android Keystore key (TEE) signed the owner-core golden
    /// `userOpHash` with NONEwithECDSA behind a biometric prompt
    /// (mobile/android, P0). The validator accepts it as it would any root key.
    function test_androidVector_passesValidator() public {
        string memory json = vm.readFile("test/vectors/p256_android.json");
        bytes32 digest = vm.parseJsonBytes32(json, ".digest");
        bytes32 r = vm.parseJsonBytes32(json, ".r");
        bytes32 s = vm.parseJsonBytes32(json, ".s");
        _install(account, vm.parseJsonBytes32(json, ".x"), vm.parseJsonBytes32(json, ".y"));

        assertEq(_validate(account, digest, abi.encodePacked(r, s)), SIG_VALIDATION_SUCCESS_UINT);
        assertEq(
            _validate(account, digest ^ bytes32(uint256(1)), abi.encodePacked(r, s)),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    // --- end to end through EntryPoint and Kernel ---

    function test_kernel_executesUserOpSignedByP256() public {
        IEntryPoint entryPoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));

        ValidationId rootValidator = ValidatorLib.validatorToIdentifier(IValidator(address(validator)));
        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidator,
            IHook(address(0)),
            abi.encode(pkX, pkY),
            hex"",
            new bytes[](0)
        );
        address acct = factory.createAccount(initData, bytes32(0));
        assertEq(acct, factory.getAddress(initData, bytes32(0)));
        assertTrue(validator.isInitialized(acct));
        vm.deal(acct, 1 ether);

        Counter counter = new Counter();
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector,
            ExecMode.wrap(bytes32(0)), // single call, default exec type
            ExecLib.encodeSingle(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: acct,
            nonce: entryPoint.getNonce(acct, 0), // key 0 → root validator
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | uint256(1_000_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        op.signature = _sign(PRIV, userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));

        assertEq(counter.count(), 1, "account executed the call");
    }

    function test_kernel_rejectsUserOpSignedByOtherKey() public {
        IEntryPoint entryPoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));

        ValidationId rootValidator = ValidatorLib.validatorToIdentifier(IValidator(address(validator)));
        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector, rootValidator, IHook(address(0)), abi.encode(pkX, pkY), hex"", new bytes[](0)
        );
        address acct = factory.createAccount(initData, bytes32(0));
        vm.deal(acct, 1 ether);

        Counter counter = new Counter();
        PackedUserOperation memory op = PackedUserOperation({
            sender: acct,
            nonce: entryPoint.getNonce(acct, 0),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                ExecMode.wrap(bytes32(0)),
                ExecLib.encodeSingle(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
            ),
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | uint256(1_000_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature = _sign(OTHER, entryPoint.getUserOpHash(op));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        // EntryPoint reports AA24 for a validator that returned SIG_VALIDATION_FAILED.
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
        assertEq(counter.count(), 0);
    }
}
