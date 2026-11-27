// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";

import {IEntryPoint as IAAEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {IHook, IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecMode} from "kernel/src/types/Types.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }
}

/// Phase 3.2: a sponsored account holds no ETH at all; the paymaster's
/// EntryPoint deposit pays. Sponsorship is a separate check from
/// authorization — an unlisted account is refused even with a valid signature.
contract PaymasterTest is Test {
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant PRIV = 0x0000000000000000000000000000000000000000000000000000000000000AA1;

    IEntryPoint internal entryPoint;
    WhitelistPaymaster internal paymaster;
    Counter internal counter;
    address internal acct;

    function setUp() public {
        entryPoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));
        P256Validator validator = new P256Validator();
        counter = new Counter();

        paymaster = new WhitelistPaymaster(IAAEntryPoint(address(entryPoint)), address(this));
        paymaster.deposit{value: 1 ether}();

        (uint256 x, uint256 y) = vm.publicKeyP256(PRIV);
        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(IValidator(address(validator))),
            IHook(address(0)),
            abi.encode(bytes32(x), bytes32(y)),
            hex"",
            new bytes[](0)
        );
        acct = factory.createAccount(initData, bytes32(0));
        assertEq(acct.balance, 0, "the account holds no ETH");
    }

    function _op(bool sponsored) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: acct,
            nonce: entryPoint.getNonce(acct, 0),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                ExecMode.wrap(bytes32(0)),
                ExecLib.encodeSingle(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector))
            ),
            accountGasLimits: bytes32((uint256(300_000) << 128) | uint256(200_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(1 gwei)),
            // v0.7: paymaster ‖ verificationGasLimit(16) ‖ postOpGasLimit(16) ‖ data
            paymasterAndData: sponsored ? abi.encodePacked(address(paymaster), uint128(100_000), uint128(0)) : bytes(""),
            signature: hex""
        });
        (bytes32 r, bytes32 s) = vm.signP256(PRIV, entryPoint.getUserOpHash(op));
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        op.signature = abi.encodePacked(r, s);
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(makeAddr("bundler")));
    }

    function test_sponsoredAccountPaysNothing() public {
        paymaster.setSponsored(acct, 1 ether, 0.1 ether);
        uint256 depositBefore = paymaster.getDeposit();

        _send(_op(true));

        assertEq(counter.count(), 1);
        assertEq(acct.balance, 0, "the account still holds no ETH");
        assertLt(paymaster.getDeposit(), depositBefore, "the sponsor paid");
    }

    function test_unlistedAccountIsRefused() public {
        PackedUserOperation memory op = _op(true);
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 0);
    }

    function test_withoutSponsorAnUnfundedAccountCannotPay() public {
        PackedUserOperation memory op = _op(false);
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 0);
    }

    function test_onlyOwnerSponsors() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert();
        paymaster.setSponsored(acct, 1 ether, 0.1 ether);
    }

    /// Audit F3: each operation is charged its maximum cost — here
    /// (300k + 200k + 100k paymaster verification + 100k pre-verification)
    /// gas at 1 gwei = 0.0007 ETH — against the account's own budget.
    uint256 internal constant MAX_COST = 700_000 gwei;

    function test_perOperationCapHolds() public {
        paymaster.setSponsored(acct, 1 ether, uint128(MAX_COST - 1));
        PackedUserOperation memory op = _op(true);
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 0);
    }

    function test_budgetRunsOut() public {
        paymaster.setSponsored(acct, uint128(MAX_COST + MAX_COST / 2), uint128(MAX_COST));
        _send(_op(true));
        (uint128 remaining,) = paymaster.sponsorships(acct);
        assertEq(remaining, MAX_COST / 2);
        PackedUserOperation memory op = _op(true);
        vm.expectRevert();
        _send(op);
        assertEq(counter.count(), 1);
    }
}
