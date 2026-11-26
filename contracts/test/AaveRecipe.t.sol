// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentPermissionTest} from "./AgentPermission.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, PermissionId, ValidationId, CallType} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

interface IERC20ForRecipe {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// Aave V3's pool as the recipe uses it, and the forms the recipe leaves out.
interface IAavePoolForRecipe {
    // the L2 pool's compact forms: the pool passes its own caller as `onBehalfOf` and `to`
    function supply(bytes32 args) external;
    function withdraw(bytes32 args) external returns (uint256);
    function borrow(bytes32 args) external;
    // the forms with a beneficiary argument
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

/// Aave V3 with the mandate as it is (issue #80): an agent supplies to the
/// pool and withdraws from it under an allow-list and a token limit, with
/// no rule on the calls' arguments. It works where the pool has the compact
/// forms `supply(bytes32)` and `withdraw(bytes32)` (Base, Arbitrum, Base
/// Sepolia): they take no beneficiary, the pool uses its own caller. The
/// forms with `onBehalfOf` and `to` are not on the allow-list, and stay off
/// until a rule can pin those words to the account.
///
/// Run against the pool itself, on a fork of Base Sepolia:
///
///   FORK_BASE_SEPOLIA_RPC_URL=<an RPC of Base Sepolia> \
///     forge test --evm-version osaka --match-contract AaveRecipeTest
///
/// Without the variable the tests are skipped: CI has no RPC.
contract AaveRecipeTest is AgentPermissionTest {
    /// Aave V3's pool on Base Sepolia (an `L2Pool`), from Aave's address book.
    address internal constant POOL = 0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27;
    /// The pool's test USDC, the first of its reserves.
    address internal constant USDC = 0xba50Cd2A20f6DA35D788639E581bca8d0B5d4D5f;
    PermissionId internal constant AAVE_ID = PermissionId.wrap(0x61617665); // "aave"
    bytes32 internal constant AAVE = bytes32(PermissionId.unwrap(AAVE_ID));
    uint128 internal constant CAP = 100e6;
    uint128 internal constant USDC_BUDGET = 300e6;

    bytes4 internal constant SUPPLY = bytes4(keccak256("supply(bytes32)"));
    bytes4 internal constant WITHDRAW = bytes4(keccak256("withdraw(bytes32)"));

    IERC20ForRecipe internal poolUsdc = IERC20ForRecipe(USDC);
    IERC20ForRecipe internal aUsdc;
    uint256 internal reserveId;

    /// The fork, the account on it, the mandate; false (and the test skipped) without an RPC.
    function _onBaseSepolia() internal returns (bool) {
        string memory rpc = vm.envOr("FORK_BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return false;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 84532, "not Base Sepolia");
        // the EntryPoint, the account and the policy of this build, on the fork
        setUp();
        // the reserve's id and its aToken, as the pool has them: words 7 and 8 of `getReserveData`
        (bool ok, bytes memory data) = POOL.staticcall(abi.encodeWithSignature("getReserveData(address)", USDC));
        require(ok && data.length >= 15 * 32, "the pool does not answer getReserveData");
        uint256[15] memory words = abi.decode(data, (uint256[15]));
        reserveId = words[7];
        aUsdc = IERC20ForRecipe(address(uint160(words[8])));
        // the compact forms exist here
        assertGt(address(aUsdc).code.length, 0, "no aToken");
        _installMandate();
        deal(USDC, acct, 1_000e6);
        return true;
    }

    /// The owner's mandate for the agent: approve USDC within a cap and a
    /// budget, and the pool's two compact calls. Nothing else of the pool.
    function _installMandate() internal {
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (USDC, IERC20ForRecipe.approve.selector);
        (targets[1], selectors[1]) = (POOL, SUPPLY);
        (targets[2], selectors[2]) = (POOL, WITHDRAW);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(USDC, CAP, USDC_BUDGET, bytes32(0));
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, caps);
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(AAVE_ID);
        Execution[] memory install = new Execution[](2);
        install[0] = Execution(acct, 0, _installCall(vId, Kernel(payable(acct)).currentNonce(), abi.encode(entries)));
        install[1] = Execution(acct, 0, abi.encodeCall(Kernel.grantAccess, (vId, Kernel.execute.selector, true)));
        _send(
            _rootOp(
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))),
                    ExecLib.encodeBatch(install)
                )
            )
        );
    }

    /// Aave's compact arguments (`CalldataLogic`): the reserve's id in the
    /// low 16 bits, the amount in the next 128, a referral code above them.
    function _args(uint256 amount) internal view returns (bytes32) {
        return bytes32(reserveId | (amount << 16));
    }

    /// The agent's supply: the allowance, the supply, the allowance taken
    /// back. The policy accepts an approval only with its withdrawal in the
    /// same operation.
    function _supply(uint256 amount) internal view returns (Execution[] memory calls) {
        calls = new Execution[](3);
        calls[0] = Execution(USDC, 0, abi.encodeCall(IERC20ForRecipe.approve, (POOL, amount)));
        calls[1] = Execution(POOL, 0, abi.encodeWithSelector(SUPPLY, _args(amount)));
        calls[2] = Execution(USDC, 0, abi.encodeCall(IERC20ForRecipe.approve, (POOL, 0)));
    }

    function _spentOnUsdc() internal view returns (uint256) {
        return policy.tokenLimit(acct, AAVE, USDC).spent;
    }

    function test_aave_theAgentSuppliesAndWithdraws() public {
        if (!_onBaseSepolia()) return;
        // 100 USDC into the pool: the aTokens are the account's, the allowance is gone, the budget is charged
        _send(_agentBatchWith(AGENT, AAVE_ID, _supply(100e6)));
        assertEq(poolUsdc.balanceOf(acct), 900e6);
        assertApproxEqAbs(aUsdc.balanceOf(acct), 100e6, 2, "the aTokens are the account's");
        assertEq(poolUsdc.allowance(acct, POOL), 0, "no allowance stands");
        assertEq(_spentOnUsdc(), 100e6, "charged when approved");

        // 40 back, by one call: no allowance is involved, and nothing is charged
        _send(_agentOpWith(AGENT, AAVE_ID, POOL, 0, abi.encodeWithSelector(WITHDRAW, _args(40e6))));
        assertEq(poolUsdc.balanceOf(acct), 940e6);
        assertApproxEqAbs(aUsdc.balanceOf(acct), 60e6, 2);
        assertEq(_spentOnUsdc(), 100e6);

        // everything back: the pool reads the widest amount as "all"
        _send(_agentOpWith(AGENT, AAVE_ID, POOL, 0, abi.encodeWithSelector(WITHDRAW, _args(type(uint128).max))));
        assertGe(poolUsdc.balanceOf(acct), 1_000e6 - 2, "the account has its USDC again");
        assertEq(aUsdc.balanceOf(acct), 0);
    }

    /// The token's cap and budget bound what the agent can put into the
    /// pool. A supply is charged when it is approved and a withdrawal gives
    /// nothing back: the budget is what the agent may move, not what it may
    /// hold in the pool.
    function test_aave_theTokenLimitBoundsWhatGoesIn() public {
        if (!_onBaseSepolia()) return;
        // over the cap per operation
        _expectRefused(_agentBatchWith(AGENT, AAVE_ID, _supply(100e6 + 1)));
        // three supplies reach the budget, each withdrawn again
        for (uint256 i; i < 3; i++) {
            _send(_agentBatchWith(AGENT, AAVE_ID, _supply(100e6)));
            _send(_agentOpWith(AGENT, AAVE_ID, POOL, 0, abi.encodeWithSelector(WITHDRAW, _args(type(uint128).max))));
        }
        assertEq(_spentOnUsdc(), 300e6);
        assertGe(poolUsdc.balanceOf(acct), 1_000e6 - 6);
        // the fourth is over the budget, although the account holds the money
        _expectRefused(_agentBatchWith(AGENT, AAVE_ID, _supply(1e6)));
        assertEq(aUsdc.balanceOf(acct), 0);
    }

    /// What the recipe leaves off the allow-list stays out of reach.
    function test_aave_whatIsNotListedIsRefused() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("somebody else");
        // an allowance left standing: the supply without the closing leg
        Execution[] memory open = new Execution[](2);
        Execution[] memory whole = _supply(100e6);
        (open[0], open[1]) = (whole[0], whole[1]);
        _expectRefused(_agentBatchWith(AGENT, AAVE_ID, open));
        // an allowance to anyone but through the listed calls is still an allowance within the cap;
        // what must not pass is the supply for somebody else: the form with `onBehalfOf`
        Execution[] memory forOther = _supply(100e6);
        forOther[1] = Execution(
            POOL, 0, abi.encodeWithSignature("supply(address,uint256,address,uint16)", USDC, 100e6, other, 0)
        );
        _expectRefused(_agentBatchWith(AGENT, AAVE_ID, forOther));
        // with the account itself as beneficiary it is the same function, and as little on the list
        forOther[1] =
            Execution(POOL, 0, abi.encodeWithSignature("supply(address,uint256,address,uint16)", USDC, 100e6, acct, 0));
        _expectRefused(_agentBatchWith(AGENT, AAVE_ID, forOther));

        _send(_agentBatchWith(AGENT, AAVE_ID, _supply(100e6)));
        // the withdrawal to somebody else: the form with `to`
        _expectRefused(
            _agentOpWith(
                AGENT, AAVE_ID, POOL, 0, abi.encodeWithSignature("withdraw(address,uint256,address)", USDC, 50e6, other)
            )
        );
        // a borrow against what was supplied, compact form or not
        _expectRefused(
            _agentOpWith(
                AGENT,
                AAVE_ID,
                POOL,
                0,
                abi.encodeWithSelector(
                    IAavePoolForRecipe.borrow.selector, bytes32(reserveId | (1e6 << 16) | (2 << 144))
                )
            )
        );
        // the aToken is not the agent's to move: it is on no list
        _expectRefused(
            _agentOpWith(
                AGENT, AAVE_ID, address(aUsdc), 0, abi.encodeWithSignature("transfer(address,uint256)", other, 10e6)
            )
        );
        assertApproxEqAbs(aUsdc.balanceOf(acct), 100e6, 2);
        assertEq(aUsdc.balanceOf(other), 0);
        assertEq(poolUsdc.balanceOf(other), 0);
    }

    /// The compact forms use their caller: called by somebody else for the
    /// account's benefit, they act for that caller. So there is no argument
    /// in them for an agent to point elsewhere.
    function test_aave_theCompactFormsActOnTheirCaller() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("somebody else");
        deal(USDC, other, 10e6);
        vm.startPrank(other);
        poolUsdc.approve(POOL, 10e6);
        IAavePoolForRecipe(POOL).supply(_args(10e6));
        vm.stopPrank();
        assertApproxEqAbs(aUsdc.balanceOf(other), 10e6, 2, "the caller is credited");
        assertEq(aUsdc.balanceOf(acct), 0);
        // and a withdrawal by a caller that supplied nothing takes nothing of anybody's
        _send(_agentBatchWith(AGENT, AAVE_ID, _supply(100e6)));
        vm.prank(makeAddr("a third"));
        vm.expectRevert();
        IAavePoolForRecipe(POOL).withdraw(_args(1e6));
        assertApproxEqAbs(aUsdc.balanceOf(acct), 100e6, 2);
    }
}
