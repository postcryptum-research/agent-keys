// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AgentPermissionTest} from "./AgentPermission.t.sol";
import {TradingTest} from "./Trading.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {ExecMode, PermissionId, ValidationId, CallType} from "kernel/src/types/Types.sol";
import {CALLTYPE_BATCH} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";

/// What the recipes need of a token.
interface ITokenForRecipes {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// Recipes of `docs/DAPPS.md`, each run against the protocol's own code on a
/// fork (issue #80). A recipe is what an owner puts on a mandate so that an
/// agent can use a protocol and nothing else of it. Each test contract says
/// which chain it forks; without that chain's RPC in the environment its
/// tests are skipped, so CI, which has no RPC, runs none of them.
///
///   FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> \
///     forge test --evm-version osaka --match-path test/ProtocolRecipes.t.sol --match-test 'test_recipe|test_real'

// ---------------------------------------------------------------------------
// With the mandate as it is: an allow-list and limits, no rule on arguments
// ---------------------------------------------------------------------------

/// A recipe that needs only the allow-list: functions whose effects land on
/// their caller, whatever their arguments.
abstract contract AllowListRecipe is AgentPermissionTest {
    function _fork(string memory variable, uint256 chainId) internal returns (bool) {
        string memory rpc = vm.envOr(variable, string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return false;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, chainId, "not the chain this recipe is for");
        // the EntryPoint, the account and the policy of this build, on the fork
        setUp();
        return true;
    }

    function _installAllowList(
        PermissionId id,
        address[] memory targets,
        bytes4[] memory selectors,
        AgentPolicy.TokenCap[] memory caps
    ) internal {
        bytes[] memory entries = new bytes[](2);
        entries[0] = _policyEntry(targets, selectors, caps);
        entries[1] = abi.encodePacked(bytes2(0), address(signer), abi.encode(agentX, agentY));
        ValidationId vId = ValidatorLib.permissionToIdentifier(id);
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
}

/// Compound v3 (Comet) on Base Sepolia: `supply(asset, amount)` and
/// `withdraw(asset, amount)` act on their caller. The supply pulls through
/// an allowance, which the agent gives and takes back in the same operation.
contract CompoundRecipeTest is AllowListRecipe {
    /// The USDC market (cUSDCv3) on Base Sepolia; its base token is Circle's test USDC.
    address internal constant COMET = 0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017;
    ITokenForRecipes internal constant USDC = ITokenForRecipes(0x036CbD53842c5426634e7929541eC2318f3dCF7e);
    PermissionId internal constant ID = PermissionId.wrap(0x636f6d70); // "comp"
    bytes4 internal constant SUPPLY = 0xf2b9fdb8; // supply(address,uint256)
    bytes4 internal constant WITHDRAW = 0xf3fef3a3; // withdraw(address,uint256)

    function _onBaseSepolia() internal returns (bool) {
        if (!_fork("FORK_BASE_SEPOLIA_RPC_URL", 84532)) return false;
        (bool ok, bytes memory data) = COMET.staticcall(abi.encodeWithSignature("baseToken()"));
        require(ok && abi.decode(data, (address)) == address(USDC), "not the USDC market");
        address[] memory targets = new address[](3);
        bytes4[] memory selectors = new bytes4[](3);
        (targets[0], selectors[0]) = (address(USDC), ITokenForRecipes.approve.selector);
        (targets[1], selectors[1]) = (COMET, SUPPLY);
        (targets[2], selectors[2]) = (COMET, WITHDRAW);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(USDC), 100e6, 300e6, bytes32(0));
        _installAllowList(ID, targets, selectors, caps);
        deal(address(USDC), acct, 1_000e6);
        return true;
    }

    function _supplied(address who) internal view returns (uint256) {
        return ITokenForRecipes(COMET).balanceOf(who);
    }

    /// The allowance, the supply, the allowance taken back.
    function _supply(uint256 amount) internal pure returns (Execution[] memory calls) {
        calls = new Execution[](3);
        calls[0] = Execution(address(USDC), 0, abi.encodeCall(ITokenForRecipes.approve, (COMET, amount)));
        calls[1] = Execution(COMET, 0, abi.encodeWithSelector(SUPPLY, address(USDC), amount));
        calls[2] = Execution(address(USDC), 0, abi.encodeCall(ITokenForRecipes.approve, (COMET, 0)));
    }

    function test_recipe_compound_theAgentSuppliesAndWithdraws() public {
        if (!_onBaseSepolia()) return;
        _send(_agentBatchWith(AGENT, ID, _supply(100e6)));
        assertEq(USDC.balanceOf(acct), 900e6);
        assertApproxEqAbs(_supplied(acct), 100e6, 2, "the supply is the account's");
        assertEq(USDC.allowance(acct, COMET), 0, "no allowance stands");
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(ID)), address(USDC)).spent, 100e6);
        // 40 back, by one call: nothing is charged
        _send(_agentOpWith(AGENT, ID, COMET, 0, abi.encodeWithSelector(WITHDRAW, address(USDC), 40e6)));
        assertEq(USDC.balanceOf(acct), 940e6);
        assertEq(policy.tokenLimit(acct, bytes32(PermissionId.unwrap(ID)), address(USDC)).spent, 100e6);
    }

    function test_recipe_compound_whatIsNotListedIsRefused() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("other");
        // the forms that name another account
        bytes memory supplyTo = abi.encodeWithSignature("supplyTo(address,address,uint256)", other, address(USDC), 10e6);
        Execution[] memory calls = _supply(10e6);
        calls[1] = Execution(COMET, 0, supplyTo);
        _expectRefused(_agentBatchWith(AGENT, ID, calls));
        _expectRefused(
            _agentOpWith(
                AGENT,
                ID,
                COMET,
                0,
                abi.encodeWithSignature("withdrawTo(address,address,uint256)", other, address(USDC), 1)
            )
        );
        // letting a manager act for the account
        _expectRefused(_agentOpWith(AGENT, ID, COMET, 0, abi.encodeWithSignature("allow(address,bool)", other, true)));
        // over the cap for one operation; and without the closing approval
        _expectRefused(_agentBatchWith(AGENT, ID, _supply(100e6 + 1)));
        calls = _supply(10e6);
        Execution[] memory open = new Execution[](2);
        (open[0], open[1]) = (calls[0], calls[1]);
        _expectRefused(_agentBatchWith(AGENT, ID, open));
        assertEq(_supplied(other), 0);
        assertEq(USDC.balanceOf(acct), 1_000e6);
    }

    /// Why a word of care: a withdrawal of more than was supplied is a borrow.
    /// Without collateral in the market it reverts; with collateral it would not.
    function test_real_compound_aWithdrawalBeyondTheSupplyIsABorrow() public {
        if (!_onBaseSepolia()) return;
        _send(_agentBatchWith(AGENT, ID, _supply(100e6)));
        uint256 before = USDC.balanceOf(acct);
        vm.prank(acct);
        (bool ok,) = COMET.call(abi.encodeWithSelector(WITHDRAW, address(USDC), 500e6));
        assertFalse(ok, "no collateral: the market refuses the borrow");
        assertEq(USDC.balanceOf(acct), before);
    }

    /// Why the two functions can be listed as they are: they act on their caller.
    function test_real_compound_theFunctionsActOnTheirCaller() public {
        if (!_onBaseSepolia()) return;
        address stranger = makeAddr("stranger");
        deal(address(USDC), stranger, 50e6);
        vm.startPrank(stranger);
        USDC.approve(COMET, 50e6);
        (bool ok,) = COMET.call(abi.encodeWithSelector(SUPPLY, address(USDC), 50e6));
        vm.stopPrank();
        assertTrue(ok);
        assertApproxEqAbs(_supplied(stranger), 50e6, 2, "credited to the caller");
        assertEq(_supplied(acct), 0);
    }
}

/// Lido on Ethereum: `submit(referral)` stakes the value sent and mints
/// stETH to the caller. The referral is an address the agent may choose: it
/// receives nothing. The native cap per operation and the native budget hold
/// what goes in.
contract LidoRecipeTest is AllowListRecipe {
    ITokenForRecipes internal constant STETH = ITokenForRecipes(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    PermissionId internal constant ID = PermissionId.wrap(0x6c69646f); // "lido"
    bytes4 internal constant SUBMIT = 0xa1903eab; // submit(address)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        address[] memory targets = new address[](1);
        bytes4[] memory selectors = new bytes4[](1);
        (targets[0], selectors[0]) = (address(STETH), SUBMIT);
        _installAllowList(ID, targets, selectors, new AgentPolicy.TokenCap[](0));
        vm.deal(acct, 1 ether);
        return true;
    }

    function test_recipe_lido_theAgentStakesWithinTheNativeLimits() public {
        if (!_onEthereum()) return;
        address referral = makeAddr("referral");
        _send(_agentOpWith(AGENT, ID, address(STETH), MAX_VALUE, abi.encodeWithSelector(SUBMIT, referral)));
        // stETH is the account's (a share rounding of a wei or two); the referral gets nothing
        assertApproxEqAbs(STETH.balanceOf(acct), MAX_VALUE, 2, "the stETH is the account's");
        assertEq(STETH.balanceOf(referral), 0, "a referral receives nothing");
        // over the cap for one operation
        _expectRefused(_agentOpWith(AGENT, ID, address(STETH), MAX_VALUE + 1, abi.encodeWithSelector(SUBMIT, referral)));
        // what is not listed: sending the stETH away, approving it
        _expectRefused(
            _agentOpWith(
                AGENT, ID, address(STETH), 0, abi.encodeWithSignature("transfer(address,uint256)", referral, 1)
            )
        );
        _expectRefused(
            _agentOpWith(AGENT, ID, address(STETH), 0, abi.encodeWithSignature("approve(address,uint256)", referral, 1))
        );
    }
}

// ---------------------------------------------------------------------------
// With a rule for each argument (`CallRulesDecoder`)
// ---------------------------------------------------------------------------

/// A recipe that needs rules on arguments: a venue of rules for one contract,
/// under a mandate with a cap on the token it takes. The owner approves the
/// venue for that token, as for any venue.
abstract contract RulesRecipe is TradingTest {
    CallRulesDecoder internal rules;
    address internal venue_;
    address internal capped;
    bytes internal config_;

    function _fork(string memory variable, uint256 chainId) internal returns (bool) {
        string memory rpc = vm.envOr(variable, string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return false;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, chainId, "not the chain this recipe is for");
        setUp();
        _world();
        return true;
    }

    function _word(uint8 kind, uint256 value) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(kind, value);
    }

    /// The mandate: `token` within `cap` an operation and `budget` in all, and `venue` with `functions`.
    function _installRules(
        address venue,
        CallRulesDecoder.Function[] memory functions,
        address token,
        uint128 cap,
        uint128 budget
    ) internal {
        (venue_, capped) = (venue, token);
        rules = new CallRulesDecoder(venue, venue);
        config_ = abi.encode(CallRulesDecoder.Config(functions));
        assertTrue(rules.checkConfig(config_), "the decoder's own check of the rules");
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(token, cap, budget, bytes32(0));
        AgentPolicy.Venue[] memory v = new AgentPolicy.Venue[](1);
        v[0] = AgentPolicy.Venue(address(rules), address(rules).codehash, keccak256(config_));
        (address[] memory targets, bytes4[] memory selectors) = _targets();
        _install(
            TRD_ID,
            abi.encode(
                targets,
                selectors,
                MAX_VALUE,
                BUDGET,
                tradingExpiry,
                caps,
                uint48(0),
                new AgentPolicy.TokenPayees[](0),
                DAY,
                v
            )
        );
        // the owner's allowance to the venue, bounded by the budget
        vm.prank(acct);
        ITokenForRecipes(token).approve(venue, budget);
    }

    /// A call's registration and the call, as one operation of the agent's.
    function _call(bytes memory data) internal view returns (PackedUserOperation memory op) {
        Execution[] memory legs = new Execution[](2);
        legs[0] =
            Execution(address(policy), 0, abi.encodeCall(AgentPolicy.orderRegister, (address(rules), config_, data)));
        legs[1] = Execution(venue_, 0, data);
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector, ExecMode.wrap(bytes32(CallType.unwrap(CALLTYPE_BATCH))), ExecLib.encodeBatch(legs)
        );
        op = _op(_permissionNonce(TRD_ID), callData);
        op.signature = abi.encodePacked(
            bytes1(0), bytes8(uint64(6)), bytes6(_today()), bytes1(0xff), _sign(AGENT, entryPoint.getUserOpHash(op))
        );
    }

    function _spent() internal view returns (uint256) {
        return policy.tokenLimit(acct, TRD, capped).spent;
    }
}

/// Circle's CCTP (V2) on Base Sepolia: `depositForBurn` burns USDC here for
/// a recipient on another chain. The rules hold the destination chain, the
/// recipient (the account's own address there), the token, the caller on the
/// other side (anyone), the fee and the finality the owner chose; the amount
/// is charged.
contract CctpRecipeTest is RulesRecipe {
    address internal constant MESSENGER = 0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA;
    ITokenForRecipes internal constant USDC = ITokenForRecipes(0x036CbD53842c5426634e7929541eC2318f3dCF7e);
    /// depositForBurn(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address burnToken,
    /// bytes32 destinationCaller, uint256 maxFee, uint32 minFinalityThreshold)
    bytes4 internal constant DEPOSIT_FOR_BURN = 0x8e0250ee;
    /// CCTP's domain of Ethereum (Sepolia on the test networks).
    uint256 internal constant ETHEREUM = 0;
    /// "Standard" finality: no fee is asked for it.
    uint256 internal constant FINALIZED = 2000;

    function _onBaseSepolia() internal returns (bool) {
        if (!_fork("FORK_BASE_SEPOLIA_RPC_URL", 84532)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](1);
        fs[0].selector = DEPOSIT_FOR_BURN;
        fs[0].words = new CallRulesDecoder.Word[](7);
        fs[0].words[0] = _word(3, uint256(uint160(address(USDC)))); // the amount, charged in USDC
        fs[0].words[1] = _word(1, ETHEREUM); // to this chain only
        fs[0].words[2] = _word(0, 0); // for the account's own address there
        fs[0].words[3] = _word(1, uint256(uint160(address(USDC)))); // this token
        fs[0].words[4] = _word(1, 0); // anyone may deliver it there
        fs[0].words[5] = _word(2, 0); // no fee
        fs[0].words[6] = _word(1, FINALIZED);
        _installRules(MESSENGER, fs, address(USDC), 100e6, 300e6);
        deal(address(USDC), acct, 1_000e6);
        return true;
    }

    function _burn(uint256 amount, uint256 domain, bytes32 recipient, uint256 maxFee)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            DEPOSIT_FOR_BURN, amount, domain, recipient, address(USDC), bytes32(0), maxFee, FINALIZED
        );
    }

    function _own() internal view returns (bytes32) {
        return bytes32(uint256(uint160(acct)));
    }

    function test_recipe_cctp_theAgentBridgesToItsOwnAddress() public {
        if (!_onBaseSepolia()) return;
        uint256 supply = USDC.totalSupply();
        _send(_call(_burn(50e6, ETHEREUM, _own(), 0)));
        assertEq(USDC.balanceOf(acct), 950e6, "left the account");
        assertEq(USDC.totalSupply(), supply - 50e6, "burned here, to be minted there");
        assertEq(_spent(), 50e6, "charged");
        assertEq(USDC.allowance(acct, MESSENGER), 300e6 - 50e6);
    }

    function test_recipe_cctp_whatTheRulesRefuse() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("other");
        // another recipient, another chain, a fee, over the cap
        _expectRefused(_call(_burn(50e6, ETHEREUM, bytes32(uint256(uint160(other))), 0)));
        _expectRefused(_call(_burn(50e6, 3, _own(), 0)));
        _expectRefused(_call(_burn(50e6, ETHEREUM, _own(), 1)));
        _expectRefused(_call(_burn(100e6 + 1, ETHEREUM, _own(), 0)));
        // a caller on the other side set by the agent
        bytes memory withCaller = abi.encodeWithSelector(
            DEPOSIT_FOR_BURN, uint256(50e6), ETHEREUM, _own(), address(USDC), bytes32(uint256(1)), uint256(0), FINALIZED
        );
        _expectRefused(_call(withCaller));
        // the form with a hook, which is not listed
        bytes memory hooked = abi.encodeWithSignature(
            "depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)",
            uint256(50e6),
            uint32(0),
            _own(),
            address(USDC),
            bytes32(0),
            uint256(0),
            uint32(2000),
            hex"00"
        );
        _expectRefused(_call(hooked));
        assertEq(USDC.balanceOf(acct), 1_000e6);
        assertEq(_spent(), 0);
    }

    /// Why the recipient is held: the messenger burns for whoever is named.
    function test_real_cctp_theMessengerBurnsForWhoeverIsNamed() public {
        if (!_onBaseSepolia()) return;
        address other = makeAddr("other");
        vm.prank(acct);
        (bool ok,) = MESSENGER.call(_burn(10e6, ETHEREUM, bytes32(uint256(uint160(other))), 0));
        assertTrue(ok, "accepted for another recipient");
        assertEq(USDC.balanceOf(acct), 990e6);
    }

    /// Why the allowance may stand: the messenger takes from its caller only.
    function test_real_cctp_theMessengerTakesFromItsCallerOnly() public {
        if (!_onBaseSepolia()) return;
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        (bool ok,) = MESSENGER.call(_burn(10e6, ETHEREUM, bytes32(uint256(uint160(stranger))), 0));
        assertFalse(ok, "a stranger's burn does not spend the account's allowance");
        assertEq(USDC.balanceOf(acct), 1_000e6);
    }
}

/// An ERC-4626 vault on Ethereum (sDAI): `deposit(assets, receiver)` with the
/// receiver held to the account and the assets charged; `redeem` and
/// `withdraw` with both the receiver and the owner held to the account.
contract VaultRecipeTest is RulesRecipe {
    address internal constant VAULT = 0x83F20F44975D03b1b09e64809B757c47f942BEeA;
    ITokenForRecipes internal constant DAI = ITokenForRecipes(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    bytes4 internal constant DEPOSIT = 0x6e553f65; // deposit(uint256,address)
    bytes4 internal constant REDEEM = 0xba087652; // redeem(uint256,address,address)
    bytes4 internal constant WITHDRAW = 0xb460af94; // withdraw(uint256,address,address)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        (bool ok, bytes memory data) = VAULT.staticcall(abi.encodeWithSignature("asset()"));
        require(ok && abi.decode(data, (address)) == address(DAI), "not a vault of DAI");
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](3);
        fs[0].selector = DEPOSIT;
        fs[0].words = new CallRulesDecoder.Word[](2);
        fs[0].words[0] = _word(3, uint256(uint160(address(DAI))));
        fs[0].words[1] = _word(0, 0);
        fs[1].selector = REDEEM;
        fs[1].words = new CallRulesDecoder.Word[](3);
        (fs[1].words[0], fs[1].words[1], fs[1].words[2]) = (_word(4, 0), _word(0, 0), _word(0, 0));
        fs[2].selector = WITHDRAW;
        fs[2].words = new CallRulesDecoder.Word[](3);
        (fs[2].words[0], fs[2].words[1], fs[2].words[2]) = (_word(4, 0), _word(0, 0), _word(0, 0));
        _installRules(VAULT, fs, address(DAI), 100 ether, 300 ether);
        deal(address(DAI), acct, 1_000 ether);
        return true;
    }

    function _shares(address who) internal view returns (uint256) {
        return ITokenForRecipes(VAULT).balanceOf(who);
    }

    function test_recipe_vault_theAgentDepositsAndRedeems() public {
        if (!_onEthereum()) return;
        _send(_call(abi.encodeWithSelector(DEPOSIT, uint256(100 ether), acct)));
        assertEq(DAI.balanceOf(acct), 900 ether);
        uint256 shares = _shares(acct);
        assertGt(shares, 0, "the shares are the account's");
        assertEq(_spent(), 100 ether, "charged");
        // half of the shares back, to the account: nothing is charged
        _send(_call(abi.encodeWithSelector(REDEEM, shares / 2, acct, acct)));
        assertEq(_shares(acct), shares - shares / 2);
        assertApproxEqAbs(DAI.balanceOf(acct), 950 ether, 1e12, "half of the deposit is back");
        assertEq(_spent(), 100 ether);
        // the rest by amount
        _send(_call(abi.encodeWithSelector(WITHDRAW, uint256(40 ether), acct, acct)));
        assertApproxEqAbs(DAI.balanceOf(acct), 990 ether, 1e12);
    }

    function test_recipe_vault_whatTheRulesRefuse() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        _send(_call(abi.encodeWithSelector(DEPOSIT, uint256(100 ether), acct)));
        uint256 shares = _shares(acct);
        // a deposit for somebody else; over the cap
        _expectRefused(_call(abi.encodeWithSelector(DEPOSIT, uint256(10 ether), other)));
        _expectRefused(_call(abi.encodeWithSelector(DEPOSIT, uint256(100 ether) + 1, acct)));
        // the account's shares redeemed or withdrawn to somebody else
        _expectRefused(_call(abi.encodeWithSelector(REDEEM, shares, other, acct)));
        _expectRefused(_call(abi.encodeWithSelector(WITHDRAW, uint256(10 ether), other, acct)));
        // `mint`, and the share token's own transfer and approval: not listed
        _expectRefused(_call(abi.encodeWithSignature("mint(uint256,address)", 1 ether, acct)));
        _expectRefused(_call(abi.encodeWithSignature("transfer(address,uint256)", other, shares)));
        _expectRefused(_call(abi.encodeWithSignature("approve(address,uint256)", other, shares)));
        assertEq(_shares(acct), shares);
        assertEq(_shares(other), 0);
        assertEq(DAI.balanceOf(other), 0);
        assertEq(_spent(), 100 ether);
    }

    /// Why the receiver is held: the vault credits whoever the caller names.
    function test_real_vault_theVaultCreditsWhoeverIsNamed() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        vm.prank(acct);
        (bool ok,) = VAULT.call(abi.encodeWithSelector(DEPOSIT, uint256(10 ether), other));
        assertTrue(ok);
        assertGt(_shares(other), 0, "credited to the named address");
        assertEq(_shares(acct), 0);
    }
}
