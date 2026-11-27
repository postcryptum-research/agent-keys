// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AllowListRecipe, RulesRecipe, ITokenForRecipes} from "./ProtocolRecipes.t.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";
import {Execution} from "kernel/src/types/Structs.sol";
import {PermissionId} from "kernel/src/types/Types.sol";

/// More recipes of `docs/DAPPS.md`, each run against the protocol's own
/// code on a fork of Ethereum (issue #80): the rows that were written down
/// from a reading of the source and had no test. Without the chain's RPC in
/// the environment every test here is skipped, so CI runs none of them.
///
///   FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> \
///     forge test --evm-version osaka --match-path test/MoreRecipes.t.sol --match-test 'test_recipe|test_real'

// ---------------------------------------------------------------------------
// With the mandate as it is: an allow-list and limits
// ---------------------------------------------------------------------------

/// What the allow-list recipes of this file share: one mandate, and the
/// pattern for a protocol that pulls a token (the allowance, the call, the
/// allowance taken back, in one operation).
abstract contract AllowListOnEthereum is AllowListRecipe {
    PermissionId internal constant ID = PermissionId.wrap(0x72656370); // "recp"
    bytes32 internal constant PERMISSION = bytes32(PermissionId.unwrap(ID));
    bytes4 internal constant APPROVE = 0x095ea7b3;

    address[] internal targets_;
    bytes4[] internal selectors_;
    AgentPolicy.TokenCap[] internal caps_;

    function _allow(address target, bytes4 selector) internal {
        targets_.push(target);
        selectors_.push(selector);
    }

    /// A token the agent may approve, within a cap an operation and a budget.
    function _limit(address token, uint128 cap, uint128 budget) internal {
        _allow(token, APPROVE);
        caps_.push(AgentPolicy.TokenCap(token, cap, budget, bytes32(0)));
    }

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        // storage written before the fork is not the fork's: the lists start empty there
        delete targets_;
        delete selectors_;
        delete caps_;
        _mandate();
        _installAllowList(ID, targets_, selectors_, caps_);
        vm.deal(acct, 1 ether);
        return true;
    }

    /// The recipe: what the owner puts on the mandate.
    function _mandate() internal virtual;

    function _do(address target, uint256 value, bytes memory data) internal {
        _send(_agentOpWith(AGENT, ID, target, value, data));
    }

    function _refused(address target, uint256 value, bytes memory data) internal {
        _expectRefused(_agentOpWith(AGENT, ID, target, value, data));
    }

    /// The allowance, the call that pulls, the allowance taken back.
    function _pulling(address token, address spender, uint256 amount, address target, bytes memory data)
        internal
        pure
        returns (Execution[] memory calls)
    {
        calls = new Execution[](3);
        calls[0] = Execution(token, 0, abi.encodeWithSelector(APPROVE, spender, amount));
        calls[1] = Execution(target, 0, data);
        calls[2] = Execution(token, 0, abi.encodeWithSelector(APPROVE, spender, 0));
    }

    function _doPulling(address token, address spender, uint256 amount, address target, bytes memory data) internal {
        _send(_agentBatchWith(AGENT, ID, _pulling(token, spender, amount, target, data)));
    }

    function _spent(address token) internal view returns (uint256) {
        return policy.tokenLimit(acct, PERMISSION, token).spent;
    }

    function _bal(address token, address who) internal view returns (uint256) {
        return ITokenForRecipes(token).balanceOf(who);
    }
}

/// Lido's wrapper. A plain transfer of ether to wstETH stakes it and mints
/// wstETH to the sender; `unwrap(uint256)` burns the caller's wstETH for
/// stETH; `wrap(uint256)` pulls stETH from its caller and mints wstETH to
/// it. stETH has a limit here, for the allowance a wrap needs, and so
/// `submit` on stETH is not on this mandate: on a token with a limit the
/// policy admits its metered functions and no other.
contract LidoWrapRecipeTest is AllowListOnEthereum {
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address internal constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    bytes4 internal constant SUBMIT = 0xa1903eab; // submit(address)
    bytes4 internal constant WRAP = 0xea598cb0; // wrap(uint256)
    bytes4 internal constant UNWRAP = 0xde0e9a3e; // unwrap(uint256)
    /// How a mandate names a plain transfer of value.
    bytes4 internal constant PLAIN = bytes4(0);

    function _mandate() internal override {
        _allow(WSTETH, PLAIN);
        _limit(STETH, 1 ether, 3 ether);
        _allow(WSTETH, WRAP);
        _allow(WSTETH, UNWRAP);
    }

    function test_recipe_lidoWrap_theAgentStakesUnwrapsAndWraps() public {
        if (!_onEthereum()) return;
        // ether sent to the wrapper: staked and wrapped in one call, to the sender
        _do(WSTETH, MAX_VALUE, "");
        uint256 wrapped = _bal(WSTETH, acct);
        assertGt(wrapped, 0, "the wstETH is the account's");
        assertLt(wrapped, MAX_VALUE, "one wstETH is worth more than one ether");
        // half of it unwrapped, by one call: stETH to the account, nothing charged
        _do(WSTETH, 0, abi.encodeWithSelector(UNWRAP, wrapped / 2));
        uint256 staked = _bal(STETH, acct);
        assertApproxEqAbs(staked, MAX_VALUE / 2, 1e12, "half of the stake, as stETH");
        assertEq(_spent(STETH), 0);
        // and wrapped again: the allowance, the wrap, the allowance taken back
        _doPulling(STETH, WSTETH, staked, WSTETH, abi.encodeWithSelector(WRAP, staked));
        assertApproxEqAbs(_bal(WSTETH, acct), wrapped, 4, "all of it is wstETH again");
        assertEq(ITokenForRecipes(STETH).allowance(acct, WSTETH), 0, "no allowance stands");
        assertEq(_spent(STETH), staked, "charged when approved");
    }

    function test_recipe_lidoWrap_whatIsNotListedIsRefused() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        _do(WSTETH, MAX_VALUE, "");
        uint256 wrapped = _bal(WSTETH, acct);
        _do(WSTETH, 0, abi.encodeWithSelector(UNWRAP, wrapped / 2));
        // the wrapped token sent away or approved; the stETH sent away; more ether than the cap
        _refused(WSTETH, 0, abi.encodeWithSignature("transfer(address,uint256)", other, 1));
        _refused(WSTETH, 0, abi.encodeWithSignature("approve(address,uint256)", other, 1));
        _refused(STETH, 0, abi.encodeWithSignature("transfer(address,uint256)", other, 1));
        _refused(WSTETH, MAX_VALUE + 1, "");
        // `submit` on stETH: not a metered function, so not for a token with a limit
        _refused(STETH, 0.01 ether, abi.encodeWithSelector(SUBMIT, address(0)));
        // an allowance left open
        Execution[] memory calls = _pulling(STETH, WSTETH, 0.01 ether, WSTETH, abi.encodeWithSelector(WRAP, 0.01 ether));
        Execution[] memory open = new Execution[](2);
        (open[0], open[1]) = (calls[0], calls[1]);
        _expectRefused(_agentBatchWith(AGENT, ID, open));
        assertEq(_bal(WSTETH, other), 0);
    }

    /// Why the functions can be listed as they are: they act on their caller.
    function test_real_lidoWrap_theWrapperCreditsItsCaller() public {
        if (!_onEthereum()) return;
        address stranger = makeAddr("stranger");
        vm.deal(stranger, 1 ether);
        vm.startPrank(stranger);
        (bool ok,) = STETH.call{value: 0.1 ether}(abi.encodeWithSelector(SUBMIT, address(0)));
        ITokenForRecipes(STETH).approve(WSTETH, 0.05 ether);
        (bool wrapped,) = WSTETH.call(abi.encodeWithSelector(WRAP, 0.05 ether));
        (bool sent,) = WSTETH.call{value: 0.05 ether}("");
        vm.stopPrank();
        assertTrue(ok && wrapped && sent);
        assertGt(_bal(WSTETH, stranger), 0);
        assertEq(_bal(WSTETH, acct), 0);
    }
}

/// A mandate that lists `submit` on stETH and gives stETH a limit is not one
/// the policy installs: a token with a limit has its metered functions and
/// no other. An owner picks one of the two recipes for a mandate.
contract LidoSubmitWithALimitTest is AllowListOnEthereum {
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    bytes4 internal constant SUBMIT = 0xa1903eab; // submit(address)

    function _mandate() internal override {
        _allow(STETH, SUBMIT);
        _limit(STETH, 1 ether, 3 ether);
    }

    function test_recipe_lido_submitAndALimitDoNotShareAMandate() public {
        if (!_onEthereum()) return;
        assertFalse(policy.isAllowed(acct, PERMISSION, STETH, SUBMIT), "the mandate was not installed");
        assertFalse(policy.isAllowed(acct, PERMISSION, STETH, APPROVE));
        _refused(STETH, 0.01 ether, abi.encodeWithSelector(SUBMIT, address(0)));
    }
}

/// ether.fi: the pool's `deposit()` stakes the value sent and credits eETH
/// to its caller; weETH's `wrap` and `unwrap` act on their caller.
contract EtherFiRecipeTest is AllowListOnEthereum {
    address internal constant POOL = 0x308861A430be4cce5502d0A12724771Fc6DaF216;
    address internal constant EETH = 0x35fA164735182de50811E8e2E824cFb9B6118ac2;
    address internal constant WEETH = 0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee;
    bytes4 internal constant DEPOSIT = 0xd0e30db0; // deposit()
    bytes4 internal constant WRAP = 0xea598cb0; // wrap(uint256)
    bytes4 internal constant UNWRAP = 0xde0e9a3e; // unwrap(uint256)

    function _mandate() internal override {
        _allow(POOL, DEPOSIT);
        _limit(EETH, 1 ether, 3 ether);
        _allow(WEETH, WRAP);
        _allow(WEETH, UNWRAP);
    }

    function test_recipe_etherFi_theAgentStakesWrapsAndUnwraps() public {
        if (!_onEthereum()) return;
        _do(POOL, MAX_VALUE, abi.encodeWithSelector(DEPOSIT));
        uint256 staked = _bal(EETH, acct);
        assertApproxEqAbs(staked, MAX_VALUE, 2, "the eETH is the account's");
        _doPulling(EETH, WEETH, 0.05 ether, WEETH, abi.encodeWithSelector(WRAP, 0.05 ether));
        uint256 wrapped = _bal(WEETH, acct);
        assertGt(wrapped, 0, "the weETH is the account's");
        assertEq(ITokenForRecipes(EETH).allowance(acct, WEETH), 0);
        _do(WEETH, 0, abi.encodeWithSelector(UNWRAP, wrapped));
        assertEq(_bal(WEETH, acct), 0);
        assertApproxEqAbs(_bal(EETH, acct), staked, 6, "the eETH is back");
        // over the native cap for one operation; and the eETH sent away
        _refused(POOL, MAX_VALUE + 1, abi.encodeWithSelector(DEPOSIT));
        _refused(EETH, 0, abi.encodeWithSignature("transfer(address,uint256)", makeAddr("other"), 1));
    }
}

/// Rocket Pool: the deposit pool's `deposit()` mints rETH to its caller for
/// the value sent; rETH's `burn(uint256)` pays ETH to its caller.
contract RocketPoolRecipeTest is AllowListOnEthereum {
    /// Rocket Pool's storage contract, which names the current deposit pool.
    address internal constant STORAGE = 0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46;
    address internal constant RETH = 0xae78736Cd615f374D3085123A210448E74Fc6393;
    bytes4 internal constant DEPOSIT = 0xd0e30db0; // deposit()
    bytes4 internal constant BURN = 0x42966c68; // burn(uint256)
    address internal pool;

    function _mandate() internal override {
        // the deposit pool's address changes with Rocket Pool's upgrades: the owner reads it there
        (bool ok, bytes memory data) = STORAGE.staticcall(
            abi.encodeWithSignature("getAddress(bytes32)", keccak256("contract.addressrocketDepositPool"))
        );
        require(ok, "Rocket Pool's storage does not answer");
        pool = abi.decode(data, (address));
        _allow(pool, DEPOSIT);
        _allow(RETH, BURN);
    }

    function test_recipe_rocketPool_theAgentStakes() public {
        if (!_onEthereum()) return;
        _do(pool, 0.05 ether, abi.encodeWithSelector(DEPOSIT));
        uint256 minted = _bal(RETH, acct);
        assertGt(minted, 0, "the rETH is the account's");
        // one rETH is worth more than one ETH, less the deposit fee: between 80% and 100% of the ETH in rETH units
        assertLt(minted, 0.05 ether);
        assertGt(minted, 0.04 ether);
        // over the cap, and the rETH sent away
        _refused(pool, MAX_VALUE + 1, abi.encodeWithSelector(DEPOSIT));
        _refused(RETH, 0, abi.encodeWithSignature("transfer(address,uint256)", makeAddr("other"), 1));
    }

    function test_recipe_rocketPool_theAgentBurnsForEther() public {
        if (!_onEthereum()) return;
        _do(pool, 0.05 ether, abi.encodeWithSelector(DEPOSIT));
        uint256 minted = _bal(RETH, acct);
        uint256 before = acct.balance;
        _do(RETH, 0, abi.encodeWithSelector(BURN, minted));
        assertEq(_bal(RETH, acct), 0);
        assertGt(acct.balance, before, "the ether is the account's");
    }
}

/// Sky's staking rewards (USDS staked for SPK): `stake`, `withdraw`,
/// `getReward` and `exit` act on their caller.
contract SkyRewardsRecipeTest is AllowListOnEthereum {
    address internal constant FARM = 0x173e314C7635B45322cd8Cb14f44b312e079F3af;
    address internal constant USDS = 0xdC035D45d973E3EC169d2276DDab16f1e407384F;
    /// SPK, the token this farm pays.
    address internal constant REWARD = 0xc20059e0317DE91738d13af027DfC4a50781b066;
    bytes4 internal constant STAKE = 0xa694fc3a; // stake(uint256)
    bytes4 internal constant WITHDRAW = 0x2e1a7d4d; // withdraw(uint256)
    bytes4 internal constant GET_REWARD = 0x3d18b912; // getReward()
    bytes4 internal constant EXIT = 0xe9fad8ee; // exit()

    function _mandate() internal override {
        _limit(USDS, 100 ether, 300 ether);
        _allow(FARM, STAKE);
        _allow(FARM, WITHDRAW);
        _allow(FARM, GET_REWARD);
        _allow(FARM, EXIT);
    }

    function test_recipe_sky_theAgentStakesAndLeaves() public {
        if (!_onEthereum()) return;
        deal(USDS, acct, 1_000 ether);
        _doPulling(USDS, FARM, 100 ether, FARM, abi.encodeWithSelector(STAKE, 100 ether));
        assertEq(_bal(FARM, acct), 100 ether, "the stake is the account's");
        assertEq(_bal(USDS, acct), 900 ether);
        assertEq(_spent(USDS), 100 ether);
        _do(FARM, 0, abi.encodeWithSelector(WITHDRAW, 40 ether));
        assertEq(_bal(USDS, acct), 940 ether);
        // a farm pays in periods its project renews: a payout is required where one is running
        (, bytes memory ends) = FARM.staticcall(abi.encodeWithSignature("periodFinish()"));
        bool running = abi.decode(ends, (uint256)) > block.timestamp;
        vm.warp(block.timestamp + 10 minutes);
        _do(FARM, 0, abi.encodeWithSelector(GET_REWARD));
        if (running) assertGt(_bal(REWARD, acct), 0, "the reward is the account's");
        _do(FARM, 0, abi.encodeWithSelector(EXIT));
        assertEq(_bal(FARM, acct), 0);
        assertEq(_bal(USDS, acct), 1_000 ether, "everything is back");
        // over the cap for one operation
        _expectRefused(
            _agentBatchWith(
                AGENT, ID, _pulling(USDS, FARM, 100 ether + 1, FARM, abi.encodeWithSelector(STAKE, 100 ether + 1))
            )
        );
    }

    function test_real_sky_theFarmCreditsItsCaller() public {
        if (!_onEthereum()) return;
        address stranger = makeAddr("stranger");
        deal(USDS, stranger, 10 ether);
        vm.startPrank(stranger);
        ITokenForRecipes(USDS).approve(FARM, 10 ether);
        (bool ok,) = FARM.call(abi.encodeWithSelector(STAKE, 10 ether));
        vm.stopPrank();
        assertTrue(ok);
        assertEq(_bal(FARM, stranger), 10 ether);
        assertEq(_bal(FARM, acct), 0);
    }
}

/// Curve's 3pool: `exchange`, `add_liquidity` and `remove_liquidity` pay
/// their caller. The least received is the agent's own argument: nothing
/// holds a price, the token's budget bounds what a bad trade can lose.
contract CurveRecipeTest is AllowListOnEthereum {
    address internal constant POOL = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;
    address internal constant LP = 0x6c3F90f043a72FA612cbac8115EE7e52BDe6E490;
    address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes4 internal constant EXCHANGE = 0x3df02124; // exchange(int128,int128,uint256,uint256)
    bytes4 internal constant ADD = 0x4515cef3; // add_liquidity(uint256[3],uint256)
    bytes4 internal constant REMOVE = 0xecb586a5; // remove_liquidity(uint256,uint256[3])

    function _mandate() internal override {
        _limit(DAI, 100 ether, 300 ether);
        _allow(POOL, EXCHANGE);
        _allow(POOL, ADD);
        _allow(POOL, REMOVE);
    }

    function test_recipe_curve_theAgentSwapsAndProvides() public {
        if (!_onEthereum()) return;
        deal(DAI, acct, 1_000 ether);
        // 100 DAI for USDC, at least 99
        _doPulling(DAI, POOL, 100 ether, POOL, abi.encodeWithSelector(EXCHANGE, int128(0), int128(1), 100 ether, 99e6));
        assertGt(_bal(USDC, acct), 99e6, "the USDC is the account's");
        assertEq(_bal(DAI, acct), 900 ether);
        assertEq(_spent(DAI), 100 ether);
        // 100 DAI into the pool: the pool's token is the account's
        uint256[3] memory amounts = [uint256(100 ether), 0, 0];
        _doPulling(DAI, POOL, 100 ether, POOL, abi.encodeWithSelector(ADD, amounts, uint256(0)));
        uint256 lp = _bal(LP, acct);
        assertGt(lp, 0, "the pool's token is the account's");
        // and out again, in the pool's three coins, to the account
        uint256[3] memory none;
        uint256 usdc = _bal(USDC, acct);
        _do(POOL, 0, abi.encodeWithSelector(REMOVE, lp, none));
        assertEq(_bal(LP, acct), 0);
        assertGt(_bal(USDC, acct), usdc);
        assertGt(_bal(DAI, acct), 800 ether);
    }

    /// The word of care in the docs: the least received is the agent's.
    function test_recipe_curve_thePriceIsTheAgents() public {
        if (!_onEthereum()) return;
        deal(DAI, acct, 1_000 ether);
        // a least of nothing is accepted: the policy holds the amount spent, not what comes back
        _doPulling(DAI, POOL, 100 ether, POOL, abi.encodeWithSelector(EXCHANGE, int128(0), int128(1), 100 ether, 0));
        assertEq(_spent(DAI), 100 ether);
        // the budget is what bounds it: three such trades, and no fourth
        _doPulling(DAI, POOL, 100 ether, POOL, abi.encodeWithSelector(EXCHANGE, int128(0), int128(1), 100 ether, 0));
        _doPulling(DAI, POOL, 100 ether, POOL, abi.encodeWithSelector(EXCHANGE, int128(0), int128(1), 100 ether, 0));
        _expectRefused(
            _agentBatchWith(
                AGENT, ID, _pulling(DAI, POOL, 1, POOL, abi.encodeWithSelector(EXCHANGE, int128(0), int128(1), 1, 0))
            )
        );
    }
}

/// EigenLayer: `depositIntoStrategy` credits the shares to its caller.
/// `delegateTo` stays off the mandate.
contract EigenLayerRecipeTest is AllowListOnEthereum {
    address internal constant STRATEGY_MANAGER = 0x858646372CC42E1A627fcE94aa7A7033e7CF075A;
    address internal constant DELEGATION_MANAGER = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
    address internal constant STETH_STRATEGY = 0x93c4b944D05dfe6df7645A86cd2206016c51564D;
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    bytes4 internal constant SUBMIT = 0xa1903eab; // submit(address)
    bytes4 internal constant DEPOSIT = 0xe7a050aa; // depositIntoStrategy(address,address,uint256)

    function _mandate() internal override {
        _limit(STETH, 1 ether, 3 ether);
        _allow(STRATEGY_MANAGER, DEPOSIT);
    }

    function _shares(address who) internal view returns (uint256 shares) {
        // the strategy's own count of a staker's shares
        (bool ok, bytes memory data) = STETH_STRATEGY.staticcall(abi.encodeWithSignature("shares(address)", who));
        require(ok, "the strategy does not answer shares(address)");
        shares = abi.decode(data, (uint256));
    }

    function test_recipe_eigenLayer_theAgentRestakes() public {
        if (!_onEthereum()) return;
        // the account holds stETH: staked by its owner
        vm.prank(acct);
        (bool staked,) = STETH.call{value: 0.1 ether}(abi.encodeWithSelector(SUBMIT, address(0)));
        assertTrue(staked);
        assertEq(_shares(acct), 0);
        _doPulling(
            STETH,
            STRATEGY_MANAGER,
            0.05 ether,
            STRATEGY_MANAGER,
            abi.encodeWithSelector(DEPOSIT, STETH_STRATEGY, STETH, 0.05 ether)
        );
        assertGt(_shares(acct), 0, "the shares are the account's");
        assertEq(ITokenForRecipes(STETH).allowance(acct, STRATEGY_MANAGER), 0);
        assertEq(_spent(STETH), 0.05 ether);
        // delegation to an operator is not listed
        _refused(
            DELEGATION_MANAGER,
            0,
            abi.encodeWithSignature(
                "delegateTo(address,(bytes,uint256),bytes32)", makeAddr("operator"), bytes(""), uint256(0), bytes32(0)
            )
        );
    }
}

/// Compound v3's rewards: `claim(comet, src, shouldAccrue)` pays what `src`
/// has earned to `src` itself, whoever calls.
contract CompoundRewardsRecipeTest is AllowListOnEthereum {
    address internal constant COMET = 0xc3d688B66703497DAA19211EEdff47f25384cdc3;
    address internal constant REWARDS = 0x1B0e765F6224C21223AeA2af16c1C46E38885a40;
    address internal constant COMP = 0xc00e94Cb662C3520282E6f5717214004A7f26888;
    bytes4 internal constant CLAIM = 0xb7034f7e; // claim(address,address,bool)

    function _mandate() internal override {
        _allow(REWARDS, CLAIM);
    }

    /// No market of Compound's pays rewards at the time of writing (the
    /// speeds read zero), so what the account has earned is stood in: the
    /// market's answer to `baseTrackingAccrued(account)`, one unit, which
    /// the rewards contract turns into 1e12 of COMP. The claim is the
    /// rewards contract's own code.
    function _earned() internal returns (uint256 owed) {
        vm.mockCall(COMET, abi.encodeWithSignature("baseTrackingAccrued(address)", acct), abi.encode(uint64(1)));
        owed = 1e12;
        assertGe(_bal(COMP, REWARDS), owed, "the rewards contract holds what it would pay");
    }

    function test_recipe_compoundRewards_theAgentClaimsForTheAccount() public {
        if (!_onEthereum()) return;
        uint256 owed = _earned();
        uint256 before = _bal(COMP, acct);
        _do(REWARDS, 0, abi.encodeWithSelector(CLAIM, COMET, acct, true));
        assertEq(_bal(COMP, acct), before + owed, "what was earned is the account's");
        // the form that names a recipient is not listed
        _refused(
            REWARDS,
            0,
            abi.encodeWithSignature("claimTo(address,address,address,bool)", COMET, acct, makeAddr("other"), true)
        );
    }

    /// Why any arguments are safe: what `src` earned goes to `src`.
    function test_real_compoundRewards_aClaimPaysTheOneItIsFor() public {
        if (!_onEthereum()) return;
        uint256 owed = _earned();
        address stranger = makeAddr("stranger");
        uint256 before = _bal(COMP, acct);
        // the form with a recipient is for the account and those it permitted
        vm.prank(stranger);
        (bool taken,) =
            REWARDS.call(abi.encodeWithSignature("claimTo(address,address,address,bool)", COMET, acct, stranger, true));
        assertFalse(taken, "a stranger cannot name itself the recipient");
        vm.prank(stranger);
        (bool ok,) = REWARDS.call(abi.encodeWithSelector(CLAIM, COMET, acct, true));
        assertTrue(ok, "anyone may claim for an account");
        assertEq(_bal(COMP, stranger), 0, "and gets nothing for it");
        assertEq(_bal(COMP, acct), before + owed, "the account is paid");
    }
}

/// Aave V3 on Ethereum: `repayWithATokens(asset, amount, rateMode)` pays the
/// caller's own debt with the caller's own aTokens. It names nobody else.
contract AaveSelfRepayRecipeTest is AllowListOnEthereum {
    address internal constant POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant A_USDC = 0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c;
    address internal constant DEBT_USDC = 0x72E95b8931767C79bA4EeE721354d6E99a61D004;
    bytes4 internal constant REPAY_WITH_ATOKENS = 0x2dad97d4; // repayWithATokens(address,uint256,uint256)

    function _mandate() internal override {
        _allow(POOL, REPAY_WITH_ATOKENS);
    }

    /// The owner's doing, before the agent acts: collateral, a debt, and a supply of the borrowed asset.
    function _aDebtAndASupply() internal {
        deal(WETH, acct, 10 ether);
        deal(USDC, acct, 500e6);
        vm.startPrank(acct);
        ITokenForRecipes(WETH).approve(POOL, 10 ether);
        (bool a,) =
            POOL.call(abi.encodeWithSignature("supply(address,uint256,address,uint16)", WETH, 10 ether, acct, 0));
        (bool b,) = POOL.call(
            abi.encodeWithSignature("borrow(address,uint256,uint256,uint16,address)", USDC, 1_000e6, 2, 0, acct)
        );
        ITokenForRecipes(USDC).approve(POOL, 500e6);
        (bool c,) = POOL.call(abi.encodeWithSignature("supply(address,uint256,address,uint16)", USDC, 500e6, acct, 0));
        vm.stopPrank();
        require(a && b && c, "the pool refused the owner's setup");
    }

    function test_recipe_aave_theAgentRepaysWithTheAccountsATokens() public {
        if (!_onEthereum()) return;
        _aDebtAndASupply();
        uint256 debt = _bal(DEBT_USDC, acct);
        uint256 supplied = _bal(A_USDC, acct);
        _do(POOL, 0, abi.encodeWithSelector(REPAY_WITH_ATOKENS, USDC, 100e6, 2));
        assertApproxEqAbs(_bal(DEBT_USDC, acct), debt - 100e6, 5, "the debt is 100 less");
        assertApproxEqAbs(_bal(A_USDC, acct), supplied - 100e6, 5, "paid with the account's aTokens");
        // a borrow is not listed
        _refused(
            POOL, 0, abi.encodeWithSignature("borrow(address,uint256,uint256,uint16,address)", USDC, 1e6, 2, 0, acct)
        );
    }
}

// ---------------------------------------------------------------------------
// With a rule for each argument (`CallRulesDecoder`)
// ---------------------------------------------------------------------------

abstract contract RulesOnEthereum is RulesRecipe {
    uint8 internal constant IS_ACCOUNT = 0;
    uint8 internal constant IS_VALUE = 1;
    uint8 internal constant AT_MOST = 2;
    uint8 internal constant CHARGED = 3;
    uint8 internal constant ANY = 4;

    function _is(address a) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(IS_VALUE, uint256(uint160(a)));
    }

    function _is(uint256 v) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(IS_VALUE, v);
    }

    function _charged(address token) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(CHARGED, uint256(uint160(token)));
    }

    function _account() internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(IS_ACCOUNT, 0);
    }

    function _any() internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(ANY, 0);
    }

    function _atMost(uint256 v) internal pure returns (CallRulesDecoder.Word memory) {
        return CallRulesDecoder.Word(AT_MOST, v);
    }

    function _bal(address token, address who) internal view returns (uint256) {
        return ITokenForRecipes(token).balanceOf(who);
    }
}

/// Morpho Blue on Ethereum. Markets are permissionless, so the rules pin
/// the market itself: its five words. `supply` with the account as the one
/// supplied for and no callback data; `withdraw` with the account as owner
/// and receiver.
contract MorphoRecipeTest is RulesOnEthereum {
    address internal constant MORPHO = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    /// The USDC market with wstETH as collateral, 86% loan-to-value.
    bytes32 internal constant MARKET = 0xb323495f7e4148be5643a4ea4a8221eef163e4bccfdedc2a6f4696baacbc86cc;
    bytes4 internal constant SUPPLY = 0xa99aad89; // supply((address,address,address,address,uint256),uint256,uint256,address,bytes)
    bytes4 internal constant WITHDRAW = 0x5c2bea49; // withdraw((…),uint256,uint256,address,address)

    struct Market {
        address loanToken;
        address collateralToken;
        address oracle;
        address irm;
        uint256 lltv;
    }

    Market internal m;

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        (bool ok, bytes memory data) = MORPHO.staticcall(abi.encodeWithSignature("idToMarketParams(bytes32)", MARKET));
        require(ok, "Morpho does not answer for the market");
        m = abi.decode(data, (Market));
        require(m.loanToken == USDC, "not a market that lends USDC");
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](2);
        fs[0].selector = SUPPLY;
        fs[0].words = new CallRulesDecoder.Word[](10);
        _marketWords(fs[0].words);
        fs[0].words[5] = _charged(USDC); // the assets supplied
        fs[0].words[6] = _is(uint256(0)); // no amount in shares
        fs[0].words[7] = _account(); // supplied for the account
        fs[0].words[8] = _is(uint256(0x120)); // where the callback data starts
        fs[0].words[9] = _is(uint256(0)); // and that it is empty
        fs[1].selector = WITHDRAW;
        fs[1].words = new CallRulesDecoder.Word[](9);
        _marketWords(fs[1].words);
        fs[1].words[5] = _any(); // an amount in assets
        fs[1].words[6] = _any(); // or in shares
        fs[1].words[7] = _account(); // from the account's position
        fs[1].words[8] = _account(); // to the account
        _installRules(MORPHO, fs, USDC, 100e6, 300e6);
        deal(USDC, acct, 1_000e6);
        return true;
    }

    function _marketWords(CallRulesDecoder.Word[] memory words) internal view {
        words[0] = _is(m.loanToken);
        words[1] = _is(m.collateralToken);
        words[2] = _is(m.oracle);
        words[3] = _is(m.irm);
        words[4] = _is(m.lltv);
    }

    function _supply(Market memory market, uint256 assets, address onBehalf, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(SUPPLY, market, assets, uint256(0), onBehalf, data);
    }

    function _supplyShares(address who) internal view returns (uint256 shares) {
        (bool ok, bytes memory data) =
            MORPHO.staticcall(abi.encodeWithSignature("position(bytes32,address)", MARKET, who));
        require(ok);
        (shares,,) = abi.decode(data, (uint256, uint128, uint128));
    }

    function test_recipe_morpho_theAgentSuppliesAndWithdraws() public {
        if (!_onEthereum()) return;
        _send(_call(_supply(m, 100e6, acct, "")));
        assertGt(_supplyShares(acct), 0, "the position is the account's");
        assertEq(_bal(USDC, acct), 900e6);
        assertEq(_spent(), 100e6, "charged");
        // 40 back to the account, by assets
        _send(_call(abi.encodeWithSelector(WITHDRAW, m, uint256(40e6), uint256(0), acct, acct)));
        assertEq(_bal(USDC, acct), 940e6);
        assertEq(_spent(), 100e6);
    }

    function test_recipe_morpho_whatTheRulesRefuse() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        _send(_call(_supply(m, 100e6, acct, "")));
        // for somebody else; over the cap; with callback data
        _expectRefused(_call(_supply(m, 100e6, other, "")));
        _expectRefused(_call(_supply(m, 100e6 + 1, acct, "")));
        _expectRefused(_call(_supply(m, 100e6, acct, hex"01")));
        // another market: the same tokens at another loan-to-value
        Market memory elsewhere = m;
        elsewhere.lltv = 0.945 ether;
        _expectRefused(_call(_supply(elsewhere, 100e6, acct, "")));
        // a withdrawal to somebody else
        _expectRefused(_call(abi.encodeWithSelector(WITHDRAW, m, uint256(40e6), uint256(0), acct, other)));
        // what is not listed: handing the position to a manager, a borrow
        _expectRefused(_call(abi.encodeWithSignature("setAuthorization(address,bool)", other, true)));
        _expectRefused(
            _call(
                abi.encodeWithSignature(
                    "borrow((address,address,address,address,uint256),uint256,uint256,address,address)",
                    m,
                    uint256(1e6),
                    uint256(0),
                    acct,
                    acct
                )
            )
        );
        assertEq(_supplyShares(other), 0);
        assertEq(_bal(USDC, other), 0);
        assertEq(_spent(), 100e6);
    }

    /// Why the one supplied for is held: Morpho credits whoever is named.
    function test_real_morpho_aSupplyCreditsWhoeverIsNamed() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        vm.prank(acct);
        (bool ok,) = MORPHO.call(_supply(m, 10e6, other, ""));
        assertTrue(ok);
        assertGt(_supplyShares(other), 0);
        assertEq(_supplyShares(acct), 0);
    }
}

/// ERC-4626 vaults by the same three rules as sDAI: `deposit` charged with
/// the account as receiver; `redeem` and `withdraw` with the account as
/// receiver and owner.
abstract contract VaultByRules is RulesOnEthereum {
    bytes4 internal constant DEPOSIT = 0x6e553f65; // deposit(uint256,address)
    bytes4 internal constant REDEEM = 0xba087652; // redeem(uint256,address,address)
    bytes4 internal constant WITHDRAW = 0xb460af94; // withdraw(uint256,address,address)

    /// The vault, and one unit of its asset.
    function _vault() internal pure virtual returns (address vault, uint256 unit);

    function _onEthereum() internal returns (address vault, address asset, uint256 unit, bool there) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return (address(0), address(0), 0, false);
        (vault, unit) = _vault();
        (bool ok, bytes memory data) = vault.staticcall(abi.encodeWithSignature("asset()"));
        require(ok, "not a vault");
        asset = abi.decode(data, (address));
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](3);
        fs[0].selector = DEPOSIT;
        fs[0].words = new CallRulesDecoder.Word[](2);
        (fs[0].words[0], fs[0].words[1]) = (_charged(asset), _account());
        fs[1].selector = REDEEM;
        fs[1].words = new CallRulesDecoder.Word[](3);
        (fs[1].words[0], fs[1].words[1], fs[1].words[2]) = (_any(), _account(), _account());
        fs[2].selector = WITHDRAW;
        fs[2].words = new CallRulesDecoder.Word[](3);
        (fs[2].words[0], fs[2].words[1], fs[2].words[2]) = (_any(), _account(), _account());
        _installRules(vault, fs, asset, uint128(100 * unit), uint128(300 * unit));
        deal(asset, acct, 1_000 * unit);
        there = true;
    }

    function test_recipe_vault_theAgentDepositsAndRedeems() public {
        (address vault, address asset, uint256 unit, bool there) = _onEthereum();
        if (!there) return;
        address other = makeAddr("other");
        _send(_call(abi.encodeWithSelector(DEPOSIT, 100 * unit, acct)));
        uint256 shares = _bal(vault, acct);
        assertGt(shares, 0, "the shares are the account's");
        assertEq(_bal(asset, acct), 900 * unit);
        assertEq(_spent(), 100 * unit, "charged");
        // for somebody else, and to somebody else
        _expectRefused(_call(abi.encodeWithSelector(DEPOSIT, 10 * unit, other)));
        _expectRefused(_call(abi.encodeWithSelector(REDEEM, shares, other, acct)));
        // all of it back to the account
        _send(_call(abi.encodeWithSelector(REDEEM, shares, acct, acct)));
        assertEq(_bal(vault, acct), 0);
        assertApproxEqRel(_bal(asset, acct), 1_000 * unit, 0.001 ether, "the deposit is back, to a tenth of a percent");
        assertEq(_bal(vault, other), 0);
    }
}

/// A MetaMorpho vault (Steakhouse USDC).
contract MetaMorphoVaultRecipeTest is VaultByRules {
    function _vault() internal pure override returns (address, uint256) {
        return (0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB, 1e6);
    }
}

/// Sky's savings vault (sUSDS).
contract SavingsUsdsVaultRecipeTest is VaultByRules {
    function _vault() internal pure override returns (address, uint256) {
        return (0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD, 1 ether);
    }
}

/// Lido's withdrawal queue: `requestWithdrawals(amounts, owner)` takes
/// stETH from its caller and gives the request to `owner`. The rules hold
/// the owner to the account and the list to one amount, charged.
contract LidoWithdrawalRecipeTest is RulesOnEthereum {
    address internal constant QUEUE = 0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1;
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    bytes4 internal constant REQUEST = 0xd6681042; // requestWithdrawals(uint256[],address)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](1);
        fs[0].selector = REQUEST;
        fs[0].words = new CallRulesDecoder.Word[](4);
        fs[0].words[0] = _is(uint256(0x40)); // where the list starts
        fs[0].words[1] = _account(); // the request is the account's
        fs[0].words[2] = _is(uint256(1)); // one amount
        fs[0].words[3] = _charged(STETH);
        _installRules(QUEUE, fs, STETH, 1 ether, 3 ether);
        // the account holds stETH: staked by its owner
        vm.deal(acct, 1 ether);
        vm.prank(acct);
        (bool ok,) = STETH.call{value: 0.5 ether}(abi.encodeWithSignature("submit(address)", address(0)));
        require(ok, "Lido refused the stake");
        return true;
    }

    function _request(uint256[] memory amounts, address owner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(REQUEST, amounts, owner);
    }

    function _requestsOf(address who) internal view returns (uint256) {
        (bool ok, bytes memory data) = QUEUE.staticcall(abi.encodeWithSignature("getWithdrawalRequests(address)", who));
        require(ok);
        return abi.decode(data, (uint256[])).length;
    }

    function test_recipe_lidoQueue_theAgentRequestsAWithdrawal() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 staked = _bal(STETH, acct);
        uint256[] memory one = new uint256[](1);
        one[0] = 0.1 ether;
        _send(_call(_request(one, acct)));
        assertEq(_requestsOf(acct), 1, "the request is the account's");
        assertApproxEqAbs(_bal(STETH, acct), staked - 0.1 ether, 4);
        assertEq(_spent(), 0.1 ether, "charged");
        // a request owned by somebody else; two amounts in one call
        _expectRefused(_call(_request(one, other)));
        uint256[] memory two = new uint256[](2);
        (two[0], two[1]) = (0.1 ether, 0.1 ether);
        _expectRefused(_call(_request(two, acct)));
        assertEq(_requestsOf(other), 0);
    }

    /// Why the owner word is held: the queue gives the request to whoever is named.
    function test_real_lidoQueue_theRequestGoesToWhoeverIsNamed() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256[] memory one = new uint256[](1);
        one[0] = 0.1 ether;
        vm.prank(acct);
        (bool ok,) = QUEUE.call(_request(one, other));
        assertTrue(ok);
        assertEq(_requestsOf(other), 1);
        assertEq(_requestsOf(acct), 0);
    }
}

/// The OP-Stack bridge of Base, on Ethereum: `bridgeERC20To` locks a token
/// here for an address on Base. The rules hold both tokens, the recipient
/// (the account's own address there), the gas for the other side, and that
/// no extra data rides along; the amount is charged.
contract BaseBridgeRecipeTest is RulesOnEthereum {
    address internal constant BRIDGE = 0x3154Cf16ccdb4C6d922629664174b904d80F2C35;
    address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    /// DAI as the bridge mints it on Base.
    address internal constant DAI_ON_BASE = 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb;
    bytes4 internal constant BRIDGE_TO = 0x540abf73; // bridgeERC20To(address,address,address,uint256,uint32,bytes)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](1);
        fs[0].selector = BRIDGE_TO;
        fs[0].words = new CallRulesDecoder.Word[](7);
        fs[0].words[0] = _is(DAI);
        fs[0].words[1] = _is(DAI_ON_BASE);
        fs[0].words[2] = _account();
        fs[0].words[3] = _charged(DAI);
        fs[0].words[4] = _atMost(200_000);
        fs[0].words[5] = _is(uint256(0xc0)); // where the extra data starts
        fs[0].words[6] = _is(uint256(0)); // and that it is empty
        _installRules(BRIDGE, fs, DAI, 100 ether, 300 ether);
        deal(DAI, acct, 1_000 ether);
        return true;
    }

    function _bridge(address remote, address to, uint256 amount, uint32 gas, bytes memory extra)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(BRIDGE_TO, DAI, remote, to, amount, gas, extra);
    }

    function _locked() internal view returns (uint256 amount) {
        (bool ok, bytes memory data) =
            BRIDGE.staticcall(abi.encodeWithSignature("deposits(address,address)", DAI, DAI_ON_BASE));
        require(ok);
        amount = abi.decode(data, (uint256));
    }

    function test_recipe_baseBridge_theAgentBridgesToItsOwnAddress() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 locked = _locked();
        _send(_call(_bridge(DAI_ON_BASE, acct, 100 ether, 200_000, "")));
        assertEq(_bal(DAI, acct), 900 ether, "left the account");
        assertEq(_locked(), locked + 100 ether, "locked in the bridge for Base");
        assertEq(_spent(), 100 ether, "charged");
        // another recipient, another token on the other side, more gas, data along, over the cap
        _expectRefused(_call(_bridge(DAI_ON_BASE, other, 100 ether, 200_000, "")));
        _expectRefused(_call(_bridge(other, acct, 100 ether, 200_000, "")));
        _expectRefused(_call(_bridge(DAI_ON_BASE, acct, 100 ether, 200_001, "")));
        _expectRefused(_call(_bridge(DAI_ON_BASE, acct, 100 ether, 200_000, hex"01")));
        _expectRefused(_call(_bridge(DAI_ON_BASE, acct, 100 ether + 1, 200_000, "")));
        assertEq(_spent(), 100 ether);
    }
}

/// Aave V3 on Ethereum: `repay(asset, amount, rateMode, onBehalfOf)` with
/// the debt held to the account's own. Without the rule an agent could pay
/// anybody's debt with the account's tokens.
contract AaveRepayRecipeTest is RulesOnEthereum {
    address internal constant POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant DEBT_USDC = 0x72E95b8931767C79bA4EeE721354d6E99a61D004;
    bytes4 internal constant REPAY = 0x573ade81; // repay(address,uint256,uint256,address)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](1);
        fs[0].selector = REPAY;
        fs[0].words = new CallRulesDecoder.Word[](4);
        (fs[0].words[0], fs[0].words[1], fs[0].words[2], fs[0].words[3]) =
        (_is(USDC), _charged(USDC), _is(uint256(2)), _account());
        _installRules(POOL, fs, USDC, 100e6, 300e6);
        // the owner's doing: collateral and a debt
        deal(WETH, acct, 10 ether);
        vm.startPrank(acct);
        ITokenForRecipes(WETH).approve(POOL, 10 ether);
        (bool a,) =
            POOL.call(abi.encodeWithSignature("supply(address,uint256,address,uint16)", WETH, 10 ether, acct, 0));
        (bool b,) = POOL.call(
            abi.encodeWithSignature("borrow(address,uint256,uint256,uint16,address)", USDC, 1_000e6, 2, 0, acct)
        );
        vm.stopPrank();
        require(a && b, "the pool refused the owner's setup");
        return true;
    }

    function test_recipe_aaveRepay_theAgentRepaysTheAccountsDebt() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 debt = _bal(DEBT_USDC, acct);
        uint256 held = _bal(USDC, acct);
        _send(_call(abi.encodeWithSelector(REPAY, USDC, uint256(100e6), uint256(2), acct)));
        assertApproxEqAbs(_bal(DEBT_USDC, acct), debt - 100e6, 5, "the debt is 100 less");
        assertEq(_bal(USDC, acct), held - 100e6);
        assertEq(_spent(), 100e6, "charged");
        // somebody else's debt; over the cap; a borrow
        _expectRefused(_call(abi.encodeWithSelector(REPAY, USDC, uint256(100e6), uint256(2), other)));
        _expectRefused(_call(abi.encodeWithSelector(REPAY, USDC, uint256(100e6 + 1), uint256(2), acct)));
        _expectRefused(
            _call(abi.encodeWithSignature("borrow(address,uint256,uint256,uint16,address)", USDC, 1e6, 2, 0, acct))
        );
    }
}

/// Compound v3 on Ethereum, by the forms that name a beneficiary:
/// `supplyTo(dst, asset, amount)` and `withdrawTo(to, asset, amount)`, each
/// held to the account.
contract CompoundToRecipeTest is RulesOnEthereum {
    address internal constant COMET = 0xc3d688B66703497DAA19211EEdff47f25384cdc3;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes4 internal constant SUPPLY_TO = 0x4232cd63; // supplyTo(address,address,uint256)
    bytes4 internal constant WITHDRAW_TO = 0xc3b35a7e; // withdrawTo(address,address,uint256)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](2);
        fs[0].selector = SUPPLY_TO;
        fs[0].words = new CallRulesDecoder.Word[](3);
        (fs[0].words[0], fs[0].words[1], fs[0].words[2]) = (_account(), _is(USDC), _charged(USDC));
        fs[1].selector = WITHDRAW_TO;
        fs[1].words = new CallRulesDecoder.Word[](3);
        (fs[1].words[0], fs[1].words[1], fs[1].words[2]) = (_account(), _is(USDC), _any());
        _installRules(COMET, fs, USDC, 100e6, 300e6);
        deal(USDC, acct, 1_000e6);
        return true;
    }

    function test_recipe_compoundTo_theAgentSuppliesAndWithdrawsForTheAccount() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        _send(_call(abi.encodeWithSelector(SUPPLY_TO, acct, USDC, uint256(100e6))));
        assertApproxEqAbs(_bal(COMET, acct), 100e6, 2, "the supply is the account's");
        assertEq(_spent(), 100e6);
        _send(_call(abi.encodeWithSelector(WITHDRAW_TO, acct, USDC, uint256(40e6))));
        assertEq(_bal(USDC, acct), 940e6);
        // for somebody else, and to somebody else
        _expectRefused(_call(abi.encodeWithSelector(SUPPLY_TO, other, USDC, uint256(10e6))));
        _expectRefused(_call(abi.encodeWithSelector(WITHDRAW_TO, other, USDC, uint256(10e6))));
        assertEq(_bal(COMET, other), 0);
        assertEq(_bal(USDC, other), 0);
    }
}
