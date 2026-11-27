// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {ITokenForRecipes} from "./ProtocolRecipes.t.sol";
import {AllowListOnEthereum, RulesOnEthereum, VaultByRules} from "./MoreRecipes.t.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";

/// Further recipes of `docs/DAPPS.md`, each run against the protocol's own
/// code on a fork of Ethereum (issue #80): withdrawals that take two steps
/// and a wait, two more kinds of Curve pool, a liquidity position, and
/// three more vaults. Without the chain's RPC in the environment every test
/// here is skipped, so CI runs none of them.
///
///   FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> \
///     forge test --evm-version osaka --match-path test/FurtherRecipes.t.sol --match-test 'test_recipe|test_real'

// ---------------------------------------------------------------------------
// With the mandate as it is: an allow-list and limits
// ---------------------------------------------------------------------------

/// Lido's withdrawal queue, the second step: `claimWithdrawal(uint256)` and
/// `claimWithdrawals(uint256[],uint256[])` pay a finalized request's ether
/// to its owner, who has to be the caller. `claimWithdrawalsTo` names a
/// recipient and stays off the mandate.
contract LidoClaimRecipeTest is AllowListOnEthereum {
    address internal constant QUEUE = 0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1;
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    bytes4 internal constant CLAIM = 0xf8444436; // claimWithdrawal(uint256)
    bytes4 internal constant CLAIM_MANY = 0xe3afe0a3; // claimWithdrawals(uint256[],uint256[])

    function _mandate() internal override {
        _allow(QUEUE, CLAIM);
        _allow(QUEUE, CLAIM_MANY);
    }

    /// The owner's doing: a stake, and a request for the withdrawal of 0.1 stETH.
    function _aRequest() internal returns (uint256 id) {
        uint256[] memory one = new uint256[](1);
        one[0] = 0.1 ether;
        vm.startPrank(acct);
        (bool staked,) = STETH.call{value: 0.2 ether}(abi.encodeWithSignature("submit(address)", address(0)));
        ITokenForRecipes(STETH).approve(QUEUE, 0.1 ether);
        (bool asked,) = QUEUE.call(abi.encodeWithSignature("requestWithdrawals(uint256[],address)", one, acct));
        vm.stopPrank();
        require(staked && asked, "Lido refused the owner's setup");
        (, bytes memory data) = QUEUE.staticcall(abi.encodeWithSignature("getWithdrawalRequests(address)", acct));
        uint256[] memory ids = abi.decode(data, (uint256[]));
        id = ids[ids.length - 1];
    }

    /// Lido's own step, made here in Lido's name: every request up to the
    /// last is finalized, with the ether it is owed and no discount.
    function _finalized() internal {
        (, bytes memory last) = QUEUE.staticcall(abi.encodeWithSignature("getLastRequestId()"));
        (, bytes memory owed) = QUEUE.staticcall(abi.encodeWithSignature("unfinalizedStETH()"));
        uint256 amount = abi.decode(owed, (uint256));
        vm.deal(STETH, STETH.balance + amount);
        vm.prank(STETH);
        (bool ok,) = QUEUE.call{value: amount}(
            abi.encodeWithSignature("finalize(uint256,uint256)", abi.decode(last, (uint256)), uint256(1e36))
        );
        require(ok, "Lido's queue refused the finalization");
    }

    function test_recipe_lidoClaim_theAgentClaimsTheAccountsWithdrawal() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 id = _aRequest();
        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        uint256[] memory hints = new uint256[](1);
        hints[0] = 1;
        // before Lido finalizes it there is nothing to claim: the queue refuses, in execution
        uint256 early = acct.balance;
        _do(QUEUE, 0, abi.encodeWithSelector(CLAIM, id));
        assertLe(acct.balance, early, "nothing is paid before the finalization");
        _finalized();
        // the form that names a recipient is not listed
        _refused(
            QUEUE, 0, abi.encodeWithSignature("claimWithdrawalsTo(uint256[],uint256[],address)", ids, hints, other)
        );
        uint256 before = acct.balance;
        _do(QUEUE, 0, abi.encodeWithSelector(CLAIM, id));
        // 0.1 ether, less the operation's gas, which the account pays
        assertGt(acct.balance, before + 0.09 ether, "the ether is the account's");
        assertEq(other.balance, 0);
    }

    /// Why the two forms can be listed as they are: the queue pays a
    /// request's owner and takes the claim from nobody else.
    function test_real_lidoClaim_onlyTheOwnerClaimsAndIsPaid() public {
        if (!_onEthereum()) return;
        address stranger = makeAddr("stranger");
        uint256 id = _aRequest();
        _finalized();
        vm.prank(stranger);
        (bool taken,) = QUEUE.call(abi.encodeWithSelector(CLAIM, id));
        assertFalse(taken, "a stranger cannot claim the account's request");
        uint256 before = acct.balance;
        vm.prank(acct);
        (bool ok,) = QUEUE.call(abi.encodeWithSelector(CLAIM, id));
        assertTrue(ok);
        assertApproxEqAbs(acct.balance, before + 0.1 ether, 10, "the owner is paid the request's ether");
        assertEq(stranger.balance, 0);
    }
}

/// EigenLayer, the way out: `queueWithdrawals` takes the caller's own
/// shares into a withdrawal of the caller's, and after the delay
/// `completeQueuedWithdrawal` pays the tokens to the caller, who has to be
/// the withdrawal's own withdrawer. `delegateTo` stays off the mandate.
contract EigenLayerWithdrawalRecipeTest is AllowListOnEthereum {
    address internal constant STRATEGY_MANAGER = 0x858646372CC42E1A627fcE94aa7A7033e7CF075A;
    address internal constant DELEGATION_MANAGER = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
    address internal constant STETH_STRATEGY = 0x93c4b944D05dfe6df7645A86cd2206016c51564D;
    address internal constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    bytes4 internal constant DEPOSIT = 0xe7a050aa; // depositIntoStrategy(address,address,uint256)
    bytes4 internal constant QUEUE = 0x0dd8dd02; // queueWithdrawals((address[],uint256[],address)[])
    // completeQueuedWithdrawal((address,address,address,uint256,uint32,address[],uint256[]),address[],bool)
    bytes4 internal constant COMPLETE = 0xe4cc3f90;

    struct QueuedWithdrawalParams {
        address[] strategies;
        uint256[] depositShares;
        address withdrawer;
    }

    struct Withdrawal {
        address staker;
        address delegatedTo;
        address withdrawer;
        uint256 nonce;
        uint32 startBlock;
        address[] strategies;
        uint256[] scaledShares;
    }

    function _mandate() internal override {
        _limit(STETH, 1 ether, 3 ether);
        _allow(STRATEGY_MANAGER, DEPOSIT);
        _allow(DELEGATION_MANAGER, QUEUE);
        _allow(DELEGATION_MANAGER, COMPLETE);
    }

    function _shares(address who) internal view returns (uint256 shares) {
        (bool ok, bytes memory data) = STETH_STRATEGY.staticcall(abi.encodeWithSignature("shares(address)", who));
        require(ok, "the strategy does not answer shares(address)");
        shares = abi.decode(data, (uint256));
    }

    function _queue(uint256 shares, address withdrawer) internal pure returns (bytes memory) {
        QueuedWithdrawalParams[] memory p = new QueuedWithdrawalParams[](1);
        p[0].strategies = new address[](1);
        p[0].strategies[0] = STETH_STRATEGY;
        p[0].depositShares = new uint256[](1);
        p[0].depositShares[0] = shares;
        p[0].withdrawer = withdrawer;
        return abi.encodeWithSelector(QUEUE, p);
    }

    function _queued(address who) internal view returns (Withdrawal[] memory withdrawals) {
        (bool ok, bytes memory data) =
            DELEGATION_MANAGER.staticcall(abi.encodeWithSignature("getQueuedWithdrawals(address)", who));
        require(ok, "the delegation manager does not answer getQueuedWithdrawals(address)");
        (withdrawals,) = abi.decode(data, (Withdrawal[], uint256[][]));
    }

    function _delay() internal view returns (uint256 blocks) {
        (, bytes memory data) = DELEGATION_MANAGER.staticcall(abi.encodeWithSignature("minWithdrawalDelayBlocks()"));
        blocks = abi.decode(data, (uint32));
    }

    /// The delay is counted in blocks. After a fork is moved that far
    /// forward, forge 1.8.5 stalls on every later call under the Osaka
    /// rules and does not under Cancun's, so the step is made under
    /// Cancun's. The account's P-256 check then goes through the verifier
    /// contract on the chain, in place of the precompile.
    function _afterTheDelay() internal {
        vm.setEvmVersion("cancun");
        vm.roll(block.number + _delay() + 1);
    }

    /// The account holds stETH (staked by its owner) and the agent has restaked 0.05 of it.
    function _restaked() internal returns (uint256 shares) {
        vm.prank(acct);
        (bool staked,) = STETH.call{value: 0.1 ether}(abi.encodeWithSignature("submit(address)", address(0)));
        require(staked, "Lido refused the stake");
        _doPulling(
            STETH,
            STRATEGY_MANAGER,
            0.05 ether,
            STRATEGY_MANAGER,
            abi.encodeWithSelector(DEPOSIT, STETH_STRATEGY, STETH, 0.05 ether)
        );
        shares = _shares(acct);
        assertGt(shares, 0);
    }

    function test_recipe_eigenLayer_theAgentWithdraws() public {
        if (!_onEthereum()) return;
        uint256 shares = _restaked();
        uint256 held = _bal(STETH, acct);
        _do(DELEGATION_MANAGER, 0, _queue(shares, acct));
        assertEq(_shares(acct), 0, "the shares left the deposit");
        Withdrawal[] memory ws = _queued(acct);
        assertEq(ws.length, 1, "one withdrawal is queued");
        assertEq(ws[0].staker, acct);
        assertEq(ws[0].withdrawer, acct, "the withdrawal is the account's");
        address[] memory tokens = new address[](1);
        tokens[0] = STETH;
        // before the delay has passed EigenLayer pays nothing
        _do(DELEGATION_MANAGER, 0, abi.encodeWithSelector(COMPLETE, ws[0], tokens, true));
        assertApproxEqAbs(_bal(STETH, acct), held, 2, "nothing is paid before the delay");
        _afterTheDelay();
        _do(DELEGATION_MANAGER, 0, abi.encodeWithSelector(COMPLETE, ws[0], tokens, true));
        assertApproxEqAbs(_bal(STETH, acct), held + 0.05 ether, 10, "the stETH is back in the account");
        assertEq(_queued(acct).length, 0);
        // delegation to an operator is not listed
        _refused(
            DELEGATION_MANAGER,
            0,
            abi.encodeWithSignature(
                "delegateTo(address,(bytes,uint256),bytes32)", makeAddr("operator"), bytes(""), uint256(0), bytes32(0)
            )
        );
    }

    /// Why any arguments are safe: the field that names a withdrawer does
    /// not move the withdrawal to anybody else, and a stranger cannot
    /// complete the account's withdrawal.
    function test_real_eigenLayer_aWithdrawalIsItsStakers() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 shares = _restaked();
        vm.prank(acct);
        (bool ok,) = DELEGATION_MANAGER.call(_queue(shares, other));
        if (!ok) {
            // refused outright: nothing was queued for anybody
            assertEq(_queued(other).length, 0);
            assertEq(_shares(acct), shares);
            return;
        }
        Withdrawal[] memory ws = _queued(acct);
        assertEq(ws.length, 1);
        assertEq(ws[0].withdrawer, acct, "the field is ignored: the withdrawer is the staker");
        assertEq(_queued(other).length, 0);
        address[] memory tokens = new address[](1);
        tokens[0] = STETH;
        _afterTheDelay();
        vm.prank(other);
        (bool taken,) = DELEGATION_MANAGER.call(abi.encodeWithSelector(COMPLETE, ws[0], tokens, true));
        assertFalse(taken, "nobody else completes it");
        assertEq(_bal(STETH, other), 0);
    }
}

/// Two more kinds of Curve pool. A crypto pool (tricrypto2: USDT, WBTC,
/// WETH) takes `exchange(uint256,uint256,uint256,uint256)`; a
/// stableswap-ng pool (PYUSD, USDC) takes the classic
/// `exchange(int128,int128,uint256,uint256)`. Both pay their caller. Each
/// has a variant the mandate leaves out: the crypto pool's with a flag for
/// native ether, the ng pool's with a receiver.
contract CurveMorePoolsRecipeTest is AllowListOnEthereum {
    address internal constant TRICRYPTO = 0xD51a44d3FaE010294C616388b506AcdA1bfAAE46;
    address internal constant PAYPOOL = 0x383E6b4437b59fff47B619CBA855CA29342A8559;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant PYUSD = 0x6c3ea9036406852006290770BEdFcAbA0e23A0e8;
    bytes4 internal constant EXCHANGE_CRYPTO = 0x5b41b908; // exchange(uint256,uint256,uint256,uint256)
    bytes4 internal constant EXCHANGE = 0x3df02124; // exchange(int128,int128,uint256,uint256)

    function _mandate() internal override {
        _limit(WETH, 0.1 ether, 0.3 ether);
        _limit(USDC, 100e6, 300e6);
        _allow(TRICRYPTO, EXCHANGE_CRYPTO);
        _allow(PAYPOOL, EXCHANGE);
    }

    function test_recipe_curveCrypto_theAgentSwaps() public {
        if (!_onEthereum()) return;
        deal(WETH, acct, 1 ether);
        // 0.1 WETH (coin 2) for USDT (coin 0)
        _doPulling(
            WETH,
            TRICRYPTO,
            0.1 ether,
            TRICRYPTO,
            abi.encodeWithSelector(EXCHANGE_CRYPTO, uint256(2), uint256(0), uint256(0.1 ether), uint256(0))
        );
        assertGt(_bal(USDT, acct), 0, "the USDT is the account's");
        assertEq(_bal(WETH, acct), 0.9 ether);
        assertEq(_spent(WETH), 0.1 ether);
        assertEq(ITokenForRecipes(WETH).allowance(acct, TRICRYPTO), 0, "no allowance stands");
        // the form with a flag for native ether is not listed
        _expectRefused(
            _agentBatchWith(
                AGENT,
                ID,
                _pulling(
                    WETH,
                    TRICRYPTO,
                    0.1 ether,
                    TRICRYPTO,
                    abi.encodeWithSignature(
                        "exchange(uint256,uint256,uint256,uint256,bool)",
                        uint256(2),
                        uint256(0),
                        uint256(0.1 ether),
                        uint256(0),
                        true
                    )
                )
            )
        );
    }

    function test_recipe_curveNg_theAgentSwaps() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        deal(USDC, acct, 1_000e6);
        // 100 USDC (coin 1) for PYUSD (coin 0), at least 99
        _doPulling(
            USDC,
            PAYPOOL,
            100e6,
            PAYPOOL,
            abi.encodeWithSelector(EXCHANGE, int128(1), int128(0), uint256(100e6), uint256(99e6))
        );
        assertGt(_bal(PYUSD, acct), 99e6, "the PYUSD is the account's");
        assertEq(_bal(USDC, acct), 900e6);
        assertEq(_spent(USDC), 100e6);
        // the form with a receiver is not listed
        _expectRefused(
            _agentBatchWith(
                AGENT,
                ID,
                _pulling(
                    USDC,
                    PAYPOOL,
                    100e6,
                    PAYPOOL,
                    abi.encodeWithSignature(
                        "exchange(int128,int128,uint256,uint256,address)",
                        int128(1),
                        int128(0),
                        uint256(100e6),
                        uint256(0),
                        other
                    )
                )
            )
        );
        assertEq(_bal(PYUSD, other), 0);
    }

    /// Why the form with a receiver is left out: the pool pays whoever is named.
    function test_real_curveNg_theReceiverFormPaysWhoeverIsNamed() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        deal(USDC, acct, 1_000e6);
        vm.startPrank(acct);
        ITokenForRecipes(USDC).approve(PAYPOOL, 10e6);
        (bool ok,) = PAYPOOL.call(
            abi.encodeWithSignature(
                "exchange(int128,int128,uint256,uint256,address)",
                int128(1),
                int128(0),
                uint256(10e6),
                uint256(0),
                other
            )
        );
        vm.stopPrank();
        assertTrue(ok);
        assertGt(_bal(PYUSD, other), 0);
        assertEq(_bal(PYUSD, acct), 0);
    }
}

// ---------------------------------------------------------------------------
// With a rule for each argument (`CallRulesDecoder`)
// ---------------------------------------------------------------------------

/// A liquidity position at Uniswap v3's position manager. `mint` with the
/// pool (both tokens and the fee), the range and the recipient set; the
/// first token's amount is charged, the second token's is held by a bound
/// on its word and by the allowance the owner gave for it. `collect` with
/// the recipient the account. `decreaseLiquidity` names nobody: what it
/// frees stays owed to the position until it is collected.
/// `increaseLiquidity` is left out: it adds the caller's tokens to any
/// position, whoever owns it.
contract UniswapPositionRecipeTest is RulesOnEthereum {
    address internal constant MANAGER = 0xC36442b4a4522E871399CD717aBDD847Ab11FE88;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    uint24 internal constant FEE = 500;
    /// The widest range of a pool whose ticks are spaced by 10.
    int24 internal constant LOWER = -887270;
    int24 internal constant UPPER = 887270;
    /// The most of the second token one `mint` may ask for.
    uint256 internal constant WETH_BOUND = 0.1 ether;
    // mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))
    bytes4 internal constant MINT = 0x88316456;
    bytes4 internal constant COLLECT = 0xfc6f7865; // collect((uint256,address,uint128,uint128))
    bytes4 internal constant DECREASE = 0x0c49ccbe; // decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))
    bytes4 internal constant INCREASE = 0x219f5d17; // increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))

    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](3);
        fs[0].selector = MINT;
        fs[0].words = new CallRulesDecoder.Word[](11);
        fs[0].words[0] = _is(USDC);
        fs[0].words[1] = _is(WETH);
        fs[0].words[2] = _is(uint256(FEE));
        // a tick is a signed number: its word is the two's complement
        fs[0].words[3] = _is(uint256(int256(LOWER)));
        fs[0].words[4] = _is(uint256(int256(UPPER)));
        fs[0].words[5] = _charged(USDC); // the most of the first token the mint takes
        fs[0].words[6] = _atMost(WETH_BOUND); // the most of the second
        fs[0].words[7] = _any(); // the least of each the agent accepts
        fs[0].words[8] = _any();
        fs[0].words[9] = _account(); // the position is the account's
        fs[0].words[10] = _any(); // a deadline
        fs[1].selector = COLLECT;
        fs[1].words = new CallRulesDecoder.Word[](4);
        fs[1].words[0] = _any(); // the position: the manager takes it from its owner only
        fs[1].words[1] = _account(); // to the account
        fs[1].words[2] = _any();
        fs[1].words[3] = _any();
        fs[2].selector = DECREASE;
        fs[2].words = new CallRulesDecoder.Word[](5);
        for (uint256 i; i < 5; ++i) {
            fs[2].words[i] = _any();
        }
        _installRules(MANAGER, fs, USDC, 100e6, 300e6);
        deal(USDC, acct, 1_000e6);
        deal(WETH, acct, 1 ether);
        // the second token is not charged by the policy: the owner's allowance for it is its budget
        vm.prank(acct);
        ITokenForRecipes(WETH).approve(MANAGER, 3 * WETH_BOUND);
        return true;
    }

    function _mint(MintParams memory p) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MINT, p);
    }

    function _params(address recipient) internal view returns (MintParams memory) {
        return MintParams(USDC, WETH, FEE, LOWER, UPPER, 100e6, WETH_BOUND, 0, 0, recipient, block.timestamp + 1 hours);
    }

    function _positions(address who) internal view returns (uint256) {
        return ITokenForRecipes(MANAGER).balanceOf(who);
    }

    function _positionOf(address who) internal view returns (uint256 id) {
        (, bytes memory data) =
            MANAGER.staticcall(abi.encodeWithSignature("tokenOfOwnerByIndex(address,uint256)", who, uint256(0)));
        id = abi.decode(data, (uint256));
    }

    function _liquidity(uint256 id) internal view returns (uint128 liquidity) {
        (bool ok, bytes memory data) = MANAGER.staticcall(abi.encodeWithSignature("positions(uint256)", id));
        require(ok, "no such position");
        (,,,,,,, liquidity,,,,) = abi.decode(
            data, (uint96, address, address, address, uint24, int24, int24, uint128, uint256, uint256, uint128, uint128)
        );
    }

    function test_recipe_uniswapPosition_theAgentProvidesAndTakesBack() public {
        if (!_onEthereum()) return;
        _send(_call(_mint(_params(acct))));
        assertEq(_positions(acct), 1, "the position is the account's");
        uint256 id = _positionOf(acct);
        uint128 liquidity = _liquidity(id);
        assertGt(liquidity, 0);
        assertEq(_spent(), 100e6, "the first token's most is charged");
        assertGe(_bal(USDC, acct), 900e6);
        assertGe(_bal(WETH, acct), 1 ether - WETH_BOUND, "the second token within its bound");
        assertLt(_bal(USDC, acct) + _bal(WETH, acct), 1_000e6 + 1 ether, "tokens went into the pool");
        // all of the liquidity out, then collected to the account
        _send(_call(abi.encodeWithSelector(DECREASE, id, liquidity, uint256(0), uint256(0), block.timestamp + 1 hours)));
        _send(_call(abi.encodeWithSelector(COLLECT, id, acct, type(uint128).max, type(uint128).max)));
        assertEq(_liquidity(id), 0);
        assertApproxEqAbs(_bal(USDC, acct), 1_000e6, 5, "the first token is back");
        assertApproxEqAbs(_bal(WETH, acct), 1 ether, 1e9, "the second token is back");
        assertEq(_spent(), 100e6);
    }

    function test_recipe_uniswapPosition_whatTheRulesRefuse() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        _send(_call(_mint(_params(acct))));
        uint256 id = _positionOf(acct);
        // a position for somebody else
        _expectRefused(_call(_mint(_params(other))));
        // another pool: another second token, another fee
        MintParams memory p = _params(acct);
        p.token1 = other;
        _expectRefused(_call(_mint(p)));
        p = _params(acct);
        p.fee = 3000;
        _expectRefused(_call(_mint(p)));
        // another range
        p = _params(acct);
        p.tickLower = -887260;
        _expectRefused(_call(_mint(p)));
        // more of the second token than its bound; more of the first than its cap
        p = _params(acct);
        p.amount1Desired = WETH_BOUND + 1;
        _expectRefused(_call(_mint(p)));
        p = _params(acct);
        p.amount0Desired = 100e6 + 1;
        _expectRefused(_call(_mint(p)));
        // what the position earned, to somebody else
        _expectRefused(_call(abi.encodeWithSelector(COLLECT, id, other, type(uint128).max, type(uint128).max)));
        // not listed: adding to a position, and the position's own transfer and approval
        _expectRefused(
            _call(
                abi.encodeWithSelector(
                    INCREASE, id, uint256(10e6), uint256(0.01 ether), uint256(0), uint256(0), block.timestamp
                )
            )
        );
        _expectRefused(_call(abi.encodeWithSignature("transferFrom(address,address,uint256)", acct, other, id)));
        _expectRefused(_call(abi.encodeWithSignature("approve(address,uint256)", other, id)));
        assertEq(_positions(other), 0);
        assertEq(_positions(acct), 1);
        assertEq(_spent(), 100e6);
    }

    /// Why `increaseLiquidity` is left out: the manager takes the caller's
    /// tokens into any position, whoever owns it.
    function test_real_uniswapPosition_anIncreaseFeedsAnybodysPosition() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        deal(USDC, other, 100e6);
        deal(WETH, other, 0.1 ether);
        vm.startPrank(other);
        ITokenForRecipes(USDC).approve(MANAGER, 100e6);
        ITokenForRecipes(WETH).approve(MANAGER, 0.1 ether);
        (bool minted,) = MANAGER.call(_mint(_params(other)));
        vm.stopPrank();
        assertTrue(minted);
        uint256 id = _positionOf(other);
        uint128 before = _liquidity(id);
        uint256 held = _bal(USDC, acct) + _bal(WETH, acct);
        vm.prank(acct);
        (bool ok,) = MANAGER.call(
            abi.encodeWithSelector(
                INCREASE, id, uint256(10e6), uint256(0.01 ether), uint256(0), uint256(0), block.timestamp
            )
        );
        assertTrue(ok, "the account can add to a position that is not its own");
        assertGt(_liquidity(id), before);
        assertLt(_bal(USDC, acct) + _bal(WETH, acct), held, "and its tokens are in it");
    }
}

/// A Yearn v3 vault (USDC-1).
contract YearnVaultRecipeTest is VaultByRules {
    function _vault() internal pure override returns (address, uint256) {
        return (0xBe53A109B494E5c9f97b9Cd39Fe969BE68BF6204, 1e6);
    }
}

/// Aave's wrapped aToken for USDC (a stata token).
contract AaveStataVaultRecipeTest is VaultByRules {
    function _vault() internal pure override returns (address, uint256) {
        return (0xD4fa2D31b7968E448877f69A96DE69f5de8cD23E, 1e6);
    }
}

/// Ethena's staked USDe. Its `redeem` and `withdraw` work while its
/// cooldown is set to zero, as it was at the time of writing; with a
/// cooldown set, leaving goes by `cooldownShares` and `unstake(receiver)`,
/// which this recipe does not hold.
contract StakedUsdeVaultRecipeTest is VaultByRules {
    function _vault() internal pure override returns (address, uint256) {
        return (0x9D39A5DE30e57443BfF2A8307A4256c8797A3497, 1 ether);
    }
}

/// ether.fi's way out, the first step: `requestWithdraw(recipient, amount)`
/// at the liquidity pool takes eETH from its caller and gives the request,
/// an NFT, to `recipient`. The rules hold the recipient to the account; the
/// amount is charged.
contract EtherFiRequestRecipeTest is RulesOnEthereum {
    address internal constant POOL = 0x308861A430be4cce5502d0A12724771Fc6DaF216;
    address internal constant EETH = 0x35fA164735182de50811E8e2E824cFb9B6118ac2;
    /// The contract that holds the requests, each an NFT.
    address internal constant REQUESTS = 0x7d5706f6ef3F89B3951E23e557CDFBC3239D4E2c;
    bytes4 internal constant REQUEST = 0x397a1b28; // requestWithdraw(address,uint256)

    function _onEthereum() internal returns (bool) {
        if (!_fork("FORK_ETHEREUM_RPC_URL", 1)) return false;
        // the account holds eETH: staked by its owner
        vm.deal(acct, acct.balance + 1 ether);
        vm.prank(acct);
        (bool staked,) = POOL.call{value: 0.5 ether}(abi.encodeWithSignature("deposit()"));
        require(staked, "ether.fi refused the stake");
        CallRulesDecoder.Function[] memory fs = new CallRulesDecoder.Function[](1);
        fs[0].selector = REQUEST;
        fs[0].words = new CallRulesDecoder.Word[](2);
        (fs[0].words[0], fs[0].words[1]) = (_account(), _charged(EETH));
        _installRules(POOL, fs, EETH, 0.1 ether, 0.3 ether);
        return true;
    }

    function test_recipe_etherFiRequest_theAgentAsksForAWithdrawal() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 held = _bal(EETH, acct);
        _send(_call(abi.encodeWithSelector(REQUEST, acct, uint256(0.1 ether))));
        assertEq(_bal(REQUESTS, acct), 1, "the request is the account's");
        assertApproxEqAbs(_bal(EETH, acct), held - 0.1 ether, 4);
        assertEq(_spent(), 0.1 ether, "charged");
        // a request for somebody else; over the cap
        _expectRefused(_call(abi.encodeWithSelector(REQUEST, other, uint256(0.1 ether))));
        _expectRefused(_call(abi.encodeWithSelector(REQUEST, acct, uint256(0.1 ether + 1))));
        assertEq(_bal(REQUESTS, other), 0);
    }

    /// Why the recipient is held: the pool gives the request to whoever is named.
    function test_real_etherFiRequest_theRequestGoesToWhoeverIsNamed() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        vm.prank(acct);
        (bool ok,) = POOL.call(abi.encodeWithSelector(REQUEST, other, uint256(0.1 ether)));
        assertTrue(ok);
        assertEq(_bal(REQUESTS, other), 1);
        assertEq(_bal(REQUESTS, acct), 0);
    }
}

/// ether.fi's way out, the second step: `claimWithdraw(uint256)` and
/// `batchClaimWithdraw(uint256[])` pay a finalized request's ether to the
/// request's owner, whoever calls.
contract EtherFiClaimRecipeTest is AllowListOnEthereum {
    address internal constant POOL = 0x308861A430be4cce5502d0A12724771Fc6DaF216;
    address internal constant EETH = 0x35fA164735182de50811E8e2E824cFb9B6118ac2;
    address internal constant REQUESTS = 0x7d5706f6ef3F89B3951E23e557CDFBC3239D4E2c;
    bytes4 internal constant CLAIM = 0xb13acedd; // claimWithdraw(uint256)
    bytes4 internal constant CLAIM_MANY = 0x24fccdcf; // batchClaimWithdraw(uint256[])

    function _mandate() internal override {
        _allow(REQUESTS, CLAIM);
        _allow(REQUESTS, CLAIM_MANY);
    }

    /// The owner's doing: a stake, and a request for the withdrawal of 0.1 eETH.
    function _aRequest() internal returns (uint256 id) {
        vm.startPrank(acct);
        (bool staked,) = POOL.call{value: 0.5 ether}(abi.encodeWithSignature("deposit()"));
        ITokenForRecipes(EETH).approve(POOL, 0.1 ether);
        (bool asked, bytes memory data) =
            POOL.call(abi.encodeWithSignature("requestWithdraw(address,uint256)", acct, uint256(0.1 ether)));
        vm.stopPrank();
        require(staked && asked, "ether.fi refused the owner's setup");
        id = abi.decode(data, (uint256));
    }

    /// ether.fi's own step, made here in the name of its admin contract.
    function _finalized(uint256 id) internal {
        (, bytes memory data) = REQUESTS.staticcall(abi.encodeWithSignature("etherFiAdmin()"));
        vm.prank(abi.decode(data, (address)));
        (bool ok,) = REQUESTS.call(abi.encodeWithSignature("finalizeRequests(uint256)", id));
        require(ok, "ether.fi refused the finalization");
    }

    function test_recipe_etherFiClaim_theAgentClaimsTheAccountsWithdrawal() public {
        if (!_onEthereum()) return;
        address other = makeAddr("other");
        uint256 id = _aRequest();
        _finalized(id);
        // not listed: the request's own transfer, and a new request, which names a recipient
        _refused(REQUESTS, 0, abi.encodeWithSignature("transferFrom(address,address,uint256)", acct, other, id));
        _refused(POOL, 0, abi.encodeWithSignature("requestWithdraw(address,uint256)", other, uint256(0.1 ether)));
        uint256 before = acct.balance;
        _do(REQUESTS, 0, abi.encodeWithSelector(CLAIM, id));
        // 0.1 ether, less a rounding and the operation's gas, which the account pays
        assertGt(acct.balance, before + 0.09 ether, "the ether is the account's");
        assertEq(_bal(REQUESTS, acct), 0, "the request is spent");
        assertEq(other.balance, 0);
    }

    /// Why the two forms can be listed as they are: whoever makes the
    /// claim, the request's ether goes to the request's owner.
    function test_real_etherFiClaim_aClaimPaysTheRequestsOwner() public {
        if (!_onEthereum()) return;
        address stranger = makeAddr("stranger");
        uint256 id = _aRequest();
        _finalized(id);
        uint256 before = acct.balance;
        vm.prank(stranger);
        (bool ok,) = REQUESTS.call(abi.encodeWithSelector(CLAIM, id));
        if (!ok) {
            // a claim by anybody else is refused: the owner claims
            vm.prank(acct);
            (ok,) = REQUESTS.call(abi.encodeWithSelector(CLAIM, id));
        }
        assertTrue(ok);
        assertApproxEqAbs(acct.balance, before + 0.1 ether, 1e9, "the owner is paid the request's ether");
        assertEq(stranger.balance, 0, "and nobody else is");
        assertEq(_bal(REQUESTS, acct), 0, "the request is spent");
    }
}
