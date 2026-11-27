# What an agent can do at well-known protocols

An agent's key signs only what its mandate allows. This page says, protocol
by protocol, which calls an owner can put on a mandate today, which need
more than the mandate has, and which should never be given to an agent. It
is the working list of
[issue #80](https://github.com/postcryptum-research/agent-keys/issues/80).

`[V]` is verified with the source given, `[I]` is inferred. Dates are UTC.
Everything here is on test networks or read from sources: nothing below is
advice to put money behind an unaudited policy.

## The one question

The mandate allows calls by `(contract, function)` and does not read their
arguments, with three exceptions: a token with a limit (its `transfer`,
`approve` and their kin are counted), native value, and what a trading
venue's decoder judged: an order, or a call
([`AGENT_CONFIG.md`](AGENT_CONFIG.md)).

So for a function of some protocol the question is one:

> **Whatever its arguments, do its effects land on the account that calls it?**

- **Yes:** it takes at most what the account approved in the same
  operation, or the value sent, and credits or pays the caller. It can go
  on a mandate as it is.
- **No:** it has a `receiver`, `to`, `onBehalfOf`, `owner` or `recipient`
  argument, and an agent could name another address. It goes through a
  venue's decoder that holds that argument to the account: the policy
  admits a call a decoder judged. The swap and the calls with a rule for
  each argument, below, are such decoders.

## How an agent uses a protocol that pulls tokens

A lending pool or a staking contract takes tokens through an allowance. The
mandate accepts an approval only with its withdrawal in the same operation,
so that no allowance outlives the operation. A supply is therefore three
calls in one operation: the allowance, the call that uses it, the allowance
taken back. `op batch` sends them:

```sh
agent-signer op batch --agent agent.json \
    --allow <token>:<pool>:<amount> \
    --call  <pool>:0:<calldata of the supply>
```

- **`--allow <token>:<spender>:<amount>`** opens the operation with
  `approve(spender, amount)` and closes it with `approve(spender, 0)`.
- **`--call <target>:<wei>:<calldata>`** is one call; repeat it for several.
- **All or nothing:** the mandate judges every call, and one refused call
  refuses the operation.
- **What is charged:** the amount allowed, to the token's `maxPerOp` and
  budget, whether or not the protocol takes all of it. A withdrawal gives
  nothing back to the budget: the budget is what the agent may move, not
  what it may hold in the protocol. With a `period` it renews.
- **In the config,** the token's `approve` is named in `allow` like any
  other call (`{"target": <token>, "selector": "0x095ea7b3"}`), and the
  token has an entry in `tokens` with its limit.

[V `a_batch_gives_an_allowance_for_one_operation` in the CLI's local-chain
tests: the allowance, a pull by a stand-in pool, the allowance back; an
allowance left standing, a call outside the mandate and an amount over the
cap are each refused.]

## Works with the mandate as it is

Each row was read in the protocol's source or its verified deployed source
on 2026-11-26. A row is `[V]` when a test here runs it against the
protocol's own code; the others are `[I]` until their test exists.

| Protocol | What to allow | Where | Status |
|---|---|---|---|
| **Aave V3** | the pool's compact forms `supply(bytes32)` `0xf7a73840`, `withdraw(bytes32)` `0x8e19899e`, `repay(bytes32)` `0x563dd613`: the pool uses its own caller as beneficiary | Base, Arbitrum, Base Sepolia (the pools there are L2 pools); on Ethereum, BNB Chain and Sepolia the pool has no compact forms, and Aave goes by rules (the table of networks below) | **[V]** on Base Sepolia, see below |
| **Aave V3** | `repayWithATokens(asset, amount, rateMode)` `0x2dad97d4`: the caller's own debt, paid with its own aTokens | every chain | **[V]** on Ethereum, see below; rewards `claimRewardsToSelf`, `claimAllRewardsToSelf` [I] |
| **Compound v3** | `supply(address,uint256)` `0xf2b9fdb8`, `withdraw(address,uint256)` `0xf3fef3a3`, with the base token's `approve` and a limit for it; rewards `claim(comet, src, shouldAccrue)` `0xb7034f7e` | Ethereum, Base, Arbitrum, Sepolia, Base Sepolia | **[V]** on Base Sepolia; the rewards claim **[V]** on Ethereum, see below |
| **Lido** | `submit(address)` `0xa1903eab` (stake), under the native cap and budget; or a plain transfer of ether to wstETH, which stakes and wraps in one; wstETH `wrap` `0xea598cb0` and `unwrap` `0xde0e9a3e` | Ethereum | **[V]** on Ethereum, see below; `claimWithdrawals`, `claimWithdrawal` [I] |
| **Rocket Pool** | the deposit pool's `deposit()` `0xd0e30db0`, rETH `burn(uint256)` `0x42966c68` | Ethereum | **[V]**, see below |
| **ether.fi** | the pool's `deposit()` `0xd0e30db0`, weETH `wrap` and `unwrap` | Ethereum | **[V]**, see below; `deposit(address)`, `claimWithdraw` [I] |
| **EigenLayer** | `depositIntoStrategy` `0xe7a050aa` | Ethereum, Sepolia | **[V]** on Ethereum, see below; `queueWithdrawals`, `completeQueuedWithdrawal` [I] |
| **Sky** | staking rewards `stake` `0xa694fc3a`, `withdraw` `0x2e1a7d4d`, `getReward` `0x3d18b912`, `exit` `0xe9fad8ee` | Ethereum | **[V]**, see below |
| **Curve** | a classic pool's `exchange` `0x3df02124`, `add_liquidity` `0x4515cef3`, `remove_liquidity` `0xecb586a5` | per pool | **[V]** for the 3pool, see below; other pools and the variants [I] |
| Others | a Governor's `castVote`; a Merkle distributor's `claim`; a mint to the caller, under the native cap | per project | [I] |

Four things need a word of care:

- **Compound's `withdraw` borrows.** Asking for more of the base asset
  than the account supplied leaves a debt, while the account's collateral in
  that market covers it. With no collateral there it cannot borrow.
- **EigenLayer without `delegateTo`.** Deposits and withdrawals act on the
  caller; delegation to an operator exposes everything restaked to that
  operator's slashing, with no amount to bound it.
- **Curve's price is the agent's.** The minimum-out argument is the
  agent's own, so a bad trade loses up to what was allowed. The token's
  budget bounds it; nothing holds a price [V `CurveRecipeTest`: a least of
  nothing is accepted, and the budget stops the fourth trade].
- **A token with a limit has its metered functions and no other.** A
  protocol's own function on the token (Lido's `submit` on stETH) cannot be
  on a mandate that also gives that token a limit, which the allowance of
  a wrap needs: the policy does not install such a mandate [V
  `LidoSubmitWithALimitTest`]. Stake through the wrapper there (a plain
  transfer of ether to wstETH), or keep the two on separate mandates.

### Compound v3 and Lido, verified

[V `contracts/test/ProtocolRecipes.t.sol`, run on forks on 2026-11-26.]

- **Compound v3, the USDC market on Base Sepolia**
  (`0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017`): a supply of 100 USDC as
  three calls (the allowance, the supply, the allowance back) is the
  account's and is charged; 40 back by one call charges nothing.
  `supplyTo`, `withdrawTo` and `allow` are not listed and are refused. On
  the market's own code: a supply by another caller is credited to that
  caller, and a withdrawal of more than was supplied, with no collateral
  there, is refused by the market.
- **Lido on Ethereum** (`0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`):
  `submit` with the value of the native cap mints stETH to the account. The
  referral argument is the agent's to choose: the referral receives
  nothing. One wei over the cap, and the stETH's `transfer` or `approve`,
  are refused.

```sh
cd contracts
FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> \
    forge test --evm-version osaka --match-path test/ProtocolRecipes.t.sol --match-test 'test_recipe|test_real'
```

### Eight more by the allow-list, verified on Ethereum

[V `contracts/test/MoreRecipes.t.sol`, run on a fork of Ethereum on
2026-11-27. Where a protocol pulls a token, the agent's operation is three
calls: the allowance, the call, the allowance taken back.]

- **Lido's wrapper** (`0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0`): ether
  sent to wstETH is staked and wrapped for the sender (in the config a
  plain transfer is the selector `0x00000000` at the wrapper); `unwrap`
  gives the account stETH; `wrap` takes it back. The wstETH's and the
  stETH's `transfer`, an allowance left open, and `submit` on the limited
  stETH are refused.
- **ether.fi** (pool `0x308861A430be4cce5502d0A12724771Fc6DaF216`, weETH
  `0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee`): `deposit()` with value
  credits eETH to the account; `wrap` and `unwrap` act on it.
- **Rocket Pool** (rETH `0xae78736Cd615f374D3085123A210448E74Fc6393`; the
  deposit pool's address is read from Rocket Pool's storage contract
  `0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46`, and changes with its
  upgrades): `deposit()` mints rETH to the account; `burn` pays it ether.
- **EigenLayer** (strategy manager
  `0x858646372CC42E1A627fcE94aa7A7033e7CF075A`, the stETH strategy):
  `depositIntoStrategy` credits the shares to the account. `delegateTo` is
  not listed and is refused.
- **Sky's staking rewards** (`0x173e314C7635B45322cd8Cb14f44b312e079F3af`,
  USDS staked, SPK paid): `stake`, `withdraw`, `getReward` and `exit` act
  on the account, and a payout of SPK reached it; the farm credits its
  caller. A farm pays in periods its project renews: the farm that paid SKY
  (`0x0650CAF159C5A49f711e8169D4336ECB9b950275`) had ended its period on
  that day, and there the same calls go through and pay nothing.
- **Curve's 3pool** (`0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7`): an
  exchange of DAI for USDC, liquidity added and removed, each to the
  account.
- **Compound v3's rewards** (`0x1B0e765F6224C21223AeA2af16c1C46E38885a40`):
  `claim` pays what the account earned to the account, whoever calls;
  `claimTo`, which names a recipient, is refused, and the rewards contract
  itself refuses it from a stranger. No market read on that day paid
  rewards (the speeds were zero on five markets of Ethereum and three of
  Base), so the amount earned is a stand-in for the market's answer; the
  payment is the rewards contract's own code.
- **Aave V3's `repayWithATokens`** (the pool on Ethereum): the account's
  debt falls by what its aTokens pay; a borrow is refused.

```sh
cd contracts
FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> \
    forge test --evm-version osaka --match-path test/MoreRecipes.t.sol --match-test 'test_recipe|test_real'
```

### Aave V3 on Base Sepolia, verified

An agent supplies test USDC to Aave's pool and withdraws it, under a
mandate that lists the token's `approve` (within 100 USDC an operation and
300 in all) and the pool's two compact calls, and nothing else
[V `contracts/test/AaveRecipe.t.sol`, run on a fork of Base Sepolia on
2026-11-26 against the pool `0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27`
and its reserve `0xba50Cd2A20f6DA35D788639E581bca8d0B5d4D5f`: 4 tests pass].

| What the test shows | Result |
|---|---|
| A supply of 100 USDC, as three calls in one operation | the aTokens are the account's; no allowance stands; 100 is charged |
| A withdrawal of 40, then of everything, each one call | the USDC is the account's again; nothing is charged |
| Over the cap an operation; over the budget after three supplies | refused, although the account holds the money |
| The supply without the closing `approve(pool, 0)` | refused |
| `supply(asset, amount, onBehalfOf, …)` for somebody else, or for the account itself | refused: the function is not on the list |
| `withdraw(asset, amount, to)` to somebody else; a borrow; a transfer of the aToken | refused |
| The compact forms called by another address | they act for that caller: there is no argument to point elsewhere |
| The form with `onBehalfOf` put on the list, once, on purpose | the supply for somebody else goes through, and the test fails |

```sh
cd contracts
FORK_BASE_SEPOLIA_RPC_URL=<an RPC of Base Sepolia> \
    forge test --evm-version osaka --match-contract AaveRecipeTest
```

Without the variable the tests are skipped; CI has no RPC.

**The compact argument** is one word (Aave's `CalldataLogic`): the
reserve's id in the low 16 bits, the amount in the next 128. USDC is
reserve 0 on Base Sepolia, so a supply of 100 USDC (100,000,000 units) is
`0xf7a73840` followed by the word `100000000 << 16`. The widest amount in a
withdrawal means "everything".

**The compact forms were not run on a chain:** this test runs on a fork.
Aave by rules was run on Sepolia itself
([the runs of 2026-11-27](#on-a-chain-the-runs-on-sepolia-of-2026-11-27)).

## A swap at Uniswap's router: deployed, and run on Sepolia

A swap names a recipient, so it cannot go on an allow-list. It goes through
a venue instead, like an order: the mandate names a decoder with the
owner's pairs and their lowest prices, and the decoder
(`SwapRouter02Decoder`) judges a call instead of an order
([`CONTRACTS.md`](CONTRACTS.md#swaprouter02decoder)).

- **What the agent names:** the two tokens, the pool's fee tier, the
  amount sold and the least bought. Nothing else.
- **What is written in:** the bought token goes to the account; no native
  value; no price limit.
- **Two calls in one operation:** the swap's registration at the policy,
  then the router call the decoder built, byte for byte. Any other call at
  the router, or the same call with another recipient or for less, is
  refused.
- **The owner approves the router once,** as for CoW's relayer. The router
  takes tokens from its own caller only, and the agent reaches it through
  the decoder alone.
- **What is charged:** the amount sold, to the sold token's `maxPerOp` and
  budget, when the swap is registered. A swap that reverts (the market
  moved under the least bought) is still charged; with a `period` the
  budget renews.

[V `contracts/test/SwapRouter02.t.sol`: under a mandate with a stand-in
router, and `SwapRouter02ForkTest` on a fork of Base Sepolia on 2026-11-26
against Uniswap's router `0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4` and
the pool `0x46880b404CD35c165EDdefF7421019F8dD25F4Ad`: wrapped ether sold
for the test dollar, to the account, charged; another recipient, the
router's `multicall` around the same swap, an amount of zero, more than the
cap and a price under the owner's lowest are each refused.]

```sh
cd contracts
FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> \
    forge test --evm-version osaka --match-contract SwapRouter02ForkTest
```

The CLI makes the swap, and the phone's core shows the venue's terms to the
owner [V `swaps_under_a_mandate` and
`the_phone_reads_a_swap_config_as_the_decoder_does` in the CLI's local-chain
tests, with a stand-in router]:

```sh
agent-signer order swap --agent agent.json \
    --sell <token> --buy <token> --sell-amount <units> --buy-amount <least units> --fee 3000
```

In the config the venue is `{"kind": "uniswap", "decoder": …, "pairs": […]}`
([`AGENT_CONFIG.md`](AGENT_CONFIG.md)).

**Deployed on Sepolia and Base Sepolia on 2026-11-27,** with the policy
that admits a decoder's call; the phone's core names the venue there
([`DEPLOYMENTS.md`](DEPLOYMENTS.md)). The first swap through it on a
chain was made on Sepolia on 2026-11-27
([the runs](#on-a-chain-the-runs-on-sepolia-of-2026-11-27)). One pool and an exact amount sold only: paths through several
pools, exact-output swaps and the router's v2 functions are not allowed.

## With a rule for each argument: deployed for two contracts, and run on Sepolia

These are the same protocols' other functions, and whole families of
protocols, whose calls name a beneficiary. `CallRulesDecoder` holds each
argument word of a call to a rule the owner wrote: the word is the account,
or a value the owner set, or at most a bound, or an amount that is charged,
or the agent's to choose ([`CONTRACTS.md`](CONTRACTS.md#callrulesdecoder)).
One decoder is deployed for each contract; the mandate names it as a venue
with its rules, and a call is two legs of one operation, like a swap.

**Aave's functions that name a beneficiary, verified.** `supply(asset,
amount, onBehalfOf, referralCode)` with the asset set, the amount charged,
`onBehalfOf` the account and no referral; `withdraw(asset, amount, to)`
with the asset set and `to` the account
[V `contracts/test/CallRules.t.sol`, `PoolForkTest` and the five
`PoolOn…Test` contracts, each on a fork of its chain against Aave's pool
there: the agent supplies and the aTokens are the account's; a supply for
somebody else, a withdrawal to somebody else, a borrow and an amount over
the cap are refused]. These are the only forms the pools of Ethereum, BNB
Chain and Sepolia have, so with the rules an agent can use Aave there too.

**Aave V3, network by network.** Which forms a pool has was read in the
code of each pool's implementation on 2026-11-27 (the selectors
`0xf7a73840` and `0x617ba037`).

| Network | Aave V3's pool | Compact forms: the allow-list alone | Forms with a beneficiary: rules |
|---|---|---|---|
| Ethereum | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` | not in the pool | **[V]** with USDC, 2026-11-27 |
| BNB Chain | `0x6807dc923806fE8Fd134338EABCA509979a7e0cB` | not in the pool | **[V]** with USDC, 2026-11-27 |
| Sepolia | `0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951` | not in the pool | **[V]** with the pool's test WETH, 2026-11-27 |
| Arbitrum | `0x794a61358D6845594F94dc1DB02A252b5b4814aD` | in the pool; not run [I] | **[V]** with USDC, 2026-11-27 |
| Base | `0xA238Dd80C259a72e81d7e4664a9801593F98d1c5` | in the pool; not run [I] | **[V]** with USDC, 2026-11-27 |
| Base Sepolia | `0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27` | **[V]** with the pool's test USDC, 2026-11-26 | **[V]** with the pool's test USDC, 2026-11-26 |

- **Verified means on a fork,** with this build's policy and a rules
  decoder deployed in the test for that pool: one asset, supply and
  withdraw. Nothing was sent to those chains.
- **What it takes on a chain:** a `CallRulesDecoder` deployed for that
  chain's pool (`contracts/script/DeployCallRules.s.sol`), named in the
  mandate with its code hash. Sepolia and Base Sepolia have one for their
  pool since 2026-11-27 ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)); no other
  chain has, and a mainnet gets one only from an audited release (house
  rule 3).
- **On Sepolia the pool's test USDC, DAI and USDT cannot be supplied:**
  they are above their supply caps (4.9, 6.1 and 4.7 billion supplied
  against caps of 2 billion, read on 2026-11-27), and the pool refuses a
  supply of them whoever makes it. Its test WETH and LINK have no cap.
- **Not verified on any network:** `repay`, the gateway for native ETH,
  the rewards controller.

```sh
cd contracts
FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> \
    forge test --evm-version osaka --match-contract PoolForkTest
FORK_ETHEREUM_RPC_URL=<an Ethereum RPC> FORK_SEPOLIA_RPC_URL=<Sepolia> FORK_ARBITRUM_RPC_URL=<Arbitrum> \
FORK_BNB_RPC_URL=<BNB Chain> FORK_BASE_RPC_URL=<Base> \
    forge test --evm-version osaka --match-contract PoolOn --match-test 'test_fork|test_real'
```

**An ERC-4626 vault, verified.** sDAI on Ethereum
(`0x83F20F44975D03b1b09e64809B757c47f942BEeA`): `deposit(assets,
receiver)` with the assets charged and the receiver the account;
`redeem(shares, receiver, owner)` and `withdraw(assets, receiver, owner)`
with both the receiver and the owner the account, of any amount
[V `ProtocolRecipes.t.sol` `VaultRecipeTest`, on a fork of Ethereum on
2026-11-26: the shares are the account's and the deposit is charged; a
deposit for somebody else, a redeem or a withdrawal to somebody else,
`mint`, and the share token's `transfer` and `approve` are refused].

```json
{"selector": "0x6e553f65", "words": [{"charged": "<asset>"}, "account"]},
{"selector": "0xba087652", "words": ["any", "account", "account"]},
{"selector": "0xb460af94", "words": ["any", "account", "account"]}
```

**Circle's CCTP, verified.** `depositForBurn` at the V2 messenger on Base
Sepolia (`0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA`): the amount charged,
the destination chain set, the recipient the account's own address there,
the token set, no caller named for the other side, no fee, standard
finality [V `ProtocolRecipes.t.sol` `CctpRecipeTest`, on a fork of Base
Sepolia on 2026-11-26: 50 USDC leave the account and the token's supply,
and are charged; another recipient, another chain, a fee, a caller for the
other side, the form with a hook and an amount over the cap are refused].
The recipient "the account" is the same address on the other chain: it is
the owner's there only if the account exists, or can be created, at that
address on that chain.

```json
{"selector": "0x8e0250ee", "words": [{"charged": "<USDC>"}, {"is": "<destination domain>"}, "account",
                                    {"is": "<USDC>"}, {"is": "0"}, {"atMost": "0"}, {"is": "2000"}]}
```

With one rule of a recipe loosened at a time (the recipient, the chain or
the fee of the bridge; a receiver of the vault), its test fails: the
refusals are the rules' doing.

**A bid for an NFT at Seaport, verified in the contracts.**
`SeaportBidDecoder` lets an agent bid for one item of a collection the
owner listed, at no more than the collection's highest price, within the
token's cap and budget: a named item or any item of the collection, with
the marketplace's fees inside the price. Whichever way the bid is filled,
the account pays the price and gets the item [V `SeaportTrading.t.sol`
`SeaportRealTest`, against Seaport's own code on a fork of Base Sepolia on
2026-11-27]. The owner lists a collection as a pair: the token paid, the
collection, and "at least one item for each <highest price> of the token".
A collection must say itself that it is an ERC-721: Seaport does not check,
and would take a token listed as a collection in its units. Three things
the owner should know are in
[`docs/CONTRACTS.md`](CONTRACTS.md#seaportbiddecoder): an order can be
validated at Seaport and then no longer asks the account; the allowance
goes to a marketplace's conduit; with a bid for any item the seller picks
the item. The decoder is deployed on Sepolia and Base Sepolia since
2026-11-27; the CLI and the phone do not place or show bids yet: `[I]` for
everything beyond the contracts.

**Six more by rules, verified on Ethereum** [V
`contracts/test/MoreRecipes.t.sol`, on a fork of Ethereum on 2026-11-27;
each also with what the rules refuse].

- **Morpho Blue** (`0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`). Markets
  are permissionless, so the rules pin the market itself, its five words.
  A supply for the account with no callback data; a withdrawal from the
  account's position to the account. Another market, another beneficiary,
  callback data, `setAuthorization` and `borrow` are refused; Morpho itself
  credits whoever is named.

```json
{"selector": "0xa99aad89", "words": [{"is": "<loan token>"}, {"is": "<collateral token>"}, {"is": "<oracle>"},
                                    {"is": "<rate model>"}, {"is": "<loan-to-value>"}, {"charged": "<loan token>"},
                                    {"is": "0"}, "account", {"is": "0x120"}, {"is": "0"}]},
{"selector": "0x5c2bea49", "words": [{"is": "<loan token>"}, {"is": "<collateral token>"}, {"is": "<oracle>"},
                                    {"is": "<rate model>"}, {"is": "<loan-to-value>"}, "any", "any", "account", "account"]}
```

- **Two more ERC-4626 vaults** by the three rules of sDAI above: a
  MetaMorpho vault (`0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB`, USDC) and
  Sky's savings vault (`0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD`, USDS).
- **Lido's withdrawal queue** (`0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1`):
  `requestWithdrawals(amounts, owner)` with the request held to the account
  and the list to one amount, charged in stETH. The queue gives the request
  to whoever is named. Claiming it later needs Lido's finalization and was
  not run.

```json
{"selector": "0xd6681042", "words": [{"is": "0x40"}, "account", {"is": "1"}, {"charged": "<stETH>"}]}
```

- **The Base bridge on Ethereum**
  (`0x3154Cf16ccdb4C6d922629664174b904d80F2C35`): `bridgeERC20To` with both
  tokens set, the recipient the account's own address on Base, a bound on
  the gas for the other side and no extra data; the amount charged. As
  with CCTP above, that address is the owner's on Base only if the account
  exists, or can be created, there. The test sees the token locked in the
  bridge on Ethereum; the mint on Base was not run.

```json
{"selector": "0x540abf73", "words": [{"is": "<token here>"}, {"is": "<token on Base>"}, "account",
                                    {"charged": "<token here>"}, {"atMost": "200000"}, {"is": "0xc0"}, {"is": "0"}]}
```

- **Aave V3's `repay`** with the debt held to the account's own.

```json
{"selector": "0x573ade81", "words": [{"is": "<asset>"}, {"charged": "<asset>"}, {"is": "2"}, "account"]}
```

- **Compound v3's `supplyTo` and `withdrawTo`,** each held to the account.

```json
{"selector": "0x4232cd63", "words": ["account", {"is": "<asset>"}, {"charged": "<asset>"}]},
{"selector": "0xc3b35a7e", "words": ["account", {"is": "<asset>"}, "any"]}
```

**What is left,** each `[I]` until its test exists, or struck:

| Opens with | What |
|---|---|
| One word = the account | Uniswap v3 `collect`; ether.fi's withdrawal request; other ERC-4626 vaults (Yearn, sUSDe, Aave's stata tokens), by the rules verified for three vaults |
| Words = values the owner sets | Uniswap v3 `mint`. It pulls two tokens and a call has one charged word: the second token is held by a bound on its word and by its allowance |
| **Not possible with rules as they are** | Aave's gateway for native ETH and the Base bridge's `bridgeETHTo`: they are paid in native value, and a call under rules carries none [V `test_poolRules_whatIsNotListedIsRefused` in `contracts/test/CallRules.t.sol`]. They need a decoder that judges a value |
| A decoder of its own | other swaps at a router (several pools, exact output, v2 pools, other routers); Seaport listings (a bid has its decoder, below); GMX orders; Uniswap v4; Balancer; Pendle |

The CLI makes such calls, and the phone's core shows the owner each
function with the rule for every argument [V
`calls_with_rules_under_a_mandate` and
`the_phone_reads_a_rules_config_as_the_decoder_does` in the CLI's
local-chain tests, with a stand-in pool]. Aave's supply for one asset and
the account only, in a config's `venues`:

```json
{"kind": "rules", "decoder": "<the decoder for the pool>", "codeHash": "<its code hash>",
 "functions": [
   {"selector": "0x617ba037", "words": [{"is": "<asset>"}, {"charged": "<asset>"}, "account", {"is": "0"}]},
   {"selector": "0x69328dec", "words": [{"is": "<asset>"}, "any", "account"]}]}
```

```sh
agent-signer order call --agent agent.json --data <calldata of the supply>
```

The owner's screen then reads, for the supply: the first argument exactly
the asset, the second an amount charged to the asset's budget, the third
this account, the fourth exactly 0; and for the withdrawal's amount, in
bold, "anything — the agent picks it", with a warning.

**Deployed for two contracts on each test network on 2026-11-27:** Aave
V3's pool and CCTP's messenger, on Sepolia and on Base Sepolia; the phone's
core names both ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)). Both were used on
Sepolia on 2026-11-27: a supply and a withdrawal at Aave, a transfer by
CCTP ([the runs](#on-a-chain-the-runs-on-sepolia-of-2026-11-27)).

Without its rules none of these is safe on a mandate. A pull-side function
(`supply`, `deposit`) left unpinned loses at most what the token's budget
charged, but it turns the budget into a payment to anyone, past the payee
list. A release-side function (`withdraw`, `redeem`, `claim` with a
recipient) moves what the account already holds in the protocol, and
nothing in the mandate bounds that.

## On a chain: the runs on Sepolia of 2026-11-27

Everything above this section's date was shown on forks. On 2026-11-27
(UTC) it ran on Sepolia itself, through the policy and the decoders
deployed that day ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)), on the account of
the first live order, `0xeAb60Ce78Af6e62E268dfF4af9186b7C61c2bcEd`
([`TRADING_WALKTHROUGH.md`](TRADING_WALKTHROUGH.md)).

**The owner's step, once.** One operation, approved on the phone (the
Android owner app 0.4.4, core 0.3.5), removed the account's earlier
permission and installed a mandate on the policy
`0xdA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6` with five venues: CoW Swap,
1inch, Uniswap, rules for Aave V3's pool, rules for CCTP's messenger; a
cap and a budget for WETH, USDC and Aave's test LINK; one allowance to
each venue's spender; and Aave's test faucet on the allow-list. The phone
showed each venue from its build's facts, the two tokens it knows by name
and the third by its address, and one warning: the amount of a withdrawal
from Aave is the agent's to choose
[V [`0x3c140c6b36dec2d83586930ec517cf7c4d23c9177444cb140b6ac1f569ea20b0`](https://sepolia.etherscan.io/tx/0x3c140c6b36dec2d83586930ec517cf7c4d23c9177444cb140b6ac1f569ea20b0), 5,331,697 gas].

**The agent's steps,** each signed by the agent's key in the secure
hardware of the machine it runs on, each through the policy [V the
transactions; every one succeeded]:

| What the agent did | Transaction | What it did on the chain |
|---|---|---|
| a call on the allow-list: Aave's test faucet | [`0x0f3e6e678c49366f0f1b2aa5f1acced2c36abed1a8912c8fef0ce6ab279c040a`](https://sepolia.etherscan.io/tx/0x0f3e6e678c49366f0f1b2aa5f1acced2c36abed1a8912c8fef0ce6ab279c040a) | 200 test LINK minted to the account |
| a supply to Aave V3, by rules | [`0x426a010da476eb45302025724b2b1bf62538478a87da52cc32dd6d1ecba65e59`](https://sepolia.etherscan.io/tx/0x426a010da476eb45302025724b2b1bf62538478a87da52cc32dd6d1ecba65e59) | 100 LINK supplied with the account as beneficiary; the aLINK is the account's; 100 LINK charged |
| a withdrawal from Aave V3, by rules | [`0xb51f058a1cca46fd55ccf9de33592b2d9d4da1cb2010e54dfb950029b6409c99`](https://sepolia.etherscan.io/tx/0xb51f058a1cca46fd55ccf9de33592b2d9d4da1cb2010e54dfb950029b6409c99) | 40 LINK back to the account; nothing charged |
| a bridge transfer by CCTP, by rules | [`0xfd8b7209986aed74d7cee6a0534c3af83e6f4033a05c77fb583043ce42c35be9`](https://sepolia.etherscan.io/tx/0xfd8b7209986aed74d7cee6a0534c3af83e6f4033a05c77fb583043ce42c35be9) | 5 USDC burned for the account's own address on Base Sepolia (CCTP's domain 6) [V the messenger's event in that transaction: the depositor and the recipient are the account, the destination is 6]; 5 USDC charged |
| a swap at Uniswap's SwapRouter02 | [`0x19c78c6a8cd1dd8a873ea612ad887e51f60298de9ffd22ef9355781b6e7e9706`](https://sepolia.etherscan.io/tx/0x19c78c6a8cd1dd8a873ea612ad887e51f60298de9ffd22ef9355781b6e7e9706) | 0.0002 WETH for 8.583915 USDC through the 0.05% pool, the least accepted being 4 USDC; 0.0002 WETH charged |
| a 1inch limit order | [`0x8a5705b688ff989d68f8a39e85ed5698fbe4b521f6891a4948f9e29ef85f5537`](https://sepolia.etherscan.io/tx/0x8a5705b688ff989d68f8a39e85ed5698fbe4b521f6891a4948f9e29ef85f5537) | the order registered and charged; the account answers `isValidSignature` for its hash `0x1e361b72b3bb06be8c9a7bedcad4ac70c49cb7ce03225f416f5b7494cd8423ba` with the magic value, and refuses another digest with the same signature |
| a CoW Swap order under the new policy | [`0x2bde34e2dbbf492e91812951baa5f188250b32d19412e0d9b5ac7b3be7ad9582`](https://sepolia.etherscan.io/tx/0x2bde34e2dbbf492e91812951baa5f188250b32d19412e0d9b5ac7b3be7ad9582) | the order registered and charged; CoW's order book took it, and a solver filled it within a minute: 0.0002 WETH for 7.903168 USDC [V [`0x8e7a877606cad11b83792a08e41432030d6a1eae312b18694a000f042dda069b`](https://sepolia.etherscan.io/tx/0x8e7a877606cad11b83792a08e41432030d6a1eae312b18694a000f042dda069b)] |

**Refused, before anything was sent** (the CLI puts a call to the venue's
decoder first, and the decoder refused): a supply to Aave on behalf of
another address; a CCTP transfer for another recipient; a CCTP transfer to
another chain than the one the owner set.

**The other side of the bridge.** Circle attested the burn about an hour
later, and the attestation was delivered to the message transmitter on Base
Sepolia, which anyone may do: 5 USDC were minted there to the account's
address [V
[`0xa145a77742a009b57bb24e51530d22b2c1aae0a9e65fbf40e40a5dfd46d084a5`](https://sepolia.basescan.org/tx/0xa145a77742a009b57bb24e51530d22b2c1aae0a9e65fbf40e40a5dfd46d084a5),
2026-11-27 10:15:43 UTC; the balance read afterwards]. The account does not
exist on Base Sepolia yet: the USDC waits at its address, which the same
creation data gives there.

**The mandate's counters afterwards** [V `permission show`]: WETH 0.0006 of
0.001, USDC 5 of 10, LINK 100 of 300, and 0.000111 ETH of gas against the
native budget.

**Not done in this run.**
- The 1inch order was sent to no order book and had no taker: its fill at
  the router is shown on a fork only.
- No ERC-7562 trace was taken of these operations on the chain; the same
  kinds of operation are traced on a local chain
  ([`FUZZING.md`](FUZZING.md)).
- One account, one chain, small amounts, one run of each.

## Never for an agent key

Whatever the policy learns to read, these hand something over that no
amount bounds:

- **Rights given to a third party:** Aave `approveDelegation` and
  `approvePositionManager`, Compound `allow`, Morpho `setAuthorization`,
  EigenLayer `delegateTo`, every `permit`, approvals of position NFTs.
- **Calls that hide other calls:** every `multicall`, flash loans,
  Compound's Bulker, any call with a callback argument that is not empty.
- **Borrowing,** until it has a rule of its own. The loss of a borrow is
  bounded by the collateral in that market, not by an amount: prices move,
  and a liquidation takes the collateral with a bonus.
- **Signatures.** Several of these protocols accept a contract account's
  signature (sUSDS and stETH `permit`, a Governor's `castVoteBySig`, a
  bridge's change of recipient). The policy vouches only for what the agent
  registered under the mandate, which keeps all of them closed
  ([`ERC1271.md`](ERC1271.md)).

**Value the budget does not see.** Some protocols take value without an
allowance: a bridged token burned by its bridge, a position held as an NFT,
a balance kept inside the protocol. The token's limit counts `transfer` and
`approve` only, so such a call is outside it. Each is marked in the notes
of #80, and a rule for one has to count the amount itself.

## What the owner sees

A mandate names contracts and functions; the phone shows a contract it
knows by name and any other by its address. None of the protocols above is
in a phone build's list yet, so their calls appear as an address and a
selector, with the token's limit in the token's units when the build knows
the token. Naming these protocols on the owner's screen is part of the same
work.

## Sources

The functions, their arguments and the addresses were read in the
protocols' repositories and their verified deployed sources on 2026-11-26;
the summary and what was not checked are on
[issue #80](https://github.com/postcryptum-research/agent-keys/issues/80).
For Aave, the compact forms were also read here in
`aave-v3-origin` at `8305565ae342f1773c42cd2e4593f175fe5968a0`
(`src/contracts/protocol/pool/L2Pool.sol`), and their selectors are in the
code of Base Sepolia's pool implementation
`0xE9fb54369E85b9714F9d86366D918c5C7C87783A`.
