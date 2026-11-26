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
  argument, and an agent could name another address. It stays off until a
  decoder holds that argument to the account: the policy admits a call a
  venue's decoder judged, and the first such decoder is the swap below.

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
| **Aave V3** | the pool's compact forms `supply(bytes32)` `0xf7a73840`, `withdraw(bytes32)` `0x8e19899e`, `repay(bytes32)` `0x563dd613`: the pool uses its own caller as beneficiary | Base, Arbitrum, Base Sepolia (the pools there are L2 pools) | **[V]** on Base Sepolia, see below |
| Aave V3 | `repayWithATokens`, rewards `claimRewardsToSelf`, `claimAllRewardsToSelf` | every chain | [I] |
| Compound v3 | `supply(address,uint256)`, `withdraw(address,uint256)`, rewards `claim` | Ethereum, Base, Arbitrum, Sepolia, Base Sepolia | [I] |
| Lido | `submit(address)` (stake), wstETH `wrap` and `unwrap`, `claimWithdrawals`, `claimWithdrawal` | Ethereum; Sepolia in part | [I] |
| Rocket Pool | `deposit()`, rETH `burn` | Ethereum | [I] |
| ether.fi | `deposit()`, `deposit(address)`, weETH `wrap` and `unwrap`, `claimWithdraw` | Ethereum | [I] |
| EigenLayer | `depositIntoStrategy`, `queueWithdrawals`, `completeQueuedWithdrawal` | Ethereum, Sepolia | [I] |
| Sky | staking rewards `stake`, `withdraw`, `getReward`, `exit` | Ethereum | [I] |
| Curve | a classic pool's `exchange`, `add_liquidity`, `remove_liquidity` and its variants | per pool | [I] |
| Others | a Governor's `castVote`; a Merkle distributor's `claim`; a mint to the caller, under the native cap | per project | [I] |

Three of these need a word of care:

- **Compound's `withdraw` borrows.** Asking for more of the base asset
  than the account supplied leaves a debt, while the account's collateral in
  that market covers it. With no collateral there it cannot borrow.
- **EigenLayer without `delegateTo`.** Deposits and withdrawals act on the
  caller; delegation to an operator exposes everything restaked to that
  operator's slashing, with no amount to bound it.
- **Curve's price is the agent's.** The minimum-out argument is the
  agent's own, so a bad trade loses up to what was allowed. The token's
  budget bounds it; nothing holds a price.

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

**Not on a chain yet:** the test runs on a fork. A live run on Base Sepolia
follows.

## A swap at Uniswap's router: built, not on a chain yet

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

**Not on a chain yet.** No network has this decoder, or the policy that
admits a decoder's call, so no phone build names the venue. One pool and an
exact amount sold only: paths through several pools, exact-output swaps and
the router's v2 functions are not allowed.

## Not yet: needs an argument held to the account

These are the same protocols' other functions, and whole families of
protocols, whose calls name a beneficiary. One rule kind would open them: a
word of the call pinned to the account, or to a value the owner sets. The
policy now admits a call a venue's decoder judged, which is what such a
rule rides on; a decoder that holds a word to the account is the next step
of #80.

| Opens with | What |
|---|---|
| One word = the account | Aave `supply`, `withdraw`, `repay` and its ETH gateway on Ethereum, BNB Chain and Sepolia; every ERC-4626 vault's `deposit` and `mint` (MetaMorpho, sDAI, sUSDS, Yearn, sUSDe, Aave's stata tokens); Lido and ether.fi withdrawal requests; Compound's `supplyTo` and `withdrawTo`; Uniswap v3 `collect` |
| Two words = the account | every ERC-4626 vault's `withdraw` and `redeem` |
| Words = values the owner sets | Morpho (the market: markets are permissionless, so the market itself is pinned); Circle's CCTP (the destination chain and recipient); the Base bridge's `bridgeETHTo` and `bridgeERC20To`; Uniswap v3 `mint` |
| A decoder of its own | other swaps at a router (several pools, exact output, v2 pools, other routers); Seaport orders; GMX orders; Uniswap v4; Balancer; Pendle |

Until then none of these is safe on a mandate. A pull-side function
(`supply`, `deposit`) left unpinned loses at most what the token's budget
charged, but it turns the budget into a payment to anyone, past the payee
list. A release-side function (`withdraw`, `redeem`, `claim` with a
recipient) moves what the account already holds in the protocol, and
nothing in the mandate bounds that.

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
