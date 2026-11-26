# A trading agent, end to end: the first live order

On 2026-11-26 (UTC) an agent's key sold 0.001 WETH for 47.258592 USDC
through CoW Swap on Sepolia, inside limits the account's owner had approved
on a phone. This page walks through that run step by step: who signed what,
what each step put on the chain, and what kept the agent inside its
mandate. Every transaction is given in full, so each claim can be checked.

It is a test network, and the code has had internal reviews and no external
audit ([`FAQ.md`](FAQ.md#is-it-audited)). `[V]` is verified with the source
given, `[I]` is inferred (house rule 6).

## What the run shows

- **The agent trades, and cannot do anything else.** Its key can register
  an order with the policy. It cannot call a token, a venue or any other
  contract, and it cannot sign an order outside the owner's terms: the
  account vouches only for orders the policy registered.
- **The owner approves the terms once, on a screen that names them.** The
  phone's review showed the venue, the pair, the lowest price, the caps and
  the allowance before the owner's key signed. The owner signed nothing for
  the trade itself.
- **The venue needed no integration.** CoW's order book and settlement
  contract asked the account whether it vouches for the order (ERC-1271),
  as they ask any smart-contract wallet.
- **Four keys, each in its own place, none of them in a file on the agent's
  host:** two owner keys in turn, the agent's key and a cold recovery key.
- **The account existed before its owner signed anything.** Its address
  commits to the owner's public key and the first mandate.

## Who takes part

| Part | What it is | Address or key |
|---|---|---|
| The account | a ZeroDev Kernel v3.3 smart account (ERC-4337, ERC-7579) | `0xeAb60Ce78Af6e62E268dfF4af9186b7C61c2bcEd` |
| The first owner key | a hardware-held P-256 key; root of the account when it is created | fingerprint `LHW2Z-OLL2M-SDLED-4X2SB` |
| The phone's owner key | a P-256 key made in the phone's key hardware by the Android owner app 0.4.3 (core 0.3.3); it signs only after a biometric check | fingerprint `3MWVT-XG7AV-35AQB-4J6RZ` |
| The agent key | a P-256 key in the secure hardware of the machine the agent runs on | fingerprint `UCSM7-MXSJK-KDW3E-EZMYU` |
| The recovery key | a cold key file, allowed only to take over root | fingerprint `CJZ2R-4FSTX-6YGXU-2XT4S` |
| `P256Validator` | checks the owner key's signatures on chain | `0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63` |
| `P256RecoveryValidator` | holds the recovery key | `0xb7a06e6c7B5cC9852578EF89f38d161C31218047` |
| `P256Signer` | checks the agent key's signatures on chain | `0xd88d25Ca3e042A28893781935756ee90Bc2d2769` |
| `AgentPolicy` | the mandate: what the agent key may do | `0x530DD3C000b3939294072409834c4c4dd160BCd9` |
| `CowSwapDecoder` | reads a CoW Swap order for the policy | `0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a` |
| CoW's settlement | GPv2Settlement, the venue | `0x9008D19f58AAbD9eD0D60971565AA8510560ab41` |
| CoW's vault relayer | takes the sold token for the settlement | `0xC92E8bdf79f0507f65a392b0ab4667716BFE0110` |
| WETH, USDC | the token sold and the token bought | `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`, `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` |
| The gas wallet | a small hot wallet that submits `EntryPoint.handleOps`; it holds no rights over the account | `0x52370eE170c0E2767B32687166791973a0dE7966` |

The instances are the ones of [`DEPLOYMENTS.md`](DEPLOYMENTS.md) for
Sepolia. No bundler service and no paymaster took part: the CLI submitted
each operation itself, and the account paid its own gas.

## The mandate

In words:

- **One call:** `orderRegister` on the policy. Nothing else is on the
  allow-list.
- **One venue:** CoW Swap, through its decoder.
- **One pair, one direction:** WETH sold for USDC, never for less than
  20 USDC per 0.001 WETH.
- **Caps:** at most 0.001 WETH an order and 0.002 WETH a day; the day starts
  at 00:00 UTC.
- **Orders:** sell orders, filled whole or not at all, alive for at most
  30 minutes, with the proceeds to the account itself.
- **Until:** 2026-12-31 00:00:00 UTC.

As the config says it ([`AGENT_CONFIG.md`](AGENT_CONFIG.md)):

```json
"permissionId": "0x636f7731",
"policy": {
  "allow": [{"target": "0x530DD3C000b3939294072409834c4c4dd160BCd9", "selector": "0x27ddae76"}],
  "maxValuePerOp": "0",
  "budget": "2000000000000000",
  "validUntil": 1798675200,
  "tokens": [{"token": "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
              "maxPerOp": "1000000000000000", "budget": "2000000000000000", "payees": "anyone"}],
  "period": 86400,
  "venues": [{"kind": "cowswap", "decoder": "0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a",
              "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "maxLife": 1800,
              "pairs": [{"sellToken": "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
                         "buyToken": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
                         "minBuy": "20000000", "perSell": "1000000000000000"}]}]
}
```

## The run

All times are UTC on 2026-11-26. The CLI was built from master
`814bfc59b028866614b1e7fa5266a894e6d356c3`; step 7b ran with the fix of
[#211](https://github.com/postcryptum-research/agent-keys/pull/211).

| # | Step | Signed by | Transaction | Gas used | Time |
|---|---|---|---|---|---|
| 1 | The account is created | the agent key | [`0x8c4d5dacec2899dbb7678124cab45c3b3eeaabb285449b3ef6fbcd79c5fba94f`](https://sepolia.etherscan.io/tx/0x8c4d5dacec2899dbb7678124cab45c3b3eeaabb285449b3ef6fbcd79c5fba94f) | 2,618,934 | 07:03:12 |
| 2 | A recovery key is installed | the first owner key | [`0xabfe4f9abe3506348808d30e28e8ed500c7e20c71a381d9c2d80d36b90aa134d`](https://sepolia.etherscan.io/tx/0xabfe4f9abe3506348808d30e28e8ed500c7e20c71a381d9c2d80d36b90aa134d) | 791,708 | 07:08:00 |
| 3 | The phone enrolls a key | nobody on chain | none | | |
| 4 | Root goes to the phone's key | the first owner key | [`0x7d8a696cb2719498432765863c401467fc8b1efbbd034c19be99f0e490f92c5c`](https://sepolia.etherscan.io/tx/0x7d8a696cb2719498432765863c401467fc8b1efbbd034c19be99f0e490f92c5c) | 311,080 | 07:19:36 |
| 5 | The trading mandate is installed | the phone's key | [`0x18599982ccff6200ebf8a3084cda13de1652c9ccfc935fd00d5064553a475b10`](https://sepolia.etherscan.io/tx/0x18599982ccff6200ebf8a3084cda13de1652c9ccfc935fd00d5064553a475b10) | 2,435,793 | 07:22:36 |
| 6 | 0.002 ETH is wrapped into WETH | the phone's key | [`0x43aea7fc123ffd852f210d103a67017537e43f4a2fe60db60abab1662c00df07`](https://sepolia.etherscan.io/tx/0x43aea7fc123ffd852f210d103a67017537e43f4a2fe60db60abab1662c00df07) | 352,324 | 07:28:12 |
| 7a | An order is registered; the CLI stops before printing it | the agent key | [`0xa13aab5bef7c1db71f865f27cf8f8f0fd8a4b8d3e2de91f482c5422f71c6f119`](https://sepolia.etherscan.io/tx/0xa13aab5bef7c1db71f865f27cf8f8f0fd8a4b8d3e2de91f482c5422f71c6f119) | 870,097 | 07:29:36 |
| 7b | A second order is registered and signed | the agent key | [`0x607c0f28bfcc13565e7fb5b7f50fe4fd06989f3e95e353a5491efeb52caf0aca`](https://sepolia.etherscan.io/tx/0x607c0f28bfcc13565e7fb5b7f50fe4fd06989f3e95e353a5491efeb52caf0aca) | 653,190 | 07:33:24 |
| 8 | CoW settles the order | a CoW solver | [`0xc7cc5d07e3156edde4cb85ac264544f508f931e4f1fdaf1eb0811622a3f98fa0`](https://sepolia.etherscan.io/tx/0xc7cc5d07e3156edde4cb85ac264544f508f931e4f1fdaf1eb0811622a3f98fa0) | 519,231 | 07:34:00 |

[V] Each transaction's receipt (status, block, gas used) was read from
Sepolia after the run; the reads named in the steps below were made after
each step.

### 1. The account is created, without an owner signature

`op send` from the agent, on an account that does not exist yet. The first
operation carries the account's creation data: it deploys the account with
the first owner key as root and a plain first mandate (`0x636f7730`: one
call to the demo counter), and the agent increments the counter.

- **Why no owner signature is needed.** The account's address is derived
  from the owner's public key and the first mandate. Nobody can deploy a
  different account at that address, so the agent key alone can bring it
  into being and act within that first mandate [V `owner status`: the root
  key is the first owner key; `permission show`: every field `ok`; the
  counter reads 1].
- **A trading mandate cannot be the first one.** The CLI refuses it: a
  mandate with venues goes to an existing account, because the owner's
  allowance to the venue is given in the same operation (step 5).
- **Gas.** Sepolia prices the creation of state separately
  ([`REDEPLOY.md`](REDEPLOY.md)). The node sized the transaction at
  17,738,306 gas, above the cap on regular gas, so that the new state was
  paid from the separate pool; 2,618,934 was used [V the transaction].

### 2. A recovery key

`owner add-recovery`, signed by the first owner key. The recovery key can
do one thing, take over root, and it is the fallback when root moves to a
phone. The handover of step 4 also stands on it.

### 3. The phone enrolls a key

`key create --phone`: the CLI shows a QR code, the owner app scans it and
makes a new key for this account in the phone's key hardware. Nothing goes
to the chain. What the CLI verified before it accepted the key [V its
output]:

- **The attestation:** five certificates up to Google's root; made for this
  request; the key is the one enrolled; generated in the hardware; it signs
  only after a biometric check. None of the chain is on Google's revocation
  list, fetched at that moment.
- **The app:** `dev.tpmsign.owner.spike`, version code 13, signed with the
  expected certificate; it reported `android 0.4.3 (core 0.3.3)`.
- **The boot state:** verified.
- **The fingerprint.** The phone shows the new key's fingerprint and the
  owner types it into the terminal. A fingerprint that does not match the
  key in the answer is refused, and was, once, in this run.

Attestation is evidence of where the key lives, not of whose phone it is;
that is what the secret in the QR code is for
([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)).

### 4. Root goes to the phone's key

`owner set-root --to-phone`, on the same validator contract.

- **First the phone shows that it holds the key.** A second QR code: the
  app signs a fresh digest with the enrolled key. Root is never handed to a
  key that nobody has shown they can use.
- **Then the first owner key signs the handover.** It is its last signature
  for this account [V `owner status`: the root key is
  `3MWVT-XG7AV-35AQB-4J6RZ`; the recovery key is installed].

### 5. The trading mandate, approved on the phone

`permission add`, signed by the phone's key. One operation, three calls:
the permission is installed, it is allowed to call `execute`, and CoW's
vault relayer gets an allowance of one day's budget.

The CLI prints what the phone will show, and the phone shows the same. For
this operation:

```text
## Call 1 of 3
Install agent permission: 0x636f7731
Policy module: 0x530DD3C000b3939294072409834c4c4dd160BCd9 — AgentPolicy (verified in this build)
Allow: 0x530DD3C000b3939294072409834c4c4dd160BCd9 — AgentPolicy (verified in this build) · orderRegister (0x27ddae76)
Max value per operation: 0 ETH
Budget: 0.002 ETH
Budgets renew: every day, from 00:00 UTC. Each budget above is per period; across a renewal up to twice a budget can be spent in a short time, and no more: a payment or an order the agent registers ends with its period
Valid from: now
Valid until: 2026-12-31 00:00:00 UTC (1798675200)
Token cap: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14 — WETH (verified in this build): max 0.001 WETH per operation, budget 0.002 WETH
Token payee: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14 — WETH (verified in this build): anyone — the agent picks the recipient and the spender
Trading on: CoW Swap (decoder 0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a verified in this build)
Proceeds go to: this account only
May sell: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14 — WETH (verified in this build) for 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 — USDC (verified in this build): never for less than 20 USDC per 0.001 WETH
Price: not below the lowest price above; above it the agent picks. At worst it sells all its budgets allow at the lowest price
Orders live: at most 30 minutes
An order is charged: to the budget when it is registered, filled or not; the charge is not given back, it returns when budgets renew
Order data: none (appData is zero)
Tokens are taken by: 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110 — CoW Swap vault relayer (verified in this build)
Signer module: 0xd88d25Ca3e042A28893781935756ee90Bc2d2769 — P256Signer (verified in this build)
Agent key: UCSM7-MXSJK-KDW3E-EZMYU
## Call 2 of 3
Allow permission 0x636f7731 to call: execute (0xe9ae5c53)
## Call 3 of 3
To: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14 — WETH (verified in this build)
Allowance to the venue: 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110 — CoW Swap vault relayer (verified in this build) may take 0.002 WETH for orders at CoW Swap: at most one budget of this token
```

- **"Verified in this build"** means the phone's own build knows the
  address: the policy, the decoder with its code hash, the tokens, the
  relayer. The laptop cannot make the phone name an address it does not
  know ([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)).
- **The review says what can go wrong,** not only what is allowed: twice a
  budget across a renewal, the whole budget at the lowest price, a charge
  for an order that is never filled.
- **After it** [V]: `permission show` reads every field `ok`, the venue
  included, and `allowance(account, relayer)` on WETH is
  2,000,000,000,000,000.

### 6. The wrap, and a refusal

The account held ETH and the mandate sells WETH.

- **`WETH.deposit()` was refused by the phone.** From the root key the
  phone does not sign a call whose function it cannot decode: such a call
  could move everything the account holds. The CLI said so before it showed
  the QR code, and the phone refused [V the CLI's output: "the phone
  refused"].
- **A plain transfer of 0.002 ETH to WETH was accepted.** The WETH contract
  wraps what it receives for the sender, and a plain transfer has nothing
  to decode: the review read "To: WETH (verified in this build), Send:
  0.002 ETH" [V the account's WETH balance afterwards:
  2,000,000,000,000,000].

### 7. The agent places an order

`order sell --sell <WETH> --buy <USDC> --sell-amount 1000000000000000
--buy-amount 40000000`, by the agent key alone. Three things happen
([`CONTRACTS.md`](CONTRACTS.md), [`ERC1271.md`](ERC1271.md)):

1. **The agent signs the order** with its key, as an ERC-1271 signature of
   the account.
2. **The agent registers it** in an operation that calls `orderRegister`.
   In validation the policy asks the decoder whether the order is within
   the terms: a sell order, whole or nothing, no fee, the proceeds to the
   account, the pinned `appData`, a life within 30 minutes, and at least
   20 USDC per 0.001 WETH. It charges 0.001 WETH to the cap and the day's
   budget, and records the order's digest.
3. **The CLI asks the account, as the venue will,** whether it vouches for
   the order, and prints the order for the order book. It sends it nowhere.

**7a: the first try stopped at the third step.** The registration was
included, but the public RPC endpoint answered the check from a node one
block behind, where the digest was not registered yet, and the CLI took
that refusal as final [V the CLI's error: `PolicyFailed(0)`; `x402Pending`
then held the digest
`0x8e8c0efbc098d494e04a81930213211bca20d145068545ac7fda096b127d1f47`].
The order was registered and charged, and never placed; it ended at
07:49:12. Fixed in
[#211](https://github.com/postcryptum-research/agent-keys/pull/211): a
refusal is asked again for a while.

**7b: the second try went through,** with digest
`0x0910a32bad9f8e20d25ab3eafb4a4a23d40736608a1ff2c615287730e12f806d`
and a life until 07:58:12.

### 8. CoW takes the order and fills it

- **Posted** to CoW's Sepolia order book at 07:33:44. It answered `201`
  with the order's uid,
  `0x0910a32bad9f8e20d25ab3eafb4a4a23d40736608a1ff2c615287730e12f806deab60ce78af6e62e268dff4af9186b7c61c2bced6b07e694`,
  which is the one the CLI had computed. The order book checks an ERC-1271
  order against the account before it takes it, so the account's answer
  passed there too [I from the acceptance].
- **Filled** by 07:34:14, in the settlement of 07:34:00: 0.001 WETH sold,
  47.258592 USDC bought [V CoW's order and trade records; the settlement
  transaction]. The order's own floor was 40 USDC, and the mandate's 20.
- **Afterwards** [V]: the account holds 0.001 WETH and 47.258592 USDC; the
  relayer's allowance is 0.001 WETH; `permission show` reads the token's
  budget as spent for the day (0.002), because both registrations were
  charged. It returns at 00:00 UTC.

The order on CoW's explorer:
`https://explorer.cow.fi/sepolia/orders/0x0910a32bad9f8e20d25ab3eafb4a4a23d40736608a1ff2c615287730e12f806deab60ce78af6e62e268dff4af9186b7c61c2bced6b07e694`

## What kept the agent inside the mandate

| What the agent might try | What stops it |
|---|---|
| Sell at a bad price | the decoder refuses an order under the pair's lowest price, at registration |
| Sell more than the owner allowed | the cap per operation and the budget per day, charged at registration |
| Send the proceeds elsewhere | the decoder admits only orders whose receiver is the account |
| Sign an order without registering it | the account vouches only for digests the policy recorded |
| Call the token, the venue or the relayer directly | none of them is on the allow-list; the policy refuses a venue's contracts as targets |
| Give a standing allowance | the agent gives none: the relayer's allowance is the owner's, in the operation of step 5, and never more than one budget |
| Keep trading after the owner says stop | `permission revoke`, one owner operation, also takes back the allowance |

The details and their tests: [`CONTRACTS.md`](CONTRACTS.md). What the
policy vouches for and why: [`ERC1271.md`](ERC1271.md). The proofs and the
fuzzing behind the accounting: [`FUZZING.md`](FUZZING.md).

**What the mandate does not do:** above the lowest price, the price is the
agent's. An order is charged when it is registered, filled or not, so an
order that is never placed still uses budget until the day turns, as 7a
did.

## The validation trace

An ERC-4337 bundler that enforces the validation rules (ERC-7562) has to
accept the registration. Checked on a local fork of Sepolia at block
12215127, with the deployed code of the policy (23,718 bytes) and the
decoder (4,097 bytes), a new account with throwaway keys, the operations
sent through Alto 0.0.21 in safe mode, and each trace put to
`scripts/erc7562`'s checker [V the run of 2026-11-26]:

| Operation | As it is | With the P-256 precompile allowed |
|---|---|---|
| A plain operation under a mandate with a period | refused: `STATICCALL` to `0x0000000000000000000000000000000000000100`, which the tracer takes for an undeployed address | passes |
| `orderRegister` | the same | passes |

- **`orderRegister`** touches 20 storage slots of the policy in validation,
  all of them the account's own. The decoder is reached and touches no
  storage.
- **The plain operation** touches 13, all the account's own.

The one stop is the precompile, which is the known item of
[`scripts/erc7562/README.md`](../scripts/erc7562/README.md). The trading
path adds nothing to it.

## What the run found

1. **The CLI's check after a registration** took a lagging node's answer as
   final (step 7a). Fixed in
   [#211](https://github.com/postcryptum-research/agent-keys/pull/211).
2. **Sepolia's gas rules needed no change in the CLI** (step 1).
3. **The phone refuses `WETH.deposit()` from the root key** (step 6). The
   rule is right. Decoding `deposit()` and `withdraw(uint256)` on a token
   the build knows as WETH would spare the owner the detour.
4. **A review row to reword** (step 5): "Token payee: … anyone — the agent
   picks the recipient and the spender" is shown for a token on which this
   mandate lets the agent call nothing. It errs on the careful side.
5. **The app showed nothing visible when it could not reach the laptop's
   session:** the error was printed under the buttons. From app 0.4.4 a
   failure opens a dialog
   ([#217](https://github.com/postcryptum-research/agent-keys/pull/217)).

They are recorded on
[#80](https://github.com/postcryptum-research/agent-keys/issues/80).

## To repeat it

The commands, in order; `$F` is a config with a plain first mandate and
`$T` the same account's config with the trading mandate
([`AGENT_CONFIG.md`](AGENT_CONFIG.md)).

```sh
agent-signer account fund      --agent $F --wei 20000000000000000          # the gas wallet funds the address
agent-signer op send           --agent $F --target <demo counter> --data 0xd09de08a   # 1: creates the account
agent-signer owner add-recovery --agent $F                                  # 2
agent-signer key create        --phone owner-phone --agent $F               # 3: the enrollment QR
agent-signer owner set-root    --agent $F --validator <P256Validator> --retire <P256Validator> \
    --public-key <x>,<y> --expect-fingerprint <fingerprint> --to-phone owner-phone   # 4
agent-signer permission add    --agent $T                                   # 5: signed on the phone
agent-signer op send --root    --agent $T --target <WETH> --wei 2000000000000000     # 6: a plain transfer wraps
agent-signer order sell        --agent $T --sell <WETH> --buy <USDC> \
    --sell-amount 1000000000000000 --buy-amount 40000000 > order.json       # 7
curl -X POST https://api.cow.fi/sepolia/api/v1/orders \
    -H 'content-type: application/json' --data @order.json                  # 8: without its "uid" and "registeredIn"
```

After step 4 the config's `owner` is the phone's entry, as `key create
--phone` prints it. The phone and the laptop are on the same local network
for steps 3 to 6.

## Limits of what this shows

- **A test network,** with test tokens and CoW's solvers for Sepolia.
- **One order, one venue, one pair, one direction.** No partial fills, no
  cancellation, no second venue.
- **One owner path:** the handover to a phone. The other owner keys and the
  recovery path are in their own guides.
- **No bundler service and no paymaster** in the run itself; the validation
  trace above is the evidence for a bundler.
- **The revoke was not run.** `permission revoke` is covered by the CLI's
  tests, not by this run.
