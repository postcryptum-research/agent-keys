# Circle's products under a mandate

What of Circle's stack an agent-keys account uses today, each with the
transaction that shows it, and what could be added, with what each would
take. One page, so that the claims have one place to be checked.

`[V]` is verified with the source given, `[I]` is inferred. Dates are UTC.
Test networks only: nothing here is on a mainnet, and nothing is audited
([`FAQ.md`](FAQ.md#is-it-audited)).

## In use

| Product | What the account does with it | State |
|---|---|---|
| **USDC** | limits per operation and per period, payee lists, and x402 payments: an EIP-3009 authorization is registered and charged by the policy before the account vouches for it | [V] x402 payments on Base Sepolia ([`STATUS.md`](STATUS.md)); on Arc testnet, 2026-11-27: 0.5 USDC to a listed payee in [`0xde0a3e9931fb731155008e1bdbe5d4d351ed3178dccf3cfd7900398565e09d99`](https://explorer.testnet.arc.io/tx/0xde0a3e9931fb731155008e1bdbe5d4d351ed3178dccf3cfd7900398565e09d99), and refused in validation: another recipient, more than the cap, an approval |
| **USDC as gas** (Arc) | on Arc the gas token is USDC. An account pays its own gas in it, and a mandate bounds it by its native budget | [V] the first account on Arc testnet was created by the agent's own operation, its gas paid in USDC: [`0x9bf9be3f5d81203d1cf2310f40518cd55c0d649d995911a7e3851cf6574684fc`](https://explorer.testnet.arc.io/tx/0x9bf9be3f5d81203d1cf2310f40518cd55c0d649d995911a7e3851cf6574684fc) (2026-11-27) |
| **CCTP** (V2) | `depositForBurn` by rules: the recipient is the account's own address on the other chain, the destination, the token, the fee and the finality are set, the amount is charged ([`DAPPS.md`](DAPPS.md)) | [V] Sepolia to Base Sepolia under a mandate on 2026-11-27: burn [`0xfd8b7209986aed74d7cee6a0534c3af83e6f4033a05c77fb583043ce42c35be9`](https://sepolia.etherscan.io/tx/0xfd8b7209986aed74d7cee6a0534c3af83e6f4033a05c77fb583043ce42c35be9), mint [`0xa145a77742a009b57bb24e51530d22b2c1aae0a9e65fbf40e40a5dfd46d084a5`](https://sepolia.basescan.org/tx/0xa145a77742a009b57bb24e51530d22b2c1aae0a9e65fbf40e40a5dfd46d084a5). Out of Arc testnet to Base Sepolia the same day: burn [`0xdbf8dd582909f0d8f3617125b29fb36e9142d567c94ca0b713ae61a010f80d95`](https://explorer.testnet.arc.io/tx/0xdbf8dd582909f0d8f3617125b29fb36e9142d567c94ca0b713ae61a010f80d95), attested by Circle, mint on Base Sepolia [`0x5b7e5d0e4d158877f12638f6b22443f51a9c6da4c37d1f44ee4069040b42113e`](https://sepolia.basescan.org/tx/0x5b7e5d0e4d158877f12638f6b22443f51a9c6da4c37d1f44ee4069040b42113e) (delivered by our gas wallet, as anyone may): 1 USDC at the account's own address there. The rules decoder for the messenger is deployed on Sepolia, Base Sepolia and Arc testnet ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)) |
| **Paymaster** (gas in USDC where gas is not USDC) | with `GAS_TOKEN_PAYMASTER` set, the agent's operations go with Circle's paymaster, which takes USDC from the account through an allowance the owner gave ([`FAQ.md`](FAQ.md)). No permit is sent: the agent's key cannot sign one, so the owner's allowance is all the paymaster can take, and the mandate's native budget is not touched | [V] Base Sepolia, 2026-11-27: the owner's approval of 5 USDC to the paymaster `0x31BE08D380A21fc740883c0BC434FcFc88740b58` in [`0x9a9a97137d7322590db081e1437880f9019757a7cabf4de27b6973a537fd7f60`](https://sepolia.basescan.org/tx/0x9a9a97137d7322590db081e1437880f9019757a7cabf4de27b6973a537fd7f60); then an agent's operation delivered by a bundler paid 0.006296 USDC for gas and no ETH: [`0x3d7ba1d1bbe8d28f836bd7836ce84ebab457075f6a2704e19faf3193576cae70`](https://sepolia.basescan.org/tx/0x3d7ba1d1bbe8d28f836bd7836ce84ebab457075f6a2704e19faf3193576cae70). For EntryPoint v0.7, which these accounts use, Circle lists its paymaster on Base and Arbitrum and their test networks |
| **EURC**, **cirBTC** (Arc testnet) | a mandate's limits hold any ERC-20: a limit per operation and per period and a payee list for each. The phone names both there: EURC `0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a` (6 decimals) and cirBTC `0xf0C4a4CE82A5746AbAAd9425360Ab04fbBA432BF` (8 decimals), each with the signing domain its name and version give | [V] Arc testnet, 2026-11-27: 0.5 EURC to the listed payee in [`0x25393df680297f3fe5969d2523a0d5eaedf4b4d3f5c25cf5b47de17ecd1487d1`](https://explorer.testnet.arc.io/tx/0x25393df680297f3fe5969d2523a0d5eaedf4b4d3f5c25cf5b47de17ecd1487d1), 0.00005 cirBTC in [`0xe2ffbf8c8640f2a69b35d4b822d50df2d9999db4edf1bc6cfd7f3e03db42c618`](https://explorer.testnet.arc.io/tx/0xe2ffbf8c8640f2a69b35d4b822d50df2d9999db4edf1bc6cfd7f3e03db42c618); EURC to an address that is not its payee was refused |
| **x402 Facilitator Service** | Circle's hosted x402 facilitator is the seller's side of a payment: it verifies the buyer's EIP-3009 authorization and settles it through its own relayer. The account is the buyer: it registers the authorization under the mandate and vouches for it by ERC-1271 | [V] Arc testnet, 2026-11-27, with a seller of our own in the facilitator's keyless trial: the authorization of 0.01 USDC registered in [`0x1a634ce402cbeda626bd540781559cc493f85c20669ccddc90f98bd71e5247ef`](https://explorer.testnet.arc.io/tx/0x1a634ce402cbeda626bd540781559cc493f85c20669ccddc90f98bd71e5247ef); `/verify` answered valid with the account as payer; `/settle` settled it in [`0xbd8a9bdd9ae9e2fa44a1b8b82113d6e9afb8a8936b1b2de25fa5e210b5b5a987`](https://explorer.testnet.arc.io/tx/0xbd8a9bdd9ae9e2fa44a1b8b82113d6e9afb8a8936b1b2de25fa5e210b5b5a987), sent by Circle's relayer |

**On Arc, USDC is one balance behind two doors.** [V, read from Arc testnet
on 2026-11-27] As the native token it has 18 decimals: value sent and gas
are counted in it. As the token
`0x3600000000000000000000000000000000000000` it has 6: transfers,
approvals and signed authorizations move the same balance. A mandate has a
limit for each door and an owner sets both. The owner's phone names native
amounts in USDC there and says on a mandate's review that the limits spend
one balance.

**A transfer by CCTP goes to the same address on the other chain.** That
address is the account's there only if the account exists, or can be
created, at it. An account has the same address on every chain where the
contracts are at the same addresses and it is created from the same keys
and first mandate [V: the first Arc account has the address
`0xae7b1a3f214d27C55129896CD92B742C311C8BC8` on Arc testnet and on Base
Sepolia, where it was created on 2026-11-27].

## The account these runs used on Arc testnet

[`0xae7b1a3f214d27C55129896CD92B742C311C8BC8`](https://explorer.testnet.arc.io/address/0xae7b1a3f214d27C55129896CD92B742C311C8BC8). Its owner key is on a phone
since [`0x4c413b8fd76ea601799182f3b6c808cc1aa8142352123806ffbdaa3b830f7a81`](https://explorer.testnet.arc.io/tx/0x4c413b8fd76ea601799182f3b6c808cc1aa8142352123806ffbdaa3b830f7a81);
the agent's key is in the secure hardware of the machine the agent runs
on. The owner approved two mandates on the phone (Android owner app 0.4.6,
core 0.3.7): payments, with a payee list for each token, in
[`0xf8b9dbc226b1f2713fb669f67b292e3a6c09291a4d6366edbf7ce9179320002a`](https://explorer.testnet.arc.io/tx/0xf8b9dbc226b1f2713fb669f67b292e3a6c09291a4d6366edbf7ce9179320002a), and the
bridge in [`0x5e18bdf13240d06d4a0749089b6134a69d64e2d79e8f7d077ac2f3f15ccc8b30`](https://explorer.testnet.arc.io/tx/0x5e18bdf13240d06d4a0749089b6134a69d64e2d79e8f7d077ac2f3f15ccc8b30).
They are two because the phone does not let a venue charge a token whose
payees a mandate lists: what a venue takes does not go to a listed payee.
The agent's operations went through a public bundler, the account paying
its gas in USDC; no gas wallet of ours was in their path. Each receipt was
read afterwards: every one succeeded.

## Could be added

| Product | How it would fit | What it takes |
|---|---|---|
| **CCTP into Arc** | the same rules with Arc as the destination | a sender account whose own address exists on Arc: the Arc account's counterpart on Sepolia or Base Sepolia |
| **Gateway** | a balance of USDC, EURC or cirBTC spendable on many chains. Depositing and withdrawing are calls with a rule for each argument, as they are. Spending is a signed transfer intent, and Gateway's documentation says it validates a smart account's signature directly | for spending: a decoder that reads an intent and registers it, as for an order, so that the account vouches only for intents inside the mandate; a CLI command; the phone's wording. A new contract. Not started |
| **USYC** | its Teller has `deposit(assets, receiver)` and `redeem(shares, receiver, account)`: the rules already shown for ERC-4626 vaults ([`DAPPS.md`](DAPPS.md)) | the issuer's permission for the account's address, on the test network too [V: a deposit simulated from the Arc account on 2026-11-27 reverts with `NotPermissioned`]. The fund is for qualified investors outside the United States |
| **StableFX** | USDC against EURC on Arc: a venue with a decoder of its own, like an order book's | admission: it is a permissioned platform for vetted institutions. Nothing can be run before that |
| **App Kits** | Circle's SDKs over CCTP and Gateway drive a signer | an adapter that lets them drive an agent-keys account |

Not in scope: Circle's wallets (this project is another way to hold an
agent's key: in the device's own chip, with the limits on the chain),
Circle Contracts and Circle Mint.

## What this page does not show

- **No mainnet and no audit.** Every address above is on a test network.
- **One run of each.** The transactions are single runs with small amounts.
- **Circle's side is read, not tested by us beyond what is stated.** Where
  a row cites Circle's documentation, the claim is theirs [I] until a run
  here confirms it.
