# BTCPay Server: the hot-wallet sweep of 2026-11, and what fits agent-keys

*Researched 2026-11-02, from the press coverage of the incident and BTCPay's
own documentation; §1 updated 2026-11-03 with BTCPay's incident post and the
Bitquery tally; since 2026-11-10 every BTCPay integration, including option E
below, belongs to the owner's separate project `77ph/BTCPayTEE`, and this
page is analysis only. The owner brought the case as "a project for integration
lying on the surface". This page analyses every option, and marks which ones
are in scope for agent-keys (a commodity hardware key under an on-chain
mandate) and which belong to a different product. Marks: **V** verified at
the linked source; **I** inferred from documentation or press, not tested.*

## 1. What happened

- **2026-11-01.** BTCPay Server: "We are receiving reports of hot wallets on
  BTCPay Servers being swept by unauthorized attackers. If you're running an
  instance, please shut it down (`./btcpay-down.sh`) until we complete the
  investigation." (V, quoted by CoinDesk.)
- Nicolas Dorier, the same day: the reports "appear to involve BTCPay Server
  releases older than version 2.4.2"; an attacker **had logged in as an
  administrator**; the project's own public servers on 2.4.7 "were not
  attacked" (V, CoinDesk).
- **2026-11-02, BTCPay's incident post**
  ([blog](https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/),
  V): the servers hit ran "BTCPay Server 2.4.1 (released on 23 July 2026) or
  earlier"; "the attackers used a different method to exploit the
  vulnerability fixed in 2.4.2, released on 7 August 2026" (that
  [advisory](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/)
  covered controller helper methods reachable unauthenticated over HTTP and
  LND APIs proxied through the public domain: I, Ostorlab's reading).
  **Bitcoin and Litecoin** hot wallets were swept. "Funds in wallets whose
  spending keys are held off the server, including hardware wallets, were
  unaffected by these thefts." Advice: create a new wallet and sweep what is
  left into it, move to a fresh server on the current release, take the old
  one offline and keep its logs, replace passwords and access keys from a
  trusted device. No official total: the two destination addresses' balances
  "should not be treated as a confirmed total of losses".
- **Third-party tally** (Bitquery, as reported by Infosecurity Magazine; I):
  about **$1.63M** in **682 sweeps**, 18.38 BTC and 3,405 LTC, between
  2026-10-30 and the morning of 2026-11-02; 87% of it in one wave on the
  afternoon and evening of 2026-11-01; 267 sweeps, about $150K, after the
  22:25 UTC shutdown alert.
- 2.4.7 (2026-10-29) closed a batch of security findings, one of them
  critical (I, Forklog).

## 2. Why the wallet could be swept

A BTCPay **hot wallet** is the store's seed kept on the internet-facing
server so that BTCPay can sign payouts without a human. BTCPay's own
documentation labels the feature **DANGER** and says it "comes with security
implications" (V, docs as quoted by CoinDesk). Whoever is admin on the server
can spend from it, which is what happened.

BTCPay's alternative is a **watch-only** store: the server holds only the
xpub; spending goes through **BTCPay Server Vault**, a desktop app that talks
to a hardware wallet over HWI; "your private keys never leave the device"; the
operator must "verify the transaction on your hardware wallet and confirm
it" for each spend; "the hardware wallet integration in BTCPay Server only
supports Bitcoin" (V, [docs](https://docs.btcpayserver.org/HardwareWalletIntegration/)).

So a merchant has two choices today: a key the admin can use, or no
automation at all. That gap, "an unattended key that the host's admin cannot
misuse", is exactly the problem agent-keys is built around, for a different
chain.

## 3. Every option

| | Option | What it takes | Who enforces the spending rule | In scope here? |
|---|---|---|---|---|
| A | **The Bitcoin (or Litecoin) hot key in a hardware element on the BTCPay host** | secp256k1 signing. TPM 2.0 and the Secure Enclave cannot (the project's original dead end, `../ARCHITECTURE.md`); a few elements can (NXP SE050, OnlyKey: I, `../OWNER_DEVICES_ru.md`) | **nobody**: an admin on the host drives the element as a signing oracle. Bitcoin has no on-chain policy for outputs or amounts (no covenants deployed as of 2026-11, I), so the element only stops key *export*, not theft | **No.** It would reproduce the incident with one extra step |
| B | **Bitcoin signing inside a server TEE with a policy co-signer the host cannot bypass**: PSBT outputs only to the merchant's cold descriptor, per-period caps for refunds, expiry, owner approvals from a device the host cannot reach | a TEE on server hardware, attestation of the signer, a PSBT policy engine, Lightning aside | the TEE's policy, which the admin cannot change | **No, a different product:** the owner's [`77ph/BTCPayTEE`](https://github.com/77ph/BTCPayTEE) (private), which links back here for what it takes from agent-keys. This page only records the requirements (§6) |
| C | **Multisig with an external co-signer service** | a service that signs the second key under its own rules | the service | **No.** That is the hosted-custodian model of `LANDSCAPE.md` §2a; agent-keys exists to avoid it |
| D | **Timelocked vault scripts** (hot key spends only after a delay the cold key can interrupt) | script design, a watcher, user education | the script, for timing only; no amount or destination rule | **No.** A real Bitcoin mitigation, but not ours, and it still needs someone watching |
| E | **A BTCPay plugin for USDC on Base whose store wallet is a Kernel account** | a BTCPay plugin (C#), a Base RPC, `agent-signer` next to BTCPay, a mandate template | **the chain**: `AgentPolicy`, which the admin cannot change without the owner's hardware key | **Fits the architecture, but not built here.** On 2026-11-10 the owner moved the whole BTCPay integration, this option included, into [`77ph/BTCPayTEE`](https://github.com/77ph/BTCPayTEE); #13 closed. §4 and §5 stay as the design that project can take |
| F | **Lightning** (the LND node's credentials, the other hot asset) | — | — | **No.** Out of scope for both products until the Bitcoin side exists |

BTCPay itself leaves room for E: it keeps opt-in integrations for other
chains, hosts stablecoin plugins (USDt on Tron), and states that "BTCPay
developers don't add alternative coins on request. Adding a new coin
explicitly depends on the community and developers of those coins" (V,
[docs](https://docs.btcpayserver.org/FAQ/Altcoin/)). Ethereum is not on that
page (I: the old Ethereum plugin is no longer maintained).

## 4. Option E in detail

**Receiving.** The invoice address is the Kernel account. Receiving needs no
key, so nothing on the server can be stolen to redirect *incoming* funds
(see B2 for the display attack).

**Payouts.** Sweeps and refunds are UserOperations signed by the agent key in
the server's TPM (or any `hw-signer` backend) under an `AgentPolicy`
mandate. The admin who owns the server can make the key sign, but only what
the mandate allows.

**Sweeps to the merchant's cold address.** `AgentPolicy` caps ERC-20
amounts per operation and per budget (`_chargeToken`, V) but does **not**
constrain the recipient of `transfer`. The constraint is still expressible
today without a policy change: the owner deploys a `Forwarder` with one
immutable destination and approves it once for USDC (a root operation);
the mandate allow-lists only `Forwarder.sweep()`; `USDC.transfer` is not in
the allow-list. An admin can then only move the store's balance to the
merchant's own cold address. A per-token **payee list**
([#66](https://github.com/postcryptum-research/agent-keys/issues/66), deployed 2026-11-20) removes the
forwarder: allow `USDC.transfer` and list the cold address as the token's
only payee.

**Refunds.** They need arbitrary recipients. Two ways: a small refund mandate
(USDC cap per operation, budget per period, short expiry) whose worst case is
the budget, or refunds signed on the owner's phone. A budget is one total
per permission, so "per period" means one permission per period
(`permission add`). A store can use both:
automatic below a threshold, the phone above it.

**The owner.** Mandate changes, the forwarder approval, large refunds and
revocation are root operations signed on the owner's phone
(`../MOBILE_OWNER_DESIGN.md`), which the BTCPay host never touches. In the
terms of `LANDSCAPE.md` §2a this is the inalienable human-in-the-loop that
the Circle case lacked.

**Gas.** `WhitelistPaymaster` for sponsored payouts, or the account pays in
ETH under the mandate's value budget.

**The plugin.** C#, the BTCPay plugin API: invoice detection from USDC
`Transfer` events on Base with a confirmation depth, rates, and a payout
processor (I: BTCPay's automated payout processors) that calls
`agent-signer` for sweeps and refunds. Precedent for a stablecoin on another
chain: the USDt-on-Tron plugin (V, listed in the docs).

## 5. Threats, option E

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| B1 | **Admin compromise of the BTCPay host** (the incident) | the key never leaves the TPM; the mandate allows only `Forwarder.sweep()` and refunds within the budget; expiry forces renewal; the owner revokes from the phone | refunds up to the budget until the owner notices; alert on every payout |
| B2 | **The admin edits the store's receiving address** | not a custody problem: the plugin reads the account from `agent-signer`'s pinned config, not from an editable field | root on the host can edit files too; monitoring, as for any wallet |
| B3 | **Refund abuse** to attacker addresses | the refund mandate's cap and budget; the phone for anything above | the budget |
| B4 | **The oracle persists** after the compromise is found | `permission revoke` / `rotate` from the phone; short expiry; PCR sealing stops a changed boot chain from using the key, a runtime compromise does not (`../KEY_POLICY.md`) | the window until revocation |
| B5 | **Chain-side** (reorgs, confirmations, token blacklists) | the plugin's confirmation depth; USDC's issuer controls remain | not custody |
| B6 | **The owner's phone is lost** | `../RECOVERY_DRILL.md` | — |

## 6. Requirements for the Bitcoin and Litecoin side, recorded for the other product

Not designed here: that product is [`77ph/BTCPayTEE`](https://github.com/77ph/BTCPayTEE).
What the incident says it must have:

- unattended secp256k1 signing inside a TEE or secure element from which the
  host's admin cannot export the key;
- a spending policy the host cannot change: PSBT outputs only to the
  merchant's cold descriptor, per-period caps for refunds, expiry;
- owner approvals through a channel the host cannot reach (an inalienable
  human-in-the-loop device; the phone design here applies);
- attestation of the signer to the operator, so a swapped signer is visible;
- the Lightning node is a separate hot asset with its own answer.

## 7. What this project does next

Nothing BTCPay-specific. Since 2026-11-10 the BTCPay integration in all its
forms, the Bitcoin and Litecoin side (option B) and the USDC-on-Base store
wallet (option E), is the owner's separate project
[`77ph/BTCPayTEE`](https://github.com/77ph/BTCPayTEE); #13 was closed. This
page stays as the analysis that project builds on. What remains here from
the case is general: [#66](https://github.com/postcryptum-research/agent-keys/issues/66), a
per-token payee list, since deployed (2026-11-20), which replaces the forwarder
for any deployment that sweeps to a fixed address.

## Sources

- BTCPay Server, 2026-11-02: [BTCPay Server security incident: 2.4.1 and earlier](https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/); 2026-08-07: [Security advisory: BTCPay Server 2.4.2](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/)
- Infosecurity Magazine, 2026-11-03 (the Bitquery tally): [Hackers Exploit BTCPay Server Flaw to Steal Cryptocurrency](https://www.infosecurity-magazine.com/news/btcpay-server-flaw-cryptocurrency/); Ostorlab: [BTCPay Server Hot Wallet Thefts, Fixed in 2.4.2](https://blog.ostorlab.co/btcpay-server-hot-wallet-thefts.html)
- CoinDesk, 2026-11-02: [BTCPay tells users to turn off their servers after reports of drained wallets](https://www.coindesk.com/tech/2026/11/02/btcpay-a-bitcoin-payment-tool-tells-users-to-switch-off-their-servers-after-reports-of-drained-wallets)
- Forklog, 2026-11-02: [Хакеры похитили биткоины из горячих кошельков BTCPay Server](https://forklog.com/news/hakery-pohitili-bitkoiny-iz-goryachih-koshelkov-btcpay-server)
- BTCPay Server docs: [Hardware wallet integration](https://docs.btcpayserver.org/HardwareWalletIntegration/), [Altcoins FAQ](https://docs.btcpayserver.org/FAQ/Altcoin/)
- The Circle case and the I-HITL paper: `LANDSCAPE.md` §2a, [arXiv 2610.35835](https://arxiv.org/abs/2610.35835)
