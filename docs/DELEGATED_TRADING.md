# Delegated trading under an on-chain mandate

*Design draft for discussion, 2026-10-22. Reviewed by the project's auditor
(verdict: sound with changes; the changes are folded in). Nothing here is
built yet beyond what is marked EXISTS.*

## The idea

- **A** owns the capital.
- **B** develops a trading strategy and runs a bot for it.
- A lets B's bot trade A's money, but only inside a risk frame that A
  signed. B is paid a share of the profit.

The original sketch: B sends A the strategy to sign; A transfers funds to
B's bot together with a signed policy; the bot trades within the policy and
sends the profit back to A and B.

The reworked version below keeps the intent but changes one thing: **the
money never leaves A's account.**

## Status legend

Every item is marked with one of these:

- **[EXISTS]**: the project already does this.
- **[IMPLEMENT — idea clear]**: we know what to build.
- **[DISCUSS — idea unclear]**: plausible, but key choices are open.

## The security model, in one sentence

**The mandate is a frame on the size, surface and timing of what the bot
can do — not a guarantee that B is honest.**

- **Today:** A's maximum loss to a malicious B is bounded by the mandate's
  budgets for native value, self-paid gas and the four metered ERC-20
  functions (`transfer`, `transferFrom`, `approve`, `increaseAllowance`).
  Any other allow-listed function that moves value (a vault's `withdraw`, a
  router's `swap` over an existing allowance) is gated by the allow-list but
  not metered.
- **Each control below shrinks that bound:**
  - argument checks (item 4);
  - the price check (item 5);
  - the drawdown limit (item 6).

  Built together, they move the loss bound from "the whole budget" towards
  "the slippage tolerance times the trading volume".
- **Nothing in this design makes a dishonest B honest.** It limits how much
  a dishonest B can take.

## The flow (reworked)

1. **B proposes a mandate,** not the strategy. The mandate says where to
   trade, which tokens, what sizes, how long, and with what maximum loss.
2. **A reviews the mandate and installs it** as a permission on A's own
   account. The permission is bound to B's bot key, and the funds stay
   where they are.
3. **The bot trades inside the mandate.** Anything outside it is refused
   on-chain.
4. **Profit is shared by an on-chain rule,** not by B sending money back.
5. **A can revoke or withdraw at any moment.** B can never withdraw.

## Items

### 1. Funds stay in A's account; B's bot gets only a key with a mandate — [EXISTS]

- A is the owner (root key) of a Kernel smart account.
- B's bot holds an agent key with a permission installed by A
  (`permission add`).
- A removes it with `permission revoke`, and can withdraw at any time with
  the owner key.
- B's key cannot withdraw, change the mandate or add owners.

This replaces "A transfers funds to the bot", in which the policy is only a
promise and B controls the money.

One caveat: revoking ends the bot's own access, but **not** token
allowances the bot already granted. See item 4.

### 2. The bot's key lives in hardware — [EXISTS]

- **Hardware:** a TPM, Secure Enclave, TROPIC01 or Windows TPM.
- **A stolen copy of the bot's disk** does not yield the key.
- **A compromised bot host** is still held to the mandate.

### 3. The mandate proposal from B to A — [IMPLEMENT — idea clear; security-relevant]

**The whole model rests on A understanding what A signs.** A mandate that A
approves without understanding defeats every other control, so the review
step is part of the security, not a convenience.

What exists today:

- B can send the mandate as an agent config file.
- `permission add --dry-run` shows the calldata.
- `permission show` compares the chain with the file.

Still missing:

- a human-readable review, for example: "lets the bot call `swap` on router
  X for USDC/WETH, recipient this account, at most N per trade, M in total,
  until date D";
- optionally, B's signature on the proposal.

### 4. Argument checks: recipient, spender, wrapped calls — [IMPLEMENT — idea clear for recipient/spender; DISCUSS for the general case]

Today's policy checks:

- the target contract and the function;
- the native value;
- for the four standard ERC-20 functions (`transfer`, `transferFrom`,
  `approve`, `increaseAllowance`), the **amount**, against per-token caps.

It does **not** check who receives:

- **`transfer(to, amount)`, swap recipients.** A bot allowed to call a
  `swap` or `transfer` can name B as the recipient, and every check passes.
- **The `approve` spender — the sharpest hole.** The bot calls
  `approve(B's contract, amount)` within the cap. From then on B pulls
  the tokens with `transferFrom` from its own address, with no agent key
  and no mandate involved. The amount is capped by the token budget.
  An allowance granted in one operation and left standing would **survive
  a revoke**: B could still pull it after A has revoked the bot.
  Resetting the allowance in a later operation would not help, because B
  chooses when to pull. The policy therefore refuses an operation that
  leaves an allowance of the agent's standing: it must be withdrawn
  (`approve(spender, 0)`) in the same operation (item 9). The spender
  itself is still unconstrained during that operation.

What needs to be built:

- recipient and spender rules per allowed function: the recipient is A's
  account, and the spender is one of the vetted routers, never anything
  else;
- token paths within the allowed tokens.

This simple part is clear: decode the known arguments of the standard
calls.

**The general case is open:** routers have `multicall`, batch functions
and callbacks that carry inner calls. A rule set only constrains the calls
it decodes. It must either decode recursively and completely, or restrict
the mandate to a vetted list of plain functions with no wrappers.

Comparable designs: Zodiac Roles (Safe), ZeroDev CallPolicy parameter
rules.

### 5. Price / slippage protection — [IMPLEMENT — idea clear; details: DISCUSS]

Even with the right recipient, the bot can trade at a bad price:

- into a pool that B controls;
- by sandwiching its own trades.

Every trade is then "allowed", yet value flows to B.

**The control:** the amount out must not be worse than an oracle price by
more than X%. It can only be judged after the swap, so it is a check at
execution time, not at validation (see "Requirements for the execution
hook").

Open questions:

- **Which oracle:** Chainlink, a TWAP from the venue, or both? What about
  tokens without an oracle — refuse them?
- **Tolerance:** how to set it, and is it per pair?

### 6. Maximum drawdown — [DISCUSS — idea unclear]

The goal: never lose more than Y% per day, or never fall below an absolute
floor.

This cannot be checked at validation. ERC-4337's validation rules
(ERC-7562) do not allow reading oracles or other contracts' storage there.
It can be checked by an execution hook after each operation.

Open questions:

- **Portfolio value (NAV):** which assets count, priced by which oracle?
  What about positions outside plain balances (LP tokens, lending)?
- **The window:** "per day" needs on-chain state, a daily starting value.
  When does it roll over?
- **Gas:** the cost of computing NAV after every trade.

### 7. NAV and the oracle are themselves an attack surface — [DISCUSS — idea unclear]

Items 5, 6 and 8 all rest on pricing A's portfolio. That pricing is
adversarial, not just a measurement problem. B can move value into a pool
B controls, or into an illiquid or unpriced token the oracle misprices.
That:

- **defeats the drawdown check,** because item 6 reads a NAV the attacker
  inflated;
- **lets B draw a real performance fee on fake gains** (item 8).

The drawdown limit and the fee are only as sound as the NAV oracle.

The likely answer:

- price only an allow-list of liquid tokens with robust oracles;
- count anything else as zero.

How to treat positions such as LP tokens is still open.

### 8. No approval-style signatures — [EXISTS today; must stay an invariant]

Besides on-chain `approve`, tokens accept **signatures** as approvals:

- EIP-2612 `permit`;
- DAI's `permit`;
- Permit2.

A smart account makes such signatures through ERC-1271 (`isValidSignature`).
If the agent key could produce one, B would get the same persistent drain
as in item 4, off the books.

Today the agent's account vouches only for what the agent registered within
the mandate: x402 payment authorizations (since AgentPolicy v6) and venue
orders (`orderRegister`), and for nothing else.
Every extension must keep it that way: **the agent key can never produce a
valid approval-style signature.**

### 9. Bounded token approvals — [EXISTS for the amount and the lifetime; the spender is item 4]

The token caps already limit the **amount** of every `approve`, and no
allowance the agent grants outlives the operation: the policy refuses an
operation that does not withdraw it (`approve(spender, 0)`) by its end.
The pattern is approve exactly the trade's amount, trade, withdraw, in
one batch. An operator grant of ERC-721 and ERC-1155
(`setApprovalForAll`) is held to the same rule, and so are ERC-6909's
`setOperator` and its allowance of one id (`approve(spender, id, amount)`);
the amounts of an id's transfers and allowances are bounded by limits per
id (`docs/CONTRACTS.md`, #186).
ERC-777's `authorizeOperator` cannot be listed in a mandate at all. Allowances and grants the
owner makes, such as a venue's spender's allowance, are not the agent's
and are not counted.

What remains:

- spender allow-listing (item 4).

### 10. Profit sharing for B (performance fee) — [IMPLEMENT once NAV is resolved (items 6–7)]

Instead of "the bot sends profit to A and B", a settlement function pays B
a share of the gain above a **high-water mark**: the highest portfolio
value already paid on. This is the usual hedge-fund rule, and Enzyme and
dHEDGE use it on-chain.

**It is an incentive mechanism, not a security control.** It inherits the
NAV problem of item 7: an inflated NAV means a real fee on fake profit.

Open questions:

- **Settlement:** how often it runs, and who pays the gas.
- **High-water mark:** how A's deposits and withdrawals adjust it.
- **Fee terms:** which token the fee is paid in, and whether there is a
  management fee as well.

### 11. The strategy stays B's secret — [EXISTS as a property]

A signs the **risk frame**, not the strategy. The mandate shows where and
how much, not why or when.

### 12. Pinning the bot's code — [DISCUSS — idea unclear]

**Attestation proves which code runs. It does not prove that the code is
safe or honest.** Protection against a dishonest B comes from the mandate
and the revoke, not from attestation.

Attestation adds something only if A (or someone A trusts) **audits that
specific binary and pins its measurement**. Then A trusts code that A
reviewed, not B.

Routes:

- **TPM:** a key sealed to PCR measurements of a known boot image (the
  project already supports PCR sealing), plus a TPM quote. Sealing proves
  host boot integrity, not that the strategy is sound.
- **TEE attestation:** Intel SGX/TDX, AWS Nitro Enclaves.

Open questions:

- How does A verify the attestation — once off-chain at install time, or
  on-chain?
- What happens on every bot update? New measurements mean a new key and a
  new mandate.
- **Secrecy versus audit:** attesting a binary is not the same as revealing
  its source, but an audit needs someone to see it.

### 13. MEV and front-running — [DISCUSS — idea unclear]

Trades in the public mempool can be sandwiched by third parties.

Options:

- a private order flow;
- the slippage bound of item 5;
- venues with MEV protection.

How much of this belongs in the mandate, and how much is B's own
operational concern?

### 14. Gas griefing — [EXISTS as a bound]

B can burn A's gas on reverting or useless operations. This is bounded by
the gas the mandate's budget allows, so it is griefing, not theft. It is
also worth watching.

### 15. Disputes and incentives between A and B — [DISCUSS — idea unclear]

- **Revocation:** A can revoke at any moment. Is B owed anything for the
  period so far? A notice period would be an agreement, not code, unless
  it is enforced on-chain.
- **Bad but legal trading:** if B's bot trades badly within the mandate,
  is there any recourse beyond revoking?
- **Several parties:** one B serving many A's, or one A with several B's.

### 16. Legal and regulatory — [DISCUSS — not a technical question]

Managing other people's crypto-assets for a fee is regulated in many
jurisdictions. In the EU, portfolio management of crypto-assets under MiCA
requires a CASP licence.

Keeping the money in A's account, with B only supplying an agent that acts
under A's mandate, may matter for how the activity is classified. It does
not settle the question. That is for a lawyer.

## Requirements for the execution hook (items 5 and 6)

The price and drawdown checks run at execution, because ERC-7562 forbids
oracle reads at validation. These are requirements, not open questions:

1. **After the call, and reverting.** Slippage and drawdown can only be
   judged after the swap has produced its output. The hook runs after the
   execution and reverts the whole operation when a limit is broken.
2. **Complete coverage.** The hook must apply to every way the agent can
   execute: single calls, batches, and any other execution mode the
   account offers. A hook over a subset certifies only that subset.
3. **Fail-closed.** If the oracle is stale or reverting, the trade is
   refused.
4. **Owner-controlled and inseparable.** Only A can install or remove the
   hook. The bot's permission must not be able to execute while the hook is
   absent.

## Summary

| # | Item | Status |
|---|---|---|
| 1 | Funds stay with A; the bot gets a key and a mandate | EXISTS (no allowance of the bot's outlives its operation — item 9) |
| 2 | Bot key in hardware | EXISTS |
| 3 | Mandate proposal and a review A understands | IMPLEMENT — idea clear; security-relevant |
| 4a | Recipient / spender checks | IMPLEMENT — idea clear |
| 4b | Wrapped calls (multicall, callbacks) | DISCUSS — idea unclear |
| 5 | Price / slippage check via an execution hook | IMPLEMENT — idea clear; details: DISCUSS |
| 6 | Maximum drawdown via an execution hook | DISCUSS — idea unclear |
| 7 | NAV / oracle as an attack surface | DISCUSS — idea unclear |
| 8 | No approval-style signatures (permit, Permit2) | EXISTS — must stay an invariant |
| 9 | Bounded approvals | EXISTS for amounts and lifetime (withdrawn in the same operation); spender → item 4 |
| 10 | Performance fee with a high-water mark | IMPLEMENT once NAV is resolved |
| 11 | Strategy stays secret | EXISTS as a property |
| 12 | Pinning the bot's code (attestation) | DISCUSS — idea unclear |
| 13 | MEV / front-running | DISCUSS — idea unclear |
| 14 | Gas griefing | EXISTS as a bound |
| 15 | Disputes and incentives | DISCUSS — idea unclear |
| 16 | Legal / regulatory | DISCUSS — not technical |

**Suggested order if this goes ahead:**

1. Item 4: recipient and spender, with no wrappers in the mandate.
2. Item 5, together with the hook requirements.
3. Items 3 and 9.
4. Items 6, 7 and 10 as one piece, once the NAV design is settled.
5. Items 12, 13, 15 and 16 need discussion before any code.

## Similar products

- **Brahma Console:** sub-accounts with policies for bots and agents.
- **Safe + Zodiac Roles:** permissions at the level of arguments.
- **Enzyme, dHEDGE:** vaults with restricted manager rights and
  performance fees.
- **ERC-7715 and session keys** (ZeroDev, Rhinestone): standard
  permission grants to agents.

What this design adds: **the bot's key is in hardware, and the risk frame
is enforced by A's own account.**
