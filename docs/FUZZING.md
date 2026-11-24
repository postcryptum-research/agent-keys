# Fuzzing

Fuzzing is a stage of its own beside the tests and the audit: it replaces
neither. The tests hold what someone thought of; the audit is a careful
read; fuzzing tries a great many inputs nobody wrote down and checks them
against a rule that must hold for all of them.

## Contracts: `AgentPolicy`

`contracts/test/PolicyFuzz.t.sol`. The policy is driven at its own
interface (`onInstall`, `checkUserOpPolicy`, the views), without Kernel,
keys or signatures, so a run is cheap. Operations come from a seed: mostly
well-formed and near the limits (a cap, one over, the last unit of a
budget, one past it), with a share of damaged ones.

| Test | What must hold |
|---|---|
| `testFuzz_model_decisionsAndCounters` | a second, plain statement of the rules (the model in the test) and the policy decide every operation alike, 40 in a row per seed, and count alike; no counter passes its limit |
| `testFuzz_model_arbitraryCallDataIsRefused` | bytes that are no `execute` call are never let through |
| `testFuzz_model_arbitraryExecuteBodyStaysWithinLimits` | an `execute` with arbitrary bytes behind it moves no counter past one operation's limits |
| `testFuzz_differential_sourceAgainstTheDeployedInstance` | the policy in the source and the runtime code deployed to Base Sepolia on 2026-11-20 agree on every decision, every returned validation word and every view, 40 operations per seed, across uninstall and reinstall; here the operations also go through a Safe, MultiSend batches and x402 registrations. Between operations the account asks for a registered authorization back (`x402Reclaim`), as registered or with one field changed, after time has moved or the token has come to say the nonce was used: both answer alike, and as the rule says on its own (only what is registered, past its `validBefore` and not settled comes back, once, and the token's counter falls by exactly its value) |
| `testFuzz_differential_mandatesFromTheSeed` | both install or both refuse a mandate built from the seed (it draws from everything install must refuse), and what is then readable of it is the same |
| `testFuzz_differential_arbitraryCallData`, `…arbitraryInstallData` | the same answer from both for arbitrary bytes |

The differential tests were written when the source and the deployed
instance differed only in where they kept their state
([#83](https://github.com/postcryptum-research/agent-keys/issues/83)): any
difference in behaviour was a bug in one of them, and 10,000 runs found
none. That source was deployed on 2026-11-21 and its runtime code is now the
vector in `contracts/test/vectors/`, so today both sides are the same code
and the differential tests guard the next change to the source. The model
tests do not depend on the vector.

```sh
cd contracts
forge test --evm-version osaka --match-contract PolicyFuzz                      # 256 runs each, seconds
FOUNDRY_FUZZ_RUNS=10000 forge test --evm-version osaka --match-contract PolicyFuzz   # about six minutes
```

**That they bite.** Seventeen rules were broken in the source one at a time
(the payee's upper bits not checked; the per-operation sum replaced by a
per-call check; a token budget and the value cap each off by one; the zero
selector allowed with a body; gas not charged to the budget; the payee list
not held for x402; the epoch not moved at uninstall; a Safe gas refund
allowed; and at install: a function outside the four on a limited token,
a payee twice, Permit2, a token twice; and in `x402Reclaim`: before
`validBefore`, of a settled authorization, returning nothing, leaving the
record). Every one is found at 256 runs.
Two were missed by the first form of the generator (a budget off by one,
the payee list for x402), which is why it now aims at a budget's last unit
and gives the listed token an x402 domain.

**What they do not cover.**

- The model covers the account's own calls and batches; Safe, MultiSend and
  x402 are held by the differential tests only, that is, against the
  deployed instance and not against an independent statement of the rules.
- `x402Reclaim` runs against a stand-in for the token that answers the one
  question it asks (was the nonce used); no real token is involved.
- **Contracts that are not ours are taken to be correct:** Kernel, the
  EntryPoint, Safe, MultiSend and Solady's P-256 verifier. The fuzzing
  holds this project's own code to its rules and does not look for errors
  in theirs; the policy is driven without them. The existing tests run
  the whole path through them end to end, on examples.
- A generator finds what it can reach. These reach the limits by aiming at
  them; a rule nobody aimed at may go unvisited.

## Contracts: trading

`contracts/test/TradingFuzz.t.sol`, for the budget per period and the
orders of [#80](https://github.com/postcryptum-research/agent-keys/issues/80).
A mandate with a period and one venue (CoW's decoder over a stand-in for
the settlement, whose fills the test decides) is driven at the policy's own
interface while the clock moves: to a period's last second, its first one
and the one after, among others. An operation names its period, the right
one or a neighbour, and carries transfers, order registrations and plain
calls; between operations the venue fills an order or the account asks for
one back. The account in the test does the EntryPoint's part: the policy
answers with a window and may not read the clock, so an operation counts
as accepted only if the clock is inside that window.

| Test | What must hold |
|---|---|
| `testFuzz_trading_modelDecisionsCountersAndOutflow` | the model and the policy decide every operation and every reclaim alike (an order that would outlive the period it is charged in is refused by both), 40 steps per seed, and count alike (native spent, token spent, the period seen); the account vouches for an order exactly while it is registered and not past its end; and, without leaning on the model's counters, in no period does more of the token leave than its budget, counting the transfers of that period and every order charged to it that the venue filled |
| `testFuzz_trading_noMoreThanTwoBudgetsAcrossARenewal` | the number the owner is shown: what is transferred in two neighbouring periods together is never more than two budgets |

```sh
cd contracts
forge test --evm-version osaka --match-contract TradingFuzz                        # 256 runs each, seconds
FOUNDRY_FUZZ_RUNS=10000 forge test --evm-version osaka --match-contract TradingFuzz    # under two minutes
```

10,000 runs of each find nothing.

**What it found while it was written.** The policy cut an operation's
window to its period with a lower bound one second early: it took the
EntryPoint to read `validAfter` as exclusive, and EntryPoint v0.7 reads it
as inclusive. In a period's last second an operation naming the next period
was accepted. Nothing more could be spent than the two budgets across a
renewal that the owner is told of, and no earlier test held that second.
The bound is corrected and the model holds it.

**What it did not find, and a review did.** An order or an x402
authorization was charged in the period it was registered in and stayed
good after that period: with a lifetime longer than a period, several
periods' registrations could be taken together, past the "twice a budget
and no more" the owner is shown. The model missed it for two reasons a
generator should be checked for: its orders lived 600 seconds against a
period of 1,000 and were filled within the step that made them, and it has
no x402 at all. The policy now refuses a registration that ends after its
period; the model holds the rule for orders and aims at the period's last
second and the one after it, and `Trading.t.sol` holds it for x402
(`test_period_anAuthorizationEndsWithThePeriodItIsChargedIn`: three days'
authorizations, of which only the last can still be used). Breaking the new
rule five ways (no check for x402, none for orders, each bound off by one,
the period's end not noted) is found every time.

**That it bites.** Eighteen rules were broken in the source one at a time:
the period's first second, the reset of the native and of the token counter,
the period's end, a refund across periods, a reclaim at `validTo` and of a
filled order, the record left after a refund, an order's end and its
"not before", the same order twice, an order past the cap, the budget off
by one, an order with value attached, an order not charged, a window of a
single second; these sixteen are found at 256 runs. Two are not, and cannot
be while the EntryPoint holds the window: accepting a period earlier than
one already seen (to have seen a later one, an operation must have been
accepted outside its window), and accepting a period index of fewer than
six bytes (it reads as an index 256 times larger or more, a window far
from now). Both checks stay in the policy; they do not rest on the clock.

**What it does not cover.** One venue, one pair, one token with a limit;
the decoder is the real one, the settlement is not. The mandate's own
window (`validAfter`, `validUntil`) is wide open here and is held by the
earlier tests. The Safe paths and x402 are not mixed in: x402 under a
period is held by examples in `Trading.t.sol`, not by the model.

## Rust

Not built yet. The code that reads input it has no reason to trust, most
important first:

- `mobile/owner-core/src/review.rs`: what the phone shows the owner, from
  bytes a laptop sent. Also as a differential target: what the review says
  a mandate installs against what `AgentPolicy` does install from the same
  bytes;
- `signer/crates/hw-signer/src/enclave_blob.rs`: a DER reader in front of
  CryptoKit;
- `signer/crates/agent-signer/src/der.rs`, `attestation.rs`, `x402.rs` (a
  server's answers) and `mobile/owner-core/src/request.rs`.

The tool for these is `cargo-fuzz` (libFuzzer; it needs a nightly
toolchain), with the same two kinds of rule: no panic and no hang on any
bytes, and agreement with a second implementation where there is one.

## Third-party fuzzing tools

Agentic tools that write and run tests on their own are a source of ideas
for properties, not a part of this repository's build. One is never run on
a developer's machine or on any machine that holds a key.
