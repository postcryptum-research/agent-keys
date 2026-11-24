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

## Rust

Not built yet. The code that reads input it has no reason to trust, most
important first:

- `mobile/owner-core/src/review.rs`: what the phone shows the owner, from
  bytes a laptop sent (its reading of a mandate is held to the policy's
  install by the test below);
- `signer/crates/hw-signer/src/enclave_blob.rs`: a DER reader in front of
  CryptoKit;
- `signer/crates/agent-signer/src/der.rs`, `attestation.rs`, `x402.rs` (a
  server's answers) and `mobile/owner-core/src/request.rs`.

The tool for these is `cargo-fuzz` (libFuzzer; it needs a nightly
toolchain), with the same two kinds of rule: no panic and no hang on any
bytes, and agreement with a second implementation where there is one.

## The phone's review against the policy's install

What the owner is shown of a mandate and what `AgentPolicy` installs from
the same bytes are two readings in two languages. One test holds them
together: `the_phone_reads_a_mandate_as_the_policy_installs_it`, among the
CLI's local-chain tests (`signer/crates/agent-signer/tests/anvil_cli.rs`).

```sh
cd signer
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli the_phone_reads_a_mandate -- --nocapture
MANDATE_DIFFERENTIAL_CASES=20000 cargo test ...    # more mandates than the 400 of a normal run
```

Mandates come from a seed: mostly well-formed and near what an install
must refuse, a quarter of them damaged (a bit flipped, the end cut off, a
word added, a word's top bit set). Each one goes two ways. The phone
reviews a root operation that installs it as a permission, built the way
`permission add` builds it, and the test also takes the terms the review
read (`owner_core::review::mandate_terms`, the function the review itself
calls). On a local chain with the deployed policy's code, a Kernel account
calls `onInstall` with the same bytes.

**The rules.**

- A mandate the review lets the owner sign is one the policy installs.
- For such a mandate the policy's views give back what the review read and
  nothing more: the window and the two native limits (`configs`); every
  call of the generator's pools allowed exactly when the review lists it
  (`isAllowed`, 9 targets by 9 functions); for each token whether it is
  limited, its two limits, its x402 domain and whether it has a payee list
  (`tokenLimit`); every payee of the pool reachable exactly when the
  review says so (`payeeAllowed`).
- The review may refuse what the policy installs. Today that is one kind:
  bytes the policy decodes although they are not the one encoding of
  their values.
- The generator reaches all three outcomes, or the test fails: at least a
  fifth shown and installed, a fifth refused by both, one in a hundred
  installed and not shown.

**That it bites.** Sixteen rules were broken in the review's reader one at
a time: fourteen refusals (the account or its EntryPoint as a target; the
policy outside x402; a limit past 128 bits; a time past 48; a window never
open; no call; a token twice; Permit2; a function outside the four on a
limited token; a payee twice; a payee list for a token without a limit;
targets and functions of different lengths; the payee form without a
list; an encoding that is not canonical) and two misreadings (the budget
read as the value cap; a payee list dropped). Every one fails the test at
400 mandates. Dropping the canonical-encoding rule is seen only by the
count of mandates installed and not shown falling to none: over these
mandates the policy read such bytes as the review would have. Two were
missed by the first form of the generator (the lengths, the payee form
without a list), which is why it now makes both.

**What it found.** The first run had 152 of 400 mandates that the review
showed and the policy refused to install: a limit past 128 bits or a time
past 48, no call at all, a window that is never open, a limit for the zero
address or two for one token, and a call to the account, to its EntryPoint
or to the policy outside its two x402 entries. No rights came of any of
them, since such an install fails on chain; but the owner would have
confirmed a screen that did not come true. The review now refuses each
(`a_mandate_the_policy_would_not_install_is_not_shown` in
`mobile/owner-core/src/review.rs` has one case per rule). No mandate was
found that the two sides read differently.

**What it does not cover.**

- It is a seeded test of a fixed number of mandates, not a campaign with
  coverage feedback.
- The views say what the policy stored. That the policy then enforces what
  it stored is the subject of the contract fuzzing above.
- Allowed calls and payees are probed over the generator's pools; an entry
  outside them that the policy stored and the review did not read would
  not be seen. A venue's configuration is not part of these mandates.
- The review's wording of a term on the screen (units, dates, names) is
  not compared, only the values it read.

## Third-party fuzzing tools

Agentic tools that write and run tests on their own are a source of ideas
for properties, not a part of this repository's build. One is never run on
a developer's machine or on any machine that holds a key.
