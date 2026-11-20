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
| `testFuzz_differential_sourceAgainstTheDeployedInstance` | the policy in the source and the runtime code deployed to Base Sepolia on 2026-11-20 agree on every decision, every returned validation word and every view, 40 operations per seed, across uninstall and reinstall; here the operations also go through a Safe, MultiSend batches and x402 registrations |
| `testFuzz_differential_mandatesFromTheSeed` | both install or both refuse a mandate built from the seed (it draws from everything install must refuse), and what is then readable of it is the same |
| `testFuzz_differential_arbitraryCallData`, `…arbitraryInstallData` | the same answer from both for arbitrary bytes |

The differential tests exist because the source and the deployed instance
differ only in where they keep their state
([#83](https://github.com/postcryptum-research/agent-keys/issues/83)): any
difference in behaviour is a bug in one of them. When a new instance is
deployed, its runtime code replaces the vector in `contracts/test/vectors/`
and the differential tests then guard the next change.

```sh
cd contracts
forge test --evm-version osaka --match-contract PolicyFuzz                      # 256 runs each, seconds
FOUNDRY_FUZZ_RUNS=10000 forge test --evm-version osaka --match-contract PolicyFuzz   # about five minutes
```

**That they bite.** Thirteen rules were broken in the source one at a time
(the payee's upper bits not checked; the per-operation sum replaced by a
per-call check; a token budget and the value cap each off by one; the zero
selector allowed with a body; gas not charged to the budget; the payee list
not held for x402; the epoch not moved at uninstall; a Safe gas refund
allowed; and at install: a function outside the four on a limited token,
a payee twice, Permit2, a token twice). Every one is found at 256 runs.
Two were missed by the first form of the generator (a budget off by one,
the payee list for x402), which is why it now aims at a budget's last unit
and gives the listed token an x402 domain.

**What they do not cover.**

- The model covers the account's own calls and batches; Safe, MultiSend and
  x402 are held by the differential tests only, that is, against the
  deployed instance and not against an independent statement of the rules.
- `x402Reclaim` is not exercised (it asks the token for the nonce's state).
- Kernel, the EntryPoint, signatures and the other modules are outside:
  the existing tests run those end to end.
- A generator finds what it can reach. These reach the limits by aiming at
  them; a rule nobody aimed at may go unvisited.

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
