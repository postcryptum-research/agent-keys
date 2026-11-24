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

## Beyond fuzzing: a proof of the budget

`contracts/test/BudgetProof.t.sol` states the budget rule with symbolic
amounts, so a proof holds it for every value, not for the values a
generator tried. Kontrol (KEVM, by Runtime Verification) proves it. Halmos
cannot run this codebase: its symbolic EVM has no MCOPY, which the
bytecode needs.

| Proof | What holds, for any amount |
|---|---|
| `check_tokenTransfer_oneOp` | a token `transfer` in one operation is accepted only within the token's cap per operation; the token's counter then equals the amount and stays within the budget; a refused one books nothing |
| `check_nativeTransfer_oneOp` | the same for a plain native transfer and the native cap and budget |
| `check_tokenTransfer_twoOps` | two token transfers in a row add up without wrapping and without passing the budget |

**The run of 2026-11-24** ([issue #124](https://github.com/postcryptum-research/agent-keys/issues/124#issuecomment-7131857893)):
- Setup: image `runtimeverificationinc/kontrol:ubuntu-jammy-1.0.255`, a copy of `contracts/` with this one test, the container limited to 12 CPUs and 11 GB.
- `kontrol build`: 3 min 24 s.
- `kontrol prove` with three workers: 6 min 41 s of wall time, about 4 GB of memory at the peak seen. The three proofs took 2 min 52 s, 2 min 42 s and 4 min 37 s.
- With three rules broken at once (the token budget off by one, the token's cap not checked, the native cap off by one), every proof fails, with the counterexamples `amount = 101` and `value = 1000000000000000001`, in 10 min 56 s.

**In CI:** `.github/workflows/kontrol.yml` runs the same by hand, once a week, and on a pull request that changes `AgentPolicy.sol`, the harness, `foundry.toml` or the workflow. The image is pinned by digest. Kontrol sends anonymous usage data unless `KPROFILE_TELEMETRY_DISABLED=true` is set, as the workflow does. The command to run it by hand is in the harness's header.

**What it does not prove** ([#130](https://github.com/postcryptum-research/agent-keys/issues/130)):
- **The batch, Safe and MultiSend paths.** Their loops run over a length the caller sets; they stay with the fuzzing above.
- **Value-faithfulness.** That the executed call moves no more than the policy counted needs a model of Kernel's `execute`; the differential tests are the evidence for it.
- **The breaks one at a time.** In the run above the three rules were broken together, not one at a time.
