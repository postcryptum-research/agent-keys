# Audit 2: the whole repository at `4295e00`, 2026-11-28

An internal audit of a named commit, the second of its kind. It is not an
external audit.

**Preliminary.** The four findings are filed as issues; this page is
updated with the pull request of each fix as it lands.

- **Commit:** `4295e00bcf7ef19a2cde92b191d6ad40604a543b` (2026-11-27). The
  sources were taken with `git archive` of that commit, not from a working
  tree.
- **The report carries the date 2026-11-28; in UTC it was finished on
  2026-11-27.** Its findings are numbered `AK-2026-11-28-01` to `-04`.
- **State of the project:** test networks only; no transaction was sent to
  a network by the audit.
- **The deployed policy.** `contracts/src` does not differ between
  `b11adb7cf2dcb2660b4c93c81c62f8945e246706` and the audited commit, so the
  source read here is the source of the `AgentPolicy` recorded on the test
  networks, `0xdA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6`. The audit did not
  compare the bytecode on a chain with it.

## Scope

The 17 files of `contracts/src` (about 4,600 lines), the Rust signer,
`mobile/owner-core`, the native Android and iOS code paths, and the
integrations in `examples/`, the Jinn patches among them. Third-party
libraries were not audited as a whole: the paths of Kernel v3.3,
EntryPoint v0.7 and Safe that a finding rests on were read.

## Method

1. An audit of the commit made without reading the report of
   [`audit1`](../audit1/README.md).
2. A comparison with that report, finding by finding.
3. Each finding confirmed again with a proof of concept on a local chain
   (anvil, forge), in temporary copies of the repository.

Findings 01 to 03 were made in the first step.

## Verdict

**No Critical. 2 High, 1 Medium, 1 Low.**

| # | Severity | Where | Summary | Issue | Fix | State |
|---|---|---|---|---|---|---|
| AK-2026-11-28-01 | High | `AgentPolicy` | A paymaster field that names the zero address is not charged to the native budget, and the account pays | #244 | #249 | fixed in the source, in review; the test networks carry the fix after a redeploy |
| AK-2026-11-28-02 | High | Jinn example | After the handover the former EOA keeps full power over the Safe where it is an enabled module | #245 | #252 | fixed in the example, in review |
| AK-2026-11-28-03 | Medium | Jinn example | The migration's first step, a lone operator grant by the agent, is refused by the current policy | #246 | #252 | fixed in the example, in review |
| AK-2026-11-28-04 | Low | `AgentPolicy` | `transferFrom` is not held to a source: tokens a third party approved to the account can be moved | #247 | #249 | accepted as the function's meaning: stated for owners and held by tests, in review |

## The findings

### AK-2026-11-28-01 (High): a zero-address paymaster passes the native budget by

**Where:** `AgentPolicy.checkUserOpPolicy`; EntryPoint v0.7's
`_copyUserOpToMemory`, `_validateAccountPrepayment` and `_compensate`.

The policy decides who pays for gas by the length of a field:

```solidity
uint256 charged = value;
if (userOp.paymasterAndData.length == 0) charged += _maxGasCost(userOp);
```

The EntryPoint decides by the address it unpacks from the field. With 52
bytes or more whose first twenty are zero it has `paymaster == address(0)`
and takes the ordinary branch **without a paymaster**: the prefund comes
from the account, and the policy has counted no gas. The prefund then
includes the field's two paymaster gas limits as well, and the cost
includes `preVerificationGas`, which the operation's signer sets. The
caller of `handleOps` names the beneficiary that is paid.

**Scenario.** The agent signs an operation its mandate allows, with
`paymasterAndData = address(0) ‖ uint128(0) ‖ uint128(0)` and a large
`preVerificationGas`. The same operation with an empty field is refused,
over the budget. With the zero-address field it passes validation and
runs; the policy records `spent == 0`; the account pays more than its
whole budget and the beneficiary receives it. The proof of concept used a
budget of 0.25 ether, `preVerificationGas` of 300,000,000 and a fee of 1
gwei, through a full `handleOps`.

**Impact.** A compromised agent key moves the account's native balance and
its EntryPoint deposit past the budget the owner set. The funds there and
the gas fields bound it, not the mandate. Every mandate on the policy is
affected; the operation's calls can all be allowed ones.

**Recommended.** Take sponsorship from the unpacked address, not from the
length; count the whole prefund where the address is zero, or refuse such
a field. A regression through `handleOps` with the 52-byte field.

**Resolution (#249).** Who pays is read as the EntryPoint reads it. An
empty field is charged as before; a field that names no paymaster, shorter
than its 52 fixed bytes or with the zero address, is refused; a
paymaster's field passes uncounted as before. Held by
`test_gas_aPaymasterFieldThatNamesNoPaymasterIsRefused` (through
`handleOps`, with the account funded to pay: nothing runs, nothing is
spent, no beneficiary is paid), by
`test_gas_aPaymasterFieldShorterThanItsFixedPartIsRefused` and by
`testFuzz_gas_whoPaysIsWhatTheEntryPointReads` over any field. The rule
was broken once in two ways and the tests failed. The `AgentPolicy`
instances on the test networks were built before the fix and carry the
finding until they are redeployed
([`docs/DEPLOYMENTS.md`](../../docs/DEPLOYMENTS.md)).

### AK-2026-11-28-02 (High): the former EOA as a Safe module

**Where:** the Jinn example, `examples/jinn/patches/0008-…` (the check
that the keystore EOA has no authority) and `0009-…` (the migration);
Safe's `ModuleManager.execTransactionFromModule`.

`assertAgentEoaHasNoAuthority` checks `Safe.isOwner(agentEoa)` and the
owner of the ERC-8004 agent NFT. The migration requires a 1/1 Safe and
swaps its owner from the EOA to the Kernel account. Neither reads the
Safe's modules. A module is not an owner, `swapOwner` does not remove it,
and a call from a module needs only that the caller is enabled:

```solidity
require(msg.sender != SENTINEL_MODULES && modules[msg.sender] != address(0), "GS104");
success = execute(to, value, data, operation, type(uint256).max);
```

**Shown on a real Safe.** A 1/1 Safe owned by the EOA, with the same EOA
enabled as a module. After the swap `isOwner(former)` is false and
`isModuleEnabled(former)` is true, and the former owner makes a call from
the Safe.

**Impact.** After a migration that reports that the EOA has no authority,
it keeps any CALL and DELEGATECALL from the Safe, past `AgentPolicy` and
`SafeNonceAssert`. It needs the EOA to have been made a module before;
the checks do not refuse that configuration. Hashes the former owner
approved earlier are not part of this: Safe requires the approver to be a
current owner.

**Recommended.** Read the modules before the migration and in the check:
refuse while the EOA is one, or disable it in the same step as the swap.
Other modules have the same power: have the operator review each. A
regression in which the former EOA is a module.

**Resolution (#252, patch 0010 of the example).** The check and the
migration read the Safe's modules: while the EOA is an enabled module the
migration refuses before anything changes hands, in a dry run too, and the
daemon refuses to boot. Every other module is named for the operator's
review (`safe-modules: review`). Held by unit tests and, on Safe 1.3.0's
own bytecode on Jinn's snapshot, by
`test/hermetic/signer-migrate-refusals.test.ts`: the migration refuses and
the owner is unchanged; after a swap done by hand the former owner still
pays out of the Safe and the check refuses. Jinn's full solution loop
showed why the review matters: a service Safe that stOLAS creates has
three modules from the start (its distributor, its guard and the recovery
module), and the loop now asserts that the step names them.

### AK-2026-11-28-03 (Medium): the migration against the current policy

**Where:** the Jinn example, `examples/jinn/patches/0009-…`, the step
`kernel-approves-safe`; `AgentPolicy`'s rule for operator grants.

The step sends, with the agent's permission, the single call
`IdentityRegistry.setApprovalForAll(Safe, true)`. The current policy
requires an operator grant the agent opens to be withdrawn before the same
operation ends: a lone grant ends with one open, and validation fails.
`test_allowances_anOperatorGrantIsWithdrawnInTheSameOperation` holds
exactly that.

**Impact.** `jinn signer-migrate` cannot complete on the current policy,
and the example's later Safe-routed writes to ERC-8004 are blocked with
it. Adding the withdrawal to the batch does not help: the Safe's standing
right would be gone again.

**Recommended.** A grant that stays is the owner's: sign it on the root
path. Split the migration into the owner's step and the agent's steps, and
run it against the current policy, not an older bytecode fixture.

**Resolution (#252, patch 0011 of the example).** The migration never
sends the grant. Its step `owner-approved-safe` reads
`isApprovedForAll(Kernel, Safe)`; when the grant is missing it changes
nothing and prints the owner's root command. The proof that the Kernel's
agent key signs before the Safe changes hands is now a call the mandate
lists and the current policy admits: the publication of the attestation
key. The loop's bytecode fixture carries the `AgentPolicy` of #249, and
Jinn's full solution loop with a Kernel owner passes on it with an
`agent-signer` built with software keys
([`examples/jinn/README.md`](../../examples/jinn/README.md)).

### AK-2026-11-28-04 (Low): `transferFrom` and its source

**Where:** `AgentPolicy._chargeToken`.

For `transferFrom(from, to, amount)` the policy reads the amount, applies
the cap, the budget and the payee list to `to`, and does not look at
`from`. An operation the agent signs can move the tokens of any address
that gave the account an allowance; inside a Safe transaction, of any
address that gave the Safe one. Shown through a full `handleOps` with an
installed permission: one test token of a third party went to a recipient
the agent chose.

**Impact.** Tokens of a third party, within the token's `maxPerOp` and
budget. It needs `transferFrom` on the owner's allow-list for a token with
a limit, and an allowance given beforehand. A boundary of access control,
not a drain of the account.

**Recommended.** Hold `from` to the holder (the account for a direct call,
the Safe inside a Safe transaction), or state that allowances others gave
are within what such a mandate hands to the agent. Tests for both
contexts and both kinds of payee list.

**Resolution (#249).** The second answer: no change in the code. An
account pays out of its own balance with `transfer`; `transferFrom` on an
account is for collecting what others approved to it, and holding `from`
to the account would leave it without a use. The rule is stated where an
owner writes a mandate
([`docs/AGENT_CONFIG.md`](../../docs/AGENT_CONFIG.md)) and in
[`docs/CONTRACTS.md`](../../docs/CONTRACTS.md), for ERC-6909's form too:
listing `transferFrom` hands the agent what others approved to the account
and, inside a Safe transaction, to the Safe. `test_token_transferFromMovesWhatOthersApproved`
holds it for a direct call and a Safe transaction, with a payee list and
without.

## The findings of audit 1, read again

Read at `4295e00bcf7ef19a2cde92b191d6ad40604a543b`, after this audit's own
list was made.

| Finding of audit 1 | State | By what |
|---|---|---|
| AK-M-1: the wrong key on the screen for `changeRootValidator` | fixed | the phone refuses `validatorData` that is not empty; a regression test |
| AK-S-1: a bundler's gas unbounded | fixed | estimates are bounded; a fee floor and a fee ceiling. The factor per chain is the owner's setting |
| AK-C-1: a venue's spender as a target | fixed | install reads `spender()` and bars it; tests |
| AK-S-2: panics on wide gas values | fixed | checked conversions and bounded parsing |
| AK-S-3: overflow and endless lifetime of an x402 authorization | fixed | saturating sum, held between 120 and 3600 seconds |
| AK-E-1: address case in a trace | fixed | recursive lower-casing, keys included; a test |
| AK-E-2: the factory of a first operation | fixed | the factory is read from the trace; a test |
| Note: an uncaught error on a malformed trace | fixed | refused with a clear error; a test |
| Note: bytes after a P-256 key at install | fixed | exactly 64 or 96 bytes |
| Note: a TPM key's `authFile` lost | fixed | unknown fields refused; `pcrs` with `authFile` refused |
| Note: the mode of an auth file | fixed | readable by group or others is refused |
| Note: the mode of enrollment records | fixed | owner-only, also over an existing file |
| Note: registering again after a reclaim | stays a note | the entry is deleted and can be registered again: an agent holds its own budget, nothing is taken |
| Note: the wording about the x402 entry points | stays a note | the code admits the three calls correctly; no weakness |

The ERC-7562 set grew: traces with a factory, with a paymaster, of
transient storage and of the rule-breaking policy are in it.

These findings do not repeat the earlier ones: 01 is another way in which
the policy and the EntryPoint differ, 02 and 03 belong to the Jinn
migration, which is later than audit 1, and 04 is about an allowance given
by a third party.

## What was run

| Check | Result |
|---|---|
| `contracts`: `forge test --evm-version osaka` | 5282 passed, 0 failed, 125 skipped (fork and hardware tests) |
| `signer`: `cargo test` | every test that ran passed; 2 hardware tests ignored |
| `mobile/owner-core`: `cargo test` | 68 passed |
| `cargo clippy`, signer and owner-core | no denied arithmetic lint; ordinary warnings remain |
| `scripts/erc7562`: `npm run check` | the recorded traces and 5 regression tests pass |
| `examples/jinn`, `examples/agentkit`: `npm run typecheck` | pass |
| `examples/elizaos`: `npm run typecheck` | passes after `npm install`; the commit has no lock file there, so `npm ci` does not apply |
| `signer`: the local-chain suite (`anvil_cli`) | 19 passed, 6 timed out, 1 ignored |

The six timeouts came on opening a new TCP connection in the differential
tests, not on an assertion about the policy; run one at a time, one passed
and the others timed out again. The audit counts them neither as passed
nor as a defect of the product.

## What it did not cover

Hardware backends on real devices (TPM, YubiKey, TROPIC01) and the
fork-only tests were not run. The native phone apps were read; no full
Xcode or Gradle build was made. Third-party libraries beyond the paths
named above.

## Order of the fixes

1. AK-2026-11-28-01: the policy's notion of sponsorship made the
   EntryPoint's, with a regression on the zero-address paymaster.
2. AK-2026-11-28-02: the former EOA as a Safe module checked before the
   migration ends.
3. AK-2026-11-28-03: the standing operator grant moved to the owner's
   root path, and the migration run against the current policy.
4. AK-2026-11-28-04: `from` held to the holder, or third-party allowances
   stated as part of what the mandate hands over.
