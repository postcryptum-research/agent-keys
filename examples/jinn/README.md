# Jinn operator on a hardware-signed owner

[Jinn](https://github.com/Jinn-Network/mono) operators claim, deliver,
settle and verify work through a 1/1 **service Safe** registered with Olas.
Today the Safe's owner is an agent EOA whose key is derived from a mnemonic
in a keystore on disk; every Safe transaction is signed with it (eth_sign,
`v + 4`) and sent from it.

This example keeps the Safe — Olas staking, the mech and Jinn's router all
require it — and replaces its **owner**:

```
Jinn venue writer ──execute({to, value, data, operation})──▶ KernelSafeBroadcaster
    │  Safe.execTransaction(to, value, data, op, 0,0,0,0,0, sig = r:Kernel s:0 v:1)
    ▼
agent-signer op send --json ──▶ UserOperation signed in TPM / TROPIC01
    ▼
EntryPoint ─▶ Kernel ─▶ AgentPolicy: judges the *inner* call / every batch leg
    ▼
Safe (owner = Kernel) ─▶ router / mech / registries   (msg.sender = Safe, as before)
```

Why this works for Olas/Jinn contracts (details and file:line in
`ADAPTATION.md` §2): `ServiceRegistryL2.registerAgents` does not require the
agent instance to be an EOA; staking checks the Safe proxy's codehash and
threshold, not its owner's type; mech and router check `msg.sender == Safe`,
which stays true. Bonus: rotating the agent key no longer changes the agent
instance — the Kernel address stays, only the hardware key behind it rotates.

## What the policy enforces through the Safe

With `(safe, execTransaction)` on the agent's allow-list, `AgentPolicy`
(v3) decodes the Safe transaction and requires:

- inner `(to, selector)` on the owner's allow-list — e.g. Jinn's router and
  mech entry points, nothing else;
- inner value within the per-operation cap and the budget;
- `gasPrice == 0` (no refunds paid out of the Safe);
- no nested Safe transaction;
- the Safe transaction arrives as a batch whose first call asserts the
  Safe's nonce (`SafeNonceAssert`), so a retry of one that already landed
  reverts on-chain — the adapter fixes that nonce per `logicalTx` at the
  first attempt;
- `operation == CALL`, or DELEGATECALL into an allow-listed
  `MultiSendCallOnly.multiSend` whose every leg is a CALL that passes the
  allow-list (values summed).

So the Safe's own admin functions (`addOwnerWithThreshold`, `enableModule`,
`setGuard`, …) are refused for the agent — a compromised host cannot take
over the Safe or survive a revocation of its key. See `docs/ERC1271.md`.

## Run

```sh
npm install
npm run demo        # BASE_SEPOLIA_RPC_URL / BUNDLER_URL from ../../../.env
```

Output on Base Sepolia (2026-10-20), agent key in a TROPIC01, permission
`trs3` on AgentPolicy v3 with `(MultiSendCallOnly, multiSend)` in the mandate
(rotation tx `0xef321bd0cfce69f617c4efc28628d88f148134d0d4cdadd9a33cfaa03d5ff4aa`):

```
Safe 0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A (owner: Kernel 0xEdB645B14e2f952C5784e34949b58F0826fBc9E9), counter = 12
✔ single call (claim-like): tx 0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16, counter = 13
✔ MultiSendCallOnly batch (settlement-like): tx 0xd9bdc92ab3afac2baf9ab4ac8055c0cb5cbc195dd8a4db2b3f74025901c0fd31, counter = 15
✘ Safe adds an owner (compromised agent): policy-denied — refused by AgentPolicy on-chain
```

Under policy v2 (CALL only) the same batch was refused; the owner change is
refused under both.

## Integrating into Jinn: the patch series (first version)

[`patches/`](patches/) is a first version of `ADAPTATION.md` §5 Phase 1, as
twenty commits on `Jinn-Network/mono` `next` at `151a464aa` (2026-10-21):

| Patch | What |
|---|---|
| `0001-fix-venue-base-DEFAULT_MULTISEND_ADDRESS…` | upstream bug: the MultiSendCallOnly v1.3.0 constant had 39 hex digits (the final `D` was missing); + a test that fails without the fix — submitted upstream as [Jinn-Network/mono#5113](https://github.com/Jinn-Network/mono/pull/5113) (issue [#5112](https://github.com/Jinn-Network/mono/issues/5112)) |
| `0002-feat-venue-base-injectable-Safe-broadcaster…` | `createBaseVenue({ safeBroadcaster })`: a factory that receives the venue's own durable lock and submission ledger; `walletClient` optional when it is given |
| `0003-feat-operator-hardware-signed-Kernel-owner…` | `operator/src/signer/`: the `agent-signer` CLI as a typed call, `KernelSafeBroadcaster`, a viem transport for direct calls; the optional `signer` config section; wiring `main.ts` → composition root → venue; boot refuses if the Kernel does not own the Safe |
| `0004-test-operator-hermetic-solution-loop…` | `test/hermetic/full-loop-kernel-owner.test.ts`: Jinn's own hermetic solution loop with the service Safe owned by a Kernel account (below) |
| `0005-feat-bind-Safe-executions-inside-EntryPoint.handleOps…` | `ADAPTATION.md` §5 item 9: readers that bind an event to the Safe call behind it (`venue-base` `readVerdictSettlement`, the operator's solution-settlement binding) now also find that call inside `EntryPoint.handleOps` — so other operators recover our verdicts and our settlements are not marked orphaned |
| `0006-feat-operator-direct-calls-of-a-Kernel-agent-account…` | `ADAPTATION.md` §5 item 8: the agent's direct (non-Safe) calls — ERC-8004 `setMetadata` from `IdentityPublisher` and the SolverNet publisher — go through the Kernel via agent-signer; `tx-retry` sends a "user-operation wallet" once under the account's lock, without the EOA nonce / fee-bump / eviction / resend machinery |
| `0007-feat-operator-CLI-verbs-on-a-Kernel-owned-Safe…` | `ADAPTATION.md` §5 item 7: one-shot CLI verbs (`jinn tasks submit`, `jinn solver-plugins publish / revoke / block / feedback`) use the Kernel when `config.signer` is set — a `KernelSafeBroadcaster` on the daemon's own venue state (cross-process lock, shared ledger), no keystore decrypted |
| `0008-feat-operator-the-keystore-agent-EOA-as-a-pure-attes…` | `ADAPTATION.md` §5 item 10 (§4 option 2): the keystore agent EOA keeps signing Jinn's off-chain documents but must hold no on-chain authority — the daemon refuses to boot while it still owns the Safe or the agent NFT — and the Kernel publishes it as the agent's `jinn.attestationKey` |
| `0009-feat-operator-jinn-signer-migrate-one-step-handover…` | `jinn signer-migrate`: hands a bootstrapped operator over to the Kernel in one idempotent command; `--dry-run` shows the plan from the chain. Its steps and their order are as patches 0010 and 0011 leave them (below) |
| `0010-fix-operator-a-Safe-module-is-authority-too…` | a Safe module is authority too: the "no authority" check of patch 0008 and the migration read the Safe's modules. While the agent EOA is an enabled module the daemon refuses to boot and the migration hands nothing over; every other enabled module is listed for the operator's review; + `test/hermetic/signer-migrate-refusals.test.ts` on Safe 1.3.0's own bytecode (the internal audit of 2026-11-28, finding AK-2026-11-28-02, #245) |
| `0011-fix-operator-the-Safe-s-standing-grant-is-the-owner-…` | the Safe's standing approval on the IdentityRegistry is the owner's root operation: the migration reads it (`owner-approved-safe`) and never sends it with the agent's permission; the Kernel's agent key signs, under its mandate, before the Safe changes hands; the loop's bytecode fixture carries the current contracts (the internal audit of 2026-11-28, finding AK-2026-11-28-03, #246) |
| `0012-fix-operator-the-boot-check-reads-every-Safe-signer-…` | the daemon's boot check reads every Safe `jinn signer-migrate` hands over: the fleet identity Safe as well as the service Safe (the EOA as an owner, as a module, as the owner of the agent NFT), from one list that the migration and the boot share (`migrationTargets`) (#250) |
| `0013-fix-operator-a-Safe-s-guard-and-fallback-handler-are…` | each such Safe's guard and fallback handler are read from Safe 1.3.0's storage slots, at boot and in the migration's first step: a guard that is not also one of the Safe's modules, or a fallback handler other than Safe's `CompatibilityFallbackHandler` 1.3.0, refuses the boot and the handover; stOLAS's guard, a module of the service Safe, is reviewed as one (#250) |
| `0014-docs-operator-the-skill-page-lists-jinn-signer-migra…` | the operator's skill page, which `yarn skill:generate` makes from the CLI's verbs and `yarn skill:check` holds to them, lists `jinn signer-migrate`: the verb came with patch 0009 and the page did not have it (#250) |
| `0015-fix-operator-a-Safe-without-an-ERC-8004-identity-is-…` | a Safe without an ERC-8004 identity is handed over only with the operator's proof that the Kernel's agent key signs (`--agent-proof <userOpHash>`, step `agent-proof`): the EntryPoint's `UserOperationEvent` of a successful operation of the Kernel under the agent permission, at most an hour old; without it nothing changes hands (the internal audit of 2026-11-28 ([`audits/audit3`](../../audits/audit3/README.md)), finding AK-2026-11-28-01) |
| `0016-fix-operator-signer-migrate-checks-every-Safe-before…` | every Safe the migration hands over is checked (owners, threshold, modules, guard, fallback handler, the owner's grant, the mandate, the agent NFT, the agent proof) before the first changes hands, and again right before its own handover (#250, B1) |
| `0017-fix-operator-refuse-a-mandate-that-lets-the-agent-wi…` | the migration and the daemon's boot refuse a mandate that lists `(IdentityRegistry, setApprovalForAll)`, in the agent config or installed on the Kernel: with it the agent could withdraw the owner's grant to the Safe alone (#250, B2) |
| `0018-fix-operator-the-owner-s-command-carries-sponsored-o…` | the owner's printed command carries `--sponsored` only when the paymaster's per-operation cap and the account's remaining budget both cover the operation's maximum cost, sized as agent-signer sizes it; otherwise it says why it was left out (#250, B3) |
| `0019-fix-operator-signer-migrate-s-JSON-output-is-schemaV…` | the migration's JSON output is `schemaVersion: 2` (the changes from 1 below) (#250, B4) |
| `0020-fix-operator-half-an-ERC-8004-identity-is-refused-no…` | an agent id without an IdentityRegistry, or the reverse, is refused at boot and in the migration instead of being taken as no identity (#250) |

Apply and enable:

```sh
cd mono && git checkout 151a464aa && git am /path/to/agent-keys/examples/jinn/patches/*.patch
```

```jsonc
// ~/.jinn-operator/config.json
"signer": {
  "kind": "agent-signer",
  "bin": "/path/to/agent-keys/signer/target/release/agent-signer",
  "config": "/path/to/agent.json",          // its mandate allows (safe, execTransaction) + the router / mech calls
  "account": "0x…Kernel",                     // the agent's Kernel account (agent-signer derives / deploys it)
  "envFile": "/path/to/.env",
  "sponsored": true
}
```

Then, with the daemon stopped, hand the operator over once. The owner's
step comes first: the Kernel's standing approval of the Safe on the
IdentityRegistry, signed with the owner key on the root path (as the
account's first operation it also deploys the account):

```sh
agent-signer op send --agent /path/to/agent.json --env-file /path/to/.env --root \
  --target <IdentityRegistry> --data <setApprovalForAll(Safe, true)>
```

```sh
jinn signer-migrate --dry-run --human   # the plan, read from the chain
jinn signer-migrate --yes               # the handover; safe to re-run
```

A Safe without an ERC-8004 identity needs one more thing, the proof that
the Kernel's agent key signs (below): an operation the mandate allows, sent
with the agent key, and its userOpHash passed within the hour:

```sh
agent-signer op send --agent /path/to/agent.json --env-file /path/to/.env \
  --target <an allowed target> --data <its calldata>
jinn signer-migrate --yes --agent-proof <its userOpHash>
```

```
Migrated: agent EOA 0x7471bE25Ec54354c8D70491Ae10bd86705fAD030 -> Kernel <Kernel address>
  service Safe <Safe address>
    safe-modules           review         (enabled, each runs any call from the Safe without the Kernel and outside its mandate: <module address>, <module address>, <module address>; <module address> is the Safe's guard as well: it can veto every transaction of the Safe)
    owner-approved-safe    checked        (the owner's root operation gave the Safe its grant)
    mandate-admits-safe    checked        (AgentPolicy admits Safe.execTransaction)
    agent-proof            not-applicable (the Kernel signs in attestation-key)
    agent-nft              done     <tx>  (ERC-8004 NFT -> Kernel)
    attestation-key        done     <tx>  (jinn.attestationKey = the EOA: the Kernel's agent key signs)
    safe-owner             done     <tx>  (swapOwner: EOA -> Kernel)
    eoa-has-no-authority   checked
```

(shape of the output; the remarks in brackets below the first step are added
here. The unit tests assert the steps and their order.) A 1/1 Safe is
required. A separate fleet identity Safe is migrated in the same run. Every
Safe is checked before the first one changes hands (patch 0016): its owners
and threshold, modules, guard and fallback handler, the owner's grant, the
mandate, the agent NFT where there is an identity and the agent proof where
there is none. So a refusal on the second Safe comes while both are still
the EOA's, and it names the Safe ("the fleet identity Safe <address>, read
before any Safe changes hands: ..."). Each Safe is checked again right
before its own handover. A Safe whose fleet state has an agent id and no
IdentityRegistry, or the reverse, is refused, at boot as well, rather than
taken as a Safe without an identity (patch 0020): run the bootstrap again,
which records the two together.

**The owner's step** (`owner-approved-safe`). The Safe writes the agent's
ERC-8004 records only with the Kernel's standing approval, and a grant that
stands is the owner's to give: `AgentPolicy` refuses an operation of the
agent that leaves an operator grant open (#176), so the migration never
sends it with the agent's permission. It reads
`isApprovedForAll(Kernel, Safe)`; when the grant is missing, in a dry run
too, it changes nothing and prints the command above with the config's
`agent-signer` arguments, the registry's address and the calldata filled
in. The mandate needs no `setApprovalForAll` entry and must have none: with
one, the agent could withdraw the owner's grant by itself [V:
`test_allowances_anOperatorGrantIsWithdrawnInTheSameOperation` in
`contracts/test/AgentPermission.t.sol`, where the lone grant is refused and
the lone withdrawal passes]. The migration (in `mandate-admits-safe`, for a
Safe with an identity) and the daemon's boot refuse while the agent config's
`policy.allow` lists `(IdentityRegistry, setApprovalForAll)` or the
`AgentPolicy` installed for the permission admits it (patch 0017); the owner
rotates the permission to a mandate without that entry.

With `"sponsored": true` in the `signer` section the printed command
carries `--sponsored` only when the paymaster would sponsor it (patch
0018). The paymaster is the agent config's deployments file's
`whitelistPaymaster`, as agent-signer reads it, and this repository's
`WhitelistPaymaster` refuses an operation whose maximum cost (`maxCost`, its
gas limits times its fee cap) is above the account's per-operation cap or
above what is left of its budget. The migration reads both
(`sponsorships(account)`) and sizes the operation as agent-signer sizes a
root operation of one call before it asks a bundler: verification gas
300,000, or 1,500,000 for the operation that deploys the account; call gas
from `eth_estimateGas` of the Kernel's `execute` called by the EntryPoint,
plus 30%, at least 150,000 (before the account has code: the call from the
account's address plus 40,000, plus 30%, at least 300,000);
preVerification gas 100,000; the paymaster's verification gas 100,000 and
no postOp; and the fee cap as alloy estimates it from the node, twice the
next block's base fee plus the median 20th-percentile priority fee of the
last ten blocks. When the cost fits both, the command ends in `--sponsored`
and a line says what was compared; otherwise, or when the paymaster or the
gas cannot be read, it is printed without `--sponsored` and a line says
why. A bundler may replace agent-signer's figures, bounded at twice each
(its fee at twice the node's), so with a bundler the check is of the figure
that bound starts from: if the bundler sizes the operation above the cap,
the paymaster refuses it in validation [I: its `SIG_VALIDATION_FAILED`
fails the operation before it runs]; send it without `--sponsored`.

**Before the Safe changes hands.** The mandate is checked to admit
`(Safe, execTransaction)`; the agent NFT moves; and the Kernel publishes
`jinn.attestationKey` through agent-signer. That is `setMetadata`, a call
the mandate lists, signed by the agent key: the proof that the hardware key
signs for the Kernel under its mandate. It is sent in every run that still
has the Safe to hand over, whatever the registry already says, and when it
fails the Safe stays with the EOA (the NFT is then the Kernel's already:
fix the agent key or the mandate and re-run). So the Safe is never handed
to an address that cannot operate it. The agent mandate must list
`(Safe, execTransaction)`, the Safe-routed calls the operator makes, and
`(IdentityRegistry, setMetadata)`.

**A Safe without an ERC-8004 identity** (`agent-proof`, patch 0015). Such a
Safe has no attestation key to publish, so the migration sends no operation
of the Kernel's before the swap. Until patch 0015 the mandate check was all
that stood before it, and a Safe could go to a Kernel whose agent key or
backend does not sign (the internal audit of 2026-11-28 ([`audits/audit3`](../../audits/audit3/README.md)), finding
AK-2026-11-28-01). Now the operator proves it: `--agent-proof <userOpHash>`
names an operation the agent's mandate allows, sent with
`agent-signer op send` (no `--root`). The migration reads the EntryPoint's
`UserOperationEvent` for it, in the last 3600 blocks, and requires the
Kernel as its sender, `success`, a nonce whose key names the agent
permission (Kernel v3.3 puts the mode, the validation type `0x02` and the
permission id in the nonce key's first six bytes, as agent-signer builds
it; an owner's operation, on the root path, is key 0 and is refused) and a
block at most an hour old by its timestamp. An hour leaves time to send the
operation, read the dry run and run the migration, and not to bring one
from before a change of the key, the backend or the mandate. Without such a
proof nothing changes hands, in a dry run too, and the error says how to
make one. A re-run that finds the Safe handed over needs none.

**The Safe's modules** (`safe-modules`). A module is not an owner:
`execTransactionFromModule` runs any call or delegatecall from the Safe for
an enabled module, with no owner's signature and past `AgentPolicy` and
`SafeNonceAssert`, and `swapOwner` does not remove it. The migration reads
the modules before anything else. While the agent EOA is an enabled module
it refuses, in a dry run too, and nothing changes hands: disable the module
with a transaction of the Safe (`disableModule`) and re-run. Every other
enabled module has the same power over the Safe and is the operator's to
review; nothing is refused for it, and the plan and the result name each:

```
    safe-modules           review         (enabled, each runs any call from the Safe without the Kernel and outside its mandate: <module address>, <module address>)
```

A service Safe that stOLAS creates has three modules from the start: its
`ExternalStakingDistributor` creates the Safe through the factory with the
recovery module, then enables itself and its guard as modules
(`_createMultisigWithSelfAsModule` in
`contracts/src/vendor/stolas/ExternalStakingDistributor.sol` of the Jinn
monorepo). So on such a Safe the step reports `review`, as the loop on
Jinn's snapshot shows, and the operator reviews the three; a Safe without
modules reports `checked`.

**The Safe's guard and fallback handler** (read in `safe-modules`, patch
0013). A guard runs before and after every transaction of the Safe and can
veto each. The fallback handler answers the calls the Safe does not
implement, `isValidSignature` among them, so it decides the Safe's ERC-1271
answers. Safe 1.3.0 has no getter for either and keeps them at fixed
storage slots, which the migration reads with `eth_getStorageAt`. It
refuses, in a dry run too, and nothing changes hands:

- while the Safe has a guard that is not also one of its enabled modules;
- while its fallback handler is neither zero nor Safe's
  `CompatibilityFallbackHandler` of the Safe's `VERSION()`. For 1.3.0, the
  version the operator creates, Safe's deployment records
  (safe-global/safe-deployments) list two deployments of it on Base and
  Base Sepolia, and both pass:
  `0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4` (`canonical`; stOLAS's deploy
  script gives it to the service Safe) and
  `0x017062a1dE2FE6b99BE3d9d37841FeD19F573804` (`eip155`; protocol-kit
  gives it to the fleet identity Safe on Base). A handler of a version with
  no record is refused.

A guard that is one of the modules passes: a module already runs any call
from the Safe, `setGuard` included, so it is reviewed as the module it is,
and the review names it as the guard. That is the service Safe stOLAS
creates: its `MultisigGuard` is enabled as a module and set as the guard,
and it keeps itself set (its `checkAfterExecution` reverts when the guard
slot holds another address; `ADAPTATION.md` §3, M2). Refusing it would
refuse every staked operator, with no way to clear it. Clear a refused
guard or handler with a transaction of the Safe by its current owner
(`setGuard(0x0000000000000000000000000000000000000000)`,
`setFallbackHandler(<handler>)`) and re-run.

The daemon makes the same checks at boot (patch 0008's
`assertAgentEoaHasNoAuthority`), for every Safe the migration hands over:
the service Safe and, when it is another one, the fleet identity Safe
(patch 0012; one list, `migrationTargets`, serves both). It refuses while
the EOA owns such a Safe or the agent NFT or is an enabled module of the
Safe, and while the Safe has a guard or a fallback handler the migration
refuses (patch 0013); that error names what it found and that the owner
clears it with a root operation, a transaction of the Safe from the Kernel
signed with the owner key, since the mandate refuses the Safe's own
administration. It warns about every other module and says which one is
the guard. The threshold is the migration's check (a 1/1 Safe) and is not
read at boot. It also refuses while the agent's mandate lets the agent
withdraw the owner's grant to a Safe with an identity (patch 0017), and
while the fleet state gives a Safe half an identity (patch 0020).

**The migration's JSON output** (`jinn signer-migrate --json`) is
`{ schemaVersion, dryRun, kernel, agentEoa, safes: [{ label, safe, steps:
[{ step, status, txHash?, detail?, modules? }] }] }`. Patch 0019 raised
`schemaVersion` from 1 (patch 0009) to 2. From 1 to 2:

- `safe-modules` is a new first step (patch 0010), with a new status,
  `review`, and a new field, `modules`, the Safe's enabled modules;
- `kernel-approves-safe`, the grant the Kernel sent (`done`, `already`,
  `would`, `not-applicable`), is gone; `owner-approved-safe` takes its place as a read
  (`checked`, or `not-applicable` without an identity), and a missing grant
  is a refusal (patch 0011);
- `safe-owner` comes after `agent-nft` and `attestation-key`, no longer
  before them (patch 0011);
- `agent-proof` is a new step after `mandate-admits-safe`: `checked`, or
  `not-applicable` for a Safe with an identity or one handed over already
  (patch 0015).

No reader in the monorepo parses this output, so no fixture of version 1 is
kept: the version is for readers elsewhere.

How `KernelSafeBroadcaster` keeps a Safe transaction from running twice (a
`v = 1` signature does not commit to the Safe nonce): agent-signer asserts the
Safe nonce on-chain in the same batch (`--safe-nonce`), and every attempt is
written ahead to the venue's SQLite ledger, keyed by (chain, Kernel, Safe
nonce), with its userOpHash. An attempt with an unknown outcome is never
resent blindly (`permanent`); when its Safe nonce turns out consumed, the
next `execute` adopts it from the EntryPoint's `UserOperationEvent` if it was
ours.

Verified:

- `venue-base`: typecheck clean; its 204 unit tests + 3 new pass (the anvil
  fork test needs `anvil` and is a separate CI job upstream);
- operator: `tsc --noEmit` clean; Jinn's own test typecheck gate
  (`check-test-typecheck`) "no regression"; 13 new tests (against
  venue-base's real SQLite ledger and lock; a fake `agent-signer` binary
  for the CLI) catch each of three mutations (no adoption, wrong `v = 1`
  owner, no Safe-nonce assertion); 302 existing config / composition-root
  tests pass;
- **the full Jinn solution loop on Jinn's hermetic Anvil snapshot** (patch
  0004, 2026-10-21): the real production daemon bootstraps a staked
  operator, the test moves the service Safe's ownership from the agent EOA
  to a Kernel account (`swapOwner`), and the daemon — with
  `kernelSafeBroadcasterFactory` — discovers, **claims**
  (`router.claimTask`), executes the deterministic harness, **delivers**
  (`mech.deliver`) and **settles** (`router.claimSolutionDelivery`). Each of
  the three is checked to be a UserOperation of the Kernel through the
  EntryPoint (`UserOperationEvent.success`), signed by the agent key in
  TROPIC01 and admitted by a mandate of exactly
  `(Safe, execTransaction)` + those three calls; afterwards
  `Safe.addOwnerWithThreshold` through the Kernel is refused
  (`policy-denied`) and the Safe's owners are unchanged. The ERC-4337 side
  is installed from a committed bytecode fixture (`anvil_setCode`), so the
  run needs no live RPC; Jinn's baseline `full-loop.test.ts` still passes
  next to it (two consecutive runs, ~77 s for both). Run it with
  `TPM_SIGN_AGENT_SIGNER=…/agent-signer TPM_SIGN_KEYS=…/agent.json`
  (skipped otherwise; Foundry
  `nightly-1c7c4bebce1e075989780fd401bf6bffcb424746`, the version Jinn's CI
  pins, is needed for the snapshot). Since patch 0011 the keys file holds
  the owner key as well: the owner's grant to the Safe is a root operation
  of the test;
- live, Base Sepolia, agent key in TROPIC01: the operator's
  `KernelSafeBroadcaster` on venue-base's ledger and lock ran a Safe
  transaction (counter 25 → 26, tx
  `0xb57ad3641c3c0fad1fb6e00c3dad3cb2b17db51e4ea97754b932cdae0673d7e7`, ledger
  row resolved, logs cut to our userOp) and got `addOwnerWithThreshold` on
  the Safe refused by AgentPolicy (`policy-denied` → `permanent`);
- patches 0010 and 0011 (2026-11-27), on the monorepo with the eleven
  patches applied, an `agent-signer` built with software keys
  (`--features insecure-software-keys`, throwaway keys made for the run)
  and the anvil of the Foundry named above:
  - **the full loop above, with the Kernel owner, passes.** The owner's
    grant to the Safe is a root operation; the migration reports
    `safe-modules: review` (the staked service Safe has three modules, the
    stOLAS distributor among them, none of them the agent EOA) and
    `owner-approved-safe: checked`; the NFT moves, the Kernel publishes the
    attestation key, and only then the Safe changes hands; a re-run changes
    nothing; the daemon then claims, delivers and settles through the
    Kernel, and the mandate refuses `addOwnerWithThreshold`. It runs on the
    bytecode fixture of this repository's commit
    `54f1619cb244fbcab924b8bc2f9bd9b098e641d7`, whose `AgentPolicy` refuses
    a paymaster field that names no paymaster. Jinn's baseline
    `full-loop.test.ts` passes next to it;
  - `test/hermetic/signer-migrate-refusals.test.ts` (4 pass), against Safe
    1.3.0's own bytecode and the snapshot's IdentityRegistry: with the
    agent EOA as a module the migration refuses and the Safe's owner is
    unchanged; after a swap done by hand the former owner still pays out of
    the Safe and the check refuses; three modules are listed across pages;
    without the owner's grant nothing is sent;
  - the operator's unit tests of `test/signer/` (6 files, 40 pass),
    `tsc --noEmit` over the operator, `main.ts` and the CLI verb included
    (no error), and Jinn's test typecheck gate (`typecheck:test`: no
    regression);
  - each rule was broken once on purpose and a test caught it (the module
    check in the daemon's check and in the migration, the paging, the
    owner's grant, the Kernel signing before the swap);
  - the first runs of the full loop failed, on an expectation and not on
    the code: they expected `safe-modules: checked`, and the staked Safe's
    modules give `review`. Patch 0010 now asserts the modules instead.

  Not run: the loop with a hardware key, and the CLI verb
  `jinn signer-migrate` as a command (the tests call the migration it
  runs).
- patches 0012 and 0013 (2026-11-28), on the monorepo with the thirteen
  patches applied (`git am` of 0001 to 0013 onto a fresh `151a464aa`
  applies cleanly and gives the tree the tests ran on), an `agent-signer`
  built with software keys from this branch (throwaway keys made for the
  run) and the anvil of the Foundry named above:
  - **the full loop with the Kernel owner passes**, with the checks of both
    patches on the operator's own Safes. The staked service Safe's guard is
    stOLAS's `MultisigGuard`, one of its three modules
    (`0x4D3911420a8E4E7dB8c979f4915dA8983C5e3ba2` on Jinn's snapshot, what
    the distributor's `guard()` returns there), and its fallback
    handler is `0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4`: the migration
    refuses nothing for them and names the guard in `safe-modules`. The
    fleet identity Safe, which protocol-kit created, has no guard and the
    handler `0x017062a1dE2FE6b99BE3d9d37841FeD19F573804`; the loop hands
    over the service Safe only, and the check refuses the identity Safe by
    name while the EOA owns it. Jinn's baseline `full-loop.test.ts` passes
    next to it (34.6 s and 33.3 s). In a first run beside the unit suite
    the baseline loop timed out waiting for the settlement; alone, both
    pass;
  - `test/hermetic/signer-migrate-refusals.test.ts` (6 pass, 2 of them new),
    on Safe 1.3.0's own bytecode: a guard set with `setGuard` is read from
    its slot and refused, by the migration in a dry run and in a real run
    with nothing changed, and by the check after a swap done by hand; as a
    module as well it passes and is named; Safes set up with either 1.3.0
    handler pass, one with another handler is refused;
  - the operator's unit tests of `test/signer/` (6 files, 51 pass, 11 of
    them new); the operator's whole unit suite (`yarn test`: 8366 pass, 33
    skipped, and one failure that is not this change's:
    `test/_support/chain/anvil.test.ts` forks Base over a public RPC and
    its anvil was not ready within 15 s under the load of the suite; run
    again alone, it passes); `yarn typecheck` and `tsc --noEmit` over the
    operator (no error); Jinn's test typecheck gate (`typecheck:test`: no
    regression); the lint scripts of Jinn's CI for the operator
    (`lint:no-late-mount`, `lint:no-error-leak`, `lint:no-fixed-test-port`);
  - each rule was broken once on purpose and a test caught it: the fleet
    identity Safe left out of the list, the Safe's name ignored, no guard
    refused, every guard refused (then the full loop refuses the staked
    Safe's guard as well), any handler accepted, the two slots swapped, no
    pre-check in the migration, the check ignoring guard and handler.

  Not run: the daemon's boot itself (`main.ts`: the tests call the check it
  runs on each Safe of the list, and the typecheck covers the wiring), the
  loop with a hardware key, and the CLI verb as a command.
- patch 0014 (2026-11-28): `yarn skill:generate` adds exactly one row,
  `jinn signer-migrate`, and `yarn skill:check` then passes; `git am` of
  0001 to 0014 onto a fresh `151a464aa` applies cleanly and gives the tree
  that was checked.
- patches 0015 to 0020 (2026-11-28), on the monorepo with the twenty
  patches applied (`git am` of 0001 to 0020 onto a fresh `151a464aa`
  applies cleanly and gives the tree
  `2e03c2d059a665aa3873fd60a373264adfe72bfe`, which differs from the one the
  tests ran on in two code comments of patch 0015 only), an `agent-signer`
  built with software keys (throwaway keys made for the run) and the anvil
  of the Foundry named above:
  - **the full loop with the Kernel owner passes**, with these checks on
    the snapshot's chain: the owner's root grant is refused as an agent
    proof (its nonce key is the root path's) and the migration's
    attestation-key operation is taken as one; the migration's sizing of
    the owner's grant equals the operation agent-signer sent for it (no
    bundler there): the same verificationGasLimit (1,500,000, the
    operation that deploys the account), callGasLimit, preVerificationGas
    and maxFeePerGas; a run over both Safes refuses at the fleet identity
    Safe, which the mandate does not admit, and the service Safe and its
    NFT are still the EOA's; the `AgentPolicy` on the chain does not admit
    `(IdentityRegistry, setApprovalForAll)` for the loop's mandate, and the
    same agent config with that entry added is refused. Jinn's baseline
    `full-loop.test.ts` passes after it (34.8 s and 33.7 s);
  - `test/hermetic/signer-migrate-refusals.test.ts` (7 pass, 1 new), on
    Safe 1.3.0's own bytecode, with a stand-in at the EntryPoint's address
    that emits `UserOperationEvent` as it is given: a Safe without an
    identity is refused without a proof, for an unknown hash, an operation
    of another sender, a reverted one, one on the root path and one older
    than an hour (`evm_increaseTime`); a fresh one passes;
  - the operator's unit tests of `test/signer/` (6 files, 68 pass, 17 of
    them new); the operator's whole unit suite (`yarn test`: 8384 pass, 33
    skipped, no failure); `yarn typecheck` and `tsc --noEmit` (no error);
    Jinn's test typecheck gate (`typecheck:test`: no regression); the three
    lint scripts of Jinn's CI for the operator; `yarn skill:check` (passes:
    the verb's help changed, its name and summary did not);
  - each rule was broken on purpose and a test caught it every time, 21
    rules in 27 runs: for 0015, no proof accepted, the nonce key (also
    against the stand-in and against the full loop), the age (also against
    the stand-in), the sender, `success`, the step skipped; for 0016, no
    reading of every Safe first (also against the full loop), no check of
    the NFT's owner; for 0017,
    the config's entry, the installed mandate's, the step not calling the
    check, the selector's case; for 0018, the cap, the budget,
    `--sponsored` printed regardless, the first operation's call floor
    (also against the full loop), the fee's multiplier (also against the
    full loop), the paymaster's gas; for 0019, the version; for 0020,
    `migrationTargets` and the migration.

  Not run: the daemon's boot itself (`main.ts`: the tests call the checks
  it runs, and the typecheck covers the wiring), the CLI verb as a command
  (the tests call `migrateTargets`, which it runs), an owner's operation
  sponsored by a real `WhitelistPaymaster` (the loop has no paymaster: the
  sponsorship check is tested against a mocked `sponsorships`, and its
  sizing against agent-signer's own operation), an operation sized by a
  bundler, and the loop with a hardware key.

**The loop's bytecode fixture.**
`operator/test/_support/fixtures/tpm-sign-aa-code.json` holds the
EntryPoint, Kernel and Solady's verifier as read from Base Sepolia, and this
project's `P256Validator`, `P256Signer`, `AgentPolicy` and `SafeNonceAssert`
as built from this repository. A change to one of those four must reach it,
or the loop goes on running an earlier contract and passes: with the
`AgentPolicy` it carried before patch 0011 the loop admitted the agent's
lone grant to the Safe. One command rewrites the four entries in a Jinn
checkout that has the series applied:

```sh
examples/jinn/aa-fixture.py /path/to/mono
```

It runs `scripts/test-fixtures.py` first, which builds the contracts
(`forge build --evm-version osaka`) and fails when the CLI's own test
fixture is behind the build, then takes address and code of the four
contracts from that fixture and writes into the file's `_source` the last
commit of this repository that changed `contracts/src` or
`contracts/foundry.toml`: the sources the code was built from, whatever is
committed after them. Commit the file in the Jinn checkout and add the commit
to the series (`git format-patch -1 --start-number <n> --no-signature`).
The code is built for Osaka, as the CLI's tests run it; the anvil of the
Foundry that Jinn's CI pins runs those rules by default [V: on it `CLZ` and
the P-256 precompile at
`0x0000000000000000000000000000000000000100` answer, 2026-11-27].

Found by the Anvil run and fixed in agent-signer: the first operation of a
not-yet-deployed account used a fixed 300k `callGasLimit` (nothing to
simulate `execute` against), which starved Jinn's `claimTask` through the
Safe (`GS013`). It now estimates each inner call from the account's address
plus Kernel's overhead.

How peers read a Safe transaction sent by a smart account (patch 0005):
`safeExecutionsOf(publicClient, txHash)` in `marketplace-binding` returns the
Safe executions a transaction actually ran — the transaction itself when an
owner EOA sent `execTransaction`, or, for an EntryPoint v0.7 `handleOps`
bundle, the `execTransaction` calls inside the ERC-7579 `execute` (single or
batch) of each UserOperation whose `UserOperationEvent` (from that
EntryPoint) reports success. A reverted operation in the same bundle, or a
`UserOperationEvent` emitted by another contract, proves nothing and is
ignored. The direct path keeps its exact behaviour and error messages. Tests:
the helper on its own; both readers on a bundle (bound when the operation
succeeded, refused when it failed — and the new tests fail against the old
readers); and on real bytes, the Anvil loop's settlement transaction is
bound to `router.claimSolutionDelivery(requestId)`, run by the Safe, from
the Kernel.

Direct calls (patch 0006): with `config.signer`, `main.ts` gives the
identity and SolverNet publishers `createAgentSignerWalletClient` — the
Kernel's address as a json-rpc account over the agent-signer transport,
marked for `tx-retry`. `tx-retry` then sends each transaction exactly once,
under the same broadcast lock as the Kernel's Safe transactions (no EOA
nonce ledger, fee bump, stuck-nonce eviction or resend after an unknown
outcome); unmarked wallets keep the EOA path. ERC-8004 authorizes
`setMetadata` by the agent NFT's owner, so the NFT moves from the agent EOA
to the Kernel once (`transferFrom`), and the mandate lists
`(IdentityRegistry, setMetadata)`. Verified in the Anvil loop: after the NFT
transfer the solution loop still runs, then the daemon's publisher writes
ERC-8004 metadata through agent-signer (TROPIC01), read back from the
registry, sent as a `handleOps` of the Kernel. After the transfer the Safe
needs the Kernel's approval to write the agent's records (patch 0007); the
solution loop itself does not depend on it.

CLI verbs (patch 0007): a verb's Safe broadcaster is
`openCliKernelSafeBroadcaster` — the same `KernelSafeBroadcaster`, opened on
the daemon's venue state (`<earningDir>/../venue/venue.db`), whose
`BroadcastLock` is cross-process: a verb and a daemon serialize on the
Kernel (the verbs also keep refusing to run beside a live daemon), and the
ledger reconciles an attempt either of them left with an unknown outcome.
It refuses when the Kernel does not own the Safe. With a signer the
`solver-plugins` factories decrypt no keystore. Verified in the Anvil loop
with the production `solver-plugins` publisher: once the agent NFT belongs
to the Kernel, the Safe can write the agent's ERC-8004 records only after
the Kernel approves it (`setApprovalForAll(Safe, true)` — not `approve`,
which the policy treats as an ERC-20 approval); then the plugin record is
written Safe-routed through the Kernel and read back. In that run the
approval was a direct call of the agent through agent-signer, which the
`AgentPolicy` of that date admitted; it is the owner's root operation now
(the migration, above). `jinn tasks submit` is switched the same way but only
covered by the existing unit tests and the typecheck, not run live.

Off-chain signatures (patch 0008). Jinn's documents — task.v1, execution
envelopes, captures, the legacy bridge — are raw secp256k1 signatures that
verifiers check against the address inside the document; a P-256 key in
hardware cannot produce them, and no verifier calls ERC-1271. So the agent
EOA keeps signing them, but as a **pure attestation key**: with
`config.signer` the daemon refuses to boot while that EOA still owns the
service Safe or the agent NFT, or is an enabled module of that Safe (patch
0010), and the same for the fleet identity Safe (patch 0012), and the Kernel publishes
`jinn.attestationKey = <EOA>` under the agent's ERC-8004 identity (once;
`readAttestationKey` reads it back for a verifier). Its compromise forges
attestations — a reputational risk — but moves no funds and no rights;
those sit behind the hardware key and the mandate. Verified in the Anvil
loop: the check refuses before the Safe / NFT move and passes after, and
the binding is published through agent-signer once, then left alone. The
stronger form — P-256 as a second `signature.algo` in Jinn's documents,
signed by a separate hardware key — changes Jinn's verifiers and is a
proposal for their team (`ADAPTATION.md` §4 option 4). Leftover ETH on the
old EOA is the operator's to sweep.

Not in this version (the rest of `ADAPTATION.md` §5): verifiers that use
`jinn.attestationKey` (Jinn's side — today they trust the address inside
the document); `ValidationRegistryClient`, used only outside the daemon;
bootstrapping a new operator directly onto a Kernel and the master role
(Phase 2 — an existing one migrates with `jinn signer-migrate`); native
mode and its trust ceremony (Phase 3, needs a Jinn spec change).
