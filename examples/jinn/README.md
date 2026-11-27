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
ten commits on `Jinn-Network/mono` `next` at `151a464aa` (2026-10-21):

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
| `0009-feat-operator-jinn-signer-migrate-one-step-handover…` | `jinn signer-migrate`: hands a bootstrapped operator over to the Kernel in one idempotent command — the Kernel signs first and its mandate is checked, then the Safe(s) and the agent NFT move, and the attestation key is published; `--dry-run` shows the plan from the chain |
| `0010-fix-operator-a-Safe-module-is-authority-too…` | a Safe module is authority too: the "no authority" check of patch 0008 and the migration read the Safe's modules. While the agent EOA is an enabled module the daemon refuses to boot and the migration hands nothing over; every other enabled module is listed for the operator's review; + `test/hermetic/signer-migrate-refusals.test.ts` on Safe 1.3.0's own bytecode (the internal audit of 2026-11-28, finding AK-2026-11-28-02, #245) |

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

Then, with the daemon stopped, hand the operator over once:

```sh
jinn signer-migrate --dry-run --human   # the plan, read from the chain
jinn signer-migrate --yes               # the handover; safe to re-run
```

```
Migrated: agent EOA 0x7471bE25Ec54354c8D70491Ae10bd86705fAD030 -> Kernel <Kernel address>
  service Safe <Safe address>
    safe-modules           checked        (no module is enabled)
    kernel-approves-safe   done     <tx>  (the Kernel signs first: deployed, key proven)
    mandate-admits-safe    checked        (AgentPolicy admits Safe.execTransaction)
    safe-owner             done     <tx>  (swapOwner: EOA -> Kernel)
    agent-nft              done     <tx>  (ERC-8004 NFT -> Kernel)
    attestation-key        done     <tx>  (jinn.attestationKey = the EOA)
    eoa-has-no-authority   checked
```

(shape of the output; the steps and their order are what the Anvil test
asserts.) The Kernel signs and its mandate is checked *before* the Safe
changes hands, so the Safe is never handed to an address that cannot
operate it; a 1/1 Safe is required. The agent mandate must list
`(Safe, execTransaction)`, the Safe-routed calls the operator makes, and
`(IdentityRegistry, setApprovalForAll)` / `setMetadata`. With an
`AgentPolicy` from 2026-11-25 on, the agent cannot leave the Safe's
operator grant standing (#176), so the owner grants it once, as a root
operation, before the migration: `agent-signer op send --root --target
<IdentityRegistry> --data <setApprovalForAll(Safe, true)>`. The migration
then finds it and reports the step as `already`; the mandate needs no
`setApprovalForAll` entry. A separate fleet
identity Safe is migrated in the same run.

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

The daemon makes the same check at boot (patch 0008's
`assertAgentEoaHasNoAuthority`): it refuses while the EOA owns the Safe or
the agent NFT or is an enabled module of the Safe, and warns about every
other module.

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
  pins, is needed for the snapshot);
- live, Base Sepolia, agent key in TROPIC01: the operator's
  `KernelSafeBroadcaster` on venue-base's ledger and lock ran a Safe
  transaction (counter 25 → 26, tx
  `0xb57ad3641c3c0fad1fb6e00c3dad3cb2b17db51e4ea97754b932cdae0673d7e7`, ledger
  row resolved, logs cut to our userOp) and got `addOwnerWithThreshold` on
  the Safe refused by AgentPolicy (`policy-denied` → `permanent`);
- patch 0010 (2026-11-27), in runs that need no `agent-signer`: the
  operator's unit tests of the check and of the migration
  (`test/signer/attestation.test.ts`, `migrate.test.ts`: 16 pass), and
  `test/hermetic/signer-migrate-refusals.test.ts` on Jinn's snapshot with
  the anvil of the Foundry named above (3 pass). The second runs against
  Safe 1.3.0's own bytecode: with the agent EOA as a module the migration
  refuses and the Safe's owner is unchanged; after a swap done by hand the
  former owner still pays out of the Safe and the check refuses; three
  modules are listed across pages. Each rule was broken once on purpose and
  a test caught it (the module check in the daemon's check and in the
  migration, the paging). **Not re-run with this patch: the full loop
  above.** It needs an `agent-signer` built with a key backend and the
  monorepo's packages. `main.ts` and the CLI verb were not compiled against
  the monorepo's packages either.

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
the Kernel approves it (`setApprovalForAll(Safe, true)`, a direct call
through agent-signer — not `approve`, which the policy treats as an ERC-20
approval); then the plugin record is written Safe-routed through the
Kernel and read back. `jinn tasks submit` is switched the same way but only
covered by the existing unit tests and the typecheck, not run live.

Off-chain signatures (patch 0008). Jinn's documents — task.v1, execution
envelopes, captures, the legacy bridge — are raw secp256k1 signatures that
verifiers check against the address inside the document; a P-256 key in
hardware cannot produce them, and no verifier calls ERC-1271. So the agent
EOA keeps signing them, but as a **pure attestation key**: with
`config.signer` the daemon refuses to boot while that EOA still owns the
service Safe or the agent NFT, or is an enabled module of that Safe (patch
0010), and the Kernel publishes
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
