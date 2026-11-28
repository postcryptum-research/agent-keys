# Audit 3: the division of AgentPolicy and the Jinn fixes, 2026-11-28

An internal audit, the third of its kind: a re-audit of the pull requests
that answer [`audit2`](../audit2/README.md) and divide `AgentPolicy`
(#251), then of the changes made on top of them the same day. It is not an
external audit.

- **Date:** 2026-11-28 (UTC). The finding is numbered `AK-2026-11-28-01`.
- **State of the project:** test networks only; no transaction was sent to
  a network by the audit. The divided policy is in open pull requests and
  not deployed: the instances on the test networks are the earlier, whole
  policy until their redeploy, and "fixed" below names source commits only.

## Scope

| Part | Base | Audited head |
|---|---|---|
| The answers to audit2, policy and Jinn | `4295e00bcf7ef19a2cde92b191d6ad40604a543b` | `17f356b37b4215a43d16e9d70fb564f591d748ab`; `dbf108cd56c80931d56cff224bbbe18ee3e9fd7b` (#252) |
| #255, the division of `AgentPolicy` | `17f356b37b4215a43d16e9d70fb564f591d748ab` | `a05eaea98c32d8309af262c5019e810466d90a44` |
| #257, `SafeShapes` reads each word with one calldata load | `a05eaea98c32d8309af262c5019e810466d90a44` | `52fb4608cd00896e78c7099cfafe3b53b539c129` |
| #258, the Jinn boot check, the Safe's guard and fallback handler | `dbf108cd56c80931d56cff224bbbe18ee3e9fd7b` | `5ca779a98c38829f37c81536e5715a6a61628dfa` |
| #259, a venue's pause over its registered orders | `52fb4608cd00896e78c7099cfafe3b53b539c129` | `f9d0a3277eadfd25a297c5fca671e7eb0e1aad58` |
| #261, one budget where the native token is an ERC-20 too | `f9d0a3277eadfd25a297c5fca671e7eb0e1aad58` | `0359e51a09c18f1e93902587fc8373c4350668da` |
| #260, the Jinn skill page (patch 0014) | `5ca779a98c38829f37c81536e5715a6a61628dfa` | `e730b8023979ed78deb5d5104683cc451d45e493` |

Read: `AgentPolicy`, `PolicyInstall`, `PolicyStorage`, `PolicyRules`,
`IShapeJudge`, `SafeShapes` and the calls between them; the phone's review,
facts and encoder (`mobile/owner-core`); the CLI's chain session; the Jinn
patches 0010 to 0014 with Safe 1.3.0's storage layout; the end-to-end path
of the CLI and the phone's review, with ERC-7562 traces.

## Method

The diffs were read and checked first, without the earlier report; the
conclusions were then compared with audit2, with the commit message of
`a05eaea` (the fixes of two earlier independent reviews) and with #250.
Tests ran in separate copies of the repository.

## Verdict

**No Critical, no High. 1 Medium. No Low.** No change in #255, #257, #259
or #261 lets the agent go past its mandate.

| # | Severity | Where | Summary | Issue | Fix | State |
|---|---|---|---|---|---|---|
| AK-2026-11-28-01 | Medium | Jinn example | A Safe without an ERC-8004 identity is handed over without the Kernel ever proving it can sign | #262 | #260 | fixed in the example (patch 0015, with B1 to B4 and the identity pair in 0016 to 0020), in review |

## The finding

### AK-2026-11-28-01 (Medium): the handover of a Safe without an identity

**Where:** the Jinn migration (`jinn signer-migrate`), patch 0011 onward.
Present since #252; #258 keeps it.

For a Safe with an identity, the migration makes the Kernel publish
`jinn.attestationKey` through the agent's key before `swapOwner`; if that
signature fails, the Safe stays with the old EOA. For a Safe **without** an
identity, the identity steps are "not-applicable" and the only check left
is `mandate-admits-safe` (the Kernel's code and `AgentPolicy.isAllowed`).
Then the old EOA runs `swapOwner` to the Kernel, which is never asked to
sign. `isAllowed` proves that the mandate exists on chain, not that the
agent's key, its backend and `agent-signer` can sign now; the final check
of the migration reads the old EOA's authority, not the new owner's ability
to act.

**Shown:** the migration run with a Safe without an identity and a Kernel
whose signing always fails reported success with one EOA transaction and no
Kernel signature at all.

**Impact:** after a reported success the agent cannot act for the Safe
through the hardware-signed path. The owner's root key can repair it with
root operations and a rotation; without that key the Safe and its assets
can be stuck. No attacker gains anything: Medium, for availability.

**Fix asked for:** before the first `swapOwner` of such a Safe (not on a
re-run that finds it handed over), require a fresh, successful operation
signed with the agent permission of that same Kernel account, checked on
chain; until then, refuse the handover of a Safe without an identity. A
root signature does not replace it: it proves another key. A regression
test: no identity and a Kernel that cannot sign, and `swapOwner` is never
sent.

## The findings of audit2

| # | State at the audited heads |
|---|---|
| AK-2026-11-27-01, a zero-address paymaster | fixed in the source (#249): the policy reads sponsorship by the paymaster's address; a field shorter than 52 bytes, or naming the zero address, is refused |
| AK-2026-11-27-02, the former EOA as a Safe module | fixed in the example (#252), and extended to the fleet identity Safe (#258) |
| AK-2026-11-27-03, the standing operator grant | fixed in the example (#252): the grant is the owner's root operation, and the identity path proves the agent's key before the swap; what is left for a Safe without identity is AK-2026-11-28-01 |
| AK-2026-11-27-04, `transferFrom` and its source | accepted and documented (#249, `docs/AGENT_CONFIG.md`, `docs/CONTRACTS.md`), held by tests |

## What was confirmed of the division (#255, #257)

- `pause` finds a judge's pins from the selectors recorded at install and
  calls no module; the owner and the guardian have separate pause bits, and
  the guardian never lifts the owner's; install refuses the selectors the
  policy owns and more than eight per judge.
- The layout keeps the order of the earlier mappings, the new ones after
  them; `PolicyInstall` runs by DELEGATECALL with the account as the caller,
  and a direct call creates no mandate the policy reads.
- A selector's pin, its allow-list kind and the Safe nonce guard agree: a
  plain Safe call and a direct or nested batch open no way around them. The
  positions a judge answers are bounded by the policy's own calldata; the
  target, value and kind it answers stay the owner's trusted judge.
- `SafeShapes`' word reads: every read lies within the calldata, and two
  differential fuzz tests (20,000 runs each) hold its answers equal to the
  earlier slice reader's.
- In the Jinn patches: the guard and fallback handler slots are Safe
  1.3.0's; a guard that is also an enabled module adds no power and is shown
  to the operator; the two-Safe and the one-Safe topologies hold.

## The delta: #259, #261 and #260

No finding. The answers to the questions put with it:

| Question | Answer |
|---|---|
| A1, a venue's pause and its registered orders (#259) | keep: the tag fits the record's first slot, is keyed with the account inside, and is derived the same way where it is written and read; a paused venue's order is neither vouched for nor settled. The tag has 79 bits of entropy (the lowest is set); a collision can only refuse orders |
| A2, the policy takes a judge's answer on target, value and kind | keep: an owner-pinned, trusted module; the phone's table of known judges must not be weakened, and an unknown judge is never a default |
| A3, a judge that reverts makes validation revert | keep for this redeploy; a bounded call later, if third-party judges are admitted, with a budget measured for judges (#263) |
| A4, the guardian lifts its own pauses only | keep; a view of who paused is useful for tooling, not a security requirement (#264) |
| B1 to B4, the rest of #250 | change, all four: both Safes checked before either is handed over (and each again just before its own); a mandate listing `(IdentityRegistry, setApprovalForAll)` refused at migration and boot; the printed owner command's `--sponsored` only where that operation's sponsorship is established; `schemaVersion: 2`. Done in #260, patches 0016 to 0019 |
| C1, one budget on Arc: is the charge complete and only tightening? | keep: every path that moves the face reaches its per-operation total, read once after all calls are judged; naming a wrong token or decimals only adds a limit. The CLI then took the face from its config; it now takes only the chain's own, as the phone does |
| C2, a reclaimed x402 payment returns to the token's budget only | keep: conservative, and it keeps the reclaim apart from the native budget |
| C3, about 150 gas per validation for the face's flag | keep |
| C4, the fourteen-word form built from the twelve-word encoding | keep: right for every canonical encoding. The policy's decoding is loose, as `abi.decode` is, and some malformed input reverts with an ABI panic rather than `InvalidConfig`; the phone refuses non-canonical input before a signature, so no mandate is widened |

## The redeploy

**Nothing in the contracts of #259 and #261 blocks deploying the exact
head `0359e51a09c18f1e93902587fc8373c4350668da` to the test networks.**
Before the phone and the new mandates are used on them:

1. With the real addresses, every deployments file and the phone's facts
   on every chain: the policy lists (payees, trading, ids, shape judges,
   guardian, native face) and `SafeShapes`' addresses and code hashes. At
   the audited head the judge table is empty and the new capabilities are
   enabled for the local test chain only: the phone refuses the new
   mandates until then, which is the safe direction.
2. A real run on Arc testnet: the phone's review, the owner's install, and
   an agent operation under a mandate that names the native face. The
   local-chain differential cannot show one, since the local chain's gas
   token is ether.
3. The CLI's fixtures rebuilt and the fixture and ERC-7562 checks run on
   the final deployment. The earlier instances are not described as fixed
   before the owners have moved to the new ones.

## Notes without severity

- The Jinn migration treats an inconsistent identity pair (an agent id
  without a registry, or the reverse) as "no identity"; refusing it is
  better. Done in #260, patch 0020.
- Comments: the config's slot of the face flag, the forms that carry a
  period, the tag's entropy; `x402Pending` answers four words since #259.
  Done in #261, without a change of bytecode.

## Checks run

| Check | Result |
|---|---|
| `forge test --evm-version osaka`, #255 / #257 | 6,455 / 6,457 passed, 0 failed, 125 skipped |
| `SafeShapes` differential, #257 | 2 tests × 20,000 runs, passed |
| `mobile/owner-core`: `cargo test --features ffi,test-chains` | 80 passed |
| `signer`: `cargo test` | every test that ran passed; 2 hardware tests ignored |
| `signer`: the local-chain suite (`anvil_cli`, 2 threads) | 26 passed, 1 hardware-only ignored |
| ERC-7562, the traces of that suite | 116 operations, none outside the gate |
| `scripts/erc7562`: `npm run check` | the recorded traces and 5 regression tests pass |
| `scripts/test-fixtures.py` | the fixtures are the build |
| `cargo clippy`, signer and owner-core | no denied arithmetic or cast lint |
| Jinn `test/signer/`; migration refusals on Safe 1.3.0 | 51 passed; 6 passed |
| The delta's added tests, and the full Foundry, owner-core and local-chain suites at `0359e51` | passed |

## What it did not cover

The Kontrol proofs and the fork-only tests; hardware backends on real
devices and the phone itself; the native Gradle and Xcode builds; the full
Jinn unit suite and its full loop with the Kernel owner in this run; live
networks and the bytecode on them; third-party libraries beyond the paths
named.
