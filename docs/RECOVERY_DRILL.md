# Recovery drill — procedure and pass criteria

*Draft, 2026-10-29. It answers the condition on decision D2 of
[`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md) §12: the biometric-only
default of the phone owner key leaves recovery as the only way out after a
broken sensor or a changed biometric, so "the recovery path must be robust
and tested before that default ships". This page defines what "robust and
tested" means, as a procedure anyone can run and a list of criteria that
either pass or fail. The mechanism itself is in
[`RESILIENCE.md`](RESILIENCE.md) §3.2 and §4; the first real run is in
[`SECURE_ENCLAVE.md`](SECURE_ENCLAVE.md) §13.*

Marks: **V** verified in code or on-chain; **I** inferred, to confirm in the
phase named.

## 1. What is being tested

The cold recovery key is an encrypted key file (`key create --keyfile`,
scrypt N = 2^18 + AES-256-GCM, passphrase typed at use), installed on
`P256RecoveryValidator`, which Kernel grants exactly one right:
`changeRootValidator` (V, `kernel::add_recovery_calldata`). The drill proves
that, with the owner key gone, the holder of the file and the passphrase can
take root, hand it to a new owner device, and leave the lost key powerless,
while the agent keeps running.

The drill has three layers, and all three must pass:

| Layer | Where | Proves |
|---|---|---|
| L1 — mechanism | local anvil, `tests/anvil_cli.rs::recovery_drill` (V) | the contracts and the CLI do what §2 says |
| L2 — the real artefacts | the operator's own recovery file, media and passphrase, offline | the file that exists can actually be used by the people who would need it |
| L3 — the real account | the testnet or production account, with the owner's explicit yes | the procedure works end to end on the chain, with the devices in use |

## 2. The procedure (L3; L1 runs steps 2 and 4–8 automatically)

Setup, once: the account has an owner key (any backend), an agent permission
in use, and a config `recovery.json` that names the key file. All commands
are `agent-signer …`, run where the key in question lives.

| Step | Command | Expected (V, run 2026-10-21 on Base Sepolia; steps 2 and 4–8 also in the anvil test) |
|---|---|---|
| 0 | `key check --keyfile <file>` | `OK: … signs (…)` after the passphrase; proves the file opens |
| 1 | `owner status --agent recovery.json` | `recovery: … installed = false` |
| 2 | `owner add-recovery --agent recovery.json` (owner key signs) | `recovery key installed: tx …`; `owner status` shows `installed = true, may take root = true, is root now = false` |
| 3 | *simulate the loss*: put the owner device away, or use a config that no longer names it | — |
| 4 | `owner recover --agent recovery.json` (recovery key signs, passphrase) | `the recovery key is root now: tx …`; `owner status`: `is root now = true` |
| 5 | `owner set-root --agent recovery.json --as-recovery --validator <P256Validator> --retire <P256Validator> --not-a-phone --new-key '<the new owner key, as a config names it>'` (the new key signs a challenge first; for a key on another machine give `--public-key <x>,<y>` instead of `--new-key` and answer the printed challenge with `key prove` there; when the new owner key is a phone's, give `--public-key <x>,<y> --to-phone <label>` in place of `--not-a-phone --new-key …`: the phone then shows that it holds the key first; with neither `--to-phone` nor `--not-a-phone` the command refuses) | `new key: holds the key … (signed a fresh challenge)`, then `root handed to …: tx …`; `owner status`: root validator is `P256Validator`, `is root now = false` |
| 6 | a root operation with the **new** owner key (`op send --root …`) | included |
| 7 | the same root operation with the **lost** owner key | refused before anything is sent: `the key about to sign (…) is not the account's root key (… in validator …)`. The CLI reads the root validator's key from the chain; the validator's own `AA24` is what the forge tests exercise |
| 8 | `demo --agent <new owner config>` (the agent key) | included: the permission survived |
| 9 | `permission show` | every field `ok` |

Steps 4 and 5 should be done in one sitting: between them the recovery key
**is root** and can sign any root operation (`SignAs::RecoveryAsRoot`, V),
which is more than the "changeRootValidator only" grant it had before. The
window is the operator's own; keep it short.

## 3. Pass criteria

The recovery path is **robust** when every item below holds, and **tested**
when L1–L3 have each passed within the periods in §5.

### 3.1 Artefacts (L2)

- [ ] **Two copies** of the recovery file on two media, in two places
      (`KEY_POLICY.md` rule 5; `RESILIENCE.md` §4).
- [ ] **Each copy opens**: `key check --keyfile` prints `OK` for both,
      run on a machine that is not the agent's host.
- [ ] **The passphrase is known to at least two people**, or to one person
      plus a sealed written copy in a third place. A recovery that one
      person's memory can defeat is not robust.
- [ ] **The public key on-chain matches the file**: `key show --keyfile`
      prints the file's `x`, `y`; `P256RecoveryValidator.publicKeys(account)`
      read on a block explorer shows the same pair. The CLI makes the same
      comparison before every `owner recover`, from the file's public half
      and without the passphrase, and refuses a file that does not match
      (V, `chain.rs` `check_recovery_key`); `owner status` still reports only
      the install state, so the explorer check stays in the drill (I: add the
      comparison to `owner status` too).
- [ ] **Nothing on the agent's host**: the file is never copied there,
      and the agent's config carries no `recovery` entry (only the owner's
      local config does).

### 3.2 Mechanism (L1, L3)

- [ ] Steps 0–9 pass in order on L3, with the outputs in §2. L1
      (`recovery_drill`) covers steps 2 and 4–8 and the wrong-file refusal
      of §4 (I: add steps 1 and 9 and the `is root now` lines to it; step 0
      needs a real key file, so it stays in L2).
- [ ] Step 7 fails with "not the account's root key", quoting the key the
      chain holds: the CLI read `publicKeys(account)` from the root validator
      and it is the new key, not the lost one. (Before 2026-11-03 this step
      ended at the EntryPoint with `AA24`; the check now runs before any PIN,
      touch or signature is spent. The validator's refusal itself is covered
      by `test_agent_keyIsNotRoot` and the P256Validator tests.)
- [ ] Step 8 passes: no agent permission was lost or re-installed.
- [ ] After step 5, `P256Validator.publicKeys(account)` is the **new**
      key, read from a block explorer on a device that is not the one that
      ran step 5 (the T2 check of the mobile design).
- [ ] For a phone owner (mobile design §2.2): the new key in step 5 is the
      phone's, and the phone's fingerprint matches what the CLI printed.

### 3.3 People and time

- [ ] **Someone other than the person who set it up** has run L1 and
      understood L3 from this page alone, without help. If they could not,
      the page is the defect.
- [ ] L3 completed in under **one hour** from "the owner device is lost" to
      step 8, by the people who would do it for real.
- [ ] The owner knows the two things that make recovery impossible
      (`RESILIENCE.md` §2.3): losing the file **and** the owner key, or
      losing the passphrase. Both are written down in the deployment's
      runbook, with where the copies are.

## 4. Failure modes the drill must exercise at least once

| What goes wrong | Expected behaviour | Drill |
|---|---|---|
| Wrong passphrase | `wrong passphrase, or the key file was altered`; nothing sent (V, `keyfile.rs`) | the signer unit test `roundtrip_wrong_passphrase_and_tamper`; do it once by hand in L2 |
| A byte of the file altered | the same error (AES-GCM authentication) | the same unit test |
| A different recovery file (another key) | refused before the passphrase: `the recovery key about to sign (…) is not the one installed on the account` (V, `check_recovery_key`) | L1 (`recovery_drill`) |
| `set-root` without `--retire` after a recovery | refused by the CLI: "retire the lost owner's validator" (V) | L1 (I: add a `chain.fails` case; not in `recovery_drill` today) |
| `set-root` to a validator that is already installed, without retiring it | refused: Kernel would keep the old key (V) | L1 (I: add a `chain.fails` case; not in `recovery_drill` today) |
| The recovery key is asked to sign an ordinary root operation **before** `recover` | the validator only has `changeRootValidator`: Kernel refuses (V, forge `test_recovery_canOnlyTakeOverRoot`). The CLI has no command that sends such an operation on the recovery validator's path; a config that names the recovery key as `owner` is refused earlier, before signing: `not the account's root key` (V, `chain.rs` `check_root_key`) | the forge test; L1 (I: add the CLI refusal case) |
| Steps 4 and 5 interrupted (laptop dies between them) | the recovery key is root; rerunning step 5 completes it | L3 once, deliberately |
| The new owner device is a phone whose key was reset | redo from step 4 with the next device: the recovery key is reusable until retired | documented; exercised when the phone work reaches P1 |

## 5. Cadence and evidence

- **L1** runs in CI once the repository has one, and by hand before every
  release of `agent-signer` until then.
- **L2** every **three months**, and after any change of media, passphrase
  or custodian.
- **L3** once before the biometric-only default ships (the D2 condition),
  once on each new chain the account lives on, and after any contract
  upgrade that touches the validators.
- **Evidence**: transaction hashes and the pasted `owner status` lines, as
  in `SECURE_ENCLAVE.md` §13. No device models, OS versions or file paths
  from personal machines.

## 6. What the drill does not cover

- **Coercion** of the passphrase holder (T8 of the mobile design): a
  timelock on recovery (`RESILIENCE.md` §3.4) is the answer, and is not
  built yet.
- **A compromised laptop during step 5** substituting the new key (T2):
  mitigated by the third-device check in §3.2, which is why it is a pass
  criterion.
- **Loss of both the owner key and the recovery file**: unrecoverable by
  design. The agent's mandate still bounds what the agent can do, and the
  funds are what the mandate lets it move, until expiry.
