# The agent config file

`agent-signer` reads one JSON file per agent permission — for example
`signer/agent.base-sepolia.json`, `signer/agent.tropic01.base-sepolia.json`,
`signer/agent.window-demo.base-sepolia.json`. This document lists every
field, its syntax and allowed values, and — just as important — how the file
relates to what the smart contracts enforce.

## The one rule: the file is intent, the chain is state

**Editing the file changes nothing on-chain.** The account enforces only what
was written into the contracts by an operation signed with the **owner** key
(or, after a recovery, the recovery key). The file is read:

- by the **owner**, as the description of what to install — the next
  `permission rotate` / `permission add` / `owner add-recovery` writes it
  on-chain, and only then;
- by the **agent**, to know which key to sign with, which permission it acts
  under (`permissionId`) and which account it acts for (`account`).

So a file edited on the agent's machine — by mistake or by malware — cannot
widen the agent's rights: raise `budget` to 1,000 ETH or add a target to
`allow`, and every operation outside the installed mandate is still refused
on-chain. What a wrong file *can* do is break the agent's own operations
(a wrong key or permission id makes them fail), or, on the owner's machine,
get installed by the next owner operation — check with `--dry-run` and
`permission show` before signing one.

To see what the chain actually enforces for a file's permission, field by
field next to the file:

```sh
agent-signer permission show --agent my-agent.json --env-file .env
```

```
  ok agent key       chain 0xff669706… / config 0xff669706…
policy module:  0x3f590A58…b424
  ok validUntil      chain 1795046400 / config 1795046400
DIFF budget          chain 3000000000000000 / config 999000000000000000000
DIFF allow           0x…dEaD 0x00000000  — in the config, NOT allowed on chain
```

(`DIFF` lines here come from a deliberately edited copy: the chain kept its
values.) `account status` and `owner status` show the account, its balances
and its root / recovery keys the same way.

## Example

```json
{
  "deployments": "../contracts/deployments/84532.json",
  "owner": { "tpm": "0x81010010" },
  "ownerPublicKey": { "x": "0xa616…dc09", "y": "0xebe5…fa45" },
  "agent": { "tropic01": { "port": "/dev/ttyACM0", "slot": 1 } },
  "recovery": { "keyfile": "/media/me/USB/recovery.json" },
  "permissionId": "0x74727334",
  "salt": "0x0",
  "account": "0xEdB645B14e2f952C5784e34949b58F0826fBc9E9",
  "policy": {
    "allow": [
      { "target": "0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1", "selector": "0xd09de08a" },
      { "target": "0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1", "selector": "0x00000000" }
    ],
    "maxValuePerOp": "1000000000000000",
    "budget": "3000000000000000",
    "validAfter": 0,
    "validUntil": 1795046400,
    "tokens": [
      { "token": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "maxPerOp": "20000000", "budget": "100000000" }
    ]
  }
}
```

(The public keys are shortened here; a real file carries all 64 hex digits.
The `tokens` entry is illustrative.) Unknown fields are an **error** (a
misspelled `validAfter` must not silently become 0). Field names are
case-sensitive.

## Fields

### Top level

| Field | Required | Type and syntax | Meaning |
|---|---|---|---|
| `deployments` | yes | path, relative to this file's directory (or absolute) | the module addresses for the chain: `contracts/deployments/<chainId>.json` |
| `owner` | yes | key spec (below) | where the owner (root) key lives; opened **only** to sign an owner operation |
| `agent` | yes | key spec | where the agent key lives; opened to sign the agent's operations |
| `permissionId` | yes | `0x` + exactly 8 hex digits (4 bytes) | which permission of the account this file describes; unique per account — a schedule uses one id per window |
| `account` | no | address | **pins** the deployed account. Without it the address is *derived* from the file (owner key, first permission, salt) — which changes as soon as the mandate changes, so pin it once the account exists |
| `ownerPublicKey` | no | `{"x": "0x…64 hex", "y": "0x…64 hex"}` | the owner's public key, as `key show` prints it. Lets the agent derive and deploy the account without the owner key being reachable. Needed when `account` is not pinned, and for the first operation that deploys the account |
| `agentPublicKey` | no | same | the agent's public key; lets the owner install or rotate to it from a machine that cannot reach the agent's chip |
| `recovery` | no | key spec (`keyfile` or a hardware key) | the cold recovery key (`owner add-recovery`, `owner recover`, `owner set-root --as-recovery`) |
| `salt` | no | hex number, default `0x0` | the factory salt; only affects the address of an account not deployed yet |
| `policy` | yes | object (below) | the mandate this permission should have |

### Key specs

Exactly one of:

| JSON | Backend | Notes |
|---|---|---|
| `{"tpm": "0x81010011"}` | TPM 2.0 (Linux), persistent handle | build with `--features tpm` |
| `{"tpm": {"handle": "0x81010012", "pcrs": [0, 2, 4, 7]}}` | TPM key sealed to those PCRs | signs only while the boot state matches |
| `{"tpm": {"handle": "0x81010013", "authFile": "/etc/tpm_sign/owner.auth"}}` | TPM key protected by a secret (created with `key create --auth-file`) | for an owner key on the agent's chip; the file root-only ([`KEY_POLICY.md`](KEY_POLICY.md) rule 3) |
| `{"secure-enclave": "label"}` | Apple Secure Enclave | `--features secure-enclave`, macOS |
| `{"windows-tpm": "name"}` | Windows TPM through CNG | `--features windows-tpm`, Windows |
| `{"tropic01": {"port": "/dev/ttyACM0", "slot": 1}}` | TROPIC01 USB devkit, ECC slot 0–31 | `--features tropic01` |
| `{"keyfile": "/media/…/owner.json"}` | encrypted key file | **owner or recovery only**, refused for the agent; asks the passphrase at use |
| `{"phone": {"label": "owner-phone", "publicKey": {"x": "0x…", "y": "0x…"}, "fingerprint": "ABCDE-FGHIJ-KLMNO-PQRST"}}` | the owner's phone ([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)) | **owner only**. `key create --phone <label> --agent <cfg>` enrolls the key and prints this snippet, with three records of the enrollment that the CLI does not act on: `"platform"`, `"attestation"` (`strongbox` or `tee` as the verified attestation says, `none` without evidence) and `"deviceCredential"`. The phone's answer is authenticated by a secret in the QR, and the CLI also asks for the fingerprint on the phone's screen (`--phone-skip-fingerprint` to rely on the secret alone, `--phone-fingerprint` for scripts); `fingerprint` is what the phone showed, and the key is refused before any session when it is not its `publicKey`'s. Every owner operation opens a one-shot LAN session behind a QR (`--listen`, `--phone-timeout`) |
| `{"software": "0x…64 hex"}` | plaintext scalar | **tests only**: refused in every role unless built with `--features insecure-software-keys` (the integration tests' build; never a release) |

### `policy` — the mandate

| Field | Required | Type and syntax | Meaning |
|---|---|---|---|
| `allow` | yes, non-empty | list of `{"target": address, "selector": "0x" + 8 hex}` | the calls the agent may make. `selector` `0x00000000` = a plain value transfer (empty calldata; 1–3 bytes of calldata are refused). One entry admits its call directly, through an owned Safe and as a Safe batch leg alike |
| `maxValuePerOp` | yes | decimal string, wei (≤ 2¹²⁸−1) | most native value one operation may move (including value moved inside a Safe transaction) |
| `budget` | yes | decimal string, wei | total native value over the permission's life, **plus** the maximum gas cost of each operation the account pays for itself |
| `validUntil` | yes | integer, Unix seconds, > 0 | end of the window: after it the EntryPoint refuses the agent's operations |
| `validAfter` | no, default 0 | integer, Unix seconds, < `validUntil` | start of the window (0 = at once); several permissions with their own windows make a schedule |
| `tokens` | no | list of `{"token": address, "maxPerOp": decimal string, "budget": decimal string, "x402": bool}` | per-token limits in the token's base units (USDC: 6 decimals, so `"20000000"` = 20 USDC). Required for every token whose `transfer` / `transferFrom` / `approve` / `increaseAllowance` is in `allow` — without one the call is refused. One entry per token. `x402` (default `false`): the agent may also pay x402 in this token (EIP-3009, e.g. USDC) from the same budget; the CLI reads the token's `DOMAIN_SEPARATOR()` and installs it with the limit ([`ERC1271.md`](ERC1271.md)) |

Never valid `allow` targets, refused by the CLI before anything is signed and
by `AgentPolicy` at install (`ForbiddenTarget`) and again at validation: the
**account itself** (Kernel's `grantAccess`, `installValidations`,
`changeRootValidator`, `execute`: the mandate would widen or replace itself),
its **EntryPoint** (`withdrawTo` on the deposit), the project's **validators,
signer, Kernel implementation and factory** (CLI only: they could replace the
owner, recovery or agent key), and the **policy itself** except its two x402
entry points. The Circle Agent Wallets case is why (`related/INCIDENTS.md`).

Special `allow` entries:

| Entry | Effect |
|---|---|
| `(safe, 0x6a761202)` — `Safe.execTransaction` | the account may drive that Safe (which it owns); the call *inside* each Safe transaction is judged against the same `allow`, value cap, budget and token limits; refunds, nested Safes and Safe self-administration are refused; each Safe transaction must come with an on-chain nonce assertion (`op send --safe-nonce`) |
| `(multiSendCallOnly, 0x8d80ff0a)` — `multiSend` | Safe transactions may delegatecall this batcher; every leg must be a CALL that passes the mandate |
| `(agentPolicy, 0x4993d616)` — `x402Authorize` | the agent may register x402 payments in its `x402` tokens; each is held to the token's `maxPerOp` and budget, and only registered ones get an ERC-1271 yes |
| `(agentPolicy, 0xf3ea183e)` — `x402Reclaim` | the agent may return expired, unused registrations to the budget (`x402 reclaim`) |

## From file to contracts

Where each field ends up, and which signed operation puts it there:

| Field | On-chain state | Written by |
|---|---|---|
| `owner` / `ownerPublicKey` | the root validator's key for the account: `P256Validator.publicKeys(account)` (Kernel's `rootValidator()`) | account creation (its first operation's `initCode`), or `owner set-root` (signed by the current root) |
| `agent` / `agentPublicKey` | `P256Signer.publicKeys(permissionId, account)` | `permission rotate` / `permission add` (owner) — and account creation for the first permission |
| `permissionId` | the Kernel permission `0x02 ‖ id`, with its signer and policy (`permissionConfig(id)`) and its EntryPoint nonce space | same |
| `policy.allow` | `AgentPolicy.isAllowed(account, id, target, selector)` | same |
| `policy.maxValuePerOp`, `budget`, `validUntil`, `validAfter` | `AgentPolicy.configs(account, id)` (with `spent`, which the chain updates) | same |
| `policy.tokens` | `AgentPolicy.tokenLimit(account, id, token)` (with its `spent`; for `x402` tokens also the token's EIP-712 domain) | same |
| `recovery` | `P256RecoveryValidator.publicKeys(account)` + Kernel `isAllowedSelector(recovery, changeRootValidator)` | `owner add-recovery` (owner) |
| `account`, `salt` | the account's address (`salt` only before deployment) | — (identifies the account) |
| `deployments` | — | — (which module addresses the CLI uses for *new* installs) |
| key locations (`tpm` handle, `pcrs`, `authFile`, `port`/`slot`, `keyfile` path, labels) | nothing | — (how this machine reaches its key) |

An installed mandate is fixed: to change it, install a new one —
`permission rotate --old-id <old>` (replace) or `permission add` (alongside,
e.g. a schedule window) — and remove ones you no longer want with
`permission revoke`. The policy module a permission was installed with stays
its module until then; `permission show` names it.

## Which commands read what, and what they change

| Command | Reads from the file | Changes on-chain | Signed by |
|---|---|---|---|
| `op send`, `demo` | `agent`, `permissionId`, `account` (or derivation fields) | executes the call — **only within the installed mandate** | agent key |
| `x402 fetch`, `x402 reclaim` | same, + `policy.tokens` (which are `x402`) | registers / reclaims an x402 payment — within the mandate | agent key |
| `account status`, `owner status`, `permission show` | everything | nothing | — |
| `permission rotate` / `add` | `agent`, `permissionId`, `policy`, `account`, `deployments` | installs this file's permission (rotate: and removes `--old-id`) | owner key |
| `permission revoke --id` | `account` | removes a permission | owner key |
| `owner add-recovery` | `recovery`, `account` | installs the recovery key | owner key |
| `owner recover` | `recovery`, `account` | makes the recovery key root | recovery key |
| `owner set-root` | `account` (+ arguments; `--expect-fingerprint` refuses a `--public-key` that is not the one the owner saw) | hands root to a new key, retires the old | current root (owner, or recovery after `recover`) |
| `key create --phone` | `account`, `deployments` | nothing on-chain: enrolls a new key on the phone for the account and prints the `phone` key spec | — (the phone's user confirms) |
| `account fund`, `paymaster …` | `account`, `deployments` | ETH transfers / paymaster settings | gas wallet / paymaster owner |

The agent's own key can only ever do the first row. Every row that changes
the account's rights needs the owner (or recovery) key — which, by the key
policy, is not on the agent's machine.
