# FAQ

Practical questions about running an AI agent on an agent-keys account. Each
answer says what works today and what does not yet; the project runs on Base
Sepolia (testnet), and an internal review, not a professional audit, is all
the code has had (see the last section).

The words used below:

- **agent key** — signs the agent's operations automatically; lives in a
  secure element on the machine the agent runs on;
- **owner key** — the account's root: changes or revokes the agent's
  mandate; used rarely, a human may confirm it;
- **recovery key** — a cold key that can only take the owner role over if
  the owner key is lost ([`RESILIENCE.md`](RESILIENCE.md));
- **mandate** — what the agent may do, enforced on-chain by `AgentPolicy`:
  allowed contracts and functions, a cap per operation, a total budget,
  per-token limits, an expiry ([`KEY_POLICY.md`](KEY_POLICY.md)).

---

## 1. "I have a Linux laptop (it probably has a TPM 2.0, I'm not sure) and one or two USB drives. The agent will manage up to $100. I don't need special security. What do I do?"

That fits what works today. Plan: agent key in the laptop's TPM, owner key
and recovery key as encrypted files on the two USB drives.

**1. Check the TPM.** Almost every laptop since ~2016 has one, often a
firmware TPM (Intel PTT, AMD fTPM) that must be enabled in the firmware setup.

```sh
ls /dev/tpmrm0                                   # exists → the kernel sees a TPM
cat /sys/class/tpm/tpm0/tpm_version_major         # must print 2
```

If `/dev/tpmrm0` is missing, enable "TPM", "PTT" or "fTPM" in the firmware
setup and reboot. Without a TPM, a supported alternative for the agent key
is a TROPIC01 devkit ([`TROPIC01.md`](TROPIC01.md)); a software key is not
allowed for an agent with money (it would be a file, which is what the
project exists to avoid).

**2. Install and build.**

```sh
sudo apt install libtss2-dev libclang-dev git build-essential
sudo usermod -aG tss "$USER"                      # TPM access; log out and back in
curl https://sh.rustup.rs -sSf | sh               # Rust
git clone --recursive https://github.com/postcryptum-research/agent-keys.git
cd agent-keys/signer && cargo build -p agent-signer --features tpm
B=target/debug/agent-signer
```

**3. Create the keys.**

Keys are created under the TPM's storage root key at `0x81000001`. Many
distributions persist one there already. If `key create` says "no storage
parent at 0x81000001", there is none yet, as on a new virtual machine:
create it once with tpm2-tools:

```sh
sudo apt install tpm2-tools
tpm2_createprimary -C o -g sha256 -G ecc -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' -c srk.ctx \
  && tpm2_evictcontrol -C o -c srk.ctx 0x81000001
```

(`noda` keeps the parent usable for making keys while the TPM is in a
dictionary-attack lockout; it has no password to guess.)

Then:

```sh
$B key create --handle 0x81010011                           # agent key, inside the TPM
$B key create --keyfile /media/$USER/USB1/owner.json        # owner key, encrypted (asks a passphrase)
$B key create --keyfile /media/$USER/USB2/recovery.json     # recovery key, on the second drive
```

Each `key create` prints the public key. Write the passphrases down
somewhere safe: they cannot be recovered. Copy each file to a second place
too (another drive, a cloud folder — the file is useless without the
passphrase).

**4. Write the agent config** (start from `signer/agent.tropic01.base-sepolia.json`;
every field is specified in [`AGENT_CONFIG.md`](AGENT_CONFIG.md)):

- `"agent": {"tpm": "0x81010011"}`;
- `"owner": {"keyfile": "/media/…/owner.json"}` and `"ownerPublicKey"` with
  the `x`, `y` that `key create` printed — so the agent never needs the
  owner's drive plugged in;
- `"recovery": {"keyfile": "/media/…/recovery.json"}`;
- the **mandate** in `"policy"`: which contracts and functions the agent may
  call (`allow`), `maxValuePerOp` and `budget` in wei, `validUntil` (a Unix
  time), and for tokens a `tokens` entry with per-operation and total limits
  (for $100 in USDC: e.g. `maxPerOp` 20 USDC, `budget` 100 USDC, in 6-decimal
  units);
- a new `permissionId` (any 4 bytes, e.g. `0x61676e74`).

**5. Fund the account and start.**

The CLI reads an `.env` (outside the repository) with `BASE_SEPOLIA_RPC_URL`
(or your chain's RPC) and `BUNDLER_URL` (e.g. Pimlico's public endpoint).
A gas wallet (`GAS_WALLET_KEYFILE`) is optional — see "Do I need a bundler or
a gas wallet?" below.

```sh
$B account status --agent my-agent.json --env-file .env     # prints the account address
# send up to $100 of ETH or tokens to that address (some ETH for gas)
$B op send --agent my-agent.json --env-file .env --target <an allowed contract> --data <calldata>
#   ↑ the first operation also deploys the account
$B owner add-recovery --agent my-agent.json --env-file .env  # plug in USB1; enter the owner passphrase
```

Then point the agent at `agent-signer op send …` (or one of the
[examples](../examples/README.md): AgentKit, a Claude Code skill).

**What you get:** the agent key cannot be copied off the laptop; a hacked
laptop can spend at most what the mandate allows; you can revoke the agent
from anywhere you have the owner drive and passphrase.

**What to know:** today this runs on Base **Sepolia** (testnet). For real
money on Base, the project has to deploy its modules there first — once, for
everyone (see "Who deploys the contracts?" below); you deploy nothing
yourself. A firmware update that clears the TPM loses the agent key —
harmless: create a new one and `permission rotate` with the owner drive.

---

## 2. "I have a Mac, I can buy whatever devices you recommend. The agent will manage up to $100k, not continuously: I want a schedule — on which days it may spend how much, and on what. What do I do?"

The design supports this, but **not everything it needs is built yet**. Here
is the target setup, and which parts are missing.

**Target setup:**

| Role | Where | Status |
|---|---|---|
| agent key | the Mac's Secure Enclave | **works today** — run on an Apple M1, keys on-chain ([`SECURE_ENCLAVE.md`](SECURE_ENCLAVE.md)) |
| owner key | a separate device with a button: a YubiKey 5 (PIV, P-256) | **works today** — PIN and a touch per signature; root of the Base Sepolia account since 2026-11-02, run on macOS too ([`YUBIKEY.md`](YUBIKEY.md)). Nitrokey 3, Ledger and Trezor: studied, not supported ([`OWNER_DEVICES.md`](OWNER_DEVICES.md)) |
| owner key, the other way | the owner's phone: the project's own app, the key in the Android Keystore or the iPhone's Secure Enclave, a fingerprint or Face ID per signature, the operation reviewed on the phone's screen before signing | **development builds only** — the loop passed on a real Android phone and a real iPhone against a local chain, not on Base Sepolia; no store distribution, the app is installed with `adb` or from Xcode ([`MOBILE_OWNER_PLAN.md`](MOBILE_OWNER_PLAN.md), [`MOBILE_DEV_MODE.md`](MOBILE_DEV_MODE.md)) |
| recovery key | an encrypted file on two USB drives in different places | file: works today; behind a time lock: **not built** — today the recovery key takes over at once ([`RESILIENCE.md`](RESILIENCE.md)) |
| money | most of it **not** on the agent's account — in an owner-controlled vault; the agent's account is topped up per period | operational, works today |

**The schedule.** Each mandate has a time window — `validAfter` (start) and
`validUntil` (end) — that the EntryPoint enforces. The owner installs
several mandates for the same agent key, each with its own window, budget,
token limits and allowed contracts, e.g.:

- "Mon–Fri of this week: up to 5,000 USDC per day through these two
  contracts" — one mandate per day;
- "the 1st of the month: payroll up to 40,000 USDC".

**What a mandate does not say today: who receives a token transfer.** It
allows contracts and functions and caps token amounts per operation and in
total; with `USDC.transfer` allowed, the agent picks the recipient, within
those caps. To fix the destination, leave `transfer` out and allow a contract
that can pay only where the owner decided — e.g. a forwarder with one
immutable destination, which the owner approves for the token once.

Each mandate is one agent config file with its own `permissionId` and
`policy.validAfter` / `validUntil`; `agent-signer permission add` installs
it next to the others (an owner operation). The agent uses the config of the
window it is in; outside every window it can do nothing. Install the
calendar ahead (one owner session for a month), or week by week.

Shown on Base Sepolia (2026-10-20): a window permission
(`signer/agent.window-demo.base-sepolia.json`, opening four minutes after
installation) was added next to the agent's everyday one (tx
`0x11032de8dcec0a361d2f18118049ad182d2fb2c3807be291ae3cbded8dd0f2b6`); an
agent operation under it before the window opened was refused by the
EntryPoint (`AA22 expired or not due`), and the same operation right after
it opened went through (tx
`0x64b99b7b0126fd0a20967d98dcdc84bf4766787b3992dd32ecec1607139aef0e`).

**Sequence** (step 3 waits for the mainnet deployment, the time lock in step 4 is not built):

1. Run [`SECURE_ENCLAVE.md`](SECURE_ENCLAVE.md) on the Mac (build, hardware
   test, `key create --enclave agent`).
2. Buy a YubiKey 5 (owner) and two USB drives (recovery file copies). Set
   the YubiKey up as in [`YUBIKEY.md`](YUBIKEY.md).
3. Once the project's modules are on Base mainnet (a one-time deployment for
   everyone), either let the account pay its own gas or run your own sponsor
   (deploy a `WhitelistPaymaster` you own, `paymaster deposit`,
   `paymaster sponsor --budget --max-per-op`).
4. Create the account with the owner on the YubiKey
   (`"owner": {"yubikey": {"slot": "9c"}}`), install the recovery key
   (behind a time lock, once that exists), rehearse a recovery once with a
   small amount.
5. Put the $100k in an owner-controlled vault (an owner Safe or a separate
   account), not on the agent's account.
6. Install the calendar of mandates (`permission add`, one per window) and
   top the agent's account up before each window to that window's budget.
7. Monitor the account's events; run `key check` on the owner device monthly.

**Why the money should not sit on the agent's account:** the mandate bounds
what the agent can do, but the smallest possible exposure is "what is on the
account right now". A compromised Mac can spend at most the current period's
budget — not the $100k.

**Before $100k, also:** a professional audit of `AgentPolicy`, the
validators and `agent-signer`; the modules deployed on Base mainnet; and a
time lock on recovery. Those are the prerequisites, not options. (The Secure
Enclave run and the owner device backend, once on this list, are done.)

---

## 3. More questions

### My agent's computer was hacked. What can the attacker actually do?

Assume malware can do whatever the agent's user can do — that is the
realistic case, and the project does not try to tell them apart
([`KEY_POLICY.md`](KEY_POLICY.md)). So, while it is on the machine, it can:

- **use the agent key** — ask the TPM (or Secure Enclave, TROPIC01) to sign,
  exactly as the agent does. It gets *as much as the mandate allows*: the
  allowed contracts and functions, the per-operation cap, the budget, the
  token limits, until the expiry. It cannot **copy** the key: once the
  machine is cleaned, the key is safe again;
- **read every file the user can read** — the agent config (public data),
  the `.env` with RPC / bundler URLs and API keys, and the **gas wallet's key
  file** if you use one (a plain hot key: keep only a few dollars in it);
- **take the owner or recovery key if it can reach it** — an owner key file on
  a drive that is plugged in while you type its passphrase, or an owner TPM
  key without a root-only secret on that same machine. Keep owner keys off the
  agent's machine, or behind root (rule 3), and plug the owner drive in only
  for owner operations.

What it cannot do: sign messages for the account (no permits, no SIWE logins
— the policy refuses ERC-1271, except x402 payments it registered within the
mandate's token budget), change the mandate, or act beyond it.
What you do: revoke the agent with the owner key
(`agent-signer permission revoke`) from another machine, then reinstall.
The revoke takes effect in its block, including for x402 payments the agent
had already signed: none of them can settle any more.

### Realistic failures — what breaks, and what happens then?

The common ones, roughly from most to least likely:

| What happens | Effect | Fix |
|---|---|---|
| you forget the passphrase of an owner/recovery key file | that key is gone | run `key check` now and then; keep the passphrase written down somewhere safe |
| a BIOS/firmware update or "Clear TPM" wipes a firmware TPM | the TPM's keys are gone | agent key: create a new one, `permission rotate`. Owner key in that TPM: use the recovery key |
| the laptop is lost, stolen or replaced | its TPM / Secure Enclave keys are gone for you — and a thief may still use an unsealed TPM key (e.g. by booting another OS on it) | revoke or rotate the agent with the owner key right away; a PCR-sealed agent key (`key create --pcrs`) refuses to sign under another OS |
| a USB drive dies after a few years | that copy of a key file is gone | keep two copies on different media |
| the mandate expires (`validUntil`) | the agent stops — by design | renew it with the owner key |

An ordinary OS reinstall does **not** remove TPM keys, and a reboot never
does. Losing the agent key costs nothing but a rotation; losing the owner key
is what the recovery key is for; losing both freezes the account for good
([`RESILIENCE.md`](RESILIENCE.md)).

### How do I move the owner key to a new device?

One command, signed by the current owner key (or by the recovery key after
`owner recover`, with `--as-recovery`). The new key first shows that it can
sign: the handover is a single step with no way back except the recovery
key, and a key nobody can sign with takes the account with it.

```sh
# the new key is on this machine: name it as the config will
$B owner set-root --agent agent.json --validator <P256Validator> --retire <the old validator> \
    --not-a-phone --new-key '{"yubikey": {"slot": "9c"}}'

# the new key is on another machine: this prints a challenge and waits
$B owner set-root --agent agent.json --validator <P256Validator> --retire <the old validator> \
    --public-key <x>,<y> --not-a-phone
# there, with the key:
$B key prove --key '{"tpm": "0x81010010"}' --challenge <the line printed above>
# paste the one line it prints back into the waiting command
```

A device that asks before it signs asks here too: a YubiKey wants its PIN
and a touch during `--new-key` or `key prove`, a key file its passphrase.
A line pasted wrong does not end the wait: the command says so and reads
the next one until the challenge expires.

Then put the new key in the config as `owner`. A phone's key goes with
`--to-phone <label>` instead, and the phone shows the key in a session.
`--no-proof-of-possession` hands the root over without the proof; the
command says what that risks.

### Do I need a Ledger, YubiKey or Trezor?

Only for setups that hold real value, as the **owner** key — a separate
device with a button. For small amounts, owner and recovery keys as encrypted
files on USB drives are enough. A YubiKey 5 works as the owner key today
([`YUBIKEY.md`](YUBIKEY.md)); Ledger and Trezor are not supported
([`OWNER_DEVICES.md`](OWNER_DEVICES.md)). None of them suits the agent key:
they want a button press per signature.

### Which machines and which networks?

**Machines** for the agent key: Linux with a TPM 2.0, Windows with a TPM 2.0,
a TROPIC01 USB devkit and a Mac's Secure Enclave (all four verified).

**A server or a virtual machine:** the Linux `tpm` backend works as it is
against a virtual TPM. That is checked against the software TPM that QEMU,
libvirt and Proxmox use (`scripts/tpm-check.sh --swtpm`) and on an Azure
Trusted Launch VM; other clouds were not run. What changes there is who
else can reach the key: the host, and whoever may copy the VM. On Azure a
VM made from a snapshot signed with the same key
([`SERVER_KEY_STORES.md`](SERVER_KEY_STORES.md)). On a cloud VM:

- **The agent key only.** Keep the owner and recovery keys off it:
  whoever administers the cloud account can run commands as root in the
  VM and copy it ([`KEY_POLICY.md`](KEY_POLICY.md), rule 3).
- **Make the storage parent once** (question 1, step 3). On Azure the
  vTPM had room for three persistent objects of ours: the parent, the
  agent key, and one spare for a rotation.
- **A managed OS disk, not an ephemeral one**: an ephemeral disk can lose
  the key on a reimage.
- **No rights over disks, snapshots or VMs** for the VM's own identity.
- **Snapshots and restore points of the VM are copies of the key**: on
  Azure a VM made from either signed as the agent. Treat images and
  backups of the VM the same way. Whoever may make them can sign.
- **An `--auth-file` does not help here**: it is on the same disk, and
  every copy starts with a clean lockout counter.
- **Seal to PCRs only after the VM has restarted once**: on Azure, PCR 7
  changed between the first and the second boot.
- **Make the key with a CLI that includes #43.** Such a key, made without
  `--auth-file`, signs through a lockout; an older one does not, and on a
  virtual TPM three hard power-offs after signatures lock it out. If
  yours is older, make a new key and rotate onto it.
- **After any incident in the cloud account, rotate the agent's
  permission** (`permission rotate`), even if the VM looks clean: a copy
  taken during the incident signs until then.

**Networks:** every EVM network that has the contracts it needs — the
ERC-4337 EntryPoint v0.7, ZeroDev Kernel v3.3 and its factory, a P-256
signature precompile (RIP-7212; on Ethereum mainnet EIP-7951), and the
canonical CREATE2 deployer — plus this project's modules, deployed once per
network. Today: Base Sepolia. Base mainnet has all the prerequisites; the
modules are not deployed there yet.

### Who deploys the contracts — every user, or the project once?

The project, once per chain, for everyone. The modules — `P256Validator`,
`P256Signer`, `AgentPolicy`, `SafeNonceAssert`, `P256RecoveryValidator` —
are shared singletons: no owner, no admin functions, all state keyed by the
calling account, so one deployment serves every user and no user can touch
another's. They go through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) with salt 0, so their
addresses depend only on their bytecode — the same on every chain, whoever
deploys them; anyone may run `contracts/script/Deploy.s.sol`, and the first
run makes them available to all.

What each user gets is their **account**: a Kernel proxy created by ZeroDev's
factory, automatically, by the user's first operation (it carries the
`initCode`) — no separate step.

The exception is the gas sponsor: a `WhitelistPaymaster` has an owner who
decides whom it pays for and how much, so each sponsor deploys their own (its
address depends on the owner). Users who pay their own gas need none.

### Who pays for gas?

Plan for **the user paying** — that always works. The variants:

1. **The account pays for itself** (default). Keep some ETH on the agent's
   account; each operation is paid from it. The maximum possible gas cost of
   each operation counts against the agent's budget, so a compromised host
   cannot burn the balance on fees beyond the mandate.
2. **Your own sponsor.** Deploy a `WhitelistPaymaster` you own, deposit ETH
   into it and list your accounts with a gas budget and a per-operation cap
   (`paymaster sponsor --budget --max-per-op`). Useful for several agents, or
   to keep the agent's account free of ETH.
3. **Someone else's sponsor** — a service's paymaster, or an ERC-20 paymaster
   that takes gas in USDC. Works with any ERC-4337 paymaster; the CLI only
   speaks to the project's own paymaster today.

How the operation reaches the chain (next question) is a separate choice.

### Do I need a bundler or a gas wallet?

An ERC-4337 operation has to be put on-chain by *someone* sending an
ordinary transaction (`EntryPoint.handleOps`). Three ways:

| Who submits | What you need | Notes |
|---|---|---|
| **a public bundler** (e.g. Pimlico's free endpoint) | its URL (`BUNDLER_URL`) | the bundler pays the outer transaction and is repaid from the account or the paymaster; no hot key of yours involved. Public endpoints have rate limits (Pimlico's free one: about 20 requests per minute). |
| **a bundler you run or rent** | its URL, possibly an API key | same, without others' rate limits |
| **`agent-signer` itself** | a **gas wallet**: a small hot key with ETH (`GAS_WALLET_KEYFILE`) | the CLI sends `handleOps` from it; the EntryPoint repays it from the account's deposit or the paymaster's, so it only needs a float. It is a plain key file — keep a few dollars in it. |

With a bundler, no gas wallet is needed: leave `GAS_WALLET_KEYFILE` unset.
It is only required to submit `handleOps` yourself and for the commands that
send ETH from it (`account fund`, `paymaster deposit / sponsor / stake`);
those say so when it is missing.

### Can it drive a Safe (Olas, Jinn)? Which AI frameworks work?

Yes: the account can own a Safe, and the mandate judges the Safe's
transactions call by call, including MultiSend batches; replays are refused
on-chain ([`ERC1271.md`](ERC1271.md)). Frameworks with a worked example:
Coinbase AgentKit, a Claude Code / OpenClaw skill, Jinn and Olas
([`examples/`](../examples/README.md)). Anything else that can run a command
(`agent-signer op send --json`) or call a function that sends one transaction
works the same way.

It can also pay for HTTP APIs with x402 (USDC on Base): each payment is
first registered on-chain against the mandate's token budget, then signed
([`ERC1271.md`](ERC1271.md#x402--registered-authorizations-implemented-agentpolicy-v6),
`agent-signer x402 fetch`). One registration costs one operation's gas, so
x402 suits payments well above a cent.

### What does an operation cost, and how long does it take?

**Gas**, measured on Base Sepolia (whole transactions, from the receipts,
[`BENCHMARK.md`](BENCHMARK.md)):

| Operation | Gas | For comparison |
|---|---:|---|
| a simple agent call, account pays | ~154,000 | a plain ETH transfer from a normal wallet: 21,000 |
| the same, gas sponsored | ~163,000 | |
| the first operation (deploys the account) | ~700,000 | once per account |
| an owner operation (rotate the agent) | ~450,000 | rare |

The money depends on the network: multiply by its gas price (on rollups such
as Base, add the L1 data fee, which grows with the operation's size). On Base,
at ~0.01 gwei, a simple agent call is about 1.5 × 10⁻⁶ ETH of L2 gas — a
fraction of a cent; on a network with 10 gwei it would be a thousand times
more. Verifying
the P-256 signature itself costs the same as an ordinary `ecrecover`
(~7,400 gas); the overhead is the smart-account machinery, about 77k gas per
operation over a bare call.

**Time**, from "the agent decides" to "the call is on-chain": signing takes
milliseconds in a TPM, about 2 seconds on the TROPIC01 devkit, about 1 second
to open an encrypted key file; then the operation waits for the next block
(Base: 2 s) plus the bundler's own delay — a few seconds in our runs.

### Is it audited?

An internal review on 2026-10-20 by a separate AI session found eight
issues; all are fixed and re-checked
([`AUDIT-2026-10-20.md`](AUDIT-2026-10-20.md)). It is not a professional
audit. The bigger the amount, the more review it deserves — an independent
professional audit before anything substantial. But no audit makes a system
safe on its own: keep the agent's account holding only what the current
period needs, keep mandates tight and short-lived, and keep the owner key on
a separate device. Those limits hold even if a bug slips through.
