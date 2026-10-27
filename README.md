# TPM_sign — hardware-held keys for on-chain agents

An AI agent (or any unattended process) signs its on-chain actions with a key
that lives in a secure element — a TPM 2.0 on Linux or Windows, a Tropic
Square TROPIC01, Apple's Secure Enclave — and never exists as a file. Its account is an
ERC-4337 smart account that verifies the chip's **P-256** signature on-chain
through the RIP-7212 precompile. No secp256k1 key, no MPC, no custodian: the
only on-chain owner is the public key of the chip.

**Status: it runs on Base Sepolia.** An account whose owner key and agent key
both live in a TPM 2.0 executed its first operation on 2026-10-20 — the agent
key, bound by `AgentPolicy`, incremented the demo counter; the operation was
built and submitted by `agent-signer`, with no bundler, paymaster or custodian
in between:
account [`0xEdB645B14e2f952C5784e34949b58F0826fBc9E9`](https://sepolia.basescan.org/address/0xEdB645B14e2f952C5784e34949b58F0826fBc9E9),
tx [`0x785332…e669bb`](https://sepolia.basescan.org/tx/0x785332105fd8085d50e542ff9f677eba964399bbc0d71333ddd71fed03e669bb).

- Phase 0 — a signature produced inside a real TPM verifies on-chain (RIP-7212).
- Phase 1 — on ZeroDev Kernel v3.3 (ERC-7579): `P256Validator` makes the chip
  the account's root; `P256Signer` + `AgentPolicy` make it an *agent
  permission* bound by a call allow-list, value cap, budget and expiry.
- Phase 2 — `agent-signer` (Rust) derives the account, builds the
  UserOperation, signs its hash in the TPM and submits it through
  `EntryPoint.handleOps` itself.
- Phase 3 — `WhitelistPaymaster` sponsors listed accounts, so an agent
  account need not hold ETH at all (`demo --sponsored`,
  tx [`0xae73b5…5f2106`](https://sepolia.basescan.org/tx/0xae73b53d17b74ad8c7b6d65f8cc98abd40c513a808b09764828dff8a3a5f2106));
  the owner key rotates or revokes the agent's mandate in one root operation
  (tx [`0x4519a3…195370`](https://sepolia.basescan.org/tx/0x4519a35b5acdc19ffe713326964b5214677825d11040684f9869adbd8b195370));
  TPM keys can be sealed to the measured boot state (`key create --pcrs
  0,2,4,7`) and a sealed agent key ran on-chain
  (tx [`0xc81174…75db4b`](https://sepolia.basescan.org/tx/0xc8117420694a9c17d3c91a14df3ce70f00298d2bc0fcd38f55997c1bfc75db4b));
  operations can also go through an ERC-4337 bundler instead of our own
  `handleOps` — a public bundler accepted and included one
  (tx [`0xb42e30…527675`](https://sepolia.basescan.org/tx/0xb42e30ae72ac8d676c33198b65ae85e8ef06936d15b28cda5832ed4cc0527675)).
- More hardware — the agent permission was rotated onto a key inside a
  **TROPIC01** open-architecture secure element, which then signed a
  sponsored operation
  (tx [`0x6c1060…3622b5`](https://sepolia.basescan.org/tx/0x6c1060b43c1a40e3d123fe766adad914edccac8e9596cc1dc658617cf53622b5));
  the **Windows TPM** backend (CNG) ran on a Windows 11 PC and its signature
  is one of the test vectors; the **Apple Secure Enclave** backend ran on an
  M1 Mac — an account whose owner and agent keys both live in the enclave
  executed an agent operation
  (tx [`0xc431ba…01300c`](https://sepolia.basescan.org/tx/0xc431bafe3588431c82b96aac7318c3c4340e16be784322bba5d801f3a401300c))
  and a root operation
  (tx [`0x547e4f…4da40c`](https://sepolia.basescan.org/tx/0x547e4fa8caf1b5725f9043ece7df13f3e713c98107f1b1726ac24139674da40c)),
  and its signature is one of the test vectors.
- Safes — `AgentPolicy` v3 lets the agent drive a Safe its account owns
  (Olas / Jinn service Safes) and still judges the Safe transaction's
  *inner* call, or every leg of a MultiSend batch, against the mandate
  ([`docs/ERC1271.md`](docs/ERC1271.md)).
- x402 payments — `AgentPolicy` v6 gives the agent a narrow ERC-1271: it
  vouches only for USDC payment authorizations the agent registered first,
  inside the mandate's token budget. An agent with its key in a TROPIC01
  paid an x402 API through the public x402.org facilitator
  (settlement tx [`0xd3535c…e06379`](https://sepolia.basescan.org/tx/0xd3535c28f33cc63de48733332e8c37c9ca9b2d559097b56b5d4b81e06379a31d))
  ([`docs/ERC1271.md`](docs/ERC1271.md#x402--registered-authorizations-implemented-agentpolicy-v6)).
- Existing agent frameworks on top — Coinbase AgentKit, a Claude Code /
  OpenClaw skill, Jinn, Olas and ElizaOS, each run on Base Sepolia; the
  ElizaOS agent also pays for APIs with x402
  (tx [`0x344e94…6f1757`](https://sepolia.basescan.org/tx/0x344e94449df0a5fbb363136b8de4f02f4b78850992e7fc16352aaa10d46f1757);
  see [Examples](#examples)).

| Backend | Platform | Status |
|---|---|---|
| `tpm` | Linux, TPM 2.0 (tss-esapi) | on-chain since phase 0; PCR-sealed keys |
| `windows-tpm` | Windows, TPM 2.0 via CNG | run on Windows 11; vector in the tests ([`docs/WINDOWS.md`](docs/WINDOWS.md)) |
| `tropic01` | any, TROPIC01 USB DevKit | on-chain agent key ([`docs/TROPIC01.md`](docs/TROPIC01.md)) |
| `secure-enclave` | macOS, Secure Enclave via CryptoKit | run on an Apple M1 Mac: hardware test, vector in the tests, owner + agent keys on-chain — sponsored, via a bundler, x402, recovery drill ([`docs/SECURE_ENCLAVE.md`](docs/SECURE_ENCLAVE.md)) |
| `software` | any | dev/CI only |

New here? Start with [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) — the idea on one page. [`docs/FAQ.md`](docs/FAQ.md) walks through two setups (a Linux
laptop with $100, a Mac with a scheduled $100k budget) and common questions;
[`docs/AGENT_CONFIG.md`](docs/AGENT_CONFIG.md) specifies the agent config file
and how it maps to what the contracts enforce.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and
[`docs/BENCHMARK.md`](docs/BENCHMARK.md) for what each authorization method
costs — P-256 through RIP-7212 is as cheap as `ecrecover`, and the whole
agent path adds about 77k gas per operation.
How this compares with what else exists — old-phone signers such as Cake
Wallet's Cupcake, hosted agent-wallet platforms, passkey accounts and the
nearest open-source projects: [`docs/related/`](docs/related/README.md).

## Why not an EOA

Every secure element speaks NIST P-256; none speaks secp256k1, and an EOA is
secp256k1 + `ecrecover`. The first prototype ([`legacy/`](legacy/)) hit exactly
that wall. Account abstraction removes it: the chip stays a P-256 signer, and
the smart account checks that signature itself.

## Examples

Open-source agent stacks with their wallet layer — a key file or a custodial
wallet — replaced by a hardware-signed agent account. All of them go through
one seam, `agent-signer op send --json` (x402 payments through
`agent-signer x402 fetch`); details in
[`examples/README.md`](examples/README.md).

| Example | What changes | Shown on Base Sepolia |
|---|---|---|
| [Coinbase AgentKit](examples/agentkit/) (TS, Claude via LangChain) | a new `EvmWalletProvider` | an allowed call lands; a transfer to an outsider — what a prompt injection asks for — is refused by `AgentPolicy` |
| [Claude Code / OpenClaw skill](examples/claude-skill/) | a `SKILL.md` that teaches the agent the CLI | — |
| [Jinn](examples/jinn/) (Olas-based operator) | a Safe broadcaster whose Safe owner is the Kernel account | a claim-like call and a settlement-like MultiSend batch through the Safe execute; the Safe adding an owner is refused |
| [Olas](examples/olas/) (open-autonomy, Python) | Safe owner and keeper become the Kernel account; the consensus key stays, without funds | a 1-agent service's `transaction_settlement_abci` path, built with open-autonomy's own code, settles through the Kernel; a keeper retry cannot execute twice |
| [ElizaOS](examples/elizaos/) (1.7, Claude) | a plugin (`plugin-tpm-sign`) instead of `plugin-evm`'s private key | an allowed call lands, a transfer to an outsider is refused; `PAY_FOR_URL` pays an x402 API from the mandate's USDC budget |
| [x402](examples/x402/) (HTTP 402 payments) | `agent-signer x402 fetch`: each payment registered under the mandate, then signed | a paid API answers 200 and the x402.org facilitator settles the USDC on-chain; expired unused registrations are reclaimed |

The Jinn and Olas folders also hold an integration analysis with file:line
references, a patch plan and proposals for upstream; for Jinn, a first patch
series against `Jinn-Network/mono` (the venue loop on a Kernel-owned Safe,
[`examples/jinn/patches/`](examples/jinn/patches/)).

## Layout

```
signer/      Rust: hw-signer (HardwareSigner trait; tpm, windows-tpm,
             secure-enclave, tropic01, software backends), agent-signer CLI
contracts/   Foundry: P256Validator, P256Signer, AgentPolicy (ERC-7579 modules),
             WhitelistPaymaster + tests against Kernel v3.3, EntryPoint v0.7
             and Safe v1.4.1; P-256 vectors signed in software, a Linux TPM,
             a Windows TPM, a TROPIC01 and an Apple Secure Enclave
examples/    AgentKit, Claude Code skill, Jinn, Olas, ElizaOS, x402
docs/        architecture, benchmark, ERC-1271 (Safes, x402), per-platform guides;
             related/ — how other products compare (Cupcake, agent-wallet platforms)
scripts/     testnet chores (testnet_usdc.py: gas-wallet ETH -> Base Sepolia USDC)
legacy/      the original Python / tpm2-tools prototype, kept for reference
```

## Quick start

Any platform, no hardware (software backend — dev/CI only):

```sh
cd signer && cargo test
# end to end on a local anvil: the real CLI against EntryPoint, Kernel, our
# modules, a Safe, a paymaster, a fake bundler and an x402 server (software
# keys, so only in this test-only build)
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli
cd ../contracts && forge test      # RIP-7212 enabled locally via odyssey = true
# forge 1.8+ dropped `odyssey`; there the precompile comes with the Osaka
# EVM: forge test --evm-version osaka
```

Linux with a TPM 2.0:

```sh
sudo apt install libtss2-dev libclang-dev
sudo usermod -aG tss "$USER"       # access to /dev/tpmrm0; re-login
cd signer
cargo test --features tpm -- --ignored
cargo run -p agent-signer --features tpm -- vector --backend tpm --message hello
```

The `vector` command prints a JSON `(digest, r, s, x, y)` record; the Solidity
tests verify every file under `contracts/test/vectors/` — signed inside an
Intel PTT, a Windows TPM, a TROPIC01 and an Apple Secure Enclave. Windows: [`docs/WINDOWS.md`](docs/WINDOWS.md)
(free toolchain only); TROPIC01: `--features tropic01`, [`docs/TROPIC01.md`](docs/TROPIC01.md).

## Run an agent account on Base Sepolia

Secrets stay outside the repository: a `.env` with `BASE_SEPOLIA_RPC_URL`,
and `BUNDLER_URL` and/or `GAS_WALLET_KEYFILE` (a file holding the hex key of
a small funded EOA that submits `handleOps` itself and pays for funding
commands; not needed when a bundler delivers the operations). The account itself is described
by `signer/agent.base-sepolia.json`: two TPM handles, a permission id and the
agent's mandate. Module addresses come from `contracts/deployments/84532.json`
(`forge script script/Deploy.s.sol` writes it; CREATE2 with salt 0, so they
are the same on every chain).

```sh
cd signer && cargo build -p agent-signer --features tpm
B=target/debug/agent-signer; A=agent.base-sepolia.json; E=../../.env

$B key create --handle 0x81010010      # owner key, stays in the TPM
$B key create --handle 0x81010011      # agent key, stays in the TPM
$B account status --agent $A --env-file $E   # counterfactual address
$B account fund   --agent $A --env-file $E --wei 2000000000000000
$B demo           --agent $A --env-file $E   # first op deploys the account
$B op send --agent $A --env-file $E --target 0x... --data 0x...   # anything the mandate allows
```

`account fund` simulates `createAccount` first and refuses to send ETH to an
address that could never be deployed. Operations outside the mandate are
rejected during simulation, before any gas is spent.

For programs driving the CLI, `op send --json` prints one JSON line
(`account`, `userOpHash`, `nonce`, `tx`, `block`, `gasUsed`) and keeps progress
on stderr; `--nonce` reuses the nonce of an earlier attempt, so retrying the
same action can never execute it twice. A Safe transaction (`execTransaction`
calldata) needs `--safe-nonce <n>`: it goes out as a batch that asserts the
Safe's nonce on-chain first, so a replay reverts instead of running again.

Keys: the agent's operations never open the owner key — the config carries
the owner's public key (`ownerPublicKey`), and only root operations open the
key itself. Where to keep it is a custody decision
([`docs/KEY_POLICY.md`](docs/KEY_POLICY.md)); on one chip, a TPM owner key can
be protected by a root-only secret (`key create --handle … --auth-file …`).
Security review: [`docs/AUDIT-2026-10-20.md`](docs/AUDIT-2026-10-20.md).

Losing a key: the agent's is replaced by the owner (`permission rotate`); for
the owner's, a cold recovery key — e.g. an encrypted key file on a USB drive
(`key create --keyfile …`) installed with `owner add-recovery` — may take
root over and hand it to a new device (`owner recover`, `owner set-root
--retire …`), and can do nothing else, not even sign a message.
`key check` proves a key (or a key file's passphrase) still works without
sending anything. Devices and failure modes:
[`docs/OWNER_DEVICES.md`](docs/OWNER_DEVICES.md),
[`docs/RESILIENCE.md`](docs/RESILIENCE.md).

Gasless, and the owner's controls:

```sh
$B paymaster deposit --agent $A --env-file $E --wei 3000000000000000
$B paymaster sponsor --agent $A --env-file $E --budget 2000000000000000 --max-per-op 300000000000000   # gas budget and per-op cap, wei
$B demo --agent $A --env-file $E --sponsored           # the paymaster pays

$B demo --agent $A --env-file $E --bundler https://public.pimlico.io/v2/84532/rpc
# ...or set BUNDLER_URL in .env: the bundler submits handleOps from its own
# wallet and is paid from the account's (or the paymaster's) EntryPoint
# deposit; the gas wallet is then only needed for deploying and funding.
$B demo --agent $A --env-file $E --bundler https://public.pimlico.io/v2/84532/rpc --sponsored
# ...chip signs, paymaster pays, bundler relays: no gas wallet in the path.
$B paymaster stake --agent $A --env-file $E --wei 100000000000000000   # if a bundler's reputation rules require it

$B key create --handle 0x81010012 --pcrs 0,2,4,7       # a key sealed to the boot state
# in agent.json: pin "account", point "agent" at {"tpm": {"handle": "0x81010012", "pcrs": [0,2,4,7]}},
# give the new permission a fresh id — then, signed by the owner key:
$B permission rotate --agent $A --env-file $E --old-id 0x61676e74 --sponsored
$B permission revoke --agent $A --env-file $E --id 0x61676e32          # when the agent is retired
# a schedule: one config per time window (own permissionId, policy.validAfter … validUntil,
# budget, allow-list), each installed alongside the others:
$B permission add --agent window-mon.json --env-file $E --sponsored

$B key create --tropic01 /dev/ttyACM0 --slot 1         # a key inside a TROPIC01 (--features tropic01)
# signer/agent.tropic01.base-sepolia.json: that key as the agent, a Safe in the mandate

# x402: a permission that may pay in USDC ("x402": true in policy.tokens), then
$B permission add --agent agent.x402.base-sepolia.json --env-file $E          # owner, once
$B x402 fetch --agent agent.x402.base-sepolia.json --env-file $E <url>        # agent: pays on 402
$B x402 reclaim --agent agent.x402.base-sepolia.json --env-file $E            # expired unused -> budget
```

## Reference

Y. Madhwal, *Integrating Secure Elements with Account Abstraction for
Autonomous IoT Blockchain Agents* (Skoltech research seminar, 2026) — the same
design with an ATECC608A; this project generalizes it to the TPM / Secure
Enclave in ordinary machines and to AI agents.

## License

The repository is under two permissive licenses, by directory:

| Path | License | Files |
|---|---|---|
| `signer/` — `hw-signer`, `agent-signer`, the Swift shim | Apache-2.0 | [`signer/LICENSE`](signer/LICENSE), [`signer/NOTICE`](signer/NOTICE) |
| everything else — `contracts/`, `examples/`, `scripts/`, `legacy/`, `docs/` | MIT | [`LICENSE`](LICENSE) |

The signer is Apache-2.0 for its explicit patent grant and contribution
terms, which matter for security software adopted by companies; versions
published before the change were MIT and stay available under MIT. The
contracts stay MIT so that any account, module or framework can import them,
and their SPDX headers match the verified on-chain sources. Contributions are
accepted under the license of the directory they change. Third-party code —
the git submodules under `contracts/lib`, crates and npm packages — keeps its
own license.
