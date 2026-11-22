# agent-keys — hardware-held keys for on-chain agents

An AI agent (or any unattended process) signs its on-chain actions with a key
that lives in a secure element — a TPM 2.0 on Linux or Windows, a Tropic
Square TROPIC01, Apple's Secure Enclave — and never exists as a file. Its account is an
ERC-4337 smart account that verifies the chip's **P-256** signature on-chain
through the RIP-7212 precompile. No secp256k1 key, no MPC, no custodian: the
only on-chain owner is the public key of the chip.

**Status: it runs on Base Sepolia.** What runs today, phase by phase and backend by backend, with the
transactions: [`docs/STATUS.md`](docs/STATUS.md).

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

In the FAQ: [`docs/FAQ.md`](docs/FAQ.md#why-not-an-eoa).

## Examples

Open-source agent stacks with their wallet layer — a key file or a custodial
wallet — replaced by a hardware-signed agent account. All of them go through
one seam, `agent-signer op send --json` (x402 payments through
`agent-signer x402 fetch`); details in
[`examples/README.md`](examples/README.md).

[Coinbase AgentKit](examples/agentkit/) · [Claude Code / OpenClaw skill](examples/claude-skill/) ·
[Jinn](examples/jinn/) · [Olas](examples/olas/) · [ElizaOS](examples/elizaos/) · [x402](examples/x402/).
What each one changes and what it showed on Base Sepolia:
[`examples/README.md`](examples/README.md#what-each-example-shows-on-base-sepolia).

## Layout

In [`CONTRIBUTING.md`](CONTRIBUTING.md#layout).

## Quick start

Any platform, no hardware (software backend — dev/CI only):

```sh
cd signer && cargo test
cd ../mobile/owner-core && cargo test   # the core shared with the phone apps; outside the signer workspace
cd ../../signer
# end to end on a local anvil: the real CLI against EntryPoint, Kernel, our
# modules, a Safe, a paymaster, a fake bundler and an x402 server (software
# keys, so only in this test-only build)
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli
cd ../contracts && forge test      # RIP-7212 enabled locally via odyssey = true
# forge 1.8+ dropped `odyssey`; there the precompile comes with the Osaka
# EVM: forge test --evm-version osaka
```

Linux with a TPM, the `vector` command and the other platforms:
[`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md#quick-start).

## Run an agent account on Base Sepolia

The walkthrough is in
[`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md#run-an-agent-account-on-base-sepolia).

## Reference

Y. Madhwal, *Integrating Secure Elements with Account Abstraction for
Autonomous IoT Blockchain Agents* (Skoltech research seminar, 2026) — the same
design with an ATECC608A; this project generalizes it to the TPM / Secure
Enclave in ordinary machines and to AI agents.

## Earlier name

Until November 2026 the project was called TPM_sign. Which identifiers keep that name, and why renaming
them needs a migration: [`CONTRIBUTING.md`](CONTRIBUTING.md#earlier-name).

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
