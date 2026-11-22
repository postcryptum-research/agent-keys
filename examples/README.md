# Examples: existing agent frameworks on a hardware-signed account

Each example takes an open-source agent stack and replaces its wallet layer
— usually a private key in a file or a custodial MPC/TEE wallet — with a
agent-keys agent account: a P-256 key inside a TPM, Secure Enclave or
TROPIC01, an ERC-4337 Kernel account on Base Sepolia, and an on-chain
mandate (`AgentPolicy`) that bounds what a compromised agent host can do.

All of them drive the same seam: `agent-signer op send --json` (one call →
one UserOperation signed in hardware → JSON result on stdout). Callers that
may retry the same action pass `--nonce` with the nonce of their first
attempt, so a retry can never execute it twice.

| Example | Stack | What changes | Status |
|---|---|---|---|
| [`agentkit/`](agentkit/) | Coinbase AgentKit (TS) + LangChain/Claude | a new `EvmWalletProvider` | smoke test verified on Base Sepolia |
| [`claude-skill/`](claude-skill/) | Claude Code / OpenClaw skills | a `SKILL.md` that teaches the agent the CLI | ready |
| [`jinn/`](jinn/) | Jinn operator (Olas ecosystem) | a Safe broadcaster with a Kernel owner (`v = 1`) | adapter + demo verified on Base Sepolia; integration plan; first patch series for `Jinn-Network/mono`: Jinn's full solution loop (claim → deliver → settle) passes on its hermetic Anvil snapshot with a Kernel-owned Safe and the agent key in TROPIC01 |
| [`olas/`](olas/) | Olas / open-autonomy (Python) | Safe owner and keeper become the Kernel; consensus key stays, without funds | `transaction_settlement_abci` path verified on Base Sepolia; upstream plan |
| [`elizaos/`](elizaos/) | ElizaOS 1.7 (TS, Bun) + Claude | a plugin with its own wallet service instead of `plugin-evm`; `PAY_FOR_URL` pays x402 | smoke test verified on Base Sepolia (call lands, outsider refused, x402 paid) |
| [`x402/`](x402/) | x402 (HTTP 402 payments, USDC) | `agent-signer x402 fetch`: register under the mandate, then sign ERC-1271 | paid and settled on Base Sepolia (x402.org facilitator); reclaim verified |

Background: `docs/ERC1271.md` — why the agent signs no general off-chain
messages, how Safes (Olas, Jinn) work anyway through `AgentPolicy`'s Safe
pass-through, and how x402 payments get a narrow ERC-1271 by registration.

## What each example shows on Base Sepolia

| Example | What changes | Shown on Base Sepolia |
|---|---|---|
| [Coinbase AgentKit](agentkit/) (TS, Claude via LangChain) | a new `EvmWalletProvider` | an allowed call lands; a transfer to an outsider — what a prompt injection asks for — is refused by `AgentPolicy` |
| [Claude Code / OpenClaw skill](claude-skill/) | a `SKILL.md` that teaches the agent the CLI | — |
| [Jinn](jinn/) (Olas-based operator) | a Safe broadcaster whose Safe owner is the Kernel account | a claim-like call and a settlement-like MultiSend batch through the Safe execute; the Safe adding an owner is refused |
| [Olas](olas/) (open-autonomy, Python) | Safe owner and keeper become the Kernel account; the consensus key stays, without funds | a 1-agent service's `transaction_settlement_abci` path, built with open-autonomy's own code, settles through the Kernel; a keeper retry cannot execute twice |
| [ElizaOS](elizaos/) (1.7, Claude) | a plugin (`plugin-agent-keys`) instead of `plugin-evm`'s private key | an allowed call lands, a transfer to an outsider is refused; `PAY_FOR_URL` pays an x402 API from the mandate's USDC budget |
| [x402](x402/) (HTTP 402 payments) | `agent-signer x402 fetch`: each payment registered under the mandate, then signed | a paid API answers 200 and the x402.org facilitator settles the USDC on-chain; expired unused registrations are reclaimed |

The Jinn and Olas folders also hold an integration analysis with file:line
references, a patch plan and proposals for upstream; for Jinn, a first patch
series against `Jinn-Network/mono` (the venue loop on a Kernel-owned Safe,
[`examples/jinn/patches/`](jinn/patches/)).

## Common setup

```sh
cd signer
cargo build -p agent-signer --features tpm,tropic01   # the backends this machine has
```

The examples read `BASE_SEPOLIA_RPC_URL` and `BUNDLER_URL` from the project
`.env` (outside the repo) and the agent config from
`signer/agent.tropic01.base-sepolia.json` by default. The user running the
agent needs group `tss` (TPM) and/or `dialout` (TROPIC01).
