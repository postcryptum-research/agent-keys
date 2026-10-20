# Coinbase AgentKit on a hardware-signed agent account

[AgentKit](https://github.com/coinbase/agentkit) gives an LLM agent on-chain
tools (transfers, ERC-20, DeFi actions, …) through one abstraction,
`EvmWalletProvider`. This example implements that class for a TPM_sign agent
account, so every AgentKit action becomes a UserOperation signed inside a
TPM, Secure Enclave or TROPIC01 and checked on-chain by `AgentPolicy`.

```
LLM ──tools──▶ AgentKit actions ──▶ TpmKernelWalletProvider
                                       │ reads: viem PublicClient
                                       │ writes: agent-signer op send --json
                                       ▼
                         hardware signs userOpHash ─▶ bundler ─▶ EntryPoint
                                                          ─▶ Kernel + AgentPolicy
```

| File | What it does |
|---|---|
| `src/tpmKernelWalletProvider.ts` | The provider: `sendTransaction` / `nativeTransfer` go through the CLI; `sign*` refuse (ERC-1271 is off for the agent) |
| `src/agentSigner.ts` | Spawns `agent-signer op send --json`, maps a policy refusal (`PolicyFailed`) to a readable error |
| `src/setup.ts` | Builds AgentKit from env, plus `demo_counter_read` / `demo_counter_increment` actions |
| `src/smoke.ts` | No LLM: an allowed call lands, a transfer to an outsider is refused |
| `src/chatbot.ts` | Interactive Claude agent (LangChain + LangGraph) with the same tools |
| `src/noTelemetry.ts` | Blocks AgentKit's built-in analytics (see below) |

## Run

```sh
cd signer && cargo build -p agent-signer --features tpm,tropic01 && cd -
cd examples/agentkit && npm install

npm run smoke          # needs BASE_SEPOLIA_RPC_URL / BUNDLER_URL (../../../.env by default)
ANTHROPIC_API_KEY=… npm run chat
```

Environment: `AGENT_CONFIG` (default `signer/agent.tropic01.base-sepolia.json`),
`AGENT_SIGNER_BIN`, `AGENT_ENV_FILE`, `AGENT_SPONSORED=0` to make the account
pay its own gas, `ANTHROPIC_MODEL`. The hardware needs group `tss` (TPM) or
`dialout` (TROPIC01) for the user running the agent.

## Verified on Base Sepolia (2026-10-20)

`npm run smoke` with the TROPIC01-held agent key:

- `demo_counter_increment` → tx `0x8e8c582dbda0cb2da906b508aa3758ee3d5ca514d2a2600873a7f300a56b1aa7` (counter 8 → 9);
- `native_transfer` of 0.0000001 ETH to `0x…dEaD` → refused at simulation:
  `AA23 reverted PolicyFailed(0)` — the chip signed, the account said no.

## Notes

- **Telemetry.** AgentKit 0.10 posts every wallet initialization and action
  call, with the wallet address, to `cca-lite.coinbase.com`, with no opt-out;
  an HTTP error there crashes the process. `noTelemetry.ts` answers those
  requests locally.
- **viem** is pinned to the version AgentKit bundles; two copies make the
  `PublicClient` types incompatible.
- Actions that need off-chain signatures (x402 `eip3009`, Permit2, SIWE) fail
  by design — see `docs/ERC1271.md`.
