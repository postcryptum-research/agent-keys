# ElizaOS on a hardware-signed agent account

An [ElizaOS](https://github.com/elizaOS/eliza) agent whose only wallet is a
agent-keys account: every on-chain action becomes one ERC-4337 UserOperation
signed inside a TPM, Secure Enclave or TROPIC01 and checked on-chain by
`AgentPolicy`. The plugin reuses the AgentKit example's bridge
(`../agentkit/src/agentSigner.ts`, `agent-signer op send --json`).

```
user ─▶ ElizaOS (Claude) ─▶ plugin-agent-keys action ─▶ agent-signer op send --json
                                                         │ hardware signs userOpHash
                                                         ▼
                                     bundler ─▶ EntryPoint ─▶ Kernel + AgentPolicy
```

| File | What it does |
|---|---|
| `src/plugin/index.ts` | `plugin-agent-keys`: service, `TPM_WALLET` provider, actions `GET_AGENT_WALLET`, `READ_DEMO_COUNTER`, `INCREMENT_DEMO_COUNTER`, `SEND_TX_WITHIN_MANDATE`, `PAY_FOR_URL` |
| `src/plugin/wallet.ts` | Account address and deployments from the agent config, viem reads, writes and x402 payments through the bridge |
| `src/agent.ts` | Headless ElizaOS host: PGlite, migrations, plugins |
| `src/smoke.ts` | No LLM: an allowed call lands, a transfer to an outsider is refused |
| `src/chat.ts` | Terminal chat with the Claude-driven agent |
| `src/character.ts` | The character (`Keel`) |
| `src/index.ts` | Optional project entry for `elizaos start` (web UI) |

## Run

```sh
cd signer && cargo build -p agent-signer --features tpm,tropic01 && cd -
cd examples/elizaos && bun install          # Bun >= 1.2

bun run smoke:dry      # boot ElizaOS + plugin, read balance and counter; no transaction
bun run smoke          # + increment (lands) + transfer to 0x…dEaD (refused by AgentPolicy)
ANTHROPIC_API_KEY=… bun run chat
```

## Paying for APIs (x402)

With a second permission of the same account whose mandate may pay x402
(`signer/agent.x402.base-sepolia.json`, installed once by the owner with
`agent-signer permission add`), the agent gets `PAY_FOR_URL`: it fetches a
URL and, on `402 Payment Required`, pays the price in USDC from the
mandate's token budget — registered on-chain first, then signed in
hardware ([`docs/ERC1271.md`](../../docs/ERC1271.md#x402--registered-authorizations-implemented-agentpolicy-v6)).
The two permissions keep separate mandates: the paying one can do nothing
but register and reclaim x402 payments.

```sh
cd examples/x402 && PAY_TO=0x… npm run server &       # a paid endpoint
cd examples/elizaos
X402_AGENT_CONFIG=../../signer/agent.x402.base-sepolia.json \
X402_URL=http://localhost:4021/quote bun run smoke    # … + PAY_FOR_URL
X402_AGENT_CONFIG=../../signer/agent.x402.base-sepolia.json bun run chat
> get me the quote from http://localhost:4021/quote
```

Environment: as in `examples/agentkit` (`AGENT_CONFIG`, `AGENT_SIGNER_BIN`,
`AGENT_ENV_FILE`, `AGENT_SPONSORED`), plus `ANTHROPIC_*`, see `.env.example`.

## Notes

- **ElizaOS version.** Pinned to the 1.x line on npm (`@elizaos/core` 1.7.2,
  the `latest` tag). The 2.x line on `develop` (2.0.x, needs Node 24) ships as
  `beta` only and no longer has the project CLI. The plugin uses only the
  `Action` / `Provider` / `Service` subset shared by both.
- **Do not add `@elizaos/plugin-wallet` / `plugin-evm`.** Their EVM path reads
  `EVM_PRIVATE_KEY` and generates and saves one if it is missing.
- **Models.** plugin-anthropic 1.5.x always sends `temperature`, so use a model
  that still accepts it (`claude-sonnet-4-6`, `claude-haiku-4-5`). No
  embedding model is configured; ElizaOS warns and works without one.
- **Database.** PGlite under `.eliza/pglite`. `src/agent.ts` runs the SQL
  migrations before starting the agent: core 1.7.2 reads the `agents` table
  before it migrates, so a fresh database fails otherwise.
- **`elizaos start`** (`bun run start:ui`) also works, but `@elizaos/server`
  1.7.2 sends errors to a built-in Sentry DSN unless `SENTRY_DSN` is set to
  some other value. An empty value does not turn it off. The headless
  scripts do not load the server.
- Off-chain signatures (permits, SIWE) are not offered, by design; x402 is
  the one exception, through registration. See `docs/ERC1271.md`.
