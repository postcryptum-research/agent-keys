---
name: tpm-agent-wallet
description: Send on-chain transactions from this agent's hardware-signed ERC-4337 account on Base Sepolia (key inside a TPM / Secure Enclave / TROPIC01, mandate enforced on-chain). Use when asked to check the agent wallet, call a contract, or transfer ETH as the agent.
---

# Agent wallet with a hardware key

This agent owns an ERC-4337 smart account (ZeroDev Kernel v3.3) on Base
Sepolia. Its signing key is a P-256 key inside a hardware secure element; it
is never in a file, an environment variable, or this conversation. The only
way to act on-chain is the `agent-signer` CLI, which builds a
UserOperation, has the hardware sign its hash, and waits for inclusion.

The account enforces a **mandate** on-chain (AgentPolicy): only allow-listed
`(contract, function)` pairs, a value cap per operation, a total budget and an
expiry. Anything outside it is refused by the account itself, whatever is
asked here — so do not try to work around a refusal.

## Setup (read from the environment)

- `AGENT_SIGNER` — path to the `agent-signer` binary
  (default `signer/target/debug/agent-signer` in the TPM_sign repo).
- `AGENT_CONFIG` — agent account config, e.g. `signer/agent.tropic01.base-sepolia.json`.
- `AGENT_ENV_FILE` — `.env` with `BASE_SEPOLIA_RPC_URL` and `BUNDLER_URL`.

The config's `policy.allow` lists exactly what the agent may call; read it
before proposing an action so you only attempt allowed calls.

## Commands

Account state (address, deployment, balances):

```sh
"$AGENT_SIGNER" account status --agent "$AGENT_CONFIG" --env-file "$AGENT_ENV_FILE"
```

Send one call — the only write operation. Gas is sponsored by the project's
paymaster with `--sponsored`:

```sh
"$AGENT_SIGNER" op send --agent "$AGENT_CONFIG" --env-file "$AGENT_ENV_FILE" \
  --target 0xCONTRACT --data 0xCALLDATA --wei 0 --sponsored --json
```

- `--data` is ABI-encoded calldata; build it with `cast calldata "increment()"`
  (Foundry) or leave `0x` for a plain ETH transfer with `--wei <amount>`.
- On success stdout is one JSON line:
  `{"account","userOpHash","tx","block","gasUsed"}`. Report the `tx` as
  `https://sepolia.basescan.org/tx/<tx>`.
- The hardware takes a couple of seconds per signature and the CLI waits for
  inclusion; allow up to two minutes.

Read-only calls do not need the agent at all:

```sh
cast call 0xCONTRACT "count()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
```

## Errors

- stderr contains `3e4983f6` (`PolicyFailed`) or `AA23`: **the mandate
  refused the call.** Tell the user plainly which call was refused and why it
  is outside the allow-list or limits. Do not retry with other targets,
  amounts, or encodings.
- `Permission denied` on `/dev/tpmrm0` or `/dev/ttyACM0`: the user's session
  lacks the `tss` / `dialout` group — ask them to fix it; do not use `sudo`.
- No message signing exists: the account has ERC-1271 disabled for the
  agent, so permits, SIWE logins and off-chain orders are not possible by
  design.

## Never

- Never look for, print, or ask for a private key — there is none to find.
- Never run `permission rotate`, `permission revoke`, `--root`, or `key …`
  commands: those are the owner's controls over this agent, not the agent's.
