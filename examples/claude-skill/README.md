# Agent wallet skill for Claude Code and OpenClaw

`tpm-agent-wallet/SKILL.md` teaches an agent to act on-chain only through
`agent-signer`: check the account, send one call per operation, read the
mandate before trying, and report a policy refusal instead of working
around it. The key is in hardware, so there is nothing for the model to
see, leak or be tricked into printing.

Install:

```sh
# Claude Code (per project or per user)
mkdir -p .claude/skills && cp -r examples/claude-skill/tpm-agent-wallet .claude/skills/
```

OpenClaw uses the same `SKILL.md` format: copy the folder into the skills
directory of the OpenClaw workspace (see its documentation for the path).

and export `AGENT_SIGNER`, `AGENT_CONFIG`, `AGENT_ENV_FILE` for the agent's
shell. Pattern after `coinbase/agentic-wallet-skills`, with the custodial
CLI replaced by a hardware-signed one.

Grant the agent permission to run `agent-signer op send` and
`agent-signer account status` only; the owner's commands (`permission …`,
`key …`, `--root`) stay with the human.
