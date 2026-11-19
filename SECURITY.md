# Security policy

## Status

This project runs on Base Sepolia, a test network, and holds no real funds.
It has had an internal review ([`docs/AUDIT-2026-10-20.md`](docs/AUDIT-2026-10-20.md)),
not a third-party audit. A third-party audit comes before any mainnet funds.

## Reporting a vulnerability

Report it privately through GitHub: the **Report a vulnerability** button on
the repository's
[Security tab](https://github.com/postcryptum-research/agent-keys/security/advisories/new).
Only the maintainers see the report. Please do not open a public issue for it.

We aim to acknowledge a report within 5 business days.

## Scope

- The contracts in `contracts/`.
- The signer in `signer/` (`hw-signer`, `agent-signer`).
- The owner apps and their shared core in `mobile/`.

The machine the agent runs on is untrusted by design: what a compromised
agent host can and cannot do is the subject of
[`docs/AUDIT-2026-10-20.md`](docs/AUDIT-2026-10-20.md). A report that shows
it can do more than the account's on-chain policy allows is in scope.
