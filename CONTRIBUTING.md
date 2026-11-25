# Contributing

agent-keys runs on a test network, and its contracts are deployed and in use. A change is judged by two
questions: is it right, and does the repository still say what is on chain. This page is how to report a
problem and how to send a change.

## Reporting

- **A question, an idea, a bug:** open an [issue](https://github.com/postcryptum-research/agent-keys/issues).
  For a bug, give the command you ran, what it printed and what you expected.
- **A vulnerability:** not in an issue. [`SECURITY.md`](SECURITY.md) says how to report it privately.
- **A run on hardware that is not on the tested list:** welcome. The record names the model and the software
  version, and nothing else about the device or its owner.

Before a larger change (a contract, a hardware backend, the phone apps), open an issue first, so that the scope
is agreed before the work.

## Build and test

```sh
git submodule update --init --recursive          # after cloning: contracts/lib
cd contracts && forge test --evm-version osaka    # Foundry 1.8 or later: the P-256 precompile comes with Osaka
cd ../signer && cargo test                        # Rust 1.94.1 or later; software backend, no hardware
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli   # the CLI end to end on a local anvil
cd ../mobile/owner-core && cargo test             # the core shared with the phone apps
cargo clippy                                      # in signer/ and in mobile/owner-core/: unchecked arithmetic fails
cd ../../scripts/erc7562 && npm install && npm run check
```

- `forge test` rewrites `contracts/benchmarks/gas.json`. Restore it unless the change is about gas.
- Each `anvil_cli` test starts a local chain. If several fail with "anvil did not start", run them with
  `-- --test-threads 2`.
- Tests on real hardware are `--features <backend> -- --ignored` and need the device: see the platform's page
  in [`docs/`](docs/) (`WINDOWS.md`, `SECURE_ENCLAVE.md`, `TROPIC01.md`, `YUBIKEY.md`).

## What a change needs

1. **Fresh `master` under it.** Branch from it, or merge it in before adding to a branch.
2. **Its test and its docs, in the same pull request.** Where a doc has a Russian original (`*_ru.md`), both
   change.
3. **A deployed contract's source is the release it was built from.** Nothing goes to a mainnet but an audited
   release tag. Instances on test networks are pre-audit and are recorded with the commit they were built from:
   `contracts/deployments/<chainId>.json` lists them, and [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) names the
   tag or commit. `master` may differ from every deployment. A tagged release's source never changes, comments
   included. `scripts/source-record.sh <tag or commit>` compares a build with another's, contract by contract.
4. **Validation code that passes ERC-7562.** No clock and no storage but the account's in validator, signer and
   policy code. [`scripts/erc7562/`](scripts/erc7562/) checks a trace.
5. **Claims with their source.** In docs, `[V]` is verified with the source given and `[I]` is inferred. Dates
   are UTC. Addresses and transaction hashes are written in full, never cut.
6. **Files staged by path.** Build outputs never go in.
7. **Checked arithmetic in Rust.** In the code that ships (not in tests or fuzz targets) no bare `+`, `-`, `*`,
   no division or shift by a variable, and no `as` between integer types: `checked_*` with a refusal, and
   `try_from`. `cargo clippy` fails on a violation, and CI runs it.

Never in a commit, a pull request or an issue: keys, seed phrases, PINs, `.env` files and RPC URLs that carry a
key; a person's name; serial numbers, device names, local network addresses and home-directory paths;
statements about what anyone owns or lacks. An account handle only to address a collaborator directly in a
comment (a task handed over, a review asked for, thanks), never in code, docs or commits, and never to say who
made a mistake or decided something: that is "the review", "the owner" and the issue's number.

## The pull request

- One topic. Say what it changes and why, what you ran and what it showed, what you did not check, and which
  commit of `master` it was built on.
- The secret scan runs on every push and pull request. Run it before pushing:
  `gitleaks git . --redact --log-opts="--all" --exit-code 1`.
- A maintainer reviews it. What changes rights on a real chain (installing or revoking a mandate, changing a
  root key, moving funds) is done by the account's owner with the owner key, never by a pull request or a
  script.
- Contributions are accepted under the licence of the directory they change: Apache-2.0 in `signer/`, MIT
  elsewhere ([`README.md`](README.md#license)).

Working with an AI coding agent: [`CLAUDE.md`](CLAUDE.md) gives it the same rules and commands.

## Where things are

```
signer/      Rust: hw-signer (HardwareSigner trait; tpm, windows-tpm,
             secure-enclave, tropic01, yubikey-piv, software backends), agent-signer CLI
contracts/   Foundry: P256Validator, P256Signer, AgentPolicy (ERC-7579 modules),
             WhitelistPaymaster + tests against Kernel v3.3, EntryPoint v0.7
             and Safe v1.4.1; P-256 vectors signed in software, a Linux TPM,
             a Windows TPM, a TROPIC01, an Apple Secure Enclave and a YubiKey 5
mobile/      owner-core: Kernel encodings and the ERC-4337 hash shared with the
             phone owner apps (docs/MOBILE_OWNER_DESIGN.md); licence pending
examples/    AgentKit, Claude Code skill, Jinn, Olas, ElizaOS, x402
docs/        architecture, benchmark, ERC-1271 (Safes, x402), per-platform guides;
             related/ — how other products compare (Cupcake, agent-wallet platforms)
scripts/     testnet chores (testnet_usdc.py: gas-wallet ETH -> Base Sepolia USDC)
legacy/      the original Python / tpm2-tools prototype, kept for reference
```

## Names that must not be renamed

Until November 2026 the project was called TPM_sign. That name is still part
of identifiers that existing keys, key files and signatures depend on, and it
stays there on purpose:

- key labels and paths (`tpm_sign-*`, `/etc/tpm_sign/`,
  `~/Library/Application Support/tpm_sign/`);
- environment variables (`TPM_SIGN_*`);
- domain strings in signed data (`TPM_sign/v1/…`) and the key-file prefix;
- the messages of the signed test vectors in `contracts/test/vectors/`.

Renaming any of them needs a migration, not a search and replace.
