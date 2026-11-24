# agent-keys: notes for AI coding agents

Read by every agent session in this repository, and a fair summary of the
house rules for people. It is kept short on purpose: details live in the docs
it points to.

## What this is

An AI agent signs its on-chain actions with a key held in a secure element.
Its ERC-4337 smart account (ZeroDev Kernel v3.3) checks the chip's P-256
signature on chain, and `AgentPolicy` holds the agent to the owner's mandate.
The idea on one page: `docs/HOW_IT_WORKS.md`. The design:
`docs/ARCHITECTURE.md`.

| Where | What |
|---|---|
| `contracts/` | Foundry: the modules (`P256Validator`, `P256Signer`, `AgentPolicy`, `P256RecoveryValidator`, `WhitelistPaymaster`), their tests, `deployments/<chainId>.json` |
| `signer/` | Rust workspace: `hw-signer` (the hardware backends) and `agent-signer` (the CLI) |
| `mobile/` | `owner-core` (shared with the phone apps, outside the signer workspace), `android/`, `ios/` |
| `examples/` | agent frameworks on top of the CLI |
| `scripts/erc7562/` | the ERC-7562 check of validation traces |
| `docs/` | platform guides, FAQ, resilience, the agent config (`AGENT_CONFIG.md`) |

## Commands that work

```sh
git submodule update --init --recursive          # contracts/lib
cd contracts && forge test --evm-version osaka    # forge 1.8 or later: the P-256 precompile comes with Osaka
cd signer && cargo test                           # software backend, no hardware
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli   # the CLI end to end on a local anvil
cd mobile/owner-core && cargo test                # add --features ffi,test-chains for the phone's side
cargo clippy                                      # in signer/ and in mobile/owner-core/: unchecked arithmetic fails (house rule 10); add a backend's --features to lint it
cd scripts/erc7562 && npm install && npm run check
gitleaks git . --redact --log-opts="--all" --exit-code 1    # what CI runs, over the whole history
scripts/source-record.sh                          # every contract's bytecode and VERSION against origin/master (house rules 3 and 9)
```

- Rust 1.94.1 or newer.
- `forge test` rewrites `contracts/benchmarks/gas.json`. Restore it unless the
  change is about gas.
- Each `anvil_cli` test starts a local chain. If several fail with "anvil did
  not start", run them with `-- --test-threads 2`.
- Hardware tests are `--features <backend> -- --ignored` and need the device:
  see the platform's doc (`docs/WINDOWS.md`, `SECURE_ENCLAVE.md`,
  `TROPIC01.md`, `YUBIKEY.md`).

## House rules

1. **Start from fresh `master`.** Fetch and branch from it, or merge it into
   the branch before adding to it. Say in the pull request which commit it
   was built on.
2. **A change comes with its test and its docs.** A rule added to a contract
   or to the phone's review is broken once on purpose, to see a test catch it
   (`docs/FUZZING.md` shows how). Docs change in the same pull request; where
   a doc has a Russian original (`*_ru.md`), both do.
3. **A deployed contract's source is the release it was built from.**
   Nothing is deployed to a mainnet but an audited release tag. Instances
   on test networks are pre-audit and are recorded with the commit they
   were built from: `contracts/deployments/<chainId>.json` lists them,
   earlier ones under a versioned name, and `docs/DEPLOYMENTS.md` names the
   tag or commit. Master may differ from every deployment. A tagged
   release's source never changes, comments included.
   `scripts/source-record.sh <tag or commit>` compares a build with
   another's, contract by contract.
4. **Validation runs under ERC-7562.** No clock and no storage but the
   account's (`keccak(account ‖ x) + n`) in validator, signer and policy
   code. `scripts/erc7562/` checks a trace.
5. **What changes rights on a real chain is the owner's step.** Installing,
   rotating or revoking a mandate, changing the root key, moving funds: an
   agent session prepares the command and explains it, and the owner signs
   with the owner key.
6. **Claims carry their source.** In docs, `[V]` is verified with the source
   given and `[I]` is inferred. A pull request says what was run, what it
   showed and what was not checked. Dates are UTC.
7. **Stage files by path.** Build outputs (`target/`, `out/`, `build/`,
   compiled libraries) never go in.
8. **Addresses and transaction hashes are written in full.** All 42
   characters of an address and all 66 of a hash, in docs, commit messages,
   pull requests and issues; never cut with an ellipsis. A cut value cannot
   be searched for or checked against the chain. Text moved or quoted from
   elsewhere gets its cut values restored from the link target or the chain.
9. **Versions and releases.** Every deployable contract carries
   `string public constant VERSION = "x.y.z"` (semantic versioning, per
   contract, from `0.1.0`), and a change to a contract's bytecode raises
   its version: CI's `source-record` job fails a pull request where a
   contract's bytecode differs from the base's and its version does not. A
   release is tagged at each stage: `vX.Y.Z-pre-internal-audit`,
   `vX.Y.Z-pre-external-audit` (the commit given to the auditors),
   `vX.Y.Z-post-external-audit` (after the fix review), and `vX.Y.Z` (the
   commit deployed). Audit reports are kept in the repository with the tag
   they cover.
10. **Arithmetic in Rust is checked.** In the code that ships (everything
    outside tests) an integer is never added, subtracted, multiplied,
    divided by a variable or shifted by a variable with a bare operator:
    `a = b + x` is forbidden. Write `checked_add` and its kin and handle
    `None` as a refusal with a reason; `saturating_*` only where the
    clamped value is the right answer (a counter, a number of seconds
    left). A conversion that can lose bits is `try_from`, never `as`, and
    never `.to::<T>()` on a 256-bit value. Clippy holds the operators and
    the casts (`arithmetic_side_effects` and the three `cast_*` lints,
    denied in the `Cargo.toml` files): `cargo clippy` fails on a violation
    and CI runs it on every pull request. No `#[allow]` of these lints. A
    shift by a variable and `.to::<T>()` it does not see: those stay with
    the review. Release builds keep `overflow-checks` on as the second
    line.

## Never in the repository, a pull request or an issue

- Keys, seed phrases, PINs, RPC URLs that carry a key, `.env` files.
- A person's name or account handle. Write "the owner", "the reviewer", "the
  auditor", and cite a finding by its number.
- Anything from a private repository: its paths, issue numbers or wording.
- Statements about anyone's devices or holdings: what someone owns, has at
  hand, ordered or lacks. The record of a test names the model and the
  software version it ran on, and nothing else.
- Device data: serial numbers, device names, local network addresses,
  home-directory paths.

## Phones

- The owner app holds key handles. Update it in place (`adb install -r`,
  `mobile/ios/install-phone.sh`) and never uninstall it
  (`docs/MOBILE_DEV_MODE.md`).
- The regular build does not know the local test chain.
  `OWNER_CORE_FEATURES=ffi,test-chains ./build-core.sh` builds the
  development variant for local-chain runs; put the regular build back
  afterwards.

If a task and a rule here disagree, stop and ask before going on.
