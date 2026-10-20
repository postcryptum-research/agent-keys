# TPM_sign — hardware-held keys for on-chain agents

An AI agent (or any unattended process) signs its on-chain actions with a key
that lives in the machine's secure element — TPM 2.0 today, Apple Secure
Enclave and Windows CNG next — and never exists as a file. Its account is an
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
  a Secure Enclave backend awaits its first run on a Mac
  ([`docs/SECURE_ENCLAVE.md`](docs/SECURE_ENCLAVE.md)).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and
[`docs/BENCHMARK.md`](docs/BENCHMARK.md) for what each authorization method
costs — P-256 through RIP-7212 is as cheap as `ecrecover`, and the whole
agent path adds about 77k gas per operation.

## Why not an EOA

Every secure element speaks NIST P-256; none speaks secp256k1, and an EOA is
secp256k1 + `ecrecover`. The first prototype ([`legacy/`](legacy/)) hit exactly
that wall. Account abstraction removes it: the chip stays a P-256 signer, and
the smart account checks that signature itself.

## Layout

```
signer/      Rust: hw-signer (HardwareSigner trait; software + tpm backends),
             agent-signer CLI
contracts/   Foundry: P256Validator, P256Signer, AgentPolicy (ERC-7579 modules)
             + tests against Kernel v3.3 and EntryPoint v0.7; P-256 vectors
             signed in software and in a TPM
docs/        architecture, threat model, TPM design notes
legacy/      the original Python / tpm2-tools prototype, kept for reference
```

## Quick start

Any platform, no hardware (software backend — dev/CI only):

```sh
cd signer && cargo test
cd ../contracts && forge test      # RIP-7212 enabled locally via odyssey = true
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
tests under `contracts/test/vectors/` consume these, including one signed
inside an Intel PTT.

## Run an agent account on Base Sepolia

Secrets stay outside the repository: a `.env` with `BASE_SEPOLIA_RPC_URL` and
`GAS_WALLET_KEYFILE` (a file holding the hex key of a funded testnet EOA that
pays for the outer `handleOps` transactions). The account itself is described
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

Gasless, and the owner's controls:

```sh
$B paymaster deposit --agent $A --env-file $E --wei 3000000000000000
$B paymaster sponsor --agent $A --env-file $E          # list the account
$B demo --agent $A --env-file $E --sponsored           # the paymaster pays

$B key create --handle 0x81010012 --pcrs 0,2,4,7       # a key sealed to the boot state
# in agent.json: pin "account", point "agent" at {"tpm": {"handle": "0x81010012", "pcrs": [0,2,4,7]}},
# give the new permission a fresh id — then, signed by the owner key:
$B permission rotate --agent $A --env-file $E --old-id 0x61676e74 --sponsored
$B permission revoke --agent $A --env-file $E --id 0x61676e32          # when the agent is retired
```

## Reference

Y. Madhwal, *Integrating Secure Elements with Account Abstraction for
Autonomous IoT Blockchain Agents* (Skoltech research seminar, 2026) — the same
design with an ATECC608A; this project generalizes it to the TPM / Secure
Enclave in ordinary machines and to AI agents.

## License

MIT.
