# TPM_sign — hardware-held keys for on-chain agents

An AI agent (or any unattended process) signs its on-chain actions with a key
that lives in the machine's secure element — TPM 2.0 today, Apple Secure
Enclave and Windows CNG next — and never exists as a file. Its account is an
ERC-4337 smart account that verifies the chip's **P-256** signature on-chain
through the RIP-7212 precompile. No secp256k1 key, no MPC, no custodian: the
only on-chain owner is the public key of the chip.

**Status:** Phase 0 done — a signature produced inside a real TPM 2.0 verifies
on-chain in `forge test`. Phase 1a done — `P256Validator` (ERC-7579, ZeroDev
Kernel v3.3) runs the full ERC-4337 path in `forge test`: EntryPoint → Kernel
account → P-256 signature → `execute`. Next: a policy-bound signer so the agent
key never holds root authority. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Why not an EOA

Every secure element speaks NIST P-256; none speaks secp256k1, and an EOA is
secp256k1 + `ecrecover`. The first prototype ([`legacy/`](legacy/)) hit exactly
that wall. Account abstraction removes it: the chip stays a P-256 signer, and
the smart account checks that signature itself.

## Layout

```
signer/      Rust: hw-signer (HardwareSigner trait; software + tpm backends),
             agent-signer CLI
contracts/   Foundry: P256Validator (ERC-7579) + tests against Kernel v3.3 and
             EntryPoint v0.7; P-256 vectors signed in software and in a TPM
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

## Reference

Y. Madhwal, *Integrating Secure Elements with Account Abstraction for
Autonomous IoT Blockchain Agents* (Skoltech research seminar, 2026) — the same
design with an ATECC608A; this project generalizes it to the TPM / Secure
Enclave in ordinary machines and to AI agents.

## License

MIT.
