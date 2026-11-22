# Contributing

What is where in this repository, and the identifiers that keep the project's earlier name.
*Moved here from the README on 2026-11-22, word for word; only link paths were changed.*

## Layout

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

## Earlier name

Until November 2026 the project was called TPM_sign. That name is still part
of identifiers that existing keys, key files and signatures depend on, and it
stays there on purpose:

- key labels and paths (`tpm_sign-*`, `/etc/tpm_sign/`,
  `~/Library/Application Support/tpm_sign/`);
- environment variables (`TPM_SIGN_*`);
- domain strings in signed data (`TPM_sign/v1/…`) and the key-file prefix;
- the messages of the signed test vectors in `contracts/test/vectors/`.

Renaming any of them needs a migration, not a search and replace.
