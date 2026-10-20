# Architecture: hardware-held P-256 keys + ERC-4337 smart accounts

## Why the project pivoted

TPM 2.0, Apple Secure Enclave, Windows Platform Crypto Provider and WebAuthn
passkeys all expose hardware-protected ECDSA keys on **NIST P-256
(secp256r1)**. None of them support secp256k1, and an Ethereum EOA is
secp256k1 + `ecrecover`. There is no recovery id `v` for a P-256 signature,
so a hardware key can never own an EOA. The original prototype hit exactly
this wall (`git log`: `f6e2874 "my laptop don't have a secp256k1 in TPM
2.0"`; `src/sign.py: compute_eth_v` tried secp256k1 recovery over a P-256
signature).

So we stop trying to make the chip own an EOA. **The chip stays a P-256
signer; the account becomes a smart account** whose `validateUserOp` verifies
P-256 against the enrolled `(Qx, Qy)`. The bundler signs the outer transaction
with its own secp256k1 key — the chip never touches that curve.

What made this viable now: the RIP-7212 precompile brings on-chain P-256
verification from ~300k gas (pure Solidity) to ~3.4k. It is live on Base,
Optimism and other OP-Stack chains, Polygon, zkSync, Scroll and Linea, and
reaches mainnet via EIP-7951 (Osaka).

Reference design: Y. Madhwal, *Integrating Secure Elements with Account
Abstraction for Autonomous IoT Blockchain Agents* (Skoltech research seminar,
October 2026). It uses an ATECC608A on a Raspberry Pi with a P256 smart
account, a whitelist paymaster and a telemetry logger. We generalize it in two
directions: the secure element is the TPM / Secure Enclave already present in
general-purpose machines, and the "device" is an AI agent.

## Goals

- The agent's signing key never exists as a file. It is generated inside the
  hardware and never exported. The `key.priv` blobs on disk are TPM-wrapped
  and useless outside the chip that wrapped them.
- No third party holds signing authority. The sole on-chain owner of the
  account is the hardware public key. No MPC, no custodial gateway. The
  bundler and paymaster are untrusted infrastructure: they can delay or drop
  a request, they cannot forge one or move funds.
- Cross-platform. One account, one trait, one backend per platform.

## Threat model for an agent

Hardware custody is not trusted intent. The chip signs any 32-byte digest the
host presents, so a compromised or misbehaving agent process can ask it to
sign a malicious operation and the chip will comply. For a sensor that means a
forged reading; for an agent with funds it means a drained account.

Therefore the **smart account's policy is the containment boundary**:

| Control | Enforced by | Protects against |
|---|---|---|
| Key cannot be copied or extracted | TPM / Secure Enclave | key theft, impersonating the agent from another machine |
| Per-operation and daily value limits | account policy module | a compromised host draining the account |
| Target contract / selector allow-list | account policy module | the agent acting outside its mandate |
| Session keys with TTL and budget | account validator | the agent holding root authority at all times |
| Rotation / revocation under a separate factor | account root path | losing control when a host is retired or breached |

Chip and policy answer different questions. The chip guarantees nobody else
can be this agent. The policy guarantees that even this agent, compromised,
cannot exceed what it was allowed to do. Together they provide what MPC
providers sell as a service, without the provider.

## System

```
 host (Linux / macOS / Windows)                  chain (Base Sepolia → L2s)
 ┌────────────────────────────────┐              ┌───────────────────────────────┐
 │ agent (LLM or workflow)        │              │ EntryPoint (ERC-4337)         │
 │   │ intent → UserOperation     │   bundler    │   │                           │
 │   ▼                            │ ───────────▶ │   ▼ validateUserOp            │
 │ agent-signer (Rust)            │              │ P256 smart account            │
 │   │ userOpHash                 │              │   • P256 validator (RIP-7212) │
 │   ▼                            │              │   • policy / session keys     │
 │ HardwareSigner trait           │              │   ▼ execute                   │
 │   ├ tpm            (Linux)     │              │ target contract               │
 │   ├ secure-enclave (macOS)     │              │                               │
 │   ├ windows-tpm    (Windows)   │              │ Paymaster (sponsors gas)      │
 │   └ software       (dev/CI)    │              └───────────────────────────────┘
 └────────────────────────────────┘
```

The device never holds the native token: a paymaster sponsors eligible
operations, following the reference design.

## The signer trait

`signer/crates/hw-signer` defines the only platform-specific seam:

```rust
pub trait HardwareSigner {
    fn public_key(&self) -> Result<PublicKey, SignerError>;        // (x, y)
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError>; // (r, s), low-s
}
```

A digest goes in, `(r, s)` comes out. Everything above it — UserOperation
building, signature packing, bundler I/O — is platform-neutral. Backends are
cargo features so a machine compiles only the one it has:

| Feature | Platform | Mechanism | Status |
|---|---|---|---|
| `software` | all | in-memory `p256` key — **dev/CI only**, never for a funded account | done |
| `tpm` | Linux | TPM 2.0 via `tss-esapi`; keys created under the SRK (`0x81000001`), transient or persisted | done |
| `secure-enclave` | macOS | Secure Enclave via Security.framework (`kSecAttrTokenIDSecureEnclave`) | planned |
| `windows-tpm` | Windows | TPM 2.0 via CNG Platform Crypto Provider | planned |

Signatures are normalized to low-s off-chip: `(r, n − s)` is equally valid,
RIP-7212 accepts either, and the Solady verifier rejects high-s to kill
malleability.

## Repository layout

```
signer/        Rust workspace: hw-signer (trait + backends), agent-signer (CLI)
contracts/     Foundry: P256 validator, account, paymaster; tests consume
               JSON vectors produced by the Rust CLI
docs/          this document and design notes
src/, tests/   legacy Python prototype — kept as reference until the Rust
               CLI reaches parity, then removed
```

Secrets (RPC URLs, the testnet gas wallet) live **outside** the repository
in `../.env` and `../gas-wallet.key`; `.gitignore` and `.git/info/exclude`
refuse them if they are ever copied in.

## Development

Any platform — software backend, no hardware needed:

```sh
cd signer && cargo test
cd contracts && forge test        # RIP-7212 enabled locally via `odyssey = true`
```

Linux — TPM backend:

```sh
sudo apt install libtss2-dev libclang-dev    # ESAPI headers + bindgen
sudo usermod -aG tss "$USER"                 # access to /dev/tpmrm0; re-login
cd signer
cargo test --features tpm -- --ignored       # signs inside the TPM
cargo run -p agent-signer --features tpm -- vector --backend tpm --message hello
```

Lessons that cost real debugging time:

- Talk to `/dev/tpmrm0` (kernel resource manager, group `tss`), never raw
  `/dev/tpm0` (root-only, single client).
- `ReadPublic` and `TR_FromTPMPublic` have no auth area. Run them with
  `execute_without_session`; under the password session tpm2-tss 4.0.1 returns
  `TPM_RC_HANDLE`, and with the crate's pre-generated bindings it segfaulted.
- Build `tss-esapi` with `generate-bindings` so bindgen targets the installed
  tpm2-tss 4.x headers.
- The signing key must be *unrestricted*: a restricted key refuses to sign a
  host-computed digest without a TPM hash-check ticket.
- Kernel permission ids must be *clean* 4-byte values. `bytes4(keccak256(…))`
  leaves the rest of the hash as dirty low-order bits, and
  `ValidatorLib.permissionToIdentifier` ORs the raw word in assembly: the
  permission installs under `0x02 ‖ id ‖ garbage`, the nonce encodes
  `0x02 ‖ id ‖ 0…0`, and every operation fails the allowed-selector check
  with `InvalidValidator()` after the signer has already passed.

## Roadmap

- **Phase 0 — prove the primitive. Done (2026-10-20).** Vectors signed by the
  software backend and inside a TPM 2.0 (Intel PTT) both verify on-chain
  through RIP-7212 in `forge test`; a `P256.verifySignature` call costs about
  11k gas including test overhead. The secp256k1-recovery path in
  `src/sign.py` is obsolete.
- **Phase 1 — on-chain.** *1a done (2026-10-20):*
  `contracts/src/P256Validator.sol`, an ERC-7579 validator on ZeroDev Kernel
  v3.3. `forge test` runs the full ERC-4337 path — EntryPoint v0.7 →
  `KernelFactory.createAccount` → Kernel → validator → `execute` — with a
  P-256 signature, and the committed TPM vector passes the validator.
  *1b done (2026-10-20):* the agent key as a Kernel *permission* instead of
  root — `contracts/src/P256Signer.sol` (`ISigner`) plus
  `contracts/src/AgentPolicy.sol` (`IPolicy`): single-call `execute` only,
  (target, selector) allow-list with `0x00000000` for plain transfers, value
  cap per operation, total budget, hard expiry enforced by the EntryPoint via
  `validUntil`, and ERC-1271 refused so the agent cannot sign permits or
  orders off-chain. `forge test` covers allowed/denied targets and selectors,
  cap and budget, expiry, and that the agent key is rejected on the root
  path while the owner key is not. Permission signature format:
  `0xff ‖ r ‖ s`; nonce key: `0x00 ‖ 0x02 ‖ id(4) ‖ 0×16 ‖ nonceKey(2)`.
  *1c done:* `script/Deploy.s.sol` deploys the three modules and a demo
  target through the canonical CREATE2 deployer (salt 0) and records them in
  `deployments/<chainid>.json`; Kernel v3.3, its factory and EntryPoint v0.7
  are ZeroDev's and eth-infinitism's canonical deployments.
- **Phase 2 — off-chain. Done (2026-10-20).** `agent-signer` derives the
  account from the two hardware public keys and the mandate (`agent.*.json`),
  builds the `PackedUserOperation` with `alloy`, fetches `userOpHash` from the
  EntryPoint, signs it through the `HardwareSigner` trait, frames the
  signature for the root or the permission path, and submits
  `EntryPoint.handleOps` itself from a gas wallet — no bundler, no paymaster,
  no custodian. First on-chain run on Base Sepolia: account
  `0xEdB645B14e2f952C5784e34949b58F0826fBc9E9`, tx
  `0x785332105fd8085d50e542ff9f677eba964399bbc0d71333ddd71fed03e669bb`
  (deploys the account and executes the agent's call in one operation).
  Lessons: `alloy`'s `abi_encode()` on a dynamic tuple prepends an offset
  word — use `abi_encode_params()` for `abi.encode(a, b, c)`; public RPC
  replicas lag behind the one that returned the receipt, so post-inclusion
  reads are pinned to the receipt's block; simulate `createAccount` before
  funding a counterfactual address.
- **Phase 3 — operations.** Whitelist paymaster (gasless agent), optional
  bundler RPC as a drop-in for self-bundling, rotation and revocation of the
  agent permission, PCR-sealed TPM keys so the chip only signs from a trusted
  boot state, Secure Enclave and Windows CNG backends.
- **Phase 4 — gas benchmark** on Base Sepolia, mirroring the reference paper's
  measurements with a TPM in place of the ATECC608A.

## License

MIT. Dependencies are MIT-compatible: Solady (MIT), ZeroDev Kernel (MIT),
alloy (MIT / Apache-2.0), tss-esapi (Apache-2.0).
