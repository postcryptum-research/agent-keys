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
| `secure-enclave` | macOS | Secure Enclave via Security.framework (`kSecAttrTokenIDSecureEnclave`), keys by keychain label | written, type-checked for `aarch64-apple-darwin`; awaiting a run on Apple hardware — see `docs/SECURE_ENCLAVE.md` |
| `windows-tpm` | Windows | TPM 2.0 via CNG's Platform Crypto Provider, keys by name | written, type-checked for `x86_64-pc-windows-msvc`; awaiting a run on Windows — see `docs/WINDOWS.md` |
| *(candidate)* | any (USB) | Tropic Square TROPIC01 USB DevKit — an open-architecture secure element with ECDSA P-256; verified responsive with the vendor's Rust SDK (`tropicsquare/libtropic-rs`), whose USB-devkit example holds the transport and a full key-gen/sign flow | backend not yet in tree |

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
- **Phase 3 — operations.**
  - *3.1 Secure Enclave backend — written (2026-10-20), awaiting a run on
    Apple hardware.* `docs/SECURE_ENCLAVE.md` is the build-and-test guide
    for whoever has a Mac.
  - *3.2 Paymaster — done (2026-10-20).* `contracts/src/WhitelistPaymaster.sol`
    on eth-infinitism's `BasePaymaster` v0.7.0: the sponsor keeps a deposit
    in the EntryPoint and lists the accounts it pays for; sponsorship and
    authorization stay separate checks. Deployed on Base Sepolia at
    `0xe314e95bef9b891c48429aD127D79e601240BB52`; a sponsored agent
    operation (tx `0xae73b53d17b74ad8c7b6d65f8cc98abd40c513a808b09764828dff8a3a5f2106`)
    left the account's balance untouched. `agent-signer paymaster
    deposit|sponsor` and `--sponsored` on `op send` / `demo`.
  - *3.3 done (2026-10-20).* **Rotation and revocation:** root operations
    signed by the owner key — `permission revoke` uninstalls the agent
    permission; `permission rotate` replaces it in one batch (uninstall the
    old id, `installValidations` the one the config describes, grant
    `execute`), with the install nonce derived from Kernel's rule
    (`currentNonce()`, plus one when re-installing the same id). The config
    pins the deployed `account` so a changed mandate or key describes the
    *next* permission, not a new address. **PCR sealing:** `key create
    --pcrs 0,2,4,7` creates a key whose auth policy is `TPM2_PolicyPCR`
    over those registers with `userWithAuth` cleared; signing opens a policy
    session with an empty digest so the TPM compares the registers' current
    values itself, and refuses once the measured boot state changed (the
    hardware test seals to the resettable PCR 16, extends it, sees the refusal,
    resets it). On Base Sepolia: rotation `agnt → agn2` to a sealed key, tx
    `0x4519a35b5acdc19ffe713326964b5214677825d11040684f9869adbd8b195370`;
    the sealed key's first sponsored operation, tx
    `0xc8117420694a9c17d3c91a14df3ce70f00298d2bc0fcd38f55997c1bfc75db4b`.
  - *3.4 done (2026-10-20): gas benchmark* — `docs/BENCHMARK.md`,
    `contracts/test/GasBenchmark.t.sol`. P-256 verification via RIP-7212
    costs the same as `ecrecover` (7,433 vs 7,402 gas), so hardware keys
    carry no gas penalty; the full agent path (real EntryPoint, Kernel,
    policy + signer, paymaster) adds about 77k gas per operation; large
    payloads are dominated by data cost, as the paper found.
  - *3.5 done (2026-10-20): bundler RPC as a drop-in.* `--bundler <url>` or
    `BUNDLER_URL` routes an operation through an ERC-4337 bundler: the
    operation is serialized in the v0.7 unpacked form, the bundler's
    `eth_estimateUserOperationGas` replaces our limits (the hash covers them,
    so the hardware signs a second time), `eth_sendUserOperation`, then
    `eth_getUserOperationReceipt` until inclusion. Pimlico's public endpoint
    (no key, 20 requests/minute) accepted an agent operation — its ERC-7562
    simulation passed `P256Signer` and `AgentPolicy` — and included it: tx
    `0xb42e30ae72ac8d676c33198b65ae85e8ef06936d15b28cda5832ed4cc0527675`,
    paid from the account's EntryPoint deposit; the gas wallet took no part.
    A *sponsored* operation went through the same way (tx
    `0x59b2814afc86bd161cd0ebf8abb96824a881746375881fabc686bb17c4c2539f`):
    the chip signs, the paymaster pays, the bundler relays — no gas wallet
    anywhere in the path. Trust does not change: a bundler can delay or
    drop, not forge or redirect. Pimlico's public testnet endpoint relayed
    from an unstaked paymaster; bundlers with default ERC-7562 reputation
    rules require a staked one (`paymaster stake`).
  - *later:* Windows CNG backend's first run; a TROPIC01 backend.

  Lessons from 3.3: a fixed `callGasLimit` is a trap — an execution phase
  that runs out of gas reverts with *no data*, the outer `handleOps`
  still succeeds and the sponsor pays; `agent-signer` now estimates the
  execution as a call from the EntryPoint and treats
  `UserOperationEvent.success == false` as failure. `cast run` replays in a
  local EVM without RIP-7212 unless given `--odyssey`, so it shows
  `AA24 signature error` for operations the chain accepted; use it only
  with the flag, or trace the execution calldata with `cast call --from
  <EntryPoint> --trace`, where no signature is involved.

  Lesson from 3.2: solc's metadata hash embeds compiler settings, so adding
  remappings changed every contract's creation code and the deploy script
  minted a second, unused set of modules (`0xA3DF…`, `0x492E…`, `0xFA85…`,
  `0x617D…`). Bytecode is now metadata-free (`bytecode_hash = "none"`,
  `cbor_metadata = false`) and the script reuses addresses recorded in
  `deployments/<chainid>.json` whenever they hold code.
- **Phase 4 — gas benchmark** on Base Sepolia, mirroring the reference paper's
  measurements with a TPM in place of the ATECC608A.

## License

MIT. Dependencies are MIT-compatible: Solady (MIT), ZeroDev Kernel (MIT),
alloy (MIT / Apache-2.0), tss-esapi (Apache-2.0).
