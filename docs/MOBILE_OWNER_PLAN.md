# Mobile owner app — development plan

*Hand-off document, 2026-10-27. Nothing here is built yet. Read this first
if you are picking up the phone work.*

## Goal

A laptop and a phone working together. The laptop runs the agent and the
CLI. The phone holds the account's **owner key** inside its own secure
hardware: the Secure Enclave on iPhone, StrongBox or the TEE on Android.
The phone signs owner operations only after a fingerprint or face check.

The business point is a gap in the market. Mainstream mobile wallets use
secp256k1, which phone secure elements cannot do, so they keep an encrypted
seed and the key ends up in app memory while it signs. Here the key is
P-256, it never leaves the chip, and the smart account verifies it
on-chain. This claim should be backed by sources for named wallets before
anything is published.

Background and rejected alternatives (Termux, passkeys, and why passkeys
sync to the cloud): [`PHONE_OWNER.md`](PHONE_OWNER.md).

## Start here (for a new session)

1. **Read the docs.** [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md) (one page),
   [`KEY_POLICY.md`](KEY_POLICY.md) (the owner key's rules),
   [`PHONE_OWNER.md`](PHONE_OWNER.md), then this file.
2. **Build and run the tests.**
   - `cd signer && cargo test`
   - `cargo test -p agent-signer --features insecure-software-keys --test anvil_cli`
     — end-to-end tests on a local anvil, needs Foundry. It is the harness
     to reuse for the phone's signatures.
   - `cd contracts && forge test`
3. **Two decisions are open** — see "Open decisions" below. Ask the owner
   before choosing.

## What already exists and is reused unchanged

**On-chain: nothing changes.** The owner key is a P-256 key checked by
`P256Validator` (`contracts/src/P256Validator.sol`, Base Sepolia
`0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`). It expects exactly 64
bytes, `r ‖ s` over the 32-byte `userOpHash`. The phone only has to produce
that.

**What the phone signs:** the EntryPoint v0.7 `userOpHash`, which is
`keccak256(abi.encode(keccak256(pack(op)), entryPoint, chainId))`. The
phone must sign the raw 32-byte digest, without hashing it again.

**Making the phone the owner** is one root operation, signed by the current
owner: `owner set-root --validator <P256Validator> --retire <P256Validator>
--public-key <x>,<y>`.
- `--retire` matters here. Re-pointing root at an already installed
  validator keeps its old key; `--retire` uninstalls it first.
- This exact flow is exercised in `tests/anvil_cli.rs::recovery_drill`.

**Rust code to share with the phone:**
- `signer/crates/agent-signer/src/kernel.rs`: Kernel calldata, nonce keys,
  hashes; `decode_execute` already decodes `execute` calldata.
- The AgentPolicy install-data encoding (`PolicyParams`).
- `hw-signer::verify_p256` and the low-s rule.

**Swift precedent:** `signer/crates/hw-signer/swift/SecureEnclaveShim.swift`
signs a given P-256 digest in the Mac's Secure Enclave through CryptoKit.
It is verified on an Apple M1 (`SECURE_ENCLAVE.md`). iOS uses the same
framework.

## Verified platform facts

### iOS (Secure Enclave)

- **Every current iPhone has one.**
- **The key:** created in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`
  / CryptoKit `SecureEnclave.P256`), with an access control of
  `.privateKeyUsage` plus `.biometryCurrentSet` or `.userPresence`.
- **Signing a given digest:**
  `SecKeyCreateSignature(..., .ecdsaSignatureDigestX962SHA256, digest)`
  takes the 32 bytes as the digest; CryptoKit's `signature(for: Digest)`
  does the same. The Mac shim shows one way to do it.
- **Open:** iOS has no per-key attestation comparable to Android's. App
  Attest proves the app, not that the key lives in the Secure Enclave. How
  the laptop gets evidence of where the key lives is to be decided.

### Android (Keystore)

- **The key:** `KeyGenParameterSpec`, EC `secp256r1`, `PURPOSE_SIGN`,
  digests `DIGEST_NONE` (and `SHA-256`), and `setIsStrongBoxBacked(true)`
  with a fallback to the TEE.
- **A check on every signature:**
  `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`
  (Android 11+) and `setUnlockedDeviceRequired(true)`.
- **Signing:** `Signature("NONEwithECDSA")` in a `BiometricPrompt`
  `CryptoObject` over the 32 bytes, which gives DER → `r ‖ s`; the CLI
  normalises to low-s.
- **The security level:** `KeyInfo.getSecurityLevel()` gives StrongBox, TEE
  or software. Refuse software.
- **Attestation:** with `setAttestationChallenge(...)`, a certificate chain
  to Google's root proves the key's security level. The laptop can verify
  it at enrollment.
- **StrongBox is present only on some phones;** many budget phones have the
  TEE only. Detection:
  `adb shell pm list features | grep -iE "strongbox|keystore"`.
- **Risk:** AOSP marks `DIGEST_NONE` for ECDSA as deprecated. It is
  mandatory today, but a long-term risk.

## Proposed architecture

```
laptop: agent-signer CLI                         phone: owner app
  builds the owner operation (UserOp)
  shows a QR: LAN URL + one-time token  ───────▶ scans the QR
  serves the request on the LAN         ◀─────── fetches it (HTTP on the LAN)
                                                 decodes the operation, shows it
                                                 recomputes userOpHash itself
                                                 Face ID / fingerprint → signs (SE / Keystore)
  receives r‖s                          ◀─────── posts the signature
  verifies it against ownerPublicKey
  submits handleOps / sends to the bundler
```

- **Transport: QR, then the local network.** No server, no cloud, no
  Bluetooth. The channel needs no secrecy (a signature is public), but the
  CLI must verify every signature against `ownerPublicKey` before use.
- **The request** is JSON: protocol version, `chainId`, `entryPoint`,
  `account`, the full packed UserOperation, and optionally address labels.
  The phone **never trusts a hash or a summary from the laptop**. It
  decodes the operation and recomputes `userOpHash` itself. "What you see
  is what you sign" is the main advantage over a blind token such as a
  YubiKey.
- **What the screen shows**, decoded from the operation's calldata:
  - Kernel `execute`, single or batch;
  - `installValidations` / `uninstallValidation`, with the AgentPolicy
    mandate in full: targets and selectors, value cap, budget, validity
    window, token caps, x402 tokens;
  - `changeRootValidator`;
  - the chain and the account.
  - Anything it cannot decode is shown as "unknown call — refuse
    recommended".
- **The shared core in Rust**, compiled for iOS and Android via `uniffi`:
  decoding, hashing and display text, so the CLI and the phone always
  agree. The phone apps stay thin: secure-hardware signing, camera and
  networking.
- **On the CLI side:**
  - a new owner key spec, for example `{"phone": {...}}`, with the public
    key in `ownerPublicKey`;
  - `key create --phone` for enrollment (QR → receive the public key, plus
    attestation on Android);
  - signing through a one-shot LAN server;
  - tests in `tests/anvil_cli.rs` style.

## Phases

| # | Phase | Proves | Done when |
|---|---|---|---|
| P0 | **Spike** on the first platform | the hardware signs a raw 32-byte digest that `P256Validator` accepts | a phone signature verifies on a local anvil through a root operation (`anvil_cli` harness) |
| P1 | Enrollment and blind signing | the QR → LAN loop works with the real CLI | `owner set-root` to the phone key, then a root op signed on the phone, on anvil; then on Base Sepolia with the owner's yes |
| P2 | Decode and display | what you see is what you sign | the phone shows a decoded mandate and recomputes the hash; a tampered request is visibly different |
| P3 | Attestation | the laptop knows where the key lives | Android chain verified at enrollment; the iOS approach decided |
| P4 | Second platform | the same thing on the other OS | P0–P2 pass there |
| P5 | Distribution | others can install it | TestFlight / APK to testers; app stores later |

## Threat model, briefly

- **The laptop is compromised.** It can request a malicious operation, but
  the phone shows its real content, and the user refuses. That is the
  point of P2.
- **The phone has malware.** It cannot sign without biometrics or the PIN,
  which the hardware enforces. In theory it could fake the display, but
  then both devices must be compromised.
- **The phone is lost.** The key is not extractable. The owner recovers
  through the cold recovery key (`owner recover`, `RESILIENCE.md`), which
  stays mandatory.
- **The phone is reset or replaced.** Keystore and Secure Enclave keys are
  not backed up — correctly — so the key is gone, and recovery applies.
- **No silent extra trust:** no relay server, and no cloud sync of the key.
  These are what distinguish this design from passkeys.

## Open decisions (ask the project owner)

1. **First platform:** iPhone (needs an iPhone and a Mac with Xcode) or
   Android (APK, no store; StrongBox only on some phones) — or both, with
   the shared Rust core.
2. **Start with a short design review of this plan, or go straight to P0.**
   The auditor session (`security-audit-playbook-13`) reviewed the earlier
   design docs.
3. **Licence:** a colleague is deciding it; the repository is private until
   then.

## Project rules that apply

- **Private repository.** Publish nothing from it externally (artifacts, PRs
  elsewhere, posts) without the owner's explicit consent. The licence is
  pending.
- **No personal device data** — the models, OS versions or patch levels of
  the owner's own phones — in the repository, commits or tests.
- **Secrets stay out of the repository and out of output:** `../.env` and
  `../gas-wallet.key`. Scan the diff before every commit.
- **On-chain actions that change rights** — a new root key, installing a
  permission — need the owner's explicit yes, every time.
- **Code:** Rust for the core (`signer/`). Native Swift and Kotlin only
  where the platform requires it.
- **Git:** commit and push only when asked; work on `master`; delete merged
  branches.
