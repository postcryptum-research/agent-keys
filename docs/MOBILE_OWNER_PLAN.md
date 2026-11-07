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
   - `cd mobile/owner-core && cargo test` — the shared core is outside the
     signer workspace, so the first command does not cover it
   - `cargo test -p agent-signer --features insecure-software-keys --test anvil_cli`
     — end-to-end tests on a local anvil, needs Foundry. It is the harness
     to reuse for the phone's signatures.
   - `cd contracts && forge test` — with forge 1.8.x, which ignores
     `odyssey`, run `forge test --evm-version osaka`
3. **Decisions are made** (see "Decisions" below): both platforms, and
   the design document is drafted —
   [`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md). The owner confirmed
   its decisions on 2026-10-28, and revision 2 answers the review and the
   audit response
   ([`audit/RESP-mobile-owner-design-2026-10-28.md`](audit/RESP-mobile-owner-design-2026-10-28.md)).
   Next: the owner's look at revision 2, then P0.

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
  (Android 11+) and `setUnlockedDeviceRequired(true)`. The design makes
  `BIOMETRIC_STRONG` alone the default and the device PIN a per-enrollment
  opt-in (decision D2 in [`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)).
- **Signing:** `Signature("NONEwithECDSA")` in a `BiometricPrompt`
  `CryptoObject` over the 32 bytes, which gives DER → `r ‖ s`; the CLI
  normalises to low-s.
- **The security level:** on Android 11 (API 30) the creation path tells
  StrongBox from TEE (`setIsStrongBoxBacked(true)` succeeded, or the retry
  after `StrongBoxUnavailableException`), and `KeyInfo.isInsideSecureHardware()`
  must be true; `KeyInfo.getSecurityLevel()` exists only from Android 12
  (API 31). The attestation's `keyMintSecurityLevel` is authoritative.
  Refuse software.
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
|    | *Status 2026-11-07:* Android, TEE-only phone — the key, the biometric-gated signature over the golden `userOpHash`, the attestation chain to Google's root and the committed vector `p256_android.json` (`mobile/android/README.md`, run record). The anvil root operation waits for P1's signing hook. | | |
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

## Decisions (owner, 2026-10-27)

1. **Platforms: both, iPhone and Android,** sharing one Rust core
   (decoding, hashing, display text, via `uniffi`) with two thin native
   apps (Swift, Kotlin).
2. **First deliverable: a design document, not code.** The next step is a
   detailed design spec, and no prototype until it is reviewed. It covers:
   - the request/response wire format and its versioning;
   - the QR payload and the LAN session (token lifetime, what the laptop
     serves, error cases);
   - the enrollment flow and the attestation evidence per platform (iOS
     approach to be proposed);
   - exactly what the screen shows for each owner operation, and what is
     refused;
   - the shared-core API (`uniffi`);
   - the CLI changes (key spec, commands);
   - the test plan (anvil harness first);
   - the threat model, in full.

   The spec goes to the auditor session (`security-audit-playbook-13`) for
   review, as the earlier design docs did, before P0 starts.
3. **Licence.** Existing code: MIT, with Apache-2.0 for `signer/`
   (README, #4). **The mobile owner apps and `owner-core`: not decided.**
   That is a separate study (app-store distribution terms, the
   dependencies' licences, the native apps), to be done before P5 and
   before any code of the apps is published. Draft:
   [`MOBILE_LICENSE_STUDY.md`](MOBILE_LICENSE_STUDY.md).
4. **Design decisions (2026-10-28):** D1–D9 and the v1/v2 split of
   [`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md) §12:
   - confirmed as proposed: D1 (the local network for v1, an air-gapped
     QR mode later), D3 (one key per account), D6 (no `initCode`), D7
     (iOS 16 / Android 11), D8 (a 0.005 ETH gas cap), D9 (a new
     `owner-core` crate);
   - D2: biometric only by default, and the device PIN as a
     per-enrollment opt-in. Condition, from the audit: because the
     biometric-only default leaves recovery as the only way out after a
     broken sensor or a changed biometric, **the recovery path must be
     robust and tested before the biometric-only default ships**. The
     condition is on the default, not on the PIN opt-in. What "robust and
     tested" means: [`RECOVERY_DRILL.md`](RECOVERY_DRILL.md);
   - D4: unknown root external calls refused by default; a per-enrollment
     expert mode, off by default, allows them with a second confirmation;
   - D5: App Attest on iOS, after the organisational study
     (`APP_ATTEST_ORG.md`, PR #6), before P3;
   - v1: build-embedded pins, the LAN only, handover decoded on a phone.
     v2, "the phone sees the chain": the on-chain Registry, codehash pins
     and on-chain root checks, as one feature.

## Project rules that apply

- **Private repository, for now.** Publish nothing from it externally
  (artifacts, PRs elsewhere, posts) without the owner's explicit consent.
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
