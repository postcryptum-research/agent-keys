# Mobile owner app — design specification

*Draft, 2026-10-27. Nothing here is built. It answers decision 2 of
[`MOBILE_OWNER_PLAN.md`](MOBILE_OWNER_PLAN.md): the spec that goes to
review before P0 starts. The nine design decisions in §12 were accepted as
proposed on 2026-10-27, for the owner to confirm in the review of this
document; the rest is open to challenge in that review too.*

Evidence marks, as elsewhere: **V** verified in this repository's code or at
the linked source; **I** inferred, to be confirmed in the phase named.

## 0. Scope

**In scope.** A phone holds the account's **owner** key in its secure
hardware and signs **root operations** that the laptop's `agent-signer`
builds: permission add, rotate, revoke; `owner add-recovery`;
`owner set-root` (away from the phone, e.g. to a new phone); and
`op send --root`. The phone decodes every operation, shows it, recomputes
its hash itself, and signs only after biometric verification.

**Out of scope for v1.**
- The agent key. It signs unattended, so it must not need a human or a
  phone (`KEY_POLICY.md`, premise 1).
- The recovery key. It stays a cold key file (`RESILIENCE.md`). A phone as
  a *second* recovery device is possible later with the same protocol.
- ERC-1271 messages and any digest chosen by the laptop. See §6.5.
- Account creation. Operations with a non-empty `initCode` are refused, so
  the phone takes over an existing account through `owner set-root` (§5.5).
- Distribution through app stores (P5).

**Unchanged.** No contract changes. The owner key is checked by the
deployed `P256Validator`, which takes exactly 64 bytes, `r ‖ s`, over the
EntryPoint v0.7 `userOpHash` (V, `contracts/src/P256Validator.sol`,
`kernel::root_signature`).

## 1. Components

```
laptop                                   phone
┌──────────────────────────────┐         ┌───────────────────────────────┐
│ agent-signer CLI             │         │ native app (Swift / Kotlin)   │
│  ├ builds the UserOperation  │  QR     │  ├ camera: scans the QR       │
│  ├ owner-core (Rust)         │ ──────▶ │  ├ HTTP client (LAN only)     │
│  ├ one-shot LAN session      │ ◀─────▶ │  ├ Secure Enclave / Keystore  │
│  └ verifies, then submits    │  HTTP   │  └ renders owner-core's view  │
└──────────────────────────────┘         │ owner-core (Rust, via uniffi) │
                                         │  parse · decode · hash · text │
                                         └───────────────────────────────┘
```

**`owner-core`** is one Rust crate compiled into both sides. It owns the
request format, the decoding of Kernel calls and the AgentPolicy mandate,
the `userOpHash` computation and the display text. The CLI and the phone
therefore cannot disagree about what an operation means. The native apps
only scan, fetch, sign in hardware and render a list of sections.

## 2. Flows

### 2.1 Enrollment (once per account)

1. On the laptop, `agent-signer key create --phone <label> --agent <config>`
   builds an **enrollment request** (§4.3): chain, EntryPoint, account, the
   deployment addresses and known tokens to pin, and a 32-byte challenge.
2. The CLI opens a LAN session (§3) and prints a QR in the terminal.
3. The phone scans it, fetches the request, checks it against the QR's
   commitment, and shows: the chain, the full account address, and the
   label.
4. The user confirms. The phone creates a **new** key for this account
   (§5.1) and returns the public key plus attestation evidence (§5).
5. The CLI verifies the evidence, prints the public key and its
   fingerprint, and writes the config snippet (§8.1).
6. The phone stores the enrollment record (§5.4). Nothing is on-chain yet.

### 2.2 Handover (once)

The **current** owner signs `owner set-root --validator <P256Validator>
--retire <P256Validator> --public-key <phone x,y>` (V: this exact sequence
is `tests/anvil_cli.rs::recovery_drill`). After it, the phone's key is root
and the old owner key signs nothing (AA24). §10, T2 covers checking the
result from a third device.

### 2.3 Signing a root operation

1. Any owner command whose config names a phone owner key builds the
   operation, estimates gas first (§8.3), then opens a LAN session and
   shows the QR.
2. The phone fetches the request, verifies the commitment, decodes the
   operation, recomputes `userOpHash`, and shows the review screen (§6).
3. The user approves. Biometric verification unlocks the key, and the
   hardware signs the 32-byte hash.
4. The phone posts the signature. The CLI checks that it verifies against
   `ownerPublicKey` over its own `userOpHash`, frames it as `r ‖ s`, and
   submits through `handleOps` or the bundler.

### 2.4 Health check

`agent-signer key check --phone <label>` proves the phone can still sign,
without any transaction. The digest is
`sha256("TPM_sign/v1/health" ‖ laptopNonce ‖ phoneNonce)`. The phone
contributes `phoneNonce`, so the laptop cannot choose the digest and cannot
use a health check to obtain a signature over a meaningful hash (§6.5).

## 3. Transport: QR, then the local network

### 3.1 Why this shape

- **No server, no cloud, no Bluetooth** (plan). The laptop serves one
  request on the LAN for one phone, then stops.
- **The QR is the trusted channel.** It travels from the laptop's screen to
  the phone's camera, which a network attacker cannot touch. The QR carries
  a SHA-256 **commitment** to the exact request bytes. The phone refuses
  any fetched request that does not match. Plain HTTP is then acceptable:
  a network attacker can only make the session fail.
- **Secrecy is not needed.** The request becomes public on-chain anyway,
  and a signature is public. Integrity comes from the commitment, and the
  laptop verifies every signature.

### 3.2 QR payload

A URI, kept short so the QR stays small (V2, about 25 × 25 modules,
scannable from a terminal):

```
tpmsign:1?u=http://192.168.1.23:49731/s/<token>&h=<commitment>
```

| Field | Content |
|---|---|
| `1` | protocol major version |
| `u` | session URL; the host must be a private, link-local or ULA address, else the phone refuses |
| `<token>` | 128 random bits, base64url (22 characters) |
| `h` | SHA-256 of the exact request bytes the URL serves, base64url (43 characters) |

The phone registers the `tpmsign:` scheme, but in-app scanning is the main
path, because a system camera may open the URI in another app.

### 3.3 The LAN session

| Aspect | Rule |
|---|---|
| Bind | one IPv4 address: the default-route interface, or `--listen <ip[:port]>`. Never `0.0.0.0` unless given explicitly |
| Port | random ephemeral, unless given |
| Lifetime | 120 s from the QR being shown (`--phone-timeout`), or until a valid response arrives |
| `GET /s/<token>` | returns the request bytes (`application/json`). Allowed again within the lifetime, so the phone can retry |
| `POST /s/<token>` | body = response (§4.2). The first well-formed response ends the session |
| Wrong token | `404`, compared in constant time; 20 wrong tokens end the session |
| After the end | every path returns `410`; the port closes |
| Body limits | request ≤ 64 KiB; response ≤ 4 KiB |

**CLI-side errors**, each with a plain message and a non-zero exit:
timeout, a refusal reported by the phone (with its reason), a malformed
response, a signature that does not verify, or a `userOpHash` mismatch.

### 3.4 Platform notes (I, confirmed in P1)

- **iOS** needs `NSLocalNetworkUsageDescription`, and the first fetch
  shows the system's local-network prompt. Plain HTTP to a local address
  needs `NSAllowsLocalNetworking` in App Transport Security.
- **Android** blocks cleartext HTTP by default (API 28+). The network
  security config permits it, and the app itself enforces the
  private-address rule from §3.2 before connecting.
- **Networks with client isolation** (guest Wi-Fi, some offices) block
  phone-to-laptop traffic. The fallback is the laptop joining the phone's
  hotspot. The air-gapped mode (§3.5) removes the problem.

### 3.5 Later: an air-gapped mode

The request format (§4) does not depend on the transport. A later version
can move the same request bytes over animated BC-UR QR codes (laptop →
phone) and return the response (about 200 bytes) as one static QR read by
the laptop's camera. The phone app then needs no network permission at all,
as Cake Wallet's Cupcake does ([`related/CUPCAKE.md`](related/CUPCAKE.md)),
but with a hardware-bound key. Cost: camera access and QR decoding in the
CLI, and no headless laptops. Decision D1: later, not in v1.

## 4. Wire format

JSON, UTF-8, exactly as served. The commitment covers the bytes, so there
is no canonicalization. Byte strings are `0x`-prefixed lowercase hex;
integers that can exceed 2^53 are decimal strings.

### 4.1 Sign request

```json
{
  "tpmSign": "sign-request",
  "version": 1,
  "expires": 1793026000,
  "chainId": "84532",
  "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  "userOp": {
    "sender": "0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628",
    "nonce": "4",
    "initCode": "0x",
    "callData": "0xe9ae5c53…",
    "accountGasLimits": "0x…",
    "preVerificationGas": "100000",
    "gasFees": "0x…",
    "paymasterAndData": "0x"
  },
  "laptop": {
    "userOpHash": "0x…",
    "command": "permission rotate",
    "labels": { "0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1": "demo counter" },
    "agentVersion": "0.1.0"
  }
}
```

- **`userOp`** is the packed v0.7 operation without its signature: exactly
  the fields the hash covers.
- **`laptop.*` is advisory.** The phone recomputes the hash and, if it
  differs from `laptop.userOpHash`, refuses (a bug or tampering). Labels
  are shown as "the laptop calls this …", never as facts (§6.3).
- **Unknown fields** are ignored and listed under "details". They cannot
  change what is signed: the hash comes only from `chainId`, `entryPoint`
  and `userOp`.
- **A version mismatch** is refused, with a message naming both versions.

### 4.2 Response

```json
{
  "tpmSign": "sign-response",
  "version": 1,
  "request": "<base64url SHA-256 of the request bytes>",
  "result": "signed",
  "userOpHash": "0x…",
  "signature": "0x<r ‖ s, 64 bytes, low-s>",
  "publicKey": { "x": "0x…", "y": "0x…" },
  "app": { "platform": "ios", "version": "0.1.0", "core": "0.1.0" }
}
```

On refusal: `"result": "refused"` and `"reason"`, one of `user`,
`unknown-account`, `wrong-chain`, `commitment`, `hash-mismatch`, `expired`,
`policy` (§6.4) or `version`, with optional free text. A refusal ends the
session like a signature does.

The core converts the platform's DER signature to `r ‖ s`, normalizes to
low-s (V: the CLI already requires it, `hw_signer::normalize_low_s`), and
verifies it against the enrolled key before posting.

### 4.3 Enrollment request and response

The request carries `"tpmSign": "enroll-request"`, `chainId`,
`entryPoint`, `account`, `label`, a 32-byte `challenge`, and `pin`: the
deployment addresses (`p256Validator`, `p256RecoveryValidator`,
`p256Signer`, `agentPolicy` and its superseded versions, `safeNonceAssert`,
`whitelistPaymaster`) and known tokens (`address`, `symbol`, `decimals`).

The response carries `publicKey`, the key's `securityLevel` as the phone
sees it, and `attestation`. On Android that is the certificate chain,
base64 DER. On iOS it is the App Attest object and key id (§5.3).

## 5. Keys, enrollment and attestation

### 5.1 One key per account

Each enrollment creates a fresh key, bound to that one (chain, EntryPoint,
account). A compromise or confusion about one account cannot reach
another. Rotation is per account, and the phone's list of accounts doubles
as its list of keys. (§12, D3.)

### 5.2 Android (Keystore)

Key parameters (V for the API names, plan "Verified platform facts"):

| Parameter | Value |
|---|---|
| Algorithm | EC `secp256r1`, `PURPOSE_SIGN` |
| Digests | `DIGEST_NONE` **and** `DIGEST_SHA256`, both set at creation so plan B (§11.1) needs no re-enrollment |
| Hardware | `setIsStrongBoxBacked(true)`; on `StrongBoxUnavailableException`, retry in the TEE. Refuse software |
| User verification | `setUserAuthenticationParameters(0, BIOMETRIC_STRONG)` — a check on every use, biometric only (D2) |
| | `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)` |
| Attestation | `setAttestationChallenge(sha256("TPM_sign/v1/enroll" ‖ requestCommitment))`; **no** device-ID attestation, so no serial numbers reach the laptop |

**Signing:** `Signature("NONEwithECDSA")` inside a `BiometricPrompt`
`CryptoObject`, over the 32-byte hash.

**What the laptop verifies** in the chain:
- the chain ends at a Google hardware attestation root;
- `attestationChallenge` equals the expected value;
- `attestationSecurityLevel` and `keyMintSecurityLevel` are both
  `StrongBox` or both `TrustedEnvironment`;
- the key is EC P-256, purpose sign, with `NONE` among its digests;
- user authentication is required, by biometric, on every use;
- `attestationApplicationId` names our package and signing-certificate
  digest;
- `rootOfTrust`: `deviceLocked = true`. A `verifiedBootState` other than
  `Verified` is shown as a warning, not refused. A re-locked custom OS
  such as GrapheneOS reports `SelfSigned`.

Revocation: Google publishes an attestation revocation list. The CLI checks
it when online and says so in the result. Leaked attestation keys have
existed, so attestation is evidence, not proof (§10, T15).

### 5.3 iOS (Secure Enclave)

**Key:** `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`. The
access control is `.privateKeyUsage` plus `.biometryCurrentSet`. The key is
stored in the app's keychain as `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`,
so removing the passcode makes it unusable. A real app has keychain
entitlements, unlike the CLI's Mac shim, which is why that shim uses
CryptoKit blobs instead (V, `SecureEnclaveShim.swift`).

**Signing:** `SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256,
hash)` takes the 32 bytes as the digest (V: plan; the Mac backend does the
same through CryptoKit). The output is DER.

**Attestation (D5).** iOS has no per-key attestation, so bind our key to
an **App Attest** attestation:

1. Create the Secure Enclave signing key `K`.
2. `DCAppAttestService.generateKey()`, then
   `attestKey(keyId, clientDataHash: sha256("TPM_sign/v1/enroll" ‖
   requestCommitment ‖ K.x ‖ K.y))`.
3. The laptop verifies the attestation object as Apple specifies (V,
   [Apple: validating apps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)):
   - the certificate chain ends at the App Attestation root;
   - `nonce = sha256(authData ‖ clientDataHash)` matches the certificate
     extension;
   - the RP ID hash is `sha256(<team id>.<bundle id>)`;
   - the counter is 0;
   - `aaguid` is `appattest` (production) or `appattestdevelop`.

**What it proves:** a genuine instance of our app, on genuine Apple
hardware, vouched for `K`'s public key during this enrollment. It does
**not** prove that `K` lives in the Secure Enclave. That follows only from
the app's code, which creates keys nowhere else. So iOS evidence is as
strong as trust in the shipped build (§10, T6).

**Network (I, confirmed in P3):** attestation is believed to contact
Apple's servers, so the phone needs internet once, at enrollment. If that
is unacceptable, the alternative is no attestation, plus the post-handover
check in T2.

### 5.4 What the phone stores per enrollment

The label; chain id; EntryPoint; account; the key reference (Keystore alias
or keychain item); the public key; the pinned deployment addresses and
tokens; the enrollment time; and a local history of signed hashes with
their summaries. None of this is secret. Losing it only loses the key
reference, and recovery covers that.

### 5.5 Why no `initCode`

A counterfactual account's address depends on its owner key (the root
validator is in `initData`), so the phone cannot be enrolled for an address
before its own key exists. v1 enrolls existing accounts only, then hands
over. A later version can enroll first and bind the account at creation.

## 6. What the phone shows, and what it refuses

### 6.1 Pipeline (one parse)

`owner-core` parses the request **once** into a `Review` object (§7). The
display text, the verdict and the digest to sign all come from that one
object, so the native code never sees a digest before the user approves.
There is no second parser whose result could differ from what is shown.

### 6.2 Checks before anything is shown

Failing any check means a refusal screen with its reason. No signing button
is offered.

1. The commitment matches.
2. The version is supported, and the request has not expired. The phone's
   clock gets 5 minutes of tolerance, because offline phones drift.
3. `(chainId, entryPoint, sender)` matches an enrollment.
4. `initCode` is empty.
5. The nonce key (the upper 192 bits of `nonce`) is the **root** key, 0
   (V, `kernel::root_nonce_key`). The phone signs only for the root path.
6. The recomputed `userOpHash` equals `laptop.userOpHash`.

### 6.3 Decoding the calldata

**Top level** — one of:
- Kernel `execute(mode, data)` with call type `0x00` (single) or `0x01`
  (batch) and exec type `0x00` (revert on failure). Delegatecall (`0xff`),
  try-mode and any other mode are **refused**.
- A direct Kernel admin call: `uninstallValidation`. This is how
  `permission revoke` is sent (V, `chain.rs`).

**Each inner call** whose target is the account itself is decoded as a
Kernel admin call:

| Call | Shown as |
|---|---|
| `installValidations` of a **permission** id (type `0x02`) | "Install agent permission `<id>`", with the full mandate: signer module (pinned `P256Signer`?), agent key fingerprint, policy module (pinned `AgentPolicy`, or "superseded version"), every allow entry (target, selector, and the name where known), value cap, budget, validity window, token caps and x402 flags |
| `installValidations` of a **validator** (type `0x01`) | "Install validator `<address>` with key `<fingerprint>`". For the pinned recovery validator: "Install a recovery key — **it will be able to take over this account**" |
| `grantAccess(vId, selector, allow)` | "Allow `<vId>` to call `<selector name>`". For `changeRootValidator`: "**may take over this account**" |
| `changeRootValidator(...)` | "**Hand control of this account to** validator `<address>`" |
| `uninstallValidation(vId, …)` | "Remove permission `<id>`" or "Remove validator `<address>`". If that validator holds this phone's key: "**this phone will no longer control the account**" |
| any other self-call | **refused** (v1) |

An inner call to **another** target is an external call: the target, the
value, and the decoded function where known (ERC-20 `transfer` and
`approve` with pinned decimals, the Safe-nonce assertion followed by Safe
`execTransaction`). Anything else is shown as "unknown call — refuse
recommended", with the raw selector and data (§12, D4).

**Rules for the text:**
- **Addresses in full**, checksummed, never truncated. Truncation invites
  vanity-address poisoning.
- **Key fingerprints:** 80 bits of `sha256(x ‖ y)`, shown as four groups
  of five base32 characters. 32 bits can be ground; 80 bits cannot,
  practically. The CLI prints the same fingerprint, for comparison across
  devices.
- **Amounts:** ETH from wei; tokens only with pinned decimals, otherwise as
  raw units plus "unknown token".
- **Times:** local date and time plus UTC, with the raw value under
  details.
- **Labels:** pinned names (from enrollment) are shown plainly. Labels from
  `laptop.labels` are shown in quotes, as "the laptop calls this", in a
  distinct style. A label never replaces an address.
- **Text:** labels are restricted to printable ASCII plus spaces, at most
  32 characters. Anything else is refused, which closes homoglyph and
  bidirectional-text tricks.

### 6.4 Cost and sponsorship

- The phone shows the **maximum gas cost**:
  `(verificationGasLimit + callGasLimit + preVerificationGas +
  paymaster gas limits) × maxFeePerGas`.
- It **refuses** above a per-enrollment cap. The default is 0.005 ETH, and
  the user can change it on the phone (§12, D8). This stops a compromised
  laptop from draining the account through the gas prefund.
- A paymaster is shown by address. One that is not pinned gets a warning.

### 6.5 What is never signed

- **A digest supplied by the laptop.** The protocol has no message for it.
  A laptop-chosen 32 bytes could be the hash of a malicious operation, an
  ERC-1271 message (Kernel wraps them, `kernel::kernel_wrapped_hash`) or a
  permit. Health checks use a digest the phone co-randomizes (§2.4).
- **Operations for an unenrolled account, chain or EntryPoint.**
- **Non-root nonce keys,** delegatecall, unknown self-calls, or a non-empty
  `initCode`.

### 6.6 Approving

- The review screen has one "Sign" action, enabled only after scrolling
  through every section. Then comes the system biometric prompt.
- Calls marked **bold** in §6.3 (taking over, removing this phone's
  control, installing a recovery key) need a second confirmation that
  repeats the effect in plain words.

## 7. `owner-core` and its `uniffi` interface

### 7.1 Crate layout (§12, D9)

- **New crate `signer/crates/owner-core`.** Dependencies: `alloy-primitives`,
  `alloy-sol-types`, `sha2`, `p256`, `serde`. No network, no async, no
  `alloy` providers, so it builds for `aarch64-apple-ios`,
  `aarch64-linux-android` and `armv7-linux-androideabi`.
- **Moved from `agent-signer/src/kernel.rs`:** the pure encode and decode
  functions (validation ids, nonce keys, `decode_execute`,
  `PolicyParams` and `permission_data`, plus decoders the CLI lacks for
  `installValidations` and `grantAccess`). `agent-signer` depends on
  `owner-core` and keeps its existing tests. This is a refactor of the
  CLI, not a change of behaviour; its unit tests and the anvil suite
  guard it.
- **New in the crate:** `user_op_hash(op, entry_point, chain_id)` computed
  locally (V for the formula, plan), the request and response types, the
  `Review` builder, display text and fingerprints.

### 7.2 Exported API (proc-macro `uniffi`, sketch)

```rust
#[uniffi::export] fn parse_qr(uri: String) -> Result<QrPayload, CoreError>;
#[uniffi::export] fn open_enrollment(bytes: Vec<u8>, commitment: String, now: u64)
    -> Result<Arc<EnrollReview>, CoreError>;
#[uniffi::export] fn open_request(bytes: Vec<u8>, commitment: String, now: u64,
    enrollments: Vec<Enrollment>) -> Result<Arc<Review>, CoreError>;

#[uniffi::export] impl Review {
    fn verdict(&self) -> Verdict;            // Sign | SignWithWarnings | Refuse(reason)
    fn sections(&self) -> Vec<Section>;      // title, rows (label, value, emphasis)
    fn needs_second_confirmation(&self) -> bool;
    fn digest_to_sign(&self) -> Result<Vec<u8>, CoreError>; // Err if verdict is Refuse
    fn finish(&self, der_signature: Vec<u8>, public_key: Vec<u8>, app: AppInfo)
        -> Result<Vec<u8>, CoreError>;      // DER → r‖s, low-s, self-verify, response JSON
    fn refuse(&self, reason: RefuseReason) -> Vec<u8>;
}
#[uniffi::export] fn health_digest(laptop_nonce: Vec<u8>) -> HealthChallenge;
#[uniffi::export] fn fingerprint(public_key: Vec<u8>) -> String;
```

The native side renders `sections()` generically. Every word on the review
screen comes from the core, in English for v1, with structured rows so
translation can follow.

### 7.3 Builds

- **iOS:** an `xcframework` (device plus simulator), and the generated
  Swift.
- **Android:** `cargo-ndk` libraries for `arm64-v8a` and `armeabi-v7a`,
  plus the generated Kotlin (JNA).
- Both are pinned to the same `owner-core` version, which the response
  reports.

## 8. CLI changes

### 8.1 Key spec and config

```json
"owner": { "phone": { "label": "owner-phone", "platform": "android",
                      "attestation": "strongbox", "fingerprint": "ABCDE-FGHIJ-KLMNO-PQRST" } },
"ownerPublicKey": { "x": "0x…", "y": "0x…" }
```

- **New variant `KeySpec::Phone`,** accepted for the **owner** role only;
  refused for the agent with an explanation. Recovery may come later.
- **`ownerPublicKey` is required** with a phone owner. The CLI checks that
  the fingerprint matches it.

### 8.2 Commands

| Command | Change |
|---|---|
| `key create --phone <label> --agent <cfg>` | the enrollment session (§2.1); verifies attestation, prints the public key, fingerprint and config snippet; `--allow-no-attestation` for iOS without App Attest |
| `key check --phone <label>` | the health check (§2.4) |
| `key show --phone <label>` | prints the configured public key and fingerprint (no session) |
| every owner command | unchanged syntax; with a phone owner they open a session. New flags `--listen`, `--phone-timeout` |

### 8.3 Signing path (`chain.rs`)

1. **The trait gains a method with a default.**
   `HardwareSigner::sign_user_op(&self, ctx: &UserOpContext) -> Result<Signature>`,
   where the default calls `sign_digest(ctx.hash)`. Every existing backend
   keeps working unchanged. `PhoneSigner` implements `sign_user_op` and
   returns an error from `sign_digest` ("a phone key signs operations, not
   digests").
2. **The hash is computed locally.** The CLI computes `userOpHash` with
   `owner-core`, compares it with `EntryPoint.getUserOpHash`, and stops on
   any difference. That check doubles as a test of the core against the
   chain on every run.
3. **One signature with a bundler.** Today the hardware signs twice when a
   bundler is used, before and after gas estimation (V, `chain.rs`). With
   a phone that would mean two biometric prompts. The CLI estimates with a
   placeholder signature, then asks the phone once. Bundlers accept a
   failing signature during estimation (I, confirmed in P1 against the
   public bundler used before).
4. **After the phone answers:** verify against `ownerPublicKey`, frame
   with `root_signature`, submit.

### 8.4 Terminal QR

The CLI renders with the `qrcode` crate (half-block characters), and adds
two lines: the URL in text, for a manual fallback, and the request's
fingerprint, which the phone also shows.

## 9. Test plan

**Anvil first, as the plan asks.**

1. **`owner-core` unit tests:**
   - `user_op_hash` against reference values computed with `cast`;
   - golden files: every owner command's request (from the CLI, with a
     fixed account) and its expected `sections()` text;
   - DER → `r ‖ s` → low-s round trips;
   - fingerprints.
2. **Tamper tests.** Flip every byte of a golden request. Each flip must
   either be refused (commitment, parse or a §6.2 check) or change the
   displayed text or the hash. No byte may change the hash without
   changing the text.
3. **Fuzzing** (`cargo-fuzz`) of `open_request` and the calldata decoders,
   which are the security boundary. The invariants: no panic; and whenever
   the verdict is not Refuse, the displayed calls re-encode to the signed
   `callData`.
4. **A phone simulator.** A test binary that speaks the phone side of the
   protocol with `owner-core` and a software key, built only with
   `insecure-software-keys` (`KEY_POLICY.md`). New `anvil_cli.rs` cases:
   - enrollment, then `owner set-root` to the simulated phone key, then a
     root operation signed through the LAN session;
   - permission add, rotate and revoke through the phone;
   - refusals: wrong account, wrong chain, an expired request, a reused
     token, a wrong commitment, a non-root nonce key, delegatecall, a
     gas-cap breach;
   - a malicious laptop: the request served differs from the committed
     one, and the phone refuses;
   - the health check;
   - with a bundler: exactly one signature request per operation.
5. **Attestation verification tests** on synthetic chains, built by the
   test itself with its own root, plus Google's and Apple's published
   sample objects where licensing allows. No attestation from the owner's
   devices goes into the repository (plan rule: no personal device data).
6. **Device tests (P0, P4).** A real phone signs the hash of a golden
   request. The test verifies it off-chain, then on anvil through a root
   operation. The result is recorded as pasted output, without device
   models or OS versions.
7. **Base Sepolia, with the owner's explicit yes each time.** Handover to
   the phone, one root operation, then the recovery drill back to a
   non-phone key.

Note for the "Start here" step in the plan: with forge 1.8.x, `odyssey` in
`foundry.toml` is ignored, so `forge test` must be run as
`forge test --evm-version osaka`. The anvil harness already copes with
both (V, `anvil_cli.rs`).

## 10. Threat model

**Assets:** root control of the account (everything the account holds); the
agent's mandate; the owner's ability to recover.

**Trust boundaries:** the laptop; the LAN; the QR's optical channel; the
phone OS; our app and its build; the phone's secure hardware; the chain.

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | **The laptop is compromised** and requests a malicious operation | the phone decodes, recomputes the hash and shows the real effect; laptop labels are marked as such; addresses are shown in full; gas cap | a user who approves without reading. The bold second confirmation targets the dangerous cases |
| T2 | **The laptop is compromised during enrollment or handover** and substitutes its own key in `set-root` (signed blind by the old owner) | the phone shows its fingerprint; after handover, the user reads `P256Validator.publicKeys(account)` on a block explorer from a **third** device and compares | handover trust: do it from a clean machine, and check |
| T3 | **A LAN attacker** swaps the request or the response | QR commitment; the laptop verifies the signature against its own hash | denial of service only |
| T4 | **A foreign QR** (another screen, a poster) | unenrolled accounts are refused; for an enrolled one, the normal review applies | as T1 |
| T5 | **Malware on the phone** (user level) | Keystore and keychain keys are bound to our app; use needs biometrics enforced by hardware | a rooted or jailbroken phone. Treat a phone that cannot pass attestation as untrusted |
| T6 | **Our app itself is malicious or compromised** (supply chain, a bad update) | open source; minimal dependencies; release signing; the Android attestation names our signing certificate | it could show one operation and sign another. Mitigation by reproducible Android builds (P5); none on iOS beyond App Store review. The largest residual risk; say so in user docs |
| T7 | **A thief with the phone** | biometric only (D2); the key is invalidated by a new biometric enrollment | with a PIN fallback, a thief who saw the PIN could sign. Hence D2 |
| T8 | **Coercion** | out of scope | keep the recovery key with someone else, or in another place |
| T9 | **A biometric change or a reset** invalidates the key | expected, correct behaviour | availability: recovery is mandatory (`RESILIENCE.md`), stated at enrollment |
| T10 | **A lost phone** | the key is not extractable; recovery | as T9 |
| T11 | **Gas griefing** | the cost cap (§6.4) | up to the cap per approved operation |
| T12 | **Replay across chain, EntryPoint or account** | all three are inside `userOpHash`, and the phone pins them | none |
| T13 | **A signature over a chosen digest** (ERC-1271, permits) | no such message exists in the protocol; the health digest is co-randomized | none |
| T14 | **Downgrade** to an old protocol or app | version field; the CLI may require a minimum app and core version | none |
| T15 | **Forged attestation** (leaked attestation keys) | revocation list; attestation treated as evidence | a determined attacker with a leaked key can fake "StrongBox". It only matters if they also control enrollment |
| T16 | **Display confusion** (homoglyphs, bidirectional text, long labels) | ASCII-only labels; full addresses; addresses never replaced by labels | none known |
| T17 | **Removal of `DIGEST_NONE`** from Android | plan B (§11.1) | needs one `set-root` to a WebAuthn validator when it happens |
| T18 | **The phone's clock** | 5 minutes of tolerance; raw timestamps under details | a wrong clock misstates "valid until" relative to now; the dates themselves stay correct |

## 11. Risks and plan B

### 11.1 Android `DIGEST_NONE` is deprecated

AOSP says of ECDSA "No digest (deprecated, will be removed in the future)"
(V, [AOSP Keystore features](https://source.android.com/docs/security/features/keystore/features)).
It is mandatory today, but it could disappear in a future Android.

**Plan B, without new contracts:** sign in a WebAuthn envelope. The phone
builds `authenticatorData` (with the user-verified flag set) and
`clientDataJSON` with `challenge = base64url(userOpHash)`, then signs
`authenticatorData ‖ sha256(clientDataJSON)` with `SHA256withECDSA`, a
supported mode. ZeroDev's WebAuthn validator, already deployed on Base,
verifies exactly that format. It requires user verification and does not
check the rpId (V for the latter two, `PHONE_OWNER.md`). Switching means
one `set-root` to that validator with the same key. The key was created
with `DIGEST_SHA256` too (§5.2), so no re-enrollment is needed. That the
validator accepts a self-built envelope: I, checked in P0 on anvil.

### 11.2 Other risks

- **iOS attestation is weaker than Android's** (§5.3). Accept it and say
  so, or skip attestation on iOS and rely on T2's check.
- **App store review** may question an app that signs for crypto accounts
  with no backend. TestFlight and APK distribution first (P5).
- **Minimum OS versions** (I): iOS 16 and Android 11 (API 30, needed for
  `setUserAuthenticationParameters`). That excludes some "old phones",
  which the business case mentions. §12, D7.
- **Not all phones have StrongBox.** The TEE is accepted and shown as such
  in the CLI output; the deployer decides.

## 12. Decisions (accepted 2026-10-27, for the owner to confirm)

Every proposal below was accepted as it stands on 2026-10-27. The owner
confirms or changes them in the review of this document.

| # | Question | Decision |
|---|---|---|
| D1 | Transport for v1: LAN with QR commitment (the plan's), or QR-only air-gapped | **LAN for v1**, request format transport-independent, air-gapped mode later (§3.5) |
| D2 | User verification: biometric or device PIN (the plan says `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL`), or biometric only | **biometric only, invalidated on a new biometric enrollment** (T7). Cost: a broken sensor or a changed face means recovery |
| D3 | One key per account, or one per phone | **one per account** (§5.1) |
| D4 | Unknown external calls in `op send --root`: refuse, or warn | **warn and require the second confirmation**; `op send --root` exists to call arbitrary targets |
| D5 | iOS evidence: App Attest bound to the key (needs Apple's servers once), or none | **App Attest**, with `--allow-no-attestation` for users who refuse the network |
| D6 | Operations with `initCode` | **refused in v1** (§5.5) |
| D7 | Minimum OS | **iOS 16, Android 11** |
| D8 | Default gas cap | **0.005 ETH per operation**, adjustable per enrollment on the phone |
| D9 | Crate split | **new `owner-core` crate**, with pure Kernel encoding moved out of `agent-signer` |

## 13. Mapping to the phases

| Phase | From this spec |
|---|---|
| P0 spike | §5.2 or §5.3 key creation and signing on one platform; a golden request's hash signed and verified on anvil; plan B's envelope checked against the WebAuthn validator on anvil |
| P1 enrollment + blind signing | §3, §4, §8 (the session, the key spec, the trait method, single signing with a bundler); simulator tests in §9.4; the display may still be minimal |
| P2 decode + display | §6 and §7 in full; golden, tamper and fuzz tests |
| P3 attestation | §5.2 verification, §5.3 App Attest, the revocation check |
| P4 second platform | P0–P2 on the other OS, with the same `owner-core` |
| P5 distribution | TestFlight and APK, reproducible Android builds, user documentation on T6 and recovery |
