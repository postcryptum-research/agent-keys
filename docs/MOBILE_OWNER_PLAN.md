# Mobile owner app — development plan

*Hand-off document of 2026-10-27, kept current by the status paragraphs
under "Phases": P0–P2 are done, P3 is done for Android, and P4 passes on an
iPhone. Read this first if you are picking up the phone work.*

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
   - `cd contracts && forge test --evm-version osaka` (forge 1.8 or later)
3. **Decisions are made** (see "Decisions" below): both platforms, and
   the design document is drafted —
   [`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md). The owner confirmed
   its decisions on 2026-10-28, and revision 2 answers the review and the
   audit response
   ([`audit/RESP-mobile-owner-design-2026-10-28.md`](audit/RESP-mobile-owner-design-2026-10-28.md)).
   Next: see the status paragraphs under "Phases" (open: the Base Sepolia
   run of P1, iOS attestation, P5).

## What already exists and is reused unchanged

**On-chain: nothing changes.** The owner key is a P-256 key checked by
`P256Validator` (`contracts/src/P256Validator.sol`, Base Sepolia
`0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63`). It expects exactly 64
bytes, `r ‖ s` over the 32-byte `userOpHash`. The phone only has to produce
that.

**What the phone signs:** the EntryPoint v0.7 `userOpHash`, which is
`keccak256(abi.encode(keccak256(pack(op)), entryPoint, chainId))`. The
phone must sign the raw 32-byte digest, without hashing it again.

**Making the phone the owner** is one root operation, signed by the current
owner: `owner set-root --validator <P256Validator> --retire <P256Validator>
--public-key <x>,<y> --to-phone <label>`.
- `--retire` matters here. Re-pointing root at an already installed
  validator keeps its old key; `--retire` uninstalls it first.
- The handover to a phone is exercised in
  `tests/anvil_cli.rs::phone_is_enrolled_then_takes_over_root`;
  `recovery_drill` exercises the same `--retire` flow to a key that is not
  a phone's (`--as-recovery --not-a-phone --new-key`).

**Rust code to share with the phone:**
- `mobile/owner-core/src/kernel.rs` (moved there from `agent-signer`):
  Kernel calldata, nonce keys, hashes; `decode_execute` decodes `execute`
  calldata.
- The AgentPolicy install-data encoding (`PolicyParams`, in the same file).
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

*The proposal of 2026-10-27. As built it differs in details; see
[`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md) §3–§4 and the status
paragraphs under "Phases".*

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

P0 status (2026-11-07, PR #18): run on a TEE-only Android phone — the key
with §5.2's parameters, the biometric-gated signature over the golden
`userOpHash`, the attestation chain to Google's root, and the committed
vector `contracts/test/vectors/p256_android.json` (run record in
`mobile/android/README.md`). **P0 closed on 2026-11-11:** with P1's signing
hook, the phone signed a real root operation on a local anvil through the
CLI (`mobile/android/README.md`, "P1 run record").

P1 status (2026-11-11): the QR → LAN loop works with the real CLI and the
real phone — `owner-core` carries the wire format and the checks, the CLI
has the `phone` owner key, the one-shot LAN session and
`HardwareSigner::sign_user_op`, the app scans, checks the commitment and
signs behind the fingerprint (blind: it signs the laptop's `userOpHash`
after checking the request's shape; decoding and recomputing on the phone
is P2). The enrollment session is in: `key create --phone <label> --agent
<cfg>` (design §2.1, §4.3) asks the phone for a new key per account, with
the attestation challenge bound to the request, and prints the key, its
fingerprint and the config snippet. An enrollment answer is the one
message nothing authenticates until P3, so the owner types at least the
first two groups of the fingerprint from the phone's screen (once per
enrollment; two because a host in the path can read the phone's key from
its cleartext answer and grind a one-group match within a session;
`--phone-fingerprint` for scripts; superseded in P3, see below) and an answer with another key is rejected
while the session waits for the phone's. P3 retires the prompt: the
attestation with the bound challenge then authenticates the answer. (That
is not how P3 went. Today the answer is authenticated by the secret in the
QR, and the CLI still asks for the fingerprint by default;
`--phone-skip-fingerprint` relies on the secret alone. See P3, slice 1.) The
config's `fingerprint` is checked against its `publicKey` before any
session, and `owner set-root --expect-fingerprint` refuses a handover to a
key the owner did not see. The session itself answers 400 to a bad POST
and keeps waiting, reads the body under the session's deadline, and
refuses to run without a network route.
What P1 still lacks: the attestation chain the phone returns is stored, not
verified — that is P3, and until then the security tier is the phone's own
word; the phone health check (design §2.4); and the Base Sepolia run with
the owner's yes. Tests: the anvil cases `phone_owner_signs_a_root_operation`
(a simulated phone: sign, a wrong signature, a refusal, the agent-role
refusal, a wrong config fingerprint) and
`phone_is_enrolled_then_takes_over_root` (enrollment refused, without
evidence, accepted; an intruder's answer rejected and the phone's taken; the
handover with the fingerprint check and an off-curve key refused; a root
operation through the session; the old key refused), and
the ignored real-device case `phone_owner_real_device` (enrollment, handover,
a phone-signed operation).

P2 status (2026-11-12, slice 1): the review lives in `owner-core`
(`review.rs`, design §6): one parse of a sign request into a `Review` — the
§6.2 checks (commitment, version and expiry with the 5-minute tolerance,
the enrollment match, no `initCode`, the root nonce key, the recomputed
hash), the decoders for every call the CLI emits today (execute single and
batch with delegatecall and other modes refused, `installValidations` of a
permission with its full mandate or of a validator, `grantAccess`,
`changeRootValidator`, `uninstallValidation`, the demo counter, ERC-20
`transfer` and `approve` in raw units, plain value transfers), the bold
effects that need the second confirmation, unknown external calls refused
unless expert mode, the maximum gas cost against the enrollment's cap and
the no-charge paymaster rule, every hash-covered field under details, and
the label rules. The facts (names, paymasters, recovery validators) come
from the caller for now; the build-embedded table is slice 3. Decoding is
strict: a call whose re-encoding does not reproduce its bytes, a permission
whose pass flags are not zero (Kernel would skip the policy or the
signature), a hook, hook data or deinit data, a non-canonical ERC-20
address word — all refused, because the screen cannot show what they do;
`increment()` is recognised on the demo counter only, and a policy or
signer module the build cannot read refuses the install unless expert
mode. Tests: the §9.2 tamper test over a batch that exercises every
decoder (every field and every calldata byte, two flips each, either
changes the screen *without its hash row* or is refused; both outcomes
counted), the hidden-field cases from the review of PR #30, the §6.2 and
§6.5 cases, the admin calls. The CLI prints the same review on the laptop before
the QR, so the owner compares screens and a refusal is known before the
phone is asked; the anvil phone case asserts it on a real request.
Slice 2 (2026-11-12): `owner-core` runs on the phone — `src/ffi.rs` behind
`--features ffi` is the §7.2 surface, `mobile/android/build-core.sh`
builds the arm64 library with `cargo-ndk` and the Kotlin bindings with
`uniffi`, and the app's button 3 renders the review from one parse, asks
the second confirmation for bold effects, signs the recomputed hash and
lets the core build the response (DER → r‖s, low-s, self-verified). Blind
signing is gone. Where the build has no facts the phone's review emphasises
what it cannot classify (a key on an unknown validator, every validator
removal) and refuses a permission whose modules it cannot read.
Sepolia (2026-11-24): the build knows a second chain, 11155111, from
`contracts/deployments/11155111.json`: the policy that holds a budget per
period and venues, CoW Swap's venue by its decoder's address and code hash
(with the settlement and the vault relayer named), and USDC and WETH there.
A trading mandate is readable on that chain only; an app has to be rebuilt
to know it.
Slice 3 (2026-11-13): the build knows the project's contracts.
`owner-core/src/facts.rs` embeds the canonical
`contracts/deployments/84532.json` (parsed in `build.rs`, so a broken file
fails the build) and a token table (USDC on Base Sepolia: decimals and
EIP-712 domain, read from the chain). The phone and the laptop's preview
both run `open_request_with_build_facts`: names are "verified in this
build", superseded versions are named as such and are not readable
modules, only the canonical no-charge paymaster sponsors, known tokens are
shown in their units, and a mandate whose x402 domain is not the known
token's own is refused. A paymaster that only a variant file names (such
as `whitelistPaymasterV2` of `84532.enclave.json`) is not a fact, so the
phone refuses operations it sponsors. The laptop's pins
(§4.3) travel in the enrollment request for addresses the build does not
know; the phone keeps them as unverified labels, reports the ones its
build names itself or whose label is a name the build reserves, and never
lets a pin change a verdict or an emphasis. Two rules were tightened in
review, because with names on the screen a plain row reads as safe: a key
installed on **any** validator is an effect, and a `grantAccess` is plain
only for a permission's `execute` or when it takes access away; a
validator's `execute` or `changeRootValidator` is an effect, and every
other grant is refused unless expert mode is on, where it is an effect
with a warning (neither app can turn expert mode on yet).
On the device the review is rendered from the core's sections, and Sign is
enabled only at the end of the scroll (§6.6). A development build with
`test-chains` knows the CLI's anvil chain, where the harness installs the
same code at the same addresses; it shows `+test-chains` in its version.
The simulated phone in the anvil suite runs the same review, so the suite
covers a permission install through the phone (the mandate in the
laptop's preview) and an unknown call refused by the phone. P2's "done
when" is met: the phone shows a decoded mandate, recomputes the hash, and
a tampered request is visibly different or refused. Not done in P2 and
moved on: the enrollment options on the phone (gas cap, expert mode,
device PIN — §5.4), the Safe `execTransaction` decoder named in §6.3, and
the phone learning which validator holds its key (v2, §14).

P3 status (2026-11-13, slice 1): every answer of a session is now
authenticated. The QR carries a 128-bit secret next to the commitment
(`tpmsign:1?u=…&h=…&k=…`); it reaches the phone through the camera and is
never sent over the network, and the CLI prints the URI without it. The
phone puts `HMAC-SHA256(k, body)` on every POST (`X-TpmSign-Mac`), and the
laptop ignores an answer without it — enrollment answers, sign responses
and refusals alike — so a host on the network can no longer answer an
enrollment with its own key or stop a session with a forged refusal. The
laptop's acceptance is authenticated too: its `200` carries a confirmation
MAC, and the app keeps a new key only on that, since a bare `200` can come
from any host in the path. (Since issue #38, below, the apps keep the key
either way and mark it confirmed only on that.) What is left to a network attacker is denial of
service. This, not attestation, is what answers "is it the owner's phone":
an attestation shows that a genuine device running our app made the key
for this request, and anyone can hold such a device. The owner's decision
on the fingerprint: **the CLI still asks for it at enrollment by default**
(two groups at least), because the secret assumes nobody else read the QR
and an enrollment is followed by a root handover; `--phone-skip-fingerprint`
relies on the secret alone, and `--phone-fingerprint` serves scripts.
`--phone-fingerprint-cmd` is gone. The protocol version stays `1` while
the QR and the answers change incompatibly: nothing has been distributed,
and version 1 is frozen only at the first distributed build. Tests: the
MACs against RFC 4231 and against each other; in the anvil suite an
intruder without the secret posts its own key first, is ignored and gets
no confirmation, a forged refusal does not stop a signature, the secret is
not in the printed text, and an intruder with the secret is rejected by
the fingerprint.

P3 status (2026-11-13, slice 2): the laptop verifies the Android key
attestation at enrollment (`agent-signer/src/attestation.rs`, design §5.2).
The chain must end at one of Google's two roots, embedded as published and
matched by public key; every certificate valid now and signed by the next;
every issuer a CA and only the key's certificate carrying the record, so
an attested key cannot issue attestations. The record must be made for
this request (the challenge bound to its commitment), for the key the
answer names, generated in the hardware, EC P-256, sign only, with
`DIGEST_NONE`, usable only after a biometric check on every use (or with
the device PIN exactly when the enrollment chose that), both security
levels StrongBox or both TEE, the bootloader locked; the app named by
package, minimum version and signing-certificate digest. A boot state of
SelfSigned is a warning that says the app's identity then carries no
weight; Unverified is refused unless `--allow-unverified-boot` and then
carries the same warning; Failed is refused. The state is recorded in the
config (`bootState`), and a build to distribute cannot be made in the
development posture (issue #35, design §5.2). Google's revocation list is fetched,
the result and the config say whether it was checked, and
`--require-revocation-check` refuses when it cannot be. `--require-strongbox` decides on
the attested level; `--android-app-digest` accepts a developer's own build
until the project pins a release certificate; the config's phone spec
records `attestation`, `platform` and `deviceCredential`. A failure ends
the session with its reason, and the phone discards the key. (Today the
phone keeps it as unconfirmed, and the next enrollment of that account
replaces it: issue #38, below.) Evidence
from a platform other than Android is refused until its verifier exists.
Signatures
are checked by `aws-lc-rs`, already in the tree, over bytes parsed by a
strict DER reader of our own (`der.rs`), needed because the record's tags
go beyond what the `der` crate holds. Tests build their own chains with a
P-384 and an RSA root and vary every rule, including the forged
certificate signed by an attested key; Google's two roots verify their own
signatures; an ignored test runs a real enrollment's evidence from a
directory outside the repository, and one such run passed: five
certificates to the remote-provisioning root, tier TEE. Not done: iOS
(App Attest, design §5.3), which waits for the organization account.

P4 status (2026-11-13, slice 1): the iPhone app exists (`mobile/ios`,
SwiftUI on the same `owner-core` through its Swift bindings) and passes
the loop **in the iOS simulator**, against the real CLI on a local anvil:
enrollment, handover, an agent permission reviewed and signed in the app,
and the app signing a change of the root key itself, with the second
confirmation. One command runs it (`mobile/ios/run-simulator.sh`); a UI
test stands in for the owner and checks the screen: every row the core
produced is shown, Sign waits for the end of the review, the second
confirmation appears exactly for the review with bold effects. The
simulator has no Secure Enclave and no camera, so there the key is
software with the tier `simulator`, accepted only with
`--allow-no-attestation`, and the QR's text arrives through a file; all
of that is compiled for the simulator only. `owner-core` now builds the
enrollment answer for the apps (`enroll_answer`, `enroll_refusal`). Today
only the iPhone app calls them; the Android app still assembles the same
JSON itself.

P4 status (2026-11-13, on an iPhone): the same loop passed on a real
iPhone, as a development build under a free personal team
(`MOBILE_DEV_MODE.md` §3; run record in `mobile/ios/README.md`). The key
was created in the Secure Enclave (design §5.3, the CryptoKit handle of
`MOBILE_DEV_MODE.md` §3.4) and signed the raw `userOpHash` after Face ID,
in the form `P256Validator` accepts, through two root operations on a
local anvil: an agent permission, and the change of the root key itself.
The QR came through the camera; a failed Face ID check became a refusal
on the laptop. So P0–P2 pass on the second platform, without attestation,
which iOS under plan B does not have. Not done there: Base Sepolia, the
screen's rules checked by anything but the simulator's robot, the 7-day
expiry of the free profile, and the first fetch, which fails once while
iOS asks for the local network.

Issue #38 (2026-11-13): an enrollment could end with the laptop saying
"enrolled" and the phone having deleted the key, when the laptop's
confirmation was lost or replaced on the way, and the handover had no way
to notice. Closed on three sides. The phone health check of design §2.4
exists (`key check --phone`; `owner-core` 0.3.0, `health.rs`): the phone
signs `sha256("TPM_sign/v1/health" ‖ laptopNonce ‖ phoneNonce)` with a
nonce the core draws. `owner set-root --to-phone <label>` runs it against
the key that is about to become root, before anything is signed or sent;
the command refuses unless it is told what the new key is, that or
`--not-a-phone` (the owner's decision on #39).
And both apps keep a key whose enrollment was not confirmed, instead of
deleting it; showing the key to the laptop is what confirms it. The anvil
suite replays the attack with a host on the path, against a phone that
lost the key and one that kept it; the iOS simulator run does the same
against the real app. The Android minimum version code is 11.

Issue #40 (2026-11-13): the owner can delete an enrollment on the phone on
purpose (design §5.4): asked twice in `owner-core`'s words, the same on
both apps and for confirmed and unconfirmed keys, then the biometric
check; `owner status` prints the root key's fingerprint to compare first,
and `key evict --phone` points at the screen.

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

- **The repository is public** since 2026-11-19
  (<https://github.com/postcryptum-research/agent-keys>). Everything
  written to it, to its issues and to its pull requests is public at once:
  no keys, no RPC URLs that carry a key, no personal device data.
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
