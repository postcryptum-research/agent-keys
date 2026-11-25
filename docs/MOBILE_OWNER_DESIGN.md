# Mobile owner app — design specification

*Revision 2, 2026-10-28; status as of 2026-11. Built: the LAN session and
the wire format (§3, §4), the review in `owner-core` (§6, §7), Android key
attestation (§5.2), the health and possession checks (§2.2, §2.4), deletion
(§5.4), and both apps as development builds. Not built: App Attest and
`--allow-dev-build` (§5.3), the per-enrollment options in the apps (§5.4),
the plan-B WebAuthn envelope (§11.1), parts of the §9 test plan, and §14.
Where the code differs from the design, a note beginning "As built
(2026-11):" says what the code does. This spec answers decision 2 of
[`MOBILE_OWNER_PLAN.md`](MOBILE_OWNER_PLAN.md): the spec that goes to
review before P0 starts. This revision answers the owner's review of PR #5
and the audit response,
[`audit/RESP-mobile-owner-design-2026-10-28.md`](audit/RESP-mobile-owner-design-2026-10-28.md).
The owner's decisions of 2026-10-28 are in §12; v2 is outlined in §14.*

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

**v1's ceiling.** v1 verifies **no chain state**. The phone shows what it
can decode and what its own build knows (§6.7); every other fact about the
chain comes from the laptop (T21). Giving the phone its own view of the
chain is v2, shipped as one feature (§14).

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
   builds an **enrollment request** (§4.3): chain, EntryPoint, account, a
   32-byte challenge, and laptop pins for any address the app's build does
   not know (§6.7).
2. The CLI opens a LAN session (§3) and prints a QR in the terminal.
3. The phone scans it, fetches the request, checks it against the QR's
   commitment, and shows: the chain, the full account address, the label,
   any laptop pins, marked "from the laptop — unverified", and **the
   security level this phone can give the key** (§5.6). On a TEE-only
   phone the user must acknowledge the warning before going on.
4. The user confirms and sets the enrollment's options (§5.4): the gas cap,
   expert mode (off by default) and the device PIN (off by default). The
   phone creates a **new** key for this account (§5.1) and returns the
   public key plus attestation evidence (§5). As built (2026-11): the apps
   offer no options; every enrollment gets the defaults (§5.4).
5. The CLI verifies the evidence, prints the public key and its
   fingerprint, and writes the config snippet (§8.1).
6. The phone stores the enrollment record (§5.4). Nothing is on-chain yet.

**The two sides can end apart** (issue #38). The laptop accepts the answer
and replies with its confirmation (§3.3); only that reply tells the phone
that the laptop has the key. A reply that is lost — the phone locked, the
Wi-Fi dropped — or replaced by a host on the path, which needs no secret,
leaves the laptop saying "enrolled" and the phone without a confirmation.
So:
- **the phone keeps the key, as unconfirmed.** A timeout, a network error
  and any reply that is not the laptop's confirmation say nothing about
  what the laptop has. Deleting the key is the one step that cannot be
  undone, and the laptop may be about to make that key root;
- **the handover does not take the laptop's word for it** (§2.2): the
  phone shows that it holds the key first.
An unconfirmed key is replaced only by a new enrollment of the same
account, which the owner starts and confirms on the phone.

### 2.2 Handover

The phone becomes root through `owner set-root --validator <P256Validator>
--retire <P256Validator> --public-key <phone x,y> --to-phone <label>` (V: this sequence
is `tests/anvil_cli.rs::recovery_drill`). After it, the old owner key signs
nothing (AA24).

**The phone shows the key first** (issue #38). `--to-phone <label>` makes
the handover wait for a session of its own, before anything is signed or
sent: the phone signs the health digest of §2.4 with the key that is
about to become root, and the laptop verifies it against that key. A
phone that did not keep the key, that holds another one for the account,
or that is not there at all stops the handover; without this, root would
go to a key nobody holds, and the account with it unless a recovery key
is installed. On the phone, a key it has shown is confirmed from then on,
whatever becomes of the laptop's reply: it may be root. The CLI cannot
tell a phone's key from any other pasted `--public-key`, so **it must be
told** (the owner's decision): `owner set-root` refuses, before anything
is read or built, unless it is given `--to-phone <label>` or the
statement `--not-a-phone`. The two together are a usage error, and a
handover after a recovery (`--as-recovery`) is under the same rule. `key
create --phone` prints the command with `--to-phone`.

A key that is not a phone's shows the same thing in its own way (issue
#51): with `--not-a-phone` the command makes a challenge that names the
chain, the account and the new key, with a nonce and an expiry; the new
key signs `sha256("TPM_sign/v1/handover-possession" ‖ challenge ‖ its own
nonce)`, and the command verifies that against the key the root is going
to before anything is signed or sent. A key on the same machine does it
inside the command (`--new-key`); a key elsewhere answers through `key
prove`, the two lines carried by hand. `--no-proof-of-possession` is the
stated exception.

Who signs the `set-root` decides how safe it is (T2):

- **Phone to phone** (a new phone, or a second enrolled one), and a **new
  key on the same phone** (§5.4). Kernel never uninstalls the validator
  that is root at that moment, so when the new key goes onto the *same*
  validator the CLI pivots root through the installed recovery validator
  inside the batch (found on 2026-11-10, `YUBIKEY.md`): the recovery key
  must be installed before such a rotation — a precondition of
  [`RECOVERY_DRILL.md`](RECOVERY_DRILL.md) §3.1 now. The
  **current phone** signs the `set-root`, so it decodes it and shows
  "**Hand control of this account to key `<fingerprint>`**" (§6.3). A key
  substituted by the laptop shows a fingerprint that differs from the one
  the new phone displays. This is prevention, and it needs no network.
  As built (2026-11): the apps hold one key per chain and account and
  refuse a second enrollment while a confirmed one exists, so a new key
  on the same phone is not possible yet.
- **The first handover** (a TPM, Secure Enclave or key-file owner to the
  first phone). The old key signs on the laptop, blind, under T1. This is
  the one step to do from a clean machine:
  1. the phone shows its fingerprint at enrollment;
  2. `owner set-root --expect-fingerprint <fp>` refuses unless
     `--public-key` has exactly that fingerprint, and the user compares it
     with the phone's screen;
  3. after it lands, the user reads `P256Validator.publicKeys(account)` on
     a block explorer from a **third** device and compares.

  Between the `set-root` landing and that check, a substituted key would
  already hold root (T2's residual).

### 2.3 Signing a root operation

1. Any owner command whose config names a phone owner key builds the
   operation, estimates gas first (§8.3), then opens a LAN session and
   shows the QR.
2. The phone fetches the request, verifies the commitment, decodes the
   operation, recomputes `userOpHash`, and shows the review screen (§6).
3. The user approves. Biometric verification unlocks the key, and the
   hardware signs the 32-byte hash.
4. The phone posts the signature. The CLI checks that it verifies against
   the account's **on-chain root key** over its own `userOpHash`, frames it
   as `r ‖ s`, and submits through `handleOps` or the bundler.

### 2.4 Health check

`agent-signer key check --phone <label>` proves the phone can still sign,
without any transaction. The digest is
`sha256("TPM_sign/v1/health" ‖ laptopNonce ‖ phoneNonce)`. The phone
contributes `phoneNonce`, so the laptop cannot choose the digest and cannot
use a health check to obtain a signature over a meaningful hash (§6.5).
`owner-core` draws `phoneNonce` itself; the app never chooses it.

The same session is the proof a handover waits for (§2.2). The request
(§4.4) names the key; the phone answers for the key it holds for that
chain and account, confirmed or not, and refuses with `no-key` or
`other-key` otherwise, so the laptop learns which it is. The phone asks
the owner and the key's biometric check before it signs.

## 3. Transport: QR, then the local network

### 3.1 Why this shape

- **No server, no cloud, no Bluetooth** (plan). The laptop serves one
  request on the LAN for one phone, then stops.
- **The QR is the trusted channel.** It travels from the laptop's screen to
  the phone's camera, which a network attacker cannot touch. The QR carries
  a SHA-256 **commitment** to the exact request bytes. The phone refuses
  any fetched request that does not match. Plain HTTP is then acceptable:
  a network attacker can only make the session fail.
- **Secrecy of the traffic is not needed.** The request becomes public
  on-chain anyway, and a signature is public. Integrity of the request
  comes from the commitment, and the laptop verifies every signature.
- **The answer is authenticated by a secret in the QR.** The session token
  travels in the phone's cleartext GET, so a host on the network can post
  in the phone's place. The QR therefore also carries a 128-bit secret
  that is never sent anywhere: the phone puts `HMAC-SHA256(secret, body)`
  on every answer, and the laptop ignores an answer without it, whatever
  it says. That covers the one answer the laptop cannot verify by itself,
  the enrollment's (§4.3): a signature proves itself against the enrolled
  key, a new key proves nothing. Key attestation does not replace this.
  It shows that a genuine device running our app made the key for this
  request, not that it was the owner's device: anyone can hold a genuine
  phone with the published app.
- **The laptop's "accepted" is authenticated the same way.** It answers an
  accepted POST with `HMAC-SHA256(secret, "TPM_sign/v1/accepted" ‖ the
  answer's MAC)`, and the phone takes nothing else as confirmation. A bare
  `200` can be written by a host in the path that dropped the real POST; a
  phone that believed it would keep, as confirmed, a key the laptop never
  saw, and that key would block a new enrollment of the account.
- **What a network attacker can still do** is deny service: delay or drop
  traffic so the session times out, or send enough wrong tokens (20) or
  unauthenticated answers (200) to close it. Not substitute an answer, not
  end the session with a refusal, not make the phone believe the laptop
  accepted.
- **What the secret assumes:** the QR is seen by the owner's phone only.
  Someone who can read it — over a shoulder, through a camera, on a shared
  screen — and is on the network within the session has the secret too.
  The CLI therefore prints the session URI with the secret left out, and
  **at enrollment it asks the owner for the fingerprint the phone shows**
  (two groups at least) and refuses another key: an enrollment is followed
  by a root handover, so the ten characters are spent once where they
  matter. `--phone-skip-fingerprint` relies on the secret alone;
  `--phone-fingerprint` gives the expected one to a script.

### 3.2 QR payload

A URI of about 136 bytes. In byte mode that needs a **version 7** QR
(45 × 45 modules) at error-correction level L: about 23 terminal lines with
half-block characters, which a phone camera reads well (V, P1 and P3 on a
real phone). If it must shrink, the token can be dropped and the path
derived from `k`, or `h` can be uppercase base32 to use the denser
alphanumeric mode. As built (2026-11): the CLI renders at
error-correction level M, the `qrcode` crate's default (`QrCode::new`),
not L, so the version and line count above, computed for level L, do not
describe what the terminal shows; the rendered size was not measured.

```
tpmsign:1?u=http://192.168.1.23:49731/s/<token>&h=<commitment>&k=<secret>
```

| Field | Content |
|---|---|
| `1` | protocol major version |
| `u` | session URL; the host must be a private, link-local or ULA address, else the phone refuses |
| `<token>` | 128 random bits, base64url (22 characters) |
| `h` | SHA-256 of the exact request bytes the URL serves, base64url (43 characters) |
| `k` | the session's secret: 128 random bits, base64url (22 characters). The key of the answer MAC (§3.3). The phone never sends it and never stores it |

The phone registers the `tpmsign:` scheme, but in-app scanning is the main
path, because a system camera may open the URI in another app. As built
(2026-11): neither app registers the scheme; scanning inside the app is
the only path.

### 3.3 The LAN session

| Aspect | Rule |
|---|---|
| Bind | one IPv4 address: the default-route interface, or `--listen <ip:port>` (port 0 for an ephemeral one). Never `0.0.0.0` unless given explicitly |
| Port | random ephemeral, unless given |
| Lifetime | 120 s from the QR being shown (`--phone-timeout`), or until a valid response arrives |
| `GET /s/<token>` | returns the request bytes (`application/json`). Allowed again within the lifetime, so the phone can retry |
| `POST /s/<token>` | body = response (§4.2, §4.3), with the header `X-TpmSign-Mac: base64url(HMAC-SHA256(k, body))`. Without a valid MAC: `401`, the answer is ignored and the session waits on. With one: an answer that fails its checks gets `400` and the session waits on; the phone's refusal ends the session; the first accepted answer ends it, and its `200` carries the laptop's confirmation, `base64url(HMAC-SHA256(k, "TPM_sign/v1/accepted" ‖ that MAC))`, as its body |
| Wrong token | `404`, compared in constant time; 20 wrong tokens or rejected answers end the session; unauthenticated answers have their own cap of 200 |
| After the end | the port closes |
| Body limits | request ≤ 64 KiB; answer ≤ 64 KiB (an enrollment carries a certificate chain); the body is read under the session's deadline |

**CLI-side errors**, each with a plain message and a non-zero exit:
timeout, a refusal reported by the phone (with its reason), a malformed
response, a signature that does not verify, or a `userOpHash` mismatch.

The confirmation can fail to arrive, or be replaced on the way, and the
laptop cannot see that: it reports a write the system says failed, and
no more. What follows from that is in §2.1 and §2.2.

### 3.4 Platform notes (I, confirmed in P1)

- **iOS** needs `NSLocalNetworkUsageDescription`, and the first fetch
  shows the system's local-network prompt. Plain HTTP to a local address
  needs `NSAllowsLocalNetworking` in App Transport Security. Seen on an
  iPhone in P4: that first fetch fails while the prompt is up, and
  scanning the same QR again works.
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
    "command": "owner operation (root)",
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
- **Unknown fields** at the top level and under `laptop` are ignored and
  not shown; an unknown field inside `userOp` is refused. They cannot
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

On refusal: `"result": "refused"` and `"reason"`, with optional free text
in `"detail"`. The apps send two reasons: `user` (the owner said no, or
the biometric check failed) and `core` (`owner-core` refused; `detail`
carries its sentence, which names the cause: an unknown account, the hash,
the expiry, the cap of §6.4, the version). A request that does not match
the QR's commitment gets no answer at all. A refusal ends the session like
a signature does.

The core converts the platform's DER signature to `r ‖ s`, normalizes to
low-s (V: the CLI already requires it, `hw_signer::normalize_low_s`), and
verifies it against the enrolled key before posting.

### 4.3 Enrollment request and response

The request carries `"tpmSign": "enroll-request"`, `version`, `expires`,
`chainId`, `entryPoint`, `account`, `label`, a 32-byte `challenge`, and
optional `laptopPins` (at most 32): addresses and tokens the app's build
does not know (§6.7).

- The phone shows each laptop pin as "from the laptop — unverified", and
  keeps that marking for the life of the enrollment.
- A laptop pin for an address the build already knows is ignored and
  reported.
- A laptop-supplied token never has its decimals trusted. Its amounts show
  in raw units, with "unverified decimals".

The response carries `result` (`enrolled` or `refused`), `publicKey`, the
key's `securityLevel` as the phone sees it, `deviceCredential` (whether the
PIN opt-in was chosen, §5.4), and `attestation`. On Android that is the
certificate chain, base64 DER. On iOS it is the App Attest object and key
id (§5.3). As built (2026-11): `attestation` is a list of base64 DER
certificates only, and the iOS app sends it empty.

### 4.4 Health request and response

The request carries `"tpmSign": "health-request"`, `expires`, `chainId`,
`account`, the `publicKey` to prove and a 32-byte `nonce` (the laptop's
half of the digest). The response carries `"tpmSign": "health-response"`,
the `request` commitment, `result` (`signed` or `refused`), and for
`signed` the `phoneNonce` and the 64-byte `signature` over
`sha256("TPM_sign/v1/health" ‖ nonce ‖ phoneNonce)`. The laptop verifies
it against the key its own request named. A refusal carries `reason`:
`user`, `no-key` (the phone holds no key for the account) or `other-key`
(it holds another one; `detail` names both fingerprints).

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
| User verification | `setUserAuthenticationParameters(0, BIOMETRIC_STRONG)`: a check on every use, biometric only by default (D2). With the per-enrollment PIN opt-in: `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` |
| | `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)` |
| Attestation | `setAttestationChallenge(sha256("TPM_sign/v1/enroll" ‖ requestCommitment))`; **no** device-ID attestation, so no serial numbers reach the laptop |

**Signing:** `Signature("NONEwithECDSA")` inside a `BiometricPrompt`
`CryptoObject`, over the 32-byte hash. The key also allows
`SHA256withECDSA` for plan B, but only `owner-core`'s WebAuthn-envelope
builder may use it (§11.1).

**What the laptop verifies** in the chain (`agent-signer/src/attestation.rs`):
- the chain ends at one of Google's two hardware attestation roots, both
  embedded in the CLI: the old RSA root (keys provisioned at the factory)
  and the ECDSA P-384 root used for remotely provisioned keys since
  2026-04-10 (V per the owner's study, `MOBILE_DEV_MODE.md` §2.4, PR #7).
  A root is matched by its public key, since Google has reissued the RSA
  certificate;
- every certificate is valid now, is signed by the next, and **every
  issuer is a CA; only the key's own certificate may carry the attestation
  record.** Without these two an attested key, which signs whatever its
  owner asks, could issue a certificate with a record of its owner's
  choosing;
- the attested key **is the key the phone's answer names**, and its origin
  is "generated" in the hardware, not imported;
- `attestationChallenge` equals the expected value;
- `attestationSecurityLevel` and `keyMintSecurityLevel` are both
  `StrongBox` or both `TrustedEnvironment`;
- the key is EC P-256, purpose sign, with `NONE` among its digests;
- user authentication is required on every use, by biometric, or by
  biometric or PIN exactly when the enrollment chose the opt-in;
- `attestationApplicationId` names our package, the signing-certificate
  digest **of the build's channel**, and a `versionCode` at or above the
  minimum (T14). A self-signed APK carries our own digest. A Play build
  carries the digest of Google's app-signing key, which puts Google in
  T6's trust root (`APP_ATTEST_ORG.md` §7, PR #6);
- `rootOfTrust`: `deviceLocked = true`, and the `verifiedBootState`
  (the auditor's answer, issue #35). The owner confirms the enrollment by
  reading the fingerprint off the app's screen, and boot integrity is what
  makes that screen the app's. The hardware facts of the record hold in
  every state; what an unvouched operating system takes away is the app's
  identity and the integrity of what it shows.

  | `verifiedBootState` | The CLI |
  |---|---|
  | `Verified` | accepts |
  | `SelfSigned`: a custom OS on a locked bootloader, verified against a root the owner chose (GrapheneOS). Its integrity holds | accepts, with a warning |
  | `Unverified`: integrity not guaranteed; a modified system could show the fingerprint of another key | **refuses**, unless `--allow-unverified-boot`; then accepts with the warning |
  | `Failed`, or `deviceLocked = false` | refuses, with or without the flag |

  The warning says what follows: `attestationApplicationId` is asserted by
  the operating system, so on a system nobody vouches for, "made by" and
  the digest pin carry no weight. The state is printed in the result and
  recorded in the config's phone spec (`"bootState": "verified"`,
  `"self-signed"` or `"unverified"`; `"none"` without evidence), so a key
  accepted with the flag stays recognisable.

Until the project has a signing key no digest is pinned in the CLI, and a
developer's own build is accepted by naming its certificate
(`--android-app-digest`); a refusal prints the digest it saw. That, the
provisional package name and the test chain are the **development
posture**, and a build that is handed to anyone must not be in it. Two
checks refuse to produce one (issue #35): the CLI's `distribution` feature
does not compile while `PINNED_SIGNING_DIGESTS` is empty, a package ends in
`.spike`, or software keys and the test chain are compiled in; the Android
project's release build type refuses a `.spike` application id and a core
built with `test-chains`. A release is built with both; the decisions that
would let them pass stay open (`APP_ATTEST_ORG.md` §8).

Revocation: Google publishes an attestation revocation list. The CLI checks
it when online and says so in the result, and the config's phone spec
records it (`"revocation": "checked"` or `"not checked"`), because anyone
on the path can make the fetch fail; `--require-revocation-check` refuses
the enrollment instead. Leaked attestation keys have existed, so
attestation is evidence, not proof (§10, T15).

**What a verified attestation does not show:** whose phone it is. Anyone
can hold a genuine device with the published app. The answer is tied to
the owner's phone by the session secret in the QR (§3.1), not by this.

### 5.3 iOS (Secure Enclave)

**Key:** `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`. The
access control is `.privateKeyUsage` plus `.biometryCurrentSet`, or plus
`.userPresence` (biometry or passcode) when the enrollment chose the PIN
opt-in (D2). The key is
stored in the app's keychain as `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`,
so removing the passcode makes it unusable. A real app has keychain
entitlements, unlike the CLI's Mac shim, which is why that shim uses
CryptoKit blobs instead (V, `SecureEnclaveShim.swift`). Development without
an Apple organisation uses the shim's approach on the phone: a CryptoKit
handle in the app's files, excluded from backup, and no App Attest
(`MOBILE_DEV_MODE.md` §3.4, PR #7).

**Signing:** `SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256,
hash)` takes the 32 bytes as the digest (V: plan; the Mac backend does the
same through CryptoKit). The output is DER. As built (2026-11): the app
signs through CryptoKit too, `SecureEnclave.P256.Signing.PrivateKey`'s
`signature(for:)` over the 32 bytes taken as the digest.

**Attestation (D5).** iOS has no per-key attestation, so bind our key to
an **App Attest** attestation:

1. Create the Secure Enclave signing key `K`.
2. `DCAppAttestService.generateKey()`, then
   `attestKey(keyId, clientDataHash: sha256("TPM_sign/v1/enroll" ‖
   requestCommitment ‖ K.x ‖ K.y))`.
3. The laptop verifies the attestation object as Apple specifies (V,
   [Apple: validating apps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)),
   with the additions from the owner's App Attest study
   (`APP_ATTEST_ORG.md` §2, PR #6):
   - the certificate chain ends at the App Attestation root;
   - `nonce = sha256(authData ‖ clientDataHash)` matches the certificate
     extension;
   - the RP ID hash is `sha256(<App ID prefix>.<bundle id>)`;
   - the counter is 0;
   - `aaguid` is `appattest` followed by seven zero bytes for production.
     For development builds, accept both `appattestdevelop` and
     `appattestsandbox`, because Apple's two pages disagree;
   - the distribution channel, `apple_validation_category_01`: accept 2
     (TestFlight) and 4 (App Store); 3 (development) only with
     `--allow-dev-build` on a test chain; refuse every other value of
     Apple's table (0–10), including 5 (ad-hoc and enterprise) and 6
     (Developer ID) (V, Apple's validation page, 2026-10-28). Testers get
     TestFlight builds, not ad-hoc ones;
   - the app version, `apple_bundle_version_01`, is at or above the
     minimum (T14).

As built (2026-11): none of this exists yet. The iOS app sends no evidence
and the CLI verifies only Android key attestation, refusing evidence from
any other platform, so an iPhone is enrolled with `--allow-no-attestation`.

**What it proves:** a genuine instance of our app, on genuine Apple
hardware, vouched for `K`'s public key during this enrollment. It does
**not** prove that `K` lives in the Secure Enclave. That follows only from
the app's code, which creates keys nowhere else. So iOS evidence is as
strong as trust in the shipped build (§10, T6).

**Network:** `attestKey` calls an Apple server, so the phone needs
internet once per enrollment (V, Apple's preparation page, via PR #6).
`--allow-no-attestation` remains for users who refuse that; the T2 check
from a third device is then mandatory.

**Prerequisites:** an Apple Developer team, the App Attest entitlement,
and a fixed Team ID and bundle id, which become protocol constants in the
CLI. The organisational side is the owner's study, `APP_ATTEST_ORG.md`
(PR #6), due before P3.

### 5.4 What the phone stores per enrollment

Per enrollment, the phone stores:
- the label, chain id, EntryPoint and account;
- the key reference (Keystore alias or keychain item) and the public key;
- the security tier the key got: StrongBox, TEE or Secure Enclave (§5.6);
- the laptop pins, each marked unverified (§6.7);
- **the options**, chosen at enrollment and changeable only on the phone:
  the gas cap (D8, default 0.005 ETH), expert mode (D4, default off) and
  the device PIN (D2, default off). Changing it means a **new key**,
  because the access control is fixed when the key is created. A new key
  needs a `set-root` to it, signed by the current key on the same phone.
  That is the phone-to-phone handover of §2.2: the phone decodes it and
  shows the new key's fingerprint. As built (2026-11): `owner-core` and
  the CLI support the options, but neither app offers or stores them:
  every enrollment uses the 0.005 ETH cap, expert mode off and biometric
  only, and a new key for an enrolled account is refused (§2.2);
- the enrollment time, and a local history of signed hashes with their
  summaries. As built (2026-11): the time is stored, the history is not.

None of this is secret. Losing it only loses the key reference, and
recovery covers that.

**Deleting an enrollment** (issue #40). The apps never delete a key the
laptop may have (§2.1), so the owner needs a way to do it on purpose: an
abandoned enrollment, a key root has been handed away from, a phone being
given up. It is per enrollment and cannot happen by accident:
- the phone has no view of the chain (T21), so it **cannot know whether
  the key is root**, and says so. Deleting the root key takes the account
  with it, unless a recovery key is installed. The screen sends the owner
  to the laptop first: `owner status`, for that account, prints the root
  key's fingerprint and the recovery state, to compare with the
  fingerprint on the phone. The comparison covers the root key only: a
  key that is not root but sits on a validator that was granted `execute`
  (§6.3) still acts for the account, and the phone cannot see that
  either;
- it asks **twice**, then for the **biometric check**;
- the words are `owner-core`'s (`enroll::deletion_prompt`), so both apps
  say the same, and they are the same for a key the laptop confirmed and
  for one it did not: an unconfirmed key may be root all the same;
- the key and its record go **together**. Where they are two things
  (Android: a Keystore entry and a record), the key goes first, and the
  app says which of the two it could not remove; where the record holds
  the key's handle (iOS), one write removes both or neither.
On the laptop, `key evict --phone` names this screen.

### 5.5 Why no `initCode`

A counterfactual account's address depends on its owner key (the root
validator is in `initData`), so the phone cannot be enrolled for an address
before its own key exists. v1 enrolls existing accounts only, then hands
over. A later version can enroll first and bind the account at creation.

### 5.6 Telling the user what the phone can give: StrongBox or TEE only

Two Android tiers exist, and the user must know which one holds the key:

| Tier | Where the key lives | What it resists | What it does not |
|---|---|---|---|
| **StrongBox** | a separate secure element with its own CPU and storage (Titan M on Pixels, Knox Vault on recent Galaxy S) — comparable to the iPhone's Secure Enclave, which is a coprocessor on the SoC with its own memory rather than a discrete chip | everything the TEE resists, plus bugs in the trusted OS and physical attacks on the chip | — |
| **TEE only** | the main processor's trusted mode (TrustZone); non-extractable, signs inside | malware on the phone, even with root; copying the key | a bug in the trusted OS or the main processor's firmware; physical attacks on the silicon |

Both are accepted (§5.2), and both are far above a key file. But the
difference is exactly the class of attack a separate chip is for, so the
app says it plainly, in three places:

- **At first launch** and on the accounts screen: a persistent notice,
  "This phone keeps keys in its processor's trusted mode (TEE), not in a
  separate secure chip. A phone with StrongBox, or an iPhone, protects the
  owner key better. Details →", with a short explanation of the table
  above. On a StrongBox phone the notice says so, once. As built
  (2026-11): the Android app has no persistent notice at launch or on an
  accounts screen; it shows the tier and the warning at enrollment (the
  next item).
- **At enrollment**, before the user confirms (§2.1): the tier is shown
  with the warning on a TEE-only phone, and the user acknowledges it.
  How the phone knows the tier: on Android 11 (API 30, the D7 floor) the
  key creation path says it — `setIsStrongBoxBacked(true)` succeeded means
  StrongBox, the retry after `StrongBoxUnavailableException` means TEE,
  and `KeyInfo.isInsideSecureHardware()` must be true either way;
  `KeyInfo.getSecurityLevel()` exists only from Android 12 (API 31) and
  confirms it there (V, AOSP `KeyInfo.java` at `android-11.0.0_r1` and
  `android-12.0.0_r1`, per the review). The tier is stored in the
  enrollment record (§5.4) and returned in the enrollment response, **for
  display**. The authoritative value is `attestationSecurityLevel` /
  `keyMintSecurityLevel` in the attestation record, which the laptop
  verifies (§5.2).
- **On the laptop**: `key create --phone` prints the tier, the config
  snippet carries it (`"attestation": "strongbox"` or `"tee"`, §8.1), and
  the attestation check confirms it (§5.2). A deployment may refuse TEE-only
  owner keys for a value-bearing account; the CLI offers
  `--require-strongbox` for that, and it decides on the attestation's
  security level, never on the phone's self-report.

iPhones have no such split: every model the app supports has the Secure
Enclave. The notice is therefore Android-only. As built (2026-11): the
iPhone app shows one line saying that the key is in the Secure Enclave.

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

The code runs them in the order 1, 2, 6, 3, 4, 5 (the hash comparison is
part of parsing the request), and then checks the EntryPoint against the
build's (§6.7).

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
| `installValidations` of a **permission** id (type `0x02`) | "Install agent permission `<id>`", with the full mandate: the signer module and the policy module, each marked as in §6.7 (including "superseded version", a build fact); the agent key fingerprint; every allow entry (target, selector, and the name where known); value cap, budget, validity window, token caps and x402 flags. As built (2026-11): a permission whose policy or signer module is not the build's current one, superseded versions included, is refused; expert mode turns that into a bold "Unknown policy module" or "Unknown signer module" row |
| `installValidations` of a **validator** (type `0x01`) | always an effect, since v1 does not know which validators the account uses: "**Install a key on a validator** `<fingerprint>` — it controls this account once it is root or is granted access", whether the validator is current, superseded or unknown to the build. For a recovery validator: "Install a recovery key — **it will be able to take over this account**". As built (2026-11): a validator the build does not know gets its own bold row, "Install a key on a validator this build cannot classify — it may be able to take over this account" |
| `grantAccess(vId, selector, allow)` | Kernel lets a non-root validation call a top-level selector only when it is granted here, so a grant is judged by what bounds it. Plain: a **permission's** `execute` (its policy bounds it), and any grant with `allow = false`. Bold: a **validator's** `changeRootValidator` ("**may take over this account**") and a validator's `execute` ("**this key will be able to do anything with this account**"). Every other grant — an admin selector to a permission or a validator, a selector the build cannot name — is **refused**; expert mode turns the refusal into a bold row |
| `changeRootValidator(...)` | "**Hand control of this account to** validator `<address>`". In a `set-root` batch, the summary names the key: "**Hand control of this account to key `<fingerprint>`**" (§2.2). As built (2026-11): the key named is the one an `installValidations` of that validator in the same batch installs, and only for a validator the build knows to keep the key it is given (this phone's validator, a known recovery validator, a `P256Validator` by name); any other contract may ignore it and is named by its address. A root change that carries a key in its validator data is **refused**: Kernel installs that data only when the validator is not installed yet and ignores it otherwise, an install earlier in the same batch included [V `contracts/lib/kernel/src/Kernel.sol:149-154`], so the key it carries may not be the one taking control (issue #147). The CLI sends that data empty |
| `uninstallValidation(vId, …)` | "Remove permission `<id>`" or "Remove validator `<address>`". If that validator holds this phone's key: "**this phone will no longer control the account**". As built (2026-11): the apps do not record which validator holds the phone's key, so every validator removal is bold, "this may be the validator holding this phone's key" |
| any other self-call | **refused** (v1) |

An inner call to **another** target is an external call: the target, the
value, and the decoded function where known (ERC-20 `transfer` and
`approve` for build-known tokens, the Safe-nonce assertion followed by Safe
`execTransaction`). As built (2026-11): the core decodes the demo
counter's `increment()` and ERC-20 `transfer` and `approve` on any target
(scaled only for build-known tokens); the Safe calls are not decoded and
fall under the rule below. An external call the core cannot decode (D4):

- is **refused by default**. From the root key it is unbounded: it can move
  everything the account holds, and the gas cap does not limit it;
- is allowed only in **expert mode**, a per-enrollment option that is off
  by default and can be turned on only on the phone. Even then it needs
  the second confirmation (§6.6), worded with the unbounded effect: "This
  calls an unknown contract that can move everything this account holds."

**Rules for the text:**
- **Addresses in full**, checksummed, never truncated. Truncation invites
  vanity-address poisoning.
- **Key fingerprints:** 100 bits of `sha256(x ‖ y)`, shown as four groups
  of five base32 characters. 32 bits can be ground; 100 bits cannot. The
  CLI prints the same fingerprint, for comparison across devices.
- **Amounts:** ETH from wei. Token amounts are scaled only with decimals
  from the build (§6.7). Otherwise they show in raw units, with "unknown
  token" or "unverified decimals".
- **Times:** UTC date and time, with the raw value in brackets beside it.
  Local time is not shown.
- **Labels and pins:** names from the build are shown as "verified in
  this build". Laptop pins and `laptop.labels` are shown in quotes, as
  "from the laptop — unverified", in a visually subordinate style. A label
  never replaces an address.
- **Text:** labels are restricted to printable ASCII plus spaces, at most
  32 characters (64 for the key's own label, §2.1). Anything else is
  refused, which closes homoglyph and bidirectional-text tricks.

### 6.4 Cost, gas fields and sponsorship

- The phone shows the **maximum gas cost**:
  `(verificationGasLimit + callGasLimit + preVerificationGas +
  paymasterVerificationGasLimit + paymasterPostOpGasLimit) × maxFeePerGas`
  (correct for v0.7's maximum prefund, per the audit).
- It **refuses** above a per-enrollment cap. The default is 0.005 ETH, and
  the user can change it on the phone (D8). This stops a compromised laptop
  from draining the account through the gas prefund. As built (2026-11):
  the cap is checked only when the account pays; an operation sponsored by
  a build-known paymaster shows its maximum cost and is not refused for it.
- **Every field the hash covers is on the screen.** Under "details", the
  phone lists `verificationGasLimit`, `callGasLimit`, `preVerificationGas`,
  both paymaster gas limits, `maxFeePerGas`, `maxPriorityFeePerGas` and the
  full `nonce` (key and sequence). Without them, swapping
  `verificationGasLimit` and `callGasLimit` would change the hash but not
  the displayed total (audit, Q3).
- **Paymasters (T20).** A paymaster can charge the account in tokens in
  `postOp`, which the ETH cap does not bound. v1 therefore accepts only
  paymasters that the build knows and knows to charge nothing: today the
  project's `WhitelistPaymaster`, which has no `postOp` (V,
  `contracts/src/WhitelistPaymaster.sol`). The screen says "gas sponsored
  by `<paymaster>` (verified in this build)". Any other paymaster is
  refused. Token-charging paymasters can come later, each with a decoder
  for its charge and a per-enrollment token cap.

### 6.5 What is never signed

- **A digest supplied by the laptop.** The protocol has no message for it.
  A laptop-chosen 32 bytes could be the hash of a malicious operation, an
  ERC-1271 message (Kernel wraps them, `kernel::kernel_wrapped_hash`) or a
  permit. Health checks use a digest the phone co-randomizes (§2.4).
- **Operations for an unenrolled account, chain or EntryPoint.**
- **Non-root nonce keys,** delegatecall, unknown self-calls, or a non-empty
  `initCode`.
- **Anything with `SHA256withECDSA`** except the plan-B WebAuthn envelope
  that `owner-core` builds itself around a `userOpHash` it has reviewed
  (§11.1). Never over a `clientDataJSON` from the laptop.
- **Unknown external calls and unknown paymasters,** unless expert mode
  allows the former (§6.3). Unknown paymasters are refused in every mode.

### 6.6 Approving

- The review screen has one "Sign" action, enabled only after scrolling
  through every section. Then comes the system biometric prompt.
- Effects marked **bold** in §6.3 (taking over, removing this phone's
  control, installing a recovery key, an unknown call in expert mode)
  need a second confirmation that repeats the effect in plain words.

### 6.7 Where the phone's facts come from (pins)

A laptop compromised **at enrollment** could otherwise pin its own
contract as "AgentPolicy" or "P256Signer", or a fake token with wrong
decimals, and every later review would show a malicious mandate as a normal
one (T19). So the facts come from the **build**:

- **Build-embedded deployments.** `owner-core` embeds the canonical
  `contracts/deployments/<chainId>.json` files at build time
  (`include_str!` and a parse in the build), today `84532.json` for Base
  Sepolia. That includes the **version history**: `agentPolicyV1`–`V6`,
  `p256SignerV1`, `p256ValidatorV1`, `whitelistPaymasterV1` and
  `p256RecoveryValidatorV1`. "Superseded version" is therefore a build
  fact, not a laptop claim. Only canonical files are embedded. Variants
  such as `84532.enclave.json`, which names a test paymaster owned by a
  developer's wallet, are not.
- **Build-embedded tokens.** A small reviewed table in `owner-core`
  (address, symbol, decimals per chain), today USDC on Base Sepolia.
- **The EntryPoint is a build fact too.** Where the build knows a chain,
  an enrollment or a request naming another EntryPoint is refused.
- **A known token's signing domain.** The table carries the token's
  EIP-712 domain separator; a mandate that allows x402 payments in that
  token under another domain is refused, since the policy would then
  check payment signatures for a different contract.
- **Laptop pins** are accepted only for addresses the build does not know,
  and are shown as "from the laptop — unverified" (§4.3). A pin is a label
  and nothing more: it never makes a call decodable, a module readable, a
  paymaster acceptable or an effect plain. A pin whose label is a name the
  build gives to what it verifies ("AgentPolicy", "USDC", with or without
  a version) is refused and reported, so a stranger cannot be made to look
  like a known contract; the CLI labels its pins by role ("policy module
  (config)").
- **Development builds** may add the CLI's local anvil chain (feature
  `test-chains`), where the test harness installs the same code at the
  same addresses. Such a build shows `+test-chains` in its version and is
  never distributed.
- **Trade-off.** A new deployment or a new chain needs a new app release.
  Until then the laptop may pin the new addresses, always marked as
  unverified. The durable answer is the on-chain Registry in v2 (§14).

## 7. `owner-core` and its `uniffi` interface

### 7.1 Crate layout (D9)

- **New crate `owner-core`,** proposed **outside `signer/`**, at
  `mobile/owner-core`. `signer/` carries an Apache-2.0 `LICENSE` and
  `NOTICE` for the whole directory, so placing the crate there would
  suggest Apache-2.0 by location, whatever its manifest says.
  Dependencies: `alloy-primitives`, `alloy-sol-types`, `hw-signer` (no
  default features; it brings `p256`), `serde`, `serde_json`, `sha2`,
  `hmac`, `base64`, and for the apps' build `uniffi` and `getrandom`.
  No network, no async, no `alloy` providers, so it builds for
  `aarch64-apple-ios`, `aarch64-linux-android` and
  `armv7-linux-androideabi`.
- **Its licence is not decided.** The licence of the mobile apps and of
  `owner-core` is a separate study (plan, decision 3), done before P5 and
  before any of the apps' code is published. Until then the placement is
  provisional, and the crate's manifest does **not** take
  `license.workspace` (which would make it Apache-2.0 automatically). It
  has `publish = false`, no `license` field, and its own README saying
  "licence not decided". The study also has to settle that the Apache-2.0
  CLI depends on it.
- **Code moved from `kernel.rs` stays under Apache-2.0** (with its notice),
  whatever the study decides for the rest of the crate.
- **Moved from `agent-signer/src/kernel.rs`:** the pure encode and decode
  functions (validation ids, nonce keys, `decode_execute`,
  `PolicyParams` and `permission_data`, plus decoders the CLI lacks for
  `installValidations` and `grantAccess`). `agent-signer` depends on
  `owner-core` and keeps its existing tests. This is a refactor of the
  CLI, not a change of behaviour; its unit tests and the anvil suite
  guard it.
- **New in the crate:** `user_op_hash(op, entry_point, chain_id)` computed
  locally (V for the formula, plan); the request and response types; the
  `Review` builder; display text and fingerprints; the build-embedded
  deployments and token table (§6.7); and the plan-B envelope builder
  (§11.1). As built (2026-11): everything in this item but the plan-B
  envelope builder, which is not written.

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
// The phone's answer to an enrollment, and its refusal (§4.3): built here, not in each app.
#[uniffi::export] fn enroll_answer(commitment: String, public_key: Vec<u8>, security_level: String,
    device_credential: bool, attestation: Vec<Vec<u8>>, app: AppInfo) -> Result<Vec<u8>, CoreError>;
#[uniffi::export] fn enroll_refusal(commitment: String, reason: String, detail: Option<String>,
    app: AppInfo) -> Vec<u8>;
// §2.4: which of the phone's keys the request is about, the digest (the core draws the phone's
// nonce), the answer or the refusal.
#[uniffi::export] fn open_health(bytes: Vec<u8>, commitment: String, now: u64, held: Vec<HeldKey>)
    -> Result<Arc<Health>, CoreError>;
#[uniffi::export] fn fingerprint(public_key: Vec<u8>) -> String;   // 100 bits, 4 × 5 base32
// Enrollment carries its options: gas cap, expert mode, device PIN.
// Plan B: Review::webauthn_message() is the only input SHA256withECDSA may sign.
```

The native side renders `sections()` generically. Every word on the review
screen comes from the core, in English for v1, with structured rows so
translation can follow.

As built (2026-11): the surface is `ffi.rs`, and it differs from the
sketch: `open_enrollment` returns a record (`FfiEnrollment`), the review
object is `ReviewHandle` with `refuse(reason, detail, app)`, the
fingerprint function is `fingerprint_of`, there is no
`webauthn_message()`, and the answer MAC, the laptop's confirmation, the
deletion prompt and the health handle are exported too. The Android app
still builds the enrollment answer and its refusal itself; the iOS app
uses `enroll_answer` and `enroll_refusal`.

### 7.3 Builds

- **iOS:** an `xcframework` (device plus simulator), and the generated
  Swift (`mobile/ios/build-core.sh`; arm64 for both).
- **Android:** `cargo-ndk` libraries for `arm64-v8a` and `armeabi-v7a`,
  plus the generated Kotlin (JNA). Today `mobile/android/build-core.sh`
  builds `arm64-v8a` only; `armeabi-v7a` comes with P5.
- Both are pinned to the same `owner-core` version, which the response
  reports.

## 8. CLI changes

### 8.1 Key spec and config

```json
"owner": { "phone": { "label": "owner-phone", "platform": "android",
                      "attestation": "strongbox", "revocation": "checked",
                      "bootState": "verified", "deviceCredential": false,
                      "publicKey": { "x": "0x…", "y": "0x…" },
                      "fingerprint": "ABCDE-FGHIJ-KLMNO-PQRST" } },
"ownerPublicKey": { "x": "0x…", "y": "0x…" }
```

- **New variant `KeySpec::Phone`,** accepted for the **owner** role only;
  refused for the agent with an explanation. Recovery may come later.
- **`ownerPublicKey` stays the account's creation key** (the convention
  decided on 2026-11-10: it derives the counterfactual address and is not
  rewritten after a handover). The key the phone must hold is the
  **on-chain root key**, which the CLI reads from the root validator before
  every root operation (`check_root_key`; skipped with a message when the
  root validator is not one of this repository's P-256 validators). The
  phone spec carries the enrolled key as `publicKey`: the config's
  `fingerprint` is checked against it, and it against the on-chain key,
  and a mismatch in either is refused before any prompt.

### 8.2 Commands

| Command | Change |
|---|---|
| `key create --phone <label> --agent <cfg>` | the enrollment session (§2.1); verifies attestation, prints the public key, fingerprint, security tier and config snippet; `--allow-no-attestation` for iOS without App Attest; `--allow-dev-build` for development-signed iOS builds, test chains only (with iOS); `--require-strongbox` to refuse a TEE-only key (§5.6); `--android-app-digest <sha256>` to accept one's own build of the app; `--require-revocation-check` to refuse when Google's revocation list cannot be fetched; `--allow-unverified-boot` to accept a phone whose boot state is Unverified (§5.2); `--phone-skip-fingerprint` to rely on the QR's secret without the fingerprint prompt, `--phone-fingerprint <fp>` to give the fingerprint to a script (§3.1); `--out <dir>` to keep the request, the answer and the chain (each file mode 0600). As built (2026-11): `--allow-dev-build` does not exist (§5.3); the other flags do |
| `owner set-root … --expect-fingerprint <fp>` | refuses unless `--public-key` has that fingerprint; for the first handover (§2.2) |
| `owner set-root … --to-phone <label>` | the new key is that phone key: the phone shows that it holds it, in a session of its own, before anything is signed or sent (§2.2) |
| `owner set-root … --not-a-phone` | the new key is not a phone's: no phone session. One of the two is required; with neither the command refuses before anything is built. The new key signs a fresh challenge first (issue #51): `--new-key '<key spec>'` on this machine, or `key prove` on another; `--no-proof-of-possession` skips it with a warning |
| `key prove --key '<key spec>' --challenge <line>` | the key's half of that proof, on the machine that holds the key; prints one line to paste back. No transaction |
| `key check --phone <label>` | the health check (§2.4): the phone signs a digest it co-randomizes with the configured key; no transaction |
| `key show --phone <label>` | prints the configured public key and fingerprint, and what the enrollment recorded: attestation, revocation, boot state (no session) |
| `key evict --phone <label>` | refuses: a phone's key is deleted on the phone (§5.4), and says to look at `owner status` first |
| `owner status` | also prints the root key's fingerprint, which is what the owner compares with the phone's screen before deleting a key there |
| every owner command | unchanged syntax; with a phone owner they open a session. New flags `--listen`, `--phone-timeout` |

### 8.3 Signing path (`chain.rs`)

1. **The trait gains a method with a default.**
   `HardwareSigner::sign_user_op(&self, ctx: &UserOpContext) -> Result<Signature>`,
   where the default calls `sign_digest(ctx.hash)`. Every existing backend
   keeps working unchanged. `PhoneSigner` implements `sign_user_op` and
   returns an error from `sign_digest` ("phone key … signs operations, not
   bare digests: the phone must see what it signs"). The trait also has
   `needs_request()`, false by default; a signer that returns true gets
   the sign request attached to the context.
2. **The hash is computed locally.** The CLI computes `userOpHash` with
   `owner-core`, compares it with `EntryPoint.getUserOpHash`, and stops on
   any difference. That check doubles as a test of the core against the
   chain on every run.
3. **One signature with a bundler.** Until 2026-11-10 the hardware signed
   twice when a bundler was used, before and after gas estimation; with a
   phone that would have meant two biometric prompts, with a YubiKey two
   touches. The CLI now does what this item asked (V, `chain.rs`
   `send_raw_at`, issue #15):
   - it estimates with a placeholder signature of **exactly the real
     one's length**, 64 bytes on the root path and 65 under a permission
     (`PLACEHOLDER_SIGNATURE`, framed like the real one). `P256Validator`
     returns early when the length is not 64 (V, `P256Validator.sol`), so
     any other length would measure validation without the P-256
     verification and underestimate it, and the real operation would fail
     with AA23 after the user had already approved;
   - estimation works because `validateUserOp` returns
     `SIG_VALIDATION_FAILED` for a bad signature instead of reverting (V,
     checked by the audit; the anvil suite's fake bundler refuses any other
     placeholder length);
   - it adds a **20 % margin** to `verificationGasLimit`, then asks the
     device once;
   - gas prices come from the bundler itself when it publishes them
     (`pimlico_getUserOperationGasPrice`), since the node's estimate can
     fall under the floor the bundler enforces at submission. If a bundler
     publishes no prices and refuses the operation naming its floor, the CLI
     reprices to it and asks for **one more** signature, saying so; that is
     the only case with two prompts (V, anvil `sponsored_and_bundled`);
   - confirmed against the public Pimlico endpoint on Base Sepolia on
     2026-11-10: prices from the bundler, estimate on the placeholder
     accepted, one signature, included (tx
     `0x15a5fcf916b2dd0f3516a5eca2bdb0aebf075909e8e895c08c00ec6f7751ff65`);
   - the precompile is present on Base Sepolia (V, 2026-10-28: a call to
     `0x…0100` with the committed enclave vector returns 1, a tampered copy
     returns nothing). A direct call estimates at 30,811 gas, which after
     the base cost and calldata fits EIP-7951's price of 6,900 rather than
     RIP-7212's 3,450 (I). The spec records the verification gas the
     tests expect, so that a fall back to the Solidity verifier, about 100
     times dearer, shows up as a failure.
4. **After the phone answers:** verify against the on-chain root key (the
   one `check_root_key` read), frame
   with `root_signature`, submit.

### 8.4 Terminal QR

The CLI renders with the `qrcode` crate (half-block characters), under a
headline that carries the key's fingerprint and, for an operation, the
`userOpHash`, which the phone also shows. Below the QR it prints the
session URI with the secret left out (§3.1): a record, not a manual
fallback, since the secret is in the QR only.

## 9. Test plan

**Anvil first, as the plan asks.**

As built (2026-11): there are no golden files and no `cargo-fuzz` target;
the tamper test (`review.rs`, `tamper_every_hash_covered_field`) builds its
operation in code and mutates each hash-covered field and every calldata
byte, not the bytes of the request. The phone simulator is a thread inside
`tests/anvil_cli.rs`, not a binary, and the plan-B cross-protocol test is
not written.

1. **`owner-core` unit tests:**
   - `user_op_hash` against reference values computed with `cast`;
   - golden files: every owner command's request (from the CLI, with a
     fixed account) and its expected `sections()` text;
   - DER → `r ‖ s` → low-s round trips;
   - fingerprints.
2. **Tamper tests.** Flip every byte of a golden request. **Every flip
   that changes the hash must change the displayed text** (details
   included). A flip that fails a §6.2 check must be refused. Swapping
   `verificationGasLimit` and `callGasLimit` is a named case.
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
     gas-cap breach, an unknown paymaster, an unknown external call with
     expert mode off;
   - pins: a laptop pin for an address the build knows is ignored; a
     laptop token shows raw units with "unverified decimals";
   - a phone-to-phone `set-root` signed on the simulated phone, whose
     summary names the new key's fingerprint;
   - a malicious laptop: the request served differs from the committed
     one, and the phone refuses;
   - the health check;
   - with a bundler: exactly one signature request per operation, with a
     64-byte placeholder, and an operation that lands;
   - plan B: a signature for `P256Validator` does not verify on the
     WebAuthn validator, and the reverse (a cross-protocol test).
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

**Formal model.** This design is an instance of what Breckenridge,
Vilardell, Wang, Zhang and Juels call an *inalienable human-in-the-loop*
([arXiv 2610.35835](https://arxiv.org/abs/2610.35835), 2026; V for their
statements). Their impossibility result: if the approval passes through a
platform the agent controls (here, the laptop), no protocol can bind the
approval to the action. Their sufficient condition: a trusted device that
either shows the human a message the adversary cannot fake or produces an
approval the adversary cannot forge, with authentic channels to the service.
Here the phone is that device: the message it shows is decoded by
`owner-core` from the raw request and checked against the QR commitment
(§3, §6); the approval is a hardware signature verified by `P256Validator`
on the chain, which is the honest service; attestation (§5) ties the key to
that device. Their "strong" variant, where the human must not be able to
hand approvals to the agent, is the non-extractable, biometric-gated key
(D2, D5). Their Circle experiment, in which agents raised their own caps
through an e-mailed code, is in `related/LANDSCAPE.md` §2a. The first
handover (T2) is our gap in their terms: an approval signed before the
device has a channel of its own. It is the same for every owner key without
a screen, a TPM or a YubiKey alike: the first `set-root` to a phone is
signed on the laptop's word.

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | **The laptop is compromised** and requests a malicious operation | the phone decodes, recomputes the hash and shows the real effect; laptop labels are marked as such; addresses are shown in full; gas cap | a user who approves without reading. The bold second confirmation targets the dangerous cases |
| T2 | **The laptop is compromised during a handover** and substitutes its own key in `set-root` | phone to phone: the current phone decodes the `set-root` and shows the new key's fingerprint, which prevents it (§2.2). First handover: `--expect-fingerprint`, a clean machine, and a check from a **third** device of `P256Validator.publicKeys(account)` | the first handover is signed blind. Between a substituted `set-root` landing and the third-device check, the attacker holds root and can rotate again or drain. v2 adds on-chain checks by the phone itself (§14) |
| T3 | **A LAN attacker** swaps the request or the response, or answers an enrollment with its own key | QR commitment; every answer carries a MAC under the QR's secret (§3.1); the laptop verifies the signature against its own hash | denial of service by dropping traffic only. Replacing the laptop's confirmation of an enrollment needs no secret; it used to make the phone delete a key the laptop had accepted, and no longer does: the phone keeps the key, and a handover waits for the phone to show it (§2.1, §2.2, issue #38). An attacker who can also read the QR has the secret: the fingerprint the CLI asks for at enrollment covers that, unless the owner skips it (`--phone-skip-fingerprint`) |
| T4 | **A foreign QR** (another screen, a poster) | unenrolled accounts are refused; for an enrolled one, the normal review applies | as T1 |
| T5 | **Malware on the phone** (user level) | Keystore and keychain keys are bound to our app; use needs biometrics enforced by hardware | a rooted or jailbroken phone. Treat a phone that cannot pass attestation as untrusted: an unlocked bootloader or a failed boot is refused at enrollment, an Unverified boot state too unless the owner asks for it (`--allow-unverified-boot`, §5.2), and the config records the state. That is the phone as it was at enrollment; nothing re-checks it later. On a TEE-only phone, a bug in the trusted OS reaches the key; the app says so (§5.6) |
| T6 | **Our app itself is malicious or compromised** (supply chain, a bad update) | open source; minimal dependencies; release signing; the Android attestation names our signing certificate, which means something only on a system whose boot is verified (§5.2); a build to distribute cannot be made while no certificate is pinned or the package is provisional (§5.2); custody of the signing keys and release roles (`APP_ATTEST_ORG.md` §4) | it could show one operation and sign another. Mitigation by reproducible Android builds (P5); none on iOS beyond App Store review. Store distribution also puts the store operator in this root (Google signs Play builds, Apple re-signs App Store builds). The largest residual risk; say so in user docs |
| T7 | **A thief with the phone** | biometric only by default (D2); the key is invalidated by a new biometric enrollment | with the per-enrollment PIN opt-in, a thief who saw the PIN can sign. The opt-in says so when it is chosen |
| T8 | **Coercion** | out of scope | keep the recovery key with someone else, or in another place |
| T9 | **A biometric change or a reset** invalidates the key | expected, correct behaviour | availability: recovery is mandatory (`RESILIENCE.md`), stated at enrollment |
| T10 | **A lost phone** | the key is not extractable; recovery | as T9 |
| T11 | **Gas griefing** | the cost cap (§6.4) | up to the cap per approved operation |
| T12 | **Replay across chain, EntryPoint or account** | all three are inside `userOpHash`, and the phone pins them | none |
| T13 | **A signature over a chosen digest** (ERC-1271, permits) | no such message exists in the protocol; the health digest is co-randomized; `SHA256withECDSA` only through the plan-B envelope builder | the Android key allows `SHA256withECDSA`, so the app's code could use it to sign arbitrary messages. The protection is that code (T6), as for everything else the app does |
| T14 | **Downgrade** to an old protocol or app | version field; the CLI may require a minimum app and core version | none |
| T15 | **Forged attestation** (leaked attestation keys) | revocation list; attestation treated as evidence | a determined attacker with a leaked key can fake "StrongBox". It only matters if they also control enrollment |
| T16 | **Display confusion** (homoglyphs, bidirectional text, long labels) | ASCII-only labels; full addresses; addresses never replaced by labels | none known |
| T17 | **Removal of `DIGEST_NONE`** from Android | plan B (§11.1) | needs one `set-root` to a WebAuthn validator when it happens |
| T18 | **The phone's clock** | 5 minutes of tolerance; raw timestamps under details | a wrong clock misstates "valid until" relative to now; the dates themselves stay correct |
| T19 | **Pin poisoning at enrollment.** A laptop compromised at enrollment pins its own contracts or tokens, so later malicious installs look trusted | build-embedded deployments, version history and tokens; laptop pins only for unknown addresses, always marked unverified; laptop tokens in raw units (§6.7) | a new deployment the build does not know yet is shown as unverified, and the user must judge it. v2: the Registry (§14) |
| T20 | **A paymaster charges tokens** in `postOp`, beyond the ETH gas cap | v1 accepts only build-known paymasters that charge nothing (§6.4) | none in v1. Token-charging paymasters need their own decoder and cap |
| T21 | **v1 has no view of the chain.** The phone takes every chain fact from the laptop: which validator is root, whether its key still controls the account, balances, the current mandate | v1 shows only what it decodes and what its build knows, and says so | the ceiling of v1, stated on purpose. v2 is "the phone sees the chain" (§14) |

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
As built (2026-11): the Android key is created with both digests, but the
envelope builder and the cross-protocol test are not written.

The audit found no practical cross-protocol collision: a signature valid on
one validator would need a SHA-256 preimage to verify on the other. The
health digest is safe on the same grounds. Three requirements keep it so:
1. **One root validator at a time.** The switch to the WebAuthn validator
   is a `set-root` that retires `P256Validator` in the same operation.
2. **`SHA256withECDSA` only from `owner-core`'s envelope builder,** around
   a `userOpHash` the phone has reviewed; never over another
   `clientDataJSON` (§6.5).
3. **A cross-protocol test** (§9.4).

### 11.2 Other risks

- **iOS attestation is weaker than Android's** (§5.3). It binds the key to
  a genuine instance of our app, not to the Secure Enclave. Kept, and said
  plainly (D5).
- **App Store:** wallets only from developers enrolled as an organization,
  which needs a legal entity and a D-U-N-S number (V, guideline
  3.1.5(i), per `APP_ATTEST_ORG.md` §3, PR #6). P0–P4 and TestFlight do
  not need it. Development without any vendor account is covered by
  `MOBILE_DEV_MODE.md` (PR #7).
- **Minimum OS versions** (I): iOS 16 and Android 11 (API 30, needed for
  `setUserAuthenticationParameters`). That excludes some "old phones",
  which the business case mentions (D7).
- **Biometric class.** `BIOMETRIC_STRONG` (Class 3) excludes phones whose
  only sensor is Class 2, which includes many budget face-unlock
  implementations. Their users need the PIN opt-in or another phone (D2).
- **Not all phones have StrongBox.** The TEE is accepted and shown as such
  in the CLI output; the deployer decides.
- **Biometric only leans on recovery.** The condition for D2's
  biometric-only default (not for the PIN opt-in): the recovery path must
  be robust and tested before that default ships.

## 12. Decisions (owner, 2026-10-28)

Confirmed in the review of PR #5, with changes to D2 and D4 and the v1/v2
split added.

| # | Question | Decision |
|---|---|---|
| D1 | Transport for v1 | **LAN with the QR commitment.** The request format is transport-independent; the air-gapped mode comes later (§3.5). Confirmed |
| D2 | User verification | **Biometric only by default,** invalidated on a new biometric enrollment. **The device PIN (`DEVICE_CREDENTIAL`) is a per-enrollment opt-in.** Condition (audit Q6): the **biometric-only default** leaves recovery as the only way out after a broken sensor or a changed biometric, so the recovery path must be robust and tested before that default ships. The condition is on the default, not on the PIN opt-in |
| D3 | Keys | **One per account** (§5.1). Confirmed |
| D4 | Unknown external calls from the root key | **Refused by default.** A per-enrollment **expert mode**, off by default, allows them with a warning and a second confirmation stating the unbounded effect (§6.3) |
| D5 | iOS evidence | **App Attest,** with `--allow-no-attestation` kept. The organisational study comes before P3 (`APP_ATTEST_ORG.md`, PR #6) |
| D6 | Operations with `initCode` | **Refused in v1** (§5.5). Confirmed |
| D7 | Minimum OS | **iOS 16, Android 11.** Confirmed |
| D8 | Default gas cap | **0.005 ETH per operation,** adjustable per enrollment on the phone. Confirmed |
| D9 | Crate split | **A new `owner-core` crate,** pure Kernel encoding moved out of `agent-signer`. Confirmed; its licence follows the mobile licensing study (§7.1) |
| v1/v2 | Scope | **v1:** build-embedded pins with laptop pins labelled, LAN only, handover decoded on a phone. **v2, "the phone sees the chain",** as one feature (§14) |

## 13. Mapping to the phases

| Phase | From this spec |
|---|---|
| P0 spike | §5.2 or §5.3 key creation and signing on one platform; a golden request's hash signed and verified on anvil; plan B's envelope checked against the WebAuthn validator on anvil, with the cross-protocol test |
| P1 enrollment + blind signing | §3, §4, §8 (the session, the key spec, the trait method, single signing with a 64-byte placeholder and the margin); `--expect-fingerprint`; simulator tests in §9.4; the display may still be minimal |
| P2 decode + display | §6 and §7 in full, including build-embedded pins, every gas field, the paymaster rule and expert mode; golden, tamper and fuzz tests |
| P3 attestation | §5.2 verification with both Google roots and the channel's digest; §5.3 App Attest with the channel and version checks; the revocation check. Prerequisite: the App Attest study (PR #6) |
| P4 second platform | P0–P2 on the other OS, with the same `owner-core` |
| P5 distribution | TestFlight and APK, reproducible Android builds, user documentation on T6 and recovery. Prerequisites: the licence study for the apps and `owner-core`, and, for the App Store, an organization account |

## 14. v2: the phone sees the chain

Everything in T19 and T21, and the residual of T2, comes down to the phone
having no view of the chain. v2 gives it one, and ships these three parts
together, because each needs the same thing:

1. **An on-chain Registry** of the project's deployments, owned by a
   multisig, with an **asymmetric timelock**: additions take effect after a
   delay of days, removals and revocations immediately. Its events, and
   "registered N days ago" on the phone's screen, give time to notice a bad
   entry. A Registry entry means "the project vouches for this", never
   "this is safe"; the user still reads the address. The phone combines
   it with the build snapshot: the snapshot for what it knows, the Registry
   only for what it lacks, laptop pins still marked unverified.
2. **Codehash pins.** For each build-known contract, the address **and**
   its `EXTCODEHASH`, so the phone catches a code swap, not only an address
   swap. Only for non-proxy singletons. `P256Validator`, `P256Signer` and
   `AgentPolicy` are believed to be non-proxy (I); confirm before relying
   on it.
3. **On-chain root and handover checks.** After a handover, and from time
   to time, the phone checks that `P256Validator.publicKeys(account)` is its
   own key, that the root validator is the pinned `P256Validator`, and the
   list of installed validators.

**Trust in the reads:** the phone asks a **2-of-3 quorum of independent
public RPC providers**, so one lying provider is not enough. A mobile light
client is the later upgrade; v2 does not wait for it.

**Cost:** the phone app needs network access to RPC providers, which v1
avoids. v2 therefore makes it an option per enrollment.
