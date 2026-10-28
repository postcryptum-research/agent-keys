# Mobile owner app — plan B: development mode without vendors

*Study, 2026-10-28. This is the alternative to the organisational path in
[`APP_ATTEST_ORG.md`](APP_ATTEST_ORG.md) (PR #6). It asks: what can be
built and used with **only hardware, downloadable software and
self-signed certificates**? That means no company, no D-U-N-S number, no
paid developer programs and no app-store accounts. The design itself
(`MOBILE_OWNER_DESIGN.md`, PR #5) does not change; only the way the app
gets onto the phone and what attestation is available.*

Evidence marks: **V** verified at the linked source on 2026-10-28; **I**
inferred, to be confirmed in the phase named.

## 1. Summary

| | Android | iOS |
|---|---|---|
| Possible without any vendor account | **yes** | **no**. The minimum is a free personal Apple Account. There is no company, payment or store, but Apple is still involved |
| Signing | our own self-signed key | Apple's free "Personal Team" development certificate |
| Install | `adb install` from the laptop | Xcode, from a Mac, onto a phone in Developer Mode |
| Key attestation | **full** (Google's hardware attestation chain, our certificate digest pinned) | **none** (no App Attest) |
| Lifetime of an install | unlimited | **7 days**, then rebuild and reinstall |
| Devices | any number | 3 per Apple Account |
| Fit | development, pilots, and a serious trust-minimised path for real use | development and the developer's own phone only |

**Android plan B is nearly production-grade**: it is the auditor's
"trust-minimising path" from the PR #6 review. **iOS plan B is a
development mode**, useful for P0–P4 on the developer's own iPhone, not
for distribution.

## 2. Android

### 2.1 What is needed

| Item | What | Mark |
|---|---|---|
| Laptop | Linux, macOS or Windows; the one that runs the CLI is fine | — |
| Phone | Android 11 (API 30) or later, which `setUserAuthenticationParameters` needs (D7); StrongBox preferred, the TEE accepted | V (design D7) |
| Connection | a USB cable, or Wi-Fi debugging (`adb pair`, Android 11+) | V |
| Software | a JDK; the Android command-line tools (`sdkmanager`, `platform-tools` for `adb`, `build-tools` for `apksigner`); the NDK; Rust with `aarch64-linux-android` and `armv7-linux-androideabi`; `cargo-ndk`; `uniffi-bindgen`; Gradle. All free downloads, no account (the SDK licence is accepted in `sdkmanager`) | I, P0 |
| Signing key | a self-signed certificate made with `keytool` | V (Android signs only with self-signed certificates) |

### 2.2 Signing: our own key

- **Make the key once:** `keytool -genkeypair -keyalg EC -groupname
  secp256r1 -validity 10000 -keystore owner-app.jks …`.
- **Sign:** `apksigner sign --ks owner-app.jks app.apk`. Use APK Signature
  Scheme v2/v3.
- **Pin it.** The CLI pins the certificate's SHA-256 digest. The key
  attestation names it in `attestationApplicationId` (design §5.2), so the
  laptop knows the key belongs to **our** build, signed by **us**.
- **The signing key may live on a token.** `apksigner` can use a PKCS#11
  provider, for example the YubiKey's PIV slot (I, P1). Then the app's
  signing key is as hard to steal as the owner keys.

**The signing key is critical, more than in the store path:**
- Android installs an update only if it is signed by the same key (or by
  a successor in a v3 rotation lineage).
- **Losing the key** means a new app id, so every phone uninstalls the old
  app. **Uninstalling deletes its Keystore keys**, so every enrolled
  account goes through recovery (`RESILIENCE.md`).
- **Back up the key**, encrypted and offline, as the recovery key is
  (I, P1: the rotation lineage as the planned way to replace it).

### 2.3 Installing: ADB, exempt from Google's verification

Google now requires apps on **certified** Android devices to come from
**registered, verified developers**. Enforcement starts on 2026-09-30 in
Brazil, Indonesia, Singapore and Thailand, and goes global in 2027 (V,
[Android Developers Blog](https://android-developers.googleblog.com/2026/03/android-developer-verification-rolling-out-to-all-developers.html)).
For plan B:

| Way | Verification applies? | What it takes | Mark |
|---|---|---|---|
| **`adb install`** from the laptop | **no**: "ADB remains available" for unregistered apps | Developer Options and USB or Wi-Fi debugging; no waiting | V (Google) |
| The "advanced flow" on the phone | the user lifts it once per device | Developer Options → "Apps from unverified developers", restart, a **mandatory 24-hour wait**, then biometric confirmation; it stays lifted afterwards | V ([Android Authority](https://www.androidauthority.com/how-to-bypass-android-developer-verification-sideloading-rules-3718002/)) |
| The free "limited distribution" account (up to 20 devices) | registered | **a Google account**. Not plan B | V (Google) |

Recommended: **`adb install`** for development and pilots, and `adb
install -r` for updates, which keeps the app's data and keys.

Turn wireless debugging off after use. An open debugging session on the
owner's phone is an attack surface (T5).

**Risk:** the ADB exemption is Google's policy and can change (I). If it
narrows, the advanced flow remains, at the cost of the 24-hour wait once.

### 2.4 Attestation works fully

Android key attestation does not depend on how the app was installed. The
chain is issued by the phone's secure hardware and ends at Google's
hardware attestation root. That is the chip vendor's chain, not the
store's. The CLI verifies everything listed in design §5.2, offline:
- **Both roots are embedded in the CLI.** Since 2026-04-10, phones with
  remote key provisioning chain to a **new ECDSA P-384 root**. Phones keyed
  at the factory still chain to the **old RSA root**. Accept both (V,
  [Bayton](https://bayton.org/android/android-enterprise-faq/key-attestation-root-certificate-change/)).
- **`attestationApplicationId` holds our own certificate digest**, not
  Google's. Unlike the Play path (`APP_ATTEST_ORG.md` §7), Google is not in
  the app-identity part of the trust root.
- **Revocation list:** checked when online, skipped offline, and the result
  says so.
- **Phones with remote key provisioning** fetch their attestation
  certificates from Google from time to time, so the phone needs internet
  occasionally for attestation to keep working (I, P3).

### 2.5 What plan B gives up on Android

- **Ease of install:** testers need a cable or Wi-Fi debugging, or the
  advanced flow.
- **No automatic updates.** Updates are pushed by `adb` or shared as an
  APK.
- **No store review.** Store review was never a real safeguard against T6;
  plan B relies on **reproducible builds** instead, so a tester can
  rebuild from the tagged commit and compare.

## 3. iOS

### 3.1 The floor: a free personal Apple Account

**No legitimate way installs our own app on an iPhone without Apple.** Every
binary must be signed by an Apple-issued certificate. The least Apple
involvement is a **free personal Apple Account** in Xcode, the "Personal
Team": no company, no payment, no store. Excluded:
- **Jailbreaks and TrollStore** rely on iOS exploits and break T5;
- **AltStore and SideStore** still use an Apple Account and add a
  third-party service, so they gain nothing.

### 3.2 What is needed

| Item | What | Mark |
|---|---|---|
| A Mac | Xcode runs only on macOS. Apple silicon matches our Secure Enclave shim, verified on a Mac (`SECURE_ENCLAVE.md`) | V |
| iPhone | iOS 16 or later (D7), with **Developer Mode** on (Settings → Privacy & Security; needs a restart) | I, P0 |
| Software | Xcode (free); Rust with `aarch64-apple-ios` (and the simulator target); `uniffi-bindgen` | I, P0 |
| Account | a free personal Apple Account signed in to Xcode | V |

### 3.3 The Personal Team's limits

| Limit | Value | Mark |
|---|---|---|
| Lifetime of a provisioning profile | **7 days**; then the app stops launching until rebuilt and reinstalled from Xcode | I, P0 (widely reported; Apple does not publish a table) |
| Devices | 3 | I, P0 |
| Apps per device | 3 | I, P0 |
| New App IDs | 10 per 7 days | I, P0 |
| Capabilities | many are unavailable (push, iCloud, app groups, and others); **App Attest is not available** | I, P0 |
| App Store or TestFlight | not possible | V ([Apple QA1915](https://developer.apple.com/library/archive/qa/qa1915/_index.html)) |

### 3.4 The key: like our Mac shim, no keychain entitlement

The Personal Team may not get the `keychain-access-groups` entitlement
reliably (I). So plan B uses what the Mac backend already does (V,
`signer/crates/hw-signer/swift/SecureEnclaveShim.swift`):
- **Create** `SecureEnclave.P256.Signing.PrivateKey` (CryptoKit), with an
  access control of `.privateKeyUsage` and `.biometryCurrentSet`.
- **Store** its `dataRepresentation` in the app's own files. That is an
  encrypted handle that only this phone's Secure Enclave can use, not the
  key itself.
- **Sign** the 32-byte digest, as in the design (§5.3).

**Reinstalls and the 7-day expiry.** Reinstalling from Xcode over the
expired app, with the same bundle id and the same team, should keep the
app's files and therefore the key handle (I, P0). **Deleting the app
deletes the handle**, and then the account goes through recovery.

### 3.5 Attestation: none

No App Attest. A Personal Team build would be category 3, "development",
anyway, which PR #6 says the CLI must not trust for real accounts. So:
- the enrollment uses `--allow-no-attestation` (design §8.2);
- **the handover check from a third device (T2) is mandatory**;
- the CLI marks such enrollments "no attestation — development mode".

## 4. Certificates and transport

Plan B needs **one self-signed certificate**: the Android signing
certificate (§2.2). Nothing else needs one:
- **The LAN session** is plain HTTP. Its integrity comes from the QR
  commitment, and every signature is checked against the owner's public
  key (design §3). No TLS, so no certificate to install on the phone.
- **iOS** uses the certificate Xcode issues to the Personal Team.

## 5. Plan A and plan B side by side

| | Plan A (organisation, `APP_ATTEST_ORG.md`) | Plan B (this document) |
|---|---|---|
| Legal entity, D-U-N-S | needed (App Store wallet rule) | none |
| Accounts | Apple Developer Program (organization); Play Console | Android: none. iOS: a free personal Apple Account |
| Who is in T6's trust root | our code + the release roles + Apple (re-signing) and Google (Play App Signing) | **our code + our signing key** on Android; on iOS our code + the developer's Apple Account |
| Android attestation | full; Google's digest for Play builds | **full, our own digest** |
| iOS attestation | App Attest, channel-filtered | **none** (`--allow-no-attestation` + T2) |
| Distribution | stores, TestFlight | `adb` / APK files; Xcode to own devices |
| Who can use it | anyone | technically capable users; iOS: only the developer |

## 6. Phases under plan B

| Phase | Under plan B |
|---|---|
| P0 spike | **fully**, on both platforms |
| P1 enrollment and blind signing | **fully** |
| P2 decode and display | **fully** |
| P3 attestation | **Android fully**; iOS: none, by construction |
| P4 second platform | **fully** (iOS limited to the developer's own phone) |
| P5 distribution | **Android:** signed APK plus reproducible build, installed with `adb` or the advanced flow. **iOS:** not possible; that needs plan A |

So plan B carries the whole development and an Android pilot without any
organisational step. Plan A is needed only for iOS beyond the developer's
own phone, and for store distribution.

## 7. Risks

- **Google's sideloading policy** may narrow further. The `adb` exemption
  is a policy, not a technical guarantee (I).
- **Apple's free-tier limits** have tightened before (I) and may again.
- **The Android signing key is a single point of failure** for updates, and
  so for every enrolled phone (§2.2). Back it up and plan its rotation.
- **Wireless debugging** left on is an attack surface. Turn it off after
  use (§2.3).
- **The `DIGEST_NONE` deprecation** (design §11.1) is the same in both
  plans.

## 8. Open questions for the owner

1. **Is plan B the default for development and the Android pilot,** with
   plan A only when iOS distribution is needed?
2. **Where the Android signing key lives:** a file plus an offline backup,
   or a YubiKey PIV slot plus a backup.
3. **Which free Apple Account** the iOS development uses: a project
   account, not a person's main one, so a departure does not take the
   Team ID with it.

## Sources

- Android Developers Blog, [Android developer verification: rolling out to all developers](https://android-developers.googleblog.com/2026/03/android-developer-verification-rolling-out-to-all-developers.html) (2026-03)
- Android Authority, [How to bypass Android developer verification](https://www.androidauthority.com/how-to-bypass-android-developer-verification-sideloading-rules-3718002/)
- Bayton, [Key attestation root certificate change](https://bayton.org/android/android-enterprise-faq/key-attestation-root-certificate-change/)
- Apple, [QA1915: a Personal Team cannot sign for App Store submission](https://developer.apple.com/library/archive/qa/qa1915/_index.html)
- Apple Developer Forums, [Bundle IDs and limiting apps deployed on a testing phone](https://developer.apple.com/forums/thread/724896)
