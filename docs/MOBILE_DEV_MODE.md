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
| Key attestation | **full** (Google's hardware attestation chain, our certificate digest pinned); verifiable offline, but the revocation check and some phones' certificate refresh need internet occasionally (§2.4) | **none** (no App Attest) |
| Lifetime of an install | unlimited | **7 days**, then rebuild and reinstall |
| Devices | any number | 3 per Apple Account |
| Fit | development and pilots; the trust-minimising path | development and the developer's own phone only |

**Android plan B is the trust-minimising path** (the auditor's term from the
PR #6 review): the app's identity rests on our code and our key, with no
Google or Apple in it. **Operationally it is development- and pilot-grade,
not production-grade:**
- there is no automatic update, so a security fix cannot be pushed to
  testers;
- installing needs an `adb`-authorised laptop (§2.3).

**iOS plan B is a development mode**, useful for P0–P4 on the developer's
own iPhone, not for distribution.

## 2. Android

### 2.1 What is needed

| Item | What | Mark |
|---|---|---|
| Laptop | Linux, macOS or Windows; the one that runs the CLI is fine | — |
| Phone | Android 11 (API 30) or later, which `setUserAuthenticationParameters` needs (D7); StrongBox preferred, the TEE accepted. User verification is `BIOMETRIC_STRONG` by default, or `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` with the PIN opt-in (D2); development builds should exercise both | V (design D7, D2) |
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
- **Keep the signing key on a token. This is recommended for any real
  use.** `apksigner` can sign through a PKCS#11 provider, for example a
  YubiKey's PIV slot (sound per the audit; the setup is I, P1). The app's
  signing key is then as hard to steal as the owner keys.
  - **Use a separate token** from the owner's YubiKey (`PHONE_OWNER.md`,
    `OWNER_DEVICES.md`), or at least a separate slot with its own PIN.
  - Otherwise one lost or compromised device hits both the app's integrity
    (T6) and owner control.
- **Check the version.** The attestation's `attestationApplicationId` also
  carries the app's `versionCode`. The CLI refuses versions below a
  minimum: T14, the Android twin of the iOS version check in
  `APP_ATTEST_ORG.md` §2.

**The signing key plays two roles, more than in the store path:**
- Android installs an update only if it is signed by the same key (or by
  a successor in a v3 rotation lineage).
- **Losing the key hurts availability.** It means a new app id, so every
  phone uninstalls the old app. **Uninstalling deletes its Keystore keys**,
  so every enrolled account goes through recovery (`RESILIENCE.md`).
  Mitigation: an encrypted offline **backup**, as for the recovery key,
  plus a v3 **rotation lineage** as the planned way to replace the key
  (I, P1).
- **A compromised key breaks integrity (T6).** An attacker with the key
  can ship a malicious update with the same key through `adb install -r`.
  That update inherits the app's access to the Keystore keys, so it can
  show one operation and sign another. The per-use biometric does not
  help, because the user approves what is shown. Mitigation: the key on a
  **token** (non-extractable), and **reproducible builds** (§2.5), so a
  verifier can catch a build that does not match the tagged commit.

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

**Turn debugging off after every install. This is mandatory.** The
`adb`-authorised laptop is the CLI's laptop, which the design treats as
untrusted (T1).
- It cannot forge an update, because it lacks the signing key.
- But while debugging is on, it can `adb uninstall` the app. That wipes
  the Keystore keys and forces recovery.

So debugging is a transient trust surface: open it for the install, then
close it, and revoke the USB debugging authorisations. Debugging can be
turned off only on the phone, so any install helper we write ends by
printing that reminder.

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
  APK, so a security fix reaches a tester only when they install it. This
  is the main operational gap compared with a store.
- **No store review.** Store review was never a real safeguard against T6.
  Plan B relies on **reproducible builds** instead, so a tester can
  rebuild from the tagged commit and compare.
  - **This protection is conditional.** It covers only someone who
    actually rebuilds and compares.
  - A tester who installs a shared APK without checking has no more T6
    protection than in the store path.

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
  access control of `.privateKeyUsage` and `.biometryCurrentSet`, or
  `.privateKeyUsage` and `.userPresence` (biometry or passcode) with the
  PIN opt-in (D2). Development builds should exercise both.
- **Store** its `dataRepresentation` in the app's own files. That is an
  encrypted handle that only this phone's Secure Enclave can use, not the
  key itself.
  - It is the same as a keychain item for extraction. The Secure Enclave
    enforces the biometric gate on the key either way.
  - **Mark the file excluded from backup** (`isExcludedFromBackup`). A
    plain file goes into iCloud and computer backups by default. The
    handle is useless off the device, but the backup would still leak
    which accounts this phone controls, and it costs no availability.
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
| Who is in T6's trust root | our code + the release roles + Apple (re-signing) and Google (Play App Signing) | **our code + our signing key** on Android: its loss costs availability, its compromise costs integrity (§2.2); on iOS our code + the developer's Apple Account |
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
- **The Android signing key is a single point of failure**, both ways.
  Its loss forces recovery on every enrolled phone; its compromise allows
  a malicious update. Keep it on a token, back it up, plan its rotation
  (§2.2).
- **No automatic updates.** A fix reaches testers only when they install
  it (§2.5).
- **Wireless debugging** left on is an attack surface. Turn it off after
  use (§2.3).
- **The `DIGEST_NONE` deprecation** (design §11.1) is the same in both
  plans.

## 8. Open questions for the owner

1. **Is plan B the default for development and the Android pilot,** with
   plan A only when iOS distribution is needed?
2. **Where the Android signing key lives.** Recommended for any real use:
   a YubiKey PIV slot plus an offline backup. A plain file is acceptable
   for development only (§2.2).
3. **Which free Apple Account** the iOS development uses: a project
   account, not a person's main one, so a departure does not take the
   Team ID with it.

*Reviewed by the auditor on 2026-10-28: no blocker. Folded in: the
operational qualification of Android plan B, the mandatory end of
debugging, the Android version floor, the signing key's integrity role,
the exclusion of the iOS key handle from backups, and the conditions on
reproducible builds and offline attestation.*

## Sources

- Android Developers Blog, [Android developer verification: rolling out to all developers](https://android-developers.googleblog.com/2026/03/android-developer-verification-rolling-out-to-all-developers.html) (2026-03)
- Android Authority, [How to bypass Android developer verification](https://www.androidauthority.com/how-to-bypass-android-developer-verification-sideloading-rules-3718002/)
- Bayton, [Key attestation root certificate change](https://bayton.org/android/android-enterprise-faq/key-attestation-root-certificate-change/)
- Apple, [QA1915: a Personal Team cannot sign for App Store submission](https://developer.apple.com/library/archive/qa/qa1915/_index.html)
- Apple Developer Forums, [Bundle IDs and limiting apps deployed on a testing phone](https://developer.apple.com/forums/thread/724896)
