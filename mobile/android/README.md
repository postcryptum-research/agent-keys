# Android owner app — P0 spike, P1 signing loop

The first phase of [`docs/MOBILE_OWNER_PLAN.md`](../../docs/MOBILE_OWNER_PLAN.md):
does the phone's secure hardware sign a raw 32-byte digest with a P-256 key,
behind a biometric check, in the form `P256Validator` accepts? One screen,
three buttons, no network permission. The design is
[`docs/MOBILE_OWNER_DESIGN.md`](../../docs/MOBILE_OWNER_DESIGN.md); this app
implements §5.2 (key parameters) and §5.6 (the StrongBox / TEE notice) and
nothing of the protocol yet.

**Licence: not decided** — the same study as `mobile/owner-core`
(`docs/MOBILE_LICENSE_STUDY.md`). The application id `dev.tpmsign.owner.spike`
is provisional (`docs/APP_ATTEST_ORG.md` §8).

## Build and run (plan B, no vendor accounts: `docs/MOBILE_DEV_MODE.md`)

```sh
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools   # or your SDK
export JAVA_HOME=$(/usr/libexec/java_home -v 21)                   # JDK 17 or 21
cd mobile/android
./build-core.sh          # owner-core for arm64 + its Kotlin bindings (cargo-ndk, the NDK; CARGO="cargo +1.94" if needed)
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n dev.tpmsign.owner.spike/.MainActivity
```

On the phone: **1. Create the owner key** (the notice tells you the tier),
then **2. Sign the golden digest** and put your finger on the sensor. Then:

```sh
adb pull /sdcard/Android/data/dev.tpmsign.owner.spike/files/ ./p0-out/
cd ../../signer && cargo run -p agent-signer -- verify --file ../mobile/android/p0-out/files/p0-vector.json   # OK
```

The vector has the layout of `contracts/test/vectors/*.json`; `attest-*.der`
is the key's attestation chain, verified against Google's roots on the laptop
(§5.2). Neither file goes into the repository from a personal phone.

## Run record — P0 on a TEE-only phone (2026-11-07)

Android 16 (API 36), no StrongBox feature, a Class 3 fingerprint sensor.
The phone's make, model and patch level are left out on purpose (plan rule).
Install: the vendor's "Installation via USB" guard refused `adb install`, so
the APK was pushed to `Download/` and installed from the Files app.

```
StrongBox feature: false
BIOMETRIC_STRONG available: true (code 0)
StrongBox unavailable (Failed to generated key pair.); retrying in the TEE
key created; tier by creation path: tee
isInsideSecureHardware: true
KeyInfo.securityLevel (API 31+): TRUSTED_ENVIRONMENT
user auth required: true, validity 0s, auth type 2
NOTICE — this phone keeps keys in its processor's trusted mode (TEE), not in a separate secure chip. …
attestation chain: 5 certificates
signed after biometric; DER 71 bytes
```

Laptop side (a scratch script, not in the repository):

| Check | Result |
|---|---|
| `agent-signer verify --file p0-vector.json` | `OK` |
| the vector through the RIP-7212 precompile (`cast call 0x…0100`, Base Sepolia) | returns 1 |
| low-s | true (normalized on the phone) |
| attestation chain | 5 certificates: `Android Keystore Key ← <TEE CA> ← Droid CA3 ← Droid CA2 ← Key Attestation CA1`; `openssl verify` against Google's published root → `OK`; the root is byte-identical to the second entry of `https://android.googleapis.com/attestation/root` (the remote-provisioning root) |
| attestation extension | `attestationVersion 400`, `attestationSecurityLevel TrustedEnvironment`, `keyMintVersion 400`, `keyMintSecurityLevel TrustedEnvironment`; `attestationChallenge` = `sha256("TPM_sign/P0/enroll")` |
| revocation | no certificate of the chain in Google's status list (1,771 entries that day) |
| `forge test --evm-version osaka` | the vector, committed as `contracts/test/vectors/p256_android.json`, passes `P256VectorTest.test_everyCommittedVector` and `P256ValidatorTest.test_androidVector_passesValidator` |

What this proves for P0: the phone's secure hardware signs a raw 32-byte
`userOpHash` with a P-256 key, only after a biometric check, in the exact
form `P256Validator` accepts; the laptop can verify from the attestation
where the key lives and which challenge it was created for. What it does not
yet do: the phone signs a **real** root operation on anvil through the CLI.
That needs the signing hook of the design's §8.3 (P1).

## P1: the signing loop with the laptop (2026-11-11)

Button **3. Scan the laptop's QR and sign** (version 0.0.2-p1): the app
scans the QR `agent-signer` prints for a `phone` owner key, refuses a
session host that is not a private / link-local address, fetches the sign
request, checks the SHA-256 commitment from the QR, checks the request's
shape (type, version, expiry, a root-path nonce, no `initCode`), shows the
account, nonce, calldata prefix and the laptop's `userOpHash`, signs that
hash with `NONEwithECDSA` behind the fingerprint prompt, and posts the
response. This is P1's **blind** signing: the phone does not yet decode the
calldata or recompute the hash itself — that is P2, with `owner-core` on
the phone through `uniffi`. A refused biometric prompt posts a refusal, so
the laptop stops at once instead of waiting for the timeout.

QR scanning is `zxing-android-embedded` + `zxing:core` (Apache-2.0); the
LAN session is plain HTTP, permitted in `res/xml/network_security_config.xml`
because the QR commitment provides the integrity (design §3.1). An update
of an already installed app goes through `adb install -r`; only a fresh
install trips the vendor's USB-install guard.

### P1: enrollment (version 0.0.3-p1)

Button **4. Enroll this phone for an account**: scan the QR that
`agent-signer key create --phone <label> --agent <cfg>` prints, same
transport and commitment check as a sign request. The app shows the chain,
the account, the label and the §5.6 notice for this phone's tier; on a
TEE-only phone the button reads "I understand, enroll". On yes it creates a
**new** key for that account (alias by chain and account, design §5.1) with
the attestation challenge `sha256("TPM_sign/v1/enroll" ‖ commitment)`
(§5.2), shows the key's **fingerprint** in a dialog that stays — the laptop
asks the owner to type at least its first two groups, because nothing else
authenticates an enrollment answer until P3 and a host in the path could
grind a one-group match — and posts the public key, the tier, and the
attestation chain as base64 DER. The laptop answers that POST only after
the owner confirmed the fingerprint there, so the app waits up to five
minutes for it. The enrollment record (§5.4: label, chain, account, tier,
key — nothing secret) is *pending* until the laptop answers 200; on any
failure (a timeout, a rejected answer, a tier the laptop would refuse) the
key and the record are deleted, so the account can be enrolled again; a
relaunch shows the fingerprint of a pending enrollment again. Confirmed records
are listed at launch, a missing key flagged. On no it posts a refusal.
Button 3 then signs with the account's enrolled key and, for now, falls
back to the P0 key for accounts enrolled by hand (to go with P2).

The laptop writes the enrollment (request, answer, `attest-*.der`) with
`--out <dir>`; verifying the chain there is P3.

## P2: owner-core on the phone (version 0.1.0-p2)

`build-core.sh` builds `mobile/owner-core` with `--features ffi` for
`arm64-v8a` through `cargo-ndk` (about 1.2 MB, into `app/src/main/jniLibs`,
not committed) and generates the Kotlin bindings with `uniffi` 0.32 into
`app/build/generated/uniffi` (a source set of the app). The bindings load
the library through JNA. The surface is design §7.2: `parseQr`,
`openRequest` → a `ReviewHandle` with `verdict`, `sections`, `text`,
`needsSecondConfirmation`, `effects`, `digestToSign`, `finish` and
`refuse`; `fingerprintOf`, `attestationChallenge`, `defaultGasCapWei`,
`coreVersion`.

Button **3** now does what §6 asks: owner-core parses the request once,
with the phone's confirmed enrollments as the enrolled accounts; a refusal
posts a refusal with the core's reason; otherwise the decoded operation is
shown in a dialog with one Sign action, bold effects get a second
confirmation in plain words, and the fingerprint prompt signs the
`userOpHash` the core recomputed — never the laptop's number. The core
converts the DER signature, normalizes low-s, verifies it and builds the
response. The P0-key fallback is gone: an account must be enrolled. The
build-embedded names of §6.7 are slice 3, so on the phone addresses show
in full without names today.

### P1 run record — a real root operation on anvil, signed on the phone

`~/… phone-anvil-run.sh` (the ignored test `phone_owner_real_device`, the
phone's P0 key as the owner of a fresh anvil account, the Mac and the phone
on one Wi-Fi), 2026-11-11, app 0.0.2-p1:

```
tpmsign:1?u=http://192.168.x.x:56181/s/<token>&h=<commitment>
waiting up to 180s for the phone…
phone:          signed, signature verified against the owner key
path:           root (owner key)
gas paid by:    the account
userOpHash:     0xa728e32c6a39e5b1c49f54772d2360878826cc6800c9c67e863ca56f7e95f32b
delivery:       self-bundled via handleOps
included: tx 0x139037bb13352c1ab52d3f27adf119eb2fd2e3188512ef39960efd5c4b1e2e41 (block 3, 144077 gas)

phone-signed root operation included on anvil; the agent still runs:
done.
test phone_owner_real_device ... ok
```

On the phone: the QR scanned at once, the review showed the account, nonce
and hash, the fingerprint prompt signed, `signed and posted: HTTP 200`.

### P1 run record — enrollment, handover, a phone-signed operation

The same script with app 0.0.3-p1, later on 2026-11-11: the test now
enrolls first. A fresh anvil account owned by a software key; the phone
enrolls a new key for it (button 4, the TEE notice acknowledged), the
laptop hands root to that key with the fingerprint check, the phone signs a
root operation (button 3), the agent still runs:

```
tpmsign:1?u=http://192.168.x.x:50324/s/<token>&h=<commitment>
waiting up to 180s for the phone…
enrollment written to …/enrollment (5 attestation certificates)
enrolled phone owner key "owner-phone" for account 0xdc0fa0c9AA445eFE417d1C07Da7CdA4a934072C6 (chain 31337)
  public key     x = 0xa6a22946b6546621392368bf5aeec01d2432ac5b871ad9d36fc13fb444c0eed5
                 y = 0x216799da099495a257f2a9fa0d92ea94dcf3195ab88ac6d46ee99e183c4bf585
  fingerprint    ZOLH5-D2DIS-66ZBB-4T6NL   ← compare with the phone's screen
  security level tee (self-reported)
  attestation    5 certificates; verification against the platform's roots is the next step (design §5.2), …
  app            android 0.0.3-p1 (core none)

Nothing changed on-chain. Next, signed by the current owner key:
  agent-signer owner set-root --agent …/owner.json --validator <P256Validator> --public-key 0xa6a2…eed5,0x2167…f585 --expect-fingerprint ZOLH5-D2DIS-66ZBB-4T6NL [--retire <validator>]
then point the config's owner at the phone (ownerPublicKey stays the account's creation key):
{ "owner": { "phone": { "label": "owner-phone", "publicKey": { … }, "fingerprint": "ZOLH5-D2DIS-66ZBB-4T6NL" } } }

root handed to the phone key ZOLH5-D2DIS-66ZBB-4T6NL.

phone owner "owner-phone": scan this with the owner app, review the operation, confirm.
key fingerprint: ZOLH5-D2DIS-66ZBB-4T6NL   userOpHash: 0x0dd703e590a76073d85f01a3a5159da0b0888355588867fa766c5e700f95865f
tpmsign:1?u=http://192.168.x.x:50362/s/<token>&h=<commitment>
phone:          signed, signature verified against the owner key
path:           root (owner key)
included: tx 0x5adc76bd46e3e9680fa57cc6dda6ca8fe37e10c76855cfa3cdf3847a6d061438 (block 5, 126989 gas)

phone-signed root operation included on anvil; the agent still runs:
test phone_owner_real_device ... ok
```

The phone showed the same fingerprint after enrolling, and listed the
enrollment at the next launch. The key enrolled here is a new Keystore
entry for that anvil account; the P0 key is untouched. The attestation
chain came back as five base64 DER certificates and was stored, not
verified: that check, with the challenge
`sha256("TPM_sign/v1/enroll" ‖ commitment)`, is P3. The test keeps the
evidence only when `TPMSIGN_PHONE_OUT` names a directory.

### P1 run record — the confirmed-fingerprint flow (2026-11-12, app 0.0.5-p1)

After the review of the enrollment PR: the laptop accepts an enrollment
answer only once the owner confirmed the fingerprint the phone shows, and
the app keeps the record pending until the laptop answers. Two things
surfaced on the real phone before this run passed, both fixed: the
fingerprint was printed only into the app's text area and was lost when
the activity was recreated (now a dialog that stays, and the pending record
keeps it); and the app gave its POST 10 seconds while the laptop held it
open during the prompt, so the app read the timeout as a refusal and deleted
the key (now the POST waits for the laptop's answer).

The run, with the fingerprint supplied over USB (`adb` reading the debug
app's pending record through `--phone-fingerprint-cmd`, development only):

```
waiting up to 180s for the phone…
an answer arrived; reading the fingerprint the phone shows through `…/phone-fingerprint-adb.sh`…
root handed to the phone key <fingerprint>.
…
phone:          signed, signature verified against the owner key
path:           root (owner key)
included: tx 0x1db3a33b4b6bc1a25231493a81957d4930a5c4d0b95912251980bbb2eed73dc3 (block 5, 126989 gas)
phone-signed root operation included on anvil; the agent still runs:
test phone_owner_real_device ... ok
```

Off-device, on the kept evidence (a preview of P3; a scratch check, not in
the repository):

| Check | Result |
|---|---|
| `openssl verify` of the five-certificate chain | `OK` against Google's remote-provisioning root (the second entry of `https://android.googleapis.com/attestation/root`), as in P0 |
| `attestationChallenge` in the key's certificate | equals `sha256("TPM_sign/v1/enroll" ‖ commitment)` recomputed from `enroll-request.json` |
| `attestationSecurityLevel`, `keyMintSecurityLevel` | both `TrustedEnvironment`, matching the answer's self-reported `tee`; `attestationVersion` and `keyMintVersion` 400 |
| `attestationApplicationId` | names the app's package |
