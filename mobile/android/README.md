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
                         # OWNER_CORE_FEATURES=ffi,test-chains for a development phone that signs on the local anvil
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n dev.tpmsign.owner.spike/.MainActivity
```

Only the debug build exists for now. A release build is one that can be
handed to someone, and Gradle refuses it while the application id is the
provisional `.spike` one or the core was built with `test-chains`
(`app/build.gradle.kts`, issue #35):

```
$ ./gradlew assembleRelease
not a build to hand to anyone:
  - the application id dev.tpmsign.owner.spike is provisional: the package is the owner's decision (docs/APP_ATTEST_ORG.md §8)
  - owner-core was built with test-chains: run ./build-core.sh without OWNER_CORE_FEATURES
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
response. The P0-key fallback is gone: an account must be enrolled. The QR
is parsed by the core too (`parseQr`, which refuses loopback on the phone).

Since 0.2.0-p2 the core names the project's contracts from the table it
embeds (`owner-core/src/facts.rs`, design §6.7): on Base Sepolia the
canonical deployments and USDC; in a development build
(`OWNER_CORE_FEATURES=ffi,test-chains`) also the CLI's local anvil chain,
and the launch line then shows `+test-chains`. Where the build has no
facts the review errs on the side of emphasis and refusal, as before.
Button 4 opens the enrollment through the core (`openEnrollment`): the
dialog lists the laptop's pins as unverified names and the ones ignored
because the app knows those addresses itself, and says when the app has
no facts for the chain. The review dialog renders the core's sections
with titles and effects in bold, and its Sign button is enabled only once
the text has been scrolled to its end (§6.6).

### P2 run record — the phone decodes, recomputes and signs (2026-11-12, app 0.1.0-p2)

The same script. The phone enrolled a new key (fingerprint over USB), root
was handed to it, and on the second QR the app showed the review built by
owner-core on the phone — the call `increment()` on the counter's address,
the maximum gas cost, every hash-covered field — and signed the
`userOpHash` the core recomputed; the laptop verified that signature over
its own hash, so the two parses agreed byte for byte:

```
phone:          signed, signature verified against the owner key
path:           root (owner key)
included: tx 0xbd1b018c40b624002dde0c82189a20c8e402ba0e1c2cea7c4d3918cda3bf0ac4 (block 5, 126989 gas)
phone-signed root operation included on anvil; the agent still runs:
test phone_owner_real_device ... ok
```

## Showing a key, and keeping one (version 0.4.0-p4, issue #38)

An enrollment could end with the laptop saying "enrolled" and the phone
having deleted the key: the laptop's confirmation lost on the way, or
replaced by a host on the path, which needs no secret. The handover then
gave root to a key nobody held. Two changes in the app, one on the laptop:

- **The key is kept.** A missing or foreign reply to the enrollment answer
  says nothing about what the laptop has, so the app keeps the key as
  unconfirmed and says so in a dialog of its own: the first device run
  showed that a line in the log, under the fingerprint dialog, is not
  seen. Only a key that never left the phone (its
  creation failed) is deleted. An unconfirmed key is replaced by the next
  enrollment of the same account, after the owner's yes.
- **The phone can show a key** (design §2.2, §2.4). Either scan button
  answers a `health-request`: the core checks it and decides whether this
  phone can answer, the dialog says which key and account, and after the
  fingerprint the key signs `sha256("TPM_sign/v1/health" ‖ laptopNonce ‖
  phoneNonce)`, with a nonce the core draws. It is never an operation. A
  key the phone has shown is confirmed from then on: the laptop may make
  it root on that answer.
- **The laptop asks before the handover**: `owner set-root … --to-phone
  <label>`, and `key check --phone <label>` at any time. The CLI accepts
  this app from version code 11.

### Run record — the key shown before the handover (2026-11-13, app 0.4.0-p4)

The real-device test on the same TEE-only phone, three QR codes: the
enrollment, the phone showing the key, a signature. Private values are
masked. The enrollment, now with the boot state and the handover's flag:

```
enrolled phone owner key "owner-phone" for account 0x38c09e253D5351767D6A512b3ed7dEd10B049A29 (chain 31337)
  public key     x = 0x5665…1dff
                 y = 0x181d…d8a7
  fingerprint    2V7PJ-3M6BV-TAXVQ-7TH6L   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level tee — the processor's trusted mode, not a separate secure chip (attested)
  attestation    verified: 5 certificates to Google's remote-provisioning root (P-384); made for this request; the key is the one above; generated in the hardware, signs only after a biometric check
  made by        dev.tpmsign.owner.spike version code 11, signing certificate <sha256 of the developer's debug certificate> (accepted by --android-app-digest)
  boot state     verified (the phone's operating system, as its verified boot reports it)
  revocation     none of the chain is on Google's list (1773 entries, fetched now)
  note           attestation is evidence of where the key lives, not of whose phone it is; that is the QR's secret
  app            android 0.4.0-p4 (core 0.3.0+test-chains)

Nothing changed on-chain. Next, signed by the current owner key:
  agent-signer owner set-root --agent …/owner.json --validator <P256Validator> --public-key 0x5665…1dff,0x181d…d8a7 --expect-fingerprint 2V7PJ-3M6BV-TAXVQ-7TH6L --to-phone owner-phone [--retire <validator>]
--to-phone makes the handover wait for the phone: one more QR, on which the phone shows that it holds this key.
Do not hand root to a phone key without it: if the phone did not keep the key, the account goes with it.
then point the config's owner at the phone (ownerPublicKey stays the account's creation key):
{ "owner": { "phone": { "label": "owner-phone", "platform": "android", "attestation": "tee", "revocation": "checked",
                        "bootState": "verified", "deviceCredential": false,
                        "publicKey": { … }, "fingerprint": "2V7PJ-3M6BV-TAXVQ-7TH6L" } } }
```

The handover, which waited for the phone (the second QR: "Show the key",
then the fingerprint), and the signature after it:

```
new root key:   fingerprint 2V7PJ-3M6BV-TAXVQ-7TH6L
…
tpmsign:1?u=http://192.168.x.x:54783/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
phone:          holds the key 2V7PJ-3M6BV-TAXVQ-7TH6L (signed a fresh digest)
nonce:          0x1
…
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x556c…546d (block 4, 171228 gas)

root handed to the phone key 2V7PJ-3M6BV-TAXVQ-7TH6L.
…
phone:          signed, signature verified against the owner key
added permission 0x74657332 (valid 0 … 1826105903): tx 0x21f7…f564 (block 5, 399078 gas)
the permission the phone installed is on-chain; the agent runs under it:
test phone_owner_real_device ... ok
```

Nothing was built or sent for the handover before the phone's answer: the
`nonce` line of the `set-root` operation comes after `phone: holds the
key`.

### Run record — the laptop's confirmation lost on the way (2026-11-13, app 0.4.0-p4)

The same test with `TPMSIGN_PHONE_PATH_ATTACKER=1`: a stand-in for a host
on the network shows its own QR in place of the laptop's, forwards the
phone's requests to the laptop untouched and replaces the laptop's reply
to the enrollment answer. The laptop accepted the enrollment; the phone
got no confirmation, so its key stayed unconfirmed.

```
(this QR leads to a host on the path, not to the laptop; waiting for the phone…)

enrolling phone owner key "owner-phone" for account 0xD4aB6e91eBCc742fd034Ee0fbe3BDFe3DFaAd713 on chain 31337: …
waiting up to 180s for the phone…
enrolled phone owner key "owner-phone" for account 0xD4aB6e91eBCc742fd034Ee0fbe3BDFe3DFaAd713 (chain 31337)
  fingerprint    2GIQE-7OPFS-4IGNR-I23XP   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level tee — the processor's trusted mode, not a separate secure chip (attested)
  …

A host on the path replaced the laptop's reply: the laptop says "enrolled" above, the phone saw no confirmation
and says so. It must have kept the key all the same.

Before root goes to the phone's key, the phone shows that it holds it: scan the QR below and confirm on the phone.

new root key:   fingerprint 2GIQE-7OPFS-4IGNR-I23XP
phone key "owner-phone" for account 0xD4aB6e91eBCc742fd034Ee0fbe3BDFe3DFaAd713 on chain 31337: scan this with the owner app and confirm there. The phone shows that it holds the key 2GIQE-7OPFS-4IGNR-I23XP; nothing goes to the chain.
tpmsign:1?u=http://192.168.x.x:58687/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
phone:          holds the key 2GIQE-7OPFS-4IGNR-I23XP (signed a fresh digest)
…
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x4bdf…d8a6 (block 4, 171240 gas)

root handed to the phone key 2GIQE-7OPFS-4IGNR-I23XP.
…
phone:          signed, signature verified against the owner key
added permission 0x74657332 (valid 0 … 1826106472): tx 0xa404…4d86 (block 5, 399078 gas)
test phone_owner_real_device ... ok
```

So the Keystore key that the app kept without the laptop's confirmation
was shown to the laptop, became root and signed. With the app before
0.4.0 the key would have been deleted at the first step and root handed
to it regardless. The phone's own words for the unconfirmed enrollment
were only a line in its log, under the fingerprint dialog, and the person
running the test did not see them. The app now says it in a dialog.

The run was repeated with that build (account
0xCd6e30783b6fe51c0722Dba1363dc8F8F2b5B8b3, key SMSGE-22ERB-P2SES-E3PZF,
the same lines and the same outcome): right after Enroll the phone showed
"The laptop did not confirm this enrollment" on top of the fingerprint
dialog, it was acknowledged, and the key was then shown, made root and
used to sign. An earlier attempt of that run was abandoned at the second
QR, whose session of 180 seconds ran out while the person was away from
the phone; the handover then stops with "no answer from the phone",
nothing is sent, and the phone is left with one more unconfirmed key for
an account that no longer exists.

## P3: authenticated answers (version 0.3.1-p3)

The QR now carries the session's secret (`&k=…`, design §3.2). The core's
`parseQr` returns it, the app keeps it in memory for the session only, and
every POST — a signature, a refusal, an enrollment answer — carries
`X-TpmSign-Mac`, computed by the core's `answerMac` over the exact body.
The laptop ignores an answer without it, and answers an accepted one with
a confirmation MAC under the same secret: the app keeps a new key only on
that (`verifyConfirmation`), never on a bare `200`, and shows the laptop's
reason when an answer is turned down. The laptop still asks for the
fingerprint at enrollment by default, so the dialog says "type"; with
`--phone-skip-fingerprint` nothing is typed. The app needs agent-signer of
the same version: a QR without `k` is refused.

### P3: what the laptop checks in the attestation

The app has returned the Keystore's certificate chain since P1. From P3 on
`agent-signer key create --phone` verifies it (design §5.2) before it
accepts the answer: the chain to Google's root, the challenge bound to the
enrollment request, the key itself, where it lives (StrongBox or TEE), that
it was generated there and signs only after a biometric check, the locked
bootloader, and which app made it. A refusal ends the session with its
reason and the app deletes the key.

The phone's verified boot state decides how much "which app made it" is
worth, since the operating system is what names the app (issue #35).
Verified: accepted. SelfSigned, a custom system on a locked bootloader
such as GrapheneOS: accepted with a warning. Unverified: refused, unless
the enrollment passes `--allow-unverified-boot`, which gives up the app's
identity and the trust in the screen the fingerprint is read from; the
hardware facts still hold. Failed: refused. The result prints the state
(`boot state     verified`) and the config snippet records it
(`"bootState"`), beside `"attestation"` and `"revocation"`.

The attestation names the certificate the app was signed with. A debug
build is signed with the developer's own debug key, which no CLI can pin,
so the developer names it: the CLI prints the digest it saw when it
refuses, and `--android-app-digest <sha256>` accepts it. For the
real-device test, `TPMSIGN_ANDROID_APP_DIGEST` carries it. To check a kept
enrollment again offline:

```sh
cd signer
TPMSIGN_ATTESTATION_DIR=<dir written by --out> TPMSIGN_ANDROID_APP_DIGEST=<sha256> \
  cargo test -p agent-signer a_real_enrollment -- --ignored --nocapture
```

Phones with remotely provisioned attestation keys carry a certificate that
lives about two weeks, so that check uses the request's own time.

### P3 run record — an authenticated, attested enrollment (2026-11-13, app 0.3.1-p3)

The same script on the P3 stack after its review. The QR carried the
session's secret, which the terminal no longer prints; the phone's
answers carried their MAC; the laptop verified the key attestation and
the revocation list before it accepted the enrollment, and answered with
its own MAC, on which alone the app kept the key. The script passes
`--phone-skip-fingerprint`, so nothing was typed; without it the CLI asks
for the fingerprint. The enrollment:

```
tpmsign:1?u=http://192.168.x.x:52726/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
enrolled phone owner key "owner-phone" for account 0x90aB6a48975CE55297c9A35CBC77F63f049E9716 (chain 31337)
  public key     x = 0x7e5d…ac2b
                 y = 0x45cc…b1ba
  fingerprint    DKIWB-JLPIT-FGQ6T-MQYZA   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level tee — the processor's trusted mode, not a separate secure chip (attested)
  attestation    verified: 5 certificates to Google's remote-provisioning root (P-384); made for this request; the key is the one above; generated in the hardware, signs only after a biometric check
  made by        dev.tpmsign.owner.spike version code 10, signing certificate <sha256 of the developer's debug certificate> (accepted by --android-app-digest)
  revocation     none of the chain is on Google's list (1773 entries, fetched now)
  note           attestation is evidence of where the key lives, not of whose phone it is; that is the QR's secret
  app            android 0.3.1-p3 (core 0.2.0+test-chains)

Nothing changed on-chain. Next, signed by the current owner key:
  agent-signer owner set-root --agent …/owner.json --validator <P256Validator> --public-key 0x7e5d…ac2b,0x45cc…b1ba --expect-fingerprint DKIWB-JLPIT-FGQ6T-MQYZA [--retire <validator>]
then point the config's owner at the phone (ownerPublicKey stays the account's creation key):
{ "owner": { "phone": { "label": "owner-phone", "platform": "android", "attestation": "tee", "deviceCredential": false,
                        "publicKey": { … }, "fingerprint": "DKIWB-JLPIT-FGQ6T-MQYZA" } } }
```

This is the output as that run printed it. The snippet has since gained
two records of what the result above already says, `"revocation":
"checked"` and `"bootState"`, and the result a `boot state` line; the run
was not repeated for them.

The handover followed, then the permission install, previewed on the
laptop and signed on the phone:

```
root handed to the phone key DKIWB-JLPIT-FGQ6T-MQYZA.

what the phone will show (owner-core 0.2.0+test-chains; pins as this config would send them now):
## Operation
Account: 0x90aB6a48975CE55297c9A35CBC77F63f049E9716
Chain: 31337
The laptop says: "owner operation (root)" (from the laptop — unverified)
## Call 1 of 2
Install agent permission: 0x74657332
Policy module: 0xdd544A6F0220778Fff16F51B468656e73E32ae85 — AgentPolicy (verified in this build)
Allow: 0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1 — demo counter (verified in this build) · increment (0xd09de08a)
Max value per operation: 0.000000000000001 ETH
Budget: 1 ETH
Valid from: now
Valid until: 2027-11-12 19:25:49 UTC (1826047549)
Signer module: 0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E — P256Signer (verified in this build)
Agent key: OIPTD-GKQWZ-L7OXL-IVB5C
Validation nonce: 2
## Call 2 of 2
Allow permission 0x74657332 to call: execute (0xe9ae5c53)
## Cost
Maximum gas cost: 0.001094076619631145 ETH
## Details
nonce: key 0 (root), sequence 2
verificationGasLimit: 300000
callGasLimit: 409065
preVerificationGas: 100000
maxFeePerGas: 1352272833 wei
maxPriorityFeePerGas: 1 wei
EntryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
expires: 2026-11-12 19:28:59 UTC (1794511739)
userOpHash: 0x4f0a98d711d3b38c164d54b79f110aebc13055145d4de6a571fc4fcb179dbfcc

tpmsign:1?u=http://192.168.x.x:52751/s/<token>&h=<commitment>&k=<in the QR only>
phone:          signed, signature verified against the owner key
path:           root (owner key)
added permission 0x74657332 (valid 0 … 1826047549): tx 0x67374e7b3cf25711fc822b16b6944e9ee6becc54a1d6c4acacc04bff4470a664 (block 5, 399078 gas)
the permission the phone installed is on-chain; the agent runs under it:
test phone_owner_real_device ... ok
```

That the phone signed at all shows the confirmation at work: the app
keeps a new key only when the laptop's reply is its MAC under the session
secret, and it had the key. The evidence the run kept was verified again
offline with the ignored test `a_real_enrollment`, with the same result.
An earlier run the same day, on the stack before its review, went the
same way with app 0.3.0-p3; it printed the session secret under the QR
and its enrollment answer said `core: none`, both since fixed.

### P2 run record — the phone names the mandate it signs (2026-11-13, app 0.2.0-p2)

The same script, with the app built as `OWNER_CORE_FEATURES=ffi,test-chains`
(launch line: `owner-core 0.2.0+test-chains loaded`). After the enrollment
and the handover, the operation was `permission add` for a new agent key.
The phone's review, built from the facts embedded in owner-core, showed the
install with its mandate; Sign became active at the end of the scroll; the
fingerprint signed; the agent then ran under the new permission:

```
phone:          signed, signature verified against the owner key
path:           root (owner key)
added permission 0x74657332 (valid 0 … 1826044451): tx 0x5f2ec1b3f9a31defc3375d82b656dd19928099130ee6b922ffc725b19ed63458 (block 5, 399078 gas)
the permission the phone installed is on-chain; the agent runs under it:
test phone_owner_real_device ... ok
```

The phone's log had rolled over before it could be read back, so the
screen's text is not quoted here. The laptop's preview before the QR is the
same review on the same embedded facts, and the anvil suite asserts its
rows for this operation: "Install agent permission", the policy and signer
modules "verified in this build", the allowed call on the demo counter, the
agent key's fingerprint.

### P2 run record, after review — a refusal and a payment (2026-11-12, app 0.1.0-p2)

With the review's rules from PR #30 and #31 on the phone and no build facts
yet, two runs of the same script:

- the counter increment was **refused on the phone**, and the laptop
  printed the phone's reason verbatim, before anything was signed:

  ```
  Error: key unavailable: phone "owner-phone": the phone refused: core (a call to 0x… with
  function 0xd09de08a this version cannot decode; from the root key it can move everything the
  account holds (expert mode is off))
  ```

- a payment of 0.001 ETH to an address the build does not know was shown
  in bold, needed the second confirmation, then the fingerprint, and
  landed:

  ```
  phone:          signed, signature verified against the owner key
  included: tx 0x4efc7ada24cbbefe054772bd9aa07b3b75c862c1c229dcf1174fc982a3b861b5 (block 5, 151714 gas)
  test phone_owner_real_device ... ok
  ```

The real-device test now sends that payment; the increment comes back
once slice 3 lets the phone know the counter.

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
app's pending record through `--phone-fingerprint-cmd`, a development flag
that was removed in P3, when the session secret made the typing optional):

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
