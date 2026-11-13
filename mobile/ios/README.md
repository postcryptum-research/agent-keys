# iPhone owner app — P4

The second platform of [`docs/MOBILE_OWNER_PLAN.md`](../../docs/MOBILE_OWNER_PLAN.md)
(phase P4): the same loop as `mobile/android`, on the same `owner-core`. A
QR opens a session with the laptop; the core checks the request, decides
the verdict and gives the screen and the digest from one parse; the key
signs that digest; the laptop's confirmation is the only thing that makes
an enrollment permanent. The design is
[`docs/MOBILE_OWNER_DESIGN.md`](../../docs/MOBILE_OWNER_DESIGN.md) (§2,
§5.3, §6.6); development without an Apple organisation is
[`docs/MOBILE_DEV_MODE.md`](../../docs/MOBILE_DEV_MODE.md) §3.

**Status (2026-11-13): it passes the loop in the iOS simulator and on an
iPhone**, end to end against the real CLI on a local anvil. On the phone
the key lives in the Secure Enclave and signs after Face ID; the QR comes
through the camera. Nothing has run on Base Sepolia.

**Licence: not decided** — the same study as `mobile/owner-core`
(`docs/MOBILE_LICENSE_STUDY.md`). The bundle id `dev.tpmsign.owner.spike`
is provisional (`docs/APP_ATTEST_ORG.md` §8).

| File | What |
|---|---|
| `build-core.sh` | `owner-core` as an `xcframework` (phone and simulator, arm64) and its Swift bindings |
| `project.yml` | the Xcode project as an `xcodegen` spec; the generated project is not committed |
| `OwnerApp/Model.swift` | the session: fetch, hand to the core, sign, answer. No rule lives here |
| `OwnerApp/Keys.swift` | the key: Secure Enclave on a phone, software in the simulator |
| `OwnerApp/Store.swift` | what the phone keeps per enrollment (§5.4), out of backups |
| `OwnerApp/Http.swift` | the two requests of a session, with the answer's MAC and the laptop's confirmation |
| `OwnerApp/Views.swift` | the screens: accounts, the enrollment prompt, the review |
| `OwnerApp/Scanner.swift` | the QR through the camera (phones only) |
| `OwnerAppUITests/OwnerRobot.swift` | the owner's hands for the simulator run, and its checks of the screen |
| `run-simulator.sh` | the whole loop in the simulator, one command |
| `install-phone.sh` | build, sign, install and start on a connected iPhone |

## Run it in the simulator

```sh
cd mobile/ios
./run-simulator.sh        # CARGO="cargo +1.94" if needed
```

Needs Xcode with an iOS simulator, `xcodegen`, `anvil`, and the Rust
targets `aarch64-apple-ios` and `aarch64-apple-ios-sim` (an Apple-silicon
Mac). No phone and no Apple account. It builds the core with the test
chain's facts, builds the app, and runs agent-signer's phone test
(`phone_owner_real_device` in `signer/crates/agent-signer/tests/anvil_cli.rs`)
against the app on a local anvil:

1. **Enrollment.** `key create --phone … --allow-no-attestation`; the app
   shows the account, the notice about its key and asks; a new key; the
   laptop confirms.
2. **Handover**, signed by the account's current software key, to the
   app's key.
3. **A new agent permission, signed in the app.** The review names
   AgentPolicy, P256Signer and the demo counter from the build's own
   table, and shows the whole mandate.
4. **A change of the root key, signed in the app** (design §2.2): four
   calls, each effect in bold, and a second confirmation that lists them.
   Root then is the software key's again, which the test proves by using
   it.

`ROBOT=0 ./run-simulator.sh` leaves the taps to you, in the Simulator
window. By default a UI test is the owner's hands. It taps what a person
would and checks what only the screen can show:

- every row the core produced for a review is on the screen, the
  emphasised ones marked `⚠` and no others;
- Sign is not enabled before the end of the review is on screen (§6.6);
- a second confirmation appears for the review with bold effects, and only
  for that one.

It keeps a screenshot of each step in `build/robot-screens`, and its log
(`build/robot.log`) has each review as the screen showed it. The script
fails if either half fails: the CLI's test, or the robot's checks.

### What is different in the simulator

Everything here is compiled only for the simulator
(`#if targetEnvironment(simulator)`); a phone build has none of it.

- **The key is software**, kept in the app's files, with no hardware and
  no biometric check. Its tier is `simulator`, the app says so on every
  screen that matters, and the laptop takes it only with
  `--allow-no-attestation`.
- **No camera.** agent-signer writes each QR's text to a file
  (`--phone-qr-file`) in the simulated device's `tmp` directory, and the
  app takes it from there.
- **The app's log** also goes to a file in that directory, for the robot.

## On an iPhone

What `docs/MOBILE_DEV_MODE.md` §3 describes, as it went on 2026-11-13 with
a free personal Apple Account:

1. Sign the Apple Account in to Xcode (Settings → Accounts). It need not be
   the account the phone itself uses.
2. Plug the phone in, tap "Trust This Computer", and turn on Developer
   Mode (Settings → Privacy & Security; the phone restarts).
3. Pick the team once. `xcodegen generate`, open `OwnerApp.xcodeproj`,
   target OwnerApp → Signing & Capabilities → Team. Xcode writes the
   team's id into the generated project (`grep DEVELOPMENT_TEAM
   OwnerApp.xcodeproj/project.pbxproj`). Keep it somewhere of your own: it
   is not in the repository and the project is regenerated.
4. Build, install and start:
   ```sh
   OWNER_CORE_FEATURES=ffi,test-chains ./build-core.sh     # the anvil run needs the test chain's facts
   DEVELOPMENT_TEAM=<your team id> ./install-phone.sh
   ```
   The first time, the phone refuses to start the app until the developer
   is trusted there: Settings → General → VPN & Device Management.
5. Run the loop from `signer/`, phone and Mac on the same Wi-Fi:
   ```sh
   TPMSIGN_PHONE_NO_ATTESTATION=1 TPMSIGN_PHONE_HANDOVER_BACK=1 \
     cargo test -p agent-signer --features insecure-software-keys \
     --test anvil_cli phone_owner_real_device -- --ignored --nocapture
   ```
   Three QR codes follow; for each, "Scan the laptop's QR" in the app.
   `--allow-no-attestation` is what the first variable adds: there is no
   App Attest without an organisation (§3.5).

On a phone the key is a CryptoKit Secure Enclave key, usable only after
Face ID or Touch ID on every signature and invalidated by a change of the
enrolled biometrics; its handle (not the key) is kept in the app's files,
as the CLI's Mac backend does.

What the phone run showed, beyond the loop passing:

- **The first fetch fails while iOS asks for the local network.** The app
  logs "offline"; scanning the same QR again works, and the question comes
  once per install. A known rough edge, not yet smoothed.
- **A failed biometric check is a refusal.** When Face ID did not
  recognise the owner, nothing was signed and the laptop got "the phone
  refused: user", with the system's message.
- **A reinstall keeps the enrollments.** After installing a new build over
  the app, with the same team and bundle id, the stored records and key
  handles were still there. Signing with a key from before a reinstall
  was not exercised.

Still open on a phone: the 7-day expiry of a free account's profile and
what a rebuild after it keeps, a key after a change of the enrolled
biometrics, Touch ID, and everything about distribution.

## A release build is refused

The Release configuration is the one that can be handed to someone. It
fails while the bundle id is the provisional `.spike` one or the core was
built with `test-chains` (`project.yml`, issue #35), as on Android:

```
$ xcodebuild build -project OwnerApp.xcodeproj -scheme OwnerApp -configuration Release …
error: the bundle id dev.tpmsign.owner.spike is provisional: it is the owner's decision (docs/APP_ATTEST_ORG.md §8)
error: owner-core was built with test-chains: run ./build-core.sh without OWNER_CORE_FEATURES
** BUILD FAILED **
```

## Run record — the loop on an iPhone (2026-11-13, app 0.4.0)

A development build under a free personal team, the phone on the same
Wi-Fi as the laptop. Session addresses, tokens and paths are masked. A
first run stopped at the first signature, because Face ID did not
recognise the owner:

```
waiting up to 180s for the phone…
Error: key unavailable: phone "owner-phone": the phone refused: user (<the system's message for a cancelled check>)
```

The second run:

```
enrolled phone owner key "owner-phone" for account 0x2e13d3d04D09a38c6F3f7D735c6071F36a69B729 (chain 31337)
  public key     x = 0x1ae9…7194
                 y = 0x57d3…10a1
  fingerprint    6SQSW-VSOWR-SSGGR-EG3LE   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level secure-enclave (the phone's own word)
  attestation    none — the laptop cannot place this key in hardware
  app            ios 0.4.0 (core 0.2.0+test-chains)
…
root handed to the phone key 6SQSW-VSOWR-SSGGR-EG3LE.
…
tpmsign:1?u=http://192.168.x.x:61213/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
phone:          signed, signature verified against the owner key
path:           root (owner key)
gas paid by:    the account
userOpHash:     0x003f58dead0c9a1c09e3983f6f76f199458d173810f5a726f8b5e4cdec010729
added permission 0x74657332 (valid 0 … 1826095043): tx 0x58b1…f1d5 (block 5, 399078 gas)
the permission the phone installed is on-chain; the agent runs under it:

Now the phone signs a change of the root key, to 36YE2-V45UT-KFLGX-7H5BF: scan the QR below. The review shows the new
key's fingerprint in bold, and Sign asks a second time.
…
phone:          signed, signature verified against the owner key
userOpHash:     0x523a482a732d34823afd0b5d3516a75e16091a68b39b262f1ec72045404d5edf
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x05e5…97c3 (block 8, 171252 gas)
test phone_owner_real_device ... ok
```

The app's own log of that run, as the launching console kept it:

```
owner-core 0.2.0+test-chains loaded; key tier on this device: secure-enclave
new key: tier secure-enclave
  FINGERPRINT  6SQSW-VSOWR-SSGGR-EG3LE
enrollment confirmed by the laptop. Next there: owner set-root … --expect-fingerprint 6SQSW-VSOWR-SSGGR-EG3LE
signed 0x003f58de…010729 and posted: confirmed by the laptop
signed 0x523a482a…4d5edf and posted: confirmed by the laptop
```

So the Secure Enclave signs the raw 32-byte `userOpHash` in the form
`P256Validator` accepts, twice through root operations on the chain; the
laptop's "what the phone will show" for both operations is the text the
core gave the phone. What the screen itself showed is checked in the
simulator, by the robot; nobody recorded the phone's screen.

## Run record — the loop in the simulator (2026-11-13, app 0.4.0)

`./run-simulator.sh` on an Apple-silicon Mac, Xcode 27.2, the iPhone 17e
simulator on iOS 27.2. Session addresses and tokens are masked.

```
enrolled phone owner key "owner-phone" for account 0xF62A4511Dc19C4CDBb7e8b1614D3e9A5B455d02E (chain 31337)
  public key     x = 0xfba5…808c
                 y = 0x354f…f976
  fingerprint    KLZCW-O3BAT-P6PX5-CWWNK   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level simulator (the phone's own word)
  attestation    none — the laptop cannot place this key in hardware
  app            ios 0.4.0 (core 0.2.0+test-chains)
…
root handed to the phone key KLZCW-O3BAT-P6PX5-CWWNK.
…
tpmsign:1?u=http://192.168.x.x:57499/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
phone:          signed, signature verified against the owner key
path:           root (owner key)
added permission 0x74657332 (valid 0 … 1826083215): tx 0x8c52…54b0 (block 5, 399066 gas)
the permission the phone installed is on-chain; the agent runs under it:
…
Now the phone signs a change of the root key, to 36YE2-V45UT-KFLGX-7H5BF: scan the QR below. The review shows the new
key's fingerprint in bold, and Sign asks a second time.
…
phone:          signed, signature verified against the owner key
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x6e70…1bf6 (block 8, 171252 gas)
test phone_owner_real_device ... ok
the robot's checks passed; the screens it saw are in mobile/ios/build/robot-screens
```

The second review as the screen showed it, from the robot's log:

```
OPERATION
Account: 0xF62A4511Dc19C4CDBb7e8b1614D3e9A5B455d02E
Chain: 31337
The laptop says: "owner operation (root)" (from the laptop — unverified)
CALL 1 OF 4
⚠ Hand control of this account to validator: 0x63dd80Fc5E109A44fd179F85050487E02c5e6958 — P256RecoveryValidator (verified in this build)
Root validator: 0x63dd80Fc5E109A44fd179F85050487E02c5e6958 — P256RecoveryValidator (verified in this build)
CALL 2 OF 4
⚠ Remove validator: 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2 — P256Validator (verified in this build) — this may be the validator holding this phone's key
CALL 3 OF 4
⚠ Install a key on a validator: 36YE2-V45UT-KFLGX-7H5BF — it controls this account once it is root or is granted access
Validator: 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2 — P256Validator (verified in this build)
Validation nonce: 3
CALL 4 OF 4
⚠ Hand control of this account to key: 36YE2-V45UT-KFLGX-7H5BF
Root validator: 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2 — P256Validator (verified in this build)
COST
Maximum gas cost: 0.00050181092445 ETH
DETAILS
nonce: key 0 (root), sequence 3
…
userOpHash: 0x039badbc645686d6be3bf2023a1928f19ced79b57304d3d32274c343913eb381
```

Two defects of the first version of the review screen were found by this
run and are what the robot's checks are for. Rows whose list id repeated
one from an earlier section were not drawn at all, the bold ones among
them; and Sign was enabled as the review opened. The screen now numbers
its rows across the whole review and measures where its end is. A third
was cosmetic but matters on this screen: iOS hyphenated the addresses it
wrapped, which put a character on screen that is in no address.
