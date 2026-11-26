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
2. **The app shows that it holds the new key** (`owner set-root …
   --to-phone`, design §2.2): it signs a check value both sides contribute
   to. Only then the **handover**, signed by the account's current
   software key, to the app's key.
3. **A new agent permission, signed in the app.** The review names
   AgentPolicy, P256Signer and the demo counter from the build's own
   table, and shows the whole mandate.
4. **A change of the root key, signed in the app** (design §2.2): four
   calls, each effect in bold, and a second confirmation that lists them.
   Root then is the software key's again, which the test proves by using
   it.

The script runs the loop twice. The second time a host on the path
replaces the laptop's confirmation of the enrollment (issue #38): the
laptop says "enrolled", the app saw no confirmation. The app must keep its
key, unconfirmed, say so at the top of its screen, show the key when the
handover asks, and go on; the script checks the app's own log and the
robot's record of that notice.

Last, a session that fails (issue #215): the robot hands the app a QR that
is no session. The app must put the reason at the top of its screen, the
same one as in its log, and take it away on OK.

`ROBOT=0 ./run-simulator.sh` leaves the taps to you, in the Simulator
window. By default a UI test is the owner's hands. It taps what a person
would and checks what only the screen can show:

- every row the core produced for a review is on the screen, the
  emphasised ones marked `⚠` and no others;
- Sign is not enabled before the end of the review is on screen (§6.6);
- a second confirmation appears for the review with bold effects, and only
  for that one;
- the app is asked to show its key once, before any signature.

It keeps a screenshot of each step in `build/robot-screens-<run>`, and its
log (`build/robot-<run>.log`) has each review as the screen showed it. The script
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
   Four QR codes follow (enrollment, showing the key, two signatures); for
   each, "Scan the laptop's QR" in the app.
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

## A failure is shown at the top of the screen (version 0.4.4, issue #215)

A failure is shown at the top of the screen, under "That did not work",
until it is dismissed, and stays in the log as before: an error of a
session or of an action, a key the phone cannot show when the handover asks
for it, an enrollment that could not be deleted, and stored enrollments
that could not be read at start. What is accepted or refused does not
change. The simulator run
checks it: its robot hands the app a QR that is no session and looks for
the reason on the screen (`testAFailedSessionIsShown`).

## Deleting an enrollment (version 0.4.2, issue #40)

Each enrolled account has **Delete…**. The app asks twice in
`owner-core`'s words (the same as on Android, and the same for a key the
laptop never confirmed): which key and account, that the phone cannot see
whether the key is root, that deleting the root key takes the account
with it unless a recovery key is installed, and to look at `agent-signer
owner status` on the laptop first, which prints the root key's
fingerprint. Then Face ID or Touch ID. The key's handle lives in the
record, so one write removes both or neither. The simulator run ends with
this delete, and its robot checks the words, that one tap deletes
nothing, and that the enrollment is gone afterwards.

### Run record — deleting an enrollment on an iPhone (2026-11-13, app 0.4.2)

On the iPhone of the earlier runs, which held five enrollments left by
them, all confirmed. No laptop session is involved; the app was started
with its console captured, and its records were read off the phone before
and after. Two things were done by hand:

1. **Delete…** on an account, both questions answered, then Face ID
   **cancelled**;
2. **Delete…** on the first account, both questions answered, Face ID
   passed.

The app's log:

```
owner-core 0.3.1+test-chains loaded; key tier on this device: secure-enclave
not deleted: Authentication canceled.
deleted the key IKQLB-AR4JF-EW5CB-NUJD4 and its record (account 0x472934c09B6fCc9EEFff2cdD5C6976600d91Fbb1, chain 31337)
```

The records: five before, four after. The one deleted is gone, with the
handle of its Secure Enclave key; the other four are byte for byte what
they were, so the attempt that stopped at Face ID deleted nothing. The
biometric check stands between the second answer and the delete on the
device as well.

Not exercised: a failed write of the records, which restores the list
and says that nothing was deleted.

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
signed 0x003f58dead0c9a1c09e3983f6f76f199458d173810f5a726f8b5e4cdec010729 and posted: confirmed by the laptop
signed 0x523a482a732d34823afd0b5d3516a75e16091a68b39b262f1ec72045404d5edf and posted: confirmed by the laptop
```

So the Secure Enclave signs the raw 32-byte `userOpHash` in the form
`P256Validator` accepts, twice through root operations on the chain; the
laptop's "what the phone will show" for both operations is the text the
core gave the phone. What the screen itself showed is checked in the
simulator, by the robot; nobody recorded the phone's screen.

## Run record — an iPhone, with the laptop's confirmation lost (2026-11-13, app 0.4.1, issue #38)

The same test with `TPMSIGN_PHONE_PATH_ATTACKER=1` and four QR codes: a
stand-in for a host on the network shows its own QR in place of the
laptop's, forwards the phone's requests untouched and replaces the
laptop's reply to the enrollment answer. Private values are masked.

```
(this QR leads to a host on the path, not to the laptop; waiting for the phone…)
…
enrolled phone owner key "owner-phone" for account 0xa0EC41e400ae606C4068Dd56509a4a37E83Efb31 (chain 31337)
  fingerprint    P7ZGR-UAU3G-X6J5U-64J74   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level secure-enclave (the phone's own word)
  attestation    none — the laptop cannot place this key in hardware
  app            ios 0.4.1 (core 0.3.0+test-chains)

Nothing changed on-chain. Next, signed by the current owner key:
  agent-signer owner set-root --agent …/owner.json --validator <P256Validator> --public-key 0xde7c…2853,0x0a90…b18d --expect-fingerprint P7ZGR-UAU3G-X6J5U-64J74 --to-phone owner-phone [--retire <validator>]
--to-phone makes the handover wait for the phone: one more QR, on which the phone shows that it holds this key.
Do not hand root to a phone key without it: if the phone did not keep the key, the account goes with it.
…
A host on the path replaced the laptop's reply: the laptop says "enrolled" above, the phone saw no confirmation
and says so. It must have kept the key all the same.

Before root goes to the phone's key, the phone shows that it holds it: scan the QR below and confirm on the phone.

new root key:   fingerprint P7ZGR-UAU3G-X6J5U-64J74
phone key "owner-phone" for account 0xa0EC41e400ae606C4068Dd56509a4a37E83Efb31 on chain 31337: scan this with the owner app and confirm there. The phone shows that it holds the key P7ZGR-UAU3G-X6J5U-64J74; nothing goes to the chain.
tpmsign:1?u=http://192.168.x.x:50288/s/<token>&h=<commitment>&k=<in the QR only>
waiting up to 180s for the phone…
phone:          holds the key P7ZGR-UAU3G-X6J5U-64J74 (signed a fresh digest)
nonce:          0x1
…
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x07ba…69f1 (block 4, 171180 gas)

root handed to the phone key P7ZGR-UAU3G-X6J5U-64J74.
…
phone:          signed, signature verified against the owner key
added permission 0x74657332 (valid 0 … 1826113854): tx 0xa00f…d275 (block 5, 399042 gas)
…
phone:          signed, signature verified against the owner key
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0xd236…3bae (block 8, 171192 gas)
test phone_owner_real_device ... ok
```

The app's own log of that run, as the launching console kept it:

```
owner-core 0.3.0+test-chains loaded; key tier on this device: secure-enclave
new key: tier secure-enclave
  FINGERPRINT  P7ZGR-UAU3G-X6J5U-64J74
enrollment NOT confirmed (HTTP 200 without the laptop's confirmation — not the laptop's answer). The key is kept, unconfirmed: …
PROOF asked: key P7ZGR-UAU3G-X6J5U-64J74, account 0xa0EC41e400ae606C4068Dd56509a4a37E83Efb31
showed the key P7ZGR-UAU3G-X6J5U-64J74 and posted: confirmed by the laptop
signed 0x9f61814b…db8f27 and posted: confirmed by the laptop
signed 0x29f2cdd2…388947 and posted: confirmed by the laptop
```

So the Secure Enclave key that the app kept without the laptop's
confirmation was shown to the laptop, became root, and signed twice. Face
ID was asked three times, once for each use of the key: the proof and the
two signatures. Creating the key asks for none.

### The same on the iPhone with the confirmation arriving

The run without the host on the path, right after it (app 0.4.1): the
first QR is the laptop's own, the laptop's confirmation reaches the app,
and the handover still waits for the phone to show the key.

```
enrolled phone owner key "owner-phone" for account 0x202c2962d06Fd7c1B68c279eB42b584c1BF20C6D (chain 31337)
  fingerprint    VT4SN-YQ5KF-WARDA-IUKSP   ← not confirmed here (--phone-skip-fingerprint): the phone shows the same one
  security level secure-enclave (the phone's own word)
  attestation    none — the laptop cannot place this key in hardware
  app            ios 0.4.1 (core 0.3.0+test-chains)
…
Before root goes to the phone's key, the phone shows that it holds it: scan the QR below and confirm on the phone.

new root key:   fingerprint VT4SN-YQ5KF-WARDA-IUKSP
…
waiting up to 180s for the phone…
phone:          holds the key VT4SN-YQ5KF-WARDA-IUKSP (signed a fresh digest)
nonce:          0x1
…
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x8134…98c3 (block 4, 171252 gas)

root handed to the phone key VT4SN-YQ5KF-WARDA-IUKSP.
…
phone:          signed, signature verified against the owner key
added permission 0x74657332 (valid 0 … 1826114247): tx 0x6cba…60ce (block 5, 399078 gas)
…
phone:          signed, signature verified against the owner key
root handed to 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2: tx 0x8fb6…b610 (block 8, 171240 gas)
test phone_owner_real_device ... ok
```

The app's log:

```
new key: tier secure-enclave
  FINGERPRINT  VT4SN-YQ5KF-WARDA-IUKSP
enrollment confirmed by the laptop. Next there: owner set-root … --expect-fingerprint VT4SN-YQ5KF-WARDA-IUKSP --to-phone owner-phone
PROOF asked: key VT4SN-YQ5KF-WARDA-IUKSP, account 0x202c2962d06Fd7c1B68c279eB42b584c1BF20C6D
showed the key VT4SN-YQ5KF-WARDA-IUKSP and posted: confirmed by the laptop
signed 0xef95eae4…e15697 and posted: confirmed by the laptop
signed 0x5769afe1…5d9b5e and posted: confirmed by the laptop
```

In both runs the handover back to the software key carried
`--not-a-phone`, and the one to the phone `--to-phone`.

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
