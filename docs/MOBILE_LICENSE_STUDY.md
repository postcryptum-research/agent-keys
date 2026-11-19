# Licensing the mobile owner apps and `owner-core` — study

*Draft, 2026-10-29. The separate study that decision 3 of
[`MOBILE_OWNER_PLAN.md`](MOBILE_OWNER_PLAN.md) requires before P5 and
before any code of the apps is published. It is the owner's decision;
this page gathers the facts and ends with a recommendation and the open
questions. Facts marked **V** were verified at the linked source on
2026-10-29; **I** are inferred and need checking before the decision.*

## 1. What is being licensed

| Component | Language | Where | Today |
|---|---|---|---|
| `owner-core` | Rust | `mobile/owner-core` | no `license` field, `publish = false`; the code moved from `agent-signer` is Apache-2.0 |
| the Android app | Kotlin | `mobile/android` (P0) | written (0.4.1-p4, version code 12, on 2026-11-19); no licence file or header |
| the iOS app | Swift | `mobile/ios` (P4) | written (0.4.2 on 2026-11-19); no licence file or header |
| the CLI that depends on `owner-core` | Rust | `signer/` | Apache-2.0 (#4) |
| the contracts | Solidity | `contracts/` | MIT, unchanged |

Three facts shape the choice:

1. **The CLI is Apache-2.0 and depends on `owner-core`.** Whatever
   `owner-core` gets must let an Apache-2.0 program link it. A copyleft
   `owner-core` would pull the CLI toward that licence.
2. **The security argument needs the source.** The design's answer to
   "our app itself could be malicious" (T6) is open source plus
   reproducible Android builds that a user can rebuild and compare. A
   closed or source-available app would weaken the project's main claim.
3. **The apps go through stores**, whose terms interact with copyleft.

## 2. Store terms versus licences

### 2.1 Apple App Store

- The App Store's terms impose conditions on the user (usage rules, a
  limited number of devices, no redistribution) that the GPL forbids
  adding. The FSF's position since 2010 is that GPL software cannot be
  distributed through the App Store; VLC was removed from it in 2011 on
  that basis and returned only after relicensing its iOS code to MPL/LGPL
  with contributor consent (V, widely documented; the FSF statement
  "More about the App Store GPL enforcement", 2010).
- **Consequence:** nothing under **GPL-2.0, GPL-3.0 or AGPL** may be in
  the iOS app or its dependency tree. LGPL is treated the same way on iOS
  because static linking is the norm and relinking is not possible (I:
  the usual reading, not a court ruling).
- **Permissive licences (MIT, BSD, Apache-2.0) and MPL-2.0** are used by
  many App Store apps without issue (V, by existence; MPL's file-level
  copyleft is satisfied by publishing the modified files).
- Apache-2.0's patent clause does not conflict with Apple's agreement
  (I: no known case; Apple ships Apache-2.0 code itself).

### 2.2 Google Play

- Play's distribution agreement does not forbid copyleft; GPL apps exist
  on Play (V, by existence). The practical constraints are Play App
  Signing (Google re-signs; see `APP_ATTEST_ORG.md` §7) and the
  developer-verification programme, neither of which is a licence matter.
- A self-signed APK installed through `adb` (`MOBILE_DEV_MODE.md`) has no
  store terms at all.

### 2.3 F-Droid (optional later channel)

- F-Droid builds from source and requires a free licence; it accepts
  Apache-2.0, MIT, MPL-2.0 and GPL alike (V, F-Droid inclusion policy).
  It is the natural channel for the "verify the build" audience.

## 3. The dependency tree (what the apps will contain)

| Dependency | Licence | Note |
|---|---|---|
| `alloy-primitives`, `alloy-sol-types` | MIT OR Apache-2.0 (V, lockfile) | |
| the rest of `owner-core`'s tree (`cargo tree -e normal`, after #16: `p256` 0.14) | mostly MIT OR Apache-2.0; also MIT only (`bytes`, `convert_case`, `derive_more` and `derive_more-impl`, `ruint` and `ruint-macro`, `zmij`), BSD-3-Clause (`subtle`), Zlib (`foldhash`), `Unlicense OR MIT` (`memchr`), `(MIT OR Apache-2.0) AND Unicode-3.0` (`unicode-ident`), `CC0-1.0 OR MIT-0 OR Apache-2.0` (`dunce`), and `hw-signer` Apache-2.0 (V, 2026-11-19; `generic-array` left the tree with `p256` 0.13) | all permissive, no copyleft and no MPL in the Rust tree without the `ffi` feature. With `ffi`, which every phone build has, the tree gains 29 crates (resolved by hand from `Cargo.lock` and the crates' manifests on 2026-11-19, not by `cargo tree`): the six `uniffi*` crates 0.32.2 (MPL-2.0, the next row) and 23 permissive ones. Of those, MIT only: `cargo_metadata` (through `uniffi`'s default feature `cargo-metadata`) and `winnow`; `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`: `rustix` and, on Android, `linux-raw-sys`; MIT OR Apache-2.0: `anyhow`, `bitflags`, `camino`, `cargo-platform`, `errno`, `fastrand`, `fs-err`, `once_cell`, `semver`, `serde_spanned`, `siphasher`, `static_assertions`, `tempfile`, `thiserror` and `thiserror-impl` 2, `toml`, `toml_datetime`, `toml_parser`, `toml_writer`. The `NOTICE` of §6 is not written yet; it must list the `ffi` tree |
| `hw-signer` (types only, no backends) | Apache-2.0 | ours |
| **`uniffi`** (bindings generator and its runtime support code) | **MPL-2.0** (V, crates.io) | the generated Swift/Kotlin bindings embed uniffi's support code. MPL-2.0 covers *files*; the generated files are derived from MPL templates. **To confirm (I):** whether the uniffi project treats generated bindings as unencumbered output. If not, those generated files stay MPL-2.0, which the stores accept, and the rest of the app keeps its own licence |
| AndroidX (`appcompat`, `biometric`, and what they bring, `core` among them) | Apache-2.0 (V) | the two the app declares; no `camera` (CameraX), the scanner below needs none |
| JNA (uniffi's Kotlin runtime) | **LGPL-2.1 OR Apache-2.0** (V) | choose Apache-2.0. **In use since P2** (2026-11-12): `uniffi` 0.32 (MPL-2.0) generates the Kotlin bindings of `owner-core` and JNA 5.17 loads the library, taken under its Apache-2.0 option. `uniffi` is in both apps (since P4 it also generates the Swift bindings of the iOS app); JNA is in the Android app only; the CLI's build does not enable `owner-core`'s `ffi` feature |
| A QR scanner on Android | ZXing: Apache-2.0 (V). ML Kit: Google proprietary terms (V) | **chosen: ZXing** (`zxing-android-embedded` 4.3.0 without its transitive dependencies, and `zxing` `core` 3.5.4), no CameraX and no ML Kit, for licence simplicity and to keep Google out of the app |
| iOS frameworks (CryptoKit, Security, LocalAuthentication, AVFoundation, VisionKit, SwiftUI; DeviceCheck once App Attest is added) | Apple SDK terms | unavoidable; not redistributed |
| Swift / Kotlin standard libraries | Apache-2.0 | |

So, with ZXing rather than ML Kit and JNA under its Apache option, the only
non-permissive item is uniffi's MPL-2.0, which is store-compatible on both
platforms.

## 4. Options

| Option | For `owner-core` | For the apps | Stores | T6 argument | Fits the CLI |
|---|---|---|---|---|---|
| **A. Apache-2.0 everywhere** | yes | yes | both | full: source + reproducible builds | yes, the same licence |
| B. MIT | yes | yes | both | full | yes; no patent grant |
| C. MPL-2.0 | yes | yes | both | full | yes (file-level copyleft; the CLI may link it) |
| D. GPL-3.0 for the apps, Apache for the core | yes | Android only | **not the App Store** | full on Android | the core stays linkable |
| E. AGPL | — | — | not the App Store; pointless for an offline app | — | would taint the CLI |
| F. Proprietary or source-available apps (BSL) on an open core | yes | closed | both | **broken**: users cannot verify the build they run | yes |

What each would buy: B and C add nothing over A for this project. D gives
a stronger guarantee that app forks stay open, at the price of no iOS
distribution — the platform where our attestation story is weakest and
where users can least verify a binary, which is exactly where we need the
store. F contradicts the security claim and the positioning in
`docs/related/LANDSCAPE.md` ("no hosted vendor to trust").

## 5. Recommendation

**Option A: Apache-2.0 for `owner-core` and for both apps,** matching the
signer, for the same reasons as #4: the explicit patent grant and
contribution terms, store compatibility on both platforms, and one licence
across the laptop and the phone, which keeps the shared-core refactor free
of licence boundaries. Keep third-party code permissive or MPL (uniffi),
with the one confirmation in §3. The name and the logo are protected by a
trademark, not by the licence, so that a fork cannot ship as "agent-keys" in
a store.

If the owner wants a copyleft guarantee on the apps, **C (MPL-2.0 for the
apps only)** is the compatible choice: file-level copyleft that the stores
accept and that leaves the Apache-2.0 core and CLI untouched.

## 6. What to do before P5, whichever option

- [ ] Confirm the uniffi generated-bindings question (§3) against the
      uniffi repository's licence notes.
- [x] Pick ZXing (or another Apache-2.0 scanner) for Android; avoid ML
      Kit. Done: `zxing-android-embedded` 4.3.0 and `zxing` `core` 3.5.4
      (§3).
- [ ] Add the `license` field to `mobile/owner-core/Cargo.toml` and the
      `LICENSE` and `NOTICE` files under `mobile/`, and remove the
      "not decided" note from its README.
- [ ] Add third-party notices to both apps (the stores and Apache-2.0 §4
      both expect them): a generated `NOTICE` for Rust crates
      (`cargo-about` or `cargo-deny`) and the Gradle licence report on
      Android.
- [ ] Store listings: the privacy labels (`APP_ATTEST_ORG.md` §6) say the
      app collects nothing; the licence text is linked from the listing.
- [ ] Trademark: register or at least assert the name and logo
      (the private market notes recommend it).

## 7. Open questions for the owner, with a recommendation on each

1. **Option A, or C for the apps?** **A.** Nothing in P0 changes it: the
   core is pure encoding and hashing, the apps are thin shells around the
   platform's key APIs, and no copyleft code has entered the tree (§3).
   C would buy a file-level guarantee that app forks stay open, at the
   cost of a licence boundary between the apps and the Apache-2.0 core and
   CLI. The T6 argument needs source availability, which A gives.
2. **Trademark before P5, and under which entity?** **Yes, before P5, not
   before P0.** The store listings make the name public and squatting a
   name in a store is cheap, so file once a release date exists. A
   trademark belongs to a legal person, so it depends on
   `APP_ATTEST_ORG.md` §8.1: the entity that enrolls with Apple should own
   the mark, the bundle id and the signing keys together. If that entity
   does not exist yet when P5 nears, file in the owner's name and assign
   it later (an assignment is routine) rather than wait. Scope: an EU
   trade mark in classes 9 (software) and 42 (software services), with a
   US filing if the stores' main market is there; one class in the EU is
   under €1,000 (I: check current fees at filing).
3. **`owner-core` on crates.io?** **Not yet: `publish = false` until the
   licence is set and the API has a stable surface.** Publishing commits
   us to semver for the wire format and the `Review` API, to publishing
   `hw-signer` first (crates.io does not accept path dependencies), to a
   release cadence with yanks for security fixes, and to supporting
   consumers we do not know. Until a second consumer exists, a git
   dependency with a tag gives third parties the same code without those
   obligations. Publish at the first tagged 1.0 of the protocol, when the
   two apps and the CLI have shipped against it.
