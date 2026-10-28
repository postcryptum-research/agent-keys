# iOS App Attest — what is needed organisationally

*Study, 2026-10-28. It answers the owner's decision on D5 (PR #5): App
Attest on iOS, yes, after a separate study of what it needs
organisationally. It is due before P3 (attestation) of
[`MOBILE_OWNER_PLAN.md`](MOBILE_OWNER_PLAN.md). The technical design is in
`MOBILE_OWNER_DESIGN.md` §5.3 (PR #5). Nothing is decided here that is the
owner's: the open questions are listed at the end.*

Evidence marks: **V** verified at the linked Apple source on 2026-10-28;
**I** inferred, to be confirmed in the phase named.

## 1. Summary

App Attest itself is cheap: an entitlement, a framework call, and
verification in our CLI against Apple's root. The organisational weight is
elsewhere:

1. **Who the Apple developer is.**
   - The App Store accepts wallets only from developers **enrolled as an
     organization** (V, guideline 3.1.5(i)).
   - Enrolling as an organization needs a **legal entity** and its
     **D-U-N-S number** (V).
2. **The Team ID and bundle id become part of the protocol.**
   - The attestation is valid only for `sha256("<Team ID>.<bundle id>")`,
     and it names the distribution channel (TestFlight, App Store,
     development, ad-hoc). The CLI pins the first and filters on the second.
   - Changing the team or the bundle id later invalidates what the CLI
     accepts.
3. **Whoever controls the Apple account and the distribution certificate
   can ship a build that App Attest vouches for.**
   - That is T6 in the design ("our app itself is malicious") in
     organisational form.
   - The account and the certificate are part of the trust root and need
     custody rules.

## 2. What App Attest needs, technically

| Item | Requirement | Mark |
|---|---|---|
| Membership | Apple Developer Program, paid yearly | V ([enroll](https://developer.apple.com/programs/enroll/)) |
| App ID | an explicit bundle id under our Team ID, with the App Attest capability | V |
| Entitlement | `com.apple.developer.devicecheck.appattest-environment`. It matters only in development: "Regardless of how you set the entitlement, your app always operates in production mode after distribution, whether through TestFlight, the App Store, or the Apple Developer Enterprise Program" | V ([Apple](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)) |
| Environments | sandbox and production keys are tracked separately and are not interchangeable. The CLI must accept the right `aaguid` per build type | V, same source |
| Network | `attestKey` calls an Apple server, so the phone needs internet once per enrollment | V, same source |
| Rate limits | under 100 `attestKey` calls per second across all installations; ramp up gradually. Irrelevant at our scale, but the app must handle a throttling error | V, same source |
| Device support | `DCAppAttestService.isSupported` is false on the simulator and some contexts. The app falls back to `--allow-no-attestation`, as designed | I, P3 |
| The CLI side | Apple's App Attestation root certificate embedded in `agent-signer`, plus the expected App ID `<App ID prefix>.<bundle id>`. The prefix is "usually" the 10-character Team ID; check it in the developer account | V ([validating](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)) |
| Distribution channel in the attestation | the authenticator data carries `apple_validation_category_01`: 2 = TestFlight, 3 = development signing, 4 = App Store, 5 = ad-hoc or enterprise. It also carries `apple_bundle_version_01`, the app version | V, same source |

**The channel field is the organisational lever.**
- A development-signed build (category 3) can be produced by any team
  member with a development certificate.
- A TestFlight or App Store build (2, 4) went through App Store Connect,
  and so through whoever holds the release roles (§4).
- So the CLI should accept **only 2 and 4** for real accounts, and 3 only
  with an explicit `--allow-dev-build` on a test chain.
- `apple_bundle_version_01` lets the CLI refuse app versions below a
  minimum (T14, downgrade).

**Three corrections for the design (PR #5):**
- **The two verification steps above are missing** from §5.3's list. Add
  them.
- **The sandbox `aaguid`.** Apple's two pages disagree. The validation page
  says `appattestdevelop`; the preparation page says `appattestsandbox`. The
  CLI should accept both for development builds and only `appattest` (padded
  with zero bytes) for production. Confirm on a device in P3.
- **Ad-hoc builds.** A developer reports that an ad-hoc build behaves like
  sandbox despite the entitlement being set to `production` (unanswered,
  [forum](https://developer.apple.com/forums/thread/845265)). TestFlight is
  documented as production, so testers should get TestFlight builds, not
  ad-hoc ones. The channel rule above refuses ad-hoc (5) anyway.

**Keys per device.** Apple suggests one `attestKey` "once per user per
device", and it keeps a per-device production key count it cannot reset.
The design attests one key **per account** (D3), which is more than one
key on one device. That is harmless at a handful of accounts per phone,
but do not reinstall-and-re-enroll in loops on production devices while
developing; use the sandbox.

## 3. Who the developer is

| Option | What it takes | What it allows | Mark |
|---|---|---|---|
| **Individual** enrollment | an Apple Account, ID check, yearly fee; no D-U-N-S | development, ad-hoc (a limited number of registered devices), TestFlight. The seller name shown is the person's | V ([enroll](https://developer.apple.com/programs/enroll/)) |
| **Organization** enrollment | a **legal entity** (a corporation, LLC, LP; "DBAs, fictitious businesses, trade names, and branches are not accepted"), a **D-U-N-S number** registered to it (free, up to 5 business days from D&B), and a person with authority to sign for it | everything, including the App Store for a wallet | V ([D-U-N-S](https://developer.apple.com/support/D-U-N-S/)) |

**The App Store rule that decides it** (V,
[guidelines 3.1.5](https://developer.apple.com/app-store/review/guidelines/#cryptocurrencies)):

> (i) Wallets: Apps may facilitate virtual currency storage, provided they
> are offered by developers enrolled as an organization.

Our app holds the owner key of a smart account that holds funds. App Review
will very likely treat it as a wallet (I). So **P5 on the App Store needs
an organization account.** Development, P0–P4 and TestFlight do not
strictly need one (I; external TestFlight goes through Beta App Review,
which applies the same guidelines).

**The trap:** an app can be moved between developer accounts later, but the
Team ID changes. Every enrollment the CLI accepted under the old team stays
valid; new ones need the new `<Team ID>.<bundle id>` pinned (I, P3). It is
simpler to **start under the account that will publish**.

## 4. Custody: the account is part of the trust root

App Attest proves "a genuine instance of the app signed by this team".
Anyone who can ship a build under the team can ship a malicious one that
attests just as well (T6). So:

| Asset | Who should hold it | Rule |
|---|---|---|
| **The Account Holder role** (one person, legally binding) | the legal entity's representative | two-factor authentication on a hardware security key; no shared credentials |
| **Admin / App Manager roles** in App Store Connect | at least two people, so one can always revoke the other | named people; reviewed when someone leaves |
| **The Apple Distribution certificate's private key** | one build machine, or Xcode Cloud | not on laptops that run the agent (`KEY_POLICY.md`, rule 3 in spirit); a written list of who can sign builds |
| **App Store Connect API keys** (for CI) | CI only, scoped to the minimum role | rotated; revoked on any doubt |
| **The bundle id and Team ID** | fixed in the repository and in the CLI | changing either is a protocol change, with a new CLI release |

**Release discipline that follows from T6:**
- the CLI accepts only TestFlight and App Store builds (§2, the channel
  field), so the release roles are the gate;
- builds come from tagged commits;
- two people approve a release;
- the build that App Review sees is the one users get.

iOS builds are not reproducible and are re-encrypted by the App Store, so
users cannot check the binary. The design says this plainly, and the user
documentation should repeat it.

## 5. Distribution paths, in order

| Path | Needs | Fits phase | Mark |
|---|---|---|---|
| Xcode, to the developer's own device | any membership; sandbox App Attest | P0–P3 | V |
| Ad-hoc | registered device UDIDs, a yearly limit per device type | not recommended (environment unclear, §2) | I |
| **TestFlight**, internal | team members in App Store Connect; production App Attest | P3–P4 | V (production, Apple) |
| **TestFlight**, external | Beta App Review; testers by email or link; builds expire after a time limit | P5 testers | I (review applies the wallet rule?) |
| App Store | an organization account (§3); App Review; privacy labels | P5 later | V (rule 3.1.5) |
| Alternative marketplaces (EU) | other notarisation rules | out of scope | — |

## 6. Other paperwork for an App Store release (P5)

| Item | Note | Mark |
|---|---|---|
| Privacy "nutrition labels" in App Store Connect | the app collects nothing and has no backend, which makes this easy, but it must still be filled in | V (required) |
| Privacy manifest (`PrivacyInfo.xcprivacy`) | declares any "required reason" APIs that the app and its libraries use | I, P5 |
| `NSLocalNetworkUsageDescription`, `NSCameraUsageDescription`, `NSFaceIDUsageDescription` | the design's LAN, QR and biometrics | I, P1 |
| Export compliance (`ITSAppUsesNonExemptEncryption`) | the app signs and hashes, it does not encrypt data; likely exempt, but answered per release | I, P5 |
| Licence | **a separate study** (the owner's decision). App Store terms vs the licences of the app and its dependencies are part of it | open |
| A support URL and a privacy-policy URL | required by App Store Connect | V |

## 7. The Android counterpart, briefly

The same question on Android, so the two are decided together:
- **The Play Console** also distinguishes personal and organization
  accounts, and organizations verify with a D-U-N-S number (I, P5).
- **Play App Signing affects the attestation.** The Android design pins the
  app's **signing-certificate digest** in the key attestation
  (`attestationApplicationId`). With Play App Signing, **Google holds the
  signing key** and the digest is that of Google's app-signing key, not
  ours (I, P3).
  - Pin the right digest per channel: the APK we sign for testers, and the
    Play-signed build.
  - Accept that Google is then in T6's trust root for Play builds.

## 8. Open questions for the owner

1. **Which legal entity enrolls.** An existing company with a D-U-N-S
   number, or a new one? This decides the seller name the users see.
2. **Who holds the Account Holder role,** and who are the two admins.
3. **The bundle id** (for example a reverse domain the entity owns). It is
   fixed once P3 starts.
4. **Whether to develop under an individual account now** and move the app
   to the organization later. It saves time, but costs a Team ID change
   (§3). Recommended: enroll the organization first if it can be done
   within weeks, since P0–P2 do not need App Attest at all.
5. **Who builds releases** (one machine, or Xcode Cloud) and the two-person
   release rule.

## Sources

- Apple, [Preparing to use the App Attest service](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)
- Apple, [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- Apple, [App Review Guidelines, 3.1.5 Cryptocurrencies](https://developer.apple.com/app-store/review/guidelines/#cryptocurrencies)
- Apple, [D-U-N-S Number](https://developer.apple.com/support/D-U-N-S/) and [enrollment](https://developer.apple.com/programs/enroll/)
- Apple Developer Forums, [App Attest production entitlement not honoured for ad-hoc distributed build](https://developer.apple.com/forums/thread/845265)
