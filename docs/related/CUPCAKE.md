# Cupcake (Cake Wallet): an old phone as a signing device

Researched 2026-10-23 from [cupcakewallet.com](https://cupcakewallet.com/),
Cake Labs' blog post ["How Cupcake actually works"](https://blog.cakewallet.com/how-cupcake-actually-works-a-technical-deep-ish-dive/)
(2025-10-20), the docs at docs.cakewallet.com, and the source at
[github.com/cake-tech/cupcake](https://github.com/cake-tech/cupcake)
(`main` at `56e8b10`, 2026-09-25; last release v1.1.0, 2025-11-25). Code
claims below are **V** (read in that checkout) unless marked **I**.

## What it is

A Flutter app by Cake Labs LLC that turns a spare Android or iOS phone into
an **offline QR-code signer** for Cake Wallet. Bitcoin, Litecoin (incl. MWEB)
and Monero only; no EVM chains. GPL-3.0, about 17.5k lines of Dart, plus
native libraries. The everyday phone runs Cake Wallet with view-only keys
and builds transactions; the Cupcake phone holds the spending keys, shows the
transaction and signs it; animated QR codes carry the data both ways.

## What it is built from (V)

| Part | Implementation |
|---|---|
| Monero | `monero_c` (the Monero wallet library compiled for mobile, via `monero.dart`): the standard view-only-wallet protocol — Cake Wallet exports outputs (`xmr-output`), Cupcake returns key images (`xmr-keyimage`), signs unsigned transactions (`xmr-txunsigned` → `xmr-txsigned`) |
| Bitcoin, Litecoin | `bdk_flutter` (Bitcoin Dev Kit): PSBT in (`psbt` UR type or raw base64), signed PSBT out |
| Transport | BC-UR animated QR codes (`bc-ur-dart`), fragment length configurable; a camera scanner package |
| Key files | Monero: the normal `monero-wallet` file format, encrypted by `monero_c` under the wallet password. Bitcoin/Litecoin: the BIP-39 mnemonic in a `<name>.keys` file, **OpenPGP symmetric encryption** (`dart_pg`) under the same user-chosen wallet password (`lib/utils/encryption/pgp.dart`) |
| Air gap | Android manifest requests only `VIBRATE` — no `INTERNET`, so the OS denies network access (`android/app/src/main/AndroidManifest.xml`). iOS has no such permission to withhold; there the claim rests on the app not opening connections |
| PIN / brute force | the author's `applock` package: after five failed unlocks a timed lockout (30 s → 2 min → 10 min); if it detects clock tampering, hashcash puzzles calibrated to 1–15 minutes of CPU. State is a JSON file in the app directory — the package README says it assumes "app files are intact" |
| Biometrics | optional: the wallet password is written to `flutter_secure_storage` (Android EncryptedSharedPreferences / iOS Keychain) and released after a `local_auth` prompt; "insecure biometrics" (non-class-3) are refused unless the user opts in |

## Where the key lives — the important part

**The private keys are software keys in app files.** Signing happens in the
app's memory with the decrypted key, exactly as in a hot wallet; what
Cupcake removes is the network, not the key's exposure to software. There is
no use of Android Keystore / StrongBox, no `SecKey` / Secure Enclave API, no
hardware-bound key anywhere in the repository (grep for `Keystore`,
`SecureEnclave`, `SecKey`, `StrongBox`: nothing). The only platform secure
storage used is the optional biometric password cache above.

That matters for comparison with TPM_sign: here the agent's and owner's keys
are **born inside** a TPM, Secure Enclave or TROPIC01 and never exist in
memory; the chip signs a digest. Cupcake's model is "a key file on a phone
that cannot talk".

## Claims versus code

The blog post (2025-10-20) states, for Pixels and iPhones, that secrets are
stored "in a secure enclave", that PIN brute-force protection is "enforced by
the secure enclave", and that the wallet file key is derived from the PIN
"as well as a part generated on your phone's secure enclave"; for phones
without an enclave, proof-of-work. The code at `main` and at v1.1.0 shows:

- no secure-enclave or Keystore use for the keys or the file-encryption key
  (V);
- the PIN brute-force limiter is the software `applock` lockout above (V);
  the proof-of-work exists, but as the *anti-tamper* penalty, not as the
  no-enclave fallback the post describes (V);
- the file key is the user's password alone (V).

Two readings are possible: the post describes a design that was not (yet)
shipped, or it describes platform properties (app sandboxing, file-based
encryption of the whole phone) in enclave vocabulary. Either way the
protection a reader gets today is: phone full-disk encryption + app sandbox
+ a password-encrypted file + a software lockout.

The site also says the code was "audited". No audit report, auditor or date
could be found — not in the repository, the release notes, Cake Labs' other
repositories (`gh search code audit --owner cake-tech` finds only mnemonic
word lists and `docs/VERIFY.md` in `cake_wallet`), nor on the web (I: it may
have been an internal or unpublished review).

## Repository health (V, 2026-10-23)

- created 2024-08-27; 80 stars, 10 forks; 7 contributors, one of them with
  about half the commits;
- last release **v1.1.0 on 2025-11-25**; `main` is ~450 lines ahead of it
  with no release since; feature branches (Zcash, passphrase UX, "security
  improvements") pushed as recently as 2026-10-23;
- release APKs ship SHA-256 hashes; no reproducible-build process seen
  (`.github/workflows`: a release build and lint only);
- notable open issues: Litecoin seed entropy (#64), MWEB ignoring the
  passphrase when deriving the seed (#46), "prevent screenshot of seed" (#47),
  FROST / multisig requests;
- a `SECURITY.md` with private-advisory reporting, a 90-day disclosure window
  and discretionary rewards (V).

Outside view: the Privacy Guides forum discussed it in November 2025 and did
not recommend it — "not a hardware wallet", "poorly documented in terms of how
it actually protects your data", and the risk that an old phone no longer gets
security updates (V, [thread](https://discuss.privacyguides.net/t/cupcake-hardware-wallet/32674)).

## What it means for TPM_sign

- **Different problem.** Cupcake isolates a software key by removing the
  network; TPM_sign keeps the key inside a secure element and limits what it
  may sign with an on-chain mandate. Cupcake has no P-256, no hardware-held
  key, no smart account and no EVM support: nothing of it is reusable as code.
- **One idea worth borrowing: the transport.** A BC-UR animated-QR channel
  between an owner's phone and the agent host would make "way 1" of
  [`../PHONE_OWNER.md`](../PHONE_OWNER.md) (a native app with the key in
  StrongBox / the iOS Secure Enclave) a genuinely air-gapped owner device:
  the phone needs only a camera and a screen, as Cupcake's does, but the key
  would be hardware-bound and the signature P-256 over our digest — stronger
  than what Cupcake offers today. UR type registry and animated-QR encoders
  exist for Dart, Rust (`ur` crate) and TypeScript.
- **A lesson for our own docs.** Cupcake's gap between the security write-up
  and the code is the kind of thing an auditor flags first. Our run records
  (`SECURE_ENCLAVE.md` §12–13, `WINDOWS.md`, `TROPIC01.md`) paste outputs and
  transaction hashes for exactly this reason; keep doing that.
