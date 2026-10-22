# A phone as the owner key — what we found

Status (2026-10-22): **explored, parked.** The owner's second factor is a
YubiKey for now. This page records what was checked, so the next person can
pick it up where we stopped instead of starting over. Device details of the
phone we tried are deliberately left out.

The goal: the owner (root) key on a phone — a device separate from the
agent's machine (`KEY_POLICY.md` rule 3), with a fingerprint or PIN for
every owner operation, and ideally a screen that shows *what* is being
signed.

## Three ways to do it

| Way | Key lives in | Validator on-chain | Confirmation | Shows what is signed | Effort |
|---|---|---|---|---|---|
| 1. Own app (Android Keystore / StrongBox; iOS Secure Enclave) | the phone only, non-extractable | **`P256Validator` as is** | fingerprint/PIN **per signature**, enforced in hardware | **yes** — the app can decode the operation and recompute its hash | a mobile app: building, signing, distributing (Play Store / App Store) |
| 2. Termux + Termux:API (`termux-keystore`), Android | the phone only (Keystore: TEE, or StrongBox where present) | **`P256Validator` as is** | an unlock **window** (e.g. 30 s), not per signature | no (blind), unless a decoder is run in Termux | no app; install two open-source apps from F-Droid; our CLI talks to the phone over SSH |
| 3. Passkey (WebAuthn), Android or iPhone | **synced** to the Google / iCloud account (see below) | a WebAuthn validator (ZeroDev's, already on Base) — the root validator changes | fingerprint/PIN per signature | no (the phone shows "sign in to localhost") | a local web page in the CLI + signature packing; no mobile code |

## What was verified

**Android Keystore** (way 1, and underneath way 2). StrongBox must support
EC P-256 with `DIGEST_NONE`, i.e. signing a 32-byte digest as is
([AOSP](https://android.googlesource.com/platform/hardware/interfaces/+/3a7e2ca%5E%21/));
the TEE Keymaster does too. That is exactly what `P256Validator` verifies, so
no on-chain change. Caveat: AOSP marks `DIGEST_NONE` for ECDSA as deprecated
— mandatory today, a long-term risk. Many budget phones have no StrongBox;
then the key is in the TEE — still non-extractable, weaker against attacks
on the chip itself. `adb shell pm list features | grep -iE "strongbox|keystore"`
tells which a phone has.

**Termux:API** (way 2), from its source
([KeystoreAPI.java](https://github.com/termux/termux-api/blob/master/app/src/main/java/com/termux/api/apis/KeystoreAPI.java),
[termux-keystore](https://github.com/termux/termux-api-package/blob/master/scripts/termux-keystore.in)):

- `termux-keystore generate owner -a EC -s 256 -u 30` creates a P-256 key in
  the Keystore with digests `NONE,SHA-1,SHA-256,…` — `NONE` included;
- `termux-keystore sign owner NONEwithECDSA` reads the 32-byte hash on stdin
  and writes a DER signature (→ `r‖s`, low-s, in our CLI);
- `termux-keystore list -d` prints the public key's x, y in hex;
- `-u N` means `setUserAuthenticationValidityDurationSeconds(N)`: the key
  works for N seconds after the user unlocks the phone (fingerprint/PIN).
  There is **no per-signature prompt** and the code never asks for
  StrongBox.

**Passkeys** (way 3):

- the browser allows WebAuthn only in a secure context — `https://` or
  `http://localhost` — and the relying-party id must be a domain, **not an
  IP address**. So "a page on the local network" means either a page on
  `localhost` on the laptop with the phone as a cross-device authenticator
  (Chrome's "use a phone or tablet": a QR code, Bluetooth proximity, an
  end-to-end encrypted relay), or a page on the phone under a local domain
  with an HTTPS certificate the phone trusts (a private CA installed on it);
- ZeroDev's WebAuthn validator requires user verification (UV) and does not
  check the rpId, so `localhost` is fine on-chain (`OWNER_DEVICES.md` §0).

## The experiment (passkey, way 3)

With [`examples/passkey-probe`](../examples/passkey-probe/) on a Linux
laptop (Chrome) and an Android phone:

- **Creating the passkey worked**: P-256 (`alg -7`), `UV = true`.
- But the authenticator flags were **`BE = true, BS = true`**: the passkey
  is *backup-eligible* and *already backed up* — synced into the Google
  Password Manager. It lives in the Google account, not only in the phone:
  any device signed into that account (with its password-manager PIN) can
  use it. As a second factor that is "the Google account", not "this phone".
  iCloud Keychain passkeys on an iPhone are synced the same way.
- **Signing stalled on the QR code.** The phone's own camera app did not
  hand the `FIDO:/…` link of the cross-device QR to Google Play services;
  Google Lens took the first QR but showed the second one as plain text.
  Google's "Scan QR code" quick-settings tile is the scanner meant for it;
  Chrome can also offer an already-linked phone by name, without a QR. We
  stopped there.

## If you pick it up

- **Quickest probe of way 3**: `cd examples/passkey-probe && python3 -m
  http.server 8765 --bind 127.0.0.1`, open `http://localhost:8765/` in
  Chrome, create a passkey with "use a phone or tablet", then sign. Check
  `flags.BE / BS` (synced?) and `verified: true`. Next step would be
  verifying that signature with ZeroDev's WebAuthn validator on a local
  anvil (the Rust integration tests show how to install contracts there).
- **Way 2 is the one that needs no app and keeps the key off any cloud**:
  install F-Droid → Termux and Termux:API; `pkg install termux-api
  openssh`; generate the key as above; start `sshd`; our CLI would gain a
  key type that runs `termux-keystore sign` over SSH. Accept the unlock
  window and blind signing, or add a confirmation dialog
  (`termux-dialog`) and a decoder run in Termux.
- **Way 1 is the strongest** (per-signature fingerprint, a screen showing
  the decoded operation, the key only in the phone) and the most work. The
  decoding could reuse our Rust (`kernel.rs`, the mandate encoding) via
  `uniffi`. On iPhone the same design runs on the Secure Enclave
  (`SecKeyCreateSignature`, `.ecdsaSignatureDigestX962SHA256`), as our Mac
  backend does — but needs an App Store / TestFlight route.
- Whatever the way, keep the cold recovery key (`RESILIENCE.md`): a phone
  is lost, reset or replaced more often than a token, and Keystore keys are
  not in any backup.
