# Devices and approaches for the OWNER key (agent-keys)
*Russian original: [OWNER_DEVICES_ru.md](OWNER_DEVICES_ru.md). Hardware beyond owner keys — agent hosts, secure elements for SBCs and IoT, HSMs — with prices: [HARDWARE_WISHLIST.md](HARDWARE_WISHLIST.md). A phone as the owner key — what was tried and where it stopped: [PHONE_OWNER.md](PHONE_OWNER.md).*

> **English summary (2026-10-20).** Which devices can hold the *owner*
> (root) key off the agent's host — the "second factor" of
> [`KEY_POLICY.md`](KEY_POLICY.md) rule 3. Main finding: many cheap devices
> sign a raw 32-byte digest with P-256 and therefore work with our
> `P256Validator` unchanged (`hw-signer` only converts DER/MPI to `r ‖ s` and
> normalizes low-s): YubiKey 5 / Nitrokey 3 PIV and OpenPGP, the Ledger
> OpenPGP app (Nano S Plus), Trezor `SignIdentity` with `nist256p1`, a second
> machine's TPM, a Mac's Secure Enclave (our backend has no presence check;
> Touch ID would need a change to it), TROPIC01 with a private pairing key
> (not implemented: our backend uses the factory key). secp256k1 wallets need ZeroDev's `ECDSAValidator`
> (`0x845ADb2C711129d4f3966735eD98a9F09fC4cE57`), FIDO2 keys and passkeys its
> `WebAuthnValidator` (`0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69`) — both
> deployed on Base and Base Sepolia (checked with `eth_getCode`). An encrypted
> key file on a USB drive is cheap but exposes the key to whatever host
> decrypts it; it fits a cold recovery owner on a separate machine, not a
> daily one. Claims are marked [V] verified (source given) or [I] inferred.
> Written by a research agent; not yet reviewed by the security audit.
> Status on 2026-11-19: the YubiKey 5 PIV backend, the phone owner apps, the
> encrypted key file, the recovery validator and `owner set-root` are
> implemented; the cells that state the project's status say so.


Date: 2026-10-20. The statements about the project's own status were brought up to the tree on 2026-11-19 (YubiKey PIV backend, phone owner apps, key file, recovery validator, `owner set-root`). Markers: **[V]** — verified (URL or
file/code), **[I]** — inference / from memory, not re-checked in this session.

## 0. What the owner key must provide and what the chain accepts

**Model** (`docs/KEY_POLICY.md`, rule 3): the owner key is out of the agent's reach.
Owner operations are rotating/revoking the agent's permission and changing the mandate. They are rare,
so a human in the loop is acceptable. Hence three questions for any device:
(a) can malware on the host the device is connected to sign
without a human (presence/PIN/button); (b) can the key be stolen (non-exportability);
(c) does the human see *what* they are signing (WYSIWYS).

**On-chain validators and signature format:**

| Class | What the device signs | Validator | Status |
|---|---|---|---|
| A. Raw P-256 over a 32-byte digest | `ECDSA(userOpHash)` → `r‖s` (64 B) | our `P256Validator` **as is** | [V] `contracts/src/P256Validator.sol`: `signature.length == 64`, `P256.verifySignature(hash, r, s, x, y)` |
| B. secp256k1 (Ethereum wallets, Keycard, Satochip) | `ECDSA(userOpHash)` **or** `personal_sign(userOpHash)` | ZeroDev `ECDSAValidator` | [V] Kernel v3.3 code (`contracts/lib/kernel/src/validator/ECDSAValidator.sol`, tag `v3.3`) first tries `recover(userOpHash)`, then `recover(toEthSignedMessageHash(userOpHash))`, so Ledger/Trezor via `personal_sign` work. Canonical address for Kernel ≥0.3.1: **`0x845ADb2C711129d4f3966735eD98a9F09fC4cE57`** ([V] [@zerodev/ecdsa-validator constants](https://unpkg.com/@zerodev/ecdsa-validator/_esm/constants.js)); code is deployed on **Base mainnet and Base Sepolia** (1819 B, [V] `eth_getCode` via `mainnet.base.org` / `sepolia.base.org`) |
| C. WebAuthn/FIDO2 assertion only | `ECDSA(sha256(authData ‖ sha256(clientDataJSON)))`, where challenge = userOpHash | ZeroDev `WebAuthnValidator` (or our own on Solady `WebAuthn.sol`) | [V] address for Kernel 0.3.0–0.3.3, version 0.0.3 (patched): **`0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69`** ([@zerodev/passkey-validator](https://unpkg.com/@zerodev/passkey-validator@5.6.0/_esm/index.js)); deployed on Base and Base Sepolia (4739 B, [V] `eth_getCode`). [V] The source at HEAD ([WebAuthnValidator.sol](https://github.com/zerodevapp/kernel-7579-plugins/blob/HEAD/src/validators/WebAuthnValidator.sol)) calls `WebAuthn.verifySignature(..., requireUserVerification = true, ...)`, `CHALLENGE_LOCATION = 23`. Hence: the **UV** flag is required (PIN or biometrics; a single touch is not enough), and clientDataJSON must start with `{"type":"webauthn.get","challenge":"…`. rpIdHash is not checked [V from the same code]. Whether the deployed bytecode matches HEAD — [I] |

**General technical notes:**
- **low-s.** Our validator (Solady `P256`) rejects high-s, while devices return a random `s`. `hw-signer` normalizes `s → n − s` in every backend (`normalize_low_s`) [V `signer/crates/hw-signer/src/lib.rs`]. This is needed for all class A devices.
- **DER→raw.** PIV, PKCS#11 and OpenPGP return DER or MPI; we convert to `r‖s` (done for PIV: `der_ecdsa_rs` in the YubiKey backend [V]; the others [I]).
- **WYSIWYS.** None of the USB devices below shows the human *what* the userOp changes: Kernel `userOpHash` is not EIP-712, there is no clear-signing. Physical confirmation protects against *silent* signing by malware, but not against a compromised host substituting the hash at the moment the human actually wants to sign. Mitigation: sign on a separate machine; check the hash or the decoded calldata on a second screen (a phone or another PC). Devices with a screen (Trezor, Ledger) at least show the hash. The exception is the phone owner app: it decodes the operation and shows it before signing [V `mobile/owner-core/src/review.rs`].
- **Our own validators.** `P256Validator` stores one key per account (`mapping(account => key)`), and the ValidationId in Kernel is the module address. A second P-256 key (recovery) requires a second contract instance at a different address [V from the code]; this is now `contracts/src/P256RecoveryValidator.sol` (§5).

---

## 1. Comparison table

Fit — suitability for the owner role: H / M / L. Prices are a 2026 guideline.

| Device | Price | Curve / mode | Validator | Presence / PIN | Openness | Integration from Rust | Fit |
|---|---|---|---|---|---|---|---|
| **YubiKey 5 — PIV** | $58 (5 NFC) [V](https://yubico.com/product/yubikey-5-nfc/) | P-256, **raw digest** (GENERAL AUTHENTICATE over the hash) [V: in the `yubikey` crate `piv::sign_data(raw_in, AlgorithmId, slot)` passes the input bytes as is] | **P256Validator as is** | PIN policy never/once/always, touch policy never/always/cached (15 s); set at generation and cannot be changed [V](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html) | closed firmware, not updatable | already in the code: `hw-signer` feature `yubikey-piv` (crate `yubikey` 0.9.0-rc.0, pure Rust over PC/SC), see `docs/YUBIKEY.md` [V]; Linux/macOS/Windows | **H** |
| YubiKey 5 — OpenPGP | same | P-256 ECDSA over the hash (PSO:CDS) [I: per the OpenPGP card spec]; no secp256k1 [I] | P256Validator | PW1 PIN + UIF (touch) [I] | closed | `openpgp-card` + `card-backend-pcsc` [V crates.io] | M (PIV is simpler) |
| YubiKey 5 / Security Key — FIDO2 | Security Key NFC ~$25 [V](https://www.pbtech.co.nz/product/MEMYBC9257/Yubico-Security-Key-NFC---USB-A-FIDO-Only---v57) | assertion only (ES256) | WebAuthnValidator | touch (UP) + PIN (UV, required by the validator) | closed | CTAP2: `ctap-hid-fido2` 3.6, `fido2-rs` (libfido2), `authenticator` [V crates.io]; on Windows without admin — only via `webauthn.dll` [I] | M |
| **Nitrokey 3 (A/C NFC)** | €55 [V](https://shop.nitrokey.com/shop/nk3an-nitrokey-3a-nfc-147) | OpenPGP: NIST P-256/384/521, brainpool, Curve25519, RSA; PIV: **P-256**, RSA-2048 [V](https://docs.nitrokey.com/nitrokey3/faq); PIV since fw 1.8 (Jan 2025) [V](https://www.nitrokey.com/node/648); secp256k1 in OpenPGP is claimed but in practice does not import [V](https://support.nitrokey.com/t/cant-import-secp256k1-key-to-nitrokey-3a-nfc/6463) | **P256Validator as is** (PIV or OpenPGP over the hash) | OpenPGP UIF: off / on / permanent, separately for sign, dec and auth [V](https://docs.nitrokey.com/nitrokeys/features/openpgp-card/uif); touch policy for PIV — [I], to check | **open firmware** (Trussed, Rust), OpenPGP keys in **NXP SE050** (EAL6+) [V FAQ] | PC/SC: `openpgp-card`, PIV via `cryptoki` + OpenSC [I] | **H** |
| SoloKeys Solo 2 | ~€59 at retailers [I], availability is unstable; shop: [solokeys.com](https://solokeys.com/collections/solo-2-secure) | FIDO2 (ES256) [I: no PIV/OpenPGP] | WebAuthnValidator | touch + PIN | open HW and FW (Trussed) | CTAP2 (as above) | L–M |
| Google Titan (FIDO2) | $30 USB-A / $35 USB-C [V](https://betanews.com/article/buy-google-titan-security-key) | FIDO2 only | WebAuthnValidator | touch + PIN | closed (OpenSK-based, [I]) | CTAP2 | M (cheap) |
| Feitian ePass K9 / Token2 PIN+ | K9 ~£23; Token2 PIN+ €15–26, Bio3 €37 [V](https://node-07-prod.token2.com/c/pin-plus-series) | FIDO2; the Token2 PIN+ R3.3 and Feitian K9PLUS models also have **PIV/OpenPGP** [V by SKU names](https://chert.ng/feitian-epass-k9plus-usb-a-fido2-u2f-nfc-piv-openpgp-otp-security-key-k9plus.html) | WebAuthn; PIV variant → P256Validator [I: P-256 support in PIV for the specific SKU to be checked] | touch + PIN; Token2 has PIN complexity | closed | CTAP2 / PKCS#11 | M |
| OnlyKey | $49.99 (usually $69.99) [V](https://onlykey.io/collections/all) | 16 ECC slots, **NIST256P1 and SECP256K1** [V](https://docs.onlykey.io/command-line/) | P256Validator (if it signs a raw hash, [I]) or ECDSAValidator | 6 touch buttons, PIN is entered on the device itself (not keylogger-able) [I] | open FW | its own HID protocol; only the Python `onlykey-cli` and the `okman` crate exist [V](https://docs.rs/crate/okman/0.1.1), incomplete | M (interesting: PIN on the device), but integration is expensive |
| **SmartCard-HSM / Nitrokey HSM 2** | NK HSM 2 €99–109 [V](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7); SmartCard-HSM card ~€25–35 [I] | NIST P-192…521, brainpool, **secp256k1**; ECDSA over the hash (`CKM_ECDSA`) [V](https://www.nitrokey.com/files/doc/Nitrokey_HSM_factsheet.pdf) | P256Validator **or** ECDSAValidator | PIN only, no button; n-of-m backup via DKEK [I] | closed card OS, open client (OpenSC) | PKCS#11: `cryptoki` 0.12 + OpenSC [V crates.io] | M (no presence) |
| Generic JavaCard (J3R180 etc.) + PivApplet / SmartPGP | ~$9–15 per card [V](https://www.ihsgonline.com/products/j3r180-jcop4-180k-java-smart-card-replace-j2a040-chip-java-j/233358068/) + reader ~$15 | SmartPGP: P-256/384/521, brainpool [V](https://github.com/github-af/SmartPGP); PIV applet: P-256 [I] | P256Validator | PIN; no touch (the card is removed from the reader) | open applets | PC/SC (`pcsc`, `openpgp-card`) | M (cheap, but DIY: flashing via GlobalPlatformPro) |
| Keycard (+ Shell) | card ~$25–30 [I]; Shell €109 discounted (usually €149) [V](https://get.keycard.tech/pages/keycard-shell) | **secp256k1**, "hash in — signature out", APDU with secure channel [V](https://docs.keycard.tech/en/developers) | ECDSAValidator | PIN + pairing; Shell has a screen and keypad | open applet and Shell | PC/SC + its own secure channel; no Rust crate [V: no `keycard` on crates.io] | M |
| Satochip | ~€25 + reader ~€15 [V](https://sitegeek.fr/article-technologie/satochip-test-du-hardware-wallet-pour-vos-cryptomonnaies-open-source-et-abordable) | **secp256k1**, hash signing [I] | ECDSAValidator | PIN | open applet [V](https://github.com/Toporin/SatoChipApplet) | PC/SC, its own protocol, no Rust crate | L–M |
| **Ledger Nano S Plus** | ~$59–79 [V](https://financer.com/crypto/crypto-wallet-hardware/) | (1) Ethereum app: secp256k1, `personal_sign` | (1) **ECDSAValidator** (address above) | screen + 2 buttons, PIN on the device; seed backup | Secure Element closed; OS partly open, apps open | `alloy-signer-ledger` 2.5 [V crates.io], `coins-ledger` | **H** |
|  |  | (2) **OpenPGP app**: secp256r1, `cx_ecdsa_sign_no_throw(..., CX_NONE, digest)`, i.e. a **raw digest** without hashing; builds for Nano S Plus (`TARGET_NANOS2`) [V](https://github.com/LedgerHQ/app-openpgp/blob/HEAD/src/gpg_pso.c) | (2) **P256Validator as is** | UIF confirmation on the device + PW1 PIN [V same file] | open app | `openpgp-card` (PC/SC CCID) [V: it does; run on 2026-11-21, see the end of section 2] | H/M |
|  |  | (3) Security Key app: FIDO2/U2F; resident keys disabled [V](https://developers.ledger.com/docs/ai-tools/hardware-security/security-key) | (3) WebAuthnValidator (non-resident will do) | button | | CTAP2 | M |
|  |  | (4) SSH/PGP Agent app — **DEPRECATED** [V](https://github.com/LedgerHQ/app-ssh-agent) | — | | | | — |
| **Trezor Safe 3 / Safe 5** | $59 / ~$129 [V](https://financer.com/crypto/crypto-wallet-hardware/) | (1) Ethereum: secp256k1, `personal_sign` | (1) ECDSAValidator | screen + button or touch, PIN on the device; seed | **fully open FW** | `alloy-signer-trezor` 2.5, `trezor-client` 0.1.6 [V crates.io] | **H** |
|  |  | (2) **`SignIdentity`, proto `gpg`, `ecdsa_curve_name = "nist256p1"`**: signs `challenge_hidden` **as is** (`nist256p1.sign(seckey, data)`, without hashing); the key is derived deterministically from the seed along a path from the identity [V](https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/misc/sign_identity.py) | (2) **P256Validator as is** | confirmation on the device (shows the identity and `challenge_visual`; the text is set by the host) | open | `trezor-client` includes `SignIdentity` [V: grep in the crate source] | **H** |
|  |  | (3) FIDO2 [I] | WebAuthn | | | | M |
| Trezor Safe 7 | $249 [V](https://www.ibtimes.co.uk/trezor-launches-trezor-safe-7-first-hardware-wallet-transparent-secure-element-1749151) | same as Safe 3/5 (core branch) [I]; inside: **TROPIC01 + OPTIGA Trust M + STM32U5**; the SEs handle PIN, authenticity and RNG, signing is done by the MCU from the seed [V](https://trezor.io/guides/trezor-devices/trezor-safe-7/dual-secure-elements-in-trezor-safe-7) | P256Validator (SignIdentity) / ECDSAValidator | touch screen, PIN | open FW, "transparent" SE | as Trezor | H (expensive) |
| Keystone 3 Pro | $149 [V](https://walletpilot.com/hardware-wallets/keystone-3-pro) | secp256k1, air-gapped via QR (UR) | ECDSAValidator | screen, PIN, fingerprint | open FW | QR/UR — own implementation; Rust UR libraries exist [I] | M |
| GridPlus Lattice1 | $397 [V](https://ethereum.org/ar/wallets/find-wallet/gridplus-lattice1/) | secp256k1 (+ ed25519) [I] | ECDSAValidator | large screen | partly open | JS SDK, network connection | L (price, complexity) |
| Platform passkey (iOS/Android/Win Hello/macOS) | $0 | WebAuthn assertion only | WebAuthnValidator | UV via biometrics or PIN | closed | needs a browser/WebAuthn page or a native app; hybrid flow (QR) for a phone as the authenticator [I] | M; synced passkeys live in a cloud account → device-bound is better |
| Phone: own app with the key in SE / StrongBox | $0 + development | **raw P-256**: Android Keystore/StrongBox supports `DIGEST_NONE` for EC P-256 [V](https://developer.android.com/training/articles/keystore); iOS — CryptoKit `SecureEnclave.P256.Signing` over the digest as is [V `mobile/ios/OwnerApp/Keys.swift`] | **P256Validator as is** | `setUserAuthenticationRequired` (Android), `.biometryCurrentSet` (iOS) — enforced in hardware [I] | closed | implemented: `mobile/android` (debug build only so far), `mobile/ios`, shared `mobile/owner-core`; a QR plus a LAN session with the CLI (`docs/MOBILE_OWNER_DESIGN.md`) [V] | M–H (strong model: separate device + biometrics + screen; owner role only) |
| **Mac with Secure Enclave + Touch ID** (own or a second Mac) | $0 | P-256, raw digest (already implemented: CryptoKit shim) [V `docs/SECURE_ENCLAVE.md`, project memory] | **P256Validator as is** | none in our backend today: the key is created with `.privateKeyUsage` only [V `SecureEnclaveShim.swift`]; `userPresence`/biometrics, enforced by the SE, needs a change to the Swift shim | closed | already in the `hw-signer` code, without presence | **H** (if it is not the agent host, otherwise placement 2) |
| **TPM of a second machine** | $0 | P-256, raw digest (already implemented) | **P256Validator as is** | authValue/PIN; the TPM has no physical presence | — | already in the code (`tss-esapi`, CNG) | **H** (as a separate machine) |
| **TROPIC01 USB DevKit** | €50 [V](https://www.tropicsquare.com/order-devboard-form) | P-256 ECDSA over a 32-byte hash (`ECDSA_Sign`, MSG_HASH 32 B) [V user API 1.4.0] | **P256Validator as is** | **none** on the chip (GPO is output only) [V user API, `CFG_GPO`]; access restricted by the pairing key (our backend opens the session with the public factory key SH0; a private pairing key is not implemented) | **open architecture** | already in the code (`tropic01` 0.1.0, git rev `3310775`) | M–H (see §3) |
| Owner = Safe / weighted multisig | gas | mix of factors | Safe (1271) or ZeroDev Weighted Validator (ECDSA + WebAuthn signers) [V](https://unpkg.com/@zerodev/weighted-validator/_esm/index.js) or our own k-of-n P-256 | sum of the factors | — | medium–high | H for mainnet (see §5) |
| Encrypted file on a USB drive | ~$5 | any curve | any (P-256 → ours as is) | none | — | `age`/`scrypt`/`eth-keystore` + `zeroize` [V crates.io] | L–M (see §6) |

---

## 2. Recommendation shortlist

### Cheapest acceptable
1. **Nitrokey 3A NFC, €55: PIV P-256 + PIN (+ touch).** Works with our
   `P256Validator` without a single line of Solidity. The firmware is open, the keys live in
   the SE050. If the NK3 has no touch policy in PIV (to check), we use an OpenPGP key
   with UIF=permanent.
2. **Token2 PIN+ R3.3, €22–23** (FIDO2 + PIV + OpenPGP). If PIV P-256
   is confirmed — the same as item 1, but cheaper and with closed firmware. If used
   only as FIDO2, `WebAuthnValidator` is needed.
3. **Trezor Safe 3, $59**: `SignIdentity` gpg/nist256p1 gives P256Validator as
   is. Plus a screen, PIN on the device and seed backup. Price-wise it is at YubiKey level,
   and the model is better: the PIN is entered on the device, and there is a backup.

A $25–30 FIDO2 key (Yubico Security Key, Titan) is also acceptable security-wise:
touch + PIN, the key is non-exportable. But it pulls in `WebAuthnValidator` and
a CTAP2 stack in the CLI. Keys with PIV/OpenPGP for the same money are simpler for our architecture.

### Best practice (mainnet)
- **A separate device with a screen and seed backup + an on-chain recovery factor.**
  Main option: Trezor (Safe 3/5/7, `SignIdentity` nist256p1 →
  `P256Validator`) or Ledger (OpenPGP app secp256r1 → `P256Validator`; or
  Ethereum app → `ECDSAValidator`). Recovery: a second validator with access
  **only** to `changeRootValidator` (see §5) — a cold key in a safe or
  a second device.
- Sign from a machine that is **not** the agent host. Check the userOpHash on
  the device screen against an independent source (a second PC or a phone).

### "Already in hand"
| What | How to use it as owner | Validator | Work |
|---|---|---|---|
| **Ledger Nano S Plus** | (a) Ethereum app, `personal_sign(userOpHash)`; (b) OpenPGP app, secp256r1 key, PSO:CDS over userOpHash | (a) ECDSAValidator `0x845A…cE57` (already on Base); (b) P256Validator as is | (a) `alloy-signer-ledger` → `signMessage`, root = ECDSAValidator: change of the root validator + CLI support; (b) `openpgp-card` client + DER/MPI → `r‖s` + low-s. Option (b) does not change the chain at all [V app-openpgp code; V — the app installs on the S Plus, run on 2026-11-21] |
| **YubiKey 5 PIV** | slot 9c, PIN always + touch always (`docs/YUBIKEY.md`) | P256Validator as is | zero: the backend exists; it is the current owner key of the test accounts |
| **TROPIC01 devkit** | a separate USB owner device, plugged in only for owner operations, with a private pairing key (§3) | P256Validator as is | provisioning the pairing key (SH1), UAP restrictions, invalidate SH0; storing SH1-priv (encrypted) on the owner machine |
| **TPM of a second machine / Windows PC / Mac** | owner key on another machine, the CLI runs there | P256Validator as is | zero for the TPM and CNG; for a Mac, zero without presence and a shim change for Touch ID: the `tpm`, `windows_tpm`, Secure Enclave backends already exist; only moving root operations (`sudo agent-signer permission …`) to that machine is needed |

### Ledger, the OpenPGP app: the first experiment (2026-11-21)

Run before any backend code, with `gpg-connect-agent` commands only: a Ledger
Nano S Plus with the OpenPGP app (card specification 3.3), from macOS with
GnuPG 2.5.18 over PC/SC.

- **The P-256 path works.** A key generated on the device in the signature
  slot (template `nistp256`) signed a 32-byte digest of our choosing as is.
  The answer is `r` and `s` in two 33-byte fields, each with a leading zero;
  cut to 32 bytes it verifies with `agent-signer verify` and with the P-256
  precompile on Base Sepolia. The vector is
  `contracts/test/vectors/p256_ledger_openpgp.json`. `s` happened to be low;
  a backend still has to normalise.
- **The confirmation is blind.** With the app's UIF setting on for
  signatures the device shows a confirmation screen that names a signature
  and nothing of the digest; two button actions approve it.
- **The PIN was asked on the computer.** GnuPG prompted for the app's PINs
  itself. The host does offer PIN verification on the reader for this device
  (the PC/SC feature `VERIFY_PIN_DIRECT`), so a backend of our own could keep
  the PIN off the computer; not tried.
- **Five seconds on macOS's built-in CCID driver.** That driver gave up 5.0 s
  after the signing request, while the device waited for the confirmation. A
  confirmation given later still signed on the device (its signature counter
  rose), the answer was lost, and the device had to be plugged in again.
  Ledger's guide recommends macOS's other driver (`useIFDCCID`); not tried.
- **The app's data does not survive updates**
  [V](https://openpgp.apps.ledger.com/app-openpgp.html): keys, PINs and
  settings are erased when the app or the device's OS is updated. In the
  app's seed mode the keys can be regenerated from the device's seed;
  otherwise they are gone. An owner key held this way needs a recovery key
  in place before any update.
- The app's PINs have public default values; change them before real use.

Not done: a backend, an account with such a key as its root, the secp256k1
route, a Trezor.

---

## 3. An open secure element as a separate USB owner device

### 3.1 TROPIC01

**Facts** (datasheet A.11 and User API 1.4.0 from
[github.com/tropicsquare/tropic01](https://github.com/tropicsquare/tropic01), as well as the `tropic01` SDK rev `3310775`):
- **Pairing keys.** 4 slots SH0–SH3 with an X25519 public key [V: `PAIRING_KEY_SLOT_MAX = 3` in `lt_3.rs`; datasheet §7.5.3]. Tropic Square writes its own SH0PUB at manufacturing and gives customers SH0PRIV; in the SDK it sits as `SH0PRIV_PROD0`, i.e. it is **public** [V `tropic01/src/keys.rs`]. A session on slot i can be opened by anyone who knows SHiPRIV (a Noise-like handshake on X25519).
- **Production path** (datasheet §5.4, fig. 4, §7.5.4) [V]:
  1. Open a session on SH0.
  2. Generate your own SH1 pair (and, for example, SH2 for a backup machine) and write SH1PUB with the `Pairing_Key_Write` command.
  3. Restrict privileges (UAP).
  4. **Invalidate SH0** (`Pairing_Key_Invalidate`).

  After that only the holder of SH1PRIV can open a session.
- **Rotation and revocation.** The slots are effectively **write-once**: `Pairing_Key_Write` to a Valid or Invalidated slot → `FAIL`, and "Invalidated is impossible to change" [V §7.5.3]. A key can be revoked (irreversibly) but not overwritten. The budget is three customer keys for the whole lifetime of the chip. If all four are invalidated, the chip is dead [V warning in §7.5.3].
- **UAP.** Each L3 command has a bit mask over the pairing-key slots; for `ECDSA_Sign` it is separate per ECC slot group 0–7/8–15/16–23/24–31 (`CFG_UAP_ECDSA_SIGN`, 0x140) [V user API]. A bit cleared in I-Config is an **irreversible** prohibition [V datasheet §7.5]. Example: slot SH2 (backup) may only do `Ping`, `ECC_Key_Read` and `ECDSA_Sign`, while `ECC_Key_Generate/Erase` and config writes are allowed only to SH1 or forbidden forever. Then a leak of SH2PRIV does not allow erasing or replacing the key.
- **Signing.** `ECDSA_Sign` takes `MSG_HASH` (32 B) and returns `R`, `S` [V user API, table 32]. This is a raw digest; `P256Validator` works as is (already proven on-chain).
- **User presence.** The chip itself has **no** button input: GPO is output only (`ALWAYS_LOW/HIGH/INTERRUPT`) [V `CFG_GPO`]. Presence is possible only on the MCU bridge side. On the devkit this is an STM32U5 with USB↔SPI firmware [V `docs/TROPIC01.md`]. Whether the devkit has a button usable by custom firmware, and whether the stock bridge firmware is open — **not confirmed** [I, check on the board and in the Tropic Square repo].
- **Hardware PIN attempt limit.** The `MAC_And_Destroy` primitive (128 slots) [V `lt_3.rs`] is a PIN mechanism with a hardware-limited number of attempts, used by Trezor Safe 7 [I per Trezor's description]. With it one can build a chip-limited PIN: the host derives the SH1PRIV decryption key via MAC-and-Destroy [I, design idea].
- **Prices and availability** [V](https://www.tropicsquare.com/order-devboard-form):
  - chip sample €5;
  - USB DevKit €50;
  - MikroE Click, RPi Shield, Arduino Shield — €20 each;
  - Mini Board €9.50;

  all in stock, ordering via a form, shipping outside the EU €35–55. The consumer product is **Trezor Safe 7, $249** (there TROPIC01 guards the PIN and secrets rather than signing, see the table). Our part `TR01-C2P-T103` is marked **Deprecated** [V part-numbers.md]. This does not affect the devkit, but a product needs a current part.

**What TROPIC01 gives as an owner device (devkit, private SH1):**
- The key is non-exportable. A host compromised at connection time can *sign* while the device is plugged in, but cannot *take away* the key. This is the main difference from a USB drive (§6).
- When disconnected, nothing can be signed.
- The pairing secret SH1PRIV is a file on the owner machine; it must be stored encrypted with a password (age/scrypt) or in that machine's TPM. A leak of SH1PRIV ≠ a leak of the owner key: the attacker also needs physical access to the device, and the slot can be invalidated.
- **No button and no screen**: malware on the host will sign anything while the devkit is plugged in. So this is the "separate device, connected only for the duration of the operation" placement, not "presence". In strength — between a USB drive and a YubiKey with touch policy.

**Improved TROPIC01 variant (DIY):** RPi Zero 2 W (~$15) + **TROPIC01 RPi Shield (€20)** + a button on GPIO + a small OLED (~$5). The result is an "owner appliance" ≈ €45–55:
- The Pi in USB-gadget mode (or over the network/QR) receives the userOpHash, shows it on the OLED and waits for the button.
- SH1PRIV lives only on the Pi (encrypted on the SD card; PIN unlock via MAC-and-Destroy).
- The owner's host never sees the pairing key at all. This is Madhwal's architecture (ATECC608A on a Raspberry Pi [V: his Skoltech research seminar of October 2026, cited in `docs/ARCHITECTURE.md`]), only with an open SE and a button.
- Weak point: Linux on the Pi is a large TCB. A stricter variant is a bare-metal MCU (RP2040/STM32) + TROPIC01 Mini Board (€9.50); the `tropic01` crate is `embedded-hal`-based, i.e. no_std-ready [V crate description].

### 3.2 Comparable SEs

| SE | Chip / board price | Raw P-256 digest? | How the host authenticates | Presence | Ready-made USB products |
|---|---|---|---|---|---|
| **TROPIC01** | €5 / devkit €50, shields €20 | **yes** (`ECDSA_Sign`, 32 B) [V] | mandatory X25519 secure channel per pairing slot; write-once, irreversible invalidate; UAP per slot [V] | no (only via MCU) | Trezor Safe 7 (not as a raw signer) |
| **Infineon OPTIGA Trust M** (P-256/384/521, brainpool, RSA-2048 [V](https://mouser.com/datasheet/2/196/Infineon_OPTIGA_Trust_M_ProductBrief_v04_00_EN-1665636.pdf)) | ~$1–2 [I]; eval/Shield2Go ~£21 [V](https://uk.rs-online.com/web/p/microcontroller-development-tools/0277233) | **yes**: `optiga_crypt_ecdsa_sign(digest, digest_length, key_oid, …)` [V](https://github.com/Infineon/optiga-trust-m/blob/master/include/optiga_crypt.h) | "Shielded Connection": I2C is encrypted with a key from the Platform Binding Secret (PBS) shared with the host MCU. On V3 the PBS is not pre-provisioned and is generated at runtime; on Express/MTR it is pre-provisioned [V](https://community.infineon.com/t5/Blogs/How-is-a-secure-connection-established-with-Host-microcontroller/ba-p/363849). Plus access conditions on data objects [I] | no | inside Trezor Safe 7; found no open USB keys [I]. No Rust crate [V crates.io] |
| **Microchip ATECC608A/B** (P-256 only) | ~$0.76–1.17 [V](https://www.microchip.com/en-us/product/atecc608a); Adafruit board ~$7 [I] | **yes**: `atcab_sign(key_id, msg[32], sig)` — "sign a 32-byte external message… R‖S big-endian, 64 bytes" [V](https://github.com/MicrochipTech/cryptoauthlib/blob/main/lib/calib/calib_sign.c) | IO Protection Key (bus encryption and binding to the MCU), slot config / KeyConfig, permanent config lock [I: full datasheet under NDA]; without a lock anyone on the bus can sign | no | Madhwal's reference (RPi) [V local PDF]; Rust: `rust-cryptoauthlib` (last release 2022) [V crates.io] |
| **NXP SE050** (P-224…521, brainpool, **secp256k1**, ed25519, RSA [V](https://git.mitjafelicijan.com/r/luna/raw/wolfssl/wolfcrypt/src/port/nxp/README_SE050.md)) | ~$4–5 [V](https://lcsc.com/product-detail/image/SE050C2HQ1-Z01SDZ_C2659345.html); OM-SE050ARD-E $60–74 [V](https://www.avnet.com/americas/product/nxp/om-se050ard-e/evolve-57690039) | **yes**: ECDSASign over a supplied hash [I per the Plug&Trust API]. **Plus secp256k1**, so it also fits ECDSAValidator | Platform SCP03 (AES) and sessions with authenticator keys (UserID / AESKey / ECKey) per object [V same README; I details] | no | **Nitrokey 3** (SE050 inside) [V](https://docs.nitrokey.com/nitrokey3/faq); Rust: `se05x` 0.4.2 (Nitrokey) [V crates.io] |

**Summary:**
- All four sign a raw P-256 digest, so any of them works with `P256Validator` as is.
- None has user presence on the die: the button and screen are always provided by the surrounding hardware (MCU/device).
- Host authentication model:
  - the most expressive and open is TROPIC01: write-once pairing, irreversible revocation, UAP per slot and per key group, all documented without an NDA;
  - SE050 — flexible, but the documentation is partly under NDA [I];
  - ATECC608 — the crudest: config lock and an IO key.

### 3.3 Recommendation: the cheapest practical "TROPIC01-like" owner device

1. **Buy ready-made: Nitrokey 3A NFC (€55).** Open firmware, SE050, button (UIF), PIN, PIV/OpenPGP P-256 → `P256Validator` as is. This is exactly the "open SE in a USB case with presence" that the TROPIC01 devkit lacks.
2. **Buy ready-made, with a screen and backup: Trezor Safe 3 ($59).** `SignIdentity` nist256p1 → `P256Validator` as is. If you specifically want TROPIC01 inside — Safe 7 ($249).
3. **Use a TROPIC01 devkit:** private SH1 + invalidate SH0 + UAP + storing SH1PRIV encrypted only on the owner machine + connecting only for the duration of the operation. No extra purchase where a devkit is already at hand, but no presence.
4. **DIY with presence: RPi Zero 2 W + TROPIC01 RPi Shield + button + OLED ≈ €50.** The best open model, but it is a project, not a purchase.

---

## 4. What is needed on-chain for each class

| Device class | Validator | Work |
|---|---|---|
| A: raw P-256 — YubiKey/Nitrokey/Token2 PIV, OpenPGP cards (incl. Ledger OpenPGP app), Trezor `SignIdentity` nist256p1, TROPIC01, ATECC/OPTIGA/SE050, TPM, Secure Enclave, Android StrongBox `DIGEST_NONE`, SmartCard-HSM | **`P256Validator` as is** | Solidity — zero. CLI: a backend per device (PKCS#11 / PC/SC / HID), DER/MPI → `r‖s`, low-s — done for YubiKey PIV, TROPIC01, TPM, Secure Enclave and the phone apps. Changing the owner to a new key: `agent-signer owner set-root` (another P256Validator instance, or `--retire` of the same one with a reinstall); the new key first shows that it can sign (`--new-key` / `key prove`, or `--to-phone`) [V `chain.rs`, `owner set-root --help`] |
| B: secp256k1 — Ledger/Trezor Ethereum app, Keycard, Satochip, Keystone, Lattice, SE050 (k1), SmartCard-HSM (k1) | ZeroDev **`ECDSAValidator` `0x845ADb2C711129d4f3966735eD98a9F09fC4cE57`** (present on Base and Base Sepolia) | Solidity — zero. CLI: `changeRootValidator(ECDSAValidator, owner address)`; signing via `alloy-signer-ledger` / `alloy-signer-trezor` (`signMessage(userOpHash)` — the validator accepts EIP-191); signature format 65 B `r‖s‖v` |
| C: FIDO2 / passkeys — Security Key, Titan, Feitian, Solo 2, Ledger Security Key, platform passkeys | ZeroDev **`WebAuthnValidator` `0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69`** or our own on Solady `WebAuthn.sol` (already in `contracts/lib/solady`) | Solidity — zero (if using ZeroDev) or a small module. CLI: CTAP2 `getAssertion` with our own `clientDataJSON` (`{"type":"webauthn.get","challenge":"<b64url(userOpHash)>",…}`), UV=required; encoding `(authData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled)`. Store the credential ID in the config (non-resident) |
| Multi-factor | ZeroDev Weighted Validator (ECDSA + WebAuthn signers) [V package], Safe owner (1271) or our own k-of-n P-256 | Our own k-of-n P-256 is ~100 lines based on `P256Validator`, needs an audit. ZeroDev's Weighted covers classes B+C, but not A |

---

## 5. Multisig, social recovery and a cold recovery owner

- **Kernel v3 allows "narrow" non-root validators.** For them `allowedSelectors[vId][selector]` is checked, and `grantAccess(vId, selector, allow)` can be called only by root [V `contracts/lib/kernel/src/Kernel.sol:261,392`; `changeRootValidator` — line 135]. Hence the **recovery owner**: a second validator (a second P256Validator instance or ECDSAValidator) with access **only** to `changeRootValidator`. Implemented: `contracts/src/P256RecoveryValidator.sol` (a `P256Validator` under its own address that refuses ERC-1271), `agent-signer owner add-recovery` / `owner recover` [V]. The everyday owner is a cheap key; recovery is a cold key (paper, safe, a second Ledger), needed only if the main one is lost.
  - **Important:** a recovery validator that is allowed `changeRootValidator` is effectively root too. Its protection must be no weaker than the main key's. Adding a timelock is desirable: `kernel-7579-plugins` has a `TimelockPolicy` [V repo tree], but its applicability to a validator rather than a permission — [I]. Our contracts have no timelock yet.
- **2-of-3 from cheap factors**, e.g. YubiKey + Trezor + TPM of a second machine: our own k-of-n P-256 validator (all three are class A) or a Safe owner. This is best practice for mainnet amounts: one compromised machine does not give root.
- **Paper or QR backup.** A P-256 key generated offline on a separate machine is printed as QR/hex and kept in a safe. It is then imported into YubiKey PIV (import is supported, [I]), TROPIC01 (`ECC_Key_Store` [V `lt_3.rs`]) or Ledger OpenPGP. This way the hardware key gets a backup. Downside: such a key "has been outside", and the "generated in the chip" attestation is lost. An alternative without import is seed wallets (Trezor `SignIdentity` and Ledger OpenPGP in seed mode [I]): the backup is 24 words, the key is deterministic.

---

## 6. The owner's idea: the owner key as an encrypted file on a USB drive

**Scheme.** The P-256 (or k1) scalar is encrypted with a password: Ethereum V3 keystore (scrypt + AES-128-CTR, the format is curve-independent; the `address` field is meaningless for P-256), `age` with an scrypt recipient, or our own argon2id + XChaCha20-Poly1305. The USB drive is inserted only for the duration of an owner operation.

**What it protects:**
- the key at rest is off the agent host: stealing the agent's file system gives nothing (closes premise 2);
- persistent compromise of the host **while the drive is not inserted** gives nothing;
- a copy on the drive (or two) solves backup; any curve;
- price ~$5, zero Solidity (for P-256 — `P256Validator` as is).

**What it does NOT protect (honestly):**
- **At signing time the key is decrypted in host memory.** A host compromised *at that moment* (and in our model root on the agent host may be reachable) gets **the key itself, forever**, not a single signature. This is a qualitative difference from any SE (TROPIC01, YubiKey, Trezor): there a compromised host can only sign while the device is connected.
- **A keylogger** captures the password; together with a copy of the file (the drive was inserted) the key is lost.
- **No presence check:** after decryption malware will sign anything, and the user does not see what is signed.
- **Drive theft + weak password = offline brute force.** scrypt/argon2 slows it down but does not prevent it.
- **It must not be used on the agent host:** there the attacker sees the password and the key (premise 3–4). It is acceptable only on a separate machine, ideally offline (an air-gapped laptop or live USB), with the userOpHash transferred by QR code.

**Comparison with a $25 FIDO2 key:**

| | USB drive + password | FIDO2 key ($25) |
|---|---|---|
| Key leaves the medium | **yes**, on every signature | never |
| Compromised host during the operation | steals the key forever | one signature on touch + PIN |
| Presence | none | touch (UP) + PIN (UV) |
| Backup | trivial (file copy) | needs a second key or a recovery validator |
| Validator | P256Validator as is | WebAuthnValidator |

**Conclusion:** the USB drive is better than a "key in a file on the agent host" and is suitable as a **cold recovery owner** (§5) on an offline machine. As an everyday owner it is worse than a $25 FIDO2 key, YubiKey PIV, Nitrokey or Trezor. Hybrid: FIDO2 **hmac-secret** (the same $25 key) derives the file encryption key — decryption requires a touch and the physical key. But the key still ends up in host memory [I: this is what `systemd-cryptenroll --fido2-device` and age plugins do].

**Conflict with rule 5 and wording.** Rule 5 read at the time: "No plaintext private key, anywhere outside tests" (`KEY_POLICY.md` carries the exception now). An encrypted file is formally not plaintext, but once decrypted it is. The wording proposed then:

> **5. No plaintext private key at rest, and no private key ever on the agent
> host.** Outside tests, a private key exists in plaintext only inside a secure
> element. Exception — *an owner or recovery key on removable media*, if all
> of: (a) encrypted with a memory-hard KDF (scrypt N ≥ 2^18 or argon2id ≥ 256
> MiB) and an AEAD; (b) the passphrase is typed at use time, never stored;
> (c) decrypted only on a machine that is not an agent host (ideally offline),
> in process memory only, zeroized after signing (`zeroize`), never written to
> disk or swap (mlock); (d) the media is disconnected outside owner operations;
> (e) used for root operations only — never as the agent key. The software
> backend remains test-only for the agent role.

Minimum implementation requirements in the CLI [I], and what `signer/crates/agent-signer/src/keyfile.rs` does today [V]:
- a separate `encrypted-file` backend, available **only** to the owner/recovery role — done, under the name `keyfile`;
- refuse to work if the config or the host is marked as an agent host — not implemented: no such mark exists;
- scrypt/argon2id + AEAD (`age` 0.12 or `scrypt` + `chacha20poly1305`) — done as scrypt N = 2^18 + AES-256-GCM;
- password via `rpassword`, not via env or arguments — done;
- `Zeroizing<[u8; 32]>`, `mlock`, signing with the same `p256` with low-s — done (`mlock` on Unix);
- check: the public key after decryption matches `ownerPublicKey` from the config — done differently: the file's public half is bound to the ciphertext and compared with the account's root or recovery key on chain before anything is signed.

---

## 7. Integration from Rust (summary by transport)

| Transport | Devices | Crates [V crates.io, 2026-10] | OS |
|---|---|---|---|
| PC/SC (CCID) | YubiKey PIV/OpenPGP, Nitrokey 3, JavaCard, Keycard, Satochip, Ledger OpenPGP app [I], SmartCard-HSM | `pcsc` 2.9, `yubikey` 0.9.0-rc.0 (already in the project), `openpgp-card` 0.7 + `card-backend-pcsc` 0.5 | Linux (pcscd), macOS, Windows — built in |
| PKCS#11 | YubiKey (ykcs11), Nitrokey (OpenSC), SmartCard-HSM | `cryptoki` 0.12 | all; needs a .so/.dll module |
| CTAP2 HID | all FIDO2 keys, Ledger/Trezor FIDO | `ctap-hid-fido2` 3.6, `fido2-rs` 0.6 (libfido2), `authenticator` 0.5 | Linux/macOS — directly; Windows — without admin only via `webauthn.dll` [I] |
| Ledger APDU over HID | Ledger Ethereum app | `alloy-signer-ledger` 2.5, `coins-ledger` 0.16 | all |
| Trezor protobuf over USB | Trezor Ethereum, `SignIdentity` | `alloy-signer-trezor` 2.5, `trezor-client` 0.1.6 (`SignIdentity` included) | all |
| SPI/I2C (embedded) / USB-CDC | TROPIC01, ATECC608, SE050, OPTIGA | `tropic01` 0.1.0, git rev `3310775` (already in the project), `se05x` 0.4.2, `rust-cryptoauthlib` 0.4.5 (2022), OPTIGA — FFI to C | devkit — USB serial; the rest via MCU/RPi |
| Platform | Secure Enclave, TPM, CNG | already in `hw-signer` | macOS / Linux / Windows |

---

## 8. Sources (main)

- Project policy and code: `docs/KEY_POLICY.md`, `contracts/src/P256Validator.sol`, `contracts/lib/kernel` (tag v3.3), `docs/TROPIC01.md`, `docs/ARCHITECTURE.md`, Y. Madhwal, *Integrating Secure Elements with Account Abstraction for Autonomous IoT Blockchain Agents* (Skoltech research seminar, 14 October 2026; the slides are not published).
- ZeroDev addresses: https://unpkg.com/@zerodev/ecdsa-validator/_esm/constants.js, https://unpkg.com/@zerodev/passkey-validator@5.6.0/_esm/index.js, https://unpkg.com/@zerodev/weighted-validator/_esm/index.js; WebAuthnValidator: https://github.com/zerodevapp/kernel-7579-plugins
- TROPIC01: https://github.com/tropicsquare/tropic01 (datasheet A.11, user API 1.4.0), https://www.tropicsquare.com/order-devboard-form, SDK `libtropic-rs` rev 3310775.
- Trezor `SignIdentity`: https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/misc/sign_identity.py; Safe 7: https://trezor.io/guides/trezor-devices/trezor-safe-7/dual-secure-elements-in-trezor-safe-7
- Ledger OpenPGP: https://github.com/LedgerHQ/app-openpgp (src/gpg_pso.c, Makefile); SSH agent deprecated: https://github.com/LedgerHQ/app-ssh-agent; Security Key: https://developers.ledger.com/docs/ai-tools/hardware-security/security-key
- YubiKey PIV policies: https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html
- Nitrokey: https://docs.nitrokey.com/nitrokey3/faq, https://www.nitrokey.com/node/648, https://docs.nitrokey.com/nitrokeys/features/openpgp-card/uif
- OPTIGA: https://github.com/Infineon/optiga-trust-m ; ATECC: https://github.com/MicrochipTech/cryptoauthlib ; Android Keystore: https://developer.android.com/training/articles/keystore
- Prices: links in the §1 table.
