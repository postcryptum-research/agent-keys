# Hardware worth adding to agent-keys

A shopping list: devices beyond what the project already runs on that would
take it further, with what each would add and what it costs. Prices are as
of 2026-10-22, in EUR, including VAT unless marked "ex VAT".

**Already in hand or covered:** a Linux TPM (Intel PTT), a Windows TPM, an
Apple Secure Enclave (a colleague's Mac), the TROPIC01 USB devkit, a YubiKey 5 NFC (owner key, [`YUBIKEY.md`](YUBIKEY.md)), the phone owner apps in `mobile/` (Android Keystore / StrongBox, iOS Secure Enclave; [`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)). Owner-key devices are compared in
depth in [`OWNER_DEVICES.md`](OWNER_DEVICES.md); this page looks wider —
where the **agent** runs, servers, IoT devices — and only summarises owner
devices.

## What makes a device fit

The account verifies P-256 (secp256r1) through the RIP-7212 precompile, so a
device fits **as is** if it can produce a plain ECDSA P-256 signature `(r, s)`
over a **32-byte digest we give it** — no extra hashing, no WebAuthn
wrapping. A device that only does secp256k1 needs a different validator (see
`OWNER_DEVICES.md` §0). Every row below says which it does.

Evidence marks: **V** — verified at the linked source; **I** — inferred
(from the API design or a related product), not tested.

## Buy first — cheap, and each opens something new

| # | What | ≈ Price | What it adds to the project | Work on our side |
|---|---|---|---|---|
| 1 | **TROPIC01 Mini Board or Raspberry Pi shield** (+ a Raspberry Pi, if you have none) | €9.50 / €20 ex VAT, [Tropic Square order form](https://www.tropicsquare.com/order-devboard-form) (V); shipping to Bulgaria is quoted only after ordering (V) | the agent on a cheap headless computer with an open-architecture SE, talking to it over SPI rather than the USB devkit | an SPI transport for the existing TROPIC01 backend (an `embedded-hal` `SpiDevice` over Linux spidev; the backend's only transport today is the devkit's serial port), and a way to name it in the config and CLI, which take a serial port. The backend also assumes the devkit's factory pairing key in slot 0. Our dependency is `tropic01` 0.1.0 from git; crates `tropic01-driver` 0.1.1, `tropic-rs` 0.1.0 also exist (V crates.io) |
| 2 | **LetsTrust TPM** (Infineon SLB 9672) for a Raspberry Pi | ≈€25–30, [buyzero.de](https://buyzero.de/products/letstrust-raspberry-pi-tpm-trusted-platform-module-slb9672) (V; single-unit price inferred); USB variant TPM2Go €49 (V) | a **discrete**, certified TPM: the agent key survives what a firmware TPM (fTPM / Intel PTT) does not — BIOS resets, CPU swaps (`RESILIENCE.md`) | none: the same `tss-esapi` backend, ARM build |
| 3 | **ATECC608B breakout** (Adafruit 4314) | ≈€5, [Adafruit](https://www.adafruit.com/product/4314), [The Pi Hut](https://thepihut.com/products/adafruit-atecc608-breakout-board-stemma-qt-qwiic-ada4314), Mouser (V) | the cheapest secure element — the one Madhwal's talk used; the path to IoT agents (row 4) | a new backend over I2C (`at-cryptoauth` 0.6.0 (V)); `atcab_sign(key_id, msg[32], …)` signs a given digest (I). The chip's configuration is locked once, forever — buy two |
| 4 | **ESP32-S3-DevKitC-1** + the ATECC608 above | ≈€14, Mouser (V) | an **IoT agent**: a microcontroller with its own key that pays for an API with x402 by itself — the project's original idea, on a €20 device | firmware: the ATECC608 signs, the x402 / UserOperation logic moves to the device or a thin relay |
| 5 | **NXP SE050** (MikroE Plug&Trust Click) | ≈CHF 18, [RS](https://ch.rs-online.com/web/p/entwicklungstools-verschlusselung-und-authentifizierung/2475657) (V); eval kit OM-SE050ARD-E $60 (V) | the only cheap SE here with **both** P-256 and secp256k1 — one chip for our validator and for Ethereum's own | a backend over I2C with the maintained `se05x` 0.4.2 (Nitrokey) (V) |
| 6 | **Nitrokey 3C NFC** (or 3A) | €65 / €60, [Nitrokey shop](https://shop.nitrokey.com/shop/nk3cn-nitrokey-3c-nfc-148) (V) | an owner key with **open firmware** (Rust) and an SE050 inside — the open counterpart to the YubiKey | not "none" until tried: our YubiKey backend needs Yubico's own slot-metadata, serial and attestation commands (V `yubikey_piv.rs`), which a Nitrokey may not answer (I); otherwise a PIV backend without them, or `cryptoki` + OpenSC (I) |

Items 1–3 together cost about €60 (without the Raspberry Pi) and give three
new agent-side placements; 4 adds the IoT direction; 5 and 6 are each
single purchases with a clear purpose.

## Everything considered

| Device | ≈ Price + shop | Raw P-256 over a digest | secp256k1 | Interface / Rust | Role |
|---|---|---|---|---|---|
| Raspberry Pi 5 | 8 GB €149 ex VAT at [comet.bg](https://store.comet.bg/en/Catalogue/Product/46735) (V, a Bulgarian shop); list prices rose in 2026 to $110 (4 GB) / $175 (8 GB) (V [techspot](https://www.techspot.com/news/111165-raspberry-pi-prices-soar-amid-ai-memory-shortage.html)) | — (host for the rows below) | — | — | agent host |
| LetsTrust TPM (SLB 9672) | see "Buy first" #2 | yes (I: the same `TPM2_Sign` as our Linux backend) | no | SPI, `/dev/tpmrm0`; `tss-esapi` (in use) | agent |
| TROPIC01 Mini Board / shields / Click | €9.50 / €20 ex VAT (V) | yes (I: the same `ECDSA_Sign` as the devkit) | no (P-256, Ed25519) | SPI; `tropic01`, `tropic01-driver`, `tropic-rs` (V) | agent |
| ATECC608B breakout | ≈€5 (V) | yes (I, CryptoAuthLib `atcab_sign`) | no | I2C; `at-cryptoauth` 0.6.0, `ecc608-linux` 0.2.4 (V) | agent, IoT |
| ESP32-S3 devkit | ≈€14 (V) | via the ATECC608 | no | firmware (esp-idf, or `at-cryptoauth` no_std) | IoT agent |
| NXP SE050 (Click / OM-SE050ARD-E) | ≈CHF 18 / $60 (V) | yes (I: ECDSASign over a given hash) | **yes** (I) | I2C T=1; `se05x` 0.4.2 (V) | agent |
| Infineon OPTIGA Trust M V3 shield | €26.44, [Mouser](https://www.mouser.bg/new/infineon/infineon-trustmv3shieldtobo1-shield) (V) | yes (I: `optiga_crypt_ecdsa_sign(digest, …)`) | no (V) | I2C; **no Rust crate** (V) — FFI to the C library | agent (low priority) |
| USB Armory Mk II | €299 ex VAT, [3mdeb](https://shop.3mdeb.com/?p=43716) (V; now built by 3mdeb) | yes, via its ATECC608 or a TrustZone applet (I) | in software (I) | USB Ethernet gadget; runs Linux, our CLI on it | a sealed signing appliance |
| **YubiHSM 2** | €773.50–812.50, [yubico.com](https://www.yubico.com/de/product/yubihsm-2-series/yubihsm-2/) (V) | **yes** — Sign ECDSA takes a hash (V [command doc](https://developers.yubico.com/Archive_Old_Dev_Docs/YubiHSM2/Commands/Sign_Ecdsa.html)) | **yes** (V) | USB / HTTP connector, PKCS#11; `yubihsm` 0.42.1 (V) | agent on a **server**: a real HSM with an audit log and per-key capabilities |
| Nitrokey HSM 2 | €109, [Nitrokey shop](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7) (V; €99 seen elsewhere) | yes (V [factsheet](https://www.nitrokey.com/files/doc/Nitrokey_HSM_factsheet.pdf)) | **yes** (V) | PC/SC, PKCS#11 via OpenSC; `cryptoki` (I) | a cheap HSM; slow (≈360 signatures/min, V) |
| Nitrokey 3A / 3C NFC | €60 / €65 (V) | yes, PIV (I) | yes, OpenPGP (V) | PC/SC; PIV — untested through our YubiKey backend, which uses Yubico's own commands (I) | owner |
| Google Pixel 9a (StrongBox) | ≈€549 EU list (V); emag.bg unverified | **yes**: StrongBox must support EC P-256 with `DIGEST_NONE` (V [AOSP](https://android.googlesource.com/platform/hardware/interfaces/+/3a7e2ca%5E%21/)) | no (V) | Android Keystore; the owner app in `mobile/android` | owner with biometrics — the app exists ([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)); a phone as the agent key is not supported; the exploration is in [`PHONE_OWNER.md`](PHONE_OWNER.md) |
| Mac mini M4 | from **€949** (16 GB / 512 GB; the cheaper model was discontinued in April 2026) (V [9to5mac](https://9to5mac.com/2026/05/01/apple-discontinues-base-mac-mini-now-starts-at-799-with-512gb-storage/)); Bulgarian price unverified | yes (our Secure Enclave backend) | no | already supported | an always-on agent host — not needed for development (the colleague's Mac covers it) |
| PC with Microsoft Pluton | — | yes (I: Pluton presents itself as a TPM 2.0 under the Platform Crypto Provider, V [Microsoft](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/pluton-as-tpm)) | no | our Windows CNG backend, unchanged (I) | worth a test run if one is at hand; not worth buying for this |
| Trezor Safe 7 | €249, [trezor.io](https://trezor.io/cs/trezor-safe-7-backup-bundle) (V) | yes, with care: `SignIdentity`, curve `nist256p1`, **gpg** mode signs the given challenge as is (ssh mode hashes first) (V [firmware](https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/misc/sign_identity.py)) | yes | USB; `trezor-client` (I) | owner with a screen; contains a TROPIC01, but signing runs on the MCU from the seed, not in the SE (I) |
| Ledger Flex / Nano Gen5 + OpenPGP app | Flex ≈€197–249 (V); Gen5 $179 (V) | likely yes, OpenPGP PSO:CDS over the given hash (I) | yes (V) | PC/SC; `openpgp-card` (I) | owner with a screen — a Nano S Plus already does this (`OWNER_DEVICES.md`) |

## Caveats

- **emag.bg was not checked** — its pages could not be fetched; any of these
  may be there too. The one Bulgarian listing found is the Raspberry Pi 5 at
  comet.bg.
- **Memory prices in 2026** roughly doubled the Raspberry Pi 5 and removed
  the cheap Mac mini; a Pi 5 with a €25 TPM is still about a quarter of the
  cheapest Mac.
- **Young Rust crates**: the TROPIC01 and ATECC608 crates are 0.x with a
  single maintainer — expect to vendor or contribute. `se05x` (Nitrokey) and
  `yubihsm` (iqlusion) are maintained.
- **ATECC608**: the configuration zone is locked once and for all; a wrong
  lock bricks the chip for our use. Buy spares.
- **Android StrongBox**: `DIGEST_NONE` for ECDSA is mandatory today, but
  AOSP marks it as deprecated — a long-term risk for a phone-based signer.
- **Inferred, not tested**: the digest semantics of the SE050 and OPTIGA
  APIs, the TROPIC01 shields running the same commands as the devkit, the
  Ledger Flex OpenPGP path, Pluton through CNG. Each would be the first
  thing to check on arrival, as was done for every backend so far.
- **secp256k1** is offered only by the SE050, the HSMs, Nitrokey 3, Ledger
  and Trezor. Everything else is P-256 only — which is exactly what the
  account verifies.
