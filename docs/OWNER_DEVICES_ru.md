# Устройства и подходы для OWNER-ключа (agent-keys)

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


Дата: 2026-10-20. Утверждения о состоянии самого проекта приведены к дереву 2026-11-19 (бэкенд YubiKey PIV, приложения владельца на телефоне, ключ-файл, recovery-валидатор, `owner set-root`). Метки: **[V]** — проверено (URL или
файл/код), **[I]** — вывод/по памяти, не перепроверено в этой сессии.

## 0. Что требуется от owner-ключа и что принимает цепь

**Модель** (`docs/KEY_POLICY.md`, правило 3): owner-ключ вне досягаемости агента.
Операции владельца — ротация/отзыв permission агента и смена мандата. Они редкие,
поэтому человек в контуре допустим. Отсюда три вопроса к любому устройству:
(а) может ли малварь на хосте, к которому устройство подключено, подписать
без человека (presence/PIN/кнопка); (б) можно ли украсть ключ (неэкспортируемость);
(в) видит ли человек, *что* подписывает (WYSIWYS).

**Валидаторы на цепи и формат подписи:**

| Класс | Что подписывает устройство | Валидатор | Статус |
|---|---|---|---|
| A. Сырой P-256 над 32-байтным дайджестом | `ECDSA(userOpHash)` → `r‖s` (64 B) | наш `P256Validator` **как есть** | [V] `contracts/src/P256Validator.sol`: `signature.length == 64`, `P256.verifySignature(hash, r, s, x, y)` |
| B. secp256k1 (Ethereum-кошельки, Keycard, Satochip) | `ECDSA(userOpHash)` **или** `personal_sign(userOpHash)` | ZeroDev `ECDSAValidator` | [V] код Kernel v3.3 (`contracts/lib/kernel/src/validator/ECDSAValidator.sol`, тег `v3.3`) сначала пробует `recover(userOpHash)`, потом `recover(toEthSignedMessageHash(userOpHash))`, так что Ledger/Trezor через `personal_sign` подходят. Канонический адрес для Kernel ≥0.3.1: **`0x845ADb2C711129d4f3966735eD98a9F09fC4cE57`** ([V] [@zerodev/ecdsa-validator constants](https://unpkg.com/@zerodev/ecdsa-validator/_esm/constants.js)); код задеплоен на **Base mainnet и Base Sepolia** (1819 B, [V] `eth_getCode` через `mainnet.base.org` / `sepolia.base.org`) |
| C. Только WebAuthn/FIDO2-assertion | `ECDSA(sha256(authData ‖ sha256(clientDataJSON)))`, где challenge = userOpHash | ZeroDev `WebAuthnValidator` (или свой на Solady `WebAuthn.sol`) | [V] адрес для Kernel 0.3.0–0.3.3, версия 0.0.3 (patched): **`0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69`** ([@zerodev/passkey-validator](https://unpkg.com/@zerodev/passkey-validator@5.6.0/_esm/index.js)); задеплоен на Base и Base Sepolia (4739 B, [V] `eth_getCode`). [V] Исходник в HEAD ([WebAuthnValidator.sol](https://github.com/zerodevapp/kernel-7579-plugins/blob/HEAD/src/validators/WebAuthnValidator.sol)) вызывает `WebAuthn.verifySignature(..., requireUserVerification = true, ...)`, `CHALLENGE_LOCATION = 23`. Отсюда: нужен флаг **UV** (PIN или биометрия, одного касания мало), а clientDataJSON должен начинаться с `{"type":"webauthn.get","challenge":"…`. rpIdHash не проверяется [V по тому же коду]. Совпадает ли задеплоенный байткод с HEAD — [I] |

**Общие технические замечания:**
- **low-s.** Наш валидатор (Solady `P256`) отвергает high-s, а устройства отдают случайный `s`. `hw-signer` нормализует `s → n − s` в каждом бэкенде (`normalize_low_s`) [V `signer/crates/hw-signer/src/lib.rs`]. Это нужно для всех устройств класса A.
- **DER→raw.** PIV, PKCS#11 и OpenPGP отдают DER или MPI; переводим в `r‖s` (для PIV сделано: `der_ecdsa_rs` в бэкенде YubiKey [V]; для остальных [I]).
- **WYSIWYS.** Ни одно USB-устройство ниже не показывает человеку, *что* меняет userOp: Kernel `userOpHash` — не EIP-712, clear-signing нет. Физическое подтверждение защищает от *незаметной* подписи малварью, но не от подмены хэша скомпрометированным хостом в момент, когда человек сам хочет подписать. Смягчение: подписывать на отдельной машине; сверять хэш или декодированный calldata на втором экране (телефон или другой ПК). Устройства с экраном (Trezor, Ledger) показывают хотя бы хэш. Исключение — приложение владельца на телефоне: оно декодирует операцию и показывает её до подписи [V `mobile/owner-core/src/review.rs`].
- **Свои валидаторы.** `P256Validator` хранит один ключ на аккаунт (`mapping(account => key)`), а ValidationId в Kernel — адрес модуля. Второй P-256-ключ (recovery) требует второго экземпляра контракта по другому адресу [V по коду]; теперь это `contracts/src/P256RecoveryValidator.sol` (§5).

---

## 1. Сравнительная таблица

Fit — пригодность для owner-роли: H / M / L. Цены — ориентир на 2026.

| Устройство | Цена | Кривая / режим | Валидатор | Presence / PIN | Открытость | Интеграция из Rust | Fit |
|---|---|---|---|---|---|---|---|
| **YubiKey 5 — PIV** | $58 (5 NFC) [V](https://yubico.com/product/yubikey-5-nfc/) | P-256, **сырой дайджест** (GENERAL AUTHENTICATE над хэшем) [V: в крейте `yubikey` `piv::sign_data(raw_in, AlgorithmId, slot)` отдаёт входные байты как есть] | **P256Validator как есть** | PIN policy never/once/always, touch policy never/always/cached (15 с); задаются при генерации и не меняются [V](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html) | закрытая прошивка, не обновляется | уже в коде: фича `yubikey-piv` в `hw-signer` (крейт `yubikey` 0.9.0-rc.0, pure Rust поверх PC/SC), см. `docs/YUBIKEY.md` [V]; Linux/macOS/Windows | **H** |
| YubiKey 5 — OpenPGP | там же | P-256 ECDSA над хэшем (PSO:CDS) [I: по спецификации OpenPGP card]; secp256k1 нет [I] | P256Validator | PW1 PIN + UIF (касание) [I] | закрытая | `openpgp-card` + `card-backend-pcsc` [V crates.io] | M (PIV проще) |
| YubiKey 5 / Security Key — FIDO2 | Security Key NFC ~$25 [V](https://www.pbtech.co.nz/product/MEMYBC9257/Yubico-Security-Key-NFC---USB-A-FIDO-Only---v57) | только assertion (ES256) | WebAuthnValidator | касание (UP) + PIN (UV, обязателен валидатору) | закрытая | CTAP2: `ctap-hid-fido2` 3.6, `fido2-rs` (libfido2), `authenticator` [V crates.io]; на Windows без админа — только через `webauthn.dll` [I] | M |
| **Nitrokey 3 (A/C NFC)** | €55 [V](https://shop.nitrokey.com/shop/nk3an-nitrokey-3a-nfc-147) | OpenPGP: NIST P-256/384/521, brainpool, Curve25519, RSA; PIV: **P-256**, RSA-2048 [V](https://docs.nitrokey.com/nitrokey3/faq); PIV с fw 1.8 (янв. 2025) [V](https://www.nitrokey.com/node/648); secp256k1 в OpenPGP заявлен, но на практике не импортируется [V](https://support.nitrokey.com/t/cant-import-secp256k1-key-to-nitrokey-3a-nfc/6463) | **P256Validator как есть** (PIV или OpenPGP над хэшем) | OpenPGP UIF: off / on / permanent, отдельно для sign, dec и auth [V](https://docs.nitrokey.com/nitrokeys/features/openpgp-card/uif); touch policy для PIV — [I], проверить | **открытая прошивка** (Trussed, Rust), ключи OpenPGP в **NXP SE050** (EAL6+) [V FAQ] | PC/SC: `openpgp-card`, PIV через `cryptoki` + OpenSC [I] | **H** |
| SoloKeys Solo 2 | ~€59 у ритейлеров [I], доступность нестабильна; магазин: [solokeys.com](https://solokeys.com/collections/solo-2-secure) | FIDO2 (ES256) [I: PIV/OpenPGP нет] | WebAuthnValidator | касание + PIN | открытые HW и FW (Trussed) | CTAP2 (как выше) | L–M |
| Google Titan (FIDO2) | $30 USB-A / $35 USB-C [V](https://betanews.com/article/buy-google-titan-security-key) | FIDO2 only | WebAuthnValidator | касание + PIN | закрытая (OpenSK-основа, [I]) | CTAP2 | M (дёшево) |
| Feitian ePass K9 / Token2 PIN+ | K9 ~£23; Token2 PIN+ €15–26, Bio3 €37 [V](https://node-07-prod.token2.com/c/pin-plus-series) | FIDO2; модели Token2 PIN+ R3.3 и Feitian K9PLUS имеют также **PIV/OpenPGP** [V по названиям SKU](https://chert.ng/feitian-epass-k9plus-usb-a-fido2-u2f-nfc-piv-openpgp-otp-security-key-k9plus.html) | WebAuthn; PIV-вариант → P256Validator [I: поддержку P-256 в PIV у конкретного SKU проверить] | касание + PIN; у Token2 есть PIN complexity | закрытые | CTAP2 / PKCS#11 | M |
| OnlyKey | $49.99 (обычно $69.99) [V](https://onlykey.io/collections/all) | 16 ECC-слотов, **NIST256P1 и SECP256K1** [V](https://docs.onlykey.io/command-line/) | P256Validator (если подписывает сырой хэш, [I]) или ECDSAValidator | 6 сенсорных кнопок, PIN вводится на самом устройстве (не keylogger-able) [I] | открытая FW | свой HID-протокол; есть только Python `onlykey-cli` и крейт `okman` [V](https://docs.rs/crate/okman/0.1.1), полноты нет | M (интересно: PIN на устройстве), но интеграция дорогая |
| **SmartCard-HSM / Nitrokey HSM 2** | NK HSM 2 €99–109 [V](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7); карта SmartCard-HSM ~€25–35 [I] | NIST P-192…521, brainpool, **secp256k1**; ECDSA над хэшем (`CKM_ECDSA`) [V](https://www.nitrokey.com/files/doc/Nitrokey_HSM_factsheet.pdf) | P256Validator **или** ECDSAValidator | только PIN, кнопки нет; есть n-of-m backup через DKEK [I] | закрытая ОС карты, открытый клиент (OpenSC) | PKCS#11: `cryptoki` 0.12 + OpenSC [V crates.io] | M (нет presence) |
| Generic JavaCard (J3R180 и т.п.) + PivApplet / SmartPGP | ~$9–15 за карту [V](https://www.ihsgonline.com/products/j3r180-jcop4-180k-java-smart-card-replace-j2a040-chip-java-j/233358068/) + ридер ~$15 | SmartPGP: P-256/384/521, brainpool [V](https://github.com/github-af/SmartPGP); PIV-апплет: P-256 [I] | P256Validator | PIN; касания нет (карту вынимают из ридера) | открытые апплеты | PC/SC (`pcsc`, `openpgp-card`) | M (дёшево, но DIY: прошивка через GlobalPlatformPro) |
| Keycard (+ Shell) | карта ~$25–30 [I]; Shell €109 со скидкой (обычно €149) [V](https://get.keycard.tech/pages/keycard-shell) | **secp256k1**, «хэш входит — подпись выходит», APDU с secure channel [V](https://docs.keycard.tech/en/developers) | ECDSAValidator | PIN + pairing; у Shell экран и клавиатура | открытые апплет и Shell | PC/SC + свой secure channel; Rust-крейта нет [V: на crates.io нет `keycard`] | M |
| Satochip | ~€25 + ридер ~€15 [V](https://sitegeek.fr/article-technologie/satochip-test-du-hardware-wallet-pour-vos-cryptomonnaies-open-source-et-abordable) | **secp256k1**, подпись хэша [I] | ECDSAValidator | PIN | открытый апплет [V](https://github.com/Toporin/SatoChipApplet) | PC/SC, протокол свой, Rust-крейта нет | L–M |
| **Ledger Nano S Plus** | ~$59–79 [V](https://financer.com/crypto/crypto-wallet-hardware/) | (1) Ethereum app: secp256k1, `personal_sign` | (1) **ECDSAValidator** (адрес выше) | экран + 2 кнопки, PIN на устройстве; seed-backup | Secure Element закрыт; OS частично открыта, приложения открыты | `alloy-signer-ledger` 2.5 [V crates.io], `coins-ledger` | **H** |
|  |  | (2) **OpenPGP app**: secp256r1, `cx_ecdsa_sign_no_throw(..., CX_NONE, digest)`, то есть **сырой дайджест** без хэширования; собирается для Nano S Plus (`TARGET_NANOS2`) [V](https://github.com/LedgerHQ/app-openpgp/blob/HEAD/src/gpg_pso.c) | (2) **P256Validator как есть** | UIF-подтверждение на устройстве + PW1 PIN [V тот же файл] | открытое приложение | `openpgp-card` (PC/SC CCID) [I: Ledger OpenPGP app виден как CCID-карта] | H/M |
|  |  | (3) Security Key app: FIDO2/U2F; resident keys выключены [V](https://developers.ledger.com/docs/ai-tools/hardware-security/security-key) | (3) WebAuthnValidator (non-resident подойдёт) | кнопка | | CTAP2 | M |
|  |  | (4) SSH/PGP Agent app — **DEPRECATED** [V](https://github.com/LedgerHQ/app-ssh-agent) | — | | | | — |
| **Trezor Safe 3 / Safe 5** | $59 / ~$129 [V](https://financer.com/crypto/crypto-wallet-hardware/) | (1) Ethereum: secp256k1, `personal_sign` | (1) ECDSAValidator | экран + кнопка или тач, PIN на устройстве; seed | **полностью открытая FW** | `alloy-signer-trezor` 2.5, `trezor-client` 0.1.6 [V crates.io] | **H** |
|  |  | (2) **`SignIdentity`, proto `gpg`, `ecdsa_curve_name = "nist256p1"`**: подписывает `challenge_hidden` **как есть** (`nist256p1.sign(seckey, data)`, без хэширования); ключ детерминирован от seed по пути из identity [V](https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/misc/sign_identity.py) | (2) **P256Validator как есть** | подтверждение на устройстве (показывается identity и `challenge_visual`; текст задаёт хост) | открытая | `trezor-client` содержит `SignIdentity` [V: grep в исходнике крейта] | **H** |
|  |  | (3) FIDO2 [I] | WebAuthn | | | | M |
| Trezor Safe 7 | $249 [V](https://www.ibtimes.co.uk/trezor-launches-trezor-safe-7-first-hardware-wallet-transparent-secure-element-1749151) | как Safe 3/5 (ветка core) [I]; внутри **TROPIC01 + OPTIGA Trust M + STM32U5**; SE отвечают за PIN, аутентичность и RNG, подпись делает MCU из seed [V](https://trezor.io/guides/trezor-devices/trezor-safe-7/dual-secure-elements-in-trezor-safe-7) | P256Validator (SignIdentity) / ECDSAValidator | тач-экран, PIN | открытая FW, «прозрачный» SE | как Trezor | H (дорого) |
| Keystone 3 Pro | $149 [V](https://walletpilot.com/hardware-wallets/keystone-3-pro) | secp256k1, air-gapped через QR (UR) | ECDSAValidator | экран, PIN, отпечаток | открытая FW | QR/UR — своя реализация, Rust-библиотеки UR есть [I] | M |
| GridPlus Lattice1 | $397 [V](https://ethereum.org/ar/wallets/find-wallet/gridplus-lattice1/) | secp256k1 (+ ed25519) [I] | ECDSAValidator | большой экран | частично открыта | SDK на JS, сетевое подключение | L (цена, сложность) |
| Платформенный passkey (iOS/Android/Win Hello/macOS) | $0 | только WebAuthn assertion | WebAuthnValidator | UV биометрией или PIN | закрытые | нужен браузер/WebAuthn-страница или нативное приложение; hybrid-flow (QR) для телефона как аутентификатора [I] | M; синхронизируемые passkeys живут в облачном аккаунте → лучше device-bound |
| Телефон: свой app с ключом в SE / StrongBox | $0 + разработка | **сырой P-256**: Android Keystore/StrongBox поддерживает `DIGEST_NONE` для EC P-256 [V](https://developer.android.com/training/articles/keystore); iOS — CryptoKit `SecureEnclave.P256.Signing` над дайджестом как есть [V `mobile/ios/OwnerApp/Keys.swift`] | **P256Validator как есть** | `setUserAuthenticationRequired` (Android), `.biometryCurrentSet` (iOS) — enforced в железе [I] | закрытые | реализовано: `mobile/android` (пока только debug-сборка), `mobile/ios`, общее ядро `mobile/owner-core`; QR плюс сессия по локальной сети с CLI (`docs/MOBILE_OWNER_DESIGN.md`) [V] | M–H (сильная модель: отдельное устройство + биометрия + экран; только роль owner) |
| **Mac с Secure Enclave + Touch ID** (свой или второй Mac) | $0 | P-256, сырой дайджест (уже реализовано: CryptoKit-шим) [V `docs/SECURE_ENCLAVE.md`, память проекта] | **P256Validator как есть** | в нашем бэкенде сейчас нет: ключ создаётся только с `.privateKeyUsage` [V `SecureEnclaveShim.swift`]; для `userPresence`/биометрии (enforced SE) нужна правка Swift-шима | закрытые | уже в коде `hw-signer`, без presence | **H** (если это не хост агента, иначе placement 2) |
| **TPM второй машины** | $0 | P-256, сырой дайджест (уже реализовано) | **P256Validator как есть** | authValue/PIN; физического присутствия у TPM нет | — | уже в коде (`tss-esapi`, CNG) | **H** (как отдельная машина) |
| **TROPIC01 USB DevKit** | €50 [V](https://www.tropicsquare.com/order-devboard-form) | P-256 ECDSA над 32-байтным хэшем (`ECDSA_Sign`, MSG_HASH 32 B) [V user API 1.4.0] | **P256Validator как есть** | **нет** на чипе (GPO — только выход) [V user API, `CFG_GPO`]; доступ ограничен pairing-ключом (наш бэкенд открывает сессию публичным заводским ключом SH0; приватный pairing-ключ не реализован) | **открытая архитектура** | уже в коде (`tropic01` 0.1.0, git rev `3310775`) | M–H (см. §3) |
| Owner = Safe / weighted multisig | газ | смешение факторов | Safe (1271) или ZeroDev Weighted Validator (подписанты ECDSA + WebAuthn) [V](https://unpkg.com/@zerodev/weighted-validator/_esm/index.js) или свой k-of-n P-256 | сумма факторов | — | средняя–высокая | H для mainnet (см. §5) |
| Зашифрованный файл на флешке | ~$5 | любая кривая | любой (P-256 → наш как есть) | нет | — | `age`/`scrypt`/`eth-keystore` + `zeroize` [V crates.io] | L–M (см. §6) |

---

## 2. Шорт-лист рекомендаций

### Самое дешёвое приемлемое
1. **Nitrokey 3A NFC, €55: PIV P-256 + PIN (+ касание).** Работает с нашим
   `P256Validator` без единой строки Solidity. Прошивка открыта, ключи лежат в
   SE050. Если touch policy в PIV на NK3 нет (проверить), то ставим OpenPGP-ключ
   с UIF=permanent.
2. **Token2 PIN+ R3.3, €22–23** (FIDO2 + PIV + OpenPGP). Если PIV P-256
   подтвердится — то же, что п.1, но дешевле и с закрытой прошивкой. Если брать
   только как FIDO2, нужен `WebAuthnValidator`.
3. **Trezor Safe 3, $59**: `SignIdentity` gpg/nist256p1 даёт P256Validator как
   есть. Плюс экран, PIN на устройстве и seed-backup. По цене это уровень YubiKey,
   а модель лучше: PIN вводится на устройстве, есть резервная копия.

FIDO2-ключ за $25–30 (Yubico Security Key, Titan) тоже приемлем по безопасности:
касание + PIN, ключ неэкспортируем. Но он тянет за собой `WebAuthnValidator` и
CTAP2-стек в CLI. Ключи с PIV/OpenPGP за те же деньги проще для нашей архитектуры.

### Best practice (mainnet)
- **Отдельное устройство с экраном и seed-backup + recovery-фактор на цепи.**
  Основной вариант: Trezor (Safe 3/5/7, `SignIdentity` nist256p1 →
  `P256Validator`) или Ledger (OpenPGP app secp256r1 → `P256Validator`; либо
  Ethereum app → `ECDSAValidator`). Recovery: второй валидатор с доступом
  **только** к `changeRootValidator` (см. §5) — холодный ключ в сейфе или
  второе устройство.
- Подписывать с машины, которая **не** хост агента. userOpHash сверять на
  экране устройства с независимым источником (второй ПК или телефон).

### «Уже в руках»
| Что | Как использовать как owner | Валидатор | Работа |
|---|---|---|---|
| **Ledger Nano S Plus** | (а) Ethereum app, `personal_sign(userOpHash)`; (б) OpenPGP app, ключ secp256r1, PSO:CDS над userOpHash | (а) ECDSAValidator `0x845A…cE57` (уже на Base); (б) P256Validator как есть | (а) `alloy-signer-ledger` → `signMessage`, root = ECDSAValidator: смена root-валидатора + поддержка в CLI; (б) клиент `openpgp-card` + DER/MPI → `r‖s` + low-s. Вариант (б) не меняет цепь вообще [V код app-openpgp; I — что app ставится из Ledger Live на S Plus] |
| **YubiKey 5 PIV** | слот 9c, PIN always + touch always (`docs/YUBIKEY.md`) | P256Validator как есть | ноль: бэкенд есть; это текущий owner-ключ тестовых аккаунтов |
| **TROPIC01 devkit** | отдельное USB-устройство владельца, втыкается только для owner-операций, с приватным pairing-ключом (§3) | P256Validator как есть | provisioning pairing-ключа (SH1), UAP-ограничения, invalidate SH0; хранение SH1-priv (зашифрованно) на owner-машине |
| **TPM второй машины / Windows-ПК / Mac** | owner-ключ на другой машине, CLI запускается там | P256Validator как есть | ноль для TPM и CNG; для Mac — ноль без presence и правка шима для Touch ID: бэкенды `tpm`, `windows_tpm`, Secure Enclave уже есть; нужен только перенос root-операций (`sudo agent-signer permission …`) на ту машину |

---

## 3. Открытый secure element как отдельное USB-устройство владельца

### 3.1 TROPIC01

**Факты** (datasheet A.11 и User API 1.4.0 из
[github.com/tropicsquare/tropic01](https://github.com/tropicsquare/tropic01), а также SDK `tropic01` rev `3310775`):
- **Pairing-ключи.** 4 слота SH0–SH3 с X25519 public key [V: `PAIRING_KEY_SLOT_MAX = 3` в `lt_3.rs`; datasheet §7.5.3]. Tropic Square пишет свой SH0PUB на производстве и выдаёт клиентам SH0PRIV; в SDK он лежит как `SH0PRIV_PROD0`, то есть **публичен** [V `tropic01/src/keys.rs`]. Сессию по слоту i открывает любой, кто знает SHiPRIV (Noise-подобный handshake на X25519).
- **Production-путь** (datasheet §5.4, рис. 4, §7.5.4) [V]:
  1. Открыть сессию по SH0.
  2. Сгенерировать свою пару SH1 (и, например, SH2 для резервной машины) и записать SH1PUB командой `Pairing_Key_Write`.
  3. Ограничить привилегии (UAP).
  4. **Инвалидировать SH0** (`Pairing_Key_Invalidate`).

  После этого сессию открывает только владелец SH1PRIV.
- **Ротация и отзыв.** Слоты по сути **write-once**: `Pairing_Key_Write` в слот Valid или Invalidated → `FAIL`, а «Invalidated is impossible to change» [V §7.5.3]. Отозвать можно (необратимо), перезаписать нельзя. Бюджет — три клиентских ключа на всю жизнь чипа. Если инвалидировать все четыре, чип мёртв [V warning в §7.5.3].
- **UAP.** Для каждой L3-команды есть битовая маска по слотам pairing-ключей; для `ECDSA_Sign` — отдельно по группам ECC-слотов 0–7/8–15/16–23/24–31 (`CFG_UAP_ECDSA_SIGN`, 0x140) [V user API]. Бит, сброшенный в I-Config, — **необратимый** запрет [V datasheet §7.5]. Пример: слот SH2 (резерв) может только `Ping`, `ECC_Key_Read` и `ECDSA_Sign`, а `ECC_Key_Generate/Erase` и запись конфигов разрешены только SH1 или запрещены навсегда. Тогда утечка SH2PRIV не позволяет стереть или подменить ключ.
- **Подпись.** `ECDSA_Sign` принимает `MSG_HASH` (32 B) и отдаёт `R`, `S` [V user API, таблица 32]. Это сырой дайджест, `P256Validator` подходит как есть (уже доказано on-chain).
- **User presence.** На самом чипе **нет** входа для кнопки: GPO — только выход (`ALWAYS_LOW/HIGH/INTERRUPT`) [V `CFG_GPO`]. Presence возможна только на стороне MCU-моста. На devkit это STM32U5 с прошивкой USB↔SPI [V `docs/TROPIC01.md`]. Есть ли на devkit кнопка, пригодная для custom-прошивки, и открыта ли штатная прошивка моста — **не подтверждено** [I, проверить на плате и в репо Tropic Square].
- **Аппаратный лимит попыток PIN.** Примитив `MAC_And_Destroy` (128 слотов) [V `lt_3.rs`] — механизм PIN с аппаратно ограниченным числом попыток, который использует Trezor Safe 7 [I по описанию Trezor]. С ним можно сделать PIN, ограниченный чипом: хост выводит ключ расшифровки SH1PRIV через MAC-and-Destroy [I, дизайн-идея].
- **Цены и доступность** [V](https://www.tropicsquare.com/order-devboard-form):
  - чип-сэмпл €5;
  - USB DevKit €50;
  - MikroE Click, RPi Shield, Arduino Shield — по €20;
  - Mini Board €9.50;

  всё в наличии, заказ через форму, доставка вне ЕС €35–55. Потребительский продукт — **Trezor Safe 7, $249** (TROPIC01 там охраняет PIN и секреты, а не подписывает, см. таблицу). Наш part `TR01-C2P-T103` помечен **Deprecated** [V part-numbers.md]. Это не мешает devkit'у, но для продукта нужен актуальный part.

**Что даёт TROPIC01 как owner-устройство (devkit, приватный SH1):**
- Ключ неэкспортируем. Хост, скомпрометированный в момент подключения, может *подписывать*, пока устройство воткнуто, но не может *унести* ключ. Это главное отличие от флешки (§6).
- В отключённом состоянии подписать нельзя.
- Pairing-секрет SH1PRIV — файл на owner-машине; его надо хранить зашифрованным паролем (age/scrypt) или в TPM той машины. Утечка SH1PRIV ≠ утечка owner-ключа: атакующему нужен ещё физический доступ к устройству, а слот можно инвалидировать.
- **Нет кнопки и экрана**: малварь на хосте, пока devkit воткнут, подпишет что угодно. Значит, это placement «отдельное устройство, подключаемое только на время операции», а не «presence». По силе — между флешкой и YubiKey с touch policy.

**Улучшенный TROPIC01-вариант (DIY):** RPi Zero 2 W (~$15) + **TROPIC01 RPi Shield (€20)** + кнопка на GPIO + маленький OLED (~$5). Получается «owner appliance» ≈ €45–55:
- Pi в режиме USB-gadget (или по сети/QR) принимает userOpHash, показывает его на OLED и ждёт кнопку.
- SH1PRIV живёт только на Pi (на SD — зашифрован; разблокировка PIN через MAC-and-Destroy).
- Хост владельца pairing-ключа не видит вовсе. Это архитектура Madhwal'а (ATECC608A на Raspberry Pi [V: его доклад на исследовательском семинаре Сколтеха, октябрь 2026, ссылка в `docs/ARCHITECTURE.md`]), только с открытым SE и кнопкой.
- Слабое место: Linux на Pi — большая TCB. Вариант строже — bare-metal MCU (RP2040/STM32) + TROPIC01 Mini Board (€9.50); крейт `tropic01` — `embedded-hal`, то есть no_std-ready [V описание крейта].

### 3.2 Сопоставимые SE

| SE | Цена чипа / платы | Сырой P-256 дайджест? | Как хост аутентифицируется | Presence | Готовые USB-продукты |
|---|---|---|---|---|---|
| **TROPIC01** | €5 / devkit €50, шилды €20 | **да** (`ECDSA_Sign`, 32 B) [V] | обязательный secure channel X25519 по pairing-слоту; write-once, необратимый invalidate; UAP по слотам [V] | нет (только через MCU) | Trezor Safe 7 (не как сырой подписант) |
| **Infineon OPTIGA Trust M** (P-256/384/521, brainpool, RSA-2048 [V](https://mouser.com/datasheet/2/196/Infineon_OPTIGA_Trust_M_ProductBrief_v04_00_EN-1665636.pdf)) | ~$1–2 [I]; eval/Shield2Go ~£21 [V](https://uk.rs-online.com/web/p/microcontroller-development-tools/0277233) | **да**: `optiga_crypt_ecdsa_sign(digest, digest_length, key_oid, …)` [V](https://github.com/Infineon/optiga-trust-m/blob/master/include/optiga_crypt.h) | «Shielded Connection»: I2C шифруется ключом из Platform Binding Secret (PBS), общего с host-MCU. У V3 PBS не предзашит и генерируется в runtime; у Express/MTR — предзашит [V](https://community.infineon.com/t5/Blogs/How-is-a-secure-connection-established-with-Host-microcontroller/ba-p/363849). Плюс access conditions на объекты данных [I] | нет | внутри Trezor Safe 7; открытых USB-ключей не нашёл [I]. Rust-крейта нет [V crates.io] |
| **Microchip ATECC608A/B** (только P-256) | ~$0.76–1.17 [V](https://www.microchip.com/en-us/product/atecc608a); Adafruit-плата ~$7 [I] | **да**: `atcab_sign(key_id, msg[32], sig)` — «sign a 32-byte external message… R‖S big-endian, 64 bytes» [V](https://github.com/MicrochipTech/cryptoauthlib/blob/main/lib/calib/calib_sign.c) | IO Protection Key (шифрование шины и связка с MCU), slot config / KeyConfig, permanent lock конфигурации [I: полный datasheet под NDA]; без lock любой на шине подписывает | нет | эталон Madhwal (RPi) [V локальный PDF]; Rust: `rust-cryptoauthlib` (последний релиз 2022) [V crates.io] |
| **NXP SE050** (P-224…521, brainpool, **secp256k1**, ed25519, RSA [V](https://git.mitjafelicijan.com/r/luna/raw/wolfssl/wolfcrypt/src/port/nxp/README_SE050.md)) | ~$4–5 [V](https://lcsc.com/product-detail/image/SE050C2HQ1-Z01SDZ_C2659345.html); OM-SE050ARD-E $60–74 [V](https://www.avnet.com/americas/product/nxp/om-se050ard-e/evolve-57690039) | **да**: ECDSASign над переданным хэшем [I по Plug&Trust API]. **Плюс secp256k1**, то есть подходит и для ECDSAValidator | Platform SCP03 (AES) и сессии с ключами-аутентификаторами (UserID / AESKey / ECKey) на каждый объект [V тот же README; I детали] | нет | **Nitrokey 3** (SE050 внутри) [V](https://docs.nitrokey.com/nitrokey3/faq); Rust: `se05x` 0.4.2 (Nitrokey) [V crates.io] |

**Сводка:**
- Все четыре подписывают сырой P-256 дайджест, то есть любой из них работает с `P256Validator` как есть.
- Ни у одного нет user presence на кристалле: кнопку и экран всегда даёт обвязка (MCU/устройство).
- Модель аутентификации хоста:
  - самая выразительная и открытая — TROPIC01: write-once pairing, необратимый отзыв, UAP по слоту и по группе ключей, всё задокументировано без NDA;
  - SE050 — гибкая, но документация частично под NDA [I];
  - ATECC608 — самая грубая: lock конфигурации и IO-ключ.

### 3.3 Рекомендация: самый дешёвый практичный «TROPIC01-like» owner-device

1. **Купить готовое: Nitrokey 3A NFC (€55).** Открытая прошивка, SE050, кнопка (UIF), PIN, PIV/OpenPGP P-256 → `P256Validator` как есть. Это и есть «открытый SE в USB-корпусе с presence», которого нет у TROPIC01 devkit.
2. **Купить готовое, с экраном и backup: Trezor Safe 3 ($59).** `SignIdentity` nist256p1 → `P256Validator` как есть. Если нужен именно TROPIC01 внутри — Safe 7 ($249).
3. **Использовать TROPIC01 devkit:** приватный SH1 + invalidate SH0 + UAP + хранение SH1PRIV зашифрованным только на owner-машине + подключать только на время операции. Если devkit уже есть, покупать ничего не нужно, но presence нет.
4. **DIY с presence: RPi Zero 2 W + TROPIC01 RPi Shield + кнопка + OLED ≈ €50.** Лучшая открытая модель, но это проект, а не покупка.

---

## 4. Что нужно на цепи для каждого класса

| Класс устройств | Валидатор | Работа |
|---|---|---|
| A: сырой P-256 — YubiKey/Nitrokey/Token2 PIV, OpenPGP-карты (вкл. Ledger OpenPGP app), Trezor `SignIdentity` nist256p1, TROPIC01, ATECC/OPTIGA/SE050, TPM, Secure Enclave, Android StrongBox `DIGEST_NONE`, SmartCard-HSM | **`P256Validator` как есть** | Solidity — ноль. CLI: бэкенд на каждое устройство (PKCS#11 / PC/SC / HID), DER/MPI → `r‖s`, low-s — сделано для YubiKey PIV, TROPIC01, TPM, Secure Enclave и приложений на телефоне. Смена owner'а на новый ключ: `agent-signer owner set-root` (другой экземпляр P256Validator или `--retire` того же с переустановкой); новый ключ сначала показывает, что может подписывать (`--new-key` / `key prove` либо `--to-phone`) [V `chain.rs`, `owner set-root --help`] |
| B: secp256k1 — Ledger/Trezor Ethereum app, Keycard, Satochip, Keystone, Lattice, SE050 (k1), SmartCard-HSM (k1) | ZeroDev **`ECDSAValidator` `0x845ADb2C711129d4f3966735eD98a9F09fC4cE57`** (есть на Base и Base Sepolia) | Solidity — ноль. CLI: `changeRootValidator(ECDSAValidator, owner address)`; подпись через `alloy-signer-ledger` / `alloy-signer-trezor` (`signMessage(userOpHash)` — валидатор принимает EIP-191); формат подписи 65 B `r‖s‖v` |
| C: FIDO2 / passkeys — Security Key, Titan, Feitian, Solo 2, Ledger Security Key, платформенные passkeys | ZeroDev **`WebAuthnValidator` `0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69`** или свой на Solady `WebAuthn.sol` (уже в `contracts/lib/solady`) | Solidity — ноль (если брать ZeroDev) или небольшой модуль. CLI: CTAP2 `getAssertion` со своим `clientDataJSON` (`{"type":"webauthn.get","challenge":"<b64url(userOpHash)>",…}`), UV=required; кодирование `(authData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled)`. Credential ID хранить в конфиге (non-resident) |
| Мульти-фактор | ZeroDev Weighted Validator (ECDSA + WebAuthn signers) [V пакет], Safe-owner (1271) или свой k-of-n P-256 | Свой k-of-n P-256 ~100 строк на основе `P256Validator`, нужен аудит. Weighted от ZeroDev покрывает классы B+C, но не A |

---

## 5. Multisig, social recovery и холодный recovery-owner

- **Kernel v3 допускает «узкие» не-root валидаторы.** Для них проверяется `allowedSelectors[vId][selector]`, а `grantAccess(vId, selector, allow)` вызывает только root [V `contracts/lib/kernel/src/Kernel.sol:261,392`; `changeRootValidator` — строка 135]. Отсюда **recovery-owner**: второй валидатор (второй экземпляр P256Validator или ECDSAValidator) с доступом **только** к `changeRootValidator`. Реализовано: `contracts/src/P256RecoveryValidator.sol` (`P256Validator` под своим адресом, отказывает в ERC-1271), `agent-signer owner add-recovery` / `owner recover` [V]. Повседневный owner — дешёвый ключ; recovery — холодный ключ (бумага, сейф, второй Ledger), он нужен лишь при потере основного.
  - **Важно:** recovery-валидатор, которому разрешён `changeRootValidator`, по факту тоже root. Его защита должна быть не слабее основного ключа. Желательно добавить таймлок: в `kernel-7579-plugins` есть `TimelockPolicy` [V дерево репо], но применимость к validator, а не к permission, — [I]. В наших контрактах таймлока пока нет.
- **2-of-3 из дешёвых факторов**, например YubiKey + Trezor + TPM второй машины: свой k-of-n P-256 валидатор (все три — класс A) или Safe-owner. Это best practice для mainnet-сумм: одна скомпрометированная машина не даёт root.
- **Бумажный или QR-backup.** P-256-ключ, сгенерированный офлайн на отдельной машине, печатается как QR/hex и хранится в сейфе. Затем импортируется в YubiKey PIV (импорт поддерживается, [I]), TROPIC01 (`ECC_Key_Store` [V `lt_3.rs`]) или Ledger OpenPGP. Так ключ в железе получает резервную копию. Минус: такой ключ «был снаружи» и аттестация «сгенерирован в чипе» теряется. Альтернатива без импорта — seed-кошельки (Trezor `SignIdentity` и Ledger OpenPGP в seed-mode [I]): backup — 24 слова, ключ детерминирован.

---

## 6. Идея владельца: owner-ключ — зашифрованный файл на флешке

**Схема.** P-256 (или k1) скаляр шифруется паролем: Ethereum V3 keystore (scrypt + AES-128-CTR, формат не зависит от кривой; поле `address` бессмысленно для P-256), `age` с scrypt-recipient или свой argon2id + XChaCha20-Poly1305. Флешка вставляется только на время owner-операции.

**Что защищает:**
- ключ в покое вне хоста агента: кража файловой системы агента ничего не даёт (закрывает premise 2);
- постоянная компрометация хоста **пока флешка не вставлена** не даёт ничего;
- копия на флешке (или двух) решает backup; кривая любая;
- цена ~$5, ноль Solidity (для P-256 — `P256Validator` как есть).

**Что НЕ защищает (честно):**
- **В момент подписи ключ расшифрован в памяти хоста.** Хост, скомпрометированный *в этот момент* (а в нашей модели root на хосте агента, возможно, достижим), получает **сам ключ навсегда**, а не одну подпись. Это качественное отличие от любого SE (TROPIC01, YubiKey, Trezor): там скомпрометированный хост может только подписывать, пока устройство подключено.
- **Keylogger** снимает пароль; вместе с копией файла (флешка была вставлена) ключ потерян.
- **Нет presence-check:** после расшифровки малварь подпишет что угодно, а пользователь не видит, что подписано.
- **Кража флешки + слабый пароль = офлайн-брутфорс.** scrypt/argon2 его замедляет, но не отменяет.
- **Использовать на хосте агента нельзя:** там пароль и ключ видит атакующий (premise 3–4). Допустимо только на отдельной машине, в идеале офлайн (air-gapped ноутбук или live-USB), а userOpHash переносить QR-кодом.

**Сравнение с FIDO2-ключом за $25:**

| | Флешка + пароль | FIDO2-ключ ($25) |
|---|---|---|
| Ключ покидает носитель | **да**, при каждой подписи | никогда |
| Скомпрометированный хост во время операции | крадёт ключ навсегда | одна подпись при касании + PIN |
| Presence | нет | касание (UP) + PIN (UV) |
| Backup | тривиально (копия файла) | нужен второй ключ или recovery-валидатор |
| Валидатор | P256Validator как есть | WebAuthnValidator |

**Вывод:** флешка лучше «ключа в файле на хосте агента» и годится как **холодный recovery-owner** (§5) на офлайн-машине. Как повседневный owner она хуже FIDO2-ключа за $25, YubiKey PIV, Nitrokey или Trezor. Гибрид: FIDO2 **hmac-secret** (тот же $25-ключ) выводит ключ шифрования файла — расшифровка требует касания и физического ключа. Но ключ всё равно попадает в память хоста [I: так делают `systemd-cryptenroll --fido2-device` и age-плагины].

**Конфликт с правилом 5 и формулировка.** Тогда правило 5 гласило: «No plaintext private key, anywhere outside tests» (теперь исключение внесено в `KEY_POLICY.md`). Зашифрованный файл формально не plaintext, но расшифрованный — да. Предложенная тогда редакция:

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

Минимальные требования к реализации в CLI [I] и то, что сегодня делает `signer/crates/agent-signer/src/keyfile.rs` [V]:
- отдельный бэкенд `encrypted-file`, доступный **только** роли owner/recovery — сделано, под именем `keyfile`;
- отказ работать, если конфиг или хост помечен как agent host — не реализовано: такой пометки нет;
- scrypt/argon2id + AEAD (`age` 0.12 или `scrypt` + `chacha20poly1305`) — сделано как scrypt N = 2^18 + AES-256-GCM;
- пароль через `rpassword`, не через env или аргументы — сделано;
- `Zeroizing<[u8; 32]>`, `mlock`, подпись тем же `p256` с low-s — сделано (`mlock` на Unix);
- проверка: публичный ключ после расшифровки совпадает с `ownerPublicKey` из конфига — сделано иначе: публичная половина файла связана с шифротекстом и сверяется с root- или recovery-ключом аккаунта на цепи до любой подписи.

---

## 7. Интеграция из Rust (сводка по транспортам)

| Транспорт | Устройства | Крейты [V crates.io, 2026-10] | ОС |
|---|---|---|---|
| PC/SC (CCID) | YubiKey PIV/OpenPGP, Nitrokey 3, JavaCard, Keycard, Satochip, Ledger OpenPGP app [I], SmartCard-HSM | `pcsc` 2.9, `yubikey` 0.9.0-rc.0 (уже в проекте), `openpgp-card` 0.7 + `card-backend-pcsc` 0.5 | Linux (pcscd), macOS, Windows — встроено |
| PKCS#11 | YubiKey (ykcs11), Nitrokey (OpenSC), SmartCard-HSM | `cryptoki` 0.12 | все; нужен .so/.dll модуль |
| CTAP2 HID | все FIDO2-ключи, Ledger/Trezor FIDO | `ctap-hid-fido2` 3.6, `fido2-rs` 0.6 (libfido2), `authenticator` 0.5 | Linux/macOS — прямо; Windows — без админа только через `webauthn.dll` [I] |
| Ledger APDU over HID | Ledger Ethereum app | `alloy-signer-ledger` 2.5, `coins-ledger` 0.16 | все |
| Trezor protobuf over USB | Trezor Ethereum, `SignIdentity` | `alloy-signer-trezor` 2.5, `trezor-client` 0.1.6 (`SignIdentity` есть) | все |
| SPI/I2C (embedded) / USB-CDC | TROPIC01, ATECC608, SE050, OPTIGA | `tropic01` 0.1.0, git rev `3310775` (уже в проекте), `se05x` 0.4.2, `rust-cryptoauthlib` 0.4.5 (2022), OPTIGA — FFI к C | devkit — USB-serial; остальное через MCU/RPi |
| Платформа | Secure Enclave, TPM, CNG | уже в `hw-signer` | macOS / Linux / Windows |

---

## 8. Источники (основные)

- Политика проекта и код: `docs/KEY_POLICY.md`, `contracts/src/P256Validator.sol`, `contracts/lib/kernel` (тег v3.3), `docs/TROPIC01.md`, `docs/ARCHITECTURE.md`, Y. Madhwal, *Integrating Secure Elements with Account Abstraction for Autonomous IoT Blockchain Agents* (исследовательский семинар Сколтеха, 14 октября 2026; слайды не опубликованы).
- ZeroDev-адреса: https://unpkg.com/@zerodev/ecdsa-validator/_esm/constants.js, https://unpkg.com/@zerodev/passkey-validator@5.6.0/_esm/index.js, https://unpkg.com/@zerodev/weighted-validator/_esm/index.js; WebAuthnValidator: https://github.com/zerodevapp/kernel-7579-plugins
- TROPIC01: https://github.com/tropicsquare/tropic01 (datasheet A.11, user API 1.4.0), https://www.tropicsquare.com/order-devboard-form, SDK `libtropic-rs` rev 3310775.
- Trezor `SignIdentity`: https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/misc/sign_identity.py; Safe 7: https://trezor.io/guides/trezor-devices/trezor-safe-7/dual-secure-elements-in-trezor-safe-7
- Ledger OpenPGP: https://github.com/LedgerHQ/app-openpgp (src/gpg_pso.c, Makefile); SSH agent deprecated: https://github.com/LedgerHQ/app-ssh-agent; Security Key: https://developers.ledger.com/docs/ai-tools/hardware-security/security-key
- YubiKey PIV policies: https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html
- Nitrokey: https://docs.nitrokey.com/nitrokey3/faq, https://www.nitrokey.com/node/648, https://docs.nitrokey.com/nitrokeys/features/openpgp-card/uif
- OPTIGA: https://github.com/Infineon/optiga-trust-m ; ATECC: https://github.com/MicrochipTech/cryptoauthlib ; Android Keystore: https://developer.android.com/training/articles/keystore
- Цены: ссылки в таблице §1.
