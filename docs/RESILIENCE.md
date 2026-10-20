# Resilience: поломка и потеря ключей (TPM_sign)

> **English summary (2026-10-20).** Resilience against a secure element that
> breaks, is reset or is lost — not against an attacker. Keys here can never
> be exported, so recovery comes from redundancy on-chain, not from backups:
> losing the agent key costs nothing (the owner rotates it); losing the owner
> key freezes the account when the agent's mandate expires; losing owner and
> recovery is permanent. The most likely real-world loss on the testnet host
> is a firmware-TPM clear (BIOS update, "Clear TPM", board replacement),
> which takes the owner key with it.
>
> **Status of the two code issues this study found in the recovery design —
> both fixed before any recovery key was installed:**
> 1. Kernel lets *any* installed validator vouch for ERC-1271 signatures,
>    regardless of the selectors granted to it, so a recovery key could have
>    signed permits for the account. `P256RecoveryValidator`
>    (`0x63dd80Fc5E109A44fd179F85050487E02c5e6958` on Base Sepolia) now
>    refuses every ERC-1271 request; the earlier build that did not
>    (`0xe1dcC2CC…a64D`) was never installed on any account.
> 2. `changeRootValidator` leaves the lost owner's validator installed, so
>    its key would still pass ERC-1271. `owner set-root --retire <validator>`
>    uninstalls it in the same operation (and can reinstall the same contract
>    with the new key, under the install nonce Kernel requires).
> Both are covered by forge tests (mutation-checked).
>
> **Installed on the testnet account (2026-10-20):** a cold recovery key —
> an encrypted key file on a USB drive (scrypt N = 2^18 + AES-256-GCM) — on
> `P256RecoveryValidator`, granted only `changeRootValidator` (tx
> `0x213e1047d2f9eec431a26a63e6ee53ab6f1341b61fa53b2e179489c168d544fa`); the
> key stored on-chain matches the file's public key. Procedure if the owner
> key is lost:
>
> ```sh
> agent-signer owner recover  --agent … --sponsored     # recovery key becomes root
> agent-signer owner set-root --agent … --as-recovery --sponsored \
>     --validator <P256Validator> --retire <lost owner's validator> --public-key <x>,<y>
> ```
>
> `agent-signer key check --keyfile …` proves the passphrase still opens the
> file (and `key check --handle …` that a TPM key still signs) without
> sending anything — run it periodically. Claims are marked [V]
> verified or [I] inferred. Written by a research agent.


> **English summary (2026-10-20).** The threat here is not an attacker but a
> secure element that breaks, gets cleared or gets lost. The agent key is
> cheap to lose: the owner rotates the permission and the account's funds,
> address, mandate and Safe are untouched. The owner key is the single
> point of failure: without it and without a recovery path the agent runs
> until `validUntil` and then the account (and any Safe it solely owns) is
> frozen forever. On the testnet host both keys share one Intel PTT
> firmware TPM, so a single TPM clear or an fTPM reset kills both at once.
> Recommended minimum: (a) testnet — the planned `P256RecoveryValidator`
> granted only `changeRootValidator`, with an encrypted key on two USB
> drives, plus a tested recovery run; (b) value-bearing — a daily owner on a
> separate non-exportable device, a recovery key that is **seed-backed or
> encrypted-and-duplicated**, a **timelock with owner cancel** on the
> recovery path, ERC-1271 disabled on the recovery validator, the old owner
> validator uninstalled after recovery, health checks and a mandate-renewal
> heartbeat. Two code findings: (1) in Kernel v3.3 every installed non-root
> validator can produce ERC-1271 signatures without any selector check, so
> the recovery key (and an old owner key left installed after recovery) can
> sign permits / Permit2 for the account immediately, bypassing any
> timelock; (2) ZeroDev's `TimelockPolicy` exists (proposal → delay →
> execute, account- or guardian-cancel, 1271 refused) and composes with our
> `P256Signer` as a permission, but needs `execute` granted to create
> proposals on Kernel v3.3 and is not known to be audited or deployed.

Дата: 2026-10-20. Код репозитория **не менялся**. Метки: **[V]** — проверено
(URL или файл:строка), **[I]** — вывод / по памяти, не перепроверено.

Состояние кода на момент исследования (параллельно идёт работа):
`contracts/src/P256RecoveryValidator.sol` (= `P256Validator` по другому адресу),
`kernel.rs: add_recovery_calldata / change_root_calldata`,
`agent.rs: KeySpec::Recovery`, тесты `AgentPermission.t.sol:798–900`
(`test_recovery_canOnlyTakeOverRoot`, `test_recovery_replacesALostOwner`) [V].

---

## 0. Главное за минуту

1. **Агентский ключ терять не страшно.** Владелец ротирует permission
   (`permission rotate`), адрес аккаунта, средства, Safe и мандат остаются [V
   по коду, §2.1].
2. **Owner-ключ — единственная точка отказа.** Без него и без recovery
   агент работает до `validUntil` (в тестнет-конфиге — **2026-11-19 00:00 UTC**,
   `signer/agent.base-sepolia.json`, [V]), а после этой даты аккаунт и Safe,
   которым он владеет единолично, замораживаются навсегда (§2.3).
3. **На тестнет-хосте оба ключа в одном fTPM** (Intel PTT: ACPI HID
   `INTC6001`, Lenovo, i7-13700H, [V локально `/sys/class/tpm/tpm0/device/hid`];
   «INTC6001 = PTT» — [I]). Owner `0x81010010` без authValue, агент
   `0x81010012`, запечатан на PCR 0,2,4,7 [V конфиг]. Один `TPM2_Clear`,
   сброс PTT при обновлении BIOS или замена материнской платы уничтожат
   **оба** ключа одновременно. Recovery нужен даже на тестнете, хотя бы чтобы
   отрепетировать процедуру.
4. **Восстанавливаемость без экспорта** достигается не копированием ключа, а
   **избыточностью ключей на цепи**: несколько независимых неэкспортируемых
   ключей (или один seed-backed), каждый из которых зарегистрирован в Kernel с
   правом `changeRootValidator`. Резервная копия — это второй ключ, а не копия
   первого.
5. **Две находки по коду (важно для текущей реализации):**
   - **ERC-1271 обходит выдачу селекторов.** `ValidationManager._verifySignature`
     для не-root валидатора проверяет только «установлен» и
     `nonce >= validNonceFrom`. `allowedSelectors` не проверяется
     [V `contracts/lib/kernel/src/core/ValidationManager.sol:424–449`].
     `P256RecoveryValidator` наследует `isValidSignatureWithSender` от
     `P256Validator` [V `contracts/src/P256Validator.sol` `isValidSignatureWithSender`].
     Следовательно, **recovery-ключ уже сейчас может подписать ERC-2612
     permit / Permit2 / EIP-3009 от имени аккаунта**, без всякого
     `changeRootValidator` и без таймлока. Та же проблема со **старым
     owner-валидатором**, который остаётся установленным после
     `changeRootValidator`: `changeRootValidator` его не удаляет
     [V `Kernel.sol:135–155`], и тест `test_recovery_replacesALostOwner`
     проверяет только userOp-путь. Исправление: в `P256RecoveryValidator`
     переопределить `isValidSignatureWithSender` → `ERC1271_INVALID` (как
     `AgentPolicy.checkSignaturePolicy` для агента, [V `AgentPolicy.sol:210–218`]),
     а в процедуре recovery — `uninstallValidation(oldOwnerVId)`. Добавить
     тесты на оба случая.
   - **Recovery = root без задержки.** Кража флешки вместе с паролем даёт
     мгновенный захват. Для ценного деплоя нужен таймлок с отменой
     владельцем (§3.4).

---

## 1. Режимы отказа по бэкендам

### 1.1 TPM 2.0: семантика иерархий и сидов (основа всего остального)

- В TPM 2.0 три постоянных сида: **EPS** (endorsement), **SPS** (storage /
  owner hierarchy), **PPS** (platform). Ключи, созданные под SRK
  (`0x81000001`, первичный ключ, выводимый из SPS), зашифрованы на SRK. Если
  SPS сменился, тот же шаблон даёт **другой** SRK, и все дочерние ключи
  становятся невосстановимы.
- **SPS меняет только `TPM2_Clear`** (плюс производство). `TPM2_Clear`
  «Reset storage hierarchy seed from RNG» и сбрасывает persistent- и
  loaded-объекты storage- и endorsement-иерархий [V референсная реализация
  `Clear.c`: https://android.googlesource.com/platform/external/tpm2/+/716a46a/Clear.c;
  man `tpm2_clear`: https://www.mankier.com/1/tpm2_clear]. `TPM2_ChangeEPS`
  и `TPM2_ChangePPS` меняют другие сиды и наш ключ не трогают, но
  `ChangeEPS` тоже чистит объекты endorsement-иерархии [I].
- **Наши ключи** — persistent-объекты `0x8101xxxx` в owner-иерархии под SRK
  [V `signer/crates/hw-signer/src/tpm.rs:4,51`, конфиг]. Значит:

| Событие | Что с нашим ключом | Комментарий |
|---|---|---|
| Перезагрузка, обновление ОС/ядра | жив | persistent handle |
| `TPM2_Clear` (tpm2_clear, «Clear TPM» в Windows Security / tpm.msc / UEFI, PPI-запрос из ОС) | **уничтожен** | SPS новый, persistent-объекты удалены [V] |
| Смена SPS — только через Clear | **уничтожен** | «регенерация SRK» с тем же шаблоном без Clear даёт тот же SRK [I по спецификации: первичные ключи детерминированы от сида и шаблона] |
| Случайный `key evict` / `tpm2_evictcontrol` | **уничтожен** | blob мы не храним, восстановить нечем [V: `KeyCmd::Evict` есть в CLI, main.rs:229] |
| Обновление BIOS на машине с **fTPM** | зависит от вендора; **часто уничтожен** | §1.2 |
| Обновление **прошивки самого TPM** (dTPM или fTPM) | часто уничтожен | Intel NUC: «TPM firmware update clears all data in the TPM» [V https://www.intel.com/content/dam/support/us/en/documents/mini-pcs/NUC5i3MY-TPM-Firmware-Update.pdf]; Infineon-апдейты (ROCA) требовали очистки [V https://www.getac.com/uploads/2023/01/infineon_tpm_security_update_20230116.pdf, I детали] |
| Замена CPU (AMD fTPM) | **уничтожен** при ответе «Y» | §1.2 |
| Замена материнской платы | fTPM — **уничтожен**; пинновый dTPM-модуль, переставленный на новую плату, — ключ жив [I], PCR-запечатанные — молчат | |
| Изменение PCR (BIOS, Secure Boot db/dbx, загрузчик) | ключ жив, но **PCR-запечатанный не подписывает** | §1.4 |
| Dictionary-attack lockout (неверный authValue N раз) | жив; **временная** блокировка | восстанавливается по таймеру или через lockoutAuth [I] |

**Защита от случайного/злонамеренного Clear из ОС:**
`tpm2_clearcontrol -C l s` выставляет `disableClear`, и lockout-иерархия
больше не может выполнить Clear. Platform-иерархия (BIOS) — может всегда, и
снять `disableClear` тоже может только platform [V
https://man.archlinux.org/man/extra/tpm2-tools/tpm2_clearcontrol.1.en].
Значит, от «Clear TPM» в UEFI и PPI-запроса на очистку это не защищает
[I: PPI выполняется прошивкой через platform-иерархию]. Ставить имеет
смысл: от опечатки и от скрипта, сделавшего `tpm2_clear`, защищает.

### 1.2 Firmware TPM (Intel PTT, AMD fTPM)

- **Где живёт:** fTPM — приложение внутри Intel CSME / AMD PSP. Его NV
  лежит в SPI-флэше материнской платы и зашифровано ключом, привязанным к
  CPU/чипсету [I]. Отсюда две уязвимости: перепрошивка SPI и смена CPU.
- **AMD fTPM.** После замены CPU **или обновления BIOS** выводится
  «New CPU installed. fTPM/PSP NV corrupted or fTPM/PSP NV structure changed»
  с выбором Y (reset fTPM) или N (оставить) [V
  https://www.wintips.org/?p=55403, https://forum.asrock.com/printer_friendly_posts.asp?TID=25098].
  «Y» = Clear, ключи потеряны. При реальной смене CPU старые данные не
  расшифровать [I]. Вероятность: **высокая** для настольных AMD при апгрейде
  CPU, **средняя** при обновлениях AGESA/BIOS.
- **Intel PTT.** Сообщения пользователей: «When you flash the BIOS on a system
  using a firmware TPM, you lose the keys» [V форум,
  https://winraid.level1techs.com/t/bios-downgrade-without-tpm-key-reset/32584].
  У крупных вендоров (Lenovo, Dell, HP) обычное обновление BIOS PTT, как
  правило, сохраняет, а обновление ME-региона или даунгрейд — нет [I].
  **Это наш тестнет-хост.** Вероятность: **средняя** за год при регулярных
  обновлениях (LVFS/fwupd или вендорный апдейтер).
- **CMOS reset / батарейка.** Сам по себе NV fTPM не стирает (он в SPI) [I],
  но может выключить PTT в настройках или сбросить Secure Boot-ключи → PCR7
  → запечатанные ключи молчат.
- **Пункт «Clear TPM» / «Reset fTPM» в UEFI** — Clear, ключи потеряны [V MS
  doc ниже].
- **Ремонт ноутбука** (замена платы по гарантии) = новый fTPM =
  **гарантированная потеря** [I, следует из архитектуры].

### 1.3 Дискретный TPM

- Отдельный чип (Infineon SLB 9670/9672, Nuvoton NPCT7xx, ST33). Отказы
  самого чипа редки [I, публичной статистики нет]. Основные риски: смерть
  платы, к которой чип припаян; обновление прошивки TPM (Infineon требовал
  Clear); Clear из ОС или UEFI.
- Плюс dTPM: прошивки BIOS/ME/PSP его не касаются. Пинновый модуль
  (LPC/SPI-хедер) переживает замену материнской платы [I].

### 1.4 PCR-запечатанные ключи (по замыслу)

- Агентский ключ на тестнете запечатан на PCR 0,2,4,7 [V конфиг].
  `TPM2_PolicyPCR` с **точным** дайджестом [V `tpm.rs:240–252`]. После любого
  изменения измерений ключ **жив, но не подписывает**. Откатить измерения
  обычно нельзя.
  - PCR0 — код прошивки (обновление BIOS);
  - PCR2 — option ROM (замена GPU/NIC, обновление их прошивки);
  - PCR4 — загрузчик (обновления shim/grub/systemd-boot, ядро при UKI);
  - PCR7 — состояние Secure Boot (db/dbx/KEK; в 2026 году идёт массовая
    ротация сертификатов Microsoft: KEK CA 2011 истекает 24.06.2026, UEFI CA
    2011 — 27.06.2026, их заменяют на CA 2023 через обновления db/KEK [V
    https://support.microsoft.com/help/5062710,
    https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/]).
    Изменение db/KEK меняет PCR7 [I: PCR7 измеряет переменные Secure Boot].
- **Вывод:** PCR-sealing для агентского ключа — это ежегодная (или чаще)
  гарантированная «поломка». Это нормально, ротация дешёвая, но процедура
  должна быть рутинной: перед обновлением прошивки создать новый ключ после
  перезагрузки и ротировать. Для owner-ключа PCR-sealing **не использовать**
  (правило 4 KEY_POLICY и так говорит, что он не защищает от компрометации
  работающей системы). Альтернатива, переживающая обновления, —
  `PolicyAuthorize` с подписанными политиками [I], для нас избыточна.

### 1.5 Apple Secure Enclave (CryptoKit `dataRepresentation`)

Устройство бэкенда: blob `dataRepresentation` лежит **файлом** в
`~/Library/Application Support/tpm_sign/enclave/<label>` (или
`$TPM_SIGN_ENCLAVE_DIR`); флаги `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
+ `.privateKeyUsage`, без биометрии
[V `hw-signer/src/secure_enclave.rs:1–19`, `swift/SecureEnclaveShim.swift:53–59`].

| Событие | Результат |
|---|---|
| Удалили файл blob (удаление пользователя, чистка `~/Library`, переустановка без переноса) | **ключ потерян** — «Deleting the blob file destroys the key for good» [V `secure_enclave.rs:15`] |
| Обновление macOS | жив [I] |
| blob скопирован на другой Mac / Migration Assistant | **бесполезен**: чужой SE не развернёт [V `secure_enclave.rs:16`; DTS: https://developer.apple.com/forums/thread/708749] |
| Erase All Content and Settings / стирание с переустановкой | **потерян**, даже если blob сохранён: erase уничтожает ключи в effaceable storage / anti-replay, «does NOT survive … device restore, device erase» [V-вторичный: сводка форумов Apple DTS, https://developer.apple.com/forums/thread/708749; механизм — https://support.apple.com/en-is/guide/security/sece8608431d/web]. Точная привязка CryptoKit-blob к «эпохе» стирания — [I] |
| Замена логической платы (SE в SoC/T2) | **потерян** (новый UID) [V: UID «unique to each device», Apple Platform Security] |
| Смена Apple ID / выход из iCloud | не влияет [I: blob не в iCloud Keychain, флаг ThisDeviceOnly] |
| Смена пароля пользователя | скорее всего жив [I]; **проверить** |
| Owner-ключ с `.biometryCurrentSet` + добавили/удалили отпечаток | **ключ инвалидирован** [I, документированное поведение флага]. Для owner-ключа использовать `.userPresence` или `.biometryAny` |

**Практика:** blob **можно и нужно бэкапить** (Time Machine, вторая копия
файла). Это не нарушает «no export»: blob бесполезен вне этого SE. Бэкап
защищает от удаления файла, но не от стирания Mac или замены платы.

### 1.6 Windows CNG Platform Crypto Provider

- Наш ключ — **пользовательский** persisted key (`NCryptCreatePersistedKey`,
  флаги 0, не `NCRYPT_MACHINE_KEY_FLAG`) [V `hw-signer/src/windows_tpm.rs:40–60`].
  PCP хранит обёрнутый TPM blob **файлом в профиле пользователя**
  (`%LOCALAPPDATA%\Microsoft\Crypto\PCPKSP\…`) [I, путь не подтверждён
  официально].
- Удаление профиля, переустановка Windows, «Reset this PC → Remove
  everything» → файл удалён → **ключ потерян** [I].
- Clear TPM (Windows Security → Device security → Security processor
  troubleshooting → Clear TPM, tpm.msc, `Clear-Tpm`, UEFI) → **все ключи
  TPM потеряны**; после этого «Windows will automatically reinitialize it» [V
  https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm].
  Microsoft сама рекомендует Clear перед чистой установкой ОС: ровно та
  рутина, которую делает админ, не думая о нашем ключе.
- Переключение между двумя TPM в UEFI (dTPM ↔ fTPM) Windows не
  поддерживает, рекомендация MS — Clear и переустановка [V там же].
- **Практика:** бэкап файла PCPKEY (как blob SE) безопасен и защищает от
  потери профиля, но не от Clear [I].

### 1.7 USB secure elements и аппаратные кошельки

| Устройство | Неверный PIN | Прошивка | Физика | Восстановимость |
|---|---|---|---|---|
| **YubiKey 5 PIV** | PIN 3 попытки → PUK 3 попытки → только `reset` PIV, **все слоты стёрты** [V https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html] | не обновляется (ключ не сотрёт апдейт, но и уязвимость не закроет) [V OWNER_DEVICES] | потеря, поломка USB-разъёма, стирка | нет (если ключ сгенерирован внутри) |
| **Nitrokey 3** | PIV/OpenPGP PIN 3 → PUK/Admin PIN → factory reset [V https://docs.nitrokey.com/nitrokey3/reset.html] | обновляемая; сохранность ключей при обновлении обычно да [I], исторические инциденты — проверить | как выше | нет |
| **Ledger Nano S Plus** | **3 неверных PIN → сброс устройства**, восстановление из 24 слов [V https://ledger.com/academy/topics/ledgersolutions/ledger-pin-code-what-you-need-to-know] | Ethereum-app: ключ из seed, переживает всё. **OpenPGP-app: ключи в NVM приложения стираются при любом обновлении приложения или ОС**, если не включён **Seed Mode** [V https://openpgp.apps.ledger.com/app-openpgp.html, https://openpgp.apps.ledger.com/gpgcard-addon.html] | потеря | seed (при Seed Mode — и для P-256) |
| **Trezor Safe 3/5/7** | 16 неверных PIN → wipe, задержки растут экспоненциально [V https://trezor.io/guides/trezor-devices/pin-protection-on-trezor-devices] | `SignIdentity` nist256p1 детерминирован от seed [V OWNER_DEVICES §1] — переживает всё | потеря | **seed (12–24 слова)** |
| **TROPIC01 devkit** | PIN на чипе нет; если построен на `MAC_And_Destroy`, попытки ограничены чипом [V OWNER_DEVICES §3.1] | обновления FW чипа — сохранность R-mem [I] | потеря, ESD | нет. Плюс **уникальный риск**: потерян SH1PRIV при инвалидированном SH0 → сессию не открыть никогда, ключ мёртв, хотя чип цел. Инвалидировать все 4 pairing-слота = кирпич [V datasheet §7.5.3 через OWNER_DEVICES]. Ошибка в I-Config необратима |
| **FIDO2-ключ** | 8 неверных PIN → блок; reset стирает credentials [I] | — | потеря | нет |

### 1.8 Флешка с зашифрованным recovery-ключом

- **Удержание данных без питания.** JEDEC JESD218 требует от *клиентских SSD*
  1 год при 30 °C без питания; при нагреве удержание резко падает [V
  https://www.anandtech.com/show/9248/the-truth-abou]. Для дешёвых
  USB-флешек (TLC/QLC, неизвестный контроллер) спецификации нет, реальность
  может быть хуже [I]. Отказ контроллера — внезапный и полный [I].
- **Забытый пароль** — на практике самый вероятный отказ холодного ключа,
  который используют раз в несколько лет [I]. KDF с N ≥ 2^18 (правило 5)
  делает перебор нереальным и для самого владельца.
- **Смягчение (без ослабления no-export, т.к. это и так экспортируемый
  ключ):**
  - две флешки разных производителей в двух местах;
  - **третья копия на бумаге: QR шифротекста** (keystore JSON ~ 500 байт
    помещается в один QR). Бумага не гниёт, а шифротекст без пароля
    бесполезен [I];
  - ежегодно вставлять, проверять расшифровку и подпись (§4), переписывать
    файл (обновить заряд ячеек) [I];
  - пароль: diceware 6–7 слов, записан на бумаге и хранится **отдельно** от
    носителей (или у доверенного лица). Иначе — «ключ есть, пароля нет».

---

## 2. Последствия для каждой роли ключа

### 2.1 Потерян агентский ключ

- Owner выполняет `permission rotate` — одна root-операция, которая
  заменяет permission новым ключом и/или мандатом [V `main.rs:130–145`].
- **Ничего не теряется:**
  - адрес аккаунта (Kernel-прокси уже задеплоен, `account` закреплён в
    конфиге [V `agent.rs:140–143`]);
  - баланс и токены;
  - Safe: владелец — аккаунт, а не ключ [V `docs/ERC1271.md`];
  - отношения с paymaster: спонсорство привязано к аккаунту [I по
    `paymaster sponsor`].
- **Нюансы:**
  - Бюджет `spent` в новом мандате начинается заново — это решение
    владельца.
  - Потерянный ключ не нужно «отзывать»: он мёртв. Если же ключ скорее
    «скомпрометирован, чем потерян» — rotate тоже это закрывает.
  - Owner должен быть доступен. Цепочка «агентский ключ умер → owner нужен
    срочно» — основная практическая причина держать owner живым и
    проверенным.
  - Если агент и owner в одном fTPM (тестнет), они умирают **вместе**, и
    §2.1 не помогает.

### 2.2 Потерян owner-ключ, агент работает

- Агент продолжает работать в рамках мандата: allow-list, лимиты, бюджет,
  `validUntil` [V `AgentPolicy.sol:183–207`].
- **Недоступно** всё, что требует root:
  - ротация и отзыв агента;
  - смена мандата и продление `validUntil`;
  - `upgradeTo`;
  - установка и удаление модулей;
  - любые переводы за пределами allow-list;
  - `invalidateNonce`;
  - смена owner Safe [V `Kernel.sol:88–103,135,157,330–440` — всё под
    `onlyEntryPointOrSelfOrRoot`].
- Когда `block.timestamp > validUntil`, EntryPoint отклоняет любые
  операции агента, потому что политика возвращает `validUntil`
  [V `AgentPolicy.sol:207`].
- **Ограниченный «спасательный коридор».** Если в allow-list заранее есть
  запись `(coldAddress, 0x00000000)`, агент (и только в сторону
  `coldAddress`) может выводить ETH в пределах `maxValuePerOp` и `budget`
  до `validUntil` [I по логике `_judge`]. Это безопасно: атакующий на
  хосте агента может отправить деньги лишь владельцу. Но лимит бюджета
  ограничивает спасаемую сумму, а ERC-20 так не выведешь: получатель
  `transfer(to,…)` в allow-list не фиксируется [I: `AgentPolicy` проверяет
  `(target, selector)` и лимиты токена, а не аргумент `to`].

### 2.3 Потеряны owner **и** recovery: «мёртвый аккаунт»

- **Что происходит:**
  - До `validUntil` работает только агент, в рамках мандата.
  - После `validUntil` никто и никогда не сможет подписать операцию:
    - root-путь требует owner-ключ;
    - permission истёк;
    - восстановления нет.
  - Kernel не upgradeable без root.
  - EntryPoint deposit аккаунта не вывести (`withdrawTo` вызывает только
    аккаунт) [I].
- **Что замораживается:**
  - ETH и токены на Kernel-аккаунте;
  - всё в Safe, где Kernel — единственный owner при threshold 1;
  - NFT;
  - позиции в протоколах, которые требуют действия владельца (LP,
    стейкинг, займы — по займу возможна **ликвидация**, потому что
    довнести залог некому);
  - роли и права аккаунта в других контрактах (owner paymaster'а, если это
    этот аккаунт).
- **Масштаб:** 100 % стоимости аккаунта и подчинённых Safe, минус то, что
  агент успеет вывести по «коридору» из §2.2.
- **Вероятность:** складывается из независимых отказов. Пример на тестнете
  (owner и агент в одном PTT, без recovery): вероятность «мёртвого
  аккаунта» за год ≈ вероятность Clear/сброса PTT за год. По опыту
  обновлений прошивок это единицы–десятки процентов [I, порядок величины].
  С двумя независимыми носителями (owner на устройстве A, recovery на
  флешках B1+B2 + QR) нужен одновременный отказ нескольких независимых
  вещей, и вероятность падает на порядки — при условии регулярных проверок,
  иначе отказы «копятся» незаметно.

---

## 3. Архитектуры восстановления без экспорта ключей

### 3.0 Что даёт Kernel v3.3 (проверено по коду `contracts/lib/kernel`, тег v3.3)

- **Root-валидатор ровно один** (`vs.rootValidator`). Остальные
  валидаторы и permissions работают **только по выданным селекторам**
  (`grantAccess`) [V `Kernel.sol:229–275,392`].
- `changeRootValidator(vId, hook, data, hookData)`: если `vId` уже
  установлен, данные игнорируются (`onInstall` не зовётся) [V
  `Kernel.sol:135–155`]. **Поэтому новый owner-ключ нельзя положить в тот
  же экземпляр `P256Validator`**: в нём уже лежит старый ключ, и
  `onInstall` дважды не вызвать (`AlreadyInitialized`, [V
  `P256Validator.sol` onInstall]). Нужен **другой экземпляр контракта**
  (как в тесте `test_recovery_replacesALostOwner`) или
  `uninstallValidation` + установка заново.
- **ERC-1271** для не-root валидатора не проверяет селекторы
  [V `ValidationManager.sol:424–449`] — см. находку в §0.
- `invalidateNonce(n)` отзывает **все** не-root валидаторы и permissions с
  `nonce < n` разом [V `ValidationManager.sol:146–158`, `Kernel.sol:242–244`]:
  это «аварийный рубильник», задевающий и агента, и recovery.
- Готовые модули рядом с Kernel:
  - `WeightedECDSAValidator` (в самом репо Kernel v3.3): веса и порог
    гвардианов, **`delay`** (proposal → approve → исполнение не раньше
    `validAfter`), `veto` вызывает только сам аккаунт (`msg.sender` =
    kernel, т. е. root-операция) [V
    `contracts/lib/kernel/src/validator/WeightedECDSAValidator.sol:17–23,141–187,189–258`].
    Минусы: только secp256k1-гвардианы; **1271-путь проверяет порог подписей
    и игнорирует delay** [V там же :280–303]. Адрес деплоя на Base — [I].
  - ZeroDev `TimelockPolicy` (kernel-7579-plugins, последнее изменение
    2026-04-07): **policy** для permission. No-op userOp с данными
    предложения в подписи создаёт proposal. Исполнение возможно после
    `delay` и до `delay + expirationPeriod` — это `validAfter`/`validUntil`,
    которые форсит EntryPoint. `cancelProposal` вызывает аккаунт или
    отдельный `guardian`-адрес. ERC-1271 **отклоняет** (revert)
    [V https://github.com/zerodevapp/kernel-7579-plugins/blob/HEAD/src/policies/TimelockPolicy.sol,
    строки 17–41, 143–264, 345–365]. Аудит и канонический адрес в README не
    указаны [V README]; «не аудирован и не задеплоен» — [I].
  - ZeroDev recovery executor `0xe884C2868CC82c16177eC73a93f7D9E6F3A5DC6E`
    (`doRecovery(validator, data)`) — **только для аккаунтов с
    `ECDSAValidator`** [V https://docs.zerodev.app/sdk/advanced/recovery];
    таймлока нет. Нам не подходит.
  - Rhinestone core-modules (ERC-7579, аудит Ackee 2024 [V
    https://ackee.xyz/blog/rhinestone-core-modules-audit-summary/]):
    - `SocialRecovery`;
    - `DeadmanSwitch`: validator + hook. Hook при каждой операции
      обновляет `lastAccess`; nominee (ECDSA или 1271-контракт через
      `isValidSignatureNow`) получает доступ после
      `lastAccess + timeout`; ERC-1271 — revert [V
      https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/DeadmanSwitch/DeadmanSwitch.sol];
    - `ColdStorageHook` (таймлок исполнения).

    Совместимость с Kernel v3.3 сомнительна: Kernel не ставит hook
    отдельно, только в паре с validator/executor/selector [V комментарий
    `Kernel.sol:378–383`] — [I], проверять в форк-тесте.

### 3.1 N независимых owner-устройств (избыточность)

- **Схема:** owner A — root; устройства B, C — по отдельному экземпляру
  P-256-валидатора с `grantAccess(changeRootValidator)`. Устройство B
  становится root, когда A потеряно. Это ровно механизм
  `P256RecoveryValidator`, только ключ не «холодный», а в другом SE.
  Альтернатива — свой `P256MultiKeyValidator` (1-of-N: любой из
  зарегистрированных P-256 ключей = root), ~60–80 строк Solidity [I].
- **Плюсы:**
  - ни один ключ не экспортируется;
  - отказы независимы (разные производители, места);
  - каждое устройство тестируемо подписью (§4);
  - на цепи всё уже есть.
- **Минусы:**
  - покупка и учёт второго устройства;
  - каждое дополнительное устройство — ещё одна поверхность атаки
    (любое = root);
  - ERC-1271 — см. §0.
- **Стоимость:** Nitrokey 3 €55 / YubiKey $58 / второй Mac или ПК с TPM
  $0 [V OWNER_DEVICES §1]; Solidity — ноль (новый экземпляр
  `P256RecoveryValidator` на каждое устройство) или ~80 строк.

### 3.2 Холодный recovery-owner

| Вариант | Носитель | Валидатор | Плюсы | Минусы |
|---|---|---|---|---|
| Зашифрованный P-256 файл на флешке (текущий план) | 2 флешки + QR шифротекста | `P256RecoveryValidator` | дёшево; копируемо; кривая наша | ключ в памяти хоста в момент подписи [V KEY_POLICY rule 5]; пароль забывается; нет presence |
| Trezor `SignIdentity` nist256p1 | устройство + seed 12–24 слова | `P256RecoveryValidator` как есть | ключ в железе, seed восстанавливается на **любом** новом Trezor; экран и PIN | $59; нужен клиент `trezor-client` |
| Ledger OpenPGP-app в **Seed Mode** | устройство + seed | `P256RecoveryValidator` | у пользователя уже есть Nano S Plus | без Seed Mode ключ стирается при обновлении app/OS [V]; PIN 3 попытки → wipe |
| Ledger/Trezor Ethereum-app | устройство + seed | ZeroDev `ECDSAValidator` `0x845A…cE57` как recovery-валидатор + `grantAccess(changeRootValidator)` | никакого кода в устройстве; seed | secp256k1; вторая ветка в CLI (alloy-signer-ledger/trezor) |
| Бумажный P-256 ключ, импорт в SE при нужде | бумага в сейфе | `P256RecoveryValidator` | вечный носитель | plaintext-ключ на бумаге противоречит правилу 5 (там разрешён только *зашифрованный* носитель) — только как QR **шифротекста** |

### 3.3 M-of-N гвардианы / social recovery

- **Варианты:**
  - (а) свой `P256ThresholdValidator` k-of-n, ~100–150 строк + аудит [I];
  - (б) ZeroDev `WeightedECDSAValidator` (k1-гвардианы, есть delay+veto)
    [V код];
  - (в) Safe как гвардиан: recovery-валидатор, проверяющий 1271 у Safe
    (k-of-n владельцев Safe) — своего такого валидатора в Kernel нет, ~40
    строк поверх `SignatureCheckerLib` [I];
  - (г) Rhinestone `SocialRecovery` [V существует; совместимость — I].
- **Плюсы:** нет одной точки отказа и одной точки компрометации.
- **Минусы:**
  - координация людей;
  - гвардианы тоже теряют ключи — их свежесть надо проверять;
  - сговор k гвардианов = захват (нужен таймлок);
  - сложнее в коде и в аудите.
- Для одного владельца-разработчика это избыточно на старте. Разумно, когда
  на аккаунте реальные суммы третьих лиц.

### 3.4 Таймлок на recovery (рекомендуется для ценного деплоя)

**Цель:** recovery может заменить root только после задержки `D`. Если
текущий owner жив (его ключ украли не вместе с recovery), он видит событие
и отменяет его.

**Вариант A — ZeroDev `TimelockPolicy` + наш `P256Signer` как permission.**
- Permission = `{signer: P256Signer(recoveryKey), policies: [TimelockPolicy(delay, expiry, guardian)]}`
  + `grantAccess(changeRootValidator)`.
- **Подводный камень Kernel v3.3:** для no-op предложения нужен
  `callData = execute(single, address(0), 0, "")` (пустой callData падает
  на `bytes4(callData[0:4])`, `executeUserOp`-формы требуют hook). Значит,
  permission-у нужно выдать и селектор `execute` [V
  `Kernel.sol:259–273`; `TimelockPolicy._isNoOpCalldata`]. Это расширяет
  права recovery до «любой `execute` после задержки». Эквивалентно root
  после задержки, т. е. не хуже, чем `changeRootValidator`, но AgentPolicy-
  подобного ограничения нет [I].
- **Отмена:**
  - root-операция владельца `TimelockPolicy.cancelProposal(...)`
    (msg.sender = аккаунт);
  - или с адреса `guardian` (EOA, напр. адрес Ledger).
- **Плюсы:** код существует, ERC-1271 закрыт.
- **Минусы:**
  - аудит и деплой не подтверждены;
  - нужен форк-тест.

**Вариант B — свой `TimelockedP256RecoveryValidator`, ~100–130 строк [I].**
Набросок:
- `initiate(account, newRootCallHash, sig)`: вызывает кто угодно (газ-кошелёк).
  Проверяет P-256 подпись recovery-ключа над
  `(chainid, this, account, newRootCallHash, nonce)`, записывает
  `pending[account] = {hash, readyAt = now + D}`, эмитит
  `RecoveryInitiated`.
- `validateUserOp`:
  - `bytes4(callData) == changeRootValidator`;
  - `keccak256(callData) == pending.hash`;
  - подпись recovery-ключа над `userOpHash`;
  - вернуть `packValidationData(validAfter = readyAt, validUntil = readyAt + W)`.
  
  EntryPoint сам не пустит операцию раньше срока.
- `cancel()`: `msg.sender == account`, т. е. root-операция текущего
  владельца. Агенту в allow-list **не давать** (иначе атакующий на хосте
  агента блокирует восстановление).
- `isValidSignatureWithSender` → `ERC1271_INVALID`.
- `onInstall(x, y, D, W)` с нижней границей `D` (например ≥ 1 день на
  mainnet).

Плюсы: маленький, наш стиль, P-256 нативно, без лишних селекторов.
Минусы: свой код → свой аудит.

**Выбор `D`:**
- `D` должен быть меньше интервала, за который владелец гарантированно
  заметит событие: монитор событий на хосте агента ключей не требует и шлёт
  алерт.
- `D` должен быть больше времени реакции.
- Рекомендация: тестнет 10 минут, mainnet 3–7 дней [I].

**Цена задержки:** при честной потере owner-ключа восстановление занимает
`D` дней, а мандат агента должен эти дни пережить (`validUntil` с запасом,
§4).

**Dead-man вариант** (Rhinestone `DeadmanSwitch`-подобный): recovery
активен, только если owner молчит `T` дней. Hook нужно повесить **только на
root-валидатор**, иначе активность агента сбрасывает таймер. Семантически
это самое точное средство против «владелец исчез», но в Kernel v3.3 hook
на root ставится лишь при установке/смене root, а root-операции с hook идут
через `executeUserOp` [V `Kernel.sol:150–153,259–273`]. Сложнее
таймлока, отложить [I].

### 3.5 Seed-derivable vs неэкспортируемый SE: компромисс

| | Неэкспортируемый SE (TPM, SE, YubiKey, TROPIC01) | Seed-устройство (Trezor, Ledger Seed Mode) |
|---|---|---|
| Кража ключа удалённо | невозможна | невозможна (ключ в устройстве) |
| Кража ключа физически | нужен сам чип + PIN/auth | достаточно **бумажки с seed** |
| Поломка или потеря устройства | ключ потерян навсегда | новое устройство + seed = тот же ключ |
| Аттестация «сгенерирован в чипе» | возможна | нет (ключ выводим) |
| Что защищает | конфиденциальность | доступность |

Смешанная схема — **ежедневный ключ неэкспортируемый, recovery
seed-backed** — разумна, потому что роли разные:
- ежедневный ключ используется часто, на подключённых машинах: главное —
  чтобы его нельзя было унести (компрометация хоста = только подписи в
  момент присутствия);
- recovery используется раз в годы, хранится офлайн: главное — чтобы он
  **пережил** время. Риск кражи seed закрывается физическим хранением
  (сейф, раздельные места; SLIP-39 Shamir у Trezor [I]) и **таймлоком на
  цепи**: украденный seed ещё должен пережить `D` дней без отмены владельцем.

Таймлок превращает «кражу recovery» из мгновенной катастрофы в
обнаруживаемое событие. Поэтому именно он делает seed-backed recovery
приемлемым рядом с no-export основным ключом.

---

## 4. Эксплуатационные практики

1. **Health check без отправки транзакции** (`agent-signer health`) для
   owner, recovery и агента:
   - прочитать с цепи зарегистрированный ключ:
     `P256Validator.publicKeys(account)`,
     `P256RecoveryValidator.publicKeys(account)`, ключ агента из
     `P256Signer`;
   - попросить устройство подписать случайный challenge
     (`keccak("tpm_sign health" ‖ chainId ‖ account ‖ role ‖ timestamp)`);
   - проверить off-chain крейтом `p256` против ключа **с цепи**, а не из
     конфига: так ловится и «ключ жив, но не тот»;
   - дополнительно: `eth_call` симуляция реальной root-операции через
     бандлер (`eth_estimateUserOperationGas` прогоняет валидацию) — без
     отправки [I].
   
   Owner с presence (Touch ID / кнопка) — проверять раз в месяц вручную;
   агент — автоматически ежедневно. PCR-запечатанный агент после обновления
   прошивки здесь и отвалится — это сигнал к ротации.
2. **Продление мандата как heartbeat.**
   - `validUntil` = 2× интервал продления (например, продление раз в 30 дней,
     `validUntil` на 60). Каждое продление — это root-подпись, т. е.
     доказательство, что owner жив.
   - Пропуск продления → алерт задолго до заморозки.
   - С таймлоком на recovery: `validUntil` − сейчас > `D` + время на
     покупку нового устройства, иначе агент встанет во время честного
     восстановления.
3. **Мониторинг событий** (на хосте агента, без ключей): `RootValidatorUpdated`,
   `ModuleInstalled/Uninstalled`, `RecoveryInitiated` / `ProposalCreated`,
   `NonceInvalidated`, `P256KeyRegistered` → алерт владельцу (почта или
   Telegram).
4. **Реестр ключей** (`docs/KEYS.md` или приватный файл вне репо):
   - роль;
   - публичный ключ;
   - валидатор и адрес;
   - устройство и серийный номер;
   - место хранения;
   - кто знает PIN или пароль;
   - дата последней проверки.

   Для TPM добавить: машина, fTPM или dTPM, handle, PCR-sealing да/нет, дату
   последнего обновления BIOS.
5. **Перед обновлением BIOS/прошивки на хосте с fTPM:**
   - запустить health check;
   - убедиться, что owner **не** на этом TPM (или recovery жив);
   - после обновления: проверить агента и при необходимости ротировать.

   На тестнет-хосте до появления recovery — **не обновлять BIOS**.
6. **`tpm2_clearcontrol -C l s`** на хостах с ключами (§1.1), плюс
   lockoutAuth. Не защищает от Clear из UEFI, но защищает от скрипта.
7. **Бэкапить wrapped blobs там, где они есть:** SE `dataRepresentation`,
   Windows PCPKEY. Для Linux можно дополнительно хранить
   `TPM2B_PUBLIC/PRIVATE` агентского ключа, чтобы `evict` был обратим [I].
   Всё это безопасно: blob бесполезен вне своего чипа.
8. **Флешка recovery:**
   - две копии на разных носителях и в разных местах + QR шифротекста;
   - раз в год: расшифровать на офлайн-машине, подписать health-challenge,
     переписать файл.
   - пароль хранить отдельно.
9. **Репетиция recovery на тестнете** — раз в год и после каждого изменения
   кода: полный путь «owner потерян → recovery → новый owner → агент
   работает → старый owner-валидатор удалён → 1271 со старым и recovery
   ключом не проходит». Часть уже покрыта тестом
   `test_recovery_replacesALostOwner` [V].
10. **Safe:** если в Safe лежат значимые средства, а единственный owner —
    Kernel, Safe наследует все риски аккаунта. Вариант: второй owner Safe
    (тот же recovery-ключ через отдельный адрес) или модуль с задержкой
    (Zodiac Delay) [I]. Это усложняет `AgentPolicy`-проверки Safe — решать
    отдельно.

---

## 5. Рекомендация для проекта

### 5a. Тестнет (сейчас)

Минимум, который реально убирает «один Clear = конец»:

1. **`P256RecoveryValidator` + `grantAccess(changeRootValidator)`** — уже в
   работе [V]. Ключ — зашифрованный файл (scrypt N ≥ 2^18 + AEAD) на **двух**
   флешках + QR шифротекста. Расшифровка только на машине, которая не хост
   агента (KEY_POLICY rule 5).
2. **Сразу закрыть 1271** у recovery: переопределить
   `isValidSignatureWithSender` → `ERC1271_INVALID`, тест: подпись
   recovery-ключа через `Kernel.isValidSignature` отклоняется.
3. **Процедура recovery = три шага, все в CLI:**
   1. recovery-op `changeRootValidator(recoveryVId)`;
   2. root-op (теперь recovery) batch:
      `uninstallValidation(oldOwnerVId)` + `changeRootValidator(freshValidatorVId, key)`.
      Свежий экземпляр `P256Validator` нужен из-за `AlreadyInitialized`;
      вместо него можно `uninstallValidation(P256Validator)` и затем
      повторную установку того же адреса;
   3. проверка: health check нового owner, агент работает, старый owner и
      recovery не проходят ни userOp, ни 1271.
   
   Шаг 2 можно объединить с шагом 1, только если recovery получает больше
   селекторов. Не надо: два шага проще аудировать.
4. **Тест в Foundry** на остаточный 1271 старого owner-валидатора после
   recovery: он должен быть удалён.
5. **`validUntil`** тестнет-мандата (19.11.2026) продлевать
   `permission rotate` и рассматривать как heartbeat.
6. **Не обновлять BIOS** этого Lenovo, пока recovery не установлен и не
   отрепетирован.

Таймлок на тестнете не обязателен, но удобно сразу сделать вариант B с
`D` = 10 мин: отрепетировать UX ожидания и отмены.

### 5b. Деплой с ценностью (Base mainnet)

| Роль | Носитель | Валидатор | Почему |
|---|---|---|---|
| Агент | TPM/SE хоста агента (PCR-sealing по желанию) | `P256Signer` + `AgentPolicy` | как сейчас; потеря дешёвая |
| Owner (daily) | **отдельное** неэкспортируемое устройство с presence: Nitrokey 3 / YubiKey PIV (touch=always) / Mac SE с `.userPresence` | `P256Validator` (root) | KEY_POLICY rule 3 (i)/(ii) |
| Owner #2 (опц.) | второе устройство другого типа | `P256RecoveryValidator` #2, `changeRootValidator`, **без** таймлока или с коротким | быстрое восстановление при поломке daily |
| Recovery (cold) | **Trezor `SignIdentity` nist256p1** (seed в сейфе, SLIP-39 по желанию) **или** зашифрованный файл ×2 + QR | **`TimelockedP256RecoveryValidator`** (`D` = 3–7 дней), 1271 закрыт | переживает любые поломки; кража гасится таймлоком |
| Монитор | хост агента, без ключей | — | алерт на `RecoveryInitiated` / смену root |

Плюс:
- mandate heartbeat (продление каждые 30 дней, `validUntil` = 60 дней > `D` + запас);
- ежемесячный health check owner;
- ежегодный health check recovery;
- ежегодная репетиция на Base Sepolia;
- реестр ключей;
- `disableClear` на TPM-хостах.

### 5c. Работа по коду

**Solidity:**
1. `P256RecoveryValidator.isValidSignatureWithSender` → `ERC1271_INVALID`
   (≈5 строк) + тест.
2. Тест: после recovery старый owner-валидатор удалён, его 1271 не
   проходит.
3. `TimelockedP256RecoveryValidator` (~100–130 строк): `initiate` / `cancel` /
   `validateUserOp` с `validAfter` / 1271 закрыт; тесты:
   - раньше срока — refused;
   - cancel владельцем;
   - чужой callData;
   - повтор после исполнения;
   - истечение окна `W`.
   
   Альтернатива — форк-тест ZeroDev `TimelockPolicy` с `P256Signer` (нужен
   `execute`-грант, см. §3.4).
4. (Опц.) `P256MultiKeyValidator` 1-of-N или k-of-n, если нужно несколько
   daily-устройств.

**CLI (`agent-signer`):**
- `owner add-recovery --recovery-key <spec>` — уже есть
  `add_recovery_calldata` [V `kernel.rs:48–67`]. Добавить проверку, что
  валидатор ещё не установлен, и печать реестровой записи.
- `owner recover --new-owner <spec>`:
  - шаг 1: recovery-op `changeRootValidator(recoveryVId)`; для таймлока —
    сначала `recover initiate`, потом `recover execute` после `D`;
  - шаг 2: batch `uninstallValidation(old)` + `changeRootValidator(fresh, key)`;
  - шаг 3: обновить конфиг (`owner`, `ownerPublicKey` — адрес аккаунта
    остаётся закреплён в `account`) и запустить health.
- `owner recover cancel` — root-op отмены.
- `health [--role owner|recovery|agent]` — подпись challenge + сверка с
  ключом **с цепи** + опц. симуляция через бандлер; код выхода для cron.
- `watch` — подписка на события аккаунта и валидаторов → stdout/webhook.
- `key backup-blob` для SE и CNG (копия wrapped blob) [I].
- Бэкенд `keyfile` (encrypted) уже упомянут в `agent.rs:68–73,159–162` [V].
  Добавить `--print-qr` для бумажной копии шифротекста.

**Документация:**
- раздел «Что делать, если…» (TPM очищен / Mac стёрт / устройство
  потеряно / флешка не читается / пароль забыт);
- реестр ключей;
- запрет co-located owner на fTPM для mainnet (в духе Hardening).

---

## 6. Источники

- **Код:**
  - `contracts/lib/kernel/src/Kernel.sol` (v3.3, коммит `cd697c7`):
    88–103, 135–155, 229–275, 392, 405–427;
  - `contracts/lib/kernel/src/core/ValidationManager.sol`: 146–158,
    223–245, 424–449, 542–575;
  - `contracts/lib/kernel/src/validator/WeightedECDSAValidator.sol`;
  - `contracts/src/P256Validator.sol`, `P256RecoveryValidator.sol`,
    `AgentPolicy.sol`, `P256Signer.sol`;
  - `contracts/test/AgentPermission.t.sol:798–900`;
  - `signer/crates/hw-signer/src/{tpm.rs, secure_enclave.rs, windows_tpm.rs}`,
    `swift/SecureEnclaveShim.swift`;
  - `signer/crates/agent-signer/src/{kernel.rs, agent.rs, main.rs}`;
  - `signer/agent.base-sepolia.json`;
  - `docs/KEY_POLICY.md`, `docs/OWNER_DEVICES.md`, `docs/ERC1271.md`.
- **TPM:**
  - https://android.googlesource.com/platform/external/tpm2/+/716a46a/Clear.c
  - https://www.mankier.com/1/tpm2_clear
  - https://man.archlinux.org/man/extra/tpm2-tools/tpm2_clearcontrol.1.en
  - https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm
  - https://www.intel.com/content/dam/support/us/en/documents/mini-pcs/NUC5i3MY-TPM-Firmware-Update.pdf
  - https://www.getac.com/uploads/2023/01/infineon_tpm_security_update_20230116.pdf
  - https://winraid.level1techs.com/t/bios-downgrade-without-tpm-key-reset/32584
- **AMD fTPM:**
  - https://www.wintips.org/?p=55403
  - https://forum.asrock.com/printer_friendly_posts.asp?TID=25098
- **Secure Boot 2026:**
  - https://support.microsoft.com/help/5062710
  - https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/
- **Apple:**
  - https://support.apple.com/en-is/guide/security/sece8608431d/web
  - https://developer.apple.com/forums/thread/708749
- **Устройства:**
  - https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html
  - https://docs.nitrokey.com/nitrokey3/reset.html
  - https://ledger.com/academy/topics/ledgersolutions/ledger-pin-code-what-you-need-to-know
  - https://openpgp.apps.ledger.com/app-openpgp.html
  - https://openpgp.apps.ledger.com/gpgcard-addon.html
  - https://trezor.io/guides/trezor-devices/pin-protection-on-trezor-devices
- **Флеш-память:** https://www.anandtech.com/show/9248/the-truth-abou
- **Модули:**
  - https://github.com/zerodevapp/kernel-7579-plugins (README, `src/policies/TimelockPolicy.sol`)
  - https://docs.zerodev.app/sdk/advanced/recovery
  - https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/DeadmanSwitch/DeadmanSwitch.sol
  - https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/ColdStorageHook/ColdStorageHook.sol
  - https://ackee.xyz/blog/rhinestone-core-modules-audit-summary/
