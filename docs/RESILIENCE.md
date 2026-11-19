# Resilience: key breakage and loss (agent-keys)

*Russian original: [RESILIENCE_ru.md](RESILIENCE_ru.md).*

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
>     --validator <P256Validator> --retire <lost owner's validator> --public-key <x>,<y> \
>     --not-a-phone --new-key '<the new key, as a config names it>'
>     # the new key signs a challenge first; a key on another machine: leave --new-key out and
>     # answer the challenge the command prints with `key prove` there; a phone's key: --to-phone <label>
> ```
>
> `agent-signer key check --keyfile …` proves the passphrase still opens the
> file (and `key check --handle …` that a TPM key still signs; a PCR-sealed
> one with `--pcrs`) without sending anything — run it periodically. Claims are marked [V]
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

Date: 2026-10-20. Repository code **was not changed**. Markers: **[V]** — verified
(URL or file:line), **[I]** — inference / from memory, not re-checked.

State of the code at the time of the study (work is ongoing in parallel):
`contracts/src/P256RecoveryValidator.sol` (= `P256Validator` at a different address),
`kernel.rs: add_recovery_calldata / change_root_calldata`,
`agent.rs: KeySpec::Recovery`, tests `AgentPermission.t.sol:798–900`
(`test_recovery_canOnlyTakeOverRoot`, `test_recovery_replacesALostOwner`) [V].

---

## 0. The essentials in one minute

1. **Losing the agent key is not a problem.** The owner rotates the permission
   (`permission rotate`); the account address, funds, Safe and mandate stay [V
   by code, §2.1].
2. **The owner key is the single point of failure.** Without it and without recovery
   the agent runs until `validUntil` (in the testnet config — **2026-11-19 00:00 UTC**,
   `signer/agent.base-sepolia.json`, [V]), and after that date the account and the Safe
   it solely owns are frozen forever (§2.3).
3. **On the testnet host both keys are in one fTPM** (Intel PTT: ACPI HID
   `INTC6001`, Lenovo, i7-13700H, [V locally `/sys/class/tpm/tpm0/device/hid`];
   "INTC6001 = PTT" — [I]). Owner `0x81010010` without authValue, agent
   `0x81010012`, sealed to PCR 0,2,4,7 [V config]. A single `TPM2_Clear`,
   a PTT reset during a BIOS update or a motherboard replacement will destroy
   **both** keys at once. Recovery is needed even on the testnet, if only to
   rehearse the procedure.
4. **Recoverability without export** is achieved not by copying the key but by
   **key redundancy on-chain**: several independent non-exportable
   keys (or one seed-backed key), each registered in Kernel with the
   `changeRootValidator` right. A backup is a second key, not a copy
   of the first.
5. **Two code findings (important for the current implementation):**
   - **ERC-1271 bypasses the selector grants.** `ValidationManager._verifySignature`
     for a non-root validator checks only "installed" and
     `nonce >= validNonceFrom`. `allowedSelectors` is not checked
     [V `contracts/lib/kernel/src/core/ValidationManager.sol:424–449`].
     `P256RecoveryValidator` inherits `isValidSignatureWithSender` from
     `P256Validator` [V `contracts/src/P256Validator.sol` `isValidSignatureWithSender`].
     Consequently, **the recovery key can already sign an ERC-2612
     permit / Permit2 / EIP-3009 on behalf of the account**, without any
     `changeRootValidator` and without a timelock. The same problem applies to the **old
     owner validator**, which stays installed after
     `changeRootValidator`: `changeRootValidator` does not remove it
     [V `Kernel.sol:135–155`], and the test `test_recovery_replacesALostOwner`
     checks only the userOp path. Fix: in `P256RecoveryValidator`
     override `isValidSignatureWithSender` → `ERC1271_INVALID` (like
     `AgentPolicy.checkSignaturePolicy` for the agent, [V `AgentPolicy.sol:210–218`]),
     and in the recovery procedure — `uninstallValidation(oldOwnerVId)`. Add
     tests for both cases.
   - **Recovery = root with no delay.** Theft of the USB drive together with the passphrase gives
     an instant takeover. A value-bearing deployment needs a timelock with cancellation
     by the owner (§3.4).

---

## 1. Failure modes by backend

### 1.1 TPM 2.0: semantics of hierarchies and seeds (the basis for everything else)

- TPM 2.0 has three persistent seeds: **EPS** (endorsement), **SPS** (storage /
  owner hierarchy), **PPS** (platform). Keys created under the SRK
  (`0x81000001`, a primary key derived from the SPS) are encrypted to the SRK. If
  the SPS changes, the same template yields a **different** SRK, and all child keys
  become unrecoverable.
- **Only `TPM2_Clear` changes the SPS** (plus manufacturing). `TPM2_Clear`
  does "Reset storage hierarchy seed from RNG" and flushes persistent and
  loaded objects of the storage and endorsement hierarchies [V reference implementation
  `Clear.c`: https://android.googlesource.com/platform/external/tpm2/+/716a46a/Clear.c;
  man `tpm2_clear`: https://www.mankier.com/1/tpm2_clear]. `TPM2_ChangeEPS`
  and `TPM2_ChangePPS` change the other seeds and do not touch our key, but
  `ChangeEPS` also flushes endorsement-hierarchy objects [I].
- **Our keys** are persistent objects `0x8101xxxx` in the owner hierarchy under the SRK
  [V `signer/crates/hw-signer/src/tpm.rs:4,51`, config]. Therefore:

| Event | What happens to our key | Comment |
|---|---|---|
| Reboot, OS/kernel update | alive | persistent handle |
| `TPM2_Clear` (tpm2_clear, "Clear TPM" in Windows Security / tpm.msc / UEFI, PPI request from the OS) | **destroyed** | new SPS, persistent objects removed [V] |
| SPS change — only via Clear | **destroyed** | "regenerating the SRK" with the same template without Clear yields the same SRK [I per the specification: primary keys are deterministic from the seed and the template] |
| Accidental `key evict` / `tpm2_evictcontrol` | **destroyed** | we do not store the blob, nothing to restore from [V: `KeyCmd::Evict` exists in the CLI, main.rs:229] |
| BIOS update on a machine with **fTPM** | vendor-dependent; **often destroyed** | §1.2 |
| Update of the **TPM's own firmware** (dTPM or fTPM) | often destroyed | Intel NUC: "TPM firmware update clears all data in the TPM" [V https://www.intel.com/content/dam/support/us/en/documents/mini-pcs/NUC5i3MY-TPM-Firmware-Update.pdf]; Infineon updates (ROCA) required a clear [V https://www.getac.com/uploads/2023/01/infineon_tpm_security_update_20230116.pdf, I details] |
| CPU replacement (AMD fTPM) | **destroyed** when answering "Y" | §1.2 |
| Motherboard replacement | fTPM — **destroyed**; a pin-header dTPM module moved to the new board — key alive [I], PCR-sealed keys go silent | |
| PCR change (BIOS, Secure Boot db/dbx, bootloader) | key alive, but **a PCR-sealed key does not sign** | §1.4 |
| Dictionary-attack lockout (wrong authValue N times) | alive; **temporary** lockout. It stops a key behind an authValue. A key created without one since #43 carries `noDA` and keeps signing [V, on a software TPM and on an Azure vTPM]; a key created before does not. Besides wrong authValues, a stop of the TPM without `TPM2_Shutdown` after a signature with a key under the lockout counts as one failure: a crash, or a hard power-off of a VM. A virtual TPM allows 3 and forgives one every 1000 s [V, on a software TPM and on an Azure vTPM]; Intel PTT allows 31 [I, the backend's test] | recovers on a timer or via lockoutAuth [I]; the thresholds and causes on a virtual TPM: [`SERVER_KEY_STORES.md`](SERVER_KEY_STORES.md) §8.2, §8.4 |

**Protection against an accidental/malicious Clear from the OS:**
`tpm2_clearcontrol -C l s` sets `disableClear`, and the lockout hierarchy
can no longer perform Clear. The platform hierarchy (BIOS) always can, and
only platform can unset `disableClear` [V
https://man.archlinux.org/man/extra/tpm2-tools/tpm2_clearcontrol.1.en].
So this does not protect against "Clear TPM" in UEFI or a PPI clear request
[I: PPI is executed by the firmware via the platform hierarchy]. It is worth
setting: it protects against a typo and against a script that runs `tpm2_clear`.

### 1.2 Firmware TPM (Intel PTT, AMD fTPM)

- **Where it lives:** an fTPM is an application inside Intel CSME / AMD PSP. Its NV
  sits in the motherboard's SPI flash and is encrypted with a key bound to the
  CPU/chipset [I]. Hence two weak points: reflashing the SPI and changing the CPU.
- **AMD fTPM.** After a CPU replacement **or a BIOS update** it prints
  "New CPU installed. fTPM/PSP NV corrupted or fTPM/PSP NV structure changed"
  with a choice of Y (reset fTPM) or N (keep) [V
  https://www.wintips.org/?p=55403, https://forum.asrock.com/printer_friendly_posts.asp?TID=25098].
  "Y" = Clear, keys lost. With an actual CPU change the old data cannot be
  decrypted [I]. Likelihood: **high** for desktop AMD on a CPU
  upgrade, **medium** on AGESA/BIOS updates.
- **Intel PTT.** User reports: "When you flash the BIOS on a system
  using a firmware TPM, you lose the keys" [V forum,
  https://winraid.level1techs.com/t/bios-downgrade-without-tpm-key-reset/32584].
  With major vendors (Lenovo, Dell, HP) a regular BIOS update usually
  preserves PTT, while an ME-region update or a downgrade does not [I].
  **This is our testnet host.** Likelihood: **medium** per year with regular
  updates (LVFS/fwupd or the vendor updater).
- **CMOS reset / battery.** By itself it does not wipe the fTPM NV (that is in SPI) [I],
  but it can disable PTT in the settings or reset the Secure Boot keys → PCR7
  → sealed keys go silent.
- **The "Clear TPM" / "Reset fTPM" item in UEFI** — Clear, keys lost [V MS
  doc below].
- **Laptop repair** (board replacement under warranty) = new fTPM =
  **guaranteed loss** [I, follows from the architecture].

### 1.3 Discrete TPM

- A separate chip (Infineon SLB 9670/9672, Nuvoton NPCT7xx, ST33). Failures
  of the chip itself are rare [I, no public statistics]. The main risks: death
  of the board the chip is soldered to; a TPM firmware update (Infineon required
  Clear); Clear from the OS or UEFI.
- Plus of a dTPM: BIOS/ME/PSP firmware updates do not touch it. A pin-header module
  (LPC/SPI header) survives a motherboard replacement [I].

### 1.4 PCR-sealed keys (by design)

- The agent key on the testnet is sealed to PCR 0,2,4,7 [V config].
  `TPM2_PolicyPCR` with an **exact** digest [V `tpm.rs:240–252`]. After any
  change to the measurements the key is **alive but does not sign**. Rolling back the measurements
  is usually impossible.
  - PCR0 — firmware code (BIOS update);
  - PCR2 — option ROM (GPU/NIC replacement, update of their firmware);
  - PCR4 — bootloader (shim/grub/systemd-boot updates, the kernel with UKI);
  - PCR7 — Secure Boot state (db/dbx/KEK; in 2026 a mass rotation of
    Microsoft certificates is under way: KEK CA 2011 expires 24.06.2026, UEFI CA
    2011 — 27.06.2026, they are being replaced with CA 2023 via db/KEK updates [V
    https://support.microsoft.com/help/5062710,
    https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/]).
    A db/KEK change changes PCR7 [I: PCR7 measures the Secure Boot variables].
- **Conclusion:** PCR sealing for the agent key is a yearly (or more frequent)
  guaranteed "breakage". That is fine, rotation is cheap, but the procedure
  must be routine: before a firmware update, create a new key after
  the reboot and rotate. Do **not** use PCR sealing for the owner key
  (rule 4 of KEY_POLICY already says it does not protect against compromise of
  the running system). An alternative that survives updates is
  `PolicyAuthorize` with signed policies [I]; for us it is overkill.
  After an update, `key check --handle … --pcrs 0,2,4,7` says at once
  whether the sealed key still signs.

### 1.5 Apple Secure Enclave (CryptoKit `dataRepresentation`)

How the backend works: the `dataRepresentation` blob lies **as a file** in
`~/Library/Application Support/tpm_sign/enclave/<label>` (or
`$TPM_SIGN_ENCLAVE_DIR`); flags `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
+ `.privateKeyUsage`, no biometrics
[V `hw-signer/src/secure_enclave.rs:1–19`, `swift/SecureEnclaveShim.swift:53–59`].

| Event | Result |
|---|---|
| The blob file was deleted (user deletion, `~/Library` cleanup, reinstall without migration) | **key lost** — "Deleting the blob file destroys the key for good" [V `secure_enclave.rs:15`] |
| macOS update | alive [I] |
| blob copied to another Mac / Migration Assistant | **useless**: another SE will not unwrap it [V `secure_enclave.rs:16`; DTS: https://developer.apple.com/forums/thread/708749] |
| Erase All Content and Settings / erase with reinstall | **lost**, even if the blob was kept: erase destroys keys in effaceable storage / anti-replay, "does NOT survive … device restore, device erase" [V-secondary: summary of Apple DTS forums, https://developer.apple.com/forums/thread/708749; mechanism — https://support.apple.com/en-is/guide/security/sece8608431d/web]. The exact binding of a CryptoKit blob to the erase "epoch" — [I] |
| Logic board replacement (SE in SoC/T2) | **lost** (new UID) [V: UID "unique to each device", Apple Platform Security] |
| Apple ID change / signing out of iCloud | no effect [I: the blob is not in iCloud Keychain, ThisDeviceOnly flag] |
| User password change | most likely alive [I]; **check** |
| Owner key with `.biometryCurrentSet` + a fingerprint added/removed | **key invalidated** [I, documented behavior of the flag]. For the owner key use `.userPresence` or `.biometryAny` |

**Practice:** the blob **can and should be backed up** (Time Machine, a second copy
of the file). This does not violate "no export": the blob is useless outside this SE. The backup
protects against file deletion, but not against erasing the Mac or replacing the board.

### 1.6 Windows CNG Platform Crypto Provider

- Our key is a **per-user** persisted key (`NCryptCreatePersistedKey`,
  flags 0, not `NCRYPT_MACHINE_KEY_FLAG`) [V `hw-signer/src/windows_tpm.rs:40–60`].
  PCP stores the wrapped TPM blob **as a file in the user profile**
  (`%LOCALAPPDATA%\Microsoft\Crypto\PCPKSP\…`) [I, path not officially
  confirmed].
- Profile deletion, Windows reinstall, "Reset this PC → Remove
  everything" → file deleted → **key lost** [I].
- Clear TPM (Windows Security → Device security → Security processor
  troubleshooting → Clear TPM, tpm.msc, `Clear-Tpm`, UEFI) → **all TPM keys
  lost**; after that "Windows will automatically reinitialize it" [V
  https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm].
  Microsoft itself recommends Clear before a clean OS install: exactly the
  routine an admin performs without thinking about our key.
- Windows does not support switching between two TPMs in UEFI (dTPM ↔ fTPM);
  MS recommends Clear and a reinstall [V same source].
- **Practice:** backing up the PCPKEY file (like the SE blob) is safe and protects against
  losing the profile, but not against Clear [I].

### 1.7 USB secure elements and hardware wallets

| Device | Wrong PIN | Firmware | Physical | Recoverability |
|---|---|---|---|---|
| **YubiKey 5 PIV** | PIN 3 attempts → PUK 3 attempts → only PIV `reset`, **all slots wiped** [V https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html] | not updatable (an update will not wipe the key, but will not fix a vulnerability either) [V OWNER_DEVICES] | loss, broken USB connector, washing machine | none (if the key was generated inside) |
| **Nitrokey 3** | PIV/OpenPGP PIN 3 → PUK/Admin PIN → factory reset [V https://docs.nitrokey.com/nitrokey3/reset.html] | updatable; keys usually preserved across updates [I], historical incidents — check | as above | none |
| **Ledger Nano S Plus** | **3 wrong PINs → device reset**, restore from 24 words [V https://ledger.com/academy/topics/ledgersolutions/ledger-pin-code-what-you-need-to-know] | Ethereum app: key from the seed, survives everything. **OpenPGP app: keys in the app's NVM are wiped on any app or OS update**, unless **Seed Mode** is enabled [V https://openpgp.apps.ledger.com/app-openpgp.html, https://openpgp.apps.ledger.com/gpgcard-addon.html] | loss | seed (with Seed Mode — for P-256 too) |
| **Trezor Safe 3/5/7** | 16 wrong PINs → wipe, delays grow exponentially [V https://trezor.io/guides/trezor-devices/pin-protection-on-trezor-devices] | `SignIdentity` nist256p1 is deterministic from the seed [V OWNER_DEVICES §1] — survives everything | loss | **seed (12–24 words)** |
| **TROPIC01 devkit** | no PIN on the chip; if built on `MAC_And_Destroy`, attempts are limited by the chip [V OWNER_DEVICES §3.1] | chip FW updates — R-mem preservation [I] | loss, ESD | none. Plus a **unique risk**: SH1PRIV lost while SH0 is invalidated → the session can never be opened, the key is dead although the chip is intact. Invalidating all 4 pairing slots = brick [V datasheet §7.5.3 via OWNER_DEVICES]. A mistake in I-Config is irreversible |
| **FIDO2 key** | 8 wrong PINs → block; reset wipes credentials [I] | — | loss | none |

### 1.8 USB drive with an encrypted recovery key

- **Unpowered data retention.** JEDEC JESD218 requires 1 year at 30 °C unpowered
  from *client SSDs*; with heat, retention drops sharply [V
  https://www.anandtech.com/show/9248/the-truth-abou]. For cheap
  USB drives (TLC/QLC, unknown controller) there is no specification, reality
  may be worse [I]. Controller failure is sudden and total [I].
- **A forgotten passphrase** is in practice the most likely failure of a cold key
  that is used once every few years [I]. A KDF with N ≥ 2^18 (rule 5)
  makes brute force infeasible for the owner as well.
- **Mitigation (without weakening no-export, since this key is exportable
  anyway):**
  - two USB drives from different manufacturers in two places;
  - **a third copy on paper: a QR of the ciphertext** (keystore JSON ~ 500 bytes
    fits in one QR). Paper does not rot, and the ciphertext is useless without the passphrase
    [I];
  - yearly: plug it in, check decryption and signing (§4), rewrite the
    file (refresh the cell charge) [I];
  - passphrase: diceware 6–7 words, written on paper and stored **separately** from
    the media (or with a trusted person). Otherwise — "the key is there, the passphrase is not".

---

## 2. Consequences for each key role

### 2.1 Agent key lost

- The owner runs `permission rotate` — a single root operation that
  replaces the permission with a new key and/or mandate [V `main.rs:130–145`].
- **Nothing is lost:**
  - the account address (the Kernel proxy is already deployed, `account` is pinned in the
    config [V `agent.rs:140–143`]);
  - balance and tokens;
  - Safe: the owner is the account, not the key [V `docs/ERC1271.md`];
  - relationship with the paymaster: sponsorship is bound to the account [I based on
    `paymaster sponsor`].
- **Nuances:**
  - The `spent` budget starts over in the new mandate — this is the owner's
    decision.
  - A lost key does not need to be "revoked": it is dead. If the key is more likely
    "compromised than lost", rotate covers that too.
  - The owner must be available. The chain "agent key died → owner needed
    urgently" is the main practical reason to keep the owner alive and
    tested.
  - If the agent and the owner are in one fTPM (testnet), they die **together**, and
    §2.1 does not help.

### 2.2 Owner key lost, agent still running

- The agent keeps working within the mandate: allow-list, limits, budget,
  `validUntil` [V `AgentPolicy.sol:183–207`].
- **Unavailable** is everything that requires root:
  - rotation and revocation of the agent;
  - mandate change and extension of `validUntil`;
  - `upgradeTo`;
  - installing and uninstalling modules;
  - any transfers outside the allow-list;
  - `invalidateNonce`;
  - changing the Safe owner [V `Kernel.sol:88–103,135,157,330–440` — all under
    `onlyEntryPointOrSelfOrRoot`].
- Once `block.timestamp > validUntil`, the EntryPoint rejects any
  agent operations, because the policy returns `validUntil`
  [V `AgentPolicy.sol:207`].
- **A limited "rescue corridor".** If the allow-list contains in advance an
  entry `(coldAddress, 0x00000000)`, the agent can withdraw ETH (and only towards
  `coldAddress`) within `maxValuePerOp` and `budget`
  until `validUntil` [I based on the logic of `_judge`]. This is safe: an attacker on
  the agent host can only send money to the owner. But the budget limit
  caps the amount that can be rescued, and ERC-20 cannot be withdrawn this way: the recipient of
  `transfer(to,…)` is not pinned in the allow-list [I: `AgentPolicy` checks
  `(target, selector)` and token limits, not the `to` argument].

### 2.3 Owner **and** recovery lost: the "dead account"

- **What happens:**
  - Until `validUntil` only the agent works, within the mandate.
  - After `validUntil` nobody will ever be able to sign an operation:
    - the root path requires the owner key;
    - the permission has expired;
    - there is no recovery.
  - Kernel is not upgradeable without root.
  - The account's EntryPoint deposit cannot be withdrawn (`withdrawTo` can only be called by the
    account) [I].
- **What gets frozen:**
  - ETH and tokens on the Kernel account;
  - everything in a Safe where Kernel is the sole owner with threshold 1;
  - NFTs;
  - positions in protocols that require owner action (LP,
    staking, loans — a loan may get **liquidated**, because
    nobody can top up the collateral);
  - roles and rights of the account in other contracts (the paymaster owner, if it is
    this account).
- **Scale:** 100 % of the value of the account and the Safes under it, minus what
  the agent manages to withdraw through the "corridor" from §2.2.
- **Likelihood:** composed of independent failures. Example on the testnet
  (owner and agent in one PTT, no recovery): the likelihood of a "dead
  account" per year ≈ the likelihood of a PTT Clear/reset per year. Based on experience
  with firmware updates this is single-digit to tens of percent [I, order of magnitude].
  With two independent media (owner on device A, recovery on
  USB drives B1+B2 + QR) a simultaneous failure of several independent
  things is required, and the likelihood drops by orders of magnitude — provided there are regular checks,
  otherwise failures "accumulate" unnoticed.

---

## 3. Recovery architectures without key export

### 3.0 What Kernel v3.3 provides (verified against the code in `contracts/lib/kernel`, tag v3.3)

- **There is exactly one root validator** (`vs.rootValidator`). The other
  validators and permissions work **only for granted selectors**
  (`grantAccess`) [V `Kernel.sol:229–275,392`].
- `changeRootValidator(vId, hook, data, hookData)`: if `vId` is already
  installed, the data is ignored (`onInstall` is not called) [V
  `Kernel.sol:135–155`]. **Therefore a new owner key cannot be put into the same
  `P256Validator` instance**: it already holds the old key, and
  `onInstall` cannot be called twice (`AlreadyInitialized`, [V
  `P256Validator.sol` onInstall]). A **different contract instance** is needed
  (as in the test `test_recovery_replacesALostOwner`) or
  `uninstallValidation` + a fresh install.
- **ERC-1271** for a non-root validator does not check selectors
  [V `ValidationManager.sol:424–449`] — see the finding in §0.
- `invalidateNonce(n)` revokes **all** non-root validators and permissions with
  `nonce < n` at once [V `ValidationManager.sol:146–158`, `Kernel.sol:242–244`]:
  this is a "kill switch" that hits both the agent and recovery.
- **The agent cannot address its own account.** `AgentPolicy` refuses the
  account itself, its EntryPoint and the policy (outside x402) as allow-list
  targets at install and again at validation [V `AgentPolicy.sol`
  `_targetAllowed`, since 2026-11-10], and the CLI refuses the project's
  validators and signer as well: no mandate, however written, lets the agent
  reach `grantAccess`, `changeRootValidator`, `withdrawTo` or the modules'
  `onInstall`.
- Ready-made modules next to Kernel:
  - `WeightedECDSAValidator` (in the Kernel v3.3 repo itself): guardian weights and
    threshold, **`delay`** (proposal → approve → execution no earlier than
    `validAfter`), `veto` can only be called by the account itself (`msg.sender` =
    kernel, i.e. a root operation) [V
    `contracts/lib/kernel/src/validator/WeightedECDSAValidator.sol:17–23,141–187,189–258`].
    Downsides: secp256k1 guardians only; **the 1271 path checks the signature threshold
    and ignores the delay** [V same file :280–303]. Deployment address on Base — [I].
  - ZeroDev `TimelockPolicy` (kernel-7579-plugins, last change
    2026-04-07): a **policy** for a permission. A no-op userOp with the
    proposal data in the signature creates a proposal. Execution is possible after
    `delay` and before `delay + expirationPeriod` — these are `validAfter`/`validUntil`,
    enforced by the EntryPoint. `cancelProposal` is called by the account or by
    a separate `guardian` address. ERC-1271 is **rejected** (revert)
    [V https://github.com/zerodevapp/kernel-7579-plugins/blob/HEAD/src/policies/TimelockPolicy.sol,
    lines 17–41, 143–264, 345–365]. An audit and a canonical address are not
    given in the README [V README]; "not audited and not deployed" — [I].
  - ZeroDev recovery executor `0xe884C2868CC82c16177eC73a93f7D9E6F3A5DC6E`
    (`doRecovery(validator, data)`) — **only for accounts with
    `ECDSAValidator`** [V https://docs.zerodev.app/sdk/advanced/recovery];
    no timelock. Not suitable for us.
  - Rhinestone core-modules (ERC-7579, Ackee audit 2024 [V
    https://ackee.xyz/blog/rhinestone-core-modules-audit-summary/]):
    - `SocialRecovery`;
    - `DeadmanSwitch`: validator + hook. The hook updates `lastAccess` on every
      operation; the nominee (ECDSA or a 1271 contract via
      `isValidSignatureNow`) gets access after
      `lastAccess + timeout`; ERC-1271 — revert [V
      https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/DeadmanSwitch/DeadmanSwitch.sol];
    - `ColdStorageHook` (execution timelock).

    Compatibility with Kernel v3.3 is questionable: Kernel does not install a hook
    on its own, only paired with a validator/executor/selector [V comment
    `Kernel.sol:378–383`] — [I], to be checked in a fork test.

### 3.1 N independent owner devices (redundancy)

- **Scheme:** owner A is root; devices B, C each have a separate instance of the
  P-256 validator with `grantAccess(changeRootValidator)`. Device B
  becomes root when A is lost. This is exactly the
  `P256RecoveryValidator` mechanism, only the key is not "cold" but in another SE.
  Alternative — our own `P256MultiKeyValidator` (1-of-N: any of the
  registered P-256 keys = root), ~60–80 lines of Solidity [I].
- **Pros:**
  - no key is exported;
  - failures are independent (different manufacturers, places);
  - each device is testable with a signature (§4);
  - everything is already on-chain.
- **Cons:**
  - buying and tracking a second device;
  - each additional device is one more attack surface
    (any one = root);
  - ERC-1271 — see §0.
- **Cost:** Nitrokey 3 €55 / YubiKey $58 / a second Mac or PC with a TPM
  $0 [V OWNER_DEVICES §1]; Solidity — zero (a new instance of
  `P256RecoveryValidator` per device) or ~80 lines.

### 3.2 Cold recovery owner

| Option | Medium | Validator | Pros | Cons |
|---|---|---|---|---|
| Encrypted P-256 file on a USB drive (current plan) | 2 USB drives + QR of the ciphertext | `P256RecoveryValidator` | cheap; copyable; our curve | key in host memory at signing time [V KEY_POLICY rule 5]; passphrase gets forgotten; no presence |
| Trezor `SignIdentity` nist256p1 | device + seed of 12–24 words | `P256RecoveryValidator` as is | key in hardware, seed restores onto **any** new Trezor; screen and PIN | $59; needs the `trezor-client` client |
| Ledger OpenPGP app in **Seed Mode** | device + seed | `P256RecoveryValidator` | the user already has a Nano S Plus | without Seed Mode the key is wiped on an app/OS update [V]; PIN 3 attempts → wipe |
| Ledger/Trezor Ethereum app | device + seed | ZeroDev `ECDSAValidator` `0x845A…cE57` as the recovery validator + `grantAccess(changeRootValidator)` | no code on the device; seed | secp256k1; a second branch in the CLI (alloy-signer-ledger/trezor) |
| Paper P-256 key, imported into an SE when needed | paper in a safe | `P256RecoveryValidator` | everlasting medium | a plaintext key on paper contradicts rule 5 (which allows only an *encrypted* medium) — only as a QR of the **ciphertext** |

### 3.3 M-of-N guardians / social recovery

- **Options:**
  - (a) our own `P256ThresholdValidator` k-of-n, ~100–150 lines + audit [I];
  - (b) ZeroDev `WeightedECDSAValidator` (k1 guardians, has delay+veto)
    [V code];
  - (c) a Safe as guardian: a recovery validator that checks 1271 on the Safe
    (k-of-n Safe owners) — Kernel has no such validator of its own, ~40
    lines on top of `SignatureCheckerLib` [I];
  - (d) Rhinestone `SocialRecovery` [V exists; compatibility — I].
- **Pros:** no single point of failure and no single point of compromise.
- **Cons:**
  - coordinating people;
  - guardians lose keys too — their freshness has to be checked;
  - collusion of k guardians = takeover (a timelock is needed);
  - more complex in code and in audit.
- For a single developer-owner this is overkill at the start. It makes sense once
  the account holds real third-party funds.

### 3.4 Timelock on recovery (recommended for a value-bearing deployment)

**Goal:** recovery can replace root only after a delay `D`. If
the current owner is alive (their key was not stolen together with recovery), they see the event
and cancel it.

**Option A — ZeroDev `TimelockPolicy` + our `P256Signer` as a permission.**
- Permission = `{signer: P256Signer(recoveryKey), policies: [TimelockPolicy(delay, expiry, guardian)]}`
  + `grantAccess(changeRootValidator)`.
- **Kernel v3.3 pitfall:** a no-op proposal needs
  `callData = execute(single, address(0), 0, "")` (empty callData fails
  on `bytes4(callData[0:4])`, the `executeUserOp` forms require a hook). So
  the permission must also be granted the `execute` selector [V
  `Kernel.sol:259–273`; `TimelockPolicy._isNoOpCalldata`]. This expands the
  recovery's rights to "any `execute` after the delay". Equivalent to root
  after the delay, i.e. no worse than `changeRootValidator`, but there is no
  AgentPolicy-like restriction [I].
- **Cancellation:**
  - the owner's root operation `TimelockPolicy.cancelProposal(...)`
    (msg.sender = account);
  - or from the `guardian` address (an EOA, e.g. a Ledger address).
- **Pros:** the code exists, ERC-1271 is closed.
- **Cons:**
  - audit and deployment not confirmed;
  - a fork test is needed.

**Option B — our own `TimelockedP256RecoveryValidator`, ~100–130 lines [I].**
Sketch:
- `initiate(account, newRootCallHash, sig)`: callable by anyone (a gas wallet).
  Checks the recovery key's P-256 signature over
  `(chainid, this, account, newRootCallHash, nonce)`, records
  `pending[account] = {hash, readyAt = now + D}`, emits
  `RecoveryInitiated`.
- `validateUserOp`:
  - `bytes4(callData) == changeRootValidator`;
  - `keccak256(callData) == pending.hash`;
  - the recovery key's signature over `userOpHash`;
  - return `packValidationData(validAfter = readyAt, validUntil = readyAt + W)`.
  
  The EntryPoint itself will not let the operation through early.
- `cancel()`: `msg.sender == account`, i.e. a root operation of the current
  owner. Do **not** give it to the agent in the allow-list (otherwise an attacker on the agent
  host blocks recovery).
- `isValidSignatureWithSender` → `ERC1271_INVALID`.
- `onInstall(x, y, D, W)` with a lower bound on `D` (e.g. ≥ 1 day on
  mainnet).

Pros: small, our style, native P-256, no extra selectors.
Cons: our own code → our own audit.

**Choosing `D`:**
- `D` must be shorter than the interval within which the owner is guaranteed to
  notice the event: an event monitor on the agent host needs no keys and sends
  an alert.
- `D` must be longer than the reaction time.
- Recommendation: testnet 10 minutes, mainnet 3–7 days [I].

**The cost of the delay:** with an honest loss of the owner key, recovery takes
`D` days, and the agent's mandate must outlive those days (`validUntil` with a margin,
§4).

**Dead-man option** (`DeadmanSwitch`-like, as in Rhinestone): recovery is
active only if the owner has been silent for `T` days. The hook must be attached **only to
the root validator**, otherwise agent activity resets the timer. Semantically
this is the most precise tool against "the owner disappeared", but in Kernel v3.3 a hook
on root is set only when root is installed/changed, and root operations with a hook go
through `executeUserOp` [V `Kernel.sol:150–153,259–273`]. More complex than a
timelock, postpone [I].

### 3.5 Seed-derivable vs non-exportable SE: the trade-off

| | Non-exportable SE (TPM, SE, YubiKey, TROPIC01) | Seed device (Trezor, Ledger Seed Mode) |
|---|---|---|
| Remote key theft | impossible | impossible (key in the device) |
| Physical key theft | needs the chip itself + PIN/auth | a **slip of paper with the seed** is enough |
| Device breakage or loss | key lost forever | new device + seed = the same key |
| "Generated in the chip" attestation | possible | no (the key is derivable) |
| What it protects | confidentiality | availability |

A mixed scheme — **daily key non-exportable, recovery
seed-backed** — is reasonable, because the roles differ:
- the daily key is used often, on connected machines: the main thing is
  that it cannot be carried off (host compromise = signatures only while
  the attacker is present);
- recovery is used once in years and stored offline: the main thing is that it
  **outlives** time. The risk of seed theft is covered by physical storage
  (a safe, separate places; SLIP-39 Shamir on Trezor [I]) and by an **on-chain
  timelock**: a stolen seed still has to survive `D` days without being cancelled by the owner.

The timelock turns "recovery theft" from an instant catastrophe into a
detectable event. That is why it is what makes seed-backed recovery
acceptable next to a no-export primary key.

---

## 4. Operational practices

1. **Health check without sending a transaction** (`agent-signer health`) for
   owner, recovery and agent:
   - read the registered key from the chain:
     `P256Validator.publicKeys(account)`,
     `P256RecoveryValidator.publicKeys(account)`, the agent key from
     `P256Signer`;
   - ask the device to sign a random challenge
     (`keccak("tpm_sign health" ‖ chainId ‖ account ‖ role ‖ timestamp)`);
   - verify off-chain with the `p256` crate against the key **from the chain**, not from the
     config: this also catches "the key is alive, but it is the wrong one";
   - additionally: an `eth_call` simulation of a real root operation via the
     bundler (`eth_estimateUserOperationGas` runs validation) — without
     sending [I].
   
   Owner with presence (Touch ID / button) — check monthly by hand;
   agent — automatically daily. A PCR-sealed agent will fail here after a firmware
   update — that is the signal to rotate.
2. **Mandate renewal as a heartbeat.**
   - `validUntil` = 2× the renewal interval (e.g. renewal every 30 days,
     `validUntil` at 60). Each renewal is a root signature, i.e.
     proof that the owner is alive.
   - A missed renewal → an alert long before the freeze.
   - With a timelock on recovery: `validUntil` − now > `D` + time to
     buy a new device, otherwise the agent stops during an honest
     recovery.
3. **Event monitoring** (on the agent host, without keys): `RootValidatorUpdated`,
   `ModuleInstalled/Uninstalled`, `RecoveryInitiated` / `ProposalCreated`,
   `NonceInvalidated`, `P256KeyRegistered` → alert to the owner (email or
   Telegram).
4. **Key registry** (`docs/KEYS.md` or a private file outside the repo):
   - role;
   - public key;
   - validator and address;
   - device and serial number;
   - storage location;
   - who knows the PIN or passphrase;
   - date of the last check.

   For a TPM add: machine, fTPM or dTPM, handle, PCR sealing yes/no, date
   of the last BIOS update.
5. **Before a BIOS/firmware update on a host with an fTPM:**
   - run the health check;
   - make sure the owner is **not** on this TPM (or recovery is alive);
   - after the update: check the agent and rotate if needed.

   On the testnet host, until recovery exists — **do not update the BIOS**.
6. **`tpm2_clearcontrol -C l s`** on hosts with keys (§1.1), plus
   lockoutAuth. Does not protect against Clear from UEFI, but protects against a script.
7. **Back up wrapped blobs where they exist:** SE `dataRepresentation`,
   Windows PCPKEY. On Linux one can additionally store the agent key's
   `TPM2B_PUBLIC/PRIVATE` so that `evict` is reversible [I].
   All of this is safe: a blob is useless outside its chip.
8. **Recovery USB drive:**
   - two copies on different media and in different places + QR of the ciphertext;
   - once a year: decrypt on an offline machine, sign a health challenge,
     rewrite the file.
   - store the passphrase separately.
9. **Recovery rehearsal on the testnet** — once a year and after every code
   change: the full path "owner lost → recovery → new owner → agent
   works → old owner validator removed → 1271 with the old and the recovery
   key does not pass". Part of it is already covered by the test
   `test_recovery_replacesALostOwner` [V].
10. **Safe:** if the Safe holds significant funds and its sole owner is
    Kernel, the Safe inherits all of the account's risks. Option: a second Safe owner
    (the same recovery key via a separate address) or a module with a delay
    (Zodiac Delay) [I]. This complicates the `AgentPolicy` checks of the Safe — to be decided
    separately.

---

## 5. Recommendation for the project

### 5a. Testnet (now)

The minimum that actually removes "one Clear = the end":

1. **`P256RecoveryValidator` + `grantAccess(changeRootValidator)`** — already in
   progress [V]. The key is an encrypted file (scrypt N ≥ 2^18 + AEAD) on **two**
   USB drives + QR of the ciphertext. Decryption only on a machine that is not the agent
   host (KEY_POLICY rule 5).
2. **Close 1271 on recovery right away:** override
   `isValidSignatureWithSender` → `ERC1271_INVALID`, test: a signature by the
   recovery key via `Kernel.isValidSignature` is rejected.
3. **Recovery procedure = three steps, all in the CLI:**
   1. recovery-op `changeRootValidator(recoveryVId)`;
   2. root-op (now recovery) batch:
      `uninstallValidation(oldOwnerVId)` + `changeRootValidator(freshValidatorVId, key)`.
      A fresh `P256Validator` instance is needed because of `AlreadyInitialized`;
      instead, one can `uninstallValidation(P256Validator)` and then
      reinstall the same address;
   3. verification: health check of the new owner, the agent works, the old owner and
      recovery pass neither userOp nor 1271.
   
   Step 2 can be merged with step 1 only if recovery gets more
   selectors. Don't: two steps are easier to audit.
4. **A Foundry test** for residual 1271 of the old owner validator after
   recovery: it must be removed.
5. **`validUntil`** of the testnet mandate (19.11.2026) — extend it with
   `permission rotate` and treat it as a heartbeat.
6. **Do not update the BIOS** of this Lenovo until recovery is installed and
   rehearsed.

A timelock on the testnet is not required, but it is convenient to build option B right away with
`D` = 10 min: to rehearse the UX of waiting and cancelling.

### 5b. Value-bearing deployment (Base mainnet)

| Role | Medium | Validator | Why |
|---|---|---|---|
| Agent | TPM/SE of the agent host (PCR sealing optional) | `P256Signer` + `AgentPolicy` | as now; loss is cheap |
| Owner (daily) | a **separate** non-exportable device with presence: Nitrokey 3 / YubiKey PIV (touch=always) / Mac SE with `.userPresence` | `P256Validator` (root) | KEY_POLICY rule 3 (i)/(ii) |
| Owner #2 (opt.) | a second device of a different type | `P256RecoveryValidator` #2, `changeRootValidator`, **without** a timelock or with a short one | fast recovery if the daily one breaks |
| Recovery (cold) | **Trezor `SignIdentity` nist256p1** (seed in a safe, SLIP-39 optional) **or** encrypted file ×2 + QR | **`TimelockedP256RecoveryValidator`** (`D` = 3–7 days), 1271 closed | survives any breakage; theft is neutralized by the timelock |
| Monitor | agent host, no keys | — | alert on `RecoveryInitiated` / root change |

Plus:
- mandate heartbeat (renewal every 30 days, `validUntil` = 60 days > `D` + margin);
- monthly owner health check;
- yearly recovery health check;
- yearly rehearsal on Base Sepolia;
- key registry;
- `disableClear` on TPM hosts.

### 5c. Code work

**Solidity:**
1. `P256RecoveryValidator.isValidSignatureWithSender` → `ERC1271_INVALID`
   (≈5 lines) + test.
2. Test: after recovery the old owner validator is removed, its 1271 does not
   pass.
3. `TimelockedP256RecoveryValidator` (~100–130 lines): `initiate` / `cancel` /
   `validateUserOp` with `validAfter` / 1271 closed; tests:
   - before the deadline — refused;
   - cancel by the owner;
   - foreign callData;
   - replay after execution;
   - expiry of the `W` window.
   
   Alternative — a fork test of ZeroDev `TimelockPolicy` with `P256Signer` (needs
   the `execute` grant, see §3.4).
4. (Opt.) `P256MultiKeyValidator` 1-of-N or k-of-n, if several
   daily devices are needed.

**CLI (`agent-signer`):**
- `owner add-recovery --recovery-key <spec>` — there is already
  `add_recovery_calldata` [V `kernel.rs:48–67`]. Add a check that the
  validator is not yet installed, and printing of the registry entry.
- `owner recover --new-owner <spec>`:
  - step 1: recovery-op `changeRootValidator(recoveryVId)`; with a timelock —
    first `recover initiate`, then `recover execute` after `D`;
  - step 2: batch `uninstallValidation(old)` + `changeRootValidator(fresh, key)`;
  - step 3: update the config (`owner`, `ownerPublicKey` — the account address
    stays pinned in `account`) and run health.
- `owner recover cancel` — the cancellation root-op.
- `health [--role owner|recovery|agent]` — challenge signature + comparison with
  the key **from the chain** + opt. simulation via the bundler; exit code for cron.
- `watch` — subscription to account and validator events → stdout/webhook.
- `key backup-blob` for SE and CNG (a copy of the wrapped blob) [I].
- The `keyfile` (encrypted) backend is already mentioned in `agent.rs:68–73,159–162` [V].
  Add `--print-qr` for a paper copy of the ciphertext.

**Documentation:**
- a "What to do if…" section (TPM cleared / Mac erased / device
  lost / USB drive unreadable / passphrase forgotten);
- key registry;
- a ban on a co-located owner on an fTPM for mainnet (in the spirit of Hardening).

---

## 6. Sources

- **Code:**
  - `contracts/lib/kernel/src/Kernel.sol` (v3.3, commit `cd697c7`):
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
- **Devices:**
  - https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html
  - https://docs.nitrokey.com/nitrokey3/reset.html
  - https://ledger.com/academy/topics/ledgersolutions/ledger-pin-code-what-you-need-to-know
  - https://openpgp.apps.ledger.com/app-openpgp.html
  - https://openpgp.apps.ledger.com/gpgcard-addon.html
  - https://trezor.io/guides/trezor-devices/pin-protection-on-trezor-devices
- **Flash memory:** https://www.anandtech.com/show/9248/the-truth-abou
- **Modules:**
  - https://github.com/zerodevapp/kernel-7579-plugins (README, `src/policies/TimelockPolicy.sol`)
  - https://docs.zerodev.app/sdk/advanced/recovery
  - https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/DeadmanSwitch/DeadmanSwitch.sol
  - https://raw.githubusercontent.com/rhinestonewtf/core-modules/main/src/ColdStorageHook/ColdStorageHook.sol
  - https://ackee.xyz/blog/rhinestone-core-modules-audit-summary/
