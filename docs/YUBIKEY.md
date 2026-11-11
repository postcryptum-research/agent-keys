# YubiKey 5 PIV backend

A YubiKey as the **owner key**: a P-256 key generated inside the device's PIV
applet, used only with the PIN and a touch, never exportable. It is the cheap,
pocketable answer to `KEY_POLICY.md`'s "a separate device with physical
presence" for the owner role (`OWNER_DEVICES.md` §… YubiKey 5 — PIV). First
run on 2026-11-02 with a YubiKey 5 NFC, firmware 5.8.0.

## Hardware and host

- **YubiKey 5 series** (5 NFC, 5C, 5 Nano…), firmware 5.3 or newer for slot
  metadata; the attestation PKI below is the one firmware 5.7+ ships with.
- **Host:** PC/SC. Linux: `pcscd` and, to build, `libpcsclite-dev`; the
  tooling is `yubikey-manager` (`ykman`) and, optionally, `yubico-piv-tool`.
  macOS and Windows have PC/SC built in.
- **Remote sessions on Linux:** `pcscd` lets only *local, active* sessions in
  through polkit. From SSH it answers `Access denied` and logs "is NOT
  authorized for action: access_pcsc". A rule in `/etc/polkit-1/rules.d/`
  granting `org.debian.pcsc-lite.access_pcsc` and `access_card` to the
  operator's user fixes it; nothing else needs to change.
- **Crate:** `yubikey` 0.9.0-rc.0 (iqlusion, BSD-2-Clause), pure Rust over
  `pcsc`; feature `yubikey-piv` of `hw-signer`, `yubikey` of `agent-signer`.

## How the backend works

- `YubiKeyPivSigner::open(serial, slot)` reads the slot's **metadata**:
  algorithm (anything but P-256 is refused), public key, PIN and touch
  policies. Without a serial it takes the one YubiKey plugged in and binds
  to its serial from then on; two YubiKeys without a serial is an error.
- `sign_digest` opens the device, verifies the PIN when the slot's policy
  needs one, announces the touch when the policy waits for one, sends the
  32-byte digest through PIV `GENERAL AUTHENTICATE` (raw ECDSA, no hashing
  on the device: the `userOpHash` is signed as is) and returns `(r, s)`
  normalized to low-s. The device answers DER; the backend parses it.
- The backend never prompts and never holds the management key. The CLI
  hands it a PIN *provider* (`rpassword`, zeroized), called at the first
  signature that needs the PIN and kept for the rest of the operation; a
  rejected PIN is forgotten again. Through a bundler the CLI estimates gas
  with a placeholder and signs **once**, so an owner operation is one PIN
  and one touch; only a bundler that refuses the fee after the fact costs a
  second touch, and the CLI says so (design §8.3, #15). **An agent key is refused** unless the slot's policies are PIN
  never and touch never, because an unattended agent cannot answer either.
- **Before any root operation the CLI checks the key against the chain:**
  it reads the account's root validator and that validator's
  `publicKeys(account)`, and refuses with "not the account's root key" when
  the key in the slot is a different one. A retired owner still named in a
  config, another YubiKey, or the wrong slot therefore costs no PIN try and
  no touch. The same check serves every owner backend, the phone included,
  and the recovery path gets its twin (`check_recovery_key`, before the
  passphrase). It runs only when the root is one of this repository's P-256
  validators from the deployments file; another root validator (a WebAuthn
  or ECDSA one) is reported and skipped, never refused.
- `attestation()` returns the slot's attestation certificate (see below).
- Errors: wrong PIN → `SignerError::Key` with the tries left; PIN blocked →
  `Key` pointing at the PUK; no device, two devices, PC/SC → `Backend`;
  the device refusing to sign → `Sign`.

## Setting a YubiKey up (once, with ykman)

```sh
ykman info                                  # model, firmware, applications
ykman piv info                              # expect "Using default PIN/PUK/Management key" on a new key
ykman piv access change-pin                 # 6–8 characters; alphanumeric on firmware 5.7+
ykman piv access change-puk                 # 8 characters; unblocks the PIN after 3 wrong tries
ykman piv access change-management-key --protect --touch
                                            # random key, stored on the device behind the PIN
ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 9c owner-9c.pub.pem
```

Choices made for the owner key, and why:

- **Slot `9c`** (Digital Signature): PIV defines it as "PIN before every
  signature", which is what a root operation deserves. `9a` (PIN once per
  session) is the choice for a key that signs several operations in a row.
- **Touch `ALWAYS`**: every signature needs a finger on the key, the
  physical presence `KEY_POLICY.md` asks of an owner key. `CACHED` (15 s)
  would let malware on the host piggyback on one touch.
- **PIN `ALWAYS`**: one PIN per signature, so a stolen session cannot sign
  twice. Both policies are **fixed at generation**; changing them means a new
  key and a `set-root`.
- **`--protect`**: the management key, needed only to generate or import
  keys, lives on the device behind the PIN. Nothing to write down.

Retries: 3 wrong PINs block the PIN; the PUK unblocks it; 3 wrong PUKs leave
only `ykman piv reset`, which **wipes every PIV slot** (`RESILIENCE.md` §1.7).
The key cannot be backed up: it exists once. Losing or wiping the YubiKey is
the "owner key lost" case, answered by the cold recovery key
(`RESILIENCE.md` §2.2, `RECOVERY_DRILL.md`). Install that key before the
YubiKey becomes root.

## Attestation: proving the key was born on the device

The PIV applet signs a certificate for any slot with its attestation key
(slot `f9`), whose certificate chains to Yubico's roots. The leaf names the
firmware, the PIN and touch policies, the form factor and the device's
**serial number** (so keep it out of the repository):

```sh
agent-signer key attest --yubikey 9c --out owner-9c.attest.der   # or: ykman piv keys attest 9c
openssl x509 -inform DER -in owner-9c.attest.der -out slot.pem
ykman piv certificates export f9 f9.pem
curl -fsSLO https://developers.yubico.com/PKI/yubico-ca-1.pem          # Yubico Attestation Root 1
curl -fsSLO https://developers.yubico.com/PKI/yubico-intermediate.pem  # Yubico's intermediates
openssl verify -CAfile yubico-ca-1.pem -untrusted yubico-intermediate.pem -untrusted f9.pem slot.pem
```

Verified on 2026-11-02 for the first owner key: `slot 9c ← Yubico PIV
Attestation (f9) ← Yubico PIV Attestation B2 1 ← Yubico Attestation
Intermediate B 1 ← Yubico Attestation Root 1`, `OK`. Extensions
`1.3.6.1.4.1.41482.3.3` = `05 08 00` (firmware 5.8.0), `.3.8` = `03 02`
(PIN always, touch always), `.3.9` = `01` (USB-A keychain). Firmware older
than 5.7 chains to the older root, `Yubico PIV Root CA Serial 263751`
(`https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem`),
which a 5.7+ key does **not** verify against; check the issuer of `f9` to
know which root applies. The policy bytes in the attestation are what a
laptop should trust about a key, not the device's own metadata answer; this
is the same rule the phone design applies to Android attestation
(`MOBILE_OWNER_DESIGN.md` §5.6).

## Usage

```sh
cd signer
cargo build -p agent-signer --features tpm,yubikey        # tpm for a TPM agent key

./target/debug/agent-signer key show  --yubikey 9c         # public key and policies, no PIN
./target/debug/agent-signer key check --yubikey 9c         # asks the PIN, waits for the touch, verifies
./target/debug/agent-signer vector --backend yubikey --label 9c --message 'TPM_sign: YubiKey 5 PIV P-256 vector'

# the module's own tests; the hardware one needs the PIN in YUBIKEY_PIV_PIN
cargo test -p hw-signer --features yubikey-piv yubikey
read -s YUBIKEY_PIV_PIN && export YUBIKEY_PIV_PIN && \
  cargo test -p hw-signer --features yubikey-piv yubikey -- --ignored --nocapture
# --nocapture, or the runner swallows the "touch the YubiKey…" cue, the
# 15-second touch window closes unseen and the test fails with
# "authentication error". The key's light blinks while it waits for the touch.
```

`key create` and `key evict` refuse on purpose: ykman generates keys (it
holds the management key and sets the policies), and a PIV slot cannot be
emptied, only overwritten.

Configs take the owner (or recovery) key as

```json
"owner": { "yubikey": { "slot": "9c" } }
```

with an optional `"serial": <number>` when several YubiKeys may be plugged
in. The PIN is asked at every owner operation; the terminal then says
`touch the YubiKey to sign…`.

## On Base Sepolia (2026-11-02)

Account `0xEdB645B14e2f952C5784e34949b58F0826fBc9E9`, configs
`signer/agent.tropic01.base-sepolia.json` and the three others of that
account. Before: root = `P256Validator` V1 `0xDe1A…24D1` holding the TPM owner
key `0x81010010`; recovery installed; agent permission `trp1` in a TROPIC01.

1. **Handover.** The TPM owner key signed `owner set-root --validator
   0xdA4c…50c2 --retire 0xDe1A…24D1 --public-key <x>,<y> --sponsored`: the
   current `p256Validator` installed with the YubiKey's key, the V1 instance
   with the TPM key uninstalled in the same operation, paymaster-sponsored,
   through the public bundler — tx
   `0x010aa69c4e3ce347c851a643178a97184f350d05eeb63d56673be5e52256aff4`
   (block 53508267). `owner status`: root validator `0xda4c…50c2`, recovery
   still `installed = true, may take root = true`. On chain,
   `publicKeys(account)` on the new validator is the YubiKey's `(x, y)` and
   zeros on the old one.
2. **The old owner is powerless.** A root operation signed by the TPM key
   (a config still naming it) was refused by the EntryPoint:
   `AA24 signature error`.
3. **The agent survived.** `demo --sponsored` with the TROPIC01 key:
   `DemoCounter` 33 → 34, tx
   `0x88e0d0e0996fc069df1122dcadba48ae86c6aae5a8f699b5afdde81128e7d870`
   (block 53508948), paymaster-sponsored, delivered through our own
   `handleOps` because the public bundler had started refusing our priority
   fee (issue #15).
4. **The YubiKey is root.** `op send --root` to `DemoCounter.increment`,
   signed in slot 9c after the PIN and a touch: tx
   `0x9948458ac07de5d8839aec54f974bdde6b77964a7f471353e66bd56b0b6ed99a`
   (block 53509520, 139,115 gas), paymaster-sponsored, own `handleOps`.

The four configs now carry `"owner": { "yubikey": { "slot": "9c" } }`. Every
owner operation on this account needs the YubiKey, its PIN and a touch from
here on; the recovery key file is the way back if the YubiKey is lost.

## A second device, and the Secure Enclave test account (2026-11-10)

A **YubiKey 5C NFC** (firmware 5.8.0), set up on macOS exactly as above,
is the second device this backend has run on: `key show` and `key check`
with PIN + touch, the attestation chain to `Yubico Attestation Root 1`
(`.3.3 = 05 08 00`, `.3.8 = 03 02`, `.3.9 = 03`: USB-C keychain), a vector
through the precompile, and the hardware test (with `--nocapture`; see
the note above). macOS needs no setup: PC/SC is built in. The first time
the key is plugged in, macOS may open its Keyboard Setup Assistant for the
YubiKey's OTP interface; skip it.

With the owner's yes (PR #14), that key became the root of the **Secure
Enclave test account** `0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628`
(`signer/agent.enclave.base-sepolia.json`), whose owner until then was
`tpm_sign-owner2` in a Mac's Secure Enclave:

1. **The first attempt reverted in simulation, and nothing was sent.**
   `owner set-root --validator <P256Validator> --retire <P256Validator>` — a
   new key on the *same* validator, while that validator is root — hit
   Kernel's `RootValidatorCannotBeRemoved()` (`0x98015ee8`): Kernel never
   uninstalls the validator that is root at that moment. The CLI's
   same-validator path had only ever run after `owner recover`, when root
   was elsewhere. **Fixed the same day:** when the validator to retire is
   the current root, the batch first points root at the installed recovery
   validator, then uninstalls, reinstalls with the new key and points root
   back — one operation under the current owner's signature. Without a
   recovery key the CLI refuses with the advice to install one first. The
   anvil case `owner_rotates_its_key_on_the_root_validator` covers both.
   This is the path a phone owner takes when it rotates its own key
   (`MOBILE_OWNER_DESIGN.md` §2.2, §5.4), so it had to work.
2. **Handover**, signed by the enclave key, no prompt — tx
   `0x70543b1650778607ac7b281d130890f4add133b06da949505e08d36964e0d866`
   (block 57014798, 179,975 gas). `publicKeys(account)` on the validator
   is the YubiKey's `(x, y)`; `owner status`: root validator unchanged,
   recovery still `installed = true, may take root = true`.
3. **The old owner is refused before any signature.** A config still naming
   the enclave key: `the key about to sign (0x6b12ddff…) is not the
   account's root key (0x3c34687f… in validator 0xdA4c…50c2)`. No PIN, no
   touch, nothing sent — the check from this PR, on macOS.
4. **The YubiKey is root.** `op send --root` to `DemoCounter.increment`,
   PIN + touch — tx
   `0x8e3fc3f7285943148aeddb2ca88e68e583276099c3eefd5438077e6ac04b8c87`
   (block 57016004, 135,748 gas).
5. **The agent survived.** `demo --sponsored` with the enclave agent key:
   counter 37 → 38, tx
   `0xdf1516540a449a91f65503a7054e0c87c532e81d66b1a9e6d8fa1d1813594955`
   (block 57016142); `permission show`: every field `ok`.

The config now says `"owner": {"yubikey": {"slot": "9c"}}`; its
`ownerPublicKey` is the key the account was created with (the convention:
the creation key derives the address and is never rewritten; the current
root is read from the chain).

### Onto the new AgentPolicy (2026-11-11, issue #24)

After #23 deployed the AgentPolicy with the forbidden-target guard
(`0xdd544A6F0220778Fff16F51B468656e73E32ae85`), the enclave test account's
permission `0x73653032` moved onto it with one YubiKey signature:
`permission rotate --old-id 0x73653032 --sponsored` — tx
`0x37d637ebcc011e1de3612d02fbb1af61294dee80334edbb628965aed2a59a845`
(block 57463810, 440,350 gas, paymaster-sponsored, own `handleOps`).
`permission show` afterwards: policy module `0xdd54…ae85`, every field `ok`,
token limit `ok`; the enclave agent's `demo --sponsored` ran on it (counter
39 → 40, tx `0x32a240d3810ae387d9a1c2f13fbbceb93f637ea07207c0f332d0d2bbe7a2ef29`).

Two config changes went with it: `contracts/deployments/84532.enclave.json`
names the new policy (the previous one stays as `agentPolicyV6`), and the
mandate's two x402 allow-list entries — which name the **policy's own
address** as their target — moved to the new address too. Any mandate with
x402 entries needs that second change when it is rotated; the guard then
admits exactly those two selectors on the policy.

## Security notes

- **What the device protects:** the private key never leaves the applet;
  signing needs the PIN and a touch, so host malware cannot sign without a
  present human. What it does not protect: the host can still **choose what
  is signed**. The YubiKey has no screen, so an owner signing a root
  operation trusts the laptop's display, exactly as with the TPM owner key.
  The phone owner (`MOBILE_OWNER_DESIGN.md`) is the answer to that; a
  YubiKey is the right owner key for a laptop the owner trusts.
- **PIN entry on the host:** the PIN is typed into the laptop, so a
  keylogger learns it. It is still worth little without the key and a
  finger. Treat it like the key file passphrase.
- **Firmware is not updatable.** A vulnerability in the applet stays; the
  mitigation is rotation (`owner set-root` to a new key).
- **One key, one device.** No seed, no backup. The recovery key is the
  backup (`RESILIENCE.md` §3.2).
- **`cargo audit`:** the feature pulls `rsa` in through the `yubikey` crate,
  and `rsa` 0.10 carries RUSTSEC-2023-0071 (the Marvin timing side channel).
  We open P-256 slots only and never sign or decrypt with RSA, so the code
  never runs; the advisory is accepted with that reason in
  `signer/.cargo/audit.toml`, to be dropped when `yubikey` moves to a fixed
  `rsa`. `yubikey` 0.9.0-rc.0 itself is a release candidate, pinned by the
  lockfile until 0.9.0 lands.
