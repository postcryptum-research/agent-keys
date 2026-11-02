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
  asks the PIN (`rpassword`, zeroized) when it opens an owner or recovery
  key; **an agent key is refused** unless the slot's policies are PIN never
  and touch never, because an unattended agent cannot answer either.
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
  cargo test -p hw-signer --features yubikey-piv yubikey -- --ignored
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
