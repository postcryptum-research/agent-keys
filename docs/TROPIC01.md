# TROPIC01 backend

> **Кратко по-русски.** Устройство — TROPIC01 USB DevKit (Tropic Square,
> open-architecture secure element, чип `TR01-C2P-T103`, devkit v3.1).
> Бэкенд `signer/crates/hw-signer/src/tropic01.rs` (фича `tropic01`):
> ключ P-256 генерируется в ECC-слоте чипа и не покидает его. Проверено на
> железе (hardware-тест, вектор `p256_tropic01.json` в forge) и on-chain:
> агентский permission аккаунта на Base Sepolia переведён на ключ в слоте 1
> чипа, и чип подписал спонсированную операцию под `AgentPolicy`.

## Hardware

- **TROPIC01 USB DevKit**, product version 3.1 (PCB TS1303, STM32U5
  bridge), chip part number `TR01-C2P-T103`, RISC-V and SPECT firmware
  0.3.1, bootloader 2.0.1. On Linux it enumerates as a USB CDC serial port
  (`/dev/ttyACM0`, vendor string "TropicSquare", group `dialout`).
- **SDK:** `tropicsquare/libtropic-rs` (BSD-3-Clause-Clear), crate
  `tropic01` — an `embedded-hal` driver for the chip's L2/L3 protocol,
  pinned in `hw-signer/Cargo.toml` to the revision verified here. The
  devkit's USB-to-SPI transport in `tropic01.rs` follows the SDK's
  `tropic01-example-usb-devkit`.

## How the backend works

- `Tropic01Signer::create(port, slot)` erases the ECC slot, generates a
  P-256 key in it and reads the public key back; `open` reads an existing
  key (and refuses a non-P-256 one); `erase` clears the slot.
- `sign_digest` asks the chip for an ECDSA signature over the 32-byte
  digest (the `userOpHash`) and normalizes `s` to low-s.
- Every operation opens its own secure session (reboot into application
  firmware, X25519 handshake on pairing slot 0, command, abort). That keeps
  the signer a plain `(port, slot)` value and costs about two seconds per
  operation on the devkit — irrelevant next to block times.
- Errors: missing or wrong keys → `SignerError::Key`, signing failures →
  `SignerError::Sign`, transport and session errors → `SignerError::Backend`.

## Usage

```sh
cd signer
cargo build -p agent-signer --features tpm,tropic01     # tpm only for a TPM owner key

# hardware test (uses ECC slot 31 and erases it)
cargo test -p hw-signer --no-default-features --features software,tropic01 \
  tropic01 -- --ignored                                  # TROPIC01_PORT overrides /dev/ttyACM0

./target/debug/agent-signer key create --tropic01 /dev/ttyACM0 --slot 1
./target/debug/agent-signer vector --backend tropic01 --label /dev/ttyACM0 --slot 1 --message '…'
```

Agent configs take `"agent": { "tropic01": { "port": "/dev/ttyACM0", "slot": 1 } }`
(the owner can live there too). The serial port needs group `dialout`.

## On Base Sepolia (2026-10-20)

Account `0xEdB645B14e2f952C5784e34949b58F0826fBc9E9`, config
`signer/agent.tropic01.base-sepolia.json`:

1. The owner key (TPM) rotated the agent permission `agn2` (PCR-sealed TPM
   key) → `trp1` (`0x74727031`, TROPIC01 slot 1, same `AgentPolicy`
   mandate), sponsored, through the public bundler — tx
   `0x44bb4d6625e5ff3548273fc2f3009eb4e30fde333da8a78ef6fa74d8809bb133`.
2. The chip signed a sponsored agent operation (`DemoCounter.increment`,
   7 → 8) — tx
   `0x6c1060b43c1a40e3d123fe766adad914edccac8e9596cc1dc658617cf53622b5`:
   the first on-chain action of this project authorized by a key inside an
   open-architecture secure element.

## Security note for a deployment

A devkit opens its secure session with a pairing key that is public by
design, so any process with access to the serial port can talk to the chip.
That matches a devkit's threat model, not a deployment's: provisioning a
private pairing key into another slot is the vendor-documented step for
production. The property this project relies on — the signing key cannot
leave the chip — holds either way, and the account's `AgentPolicy` bounds
what a compromised host can make the chip sign.
