# TROPIC01 backend — status and interface

> **Кратко по-русски.** Устройство — TROPIC01 USB DevKit (Tropic Square,
> open-architecture secure element, чип `TR01-C2P-T103`, devkit v3.1). На
> железе проверено vendor-SDK: сессия открывается, чип отвечает, умеет ECDSA
> P-256. Обвязка в репозитории готова (фича, зависимости, конфиг, CLI);
> не хватает одного файла — `signer/crates/hw-signer/src/tropic01.rs` с
> типом `Tropic01Signer`, контракт которого описан ниже. Эталон для него —
> пример `tropic01-example-usb-devkit` из SDK.

## What is on hand

- **Hardware:** TROPIC01 USB DevKit, product version 3.1 (PCB TS1303,
  STM32U5 bridge), chip part number `TR01-C2P-T103`. On Linux it enumerates
  as a USB CDC serial port (`/dev/ttyACM0`, vendor string "TropicSquare",
  group `dialout`).
- **Verified (2026-10-20):** the vendor's Rust SDK example opened a secure
  session, exchanged a ping, and read the chip's identity (RISC-V and SPECT
  firmware 0.3.1, bootloader 2.0.1). The chip's ECC slots sign with ECDSA
  P-256 and Ed25519 in hardware.
- **SDK:** `tropicsquare/libtropic-rs` (BSD-3-Clause-Clear). The crate
  `tropic01` is an `embedded-hal` driver; the workspace's
  `tropic01-example-usb-devkit` contains the USB-devkit transport and a
  complete key-generate / sign / verify walkthrough. The dependency is pinned
  in `hw-signer/Cargo.toml` to the revision that was verified.

## What the repository already provides

- `hw-signer` feature `tropic01` with the SDK and transport dependencies.
- `lib.rs` declares `pub mod tropic01` under that feature — the module file
  is the missing piece.
- Agent configs accept `"tropic01": { "port": "/dev/ttyACM0", "slot": 0 }`
  for `owner` or `agent`.
- CLI: `key create|show|evict --tropic01 /dev/ttyACM0 --slot N` and
  `vector --backend tropic01 --label /dev/ttyACM0 --slot N`.
- The Solidity tests verify every `contracts/test/vectors/p256_*.json`, so a
  vector signed by the chip is covered as soon as it is committed.

## The interface `src/tropic01.rs` must expose

```rust
pub struct Tropic01Signer { /* … */ }

impl Tropic01Signer {
    /// Open the key living in ECC `slot` of the chip on `port`.
    pub fn open(port: &str, slot: u16) -> Result<Self, SignerError>;
    /// Generate a fresh P-256 key in `slot` (erasing what was there).
    pub fn create(port: &str, slot: u16) -> Result<Self, SignerError>;
    /// Erase the key in this signer's slot.
    pub fn erase(self) -> Result<(), SignerError>;
}

impl HardwareSigner for Tropic01Signer {
    fn public_key(&self) -> Result<PublicKey, SignerError>;      // x ‖ y of the slot's key
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError>; // low-s (r, s)
}
```

Conventions, as for the other backends:

- `public_key` returns the uncompressed coordinates; `sign_digest` returns
  the raw pair normalized to low-s (`crate::normalize_low_s` does that from
  any `(r, s)`), because the on-chain verifier rejects high-s.
- Map SDK and transport errors into `SignerError::Backend`, key-slot issues
  into `SignerError::Key`, signing failures into `SignerError::Sign`.
- A `#[test] #[ignore = "requires a TROPIC01 devkit"]` hardware test is
  welcome; use a high slot (e.g. 31) and erase it at the end.

## Security note for a deployment

A devkit opens its secure session with a pairing key that is public by
design, so any process with access to the serial port can talk to the chip.
That matches a devkit's threat model, not a deployment's: provisioning a
private pairing key into another slot is the vendor-documented step for
production. The property this project relies on — the signing key cannot
leave the chip — holds either way.

## What happens once the module lands

1. `cargo build -p agent-signer --features tropic01` and the hardware test.
2. `key create --tropic01 /dev/ttyACM0 --slot 1`, then a vector:
   `contracts/test/vectors/p256_tropic01.json` — verified by `forge test`.
3. An agent config with `"agent": { "tropic01": { "port": "/dev/ttyACM0", "slot": 1 } }`,
   a rotation to it signed by the TPM owner key, and a sponsored operation on
   Base Sepolia — the first on-chain action authorized by a key inside an
   open-architecture secure element.
