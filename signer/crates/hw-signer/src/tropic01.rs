//! Tropic Square TROPIC01 secure element over its USB DevKit.
//!
//! The devkit is a USB-to-SPI bridge: it enumerates as a CDC serial port and
//! takes SPI transfers as ASCII hex lines. On top of that the vendor driver
//! (`tropic01` crate) runs the chip's L2/L3 protocol inside an encrypted
//! secure session. The P-256 key is generated inside an ECC slot of the chip
//! and never leaves it; the host only gets the public key and `(r, s)`.
//!
//! Every operation opens its own short secure session and closes it again.
//! That keeps [`Tropic01Signer`] a plain `(port, slot)` value usable through
//! `&self`, and a transport hiccup can never leave a half-dead session behind.
//!
//! The transport below follows `tropic01-example-usb-devkit/src/usb_dongle.rs`
//! from `tropicsquare/libtropic-rs` (BSD-3-Clause-Clear).

use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use embedded_hal::spi::{self, Operation};
use rand_core::OsRng;
use serialport::SerialPort;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{EccCurve, Tropic01, X25519Dalek, ECC_SLOT_MAX};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::{normalize_low_s, HardwareSigner, PublicKey, Signature, SignerError};

const BAUD_RATE: u32 = 115_200;
/// Pairing-key slot the devkit's factory session key is provisioned in.
const PAIRING_SLOT: u8 = 0;

/// A P-256 key in one ECC slot of a TROPIC01 reached through `port`.
pub struct Tropic01Signer {
    port: String,
    slot: u16,
    public_key: PublicKey,
}

impl Tropic01Signer {
    /// Open the key living in ECC `slot` of the chip on `port`.
    pub fn open(port: &str, slot: u16) -> Result<Self, SignerError> {
        check_slot(slot)?;
        let public_key = with_session(port, |s| read_p256(s, slot))?;
        Ok(Self { port: port.to_owned(), slot, public_key })
    }

    /// Generate a fresh P-256 key in `slot` (erasing what was there).
    pub fn create(port: &str, slot: u16) -> Result<Self, SignerError> {
        check_slot(slot)?;
        let public_key = with_session(port, |s| {
            // Erasing an empty slot succeeds, so this is unconditional.
            s.ecc_key_erase(slot.into()).map_err(|e| key_err("erase", e))?;
            s.ecc_key_generate(slot.into(), EccCurve::P256)
                .map_err(|e| key_err("generate", e))?;
            read_p256(s, slot)
        })?;
        Ok(Self { port: port.to_owned(), slot, public_key })
    }

    /// Erase the key in this signer's slot.
    pub fn erase(self) -> Result<(), SignerError> {
        with_session(&self.port, |s| {
            s.ecc_key_erase(self.slot.into()).map_err(|e| key_err("erase", e))
        })
    }

    pub fn slot(&self) -> u16 {
        self.slot
    }
}

impl HardwareSigner for Tropic01Signer {
    fn public_key(&self) -> Result<PublicKey, SignerError> {
        Ok(self.public_key)
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, SignerError> {
        let raw = with_session(&self.port, |s| {
            s.ecdsa_sign(self.slot.into(), digest)
                .copied()
                .map_err(|e| match classify(&e) {
                    Class::Key => SignerError::Key(format!("slot {}: {e}", self.slot)),
                    _ => SignerError::Sign(e.to_string()),
                })
        })?;
        let mut sig = Signature { r: [0; 32], s: [0; 32] };
        sig.r.copy_from_slice(&raw[..32]);
        sig.s.copy_from_slice(&raw[32..]);
        Ok(normalize_low_s(sig))
    }
}

type Session = Tropic01<UsbDongle, dummy_pin::DummyPin, tropic01::ActiveSession>;
type ChipError = tropic01::Error<UsbDongleError, core::convert::Infallible>;

fn check_slot(slot: u16) -> Result<(), SignerError> {
    if slot > ECC_SLOT_MAX {
        return Err(SignerError::Key(format!("ECC slot {slot} out of range 0..={ECC_SLOT_MAX}")));
    }
    Ok(())
}

/// Open the port, start a secure session, run `f`, and close the session
/// again whatever `f` returned.
fn with_session<T>(
    port: &str,
    f: impl FnOnce(&mut Session) -> Result<T, SignerError>,
) -> Result<T, SignerError> {
    let dongle = UsbDongle::new(port, BAUD_RATE)
        .map_err(|e| SignerError::Backend(format!("{port}: {e}")))?;
    let mut chip = Tropic01::new(dongle);

    // A reboot puts the chip into application firmware (not startup mode)
    // and drops any session another process may have left open.
    chip.startup_req(tropic01::StartupReq::Reboot).map_err(backend)?;

    let ehpriv = StaticSecret::random_from_rng(OsRng);
    let ehpub = XPublicKey::from(&ehpriv);
    let mut session = chip
        .session_start(
            &X25519Dalek,
            SH0PUB_PROD0.into(),
            SH0PRIV_PROD0.into(),
            ehpub,
            ehpriv,
            PAIRING_SLOT,
        )
        .map_err(|(_, e)| SignerError::Backend(format!("secure session: {e}")))?;

    let out = f(&mut session);
    let closed = session.session_abort().map_err(|(_, e)| backend(e));
    // The operation's error is the interesting one; report a failed close
    // only when the operation itself went through.
    let out = out?;
    closed?;
    Ok(out)
}

fn read_p256(s: &mut Session, slot: u16) -> Result<PublicKey, SignerError> {
    let res = s.ecc_key_read(slot.into()).map_err(|e| key_err("read", e))?;
    if res.curve() != EccCurve::P256 {
        return Err(SignerError::Key(format!(
            "slot {slot} holds a {:?} key, not P-256",
            res.curve()
        )));
    }
    let raw = res.pub_key();
    if raw.len() != 64 {
        return Err(SignerError::Key(format!("slot {slot}: public key is {} bytes", raw.len())));
    }
    let mut pk = PublicKey { x: [0; 32], y: [0; 32] };
    pk.x.copy_from_slice(&raw[..32]);
    pk.y.copy_from_slice(&raw[32..]);
    Ok(pk)
}

enum Class {
    Key,
    Other,
}

fn classify(e: &ChipError) -> Class {
    use tropic01::Error as E;
    match e {
        E::InvalidKey | E::SlotEmpty | E::SlotInvalid | E::SlotExpired | E::SlotNotEmpty => {
            Class::Key
        }
        _ => Class::Other,
    }
}

fn key_err(what: &str, e: ChipError) -> SignerError {
    match classify(&e) {
        Class::Key => SignerError::Key(format!("{what}: {e}")),
        Class::Other => SignerError::Backend(format!("{what}: {e}")),
    }
}

fn backend(e: ChipError) -> SignerError {
    SignerError::Backend(e.to_string())
}

// ---------------------------------------------------------------------------
// USB DevKit transport: `embedded_hal::spi::SpiDevice` over the serial bridge.

#[derive(Debug)]
pub enum UsbDongleError {
    Io(std::io::Error),
    Protocol(String),
}

impl std::fmt::Display for UsbDongleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "USB devkit I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "USB devkit protocol error: {msg}"),
        }
    }
}

impl std::error::Error for UsbDongleError {}

impl spi::Error for UsbDongleError {
    fn kind(&self) -> spi::ErrorKind {
        spi::ErrorKind::Other
    }
}

impl From<std::io::Error> for UsbDongleError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct UsbDongle {
    port: Box<dyn SerialPort>,
}

impl UsbDongle {
    fn new(path: &str, baud_rate: u32) -> Result<Self, UsbDongleError> {
        let port = serialport::new(path, baud_rate)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| UsbDongleError::Protocol(e.to_string()))?;
        Ok(Self { port })
    }

    /// One full-duplex SPI transfer: send `<HEX>x\n`, read back the MISO
    /// bytes as a hex line, in place.
    fn spi_transfer(&mut self, data: &mut [u8]) -> Result<(), UsbDongleError> {
        let mut cmd: String = data.iter().map(|b| format!("{b:02X}")).collect();
        cmd.push_str("x\n");
        self.port.write_all(cmd.as_bytes())?;
        self.port.flush()?;
        thread::sleep(Duration::from_millis(10));

        let line = self.read_line()?;
        let hex = line.trim_end_matches('\n').trim_end_matches('\r');
        let expected = data.len().saturating_mul(2);
        if hex.len() != expected {
            return Err(UsbDongleError::Protocol(format!(
                "expected {expected} hex chars, got {}",
                hex.len()
            )));
        }
        for (byte, pair) in data.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair)
                .map_err(|e| UsbDongleError::Protocol(e.to_string()))?;
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|e| UsbDongleError::Protocol(format!("bad hex {pair:?}: {e}")))?;
        }
        Ok(())
    }

    /// Release chip select: `CS=0\n`, answered by `OK\r\n`.
    fn cs_deassert(&mut self) -> Result<(), UsbDongleError> {
        self.port.write_all(b"CS=0\n")?;
        self.port.flush()?;
        let mut buf = [0u8; 4];
        self.port.read_exact(&mut buf)?;
        if &buf != b"OK\r\n" {
            return Err(UsbDongleError::Protocol(format!(
                "expected OK after CS=0, got {:?}",
                String::from_utf8_lossy(&buf)
            )));
        }
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, UsbDongleError> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while byte[0] != b'\n' {
            self.port.read_exact(&mut byte)?;
            line.push(byte[0]);
        }
        String::from_utf8(line).map_err(|e| UsbDongleError::Protocol(e.to_string()))
    }
}

impl spi::ErrorType for UsbDongle {
    type Error = UsbDongleError;
}

impl spi::SpiDevice for UsbDongle {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut transferred = false;
        for op in operations {
            match op {
                Operation::TransferInPlace(data) => self.spi_transfer(data)?,
                Operation::Read(buf) => {
                    buf.fill(0);
                    self.spi_transfer(buf)?;
                }
                Operation::Transfer(read, write) => {
                    read.copy_from_slice(write);
                    self.spi_transfer(read)?;
                }
                Operation::Write(data) => self.spi_transfer(&mut data.to_vec())?,
                Operation::DelayNs(ns) => {
                    thread::sleep(Duration::from_nanos(u64::from(*ns)));
                    continue;
                }
            }
            transferred = true;
        }
        // Delay-only transactions (the driver's retry waits) must not toggle CS.
        if transferred {
            self.cs_deassert()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    /// High slot so the test never touches a key in real use.
    const TEST_SLOT: u16 = 31;

    #[test]
    #[ignore = "requires a TROPIC01 devkit"]
    fn tropic01_create_sign_verify_erase() {
        let port = std::env::var("TROPIC01_PORT").unwrap_or_else(|_| "/dev/ttyACM0".into());

        let signer = Tropic01Signer::create(&port, TEST_SLOT).expect("create key");
        let pk = signer.public_key().unwrap();

        // `open` sees the same key the chip just generated.
        let reopened = Tropic01Signer::open(&port, TEST_SLOT).expect("open key");
        assert_eq!(reopened.public_key().unwrap(), pk);

        let digest = [0x5a; 32];
        let sig = signer.sign_digest(&digest).expect("sign");
        assert!(verify_p256(&digest, &sig, &pk));
        let mut tampered = digest;
        tampered[31] ^= 1;
        assert!(!verify_p256(&tampered, &sig, &pk));

        signer.erase().expect("erase");
        assert!(matches!(
            Tropic01Signer::open(&port, TEST_SLOT),
            Err(SignerError::Key(_))
        ));
    }
}
