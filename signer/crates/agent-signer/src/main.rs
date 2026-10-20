use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hw_signer::{software::SoftwareSigner, verify_p256, HardwareSigner, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(
    name = "agent-signer",
    version,
    about = "Hardware-backed P-256 signer for ERC-4337 agent accounts"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    /// In-memory key. Dev/CI only.
    Software,
    /// TPM 2.0 via tss-esapi (build with `--features tpm`).
    Tpm,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign `message` with a fresh key and print a JSON test vector
    /// (digest, r, s, x, y) consumed by the Solidity tests.
    Vector {
        #[arg(long)]
        message: String,
        #[arg(long, value_enum, default_value_t = Backend::Software)]
        backend: Backend,
        /// TPM storage parent for the new key (persistent handle, hex).
        #[arg(long, default_value = "0x81000001", value_parser = parse_hex_u32)]
        parent: u32,
    },
    /// Verify a JSON test vector off-chain with the `p256` crate.
    Verify {
        #[arg(long)]
        file: PathBuf,
    },
}

/// Wire format shared with `contracts/test`. Every field is 0x-prefixed hex so
/// Foundry's `vm.parseJsonBytes32` reads it directly.
#[derive(Serialize, Deserialize)]
struct Vector {
    backend: String,
    message: String,
    digest: String,
    r: String,
    s: String,
    x: String,
    y: String,
}

fn parse_hex_u32(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("bad hex")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", raw.len()))
}

fn open_signer(backend: Backend, parent: u32) -> Result<Box<dyn HardwareSigner>> {
    match backend {
        Backend::Software => Ok(Box::new(SoftwareSigner::random())),
        Backend::Tpm => {
            #[cfg(feature = "tpm")]
            {
                Ok(Box::new(hw_signer::tpm::TpmSigner::create_under(parent)?))
            }
            #[cfg(not(feature = "tpm"))]
            {
                let _ = parent;
                bail!("built without the `tpm` feature: cargo build --features tpm")
            }
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Vector { message, backend, parent } => {
            let signer = open_signer(backend, parent)?;
            let digest: [u8; 32] = Sha256::digest(message.as_bytes()).into();
            let sig = signer.sign_digest(&digest)?;
            let pk = signer.public_key()?;
            if !verify_p256(&digest, &sig, &pk) {
                bail!("self-check failed: signature does not verify");
            }
            let v = Vector {
                backend: format!("{backend:?}").to_lowercase(),
                message,
                digest: hex32(&digest),
                r: hex32(&sig.r),
                s: hex32(&sig.s),
                x: hex32(&pk.x),
                y: hex32(&pk.y),
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Verify { file } => {
            let bytes = std::fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let v: Vector = serde_json::from_slice(&bytes)?;
            let ok = verify_p256(
                &parse32(&v.digest)?,
                &Signature { r: parse32(&v.r)?, s: parse32(&v.s)? },
                &PublicKey { x: parse32(&v.x)?, y: parse32(&v.y)? },
            );
            println!("{}", if ok { "OK" } else { "INVALID" });
            if !ok {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
