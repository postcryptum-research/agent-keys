mod abi;
mod agent;
mod chain;
mod kernel;

use std::path::PathBuf;

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hw_signer::{software::SoftwareSigner, verify_p256, HardwareSigner, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent::{parse32, parse_hex_u32, AgentConfig};
use crate::chain::{Env, Session};

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

#[derive(Args)]
struct AgentArgs {
    /// Agent account config (keys, mandate, deployments).
    #[arg(long)]
    agent: PathBuf,
    /// Optional .env with BASE_SEPOLIA_RPC_URL and GAS_WALLET_KEYFILE.
    #[arg(long)]
    env_file: Option<PathBuf>,
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
    /// Manage keys that live in the TPM.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// The agent's smart account.
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Send an operation from the agent account.
    Op {
        #[command(subcommand)]
        cmd: OpCmd,
    },
    /// Demo: the agent increments the deployed counter.
    Demo {
        #[command(flatten)]
        agent: AgentArgs,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a P-256 key inside the TPM and persist it at `handle`.
    Create {
        #[arg(long, value_parser = parse_hex_u32)]
        handle: u32,
        #[arg(long, default_value = "0x81000001", value_parser = parse_hex_u32)]
        parent: u32,
    },
    /// Print the public key persisted at `handle`.
    Show {
        #[arg(long, value_parser = parse_hex_u32)]
        handle: u32,
    },
    /// Remove the key persisted at `handle` from the TPM.
    Evict {
        #[arg(long, value_parser = parse_hex_u32)]
        handle: u32,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Counterfactual address, deployment state and balances.
    Status {
        #[command(flatten)]
        agent: AgentArgs,
    },
    /// Send ETH from the gas wallet to the account (it pays its own gas).
    Fund {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        wei: String,
    },
    /// Print the exact `initialize` calldata and ERC-4337 initCode (debugging).
    InitData {
        #[command(flatten)]
        agent: AgentArgs,
    },
}

#[derive(Subcommand)]
enum OpCmd {
    /// Build a single call, sign it in hardware and submit via handleOps.
    Send {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        target: Address,
        #[arg(long, default_value = "0")]
        wei: String,
        /// 0x-prefixed calldata (empty for a plain transfer)
        #[arg(long, default_value = "0x")]
        data: String,
        /// Sign with the owner key on the root path instead of the agent permission.
        #[arg(long)]
        root: bool,
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

#[derive(Serialize)]
struct KeyInfo {
    handle: String,
    x: String,
    y: String,
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn open_backend(backend: Backend, parent: u32) -> Result<Box<dyn HardwareSigner>> {
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

fn key_info(handle: u32, pk: &PublicKey) -> KeyInfo {
    KeyInfo { handle: format!("0x{handle:08x}"), x: hex32(&pk.x), y: hex32(&pk.y) }
}

#[cfg(feature = "tpm")]
fn run_key(cmd: KeyCmd) -> Result<()> {
    use hw_signer::tpm::TpmSigner;
    match cmd {
        KeyCmd::Create { handle, parent } => {
            let mut signer = TpmSigner::create_under(parent)?;
            signer.persist(handle)?;
            println!("{}", serde_json::to_string_pretty(&key_info(handle, &signer.public_key()?))?);
        }
        KeyCmd::Show { handle } => {
            let signer = TpmSigner::open_persistent(handle)?;
            println!("{}", serde_json::to_string_pretty(&key_info(handle, &signer.public_key()?))?);
        }
        KeyCmd::Evict { handle } => {
            TpmSigner::evict(handle)?;
            println!("evicted 0x{handle:08x}");
        }
    }
    Ok(())
}

#[cfg(not(feature = "tpm"))]
fn run_key(_: KeyCmd) -> Result<()> {
    bail!("`key` needs the `tpm` feature: cargo build --features tpm")
}

async fn session(args: &AgentArgs) -> Result<Session> {
    let env = Env::load(args.env_file.as_deref())?;
    let (cfg, base) = AgentConfig::load(&args.agent)?;
    Session::open(&env, cfg, &base).await
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Vector { message, backend, parent } => {
            let signer = open_backend(backend, parent)?;
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
            let bytes = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
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
        Cmd::Key { cmd } => run_key(cmd)?,
        Cmd::Account { cmd } => match cmd {
            AccountCmd::Status { agent } => session(&agent).await?.print_status().await?,
            AccountCmd::Fund { agent, wei } => {
                let s = session(&agent).await?;
                let amount: U256 = wei.parse().context("--wei")?;
                let tx = s.fund(amount).await?;
                println!("funded {} with {amount} wei: tx {tx}", s.account);
            }
            AccountCmd::InitData { agent } => {
                let s = session(&agent).await?;
                println!("account:  {}", s.account);
                println!("factory:  {}", s.dep.kernel_factory);
                println!("salt:     {}", s.cfg.salt()?);
                println!("initData: {}", s.init_data);
                println!("initCode: {}", kernel::init_code(s.dep.kernel_factory, &s.init_data, s.cfg.salt()?));
            }
        },
        Cmd::Op { cmd } => match cmd {
            OpCmd::Send { agent, target, wei, data, root } => {
                let s = session(&agent).await?;
                let value: U256 = wei.parse().context("--wei")?;
                let data = Bytes::from(hex::decode(data.trim_start_matches("0x")).context("--data")?);
                let inc = s.send_op(target, value, data, root).await?;
                println!("included: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
        },
        Cmd::Demo { agent } => {
            let s = session(&agent).await?;
            let before = s.counter().await?;
            let data = Bytes::from(abi::IDemoCounter::incrementCall::SELECTOR.to_vec());
            let inc = s.send_op(s.dep.demo_counter, U256::ZERO, data, false).await?;
            let after = s.counter_at(inc.block).await?;
            println!("included: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            println!("counter:  {before} -> {after}");
        }
    }
    Ok(())
}
