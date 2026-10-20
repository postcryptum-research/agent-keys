mod abi;
mod agent;
mod bundler;
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
    /// Apple Secure Enclave, an existing key by label (macOS, `--features secure-enclave`).
    Enclave,
    /// Windows TPM through CNG, an existing key by name (`--features windows-tpm`).
    Cng,
    /// TROPIC01 over its USB DevKit: `--label <serial port> --slot <n>` (`--features tropic01`).
    Tropic01,
}

#[derive(Args)]
struct AgentArgs {
    /// Agent account config (keys, mandate, deployments).
    #[arg(long)]
    agent: PathBuf,
    /// Optional .env with BASE_SEPOLIA_RPC_URL, GAS_WALLET_KEYFILE and BUNDLER_URL.
    #[arg(long)]
    env_file: Option<PathBuf>,
    /// Deliver operations through this ERC-4337 bundler RPC instead of our
    /// own handleOps (overrides BUNDLER_URL).
    #[arg(long)]
    bundler: Option<String>,
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
        /// Secure Enclave / CNG: key label or name; TROPIC01: serial port.
        #[arg(long)]
        label: Option<String>,
        /// TROPIC01: ECC key slot.
        #[arg(long, default_value_t = 0)]
        slot: u16,
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
    /// The whitelist paymaster that can pay the account's gas.
    Paymaster {
        #[command(subcommand)]
        cmd: PaymasterCmd,
    },
    /// The agent permission, controlled by the owner key.
    Permission {
        #[command(subcommand)]
        cmd: PermissionCmd,
    },
    /// Demo: the agent increments the deployed counter.
    Demo {
        #[command(flatten)]
        agent: AgentArgs,
        /// Let the paymaster pay instead of the account.
        #[arg(long)]
        sponsored: bool,
    },
}

#[derive(Subcommand)]
enum PermissionCmd {
    /// Remove permission `id` (root operation signed by the owner key).
    Revoke {
        #[command(flatten)]
        agent: AgentArgs,
        /// 4-byte hex permission id to remove.
        #[arg(long)]
        id: String,
        #[arg(long)]
        sponsored: bool,
    },
    /// Replace permission `old_id` with the one the config describes — new
    /// agent key and/or mandate — in one root operation. Pin `account` in
    /// the config first.
    Rotate {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        old_id: String,
        #[arg(long)]
        sponsored: bool,
        /// Print the batch calldata instead of sending it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum PaymasterCmd {
    /// Top up the paymaster's EntryPoint deposit from the gas wallet.
    Deposit {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        wei: String,
    },
    /// List this account for sponsorship (owner only); --revoke delists it.
    Sponsor {
        #[command(flatten)]
        agent: AgentArgs,
        /// Gas budget for this account, in wei (charged per operation at its
        /// maximum cost, no refunds).
        #[arg(long, default_value = "0")]
        budget: u128,
        /// The most one operation may cost, in wei.
        #[arg(long, default_value = "0")]
        max_per_op: u128,
        /// Delist the account (budget 0).
        #[arg(long)]
        revoke: bool,
    },
    /// Stake the paymaster in the EntryPoint (owner only) — public bundlers
    /// require it before relaying sponsored operations.
    Stake {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        wei: String,
        /// Seconds before a later unstake can be withdrawn.
        #[arg(long, default_value_t = 86_400)]
        unstake_delay_sec: u32,
    },
}

/// Which secure element a `key` command addresses: a TPM persistent handle
/// or a Secure Enclave key label — exactly one.
#[derive(Args)]
struct KeyRef {
    /// TPM 2.0: persistent handle (hex), e.g. 0x81010010.
    #[arg(long, value_parser = parse_hex_u32, conflicts_with = "enclave")]
    handle: Option<u32>,
    /// Apple Secure Enclave (macOS): key label.
    #[arg(long)]
    enclave: Option<String>,
    /// Windows TPM through CNG: key name.
    #[arg(long, conflicts_with_all = ["handle", "enclave"])]
    cng: Option<String>,
    /// TROPIC01 USB DevKit: serial port (e.g. /dev/ttyACM0); pair with --slot.
    #[arg(long, conflicts_with_all = ["handle", "enclave", "cng"])]
    tropic01: Option<String>,
    /// TROPIC01: ECC key slot (0..31).
    #[arg(long, default_value_t = 0)]
    slot: u16,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a P-256 key inside the secure element.
    Create {
        #[command(flatten)]
        key: KeyRef,
        /// TPM storage parent for the new key.
        #[arg(long, default_value = "0x81000001", value_parser = parse_hex_u32)]
        parent: u32,
        /// TPM: seal the key to these PCRs (e.g. 0,2,4,7); it then signs only
        /// while the measured boot state matches today's.
        #[arg(long, value_delimiter = ',')]
        pcrs: Vec<u8>,
        /// TPM: protect the key with an authValue derived from this file's
        /// contents — for an owner key sharing the chip with the agent, a
        /// file only root can read (docs/KEY_POLICY.md, rule 3).
        #[arg(long)]
        auth_file: Option<PathBuf>,
    },
    /// Print the public key.
    Show {
        #[command(flatten)]
        key: KeyRef,
    },
    /// Remove the key from the secure element.
    Evict {
        #[command(flatten)]
        key: KeyRef,
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
        /// Let the paymaster pay instead of the account.
        #[arg(long)]
        sponsored: bool,
        /// Print the result as one JSON object on stdout (progress stays on
        /// stderr), for programs that drive the CLI.
        #[arg(long)]
        json: bool,
        /// Use this EntryPoint nonce (as printed in `nonce` of an earlier
        /// attempt) instead of the next free one: resending the same action
        /// can then never execute it twice.
        #[arg(long)]
        nonce: Option<String>,
        /// For `Safe.execTransaction` calldata: the Safe nonce this
        /// transaction is meant for. The operation becomes a batch that first
        /// asserts it on-chain, so a replay reverts instead of executing again
        /// (AgentPolicy admits Safe transactions only this way).
        #[arg(long)]
        safe_nonce: Option<String>,
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
    key: String,
    x: String,
    y: String,
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse_permission_id(s: &str) -> Result<kernel::PermissionId> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("permission id")?;
    let arr: [u8; 4] = raw.as_slice().try_into().map_err(|_| anyhow::anyhow!("permission id must be 4 bytes"))?;
    Ok(kernel::PermissionId::from(arr))
}

fn open_backend(backend: Backend, parent: u32, label: Option<String>, slot: u16) -> Result<Box<dyn HardwareSigner>> {
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
        Backend::Enclave => {
            let label = label.context("--backend enclave needs --label <key label>")?;
            #[cfg(all(feature = "secure-enclave", target_os = "macos"))]
            {
                Ok(Box::new(hw_signer::secure_enclave::SecureEnclaveSigner::open(&label)?))
            }
            #[cfg(not(all(feature = "secure-enclave", target_os = "macos")))]
            {
                bail!("Secure Enclave key {label}: needs macOS and `--features secure-enclave`")
            }
        }
        Backend::Cng => {
            let name = label.context("--backend cng needs --label <key name>")?;
            #[cfg(all(feature = "windows-tpm", target_os = "windows"))]
            {
                Ok(Box::new(hw_signer::windows_tpm::CngSigner::open(&name)?))
            }
            #[cfg(not(all(feature = "windows-tpm", target_os = "windows")))]
            {
                bail!("Windows TPM key {name}: needs Windows and `--features windows-tpm`")
            }
        }
        Backend::Tropic01 => {
            let port = label.context("--backend tropic01 needs --label <serial port> (and --slot)")?;
            #[cfg(feature = "tropic01")]
            {
                Ok(Box::new(hw_signer::tropic01::Tropic01Signer::open(&port, slot)?))
            }
            #[cfg(not(feature = "tropic01"))]
            {
                bail!("TROPIC01 key in slot {slot} on {port}: needs `--features tropic01`")
            }
        }
    }
}

fn print_key(key: String, pk: &PublicKey) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&KeyInfo { key, x: hex32(&pk.x), y: hex32(&pk.y) })?);
    Ok(())
}

enum KeyOp {
    Create { parent: u32, pcrs: Vec<u8>, auth_file: Option<PathBuf> },
    Show,
    Evict,
}

fn run_key(cmd: KeyCmd) -> Result<()> {
    let (key, op) = match cmd {
        KeyCmd::Create { key, parent, pcrs, auth_file } => (key, KeyOp::Create { parent, pcrs, auth_file }),
        KeyCmd::Show { key } => (key, KeyOp::Show),
        KeyCmd::Evict { key } => (key, KeyOp::Evict),
    };
    match (key.handle, key.enclave, key.cng, key.tropic01) {
        (Some(handle), None, None, None) => tpm_key(handle, op),
        (None, Some(label), None, None) => enclave_key(&label, op),
        (None, None, Some(name), None) => cng_key(&name, op),
        (None, None, None, Some(port)) => tropic01_key(&port, key.slot, op),
        _ => bail!(
            "give exactly one of --handle (TPM), --enclave <label> (Secure Enclave), --cng <name> (Windows TPM) or --tropic01 <port> (TROPIC01)"
        ),
    }
}

#[cfg(feature = "tropic01")]
fn tropic01_key(port: &str, slot: u16, op: KeyOp) -> Result<()> {
    use hw_signer::tropic01::Tropic01Signer;
    let name = format!("{port} slot {slot}");
    match op {
        KeyOp::Create { .. } => print_key(name, &Tropic01Signer::create(port, slot)?.public_key()?),
        KeyOp::Show => print_key(name, &Tropic01Signer::open(port, slot)?.public_key()?),
        KeyOp::Evict => {
            Tropic01Signer::open(port, slot)?.erase()?;
            println!("erased {name}");
            Ok(())
        }
    }
}

#[cfg(not(feature = "tropic01"))]
fn tropic01_key(port: &str, slot: u16, _: KeyOp) -> Result<()> {
    bail!("TROPIC01 key in slot {slot} on {port}: needs `--features tropic01`")
}

#[cfg(all(feature = "windows-tpm", target_os = "windows"))]
fn cng_key(name: &str, op: KeyOp) -> Result<()> {
    use hw_signer::windows_tpm::CngSigner;
    match op {
        KeyOp::Create { .. } => print_key(name.into(), &CngSigner::create(name)?.public_key()?),
        KeyOp::Show => print_key(name.into(), &CngSigner::open(name)?.public_key()?),
        KeyOp::Evict => {
            CngSigner::open(name)?.delete()?;
            println!("deleted {name}");
            Ok(())
        }
    }
}

#[cfg(not(all(feature = "windows-tpm", target_os = "windows")))]
fn cng_key(name: &str, _: KeyOp) -> Result<()> {
    bail!("Windows TPM key {name}: needs Windows and `--features windows-tpm`")
}

#[cfg(feature = "tpm")]
fn tpm_key(handle: u32, op: KeyOp) -> Result<()> {
    use hw_signer::tpm::TpmSigner;
    let name = format!("0x{handle:08x}");
    match op {
        KeyOp::Create { parent, pcrs, auth_file } => {
            let mut signer = match (&auth_file, pcrs.is_empty()) {
                (None, true) => TpmSigner::create_under(parent)?,
                (None, false) => TpmSigner::create_sealed_under(parent, &pcrs)?,
                (Some(file), true) => {
                    let secret = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
                    TpmSigner::create_protected_under(parent, &secret)?
                }
                (Some(_), false) => bail!("--auth-file and --pcrs do not combine"),
            };
            signer.persist(handle)?;
            if !pcrs.is_empty() {
                eprintln!("sealed to PCRs {pcrs:?}: reference it as {{\"tpm\": {{\"handle\": \"{name}\", \"pcrs\": {pcrs:?}}}}}");
            }
            if let Some(file) = &auth_file {
                eprintln!(
                    "protected by the secret in {}: reference it as {{\"tpm\": {{\"handle\": \"{name}\", \"authFile\": \"{}\"}}}}; \
                     keep that file root-only (0600)",
                    file.display(),
                    file.display()
                );
            }
            print_key(name, &signer.public_key()?)
        }
        KeyOp::Show => print_key(name, &TpmSigner::open_persistent(handle)?.public_key()?),
        KeyOp::Evict => {
            TpmSigner::evict(handle)?;
            println!("evicted {name}");
            Ok(())
        }
    }
}

#[cfg(not(feature = "tpm"))]
fn tpm_key(_: u32, _: KeyOp) -> Result<()> {
    bail!("TPM keys need the `tpm` feature: cargo build --features tpm")
}

#[cfg(all(feature = "secure-enclave", target_os = "macos"))]
fn enclave_key(label: &str, op: KeyOp) -> Result<()> {
    use hw_signer::secure_enclave::SecureEnclaveSigner;
    match op {
        KeyOp::Create { .. } => print_key(label.into(), &SecureEnclaveSigner::create(label)?.public_key()?),
        KeyOp::Show => print_key(label.into(), &SecureEnclaveSigner::open(label)?.public_key()?),
        KeyOp::Evict => {
            SecureEnclaveSigner::open(label)?.delete()?;
            println!("deleted {label}");
            Ok(())
        }
    }
}

#[cfg(not(all(feature = "secure-enclave", target_os = "macos")))]
fn enclave_key(label: &str, _: KeyOp) -> Result<()> {
    bail!("Secure Enclave key {label}: needs macOS and `--features secure-enclave`")
}

async fn session(args: &AgentArgs) -> Result<Session> {
    let env = Env::load(args.env_file.as_deref(), args.bundler.as_deref())?;
    let (cfg, base) = AgentConfig::load(&args.agent)?;
    Session::open(&env, cfg, &base).await
}

/// `Safe.execTransaction(...)` selector.
const SAFE_EXEC_TRANSACTION: [u8; 4] = [0x6a, 0x76, 0x12, 0x02];

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Vector { message, backend, parent, label, slot } => {
            let signer = open_backend(backend, parent, label, slot)?;
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
            let v: Vector = serde_json::from_str(&decode_text(&bytes)?)
                .with_context(|| format!("parsing {}", file.display()))?;
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
                println!("initData: {}", s.init_data()?);
                println!("initCode: {}", kernel::init_code(s.dep.kernel_factory, s.init_data()?, s.cfg.salt()?));
            }
        },
        Cmd::Op { cmd } => match cmd {
            OpCmd::Send { agent, target, wei, data, root, sponsored, json, nonce, safe_nonce } => {
                let s = session(&agent).await?;
                let value: U256 = wei.parse().context("--wei")?;
                let data = Bytes::from(hex::decode(data.trim_start_matches("0x")).context("--data")?);
                let nonce = nonce.map(|n| n.parse::<U256>()).transpose().context("--nonce")?;
                let safe_nonce = safe_nonce.map(|n| n.parse::<U256>()).transpose().context("--safe-nonce")?;
                let is_safe_exec = data.len() >= 4 && data[..4] == SAFE_EXEC_TRANSACTION;
                let inc = match safe_nonce {
                    Some(n) if is_safe_exec => {
                        s.send_safe_guarded(target, value, data, n, root, sponsored, nonce).await?
                    }
                    Some(_) => bail!("--safe-nonce applies to Safe.execTransaction calldata only"),
                    None if is_safe_exec && !root => bail!(
                        "a Safe transaction needs --safe-nonce <n>, the Safe nonce it is meant for: \
                         the agent's mandate admits it only paired with an on-chain nonce assertion"
                    ),
                    None => s.send_op(target, value, data, root, sponsored, nonce).await?,
                };
                if json {
                    let out = serde_json::json!({
                        "account": s.account.to_string(),
                        "userOpHash": inc.user_op_hash.to_string(),
                        "nonce": format!("{:#x}", inc.nonce),
                        "tx": inc.tx.to_string(),
                        "block": inc.block,
                        "gasUsed": inc.gas_used,
                    });
                    println!("{out}");
                } else {
                    println!("included: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
                }
            }
        },
        Cmd::Permission { cmd } => match cmd {
            PermissionCmd::Revoke { agent, id, sponsored } => {
                let s = session(&agent).await?;
                let inc = s.revoke_permission(parse_permission_id(&id)?, sponsored).await?;
                println!("revoked permission {id}: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            PermissionCmd::Rotate { agent, old_id, sponsored, dry_run } => {
                let s = session(&agent).await?;
                if !s.pinned {
                    bail!("pin the deployed account in the config (\"account\": \"0x…\") before rotating");
                }
                if dry_run {
                    println!("account:  {}", s.account);
                    println!("callData: {}", s.rotate_calldata(parse_permission_id(&old_id)?).await?);
                    return Ok(());
                }
                let inc = s.rotate_permission(parse_permission_id(&old_id)?, sponsored).await?;
                println!(
                    "rotated {old_id} -> {}: tx {} (block {}, {} gas)",
                    s.cfg.permission_id, inc.tx, inc.block, inc.gas_used
                );
            }
        },
        Cmd::Paymaster { cmd } => match cmd {
            PaymasterCmd::Deposit { agent, wei } => {
                let s = session(&agent).await?;
                let amount: U256 = wei.parse().context("--wei")?;
                let tx = s.paymaster_deposit(amount).await?;
                println!("deposited {amount} wei for the paymaster: tx {tx}");
            }
            PaymasterCmd::Sponsor { agent, budget, max_per_op, revoke } => {
                let s = session(&agent).await?;
                let (budget, max_per_op) = if revoke { (0, 0) } else { (budget, max_per_op) };
                if !revoke && (budget == 0 || max_per_op == 0) {
                    bail!("give --budget and --max-per-op in wei (or --revoke)");
                }
                let tx = s.sponsor(budget, max_per_op).await?;
                if revoke {
                    println!("delisted {}: tx {tx}", s.account);
                } else {
                    println!("sponsored {} (gas budget {budget} wei, max {max_per_op} wei per op): tx {tx}", s.account);
                }
            }
            PaymasterCmd::Stake { agent, wei, unstake_delay_sec } => {
                let s = session(&agent).await?;
                let amount: U256 = wei.parse().context("--wei")?;
                let tx = s.paymaster_stake(amount, unstake_delay_sec).await?;
                println!("staked {amount} wei (unstake delay {unstake_delay_sec}s): tx {tx}");
            }
        },
        Cmd::Demo { agent, sponsored } => {
            let s = session(&agent).await?;
            let before = s.counter().await?;
            let data = Bytes::from(abi::IDemoCounter::incrementCall::SELECTOR.to_vec());
            let inc = s.send_op(s.dep.demo_counter, U256::ZERO, data, false, sponsored, None).await?;
            let after = s.counter_at(inc.block).await?;
            println!("included: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            println!("counter:  {before} -> {after}");
        }
    }
    Ok(())
}

/// Text from a file that may come from Windows PowerShell 5.1, whose `>`
/// writes UTF-16 LE with a byte-order mark: accept UTF-16 (either order) and
/// UTF-8 with or without a BOM.
fn decode_text(bytes: &[u8]) -> Result<String> {
    let utf16 = |be: bool| -> Result<String> {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| if be { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16(&units).context("invalid UTF-16")
    };
    match bytes {
        [0xFF, 0xFE, ..] => utf16(false),
        [0xFE, 0xFF, ..] => utf16(true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => Ok(std::str::from_utf8(rest).context("invalid UTF-8")?.to_owned()),
        _ => Ok(std::str::from_utf8(bytes).context("invalid UTF-8")?.to_owned()),
    }
}
