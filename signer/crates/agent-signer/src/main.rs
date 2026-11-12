mod abi;
mod agent;
mod bundler;
mod chain;
use owner_core::kernel;
mod keyfile;
mod phone;
mod x402;

use std::path::{Path, PathBuf};

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
    /// YubiKey 5 PIV, an existing key by slot: `--label 9c` (`--features yubikey`); asks the PIN.
    Yubikey,
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
    #[command(flatten)]
    phone: PhoneSessionArgs,
}

/// The phone owner's LAN session (docs/MOBILE_OWNER_DESIGN.md §3.3).
#[derive(Args, Clone)]
struct PhoneSessionArgs {
    /// Phone owner: the address (and port) the one-shot LAN session binds to.
    /// Default: the default-route interface, an ephemeral port.
    #[arg(long)]
    listen: Option<std::net::SocketAddr>,
    /// Phone owner: seconds to wait for the phone's answer.
    #[arg(long, default_value_t = 120)]
    phone_timeout: u64,
    /// Phone owner: also write the QR's URI to this file (for tests and
    /// automation; the terminal shows the QR itself). Also read from
    /// TPMSIGN_PHONE_QR_FILE.
    #[arg(long)]
    phone_qr_file: Option<PathBuf>,
}

impl PhoneSessionArgs {
    fn configure(&self) {
        phone::configure(phone::PhoneOptions {
            listen: self.listen,
            timeout: std::time::Duration::from_secs(self.phone_timeout),
            qr_file: self.phone_qr_file.clone().or_else(|| std::env::var_os("TPMSIGN_PHONE_QR_FILE").map(PathBuf::from)),
        });
    }
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
    /// The owner side: root validator and the cold recovery key.
    Owner {
        #[command(subcommand)]
        cmd: OwnerCmd,
    },
    /// The agent permission, controlled by the owner key.
    Permission {
        #[command(subcommand)]
        cmd: PermissionCmd,
    },
    /// Pay for HTTP resources with x402, within the mandate's token limits.
    X402 {
        #[command(subcommand)]
        cmd: X402Cmd,
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
enum X402Cmd {
    /// GET a URL; on 402, register an authorization under the mandate, sign
    /// it with the agent key and retry with the payment.
    Fetch {
        #[command(flatten)]
        agent: AgentArgs,
        url: String,
        /// Refuse to pay more than this many base units (on top of the
        /// mandate's own per-op cap).
        #[arg(long)]
        max_amount: Option<String>,
        /// Let the paymaster pay the registration's gas.
        #[arg(long)]
        sponsored: bool,
    },
    /// Return to the budget the authorizations that expired unused.
    Reclaim {
        #[command(flatten)]
        agent: AgentArgs,
        /// Look for registrations from this block (default: the last 50,000).
        #[arg(long)]
        from_block: Option<u64>,
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
    /// Show what the chain enforces for the config's permission, field by
    /// field next to the config (read-only).
    Show {
        #[command(flatten)]
        agent: AgentArgs,
    },
    /// Install the permission the config describes alongside the existing
    /// ones — e.g. one window of a schedule (`policy.validAfter` …
    /// `validUntil`). Root operation signed by the owner key.
    Add {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        sponsored: bool,
        /// Print the batch calldata instead of sending it.
        #[arg(long)]
        dry_run: bool,
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
    /// YubiKey 5 PIV: key slot (9a, 9c, 9d, 9e or 82..95); `--yubikey` alone
    /// means 9c. Keys are generated with ykman (docs/YUBIKEY.md).
    #[arg(long, conflicts_with_all = ["handle", "enclave", "cng", "tropic01"], num_args = 0..=1, default_missing_value = "9c")]
    yubikey: Option<String>,
    /// YubiKey: serial number, to pick one of several plugged in.
    #[arg(long, requires = "yubikey")]
    serial: Option<u32>,
    /// Encrypted key file (owner / recovery keys only, e.g. on a USB drive):
    /// `create` asks for a passphrase and refuses to overwrite.
    #[arg(long, conflicts_with_all = ["handle", "enclave", "cng", "tropic01", "yubikey"])]
    keyfile: Option<PathBuf>,
    /// The owner's phone, by the label the key has in the config
    /// (docs/MOBILE_OWNER_DESIGN.md §2.1, §8.2): `create` enrolls a new key
    /// on the phone for the config's account, `show` prints the enrolled key.
    #[arg(long, conflicts_with_all = ["handle", "enclave", "cng", "tropic01", "yubikey", "keyfile"], requires = "agent")]
    phone: Option<String>,
    /// Phone: the agent config that names the account (`account` must be
    /// pinned) and, for `show`, the enrolled key.
    #[arg(long, requires = "phone")]
    agent: Option<PathBuf>,
}

#[derive(Subcommand)]
enum OwnerCmd {
    /// Root validator, and whether a recovery key is installed.
    Status {
        #[command(flatten)]
        agent: AgentArgs,
    },
    /// Install the config's `recovery` key, allowed only to take over root
    /// (owner operation, signed by the owner key).
    AddRecovery {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        sponsored: bool,
    },
    /// The owner key is lost: the recovery key makes itself root.
    Recover {
        #[command(flatten)]
        agent: AgentArgs,
        #[arg(long)]
        sponsored: bool,
    },
    /// Hand root to a new owner key on a validator the account has not used
    /// (signed by the current root: the owner key, or `--as-recovery`).
    SetRoot {
        #[command(flatten)]
        agent: AgentArgs,
        /// P256Validator instance not installed on this account yet.
        #[arg(long)]
        validator: Address,
        /// The new owner public key: `x,y` (hex), as `key show` prints it.
        #[arg(long)]
        public_key: String,
        /// The validator of the lost or replaced owner key: uninstalled in the
        /// same operation, so its key signs nothing any more (required after
        /// `recover`). May equal `--validator` to reuse that contract.
        #[arg(long)]
        retire: Option<Address>,
        /// The recovery key is root now (after `owner recover`).
        #[arg(long)]
        as_recovery: bool,
        /// Refuse unless `--public-key` has this fingerprint (`ABCDE-FGHIJ-KLMNO-PQRST`,
        /// as `key create --phone` prints it and the phone shows it): the
        /// handover goes to the key the owner saw, not to a pasted one.
        #[arg(long)]
        expect_fingerprint: Option<String>,
        #[arg(long)]
        sponsored: bool,
    },
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
        /// Phone: accept an enrollment without attestation evidence (a
        /// simulator, or a platform without it). The laptop then cannot
        /// place the key in hardware; the config snippet says so.
        #[arg(long, requires = "phone")]
        allow_no_attestation: bool,
        /// Phone: write the enrollment — the request, the phone's answer and
        /// the attestation certificates (DER) — into this directory, for the
        /// off-device check (docs/MOBILE_OWNER_DESIGN.md §5.2) and for scripts.
        #[arg(long, requires = "phone")]
        out: Option<PathBuf>,
        /// Phone: the fingerprint the phone will show (`ABCDE-FGHIJ-…`, at
        /// least two groups), given up front instead of typed when the
        /// answer arrives: an answer with another key is refused. For
        /// scripts that know the key they expect.
        #[arg(long, requires = "phone", conflicts_with = "phone_skip_fingerprint")]
        phone_fingerprint: Option<String>,
        /// Phone: do not ask for the fingerprint the phone shows. The answer
        /// is still authenticated by the secret in the QR, which a host on
        /// the network does not have; what is skipped is the check against
        /// someone who could also read the QR. By default the CLI asks,
        /// because an enrollment is followed by a root handover.
        #[arg(long, requires = "phone")]
        phone_skip_fingerprint: bool,
        #[command(flatten)]
        session: PhoneSessionArgs,
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
    /// Health check: open the key, sign a random digest and verify it — no
    /// transaction. For a key file this proves the passphrase still opens it.
    Check {
        #[command(flatten)]
        key: KeyRef,
        /// TPM: the key's auth file, for a key created with --auth-file.
        #[arg(long)]
        auth_file: Option<PathBuf>,
    },
    /// YubiKey: write the slot's attestation certificate (DER) — proof that
    /// the key was generated on this device, with its PIN and touch policies.
    /// Verify it off-device against Yubico's roots (docs/YUBIKEY.md).
    Attest {
        #[command(flatten)]
        key: KeyRef,
        /// Where to write the DER certificate (it names the device's serial
        /// number: keep it out of the repository).
        #[arg(long)]
        out: PathBuf,
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
        Backend::Yubikey => {
            let slot = label.unwrap_or_else(|| "9c".to_owned());
            #[cfg(feature = "yubikey")]
            {
                Ok(Box::new(agent::open_yubikey(None, &slot, agent::Role::Owner, true)?))
            }
            #[cfg(not(feature = "yubikey"))]
            {
                bail!("YubiKey PIV slot {slot}: needs `--features yubikey`")
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
    Check { auth_file: Option<PathBuf> },
}

/// Sign a random digest with `signer` and verify it against its public key.
fn check_signer(name: String, signer: &dyn HardwareSigner) -> Result<()> {
    use rand_core::RngCore;
    let mut digest = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut digest);
    let pk = signer.public_key()?;
    let sig = signer.sign_digest(&digest)?;
    if !verify_p256(&digest, &sig, &pk) {
        bail!("{name}: the signature does not verify against the key's public half");
    }
    println!("OK: {name} signs (0x{}…)", hex::encode(&pk.x[..4]));
    Ok(())
}

fn run_key(cmd: KeyCmd) -> Result<()> {
    let (key, op) = match cmd {
        KeyCmd::Create { key, parent, pcrs, auth_file, allow_no_attestation, out, phone_fingerprint, phone_skip_fingerprint, session } => {
            if let (Some(label), Some(cfg)) = (&key.phone, &key.agent) {
                session.configure();
                let confirm = match (phone_fingerprint, phone_skip_fingerprint) {
                    (Some(fp), _) => phone::FingerprintSource::Given(fp),
                    (None, true) => phone::FingerprintSource::Skipped,
                    (None, false) => phone::FingerprintSource::Prompt,
                };
                return phone_enroll(label, cfg, allow_no_attestation, out.as_deref(), confirm);
            }
            (key, KeyOp::Create { parent, pcrs, auth_file })
        }
        KeyCmd::Show { key } => (key, KeyOp::Show),
        KeyCmd::Evict { key } => (key, KeyOp::Evict),
        KeyCmd::Check { key, auth_file } => (key, KeyOp::Check { auth_file }),
        KeyCmd::Attest { key, out } => return yubikey_attest(key, &out),
    };
    if let (Some(label), Some(cfg)) = (&key.phone, &key.agent) {
        return phone_key(label, cfg, op);
    }
    if let Some(path) = key.keyfile {
        return keyfile_key(&path, op);
    }
    if let Some(slot) = key.yubikey {
        return yubikey_key(&slot, key.serial, op);
    }
    match (key.handle, key.enclave, key.cng, key.tropic01) {
        (Some(handle), None, None, None) => tpm_key(handle, op),
        (None, Some(label), None, None) => enclave_key(&label, op),
        (None, None, Some(name), None) => cng_key(&name, op),
        (None, None, None, Some(port)) => tropic01_key(&port, key.slot, op),
        _ => bail!(
            "give exactly one of --handle (TPM), --enclave <label> (Secure Enclave), --cng <name> (Windows TPM), --tropic01 <port> (TROPIC01), --yubikey [slot] (YubiKey PIV), --keyfile <path> or --phone <label> --agent <config>"
        ),
    }
}

/// `key create --phone <label> --agent <cfg>`: the enrollment session
/// (docs/MOBILE_OWNER_DESIGN.md §2.1). Prints the new key, its fingerprint
/// and the config snippet; nothing on-chain. The handover is the owner's
/// next step: `owner set-root … --expect-fingerprint <fp>`.
fn phone_enroll(
    label: &str,
    cfg_path: &Path,
    allow_no_attestation: bool,
    out: Option<&Path>,
    confirm: phone::FingerprintSource,
) -> Result<()> {
    if !owner_core::enroll::valid_key_label(label) {
        bail!("the phone key's label must be 1 to 64 characters of plain text (printable ASCII): the phone shows it");
    }
    let (cfg, base) = AgentConfig::load(cfg_path)?;
    let dep = cfg.load_deployments(&base)?;
    let account = cfg.account.context(
        "the enrollment names an existing account: pin `account` in the config first (`account status` prints it; \
         docs/MOBILE_OWNER_DESIGN.md §5.5)",
    )?;
    if matches!(confirm, phone::FingerprintSource::Prompt) && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("the owner confirms the fingerprint the phone shows, and this is not a terminal to ask on: pass --phone-fingerprint <fp>, or --phone-skip-fingerprint to rely on the QR's secret alone");
    }
    let pins = phone::laptop_pins(&dep);
    if !pins.is_empty() {
        eprintln!("names sent to the phone for addresses its build does not know (it shows them as unverified):");
        for (address, name) in &pins {
            eprintln!("  {address}  {name}");
        }
    }
    let confirmed = !matches!(confirm, phone::FingerprintSource::Skipped);
    let (request, answer, e) = phone::enroll(label, dep.chain_id, dep.entry_point, account, pins, allow_no_attestation, confirm)?;
    let fp = owner_core::fingerprint::fingerprint(&e.public_key);
    let (x, y) = (hex32(&e.public_key.x), hex32(&e.public_key.y));
    let evidence = if e.attestation.is_empty() {
        "none — the laptop cannot place this key in hardware".to_string()
    } else {
        format!(
            "{} certificates; verification against the platform's roots is the next step (design §5.2), so \
             the tier above is the phone's own word for now",
            e.attestation.len()
        )
    };
    let app = e.app.as_ref().map(|a| format!("{} {} (core {})", a.platform, a.version, a.core)).unwrap_or_else(|| "unknown".into());
    println!("enrolled phone owner key {label:?} for account {account} (chain {})", dep.chain_id);
    println!("  public key     x = {x}\n                 y = {y}");
    println!("  fingerprint    {fp}   {}", if confirmed { "(confirmed against the phone's screen)" } else { "← not confirmed here (--phone-skip-fingerprint): the phone shows the same one" });
    println!("  security level {} (self-reported){}", e.security_level, if e.device_credential { ", device PIN also unlocks" } else { "" });
    println!("  attestation    {evidence}");
    println!("  app            {app}");
    println!();
    println!("Nothing changed on-chain. Next, signed by the current owner key:");
    println!("  agent-signer owner set-root --agent {} --validator <P256Validator> --public-key {x},{y} --expect-fingerprint {fp} [--retire <validator>]", cfg_path.display());
    println!("then point the config's owner at the phone (ownerPublicKey stays the account's creation key):");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "owner": {"phone": {"label": label, "publicKey": {"x": x, "y": y}, "fingerprint": fp}}
        }))?
    );
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::write(dir.join("enroll-request.json"), &request)?;
        std::fs::write(dir.join("enroll-response.json"), &answer)?;
        for (i, der) in e.attestation.iter().enumerate() {
            std::fs::write(dir.join(format!("attest-{i}.der")), der)?;
        }
        eprintln!("enrollment written to {} ({} attestation certificates)", dir.display(), e.attestation.len());
    }
    Ok(())
}

/// `key show / check / evict --phone`: the phone's key lives on the phone;
/// `show` reads the config, the rest is not a laptop operation.
fn phone_key(label: &str, cfg_path: &Path, op: KeyOp) -> Result<()> {
    use agent::KeySpec;
    let (cfg, _) = AgentConfig::load(cfg_path)?;
    let spec = [Some(&cfg.owner), cfg.recovery.as_ref(), Some(&cfg.agent)]
        .into_iter()
        .flatten()
        .find(|k| matches!(k, KeySpec::Phone { label: l, .. } if l == label))
        .with_context(|| format!("no phone key labelled {label:?} in {}", cfg_path.display()))?;
    let KeySpec::Phone { public_key, fingerprint, .. } = spec else { unreachable!() };
    match op {
        KeyOp::Show => {
            let pk = public_key.parse()?;
            let actual = owner_core::fingerprint::fingerprint(&pk);
            print_key(format!("phone {label}"), &pk)?;
            if fingerprint.eq_ignore_ascii_case(&actual) {
                println!("fingerprint {actual}");
                Ok(())
            } else {
                bail!("the config's fingerprint {fingerprint} does not match the publicKey's ({actual})")
            }
        }
        KeyOp::Create { .. } => unreachable!("handled by phone_enroll"),
        KeyOp::Evict => bail!("a phone key is deleted on the phone, after a `set-root` away from it"),
        KeyOp::Check { .. } => bail!("the phone health check (design §2.4) is not implemented yet; a root operation on anvil is the check today"),
    }
}

#[cfg(feature = "yubikey")]
fn yubikey_key(slot: &str, serial: Option<u32>, op: KeyOp) -> Result<()> {
    use agent::Role;
    match op {
        KeyOp::Create { .. } => bail!(
            "YubiKey keys are generated by ykman, which holds the management key and fixes the PIN and touch \
             policies for the life of the key:\n  ykman piv keys generate -a ECCP256 --pin-policy ALWAYS \
             --touch-policy ALWAYS {slot} <pubkey.pem>\n(docs/YUBIKEY.md)"
        ),
        KeyOp::Evict => bail!("a PIV slot cannot be emptied, only overwritten: generate a new key into it with ykman"),
        KeyOp::Show => {
            let s = agent::open_yubikey(serial, slot, Role::Owner, false)?;
            print_key(yubikey_name(&s), &s.public_key()?)
        }
        KeyOp::Check { .. } => {
            let s = agent::open_yubikey(serial, slot, Role::Owner, true)?;
            check_signer(yubikey_name(&s), &s)
        }
    }
}

#[cfg(feature = "yubikey")]
fn yubikey_name(s: &hw_signer::yubikey_piv::YubiKeyPivSigner) -> String {
    format!(
        "YubiKey {} slot {} (PIN {:?}, touch {:?})",
        s.serial(),
        hw_signer::yubikey_piv::slot_name(s.slot()),
        s.pin_policy(),
        s.touch_policy()
    )
}

#[cfg(feature = "yubikey")]
fn yubikey_attest(key: KeyRef, out: &std::path::Path) -> Result<()> {
    let slot = key.yubikey.context("`key attest` is for YubiKey keys: --yubikey [slot]")?;
    let s = agent::open_yubikey(key.serial, &slot, agent::Role::Owner, false)?;
    let der = s.attestation()?;
    std::fs::write(out, &der).with_context(|| format!("writing {}", out.display()))?;
    println!("attestation certificate of slot {slot} ({} bytes DER) written to {}", der.len(), out.display());
    println!("it names the device's serial number: keep it out of the repository");
    println!(
        "verify: openssl x509 -inform DER -in {out} -out slot.pem && ykman piv certificates export f9 f9.pem && \
         openssl verify -CAfile yubico-ca-1.pem -untrusted yubico-intermediate.pem -untrusted f9.pem slot.pem  (docs/YUBIKEY.md)",
        out = out.display()
    );
    Ok(())
}

#[cfg(not(feature = "yubikey"))]
fn yubikey_key(slot: &str, _: Option<u32>, _: KeyOp) -> Result<()> {
    bail!("YubiKey PIV slot {slot}: needs `--features yubikey`")
}

#[cfg(not(feature = "yubikey"))]
fn yubikey_attest(_: KeyRef, _: &std::path::Path) -> Result<()> {
    bail!("`key attest` needs `--features yubikey`")
}

#[cfg(feature = "tropic01")]
fn tropic01_key(port: &str, slot: u16, op: KeyOp) -> Result<()> {
    use hw_signer::tropic01::Tropic01Signer;
    let name = format!("{port} slot {slot}");
    match op {
        KeyOp::Create { .. } => print_key(name, &Tropic01Signer::create(port, slot)?.public_key()?),
        KeyOp::Show => print_key(name, &Tropic01Signer::open(port, slot)?.public_key()?),
        KeyOp::Check { .. } => check_signer(name, &Tropic01Signer::open(port, slot)?),
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
        KeyOp::Check { .. } => check_signer(name.into(), &CngSigner::open(name)?),
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
        KeyOp::Check { auth_file } => match auth_file {
            Some(file) => {
                let secret = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
                check_signer(name, &TpmSigner::open_persistent_protected(handle, &secret)?)
            }
            None => check_signer(name, &TpmSigner::open_persistent(handle)?),
        },
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

/// An encrypted key file: created with a passphrase typed twice; its public
/// key is readable without one. There is nothing to evict: delete the file.
fn keyfile_key(path: &std::path::Path, op: KeyOp) -> Result<()> {
    let name = path.display().to_string();
    match op {
        KeyOp::Create { .. } => {
            eprintln!("creating {name}: choose a passphrase; it is never stored and cannot be recovered");
            let passphrase = keyfile::prompt(true)?;
            let pk = keyfile::create(path, passphrase.as_bytes())?;
            eprintln!("reference it as {{\"keyfile\": \"{name}\"}}; keep a second copy on another medium");
            print_key(name, &pk)
        }
        KeyOp::Show => print_key(name, &keyfile::public_key(path)?),
        KeyOp::Check { .. } => {
            let passphrase = keyfile::prompt(false)?;
            check_signer(name, &keyfile::open(path, passphrase.as_bytes())?)
        }
        KeyOp::Evict => bail!("a key file is not stored in a device: delete {name} yourself if you mean to"),
    }
}

#[cfg(all(feature = "secure-enclave", target_os = "macos"))]
fn enclave_key(label: &str, op: KeyOp) -> Result<()> {
    use hw_signer::secure_enclave::SecureEnclaveSigner;
    match op {
        KeyOp::Create { .. } => print_key(label.into(), &SecureEnclaveSigner::create(label)?.public_key()?),
        KeyOp::Show => print_key(label.into(), &SecureEnclaveSigner::open(label)?.public_key()?),
        KeyOp::Check { .. } => check_signer(label.into(), &SecureEnclaveSigner::open(label)?),
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
    args.phone.configure();
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
        Cmd::Owner { cmd } => match cmd {
            OwnerCmd::Status { agent } => session(&agent).await?.owner_status().await?,
            OwnerCmd::AddRecovery { agent, sponsored } => {
                let s = session(&agent).await?;
                let spec = s.cfg.recovery.as_ref().context("the config has no `recovery` key")?;
                let key = match spec {
                    agent::KeySpec::Keyfile(path) => keyfile::public_key(path)?,
                    other => agent::open_signer(other, agent::Role::Recovery)?.public_key()?,
                };
                let inc = s.add_recovery(&key, sponsored).await?;
                println!("recovery key installed: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            OwnerCmd::Recover { agent, sponsored } => {
                let s = session(&agent).await?;
                let inc = s.recover(sponsored).await?;
                println!("the recovery key is root now: tx {}; next, `owner set-root --as-recovery` to a new owner device", inc.tx);
            }
            OwnerCmd::SetRoot { agent, validator, public_key, retire, as_recovery, expect_fingerprint, sponsored } => {
                let (x, y) = public_key.split_once(',').context("--public-key x,y")?;
                let key = hw_signer::PublicKey { x: agent::parse32(x.trim())?, y: agent::parse32(y.trim())? };
                if !hw_signer::valid_public_key(&key) {
                    bail!("--public-key is not a point on P-256; a handover to it would lose the account");
                }
                let fp = owner_core::fingerprint::fingerprint(&key);
                if let Some(expected) = &expect_fingerprint {
                    if !expected.eq_ignore_ascii_case(&fp) {
                        bail!("--public-key has fingerprint {fp}, not the expected {expected}: not the key the owner saw; nothing sent");
                    }
                }
                let s = session(&agent).await?;
                eprintln!("new root key:   fingerprint {fp}");
                let inc = s.set_root(validator, &key, retire, as_recovery, sponsored).await?;
                println!("root handed to {validator}: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
        },
        Cmd::Permission { cmd } => match cmd {
            PermissionCmd::Revoke { agent, id, sponsored } => {
                let s = session(&agent).await?;
                let inc = s.revoke_permission(parse_permission_id(&id)?, sponsored).await?;
                println!("revoked permission {id}: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            PermissionCmd::Show { agent } => session(&agent).await?.permission_show().await?,
            PermissionCmd::Add { agent, sponsored, dry_run } => {
                let s = session(&agent).await?;
                if !s.pinned {
                    bail!("pin the deployed account in the config (\"account\": \"0x…\") before adding a permission");
                }
                if dry_run {
                    println!("account:  {}", s.account);
                    println!("callData: {}", s.add_calldata().await?);
                    return Ok(());
                }
                let inc = s.add_permission(sponsored).await?;
                println!(
                    "added permission {} (valid {} … {}): tx {} (block {}, {} gas)",
                    s.cfg.permission_id,
                    s.cfg.policy.valid_after,
                    s.cfg.policy.valid_until,
                    inc.tx,
                    inc.block,
                    inc.gas_used
                );
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
        Cmd::X402 { cmd } => match cmd {
            X402Cmd::Fetch { agent, url, max_amount, sponsored } => {
                let s = session(&agent).await?;
                let max = max_amount.map(|m| m.parse::<U256>()).transpose().context("--max-amount")?;
                let paid = s.x402_fetch(&url, max, sponsored).await?;
                eprintln!("status:         {}", paid.status);
                if let Some(a) = &paid.authorization {
                    eprintln!("authorization:  nonce {} (valid before {})", a.nonce, a.valid_before);
                }
                if let Some(r) = &paid.settlement {
                    eprintln!("settlement:     {r}");
                }
                println!("{}", paid.body);
                if paid.status >= 400 {
                    std::process::exit(1);
                }
            }
            X402Cmd::Reclaim { agent, from_block, sponsored } => {
                let s = session(&agent).await?;
                let done = s.x402_reclaim(from_block, sponsored).await?;
                println!("reclaimed {} expired authorization(s)", done.len());
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
