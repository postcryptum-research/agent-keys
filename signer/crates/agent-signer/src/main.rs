mod abi;
mod agent;
mod bundler;
mod chain;
use owner_core::kernel;
mod keyfile;
mod attestation;
mod der;
mod phone;
mod possession;
mod order;
mod x402;

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(feature = "insecure-software-keys")]
use hw_signer::software::SoftwareSigner;
use hw_signer::{verify_p256, HardwareSigner, PublicKey, Signature};
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
    /// Place orders at a trading venue, within the mandate's terms.
    Order {
        #[command(subcommand)]
        cmd: OrderCmd,
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
enum OrderCmd {
    /// Register a sell order under the mandate, sign it with the agent key
    /// and print it as the venue's order book takes it. Sends it nowhere.
    Sell {
        #[command(flatten)]
        agent: AgentArgs,
        /// The venue's decoder, when the config has several venues.
        #[arg(long)]
        venue: Option<Address>,
        /// The token sold and the token bought.
        #[arg(long)]
        sell: Address,
        #[arg(long)]
        buy: Address,
        /// Base units sold: all of it or nothing.
        #[arg(long)]
        sell_amount: String,
        /// The least base units to receive for it.
        #[arg(long)]
        buy_amount: String,
        /// How long the order lives, seconds from the chain's latest block.
        #[arg(long, default_value_t = 600)]
        valid_for: u32,
        /// Let the paymaster pay the registration's gas.
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
        /// Look for registrations from this block, the one `x402 fetch` printed
        /// (default: the last 50,000 blocks).
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
        /// The config the permission was installed from, when this one no
        /// longer holds its venue's terms: its allowances are taken back.
        #[arg(long)]
        old_config: Option<PathBuf>,
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
    /// Set the allowance of each venue in the config back to one budget of
    /// the token it sells. Root operation signed by the owner key. The venue
    /// takes tokens through this allowance, not through the mandate, so it
    /// is never more than one budget; under a mandate with a period the
    /// owner renews it.
    Allowance {
        #[command(flatten)]
        agent: AgentArgs,
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
        /// The config the old permission was installed from, when this one
        /// no longer holds its venue's terms: the allowances the new
        /// mandate does not take over are taken back in the same operation.
        #[arg(long)]
        old_config: Option<PathBuf>,
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
    /// Replace the installed recovery key with the config's `recovery` key
    /// (owner operation, signed by the owner key): for a recovery file that
    /// was stolen, lost, or changes hands. The old key can sign nothing
    /// afterwards.
    ReplaceRecovery {
        #[command(flatten)]
        agent: AgentArgs,
        /// Do not open the new recovery key. By default it is opened here
        /// and signs a fresh digest before anything is sent (a key file
        /// asks for its passphrase): a recovery key that cannot sign is
        /// otherwise found out when it is needed, with the owner key
        /// already gone. With this flag only its public half is read, as
        /// `add-recovery` does, and the key stays cold.
        #[arg(long)]
        skip_key_check: bool,
        #[arg(long)]
        sponsored: bool,
    },
    /// Remove the recovery key and install none (owner operation). After
    /// it, losing the owner key loses the account, and the key of the root
    /// validator cannot be replaced in place (`set-root --retire` of the
    /// same validator stands on the recovery validator meanwhile).
    RemoveRecovery {
        #[command(flatten)]
        agent: AgentArgs,
        /// Required: says that the account is to be left without a recovery key.
        #[arg(long)]
        leave_no_recovery: bool,
        /// Remove the key from this earlier recovery validator, one the
        /// deployments file keeps as `p256RecoveryValidatorV<n>` after a
        /// redeploy, instead of from the current one. After `owner
        /// add-recovery` has installed the key on the current validator, this
        /// leaves the account with that one and needs no --leave-no-recovery
        /// (docs/REDEPLOY.md).
        #[arg(long)]
        earlier: Option<Address>,
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
        /// Not needed with `--new-key`, which reads it from the key.
        #[arg(long, required_unless_present = "new_key")]
        public_key: Option<String>,
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
        /// The new key is the phone key with this label (`key create --phone`).
        /// Before anything is sent, the phone must show that it holds the
        /// key, by signing a fresh digest in a session of its own (the
        /// health check, `key check --phone`). An enrollment the phone did
        /// not keep stops here, not after root has gone to a key nobody
        /// holds. One of this and `--not-a-phone` is required.
        #[arg(long, requires = "public_key")]
        to_phone: Option<String>,
        /// The new key is not a phone's key, so no phone is asked to show
        /// it. One of this and `--to-phone` is required: the command cannot
        /// tell a phone's key from any other pasted `--public-key`, and
        /// root handed to a key nobody holds takes the account with it.
        /// The key shows that it can sign before anything is sent (issue
        /// #51): with `--new-key` in this command, or else the command
        /// prints a challenge, `key prove` answers it on the machine that
        /// holds the key, and the proof is pasted back here.
        #[arg(long, conflicts_with = "to_phone")]
        not_a_phone: bool,
        /// The new key is on this machine: the key as a config names it and
        /// `key create` prints it, e.g. '{"yubikey": {"slot": "9c"}}' or
        /// '{"tpm": "0x81010010"}'. It signs the proof of possession here,
        /// so one command does both, and `--public-key` is read from it.
        #[arg(long, requires = "not_a_phone", conflicts_with = "no_proof_of_possession")]
        new_key: Option<String>,
        /// Seconds the new key has to answer the challenge.
        #[arg(long, default_value_t = 900)]
        proof_timeout: u64,
        /// Hand the root over although the new key has not shown that it
        /// can sign. A fingerprint only tells which public key was pasted.
        /// If nobody can sign with the key — the private key is lost, was
        /// never made, or is on a device that no longer works — the
        /// account goes with it, unless a recovery key is installed and
        /// under control. Without this flag such a handover is refused.
        #[arg(long, requires = "not_a_phone")]
        no_proof_of_possession: bool,
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
        /// file only root can read (docs/KEY_POLICY.md, rule 3); refused
        /// unless group and others have no access to it (mode 0600).
        #[arg(long)]
        auth_file: Option<PathBuf>,
        /// Phone: accept an enrollment without attestation evidence (a
        /// simulator, or a platform without it). The laptop then cannot
        /// place the key in hardware; the config snippet says so.
        #[arg(long, requires = "phone", conflicts_with = "require_strongbox")]
        allow_no_attestation: bool,
        /// Phone: refuse a key that the attestation places in the
        /// processor's trusted mode (TEE) instead of a StrongBox
        /// (docs/MOBILE_OWNER_DESIGN.md §5.6). Decided on the attestation,
        /// never on the phone's own word.
        #[arg(long, requires = "phone")]
        require_strongbox: bool,
        /// Phone: refuse the enrollment when Google's list of revoked
        /// attestation certificates cannot be fetched. Without this the
        /// result and the config say "not checked".
        #[arg(long, requires = "phone", conflicts_with = "allow_no_attestation")]
        require_revocation_check: bool,
        /// Phone: accept a key from a phone whose verified boot state is
        /// Unverified. The integrity of its operating system is then not
        /// guaranteed, so this gives up the app's identity and the trust in
        /// the screen the fingerprint was read from; the hardware facts of
        /// the attestation still hold. A custom system on a locked
        /// bootloader (SelfSigned) needs no flag; a failed boot or an
        /// unlocked bootloader is refused with or without it.
        #[arg(long, requires = "phone", conflicts_with = "allow_no_attestation")]
        allow_unverified_boot: bool,
        /// Phone: also accept the app when its signing certificate has this
        /// SHA-256 digest (hex, colons allowed) — your own build of the
        /// app. The attestation names the certificate; a digest that is
        /// neither pinned in this CLI nor given here is refused, with the
        /// digest printed. May be repeated.
        #[arg(long, requires = "phone")]
        android_app_digest: Vec<String>,
        /// Phone: write the enrollment — the request, the phone's answer and
        /// the attestation certificates (DER) — into this directory, for the
        /// off-device check (docs/MOBILE_OWNER_DESIGN.md §5.2) and for scripts.
        /// Each file is written with mode 0600.
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
    /// Remove the key from the secure element. It cannot be undone, so the
    /// key at the place named is shown first and removed only with `--yes`.
    Evict {
        #[command(flatten)]
        key: KeyRef,
        /// Remove the key shown. Without it the command shows the key and
        /// removes nothing.
        #[arg(long)]
        yes: bool,
    },
    /// Health check: open the key, sign a random digest and verify it — no
    /// transaction. For a key file this proves the passphrase still opens it.
    /// For a phone it is a session: the phone signs a digest it
    /// co-randomizes, which shows that it still holds the key.
    Check {
        #[command(flatten)]
        key: KeyRef,
        /// TPM: the key's auth file, for a key created with --auth-file.
        #[arg(long)]
        auth_file: Option<PathBuf>,
        /// TPM: the PCRs the key is sealed to, for a key created with --pcrs.
        /// The check then also shows that the measured boot state is still
        /// the one the key was created under.
        #[arg(long, value_delimiter = ',')]
        pcrs: Vec<u8>,
        #[command(flatten)]
        session: PhoneSessionArgs,
    },
    /// Show that this machine holds a key, for a root handover made on
    /// another machine (`owner set-root --not-a-phone`, which prints the
    /// challenge): the key signs the challenge, and the proof printed here
    /// is pasted there. Nothing is sent anywhere.
    Prove {
        /// The key, as a config names it and `key create` prints it, e.g.
        /// '{"yubikey": {"slot": "9c"}}' or '{"tpm": "0x81010010"}'.
        #[arg(long)]
        key: String,
        /// The challenge line `owner set-root` printed.
        #[arg(long)]
        challenge: String,
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
    fingerprint: String,
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
        Backend::Software => {
            #[cfg(feature = "insecure-software-keys")]
            {
                Ok(Box::new(SoftwareSigner::random()))
            }
            #[cfg(not(feature = "insecure-software-keys"))]
            {
                bail!("the software backend is not in this build (tests only: `--features insecure-software-keys`); name a hardware one with --backend")
            }
        }
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
    let fingerprint = owner_core::fingerprint::fingerprint(pk);
    println!("{}", serde_json::to_string_pretty(&KeyInfo { key, x: hex32(&pk.x), y: hex32(&pk.y), fingerprint })?);
    Ok(())
}

enum KeyOp {
    Create { parent: u32, pcrs: Vec<u8>, auth_file: Option<PathBuf> },
    Show,
    Evict { yes: bool },
    Check { auth_file: Option<PathBuf>, pcrs: Vec<u8> },
}

/// Whether `key evict` goes on. Removing a key from a device cannot be
/// undone, and a mistyped handle or label names another key: the key at
/// `name` is shown, and it is removed only when the command carries `--yes`.
/// A place whose key cannot be read is said so, and still needs `--yes`.
#[cfg_attr(not(any(feature = "tpm", feature = "tropic01", feature = "secure-enclave", feature = "windows-tpm")), allow(dead_code))]
fn may_evict(name: &str, key: Result<PublicKey>, yes: bool) -> bool {
    match key {
        Ok(pk) => eprintln!("the key at {name}:\n  {}", chain::key_text(&pk, "  ")),
        Err(e) => eprintln!("the key at {name} could not be read ({e:#})"),
    }
    if !yes {
        eprintln!("nothing was removed. Removing a key cannot be undone: if this is the key you mean, run the command again with --yes");
    }
    yes
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
    println!("OK: {name} signs\n  {}", chain::key_text(&pk, "  "));
    Ok(())
}

/// A key named as a config names it (what `key create` prints), opened as an
/// owner key is: the key a root handover goes to (issue #51).
fn open_key_spec(spec: &str) -> Result<Box<dyn HardwareSigner>> {
    const FORM: &str =
        "the key, as a config names it and `key create` prints it, e.g. '{\"yubikey\": {\"slot\": \"9c\"}}' or '{\"tpm\": \"0x81010010\"}'";
    // before the spec is read in full: a phone's spec needs fields this proof has no use for
    let named: serde_json::Value = serde_json::from_str(spec).context(FORM)?;
    if named.get("phone").is_some() {
        bail!("a phone shows that it holds its key in a session of its own: `owner set-root --to-phone <label>`");
    }
    let spec: agent::KeySpec = serde_json::from_value(named).context(FORM)?;
    agent::open_signer(&spec, agent::Role::Owner)
}

/// `key prove`: the key's half of the proof of possession (issue #51).
fn prove_key(spec: &str, challenge: &str) -> Result<()> {
    let challenge = possession::Challenge::parse(challenge)?;
    eprintln!(
        "asked to show that this machine holds the key {}\n  for account {} on chain {}\n  \
         this is the step before that account's root is handed to the key; nothing is sent from here",
        owner_core::fingerprint::fingerprint(&challenge.key),
        challenge.account,
        challenge.chain_id
    );
    let at = possession::now()?;
    if at > challenge.expires {
        eprintln!("  note: by this machine's clock the challenge expired {} s ago; the machine that asked decides", at.saturating_sub(challenge.expires));
    } else {
        eprintln!("  the challenge is good for another {} s", challenge.expires.saturating_sub(at));
    }
    let signer = open_key_spec(spec)?;
    println!("{}", challenge.prove(signer.as_ref())?);
    eprintln!("paste the line above where `owner set-root` is waiting");
    Ok(())
}

/// The new key is on another machine (issue #51): print the challenge, and
/// read the proof that `key prove` printed there. A line that is not the
/// proof (the wrong line, a paste cut short) is said to be so and the next
/// one is read, until one verifies or the challenge expires: a bad paste
/// does not cost a new challenge and a second trip to the other machine.
fn ask_for_proof(challenge: &possession::Challenge, seconds: u64) -> Result<()> {
    eprintln!(
        "\nBefore the root goes to this key, the key shows that it can sign. On the machine that holds it, run\n\n  \
         agent-signer key prove --key '<the key, as a config names it>' --challenge <the line below>\n\n\
         and paste the line that command prints here, within {seconds} s. For a key on this machine,\n\
         --new-key '<the key>' does both in one command.\n\nchallenge:"
    );
    println!("{}", challenge.line());
    let mut refused = false;
    loop {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).context("reading the proof of possession")? == 0 {
            if refused {
                bail!("no proof was accepted; nothing sent");
            }
            bail!(
                "no proof of possession, and the root is not handed to a key that has not shown it can sign: a key nobody \
                 can sign with takes the account with it. Give the proof (`key prove` on the key's machine, or --new-key \
                 for a key on this one), or say --no-proof-of-possession. Nothing sent"
            );
        }
        // the clock first: once the challenge has expired, any line ends the wait, an empty one too
        let at = possession::now()?;
        if line.trim().is_empty() {
            if at > challenge.expires {
                bail!("the challenge expired {} s ago and no proof was accepted: run the command again. Nothing sent", at.saturating_sub(challenge.expires));
            }
            continue;
        }
        match challenge.verify(&line, at) {
            Ok(()) => return Ok(()),
            Err(e) if at > challenge.expires => return Err(e.context("nothing sent")),
            Err(e) => {
                refused = true;
                eprintln!("not accepted: {e:#}\npaste the proof again ({} s left), or end the command", challenge.expires.saturating_sub(at));
            }
        }
    }
}

fn run_key(cmd: KeyCmd) -> Result<()> {
    let (key, op) = match cmd {
        KeyCmd::Create {
            key,
            parent,
            pcrs,
            auth_file,
            allow_no_attestation,
            require_strongbox,
            require_revocation_check,
            allow_unverified_boot,
            android_app_digest,
            out,
            phone_fingerprint,
            phone_skip_fingerprint,
            session,
        } => {
            if let (Some(label), Some(cfg)) = (&key.phone, &key.agent) {
                session.configure();
                let confirm = match (phone_fingerprint, phone_skip_fingerprint) {
                    (Some(fp), _) => phone::FingerprintSource::Given(fp),
                    (None, true) => phone::FingerprintSource::Skipped,
                    (None, false) => phone::FingerprintSource::Prompt,
                };
                let policy = phone::AttestationPolicy {
                    allow_none: allow_no_attestation,
                    signing_digests: android_app_digest.iter().map(|d| attestation::parse_digest(d)).collect::<Result<_, _>>().map_err(|e| anyhow::anyhow!("--android-app-digest: {e}"))?,
                    require_strongbox,
                    require_revocation_check,
                    allow_unverified_boot,
                };
                return phone_enroll(label, cfg, &policy, out.as_deref(), confirm);
            }
            (key, KeyOp::Create { parent, pcrs, auth_file })
        }
        KeyCmd::Show { key } => (key, KeyOp::Show),
        KeyCmd::Evict { key, yes } => (key, KeyOp::Evict { yes }),
        KeyCmd::Check { key, auth_file, pcrs, session } => {
            session.configure();
            (key, KeyOp::Check { auth_file, pcrs })
        }
        KeyCmd::Prove { key, challenge } => return prove_key(&key, &challenge),
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
    policy: &phone::AttestationPolicy,
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
    let phone::Enrolled { request, answer, enrollment: e, evidence } =
        phone::enroll(label, dep.chain_id, dep.entry_point, account, pins, policy, confirm)?;
    let fp = owner_core::fingerprint::fingerprint(&e.public_key);
    let (x, y) = (hex32(&e.public_key.x), hex32(&e.public_key.y));
    let app = e.app.as_ref().map(|a| format!("{} {} (core {})", a.platform, a.version, a.core)).unwrap_or_else(|| "unknown".into());
    let pin = if e.device_credential { ", device PIN also unlocks" } else { "" };
    println!("enrolled phone owner key {label:?} for account {account} (chain {})", dep.chain_id);
    println!("  public key     x = {x}\n                 y = {y}");
    println!("  fingerprint    {fp}   {}", if confirmed { "(confirmed against the phone's screen)" } else { "← not confirmed here (--phone-skip-fingerprint): the phone shows the same one" });
    // what the config records about the key's hardware: the attested tier, or that there is no
    // evidence; and whether the chain was checked against the revocation list at that time
    let revocation = match &evidence {
        Some(ev) if ev.revocation.is_ok() => "checked",
        _ => "not checked",
    };
    let boot_state = evidence.as_ref().map(|ev| ev.attested.boot_state.as_str()).unwrap_or("none");
    let attestation = match &evidence {
        Some(ev) => {
            let a = &ev.attested;
            let tier = match a.tier {
                attestation::Tier::StrongBox => "strongbox — a separate secure chip",
                attestation::Tier::Tee => "tee — the processor's trusted mode, not a separate secure chip",
            };
            println!("  security level {tier} (attested){pin}");
            println!(
                "  attestation    verified: {} certificates to {}; made for this request; the key is the one above; \
                 generated in the hardware, signs only after a biometric check",
                a.chain_len, a.root
            );
            println!(
                "  made by        {} version code {}, signing certificate {}{}",
                a.package,
                a.version_code,
                hex::encode(a.signing_digest),
                if attestation::PINNED_SIGNING_DIGESTS.contains(&a.signing_digest) { " (pinned)" } else { " (accepted by --android-app-digest)" }
            );
            println!("  boot state     {} (the phone's operating system, as its verified boot reports it)", a.boot_state.as_str());
            match &ev.revocation {
                Ok(entries) => println!("  revocation     none of the chain is on Google's list ({entries} entries, fetched now)"),
                Err(why) => println!("  revocation     NOT checked ({why}): the config will say so; --require-revocation-check refuses instead"),
            }
            for w in &a.warnings {
                println!("  warning        {w}");
            }
            println!("  note           attestation is evidence of where the key lives, not of whose phone it is; that is the QR's secret");
            a.tier.as_str()
        }
        None => {
            println!("  security level {} (the phone's own word){pin}", e.security_level);
            println!("  attestation    none — the laptop cannot place this key in hardware");
            "none"
        }
    };
    println!("  app            {app}");
    println!();
    println!("Nothing changed on-chain. Next, signed by the current owner key:");
    println!("  agent-signer owner set-root --agent {} --validator <P256Validator> --public-key {x},{y} --expect-fingerprint {fp} --to-phone {label} [--retire <validator>]", cfg_path.display());
    println!("--to-phone makes the handover wait for the phone: one more QR, on which the phone shows that it holds this key.");
    println!("Do not hand root to a phone key without it: if the phone did not keep the key, the account goes with it.");
    println!("then point the config's owner at the phone (ownerPublicKey stays the account's creation key):");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "owner": {"phone": {
                "label": label,
                "platform": e.app.as_ref().map(|a| a.platform.as_str()).unwrap_or("unknown"),
                "attestation": attestation,
                "revocation": revocation,
                "bootState": boot_state,
                "deviceCredential": e.device_credential,
                "publicKey": {"x": x, "y": y},
                "fingerprint": fp,
            }}
        }))?
    );
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        // the records identify the phone: owner-only
        agent::write_private(&dir.join("enroll-request.json"), &request)?;
        agent::write_private(&dir.join("enroll-response.json"), &answer)?;
        for (i, der) in e.attestation.iter().enumerate() {
            agent::write_private(&dir.join(format!("attest-{i}.der")), der)?;
        }
        eprintln!("enrollment written to {} ({} attestation certificates)", dir.display(), e.attestation.len());
    }
    Ok(())
}

/// `key show / check / evict --phone`: the phone's key lives on the phone;
/// `show` reads the config, the rest is not a laptop operation.
fn phone_key(label: &str, cfg_path: &Path, op: KeyOp) -> Result<()> {
    use agent::KeySpec;
    let (cfg, base) = AgentConfig::load(cfg_path)?;
    let spec = [Some(&cfg.owner), cfg.recovery.as_ref(), Some(&cfg.agent)]
        .into_iter()
        .flatten()
        .find(|k| matches!(k, KeySpec::Phone { label: l, .. } if l == label))
        .with_context(|| format!("no phone key labelled {label:?} in {}", cfg_path.display()))?;
    let KeySpec::Phone { public_key, fingerprint, attestation, revocation, boot_state, .. } = spec else { unreachable!() };
    match op {
        KeyOp::Show => {
            let pk = public_key.parse()?;
            let actual = owner_core::fingerprint::fingerprint(&pk);
            print_key(format!("phone {label}"), &pk)?;
            if fingerprint.eq_ignore_ascii_case(&actual) {
                println!("fingerprint {actual}");
                println!("attestation {}", attestation.as_deref().unwrap_or("not recorded"));
                println!("revocation  {}", revocation.as_deref().unwrap_or("not recorded"));
                println!("boot state  {}", boot_state.as_deref().unwrap_or("not recorded"));
                Ok(())
            } else {
                bail!("the config's fingerprint {fingerprint} does not match the publicKey's ({actual})")
            }
        }
        KeyOp::Create { .. } => unreachable!("handled by phone_enroll"),
        KeyOp::Evict { .. } => bail!(
            "a phone key is deleted on the phone, after a `set-root` away from it: in the owner app, Delete on that enrollment \
             (it asks twice, then for the biometric check). Look at `owner status` first: a key that is still the root key \
             takes the account with it"
        ),
        KeyOp::Check { .. } => {
            let pk = public_key.parse()?;
            let account = cfg.account.context("the health check names the account the key is for: pin `account` in the config first")?;
            phone::prove_possession(label, cfg.load_deployments(&base)?.chain_id, account, &pk)?;
            println!("OK: phone {label} holds its key {} (signed a fresh digest)", owner_core::fingerprint::fingerprint(&pk));
            Ok(())
        }
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
        KeyOp::Evict { .. } => bail!("a PIV slot cannot be emptied, only overwritten: generate a new key into it with ykman"),
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
    agent::write_private(out, &der)?;
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
        KeyOp::Evict { yes } => {
            let signer = Tropic01Signer::open(port, slot)?;
            if may_evict(&name, signer.public_key().map_err(Into::into), yes) {
                signer.erase()?;
                println!("erased {name}");
            }
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
        KeyOp::Evict { yes } => {
            let signer = CngSigner::open(name)?;
            if may_evict(name, signer.public_key().map_err(Into::into), yes) {
                signer.delete()?;
                println!("deleted {name}");
            }
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
                    let secret = agent::read_auth_file(file)?;
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
        KeyOp::Check { auth_file, pcrs } => match (auth_file, pcrs.is_empty()) {
            (Some(file), true) => {
                let secret = agent::read_auth_file(&file)?;
                check_signer(name, &TpmSigner::open_persistent_protected(handle, &secret)?)
            }
            (None, false) => check_signer(name, &TpmSigner::open_persistent_sealed(handle, &pcrs)?),
            // a sealed key opened plainly is named by the backend (#49); every other
            // refusal keeps the TPM's words
            (None, true) => check_signer(name, &TpmSigner::open_persistent(handle)?),
            (Some(_), false) => bail!("--auth-file and --pcrs do not combine"),
        },
        KeyOp::Evict { yes } => {
            // a handle is typed by hand: show which key is there before it is gone for good (#178)
            let key = TpmSigner::open_persistent(handle).and_then(|s| s.public_key()).map_err(Into::into);
            if may_evict(&name, key, yes) {
                TpmSigner::evict(handle)?;
                println!("evicted {name}");
            }
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
        KeyOp::Evict { .. } => bail!("a key file is not stored in a device: delete {name} yourself if you mean to"),
    }
}

#[cfg(all(feature = "secure-enclave", target_os = "macos"))]
fn enclave_key(label: &str, op: KeyOp) -> Result<()> {
    use hw_signer::secure_enclave::SecureEnclaveSigner;
    match op {
        KeyOp::Create { .. } => print_key(label.into(), &SecureEnclaveSigner::create(label)?.public_key()?),
        KeyOp::Show => print_key(label.into(), &SecureEnclaveSigner::open(label)?.public_key()?),
        KeyOp::Check { .. } => check_signer(label.into(), &SecureEnclaveSigner::open(label)?),
        KeyOp::Evict { yes } => {
            let signer = SecureEnclaveSigner::open(label)?;
            if may_evict(label, signer.public_key().map_err(Into::into), yes) {
                signer.delete()?;
                println!("deleted {label}");
            }
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

/// The stack the CLI runs on. An unoptimized build needs more than 1 MiB for
/// the command dispatch below, and 1 MiB is all a Windows process's main
/// thread has: there a debug build overflowed its stack on every command,
/// `key show` included. The work therefore runs on a thread whose stack is
/// stated here, the same on every platform.
const STACK_BYTES: usize = 16_777_216;

fn main() -> Result<()> {
    let work = std::thread::Builder::new().stack_size(STACK_BYTES).spawn(|| {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().context("starting the runtime")?.block_on(run())
    })?;
    match work.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn run() -> Result<()> {
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
                if let Some(staker) = s.factory_staker().await? {
                    println!("staker:   {staker}");
                }
                println!("salt:     {}", s.cfg.salt()?);
                println!("initData: {}", s.init_data()?);
                println!("initCode: {}", s.init_code().await?);
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
            OwnerCmd::ReplaceRecovery { agent, skip_key_check, sponsored } => {
                let s = session(&agent).await?;
                let spec = s.cfg.recovery.as_ref().context("the config has no `recovery` key")?;
                let key = match spec {
                    agent::KeySpec::Keyfile(path) => keyfile::public_key(path)?,
                    other => agent::open_signer(other, agent::Role::Recovery)?.public_key()?,
                };
                eprintln!("new recovery key: {}", chain::key_text(&key, "                  "));
                if skip_key_check {
                    eprintln!("the new recovery key is not opened here (--skip-key-check): that it can sign is not shown");
                } else {
                    let signer = agent::open_signer(spec, agent::Role::Recovery)
                        .context("the new recovery key does not open; nothing sent (--skip-key-check leaves it unopened)")?;
                    check_signer("the new recovery key".into(), signer.as_ref())
                        .context("nothing sent (--skip-key-check leaves the key unopened)")?;
                }
                let inc = s.replace_recovery(&key, sponsored).await?;
                println!("recovery key replaced: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            OwnerCmd::RemoveRecovery { agent, leave_no_recovery, earlier: Some(earlier), sponsored } => {
                let s = session(&agent).await?;
                let inc = s.remove_earlier_recovery(earlier, leave_no_recovery, sponsored).await?;
                println!(
                    "recovery key removed from the earlier validator {earlier}: tx {} (block {}, {} gas)",
                    inc.tx, inc.block, inc.gas_used
                );
            }
            OwnerCmd::RemoveRecovery { agent, leave_no_recovery, earlier: None, sponsored } => {
                if !leave_no_recovery {
                    bail!(
                        "this leaves the account without a recovery key: losing the owner key then loses the account. \
                         To put another key in its place use `owner replace-recovery`; to go on, add --leave-no-recovery"
                    );
                }
                let s = session(&agent).await?;
                let inc = s.remove_recovery(sponsored).await?;
                println!("recovery key removed, none installed: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            OwnerCmd::Recover { agent, sponsored } => {
                let s = session(&agent).await?;
                let inc = s.recover(sponsored).await?;
                println!("the recovery key is root now: tx {}; next, `owner set-root --as-recovery` to a new owner device (--to-phone <label>, or --not-a-phone)", inc.tx);
            }
            OwnerCmd::SetRoot {
                agent,
                validator,
                public_key,
                retire,
                as_recovery,
                expect_fingerprint,
                to_phone,
                not_a_phone,
                new_key,
                proof_timeout,
                no_proof_of_possession,
                sponsored,
            } => {
                // before anything is read, built or asked of a key (issue #38)
                if to_phone.is_none() && !not_a_phone {
                    bail!(
                        "say what the new key is: --to-phone <label> when it is a phone's key (the phone then shows that it holds \
                         the key, before anything is signed or sent), or --not-a-phone for any other key. Root handed to a key \
                         nobody holds takes the account with it. Nothing built, nothing sent"
                    );
                }
                let local = new_key.as_deref().map(open_key_spec).transpose()?;
                let key = match (&public_key, &local) {
                    (Some(pasted), _) => {
                        let (x, y) = pasted.split_once(',').context("--public-key x,y")?;
                        hw_signer::PublicKey { x: agent::parse32(x.trim())?, y: agent::parse32(y.trim())? }
                    }
                    (None, Some(signer)) => signer.public_key()?,
                    (None, None) => bail!("--public-key x,y"),
                };
                if !hw_signer::valid_public_key(&key) {
                    bail!("--public-key is not a point on P-256; a handover to it would lose the account");
                }
                let fp = owner_core::fingerprint::fingerprint(&key);
                if let Some(signer) = &local {
                    let held = signer.public_key()?;
                    if held != key {
                        bail!(
                            "--new-key is the key {}, and --public-key names {fp}: which of the two does the root go to? Nothing sent",
                            owner_core::fingerprint::fingerprint(&held)
                        );
                    }
                }
                if let Some(expected) = &expect_fingerprint {
                    if !expected.eq_ignore_ascii_case(&fp) {
                        bail!("--public-key has fingerprint {fp}, not the expected {expected}: not the key the owner saw; nothing sent");
                    }
                }
                let s = session(&agent).await?;
                eprintln!("new root key:   fingerprint {fp}");
                if let Some(label) = &to_phone {
                    // a handover to a phone waits for the phone to show the key (design §2.2): nothing is
                    // signed or sent before that
                    phone::prove_possession(label, s.dep.chain_id, s.account, &key).context("nothing sent")?;
                    eprintln!("phone:          holds the key {fp} (signed a fresh digest)");
                } else if no_proof_of_possession {
                    eprintln!(
                        "WARNING: no proof of possession (--no-proof-of-possession). The root goes to the key {fp} although \
                         that key has not signed anything. If nobody can sign with it — the private key is lost, was never \
                         made, or is on a device that no longer works — the account goes with it, unless a recovery key \
                         is installed and under control."
                    );
                } else {
                    // any other key shows the same before anything is signed or sent (issue #51)
                    let challenge =
                        possession::Challenge::new(s.dep.chain_id, s.account, &key, std::time::Duration::from_secs(proof_timeout))?;
                    match &local {
                        Some(signer) => {
                            let proof = challenge.prove(signer.as_ref()).context("nothing sent")?;
                            challenge.verify(&proof, possession::now()?).context("nothing sent")?;
                        }
                        None => ask_for_proof(&challenge, proof_timeout)?,
                    }
                    eprintln!("new key:        holds the key {fp} (signed a fresh challenge)");
                }
                // the device is free again before the current root key signs: both may be on one token
                drop(local);
                let inc = s.set_root(validator, &key, retire, as_recovery, sponsored).await?;
                println!("root handed to {validator}: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
        },
        Cmd::Permission { cmd } => match cmd {
            PermissionCmd::Revoke { agent, id, old_config, sponsored } => {
                let s = session(&agent).await?;
                let old = old_config.as_deref().map(AgentConfig::load).transpose()?.map(|c| c.0);
                let inc = s.revoke_permission(parse_permission_id(&id)?, old.as_ref(), sponsored).await?;
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
            PermissionCmd::Allowance { agent, sponsored } => {
                let s = session(&agent).await?;
                let inc = s.renew_venue_allowances(sponsored).await?;
                println!("venue allowances set to one budget: tx {} (block {}, {} gas)", inc.tx, inc.block, inc.gas_used);
            }
            PermissionCmd::Rotate { agent, old_id, old_config, sponsored, dry_run } => {
                let old = old_config.as_deref().map(AgentConfig::load).transpose()?.map(|c| c.0);
                let s = session(&agent).await?;
                if !s.pinned {
                    bail!("pin the deployed account in the config (\"account\": \"0x…\") before rotating");
                }
                if dry_run {
                    println!("account:  {}", s.account);
                    println!("callData: {}", s.rotate_calldata(parse_permission_id(&old_id)?, old.as_ref()).await?);
                    return Ok(());
                }
                let inc = s.rotate_permission(parse_permission_id(&old_id)?, old.as_ref(), sponsored).await?;
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
                let (done, (from, to)) = s.x402_reclaim(from_block, sponsored).await?;
                // the blocks looked at, so that 0 is not read as "nothing is booked" (issue #116)
                let older = if from_block.is_none() {
                    format!(" (the last {}; an older registration needs --from-block, the block `x402 fetch` printed)", x402::RECLAIM_WINDOW)
                } else {
                    String::new()
                };
                println!("reclaimed {} expired authorization(s), looking at blocks {from} to {to}{older}", done.len());
            }
        },
        Cmd::Order { cmd } => match cmd {
            OrderCmd::Sell { agent, venue, sell, buy, sell_amount, buy_amount, valid_for, sponsored } => {
                let s = session(&agent).await?;
                let sell_amount = sell_amount.parse::<U256>().context("--sell-amount")?;
                let buy_amount = buy_amount.parse::<U256>().context("--buy-amount")?;
                let placed = s.order_sell(venue, sell, buy, sell_amount, buy_amount, valid_for, sponsored).await?;
                eprintln!("order digest:   {}", placed.digest);
                eprintln!("not sent to any order book: the order is live once one has it");
                eprintln!("charged to the token's budget now, filled or not: an order's charge is not given back, it returns when the budget period turns");
                println!("{}", placed.json());
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
