//! End-to-end tests of the `agent-signer` CLI on a local chain.
//!
//! Each test starts its own `anvil`, installs the account-abstraction stack
//! and TPM_sign's modules from `fixtures/chain-code.json` (runtime bytecode
//! taken from Base Sepolia: EntryPoint v0.7, Kernel v3.3 + factory,
//! P256Validator, P256RecoveryValidator, P256Signer, AgentPolicy v6,
//! SafeNonceAssert, the demo counter, Solady's P-256 verifier) and runs the
//! real binary against it -- config parsing, operation building, signing,
//! `handleOps`, and the contracts' verdicts, together.
//!
//! The keys are software keys, which only a build with the test-only
//! `insecure-software-keys` feature accepts:
//!
//!     cargo test -p agent-signer --features insecure-software-keys --test anvil_cli
//!
//! Needs `anvil` (Foundry) on PATH; skipped with a note otherwise.
#![cfg(feature = "insecure-software-keys")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};

sol! {
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }
    function handleOps(PackedUserOperation[] ops, address beneficiary) external;
    function getUserOpHash(PackedUserOperation op) external view returns (bytes32);
    event UserOperationEvent(
        bytes32 indexed userOpHash, address indexed sender, address indexed paymaster,
        uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed
    );
    function count() external view returns (uint256);
    function setup(
        address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler,
        address paymentToken, uint256 payment, address paymentReceiver
    ) external;
    function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) external returns (address proxy);
    function execTransaction(
        address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas,
        uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures
    ) external payable returns (bool success);
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;
    function getOwners() external view returns (address[]);
    function nonce() external view returns (uint256);
    function multiSend(bytes transactions) external payable;
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function transferWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature
    ) external;
}

/// anvil's first and second well-known development accounts: the gas wallet
/// and a stand-in facilitator. Public test keys, funded by anvil.
const GAS_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const FACILITATOR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const PAYEE: &str = "0x000000000000000000000000000000000000bEEF";
/// anvil's third development account: the fake bundler's own wallet.
const BUNDLER_WALLET: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const INCREMENT: &str = "0xd09de08a";
const X402_AUTHORIZE: &str = "0x4993d616";
const X402_RECLAIM: &str = "0xf3ea183e";

// ---------------------------------------------------------------- the chain

struct Chain {
    anvil: Child,
    url: String,
    dir: PathBuf,
    code: Value,
}

impl Drop for Chain {
    fn drop(&mut self) {
        let _ = self.anvil.kill();
        let _ = self.anvil.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A plain blocking JSON-RPC call over HTTP/1.1 (no async runtime needed).
fn http_post(url: &str, body: &str) -> String {
    http_post_with(url, body, "")
}

/// `headers`: extra header lines, each ending in CRLF.
fn http_post_with(url: &str, body: &str, headers: &str) -> String {
    let rest = url.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let mut s = TcpStream::connect(host).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let (_, body) = resp.split_once("\r\n\r\n").unwrap();
    if resp.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        // de-chunk
        let mut out = String::new();
        let mut rest = body;
        loop {
            let (len, after) = rest.split_once("\r\n").unwrap();
            let n = usize::from_str_radix(len.trim(), 16).unwrap();
            if n == 0 {
                break;
            }
            out.push_str(&after[..n]);
            rest = &after[n + 2..];
        }
        out
    } else {
        body.to_string()
    }
}

impl Chain {
    /// None when `anvil` is not installed.
    fn start(test: &str) -> Option<Chain> {
        let port = free_port();
        // Base has the RIP-7212 P-256 precompile; give anvil the same, so P-256
        // costs what it costs there (~3.5k gas, not the Solidity verifier's
        // ~300k). Older anvils call it --odyssey, newer ones ship it with Osaka;
        // a plain anvil still works through the VERIFIER in the fixture.
        let mut anvil = None;
        for extra in [&["--odyssey"][..], &["--hardfork", "osaka"][..], &[][..]] {
            let mut child = Command::new("anvil")
                .args(["--port", &port.to_string(), "--silent"])
                .args(extra)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            std::thread::sleep(Duration::from_millis(300));
            if child.try_wait().ok().flatten().is_none() {
                anvil = Some(child);
                break;
            }
        }
        let anvil = anvil?;
        let dir = std::env::temp_dir().join(format!("agent-signer-it-{test}-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let code: Value = serde_json::from_str(
            &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chain-code.json")).unwrap(),
        )
        .unwrap();
        let chain = Chain { anvil, url: format!("http://127.0.0.1:{port}"), dir, code };
        let started = Instant::now();
        while TcpStream::connect(format!("127.0.0.1:{port}")).is_err() {
            assert!(started.elapsed() < Duration::from_secs(20), "anvil did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        chain.install();
        Some(chain)
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let v: Value = serde_json::from_str(&http_post(&self.url, &body)).unwrap();
        if let Some(e) = v.get("error") {
            panic!("{method}: {e}");
        }
        v["result"].clone()
    }

    fn addr(&self, name: &str) -> String {
        self.code["contracts"][name]["address"].as_str().unwrap().to_string()
    }

    fn install(&self) {
        for (_, c) in self.code["contracts"].as_object().unwrap() {
            self.rpc("anvil_setCode", json!([c["address"], c["code"]]));
        }
        let deployments = json!({
            "chainId": 31337,
            "entryPoint": self.addr("entryPoint"), "kernel": self.addr("kernel"), "kernelFactory": self.addr("kernelFactory"),
            "p256Validator": self.addr("p256Validator"), "p256RecoveryValidator": self.addr("p256RecoveryValidator"),
            "p256Signer": self.addr("p256Signer"), "agentPolicy": self.addr("agentPolicy"),
            "safeNonceAssert": self.addr("safeNonceAssert"), "demoCounter": self.addr("demoCounter"),
        });
        std::fs::write(self.dir.join("deployments.json"), deployments.to_string()).unwrap();
        std::fs::write(self.dir.join("gas.key"), GAS_KEY).unwrap();
        std::fs::write(
            self.dir.join(".env"),
            format!("RPC_URL={}\nGAS_WALLET_KEYFILE={}\n", self.url, self.dir.join("gas.key").display()),
        )
        .unwrap();
    }

    fn call(&self, to: &str, data: Vec<u8>) -> Vec<u8> {
        let out = self.rpc("eth_call", json!([{"to": to, "data": Bytes::from(data).to_string()}, "latest"]));
        hex::decode(out.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn counter(&self) -> U256 {
        U256::from_be_slice(&self.call(&self.addr("demoCounter"), countCall {}.abi_encode()))
    }

    fn now(&self) -> u64 {
        let b = self.rpc("eth_getBlockByNumber", json!(["latest", false]));
        u64::from_str_radix(b["timestamp"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    fn advance(&self, secs: u64) {
        self.rpc("evm_increaseTime", json!([secs]));
        self.rpc("evm_mine", json!([]));
    }

    /// Send a transaction from an anvil-unlocked account and wait for it.
    fn send_from(&self, from: &str, to: Option<&str>, data: Vec<u8>) -> Value {
        let mut tx = json!({"from": from, "data": Bytes::from(data).to_string(), "gas": "0x989680"});
        if let Some(to) = to {
            tx["to"] = json!(to);
        }
        let hash = self.rpc("eth_sendTransaction", json!([tx]));
        let started = Instant::now();
        let receipt = loop {
            let r = self.rpc("eth_getTransactionReceipt", json!([hash]));
            if !r.is_null() || started.elapsed() > Duration::from_secs(10) {
                break r;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(receipt["status"], "0x1", "transaction from {from} reverted: {receipt}");
        receipt
    }

    /// Run the CLI with this chain's `.env`, never the developer's.
    fn cli(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signer"));
        cmd.args(args).env_remove("BASE_SEPOLIA_RPC_URL");
        if args.first() != Some(&"key") {
            // `key` commands talk to a device, not to the chain
            cmd.args(["--env-file", self.dir.join(".env").to_str().unwrap()]);
        }
        cmd.env_remove("BASE_SEPOLIA_RPC_URL")
            .env_remove("BUNDLER_URL")
            .env_remove("GAS_WALLET_KEYFILE");
        cmd.output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "agent-signer {args:?} failed:\n{stderr}\n{stdout}");
        format!("{stdout}{stderr}")
    }

    fn fails(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "agent-signer {args:?} was expected to fail:\n{text}");
        text
    }
}

// ---------------------------------------------------------------- keys and configs

struct Key {
    scalar: String,
    x: String,
    y: String,
}

fn key(n: u8) -> Key {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    bytes[0] = 0x11;
    let sk = SigningKey::from_bytes(&bytes.into()).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    Key {
        scalar: format!("0x{}", hex::encode(bytes)),
        x: format!("0x{}", hex::encode(point.x().unwrap())),
        y: format!("0x{}", hex::encode(point.y().unwrap())),
    }
}

struct Cfg<'a> {
    owner: &'a Key,
    agent: &'a Key,
    permission: &'a str,
    allow: Vec<(String, &'a str)>,
    account: Option<String>,
    recovery: Option<&'a Key>,
    valid_after: u64,
    valid_until: u64,
    tokens: Value,
}

impl Chain {
    fn config(&self, name: &str, c: &Cfg) -> String {
        let mut v = json!({
            "deployments": self.dir.join("deployments.json"),
            "owner": {"software": c.owner.scalar},
            "ownerPublicKey": {"x": c.owner.x, "y": c.owner.y},
            "agent": {"software": c.agent.scalar},
            "agentPublicKey": {"x": c.agent.x, "y": c.agent.y},
            "permissionId": c.permission,
            "salt": "0x0",
            "policy": {
                "allow": c.allow.iter().map(|(t, s)| json!({"target": t, "selector": s})).collect::<Vec<_>>(),
                "maxValuePerOp": "1000",
                "budget": "1000000000000000000",
                "validAfter": c.valid_after,
                "validUntil": c.valid_until,
            },
        });
        if let Some(a) = &c.account {
            v["account"] = json!(a);
        }
        if let Some(r) = c.recovery {
            v["recovery"] = json!({"software": r.scalar});
        }
        if !c.tokens.is_null() {
            v["policy"]["tokens"] = c.tokens.clone();
        }
        let path = self.dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Fund and deploy an account through its first agent operation (a demo
    /// increment); returns its address.
    fn deploy(&self, cfg: &str) -> String {
        let init = self.ok(&["account", "init-data", "--agent", cfg]);
        let account = init.lines().find_map(|l| l.strip_prefix("account:")).unwrap().trim().to_string();
        self.ok(&["account", "fund", "--agent", cfg, "--wei", "1000000000000000000"]);
        let before = self.counter();
        self.ok(&["demo", "--agent", cfg]);
        assert_eq!(self.counter(), before + U256::from(1), "the first operation deploys the account and runs");
        account
    }
}

macro_rules! chain_or_skip {
    ($name:expr) => {
        match Chain::start($name) {
            Some(c) => c,
            None => {
                eprintln!("skipping: anvil (Foundry) is not on PATH");
                return;
            }
        }
    };
}

fn far_future(chain: &Chain) -> u64 {
    chain.now() + 365 * 24 * 3600
}

// ---------------------------------------------------------------- tests

/// Deploy, act within the mandate, be refused outside it, inspect, rotate,
/// revoke.
#[test]
fn agent_lifecycle() {
    let chain = chain_or_skip!("lifecycle");
    let (owner, agent, agent2) = (key(1), key(2), key(3));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let base = Cfg {
        owner: &owner, agent: &agent, permission: "0x74657331", allow: vec![(counter.clone(), INCREMENT)],
        account: None, recovery: None, valid_after: 0, valid_until: until, tokens: Value::Null,
    };
    let cfg = chain.config("agent.json", &base);
    let account = chain.deploy(&cfg);

    // the agent's own account is never a valid target: the CLI refuses the
    // mandate before anything is signed (the policy would refuse it on chain)
    let selfish = chain.config(
        "selfish.json",
        &Cfg {
            owner: &owner, agent: &agent, permission: "0x73656c66", allow: vec![(account.clone(), "0x12345678")],
            account: Some(account.clone()), recovery: None, valid_after: 0, valid_until: until, tokens: Value::Null,
        },
    );
    let refused = chain.fails(&["permission", "add", "--agent", &selfish]);
    assert!(refused.contains("never a valid target for the agent"), "{refused}");

    // outside the mandate: a transfer to an outsider is refused, nothing moves
    let refused = chain.fails(&["op", "send", "--agent", &cfg, "--target", "0x000000000000000000000000000000000000dEaD", "--wei", "1"]);
    assert!(refused.contains("3e4983f6") || refused.to_lowercase().contains("policy"), "{refused}");

    // a resend with the first attempt's EntryPoint nonce can never execute twice
    let sent: Value = serde_json::from_str(
        chain.ok(&["op", "send", "--agent", &cfg, "--target", &counter, "--data", INCREMENT, "--json"]).lines().find(|l| l.starts_with('{')).unwrap(),
    )
    .unwrap();
    let nonce = sent["nonce"].as_str().unwrap().to_string();
    let before = chain.counter();
    let again = chain.fails(&["op", "send", "--agent", &cfg, "--target", &counter, "--data", INCREMENT, "--nonce", &nonce]);
    assert!(again.contains("already used"), "{again}");
    assert_eq!(chain.counter(), before);

    // the chain enforces exactly the config
    let pinned = chain.config("pinned.json", &Cfg { account: Some(account.clone()), ..base });
    let shown = chain.ok(&["permission", "show", "--agent", &pinned]);
    assert!(shown.contains("ok agent key") && !shown.contains("DIFF"), "{shown}");

    // rotate to a new agent key under a new id: the old permission is gone
    let rotated = chain.config(
        "rotated.json",
        &Cfg { agent: &agent2, permission: "0x74657332", account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    chain.ok(&["permission", "rotate", "--agent", &rotated, "--old-id", "0x74657331"]);
    chain.fails(&["demo", "--agent", &pinned]);
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &rotated]);
    assert_eq!(chain.counter(), before + U256::from(1));

    // revoke: the agent can do nothing any more
    chain.ok(&["permission", "revoke", "--agent", &rotated, "--id", "0x74657332"]);
    chain.fails(&["demo", "--agent", &rotated]);
}

/// The `phone` owner key spec as `key create --phone` prints it.
fn phone_spec(label: &str, k: &Key) -> Value {
    json!({"phone": {"label": label, "publicKey": {"x": k.x, "y": k.y}, "fingerprint": fingerprint_of(k)}})
}

fn fingerprint_of(k: &Key) -> String {
    let pk = hw_signer::PublicKey {
        x: hex::decode(&k.x[2..]).unwrap().try_into().unwrap(),
        y: hex::decode(&k.y[2..]).unwrap().try_into().unwrap(),
    };
    owner_core::fingerprint::fingerprint(&pk)
}

fn base_cfg<'a>(owner: &'a Key, agent: &'a Key, counter: &str, until: u64) -> Cfg<'a> {
    Cfg {
        owner, agent, permission: "0x74657331", allow: vec![(counter.to_string(), INCREMENT)],
        account: None, recovery: None, valid_after: 0, valid_until: until, tokens: Value::Null,
    }
}

/// A scheduled window: installed alongside, refused before it opens, used after.
#[test]
fn schedule_window() {
    let chain = chain_or_skip!("schedule");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));

    let opens = chain.now() + 3600;
    let window = chain.config(
        "window.json",
        &Cfg { permission: "0x77696e31", account: Some(account), valid_after: opens, valid_until: opens + 3600, ..base_cfg(&owner, &agent, &counter, until) },
    );
    chain.ok(&["permission", "add", "--agent", &window]);
    let early = chain.fails(&["demo", "--agent", &window]);
    assert!(early.contains("AA22") || early.to_lowercase().contains("not due") || early.to_lowercase().contains("expired"), "{early}");

    chain.advance(3700);
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &window]);
    assert_eq!(chain.counter(), before + U256::from(1));
}

/// The recovery drill of docs/RESILIENCE.md: the owner key is lost.
#[test]
fn recovery_drill() {
    let chain = chain_or_skip!("recovery");
    let (owner, agent, recovery, new_owner) = (key(1), key(2), key(4), key(5));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let with = |name: &str, o: &Key| {
        chain.config(name, &Cfg { owner: o, recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(o, &agent, &counter, until) })
    };
    let old_cfg = with("old-owner.json", &owner);

    chain.ok(&["owner", "add-recovery", "--agent", &old_cfg]);
    assert!(chain.ok(&["owner", "status", "--agent", &old_cfg]).contains("installed = true"));
    // a different recovery key is refused by the CLI's check against the
    // chain, before anything is signed
    let wrong = key(6);
    let wrong_cfg = chain.config(
        "wrong-recovery.json",
        &Cfg { owner: &owner, recovery: Some(&wrong), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    let refused = chain.fails(&["owner", "recover", "--agent", &wrong_cfg]);
    assert!(refused.contains("not the one installed on the account"), "{refused}");
    chain.ok(&["owner", "recover", "--agent", &old_cfg]);
    let validator = chain.addr("p256Validator");
    let public_key = format!("{},{}", new_owner.x, new_owner.y);
    chain.ok(&[
        "owner", "set-root", "--agent", &old_cfg, "--as-recovery",
        "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
    ]);

    // the new owner signs root operations; the lost one is refused
    let new_cfg = with("new-owner.json", &new_owner);
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &new_cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1));
    let refused = chain.fails(&["op", "send", "--agent", &old_cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    // refused by the CLI's root-key check, which reads the validator's key
    // from the chain; the validator's own AA24 is what the forge tests cover
    assert!(refused.contains("not the account's root key"), "{refused}");
    // and the agent permission survived the change of owner
    chain.ok(&["demo", "--agent", &new_cfg]);
}

/// The owner replaces its own key on the same validator — a new device, or
/// the phone design's "new key on the same phone" (D2) — while that validator
/// is root. Kernel will not uninstall the root validator, so the CLI pivots
/// root onto the installed recovery validator inside the batch and back.
/// Without a recovery key the CLI says what to do instead of sending.
#[test]
fn owner_rotates_its_key_on_the_root_validator() {
    let chain = chain_or_skip!("rotate-root-key");
    let (owner, agent, recovery, new_owner) = (key(1), key(2), key(4), key(6));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let with = |name: &str, o: &Key, rec: Option<&Key>| {
        chain.config(name, &Cfg { owner: o, recovery: rec, account: Some(account.clone()), ..base_cfg(o, &agent, &counter, until) })
    };
    let validator = chain.addr("p256Validator");
    let public_key = format!("{},{}", new_owner.x, new_owner.y);

    // no recovery key installed: refused with guidance, nothing sent
    let bare = with("owner-norec.json", &owner, None);
    let refused = chain.fails(&[
        "owner", "set-root", "--agent", &bare, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
    ]);
    assert!(refused.contains("owner add-recovery"), "{refused}");

    // with the recovery key installed, the rotation goes through in one operation
    let old_cfg = with("owner.json", &owner, Some(&recovery));
    chain.ok(&["owner", "add-recovery", "--agent", &old_cfg]);
    chain.ok(&[
        "owner", "set-root", "--agent", &old_cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
    ]);
    let status = chain.ok(&["owner", "status", "--agent", &old_cfg]);
    assert!(status.contains(&validator.to_lowercase()), "root is back on the validator: {status}");
    assert!(status.contains("is root now = false"), "{status}");

    // the new key is root; the old one is refused before any signature
    let new_cfg = with("new-owner.json", &new_owner, Some(&recovery));
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &new_cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1));
    let refused = chain.fails(&["op", "send", "--agent", &old_cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert!(refused.contains("not the account's root key"), "{refused}");
    // and the agent permission survived
    chain.ok(&["demo", "--agent", &new_cfg]);
}

// ---------------------------------------------------------------- phone owner (P1)

/// GET over the harness's bare TCP client (the CLI's LAN session is plain HTTP).
fn http_get(url: &str) -> Vec<u8> {
    let rest = url.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let mut s = TcpStream::connect(host).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let sep = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    resp[sep + 4..].to_vec()
}

/// What the phone does, in a thread: wait for the QR the CLI writes to
/// `qr_file`, fetch the request, check the commitment, recompute the hash,
/// sign with `key` (or misbehave as `mode` says), post the answer.
/// The phone side of the protocol with a software key. Modes: `sign`,
/// `wrong-hash`, `refuse` answer a sign request; `enroll` and `enroll-refuse`
/// answer an enrollment request with `key` as the new key (no attestation:
/// a simulator has none; `enroll-fake-attestation` claims a hardware key with
/// evidence that is not a chain). Every answer carries the MAC of the QR's secret,
/// as the app's does; a mode ending in `-nomac` posts without it — a host on
/// the network that saw the session URL but never the QR.
fn phone_simulator(qr_file: std::path::PathBuf, key: Key, mode: &'static str) -> std::thread::JoinHandle<()> {
    phone_simulator_after(qr_file, key, mode, Duration::ZERO)
}

/// `delay` holds the answer back, so another "phone" can post first.
fn phone_simulator_after(qr_file: std::path::PathBuf, key: Key, mode: &'static str, delay: Duration) -> std::thread::JoinHandle<()> {
    use owner_core::enroll::{EnrollRequest, EnrollResponse};
    use owner_core::request::{answer_mac, commitment, AppInfo, QrPayload, SignRequest, SignResponse, MAC_HEADER};
    let (mode, with_mac) = match mode.strip_suffix("-nomac") {
        Some(m) => (m, false),
        None => (mode, true),
    };
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let uri = loop {
            if let Ok(u) = std::fs::read_to_string(&qr_file) {
                if u.starts_with("tpmsign:") {
                    break u;
                }
            }
            assert!(started.elapsed() < Duration::from_secs(30), "the CLI never showed a QR");
            std::thread::sleep(Duration::from_millis(50));
        };
        let qr = QrPayload::parse(&uri).expect("a valid QR payload");
        let post = |body: Vec<u8>| {
            let body = String::from_utf8(body).unwrap();
            let headers = if with_mac { format!("{MAC_HEADER}: {}\r\n", answer_mac(&qr.secret, body.as_bytes()).unwrap()) } else { String::new() };
            http_post_with(&qr.url, &body, &headers)
        };
        let bytes = http_get(&qr.url);
        assert_eq!(commitment(&bytes), qr.commitment, "the served request must match the QR's commitment");
        std::thread::sleep(delay);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let app = AppInfo { platform: "simulator".into(), version: "0".into(), core: "0".into() };
        let pk = hw_signer::PublicKey {
            x: hex::decode(&key.x[2..]).unwrap().try_into().unwrap(),
            y: hex::decode(&key.y[2..]).unwrap().try_into().unwrap(),
        };
        if mode.starts_with("enroll") {
            let req = EnrollRequest::parse(&bytes, now, 300).expect("a well-formed enrollment request");
            assert_eq!(req.chain_id().unwrap(), 31337);
            assert!(!req.label.is_empty());
            let resp = match mode {
                "enroll" => EnrollResponse::enrolled(&qr.commitment, &pk, "simulator", false, &[], app),
                // claims a hardware key and attaches something DER-shaped as its evidence
                "enroll-fake-attestation" => EnrollResponse::enrolled(&qr.commitment, &pk, "tee", false, &[vec![0x30, 0x03, 0x02, 0x01, 0x01]], app),
                "enroll-refuse" => EnrollResponse::refused(&qr.commitment, "user", Some("declined on the phone".into()), app),
                other => panic!("mode {other}"),
            };
            post(resp.to_bytes());
            return;
        }
        let req = SignRequest::parse(&bytes, now, 300).expect("a well-formed request");
        assert_eq!(req.nonce_key().unwrap(), U256::ZERO, "the phone signs root operations only");
        // the phone's own review, with the facts its build embeds (design §6, §6.7): it signs
        // the hash that review recomputed, or answers with the review's refusal
        let me = owner_core::review::EnrolledAccount::new(req.chain_id().unwrap(), req.entry_point, req.user_op.sender);
        let review = owner_core::review::open_request_with_build_facts(&bytes, &qr.commitment, now, &[me]);
        if let owner_core::review::Verdict::Refuse(why) = &review.verdict {
            let resp = SignResponse::refused(&qr.commitment, "core", Some(why.clone()), app);
            post(resp.to_bytes());
            return;
        }
        let hash = review.digest_to_sign().unwrap();
        assert_eq!(hash, req.user_op_hash().unwrap());
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hex::decode(&key.scalar[2..]).unwrap());
        let sk = SigningKey::from_bytes(&scalar.into()).unwrap();
        let sign = |h: &B256| {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let s: p256::ecdsa::Signature = sk.sign_prehash(&h.0).unwrap();
            let (r, s) = s.split_bytes();
            hw_signer::Signature { r: r.into(), s: s.into() }
        };
        let resp = match mode {
            "sign" => SignResponse::signed(&qr.commitment, hash, &sign(&hash), &pk, app),
            "wrong-hash" => SignResponse::signed(&qr.commitment, hash, &sign(&B256::repeat_byte(0x42)), &pk, app),
            "refuse" => SignResponse::refused(&qr.commitment, "user", Some("declined on the phone".into()), app),
            other => panic!("mode {other}"),
        };
        post(resp.to_bytes());
    })
}

/// A phone as the owner key: the CLI serves the operation on the LAN behind
/// a QR, the (simulated) phone recomputes the hash and signs it, the CLI
/// verifies the signature and submits. A wrong signature and a refusal both
/// stop the operation before anything is sent; the agent role is refused.
#[test]
fn phone_owner_signs_a_root_operation() {
    let chain = chain_or_skip!("phone");
    let (phone, agent) = (key(7), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    // the config, with the owner replaced by the phone key spec
    let cfg_path = chain.config("phone.json", &base_cfg(&phone, &agent, &counter, until));
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    v["owner"] = phone_spec("sim-phone", &phone);
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let account = chain.deploy(&cfg_path); // the agent's first operation; no owner signature needed
    let qr_file = chain.dir.join("phone.qr");
    let qr = qr_file.to_str().unwrap();

    // 1. a real root operation, signed on the "phone"
    let sim = phone_simulator(qr_file.clone(), key(7), "sign");
    let before = chain.counter();
    let out = chain.ok(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    sim.join().unwrap();
    assert!(out.contains("path:           root (owner key)"), "{out}");
    assert!(out.contains("phone:          signed, signature verified"), "{out}");
    // the laptop previews the phone's review of the CLI's own request (P2)
    assert!(out.contains("what the phone will show (owner-core") && out.contains("+test-chains"), "{out}");
    assert!(out.contains("Call: increment()"), "{out}");
    assert!(out.contains("demo counter (verified in this build)"), "{out}");
    assert!(out.contains("Maximum gas cost:"), "{out}");
    assert!(!out.contains("will REFUSE"), "{out}");
    assert_eq!(chain.counter(), before + U256::from(1));
    let _ = std::fs::remove_file(&qr_file);

    // 2. a signature over another hash is rejected (400) and the session keeps waiting
    //    for the phone — a host on the LAN with the token can only make it fail; nothing sent
    let sim = phone_simulator(qr_file.clone(), key(7), "wrong-hash");
    let before = chain.counter();
    let err = chain.fails(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "4",
    ]);
    sim.join().unwrap();
    assert!(err.contains("does not verify"), "{err}");
    assert!(err.contains("no answer from the phone within 4s"), "the session waited on after the bad answer: {err}");
    assert_eq!(chain.counter(), before);
    let _ = std::fs::remove_file(&qr_file);

    // 3. the phone refuses: the CLI reports it and sends nothing
    let sim = phone_simulator(qr_file.clone(), key(7), "refuse");
    let err = chain.fails(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    sim.join().unwrap();
    assert!(err.contains("the phone refused: user"), "{err}");
    assert_eq!(chain.counter(), before);

    // 4. a phone can never be the agent key
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    v["owner"] = json!({"software": key(1).scalar});
    v["agent"] = phone_spec("sim-phone", &phone);
    v["account"] = json!(account);
    let bad = chain.dir.join("phone-as-agent.json");
    std::fs::write(&bad, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let err = chain.fails(&["demo", "--agent", bad.to_str().unwrap()]);
    assert!(err.contains("signs only owner operations"), "{err}");

    // 5. a config whose fingerprint is not its key's is refused before any session
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    v["owner"]["phone"]["fingerprint"] = json!(fingerprint_of(&key(8)));
    let wrong = chain.dir.join("phone-wrong-fp.json");
    std::fs::write(&wrong, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let err = chain.fails(&[
        "op", "send", "--agent", wrong.to_str().unwrap(), "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-timeout", "5",
    ]);
    assert!(err.contains("is not the fingerprint of its publicKey"), "{err}");
    assert!(!err.contains("tpmsign:1?"), "no session was opened: {err}");

    // 6. the phone reviews what it signs (P2): a call it cannot classify is refused on the
    //    phone with the review's reason, and the laptop had said so before the QR
    let _ = std::fs::remove_file(&qr_file);
    let sim = phone_simulator(qr_file.clone(), key(7), "sign");
    let before = chain.counter();
    let err = chain.fails(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", "0x7000000000000000000000000000000000000007", "--data", "0xdeadbeef",
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    sim.join().unwrap();
    assert!(err.contains("the phone will REFUSE this operation"), "{err}");
    assert!(err.contains("the phone refused: core") && err.contains("cannot decode"), "{err}");
    assert_eq!(chain.counter(), before);

    // 6a. a host on the network that never saw the QR posts a refusal in the phone's place:
    //     it carries no MAC of the session's secret, so it is ignored and the phone's own
    //     answer, a moment later, signs the operation
    let _ = std::fs::remove_file(&qr_file);
    let forger = phone_simulator(qr_file.clone(), key(7), "refuse-nomac");
    let sim = phone_simulator_after(qr_file.clone(), key(7), "sign", Duration::from_millis(1500));
    let before = chain.counter();
    let out = chain.ok(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    forger.join().unwrap();
    sim.join().unwrap();
    assert!(out.contains("without this session's secret was ignored"), "{out}");
    assert!(out.contains("phone:          signed, signature verified"), "{out}");
    assert_eq!(chain.counter(), before + U256::from(1));

    // 7. a new agent permission installed through the phone: the laptop previews the mandate
    //    the phone shows — the modules named by the build, the allow-list, the agent's key —
    //    and the agent then runs under it
    let _ = std::fs::remove_file(&qr_file);
    let agent2 = key(3);
    let cfg2 = chain.config(
        "phone-perm2.json",
        &Cfg { agent: &agent2, permission: "0x74657332", account: Some(account.clone()), ..base_cfg(&phone, &agent, &counter, until) },
    );
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg2).unwrap()).unwrap();
    v["owner"] = phone_spec("sim-phone", &phone);
    std::fs::write(&cfg2, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let sim = phone_simulator(qr_file.clone(), key(7), "sign");
    let out = chain.ok(&["permission", "add", "--agent", &cfg2, "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60"]);
    sim.join().unwrap();
    assert!(out.contains("Install agent permission: 0x74657332"), "{out}");
    assert!(out.contains("AgentPolicy (verified in this build)") && out.contains("P256Signer (verified in this build)"), "{out}");
    assert!(out.contains("demo counter (verified in this build) · increment"), "{out}");
    assert!(out.contains(&format!("Agent key: {}", fingerprint_of(&agent2))), "{out}");
    assert!(!out.contains("will REFUSE"), "{out}");
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &cfg2]);
    assert_eq!(chain.counter(), before + U256::from(1), "the agent runs under the permission the phone installed");
}

/// Design §2.1 and §9.4: enrollment on the (simulated) phone, the handover
/// to the enrolled key with the fingerprint check, then a root operation
/// signed through the LAN session — and what is refused on the way.
#[test]
fn phone_is_enrolled_then_takes_over_root() {
    let chain = chain_or_skip!("phone-enroll");
    let (owner, agent, recovery, phone) = (key(1), key(2), key(4), key(9));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let cfg = chain.config(
        "owner.json",
        &Cfg { recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    let qr_file = chain.dir.join("enroll.qr");
    let qr = qr_file.to_str().unwrap();
    let out_dir = chain.dir.join("enrollment");
    let out = out_dir.to_str().unwrap();

    // the config must name the account (§5.5)
    let unpinned = chain.config("unpinned.json", &base_cfg(&owner, &agent, &counter, until));
    let err = chain.fails(&["key", "create", "--phone", "owner-phone", "--agent", &unpinned, "--listen", "127.0.0.1:0", "--phone-timeout", "5"]);
    assert!(err.contains("pin `account`"), "{err}");

    let fp = fingerprint_of(&phone);
    let two_groups = fp[..11].to_lowercase(); // what the owner types from the phone's screen
    let session = ["--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60", "--phone-fingerprint", &two_groups];

    // the label is checked before any QR
    let err = chain.fails(&["key", "create", "--phone", "", "--agent", &cfg, "--listen", "127.0.0.1:0", "--phone-timeout", "5"]);
    assert!(err.contains("label must be 1 to 64"), "{err}");
    // asking for the fingerprint needs a terminal: said before any QR
    let err = chain.fails(&[
        "key", "create", "--phone", "owner-phone", "--agent", &cfg, "--phone-confirm-fingerprint", "--listen", "127.0.0.1:0", "--phone-timeout", "5",
    ]);
    assert!(err.contains("--phone-confirm-fingerprint asks on a terminal"), "{err}");
    assert!(!err.contains("tpmsign:1?"), "no session: {err}");

    // 1. the phone declines
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll-refuse");
    let err = chain.fails(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg], &session[..]].concat());
    sim.join().unwrap();
    assert!(err.contains("the phone refused: user"), "{err}");
    let _ = std::fs::remove_file(&qr_file);

    // 2. a simulator has no attestation: rejected (400, the session waits on) unless allowed
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll");
    let err = chain.fails(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--phone-timeout", "4"], &session[..4], &session[6..]].concat());
    sim.join().unwrap();
    assert!(err.contains("no attestation evidence"), "{err}");
    assert!(err.contains("no answer from the phone within"), "the session kept waiting after the rejected answer: {err}");
    let _ = std::fs::remove_file(&qr_file);

    // 2a. an answer that claims a hardware key must prove it (P3): evidence that is not a
    //     chain to an attestation root ends the session with the reason, and nothing is enrolled.
    //     Before the verifier, this answer was accepted as "tee".
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll-fake-attestation");
    let err = chain.fails(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg], &session[..]].concat());
    sim.join().unwrap();
    assert!(err.contains("the key attestation was not accepted"), "{err}");
    assert!(!err.contains("enrolled phone owner key"), "{err}");
    let _ = std::fs::remove_file(&qr_file);
    // StrongBox cannot be required of an answer without evidence, and the two flags exclude each other
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll");
    let err = chain.fails(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--require-strongbox", "--phone-timeout", "4"], &session[..4], &session[6..]].concat());
    sim.join().unwrap();
    assert!(err.contains("no attestation evidence"), "{err}");
    let _ = std::fs::remove_file(&qr_file);
    let err = chain.fails(&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--require-strongbox", "--allow-no-attestation"]);
    assert!(err.contains("cannot be used with"), "{err}");
    let err = chain.fails(&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--android-app-digest", "abcd"]);
    assert!(err.contains("--android-app-digest") && err.contains("32 bytes"), "{err}");

    // 3. enrolled: the key, its fingerprint, the next step, the config snippet
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll");
    let text = chain.ok(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--allow-no-attestation", "--out", out], &session[..]].concat());
    sim.join().unwrap();
    assert!(text.contains(&format!("x = {}", phone.x)), "{text}");
    assert!(text.contains(&format!("fingerprint    {fp}   (confirmed")), "{text}");
    assert!(text.contains("security level simulator (the phone's own word)"), "{text}");
    assert!(text.contains("attestation    none"), "{text}");
    assert!(text.contains("Nothing changed on-chain"), "{text}");
    assert!(text.contains(&format!("--expect-fingerprint {fp}")), "{text}");
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(out_dir.join("enroll-response.json")).unwrap()).unwrap();
    assert_eq!(saved["publicKey"]["x"].as_str().unwrap().to_lowercase(), phone.x.to_lowercase());
    let req: Value = serde_json::from_str(&std::fs::read_to_string(out_dir.join("enroll-request.json")).unwrap()).unwrap();
    assert_eq!(req["account"].as_str().unwrap().to_lowercase(), account.to_lowercase());
    assert_eq!(req["label"], "owner-phone");
    assert!(req.get("laptopPins").is_none(), "the build knows every contract of this deployment: nothing to pin");
    assert!(!text.contains("names sent to the phone"), "{text}");

    // 3a. a deployment with a contract the phone's build does not know: the laptop pins its
    //     name for it (design §4.3), and only for it
    let _ = std::fs::remove_file(&qr_file);
    let stranger = "0x9000000000000000000000000000000000000009";
    let mut dep: Value = serde_json::from_str(&std::fs::read_to_string(chain.dir.join("deployments.json")).unwrap()).unwrap();
    dep["demoCounter"] = json!(stranger);
    std::fs::write(chain.dir.join("deployments-odd.json"), dep.to_string()).unwrap();
    let mut odd: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    odd["deployments"] = json!(chain.dir.join("deployments-odd.json"));
    let odd_cfg = chain.dir.join("owner-odd.json");
    std::fs::write(&odd_cfg, serde_json::to_string_pretty(&odd).unwrap()).unwrap();
    let odd_out = chain.dir.join("enrollment-odd");
    let sim = phone_simulator(qr_file.clone(), key(9), "enroll");
    let text = chain.ok(&[
        &["key", "create", "--phone", "owner-phone", "--agent", odd_cfg.to_str().unwrap(), "--allow-no-attestation", "--out", odd_out.to_str().unwrap()],
        &session[..],
    ]
    .concat());
    sim.join().unwrap();
    assert!(text.contains("names sent to the phone") && text.contains("demo counter"), "{text}");
    let req: Value = serde_json::from_str(&std::fs::read_to_string(odd_out.join("enroll-request.json")).unwrap()).unwrap();
    let pins = req["laptopPins"].as_object().expect("the request carries the pins");
    assert_eq!(pins.len(), 1, "{pins:?}");
    let (pinned, name) = pins.iter().next().unwrap();
    assert_eq!((pinned.to_lowercase().as_str(), name.as_str().unwrap()), (stranger, "demo counter"));
    // a label the phone would not show is stopped before any QR
    let err = chain.fails(&["key", "create", "--phone", "owner\u{202e}phone", "--agent", &cfg, "--listen", "127.0.0.1:0", "--phone-timeout", "5"]);
    assert!(err.contains("plain text"), "{err}");
    let _ = std::fs::remove_file(&qr_file);
    // the snippet it printed is a valid owner spec
    let snippet_start = text.find("{\n  \"owner\"").expect("a config snippet");
    let snippet_end = snippet_start + text[snippet_start..].find("\n}").expect("the snippet's end") + 2;
    let snippet: Value = serde_json::from_str(&text[snippet_start..snippet_end]).expect("the snippet parses");
    assert_eq!(snippet["owner"]["phone"]["fingerprint"], fp);
    assert_eq!(snippet["owner"]["phone"]["attestation"], "none", "the config records that nothing places this key in hardware");

    // 3b. the answer is authenticated by the secret in the QR: a host on the network that saw
    // the session URL in the phone's GET, but never the QR, posts its own key first. Without
    // any fingerprint given, it is ignored (no MAC) and the phone's answer is the one accepted.
    let _ = std::fs::remove_file(&qr_file);
    let intruder = phone_simulator(qr_file.clone(), key(8), "enroll-nomac");
    let real = phone_simulator_after(qr_file.clone(), key(9), "enroll", Duration::from_millis(1500));
    let text = chain.ok(&[
        "key", "create", "--phone", "owner-phone", "--agent", &cfg, "--allow-no-attestation",
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    intruder.join().unwrap();
    real.join().unwrap();
    assert!(text.contains("without this session's secret was ignored"), "{text}");
    assert!(text.contains(&format!("fingerprint    {fp}   ← the phone shows the same one")), "{text}");
    assert!(!text.contains(&key(8).x), "no line names the intruder's key: {text}");

    // 3c. someone who could read the QR (so they have the secret) and is on the network too:
    // the fingerprint from the phone's own screen, when the owner gives it, still rejects
    // their key (400), the session waits on, and the phone's answer is the one accepted.
    let _ = std::fs::remove_file(&qr_file);
    let intruder = phone_simulator_after(qr_file.clone(), key(8), "enroll", Duration::ZERO);
    let real = phone_simulator_after(qr_file.clone(), key(9), "enroll", Duration::from_millis(1500));
    let text = chain.ok(&[&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--allow-no-attestation"], &session[..]].concat());
    intruder.join().unwrap();
    real.join().unwrap();
    assert!(text.contains("is not the one on the phone's screen"), "the intruder's key was rejected: {text}");
    assert!(text.contains(&format!("fingerprint    {fp}   (confirmed")), "the phone's key was enrolled: {text}");
    assert!(!text.contains(&key(8).x), "no line names the intruder's key as the owner's: {text}");
    let _ = std::fs::remove_file(&qr_file);

    // 4. the handover goes only to the key the owner saw
    let validator = chain.addr("p256Validator");
    let public_key = format!("{},{}", phone.x, phone.y);
    chain.ok(&["owner", "add-recovery", "--agent", &cfg]);
    let other = fingerprint_of(&key(8));
    let err = chain.fails(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
        "--expect-fingerprint", &other,
    ]);
    assert!(err.contains(&format!("has fingerprint {fp}, not the expected {other}")), "{err}");
    let err = chain.fails(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key",
        &format!("{},{}", phone.x, "0x".to_string() + &"11".repeat(32)),
    ]);
    assert!(err.contains("not a point on P-256"), "{err}");
    let text = chain.ok(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
        "--expect-fingerprint", &fp.to_lowercase(),
    ]);
    assert!(text.contains(&format!("fingerprint {fp}")), "{text}");

    // 5. the phone is root: the config points at it; a root operation goes through the session
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    v["owner"] = snippet["owner"].clone();
    let phone_cfg = chain.dir.join("phone-owner.json");
    std::fs::write(&phone_cfg, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let phone_cfg = phone_cfg.to_str().unwrap();
    let shown = chain.ok(&["key", "show", "--phone", "owner-phone", "--agent", phone_cfg]);
    assert!(shown.contains(&format!("fingerprint {fp}")) && shown.contains("attestation none"), "{shown}");
    let sim = phone_simulator(qr_file.clone(), key(9), "sign");
    let before = chain.counter();
    let text = chain.ok(&[
        "op", "send", "--agent", phone_cfg, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    sim.join().unwrap();
    assert!(text.contains("phone:          signed, signature verified"), "{text}");
    assert_eq!(chain.counter(), before + U256::from(1));
    // the old owner key is refused before any signature; the agent still runs
    let refused = chain.fails(&["op", "send", "--agent", &cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert!(refused.contains("not the account's root key"), "{refused}");
    chain.ok(&["demo", "--agent", phone_cfg]);
}

/// The real thing, with a real phone on the same network (design §9.6): the
/// phone enrolls a new key for a fresh anvil account, the current owner hands
/// root to it (`set-root` with the fingerprint check), the phone signs a root
/// operation, and the agent still runs. Run from `signer/`:
///
///   cargo test -p agent-signer --features insecure-software-keys \
///     --test anvil_cli phone_owner_real_device -- --ignored --nocapture
///
/// On the phone: "4. Enroll" for the first QR, "3. Scan and sign" for the second
/// (a new agent permission, whose mandate the phone shows). The app needs the
/// test chain's facts: `OWNER_CORE_FEATURES=ffi,test-chains ./build-core.sh`.
/// The enrollment verifies the phone's key attestation against Google's roots;
/// `TPMSIGN_ANDROID_APP_DIGEST=<sha256>` names the certificate your own build
/// of the app is signed with (the CLI prints the digest it saw when it refuses).
/// `TPMSIGN_PHONE_OUT=<dir>` keeps the enrollment (request, answer, attestation
/// DER) after the run; the temp directory is removed otherwise.
#[test]
#[ignore = "needs a phone with the owner app on the same network"]
fn phone_owner_real_device() {
    let chain = chain_or_skip!("phone-real");
    let (owner, agent, recovery) = (key(1), key(2), key(4));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let cfg = chain.config(
        "owner.json",
        &Cfg { recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    let env_file = chain.dir.join(".env");
    let env_file = env_file.to_str().unwrap();
    // inherit stdio so the QR shows on the terminal
    let run = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signer"));
        cmd.args(args).args(["--phone-timeout", "180"]);
        if args[0] != "key" {
            cmd.args(["--env-file", env_file]);
        }
        cmd
            .env_remove("BASE_SEPOLIA_RPC_URL")
            .env_remove("BUNDLER_URL")
            .env_remove("GAS_WALLET_KEYFILE");
        cmd.status().expect("run agent-signer")
    };

    // 1. enrollment; the evidence survives the run when TPMSIGN_PHONE_OUT names a directory
    let out_dir = std::env::var_os("TPMSIGN_PHONE_OUT").map(PathBuf::from).unwrap_or_else(|| chain.dir.join("enrollment"));
    eprintln!("\naccount {account} on a local anvil. On the phone tap \"4. Enroll this phone for an account\", scan the QR\nbelow, read the notice, confirm. The phone and this terminal then show the same fingerprint.\n");
    // the attestation names the certificate the app was signed with; a development build is the
    // developer's own, so its digest comes from the environment (docs/MOBILE_DEV_MODE.md §2.2)
    let digest = std::env::var("TPMSIGN_ANDROID_APP_DIGEST").ok();
    let mut args = vec!["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--out", out_dir.to_str().unwrap()];
    if let Some(d) = &digest {
        args.extend(["--android-app-digest", d.as_str()]);
    }
    let status = run(&args);
    assert!(status.success(), "the enrollment failed");
    let resp: Value = serde_json::from_str(&std::fs::read_to_string(out_dir.join("enroll-response.json")).unwrap()).unwrap();
    let phone = Key {
        scalar: String::new(),
        x: resp["publicKey"]["x"].as_str().unwrap().to_string(),
        y: resp["publicKey"]["y"].as_str().unwrap().to_string(),
    };
    let fp = fingerprint_of(&phone);

    // 2. the handover, signed by the current (software) owner, to the key the phone showed
    let validator = chain.addr("p256Validator");
    chain.ok(&["owner", "add-recovery", "--agent", &cfg]);
    chain.ok(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator,
        "--public-key", &format!("{},{}", phone.x, phone.y), "--expect-fingerprint", &fp,
    ]);
    eprintln!("\nroot handed to the phone key {fp}.");

    // 3. a root operation signed on the phone
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    v["owner"] = phone_spec("owner-phone", &phone);
    let phone_cfg = chain.dir.join("phone-owner.json");
    std::fs::write(&phone_cfg, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let phone_cfg = phone_cfg.to_str().unwrap();
    // P2: the phone decodes what it signs, and its build names the project's contracts
    // (design §6.7; the app must be built with OWNER_CORE_FEATURES=ffi,test-chains to know the
    // anvil chain). The operation is a new agent permission: the phone shows the whole mandate.
    let agent2 = key(3);
    let cfg2 = chain.config(
        "owner-perm2.json",
        &Cfg {
            agent: &agent2,
            permission: "0x74657332",
            recovery: Some(&recovery),
            account: Some(account.clone()),
            ..base_cfg(&owner, &agent, &counter, until)
        },
    );
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg2).unwrap()).unwrap();
    v["owner"] = phone_spec("owner-phone", &phone);
    std::fs::write(&cfg2, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    eprintln!(
        "On the phone tap \"3. Scan the laptop's QR and sign\", scan the QR below. The review shows \"Install agent\npermission 0x74657332\" with its mandate: AgentPolicy and P256Signer named by the app, the demo counter's\nincrement allowed, the agent key {}. Scroll to the end, Sign, then your fingerprint.\n",
        fingerprint_of(&agent2)
    );
    let status = run(&["permission", "add", "--agent", &cfg2]);
    assert!(status.success(), "the phone-signed permission install failed");
    eprintln!("\nthe permission the phone installed is on-chain; the agent runs under it:");
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &cfg2]);
    assert_eq!(chain.counter(), before + U256::from(1), "the agent acts under the mandate the phone signed");
    chain.ok(&["demo", "--agent", phone_cfg]);
    eprintln!("done. The enrollment (request, answer, attestation DER) is in {}", out_dir.display());
}

// ---------------------------------------------------------------- x402

/// A minimal x402 server: 402 with PAYMENT-REQUIRED; with PAYMENT-SIGNATURE it
/// settles through USDC's transferWithAuthorization (as a facilitator would)
/// when `settle` is on, otherwise refuses.
fn x402_server(chain_url: String, usdc: String, amount: u64, settle: Arc<AtomicBool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/quote", listener.local_addr().unwrap());
    let resource = url.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut payment = None;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("payment-signature") {
                        payment = Some(value.trim().to_string());
                    }
                }
            }
            let required = json!({
                "x402Version": 2,
                "resource": {"url": resource},
                "accepts": [{"scheme": "exact", "network": "eip155:31337", "amount": amount.to_string(), "asset": usdc,
                             "payTo": PAYEE, "maxTimeoutSeconds": 60, "extra": {"name": "USDC", "version": "2"}}],
            });
            let refuse = |s: &mut TcpStream| {
                let h = B64.encode(required.to_string());
                write!(s, "HTTP/1.1 402 Payment Required\r\nPAYMENT-REQUIRED: {h}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            };
            match payment {
                Some(p) if settle.load(Ordering::SeqCst) => {
                    let v: Value = serde_json::from_slice(&B64.decode(p).unwrap()).unwrap();
                    let a = &v["payload"]["authorization"];
                    let n = |k: &str| U256::from_str_radix(a[k].as_str().unwrap(), 10).unwrap();
                    let data = transferWithAuthorizationCall {
                        from: a["from"].as_str().unwrap().parse().unwrap(),
                        to: a["to"].as_str().unwrap().parse().unwrap(),
                        value: n("value"),
                        validAfter: n("validAfter"),
                        validBefore: n("validBefore"),
                        nonce: a["nonce"].as_str().unwrap().parse().unwrap(),
                        signature: v["payload"]["signature"].as_str().unwrap().parse().unwrap(),
                    }
                    .abi_encode();
                    let tx = json!({"from": FACILITATOR, "to": usdc, "data": Bytes::from(data).to_string(), "gas": "0x989680"});
                    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction", "params": [tx]}).to_string();
                    let sent: Value = serde_json::from_str(&http_post(&chain_url, &body)).unwrap();
                    // a reverted settlement still returns a hash: check the receipt
                    let ok = sent.get("result").is_some_and(|hash| {
                        let q = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionReceipt", "params": [hash]}).to_string();
                        for _ in 0..200 {
                            let r: Value = serde_json::from_str(&http_post(&chain_url, &q)).unwrap();
                            if !r["result"].is_null() {
                                return r["result"]["status"] == "0x1";
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        false
                    });
                    if ok {
                        let settled = B64.encode(json!({"success": true, "transaction": sent["result"]}).to_string());
                        let content = "paid content";
                        write!(stream, "HTTP/1.1 200 OK\r\nPAYMENT-RESPONSE: {settled}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}", content.len()).unwrap();
                    } else {
                        refuse(&mut stream);
                    }
                }
                _ => refuse(&mut stream),
            }
        }
    });
    url
}

/// x402: a paid request settles from the account's USDC; an unsettled
/// registration expires and its budget is reclaimed.
#[test]
fn x402_pay_and_reclaim() {
    let chain = chain_or_skip!("x402");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let policy = chain.addr("agentPolicy");
    let until = far_future(&chain);

    // a USDC with the EIP-3009 + ERC-1271 path (the Solidity tests' MockUSDC)
    let deployed = chain.send_from(FACILITATOR, None, hex::decode(chain.code["mockUsdcInitCode"].as_str().unwrap().trim_start_matches("0x")).unwrap());
    let usdc = deployed["contractAddress"].as_str().unwrap().to_string();

    let cfg_for = |name: &str, account: Option<String>| {
        chain.config(
            name,
            &Cfg {
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), X402_AUTHORIZE), (policy.clone(), X402_RECLAIM)],
                account,
                tokens: json!([{"token": usdc, "maxPerOp": "1000000", "budget": "2000000", "x402": true}]),
                ..base_cfg(&owner, &agent, &counter, until)
            },
        )
    };
    let account = chain.deploy(&cfg_for("agent.json", None));
    let cfg = cfg_for("pinned.json", Some(account.clone()));
    chain.send_from(FACILITATOR, Some(&usdc), mintCall { to: account.parse().unwrap(), amount: U256::from(10_000_000u64) }.abi_encode());
    let payee_balance =
        || U256::from_be_slice(&chain.call(&usdc, balanceOfCall { account: PAYEE.parse::<Address>().unwrap() }.abi_encode()));

    let settle = Arc::new(AtomicBool::new(true));
    let url = x402_server(chain.url.clone(), usdc.clone(), 250_000, settle.clone());
    let paid = chain.ok(&["x402", "fetch", "--agent", &cfg, &url]);
    assert!(paid.contains("paid content"), "{paid}");
    assert_eq!(payee_balance(), U256::from(250_000));

    // a registration the server never settles: booked, then reclaimed after expiry
    settle.store(false, Ordering::SeqCst);
    chain.fails(&["x402", "fetch", "--agent", &cfg, &url]);
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 500000)"));
    chain.advance(300);
    let reclaimed = chain.ok(&["x402", "reclaim", "--agent", &cfg, "--from-block", "0"]);
    assert!(reclaimed.contains("reclaimed 1 expired"), "{reclaimed}");
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 250000)"));
    assert_eq!(payee_balance(), U256::from(250_000));
}

// ---------------------------------------------------------------- bundler and paymaster

/// A fake ERC-4337 bundler with the four methods `agent-signer` uses. It packs
/// the UserOperation back and submits it through the real
/// `EntryPoint.handleOps` on anvil, so the client is judged by the real
/// EntryPoint, not by a mock.
#[derive(Clone, Copy, PartialEq)]
enum FakeBundler {
    /// Publishes gas prices (`pimlico_getUserOperationGasPrice`) and accepts
    /// what it estimated.
    Plain,
    /// Publishes no prices and refuses the first submission as underpriced,
    /// naming a floor the way Pimlico does; accepts the repriced resend.
    FeeFloor,
}

fn fake_bundler(chain_url: String, entry_point: String) -> String {
    fake_bundler_with(chain_url, entry_point, FakeBundler::Plain)
}

fn fake_bundler_with(chain_url: String, entry_point: String, mode: FakeBundler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut receipts: std::collections::HashMap<String, Value> = Default::default();
        let mut refused_once = false;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let rpc = |method: &str, params: Value| -> Value {
                let b = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
                serde_json::from_str(&http_post(&chain_url, &b)).unwrap()
            };
            let result: Result<Value, String> = match req["method"].as_str().unwrap() {
                "eth_supportedEntryPoints" => Ok(json!([entry_point])),
                "pimlico_getUserOperationGasPrice" => match mode {
                    FakeBundler::Plain => Ok(json!({
                        "slow": {"maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0xf4240"},
                        "standard": {"maxFeePerGas": "0x77359400", "maxPriorityFeePerGas": "0x1e8480"},
                        "fast": {"maxFeePerGas": "0xb2d05e00", "maxPriorityFeePerGas": "0x2dc6c0"},
                    })),
                    FakeBundler::FeeFloor => Err("unsupported method pimlico_getUserOperationGasPrice".into()),
                },
                "eth_estimateUserOperationGas" => {
                    // the client estimates with a placeholder of the real signature's
                    // length: 64 bytes on the root path, 65 under a permission
                    let sig_len = req["params"][0]["signature"].as_str().map(|s| (s.len() - 2) / 2).unwrap_or(0);
                    if sig_len != 64 && sig_len != 65 {
                        Err(format!("estimate expects a 64- or 65-byte placeholder signature, got {sig_len} bytes"))
                    } else {
                        Ok(json!({
                            "preVerificationGas": "0x186a0", "verificationGasLimit": "0x16e360", "callGasLimit": "0x7a120",
                            "paymasterVerificationGasLimit": "0x186a0", "paymasterPostOpGasLimit": "0x0",
                        }))
                    }
                }
                "eth_sendUserOperation" if mode == FakeBundler::FeeFloor && !refused_once => {
                    refused_once = true;
                    let current = req["params"][0]["maxPriorityFeePerGas"]
                        .as_str()
                        .map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                        .unwrap_or(0);
                    Err(format!(
                        "error code -32602: maxPriorityFeePerGas must be at least {} (current maxPriorityFeePerGas: {current}) - \
                         use pimlico_getUserOperationGasPrice to get the current gas price",
                        current + 1
                    ))
                }
                "eth_sendUserOperation" => {
                    let op = &req["params"][0];
                    let hex_bytes = |k: &str| -> Vec<u8> {
                        op.get(k).and_then(Value::as_str).map(|s| hex::decode(s.trim_start_matches("0x")).unwrap()).unwrap_or_default()
                    };
                    let q = |k: &str| -> u128 {
                        op.get(k).and_then(Value::as_str).map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()).unwrap_or(0)
                    };
                    let pack = |hi: u128, lo: u128| -> alloy::primitives::B256 {
                        let mut b = [0u8; 32];
                        b[..16].copy_from_slice(&hi.to_be_bytes());
                        b[16..].copy_from_slice(&lo.to_be_bytes());
                        b.into()
                    };
                    let mut init_code = hex_bytes("factory");
                    init_code.extend(hex_bytes("factoryData"));
                    let mut pm = hex_bytes("paymaster");
                    if !pm.is_empty() {
                        pm.extend(q("paymasterVerificationGasLimit").to_be_bytes());
                        pm.extend(q("paymasterPostOpGasLimit").to_be_bytes());
                        pm.extend(hex_bytes("paymasterData"));
                    }
                    let packed = PackedUserOperation {
                        sender: op["sender"].as_str().unwrap().parse().unwrap(),
                        nonce: U256::from_str_radix(op["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
                        initCode: init_code.into(),
                        callData: hex_bytes("callData").into(),
                        accountGasLimits: pack(q("verificationGasLimit"), q("callGasLimit")),
                        preVerificationGas: U256::from(q("preVerificationGas")),
                        gasFees: pack(q("maxPriorityFeePerGas"), q("maxFeePerGas")),
                        paymasterAndData: pm.into(),
                        signature: hex_bytes("signature").into(),
                    };
                    let hash = rpc("eth_call", json!([{"to": entry_point, "data": Bytes::from(getUserOpHashCall { op: packed.clone() }.abi_encode()).to_string()}, "latest"]))["result"].clone();
                    let data = handleOpsCall { ops: vec![packed], beneficiary: BUNDLER_WALLET.parse().unwrap() }.abi_encode();
                    let sent = rpc("eth_sendTransaction", json!([{"from": BUNDLER_WALLET, "to": entry_point, "data": Bytes::from(data).to_string(), "gas": "0x1c9c380"}]));
                    match sent.get("result") {
                        None => Err(sent["error"]["message"].as_str().unwrap_or("handleOps failed").to_string()),
                        Some(tx) => {
                            let mut receipt = Value::Null;
                            for _ in 0..200 {
                                receipt = rpc("eth_getTransactionReceipt", json!([tx]))["result"].clone();
                                if !receipt.is_null() {
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            }
                            let event = receipt["logs"].as_array().into_iter().flatten().find(|l| l["topics"][1] == hash);
                            match (receipt["status"].as_str(), event) {
                                (Some("0x1"), Some(log)) => {
                                    let data = hex::decode(log["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                                    receipts.insert(hash.as_str().unwrap().to_string(), json!({
                                        "success": data[63] == 1,
                                        "actualGasUsed": format!("0x{}", hex::encode(&data[96..128])),
                                        "receipt": {"transactionHash": tx, "blockNumber": receipt["blockNumber"]},
                                    }));
                                    Ok(hash)
                                }
                                _ => Err("handleOps reverted".into()),
                            }
                        }
                    }
                }
                "eth_getUserOperationReceipt" => Ok(receipts.get(req["params"][0].as_str().unwrap()).cloned().unwrap_or(Value::Null)),
                m => Err(format!("unsupported method {m}")),
            };
            let reply = match result {
                Ok(r) => json!({"jsonrpc": "2.0", "id": req["id"], "result": r}),
                Err(e) => json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32500, "message": e}}),
            }
            .to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len()).unwrap();
        }
    });
    url
}

impl Chain {
    /// Deploy a WhitelistPaymaster owned by the gas wallet and name it in the
    /// deployments file, as `script/Deploy.s.sol` does.
    fn with_paymaster(&self) -> String {
        let owner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // the gas wallet (GAS_KEY)
        let mut code = hex::decode(self.code["whitelistPaymasterInitCode"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend((self.addr("entryPoint").parse::<Address>().unwrap(), owner.parse::<Address>().unwrap()).abi_encode_params());
        let receipt = self.send_from(owner, None, code);
        let paymaster = receipt["contractAddress"].as_str().unwrap().to_string();
        let path = self.dir.join("deployments.json");
        let mut d: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        d["whitelistPaymaster"] = json!(paymaster);
        d["paymasterOwner"] = json!(owner);
        std::fs::write(&path, d.to_string()).unwrap();
        paymaster
    }
}

/// An account with no ETH at all: deployed and run on the paymaster's
/// deposit; then operations delivered through an ERC-4337 bundler, sponsored
/// and not.
#[test]
fn sponsored_and_bundled() {
    let chain = chain_or_skip!("bundled");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    chain.with_paymaster();
    let cfg = chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until));

    chain.ok(&["paymaster", "deposit", "--agent", &cfg, "--wei", "1000000000000000000"]);
    chain.ok(&["paymaster", "stake", "--agent", &cfg, "--wei", "100000000000000000"]);
    chain.ok(&["paymaster", "sponsor", "--agent", &cfg, "--budget", "100000000000000000", "--max-per-op", "10000000000000000"]);
    // no `account fund`: the paymaster pays for the deployment and the call
    let before = chain.counter();
    let self_bundled = chain.ok(&["demo", "--agent", &cfg, "--sponsored"]);
    assert!(self_bundled.contains("gas paid by:    paymaster"), "{self_bundled}");
    assert_eq!(chain.counter(), before + U256::from(1));
    let status = chain.ok(&["account", "status", "--agent", &cfg]);
    assert!(status.contains("deployed"), "{status}");

    // through a bundler: sponsored, then paid by the account
    let bundler = fake_bundler(chain.url.clone(), chain.addr("entryPoint"));
    let via = chain.ok(&["demo", "--agent", &cfg, "--sponsored", "--bundler", &bundler]);
    assert!(via.contains("bundler accepted"), "{via}");
    // priced by the bundler, estimated with a placeholder, signed once
    assert!(via.contains("gas prices:     from the bundler"), "{via}");
    assert!(via.contains("+20% margin"), "{via}");
    assert!(!via.contains("signing once more"), "{via}");
    assert_eq!(chain.counter(), before + U256::from(2));
    chain.ok(&["account", "fund", "--agent", &cfg, "--wei", "100000000000000000"]);
    chain.ok(&["demo", "--agent", &cfg, "--bundler", &bundler]);
    assert_eq!(chain.counter(), before + U256::from(3));
    // a bundler that publishes no prices and enforces a priority-fee floor at
    // submission: the operation is repriced, signed once more and accepted
    let strict = fake_bundler_with(chain.url.clone(), chain.addr("entryPoint"), FakeBundler::FeeFloor);
    let repriced = chain.ok(&["demo", "--agent", &cfg, "--bundler", &strict]);
    assert!(repriced.contains("repricing and signing once more"), "{repriced}");
    assert!(repriced.contains("bundler accepted"), "{repriced}");
    assert_eq!(chain.counter(), before + U256::from(4));
    // a refused operation through the bundler is reported, not swallowed
    let refused = chain.fails(&["op", "send", "--agent", &cfg, "--bundler", &bundler, "--target", "0x000000000000000000000000000000000000dEaD", "--wei", "1"]);
    assert!(!refused.is_empty());

    // the owner delists the account: no more sponsorship
    chain.ok(&["paymaster", "sponsor", "--agent", &cfg, "--revoke"]);
    chain.fails(&["demo", "--agent", &cfg, "--sponsored"]);
}

// ---------------------------------------------------------------- Safe

const SAFE_EXEC: &str = "0x6a761202";
const MULTISEND: &str = "0x8d80ff0a";

/// `Safe.execTransaction` with a pre-validated signature from `owner` (r =
/// owner, s = 0, v = 1: valid because the owner itself is msg.sender).
fn exec(owner: &str, to: &str, data: Vec<u8>, operation: u8) -> String {
    let owner: Address = owner.parse().unwrap();
    let mut sig = vec![0u8; 12];
    sig.extend(owner.as_slice());
    sig.extend([0u8; 32]);
    sig.push(1);
    let call = execTransactionCall {
        to: to.parse().unwrap(), value: U256::ZERO, data: data.into(), operation,
        safeTxGas: U256::ZERO, baseGas: U256::ZERO, gasPrice: U256::ZERO,
        gasToken: Address::ZERO, refundReceiver: Address::ZERO, signatures: sig.into(),
    };
    Bytes::from(call.abi_encode()).to_string()
}

/// The agent drives a Safe its Kernel owns: every Safe transaction is paired
/// with an on-chain Safe-nonce assertion, the inner call is judged by the
/// mandate, and a replay or a self-administration attempt goes nowhere.
#[test]
fn safe_guarded() {
    let chain = chain_or_skip!("safe");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));

    // a Safe v1.3.0 owned by the Kernel alone
    let setup = setupCall {
        _owners: vec![account.parse().unwrap()], _threshold: U256::from(1), to: Address::ZERO, data: Bytes::new(),
        fallbackHandler: Address::ZERO, paymentToken: Address::ZERO, payment: U256::ZERO, paymentReceiver: Address::ZERO,
    }
    .abi_encode();
    let created = chain.send_from(
        FACILITATOR,
        Some(&chain.addr("safeProxyFactory")),
        createProxyWithNonceCall { _singleton: chain.addr("safeSingletonL2").parse().unwrap(), initializer: setup.into(), saltNonce: U256::from(7) }.abi_encode(),
    );
    let log = created["logs"].as_array().unwrap().iter().find(|l| l["address"].as_str().unwrap().eq_ignore_ascii_case(&chain.addr("safeProxyFactory"))).unwrap();
    let safe = format!("0x{}", &log["data"].as_str().unwrap()[26..66]);
    let owners = chain.call(&safe, getOwnersCall {}.abi_encode());
    assert!(hex::encode(&owners).contains(&account[2..].to_lowercase()), "the Kernel owns the Safe");

    // the owner adds a permission that may drive the Safe
    let multisend = chain.addr("multiSendCallOnly");
    let cfg = chain.config(
        "safe.json",
        &Cfg {
            permission: "0x73616631", account: Some(account.clone()),
            allow: vec![(safe.clone(), SAFE_EXEC), (counter.clone(), INCREMENT), (multisend.clone(), MULTISEND)],
            ..base_cfg(&owner, &agent, &counter, until)
        },
    );
    chain.ok(&["permission", "add", "--agent", &cfg]);

    let increment = hex::decode(&INCREMENT[2..]).unwrap();
    let once = exec(&account, &counter, increment.clone(), 0);
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &once, "--safe-nonce", "0"]);
    assert_eq!(chain.counter(), before + U256::from(1));

    // a replay of the same Safe transaction cannot run again
    chain.fails(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &once, "--safe-nonce", "0"]);
    assert_eq!(chain.counter(), before + U256::from(1));
    // and a Safe transaction without its nonce assertion is not even sent
    let bare = chain.fails(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &once]);
    assert!(bare.contains("--safe-nonce"), "{bare}");

    // the Safe adding an owner: refused by the mandate, the owners stay
    let add_owner = exec(&account, &safe, addOwnerWithThresholdCall { owner: PAYEE.parse().unwrap(), _threshold: U256::from(1) }.abi_encode(), 0);
    let refused = chain.fails(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &add_owner, "--safe-nonce", "1"]);
    assert!(refused.contains("3e4983f6") || refused.to_lowercase().contains("policy"), "{refused}");
    assert_eq!(chain.call(&safe, getOwnersCall {}.abi_encode()), owners);

    // a MultiSendCallOnly batch of two allowed calls (DELEGATECALL into the batcher)
    let mut legs = Vec::new();
    for _ in 0..2 {
        legs.push(0u8);
        legs.extend(counter.parse::<Address>().unwrap().as_slice());
        legs.extend([0u8; 32]);
        legs.extend(U256::from(increment.len()).to_be_bytes::<32>());
        legs.extend(&increment);
    }
    let batch = exec(&account, &multisend, multiSendCall { transactions: legs.into() }.abi_encode(), 1);
    chain.ok(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &batch, "--safe-nonce", "1"]);
    assert_eq!(chain.counter(), before + U256::from(3));
    assert_eq!(U256::from_be_slice(&chain.call(&safe, nonceCall {}.abi_encode())), U256::from(2));
}
