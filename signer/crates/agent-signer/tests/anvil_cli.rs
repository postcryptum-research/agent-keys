//! End-to-end tests of the `agent-signer` CLI on a local chain.
//!
//! Each test starts its own `anvil`, installs the account-abstraction stack
//! and this project's modules from `fixtures/chain-code.json` (runtime bytecode
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

    /// The CLI with this chain's `.env`, never the developer's.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signer"));
        cmd.args(args).env_remove("BASE_SEPOLIA_RPC_URL");
        if args.first() != Some(&"key") {
            // `key` commands talk to a device, not to the chain
            cmd.args(["--env-file", self.dir.join(".env").to_str().unwrap()]);
        }
        cmd.env_remove("BASE_SEPOLIA_RPC_URL")
            .env_remove("BUNDLER_URL")
            .env_remove("GAS_WALLET_KEYFILE");
        cmd
    }

    /// Run the CLI. Its standard input is closed, as for any command nobody answers.
    fn cli(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// `owner set-root` to a key on another machine (issue #51): the command prints a
    /// challenge and waits on its standard input for the proof.
    fn handover(&self, args: &[&str]) -> Handover {
        let mut child = self.command(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut challenge = String::new();
        out.read_line(&mut challenge).unwrap();
        assert!(challenge.starts_with("tpmsign-handover-challenge:1:"), "no challenge from {args:?}: {challenge:?}");
        Handover { child, out, challenge: challenge.trim().to_string() }
    }

    /// `key prove` on "the machine that holds the key": the proof line for `challenge`.
    fn prove(&self, holder: &Key, challenge: &str) -> String {
        let said = self.ok(&["key", "prove", "--key", &spec(holder), "--challenge", challenge]);
        said.lines().find(|l| l.starts_with("tpmsign-handover-proof:1:")).unwrap_or_else(|| panic!("no proof in: {said}")).to_string()
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

/// A handover that has printed its challenge and waits for the proof.
struct Handover {
    child: Child,
    out: BufReader<std::process::ChildStdout>,
    challenge: String,
}

impl Handover {
    /// Paste a line and leave the command waiting for the next.
    fn say(&mut self, line: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{line}").unwrap();
    }

    /// Paste `proof` and let the command finish: whether it succeeded, and all it said.
    fn answer(mut self, proof: &str) -> (bool, String) {
        writeln!(self.child.stdin.take().unwrap(), "{proof}").unwrap();
        let mut said = String::new();
        self.out.read_to_string(&mut said).unwrap();
        let rest = self.child.wait_with_output().unwrap();
        (rest.status.success(), format!("{said}{}", String::from_utf8_lossy(&rest.stderr)))
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
    let point = sk.verifying_key().to_sec1_point(false);
    Key {
        scalar: format!("0x{}", hex::encode(bytes)),
        x: format!("0x{}", hex::encode(point.x().unwrap())),
        y: format!("0x{}", hex::encode(point.y().unwrap())),
    }
}

/// A test key as a config names it: what `--new-key` and `key prove --key` take.
fn spec(k: &Key) -> String {
    json!({"software": k.scalar}).to_string()
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

    // Permit2 is never a valid target either: its own `approve` would hand a
    // token's allowance to any address, a call no policy reads
    let permit2 = chain.config(
        "permit2.json",
        &Cfg {
            owner: &owner, agent: &agent, permission: "0x70726d32",
            allow: vec![("0x000000000022d473030f116ddee9f6b43ac78ba3".to_string(), "0x87517c45")],
            account: Some(account.clone()), recovery: None, valid_after: 0, valid_until: until, tokens: Value::Null,
        },
    );
    let refused = chain.fails(&["permission", "add", "--agent", &permit2]);
    assert!(refused.contains("never a valid target for the agent") && refused.contains("Permit2"), "{refused}");

    // a payee list: the mandate installs on the deployed policy (the harness runs Base
    // Sepolia's code) and the chain reports the list as the config states it. That a
    // transfer outside the list is refused is the contract tests' part: the "token"
    // here is the demo counter, which has no transfer to run
    let listed = chain.config(
        "listed.json",
        &Cfg {
            owner: &owner, agent: &agent, permission: "0x6c697374", allow: vec![(counter.clone(), "0xa9059cbb")],
            account: Some(account.clone()), recovery: None, valid_after: 0, valid_until: until,
            tokens: json!([{"token": counter, "maxPerOp": "1", "budget": "2", "payees": ["0x00000000000000000000000000000000000000d1"]}]),
        },
    );
    chain.ok(&["permission", "add", "--agent", &listed]);
    let shown = chain.ok(&["permission", "show", "--agent", &listed]);
    assert!(shown.contains("ok payee") && shown.to_lowercase().contains("00000000000000000000000000000000000000d1"), "{shown}");
    assert!(!shown.contains("DIFF"), "{shown}");
    // a token with limits and no word on who may be paid: the config loads
    // (status and revoke still work from it), but no mandate is installed
    let silent = chain.config(
        "silent.json",
        &Cfg {
            owner: &owner, agent: &agent, permission: "0x73696c65", allow: vec![(counter.clone(), "0xa9059cbb")],
            account: Some(account.clone()), recovery: None, valid_after: 0, valid_until: until,
            tokens: json!([{"token": counter, "maxPerOp": "1", "budget": "2"}]),
        },
    );
    chain.ok(&["account", "status", "--agent", &silent]);
    let refused = chain.fails(&["permission", "add", "--agent", &silent]);
    assert!(refused.contains("does not say who may be paid"), "{refused}");
    let stated = chain.config(
        "stated.json",
        &Cfg {
            owner: &owner, agent: &agent, permission: "0x73746174", allow: vec![(counter.clone(), "0xa9059cbb")],
            account: Some(account.clone()), recovery: None, valid_after: 0, valid_until: until,
            tokens: json!([{"token": counter, "maxPerOp": "1", "budget": "2", "payees": "anyone"}]),
        },
    );
    chain.ok(&["permission", "add", "--agent", &stated]);

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
    // the new owner's key is on this machine: it shows that it can sign in the same command (issue #51)
    let said = chain.ok(&[
        "owner", "set-root", "--agent", &old_cfg, "--as-recovery", "--not-a-phone",
        "--validator", &validator, "--retire", &validator, "--public-key", &public_key, "--new-key", &spec(&new_owner),
    ]);
    assert!(said.contains(&format!("holds the key {} (signed a fresh challenge)", fingerprint_of(&new_owner))), "{said}");

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

/// Issue #51: `owner set-root --not-a-phone` hands the root to a key in one step, and the
/// new key has no accept step. A fingerprint shows which public key was pasted, not that
/// anybody can sign with it. So the key shows that first, by signing a challenge the command
/// prints; `key prove` answers it on the machine that holds the key. Each refusal below
/// leaves the root where it was.
#[test]
fn a_handover_waits_for_the_new_key_to_show_it_can_sign() {
    let chain = chain_or_skip!("handover-proof");
    let (owner, agent, recovery, second, third, stranger) = (key(1), key(2), key(4), key(6), key(7), key(8));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let with = |name: &str, o: &Key| {
        chain.config(name, &Cfg { owner: o, recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(o, &agent, &counter, until) })
    };
    let cfg = with("owner.json", &owner);
    chain.ok(&["owner", "add-recovery", "--agent", &cfg]);
    let validator = chain.addr("p256Validator");
    let to = |from: &str, k: &Key| -> Vec<String> {
        ["owner", "set-root", "--agent", from, "--validator", &validator, "--retire", &validator, "--public-key", &format!("{},{}", k.x, k.y), "--not-a-phone"]
            .map(String::from)
            .to_vec()
    };
    fn refs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }
    let to_second = to(&cfg, &second);
    let root_is = |k: &Key| chain.ok(&["owner", "status", "--agent", &cfg]).contains(&format!("root key:       fingerprint {}", fingerprint_of(k)));

    // nobody answers: refused, and the refusal says what would be accepted
    let err = chain.fails(&refs(&to_second));
    assert!(err.contains("tpmsign-handover-challenge:1:") && err.contains("no proof of possession"), "{err}");
    assert!(err.contains("key prove") && err.contains("--new-key") && err.contains("--no-proof-of-possession") && err.contains("Nothing sent"), "{err}");

    // a proof by another key, made for that key's own challenge on the same account
    let waiting = chain.handover(&refs(&to_second));
    let for_stranger = chain.handover(&refs(&to(&cfg, &stranger)));
    let (ok, said) = waiting.answer(&chain.prove(&stranger, &for_stranger.challenge));
    assert!(!ok && said.contains("does not verify") && said.contains("nothing sent"), "{said}");
    let _ = for_stranger.answer("");

    // the key's own command refuses to sign for a challenge that names another key
    let waiting = chain.handover(&refs(&to_second));
    let challenge = waiting.challenge.clone();
    let err = chain.fails(&["key", "prove", "--key", &spec(&stranger), "--challenge", &challenge]);
    assert!(err.contains("not the key the root is going to; nothing signed"), "{err}");
    // ... and a challenge it cannot read back as it was printed, or that is not one
    let err = chain.fails(&["key", "prove", "--key", &spec(&second), "--challenge", &challenge.to_uppercase()]);
    assert!(err.contains("not a handover challenge"), "{err}");
    let err = chain.fails(&["key", "prove", "--key", &spec(&second), "--challenge", &challenge.replacen(":0x", ":0X", 1)]);
    assert!(err.contains("not in the form"), "{err}");

    // the right key, for another account and for another chain: the challenge line is what is
    // signed, so a proof for a line that differs in either does not verify here
    let field = |line: &str, i: usize, value: &str| {
        let mut f: Vec<&str> = line.split(':').collect();
        f[i] = value;
        f.join(":")
    };
    let other_account = field(&challenge, 3, &format!("0x{}", "11".repeat(20)));
    let (ok, said) = waiting.answer(&chain.prove(&second, &other_account));
    assert!(!ok && said.contains("does not verify") && said.contains("nothing sent"), "{said}");
    let waiting = chain.handover(&refs(&to_second));
    let chain_id: u64 = waiting.challenge.split(':').nth(2).unwrap().parse().unwrap();
    let other_chain = field(&waiting.challenge, 2, &(chain_id + 1).to_string());
    let (ok, said) = waiting.answer(&chain.prove(&second, &other_chain));
    assert!(!ok && said.contains("does not verify") && said.contains("nothing sent"), "{said}");

    // the right key and the right challenge, too late
    let mut slow = to_second.clone();
    slow.extend(["--proof-timeout", "1"].map(String::from));
    let waiting = chain.handover(&refs(&slow));
    std::thread::sleep(Duration::from_millis(2500));
    let proof = chain.prove(&second, &waiting.challenge);
    let (ok, said) = waiting.answer(&proof);
    assert!(!ok && said.contains("after the challenge expired") && said.contains("nothing sent"), "{said}");
    // ... and after the expiry an empty line ends the wait as well: Enter is answered, not skipped
    let waiting = chain.handover(&refs(&slow));
    std::thread::sleep(Duration::from_millis(2500));
    let (ok, said) = waiting.answer("");
    assert!(!ok && said.contains("the challenge expired") && said.contains("Nothing sent"), "{said}");

    // something that is not a proof
    let (ok, said) = chain.handover(&refs(&to_second)).answer("tpmsign-handover-proof:1:0x00");
    assert!(!ok && said.contains("not a proof of possession"), "{said}");

    // a key on this machine names itself; it must be the key the command names
    let mut two_keys = to_second.clone();
    two_keys.extend(["--new-key".to_string(), spec(&stranger)]);
    let err = chain.fails(&refs(&two_keys));
    assert!(err.contains("which of the two does the root go to"), "{err}");
    // a phone's spec, complete or not, is sent to its own way by `key prove` as well
    let err = chain.fails(&["key", "prove", "--key", r#"{"phone": {"label": "p"}}"#, "--challenge", &challenge]);
    assert!(err.contains("--to-phone") && !err.contains("missing field"), "{err}");
    // a phone's key has its own way, and the override does not combine with a proof
    let mut a_phone = to_second.clone();
    a_phone.extend(["--new-key".to_string(), json!({"phone": {"label": "p", "publicKey": {"x": second.x, "y": second.y}, "fingerprint": "A"}}).to_string()]);
    assert!(chain.fails(&refs(&a_phone)).contains("--to-phone"));
    let mut both = to_second.clone();
    both.extend(["--no-proof-of-possession".to_string(), "--new-key".to_string(), spec(&second)]);
    assert!(chain.fails(&refs(&both)).contains("cannot be used with"));

    // nothing was sent by any of the above
    assert!(root_is(&owner), "the root moved without a proof");

    // the override names the risk and goes through
    let mut unproven = to_second.clone();
    unproven.push("--no-proof-of-possession".into());
    let said = chain.ok(&refs(&unproven));
    assert!(said.contains("WARNING: no proof of possession") && said.contains("the account goes with it"), "{said}");
    assert!(root_is(&second));

    // and the whole path between two machines: challenge, `key prove`, the proof pasted back.
    // A line that is not the proof does not end the wait: the wrong line, an empty one and a
    // proof for another challenge are each said to be so, and the right proof is still taken.
    let cfg2 = with("second.json", &second);
    let mut waiting = chain.handover(&refs(&to(&cfg2, &third)));
    let proof = chain.prove(&third, &waiting.challenge);
    waiting.say("the wrong line from the other terminal");
    waiting.say("");
    waiting.say(&chain.prove(&third, &field(&waiting.challenge, 3, &format!("0x{}", "22".repeat(20)))));
    let (ok, said) = waiting.answer(&proof);
    assert!(ok, "{said}");
    assert!(said.matches("not accepted:").count() == 2 && said.contains("paste the proof again"), "{said}");
    assert!(said.contains(&format!("holds the key {} (signed a fresh challenge)", fingerprint_of(&third))) && said.contains("root handed to"), "{said}");
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &with("third.json", &third), "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1));
    // a proof is good for one run: the same line pasted into a second handover does not verify
    let cfg3 = with("third.json", &third);
    let (ok, said) = chain.handover(&refs(&to(&cfg3, &third))).answer(&proof);
    assert!(!ok && said.contains("does not verify"), "{said}");
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
        "--not-a-phone", "--new-key", &spec(&new_owner),
    ]);
    assert!(refused.contains("owner add-recovery"), "{refused}");

    // with the recovery key installed, the rotation goes through in one operation
    let old_cfg = with("owner.json", &owner, Some(&recovery));
    chain.ok(&["owner", "add-recovery", "--agent", &old_cfg]);
    // the handover must be told what the new key is (issue #38): with neither statement it
    // refuses before anything is read or built, and the two together are a usage error
    let untold = ["owner", "set-root", "--agent", &old_cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key];
    let err = chain.fails(&untold);
    assert!(err.contains("say what the new key is") && err.contains("--to-phone") && err.contains("--not-a-phone"), "{err}");
    assert!(err.contains("Nothing built, nothing sent") && !err.contains("new root key"), "{err}");
    let err = chain.fails(&[&untold[..], &["--to-phone", "p", "--not-a-phone"]].concat());
    assert!(err.contains("cannot be used with"), "{err}");
    // after a recovery too: the same command, the same rule
    let err = chain.fails(&[&untold[..], &["--as-recovery"]].concat());
    assert!(err.contains("say what the new key is"), "{err}");
    // the key names itself with --new-key, so --public-key may be left out
    chain.ok(&[
        "owner", "set-root", "--agent", &old_cfg, "--validator", &validator, "--retire", &validator, "--not-a-phone", "--new-key",
        &spec(&new_owner),
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
/// evidence that is not a chain). `prove` answers a health request as an
/// honest phone that holds `key` for the account — it signs when that is the
/// key the laptop named and says so when it is not; `prove-lost` is the phone
/// that no longer holds a key; `prove-forge` signs with `key` whatever the
/// laptop named. Every answer carries the MAC of the QR's secret,
/// as the app's does; a mode ending in `-nomac` posts without it — a host on
/// the network that saw the session URL but never the QR.
///
/// The thread returns whether the laptop **confirmed** the answer: its reply
/// was the confirmation MAC under the session's secret, the only thing the
/// app takes as "the laptop has it".
fn phone_simulator(qr_file: std::path::PathBuf, key: Key, mode: &'static str) -> std::thread::JoinHandle<bool> {
    phone_simulator_after(qr_file, key, mode, Duration::ZERO)
}

/// `delay` holds the answer back, so another "phone" can post first.
fn phone_simulator_after(qr_file: std::path::PathBuf, key: Key, mode: &'static str, delay: Duration) -> std::thread::JoinHandle<bool> {
    use owner_core::enroll::{EnrollRequest, EnrollResponse};
    use owner_core::request::{answer_mac, commitment, verify_confirmation_mac, AppInfo, QrPayload, SignRequest, SignResponse, MAC_HEADER};
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
            let reply = http_post_with(&qr.url, &body, &headers);
            verify_confirmation_mac(&qr.secret, body.as_bytes(), &reply)
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
        if mode.starts_with("prove") {
            use owner_core::health::{health_digest, HealthRequest, HealthResponse};
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let req = HealthRequest::parse(&bytes, now, 300).expect("a well-formed health request");
            assert_eq!(req.chain_id().unwrap(), 31337);
            let held = match mode {
                "prove" => req.held(Some(&pk)),
                "prove-lost" => req.held(None),
                "prove-forge" => Ok(()),
                other => panic!("mode {other}"),
            };
            let resp = match held {
                Ok(()) => {
                    let phone_nonce = B256::repeat_byte(0x5a);
                    let mut scalar = [0u8; 32];
                    scalar.copy_from_slice(&hex::decode(&key.scalar[2..]).unwrap());
                    let sig: p256::ecdsa::Signature =
                        SigningKey::from_bytes(&scalar.into()).unwrap().sign_prehash(&health_digest(&req.nonce, &phone_nonce)).unwrap();
                    let (r, s) = sig.split_bytes();
                    HealthResponse::signed(&qr.commitment, phone_nonce, &hw_signer::Signature { r: r.into(), s: s.into() }, app)
                }
                Err((reason, detail)) => HealthResponse::refused(&qr.commitment, reason, Some(detail), app),
            };
            return post(resp.to_bytes());
        }
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
            return post(resp.to_bytes());
        }
        let req = SignRequest::parse(&bytes, now, 300).expect("a well-formed request");
        assert_eq!(req.nonce_key().unwrap(), U256::ZERO, "the phone signs root operations only");
        // the phone's own review, with the facts its build embeds (design §6, §6.7): it signs
        // the hash that review recomputed, or answers with the review's refusal
        let me = owner_core::review::EnrolledAccount::new(req.chain_id().unwrap(), req.entry_point, req.user_op.sender);
        let review = owner_core::review::open_request_with_build_facts(&bytes, &qr.commitment, now, &[me]);
        if let owner_core::review::Verdict::Refuse(why) = &review.verdict {
            let resp = SignResponse::refused(&qr.commitment, "core", Some(why.clone()), app);
            return post(resp.to_bytes());
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
        post(resp.to_bytes())
    })
}

/// A host on the path between a phone and the laptop (issue #38): it points
/// the session's URL at itself, forwards the phone's requests to the laptop
/// untouched, and replaces the laptop's reply to the phone's answer. That
/// needs no secret. The laptop has accepted the answer; the phone sees no
/// confirmation. The phone gets the QR with the attacker's address through
/// `phone_qr`, when it takes the QR's text from a file, or off this terminal,
/// when it has a camera (the laptop's own QR is then not shown).
fn path_attacker(laptop_qr: PathBuf, phone_qr: Option<PathBuf>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let uri = loop {
            if let Ok(u) = std::fs::read_to_string(&laptop_qr) {
                if u.starts_with("tpmsign:") {
                    break u;
                }
            }
            assert!(started.elapsed() < Duration::from_secs(30), "the CLI never showed a QR");
            std::thread::sleep(Duration::from_millis(50));
        };
        // tpmsign:1?u=http://<host>:<port>/s/<token>&h=…&k=…
        let laptop = uri.split("u=http://").nth(1).unwrap().split('/').next().unwrap().to_string();
        let listener = TcpListener::bind(format!("{}:0", laptop.rsplit_once(':').unwrap().0)).unwrap();
        let uri = uri.replacen(&laptop, &listener.local_addr().unwrap().to_string(), 1);
        match &phone_qr {
            Some(file) => std::fs::write(file, &uri).unwrap(),
            None => {
                use qrcode::render::unicode;
                let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
                let qr = code.render::<unicode::Dense1x2>().dark_color(unicode::Dense1x2::Light).light_color(unicode::Dense1x2::Dark).quiet_zone(true).build();
                eprintln!("{qr}\n(this QR leads to a host on the path, not to the laptop; waiting for the phone…)");
            }
        }
        for stream in listener.incoming() {
            let mut phone = stream.unwrap();
            let mut reader = BufReader::new(phone.try_clone().unwrap());
            // one request: its head, then a body of Content-Length bytes
            let (mut head, mut length) = (Vec::new(), 0usize);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if !lower.starts_with("connection:") {
                    head.extend_from_slice(line.as_bytes());
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            let mut upstream = TcpStream::connect(&laptop).unwrap();
            upstream.write_all(&[&head[..], b"Connection: close\r\n\r\n", &body[..]].concat()).unwrap();
            let mut reply = Vec::new();
            upstream.read_to_end(&mut reply).unwrap();
            if head.starts_with(b"POST ") {
                // the laptop's confirmation stops here
                phone.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                return;
            }
            phone.write_all(&reply).unwrap();
        }
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
    // the fingerprint is asked for by default, which needs a terminal: said before any QR
    let err = chain.fails(&["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--listen", "127.0.0.1:0", "--phone-timeout", "5"]);
    assert!(err.contains("--phone-fingerprint") && err.contains("--phone-skip-fingerprint"), "{err}");
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
    assert!(sim.join().unwrap(), "the laptop's reply is its confirmation under the session's secret, not a bare 200");
    // the secret is in the QR and the QR file, never in the text the terminal keeps
    let shown_uri = text.lines().find(|l| l.starts_with("tpmsign:1?")).expect("the URI line");
    assert!(shown_uri.ends_with("&k=<in the QR only>"), "{shown_uri}");
    let real_uri = std::fs::read_to_string(&qr_file).unwrap();
    let secret = real_uri.rsplit("&k=").next().unwrap();
    assert!(secret.len() == 22 && !text.contains(secret), "the session secret is not printed");
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
    assert!(text.contains("names sent to the phone") && text.contains("counter (config)"), "{text}");
    let req: Value = serde_json::from_str(&std::fs::read_to_string(odd_out.join("enroll-request.json")).unwrap()).unwrap();
    let pins = req["laptopPins"].as_object().expect("the request carries the pins");
    assert_eq!(pins.len(), 1, "{pins:?}");
    let (pinned, name) = pins.iter().next().unwrap();
    assert_eq!((pinned.to_lowercase().as_str(), name.as_str().unwrap()), (stranger, "counter (config)"));
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
    assert_eq!(snippet["owner"]["phone"]["revocation"], "not checked");
    assert_eq!(snippet["owner"]["phone"]["bootState"], "none", "no evidence, so no boot state either");

    // 3b. the answer is authenticated by the secret in the QR: a host on the network that saw
    // the session URL in the phone's GET, but never the QR, posts its own key first. With the
    // fingerprint check skipped, it is still ignored (no MAC), gets no confirmation, and the
    // phone's answer is the one accepted and confirmed.
    let _ = std::fs::remove_file(&qr_file);
    let intruder = phone_simulator(qr_file.clone(), key(8), "enroll-nomac");
    let real = phone_simulator_after(qr_file.clone(), key(9), "enroll", Duration::from_millis(1500));
    let text = chain.ok(&[
        "key", "create", "--phone", "owner-phone", "--agent", &cfg, "--allow-no-attestation", "--phone-skip-fingerprint",
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    assert!(!intruder.join().unwrap(), "the intruder got no confirmation");
    assert!(real.join().unwrap(), "the phone did");
    assert!(text.contains("without this session's secret was ignored"), "{text}");
    assert!(text.contains(&format!("fingerprint    {fp}   ← not confirmed here (--phone-skip-fingerprint)")), "{text}");
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

    // the enrollment's own next step names the proof
    assert!(text.contains("--to-phone owner-phone") && text.contains("Do not hand root to a phone key without it"), "{text}");

    // 4. the handover goes only to the key the owner saw
    let validator = chain.addr("p256Validator");
    let public_key = format!("{},{}", phone.x, phone.y);
    chain.ok(&["owner", "add-recovery", "--agent", &cfg]);
    let other = fingerprint_of(&key(8));
    let err = chain.fails(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
        "--expect-fingerprint", &other, "--to-phone", "owner-phone",
    ]);
    assert!(err.contains(&format!("has fingerprint {fp}, not the expected {other}")), "{err}");
    let err = chain.fails(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key",
        &format!("{},{}", phone.x, "0x".to_string() + &"11".repeat(32)),
        "--to-phone", "owner-phone",
    ]);
    assert!(err.contains("not a point on P-256"), "{err}");

    // 4a. and only once the phone has shown that it holds that key (issue #38). The laptop
    // accepted the enrollment above; whether the phone kept the key is the phone's to show.
    // A phone that lost it — the laptop's confirmation never arrived and an old app deleted the
    // key, or the app was removed since — a phone holding another key for the account, and an
    // answer signed by another key all stop the handover before anything is signed or sent.
    let handover = [
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
        "--expect-fingerprint", &fp, "--to-phone", "owner-phone", "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ];
    for (mode, held, why) in [
        ("prove-lost", key(9), "the phone refused: no-key (this phone holds no key for the account)"),
        ("prove", key(8), "the phone refused: other-key"),
        ("prove-forge", key(8), "is not by the key the laptop named"),
    ] {
        let sim = phone_simulator(qr_file.clone(), held, mode);
        let err = chain.fails(&handover);
        assert!(!sim.join().unwrap(), "{mode}: the laptop confirmed an answer that proves nothing");
        assert!(err.contains("did not show that it holds the key") && err.contains(why) && err.contains("nothing sent"), "{mode}: {err}");
        assert!(!err.contains("userOpHash"), "{mode}: no operation was built for signing: {err}");
        let _ = std::fs::remove_file(&qr_file);
    }
    // nothing was sent: the old owner key is still root, and signs. `owner status` names the
    // root key, which is what the owner compares with a phone's screen before a key is deleted
    // there (design §5.4, issue #40)
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1), "root did not move");
    let status = chain.ok(&["owner", "status", "--agent", &cfg]);
    assert!(status.contains(&format!("root key:       fingerprint {}", fingerprint_of(&owner))), "{status}");
    assert!(!status.contains(&fp), "the phone's key is not root yet: {status}");

    // 4b. the phone holds the key and shows it: the handover goes through
    let sim = phone_simulator(qr_file.clone(), key(9), "prove");
    let text = chain.ok(&handover);
    assert!(sim.join().unwrap(), "the laptop confirms the proof");
    assert!(text.contains(&format!("fingerprint {fp}")) && text.contains(&format!("phone:          holds the key {fp}")), "{text}");
    let _ = std::fs::remove_file(&qr_file);
    let status = chain.ok(&["owner", "status", "--agent", &cfg]);
    assert!(status.contains(&format!("root key:       fingerprint {fp}")) && status.contains("installed = true"), "{status}");

    // 5. the phone is root: the config points at it; a root operation goes through the session
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    v["owner"] = snippet["owner"].clone();
    let phone_cfg = chain.dir.join("phone-owner.json");
    std::fs::write(&phone_cfg, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let phone_cfg = phone_cfg.to_str().unwrap();
    let shown = chain.ok(&["key", "show", "--phone", "owner-phone", "--agent", phone_cfg]);
    assert!(shown.contains(&format!("fingerprint {fp}")) && shown.contains("attestation none") && shown.contains("revocation  not checked"), "{shown}");
    assert!(shown.contains("boot state  none"), "{shown}");
    // a phone's key is deleted on the phone; the laptop says where, and what to look at first
    let err = chain.fails(&["key", "evict", "--phone", "owner-phone", "--agent", phone_cfg]);
    assert!(err.contains("Delete on that enrollment") && err.contains("owner status") && err.contains("takes the account with it"), "{err}");
    // the health check (§2.4): the same proof, any time, without a transaction
    let check = ["key", "check", "--phone", "owner-phone", "--agent", phone_cfg, "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60"];
    let sim = phone_simulator(qr_file.clone(), key(9), "prove");
    let text = chain.ok(&check);
    assert!(sim.join().unwrap());
    assert!(text.contains(&format!("OK: phone owner-phone holds its key {fp}")), "{text}");
    let _ = std::fs::remove_file(&qr_file);
    let sim = phone_simulator(qr_file.clone(), key(9), "prove-lost");
    let err = chain.fails(&check);
    sim.join().unwrap();
    assert!(err.contains("did not show that it holds the key") && err.contains("no-key"), "{err}");
    let _ = std::fs::remove_file(&qr_file);
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

/// Issue #38. A host on the path forwards the phone's enrollment answer and
/// replaces the laptop's reply, which needs no secret: the laptop says
/// "enrolled", the phone saw no confirmation. Nothing at the handover used to
/// notice, and root could go to a key the phone had deleted. Now the handover
/// to a phone waits for the phone to show the key: a phone that no longer
/// holds it stops everything before a transaction, and a phone that kept it
/// takes over as if nothing had happened.
#[test]
fn a_replaced_confirmation_does_not_cost_the_account() {
    let chain = chain_or_skip!("phone-lost");
    let (owner, agent, recovery, phone) = (key(1), key(2), key(4), key(9));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let cfg = chain.config(
        "owner.json",
        &Cfg { recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    let (laptop_qr, phone_qr) = (chain.dir.join("laptop.qr"), chain.dir.join("phone.qr"));
    let qr = phone_qr.to_str().unwrap();
    let fp = fingerprint_of(&phone);

    // the enrollment, with the host on the path
    let attacker = path_attacker(laptop_qr.clone(), Some(phone_qr.clone()));
    let sim = phone_simulator(phone_qr.clone(), key(9), "enroll");
    let text = chain.ok(&[
        "key", "create", "--phone", "owner-phone", "--agent", &cfg, "--allow-no-attestation", "--phone-skip-fingerprint",
        "--listen", "127.0.0.1:0", "--phone-qr-file", laptop_qr.to_str().unwrap(), "--phone-timeout", "60",
    ]);
    attacker.join().unwrap();
    assert!(!sim.join().unwrap(), "the phone must not take the replaced reply for the laptop's confirmation");
    assert!(text.contains("enrolled phone owner key") && text.contains(&fp), "the laptop accepted: {text}");
    let _ = std::fs::remove_file(&phone_qr);

    let validator = chain.addr("p256Validator");
    chain.ok(&["owner", "add-recovery", "--agent", &cfg]);
    let public_key = format!("{},{}", phone.x, phone.y);
    let handover = [
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator, "--public-key", &public_key,
        "--expect-fingerprint", &fp, "--to-phone", "owner-phone", "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ];

    // a phone that deleted the key on the missing confirmation, as the apps did: the handover stops
    let sim = phone_simulator(phone_qr.clone(), key(9), "prove-lost");
    let err = chain.fails(&handover);
    sim.join().unwrap();
    assert!(err.contains("did not show that it holds the key") && err.contains("no-key") && err.contains("nothing sent"), "{err}");
    let _ = std::fs::remove_file(&phone_qr);
    // and a phone that is simply not there
    let err = chain.fails(&[&handover[..handover.len() - 1], &["2"]].concat());
    assert!(err.contains("did not show that it holds the key") && err.contains("no answer from the phone"), "{err}");
    let _ = std::fs::remove_file(&phone_qr);
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &cfg, "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1), "root is still the old owner's");

    // a phone that kept the key, unconfirmed, as the apps do now: it shows the key, and takes over
    let sim = phone_simulator(phone_qr.clone(), key(9), "prove");
    chain.ok(&handover);
    assert!(sim.join().unwrap());
    let _ = std::fs::remove_file(&phone_qr);
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    v["owner"] = phone_spec("owner-phone", &phone);
    let phone_cfg = chain.dir.join("phone-owner.json");
    std::fs::write(&phone_cfg, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let sim = phone_simulator(phone_qr.clone(), key(9), "sign");
    let before = chain.counter();
    chain.ok(&[
        "op", "send", "--agent", phone_cfg.to_str().unwrap(), "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "60",
    ]);
    sim.join().unwrap();
    assert_eq!(chain.counter(), before + U256::from(1), "the phone's key is root and signs");
}

/// The real thing, with a real phone on the same network (design §9.6): the
/// phone enrolls a new key for a fresh anvil account, the current owner hands
/// root to it (`set-root` with the fingerprint check), the phone signs a root
/// operation, and the agent still runs. Run from `signer/`:
///
///   cargo test -p agent-signer --features insecure-software-keys \
///     --test anvil_cli phone_owner_real_device -- --ignored --nocapture
///
/// On the phone: "4. Enroll" for the first QR; the second asks the phone to
/// show that it holds the new key before root goes to it (`--to-phone`); the
/// third is "3. Scan and sign" (a new agent permission, whose mandate the
/// phone shows). The app needs the
/// test chain's facts: `OWNER_CORE_FEATURES=ffi,test-chains ./build-core.sh`.
/// The enrollment verifies the phone's key attestation against Google's roots;
/// `TPMSIGN_ANDROID_APP_DIGEST=<sha256>` names the certificate your own build
/// of the app is signed with (the CLI prints the digest it saw when it refuses).
/// `TPMSIGN_PHONE_OUT=<dir>` keeps the enrollment (request, answer, attestation
/// DER) after the run; the temp directory is removed otherwise.
///
/// The same run drives the iPhone app in the iOS simulator
/// (`mobile/ios/run-simulator.sh`): `TPMSIGN_PHONE_QR_FILE` hands each QR's
/// text to the app, which has no camera there, and
/// `TPMSIGN_PHONE_NO_ATTESTATION=1` accepts its key, which has no hardware
/// and so no evidence. `TPMSIGN_PHONE_HANDOVER_BACK=1` adds a last session,
/// for either phone: the phone signs the change of the root key itself
/// (§2.2), which its review shows in bold and asks about a second time.
/// `TPMSIGN_PHONE_PATH_ATTACKER=1` puts a host on the path that replaces the
/// laptop's reply to the enrollment answer (issue #38): the laptop says
/// "enrolled", the phone sees no confirmation and says so, and the run goes
/// on only if the phone kept its key and can show it. For a phone with a
/// camera the first QR is then the attacker's, shown here in place of the
/// laptop's.
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
        // The session's address, when the runner names it. The CLI's default is the address of
        // the route to the internet, which is a VPN's when one is up; the phone's core refuses
        // that as not local (and loopback as the phone itself).
        if let Some(listen) = std::env::var_os("TPMSIGN_PHONE_LISTEN") {
            cmd.arg("--listen").arg(listen);
        }
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
    // a test run does not type: the answer is authenticated by the QR's secret (the default asks).
    // The attestation names the certificate the app was signed with; a development build is the
    // developer's own, so its digest comes from the environment (docs/MOBILE_DEV_MODE.md §2.2)
    let digest = std::env::var("TPMSIGN_ANDROID_APP_DIGEST").ok();
    let mut args = vec!["key", "create", "--phone", "owner-phone", "--agent", &cfg, "--phone-skip-fingerprint", "--out", out_dir.to_str().unwrap()];
    if let Some(d) = &digest {
        args.extend(["--android-app-digest", d.as_str()]);
    }
    if std::env::var_os("TPMSIGN_PHONE_NO_ATTESTATION").is_some() {
        args.push("--allow-no-attestation");
    }
    // On request, a host on the path replaces the laptop's reply (issue #38). The CLI writes its
    // QR for the attacker, who hands the phone its own: into the QR file, or onto this terminal
    // for a phone with a camera, where the laptop's own QR must then stay out of sight.
    let laptop_qr = chain.dir.join("laptop.qr");
    if std::env::var_os("TPMSIGN_PHONE_PATH_ATTACKER").is_some() {
        let phone_qr = std::env::var_os("TPMSIGN_PHONE_QR_FILE").map(PathBuf::from);
        args.extend(["--phone-qr-file", laptop_qr.to_str().unwrap(), "--phone-timeout", "180"]);
        let attacker = path_attacker(laptop_qr.clone(), phone_qr);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signer"));
        cmd.args(&args);
        // as in `run`: the session's address, when the runner names it
        if let Some(listen) = std::env::var_os("TPMSIGN_PHONE_LISTEN") {
            cmd.arg("--listen").arg(listen);
        }
        let out = cmd.output().expect("run agent-signer");
        attacker.join().unwrap();
        // the laptop's words, without the QR it showed to nobody
        let said = String::from_utf8_lossy(&out.stderr);
        eprintln!("{}", said.lines().filter(|l| !l.contains('█') && !l.contains('▀') && !l.contains('▄')).collect::<Vec<_>>().join("\n"));
        print!("{}", String::from_utf8_lossy(&out.stdout));
        assert!(out.status.success(), "the enrollment failed");
        eprintln!("\nA host on the path replaced the laptop's reply: the laptop says \"enrolled\" above, the phone saw no confirmation\nand says so. It must have kept the key all the same.");
    } else {
        let status = run(&args);
        assert!(status.success(), "the enrollment failed");
    }
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
    eprintln!("\nBefore root goes to the phone's key, the phone shows that it holds it: scan the QR below and confirm on the phone.\n");
    let status = run(&[
        "owner", "set-root", "--agent", &cfg, "--validator", &validator, "--retire", &validator,
        "--public-key", &format!("{},{}", phone.x, phone.y), "--expect-fingerprint", &fp, "--to-phone", "owner-phone",
    ]);
    assert!(status.success(), "the handover failed");
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

    // 4. on request: the phone hands root on, here back to the software key
    if std::env::var_os("TPMSIGN_PHONE_HANDOVER_BACK").is_some() {
        let back = fingerprint_of(&owner);
        eprintln!("\nNow the phone signs a change of the root key, to {back}: scan the QR below. The review shows the new\nkey's fingerprint in bold, and Sign asks a second time.\n");
        let status = run(&[
            "owner", "set-root", "--agent", phone_cfg, "--validator", &validator, "--retire", &validator,
            "--public-key", &format!("{},{}", owner.x, owner.y), "--expect-fingerprint", &back, "--not-a-phone", "--new-key",
            &spec(&owner),
        ]);
        assert!(status.success(), "the phone-signed handover failed");
        let before = chain.counter();
        chain.ok(&["op", "send", "--agent", &cfg, "--root", "--target", &counter, "--data", INCREMENT]);
        assert_eq!(chain.counter(), before + U256::from(1), "root is the software key's again");
    }
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
                tokens: json!([{"token": usdc, "maxPerOp": "1000000", "budget": "2000000", "x402": true, "payees": "anyone"}]),
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

// ---------------------------------------------------------------- trading

mod trading_abi {
    alloy::sol! {
        struct CowOrder {
            address sellToken;
            address buyToken;
            address receiver;
            uint256 sellAmount;
            uint256 buyAmount;
            uint32 validTo;
            bytes32 appData;
            uint256 feeAmount;
            bytes32 kind;
            bool partiallyFillable;
            bytes32 sellTokenBalance;
            bytes32 buyTokenBalance;
        }
        function settle(CowOrder o, address owner, bytes signature) external;
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

const ORDER_REGISTER: &str = "0x27ddae76";
const ORDER_RECLAIM: &str = "0x4344b733";

/// A trading mandate end to end (issue #80), on the policy and the decoder
/// built from this repository's sources and a stand-in for CoW's settlement:
/// the owner installs it with the venue's allowance, the agent registers and
/// signs an order, the venue settles it on the account's word; an order
/// outside the terms goes nowhere, an unfilled one comes back to the budget,
/// a new period renews the budget, and revoking takes the allowance back.
#[test]
fn trading_orders_under_a_mandate() {
    let chain = chain_or_skip!("trading");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let policy = chain.addr("agentPolicy");
    let until = far_future(&chain);
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str, args: Vec<u8>| {
        let mut code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend(args);
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let word = |a: &str| a.parse::<Address>().unwrap().abi_encode();

    // the policy of this source in the place of the deployed one: its only
    // constructor-set state is an immutable, which is part of its code
    let built = deploy("agentPolicyInitCode", word(&chain.addr("safeNonceAssert")));
    let code = chain.rpc("eth_getCode", json!([built, "latest"]));
    chain.rpc("anvil_setCode", json!([policy, code]));

    let (usd, weth) = (deploy("mockTokenInitCode", vec![]), deploy("mockTokenInitCode", vec![]));
    let settlement = deploy("settlementInitCode", vec![]);
    let decoder = deploy("cowSwapDecoderInitCode", word(&settlement));

    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    // the trading mandate: 200 a time, 300 a period, never under 0.0002 WETH for a USD
    const PERIOD: u64 = 30 * 86_400;
    let decoder_code = chain.rpc("eth_getCode", json!([decoder, "latest"]));
    let decoder_hash = alloy::primitives::keccak256(hex::decode(decoder_code.as_str().unwrap().trim_start_matches("0x")).unwrap());
    let trading = |name: &str, permission: &'static str, code_hash: Option<String>| {
        let path = chain.config(
            name,
            &Cfg {
                permission,
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), ORDER_REGISTER), (policy.clone(), ORDER_RECLAIM)],
                account: Some(account.clone()),
                tokens: json!([{"token": usd, "maxPerOp": "200000000", "budget": "300000000", "payees": "anyone"}]),
                ..base_cfg(&owner, &agent, &counter, until)
            },
        );
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["policy"]["period"] = json!(PERIOD);
        v["policy"]["venues"] = json!([{
            "kind": "cowswap", "decoder": decoder, "appData": format!("0x{}", "00".repeat(32)), "maxLife": 1800,
            "pairs": [{"sellToken": usd, "buyToken": weth, "minBuy": "200000000000000", "perSell": "1000000"}],
        }]);
        if let Some(h) = code_hash {
            v["policy"]["venues"][0]["codeHash"] = json!(h);
        }
        std::fs::write(&path, v.to_string()).unwrap();
        path
    };
    // a decoder the deployments file does not name is taken only with its code hash stated
    let unnamed = trading("unnamed.json", "0x74726431", None);
    let out = chain.cli(&["permission", "show", "--agent", &unnamed]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("state its `codeHash`"), "{}", String::from_utf8_lossy(&out.stderr));
    let cfg = trading("trading.json", "0x74726431", Some(decoder_hash.to_string()));
    // from here on the deployments file names it, as `script/Deploy.s.sol` writes it on a chain CoW runs on
    let dep_path = chain.dir.join("deployments.json");
    let mut dep: Value = serde_json::from_str(&std::fs::read_to_string(&dep_path).unwrap()).unwrap();
    dep["cowSwapDecoder"] = json!(decoder);
    std::fs::write(&dep_path, dep.to_string()).unwrap();
    chain.ok(&["permission", "show", "--agent", &unnamed]);
    let acct: Address = account.parse().unwrap();
    let balance = |token: &str, who: Address| U256::from_be_slice(&chain.call(token, balanceOfCall { account: who }.abi_encode()));
    let allowance = || {
        let call = trading_abi::allowanceCall { owner: acct, spender: settlement.parse().unwrap() };
        U256::from_be_slice(&chain.call(&usd, call.abi_encode()))
    };
    chain.send_from(FACILITATOR, Some(&usd), mintCall { to: acct, amount: U256::from(10_000_000_000u64) }.abi_encode());
    chain.send_from(FACILITATOR, Some(&weth), mintCall { to: settlement.parse().unwrap(), amount: U256::from(10u64).pow(U256::from(18)) }.abi_encode());

    let sell = |amount: &str, least: &str| -> Vec<String> {
        ["order", "sell", "--agent", &cfg, "--sell", &usd, "--buy", &weth, "--sell-amount", amount, "--buy-amount", least]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let run = |args: &[String]| chain.cli(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let placed = |args: &[String]| -> Value {
        let out = run(args);
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "order sell failed:\n{stderr}\n{stdout}");
        serde_json::from_str(stdout.lines().find(|l| l.starts_with('{')).unwrap_or_else(|| panic!("no order in: {stdout}"))).unwrap()
    };
    let refused = |args: &[String]| -> String {
        let out = run(args);
        assert!(!out.status.success(), "the order was expected to be refused");
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    };

    // before the owner installs the mandate there is no allowance, and the CLI says so
    assert!(allowance().is_zero());
    let early = refused(&sell("150000000", "37500000000000000"));
    assert!(early.contains("the owner gives the allowance with the mandate"), "{early}");

    // the owner's one operation: the old permission out, the trading one in, the allowance given
    chain.ok(&["permission", "rotate", "--agent", &cfg, "--old-id", "0x74657331"]);
    assert!(allowance() >= U256::from(300_000_000u64), "{}", allowance());
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains("ok period") && shown.contains("ok venue") && !shown.contains("DIFF"), "{shown}");

    // an ordinary call under a mandate with a period carries the period in its signature
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &cfg]);
    assert_eq!(chain.counter(), before + U256::from(1));

    // an order within the terms: registered, signed, and settled by the venue on the account's word
    let o = placed(&sell("150000000", "37500000000000000"));
    let settle = |o: &Value| {
        let field = |k: &str| o[k].as_str().unwrap().to_string();
        trading_abi::settleCall {
            o: trading_abi::CowOrder {
                sellToken: field("sellToken").parse().unwrap(),
                buyToken: field("buyToken").parse().unwrap(),
                receiver: Address::ZERO,
                sellAmount: field("sellAmount").parse().unwrap(),
                buyAmount: field("buyAmount").parse().unwrap(),
                validTo: o["validTo"].as_u64().unwrap() as u32,
                appData: field("appData").parse().unwrap(),
                feeAmount: U256::ZERO,
                kind: alloy::primitives::keccak256("sell"),
                partiallyFillable: false,
                sellTokenBalance: alloy::primitives::keccak256("erc20"),
                buyTokenBalance: alloy::primitives::keccak256("erc20"),
            },
            owner: acct,
            signature: field("signature").parse().unwrap(),
        }
        .abi_encode()
    };
    assert_eq!(o["signingScheme"], "eip1271");
    assert_eq!(o["uid"].as_str().unwrap().len(), 2 + 2 * 56);
    chain.send_from(FACILITATOR, Some(&settlement), settle(&o));
    assert_eq!(balance(&usd, acct), U256::from(10_000_000_000u64 - 150_000_000));
    assert_eq!(balance(&weth, acct), U256::from(37_500_000_000_000_000u64));

    // outside the terms: under the lowest price (stopped before any operation),
    // over the cap for one order and over the period's budget (refused by the policy)
    let cheap = refused(&sell("150000000", "29999999999999999"));
    assert!(cheap.contains("below the mandate's lowest price"), "{cheap}");
    refused(&sell("200000001", "50000000000000000"));
    refused(&sell("151000000", "37750000000000000"));
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 150000000)"));

    // the same order again, to the second of its end, is the same order: registered once
    let mut same = sell("150000000", "37500000000000000");
    same.extend(["--valid-for".to_string(), (o["validTo"].as_u64().unwrap() - chain.now()).to_string()]);
    let twice = refused(&same);
    assert!(twice.contains("already registered"), "{twice}");

    // an order nobody fills is charged while it lives and comes back after it
    // (one unit more asked for it: another order than the first, whenever it ends)
    placed(&sell("150000000", "37500000000000001"));
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 300000000)"));
    assert!(chain.ok(&["order", "reclaim", "--agent", &cfg, "--from-block", "0"]).contains("reclaimed 0 unfilled"));
    chain.advance(700);
    let back = chain.ok(&["order", "reclaim", "--agent", &cfg, "--from-block", "0"]);
    assert!(back.contains("reclaimed 1 unfilled"), "{back}");
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 150000000)"));
    // the filled one does not come back, now or later
    assert!(chain.ok(&["order", "reclaim", "--agent", &cfg, "--from-block", "0"]).contains("reclaimed 0 unfilled"));

    // a new period, a new budget; but the venue's allowance is one budget and no more,
    // whatever the period: the owner gives the next one
    refused(&sell("200000000", "50000000000000000"));
    chain.advance(PERIOD);
    assert_eq!(allowance(), U256::from(150_000_000u64), "what the first order took is gone from the allowance");
    let dry = refused(&sell("200000000", "50000000000000000"));
    assert!(dry.contains("the owner gives the allowance"), "{dry}");
    chain.ok(&["permission", "allowance", "--agent", &cfg]);
    assert_eq!(allowance(), U256::from(300_000_000u64));
    let o = placed(&sell("200000000", "50000000000000000"));
    chain.send_from(FACILITATOR, Some(&settlement), settle(&o));
    assert_eq!(balance(&usd, acct), U256::from(10_000_000_000u64 - 350_000_000));

    // An allowance does not outlive the mandate it came with. A config that no
    // longer holds the venue's terms cannot say which tokens were sold there.
    assert_eq!(allowance(), U256::from(100_000_000u64));
    let plain = chain.config(
        "plain.json",
        &Cfg { permission: "0x706c6e31", account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    // A rotation with such a config is refused until the old config is given; nothing is sent.
    let out = chain.cli(&["permission", "rotate", "--agent", &plain, "--old-id", "0x74726431"]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success() && err.contains("--old-config"), "{err}");
    assert_eq!(allowance(), U256::from(100_000_000u64));
    // A revocation is never held up: it is the owner's move when the agent's machine is
    // lost. With a config that names no token it removes the permission, leaves the
    // allowance and says so, naming the spender to clear.
    let snapshot = chain.rpc("evm_snapshot", json!([]));
    let out = chain.cli(&["permission", "revoke", "--agent", &plain, "--id", "0x74726431"]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{err}");
    assert!(err.contains("is left standing") && err.to_lowercase().contains(&settlement.to_lowercase()), "{err}");
    assert_eq!(allowance(), U256::from(100_000_000u64));
    chain.fails(&["demo", "--agent", &cfg]);
    assert_eq!(chain.rpc("evm_revert", json!([snapshot])), json!(true));
    // With a config that names the token, though not the venue's terms, it reads the
    // allowance on the chain and takes it back in the same operation.
    let names_the_token = chain.config(
        "names-the-token.json",
        &Cfg {
            permission: "0x706c6e31",
            account: Some(account.clone()),
            tokens: json!([{"token": usd, "maxPerOp": "1", "budget": "1", "payees": "anyone"}]),
            ..base_cfg(&owner, &agent, &counter, until)
        },
    );
    let snapshot = chain.rpc("evm_snapshot", json!([]));
    chain.ok(&["permission", "revoke", "--agent", &names_the_token, "--id", "0x74726431"]);
    assert!(allowance().is_zero());
    chain.fails(&["demo", "--agent", &cfg]);
    assert_eq!(chain.rpc("evm_revert", json!([snapshot])), json!(true));
    assert_eq!(allowance(), U256::from(100_000_000u64));
    // with it, the rotation to a mandate without trading takes the allowance back
    chain.ok(&["permission", "rotate", "--agent", &plain, "--old-id", "0x74726431", "--old-config", &cfg]);
    assert!(allowance().is_zero());
    chain.fails(&["demo", "--agent", &cfg]);
    let before = chain.counter();
    chain.ok(&["demo", "--agent", &plain]);
    assert_eq!(chain.counter(), before + U256::from(1));

    // and a trading mandate given again and revoked with its own config: the same
    let again = trading("again.json", "0x74726433", Some(decoder_hash.to_string()));
    chain.ok(&["permission", "add", "--agent", &again]);
    assert_eq!(allowance(), U256::from(300_000_000u64));
    chain.ok(&["permission", "revoke", "--agent", &again, "--id", "0x74726433"]);
    assert!(allowance().is_zero());
}

/// What the phone reads from a venue's config and what the decoder on chain
/// enforces from the same bytes are held together (the auditor's point on
/// issue #80): for configs from a seed, well-formed and damaged, every one
/// the phone accepts is one the decoder accepts, and the terms the phone
/// would show are the terms the decoder judges by: an order at a pair's
/// lowest price passes with the token, the amount and the lifetime the phone
/// read, one unit under it does not, and a pair the phone did not read is
/// not traded. The phone may refuse more than the decoder; it never reads
/// other terms.
#[test]
fn the_phone_reads_a_venue_config_as_the_decoder_does() {
    use owner_core::kernel as k;
    use owner_core::review::cow_terms;
    let chain = chain_or_skip!("venue-config");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str, args: Vec<u8>| {
        let mut code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend(args);
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let settlement = deploy("settlementInitCode", vec![]);
    let decoder = deploy("cowSwapDecoderInitCode", settlement.parse::<Address>().unwrap().abi_encode());
    // a call that may revert: the returned bytes, or nothing
    let ask = |signature: &str, args: Vec<u8>| -> Option<Vec<u8>> {
        let mut data = alloy::primitives::keccak256(signature)[..4].to_vec();
        data.extend(args);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": decoder, "data": Bytes::from(data).to_string()}, "latest"]});
        let v: Value = serde_json::from_str(&http_post(&chain.url, &body.to_string())).unwrap();
        v.get("result").and_then(|r| r.as_str()).map(|r| hex::decode(r.trim_start_matches("0x")).unwrap())
    };
    let account: Address = "0x00000000000000000000000000000000000Acc01".to_lowercase().parse().unwrap();

    let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let tokens: Vec<Address> = (1u8..=5).map(|i| Address::repeat_byte(i)).collect();
    let (mut both, mut chain_only, mut neither) = (0, 0, 0);
    for _ in 0..400 {
        // a config: mostly within the rules, with a share of what the rules refuse
        let count = if next(12) == 0 { 0 } else { 1 + next(3) };
        let pairs: Vec<(Address, Address, U256, U256)> = (0..count)
            .map(|i| {
                // mostly distinct pairs: token i sold for another one
                let sell = if next(25) == 0 { Address::ZERO } else { tokens[i as usize] };
                let buy = if next(25) == 0 { sell } else { tokens[(i + 1 + next(2)) as usize] };
                let amount = |n: u64| if n % 30 == 0 { U256::ZERO } else { U256::from(1 + n % 1_000_000) };
                (sell, buy, amount(next(u64::MAX)), amount(next(u64::MAX)))
            })
            .collect();
        let life = if next(15) == 0 { 0 } else { 1 + next(86_400) as u32 };
        let app_data = if next(3) == 0 { B256::ZERO } else { B256::repeat_byte(next(256) as u8) };
        let mut config = k::cow_config(app_data, life, &pairs).to_vec();
        // and damaged bytes: one changed, the end cut, a word added
        match next(8) {
            0 => {
                let at = next(config.len() as u64) as usize;
                config[at] ^= 1 << next(8);
            }
            1 => config.truncate(config.len() - 1 - next(40) as usize % config.len()),
            2 => config.extend([0u8; 32]),
            _ => {}
        }

        let phone = cow_terms(&config);
        let on_chain = ask("checkConfig(bytes)", (Bytes::from(config.clone()),).abi_encode_params()).is_some();
        let Ok(terms) = phone else {
            if on_chain { chain_only += 1 } else { neither += 1 }
            continue;
        };
        assert!(on_chain, "the phone accepts a config the decoder refuses: 0x{}", hex::encode(&config));
        both += 1;

        let valid_to = 1_900_000_000u32;
        let judge = |sell: Address, buy: Address, sell_amount: U256, buy_amount: U256| {
            let order = k::CowSellOrder { sell_token: sell, buy_token: buy, sell_amount, buy_amount, valid_to, app_data: terms.app_data };
            ask("judge(address,bytes,bytes)", (account, Bytes::from(config.clone()), order.encode()).abi_encode_params())
        };
        for (sell, buy, min_buy, per_sell) in &terms.pairs {
            let times = U256::from(1 + next(1000));
            // a multiple of the price's two terms is exactly at the price; the terms
            // themselves when a multiple does not fit a word (the decoder compares in 512 bits)
            let (sold, least) = match (per_sell.checked_mul(times), min_buy.checked_mul(times)) {
                (Some(sold), Some(least)) => (sold, least),
                _ => (*per_sell, *min_buy),
            };
            let answer = judge(*sell, *buy, sold, least).unwrap_or_else(|| panic!("an order at the lowest price the phone read is refused: 0x{}", hex::encode(&config)));
            assert_eq!(answer.len(), 160);
            assert_eq!(Address::from_slice(&answer[12..32]), *sell, "the token charged");
            assert_eq!(U256::from_be_slice(&answer[32..64]), sold, "the amount charged");
            assert_eq!(U256::from_be_slice(&answer[64..96]), U256::from(valid_to - terms.max_life), "the lifetime");
            assert_eq!(U256::from_be_slice(&answer[96..128]), U256::from(valid_to));
            assert!(judge(*sell, *buy, sold, least - U256::from(1)).is_none(), "an order under the lowest price the phone read passes: 0x{}", hex::encode(&config));
            // other order data than the phone read
            let other = k::CowSellOrder { sell_token: *sell, buy_token: *buy, sell_amount: sold, buy_amount: least, valid_to, app_data: B256::repeat_byte(0xee) };
            if terms.app_data != other.app_data {
                assert!(ask("judge(address,bytes,bytes)", (account, Bytes::from(config.clone()), other.encode()).abi_encode_params()).is_none());
            }
        }
        // a pair the phone did not read is not traded, at any price
        for sell in &tokens {
            for buy in &tokens {
                if !terms.pairs.iter().any(|p| p.0 == *sell && p.1 == *buy) {
                    assert!(judge(*sell, *buy, U256::from(1), U256::MAX >> 1).is_none(), "a pair the phone did not read is traded: 0x{}", hex::encode(&config));
                }
            }
        }
    }
    // the generator reaches all three kinds
    assert!(both >= 150 && chain_only >= 5 && neither >= 50, "accepted by both {both}, by the decoder only {chain_only}, by neither {neither}");
    eprintln!("configs: {both} accepted by both, {chain_only} by the decoder only, {neither} by neither");
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
