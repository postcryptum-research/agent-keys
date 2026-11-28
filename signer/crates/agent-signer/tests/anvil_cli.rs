//! End-to-end tests of the `agent-signer` CLI on a local chain.
//!
//! Each test starts its own `anvil`, installs the account-abstraction stack
//! and this project's modules from `fixtures/chain-code.json` and runs the
//! real binary against it -- config parsing, operation building, signing,
//! `handleOps`, and the contracts' verdicts, together.
//!
//! The fixture's code of this project's contracts (P256Validator,
//! P256RecoveryValidator, P256Signer, AgentPolicy, SafeNonceAssert, the demo
//! counter) is built from this repository's sources:
//! `scripts/test-fixtures.py --write` rewrites it, and CI fails a pull
//! request whose contracts and fixtures disagree. The EntryPoint v0.7, Kernel
//! v3.3 and its factory, Solady's P-256 verifier and Safe are runtime
//! bytecode read from Base Sepolia.
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
    function pause(address account, bytes32 id, address module, bool paused) external;
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
    test: String,
}

/// Two contracts that pass their calldata on, the first to the second and
/// the second to the EntryPoint: the validation tracer of a rule-enforcing
/// bundler looks for the EntryPoint three calls deep, where the bundler's own
/// simulation has it.
const TRACE_VIA: [&str; 2] = ["0x00000000000000000000000000000000000a7562", "0x00000000000000000000000000000000000b7562"];

fn forwarder(to: &str) -> String {
    format!("0x363d3d373d3d363d3d73{}5af100", to.trim_start_matches("0x"))
}

impl Chain {
    /// For the ERC-7562 check (`scripts/erc7562`, issue #83). With
    /// `ERC7562_TRACER` naming a file with the bundler's validation tracer and
    /// `ERC7562_TRACE_DIR` a directory, every `handleOps` this test got
    /// included and that did not revert is run again on the state before its
    /// block, under that tracer, and the trace is written there with the
    /// operation's transaction. anvil mines a block per transaction here, so
    /// the state before the block is the state the operation met, unless a
    /// test changed the chain in between without a transaction
    /// (`anvil_setCode` and the like); the same call is therefore made
    /// plainly first and must succeed, or the trace would be of an operation
    /// that failed half-way. Without the two variables this does nothing.
    /// Needs an anvil that runs JavaScript tracers, and an empty directory:
    /// files of an earlier run are not removed.
    fn write_validation_traces(&self) {
        let (Ok(tracer), Ok(out)) = (std::env::var("ERC7562_TRACER"), std::env::var("ERC7562_TRACE_DIR")) else { return };
        let tracer = std::fs::read_to_string(tracer).expect("ERC7562_TRACER");
        std::fs::create_dir_all(&out).unwrap();
        let entry_point = self.addr("entryPoint").to_lowercase();
        let latest = u64::from_str_radix(self.rpc("eth_blockNumber", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for n in 1..=latest {
            let block = self.rpc("eth_getBlockByNumber", json!([format!("0x{n:x}"), true]));
            let txs = block["transactions"].as_array().unwrap();
            for (i, tx) in txs.iter().enumerate() {
                let input = tx["input"].as_str().unwrap();
                // handleOps(PackedUserOperation[],address)
                if tx["to"].as_str().map(str::to_lowercase).as_deref() != Some(&entry_point) || !input.starts_with("0x765e827f") {
                    continue;
                }
                // a `handleOps` that reverted on chain (a test of a refusal) included no operation
                if self.rpc("eth_getTransactionReceipt", json!([tx["hash"]]))["status"] != "0x1" {
                    continue;
                }
                assert_eq!(txs.len(), 1, "block {n} has more than one transaction: the state before it is not the state the operation met");
                let before = format!("0x{:x}", n - 1);
                // the forwarders do not pass a revert on, so the replay is asked directly first
                let replay: Value = serde_json::from_str(&http_post(
                    &self.url,
                    &json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"from": tx["from"], "to": tx["to"], "data": input, "gas": "0x1c9c380"}, before]}).to_string(),
                ))
                .unwrap();
                assert!(replay.get("error").is_none(), "{}: the handleOps of block {n} does not succeed on the state before it: {replay}", self.test);
                let trace = self.rpc(
                    "debug_traceCall",
                    json!([{"from": tx["from"], "to": TRACE_VIA[0], "data": input, "gas": "0x1c9c380"}, before, {"tracer": tracer}]),
                );
                let file = Path::new(&out).join(format!("{}-{n:04}-{i}.json", self.test));
                std::fs::write(file, json!({"test": self.test, "block": n, "from": tx["from"], "entryPoint": entry_point, "input": input, "trace": trace}).to_string()).unwrap();
            }
        }
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        // the traces need the chain; the chain and its directory (with a key file) must go whatever happens to them
        let traced = (!std::thread::panicking())
            .then(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.write_validation_traces())));
        let _ = self.anvil.kill();
        let _ = self.anvil.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        if let Some(Err(panic)) = traced {
            std::panic::resume_unwind(panic);
        }
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
        let chain = Chain { anvil, url: format!("http://127.0.0.1:{port}"), dir, code, test: test.to_string() };
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

    /// ZeroDev's FactoryStaker as it stands on the chains the project runs on
    /// (issue #102): it approves Kernel's factory and holds 0.1 ETH of stake
    /// at the EntryPoint with a day's unstake delay. Its code is installed
    /// without its storage, so an owner is written into Solady's owner slot
    /// and does the two things the real owner did.
    fn stake_the_factory_staker(&self) {
        let staker = self.addr("kernelFactoryStaker");
        let owner: Address = FACILITATOR.parse().unwrap();
        // Solady Ownable: _OWNER_SLOT
        let slot = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927";
        self.rpc("anvil_setStorageAt", json!([staker, slot, B256::left_padding_from(owner.as_slice()).to_string()]));
        let factory: Address = self.addr("kernelFactory").parse().unwrap();
        let entry: Address = self.addr("entryPoint").parse().unwrap();
        let call = |signature: &str, args: Vec<u8>, value: &str| {
            let data = [&alloy::primitives::keccak256(signature)[..4], &args[..]].concat();
            let tx = json!({"from": FACILITATOR, "to": staker, "data": Bytes::from(data).to_string(), "value": value, "gas": "0x989680"});
            let hash = self.rpc("eth_sendTransaction", json!([tx]));
            let started = Instant::now();
            loop {
                let r = self.rpc("eth_getTransactionReceipt", json!([hash]));
                if !r.is_null() {
                    assert_eq!(r["status"], "0x1", "{signature} reverted: {r}");
                    break;
                }
                assert!(started.elapsed() < Duration::from_secs(10), "{signature}: no receipt");
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        call("approveFactory(address,bool)", (factory, true).abi_encode(), "0x0");
        call("stake(address,uint32)", (entry, 86_400u32).abi_encode(), "0x16345785d8a0000");
    }

    fn install(&self) {
        for (_, c) in self.code["contracts"].as_object().unwrap() {
            self.rpc("anvil_setCode", json!([c["address"], c["code"]]));
        }
        if std::env::var("ERC7562_TRACE_DIR").is_ok() {
            self.rpc("anvil_setCode", json!([TRACE_VIA[1], forwarder(&self.addr("entryPoint"))]));
            self.rpc("anvil_setCode", json!([TRACE_VIA[0], forwarder(TRACE_VIA[1])]));
        }
        let deployments = json!({
            "chainId": 31337,
            "entryPoint": self.addr("entryPoint"), "kernel": self.addr("kernel"), "kernelFactory": self.addr("kernelFactory"),
            "kernelFactoryStaker": self.addr("kernelFactoryStaker"),
            "p256Validator": self.addr("p256Validator"), "p256RecoveryValidator": self.addr("p256RecoveryValidator"),
            "p256Signer": self.addr("p256Signer"), "agentPolicy": self.addr("agentPolicy"),
            "safeNonceAssert": self.addr("safeNonceAssert"), "demoCounter": self.addr("demoCounter"),
            "safeShapes": self.addr("safeShapes"),
        });
        std::fs::write(self.dir.join("deployments.json"), deployments.to_string()).unwrap();
        self.stake_the_factory_staker();
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
        // the first operation names the staked factory, not Kernel's own (issue #102)
        let init_code = init.lines().find_map(|l| l.strip_prefix("initCode:")).unwrap().trim().to_lowercase();
        let staker = self.addr("kernelFactoryStaker").to_lowercase();
        assert!(init_code.starts_with(&staker), "initCode names {}", &init_code[..42]);
        self.ok(&["account", "fund", "--agent", cfg, "--wei", "1000000000000000000"]);
        let before = self.counter();
        self.ok(&["demo", "--agent", cfg]);
        assert_eq!(self.counter(), before + U256::from(1), "the first operation deploys the account and runs");
        // ... and the account is where Kernel's factory puts it, with code
        assert!(self.rpc("eth_getCode", json!([account, "latest"])).as_str().unwrap().len() > 2, "no code at {account}");
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
    // the key is shown whole, with its fingerprint: nothing is cut (issue #115)
    let whole = |k: &Key| vec![format!("fingerprint {}", fingerprint_of(k)), format!("x = {}", k.x), format!("y = {}", k.y)];
    for part in whole(&agent) {
        assert!(shown.contains(&part), "{part}\n{shown}");
    }
    assert!(!shown.contains('…'), "{shown}");
    // the sample output in docs/AGENT_CONFIG.md is this key's
    assert_eq!(fingerprint_of(&agent), "BPQBJ-WZ7L7-7AHTA-QCCMZ");
    assert_eq!(agent.x, "0x2f23ebb1c38db28363df39984086922a0585f3fa7fd315d8925ebd1663548c9f");
    // a config that names another agent key: both keys can be read and told apart
    let other = key(7);
    let differs = chain.config("other-key.json", &Cfg { agent: &other, account: Some(account.clone()), ..base_cfg(&owner, &other, &counter, until) });
    let shown = chain.ok(&["permission", "show", "--agent", &differs]);
    assert!(shown.contains("DIFF agent key       chain:") && shown.contains("config: fingerprint"), "{shown}");
    for part in whole(&agent).into_iter().chain(whole(&other)) {
        assert!(shown.contains(&part), "{part}\n{shown}");
    }
    assert!(!shown.contains('…'), "{shown}");

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
    let status = chain.ok(&["owner", "status", "--agent", &old_cfg]);
    assert!(status.contains("installed = true"), "{status}");
    // both keys whole, each with its fingerprint: the root key and the recovery key (issue #115)
    for (line, k) in [("root key:       ", &owner), ("recovery key:   ", &recovery)] {
        let text = format!("{line}fingerprint {}\n                x = {}\n                y = {}", fingerprint_of(k), k.x, k.y);
        assert!(status.contains(&text), "{text}\n{status}");
    }
    assert!(!status.contains('…'), "{status}");
    // a different recovery key is refused by the CLI's check against the
    // chain, before anything is signed
    let wrong = key(6);
    let wrong_cfg = chain.config(
        "wrong-recovery.json",
        &Cfg { owner: &owner, recovery: Some(&wrong), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) },
    );
    let refused = chain.fails(&["owner", "recover", "--agent", &wrong_cfg]);
    assert!(refused.contains("not the one installed on the account"), "{refused}");
    // the refusal names both keys whole
    assert!(refused.contains(&format!("x = {}", wrong.x)) && refused.contains(&format!("x = {}", recovery.x)) && !refused.contains('…'), "{refused}");
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

/// Issue #114: the recovery key an account got first is not the one it has to keep. The
/// owner key replaces it in one operation (a file stolen, lost, or changing hands), after
/// which the old key recovers nothing and the new one does; and removes it, on an explicit
/// word, after which another can be installed again.
#[test]
fn the_recovery_key_is_replaced_and_removed() {
    let chain = chain_or_skip!("recovery-replace");
    let (owner, agent, first, second, third, new_owner) = (key(1), key(2), key(4), key(6), key(7), key(5));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let with = |name: &str, o: &Key, r: &Key| {
        chain.config(name, &Cfg { owner: o, recovery: Some(r), account: Some(account.clone()), ..base_cfg(o, &agent, &counter, until) })
    };
    let (cfg1, cfg2) = (with("first.json", &owner, &first), with("second.json", &owner, &second));
    let status = |cfg: &str| chain.ok(&["owner", "status", "--agent", cfg]);

    // nothing to replace or remove yet
    let refused = chain.fails(&["owner", "replace-recovery", "--agent", &cfg1]);
    assert!(refused.contains("no recovery key is installed"), "{refused}");
    // a recovery key is a third key: not the owner's, not the agent's
    let (as_owner, as_agent) = (with("as-owner.json", &owner, &owner), with("as-agent.json", &owner, &agent));
    let refused = chain.fails(&["owner", "add-recovery", "--agent", &as_owner]);
    assert!(refused.contains("is the account's root key") && refused.contains(&owner.x) && refused.contains(&owner.y), "{refused}");
    let refused = chain.fails(&["owner", "add-recovery", "--agent", &as_agent]);
    assert!(refused.contains("is the agent's key") && refused.contains(&agent.x), "{refused}");
    chain.ok(&["owner", "add-recovery", "--agent", &cfg1]);
    for (cfg, why) in [(&as_owner, "is the account's root key"), (&as_agent, "is the agent's key")] {
        let refused = chain.fails(&["owner", "replace-recovery", "--agent", cfg, "--skip-key-check"]);
        assert!(refused.contains(why), "{refused}");
    }
    assert!(status(&cfg1).contains("installed = true"));
    // a second add is refused and names the command that does it
    let refused = chain.fails(&["owner", "add-recovery", "--agent", &cfg2]);
    assert!(refused.contains("already installed") && refused.contains("owner replace-recovery"), "{refused}");
    // the same key again is not a replacement
    let refused = chain.fails(&["owner", "replace-recovery", "--agent", &cfg1]);
    assert!(refused.contains("the one installed already"), "{refused}");

    // replaced: by default the new key shows here that it signs
    let out = chain.cli(&["owner", "replace-recovery", "--agent", &cfg2]);
    let (said, err) = (String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string());
    assert!(out.status.success() && said.contains("recovery key replaced") && said.contains("the new recovery key signs"), "{said}\n{err}");
    assert!(err.contains(&format!("new recovery key: fingerprint {}", fingerprint_of(&second))) && err.contains(&second.x) && err.contains(&second.y), "{err}");
    assert!(status(&cfg2).contains("installed = true, may take root = true, is root now = false"));
    // the old file recovers nothing; the root did not move
    let refused = chain.fails(&["owner", "recover", "--agent", &cfg1]);
    assert!(refused.contains("not the one installed on the account"), "{refused}");
    let before = chain.counter();
    chain.ok(&["op", "send", "--agent", &cfg2, "--root", "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(1));

    // the new one does: it takes root, and while it is root it is not changed
    chain.ok(&["owner", "recover", "--agent", &cfg2]);
    for args in [vec!["owner", "replace-recovery", "--agent", &cfg1], vec!["owner", "remove-recovery", "--agent", &cfg2, "--leave-no-recovery"]] {
        let refused = chain.fails(&args);
        assert!(refused.contains("the recovery key is root now"), "{refused}");
    }
    let validator = chain.addr("p256Validator");
    chain.ok(&[
        "owner", "set-root", "--agent", &cfg2, "--as-recovery", "--not-a-phone", "--validator", &validator, "--retire", &validator,
        "--public-key", &format!("{},{}", new_owner.x, new_owner.y), "--new-key", &spec(&new_owner),
    ]);

    // the owner may leave the new key unopened, and is told what that leaves unshown
    let out = chain.cli(&["owner", "replace-recovery", "--agent", &with("new-first.json", &new_owner, &first), "--skip-key-check"]);
    let (said, err) = (String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string());
    assert!(out.status.success() && said.contains("recovery key replaced") && !said.contains("signs"), "{said}\n{err}");
    assert!(err.contains("is not opened here (--skip-key-check)"), "{err}");

    // removing it takes the owner's explicit word
    let (new2, new3) = (with("new-second.json", &new_owner, &second), with("new-third.json", &new_owner, &third));
    let refused = chain.fails(&["owner", "remove-recovery", "--agent", &new2]);
    assert!(refused.contains("--leave-no-recovery") && status(&new2).contains("installed = true"), "{refused}");
    let said = chain.ok(&["owner", "remove-recovery", "--agent", &new2, "--leave-no-recovery"]);
    assert!(said.contains("recovery key removed"), "{said}");
    assert!(status(&new2).contains("installed = false, may take root = false"), "{}", status(&new2));
    let refused = chain.fails(&["owner", "recover", "--agent", &new2]);
    assert!(refused.contains("no recovery key is installed"), "{refused}");
    // the same validator takes a key again afterwards, and that key recovers
    chain.ok(&["owner", "add-recovery", "--agent", &new3]);
    assert!(status(&new3).contains("installed = true, may take root = true"));
    chain.ok(&["owner", "recover", "--agent", &new3]);
    assert!(status(&new3).contains("is root now = true"));
    // the agent's permission is as it was through all of it
    chain.ok(&["demo", "--agent", &new3]);
}

/// After a redeploy the recovery key moves to the new recovery validator
/// (docs/REDEPLOY.md): `owner add-recovery` installs it on the current one,
/// and `owner remove-recovery --earlier` takes it off the one the deployments
/// file now keeps as `p256RecoveryValidatorV1`, which could otherwise still
/// take root.
#[test]
fn the_recovery_key_moves_to_a_redeployed_validator() {
    let chain = chain_or_skip!("recovery-move");
    let (owner, agent, recovery) = (key(1), key(2), key(4));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let cfg = Cfg { recovery: Some(&recovery), account: Some(account.clone()), ..base_cfg(&owner, &agent, &counter, until) };
    let before = chain.config("before.json", &cfg);
    chain.ok(&["owner", "add-recovery", "--agent", &before]);

    // the redeploy: the same code at a new address; the old one is kept under its versioned name
    let earlier = chain.addr("p256RecoveryValidator");
    let current = "0x7000000000000000000000000000000000000007";
    chain.rpc("anvil_setCode", json!([current, chain.code["contracts"]["p256RecoveryValidator"]["code"]]));
    let mut dep: Value = serde_json::from_str(&std::fs::read_to_string(chain.dir.join("deployments.json")).unwrap()).unwrap();
    dep["p256RecoveryValidator"] = json!(current);
    dep["p256RecoveryValidatorV1"] = json!(earlier);
    std::fs::write(chain.dir.join("deployments-redeployed.json"), dep.to_string()).unwrap();
    let after = chain.config("after.json", &cfg);
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&after).unwrap()).unwrap();
    v["deployments"] = json!(chain.dir.join("deployments-redeployed.json"));
    std::fs::write(&after, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    // not before the current validator holds the key: that would leave the account without one
    let refused = chain.fails(&["owner", "remove-recovery", "--agent", &after, "--earlier", &earlier]);
    assert!(refused.contains("the current recovery validator holds no key") && refused.contains("owner add-recovery"), "{refused}");
    chain.ok(&["owner", "add-recovery", "--agent", &after]);
    // only an earlier recovery validator the file keeps
    for not_earlier in [current, counter.as_str(), "0x7000000000000000000000000000000000000008"] {
        let refused = chain.fails(&["owner", "remove-recovery", "--agent", &after, "--earlier", not_earlier]);
        assert!(refused.contains("is not an earlier recovery validator"), "{refused}");
    }
    let said = chain.ok(&["owner", "remove-recovery", "--agent", &after, "--earlier", &earlier]);
    assert!(said.contains("recovery key removed from the earlier validator"), "{said}");
    // the earlier validator recovers nothing any more; the current one does
    let refused = chain.fails(&["owner", "recover", "--agent", &before]);
    assert!(refused.contains("no recovery key is installed"), "{refused}");
    let refused = chain.fails(&["owner", "remove-recovery", "--agent", &after, "--earlier", &earlier]);
    assert!(refused.contains("no recovery key is installed"), "{refused}");
    chain.ok(&["owner", "recover", "--agent", &after]);
    assert!(chain.ok(&["owner", "status", "--agent", &after]).contains("is root now = true"));
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
/// A QR file carries the session secret: the CLI writes it owner-only
/// (#154), and so does the path attacker below when it relays one.
fn assert_owner_only(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).expect("the QR file").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the QR file {} has mode {mode:o}", path.display());
    }
}

/// A client that opens the session's POST, announces a body and sends none of
/// it, holding the connection for `hold`. The body announced is over 1 KiB:
/// the HTTP server reads a smaller one itself before it hands the request
/// over, so only a larger one reaches the session unread.
fn stalled_post(qr_file: std::path::PathBuf, hold: Duration) -> std::thread::JoinHandle<()> {
    use owner_core::request::QrPayload;
    use std::io::Write;
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
        let rest = qr.url.strip_prefix("http://").expect("an http URL");
        let (host, path) = rest.split_once('/').expect("a path");
        let mut stream = TcpStream::connect(host).expect("the session's port");
        write!(stream, "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4096\r\n\r\n").unwrap();
        stream.flush().unwrap();
        std::thread::sleep(hold);
    })
}

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
        assert_owner_only(&qr_file);
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
            Some(file) => {
                // the CLI wrote laptop_qr owner-only; the relayed copy is written the same way
                assert_owner_only(&laptop_qr);
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
                std::io::Write::write_all(&mut opts.open(file).unwrap(), uri.as_bytes()).unwrap();
            }
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

    // 6-stall. a host on the network that saw the session's URL opens an answer and sends no
    //     body. It holds its own connection and nothing else: the phone, a moment later, is
    //     served and signs. Before #178 the session waited on that body for all the time it
    //     had left and ended with "no answer from the phone".
    let _ = std::fs::remove_file(&qr_file);
    let staller = stalled_post(qr_file.clone(), Duration::from_secs(7));
    let sim = phone_simulator_after(qr_file.clone(), key(7), "sign", Duration::from_millis(1500));
    let before = chain.counter();
    let out = chain.ok(&[
        "op", "send", "--agent", &cfg_path, "--root", "--target", &counter, "--data", INCREMENT,
        "--listen", "127.0.0.1:0", "--phone-qr-file", qr, "--phone-timeout", "6",
    ]);
    sim.join().unwrap();
    staller.join().unwrap();
    assert!(out.contains("phone:          signed, signature verified"), "{out}");
    assert_eq!(chain.counter(), before + U256::from(1));

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
/// when `settle` is on, otherwise refuses. It allows `max_timeout` seconds.
fn x402_server(chain_url: String, usdc: String, amount: u64, settle: Arc<AtomicBool>, max_timeout: u64) -> String {
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
                             "payTo": PAYEE, "maxTimeoutSeconds": max_timeout, "extra": {"name": "USDC", "version": "2"}}],
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
    let url = x402_server(chain.url.clone(), usdc.clone(), 250_000, settle.clone(), 60);
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
    // the blocks looked at are said, so that a 0 is not read as "nothing is booked" (issue #116)
    assert!(reclaimed.contains("looking at blocks 0 to "), "{reclaimed}");
    // without --from-block: the default window, and how to reach further back
    let again = chain.ok(&["x402", "reclaim", "--agent", &cfg]);
    assert!(again.contains("reclaimed 0 expired") && again.contains("the last 50000; an older registration needs --from-block"), "{again}");
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 250000)"));
    assert_eq!(payee_balance(), U256::from(250_000));

    // a server allowing u64::MAX seconds (issue #151): no overflow, an hour, said, and paid
    settle.store(true, Ordering::SeqCst);
    let lavish = x402_server(chain.url.clone(), usdc.clone(), 250_000, settle.clone(), u64::MAX);
    let paid = chain.ok(&["x402", "fetch", "--agent", &cfg, &lavish]);
    let local_now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!(paid.contains("paid content") && paid.contains("the authorization lives 3600 s"), "{paid}");
    let valid_until: u64 = paid.split("valid until ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap().parse().unwrap();
    assert!(valid_until <= local_now + 3600, "{paid}");
    assert_eq!(payee_balance(), U256::from(500_000));
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

/// A trading mandate end to end (issue #80), on the policy and the decoder
/// built from this repository's sources and a stand-in for CoW's settlement:
/// the owner installs it with the venue's allowance, the agent registers and
/// signs an order, the venue settles it on the account's word; an order
/// outside the terms goes nowhere, an unfilled one stays charged until the
/// period turns, a new period renews the budget, and revoking takes the
/// allowance back.
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
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), ORDER_REGISTER)],
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

    // an order nobody fills stays charged after its end: there is no refund, the
    // period returns it (one unit more asked for it: another order than the first)
    let out = run(&sell("150000000", "37500000000000001"));
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success() && said.contains("an order's charge is not given back"), "{said}");
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 300000000)"));
    chain.advance(700);
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 300000000)"));
    let gone = chain.fails(&["order", "reclaim", "--agent", &cfg, "--from-block", "0"]);
    assert!(gone.contains("unrecognized subcommand"), "{gone}");
    // venues without a period: refused before anything is built
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    v["policy"]["period"] = json!(0);
    let no_period = chain.dir.join("no-period.json");
    std::fs::write(&no_period, v.to_string()).unwrap();
    let why = chain.fails(&["permission", "rotate", "--agent", &no_period.display().to_string(), "--old-id", "0x74726431"]);
    assert!(why.contains("no budget period"), "{why}");

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

mod one_inch_abi {
    alloy::sol! {
        struct LimitOrder {
            uint256 salt;
            uint256 maker;
            uint256 receiver;
            uint256 makerAsset;
            uint256 takerAsset;
            uint256 makingAmount;
            uint256 takingAmount;
            uint256 makerTraits;
        }
        function fillContractOrder(LimitOrder order, bytes signature, uint256 amount, uint256 takerTraits) external;
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// A mandate that trades by plain 1inch limit orders, end to end (issue
/// #80), on the policy and the decoder built from this repository's sources
/// and a stand-in for 1inch's router, written from the router's verified
/// source: the decoder's own check stops a config that buys a "token"
/// without code; the owner installs the mandate with the router's
/// allowance; the agent registers and signs an order, each with a nonce of
/// its own; a taker fills it at the router on the account's word, once; an
/// order outside the terms goes nowhere; revoking takes the allowance back.
#[test]
fn one_inch_orders_under_a_mandate() {
    let chain = chain_or_skip!("one-inch");
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

    // the policy of this source in the place of the deployed one
    let built = deploy("agentPolicyInitCode", word(&chain.addr("safeNonceAssert")));
    let code = chain.rpc("eth_getCode", json!([built, "latest"]));
    chain.rpc("anvil_setCode", json!([policy, code]));

    let (usd, weth) = (deploy("mockTokenInitCode", vec![]), deploy("mockTokenInitCode", vec![]));
    let router = deploy("routerStandInInitCode", vec![]);
    let decoder = deploy("oneInchLimitOrderDecoderInitCode", word(&router));
    let decoder_code = chain.rpc("eth_getCode", json!([decoder, "latest"]));
    let decoder_hash = alloy::primitives::keccak256(hex::decode(decoder_code.as_str().unwrap().trim_start_matches("0x")).unwrap());

    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    const PERIOD: u64 = 30 * 86_400;
    // the trading mandate: 200 a time, 300 a period, never under 0.0002 WETH for a USD
    let mandate = |name: &str, change: &dyn Fn(&mut Value)| {
        let path = chain.config(
            name,
            &Cfg {
                permission: "0x6c696d31",
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), ORDER_REGISTER)],
                account: Some(account.clone()),
                tokens: json!([{"token": usd, "maxPerOp": "200000000", "budget": "300000000", "payees": "anyone"}]),
                ..base_cfg(&owner, &agent, &counter, until)
            },
        );
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["policy"]["period"] = json!(PERIOD);
        v["policy"]["venues"] = json!([{
            "kind": "1inch", "decoder": decoder, "codeHash": decoder_hash.to_string(), "maxLife": 1800,
            "pairs": [{"sellToken": usd, "buyToken": weth, "minBuy": "200000000000000", "perSell": "1000000"}],
        }]);
        change(&mut v);
        std::fs::write(&path, v.to_string()).unwrap();
        path
    };
    let cfg = mandate("limit.json", &|_| {});

    // the terms are put to the decoder itself before a mandate is made of them:
    // a pair that buys an address without code would give the sold amount away
    let codeless = mandate("codeless.json", &|v| v["policy"]["venues"][0]["pairs"][0]["buyToken"] = json!("0x00000000000000000000000000000000000c0de5"));
    let why = chain.fails(&["permission", "show", "--agent", &codeless]);
    assert!(why.contains("refuses this config's terms") && why.contains("without code"), "{why}");
    // a 1inch order has no appData; and CoW Swap's has one
    let with_app_data = mandate("app-data.json", &|v| v["policy"]["venues"][0]["appData"] = json!(format!("0x{}", "00".repeat(32))));
    let why = chain.fails(&["permission", "show", "--agent", &with_app_data]);
    assert!(why.contains("a 1inch order has none"), "{why}");

    let acct: Address = account.parse().unwrap();
    let balance = |token: &str, who: Address| U256::from_be_slice(&chain.call(token, balanceOfCall { account: who }.abi_encode()));
    let allowance = || {
        let call = trading_abi::allowanceCall { owner: acct, spender: router.parse().unwrap() };
        U256::from_be_slice(&chain.call(&usd, call.abi_encode()))
    };
    // the account holds what it sells; the taker holds what it pays with, and lets the router take it
    let taker: Address = FACILITATOR.parse().unwrap();
    chain.send_from(FACILITATOR, Some(&usd), mintCall { to: acct, amount: U256::from(10_000_000_000u64) }.abi_encode());
    chain.send_from(FACILITATOR, Some(&weth), mintCall { to: taker, amount: U256::from(10u64).pow(U256::from(18)) }.abi_encode());
    chain.send_from(FACILITATOR, Some(&weth), one_inch_abi::approveCall { spender: router.parse().unwrap(), amount: U256::MAX }.abi_encode());

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
    // the taker's fill at the router: the eight words as the CLI printed them, the whole making amount
    let fill = |o: &Value| -> Vec<u8> {
        let d = &o["data"];
        let num = |k: &str| d[k].as_str().unwrap().parse::<U256>().unwrap();
        let addr = |k: &str| U256::from_be_slice(d[k].as_str().unwrap().parse::<Address>().unwrap().as_slice());
        one_inch_abi::fillContractOrderCall {
            order: one_inch_abi::LimitOrder {
                salt: num("salt"),
                maker: addr("maker"),
                receiver: addr("receiver"),
                makerAsset: addr("makerAsset"),
                takerAsset: addr("takerAsset"),
                makingAmount: num("makingAmount"),
                takingAmount: num("takingAmount"),
                makerTraits: num("makerTraits"),
            },
            signature: o["signature"].as_str().unwrap().parse().unwrap(),
            amount: num("makingAmount"),
            takerTraits: U256::from(1u8) << 255usize,
        }
        .abi_encode()
    };
    let would_fill = |o: &Value| -> bool {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"from": FACILITATOR, "to": router, "data": Bytes::from(fill(o)).to_string()}, "latest"]});
        let v: Value = serde_json::from_str(&http_post(&chain.url, &body.to_string())).unwrap();
        v.get("error").is_none()
    };

    // before the owner installs the mandate there is no allowance, and the CLI says so
    assert!(allowance().is_zero());
    let early = refused(&sell("150000000", "37500000000000000"));
    assert!(early.contains("the owner gives the allowance with the mandate"), "{early}");

    // the owner's one operation: the old permission out, the trading one in, the router's allowance given
    chain.ok(&["permission", "rotate", "--agent", &cfg, "--old-id", "0x74657331"]);
    assert_eq!(allowance(), U256::from(300_000_000u64));
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains("ok period") && shown.contains("ok venue") && !shown.contains("DIFF"), "{shown}");

    // this venue takes orders, not swaps
    let why = chain.fails(&["order", "swap", "--agent", &cfg, "--sell", &usd, "--buy", &weth, "--sell-amount", "1000000", "--buy-amount", "200000000000000"]);
    assert!(why.contains("takes orders, not swaps"), "{why}");

    // an order within the terms: registered, signed, in the form 1inch's order book takes
    let o = placed(&sell("150000000", "37500000000000000"));
    assert_eq!(o["data"]["extension"], "0x");
    assert_eq!(o["data"]["receiver"], Address::ZERO.to_string());
    assert_eq!(o["data"]["maker"].as_str().unwrap().to_lowercase(), account.to_lowercase());
    // its traits: no partial fills, an expiration, a nonce, and no other bit
    let traits: U256 = o["data"]["makerTraits"].as_str().unwrap().parse().unwrap();
    let top: U256 = traits >> 255usize;
    assert_eq!(top, U256::from(1u8));
    let forty = U256::from((1u64 << 40) - 1);
    let middle: U256 = (traits >> 160usize) & ((U256::from(1u8) << 95usize) - U256::from(1u8));
    assert!(middle.is_zero(), "{traits}");
    let expiration: U256 = (traits >> 80usize) & forty;
    assert_eq!(expiration, U256::from(o["expiration"].as_u64().unwrap()));
    // the eight words the decoder judged are the ones printed
    assert_eq!(o["order"].as_str().unwrap().len(), 2 + 2 * 8 * 32);
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 150000000)"));

    // a taker fills it at the router: the router asks the account, and the account vouches
    assert!(would_fill(&o));
    chain.send_from(FACILITATOR, Some(&router), fill(&o));
    assert_eq!(balance(&usd, acct), U256::from(10_000_000_000u64 - 150_000_000));
    assert_eq!(balance(&weth, acct), U256::from(37_500_000_000_000_000u64));
    assert_eq!(balance(&usd, taker), U256::from(150_000_000u64));
    // once: the router's bit for the order's nonce is set
    assert!(!would_fill(&o));

    // the same terms again are another order: a salt and a nonce of its own
    let second = placed(&sell("150000000", "37500000000000000"));
    assert_ne!(second["orderHash"], o["orderHash"]);
    assert_ne!(second["data"]["makerTraits"], o["data"]["makerTraits"]);
    assert!(would_fill(&second));
    // with another order's signature the router gets a no from the account
    let mut forged = second.clone();
    forged["data"]["takingAmount"] = json!("1");
    assert!(!would_fill(&forged));

    // outside the terms: under the lowest price (stopped before any operation),
    // over the cap for one order, over the period's budget (refused by the policy)
    let cheap = refused(&sell("150000000", "29999999999999999"));
    assert!(cheap.contains("below the mandate's lowest price"), "{cheap}");
    refused(&sell("200000001", "50000000000000000"));
    refused(&sell("1000000", "250000000000000"));
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 300000000)"));

    // past its end the account no longer vouches, and the router no longer fills
    chain.advance(1801);
    assert!(!would_fill(&second));

    // revoking takes the router's allowance back with the mandate
    assert_eq!(allowance(), U256::from(150_000_000u64));
    chain.ok(&["permission", "revoke", "--agent", &cfg, "--id", "0x6c696d31"]);
    assert!(allowance().is_zero());
    chain.fails(&["demo", "--agent", &cfg]);
}

mod pull_abi {
    alloy::sol! {
        function pull(address token, address from, address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// `op batch`: several calls as one operation of the agent, and the shape a
/// protocol that pulls tokens needs (`--allow`): the allowance, the call that
/// uses it, the allowance taken back. The spender here is a contract that
/// pulls what it is told to, as a lending pool pulls a supply. The mandate
/// judges every call: one refused call refuses them all, and an allowance
/// that would be left standing is refused.
#[test]
fn a_batch_gives_an_allowance_for_one_operation() {
    let chain = chain_or_skip!("batch");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str| {
        let code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let (token, pool) = (deploy("mockTokenInitCode"), deploy("relayerInitCode"));
    let sink: Address = "0x00000000000000000000000000000000000051c0".parse().unwrap();

    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let acct: Address = account.parse().unwrap();
    // the mandate: the token within 100 a time and 250 in all, the pool's `pull`, the counter
    const PULL: &str = "0xdc772e94";
    assert_eq!(hex::encode(pull_abi::pullCall::SELECTOR), PULL.trim_start_matches("0x"));
    let cfg = chain.config(
        "pool.json",
        &Cfg {
            permission: "0x706f6f6c",
            // the token's `approve` is named like any other call; the limit below is what bounds it
            allow: vec![(counter.clone(), INCREMENT), (pool.clone(), PULL), (token.clone(), "0x095ea7b3")],
            account: Some(account.clone()),
            tokens: json!([{"token": token, "maxPerOp": "100", "budget": "250", "payees": "anyone"}]),
            ..base_cfg(&owner, &agent, &counter, until)
        },
    );
    chain.ok(&["permission", "rotate", "--agent", &cfg, "--old-id", "0x74657331"]);
    chain.send_from(FACILITATOR, Some(&token), mintCall { to: acct, amount: U256::from(1_000u64) }.abi_encode());
    let balance = |who: Address| U256::from_be_slice(&chain.call(&token, balanceOfCall { account: who }.abi_encode()));
    let allowance = || {
        let call = trading_abi::allowanceCall { owner: acct, spender: pool.parse().unwrap() };
        U256::from_be_slice(&chain.call(&token, call.abi_encode()))
    };
    let pull = |amount: u64| {
        let data = pull_abi::pullCall { token: token.parse().unwrap(), from: acct, to: sink, amount: U256::from(amount) }.abi_encode();
        format!("{pool}:0:0x{}", hex::encode(data))
    };
    let allow = |amount: u64| format!("{token}:{pool}:{amount}");

    // the allowance, the pull, the allowance back: one operation, and the counter with it
    let before = chain.counter();
    let out = chain.ok(&["op", "batch", "--agent", &cfg, "--allow", &allow(100), "--call", &pull(100), "--call", &format!("{counter}:0:{INCREMENT}")]);
    assert!(out.contains("4 call(s) in one operation") && out.contains("included: tx"), "{out}");
    assert_eq!(balance(sink), U256::from(100u64));
    assert_eq!(balance(acct), U256::from(900u64));
    assert!(allowance().is_zero(), "no allowance stands after the operation");
    assert_eq!(chain.counter(), before + U256::from(1));
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 100)"));

    // the pool takes less than it was allowed: the rest of the allowance is gone all the same
    chain.ok(&["op", "batch", "--agent", &cfg, "--allow", &allow(100), "--call", &pull(60)]);
    assert_eq!(balance(sink), U256::from(160u64));
    assert!(allowance().is_zero());
    // charged is what was allowed, not what was taken
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("(spent 200)"));

    // an allowance left standing: the approval and the pull as plain calls, with no withdrawal
    let approve = |amount: u64| {
        let data = pull_abi::approveCall { spender: pool.parse().unwrap(), amount: U256::from(amount) }.abi_encode();
        format!("{token}:0:0x{}", hex::encode(data))
    };
    chain.fails(&["op", "batch", "--agent", &cfg, "--call", &approve(10), "--call", &pull(10)]);
    // over the cap per operation; over what is left of the budget
    chain.fails(&["op", "batch", "--agent", &cfg, "--allow", &allow(101), "--call", &pull(1)]);
    chain.fails(&["op", "batch", "--agent", &cfg, "--allow", &allow(51), "--call", &pull(1)]);
    // one call outside the mandate refuses the whole operation: nothing of it happens
    let before = chain.counter();
    chain.fails(&["op", "batch", "--agent", &cfg, "--call", &format!("{counter}:0:{INCREMENT}"), "--call", &format!("{pool}:0:0xdeadbeef")]);
    assert_eq!(chain.counter(), before);
    // the pull without an allowance passes the mandate and fails at the token: nothing moves
    chain.fails(&["op", "batch", "--agent", &cfg, "--call", &pull(1)]);
    assert_eq!(balance(sink), U256::from(160u64));
    assert!(allowance().is_zero());
    // an entry that is not three parts is refused before anything is signed
    let why = chain.fails(&["op", "batch", "--agent", &cfg, "--call", &format!("{pool}:0x")]);
    assert!(why.contains("is not <target>:<wei>:<0x calldata>"), "{why}");
    let why = chain.fails(&["op", "batch", "--agent", &cfg]);
    assert!(why.contains("at least one call"), "{why}");
}

mod swap_abi {
    alloy::sol! {
        function setPrice(uint256 n, uint256 d) external;
    }
}

/// A mandate that swaps at a router, end to end (issue #80), on the policy
/// and the decoder built from this repository's sources and a stand-in for
/// Uniswap's SwapRouter02 with the router's three habits the decoder's rules
/// are about. The owner installs the mandate with the router's allowance;
/// `order swap` registers the swap and makes it in one operation, and what
/// is bought comes to the account; a swap outside the terms goes nowhere; a
/// swap the pool would not honour is found before anything is sent; revoking
/// ends the mandate.
#[test]
fn swaps_under_a_mandate() {
    let chain = chain_or_skip!("swap");
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

    // the policy of this source in the place of the deployed one
    let built = deploy("agentPolicyInitCode", word(&chain.addr("safeNonceAssert")));
    let code = chain.rpc("eth_getCode", json!([built, "latest"]));
    chain.rpc("anvil_setCode", json!([policy, code]));

    let (usd, weth) = (deploy("mockTokenInitCode", vec![]), deploy("mockTokenInitCode", vec![]));
    let router = deploy("swapRouterStandInInitCode", vec![]);
    let decoder = deploy("swapRouter02DecoderInitCode", word(&router));
    let decoder_code = chain.rpc("eth_getCode", json!([decoder, "latest"]));
    let decoder_hash = alloy::primitives::keccak256(hex::decode(decoder_code.as_str().unwrap().trim_start_matches("0x")).unwrap());

    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    const PERIOD: u64 = 30 * 86_400;
    // the trading mandate: 200 a time, 300 a period, never under 0.0002 WETH for a USD
    let mandate = |name: &str, change: &dyn Fn(&mut Value)| {
        let path = chain.config(
            name,
            &Cfg {
                permission: "0x73776170",
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), ORDER_REGISTER)],
                account: Some(account.clone()),
                tokens: json!([{"token": usd, "maxPerOp": "200000000", "budget": "300000000", "payees": "anyone"}]),
                ..base_cfg(&owner, &agent, &counter, until)
            },
        );
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["policy"]["period"] = json!(PERIOD);
        v["policy"]["venues"] = json!([{
            "kind": "uniswap", "decoder": decoder, "codeHash": decoder_hash.to_string(),
            "pairs": [{"sellToken": usd, "buyToken": weth, "minBuy": "200000000000000", "perSell": "1000000"}],
        }]);
        change(&mut v);
        std::fs::write(&path, v.to_string()).unwrap();
        path
    };
    let cfg = mandate("swap.json", &|_| {});

    // the terms are put to the decoder itself before a mandate is made of them
    let codeless = mandate("codeless.json", &|v| v["policy"]["venues"][0]["pairs"][0]["buyToken"] = json!("0x00000000000000000000000000000000000c0de5"));
    let why = chain.fails(&["permission", "show", "--agent", &codeless]);
    assert!(why.contains("refuses this config's terms") && why.contains("without code"), "{why}");
    // a swap is made at once: a lifetime for it is refused
    let with_life = mandate("life.json", &|v| v["policy"]["venues"][0]["maxLife"] = json!(600));
    let why = chain.fails(&["permission", "show", "--agent", &with_life]);
    assert!(why.contains("a swap is made at once and has neither"), "{why}");

    let acct: Address = account.parse().unwrap();
    let balance = |token: &str, who: Address| U256::from_be_slice(&chain.call(token, balanceOfCall { account: who }.abi_encode()));
    let allowance = || {
        let call = trading_abi::allowanceCall { owner: acct, spender: router.parse().unwrap() };
        U256::from_be_slice(&chain.call(&usd, call.abi_encode()))
    };
    // the account holds what it sells; the stand-in router holds what it pays with
    chain.send_from(FACILITATOR, Some(&usd), mintCall { to: acct, amount: U256::from(10_000_000_000u64) }.abi_encode());
    chain.send_from(FACILITATOR, Some(&weth), mintCall { to: router.parse().unwrap(), amount: U256::from(10u64).pow(U256::from(18)) }.abi_encode());

    let swap = |amount: &str, least: &str| -> Vec<String> {
        ["order", "swap", "--agent", &cfg, "--sell", &usd, "--buy", &weth, "--sell-amount", amount, "--buy-amount", least, "--fee", "500"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let run = |args: &[String]| chain.cli(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let swapped = |args: &[String]| -> Value {
        let out = run(args);
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "order swap failed:\n{stderr}\n{stdout}");
        serde_json::from_str(stdout.lines().find(|l| l.starts_with('{')).unwrap_or_else(|| panic!("no swap in: {stdout}"))).unwrap()
    };
    let refused = |args: &[String]| -> String {
        let out = run(args);
        assert!(!out.status.success(), "the swap was expected to be refused");
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    };
    let spent = |n: u64| chain.ok(&["permission", "show", "--agent", &cfg]).contains(&format!("(spent {n})"));

    // before the owner installs the mandate there is no allowance, and the CLI says so
    assert!(allowance().is_zero());
    let early = refused(&swap("150000000", "30000000000000000"));
    assert!(early.contains("the owner gives the allowance with the mandate"), "{early}");

    // the owner's one operation: the old permission out, the trading one in, the router's allowance given
    chain.ok(&["permission", "rotate", "--agent", &cfg, "--old-id", "0x74657331"]);
    assert_eq!(allowance(), U256::from(300_000_000u64));
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains("ok period") && shown.contains("ok venue") && !shown.contains("DIFF"), "{shown}");

    // a swap within the terms, at the owner's lowest price: one operation, and the
    // pool's price is what is paid (0.0003 WETH for a USD at the stand-in)
    let s = swapped(&swap("150000000", "30000000000000000"));
    assert_eq!(s["sold"], "150000000");
    assert_eq!(s["bought"], "45000000000000000");
    assert_eq!(s["leastBought"], "30000000000000000");
    assert_eq!(s["router"].as_str().unwrap().to_lowercase(), router.to_lowercase());
    assert_eq!(balance(&usd, acct), U256::from(10_000_000_000u64 - 150_000_000));
    assert_eq!(balance(&weth, acct), U256::from(45_000_000_000_000_000u64));
    // charged, and out of the owner's allowance
    assert!(spent(150_000_000));
    assert_eq!(allowance(), U256::from(150_000_000u64));

    // this venue takes swaps, not orders
    let why = chain.fails(&["order", "sell", "--agent", &cfg, "--sell", &usd, "--buy", &weth, "--sell-amount", "1000000", "--buy-amount", "200000000000000"]);
    assert!(why.contains("takes swaps, not orders"), "{why}");
    // the router is no target of the agent's by itself: its call without the registration is refused
    chain.fails(&["op", "batch", "--agent", &cfg, "--call", &format!("{router}:0:0x04e45aaf")]);

    // outside the terms: under the lowest price and a pair the other way (stopped
    // before any operation), over the cap for one operation (refused by the policy)
    let cheap = refused(&swap("150000000", "29999999999999999"));
    assert!(cheap.contains("below the mandate's lowest price"), "{cheap}");
    let back = chain.fails(&["order", "swap", "--agent", &cfg, "--sell", &weth, "--buy", &usd, "--sell-amount", "1000", "--buy-amount", "1"]);
    assert!(back.contains("is not a pair of this mandate"), "{back}");
    refused(&swap("200000001", "40000000200000000"));
    assert!(spent(150_000_000));
    assert_eq!(balance(&weth, acct), U256::from(45_000_000_000_000_000u64));

    // the pool pays less than the swap asks for: the CLI runs the operation's calls
    // before it sends anything, the router's own check fails there, and nothing is
    // sent or charged
    chain.send_from(FACILITATOR, Some(&router), swap_abi::setPriceCall { n: U256::from(250_000_000u64), d: U256::from(1u8) }.abi_encode());
    let short = refused(&swap("50000000", "15000000000000000"));
    assert!(short.contains("Too little received"), "{short}");
    assert_eq!(balance(&usd, acct), U256::from(10_000_000_000u64 - 150_000_000));
    assert_eq!(balance(&weth, acct), U256::from(45_000_000_000_000_000u64));
    assert_eq!(allowance(), U256::from(150_000_000u64));
    assert!(spent(150_000_000), "{short}");

    // the rest of the period's budget, at the pool's new price, and not a unit more
    let s = swapped(&swap("150000000", "30000000000000000"));
    assert_eq!(s["bought"], "37500000000000000");
    assert!(spent(300_000_000));
    refused(&swap("1000000", "200000000000000"));

    // revoking leaves no allowance to the router (the budget's worth was given, and all of it was swapped)
    assert!(allowance().is_zero());
    assert_eq!(balance(&weth, acct), U256::from(82_500_000_000_000_000u64));
    chain.ok(&["permission", "revoke", "--agent", &cfg, "--id", "0x73776170"]);
    assert!(allowance().is_zero());
    chain.fails(&["demo", "--agent", &cfg]);
}

mod pool_abi {
    alloy::sol! {
        function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
        function withdraw(address asset, uint256 amount, address to) external returns (uint256);
        function borrow(address asset, uint256 amount) external;
        function credit(address asset, address who) external view returns (uint256);
    }
}

/// A mandate with a venue of rules, end to end (issue #80), on the policy
/// and the decoder built from this repository's sources and a stand-in for a
/// lending pool whose two functions name a beneficiary, as Aave's do. The
/// owner installs the mandate with the pool's allowance; `order call`
/// registers a call and makes it in one operation; a supply for the account
/// is made and charged, a withdrawal to it is not charged; the same for
/// somebody else, a function the owner did not list and an amount past the
/// limits go nowhere; revoking takes the allowance back.
#[test]
fn calls_with_rules_under_a_mandate() {
    let chain = chain_or_skip!("rules");
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

    // the policy of this source in the place of the deployed one
    let built = deploy("agentPolicyInitCode", word(&chain.addr("safeNonceAssert")));
    let code = chain.rpc("eth_getCode", json!([built, "latest"]));
    chain.rpc("anvil_setCode", json!([policy, code]));

    let usd = deploy("mockTokenInitCode", vec![]);
    let pool = deploy("poolStandInInitCode", vec![]);
    // one decoder for the one contract: the pool is the venue and the spender
    let decoder = deploy("callRulesDecoderInitCode", [word(&pool), word(&pool)].concat());
    let decoder_code = chain.rpc("eth_getCode", json!([decoder, "latest"]));
    let decoder_hash = alloy::primitives::keccak256(hex::decode(decoder_code.as_str().unwrap().trim_start_matches("0x")).unwrap());

    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    const PERIOD: u64 = 30 * 86_400;
    // the mandate: 200 a time, 300 a period; a supply of the token for the account, charged,
    // and a withdrawal of it to the account
    let mandate = |name: &str, change: &dyn Fn(&mut Value)| {
        let path = chain.config(
            name,
            &Cfg {
                permission: "0x72756c65",
                allow: vec![(counter.clone(), INCREMENT), (policy.clone(), ORDER_REGISTER)],
                account: Some(account.clone()),
                tokens: json!([{"token": usd, "maxPerOp": "200000000", "budget": "300000000", "payees": "anyone"}]),
                ..base_cfg(&owner, &agent, &counter, until)
            },
        );
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["policy"]["period"] = json!(PERIOD);
        v["policy"]["venues"] = json!([{
            "kind": "rules", "decoder": decoder, "codeHash": decoder_hash.to_string(),
            "functions": [
                {"selector": "0x617ba037", "words": [{"is": usd}, {"charged": usd}, "account", {"is": "0"}]},
                {"selector": "0x69328dec", "words": [{"is": usd}, "any", "account"]},
            ],
        }]);
        change(&mut v);
        std::fs::write(&path, v.to_string()).unwrap();
        path
    };
    let cfg = mandate("rules.json", &|_| {});

    // the terms are put to the decoder itself before a mandate is made of them:
    // a function listed twice is no list of rules
    let twice = mandate("twice.json", &|v| {
        let f = v["policy"]["venues"][0]["functions"][0].clone();
        v["policy"]["venues"][0]["functions"].as_array_mut().unwrap().push(f);
    });
    let why = chain.fails(&["permission", "show", "--agent", &twice]);
    assert!(why.contains("refuses this config's terms") && why.contains("a function twice"), "{why}");
    // a venue of rules has no pairs
    let with_pairs = mandate("pairs.json", &|v| {
        v["policy"]["venues"][0]["pairs"] = json!([{"sellToken": usd, "buyToken": counter, "minBuy": "1", "perSell": "1"}]);
    });
    let why = chain.fails(&["permission", "show", "--agent", &with_pairs]);
    assert!(why.contains("it has `functions` and none of those"), "{why}");
    // such a decoder is one per contract: the deployments file names none, so its code hash is stated
    let unpinned = mandate("unpinned.json", &|v| {
        v["policy"]["venues"][0].as_object_mut().unwrap().remove("codeHash");
    });
    let why = chain.fails(&["permission", "show", "--agent", &unpinned]);
    assert!(why.contains("state its `codeHash`"), "{why}");

    let acct: Address = account.parse().unwrap();
    let (usd_a, pool_a): (Address, Address) = (usd.parse().unwrap(), pool.parse().unwrap());
    let balance = |who: Address| U256::from_be_slice(&chain.call(&usd, balanceOfCall { account: who }.abi_encode()));
    let credit = |who: Address| U256::from_be_slice(&chain.call(&pool, pool_abi::creditCall { asset: usd_a, who }.abi_encode()));
    let allowance = || U256::from_be_slice(&chain.call(&usd, trading_abi::allowanceCall { owner: acct, spender: pool_a }.abi_encode()));
    chain.send_from(FACILITATOR, Some(&usd), mintCall { to: acct, amount: U256::from(10_000_000_000u64) }.abi_encode());

    let other: Address = "0x00000000000000000000000000000000000051c0".parse().unwrap();
    let supply = |amount: u64, to: Address| {
        Bytes::from(pool_abi::supplyCall { asset: usd_a, amount: U256::from(amount), onBehalfOf: to, referralCode: 0 }.abi_encode()).to_string()
    };
    let withdraw = |amount: u64, to: Address| Bytes::from(pool_abi::withdrawCall { asset: usd_a, amount: U256::from(amount), to }.abi_encode()).to_string();
    let call = |data: &str| -> Vec<String> { ["order", "call", "--agent", &cfg, "--data", data].iter().map(|s| s.to_string()).collect() };
    let run = |args: &[String]| chain.cli(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let called = |args: &[String]| -> Value {
        let out = run(args);
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "order call failed:\n{stderr}\n{stdout}");
        serde_json::from_str(stdout.lines().find(|l| l.starts_with('{')).unwrap_or_else(|| panic!("no call in: {stdout}"))).unwrap()
    };
    let refused = |args: &[String]| -> String {
        let out = run(args);
        assert!(!out.status.success(), "the call was expected to be refused");
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    };
    let spent = |n: u64| chain.ok(&["permission", "show", "--agent", &cfg]).contains(&format!("(spent {n})"));

    // before the owner installs the mandate there is no allowance, and the CLI says so
    assert!(allowance().is_zero());
    let early = refused(&call(&supply(150_000_000, acct)));
    assert!(early.contains("the owner gives the allowance with the mandate"), "{early}");

    // the owner's one operation: the old permission out, this one in, the pool's allowance given
    chain.ok(&["permission", "rotate", "--agent", &cfg, "--old-id", "0x74657331"]);
    assert_eq!(allowance(), U256::from(300_000_000u64));
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains("ok period") && shown.contains("ok venue") && !shown.contains("DIFF"), "{shown}");

    // a supply for the account: one operation, credited to the account, charged
    let c = called(&call(&supply(150_000_000, acct)));
    assert_eq!(c["charged"], "150000000");
    assert_eq!(c["chargedToken"].as_str().unwrap().to_lowercase(), usd.to_lowercase());
    assert_eq!(c["venue"].as_str().unwrap().to_lowercase(), pool.to_lowercase());
    assert_eq!(credit(acct), U256::from(150_000_000u64));
    assert_eq!(balance(acct), U256::from(10_000_000_000u64 - 150_000_000));
    assert!(spent(150_000_000));
    assert_eq!(allowance(), U256::from(150_000_000u64));

    // a withdrawal to the account: made, and charged nothing
    let c = called(&call(&withdraw(50_000_000, acct)));
    assert_eq!(c["charged"], "0");
    assert_eq!(credit(acct), U256::from(100_000_000u64));
    assert_eq!(balance(acct), U256::from(10_000_000_000u64 - 100_000_000));
    assert!(spent(150_000_000));

    // for somebody else, each of the two: the rules refuse, before any operation
    let why = refused(&call(&supply(1_000_000, other)));
    assert!(why.contains("refuse this call"), "{why}");
    let why = refused(&call(&withdraw(1_000_000, other)));
    assert!(why.contains("refuse this call"), "{why}");
    // a function the owner did not list; a supply with a referral code; a word more
    let borrow = Bytes::from(pool_abi::borrowCall { asset: usd_a, amount: U256::from(1u8) }.abi_encode()).to_string();
    assert!(refused(&call(&borrow)).contains("refuse this call"));
    let referred = Bytes::from(pool_abi::supplyCall { asset: usd_a, amount: U256::from(1u8), onBehalfOf: acct, referralCode: 7 }.abi_encode()).to_string();
    assert!(refused(&call(&referred)).contains("refuse this call"));
    assert!(refused(&call(&format!("{}{}", supply(1, acct), "00".repeat(32)))).contains("refuse this call"));
    // this venue takes calls, not orders and not swaps
    let why = chain.fails(&["order", "sell", "--agent", &cfg, "--sell", &usd, "--buy", &counter, "--sell-amount", "1", "--buy-amount", "1"]);
    assert!(why.contains("takes calls, not orders"), "{why}");
    let why = chain.fails(&["order", "swap", "--agent", &cfg, "--sell", &usd, "--buy", &counter, "--sell-amount", "1", "--buy-amount", "1"]);
    assert!(why.contains("takes calls, not swaps"), "{why}");
    // the pool is no target of the agent's by itself: its call without the registration is refused
    chain.fails(&["op", "batch", "--agent", &cfg, "--call", &format!("{pool}:0:{}", supply(1_000_000, acct))]);

    // past the limits: over the cap for one operation, then the rest of the budget and not a unit more
    refused(&call(&supply(200_000_001, acct)));
    assert!(spent(150_000_000));
    called(&call(&supply(150_000_000, acct)));
    assert!(spent(300_000_000));
    refused(&call(&supply(1, acct)));
    // a withdrawal still passes: it is charged nothing
    called(&call(&withdraw(250_000_000, acct)));
    assert!(credit(acct).is_zero());
    assert!(credit(other).is_zero() && balance(other).is_zero());

    // revoking takes the pool's allowance back with the mandate
    assert!(allowance().is_zero());
    chain.ok(&["permission", "revoke", "--agent", &cfg, "--id", "0x72756c65"]);
    assert!(allowance().is_zero());
    chain.fails(&["demo", "--agent", &cfg]);
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

/// The same for the 1inch decoder: what the phone reads from its config
/// (`one_inch_terms`) and what `OneInchLimitOrderDecoder` enforces from the
/// same bytes. One difference is by design and is held here too: the
/// decoder's `checkConfig` asks for code at every token, which a phone
/// cannot see, so the laptop asks the chain before a mandate is made
/// (`one_inch_orders_under_a_mandate`).
#[test]
fn the_phone_reads_a_one_inch_config_as_the_decoder_does() {
    use owner_core::kernel as k;
    use owner_core::review::one_inch_terms;
    let chain = chain_or_skip!("one-inch-config");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str, args: Vec<u8>| {
        let mut code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend(args);
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let router = deploy("routerStandInInitCode", vec![]);
    let decoder = deploy("oneInchLimitOrderDecoderInitCode", router.parse::<Address>().unwrap().abi_encode());
    // a call that may revert: the returned bytes, or nothing
    let ask = |signature: &str, args: Vec<u8>| -> Option<Vec<u8>> {
        let mut data = alloy::primitives::keccak256(signature)[..4].to_vec();
        data.extend(args);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": decoder, "data": Bytes::from(data).to_string()}, "latest"]});
        let v: Value = serde_json::from_str(&http_post(&chain.url, &body.to_string())).unwrap();
        v.get("result").and_then(|r| r.as_str()).map(|r| hex::decode(r.trim_start_matches("0x")).unwrap())
    };
    let account: Address = "0x00000000000000000000000000000000000Acc01".to_lowercase().parse().unwrap();
    // five tokens with code, as `checkConfig` asks, and one address without
    let tokens: Vec<Address> = (1u8..=5).map(Address::repeat_byte).collect();
    for token in &tokens {
        chain.rpc("anvil_setCode", json!([token.to_string(), "0x00"]));
    }
    let codeless = Address::repeat_byte(0xcc);

    let mut rng: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let (mut both, mut chain_only, mut neither) = (0, 0, 0);
    for _ in 0..400 {
        // a config: mostly within the rules, with a share of what the rules refuse
        let count = if next(12) == 0 { 0 } else { 1 + next(3) };
        let pairs: Vec<(Address, Address, U256, U256)> = (0..count)
            .map(|i| {
                let sell = if next(25) == 0 { Address::ZERO } else { tokens[i as usize] };
                let buy = if next(25) == 0 { sell } else { tokens[(i + 1 + next(2)) as usize] };
                let amount = |n: u64| if n % 30 == 0 { U256::ZERO } else { U256::from(1 + n % 1_000_000) };
                (sell, buy, amount(next(u64::MAX)), amount(next(u64::MAX)))
            })
            .collect();
        let life = if next(15) == 0 { 0 } else { 1 + next(86_400) as u32 };
        let mut config = k::one_inch_config(life, &pairs).to_vec();
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

        let phone = one_inch_terms(&config);
        let on_chain = ask("checkConfig(bytes)", (Bytes::from(config.clone()),).abi_encode_params()).is_some();
        let Ok(terms) = phone else {
            if on_chain { chain_only += 1 } else { neither += 1 }
            continue;
        };
        // a changed byte can turn a token into an address without code: that is the one
        // thing the decoder refuses and the phone cannot see
        let all_have_code = terms.pairs.iter().all(|p| tokens.contains(&p.0) && tokens.contains(&p.1));
        assert_eq!(on_chain, all_have_code, "the phone and the decoder differ on more than a token's code: 0x{}", hex::encode(&config));
        if !on_chain {
            neither += 1;
            continue;
        }
        both += 1;

        let expiration = 1_900_000_000u64;
        let judge = |sell: Address, buy: Address, making: U256, taking: U256| {
            let order = k::OneInchOrder { salt: U256::from(7u8), maker: account, maker_asset: sell, taker_asset: buy, making_amount: making, taking_amount: taking, expiration, nonce: 3 };
            ask("judge(address,bytes,bytes)", (account, Bytes::from(config.clone()), order.encode().unwrap()).abi_encode_params())
        };
        for (sell, buy, min_buy, per_sell) in &terms.pairs {
            // a multiple of the price's two terms is exactly at the price; the terms
            // themselves when a multiple does not fit a word
            let times = U256::from(1 + next(1000));
            let (sold, least) = match (per_sell.checked_mul(times), min_buy.checked_mul(times)) {
                (Some(sold), Some(least)) => (sold, least),
                _ => (*per_sell, *min_buy),
            };
            // An order's amounts stay within 128 bits, the range the router's own
            // arithmetic is written for. A price whose terms are wider (a damaged byte
            // makes one) is a price no order can be made at: nothing passes.
            if sold > U256::from(u128::MAX) || least > U256::from(u128::MAX) {
                assert!(judge(*sell, *buy, sold, least).is_none(), "an order with an amount beyond 128 bits passes: 0x{}", hex::encode(&config));
                continue;
            }
            let answer = judge(*sell, *buy, sold, least).unwrap_or_else(|| panic!("an order at the lowest price the phone read is refused: 0x{}", hex::encode(&config)));
            assert_eq!(answer.len(), 160);
            assert_eq!(Address::from_slice(&answer[12..32]), *sell, "the token charged");
            assert_eq!(U256::from_be_slice(&answer[32..64]), sold, "the amount charged");
            assert_eq!(U256::from_be_slice(&answer[64..96]), U256::from(expiration - u64::from(terms.max_life)), "the lifetime");
            assert_eq!(U256::from_be_slice(&answer[96..128]), U256::from(expiration));
            assert!(judge(*sell, *buy, sold, least - U256::from(1)).is_none(), "an order under the lowest price the phone read passes: 0x{}", hex::encode(&config));
        }
        // a pair the phone did not read is not traded, at any price
        for sell in &tokens {
            for buy in &tokens {
                if !terms.pairs.iter().any(|p| p.0 == *sell && p.1 == *buy) {
                    assert!(judge(*sell, *buy, U256::from(1), U256::from(u128::MAX)).is_none(), "a pair the phone did not read is traded: 0x{}", hex::encode(&config));
                }
            }
        }
    }
    // the generator reaches all three kinds
    assert!(both >= 150 && chain_only >= 5 && neither >= 50, "accepted by both {both}, by the decoder only {chain_only}, by neither {neither}");
    eprintln!("configs: {both} accepted by both, {chain_only} by the decoder only, {neither} by neither");

    // The difference by design: terms that buy an address without code. The phone reads
    // them, since bytes cannot show code; the decoder's `checkConfig` refuses them.
    let buys_nothing = k::one_inch_config(1800, &[(tokens[0], codeless, U256::from(1u8), U256::from(1u8))]);
    assert!(one_inch_terms(&buys_nothing).is_ok());
    assert!(ask("checkConfig(bytes)", (buys_nothing.clone(),).abi_encode_params()).is_none());
}

/// The same for the swap decoder: what the phone reads from its config
/// (`swap_terms`) and what `SwapRouter02Decoder` enforces from the same
/// bytes. And the call: for every swap the decoder allows, the hash it
/// answers with is the hash of the router call this side builds
/// (`SwapOrder::call`), so the leg the CLI sends is the one the policy
/// expects. The decoder's `checkConfig` asks for code at every token, which
/// a phone cannot see: the laptop asks the chain (`swaps_under_a_mandate`).
#[test]
fn the_phone_reads_a_swap_config_as_the_decoder_does() {
    use owner_core::kernel as k;
    use owner_core::review::swap_terms;
    let chain = chain_or_skip!("swap-config");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str, args: Vec<u8>| {
        let mut code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend(args);
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let router = deploy("swapRouterStandInInitCode", vec![]);
    let decoder = deploy("swapRouter02DecoderInitCode", router.parse::<Address>().unwrap().abi_encode());
    // a call that may revert: the returned bytes, or nothing
    let ask = |signature: &str, args: Vec<u8>| -> Option<Vec<u8>> {
        let mut data = alloy::primitives::keccak256(signature)[..4].to_vec();
        data.extend(args);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": decoder, "data": Bytes::from(data).to_string()}, "latest"]});
        let v: Value = serde_json::from_str(&http_post(&chain.url, &body.to_string())).unwrap();
        v.get("result").and_then(|r| r.as_str()).map(|r| hex::decode(r.trim_start_matches("0x")).unwrap())
    };
    let account: Address = "0x00000000000000000000000000000000000Acc01".to_lowercase().parse().unwrap();
    // five tokens with code, as `checkConfig` asks, and one address without
    let tokens: Vec<Address> = (1u8..=5).map(Address::repeat_byte).collect();
    for token in &tokens {
        chain.rpc("anvil_setCode", json!([token.to_string(), "0x00"]));
    }
    let codeless = Address::repeat_byte(0xcc);

    let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let (mut both, mut chain_only, mut neither) = (0, 0, 0);
    for _ in 0..400 {
        // a config: mostly within the rules, with a share of what the rules refuse
        let count = if next(12) == 0 { 0 } else { 1 + next(3) };
        let pairs: Vec<(Address, Address, U256, U256)> = (0..count)
            .map(|i| {
                let sell = if next(25) == 0 { Address::ZERO } else { tokens[i as usize] };
                let buy = if next(25) == 0 { sell } else { tokens[(i + 1 + next(2)) as usize] };
                let amount = |n: u64| if n % 30 == 0 { U256::ZERO } else { U256::from(1 + n % 1_000_000) };
                (sell, buy, amount(next(u64::MAX)), amount(next(u64::MAX)))
            })
            .collect();
        let mut config = k::swap_config(&pairs).to_vec();
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

        let phone = swap_terms(&config);
        let on_chain = ask("checkConfig(bytes)", (Bytes::from(config.clone()),).abi_encode_params()).is_some();
        let Ok(terms) = phone else {
            if on_chain { chain_only += 1 } else { neither += 1 }
            continue;
        };
        // a changed byte can turn a token into an address without code: that is the one
        // thing the decoder refuses and the phone cannot see
        let all_have_code = terms.pairs.iter().all(|p| tokens.contains(&p.0) && tokens.contains(&p.1));
        assert_eq!(on_chain, all_have_code, "the phone and the decoder differ on more than a token's code: 0x{}", hex::encode(&config));
        if !on_chain {
            neither += 1;
            continue;
        }
        both += 1;

        let fee = [100u32, 500, 3000, 10_000][next(4) as usize];
        let swap = |sell: Address, buy: Address, sold: U256, least: U256| k::SwapOrder { token_in: sell, token_out: buy, fee, amount_in: sold, amount_out_minimum: least };
        let judge = |o: &k::SwapOrder| ask("judge(address,bytes,bytes)", (account, Bytes::from(config.clone()), o.encode().unwrap()).abi_encode_params());
        for (sell, buy, min_buy, per_sell) in &terms.pairs {
            // a multiple of the price's two terms is exactly at the price; the terms
            // themselves when a multiple does not fit a word
            let times = U256::from(1 + next(1000));
            let (sold, least) = match (per_sell.checked_mul(times), min_buy.checked_mul(times)) {
                (Some(sold), Some(least)) => (sold, least),
                _ => (*per_sell, *min_buy),
            };
            let o = swap(*sell, *buy, sold, least);
            let answer = judge(&o).unwrap_or_else(|| panic!("a swap at the lowest price the phone read is refused: 0x{}", hex::encode(&config)));
            assert_eq!(answer.len(), 160);
            assert_eq!(Address::from_slice(&answer[12..32]), *sell, "the token charged");
            assert_eq!(U256::from_be_slice(&answer[32..64]), sold, "the amount charged");
            // no beginning and no end: a call, made in the leg after its registration
            assert!(answer[64..128].iter().all(|b| *b == 0), "a swap is a call, not an order");
            // the hash the policy will hold the next leg to is the hash of the call built here
            assert_eq!(&answer[128..160], o.digest(account).unwrap().as_slice(), "the call's hash");
            let theirs = ask("swapCall(address,bytes)", (account, o.encode().unwrap()).abi_encode_params()).unwrap();
            assert_eq!(<Bytes as SolValue>::abi_decode(&theirs).unwrap(), o.call(account).unwrap(), "the call");
            assert!(judge(&swap(*sell, *buy, sold, least - U256::from(1))).is_none(), "a swap under the lowest price the phone read passes: 0x{}", hex::encode(&config));
            assert!(judge(&swap(*sell, *buy, U256::ZERO, least)).is_none(), "a swap of the router's own balance passes");
        }
        // a pair the phone did not read is not swapped, at any price
        for sell in &tokens {
            for buy in &tokens {
                if !terms.pairs.iter().any(|p| p.0 == *sell && p.1 == *buy) {
                    assert!(judge(&swap(*sell, *buy, U256::from(1), U256::MAX)).is_none(), "a pair the phone did not read is swapped: 0x{}", hex::encode(&config));
                }
            }
        }
    }
    // the generator reaches all three kinds
    assert!(both >= 150 && chain_only >= 5 && neither >= 50, "accepted by both {both}, by the decoder only {chain_only}, by neither {neither}");
    eprintln!("configs: {both} accepted by both, {chain_only} by the decoder only, {neither} by neither");

    // The difference by design: terms that buy an address without code. The phone reads
    // them, since bytes cannot show code; the decoder's `checkConfig` refuses them.
    let buys_nothing = k::swap_config(&[(tokens[0], codeless, U256::from(1u8), U256::from(1u8))]);
    assert!(swap_terms(&buys_nothing).is_ok());
    assert!(ask("checkConfig(bytes)", (buys_nothing.clone(),).abi_encode_params()).is_none());
}

/// The same for the decoder of rules: what the phone reads from its config
/// (`rules_terms`) and what `CallRulesDecoder` enforces from the same bytes.
/// For every config both accept, a call built to pass each function's rules
/// passes, with the token and the amount the phone read as charged, and the
/// same call with one held word changed does not. The decoder's
/// `checkConfig` asks for code at every charged token, which a phone cannot
/// see: the laptop asks the chain (`calls_with_rules_under_a_mandate`).
#[test]
fn the_phone_reads_a_rules_config_as_the_decoder_does() {
    use owner_core::kernel::{self as k, WordRule};
    use owner_core::review::rules_terms;
    let chain = chain_or_skip!("rules-config");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trading-code.json")).unwrap(),
    )
    .unwrap();
    let deploy = |name: &str, args: Vec<u8>| {
        let mut code = hex::decode(fixture[name].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend(args);
        chain.send_from(FACILITATOR, None, code)["contractAddress"].as_str().unwrap().to_string()
    };
    let pool = deploy("poolStandInInitCode", vec![]);
    let pool_word = pool.parse::<Address>().unwrap().abi_encode();
    let decoder = deploy("callRulesDecoderInitCode", [pool_word.clone(), pool_word].concat());
    // a call that may revert: the returned bytes, or nothing
    let ask = |signature: &str, args: Vec<u8>| -> Option<Vec<u8>> {
        let mut data = alloy::primitives::keccak256(signature)[..4].to_vec();
        data.extend(args);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": decoder, "data": Bytes::from(data).to_string()}, "latest"]});
        let v: Value = serde_json::from_str(&http_post(&chain.url, &body.to_string())).unwrap();
        v.get("result").and_then(|r| r.as_str()).map(|r| hex::decode(r.trim_start_matches("0x")).unwrap())
    };
    let account: Address = "0x00000000000000000000000000000000000Acc01".to_lowercase().parse().unwrap();
    // three tokens with code, as `checkConfig` asks of a charged token, and one address without
    let tokens: Vec<Address> = (1u8..=3).map(Address::repeat_byte).collect();
    for token in &tokens {
        chain.rpc("anvil_setCode", json!([token.to_string(), "0x00"]));
    }
    let codeless = Address::repeat_byte(0xcc);

    let mut rng: u64 = 0xd1b5_4a32_d192_ed03;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let (mut both, mut chain_only, mut neither) = (0, 0, 0);
    for _ in 0..400 {
        // a config: mostly within the rules, with a share of what the rules refuse
        let count = match next(20) {
            0 => 0,
            1 => 9,
            n => 1 + n % 3,
        };
        let functions: Vec<(alloy::primitives::FixedBytes<4>, Vec<(U256, U256)>)> = (0..count)
            .map(|i| {
                // now and then the selector of the function before it: a function twice
                let selector = if i > 0 && next(25) == 0 { [0xf0, 0, 0, (i - 1) as u8] } else { [0xf0, 0, 0, i as u8] };
                let words = if next(30) == 0 { 17 } else { next(6) };
                let rules = (0..words)
                    .map(|_| match next(40) {
                        0 => (U256::from(5u8), U256::ZERO),               // a kind the decoder does not know
                        1 => (U256::ZERO, U256::from(1u8)),               // a value where none belongs
                        2 => (U256::from(3u8), U256::ZERO),               // a charge in no token
                        n if n % 5 == 0 => (U256::ZERO, U256::ZERO),
                        n if n % 5 == 1 => (U256::from(1u8), U256::from(next(u64::MAX))),
                        n if n % 5 == 2 => (U256::from(2u8), U256::from(next(1_000_000))),
                        n if n % 5 == 3 => (U256::from(3u8), U256::from_be_slice(tokens[(n % 3) as usize].as_slice())),
                        _ => (U256::from(4u8), U256::ZERO),
                    })
                    .collect();
                (alloy::primitives::FixedBytes::from(selector), rules)
            })
            .collect();
        let mut config = (functions,).abi_encode();
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

        let phone = rules_terms(&config);
        let on_chain = ask("checkConfig(bytes)", (Bytes::from(config.clone()),).abi_encode_params()).is_some();
        let Ok(terms) = phone else {
            if on_chain { chain_only += 1 } else { neither += 1 }
            continue;
        };
        // a changed byte can turn a charged token into an address without code: that is the
        // one thing the decoder refuses and the phone cannot see
        let charged_have_code = terms.functions.iter().flat_map(|f| f.1.iter()).all(|r| !matches!(r, WordRule::Charged(t) if !tokens.contains(t)));
        assert_eq!(on_chain, charged_have_code, "the phone and the decoder differ on more than a token's code: 0x{}", hex::encode(&config));
        if !on_chain {
            neither += 1;
            continue;
        }
        both += 1;

        let judge = |call: &[u8]| ask("judge(address,bytes,bytes)", (account, Bytes::from(config.clone()), Bytes::copy_from_slice(call)).abi_encode_params());
        for (selector, rules) in &terms.functions {
            // a call that passes every rule the phone read
            let amount = U256::from(1 + next(1_000_000));
            let words: Vec<U256> = rules
                .iter()
                .map(|r| match r {
                    WordRule::IsAccount => U256::from_be_slice(account.as_slice()),
                    WordRule::IsValue(v) => *v,
                    WordRule::AtMost(bound) => *bound,
                    WordRule::Charged(_) => amount,
                    WordRule::Any => U256::from(next(u64::MAX)),
                })
                .collect();
            let call = |words: &[U256]| [selector.as_slice(), &words.iter().flat_map(|w| w.to_be_bytes::<32>()).collect::<Vec<u8>>()].concat();
            let answer = judge(&call(&words)).unwrap_or_else(|| panic!("a call within the rules the phone read is refused: 0x{}", hex::encode(&config)));
            assert_eq!(answer.len(), 160);
            // what is charged is what the phone read as charged
            let charged = rules.iter().find_map(|r| match r {
                WordRule::Charged(t) => Some(*t),
                _ => None,
            });
            assert_eq!(Address::from_slice(&answer[12..32]), charged.unwrap_or(Address::ZERO), "the token charged");
            assert_eq!(U256::from_be_slice(&answer[32..64]), if charged.is_some() { amount } else { U256::ZERO }, "the amount charged");
            assert!(answer[64..128].iter().all(|b| *b == 0), "a call, not an order");
            let hash = alloy::primitives::keccak256((U256::ZERO, alloy::primitives::keccak256(call(&words))).abi_encode());
            assert_eq!(&answer[128..160], hash.as_slice(), "the call's hash");
            // each held word, changed alone, is refused
            for (i, r) in rules.iter().enumerate() {
                let mut other = words.clone();
                match r {
                    WordRule::IsAccount | WordRule::IsValue(_) => other[i] ^= U256::from(1u8),
                    WordRule::AtMost(bound) if *bound != U256::MAX => other[i] = *bound + U256::from(1u8),
                    _ => continue,
                }
                assert!(judge(&call(&other)).is_none(), "a call that breaks the rule of word {i} passes: 0x{}", hex::encode(&config));
            }
            // a word more, and a word less where there is one
            let mut longer = words.clone();
            longer.push(U256::ZERO);
            assert!(judge(&call(&longer)).is_none(), "a call longer than its rules passes");
            if !words.is_empty() {
                assert!(judge(&call(&words[..words.len() - 1])).is_none(), "a call shorter than its rules passes");
            }
        }
        // a function the phone did not read is not called
        assert!(judge(&[0xee, 0xee, 0xee, 0xee]).is_none(), "a function the phone did not read is called: 0x{}", hex::encode(&config));
    }
    // the generator reaches all three kinds
    assert!(both >= 100 && chain_only >= 5 && neither >= 50, "accepted by both {both}, by the decoder only {chain_only}, by neither {neither}");
    eprintln!("configs: {both} accepted by both, {chain_only} by the decoder only, {neither} by neither");

    // The difference by design: a charge in an address without code. The phone reads it,
    // since bytes cannot show code; the decoder's `checkConfig` refuses it.
    let charges_nothing = k::call_rules_config(&[(alloy::primitives::FixedBytes::from([1, 2, 3, 4]), vec![WordRule::Charged(codeless)])]);
    assert!(rules_terms(&charges_nothing).is_ok());
    assert!(ask("checkConfig(bytes)", (charges_nothing.clone(),).abi_encode_params()).is_none());
}

/// An account is created through ZeroDev's staked FactoryStaker when the
/// deployments file names it and it still approves Kernel's factory, and
/// through Kernel's factory itself otherwise (issue #102). The account is
/// the same one at the same address either way: Kernel's factory derives
/// it from the same data and salt, whoever calls it.
#[test]
fn an_account_is_created_through_the_staked_factory() {
    let chain = chain_or_skip!("staker");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let cfg = chain.config("agent.json", &base_cfg(&owner, &agent, &counter, far_future(&chain)));
    let (staker, factory) = (chain.addr("kernelFactoryStaker").to_lowercase(), chain.addr("kernelFactory").to_lowercase());
    let field = |out: &str, name: &str| out.lines().find_map(|l| l.strip_prefix(name)).unwrap_or_else(|| panic!("no {name} in {out}")).trim().to_lowercase();

    // the staker holds its stake at the EntryPoint, as on the real chains; Kernel's factory holds none
    let stake = |who: &str| {
        let data = [&alloy::primitives::keccak256("getDepositInfo(address)")[..4], &who.parse::<Address>().unwrap().abi_encode()[..]].concat();
        let out = chain.call(&chain.addr("entryPoint"), data);
        (U256::from_be_slice(&out[32..64]) == U256::from(1), U256::from_be_slice(&out[64..96]), U256::from_be_slice(&out[96..128]))
    };
    assert_eq!(stake(&staker), (true, U256::from(10u64).pow(U256::from(17)), U256::from(86_400)));
    assert!(!stake(&factory).0);

    let with = chain.ok(&["account", "init-data", "--agent", &cfg]);
    assert!(field(&with, "initCode:").starts_with(&staker) && field(&with, "staker:") == staker, "{with}");

    // a deployments file without the staker: Kernel's factory by name, the same account
    let dep_path = chain.dir.join("deployments.json");
    let mut dep: Value = serde_json::from_str(&std::fs::read_to_string(&dep_path).unwrap()).unwrap();
    dep.as_object_mut().unwrap().remove("kernelFactoryStaker");
    std::fs::write(chain.dir.join("deployments-plain.json"), dep.to_string()).unwrap();
    let mut plain: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    plain["deployments"] = json!(chain.dir.join("deployments-plain.json"));
    let plain_cfg = chain.dir.join("agent-plain.json");
    std::fs::write(&plain_cfg, plain.to_string()).unwrap();
    let without = chain.ok(&["account", "init-data", "--agent", plain_cfg.to_str().unwrap()]);
    assert!(field(&without, "initCode:").starts_with(&factory) && !without.contains("staker:"), "{without}");
    assert_eq!(field(&with, "account:"), field(&without, "account:"));

    // the staker's owner withdraws the approval: the CLI says so and names the factory itself
    let revoke = [&alloy::primitives::keccak256("approveFactory(address,bool)")[..4], &(factory.parse::<Address>().unwrap(), false).abi_encode()[..]].concat();
    chain.send_from(FACILITATOR, Some(&staker), revoke);
    let fallen = chain.ok(&["account", "init-data", "--agent", &cfg]);
    assert!(fallen.contains("no longer approves") && field(&fallen, "initCode:").starts_with(&factory), "{fallen}");
    let approve = [&alloy::primitives::keccak256("approveFactory(address,bool)")[..4], &(factory.parse::<Address>().unwrap(), true).abi_encode()[..]].concat();
    chain.send_from(FACILITATOR, Some(&staker), approve);

    // created through the staker, the account is at that address and works
    assert_eq!(chain.deploy(&cfg).to_lowercase(), field(&with, "account:"));
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
    /// Hostile (issue #148): asks `preVerificationGas` 50M, the figure the
    /// review reproduced a 72-fold bill with.
    InflatedPreVerification,
    /// Hostile: publishes fees of 10^27 wei (10^18 gwei).
    Overpriced,
    /// Hostile: names a fee floor of 10^27 wei when it refuses.
    OverpricedFloor,
    /// Broken (issue #150): a gas limit wider than 128 bits.
    Oversized,
    /// Broken: includes the operation, then reports its gas used wider than
    /// 64 bits.
    OversizedReceipt,
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
                "pimlico_getUserOperationGasPrice" => {
                    // priced from the chain's base fee, as a bundler does
                    let base = u128::from_str_radix(
                        rpc("eth_getBlockByNumber", json!(["latest", false]))["result"]["baseFeePerGas"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    let tier = |priority: u128, max_fee: u128| {
                        json!({"maxFeePerGas": format!("{max_fee:#x}"), "maxPriorityFeePerGas": format!("{priority:#x}")})
                    };
                    let priority = base / 4 + 1;
                    match mode {
                        FakeBundler::FeeFloor | FakeBundler::OverpricedFloor => {
                            Err("unsupported method pimlico_getUserOperationGasPrice".into())
                        }
                        FakeBundler::Overpriced => Ok(json!({"standard": tier(10u128.pow(27), 10u128.pow(27))})),
                        _ => Ok(json!({
                            "slow": tier(priority, base + priority),
                            "standard": tier(priority, base * 3 / 2 + priority),
                            "fast": tier(priority * 2, base * 2 + priority * 2),
                        })),
                    }
                }
                "eth_estimateUserOperationGas" => {
                    // the client estimates with a placeholder of the real signature's
                    // length: 64 bytes on the root path, 65 under a permission
                    let sig_len = req["params"][0]["signature"].as_str().map(|s| (s.len() - 2) / 2).unwrap_or(0);
                    if sig_len != 64 && sig_len != 65 {
                        Err(format!("estimate expects a 64- or 65-byte placeholder signature, got {sig_len} bytes"))
                    } else {
                        // what the CLI sets for a deployed account and Pimlico's
                        // postOp answer for a paymaster without one
                        let mut est = json!({
                            "preVerificationGas": "0xc350", "verificationGasLimit": "0x493e0", "callGasLimit": "0x249f0",
                            "paymasterVerificationGasLimit": "0x186a0", "paymasterPostOpGasLimit": "0x1",
                        });
                        match mode {
                            FakeBundler::InflatedPreVerification => est["preVerificationGas"] = json!("0x2faf080"),
                            FakeBundler::Oversized => est["verificationGasLimit"] = json!("0x100000000000000000000000000000000"),
                            _ => {}
                        }
                        Ok(est)
                    }
                }
                "eth_sendUserOperation"
                    if matches!(mode, FakeBundler::FeeFloor | FakeBundler::OverpricedFloor) && !refused_once =>
                {
                    refused_once = true;
                    let current = req["params"][0]["maxPriorityFeePerGas"]
                        .as_str()
                        .map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                        .unwrap_or(0);
                    Err(format!(
                        "error code -32602: maxPriorityFeePerGas must be at least {} (current maxPriorityFeePerGas: {current}) - \
                         use pimlico_getUserOperationGasPrice to get the current gas price",
                        if mode == FakeBundler::FeeFloor { current + 1 } else { 10u128.pow(27) }
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
                                        "actualGasUsed": if mode == FakeBundler::OversizedReceipt {
                                            "0x10000000000000000".to_string()
                                        } else {
                                            format!("0x{}", hex::encode(&data[96..128]))
                                        },
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

/// A transaction can be included and still have done nothing: its gas
/// estimate passed and its execution reverted. (Seen on a fork of a chain
/// whose gas rules the node's estimate did not follow: a transfer that
/// creates an account was sent with the gas of a plain one.) The four
/// commands that send a transaction from the gas wallet say so, and do not
/// report it as done.
///
/// The stand-in for such a destination is code that reverts whenever a gas
/// price is paid: a node estimates at no price, and the transaction pays one.
#[test]
fn a_transaction_included_and_reverted_is_not_reported_as_done() {
    // GASPRICE ISZERO PUSH1 08 JUMPI PUSH0 PUSH0 REVERT JUMPDEST STOP
    const REVERTS_WHEN_PAID: &str = "0x3a156008575f5ffd5b00";
    let chain = chain_or_skip!("reverted");
    let (owner, agent) = (key(1), key(2));
    let paymaster = chain.with_paymaster();
    let cfg = chain.config("agent.json", &base_cfg(&owner, &agent, &chain.addr("demoCounter"), far_future(&chain)));
    let init = chain.ok(&["account", "init-data", "--agent", &cfg]);
    let account = init.lines().find_map(|l| l.strip_prefix("account:")).unwrap().trim().to_string();
    let balance = |who: &str| U256::from_str_radix(chain.rpc("eth_getBalance", json!([who, "latest"])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();

    // the stand-in does what it is here for: an estimate passes, the transaction reverts
    chain.rpc("anvil_setCode", json!([account, REVERTS_WHEN_PAID]));
    let estimate = chain.rpc("eth_estimateGas", json!([{"from": FACILITATOR, "to": account, "value": "0x1"}]));
    assert!(estimate.as_str().is_some(), "no estimate: {estimate}");

    let said = chain.fails(&["account", "fund", "--agent", &cfg, "--wei", "1000"]);
    assert!(said.contains("was included") && said.contains("reverted") && !said.contains("funded"), "{said}");
    assert!(balance(&account).is_zero(), "nothing arrived");

    chain.rpc("anvil_setCode", json!([paymaster, REVERTS_WHEN_PAID]));
    for args in [
        &["paymaster", "deposit", "--agent", &cfg, "--wei", "1000"][..],
        &["paymaster", "stake", "--agent", &cfg, "--wei", "1000"][..],
        &["paymaster", "sponsor", "--agent", &cfg, "--budget", "1000", "--max-per-op", "10"][..],
    ] {
        let said = chain.fails(args);
        assert!(said.contains("was included") && said.contains("reverted"), "{args:?}: {said}");
    }
    assert!(balance(&paymaster).is_zero(), "nothing arrived at the paymaster");
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

    // A hostile or broken bundler (issues #148, #150): a figure past the
    // CLI's bound is refused before anything is signed or sent, and a value
    // wider than 128 bits is an error, not a panic.
    for (mode, expected) in [
        (FakeBundler::InflatedPreVerification, "the bundler's preVerificationGas 50000000 is above"),
        (FakeBundler::Overpriced, "the bundler's maxPriorityFeePerGas"),
        (FakeBundler::OverpricedFloor, "the bundler's maxFeePerGas after its fee floor"),
        (FakeBundler::Oversized, "the bundler's verificationGasLimit 340282366920938463463374607431768211456 is above"),
    ] {
        let hostile = fake_bundler_with(chain.url.clone(), chain.addr("entryPoint"), mode);
        let said = chain.fails(&["demo", "--agent", &cfg, "--bundler", &hostile]);
        assert!(said.contains(expected) && said.contains("refusing to sign it"), "{said}");
        assert!(!said.contains("panicked") && !said.contains("bundler accepted"), "{said}");
    }
    assert_eq!(chain.counter(), before + U256::from(4));
    // a receipt it cannot have given: an error naming the transaction, not a panic
    let broken = fake_bundler_with(chain.url.clone(), chain.addr("entryPoint"), FakeBundler::OversizedReceipt);
    let said = chain.fails(&["demo", "--agent", &cfg, "--bundler", &broken]);
    assert!(said.contains("gives actualGasUsed 18446744073709551616, wider than 64 bits"), "{said}");
    assert!(!said.contains("panicked"), "{said}");
    assert_eq!(chain.counter(), before + U256::from(5));

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

    // #251, decision 2: the owner pauses the mandate's Safe judge. The agent's
    // Safe transactions are refused, its plain calls run, `permission show`
    // says what is paused
    let judge = chain.addr("safeShapes");
    let not_a_module = chain.fails(&["permission", "pause", "--agent", &cfg, "--module", &counter]);
    assert!(not_a_module.contains("none of the mandate's"), "{not_a_module}");
    chain.ok(&["permission", "pause", "--agent", &cfg, "--module", &judge]);
    chain.fails(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &once, "--safe-nonce", "2"]);
    assert_eq!(chain.counter(), before + U256::from(3));
    chain.ok(&["op", "send", "--agent", &cfg, "--target", &counter, "--data", INCREMENT]);
    assert_eq!(chain.counter(), before + U256::from(4));
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains("PAUSE module") && shown.to_lowercase().contains(&judge.to_lowercase()), "{shown}");

    // the owner names a guardian; the guardian's lift, from its own address,
    // leaves the owner's pause standing; the owner lifts it
    chain.ok(&["permission", "guardian", "--agent", &cfg, "--guardian", FACILITATOR]);
    let shown = chain.ok(&["permission", "show", "--agent", &cfg]);
    assert!(shown.contains(&format!("guardian        {FACILITATOR}")), "{shown}");
    let lift = pauseCall {
        account: account.parse().unwrap(),
        id: B256::right_padding_from(b"saf1"),
        module: judge.parse().unwrap(),
        paused: false,
    };
    chain.send_from(FACILITATOR, Some(&chain.addr("agentPolicy")), lift.abi_encode());
    assert!(chain.ok(&["permission", "show", "--agent", &cfg]).contains("PAUSE module"), "the guardian does not lift the owner's pause");
    chain.ok(&["permission", "pause", "--agent", &cfg, "--module", &judge, "--lift"]);
    chain.ok(&["op", "send", "--agent", &cfg, "--target", &safe, "--data", &once, "--safe-nonce", "2"]);
    assert_eq!(chain.counter(), before + U256::from(5));
    assert!(!chain.ok(&["permission", "show", "--agent", &cfg]).contains("PAUSE module"));

    // A rotation carries the guardian over to the new permission, in the same
    // operation, and a pause of a module the new mandate pins: the guardian
    // pauses the judge, the owner rotates. The pause carried over is the
    // owner's: the guardian cannot lift it, the owner can. The new config
    // writes the Safe's selector without `0x`, and its judge is pinned all the same
    chain.send_from(FACILITATOR, Some(&chain.addr("agentPolicy")), pauseCall { paused: true, ..lift }.abi_encode());
    let rotated = chain.config(
        "safe2.json",
        &Cfg {
            permission: "0x73616632", account: Some(account.clone()),
            allow: vec![(safe.clone(), "6a761202"), (counter.clone(), INCREMENT), (multisend.clone(), MULTISEND)],
            ..base_cfg(&owner, &agent, &counter, until)
        },
    );
    let said = chain.ok(&["permission", "rotate", "--agent", &rotated, "--old-id", "0x73616631"]);
    assert!(said.contains(&format!("guardian:       {FACILITATOR}, carried over")), "{said}");
    assert!(said.to_lowercase().contains(&format!("paused:         {}, carried over", judge.to_lowercase())), "{said}");
    let shown = chain.ok(&["permission", "show", "--agent", &rotated]);
    assert!(shown.contains(&format!("guardian        {FACILITATOR}")) && shown.contains("PAUSE module"), "{shown}");
    let third = exec(&account, &counter, increment.clone(), 0);
    chain.fails(&["op", "send", "--agent", &rotated, "--target", &safe, "--data", &third, "--safe-nonce", "3"]);
    let on_new = pauseCall { paused: false, id: B256::right_padding_from(b"saf2"), ..lift };
    chain.send_from(FACILITATOR, Some(&chain.addr("agentPolicy")), on_new.abi_encode());
    assert!(chain.ok(&["permission", "show", "--agent", &rotated]).contains("PAUSE module"), "the guardian does not lift the owner's pause");
    chain.ok(&["permission", "pause", "--agent", &rotated, "--module", &judge, "--lift"]);
    chain.ok(&["op", "send", "--agent", &rotated, "--target", &safe, "--data", &third, "--safe-nonce", "3"]);
    assert_eq!(chain.counter(), before + U256::from(6));
}

/// #251: the shape judge is pinned only where the policy takes judges, and a
/// judge the deployments file does not name refuses only what would install
/// the mandate. A pinned account's other commands run: an account set up on a
/// policy from before the division keeps working.
#[test]
fn the_judge_is_pinned_only_where_the_policy_takes_it() {
    let chain = chain_or_skip!("judge-pin");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let until = far_future(&chain);
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, until)));
    let safe = Address::repeat_byte(0x5a).to_string();
    let with_safe = |name: &str, pinned: bool, edit: &dyn Fn(&mut Value)| -> String {
        let cfg = chain.config(
            name,
            &Cfg {
                permission: "0x6a756431", account: pinned.then(|| account.clone()),
                allow: vec![(safe.clone(), SAFE_EXEC), (counter.clone(), INCREMENT)],
                ..base_cfg(&owner, &agent, &counter, until)
            },
        );
        let mut deployments: Value = serde_json::from_str(&std::fs::read_to_string(chain.dir.join("deployments.json")).unwrap()).unwrap();
        edit(&mut deployments);
        let file = chain.dir.join(format!("deployments-{name}"));
        std::fs::write(&file, deployments.to_string()).unwrap();
        let mut c: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
        c["deployments"] = json!(file);
        std::fs::write(&cfg, c.to_string()).unwrap();
        cfg
    };
    // a policy that takes judges, a deployments file that names none: the
    // pinned account's status and mandate read, its install is refused
    let no_judge = with_safe("no-judge.json", true, &|d| {
        d.as_object_mut().unwrap().remove("safeShapes");
    });
    chain.ok(&["account", "status", "--agent", &no_judge]);
    chain.ok(&["permission", "show", "--agent", &no_judge]);
    let refused = chain.fails(&["permission", "add", "--agent", &no_judge, "--dry-run"]);
    assert!(refused.contains("names no safeShapes"), "{refused}");
    // an account not yet created: its address follows from the mandate, refused at once
    let unpinned = with_safe("no-judge-new.json", false, &|d| {
        d.as_object_mut().unwrap().remove("safeShapes");
    });
    let refused = chain.fails(&["account", "status", "--agent", &unpinned]);
    assert!(refused.contains("names no safeShapes"), "{refused}");
    // a policy without guardians (the counter's code stands in for one from
    // before the division): no judge is wanted, and the session opens
    let older = with_safe("older.json", false, &|d| {
        let stand_in = d["demoCounter"].clone();
        d["agentPolicy"] = stand_in;
        d.as_object_mut().unwrap().remove("safeShapes");
    });
    chain.ok(&["account", "status", "--agent", &older]);
}

// ---------------------------------------------------------------- the phone's review against the policy's install

mod mandate_abi {
    alloy::sol! {
        function onInstall(bytes data) external;
        function configs(address account, bytes32 id) external view returns (uint48 validUntil, uint32 epoch, uint128 maxValuePerOp, uint128 budget, uint128 spent, uint48 validAfter);
        function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool);
        struct TokenLimit { uint128 maxPerOp; uint128 budget; uint128 spent; bool set; bool payeesOnly; bytes32 domainSeparator; }
        function tokenLimit(address account, bytes32 id, address token) external view returns (TokenLimit memory);
        function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool);
        function period(address account, bytes32 id) external view returns (uint32 seconds_, uint48 seen);
        function idAsset(address token, uint256 id) external pure returns (address);
    }
}

/// A small generator of its own, so a seed gives the same mandates everywhere.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
    fn pick<T: Copy>(&mut self, of: &[T]) -> T {
        of[self.below(of.len() as u64) as usize]
    }
}

/// What the owner is shown of a mandate and what `AgentPolicy` installs from
/// the same bytes are held together. Mandates come from a seed: mostly
/// well-formed and near what install must refuse (a limited token with a
/// function outside the four, a payee twice, Permit2, the account itself, a
/// number past its field, a function short of the targets, the payee form
/// with no list), with a share damaged byte by byte. Each one goes
/// to the phone's review, as an install of a permission in a root operation,
/// and to the policy on a local chain, installed by the account itself.
///
/// - Every mandate the review lets the owner sign and the policy installs is
///   the same mandate on both sides: the policy's own views give the allowed
///   calls, the two native limits, the window, each token's limits and x402
///   domain, and each payee list that `owner_core::review::mandate_terms`
///   read, and nothing else from the pools the generator draws on.
/// - The review shows no mandate the policy refuses to install: what the
///   owner signs for comes true. The review may refuse more than the policy
///   does (bytes the policy decodes although they are not the canonical
///   encoding); it never reads other terms.
///
/// The account is impersonated and calls the policy's `onInstall` itself;
/// Kernel's `installValidations` is not run here (the other tests of this
/// file run it).
///
/// `MANDATE_DIFFERENTIAL_CASES` sets the number of mandates (400 by default).
#[test]
fn the_phone_reads_a_mandate_as_the_policy_installs_it() {
    use mandate_abi::*;
    use owner_core::review::{mandate_terms, open_request_with_build_facts, EnrolledAccount, MandatePlace, Verdict};
    use owner_core::{kernel, request, user_op::PackedUserOp};

    let chain = chain_or_skip!("mandate-differential");
    let (owner, agent) = (key(1), key(2));
    let counter = chain.addr("demoCounter");
    let account = chain.deploy(&chain.config("agent.json", &base_cfg(&owner, &agent, &counter, far_future(&chain))));
    let acct: Address = account.parse().unwrap();
    let addr = |name: &str| -> Address { chain.addr(name).parse().unwrap() };
    let (policy, signer, entry) = (addr("agentPolicy"), addr("p256Signer"), addr("entryPoint"));
    chain.rpc("anvil_impersonateAccount", json!([account]));

    const NOW: u64 = 1_800_000_000;
    let tokens: [Address; 4] = [Address::repeat_byte(0xa1), Address::repeat_byte(0xa2), Address::repeat_byte(0xa3), Address::ZERO];
    let payee_pool: [Address; 4] = [Address::repeat_byte(0xb1), Address::repeat_byte(0xb2), Address::repeat_byte(0xb3), Address::ZERO];
    let permit2: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3".parse().unwrap();
    let targets: [Address; 11] = [
        addr("demoCounter"),
        tokens[0],
        tokens[1],
        tokens[2],
        Address::repeat_byte(0xc1),
        permit2,
        acct,
        entry,
        policy,
        Address::repeat_byte(0xd1),
        Address::repeat_byte(0xd2),
    ];
    // ERC-6909 contracts for limits per id (#186): two of their own, a token of the
    // other pool (a contract with both kinds of limit is refused), and zero
    let id_contracts: [Address; 4] = [targets[9], targets[10], tokens[0], Address::ZERO];
    let id_pool: [U256; 4] = [U256::ZERO, U256::from(7), U256::from(8), U256::MAX];
    let id_selectors: [[u8; 4]; 3] = [[0x09, 0x5b, 0xcd, 0xb6], [0xfe, 0x99, 0x04, 0x9a], [0x42, 0x6a, 0x84, 0x93]];
    let selectors: [[u8; 4]; 12] = [
        [0xd0, 0x9d, 0xe0, 0x8a], // increment()
        [0xa9, 0x05, 0x9c, 0xbb], // transfer
        [0x09, 0x5e, 0xa7, 0xb3], // approve
        [0x39, 0x50, 0x93, 0x51], // increaseAllowance
        [0x23, 0xb8, 0x72, 0xdd], // transferFrom
        [0xa2, 0x2c, 0xb4, 0x65], // setApprovalForAll
        [0, 0, 0, 0],
        alloy::primitives::keccak256("x402Authorize(address,address,address,uint256,uint256,uint256,bytes32)")[..4].try_into().unwrap(),
        alloy::primitives::keccak256("x402Reclaim(bytes32,address,address,uint256,uint256,uint256,bytes32)")[..4].try_into().unwrap(),
        id_selectors[0], // ERC-6909 transfer
        id_selectors[1], // ERC-6909 transferFrom
        id_selectors[2], // ERC-6909 approve
    ];
    let cases: u64 = std::env::var("MANDATE_DIFFERENTIAL_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(400);
    let mut rng = Seeded(0x6d61_6e64_6174_65); // "mandate"
    let mut ids_rng = Seeded(0x6964_6361_7073); // "idcaps"
    // the twelve-word form (#251), from a seed of its own: a Safe transaction
    // and perhaps a batch, with the shape judge, mostly well pinned
    let mut shapes_rng = Seeded(0x7368_6170_6573); // "shapes"
    let judge: Address = chain.addr("safeShapes").parse().unwrap();
    let judge_code = hex::decode(chain.rpc("eth_getCode", json!([judge.to_string(), "latest"])).as_str().unwrap().trim_start_matches("0x")).unwrap();
    let judge_hash = alloy::primitives::keccak256(&judge_code);
    let (safe_exec, multi_send) = (alloy::primitives::FixedBytes::<4>::from([0x6a, 0x76, 0x12, 0x02]), alloy::primitives::FixedBytes::<4>::from([0x8d, 0x80, 0xff, 0x0a]));
    let (mut both, mut chain_only, mut neither) = (0u64, 0u64, 0u64);
    // of those shown and installed: in the ten-, eleven- and twelve-word forms
    let (mut with_period, mut with_ids, mut with_shapes) = (0u64, 0u64, 0u64);

    for case in 0..cases {
        // ---- a mandate from the seed
        let amount = |rng: &mut Seeded| -> U256 {
            match rng.below(8) {
                0 => U256::ZERO,
                1 => U256::from(1),
                2 => U256::from(u128::MAX),
                3 if rng.one_in(3) => U256::from(u128::MAX) + U256::from(1), // past the field
                _ => U256::from(rng.next()),
            }
        };
        let n = 1 + rng.below(4) as usize;
        let mut allow: Vec<(Address, alloy::primitives::FixedBytes<4>)> = Vec::new();
        for _ in 0..n {
            // mostly a call that is fine, sometimes anything from the pools
            let (t, s) = if rng.one_in(4) { (rng.pick(&targets), rng.pick(&selectors)) } else { (rng.pick(&targets[..5]), rng.pick(&selectors[..5])) };
            allow.push((t, s.into()));
        }
        if rng.one_in(30) {
            allow.clear();
        }
        let mut caps: Vec<(Address, U256, U256, B256)> = Vec::new();
        for _ in 0..rng.below(3) {
            let token = if rng.one_in(25) { tokens[3] } else { rng.pick(&tokens[..3]) };
            let domain = if rng.one_in(2) { B256::ZERO } else { B256::from(U256::from(rng.next())) };
            caps.push((token, amount(&mut rng), amount(&mut rng), domain));
        }
        // a limited token is called through the four functions: steer most mandates that way
        if !rng.one_in(5) {
            for (t, s) in allow.iter_mut() {
                if caps.iter().any(|c| c.0 == *t) && !selectors[1..5].contains(&s.0) {
                    *s = selectors[1].into();
                }
            }
        }
        // and the four functions go to a token with a limit, which both sides require at
        // install (#175): steer most mandates that way too
        if !rng.one_in(5) {
            for (t, s) in allow.iter_mut() {
                if selectors[1..5].contains(&s.0) && !caps.iter().any(|c| c.0 == *t) {
                    match caps.first() {
                        Some(c) => *t = c.0,
                        None => *s = selectors[0].into(),
                    }
                }
            }
        }
        // Limits per id, in one mandate of three; then most of the time the three
        // functions go to a contract that has them and it lists nothing else,
        // which both sides require at install
        let mut ids: Vec<(Address, U256, U256, U256)> = Vec::new();
        if rng.one_in(3) {
            for _ in 0..1 + rng.below(3) {
                let token = if rng.one_in(30) { rng.pick(&id_contracts[2..]) } else { rng.pick(&id_contracts[..2]) };
                let id = rng.pick(&id_pool);
                if !ids.iter().any(|i| (i.0, i.1) == (token, id)) || rng.one_in(8) {
                    ids.push((token, id, amount(&mut rng), amount(&mut rng)));
                }
            }
            if rng.one_in(2) {
                if let Some(first) = ids.first() {
                    allow.push((first.0, rng.pick(&id_selectors).into()));
                }
            }
        }
        if !rng.one_in(12) {
            for (t, s) in allow.iter_mut() {
                let (has, metered) = (ids.iter().any(|i| i.0 == *t), id_selectors.contains(&s.0));
                match (has, metered) {
                    (true, false) => *s = id_selectors[0].into(),
                    (false, true) => match ids.first() {
                        Some(i) => *t = i.0,
                        None => *s = selectors[0].into(),
                    },
                    _ => {}
                }
            }
        }
        // A budget period, in the forms that carry one; and seldom a venue no build
        // knows and no chain has code for, which both sides refuse
        let period: u32 = match rng.below(12) {
            0 => 0,
            1 | 2 => 1,
            3 | 4 => u32::MAX,
            _ => 86_400,
        };
        let venues: Vec<(Address, B256, B256)> =
            if rng.one_in(20) { vec![(Address::repeat_byte(0xe1), B256::repeat_byte(1), B256::repeat_byte(2))] } else { vec![] };
        let mut lists: Vec<(Address, Vec<Address>)> = Vec::new();
        if rng.one_in(2) {
            for cap in &caps {
                if rng.one_in(2) {
                    let mut list: Vec<Address> = Vec::new();
                    for _ in 0..1 + rng.below(3) {
                        let p = if rng.one_in(12) { payee_pool[3] } else { rng.pick(&payee_pool[..3]) };
                        if !list.contains(&p) || rng.one_in(8) {
                            list.push(p);
                        }
                    }
                    lists.push((cap.0, list));
                }
            }
            if rng.one_in(15) {
                lists.push((tokens[2], vec![payee_pool[0]])); // perhaps a token without a limit, or a second list
            }
            if rng.one_in(20) {
                lists.push((rng.pick(&tokens[..3]), vec![]));
            }
        }
        let until = match rng.below(12) {
            0 => U256::ZERO,
            1 => U256::from(1u64 << 48), // past the field
            _ => U256::from(NOW + 3600 + rng.below(1 << 30)),
        };
        let after = match rng.below(10) {
            0 => until,
            1 => U256::from(NOW + rng.below(3600)),
            _ => U256::ZERO,
        };
        let (max_value, budget) = (amount(&mut rng), amount(&mut rng));
        // One mandate in six: a Safe's transaction, perhaps its batch, and the
        // twelve-word form with a judge; now and then the form without one, a
        // judge nobody knows, other code, the judge twice, or a shorter form
        let mut shapes: Option<Vec<(Address, B256)>> = None;
        if shapes_rng.one_in(6) {
            let rng = &mut shapes_rng;
            allow.push((Address::repeat_byte(0x5a), safe_exec));
            if rng.one_in(2) {
                allow.push((Address::repeat_byte(0x5b), multi_send));
            }
            shapes = match rng.below(10) {
                0 => Some(vec![]),
                1 => Some(vec![(Address::repeat_byte(0xe1), judge_hash)]),
                2 => Some(vec![(judge, B256::repeat_byte(0xe2))]),
                3 => Some(vec![(judge, judge_hash), (judge, judge_hash)]),
                4 => None,
                _ => Some(vec![(judge, judge_hash)]),
            };
        }
        let (ts, mut ss): (Vec<Address>, Vec<alloy::primitives::FixedBytes<4>>) = allow.iter().cloned().unzip();
        if rng.one_in(25) {
            ss.pop(); // a function short of the targets
        }
        let seven = (ts, ss, max_value, budget, until, caps.clone(), after);
        // The eleven-word form when there are limits per id (seldom without any, or
        // the limits dropped into a shorter form); the ten-word form one time in five
        let mut init = if let Some(sh) = &shapes {
            let (a, b, c, d, e, f, g) = seven;
            (a, b, c, d, e, f, g, lists.clone(), period, venues.clone(), ids.clone(), sh.clone()).abi_encode_params()
        } else if !ids.is_empty() && !rng.one_in(12) || rng.one_in(80) {
            let (a, b, c, d, e, f, g) = seven;
            (a, b, c, d, e, f, g, lists.clone(), period, venues.clone(), ids.clone()).abi_encode_params()
        } else if rng.one_in(5) {
            let (a, b, c, d, e, f, g) = seven;
            (a, b, c, d, e, f, g, lists.clone(), period, venues.clone()).abi_encode_params()
        } else if lists.is_empty() && !rng.one_in(12) {
            seven.abi_encode_params()
        } else {
            let (a, b, c, d, e, f, g) = seven;
            (a, b, c, d, e, f, g, lists.clone()).abi_encode_params()
        };
        // ---- damaged, one time in four
        if rng.one_in(4) {
            match rng.below(4) {
                0 => {
                    let i = rng.below(init.len() as u64) as usize;
                    init[i] ^= 1 << rng.below(8);
                }
                1 => init.truncate(init.len() - 1 - rng.below(31.min(init.len() as u64 - 1)) as usize),
                2 => init.extend_from_slice(&[0u8; 32]),
                _ => {
                    // a word's upper bits: a value the field does not hold, or an offset moved
                    let word = rng.below(init.len() as u64 / 32) as usize;
                    init[word * 32] ^= 0x80;
                }
            }
        }

        // ---- the eleven-word form's last word, which the policy reads by hand: one time
        // in six it is another array's offset, or the count of limits is one more or less.
        // From a seed of its own, so that the other mandates stay what they were.
        if init.len() >= 352 && init[..32] == U256::from(352).to_be_bytes::<32>() && ids_rng.one_in(6) {
            let rng = &mut ids_rng;
            match rng.below(3) {
                0 => {
                    let from = rng.pick(&[0usize, 1, 5, 7, 9]) * 32;
                    let word: [u8; 32] = init[from..from + 32].try_into().unwrap();
                    init[320..352].copy_from_slice(&word);
                }
                kind => {
                    let at = U256::from_be_slice(&init[320..352]);
                    if let Some(at) = usize::try_from(at).ok().filter(|at| *at + 32 <= init.len()) {
                        let count = U256::from_be_slice(&init[at..at + 32]);
                        let moved = if kind == 1 { count + U256::from(1) } else { count.saturating_sub(U256::from(1)) };
                        init[at..at + 32].copy_from_slice(&moved.to_be_bytes::<32>());
                    }
                }
            }
        }

        // ---- the phone: the review of a root operation that installs it
        let perm = alloy::primitives::FixedBytes::<4>::from((0x6d00_0000u32 + case as u32).to_be_bytes());
        let flag = alloy::primitives::FixedBytes::<2>::ZERO;
        let agent_key = (B256::from_slice(&hex::decode(&agent.x[2..]).unwrap()), B256::from_slice(&hex::decode(&agent.y[2..]).unwrap())).abi_encode();
        let entries: Vec<Bytes> = vec![
            (flag, policy, Bytes::from(init.clone())).abi_encode_packed().into(),
            (flag, signer, Bytes::from(agent_key)).abi_encode_packed().into(),
        ];
        let op = PackedUserOp {
            sender: acct,
            nonce: U256::from(case),
            init_code: Bytes::new(),
            // as `permission add` builds it: the install and the grant of `execute`, in one batch
            call_data: kernel::execute_batch_calldata(vec![
                (acct, U256::ZERO, kernel::install_permission_calldata(perm, entries.abi_encode().into(), 1)),
                (acct, U256::ZERO, kernel::grant_execute_calldata(perm)),
            ]),
            account_gas_limits: kernel::pack_gas(300_000, 150_000),
            pre_verification_gas: U256::from(60_000),
            gas_fees: kernel::pack_gas(1, 1),
            paymaster_and_data: Bytes::new(),
        };
        let bytes = request::SignRequest::new(&op, entry, 31337, NOW + 120, None, Default::default(), None).to_bytes();
        let review = open_request_with_build_facts(&bytes, &request::commitment(&bytes), NOW, &[EnrolledAccount::new(31337, entry, acct)]);
        let shown = !matches!(review.verdict, Verdict::Refuse(_));
        let place = MandatePlace {
            account: acct,
            entry_point: entry,
            policy,
            payees_enforced: true,
            trading_enforced: true,
            ids_enforced: true,
            shapes_enforced: true,
        };
        let terms = mandate_terms(&init, &place, &|a| a.to_string());
        // the review signs nothing whose mandate it could not read
        assert!(!shown || terms.is_ok(), "case {case}: signed without terms: {:?}", review.verdict);

        // ---- the chain: the account installs the same bytes
        let id = B256::right_padding_from(perm.as_slice());
        let data = onInstallCall { data: [id.as_slice(), &init[..]].concat().into() }.abi_encode();
        let tx = json!({"from": account, "to": policy, "data": Bytes::from(data).to_string(), "gas": "0x989680"});
        let hash = chain.rpc("eth_sendTransaction", json!([tx]));
        let started = Instant::now();
        let installed = loop {
            let r = chain.rpc("eth_getTransactionReceipt", json!([hash]));
            if !r.is_null() {
                break r["status"] == "0x1";
            }
            assert!(started.elapsed() < Duration::from_secs(10), "case {case}: no receipt");
            std::thread::sleep(Duration::from_millis(5));
        };

        match (shown, installed) {
            (false, false) => neither += 1,
            // Installed, and not shown. The one known reason: bytes the policy decodes
            // although they are not the one encoding of their values. Any other reason
            // is a review that refuses a mandate it should show.
            (false, true) => {
                chain_only += 1;
                assert!(
                    matches!(&review.verdict, Verdict::Refuse(why) if why.contains("not canonical")),
                    "case {case}: the review refuses a mandate the policy installs: {:?}",
                    review.verdict
                );
            }
            // Shown, and the install fails: nothing would be granted, but the owner would have
            // signed for a screen that did not come true. The review refuses whatever the
            // policy's install refuses, so there is no such mandate.
            (true, false) => panic!("case {case}: the review shows a mandate the policy refuses to install: {:?}", terms.unwrap()),
            (true, true) => {
                both += 1;
                let t = terms.unwrap();
                match init[31] {
                    0x40 => with_period += 1,
                    0x60 => with_ids += 1,
                    0x80 => with_shapes += 1,
                    _ => {}
                }
                let c = configsCall::abi_decode_returns(&chain.call(&chain.addr("agentPolicy"), configsCall { account: acct, id }.abi_encode())).unwrap();
                assert_eq!(
                    (U256::from(c.validUntil), U256::from(c.validAfter), U256::from(c.maxValuePerOp), U256::from(c.budget), c.spent),
                    (U256::from(t.valid_until), U256::from(t.valid_after), t.max_value, t.budget, 0),
                    "case {case}: the window and the native limits"
                );
                // The probes: the generator's pools, and whatever the review read in this
                // case, which damage may have moved outside them.
                let mut probe_targets = targets.to_vec();
                let mut probe_selectors = selectors.to_vec();
                for (a, s) in &t.allow {
                    if !probe_targets.contains(a) {
                        probe_targets.push(*a);
                    }
                    if !probe_selectors.contains(&s.0) {
                        probe_selectors.push(s.0);
                    }
                }
                // the period: the one the review read, or none
                let on = periodCall::abi_decode_returns(&chain.call(&chain.addr("agentPolicy"), periodCall { account: acct, id }.abi_encode())).unwrap();
                assert_eq!(on.seconds_, t.trading.as_ref().map_or(0, |p| p.0), "case {case}: the budget period");
                assert!(t.trading.as_ref().map_or(true, |p| p.1.is_empty()), "case {case}: a venue no chain has");
                // every id probed: limited exactly when the review lists it, and to that
                let mut probe_ids: Vec<(Address, U256)> = id_contracts[..3].iter().flat_map(|c| id_pool.iter().map(|i| (*c, *i))).collect();
                probe_ids.extend(t.ids.iter().map(|i| (i.0, i.1)).filter(|p| !id_contracts[..3].contains(&p.0) || !id_pool.contains(&p.1)));
                for (token, token_id) in probe_ids {
                    let key = Address::from_word(B256::from_slice(&chain.call(&chain.addr("agentPolicy"), idAssetCall { token, id: token_id }.abi_encode())));
                    let l = tokenLimitCall::abi_decode_returns(&chain.call(&chain.addr("agentPolicy"), tokenLimitCall { account: acct, id, token: key }.abi_encode())).unwrap();
                    match t.ids.iter().find(|i| (i.0, i.1) == (token, token_id)) {
                        Some(i) => assert_eq!(
                            (l.set, U256::from(l.maxPerOp), U256::from(l.budget), l.spent, l.payeesOnly, l.domainSeparator),
                            (true, i.2, i.3, 0, false, B256::ZERO),
                            "case {case}: the limits of {token} id {token_id}"
                        ),
                        None => assert!(!l.set, "case {case}: {token} id {token_id} has a limit the review did not read"),
                    }
                }
                let mut probe_tokens = tokens[..3].to_vec();
                probe_tokens.extend(t.tokens.iter().map(|c| c.0).filter(|a| !tokens.contains(a)));
                let mut probe_payees = payee_pool[..3].to_vec();
                for p in t.payees.iter().flat_map(|l| &l.1) {
                    if !probe_payees.contains(p) {
                        probe_payees.push(*p);
                    }
                }
                // every call probed: allowed exactly when the review lists it
                for target in probe_targets {
                    for selector in probe_selectors.iter().copied() {
                        let call = isAllowedCall { account: acct, id, target, selector: selector.into() };
                        let on_chain = U256::from_be_slice(&chain.call(&chain.addr("agentPolicy"), call.abi_encode())) == U256::from(1);
                        assert_eq!(on_chain, t.allow.contains(&(target, selector.into())), "case {case}: {target} {selector:02x?}");
                    }
                }
                for token in &probe_tokens {
                    let raw = chain.call(&chain.addr("agentPolicy"), tokenLimitCall { account: acct, id, token: *token }.abi_encode());
                    let l = tokenLimitCall::abi_decode_returns(&raw).unwrap();
                    let cap = t.tokens.iter().find(|c| c.0 == *token);
                    assert_eq!(l.set, cap.is_some(), "case {case}: whether {token} is limited");
                    let list = t.payees.iter().find(|p| p.0 == *token);
                    if let Some(cap) = cap {
                        assert_eq!((U256::from(l.maxPerOp), U256::from(l.budget), l.domainSeparator, l.spent), (cap.1, cap.2, cap.3, 0), "case {case}: the limits of {token}");
                        assert_eq!(l.payeesOnly, list.is_some(), "case {case}: whether {token} has a payee list");
                    }
                    for payee in &probe_payees {
                        let call = payeeAllowedCall { account: acct, id, token: *token, payee: *payee };
                        let on_chain = U256::from_be_slice(&chain.call(&chain.addr("agentPolicy"), call.abi_encode())) == U256::from(1);
                        // without a list a token may reach anyone; with one, the listed and no other
                        assert_eq!(on_chain, list.map_or(true, |l| l.1.contains(payee)), "case {case}: {token} to {payee}");
                    }
                }
            }
        }
    }
    eprintln!(
        "mandates: {cases}; shown and installed {both} ({with_period} with a period, {with_ids} with limits per id, {with_shapes} with a shape judge), installed and not shown {chain_only}, neither {neither}"
    );
    // the twelve-word form is shown and installed too, once there are cases enough
    assert!(cases < 200 || with_shapes > 0, "no mandate with a shape judge was shown and installed");
    // the generator reaches each side's yes and no, and the one-way difference between them
    assert!(both * 7 >= cases && neither * 5 >= cases && chain_only * 100 >= cases, "the generator has drifted: {both} / {chain_only} / {neither}");
}
