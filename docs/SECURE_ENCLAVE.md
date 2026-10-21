# Building and testing on a Mac (Secure Enclave)

> **Status (2026-10-21): runs on a Mac.** First run on an Apple M1
> (macOS 27.0, Swift 6.3.2, rustc 1.94): every step below passed without a
> change to the code, the enclave's signature is `p256_enclave.json` in the
> Solidity tests, and an account whose owner and agent keys both live in the
> enclave ran on Base Sepolia — the outputs are in [Run record](#12-run-record-2026-10-21-apple-m1)
> at the end. The procedure stays as the guide for the next machine.

## What you are testing

`signer/crates/hw-signer/src/secure_enclave.rs` keeps a P-256 key inside
the Apple Secure Enclave and signs digests with it, through a small Swift
shim (`signer/crates/hw-signer/swift/SecureEnclaveShim.swift`) that
`build.rs` compiles with `swiftc`. The goal: does it build, does the
enclave create and reopen the key, and does its signature verify — the
checks the Linux TPM, Windows TPM and TROPIC01 backends already pass.

Nothing here touches real funds. Steps 1–7 need the network only to
download tools and crates.

### How the key is kept

The enclave generates the key (CryptoKit
`SecureEnclave.P256.Signing.PrivateKey`) and signs inside. What the host
stores is CryptoKit's `dataRepresentation`: an opaque blob that **only
this Mac's Secure Enclave can unwrap**, in
`~/Library/Application Support/tpm_sign/enclave/<label>.se` (mode 0600).
Copied to another machine it is useless; deleted, the key is gone.

Why not a keychain item: a Secure Enclave key can only be stored in the
data-protection keychain, which requires keychain-access entitlements that
an ad-hoc signed command-line tool cannot have. The CryptoKit blob needs
no entitlements, no code-signing identity and no Apple developer account.

## 1. Requirements

- A Mac with a Secure Enclave: **any Apple Silicon Mac (M1 or later)**, or
  an Intel Mac **with a T2 chip** (2018+ MacBook Pro/Air, Mac mini, iMac
  Pro, Mac Pro). Virtual machines do not expose the enclave.
- macOS 13 (Ventura) or newer.
- An administrator account (for installing the command line tools).
- About 3 GB of free disk space.

## 2. Install the tools (all free) and start the log

### Xcode Command Line Tools (compiler, Swift, git, SDK)

```sh
xcode-select --install
```

A dialog appears; accept and wait. The full Xcode app is not needed.

### Rust

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Choose the default installation (option 1), then open a **new** Terminal
window.

No Homebrew, CMake or NASM: the one C library in the dependency tree builds
with the Command Line Tools' clang.

### Start recording, then print the environment

Everything from here on goes into one file — that file is what you send
back:

```sh
script -q ~/tpm_sign-mac.log
```

(`script` starts a recorded shell; `exit` at the end stops it.) Then:

```sh
sw_vers                                      # macOS version
uname -m                                     # arm64 = Apple Silicon
sysctl -n machdep.cpu.brand_string           # chip
system_profiler SPiBridgeDataType | grep -i model   # Intel only: "Apple T2"
xcode-select -p
xcrun swiftc --version
rustc --version                              # 1.85 or newer
cargo --version
git --version
```

## 3. Get the code

```sh
cd ~
git clone --recursive https://github.com/77ph/TPM_sign.git
cd TPM_sign/signer
```

If the folder already exists from an earlier attempt:
`cd ~/TPM_sign && git pull && git submodule update --init --recursive && cd signer`.

## 4. Sanity build (no hardware)

```sh
cargo build -p agent-signer
cargo test
```

Expected at the end: `test result: ok. 1 passed`. The first build compiles
a few hundred crates (5–10 minutes).

## 5. Build with the Secure Enclave backend

```sh
cargo build -p agent-signer --features secure-enclave
cargo test  -p hw-signer    --features secure-enclave --no-run
```

Expected: both end with `Finished`. **If either fails, stop and send the
log** — a Swift compile or link error here is the most useful outcome of
this procedure.

## 6. Hardware test

```sh
cargo test -p hw-signer --features secure-enclave -- --ignored
```

Expected: `secure_enclave::tests::enclave_key_signs_and_verifies ... ok`.
The test creates a key labelled `tpm_sign-test-<pid>`, signs a digest,
verifies the signature, reopens the key from its stored blob and signs
again, checks that a second key with the same label is refused, and deletes
it. No dialog should appear (the key needs no Touch ID or password).

## 7. Create a key and a signature vector

Copy the commands as they are:

```sh
B=target/debug/agent-signer
$B key create --enclave tpm_sign-demo
$B key show   --enclave tpm_sign-demo
$B vector --backend enclave --label tpm_sign-demo \
   --message "TPM_sign: digest signed inside an Apple Secure Enclave" \
   > ../contracts/test/vectors/p256_enclave.json
cat ../contracts/test/vectors/p256_enclave.json
$B verify --file ../contracts/test/vectors/p256_enclave.json     # prints OK
```

`key create` prints the public key; the private key stays in the enclave.
`key show` must print the same `x`, `y` — it reopens the key from the
stored blob. The vector file is what we commit next to the TPM-signed ones,
so the Solidity tests verify a real enclave signature on every run.

If `key create` says the label already exists (from an earlier run), skip
it and continue with `key show`.

## 8. Optional: an agent account on Base Sepolia

The smart account cannot tell a Secure Enclave key from a TPM key. With a
funded gas wallet and an RPC URL in a `.env` (ask the project owner; never
commit it) and an agent config with

```json
"owner": { "secure-enclave": "tpm_sign-owner" },
"agent": { "secure-enclave": "tpm_sign-agent" },
```

the flow is the one in the README: `account status` → `account fund` →
`demo`. Steps 1–7 are the deliverable; this is a nice-to-have.
`signer/agent.enclave.base-sepolia.json` is the config of the account that
ran in the run record below (its keys exist in one M1's enclave only, so on
another Mac it serves as a template: replace both public keys and drop
`account`).

## 9. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `xcrun: error: invalid active developer path` | Command Line Tools missing | step 2 |
| `cannot run xcrun swiftc` in the `hw-signer` build script | Command Line Tools missing or broken | `xcode-select --install`, or `sudo xcode-select --reset` |
| `swiftc failed to compile` | Swift / SDK older than the shim assumes | send the log (the Swift error is in it); `xcrun swiftc --version` is in step 2 |
| `ld: library not found for -lswift…` / `Undefined symbols … swift` | Swift runtime libraries not found by the linker | send the log |
| `no Secure Enclave on this Mac` | Intel without T2, or a virtual machine | run on another Mac; `uname -m` should print `arm64` |
| `open: …` on `key show` / `vector` | the blob is not from this Mac's enclave (copied, or the Mac was reset) | `key create` a new key |
| `a key labelled … already exists` | an earlier run left the key | skip `key create`, or `key evict --enclave <label>` first |
| `verify` prints `INVALID` | wrong file or a mangled copy | rerun step 7 and send the log |

## 10. What to report back

After step 11 (cleanup), stop recording and send the file:

```sh
exit        # ends `script`; the log is ~/tpm_sign-mac.log
```

It must contain, in order:

1. the environment block from step 2 (macOS, chip, Swift, `rustc`);
2. step 4 — `test result: ok. 1 passed`;
3. step 5 — both commands ending in `Finished` (or the full error);
4. step 6 — `enclave_key_signs_and_verifies ... ok`;
5. step 7 — `key create` and `key show` with the same `x`, `y`, the
   `p256_enclave.json` content, and `verify` printing `OK`;
6. step 11 — `deleted tpm_sign-demo`.

## 11. Cleanup

```sh
$B key evict --enclave tpm_sign-demo
```

deletes the demo key's blob, which destroys the key. The test key from
step 6 deletes itself.

## 12. Run record (2026-10-21, Apple M1)

The first run, on the procedure above, unchanged. Everything below is
pasted from the terminal; cargo warnings and compile progress are cut.

Deviations from the text: the machine's default `stable` Rust was 1.81, so
each cargo command used an installed newer toolchain (`cargo +1.94 …`);
nothing else differed.

### Environment (step 2)

```
ProductName:		macOS
ProductVersion:		27.0
BuildVersion:		26A428
arm64
Apple M1
/Library/Developer/CommandLineTools
swift-driver version: 1.148.6 Apple Swift version 6.3.2 (swiftlang-6.3.2.1.108 clang-2100.1.1.101)
Target: arm64-apple-macosx28.0
cargo 1.94.1 (29ea6fb6a 2026-03-24)
git version 2.50.1 (Apple Git-155)
```

### Sanity build (step 4)

```
$ cargo +1.94 build -p agent-signer
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 21s
$ cargo +1.94 test
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.91s
     Running unittests src/lib.rs (target/debug/deps/hw_signer-072649565deba88d)
test tests::software_roundtrip_rejects_tamper_and_is_low_s ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

(The agent-signer crate has grown to 9 unit tests since the "1 passed"
in step 4 was written.)

### Secure Enclave build (step 5)

```
$ cargo +1.94 build -p agent-signer --features secure-enclave
   Compiling hw-signer v0.1.0 (…/signer/crates/hw-signer)
   Compiling agent-signer v0.1.0 (…/signer/crates/agent-signer)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 43.88s
$ cargo +1.94 test -p hw-signer --features secure-enclave --no-run
    Finished `test` profile [unoptimized + debuginfo] target(s) in 4.24s
  Executable unittests src/lib.rs (target/debug/deps/hw_signer-2612eb9050ec1d66)
```

The Swift shim compiled and linked with Swift 6.3.2 as written.

### Hardware test (step 6)

```
$ cargo +1.94 test -p hw-signer --features secure-enclave -- --ignored
running 1 test
test secure_enclave::tests::enclave_key_signs_and_verifies ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.08s
```

No dialog appeared.

### Key and vector (step 7)

```
$ $B key create --enclave tpm_sign-demo
{
  "key": "tpm_sign-demo",
  "x": "0x37b8e8aa2ca3bef1522e1b27d16c23454b3beae195562f67ac631952d95c2cd9",
  "y": "0x3cc90d6478511e3007b6d28870ba854d9490ddf209a1ca8b455760ef17b177d3"
}
$ $B key show --enclave tpm_sign-demo
{
  "key": "tpm_sign-demo",
  "x": "0x37b8e8aa2ca3bef1522e1b27d16c23454b3beae195562f67ac631952d95c2cd9",
  "y": "0x3cc90d6478511e3007b6d28870ba854d9490ddf209a1ca8b455760ef17b177d3"
}
$ $B vector --backend enclave --label tpm_sign-demo --message "TPM_sign: digest signed inside an Apple Secure Enclave" > ../contracts/test/vectors/p256_enclave.json
$ cat ../contracts/test/vectors/p256_enclave.json
{
  "backend": "enclave",
  "message": "TPM_sign: digest signed inside an Apple Secure Enclave",
  "digest": "0x6a046a0b54dbdb914760fa8beef4d775678d1f311f5d2869d69759384d3521f7",
  "r": "0x3baf3024f45d6cde9814747e8e29e8bd3820ab4e825b7d605f6e9d616d405495",
  "s": "0x1d64082c14b385f8ec170c7f3dd1bcdbc9d1ce94c9e70a19f07641819fadd8e3",
  "x": "0x37b8e8aa2ca3bef1522e1b27d16c23454b3beae195562f67ac631952d95c2cd9",
  "y": "0x3cc90d6478511e3007b6d28870ba854d9490ddf209a1ca8b455760ef17b177d3"
}
$ $B verify --file ../contracts/test/vectors/p256_enclave.json
OK
```

The file is committed; `P256Vector.t.sol` picks it up with the others.
With forge 1.8.x (`odyssey` is no longer a known option there, so the
precompile must come from the Osaka EVM):

```
$ cd ../contracts && forge test --evm-version osaka --match-contract P256Vector
[PASS] test_everyCommittedVector() (gas: 220177)
[PASS] test_precompileAvailable() (gas: 7482)
[PASS] test_softwareVector() (gas: 40323)
[PASS] test_tpmVector() (gas: 40310)
Suite result: ok. 4 passed; 0 failed; 0 skipped
```

### Base Sepolia (step 8)

Two more enclave keys, `tpm_sign-owner` and `tpm_sign-agent`, and the
config `signer/agent.enclave.base-sepolia.json` (permission `0x73653031`,
mandate: the demo counter's `increment()` only, no value, budget 0.001 ETH).
The gas wallet is an ordinary funded EOA from a `.env` outside the
repository.

```
$ $B account status --agent agent.enclave.base-sepolia.json --env-file …
account:        0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628 (derived from keys + mandate)
deployed:       false
$ $B account fund --agent … --wei 2000000000000000
funded 0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628 with 2000000000000000 wei: tx 0x096fd63cc1c0daffe855d3c8c7ccc05f549a41cfbff5444ca5d13aa32b9fdc6b
$ $B demo --agent … --env-file …
path:           permission (agent key)
gas paid by:    the account
userOpHash:     0x0893b341617b0b849fd55a683d8095ae544e0d7fcba92564405cf3b798f84cfc
delivery:       self-bundled via handleOps
included: tx 0xc431bafe3588431c82b96aac7318c3c4340e16be784322bba5d801f3a401300c (block 48414001, 664572 gas)
counter:  26 -> 27
```

The first operation deployed the account and the agent key, inside the
enclave, signed the counter increment
([tx](https://sepolia.basescan.org/tx/0xc431bafe3588431c82b96aac7318c3c4340e16be784322bba5d801f3a401300c),
[account](https://sepolia.basescan.org/address/0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628)).
Then, with the account deployed:

```
$ $B op send --agent … --target 0x000000000000000000000000000000000000dEaD --wei 1
path:           permission (agent key)
Error: EntryPoint rejected the operation: AA23 reverted (op 0), inner revert 0x3e4983f6…0000
```

1 wei to an outsider is refused in simulation — `PolicyFailed(0)`,
`AgentPolicy` rejecting a target outside the allow-list — and no gas is
spent.

```
$ $B op send --agent … --root --target 0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1 --data 0xd09de08a
path:           root (owner key)
userOpHash:     0x406b55a0639b77edf55d56c91d5feaffdda9c813b8e310a156652feaf7024ddd
included: tx 0x547e4fa8caf1b5725f9043ece7df13f3e713c98107f1b1726ac24139674da40c (block 48414016, 144077 gas)
```

The owner key, also inside the enclave, signed a root operation
([tx](https://sepolia.basescan.org/tx/0x547e4fa8caf1b5725f9043ece7df13f3e713c98107f1b1726ac24139674da40c)).
`permission show` reports every field of the on-chain permission `ok`
against the config.

### Cleanup (step 11)

```
$ $B key evict --enclave tpm_sign-demo
deleted tpm_sign-demo
```

The owner and agent keys of the Base Sepolia account stay in that Mac's
enclave.
