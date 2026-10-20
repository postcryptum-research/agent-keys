# Building and testing on a Mac (Secure Enclave)

> **Status (2026-10-20): not yet run on a Mac.** The backend was rewritten
> on CryptoKit (see "How the key is kept"); the Rust side type-checks for
> `aarch64-apple-darwin`, the Swift shim compiles only on a Mac. This
> procedure is the first real run.

> **Кратко по-русски.** Нужен Mac с Secure Enclave (любой Apple Silicon или
> Intel с чипом T2). Всё бесплатно: Xcode Command Line Tools (компилятор,
> Swift, git) и Rust (`rustup`); ни Homebrew, ни CMake, ни аккаунта Apple
> Developer не нужно. Весь сеанс пишется в файл командой `script`, его и
> присылаем. Собираем `agent-signer` с фичей `secure-enclave`, запускаем
> тест на железе, создаём ключ в enclave, подписываем вектор и проверяем
> его. Приватный ключ из enclave не извлекается. 20–30 минут, бо́льшая часть
> — компиляция.

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
