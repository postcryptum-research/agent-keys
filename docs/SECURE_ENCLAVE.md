# Building and testing on a Mac (Secure Enclave backend)

> **Кратко по-русски.** Нужен Mac с Secure Enclave (любой Apple Silicon или
> Intel с чипом T2). Ставим Xcode Command Line Tools и Rust, клонируем репо
> с submodule'ами, собираем `agent-signer` с фичей `secure-enclave`,
> подписываем бинарь ad-hoc (`codesign -s -`), запускаем тест, создаём ключ
> в enclave и присылаем вывод команд из раздела «What to send back».
> Приватный ключ из enclave не извлекается — в выводе только публичные
> координаты. Ожидаемое время: 20–30 минут, бо́льшая часть — компиляция.

## What you are testing

`signer/crates/hw-signer/src/secure_enclave.rs` is a backend that keeps a
P-256 key inside the Apple Secure Enclave and signs digests with it. It was
written on Linux and type-checked for `aarch64-apple-darwin`, but it has
never run on Apple hardware. The goal is to find out whether it builds,
whether the enclave accepts the key template, and whether a signature it
produces verifies — the same checks the TPM backend already passes.

Nothing here touches real funds. Steps 1–7 need no network except for
downloading tools and crates.

## 1. Requirements

- A Mac with a Secure Enclave: **any Apple Silicon Mac (M1 or later)**, or an
  Intel Mac **with a T2 chip** (2018 or later MacBook Pro/Air, Mac mini,
  iMac Pro, Mac Pro). Virtual machines and Rosetta do not expose the enclave.
- macOS 13 (Ventura) or newer.
- An administrator account (for installing the command line tools).
- About 3 GB of free disk space and an internet connection.

Check the chip: `` → About This Mac → "Chip" (Apple M-series) or
"Processor" (Intel; then System Information → Controller → "Apple T2").

## 2. Install the tools

### Xcode Command Line Tools (compiler, linker, git, frameworks)

```sh
xcode-select --install
```

A dialog appears; accept and wait. Verify:

```sh
xcode-select -p          # /Library/Developer/CommandLineTools (or an Xcode path)
clang --version          # Apple clang version ...
git --version
```

### Rust

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Choose the default installation (option 1). Then open a **new** terminal
window, or run `source "$HOME/.cargo/env"`, and verify:

```sh
rustc --version          # rustc 1.85 or newer (the project is developed on 1.95)
cargo --version
```

### CMake (needed by one dependency)

The TLS library behind the Ethereum client (`aws-lc-sys`) builds C code with
CMake. If you have Homebrew:

```sh
brew install cmake
```

Without Homebrew: install Homebrew first from https://brew.sh, or download
CMake from https://cmake.org/download/ and make sure `cmake --version` works
in the terminal.

### Foundry (optional — only for the Solidity tests in step 8)

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
```

## 3. Get the code

```sh
git clone --recursive https://github.com/77ph/TPM_sign.git
cd TPM_sign
```

`--recursive` matters: the contracts depend on git submodules. If you
cloned without it, run `git submodule update --init --recursive`. Verify:

```sh
ls contracts/lib/kernel/src/Kernel.sol      # must exist
```

## 4. Sanity build (no hardware involved)

```sh
cd signer
cargo build -p agent-signer
cargo test
```

Expected at the end: `test result: ok. 1 passed` (the software-key
round-trip). This proves the toolchain works before the enclave is involved.
The first build compiles a few hundred crates and can take 5–10 minutes.

## 5. Build with the Secure Enclave backend

```sh
cargo build -p agent-signer --features secure-enclave
cargo test  -p hw-signer    --features secure-enclave --no-run
```

Expected: both end with `Finished`. **If either fails, stop here and send
the complete error output** — a compile error is the most valuable result
this procedure can produce, since it means the `security-framework` crate's
API differs from what the code assumes.

The second command prints the path of the test executable, like
`Executable unittests src/lib.rs (target/debug/deps/hw_signer-1a2b3c...)`.
Keep that path; it is needed in step 6.

## 6. Code-sign the binaries

The Secure Enclave only serves processes with a valid code signature. An
ad-hoc signature (no Apple developer account needed) is enough for local
use:

```sh
codesign -s - --force target/debug/agent-signer
codesign -s - --force target/debug/deps/hw_signer-XXXX      # the path from step 5
codesign -dv target/debug/agent-signer 2>&1 | grep Signature   # Signature=adhoc
```

Note: every `cargo build`/`cargo test` that recompiles a binary drops the
signature. If a later step reports a keychain or entitlement error, re-run
the `codesign` command for that binary.

## 7. Run the hardware test

Run the **signed test executable directly** (running it through `cargo
test` may rebuild and unsign it):

```sh
target/debug/deps/hw_signer-XXXX --ignored
```

Expected:

```
running 1 test
test secure_enclave::tests::enclave_key_signs_and_verifies ... ok
```

macOS may show a keychain prompt the first time ("agent-signer wants to use
your confidential information…" or similar) — click **Always Allow**. The
test creates a key labelled `tpm_sign-test-<pid>`, signs a digest, verifies
the signature off-chain, reopens the key by label, and deletes it.

If it fails, send the complete output, including any `-34018`, `-25291`,
`-25300`, `-25293` codes (see Troubleshooting).

## 8. Create a key and a signature vector

```sh
B=target/debug/agent-signer
$B key create --enclave tpm_sign-demo
$B key show   --enclave tpm_sign-demo
$B vector --backend enclave --label tpm_sign-demo \
   --message "TPM_sign: digest signed inside an Apple Secure Enclave" \
   > ../contracts/test/vectors/p256_enclave.json
cat ../contracts/test/vectors/p256_enclave.json
$B verify --file ../contracts/test/vectors/p256_enclave.json      # OK
```

`key create` prints the public key (`x`, `y`); the private key stays in the
enclave. The vector file is what we will commit next to the TPM-signed one:
it lets the Solidity tests verify a real enclave signature on every CI run.

If Foundry is installed, you can verify it on-chain-style locally right now:

```sh
cd ../contracts
cp test/vectors/p256_enclave.json test/vectors/p256_tpm.json   # temporary: reuse the TPM test slot
forge test --match-test test_tpmVector
git checkout test/vectors/p256_tpm.json                          # restore
```

Expected: `[PASS] test_tpmVector()`.

## 9. Optional: an agent account on Base Sepolia

The smart account cannot tell a Secure Enclave key from a TPM key. With a
funded gas wallet and an RPC URL in a `.env` (ask the project owner; never
commit it) and an agent config like `signer/agent.base-sepolia.json` with

```json
"owner": { "secure-enclave": "tpm_sign-owner" },
"agent": { "secure-enclave": "tpm_sign-agent" },
```

the full flow is the one in the README: `account status` → `account fund`
→ `demo`. This is a nice-to-have; steps 1–8 are the deliverable.

## 10. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `xcrun: error: invalid active developer path` | Command Line Tools missing | step 2 |
| `ld: framework not found Security` | Command Line Tools incomplete | `xcode-select --install` again, or `sudo xcode-select --reset` |
| `cmake: command not found` / `aws-lc-sys` build error | CMake missing | `brew install cmake` |
| `error[E0433]` / `no method named ...` inside `secure_enclave.rs` | `security-framework` API drift | send the full error; this is the expected kind of finding |
| `errSecMissingEntitlement` (`-34018`) | binary not code-signed | step 6; if it persists, the machine may require signing with a Developer ID certificate — say so |
| `errSecNotAvailable` (`-25291`) / "Secure Enclave is not available" | no enclave (Intel without T2, VM, Rosetta) | run on a different Mac; check `arch` prints `arm64` |
| `errSecItemNotFound` (`-25300`) on `key show` | label mismatch or key not created | `key create` first; labels are case-sensitive |
| `errSecInteractionNotAllowed` (`-25308`) | screen locked / no GUI session | run from a logged-in Terminal session |
| Repeated keychain prompts | "Allow" instead of "Always Allow" | choose Always Allow |
| `cargo test ... --ignored` fails but the signed binary passes | cargo rebuilt and unsigned the binary | run the signed executable directly (step 7) |

## 11. What to send back

1. macOS version and chip (e.g. "macOS 15.1, M2" or "macOS 14, Intel + T2").
2. `rustc --version`.
3. Step 5 output: the last 10 lines of each command (or the full error).
4. Step 7 output: the test line and anything printed around it.
5. Step 8: the `key show` JSON and the `p256_enclave.json` file.
6. Any keychain dialog you saw (a screenshot is fine).

## 12. Cleanup

```sh
$B key evict --enclave tpm_sign-demo
```

removes the demo key from the keychain and the enclave. The test key from
step 7 deletes itself.
