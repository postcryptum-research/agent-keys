# Building and testing on Windows (TPM through CNG)

> **Status (2026-10-20): verified on a Windows 11 PC.** Build without NASM or
> CMake, the hardware test `cng_key_signs_and_verifies`, `key create/show
> --cng`, and a signed vector — `contracts/test/vectors/p256_windows.json`,
> checked off-chain and by the Solidity tests (RIP-7212 path).

> **Кратко по-русски.** Нужен ПК с Windows 10/11 и включённым TPM 2.0 (у
> Windows 11 он обязателен). Всё ПО бесплатное: Rust (`rustup`), Git,
> Visual Studio Build Tools (только компилятор/линкер, без самой Visual
> Studio). CMake и NASM **не нужны**: C-библиотека AWS-LC собирается
> компилятором MSVC, а ассемблерные объекты берутся готовыми. Собираем `agent-signer` с фичей
> `windows-tpm`, запускаем тест, создаём ключ в TPM командой `key create
> --cng`, присылаем вывод из раздела «What to report back». Приватный ключ
> из TPM не извлекается.

## What you are testing

`signer/crates/hw-signer/src/windows_tpm.rs` keeps a P-256 key inside the
TPM through CNG's **Microsoft Platform Crypto Provider** — the key store
every Windows 11 machine has — and signs digests with it. It was written on
Linux and type-checked for `x86_64-pc-windows-msvc`, but has never run on
Windows. The goal is to learn whether it builds, whether the provider
accepts the key template, and whether its signatures verify.

Nothing here touches real funds. Steps 1–6 need the network only to
download tools and crates.

## 1. Requirements

- Windows 10 (21H2 or newer) or Windows 11, 64-bit.
- A TPM 2.0 that is **enabled**. Check: press Win+R, run `tpm.msc`; it must
  say "The TPM is ready for use" and "Specification Version: 2.0". If it
  says the TPM cannot be found, enable it in the firmware setup (often
  called "PTT" on Intel or "fTPM" on AMD).
- About 4 GB of free disk space, administrator rights for the installers.

No paid software is involved at any step.

## 2. Install the tools (all free)

Open **PowerShell** (not as administrator unless an installer asks).

### Git

```powershell
winget install --id Git.Git -e
```

No CMake and no NASM: one Rust dependency (`aws-lc-sys`, the TLS crypto
under the HTTP client) compiles a C library, but on Windows x86_64 it does
so with the MSVC compiler installed below, and the project enables its
prebuilt assembly objects, so NASM is not needed. If you installed them
already, they do no harm.

### Rust and the C++ build tools

Download and run <https://win.rustup.rs/x86_64> (`rustup-init.exe`).

It detects that the Visual Studio C++ build tools are missing and offers to
install them — accept ("Quick install"). This installs **Build Tools for
Visual Studio** with the "Desktop development with C++" workload: the
compiler, linker and Windows SDK, free of charge, no Visual Studio IDE. It
takes a few GB and some minutes. Then finish `rustup-init` with the default
options and reopen PowerShell.

Verify:

```powershell
rustc --version     # 1.85 or newer
cargo --version
git --version
```

## 3. Get the code

```powershell
git clone --recursive https://github.com/77ph/TPM_sign.git
cd TPM_sign\signer
```

`--recursive` matters (contracts depend on git submodules). If you already
cloned without it: `git submodule update --init --recursive`.

## 4. Sanity build (no hardware)

```powershell
cargo build -p agent-signer
cargo test
```

Expected at the end: `test result: ok. 1 passed`. The first build compiles
a few hundred crates (5–15 minutes).

If the build stops in `aws-lc-sys`, see the troubleshooting table.

## 5. Build with the Windows TPM backend

```powershell
cargo build -p agent-signer --features windows-tpm
cargo test  -p hw-signer    --features windows-tpm --no-run
```

Expected: both end with `Finished`. **If either fails, stop and send the
complete error text** — a compile error here is the most useful outcome of
this procedure (it means the `windows` crate's API differs from what the
code assumes).

## 6. Hardware test

```powershell
cargo test -p hw-signer --features windows-tpm -- --ignored
```

Expected: `cng_key_signs_and_verifies ... ok`. The test creates a key named
`tpm_sign-test-<pid>` in the TPM, signs a digest, verifies it, reopens the
key by name and deletes it.

## 7. Create a key and a signature vector

```powershell
$B = ".\target\debug\agent-signer.exe"
& $B key create --cng tpm_sign-demo
& $B key show   --cng tpm_sign-demo
& $B vector --backend cng --label tpm_sign-demo --message "TPM_sign: digest signed inside a Windows TPM via CNG" > ..\contracts\test\vectors\p256_windows.json
Get-Content ..\contracts\test\vectors\p256_windows.json
& $B verify --file ..\contracts\test\vectors\p256_windows.json     # OK
```

`key create` prints the public key; the private key stays in the TPM. The
vector file is what we commit next to the Linux TPM vector so the Solidity
tests verify a real Windows TPM signature on every run.

Note: Windows PowerShell 5.1's `>` writes UTF-16 with a byte-order mark;
`verify` reads that (and UTF-8 with or without a BOM). Before committing the
file for the Solidity tests, prefer plain UTF-8:
`& $B vector ... | Out-File -Encoding ascii ..\contracts\test\vectors\p256_windows.json`.
Always start the binary with `&` (`& $B key create …`): `$B key create …`
is a PowerShell parse error.

## 8. Optional: an agent account on Base Sepolia

The smart account cannot tell a Windows TPM key from a Linux one. With a
funded gas wallet and an RPC URL in a `.env` (ask the project owner; never
commit it) and an agent config with

```json
"owner": { "windows-tpm": "tpm_sign-owner" },
"agent": { "windows-tpm": "tpm_sign-agent" },
```

the flow is the one in the README: `account status` → `account fund` →
`demo`. Steps 1–7 are the deliverable; this is a nice-to-have.

## 9. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `error: linker 'link.exe' not found` | C++ build tools missing | rerun `rustup-init.exe` and accept the build-tools install, or install "Build Tools for Visual Studio" with the C++ workload |
| `aws-lc-sys` build error: `NASM command not found! Build cannot continue` | an old checkout without the prebuilt-objects setting | `git pull`; or for this shell `$env:AWS_LC_SYS_PREBUILT_NASM = "1"` and rebuild |
| `aws-lc-sys` build error mentioning cmake | the C build fell back to CMake | `winget install --id Kitware.CMake -e`, reopen PowerShell, send the error |
| `nasm` "not recognized" right after `winget install NASM.NASM` | the installer usually goes per-user (`%LOCALAPPDATA%\bin\NASM`) without admin rights and does not touch PATH | not needed for this project; if you want it: `$env:PATH += ";$env:LOCALAPPDATA\bin\NASM"` |
| `error[E0433]` / `no function named ...` in `windows_tpm.rs` | `windows` crate API drift | send the full error |
| `NTE_NOT_SUPPORTED` (`0x80090029`) or provider not found | TPM disabled or no Platform Crypto Provider | enable the TPM in firmware; check `tpm.msc` |
| `NTE_EXISTS` (`0x8009000F`) on `key create` | a key with that name already exists | `key evict --cng <name>` or pick another name |
| `NTE_BAD_KEYSET` (`0x80090016`) on `key show` | no key with that name for this user | `key create` first; names are per Windows user |
| `NTE_DEVICE_NOT_READY` (`0x80090030`) | TPM busy or not initialized | wait and retry; check `tpm.msc` → "Prepare the TPM" |
| `verify`: `expected value at line 1 column 1` | an older build reading a UTF-16 file from `>` | `git pull` and rebuild, or write it with `Out-File -Encoding ascii` (step 7) |
| `Unexpected token 'key' in expression or statement` | `$B key …` without the call operator | `& $B key …` |

## 10. What to report back

1. Windows version (`winver`) and the TPM manufacturer shown in `tpm.msc`.
2. `rustc --version`.
3. Step 5 output (the last lines, or the full error).
4. Step 6 output.
5. `key show` JSON and the `p256_windows.json` file from step 7.

## 11. Cleanup

```powershell
& $B key evict --cng tpm_sign-demo
```

removes the demo key from the TPM. The test key from step 6 deletes itself.
