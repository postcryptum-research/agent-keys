# Building and testing on Windows (TPM through CNG)

> **Status (2026-10-20): verified on a Windows 11 PC.** Build without NASM or
> CMake, the hardware test `cng_key_signs_and_verifies`, `key create/show
> --cng`, and a signed vector — `contracts/test/vectors/p256_windows.json`,
> checked off-chain and by the Solidity tests (RIP-7212 path).

## What you are testing

`signer/crates/hw-signer/src/windows_tpm.rs` keeps a P-256 key inside the
TPM through CNG's **Microsoft Platform Crypto Provider** — the key store
every Windows 11 machine has — and signs digests with it. It was written on
Linux and first ran on Windows on 2026-10-20 (the status above). The
procedure below checks the same on the next machine: that it builds, that
the provider accepts the key template, and that its signatures verify.

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

Open a new PowerShell and record the whole session to a file — that file
is what you send back:

```powershell
Start-Transcript -Path $HOME\tpm_sign-windows.log
```

Then print the environment (all text, no GUI windows):

```powershell
cmd /c ver                      # Windows version
tpmtool getdeviceinformation    # TPM version and manufacturer
rustc --version                 # 1.94.1 or newer (alloy 2.5 needs it)
cargo --version
git --version
```

If `tpmtool` asks for administrator rights, skip it and note the
manufacturer shown in `tpm.msc` instead.

## 3. Get the code

```powershell
git clone --recursive https://github.com/postcryptum-research/agent-keys.git
cd agent-keys\signer
```

`--recursive` matters (contracts depend on git submodules). If you already
cloned without it: `git submodule update --init --recursive`.

## 4. Sanity build (no hardware)

```powershell
cargo build -p agent-signer
cargo test
```

Expected: every `test result:` line says `ok` with `0 failed`. The first build compiles
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
& $B vector --backend cng --label tpm_sign-demo --message "TPM_sign: digest signed inside a Windows TPM via CNG" | Out-File -Encoding ascii ..\contracts\test\vectors\p256_windows.json
Get-Content ..\contracts\test\vectors\p256_windows.json
& $B verify --file ..\contracts\test\vectors\p256_windows.json     # prints OK
```

`key create` prints the public key; the private key stays in the TPM. The
vector file is what we commit next to the Linux TPM vector so the Solidity
tests verify a real Windows TPM signature on every run.

If `key create` reports `NTE_EXISTS` (`0x8009000F`) — the key is left from
an earlier run — skip it and continue with `key show`.

Copy the commands as they are: `| Out-File -Encoding ascii` keeps the file
plain text (Windows PowerShell 5.1's `>` writes UTF-16, which `verify`
accepts but the Solidity tests do not), and the binary must be started with
`&` — `$B key create …` without it is a PowerShell parse error.

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

After step 11 (cleanup), stop the transcript and send the file:

```powershell
Stop-Transcript     # writes $HOME\tpm_sign-windows.log
```

It must contain, in order:

1. the environment block from step 2 (Windows version, TPM, `rustc`);
2. step 4 — the `test result:` lines;
3. step 5 — both commands ending in `Finished` (or the full error);
4. step 6 — `cng_key_signs_and_verifies ... ok`;
5. step 7 — the `key show` JSON, the `p256_windows.json` content, and
   `verify` printing `OK`;
6. step 11 — `deleted tpm_sign-demo`.

## 11. Cleanup

```powershell
& $B key evict --cng tpm_sign-demo
```

removes the demo key from the TPM. The test key from step 6 deletes itself.
