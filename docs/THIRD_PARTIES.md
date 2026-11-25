# Third-party code: what we build on, its versions and its audits

The code of others that agent-keys runs on or calls: which version we use,
the latest release, what its maintainers call production, and the most
recent audit with the version it covers. Checked on 2026-11-25 (UTC) at
master `194e9259db18d4ac6dfce47f658c107499ff8bca`. `[V]` is verified at the
source given, `[I]` is inferred (house rule 6). An audit is named by its
firm, never by a person.

This project's own contracts have had internal reviews and no external audit
([`FAQ.md`](FAQ.md#is-it-audited)). This page is about the code around them.

## On chain

What the deployed contracts are compiled from, and what the accounts call.

| Dependency | What we use it for | Our version | Latest | Latest audit, and the version it covers |
|---|---|---|---|---|
| **ZeroDev Kernel** | the smart account; we import its interfaces, `ExecLib`, `Types` and `Constants` | v3.3 (tag commit `cd697c7e21715d015e0643af22310a99aa17433b`; the deployed implementation `0xd6CEDDe84be40893d153Be9d467CD6aD37875b28` reports `kernel.advanced.v0.3.3`) | v4.0, released 2026-10-05 [V] | **None published for v3.2 or v3.3.** The newest reports in the repository cover v3.0 (ChainLight, [2024-04-05](https://raw.githubusercontent.com/zerodevapp/kernel/v3.3/audits/chainlight_v3_0.pdf); Kalos, 2024-04-12) and a v3.0-to-3.x diff review of May to June 2024 with no Kernel commit named ([PDF](https://raw.githubusercontent.com/zerodevapp/kernel/v3.3/audits/v_3_1_incremental_audit.pdf)) [V] |
| **ERC-4337 EntryPoint** (eth-infinitism `account-abstraction`) | the EntryPoint every operation goes through; `BasePaymaster` and helpers for our paymaster | v0.7.0 (`7af70c8993a6f42973f520ae0752386a5032abe7`), at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | v0.9.0, 2025-11-16, at `0x433709009B8330FDa32311DF1C2AFA402eD8D009` [V] | v0.7: OpenZeppelin, [2024-02-20](https://github.com/eth-infinitism/account-abstraction/blob/develop/audits/ERC-4337%20Account%20Abstraction%20Incremental%20Audit%20Report%20Feb%2020%202024.pdf), at `9879c931ce92f0bee1bca1d1b1352eeb98b9a120`, fixes to `8086e7ba0d80e6f7e5d36306b73793cbcaa4ced6` [V]. v0.9: Cantina, [2025-11-16](https://github.com/eth-infinitism/account-abstraction/blob/develop/audits/ERC-4337%20Account%20Abstraction%20v0.9%20Security%20Review%20-%20Cantina.pdf) [V] |
| **Safe** | the agent's Safe in the Safe examples (Olas, Jinn); the tests build one from the library | on chain 1.3.0: the L2 singleton `0x3E5c63644E683549055b9Be8653de26E0B4CD36E`, its proxy factory `0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2`, MultiSendCallOnly `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`; the tests' library v1.4.1 (`bf943f80fec5ac647159d26161446ac5d716a294`) | v1.5.0, 2025-07-03 [V] | 1.3.0: Certora (2026-07-20 to 2026-07-29) and Nethermind (final [2026-08-17](https://github.com/safe-global/safe-smart-account/blob/main/docs/Safe_Audit_Report_1_3_0_Nethermind.pdf)), both at `767ef36bba88bdbc0c9fe3708a4290cabef4c376` [V]. 1.4.1: Ackee's audit of 1.4.0 (2023-03), plus one later fix not re-audited [V]. 1.5.0: Ackee and Certora (2024-12 to 2025-05) [V] |
| **Solady** | P-256 signature checks (`P256.sol`) and `ECDSA.sol` in our modules | v0.1.26 (`acd959aa4bd04720d640bf4e6a5c71037510cc4b`) | v0.1.26 [V] | Cantina/Spearbit for Coinbase, review 2024-12-03 to 2025-01-12 at `4c895b961d45c53a49ed500cfc76868b7ee1328b`, fixes in v0.1.1 ([PDF](https://github.com/Vectorized/solady/blob/main/audits/cantina-spearbit-coinbase-solady-report.pdf)). `P256.sol` changed after it (PRs 1363, 1391, 1394, 1396) [V] |
| **Solady inside Kernel** | `LibERC7579`: how `AgentPolicy` decodes the account's single and batch calls | Kernel's pin `3f2f5345261904463f5429c9031c3d2185c0f4fe` (2024-12-06) | v0.1.26 | The same Cantina/Spearbit review. **The pin predates two of its fixes in `LibERC7579`** (see below) [V] |
| **P-256 verifier** `0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a` | Solady's fallback where the P-256 precompile at `0x0000000000000000000000000000000000000100` is absent | as set in Solady (PR 1297, 2025-01-14) | the same | No audit of its own; its change was verified as a fix in the Cantina/Spearbit review (finding 5.6.8) [V] |
| **OpenZeppelin Contracts** | `Ownable`, through `BasePaymaster`, in `WhitelistPaymaster` | v5.0.2 (`dbb6104ce834628e473d2173bbc9d47f81a9eec3`) | v5.7.0, 2026-07-29 [V] | v5.0.0: OpenZeppelin, [October 2023](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/audits/2023-10-v5.0.pdf). The newest listed covers v5.6.0; none is listed for v5.7.0 [V] |
| **CoW Protocol** | the venue of trading mandates: GPv2Settlement `0x9008D19f58AAbD9eD0D60971565AA8510560ab41`, its vault relayer `0xC92E8bdf79f0507f65a392b0ab4667716BFE0110`; read by our decoder | the deployed contracts | immutable | G0 Group, [May 2021](https://github.com/cowprotocol/contracts/blob/main/audits/GnosisProtocolV2May2021.pdf), at `7184fc98c05d2d336d90ee4e6b36429457a56d43`; Hacken, [2021-12-10](https://github.com/cowprotocol/contracts/blob/main/audits/%5BCowswap_10122021%5DSCAudit_Report_2.pdf), at `40c349d52d14f8f3c9f787fe2fca5a496bb10ea9` [V] |
| **CREATE2 deployer** `0x4e59b44847b379578588920cA78FbF26c0B4956C` | deploys our contracts at the same address on every chain | the deployed contract | unchanged | **No public audit found.** It is six instructions with no access control; front-running a deployment gives the same address and code [V/I] |

### Compiler and tools

| Tool | Ours | Latest | Notes |
|---|---|---|---|
| solc | 0.8.38 | 0.8.39, 2026-11-19 [V] | The one bug listed for 0.8.38 (SOL-2026-8, a storage corruption when copying overlapping recursive structs) does not reach us: `contracts/src` has no recursive struct [V by scan]. A new compiler changes every contract's bytecode and address, so it comes with a redeploy only (house rules 3 and 9) |
| Foundry | 1.8.x | v1.10.0, 2026-11-19 [V] | 1.10.0 replaces revm and changes gas snapshots, remappings and test discovery [V]: a move to try on a branch |
| Kontrol | `runtimeverificationinc/kontrol:ubuntu-jammy-1.0.255` | v1.0.255 [V] | current |

### What follows for us

1. **Kernel v3.3 has no published audit that covers it** [V]. v3.2
   (2024-12-11) and v3.3 (2025-04-03) changed `Kernel.sol` and
   `ValidationManager.sol` substantially after the last published review;
   v3.3 added EIP-7702 [V]. A maintainer answered "Yes it has been audited"
   in [kernel issue 145](https://github.com/zerodevapp/kernel/issues/145)
   (2025-10-17), without a report [V]. Kernel v4.0 is released, its source
   cites Trail of Bits findings, its report is not published, and ZeroDev's
   own SDK supports versions up to v3.3 only [V/I]. So v3.3 is the newest
   line in production use. Asking ZeroDev for the v3.3 report is the owner's
   step before an audit of this project. Moving to v4 means EntryPoint v0.9
   and a redeploy.
2. **`AgentPolicy` decodes calls with Kernel's own `LibERC7579`, on
   purpose** [V `contracts/foundry.toml`: `lib/kernel/:solady/=lib/kernel/lib/solady/src/`;
   `AgentPolicy.sol` imports `kernel/lib/solady/src/accounts/LibERC7579.sol`;
   Kernel's `ExecLib` imports `solady/accounts/LibERC7579.sol`]. The
   policy judges each call of a batch with the function Kernel then
   executes it with, byte for byte, so the two cannot read one batch
   differently. That pin predates two fixes of the Cantina/Spearbit review
   (PR 1239, finding 5.2.2, High: the mode selector; PR 1244, finding
   5.3.7, Medium: `decodeBatch` bounds) [V]. The newer `decodeBatch`
   bounds-checks differently [V by diff], so moving the policy alone to a
   newer Solady would make the policy and the deployed Kernel differ. 5.2.2
   is in functions we do not call [V]. For 5.3.7 the policy and the account
   share the decoder [I]. A test that runs the report's proof-of-concept
   batch through both is still to write. Kernel's
   [issue 137](https://github.com/zerodevapp/kernel/issues/137) acknowledges
   the stale pin [V].
3. **EntryPoint v0.7 is two releases behind.** These are fixed only from
   v0.8 on, none of them a security advisory [V]:
   - initCode front-running;
   - a paymaster's `postOp` gas figure that misses the unused-gas penalty.
     `WhitelistPaymaster` returns no context and has no `postOp` [I];
   - a zero-address paymaster accepted with data;
   - `BasePaymaster`'s single-step `Ownable`, which `WhitelistPaymaster`
     inherits;
   - the lower time bound. In v0.7 `block.timestamp == validAfter` is
     inside the window, which is what `AgentPolicy` documents. From v0.8 it
     is outside, so moving shifts a mandate's start by one second [V].

   Kernel v3.3 is built for v0.7 [V], so v0.7 stays as long as Kernel v3.3
   does.
4. **Safe 1.3.0 was audited again in 2026.** Certora's one new Low needs a
   Safe transaction with a nonzero `safeTxGas` or `gasPrice` [V]. The
   policy refuses all three gas words other than 0 since #191, which
   closes that path for an agent [I]. Nethermind's two findings are fixed
   from 1.4.0 on [V]. The Safe version is the Safe owner's choice; the
   policy reads `execTransaction`, which is the same in 1.3.0, 1.4.1 and
   1.5.0 [I].
5. **No security advisory** in GitHub's database affects Kernel,
   `account-abstraction`, Safe, CoW, or `Ownable` in OpenZeppelin 5.0.2 [V].
   Solady's GHSA-8xvx-4mvg-m9v8 is in a contract we do not use, and is fixed
   from 0.1.24 [V].

## Off chain

The signer, the CLI, the phone's core and apps, and the tools around them.
Advisories were checked with `cargo audit` on the three `Cargo.lock` files
against the RustSec database of 2026-11-25, OSV for every locked crate and
the Android and npm packages, and GitHub's advisories [V].

| Dependency | What we use it for | Ours | Latest stable | Audit, and the version it covers | Advisories on ours |
|---|---|---|---|---|---|
| `p256` / `ecdsa` / `elliptic-curve` (RustCrypto) | P-256 keys and signatures in software and in checks | 0.14.0 / 0.17.0 / 0.14.3 | the same [V] | zkSecurity for NEAR, [2025-04-07](https://reports.zksecurity.xyz/reports/near-p256/), `p256` 0.14.0-pre.2, **verification only**; signing and constant time out of scope [V]. The READMEs say "never been independently audited" [V] | none [V] |
| `aes-gcm`, `scrypt`, `sha2`, `hmac`, `zeroize`, `rand_core`, `getrandom` | the cold recovery key file, hashing, secrets | 0.10.3, 0.11.0, 0.11.1, 0.13.0, 1.9.1, 0.6/0.9/0.10, 0.2/0.3/0.4 | `aes-gcm` 0.11.1, `scrypt` 0.12.0, `sha2` 0.11.2, `zeroize` 1.9.2; the rest current [V] | `aes-gcm`: NCC Group, 2020, version 0.3.0 [V]. The others: no public audit found | none (`aes-gcm`'s RUSTSEC-2023-0096 is fixed in 0.10.3) [V] |
| `x25519-dalek` | the secure channel to TROPIC01 | 2.0.1, and 3.0.0 through `yubikey` | 3.0.0 [V] | Quarkslab, 2019, version 0.5.2, a quick look only [V] | none [V] |
| `aws-lc-rs` / `aws-lc-sys` | TLS crypto under `rustls` | 1.18.2 / 0.46.0 | 1.19.0 / 0.47.0 [V] | FIPS 140-3 certificates cover the separate FIPS build, **not the `aws-lc-sys` we link** [V]; no third-party report found | none (GHSA-xv35-xp83-5wrf is fixed in our version) [V] |
| `rustls` | TLS to RPC nodes | 0.23.46 | the same [V] | Cure53, 2020, version 0.16 or newer [V] | none [V] |
| `alloy` | Ethereum RPC, ABI, the CLI's chain access | 2.5.0 (`alloy-primitives` 1.7.3) | 2.6.1 [V] | no public audit found | none directly. Through it, **`crypto-bigint` 0.5.5: RUSTSEC-2026-0387** (timing in constant-time code), with no 0.5 fix; alloy 2.6.1 still needs it. Our P-256 path uses `crypto-bigint` 0.7.x, which is fixed [V]. `url` is 2.5.9, which has the fix of RUSTSEC-2026-0592 (a crash in `Url::origin()`) [V `signer/Cargo.lock`] |
| `tss-esapi` | the TPM 2.0 backend | 7.7.0 | the same [V] | no public audit found | none in the crate. **The system `tpm2-tss` library it links had 13 advisories** published 2026-10-26 to 2026-11-04, fixed in 4.1.5 and 4.2.1 (latest 4.2.2); a Linux host needs one of those [V] |
| `yubikey` | the YubiKey backend | 0.9.0-rc.0 | no stable 0.9 (0.8.0 is the last stable) [V] | none: its README says no audit was ever done [V] | through it, **`rsa` 0.10.0-rc.19: RUSTSEC-2023-0071** (we use P-256 slots only, the RSA code is not called [I]). It cannot be moved: `yubikey` 0.9.0-rc.0 asks `rsa` for a feature `sha2` that `rsa` 0.10.0 no longer has, so the fix waits for a `yubikey` release [V `cargo update -p rsa --precise 0.10.0` fails to resolve]. `inout` is 0.2.6, which has the fix of GHSA-2943-gp7x-qg39 [V `signer/Cargo.lock`] |
| `tropic01` (libtropic-rs, git) | the TROPIC01 backend | rev `3310775775c211496d514f9110554884afa3ba80` | that rev is its master; no releases [V] | none. **Its README calls it a community project, not maintained by Tropic Square, not for production** [V]. The chip itself was audited by Ledger Donjon; the full report is due in spring 2027 [V] | none published [V] |
| `windows`, `uniffi`, `tokio`, `reqwest`, `serialport`, `clap` | Windows CNG, the phone bindings, the runtime, HTTP, serial, the CLI | 0.62.2, 0.32.2, 1.54.1, 0.13.5, 4.10.1, 4.6.7 | current, except `clap` 4.6.10 [V] | not researched | none [V] |
| Rust | the toolchain | 1.94.1 minimum, 1.95.0 for clippy in CI | 1.100.0 [V] | n/a | Cargo's CVE-2026-5222 and CVE-2026-5223 matter only with third-party registries; we use crates.io and one git dependency [V/I] |
| `@pimlico/alto` (npm) | the bundler of the ERC-7562 check | 0.0.21 | the same [V] | not researched | none (GHSA-c9v7-pgv6-hrcc is fixed in it) [V] |
| Node.js | CI | 22 | 26 is the active LTS; 22 is in maintenance until 2027-04-30 [V] | n/a | n/a |
| Android: AGP, Kotlin, `appcompat`, `biometric`, ZXing core, `zxing-android-embedded`, JNA | the Android app | 8.13.2, 2.4.21, 1.7.1, 1.1.0, 3.5.4, 4.3.0, 5.17.0 | AGP 9.5.3, `appcompat` 1.8.0, JNA 5.19.1; the rest current [V] | n/a | none [V]. AGP and `appcompat` are held back on purpose (the build file says why); `zxing-android-embedded` has had no release since 2021 [V] |
| iOS | the iPhone app | deployment target iOS 16.0; Apple's CryptoKit, Secure Enclave and LocalAuthentication only | iOS 27.2.1 [V] | n/a | iOS 16's last update was 16.7.16 on 2026-05-11, while 18, 26 and 27 were updated on 2026-11-09: treat iOS 16 as out of security support [V/I] |

### What follows for us

1. **Two of three locked crates with fixes are taken:** `inout` 0.2.6 and
   `url` 2.5.9, in `signer/Cargo.lock`, the only lock file that holds them
   [V]. **`rsa` stays at 0.10.0-rc.19** until `yubikey` has a release that
   builds with `rsa` 0.10.0; the RSA code is not called with our P-256
   slots [I]. `crypto-bigint` 0.5.5 stays until
   alloy moves to `k256` 0.14 [V]. It is not on the P-256 path; it touches
   secp256k1 arithmetic inside alloy, which signs with a real secret only
   under `insecure-software-keys` [I].
2. **A Linux TPM host needs `tpm2-tss` 4.1.5 or later, or 4.2.1 or later**
   [V]: the crate links whatever the host has installed.
3. **No audit covers P-256 signing at the versions we ship** [V]. It signs
   wherever a key is held in software: the cold recovery key file of the
   CLI (kept under scrypt and AES-GCM), the software backend, and the
   tests. The hardware backends sign in the device.
4. **The TROPIC01 binding is a community project its authors call not for
   production** [V]. The TROPIC01 backend stays experimental for that
   reason as well as for the chip's open report.
5. **The iOS deployment target** (16.0) is below what Apple still updates
   [I]. Raising it is a change to the app and its doc (design D7).
6. **Unaudited and in use:** `yubikey`, `alloy`, `tss-esapi`,
   libtropic-rs, and RustCrypto's hashing, MAC, KDF and RNG crates. No
   public audit was found for any of them [V].

## Not checked

- The audit reports were read for scope, dates, commits and the findings
  named here, not end to end.
- Whether ZeroDev holds an unpublished report on Kernel v3.2 or v3.3.
- Whether the deployed Kernel v3.3 implementation and the P-256 verifier's
  code equal a build of their sources. Only Kernel's `accountId` was read.
- The proof-of-concept batch of the Solady review run through `AgentPolicy`
  and Kernel together (point 2 of the on-chain list).
- Audits of `windows`, `uniffi`, `tokio`, `reqwest`, `serialport`, `clap`
  and the bundler; the `tpm2-tss` version on any given host.

## To refresh

- Our versions: `git submodule status --recursive`, the `Cargo.lock`
  files, `mobile/android/app/build.gradle.kts`, `mobile/ios/project.yml`.
- Advisories: `cargo audit` in `signer/`, `mobile/owner-core/` and
  `mobile/owner-core/fuzz/`.
- Audits: each project's own `audits/` folder or security page, as linked
  above.
