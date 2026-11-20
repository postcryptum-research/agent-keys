# agent-keys — Internal Review Scope (as of 2026-11-19)

These are **internal reviews by an AI auditor (Claude Opus 4.8) working with the
author.** They are at **testnet depth** (Base Sepolia, no real funds) and are
**not a professional third-party audit.** A third-party audit is intended before
any real-value custody.

Each pass below gives its date, the revision read, what was in scope, a one-line
verdict, and what is explicitly not covered.

---

## 1. Initial review — 2026-10-20

**Scope:** AgentPolicy v4 and the hardware-signer core.

**Outcome:** eight issues raised — **six fixed in code, one fixed in its code
part, one documented.**

## 2. Feature follow-ups — 2026-10-21 to 2026-11-18

**Scope (as code, at the then-current revisions):** the mandate time windows;
x402 / EIP-3009 payments; the P256 recovery validator; the encrypted key-file
store; the role × key-type gating; the WhitelistPaymaster per-sender budgets;
Android key-attestation parsing; the phone and set-root proof-of-possession; the
TPM noDA template.

**Verdict:** sound. Recommendations raised in these passes — the noDA template
keyed off the absence of an authValue, a proof-of-possession required by default
for an out-of-band `set-root`, and a proof-of-possession on phone handover — were
implemented and re-checked.

## 3. Full-codebase pass — 2026-11-19, at revision `c9197c7` (master)

**Scope:** the entire source tree, read as code.

- **On-chain:** AgentPolicy; the P256 validator, signer and on-curve point
  library; the Safe-nonce assertion; the recovery validator; the Whitelist
  paymaster; the demo targets.
- **Hardware signer backends:** software, YubiKey PIV, TPM, TROPIC01, Apple
  Secure Enclave (Rust side and the Swift shim), Windows TPM.
- **Host CLI:** the bundler relay, the x402 client, the phone transport, the
  strict DER / attestation reader.
- **Mobile owner-core:** the userOpHash computation, the request commitment and
  MAC, the review screen, enrollment, the key fingerprint, the proof-of-possession
  and health check.

**Verdict:** sound, or a documented hardware limitation (see *Not covered*). The
signature path verifies on-chain through the Solady P256 library, which rejects a
high `s`; every backend signs a 32-byte digest inside its hardware, exports only
the public half, and normalises to low `s` through one shared code path; the owner
review recomputes the userOpHash on the phone and binds it to the request
commitment, so what the owner sees is what is signed. No unreviewed code path
remains.

## 4. PR #71 — per-token payee lists — 2026-11-19 — merged and deployed 2026-11-20

**Scope:** branch `token-payees` (commits `a1bbbed`, `987e2c8`, `f22a5a7`,
`feb9d87`) — per-token payee lists in AgentPolicy and their owner-core and signer
plumbing.

**Findings and resolution:**
- One **medium**: a payee list was bypassable through a value-moving selector the
  list did not meter if that selector was also allow-listed on the token. Fixed
  fail-closed (`987e2c8`): a token with a payee list may be moved only by the four
  functions the list understands. Re-checked.
- One **design question**: the "no list means anyone" default. Resolved
  (`f22a5a7`) by requiring each token entry to state its choice — a list, or the
  word "anyone" — so the default is never silent.
- One **low hardening**: refuse an install for an account that does not name its
  EntryPoint. Implemented (`feb9d87`) and re-checked.

**Verdict:** pass. Merged after the colleague's review and deployed to Base Sepolia
on 2026-11-20 as `0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95`, together with the later
commits named below.

Later commits on that branch, and a full review of `AgentPolicy.sol` at `6fe93a7`
with its two low-severity findings and their fixes, are recorded in issue #76.

## 5. Hardware passes — November 2026

**TROPIC01 — 2026-11-19.** Hardware sign/verify pass on the devkit: the public key read from the
chip, a digest signed in the chip and verified (low `s`), and that public key found identical to the
account's agent key in the repository's config and test vector. Limitation: the secure session
is bootstrapped from the public factory pairing key (SH0, slot 0); custody depth is bounded by that
shared pairing secret until a provisioned pairing key replaces it.

**Apple Secure Enclave — 2026-11-20, Apple M1.** On-hardware pass of the on-device path, run by the
project's reviewer and recorded in issue #73: a 32-byte digest signed inside the enclave by a key
created there on 2026-10-21, the signature verified off-chain (low `s`, the digest signed as it is),
a fresh operation by that key accepted on Base Sepolia, and the key on chain shown to be the key in
the enclave (acceptance items T1–T4, T5(a), T6, T7). The enclave gates key use by device unlock only — no presence/touch
check (`.privateKeyUsage`); the private key cannot be extracted, but a signature can be produced
without a touch.

**Review findings (Secure-Enclave backend, read at `99bfdf8`):** three observations, all low or
informational, none affecting the enclave's key-binding custody property:
- *(info)* `key show` / `tpmse_public` reads the public key from the stored blob without the enclave
  — expected (the public half is public), but it means the second-machine test must exercise signing,
  not `key show`.
- *(info)* byte 108 of the stored CryptoKit blob is a don't-care byte (flips, the key still signs
  identically) — an unused byte in Apple's opaque format; no exploit; optional hardening is our own
  authenticated wrapper over the key file.
- *(low — robustness)* a key file with a damaged public-key region makes CryptoKit trap uncatchably
  (`fatalError`, which `do/catch` cannot catch), aborting the process instead of returning `badKey`;
  fix is a format guard in the Swift shim; Mac-only to test.

**Not covered (narrowed).** The second-machine refusal (acceptance item T5(b)) — a key file copied to
another Mac refused at signing — is sound by design (the enclave-wrapped blob is device-bound) but has
not been run empirically for lack of a second Apple-silicon Mac; when it is run it must exercise
signing (`vector`), not `key show` (the public key is readable from the blob without the enclave). A
full custody-depth pass on real hardware is still owed for both hardware backends before any
real-value custody.

---

## Not covered

As of 2026-11-20, see "Not covered (narrowed)" in section 5. The text of 2026-11-19, before the
hardware passes, read: a custody-depth pass on real TROPIC01 and Apple Secure Enclave hardware.

These internal reviews do not replace a professional third-party audit.

— Internal review, AI auditor (Claude Opus 4.8)
