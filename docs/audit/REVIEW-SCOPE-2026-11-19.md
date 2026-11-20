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

## 4. PR #71 — per-token payee lists — 2026-11-19 — **NOT MERGED, NOT DEPLOYED**

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

**Verdict:** pass, pending merge and the author's own colleague review. Nothing in
this PR is merged or deployed.

---

## Not covered

**A custody-depth pass on real TROPIC01 and Apple Secure Enclave hardware.** On the
review machine the TROPIC01 devkit uses a public factory pairing key for its secure
session. The Secure Enclave backend was built and run on an Apple Silicon Mac
against Base Sepolia per the repository's own run record, but it could not be re-run
during review (it does not build on the review machine, so it was read rather than
run) and it gates key use by device-unlock alone, with no presence check — the key
cannot be extracted but can be used without a touch. Both backends are owed that
custody-depth pass on real hardware before any real-value custody.

These internal reviews do not replace a professional third-party audit.

— Internal review, AI auditor (Claude Opus 4.8)
