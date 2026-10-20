# Secure Enclave backend — test procedure (macOS)

The `secure-enclave` backend of `hw-signer` was written on Linux and
type-checked there for `aarch64-apple-darwin` (`cargo check --target
aarch64-apple-darwin --features secure-enclave` passes for `hw-signer`; the
full CLI could not be cross-checked because alloy's TLS backend compiles C
for the target). It has not yet run on Apple hardware. This is the procedure
to validate it; it should take about fifteen minutes.

## Prerequisites

- A Mac with a Secure Enclave: any Apple Silicon Mac, or an Intel Mac with a
  T2 chip.
- Xcode Command Line Tools (`xcode-select --install`).
- Rust stable (https://rustup.rs) and Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
  — Foundry only for the final on-chain check.
- `git clone --recursive https://github.com/77ph/TPM_sign && cd TPM_sign/signer`

## 1. Build

```sh
cargo build -p agent-signer --features secure-enclave
cargo test  -p hw-signer    --features secure-enclave --no-run
```

If this fails, the error text is the whole point of the exercise — please
paste it verbatim. The likeliest cause is an API drift in the
`security-framework` crate (`GenerateKeyOptions`, `SecAccessControl`,
`Algorithm` names).

## 2. Code-sign the binaries (ad hoc)

Secure Enclave access requires a code-signed process. An ad-hoc signature is
enough for local use:

```sh
codesign -s - --force target/debug/agent-signer
codesign -s - --force "$(ls -t target/debug/deps/hw_signer-* | grep -v '\.d$' | head -1)"
```

macOS may show a keychain prompt the first time a key is created or used.

## 3. Hardware test

```sh
cargo test -p hw-signer --features secure-enclave -- --ignored
```

Expected: `enclave_key_signs_and_verifies ... ok`. The test creates a key
labelled `tpm_sign-test-<pid>`, signs, verifies, reopens it by label and
deletes it.

## 4. A vector for the Solidity tests

```sh
B=target/debug/agent-signer
$B key create --enclave tpm_sign-demo
$B key show   --enclave tpm_sign-demo
```

Then, so we can commit a real Secure Enclave signature next to the TPM one
under `contracts/test/vectors/`, send back the output of `key show` and of
one `vector`-style signing (we will add a `--enclave` option to `vector` once
step 3 passes; for now the public key is the useful part).

## 5. Optional: the account on Base Sepolia

With a funded gas wallet and RPC in a `.env` (see README), an agent config
with `"owner": { "secure-enclave": "tpm_sign-owner" }` and
`"agent": { "secure-enclave": "tpm_sign-agent" }` goes through the same
`account status` → `account fund` → `demo` flow as the TPM one — the smart
account cannot tell the two secure elements apart, which is the point.

## What to report back

1. macOS version and chip (Apple Silicon / T2).
2. Output of step 1 (even if it is just "Finished").
3. Output of step 3.
4. The JSON from `key show` in step 4.
