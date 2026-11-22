# Getting started

## Quick start

Any platform, no hardware (software backend — dev/CI only):

```sh
cd signer && cargo test
cd ../mobile/owner-core && cargo test   # the core shared with the phone apps; outside the signer workspace
cd ../../signer
# end to end on a local anvil: the real CLI against EntryPoint, Kernel, our
# modules, a Safe, a paymaster, a fake bundler and an x402 server (software
# keys, so only in this test-only build)
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli
cd ../contracts && forge test      # RIP-7212 enabled locally via odyssey = true
# forge 1.8+ dropped `odyssey`; there the precompile comes with the Osaka
# EVM: forge test --evm-version osaka
```

Linux with a TPM 2.0:

```sh
sudo apt install libtss2-dev libclang-dev
sudo usermod -aG tss "$USER"       # access to /dev/tpmrm0; re-login
cd signer
cargo test --features tpm -- --ignored
cargo run -p agent-signer --features tpm -- vector --backend tpm --message hello
```

The `vector` command prints a JSON `(digest, r, s, x, y)` record; the Solidity
tests verify every file under `contracts/test/vectors/` — signed inside an
Intel PTT, a Windows TPM, a TROPIC01, an Apple Secure Enclave and a YubiKey 5. Windows: [`docs/WINDOWS.md`](WINDOWS.md)
(free toolchain only); TROPIC01: `--features tropic01`, [`docs/TROPIC01.md`](TROPIC01.md);
YubiKey: `--features yubikey`, [`docs/YUBIKEY.md`](YUBIKEY.md).

## Run an agent account on Base Sepolia

Secrets stay outside the repository: a `.env` with `BASE_SEPOLIA_RPC_URL`,
and `BUNDLER_URL` and/or `GAS_WALLET_KEYFILE` (a file holding the hex key of
a small funded EOA that submits `handleOps` itself and pays for funding
commands; not needed when a bundler delivers the operations). The account itself is described
by `signer/agent.base-sepolia.json`: two TPM handles, a permission id and the
agent's mandate. Module addresses come from `contracts/deployments/84532.json`
(`forge script script/Deploy.s.sol` writes it; CREATE2 with salt 0, so they
are the same on every chain).

```sh
cd signer && cargo build -p agent-signer --features tpm
B=target/debug/agent-signer; A=agent.base-sepolia.json; E=../../.env

$B key create --handle 0x81010010      # owner key, stays in the TPM
$B key create --handle 0x81010011      # agent key, stays in the TPM
$B account status --agent $A --env-file $E   # counterfactual address
$B account fund   --agent $A --env-file $E --wei 2000000000000000
$B demo           --agent $A --env-file $E   # first op deploys the account
$B op send --agent $A --env-file $E --target 0x... --data 0x...   # anything the mandate allows
```

`account fund` simulates `createAccount` first and refuses to send ETH to an
address that could never be deployed. Operations outside the mandate are
rejected during simulation, before any gas is spent.

For programs driving the CLI, `op send --json` prints one JSON line
(`account`, `userOpHash`, `nonce`, `tx`, `block`, `gasUsed`) and keeps progress
on stderr; `--nonce` reuses the nonce of an earlier attempt, so retrying the
same action can never execute it twice. A Safe transaction (`execTransaction`
calldata) needs `--safe-nonce <n>`: it goes out as a batch that asserts the
Safe's nonce on-chain first, so a replay reverts instead of running again.

Keys: the agent's operations never open the owner key — the config carries
the owner's public key (`ownerPublicKey`), and only root operations open the
key itself. Where to keep it is a custody decision
([`docs/KEY_POLICY.md`](KEY_POLICY.md)); on one chip, a TPM owner key can
be protected by a root-only secret (`key create --handle … --auth-file …`).
Security review: [`docs/AUDIT-2026-10-20.md`](AUDIT-2026-10-20.md).

Losing a key: the agent's is replaced by the owner (`permission rotate`); for
the owner's, a cold recovery key — e.g. an encrypted key file on a USB drive
(`key create --keyfile …`) installed with `owner add-recovery` — may take
root over and hand it to a new device (`owner recover`, `owner set-root
--retire … --not-a-phone`, or `--to-phone <label>` for a phone; either way
the new key must first show that it can sign), and can do nothing else, not
even sign a message.
`key check` proves a key (or a key file's passphrase) still works without
sending anything. Devices and failure modes:
[`docs/OWNER_DEVICES.md`](OWNER_DEVICES.md),
[`docs/RESILIENCE.md`](RESILIENCE.md).

Gasless, and the owner's controls:

```sh
$B paymaster deposit --agent $A --env-file $E --wei 3000000000000000
$B paymaster sponsor --agent $A --env-file $E --budget 2000000000000000 --max-per-op 300000000000000   # gas budget and per-op cap, wei
$B demo --agent $A --env-file $E --sponsored           # the paymaster pays

$B demo --agent $A --env-file $E --bundler https://public.pimlico.io/v2/84532/rpc
# ...or set BUNDLER_URL in .env: the bundler submits handleOps from its own
# wallet and is paid from the account's (or the paymaster's) EntryPoint
# deposit; the gas wallet is then only needed for deploying and funding.
$B demo --agent $A --env-file $E --bundler https://public.pimlico.io/v2/84532/rpc --sponsored
# ...chip signs, paymaster pays, bundler relays: no gas wallet in the path.
$B paymaster stake --agent $A --env-file $E --wei 100000000000000000   # if a bundler's reputation rules require it

$B key create --handle 0x81010012 --pcrs 0,2,4,7       # a key sealed to the boot state
# in agent.json: pin "account", point "agent" at {"tpm": {"handle": "0x81010012", "pcrs": [0,2,4,7]}},
# give the new permission a fresh id — then, signed by the owner key:
$B permission rotate --agent $A --env-file $E --old-id 0x61676e74 --sponsored
$B permission revoke --agent $A --env-file $E --id 0x61676e32          # when the agent is retired
# a schedule: one config per time window (own permissionId, policy.validAfter … validUntil,
# budget, allow-list), each installed alongside the others:
$B permission add --agent window-mon.json --env-file $E --sponsored

$B key create --tropic01 /dev/ttyACM0 --slot 1         # a key inside a TROPIC01 (--features tropic01)
# signer/agent.tropic01.base-sepolia.json: that key as the agent, a Safe in the mandate

# x402: a permission that may pay in USDC ("x402": true in policy.tokens), then
$B permission add --agent agent.x402.base-sepolia.json --env-file $E          # owner, once
$B x402 fetch --agent agent.x402.base-sepolia.json --env-file $E <url>        # agent: pays on 402
$B x402 reclaim --agent agent.x402.base-sepolia.json --env-file $E            # expired unused -> budget
```
