# Gas benchmark: what authorization costs

Reproduces the measurement in Y. Madhwal's reference paper — one logging
event, payload sizes from 10 bytes to 100 kB, local execution gas, every
path warmed up before recording — for the paper's three EOA-submitted
methods and for this project's agent path.

| Method | What is checked | Who submits |
|---|---|---|
| address-only | the sending EOA is on an allow-list | an EOA |
| k1 signature | an independent secp256k1 signature over the payload (`ecrecover`) | an EOA |
| p256 signature | an independent P-256 signature over the payload (RIP-7212 via Solady `P256`) | an EOA |
| p256 agent account + paymaster | **ours**: EntryPoint v0.7 → Kernel v3.3 → `AgentPolicy` + `P256Signer` permission → `execute` → logger, gas paid by `WhitelistPaymaster` | `handleOps`, self-bundled |

The paper's fourth bar was secp256k1 account abstraction against a *mock*
EntryPoint; ours is P-256 against the real one, with a policy module in the
validation path and a real paymaster.

## Results (execution gas, warm, forge local)

`forge test --match-contract GasBenchmark -vv` → `contracts/benchmarks/gas.json`

| payload | address-only | k1 signature | p256 signature | p256 agent + paymaster |
|---:|---:|---:|---:|---:|
| 10 B | 3,443 | 7,402 | 7,433 | 81,821 |
| 100 B | 4,258 | 8,264 | 8,269 | 82,816 |
| 1 kB | 11,826 | 16,090 | 16,095 | 92,003 |
| 10 kB | 88,868 | 96,074 | 96,435 | 185,768 |
| 100 kB | 956,236 | 1,026,826 | 1,064,773 | 1,293,824 |

The agent column is the 2026-11-10 measurement (`gas.json`), with the token
budgets of the current policy and its forbidden-target guard; the guard
itself costs 141 gas per operation.

Execution gas is what the call consumes as seen from the caller. A
transaction additionally pays 21,000 base plus calldata (16 gas per non-zero
byte): about 22.8k for the 10-byte EOA calls, more for the agent path whose
outer transaction also carries the UserOperation envelope. With that added,
the 10-byte rows are roughly 26k / 30k / 30k / 110k — the same shape as the
paper's 29,158 / 35,723 / 42,603 / 92,158.

## What the numbers say

**A hardware key costs nothing extra.** P-256 verification through RIP-7212
is 7,433 gas against 7,402 for `ecrecover` — 31 gas apart. In the paper the
P-256 path cost 6,880 gas more than secp256k1 (and 13,445 more than
address-only); that gap was the cost of verifying P-256 without the
precompile. On chains with RIP-7212 (Base, OP-Stack, Polygon, zkSync, Scroll,
Linea; mainnet via EIP-7951) the curve the secure elements speak is as cheap
as the one Ethereum was built on.

**The agent account costs about 77k gas per operation on top of a bare
call.** That buys: EntryPoint accounting and nonce management, Kernel's
validation routing, the policy check (allow-list, value cap, budget, expiry,
all read from storage), the P-256 signature check, paymaster validation and
settlement, and the account calling the target. The paper measured +63k for
secp256k1 AA with a mock EntryPoint and no policy; +14k for a real EntryPoint
and a policy module is the price of the containment this project is about.

**Large payloads are the data's cost, not the authorization's.** At 10 kB
the authorization overhead is already a minority of the bill; at 100 kB the
agent path pays 336k more than address-only because the real EntryPoint
hashes and copies the operation's calldata (the paper's mock did not), while
the signature methods pay 70–110k more for the same reason. The paper's
conclusion stands and is sharper with a real EntryPoint: log compact
readings or commitments on-chain and keep large objects off-chain.

## On-chain reference points (Base Sepolia)

Whole `handleOps` transactions as reported by the receipts, self-bundled:

| operation | tx | gas used |
|---|---|---:|
| agent `increment()`, account pays | `0x00b95a89…2fafc84` | 154,412 |
| agent `increment()`, paymaster pays | `0xae73b53d…3a5f2106` | 163,012 |
| sealed agent key, paymaster pays | `0xc8117420…75db4b` | 180,100 |
| first operation, deploys the account | `0x78533210…e669bb` | 700,039 |
| owner rotates the agent permission | `0x4519a35b…195370` | 451,053 |

These include the 21k base, calldata, and the EntryPoint's own bookkeeping
around the measured execution.

## Reproduce

```sh
cd contracts
forge test --match-contract GasBenchmark -vv
cat benchmarks/gas.json
```

The benchmark deploys the real EntryPoint v0.7 bytecode, Kernel v3.3, the
three modules and the paymaster locally; `odyssey = true` in `foundry.toml`
provides the RIP-7212 precompile.
