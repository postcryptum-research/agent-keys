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
| 10 B | 3,443 | 7,402 | 7,433 | 83,223 |
| 100 B | 4,258 | 8,264 | 8,269 | 84,218 |
| 1 kB | 11,826 | 16,090 | 16,095 | 93,405 |
| 10 kB | 88,868 | 96,074 | 96,435 | 187,170 |
| 100 kB | 956,236 | 1,026,826 | 1,064,773 | 1,295,226 |

The agent column is the 2026-11-20 measurement (`gas.json`) of the policy
deployed on 2026-11-21, one step after the instance of 2026-11-20: its
storage is laid out so that every slot validation touches belongs to the
account under ERC-7562 ([#83](https://github.com/postcryptum-research/agent-keys/issues/83)),
663 gas per operation for the extra hashing. Over the instance of
2026-11-10, it knows payee
lists ([#66](https://github.com/postcryptum-research/agent-keys/issues/66)),
288 gas per operation here, holds a token's per-operation cap for the
whole operation and not per call
([#76](https://github.com/postcryptum-research/agent-keys/issues/76)), 402
gas, and refuses Permit2 as a target, 49 gas (the earlier instance measured
81,821 at 10 B on 2026-11-10). The forbidden-target guard costs 141 gas per
operation.

Execution gas is what the call consumes as seen from the caller. A
transaction additionally pays 21,000 base plus calldata (16 gas per non-zero
byte): about 22.8k for the 10-byte calls, as `gas.json` records it
(`intrinsicCalldataEstimate`). That estimate counts every byte as non-zero,
so it is an upper estimate, and it is the same for all four methods: the
agent path's outer transaction also carries the UserOperation envelope,
which is not measured here. With the estimate added, the 10-byte rows are
roughly 26k / 30k / 30k / 105k — the same shape as the paper's
29,158 / 35,723 / 42,603 / 92,158.

## What the numbers say

**A hardware key costs nothing extra.** P-256 verification through RIP-7212
is 7,433 gas against 7,402 for `ecrecover` — 31 gas apart. In the paper the
P-256 path cost 6,880 gas more than secp256k1 (and 13,445 more than
address-only); that gap was the cost of verifying P-256 without the
precompile. On chains with RIP-7212 (Base, OP-Stack, Polygon, zkSync, Scroll,
Linea; mainnet via EIP-7951) the curve the secure elements speak is as cheap
as the one Ethereum was built on.

**The agent account costs about 79k gas per operation on top of a bare
call.** That buys: EntryPoint accounting and nonce management, Kernel's
validation routing, the policy check (allow-list, value cap, budget, expiry,
all read from storage), the P-256 signature check, paymaster validation and
settlement, and the account calling the target. The paper measured +63k for
secp256k1 AA with a mock EntryPoint and no policy; +16k for a real EntryPoint
and a policy module is the price of the containment this project is about.

**Large payloads are the data's cost, not the authorization's.** At 10 kB
the authorization overhead is already a minority of the bill for the
signature methods (about 7k of 96k execution gas); for the agent path it is
about half of the execution gas (97k of 186k) and a minority only once the
transaction's calldata cost is counted; at 100 kB the
agent path pays 338k more than address-only because the real EntryPoint
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
