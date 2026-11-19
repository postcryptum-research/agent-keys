# Olas service Safe with a hardware-signed owner

## The idea

An Olas agent's key file holds one secp256k1 key with three jobs:

| Role | Today | With agent-keys |
|---|---|---|
| consensus identity — every ABCI payload is ecrecover-checked against its sender | agent key | stays a software key, **no funds, not an owner** |
| on-chain agent instance, owner of the service Safe | agent key | **Kernel account** (key in TPM / TROPIC01) |
| keeper — sends `execTransaction`, pays gas | agent key (EOA tx) | **Kernel account** via `agent-signer op send` (UserOperation, paymaster) |

Olas contracts allow the split: `ServiceRegistryL2.registerAgents` does not
require EOAs, the Safe takes a contract owner, staking checks the Safe
proxy's codehash and threshold, and activity checkers read `Safe.nonce()`,
which a Kernel-driven `execTransaction` increments like any other
(`ADAPTATION.md` §4).

The Safe "signature" of the Kernel owner is the pre-validated form
`r = Kernel, s = 0, v = 1`, accepted because the Kernel is `msg.sender`. On
chain, `AgentPolicy` judges the Safe transaction's inner call (or every leg
of a MultiSend batch) against the owner's allow-list — so the consensus key,
even compromised, can only propose what the mandate allows
(`docs/ERC1271.md`).

## The demo

`olas_kernel_safe_demo.py` reproduces what a 1-agent service does to settle
one Safe transaction, **with open-autonomy's own code**, and swaps exactly
the two EOA steps:

| Olas step | open-autonomy function | here |
|---|---|---|
| app skill: safe tx hash | `GnosisSafeContract.get_raw_safe_transaction_hash` | as is (checked against `Safe.getTransactionHash`) |
| consensus payload | `payload_tools.hash_payload_to_hex` / `skill_input_hex_to_payload` | as is |
| `SignatureBehaviour` | `get_signature(safe_tx_hash)` (raw ECDSA) | **replaced:** `r = Kernel ‖ 0 ‖ 01` |
| `FinalizeBehaviour` | `get_raw_safe_transaction(sender_address = keeper)` | as is, keeper = Kernel |
| send | DecisionMaker + `eth_sendRawTransaction` | **replaced:** `agent-signer op send --json`, nonce pinned |
| `ValidateTransactionBehaviour` | `GnosisSafeContract.verify_tx` | as is (fails under 4337) + proposed event-based check |

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
git clone --depth 1 --branch v0.21.29 https://github.com/valory-xyz/open-autonomy
OPEN_AUTONOMY_SRC=open-autonomy .venv/bin/python olas_kernel_safe_demo.py          # build + simulate
OPEN_AUTONOMY_SRC=open-autonomy .venv/bin/python olas_kernel_safe_demo.py --send   # + submit, verify, retry
```

### Output on Base Sepolia (2026-10-20, agent key in a TROPIC01)

```
Safe 0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A owners=('0xEdB645B14e2f952C5784e34949b58F0826fBc9E9',) threshold=1 nonce=4
1. safeTxHash (Olas encode_typed_data) 0x9ac3fcfccd8c2cb4bc13db18a6844e5e6097dc30c090ccbaf21aa2f46fc89a95
   Safe.getTransactionHash(nonce=4)   0x9ac3fcfccd8c2cb4bc13db18a6844e5e6097dc30c090ccbaf21aa2f46fc89a95  match=True
2. hash_payload_to_hex -> 648 hex chars; decoded to=0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1 op=0
3. participant_to_signature[0xEdB645B14e2f952C5784e34949b58F0826fBc9E9] = 000…edb645b14e2f952c5784e34949b58f0826fbc9e9 000…000 01
4. execTransaction calldata 516 bytes, eth_estimateGas from Kernel = 63733 (accepted)
   control: same v=1 signature, sender 0x…dEaD -> gas 0 (0 = estimate reverted, as expected)
5. keeper send: agent-signer op send --agent … --target 0xd0b9…E52A --wei 0 --data 0x… --sponsored --json
   userOpHash 0xe0b6e0be05b8b1148b8904a03bec813db3fc82acd1a872411b41127a569756de nonce 0x27472733300…0002
   tx 0xd8bcb257868000bf3159dd84199cfcbc35e6e8cd972c3a4ec14bd6c38958d0a2
  outer tx: from 0x4337…1b62 (bundler) to 0x0000000071727De22E5E9d8BAf0edAc6f37da032 (EntryPoint v0.7)
  upstream GnosisSafeContract.verify_tx -> verified=False status=1
  event-based verify (proposed)          -> {'verified': True, 'success': True, 'failure': False}
   Safe nonce now 5 (staking activity = Safe nonce delta)
7. keeper retry with the recorded nonce -> exit 1: nonce 0x27472733300…0002 is already used: an operation with it was included
```

Since the audit fixes (AgentPolicy v4) the Safe transaction goes out as a
batch with an on-chain nonce assertion (`--safe-nonce`), and step 7 retries
*without* pinning the EntryPoint nonce — what a naive or compromised host
would do (same Safe, nonce 7 → 8, tx
`0x1a0f2fbb3eb34473415320a118946b9c41bdd763365ed12683f01ac71217b2c0`):

```
7. keeper retry, unpinned -> exit 1: … execution reverted, data: SafeNonceMismatch(safe, 7, 8)
   Safe nonce still 8: the call ran once```

What it shows:

- Olas computes the same safe tx hash the Safe does, and the Safe accepts
  the Kernel's `v = 1` signature only from the Kernel (the control from
  another sender reverts with GS025).
- The settlement lands through a bundler; the agent never held a key file.
- `verify_tx` decodes the *outer* transaction as `execTransaction`, so it
  rejects any relayed execution (4337, relayers, modules). Looking for the
  Safe's own `ExecutionSuccess(safeTxHash)` event verifies it regardless of
  transport — the first upstream PR we would propose.
- **Retries.** A `v = 1` signature does not commit to the Safe nonce, so an
  Olas keeper retry (timeout, late messages) could execute the inner call
  twice. The agent's mandate admits a Safe transaction only together with
  an on-chain assertion of the Safe nonce it was built for, so a retry of
  one that landed reverts — whatever the host does. Pinning the EntryPoint
  nonce (`--nonce`) additionally makes such a retry fail before sending.

## Integrating into open-autonomy and Pearl

`ADAPTATION.md` §7 has the file-by-file plan; in short, for 1-of-1 services
(all Pearl services) the change is local to `transaction_settlement_abci`
and `gnosis_safe/contract.py`, plus `ALL_PARTICIPANTS` vs Safe owner in
`autonomy deploy`. Proposed upstream, by likelihood:

1. **Transport-agnostic `verify_tx`** — verify by the Safe's
   `ExecutionSuccess(safeTxHash)` event; useful without us (relayers,
   modules, 4337, 7702).
2. **Safe owner ≠ consensus identity** — a `safe_owner_address` parameter
   (defaulting to `agent_address`); rotating the consensus key then needs no
   on-chain re-registration, for plain EOA services too.
3. **`signature_mode = prevalidated` + `tx_submitter = ledger_api:<id>`** —
   an extension point; the 4337 transport stays in agent-keys as a LedgerApi
   plugin, the way the HWI plugin plugs in today.

n-of-m services work with caveats (only the keeper's `v = 1` counts; others
need `approveHash`, which `AgentPolicy` would have to recompute) —
`ADAPTATION.md` §2.3, §3.2.

## Found on the way (verified in code, not reproduced)

1. `CheckTransactionHistoryBehaviour` compares the **Safe** nonce with the
   keeper's **EOA** nonce: `mutable_params.nonce` comes from
   `raw_transaction.body["nonce"]` (`behaviours.py:252`, set from the
   keeper's transaction count in `gnosis_safe/contract.py:480`) and is
   compared with `safe_nonce` (`behaviours.py:575`).
2. `EthereumHWICrypto` cannot be loaded into an agent's `Wallet`
   (`wallet.py:62` reads `private_key`, the HWI crypto raises) — hardware
   keys exist for the owner CLI, not for agents.
3. `base_gas`, `safe_gas_price`, `gas_token`, `refund_receiver` enter the
   hashed payload but are not passed on execution or verification
   (`behaviours.py:291-308, 919-942`) — latent while skills use zeros.
