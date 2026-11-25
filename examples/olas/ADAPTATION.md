# Olas (Autonolas) → agent-keys: where to plug in a hardware Kernel owner
*Russian original: [ADAPTATION_ru.md](ADAPTATION_ru.md).*

The following repositories were read (paths below are relative to the root of each):

| Repository | Commit | Date | Version |
|---|---|---|---|
| `valory-xyz/open-autonomy` | `62033a2` | 2026-09-14 | 0.21.29 |
| `valory-xyz/open-aea` | `e2e8a83` | 2026-09-01 | 2.2.9 |
| `valory-xyz/olas-operate-middleware` (Pearl backend) | `1077ee7` | 2026-10-13 | — |
| `valory-xyz/autonolas-registries` | `cadf962` | 2026-10-16 | — |

For reference on `checkNSignatures`, `safe-global/safe-smart-account` at tag `v1.3.0` was used.

Legend: **[V]** — verified by reading the code (file:line) or by a run. **[I]** — inferred, not verified in code.

> **Summary in one paragraph.**
> A simple "agent EOA → Kernel" replacement in Olas **does not work**, and the contracts are not the problem. The contracts accept a Kernel: registries, Safe and staking do not require the agent instance or the owner to be an EOA (§4).
> The obstacle is that an Olas agent's **single secp256k1 key carries three roles**:
> - (1) consensus identity. Every ABCI payload is signed and verified by ecrecover against `payload.sender`;
> - (2) on-chain agent instance and Safe owner;
> - (3) keeper EOA, which itself sends `execTransaction` and pays gas.
>
> A Kernel can take over roles (2) and (3), but not role (1). So the right seam is **identity separation**:
> - the consensus key stays (unfunded, not an owner, holds no money);
> - the Safe owner and the agent instance become the Kernel;
> - in `transaction_settlement_abci` four points change: the "signature" (v=1 instead of ECDSA), the keeper's sender and transport (userOp instead of EOA tx), verification (Safe event instead of decoding the outer tx) and nonce/retries.
>
> For 1-of-1 services (all Pearl services) this is a small, localized patch. For n-of-m everything works, but with caveats, see §2.3.
> An open-aea Crypto plugin (option B) on its own is **not suitable**. Only a **LedgerApi plugin as transport** inside option A is suitable (§2.4).
> A demo on Base Sepolia, built from open-autonomy's own code, has already been partially run (§6).

> **Status on the agent-keys side (2026-10-20), updates §3.1, §6 and "Phase 0":**
> - `agent-signer op send --nonce <uint256>` and `nonce` in the JSON output are **done** (item 0.1, except
>   `logs`/`success` — the caller extracts the logs of its own userOp, see `examples/jinn`).
>   A retry with an already included nonce is rejected before sending ("already used").
> - **A full `--send` run was performed** on Base Sepolia, agent key in TROPIC01 (permission
>   `trs3`, AgentPolicy v3): a Safe tx built with open-autonomy functions was executed through the Kernel
>   (tx `0xd8bcb257868000bf3159dd84199cfcbc35e6e8cd972c3a4ec14bd6c38958d0a2`, Safe nonce 4 → 5);
>   upstream `verify_tx` → `False`, event-based check → `True`; a keeper retry with the recorded
>   nonce was rejected — no double execution. Output — `README.md`.
> - Bugs §8.1 and §8.3 were re-checked against the code (`behaviours.py:252,575`, `contract.py:480`;
>   `behaviours.py:919-942`).
> - 0.2 (`SafeNonceAssert`) and 0.3 (`approveHash` with hash recomputation) were not done.

---

## 1. How Olas signs and sends a Safe transaction today

### 1.1 The agent key in open-aea

**Key loading:**
- The agent gets its key from the file `ethereum_private_key.txt`, whose path is set in `private_key_paths` of aea-config. `Wallet` → `CryptoStore` calls `make_crypto(identifier, private_key_path, password)` for each ledger id (`aea/crypto/wallet.py:57-62`) **[V]**.
- `CryptoStore` **immediately reads `crypto.private_key`** (`wallet.py:62`) **[V]**.
- `EthereumCrypto.load_private_key_from_path` does `Account.from_key` (a keystore is allowed if a password is given) (`plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py:837-864`) **[V]**.

**Signatures:**
- `EthereumCrypto.sign_message(message, is_deprecated_mode)`: if `is_deprecated_mode and len(message)==32`, then `unsafe_sign_hash`, i.e. **raw ECDSA over a 32-byte hash**, v=27/28. Otherwise EIP-191 `encode_defunct` (`ethereum.py:866-883`) **[V]**.
- `sign_transaction` signs an EOA tx and returns `{raw_transaction, hash, r, s, v}` (`ethereum.py:885-898`, translator `ethereum.py:655-691`) **[V]**.

**Signing route:**
- Skill → `SigningMessage` → DecisionMaker → `wallet.sign_message/sign_transaction(ledger_id, …)` (`aea/decision_maker/default.py:156-216`, `aea/crypto/wallet.py:149-186`) **[V]**.
- The Crypto is selected by `ledger_id`; in practice this is `default_ledger_id` = `ethereum`.

**The `aea-ledger-ethereum-hwi` precedent:**
- The plugin is registered via the `aea.cryptos` / `aea.ledger_apis` entry points with a **separate** id `ethereum_hwi` (`plugins/aea-ledger-ethereum-hwi/setup.py:55-60`) **[V]**.
- Its `private_key`, `load_private_key_from_path`, `generate_private_key`, `encrypt` and `decrypt` raise `NotImplementedError` (`aea_ledger_ethereum_hwi/hwi.py:101-213`) **[V]**.
- It is used **only by the `autonomy` CLI** for owner/operator operations (`autonomy mint … --hwi`, `autonomy/cli/mint.py:80`; `OnChainHelper.get_ledger_and_crypto_objects`, `autonomy/chain/config.py:249-280`) **[V]**.
- It cannot be loaded into the agent runtime: `CryptoStore` touches `crypto.private_key` (`wallet.py:62`) and gets an exception **[V from code, not run]**.
- So **there is no hardware precedent for the agent in Olas**. There is only a precedent for the service owner.

### 1.2 The `transaction_settlement_abci` flow (same for 1 and n agents)

FSM: `RandomnessTransactionSubmissionRound → SelectKeeperTransactionSubmissionARound → CollectSignatureRound → FinalizationRound → ValidateTransactionRound → Finished`. Retry branches go through `SelectKeeper…B`, `CheckTransactionHistory`, `SynchronizeLateMessages`, `CheckLateTxHashes` (`skills/transaction_settlement_abci/rounds.py:632-805`) **[V]**.

| Step | Who | What exactly | file:line |
|---|---|---|---|
| 0. safe tx hash | **Application skill**, each agent on its own | `GnosisSafeContract.get_raw_safe_transaction_hash(to, value, data, operation, safe_tx_gas, …)`: EIP-712 `SafeTx` + domain `{chainId, verifyingContract}` for Safe ≥1.3.0. The nonce is taken from `Safe.nonce()` if not set. The hash, parameters and calldata are packed into `hash_payload_to_hex` and go through consensus as `most_voted_tx_hash`. Example: `funds_forwarder_abci/behaviours.py:71-100,143-151` | `contracts/gnosis_safe/contract.py:246-348`; `transaction_settlement_abci/payload_tools.py:91-188` **[V]** |
| 1. keeper | All | Deterministic-random selection from `participants − blacklisted` with a seed from the randomness round. The keepers list is serialized into consensus | `abstract_round_abci/common.py:166-200`; `transaction_settlement_abci/behaviours.py:356-434` **[V]** |
| 2. signature | **Each** agent | `SignatureBehaviour._get_safe_tx_signature`: `get_signature(safe_tx_hash_bytes, is_deprecated_mode=True)`, i.e. **raw ECDSA over safeTxHash, not eth_sign**. Safe verifies it with the `ecrecover(dataHash, v, r, s)` branch (`GnosisSafe.sol:297-299` v1.3.0). The signature (hex without `0x`) goes into `SignaturePayload` | `behaviours.py:772-815`; `abstract_round_abci/behaviour_utils.py:968-1004,1492-1516` **[V]** |
| 3. collection | Consensus | `CollectSignatureRound(CollectDifferentUntilThresholdRound)` waits for ≥ `consensus_threshold` distinct signatures. Threshold = `ceil((2n+1)/3)` unless set explicitly. The round **does not verify** the signatures | `rounds.py:256-263`; `abstract_round_abci/base.py:891-906,1860-1864`; `abstract_round_abci/utils.py:414-421` **[V]** |
| 4. packing | keeper (via contract_api) | `get_packed_signatures(owners=participants, signatures_by_owner)`: sorts `owners` by `str.lower`, concatenates 65-byte signatures **keyed by participant address** | `contract.py:350-364` **[V]** |
| 5. sending | **Keeper only** | `FinalizeBehaviour._sender_act`, then `_send_safe_transaction` → `get_raw_safe_transaction(sender_address=self.context.agent_address, owners=participants, …, nonce=mutable_params.nonce, old_price=…)`. Inside: `execTransaction(…, signatures)`, `from = keeper`, **EOA nonce = `get_transaction_count(keeper)`**, gas = `try_get_gas_pricing(old_price)` (repricing), `eth_estimateGas` **on behalf of the keeper** | `behaviours.py:818-951`; `contract.py:366-481` **[V]** |
| 6. EOA tx | keeper | `send_raw_transaction`: DecisionMaker → `EthereumCrypto.sign_transaction`, then ledger connection → `eth_sendRawTransaction`. The hash from the response is compared with `signed_tx["hash"]` | `behaviour_utils.py:1518-1623`; `open-aea/packages/valory/connections/ledger/ledger_dispatcher.py:385-418` **[V]** |
| 7. bookkeeping | keeper | `_get_tx_data`: stores `tx_hash`, the **EOA nonce** and gas parameters in `mutable_params` (to replace the tx at the same nonce). RPC errors are classified: INSUFFICIENT_FUNDS leads to blacklisting the keeper, INCORRECT_NONCE, ALREADY_KNOWN | `behaviours.py:165-283` **[V]** |
| 8. validation | All | `ValidateTransactionBehaviour`: `get_transaction_receipt(tx)`, then `GnosisSafeContract.verify_tx`. It **decodes `transaction.input` of the outer tx as `execTransaction`** of the Safe ABI, compares to/value/data/…/signatures and requires `"execTransaction" in decoded[0]` and `receipt.status` | `behaviours.py:445-510`; `contract.py:500-612` **[V]** |
| 9. history | All | `CheckTransactionHistoryBehaviour`: compares `Safe.nonce()` with `mutable_params.nonce`, iterates over its own tx hashes via `verify_tx`. For failed txs it calls `revert_reason`, i.e. a replay `eth_call(from=tx.from, to=tx.to, data=tx.input)` at block −1, and looks for GS026 ("nonce reused") | `behaviours.py:513-678`; `contract.py:614-650` **[V]** |
| 10. late messages | All | Late contract_api responses (raw tx) are cached and **resent** in `SynchronizeLateMessagesBehaviour` | `behaviours.py:699-769,953-966` **[V]** |

**Single-agent and multi-agent differ only in set cardinality:**
- In 1-of-1 the keeper is always the agent itself, the threshold is 1, there is one signature.
- In n-of-m the keeper is random, ≥`ceil((2n+1)/3)` signatures are collected, the Safe threshold = `service.threshold`. The registry requires `threshold ≥ ceil((2n+1)/3)` (`autonolas-registries/contracts/ServiceRegistryL2.sol:190-197`) **[V]**.
- The Safe owners are exactly the agents, since `participants` = `ALL_PARTICIPANTS` = on-chain `agentInstances` (§4.4).

### 1.3 Where else the same key is used (important for the seam)

| Role | How | file:line |
|---|---|---|
| Signing **every ABCI payload** | `_send_transaction` signs `payload.encode()` (EIP-191). `check_tx` and `deliver_tx` call `Transaction.verify`, which does `LedgerApis.recover_message(...)` and requires `payload.sender ∈ addresses` | `abstract_round_abci/behaviour_utils.py:~813-852`; `abstract_round_abci/base.py:284-296`; `abstract_round_abci/handlers.py:156-162,232` **[V]** |
| Round membership | `sender ∈ participants` / `accepting_payloads_from` | `abstract_round_abci/base.py:1416-1425,1688-1700` **[V]** |
| On-chain self-check | `my_address ∈ getAgentInstances(serviceId)`. In `registration_abci` only with `share_tm_config_on_startup=true`; in `identify_service_owner_abci` always | `registration_abci/behaviours.py:258-262,421-427`; `identify_service_owner_abci/behaviours.py:140-170` **[V]** |
| ACN (libp2p) | Certificate "agent key signs the ACN node pubkey" (`aea issue-certificates`); message addressing by `agent_address` | `open-aea/aea/cli/issue_certificates.py:125-175`; `registration_abci/behaviours.py:297-316` **[V]** |
| Tendermint validator | A **separate** ed25519 from `tendermint init` (`priv_validator_key.json`), bound to the agent via the `validator address → agent address` mapping | `autonomy/deploy/generators/localhost/tendermint/app.py:262`; `registration_abci/behaviours.py:321-325` **[V]** |

---

## 2. The integration seam

### 2.1 Option A: Safe owner and agent instance = Kernel, "signature" = v=1, keeper = `agent-signer op send`

**What is confirmed in Safe 1.3.0 (`contracts/GnosisSafe.sol`) [V]:**
- The `v == 1` branch takes `currentOwner = address(uint160(uint256(r)))` and requires `msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0`, otherwise `GS025` (`GnosisSafe.sol:286-291`).
- **Only the first `threshold` signatures** are processed (`for (i = 0; i < requiredSignatures; i++)`, `:255`). They must be in ascending owner order (`GS026`, `:301`).
- `nonce++` comes before signature verification (`:143-145`). `ExecutionSuccess(txHash, payment)` is emitted on success (`:49,186`).

**1-of-1 (all Pearl services, `threshold = len(agent_addresses) = 1`, see §5) — valid.**
- `signatures = r=Kernel ‖ s=0 ‖ v=1` and `msg.sender == Kernel` — exactly what agent-keys already does for Jinn.
- Verified by a run (§6): `get_raw_safe_transaction(sender=Kernel, signatures_by_owner={Kernel: v1})` from open-autonomy builds the calldata. `eth_estimateGas` **from the Kernel** passes (63 733 gas). The same signature from `0x…dEaD` reverts (estimate 0) **[V run]**.
- Signature order does not matter in 1-of-1.

**n-of-m with one Kernel among EOAs — valid, with caveats:**
- If the **keeper is the Kernel agent**, its v=1 counts because `msg.sender == Kernel`. The other `t−1` signatures are ordinary ECDSA. `checkNSignatures` accepts the mix, Safe does not limit the number of v=1 entries, only the correct owner order is required **[V `:255-301`]**.
- If the **keeper is an EOA agent**, the Kernel's v=1 entry **reverts with GS025** if it lands among the first `t` sorted entries. Today `get_packed_signatures` packs all collected signatures indiscriminately (`contract.py:355-363`) **[V]**. Possible ways out:
  - (a) the packer drops v=1 entries of owners ≠ sender. Then `t` ECDSA signatures from the others are needed, and the fault tolerance of the EOA part drops (n=4, t=3: all three EOAs are needed);
  - (b) the Kernel agent, at the signature step, does an on-chain `Safe.approveHash(safeTxHash)` (userOp). Then v=1 works with any keeper via `approvedHashes`. The cost is +1 userOp per Safe tx, plus a policy question (§3.2);
  - (c) not suitable: making the Kernel the permanent keeper, which breaks BFT keeper rotation (`behaviours.py:387-434`).
- ERC-1271 (v=0) would be the cleanest path for n-of-m: Safe itself would call `Kernel.isValidSignature`. But for the agent 1271 is **disabled**, and it is not needed — see §3.2.

**What breaks in `transaction_settlement_abci` if only the owner is changed [V for each item]:**
1. **Identity.** `get_packed_signatures(owners=participants, …)` sorts and keys by the addresses of **consensus participants**, not Safe owners (`behaviours.py:925,931`; `contract.py:355`). `sender_address=self.context.agent_address` (`behaviours.py:924`) serves as `from` for `eth_estimateGas`. If agent_address is the consensus EOA and the owner is the Kernel, the estimate reverts (control in §6).
2. **Signature.** `SignatureBehaviour` always calls ECDSA via the DecisionMaker (`behaviours.py:801-815`). For a Kernel a constant `r=Kernel,s=0,v=1` (not a signature) or `approveHash` is needed.
3. **Transport.** `_get_tx_data → send_raw_transaction` = DecisionMaker `sign_transaction` + `eth_sendRawTransaction` (`behaviours.py:211-217`; `behaviour_utils.py:1518-1623`). A Kernel cannot do EOA txs.
4. **Nonce/gas.** `mutable_params.nonce` is the **keeper's EOA nonce** (`contract.py:444-449,480`; `behaviours.py:252,268-281`). Repricing via `try_get_gas_pricing(old_price)` (`contract.py:456-465`). INSUFFICIENT_FUNDS leads to blacklisting the keeper (`behaviours.py:231-239`). All of this is EOA semantics. A Kernel's nonce lives in the EntryPoint; gas is userOp fields or a paymaster.
5. **Verification.** `verify_tx` decodes the **outer** tx as `execTransaction` (`contract.py:583-602`). With 4337 the outer tx is `EntryPoint.handleOps` from the bundler, so `verified=False` **always**. Verified on the real tx `0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16` (Jinn demo, Kernel → Safe v=1): upstream `verify_tx → verified=False, status=1`, event-based check `→ True` **[V run, §6]**.
6. **History/reverts.** `revert_reason` replays the outer tx `eth_call(from=bundler, to=EntryPoint, data=handleOps)` (`contract.py:631-650`). `handleOps` does not revert when the inner call fails **[I, EntryPoint v0.7 semantics]**, so the function throws `ValueError("…has not been reverted")`, and the GS026 path does not trigger. The failure indicator under 4337 is `UserOperationEvent.success=false` or the absence of `ExecutionSuccess(safeTxHash)`.
7. **Retries — the main danger, see §3.1.** v=1 with `msg.sender == owner` is **not bound to safeTxHash and nonce**, so the same calldata will execute at any subsequent nonce. Yet the Olas retry logic (keeper retry on PENDING `behaviours.py:412-421`, late messages `:699-769`) assumes that a retry either replaces the EOA tx at the same nonce or fails with GS026.
8. **Other:** `get_amount_spent` computes `tx.gasPrice × gasUsed` of the outer tx (`contract.py:727-750`). For a bundle this is meaningless (the bundle includes other parties' userOps, gas is paid by the paymaster).

### 2.2 Mandatory amendment to A: identity separation

A Kernel cannot sign an ABCI payload: `Transaction.verify` is ecrecover against `payload.sender` (`base.py:284-296`, `handlers.py:162`) **[V]**. Therefore the "agent_address = Kernel" option is impossible without rewriting consensus. We do this instead:

```
consensus key  (secp256k1, ethereum_private_key.txt, NOT owner, NOT instance, balance 0)
   ├─ ABCI payload signatures, membership in participants, keeper rotation
   ├─ ACN certificate, Tendermint validator → agent mapping
   └─ off-chain signatures of application skills (if any)  [I: depends on the application]
Kernel (ERC-4337, P-256 in TPM/TROPIC01, AgentPolicy)
   ├─ ServiceRegistry agent instance  (registerAgents)
   ├─ owner service Safe              (create(agentInstances, threshold))
   └─ keeper sending of execTransaction (v=1, msg.sender = Kernel)
```

A `participant (consensus addr) → safe owner` mapping is needed:
- **All** agents know it: they need to pack and verify correctly.
- Minimally — a skill parameter `safe_owner_address` (defaults to `agent_address`, backward compatibility).
- For n-of-m — an `owner` field in `SignaturePayload` (the payload protocol changes, version coordination across all agents of the service is needed).
- Forging the mapping is harmless to funds: someone else's v=1 entry gives GS025 and an ordinary FINALIZATION_FAILED. In terms of harm this is equivalent to a garbage ECDSA signature today, which `CollectSignatureRound` does not verify either (`rounds.py:256-263`) **[V]**.

### 2.3 Summary by service type

| Service | Works? | What is needed |
|---|---|---|
| 1-of-1, Kernel is the only agent (Pearl) | **Yes** | §2.2 + patches 2–7 from §2.1. Signature order does not matter |
| n-of-m, Kernel is one of the agents | **Yes, degraded** | + owner-aware packing (drop v=1 of owner ≠ sender). The Kernel actually "signs" only when it is the keeper; otherwise path (b) `approveHash` |
| n-of-m, all agents are Kernels | Only via `approveHash` | With keeper K1 only K1's v=1 is valid. The other t−1 Kernels must do `approveHash(h)` in advance (t−1 userOps per Safe tx) |

### 2.4 Option B: a custom open-aea Crypto/LedgerApi plugin. An honest assessment

**A Crypto plugin alone (modeled on hwi) — does not work:**
- The Crypto address = `agent_address`, and that is the consensus identity. **All** agents verify it with ecrecover via `LedgerApis.recover_message(identifier=default_ledger_id)` (`handlers.py:162`, `base.py:291-293`) **[V]**. A Kernel address cannot be obtained by ecrecover.
- One could set up a custom ledger id with its own `Helper.recover_message` (P-256 + key registry). But `default_ledger_id` also selects the contract ABI: `Contract.get_instance` takes `contract_interface[ledger_api.identifier]` (`aea/contracts/base.py:92`), and all `contract.yaml` files describe only `ethereum` **[V]**. The same id `ethereum` cannot be taken: the registry throws `Cannot re-register id` (`aea/crypto/registries/base.py:~191`) **[V]**. What remains is either forking `open-aea-ledger-ethereum` or patching all contracts. Plus the plugin is needed by **all** agents of the service.
- `sign_message(safe_tx_hash)` → constant v=1 — trivial, no hardware needed.
- `sign_transaction(tx_dict)` must return `{raw_transaction, hash, r, s, v}`. `send_raw_transaction` requires the hash from the ledger connection to match `signed["hash"]` (`behaviour_utils.py:1615-1621`) **[V]**. This is achievable only if the Crypto itself builds and signs the userOp and returns `userOpHash`. Then (1) the blocking hardware signature and the bundler call run **in the DecisionMaker thread**; (2) a `LedgerApi.send_signed_transaction` that sends `eth_sendUserOperation` is also needed; (3) a custom `get_transaction_receipt` by userOpHash is needed.
- `verify_tx` goes to web3 **directly** (`ledger_api.api.eth.get_transaction`, `contract.py:557`) and decodes `handleOps` — a plugin cannot get around this. So the contract has to be patched anyway.
- **Verdict:** B = fork of the base plugin + contract patch + the same retry problems. This is more work and more fragile than A.

**A LedgerApi-only plugin as transport inside A — a good seam:**
- The ledger connection selects the API class by `signed_transaction.ledger_id` (`ledger_dispatcher.py:99-115`). It runs synchronous handlers in an executor (`connections/ledger/base.py:104-111`) **[V]**. So a blocking `agent-signer op send` (up to 120 s) **does not block** the agent loop.
- An `ethereum_userop` plugin (entry point `aea.ledger_apis`, like hwi) with `send_signed_transaction(body={"to","value","data","nonce"?})` → spawn `agent-signer … --json` → return the **outer tx hash**. Then `get_transaction_receipt` and all subsequent requests via the regular `ethereum` work unchanged.
- No Crypto is needed for this id at all. `FinalizeBehaviour` builds `SignedTransaction(ledger_id="ethereum_userop", body)` itself and sends it via `_send_transaction_request` (`behaviour_utils.py:1033-1105`) **[V signatures]**.
- This plugin can be kept in the agent-keys repo: Olas only needs to accept a "transport strategy" in the skill (§7, PR3).

---

## 3. Security and correctness

### 3.1 Double execution due to v=1 (critical for Olas retries)
- In the EOA world a resend is either a **replacement** at the same EOA nonce (repricing, `contract.py:444-449`) or a GS026 revert: ECDSA signs the safeTxHash, which includes the Safe nonce.
- With a Kernel every send is a new userOp with a new EntryPoint nonce. A v=1 signature from `msg.sender` does not depend on `dataHash` (`GnosisSafe.sol:286-291`) **[V]**. Therefore **both** userOps can be included, and the inner call will execute twice, at nonce N and N+1.
- Olas paths that provoke this: keeper retry on PENDING (`behaviours.py:412-421`), retry after FINALIZE_TIMEOUT (`rounds.py:738,770`), resending late messages (`behaviours.py:722-741`) **[V]**.
- For thresholds > 1 with ECDSA signatures from the others, their signature protects. For 1-of-1 (Pearl) there is no protection.

Protections (both sides are needed):
1. **Pin the Kernel nonce per Safe tx.**
   - The keeper stores the userOp nonce in `mutable_params.nonce` (semantically this is the same "replacement by nonce"). Any resend of the same safeTxHash goes with the **same** EntryPoint nonce, so at most one will be included, and a retry after inclusion gives AA25.
   - An `agent-signer op send --nonce <uint256>` flag and `nonce` in the JSON output are needed.
   - Replacing a pending userOp with bumped fees is a standard bundler mempool rule **[I]**.
2. **On-chain nonce assertion.**
   - Kernel `executeBatch([SafeNonceAssert.check(safe, N), Safe.execTransaction(…)])`: a tiny helper reverts if `Safe.nonce() != N`. Then a retry at N+1 is impossible even if local state is lost.
   - AgentPolicy must allow this batch: the helper in the allow-list, 2 legs, the second parsed as now.
   - Checking the nonce directly in AgentPolicy validation is not possible: that is reading foreign storage, forbidden by ERC-7562 for unstaked entities **[I]**.

### 3.2 What AgentPolicy sees in Olas traffic
- Olas internal Safe txs: CALL or DELEGATECALL into MultiSend, `safe_gas_price = 0` (Finalize does not pass the Safe gas fields, `behaviours.py:919-942`) **[V]**.
- AgentPolicy allows DELEGATECALL into any allow-listed `(to, multiSend)` and requires every leg to be a CALL (`agent-keys/contracts/src/AgentPolicy.sol:197-201,207+`) **[V]**. So the full MultiSend 1.3.0 used by Olas skills can also be added (`funds_forwarder_abci` sends `DELEGATE_CALL` to `params.multisend_address`, `behaviours.py:143-150`) **[V]**. The address is set by the service config **[I]**.
- **Rejected by the policy (and this is correct):**
  - `termination_abci`: `removeOwner`/`swapOwner` via the Safe itself (`termination_abci/behaviours.py:297-430`) **[V]**. In Pearl this is covered by the RecoveryModule from the Master Safe (§5);
  - ERC-8004 `setAgentWallet` in Pearl: MultiSend with a `SignMessageLib.signMessage` leg = DELEGATECALL (`olas-operate-middleware/operate/services/protocol.py:2031-2077`; `open-autonomy/packages/valory/contracts/sign_message_lib/contract.py:73`) **[V]**. This should be done by the Kernel root path or the Master Safe.
- **`approveHash` for n-of-m (path b)** is a hole if allowed as is: the agent would approve any hash, and the policy does not see the preimage.
  - The right way: AgentPolicy accepts `Safe.approveHash(h)` only in a batch together with the SafeTx fields. The policy itself recomputes the EIP-712 hash (domain `chainId + safe`, a pure computation) and judges the inner `(to, selector)` against the allow-list.
  - This is ~1–2 days of Solidity on the agent-keys side **[I, design]**.
- A narrow 1271 for safeTxHash does not solve the same problem: from the hash the policy cannot see the call.

### 3.3 What stays on a software key (the consensus key)
- No money, not an owner, not an instance. Compromise allows voting in consensus on behalf of the agent: in 1-of-1 — proposing arbitrary payloads.
- **But** they can be executed only through Kernel → AgentPolicy (allow-list, value cap, budget, expiry). This is exactly the agent-keys trust boundary.
- In n-of-m, compromise of the consensus key gives no more than compromise of one agent does today (the BFT assumption), or even less: the key has no monetary authority.
- The ACN certificate is on this key too. Pearl does `add-key ethereum`, `add-key --connection` and `issue-certificates` with one and the same key (`olas-operate-middleware/operate/services/deployment_runner.py:379-403`) **[V]**. This is acceptable.

---

## 4. Registration, deployment, staking, consensus

### 4.1 ServiceRegistry / ServiceManager
- `ServiceRegistryL2.registerAgents` checks the manager, array lengths, state, slots and bond. The "instance ≠ operator" check is at `:439-441`, "instance not taken" at `:443-445`. **There is no EOA check** (`contracts/ServiceRegistryL2.sol:382-474`) **[V]**.
- `ServiceManager.registerAgents` adds `_checkAgentInstances`, which rejects only addresses ≤ `0xffff` (`contracts/ServiceManager.sol:169,447-453,460-479`) **[V]**.
- Caveat: registries HEAD may be newer than the deployed contracts. What is deployed on Base was not cross-checked **[I]**.

### 4.2 Multisig creation
- `GnosisSafeMultisig.create(owners, threshold, data)` → `setup(owners, threshold, …)` via `createProxyWithNonce` + singleton check (`contracts/multisigs/GnosisSafeMultisig.sol:104-128`) **[V]**.
- Safe `setupOwners` checks only `≠ 0`, `≠ SENTINEL`, `≠ this` and uniqueness. A contract owner is allowed (`safe-1.3.0/contracts/base/OwnerManager.sol:35-37`) **[V]**.
- `SafeMultisigWithRecoveryModule` is the Pearl default. It does the same and enables the RecoveryModule (`contracts/multisigs/SafeMultisigWithRecoveryModule.sol:70-99`) **[V from report + spot checks]**.
- `GnosisSafeSameAddressMultisig.create` (Safe reuse):
  - checks the proxy codehash;
  - **calls `multisig.call(payload)`**, where payload is an `execTransaction` with signatures of the current owners;
  - then compares `getOwners()` (in reverse order) and `getThreshold()` with instances and threshold (`GnosisSafeSameAddressMultisig.sol:~106-180`) **[V]**.
  - Here `msg.sender` for the Safe is the SameAddressMultisig contract itself. So if the current owner is a Kernel, its signature in the payload must go via the `approvedHashes` path: the Kernel, via the root path, does `approveHash(h)` in advance, then v=1. This is exactly how Pearl already does it with the Master Safe (`operate/services/protocol.py:2080-2098,2192-2213`) **[V]**.
- `RecoveryModule.recoverAccess` (service owner, `PreRegistration`) removes all agent owners via the module and puts the service owner in place via `swapOwner` (`contracts/multisigs/RecoveryModule.sol:232-276`) **[V]**. The owner type does not matter. Losing the hardware does not mean losing the Safe.

### 4.3 Staking
- On stake, `StakingBase` checks `numAgentInstances`, `threshold` (if set), `service.multisig.codehash == proxyHash` and agentIds (`contracts/staking/StakingBase.sol:880-913`) **[V]**. The owner type is not checked.
- `StakingActivityChecker.getMultisigNonces` = `IMultisig(multisig).nonce()` (`StakingActivityChecker.sol:36-39`) **[V]**. The Safe nonce increments on v=1 execution too (`GnosisSafe.sol:143`) **[V]**. Application checkers (mech requests etc.) count actions by `msg.sender == multisig`, and that does not change **[I, they are not in the repos read]**.
- Rewards go to the multisig, unchanged.

### 4.4 open-autonomy deployment
- `autonomy deploy from-token` takes `agentInstances` from the registry into `ALL_PARTICIPANTS`, and the multisig into `SAFE_CONTRACT_ADDRESS` (`autonomy/cli/helpers/deployment.py:338-358`; `autonomy/deploy/base.py:543-575`) **[V]**.
- It then requires the keys from `keys.json` to match `all_participants` (`autonomy/deploy/base.py:392-401`) **[V]**.
- With a Kernel instance there is no key with the Kernel address, and there cannot be. The deployment must put the **consensus addresses** into `ALL_PARTICIPANTS`, and pass the Kernel as a separate parameter (`SAFE_OWNER_ADDRESS`/mapping).

### 4.5 A separate key — what remains and whether it is acceptable
Exactly these remain:
1. **consensus secp256k1** (ABCI payloads, participants, ACN certificate);
2. **Tendermint validator ed25519** — same as today (`tendermint init`).

Neither holds funds, owns the Safe or is an on-chain instance. This is acceptable and matches the Jinn approach: an unfunded attestation key. Bonus: rotating the hardware key inside the Kernel does not change the agent instance. And rotating the consensus key does not require on-chain re-registration, only a new `ALL_PARTICIPANTS`. In Pearl today, changing the agent EOA = teardown and re-registration (`operate/services/manage.py:648-650`) **[V]**.

---

## 5. Pearl / olas-operate-middleware

### 5.1 Where the keys are [V]
**Agent EOA:**
- Created by `KeysManager.create`: `EthereumCrypto()` → V3 keystore under `OPERATE_USER_PASSWORD`, **or plaintext hex without a password** (`operate/keys.py:168-196`).
- Files `<OPERATE_HOME>/keys/<address>` and `.bak`, where `OPERATE_HOME = cwd/.operate` (`operate/constants.py:26-30`; `operate/cli.py:202-212`).
- One agent per service: `NUM_LOCAL_AGENT_INSTANCES = 1` (`operate/services/manage.py:105,294-297`).

**Handing over to the agent:**
- Host deployment (default): `keys.json` with an encrypted entry → `ethereum_private_key.txt` (0600) → `aea add-key --password … ethereum`, `--connection`, `issue-certificates` (`operate/services/service.py:631-721`; `operate/services/deployment_runner.py:333-403`).
- Docker/k8s: `keys.json` **in plaintext** (`get_decrypted`), then deleted (`service.py:481-553`).
- The password is passed to the agent as the argv argument `--password` or via stdin (`deployment_runner.py:656-691`).

**Master EOA:**
- Keystore `wallets/ethereum.txt` + encrypted mnemonic (`operate/wallet/master.py:993-1035`).
- **Master Safe**: owner = Master EOA (+ optional backup owner), threshold 1 (`operate/utils/gnosis.py:219-266`; `master.py:1207-1241`).

### 5.2 The chain
Master EOA → Master Safe (service owner) → mint (`threshold = len(agent_addresses) = 1`) → activate → `registerAgents(instances = agent_addresses)` → deploy via `SafeMultisigWithRecoveryModule` → stake. Usually this is **a single MultiSend tx of the Master Safe**, signed with ECDSA by the Master EOA (`manage.py:444-993`, `750,863,896-989`; `protocol.py:107-238,1409-1638`).

### 5.3 `gas_abstraction.py` — not about the agent
- EIP-7702 + ERC-4337 v0.8 + Circle Paymaster (gas in USDC) via the public Candide bundler, **only for the Master EOA** in funding runs (bridge/swap) (`operate/wallet/gas_abstraction.py:20-26,211-554`; usage `operate/funding_run/manager.py:83-89,185-198,1434-1450`).
- This is a precedent for "Pearl already knows userOps". It does not cover the Kernel or the agent path.

### 5.4 What replacing the agent EOA with a Kernel would affect [V locations, I estimates]
| Area | Locations | Change |
|---|---|---|
| Service model | `service.agent_addresses` (`manage.py:294-297`) — simultaneously the on-chain instance, the owner and the key file name | Split into `agent_account` (Kernel) and `agent_key` (consensus) |
| Registration | `manage.py:913-919,1124-1130`, comparison `manage.py:648-650` | instances = Kernel |
| Runtime env | `ALL_PARTICIPANTS = chain_data.instances` (`service.py:170-231,188-191`) | = consensus addresses + new `SAFE_OWNER_ADDRESS` |
| Middleware **itself signs with the agent key** | ERC-8004 `setAgentWallet` (`manage.py:1250-1271`); swap owner on terminate (`manage.py:1622-1636`, `protocol.py:998-1086`); `enableModule` on a legacy Safe (`manage.py:1701-1767`); claim → transfer (`manage.py:2299-2306`); withdrawal from the Safe (`operate/services/funding_manager.py:272-282`); drain agent EOA (`funding_manager.py:128-248`) | Kernel root path or Master Safe (`recoverAccess` already covers terminate, `manage.py:1456-1466,1689-1698`). Draining the EOA is not needed — the consensus key is empty |
| Funding | Initial funding of the agent EOA (`service.py:1416-1440`), top-up on agent request (`service.py:1499-1546`, `funding_manager.py:1383-1390`), gas before swap (`manage.py:1574-1620`) | Remove. Kernel gas goes through a paymaster or a deposit |
| Kernel keys | No equivalent | New manager: path to `agent-signer` and its config. Kernel root = Master Safe/Master EOA (design decision) |
| Recovery | `discard_all` + new keys (`operate/keys.py:202-234`; `operate/wallet/wallet_recovery_manager.py:172-182,495-500`) | Consensus key rotation without on-chain; hardware rotation — `permission rotate` |

---

## 6. Demo: the Olas path without the full stack, on Base Sepolia

File: `olas_kernel_safe_demo.py` (in this folder). It uses **open-autonomy code unchanged** and substitutes exactly two EOA steps.

| Olas step | open-autonomy function | In the demo |
|---|---|---|
| safeTxHash (application skill) | `GnosisSafeContract.get_raw_safe_transaction_hash` | As is. Cross-checked against on-chain `Safe.getTransactionHash` |
| consensus payload | `payload_tools.hash_payload_to_hex` / `skill_input_hex_to_payload` | As is |
| `SignatureBehaviour` | `get_signature(..., is_deprecated_mode=True)` | **Replaced:** `r=Kernel‖0‖01` |
| `FinalizeBehaviour` | `GnosisSafeContract.get_raw_safe_transaction(sender_address=Kernel, …)` | As is. `eth_estimateGas` from Kernel = on-chain check of v=1 |
| `send_raw_transaction` | DecisionMaker + `eth_sendRawTransaction` | **Replaced:** `agent-signer op send --target Safe --data … --sponsored --json` |
| `ValidateTransactionBehaviour` | `GnosisSafeContract.verify_tx` | As is (expectedly `False`) + the proposed event-based check |

Contracts are loaded via `Contract.from_dir`, as the AEA runtime does. First `gnosis_safe_proxy_factory`: it is imported by `gnosis_safe/contract.py:37`.

**Already run (read-only, public RPC `https://sepolia.base.org`, 2026-10-20) [V]:**
```
Safe 0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A owners=('0xEdB645B14e2f952C5784e34949b58F0826fBc9E9',) threshold=1 nonce=4
1. safeTxHash (Olas encode_typed_data) 0x9ac3fcfccd8c2cb4bc13db18a6844e5e6097dc30c090ccbaf21aa2f46fc89a95
   Safe.getTransactionHash(nonce=4)   0x9ac3fcfccd8c2cb4bc13db18a6844e5e6097dc30c090ccbaf21aa2f46fc89a95  match=True
2. hash_payload_to_hex -> 648 hex chars; decoded to=0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1 op=0
3. participant_to_signature[0xEdB645B14e2f952C5784e34949b58F0826fBc9E9] = 000…edb645b14e2f952c5784e34949b58f0826fbc9e9 000…000 01
4. execTransaction calldata 516 bytes, eth_estimateGas from Kernel = 63733 (accepted)
   control: same v=1 signature, sender 0x…dEaD -> gas 0 (0 = estimate reverted, as expected)
5. keeper send: agent-signer op send --agent … --target 0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A --wei 0 --data 0x… --sponsored --json
```
Verifier check on an existing Jinn demo tx (Kernel → Safe, v=1):
```
$ python olas_kernel_safe_demo.py --check-tx 0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16
  outer tx: from 0x43370277eCaAb8cb1F98622138Efc679F9aC3063 to 0x0000000071727De22E5E9d8BAf0edAc6f37da032
  upstream GnosisSafeContract.verify_tx -> verified=False status=1
  event-based verify (proposed)          -> {'verified': True, 'success': True, 'failure': False}
```
The full `--send` run was performed later — see the status at the top and `README.md`.

**Packages and environment [V]:**
- Python 3.10–3.14 (`python_requires=">=3.10,<3.15"`, `open-aea/setup.py:123`). The run was on 3.12.3.
- `pip install open-autonomy==0.21.29 open-aea-ledger-ethereum==2.2.9`. Pulls in `open-aea==2.2.9`, `web3==7.16.0`, `eth-account==0.13.7`, `hexbytes==2.0.0`. Plugin constraints: `web3>=7,<8`, `eth-account>=0.13,<0.14` (`plugins/aea-ledger-ethereum/setup.py:49-53`).

**Pitfalls:**
1. **The `open-autonomy` wheel contains the contracts** (`autonomy/data/contracts/gnosis_safe/contract.py`, identical to the repo), but **not the skills**. `payload_tools.py` is taken from a git clone (`OPEN_AUTONOMY_SRC`) or `autonomy packages sync`.
2. `GnosisSafeContract` cannot simply be imported: `contract_interface` is populated only by `Contract.from_dir`. And `gnosis_safe_proxy_factory` is needed first, otherwise `ModuleNotFoundError` **[V run]**.
3. `python3 -m venv` on Ubuntu without `python3.12-venv` fails. Workaround: `python3 -m venv --without-pip` + `get-pip.py`.
4. hexbytes 2.x: `.hex()` without `0x`. The demo normalizes this.
5. `chain_id` in contract_api messages is the **chain name** for the ledger connection. The dispatcher pops it (`open-aea/packages/valory/connections/ledger/contract_dispatcher.py:423-443`), and `get_raw_safe_transaction_hash` takes chainId from the RPC. In the demo it is passed explicitly.

---

## 7. Patch plan and estimate

### Phase 0 — agent-keys (our side)
0.1. `agent-signer op send`:
  - `--nonce <uint256>` (pin for idempotent retries, §3.1);
  - add `nonce`, `success`, `logs` of its own userOp to the JSON;
  - print `userOpHash` in the JSON error.

  ~1–2 days.

0.2. `SafeNonceAssert` (10 lines) + allowing the `[assert, execTransaction]` batch in AgentPolicy. Or consciously rely on 0.1 alone. ~1–2 days with forge tests.

0.3. (for n-of-m) `approveHash` with safeTxHash recomputation in AgentPolicy (§3.2). ~2 days.

0.4. LedgerApi plugin `open-aea-ledger-ethereum-userop` (Python, in the agent-keys repo). `send_signed_transaction` → spawn `agent-signer` → outer tx hash, classification of AA2x/AA3x errors into strings that Olas's `__parse_rpc_error` understands. ~2–3 days.

### Phase 1 — open-autonomy, 1-of-1 (file by file)
1. `packages/valory/contracts/gnosis_safe/contract.py`:
   - `verify_tx`: if the outer tx does not decode as `execTransaction` or `to ≠ safe`, look in the receipt for `ExecutionSuccess(safeTxHash)` from `contract_address` and the absence of `ExecutionFailure(safeTxHash)`. Recompute the expected `safeTxHash` from the parameters and the `safe_nonce` passed by the caller (`contract.py:500-612`);
   - `revert_reason` for failure: `UserOperationEvent.success` / `ExecutionFailure` instead of replay (`:614-650`);
   - `get_packed_signatures(owners, signatures_by_owner, sender=None)`: the key is the **Safe owner**; drop v=1 entries of owner ≠ sender (without `approvedHashes`) (`:350-364`);
   - new `get_safe_exec_calldata` — calldata only, without EOA nonce and gas.
2. `packages/valory/skills/transaction_settlement_abci/models.py`: parameters `safe_owner_address` (defaults to `agent_address`), `signature_mode: ecdsa|prevalidated`, `tx_submitter: eoa|ledger_api:<id>`, a higher `finalize_timeout` for userOps.
3. `…/behaviours.py`:
   - `SignatureBehaviour._get_safe_tx_signature` (`:801-815`): with `prevalidated` return `r=owner,s=0,v=1`, without the DecisionMaker;
   - `FinalizeBehaviour._send_safe_transaction` (`:911-951`): `sender_address = safe_owner_address`, `owners` = Safe owners; with `ledger_api:<id>` — `SignedTransaction(ledger_id=id, body={to: safe, data, value: 0, nonce: pinned})` → `_send_transaction_request`;
   - `_get_tx_data` (`:165-283`): a branch without EOA nonce and gas; pinned userOp nonce in `mutable_params.nonce`;
   - `_check_tx_history` (`:554-654`): compare the Safe nonce with the **Safe nonce**, not with the EOA nonce (this is also a bug, §8.1); events instead of GS026 replay;
   - `SynchronizeLateMessagesBehaviour` (`:722-741`): for userOps **do not resend**, instead reconcile by the pinned nonce.
4. `…/rounds.py`: the hash format (`TX_HASH_LENGTH = 66`, `payloads.py:30`) does not change if the transport returns the outer tx hash. `fsm_specification.yaml` is not touched.
5. `registration_abci/behaviours.py:258` and `identify_service_owner_abci/behaviours.py:161`: check `safe_owner_address ∈ agentInstances`, not `agent_address`.
6. `autonomy/deploy/base.py:392-401,543-575` and `autonomy/cli/helpers/deployment.py:338-358`: `ALL_PARTICIPANTS` = consensus addresses from `keys.json`; a new override `SAFE_OWNER_ADDRESS` from on-chain instances.

Test: e2e on Base Sepolia or an anvil fork with a single-agent service (for example, `funds_forwarder_abci` or `test_abci`) and a Kernel owner.

### Phase 2 — n-of-m
7. `SignaturePayload` + an `owner` field (`payloads.py`) and a participant → owner mapping in `SynchronizedData`. This is a wire-format change: all agents of the service must upgrade simultaneously.
8. Path (b): `SignatureBehaviour` for a Kernel agent that is not the keeper sends `approveHash` (requires 0.3).
9. Tests: mixed 3-of-4 and keeper rotation.

### Phase 3 — Pearl
10. Splitting `agent_addresses` (§5.4), Kernel registration, `SAFE_OWNER_ADDRESS` in env, disabling agent EOA funding.
11. Moving the "middleware signs with the agent key" locations to the Kernel root path or the Master Safe.
12. `agent-signer` configuration. UI flow for binding the hardware.

### Estimate (honest)
| Phase | Duration |
|---|---|
| 0 (our side) | 1–1.5 weeks |
| 1 (1-of-1 PoC on an open-autonomy fork, without Pearl) | 1.5–2.5 weeks. The main risks are retry semantics (§3.1) and the 100% coverage requirement in open-autonomy CI |
| 2 (n-of-m) | +2–3 weeks, including agreeing the payload protocol change with Valory |
| 3 (Pearl) | 2–4 weeks. The middleware is large: `manage.py` 2535 lines, `protocol.py` 2275 |
| **Total** | **~6–10 weeks**. A demonstration 1-of-1 on one service without Pearl — ~3 weeks including phase 0 |

### What to propose upstream (Valory), in decreasing order of likelihood
- **PR1 "transport-agnostic verify_tx"** (`gnosis_safe/contract.py`). Verification by `ExecutionSuccess(safeTxHash)` with a fallback to the old decoding, plus the §8.1 fix.
  - Useful even without us: relayers, modules, 4337, 7702 wrappers.
  - Low risk, backward compatible. **The best first PR.**
- **PR2 "Safe owner ≠ consensus identity"**. A `safe_owner_address` parameter (defaults to `agent_address`), owner-keyed packing, fixes to the two registration checks and `autonomy deploy`.
  - Justified by the fact that the consensus signature and the Safe signature are different authorities. Rotating the consensus key without on-chain re-registration is a benefit for ordinary EOA services as well.
- **PR3 "signature_mode=prevalidated + tx_submitter=ledger_api:<id>"**. A sending strategy via a LedgerApi plugin by id.
  - The 4337 plugin itself stays with us; Olas gets only an extension point. This is exactly how the hwi precedent is structured (entry points).
  - Mandatory part: pin the nonce or forbid blind resending with `prevalidated`.

---

## 8. Upstream side findings (verified by reading code)

1. **`CheckTransactionHistoryBehaviour` compares the Safe nonce with the keeper's EOA nonce.**
   - `mutable_params.nonce` is filled from `raw_transaction.body["nonce"]` (`transaction_settlement_abci/behaviours.py:252,279`). And that is the keeper's `get_transaction_count(sender)` (`gnosis_safe/contract.py:444-449,480`), which the docstring `models.py:81-85` also confirms.
   - But `_check_tx_history` does `if safe_nonce == self.params.mutable_params.nonce: … return NOT_VERIFIED` ("Safe nonce is the same as the nonce used in the transaction") (`behaviours.py:574-582`) **[V]**.
   - If the numbers coincide by chance, the history is not checked. Non-keepers have `mutable_params.nonce = None`, and they always go into the full check **[I: the practical effect is weak, not reproduced]**.
2. **`EthereumHWICrypto` cannot be loaded into the agent's `Wallet`.** `CryptoStore` reads `crypto.private_key` (`open-aea/aea/crypto/wallet.py:62`), and HWI raises `NotImplementedError` (`aea_ledger_ethereum_hwi/hwi.py:101-109`) **[V code, not run]**. For the `autonomy … --hwi` CLI this is not a bug, but a "hardware agent" via hwi is impossible in principle.
3. **SafeTx fields are lost between the hash and execution.** `hash_payload_to_hex` carries `base_gas`, `safe_gas_price`, `gas_token`, `refund_receiver` (`payload_tools.py:91-164`). But `FinalizeBehaviour` and `_verify_tx` pass only `safe_tx_gas` and `operation` to the contract (`behaviours.py:291-308,919-942`) **[V]**. If an application skill signs a hash with non-zero fields, execution will give GS026. Currently skills use zeros, so the bug is latent.

---

## 9. What was verified and what was inferred

**Verified [V]:**
- By reading: the whole `transaction_settlement_abci` flow (rounds, behaviours, payload tools); `GnosisSafeContract` (hash, packing, raw tx, verify, revert reason, nonce); the `EthereumCrypto` signature (deprecated mode = `unsafe_sign_hash`); DecisionMaker/Wallet; the ledger connection (API selection by ledger id, executor); the hwi plugin and its use only in the CLI; signing and verification of ABCI payloads; on-chain registration self-checks; ACN certificates; the Tendermint validator key.
- Registries: L2 `registerAgents` and `ServiceManager._checkAgentInstances`, `GnosisSafeMultisig`, `GnosisSafeSameAddressMultisig`, `RecoveryModule`, `StakingBase`, `StakingActivityChecker`.
- Safe 1.3.0: `checkNSignatures` (v=1, order, first `threshold`), `nonce++`, events, `OwnerManager`.
- Pearl: keys, deployment, places that sign with the agent key, `gas_abstraction`. Collected by a subagent, key quotes spot-checked (`keys.py:168-182`, `manage.py:294-297,913-919,1250-1271`, `deployment_runner.py:379-403`, `protocol.py:173-194,2060-2077`, `gas_abstraction.py:20-26`).
- AgentPolicy: DELEGATECALL into allow-listed `(to, multiSend)`.
- By a run on Base Sepolia (read-only): the Olas safeTxHash matches on-chain; `eth_estimateGas` from the Kernel with v=1 passes, from a foreign address it reverts; upstream `verify_tx` gives `False` on a 4337 tx, the event-based check gives `True`.

**Inferred [I]:**
- `handleOps` behavior when the inner call reverts and, as a consequence, `revert_reason`.
- userOp replacement rules in the bundler mempool.
- ERC-7562 restrictions on reading the Safe nonce during validation.
- That the registries deployed on Base match HEAD.
- Application activity checkers and off-chain signatures of specific Olas applications (trader, optimus, etc.) — they are not in the repos read.
- Effort.
- The full `--send` demo run was not performed (TROPIC01 is needed).
