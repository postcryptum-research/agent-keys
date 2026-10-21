# Jinn (Jinn-Network/mono) → TPM_sign: key analysis and adaptation design
*Russian original: [ADAPTATION_ru.md](ADAPTATION_ru.md).*

Analysis of `Jinn-Network/mono`, branch `next`, commit `a981363` (2026-10-20). All paths below are relative to the root of that repository.
Legend: **[V]** — verified by reading the code (file:line), **[I]** — inference/knowledge without direct verification in this repo.

> **Status on the TPM_sign side (2026-10-20), updates §3 and §5 "Phase 0":**
> - **M1 is implemented** in `AgentPolicy` v3 (`contracts/src/AgentPolicy.sol`, Base Sepolia
>   `0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24`); a separate `SafeExecPolicy` module was not needed:
>   an `(safe, execTransaction)` entry in the allow-list enables decoding of the Safe transaction; the inner
>   `(to, selector)` is checked against the same allow-list, value against the same limit and budget;
>   `gasPrice ≠ 0` (refund) is forbidden; nested Safes are forbidden; DELEGATECALL is allowed only into the
>   allow-listed `(MultiSendCallOnly, multiSend)`, and every leg of the batch must be a CALL
>   that passes the allow-list (leg values are summed). Safe self-admin (`addOwner`, `enableModule`,
>   `setGuard`) is rejected until the owner adds it to the allow-list. 44 forge tests on a real
>   Safe v1.4.1 + MultiSendCallOnly, each protection verified by mutation.
> - Differences from the proposed M1: the allow-list is shared between direct calls and calls through the Safe (not
>   a separate per-Safe one); the signature form is not checked — and it is not needed: without 1271 and without an
>   allow-listed `approveHash`, the Safe will accept only `v = 1` from `msg.sender == Kernel`.
> - `agent-signer op send --json` exists; the logs of its own userOp are sliced by the adapter
>   (`src/kernelSafeBroadcaster.ts`, `userOpLogs`).
> - Verified on Base Sepolia: Safe v1.3.0 `0xd0b972a8…E52A` with Kernel as its sole owner;
>   from a key in TROPIC01 under v3, a single call and a MultiSendCallOnly batch through the Safe went through,
>   `addOwner` was rejected by the policy (`README.md`, Run section).

> **First patch series (2026-10-21):** Phase 1 items 1–5 (and the transport of item 8) as three
> commits on `next` `151a464aa` — [`patches/`](patches/), described in [`README.md`](README.md#integrating-into-jinn-the-patch-series-first-version).
> The §5 "side finding" is confirmed and fixed there (patch 0001).

---

## 1. How Jinn holds and uses keys (summary)

### 1.1 Storage and derivation
- One BIP-39 mnemonic per operator, encrypted with a V3 keystore (scrypt) under the index-0 key + XOR obfuscation of the mnemonic with that key: `operator/src/earning/wallet.ts:40-105` **[V]**. File `~/.jinn-client/earning/master_keystore.json` (`operator/src/earning/store.ts:5,23`) **[V]**.
- Password: `JINN_PASSWORD` / `--password-fd` / **an auto-generated password file next to it** (`operator/src/cli/password.ts:6,111-124`, `operator/src/earning/password-file.ts`) **[V]** → in practice the key at rest is protected only by file permissions.
- Derivation `m/44'/60'/0'/0/{i}`: index 0 = **master** (funder), 1+ = **agent EOA** per service (`wallet.ts:20,32,118-127`) **[V]**.
- The daemon decrypts the mnemonic at startup and holds the agent's raw private key in memory (`operator/src/main.ts:1306-1340`), handing it out as `agentEoaPrivateKey`/`pk` to MechAdapter, harnesses, envelope/capture signing, SolverNet, corpus, legacy bridge (`main.ts:1422,1440,1552,1676,1753,1790,1839,2007`) **[V]**.
- Separate keys: the Hyperliquid API wallet — its own secp256k1 key in `<implStateDir>/api-wallet.json` (0600) (`operator/src/harnesses/impls/claude-mcp-hyperliquid/api-wallet.ts:90-108`) **[V]**; "native" role keys — Ed25519 in the encrypted store `@jinn-network/trust-authoring` (`operator/src/daemon/role-identities.ts:1-12,121`) **[V]**.

### 1.2 The daemon's "Signing HTTP API" — effectively absent
- `ARCHITECTURE.md:240` claims that the runner and MCP "reach signing operations through the daemon's HTTP API". The route list (`operator/src/api/*`) contains no sign/tx endpoint at all; there is only `/api/admin/claim-rewards` (master tx) and the like **[V]**. The MCP server "wraps CLI command modules directly" (`operator/src/mcp/operator-server.ts:9`) — i.e. the MCP tx verbs decrypt the keystore themselves **[V]**.
- The intended "scoped signer" (`operator/src/harnesses/capability/scoped-signer.ts:76-131`) has a `(chainId, to, selector)` allow-list + an allow-list of EIP-712 domains, but `sendAllowedCall` **throws** "signing is wired in the daemon plan" (lines 126-129), and `createScopedSigner` is never called anywhere **[V]**. This matches our AgentPolicy model 1:1 — a natural integration point (see §2).

### 1.3 All signing sites

**On-chain through a Safe (agent EOA = sole owner of a 1/1 Safe):**

| Site | What is signed | Through our account? |
|---|---|---|
| `packages/marketplace/venue-base/src/broadcast/safe-broadcaster.ts:228-266` (`createSafeBroadcaster.executeInner`) | `signMessage(safeTxHash)` → eth_sign v+4 (lines 96-103), then EOA tx `Safe.execTransaction` (line 259). The single broadcaster for all venue writers: claim (`writers/claim.ts:141`), settlement (`writers/settlement.ts:199,383` — **MultiSend DELEGATECALL**, op=1), lifecycle (`writers/lifecycle.ts:43,52,64,83`), deliver (`deliver-leg.ts:84`), verdict (`verdict.ts:495,539,580`), posting (`safe-broadcaster.ts:336`) | Yes — replace with v=1 + `agent-signer op send --target Safe` |
| `packages/marketplace/venue-base/src/broadcast/stuck-nonce.ts:52` | EOA self-tx to evict a stuck nonce | Meaningless for Kernel — disable |
| `operator/src/adapters/mech/direct-safe-broadcaster.ts:152-179` | same (eth_sign v+4 + `writeContract execTransaction`), for CLI verbs (`cli/execution-context.ts:277`, `cli/commands/solver-plugins.ts:238,298`) | Yes |
| `operator/src/adapters/mech/safe.ts:116-157` `executeSafeTransaction` | only delegates to `VenueBroadcaster.execute` | Automatically, if the broadcaster is ours |
| `operator/src/adapters/mech/contracts.ts:224,400,544,1202` | createTask, claimTask, claimDelivery, deliverToMarketplace through the Safe | Automatically (through the broadcaster) |
| `operator/src/erc8004/reputation.ts:505` | giveFeedback/appendResponse/revokeFeedback through the Safe | Automatically |
| `operator/src/erc8004/plugin-registry.ts:250` | setMetadata through the Safe | Automatically |
| `operator/src/earning/safe-adapter.ts:222-292` `executeSafeTxBatch` | Safe SDK (protocol-kit) with raw `signerKey`: `signTransaction` + `executeTransaction` | Rewrite: MultiSendCallOnly + execTransaction v=1 |
| `operator/src/earning/safe-adapter.ts:298-438` `executeSafeTxDirect` | `signMessage(safeTxHash)` v+4 (lines 349-357) + `sendTransaction` (line 407) | Yes |
| `operator/src/daemon/native-base-sepolia-infrastructure.ts:1684-1702` | **v=1** `encodePreValidatedSignature` — but only for `estimateContractGas`; the actual send goes through `executeSafeTransaction` | Yes |

> Important: `buildSafeSignature` (v=01) in `operator/src/adapters/mech/safe.ts:17` and `packages/marketplace/binding/src/venue/safe.ts:75` is currently **not used anywhere for sending** — Jinn sends eth_sign signatures (v+4) everywhere. The pre-validated form (`r = owner, s = 0, v = 1`) is exactly what Kernel needs: Safe 1.3.0 `checkNSignatures` with v==1 accepts `msg.sender == owner`. The same technique is in the vendored stOLAS: `contracts/src/vendor/stolas/ExternalStakingDistributor.sol:~389-392` (`abi.encodePacked(r, bytes32(0), uint8(1))` with `r = address(this)`) **[V]**.

**On-chain directly from the agent EOA:**

| Site | Call |
|---|---|
| `operator/src/earning/bootstrap.ts:1884` | ERC-8004 `IdentityRegistry.register("")` (the NFT is owned by the agent EOA) |
| `operator/src/earning/agent-wallet-binding.ts:285,296` | `account.sign(SafeMessage(AgentWalletSet digest))` (raw ECDSA, verified by the Safe via ERC-1271) + `IdentityRegistry.setAgentWallet(agentId, safe, deadline, sig)` |
| `operator/src/erc8004/identity.ts:680` | `IdentityRegistry.setMetadata` (per-execution anchoring) |
| `operator/src/erc8004/validation.ts:145,185` | `validationRequest` / `validationResponse` |
| `operator/src/solvernets/daemon-init.ts:223` | metadata publisher (IdentityRegistry) |
| `operator/src/earning/bootstrap.ts:2114,2153` | self-bond: top-up Safe, deploy Safe (protocol-kit deployment tx) |
| `operator/src/earning/bootstrap.ts:2219-2463` | self-bond: create/activate/registerAgents/deploy/approve/stake via `executeSafeTxBatch`/`executeSafeTxDirect` |
| `operator/src/earning/bootstrap.ts:1749` | mech `MechMarketplace.create` through the Safe (`executeSafeTxDirect`) |
| `operator/src/earning/orphan-sweep.ts:175,251,284`, `withdraw/run-withdraw-plan.ts:150` | sweep/withdraw from the agent |
| `operator/src/earning/migrate-agent-id.ts:226`, `earning/steps/fleet-identity-register.ts:43` | identity migrations/registration |

**On-chain from the master EOA (index 0):** stOLAS `distributor.stake(..., agentInstance)` (`bootstrap.ts:1626`), funding the agent/Safe (`bootstrap.ts:1729,2085`, `daemon/balance-topup-loop.ts:102,135`), `checkpoint()` (`main.ts:2393`), reStake (`bootstrap.ts:2709`, `adapters/mech/contracts.ts:120`, `daemon/degraded-recovery.ts:177`), retire `unstakeAndWithdraw` (`earning/fleet-retire.ts:76`), withdraw (`withdraw/run-withdraw-plan.ts:204,240`) **[V]**.

**Off-chain signatures:**

| Site | Scheme | Who verifies |
|---|---|---|
| `operator/src/harnesses/engine/signing.ts:40-62` `signCanonical` | raw secp256k1 over keccak256(canonical JSON), without EIP-191 | `recoverAddress` == `signer`/`creator.agentEoa`: `harnesses/impls/prediction-v0-evaluator/checks/integrity.ts:96`, `conformance/checks/hash-signature.ts:59`, `solver-types/_swe-rebench-v2-verifier-facts.ts:488` |
| `operator/src/tasks/signing.ts:8` `signTaskV1` (calls: `adapters/mech/adapter.ts:505`, `requester-adapter.ts:277`, `cli/commands/tasks.ts:840`, `solver-types/*-auto.ts`, `swe-rebench-v2.ts:430`) | task.v1, `signature.algo: 'secp256k1'` | see above |
| `harnesses/engine/envelope-assembly.ts:128`, `captures/publish.ts:313`, `trajectory/emit.ts:122`, evaluator impls (`prediction*-evaluator/index.ts:262/265`, `portfolio-v0-evaluator/index.ts:237`), `packages/layer/src/publish.ts:1708`, `publish-skill.ts:226` | `signCanonical` | ecrecover |
| `operator/src/auth/erc8128.ts:77-85` `createPrivateKeyHttpSigner` | ERC-8128 (RFC 9421 + EIP-191) | `ethVerifyMessage` (line 63) — **plain ecrecover via viem `verifyMessage`, without ERC-1271**; used only in `api/server.ts:644` for `POST /artifacts` when `requireAuth`. The client-side signing (`signRequestWithErc8128`) is **never called anywhere** **[V]** |
| `operator/src/daemon/trust-keys.ts:22` `deriveLegacyBridgeSigner` | synchronous raw secp256k1 with the same agent key (legacy execution envelope) | ecrecover |
| `operator/src/solvernets/manifest.ts:174` | EIP-191 (`recoverMessageAddress`) — the launcher manifest | ecrecover |
| Native announcements/discovery/submissions: `daemon/composition-root.ts:2302`, `daemon/native-signed-source.ts:885`, `native-requester/requester.ts:796,1173,1201`, `packages/discovery/serve/src/entry-signing.ts:39` | **Ed25519 DSSE** with role keys (not the agent EOA) | DSSE verify + trust binding |
| Trust ceremony: `packages/trust/authoring/src/ceremony.ts:59-91` `performEoaCeremony`, called from `cli/commands/ceremony.ts:720,1019`, key — agent EOA (`earning/ceremony-custody.ts:153,172`) | SIWE EIP-191 by agent E over `[agent IRI, did:key, did:pkh:Safe]`; chain: role key ← ceremony ← E ← `Safe.isOwner(E)` | **ERC-1271 explicitly forbidden** (`spec/2026-08-07-native-identity-ceremony.md:132,217-225`) |
| Trust anchor: `packages/trust/authoring/src/anchor.ts:107-130` | tx with calldata = sha256 digest; the reader `daemon/native-base-sepolia-infrastructure.ts:1460-1490` requires `tx.to == anchor` and the digest in `tx.input` at an offset; `from` is not checked | — |
| Hyperliquid `harnesses/impls/claude-mcp-hyperliquid/mcp-tools.ts:266-347` `signHlAction` | EIP-712 "Agent", chainId 1337, with a separate API-wallet key | HL L1 (secp256k1 only) |

---

## 2. Integration seam

### 2.1 Verdict on the two options

**Option A — Kernel = agent instance and owner of the 1/1 service Safe, calls via `Safe.execTransaction` with v=1. VIABLE.**
- `ServiceRegistryL2.registerAgents` does not check that the agent instance is an EOA: only `agentInstance != operator`, "not taken", slots (upstream `autonolas-registries/contracts/ServiceRegistryL2.sol:424-462`, downloaded and read) **[V]**.
- stOLAS `_deployAndStake` creates a Safe with owner = distributor and does `swapOwner(..., agentInstance)` (`contracts/src/vendor/stolas/ExternalStakingDistributor.sol:349-381,440-462`) — an address of any type **[V]**. `RecoveryModule` changes owners via a module, without EOA checks **[V]**.
- Staking checks `service.multisig.codehash == proxyHash` (Safe 1.3.0 proxy), threshold, number of instances (`contracts/src/vendor/registries/staking/StakingBase.sol:769-790`) — not the owner type **[V]**.
- Mech: `isOperator(msg.sender)` == service multisig (`contracts/src/vendor/mech/OlasMech.sol:309-325`) **[V]**; Router V4: `_validateMechOperator(priorityMech, msg.sender)`, `reservation.party == msg.sender` (`contracts/src/staking/JinnRouterV4.sol:401,484,633`) **[V]** — all expect the Safe as `msg.sender`, which is preserved.
- Kernel accepts ERC-721 (`contracts/lib/kernel/src/Kernel.sol:173` in TPM_sign) **[V]** → the ERC-8004 NFT can be owned by Kernel.
- Bonus: rotating the agent key in Kernel **does not change the address** of the agent instance / Safe owner. Currently in Jinn, rotating the EOA = re-registering the service (`bootstrap.ts:1560-1592`, error `agent_already_bound … rotate the agent EOA`).

**Option B — Kernel instead of the Safe (itself as the service multisig). NOT VIABLE for the main loop.**
- The staking `proxyHash` is the codehash of the Safe proxy; a Kernel proxy will not pass (`UnauthorizedMultisig`, `StakingBase.sol:787-790`) **[V]**.
- The activity checker calls `IMultisig(multisig).nonce()` (`StakingActivityChecker.sol:38`, `staking/TaskActivityCheckerV3.sol:156`) **[V]** — Kernel has no such method; liveness = growth of the Safe nonce.
- Staking rewards go to the multisig (`StakingBase.sol:226`) **[V]**.
- Calling directly from Kernel (without the Safe) makes sense only for: ERC-8004 IdentityRegistry (register/setMetadata/setAgentWallet — an EOA calls it there today too), ValidationRegistry, and for the requester role — `createEoaBroadcastPort` (`packages/marketplace/binding/src/venue/eoa-broadcast.ts:83-120`, creator = the account itself) **[V]**.

**Bottom line:** a hybrid. Service work (claim/deliver/settle/verdict/createTask/reputation) goes through `Safe.execTransaction(v=1)` from Kernel. Identity calls (ERC-8004) go directly from Kernel. Bootstrap and admin go via Kernel's **root path** (owner key), not via the agent path.

### 2.2 Where to put a single interface
Jinn already has a port: `BaseVenueSafeBroadcaster` (`execute({to,value,data,logicalTx,operation}) → {txHash, blockNumber, blockHash, logs, alreadySettled}`, + `classify`, + `broadcastCreateTask`) — `packages/marketplace/venue-base/src/broadcast/safe-broadcaster.ts:40-78`. Its structural subset is `VenueBroadcaster` / `DirectSafeBroadcaster` in operator (`adapters/mech/safe.ts:76-86`, `direct-safe-broadcaster.ts:66-74`). All Safe writes already go through this port (the "single broadcaster per Safe" rule). Their design principle: "venue-base is signer-injection only" (`create-base-venue.ts:62-66`), and there is a comment about "remote-signer/hardware-wallet compatible" (`daemon/trust-keys.ts:11-12`).

Proposed hierarchy (new module `operator/src/signer/`):

```
AgentSigner (sendCall: {to,value,data,logicalTx,path:'agent'|'root'} → {txHash,userOpHash,blockNumber,blockHash,logs})
   └─ AgentSignerCli          — spawn `agent-signer op send --json` (§6)
KernelSafeBroadcaster implements BaseVenueSafeBroadcaster  — wraps execTransaction(v=1) → AgentSigner
agentSignerTransport (viem custom EIP-1193)                — eth_sendTransaction → AgentSigner (for direct calls: setMetadata, validation)
ScopedSigner.sendAllowedCall                               — finally "wire up" via AgentSigner (allow-list = AgentPolicy)
```

Injection points:
1. `createBaseVenue` (`packages/marketplace/venue-base/src/create-base-venue.ts:80`): add an optional `safeBroadcaster?: BaseVenueSafeBroadcaster` to `BaseVenueConfig`. If it is set, use it instead of `createSafeBroadcaster` and drop the `walletClient.account` requirement (line 62).
2. `operator/src/daemon/composition-root.ts:2246` — pass `KernelSafeBroadcaster` when `signer.kind === 'agent-signer'`.
3. `operator/src/cli/execution-context.ts:277`, `cli/commands/solver-plugins.ts:238,298` — instead of `createDirectSafeBroadcaster`.
4. Direct EOA calls (`erc8004/identity.ts:680`, `validation.ts:145,185`, `solvernets/daemon-init.ts:223`) — put the walletClient on `agentSignerTransport`. Then `writeContract`/`sendTransaction` go to the CLI, while `signMessage`/`signTypedData` fail explicitly.
5. Do not use `tx-retry.ts` (`viemSendTransactionWithRetry`, `withNonceLedger`, `evictStuckNonce`) for the Kernel path: an EOA nonce is meaningless for Kernel. Take serialization from `BroadcastLock.withSender(chainId, kernelAddress)`.

---

## 3. Security: allow-listing `Safe.execTransaction` blinds AgentPolicy

`AgentPolicy._decodeSingleExecute` sees only the outer `(target=Safe, selector=execTransaction, value=0)` (`TPM_sign/contracts/src/AgentPolicy.sol:109-152`). What a compromised agent key can then do:
- **Take over the Safe permanently.** `execTransaction(to=Safe, addOwnerWithThreshold/swapOwner)` adds its own EOA owner. stOLAS `MultisigGuard.checkAfterExecution` checks only the guard slot, modules and the operator's bond, **but not the owners** (`contracts/src/vendor/stolas/MultisigGuard.sol:~118-200`) **[V]**. Such an owner will survive revocation of the agent key in Kernel.
- **DELEGATECALL** (`operation=1`) into an arbitrary contract: writes to any Safe slots.
- **Draining Safe assets.** ETH/OLAS and staking rewards arrive at the multisig. The outer `value=0`, so budget/maxValuePerOp do not trigger.
- **Gas-refund drain.** `gasPrice>0, gasToken, refundReceiver=attacker`: the Safe pays a "refund" to the attacker.
- **Arbitrary exec from the mech.** `Mech.exec` with `onlyOperator` (`contracts/src/vendor/mech/lib/Mech.sol:107-120`) **[V]**. Through the Safe the mech can be emptied.
- Router abuse: createTask (spends the Safe's OLAS), release/forfeit of reservations.

### Protection options
**M1 (recommended): AgentPolicy understands the Safe wrapper.** A new policy module `SafeExecPolicy` (or a mode in AgentPolicy): for `target ∈ registeredSafes` and `selector == execTransaction`, decode the arguments and require:
- `operation == 0`, **or** `operation == 1 && to == MultiSendCallOnly 1.3.0` (`0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`). Decode each packed leg; each must have op byte == 0;
- for every inner call, `(to, selector)` ∈ a separate inner allow-list for this Safe; `to != Safe` (no self-admin), `to != Kernel`;
- count inner `value` against `maxValuePerOp`/`budget` (this is the Safe's ETH);
- `safeTxGas == baseGas == gasPrice == 0`, `gasToken == refundReceiver == 0`;
- `signatures` exactly 65 bytes, `r == account`, `s == 0`, `v == 1`.

Pure calldata decoding + reading the module's own storage keyed by `account` fits within the ERC-7562 rules. Works in both stOLAS mode and self-bond. Cost: ~2-4 days of Solidity + tests on the TPM_sign side.

Minimal inner allow-list for the main Jinn loop: Router V3/V4 `claimTask`, `createTask`, `claimDelivery`, `claimSolutionDelivery`, `prepareSolutionDelivery`, `claimEvaluation`, `claimVerdictDelivery`, `releaseAttempt`, `closeTask`, `refundUnusedTaskBudget`, `forfeitDeliveredReservation`; mech `deliverToMarketplace`; OLAS `approve(router, …)` (preferably with a spender restriction); ReputationRegistry `giveFeedback/appendResponse/revokeFeedback`; IdentityRegistry `setMetadata`. Source: `venue-base/src/writers/*.ts`, `verdict.ts`, `adapters/mech/contracts.ts` **[V]**.

**M2: Safe Guard.** **Impossible** in stOLAS mode: the guard slot is occupied by `MultisigGuard`, and its `checkAfterExecution` does `checkGuard(address(this))`, i.e. compares the slot with its own address and reverts if it is replaced (`MultisigGuard.sol:~140-215`) **[V]**. Possible in self-bond mode, but the guard sees `msgSender = Kernel` and cannot distinguish the root path from the agent path, so a separate admin bypass via a call to the guard itself is needed. Weaker than M1.

**M3: bypass the Safe and call targets directly from Kernel.** Impossible for the service loop (§2.1, B). Possible only for identity/validation and the requester role.

**In addition to M1:** perform bootstrap/admin (`addOwner`, `enableModule`, `MechMarketplace.create`, ServiceManager calls, `setGuard`) **only via the root path** (owner key). The agent path should not see them at all.

A side issue, on our side. Gas on the agent path is paid from Kernel's deposit, and `budget` in AgentPolicy does not account for it (only `value`). A compromised key can burn the deposit via `maxFeePerGas`. Fixed with `--sponsored` + `WhitelistPaymaster` with per-op caps.

---

## 4. Off-chain signatures without ERC-1271

| Signature | Breaks? | Why |
|---|---|---|
| task.v1 / `signCanonical` (envelopes, captures, trajectory, verdict manifests, layer publish) | **Yes** | Raw secp256k1 + `recoverAddress` == the address in the document. P-256 does not fit, nobody calls 1271 |
| ERC-8128 HTTP | **Yes**, but currently inactive on the client | Verification = ecrecover (`erc8128.ts:63`); 1271 is not supported |
| Legacy bridge signer (`trust-keys.ts:22`) | **Yes** | Synchronous raw secp256k1 |
| SolverNet manifest (EIP-191) | **Yes** | `recoverMessageAddress` |
| Trust ceremony (native) | **Yes, hard** | SIWE EIP-191 from E + `Safe.isOwner(E)`; the spec explicitly forbids 1271 (§2.3d) |
| Trust anchor tx | Partially | The reader requires `tx.to == anchor` and the digest in `tx.input`; a userOp hides the calldata inside `handleOps`. The sender is not checked, so the anchor can be sent by any gas-paying EOA |
| ERC-8004 `setAgentWallet` | Solvable on-chain | The signature is verified by the **Safe** (Safe 1271 → owners' `checkSignatures`) |
| Ed25519 DSSE (announcements/discovery) | No | Separate role keys; only their binding (ceremony) breaks |
| Hyperliquid | No | Separate API-wallet key; HL requires secp256k1, P-256 is impossible there in principle |

### Options
1. **ERC-8004 setAgentWallet without 1271 in Kernel.** Kernel (root path) calls `Safe.approveHash(safeMessageHash)`: an owner can call it directly. Then `setAgentWallet(agentId, safe, deadline, sig)` with `sig = r=Kernel, s=0, v=1`. In `checkNSignatures`, the v==1 branch accepts `approvedHashes[owner][hash] != 0`. Two userOps, zero off-chain signatures **[I: the exact CompatibilityFallbackHandler version on the Safe is not verified, Safe 1.3.0 logic]**. The `owner` field in the digest = Kernel (the NFT owner).
2. **A separate unfunded "attestation key" (secp256k1, software).** For task.v1/`signCanonical`/ERC-8128/legacy bridge/manifest. It holds no funds, is not a Safe owner, and is rotatable. Jinn verifiers compare the recovered address with the address **inside the same document** (`creator.agentEoa`/`signer`) and do not check it against the on-chain Safe owner **[V for integrity.ts:96; I — for all other verifiers]**. So the minimal patch is to substitute this key as the "agentEoa" in documents. It is desirable to bind it on-chain: Kernel writes `IdentityRegistry.setMetadata(agentId, "jinn.attestationKey", addr)`. Honestly: compromise of this key allows forging off-chain attestations (a reputational risk), but not money and not on-chain authority.
3. **A narrow 1271 in Kernel is not needed.** Jinn verifiers do not call 1271 at all (ecrecover), and the ceremony forbids it. For the only on-chain consumer (setAgentWallet), option 1 is enough. A "hash-allowlist 1271" does not work for ERC-8128: there is a unique nonce per request.
4. **P-256 as a second `algo`.** task.v1 already has `signature.algo: 'secp256k1'` (`operator/src/tasks/signing.ts:15`). One could add `algo: 'p256'` with the pubkey from ERC-8004 metadata and verification via `@noble/curves/p256` (or RIP-7212 on-chain). This is a Jinn protocol change in roughly 5 verifiers. Such signatures need a **separate** P-256 key in hardware (domain separation from the userOp key), and the CLI needs a `sign-digest` command.
5. **Trust ceremony (native mode) — a blocker, requires an amendment to the Jinn spec.** Proposal: a "tx-ceremony" — Kernel sends an on-chain op with the digest of the SIWE message `[agent, did:key, Safe]`. Proof: inclusion in a block + `UserOperationEvent.sender == Kernel` + `Safe.isOwner(Kernel)`. The spec's objection about 1271 mutability does not apply here: transaction inclusion is immutable, and they already read `isOwner` from chain state. The alternative without a spec change — a ceremony EOA as a second Safe owner. It is **rejected**: with threshold 1 it fully controls the Safe. The Ed25519 role keys could be held in TROPIC01 (Ed25519 is supported by the chip **[I — per the datasheet, not verified in TPM_sign]**); TPM/Secure Enclave cannot do Ed25519.

---

## 5. Patch plan (in order) and estimate

### Phase 0 — our side (TPM_sign), before Jinn
0.1 `agent-signer op send --json`: add `logs` (logs of only this userOp from `eth_getUserOperationReceipt` / the slice between `UserOperationEvent`s), `blockHash`, `nonce`, `success`. Print `userOpHash` in the JSON error (stderr already prints `userOpHash:` before waiting, `chain.rs:~347`). Preferably `--nonce-key`/`--nonce` for idempotent retries. ~1 day.
0.2 `SafeExecPolicy` (M1) + forge tests: self-call, delegatecall, refund, MultiSendCallOnly, inner allow-list, inner value in budget. 2-4 days.
0.3 Document that the root and agent paths use different Kernel v3 nonce keys **[I]**, and that parallel calls on the same path are serialized by the caller.

### Phase 1 — steady-state loop (service already bootstrapped, legacy mode)
1. `operator/src/signer/agent-signer-cli.ts` (new): spawn, parsing, error classification (§6).
2. `operator/src/signer/kernel-safe-broadcaster.ts` (new): `BaseVenueSafeBroadcaster` on top of `execTransaction(v=1)`. Includes `decodeSafeInnerRevert`, `classifyBroadcastError` → `alreadySettled`, a lock on the Kernel address, and a **ban on blind retries** (§6).
3. `packages/marketplace/venue-base/src/create-base-venue.ts:58-90`: optional `safeBroadcaster`, relax the assert on `walletClient.account`.
4. `operator/src/daemon/composition-root.ts:~2241-2260,2355`: broadcaster selection by config.
5. `operator/src/config.ts` + `config/native-sections.ts`: section `signer: { kind: 'keystore' | 'agent-signer', bin, config, account, sponsored }`.
6. `operator/src/main.ts:1305-1440`: with `agent-signer`, do not decrypt the agent key. `agentEoaAddress := kernel`, `createClients` → `agentSignerTransport`.
7. `operator/src/cli/execution-context.ts:259-285`, `cli/commands/solver-plugins.ts:238,298` → `KernelSafeBroadcaster`.
8. `operator/src/erc8004/identity.ts:640-690`, `validation.ts:130-200`, `solvernets/daemon-init.ts:223`: walletClient on the transport. Check that `viemSendTransactionWithRetry` does not try to track an EOA nonce for a json-rpc account; otherwise a separate path.
9. **Readers that decode the outer `tx.input` as `Safe.execTransaction`** — critical, and affects **other** operators who verify our transactions:
   - `packages/marketplace/venue-base/src/verdict.ts:322-345` (verdict verification by any party),
   - `operator/src/daemon/native-base-sepolia-infrastructure.ts:1379-1390` (settlement reader).
   With 4337 the outer tx is `EntryPoint.handleOps`. A decoder "handleOps → op.callData → Kernel.execute → Safe.execTransaction" (or a trace) is needed. Without an upstream PR, our verdict/settlement transactions will be "orphaned/not bound" for peers.
10. Off-chain: the attestation key (§4.2) instead of `agentEoaPrivateKey` in `signTaskV1`/`signCanonical`/`envelopeDeps`/`liveCapturePublisher`/`corpus`/`legacyBridgeSigner` (`main.ts:1676,1753,1790,1839,2007`, `adapters/mech/adapter.ts:462-505`, `requester-adapter.ts:240-277`, `cli/commands/tasks.ts:840`).
11. `daemon/balance-topup-loop.ts`: for Kernel either disable agent EOA top-ups, or fund the Kernel/paymaster deposit.

### Phase 2 — bootstrap and master
12. `earning/bootstrap.ts`: `stepStolasStake` passes `agentInstance = kernel` (lines 1609-1620). `stepDeployMech` (1702-1790) switches to the root path. In `stepRegisterAgent` (1816-…), `register` goes from Kernel, `setAgentWallet` via the approveHash+v=1 scheme. Self-bond steps (2048-2475): `initPredictedSafe/initDeployedSafe` (protocol-kit with `signerKey`) are replaced by a direct `SafeProxyFactory.createProxyWithNonce` + `execTransaction` v=1, `executeSafeTxBatch` by MultiSendCallOnly.
13. `earning/safe-adapter.ts`: kernel variants of `executeSafeTxBatch/Direct`.
14. `earning/agent-wallet-binding.ts:226-330`: a `bindAgentWalletViaApprovedHash` branch.
15. The master role onto the Kernel root path, or keep the master EOA in the keystore. Affects `bootstrap.ts:1626,1729,2709`, `main.ts:2393`, `fleet-retire.ts:76`, `withdraw/*`, `orphan-sweep.ts`, `daemon/degraded-recovery.ts:177`, `adapters/mech/contracts.ts:120`. If the stOLAS staking guard is enabled, the master must be whitelisted as a curating agent (`ExternalStakingDistributor.sol:614-621`), which means Kernel has to be added to the whitelist.

### Phase 3 — native mode
16. Ceremony spec amendment (tx-ceremony) + `packages/trust/core/src/ceremony.ts`, `daemon/native-trust-catalog.ts:159-183` + anchor via a gas-paying EOA (or a reader that understands handleOps). This depends on the Jinn team.

### Estimate (honest)
- Phase 0: 3-5 days (our side).
- Phase 1 (MVP: legacy mode, service bootstrapped manually or the old way): 2-3 weeks for one engineer, including tests on an anvil fork of Base Sepolia with a local bundler. The riskiest parts are item 9 (readers) and retry/idempotency semantics.
- Phase 2: another 1-2 weeks.
- Phase 3: from 1-2 weeks of code plus an indefinite amount of upstream spec review time.
- Total for a full port: roughly 5-8 weeks. Maintaining a fork is expensive: `next` is actively force-pushed (there was a forced update on fetch), `main.ts` is 2591 lines, `bootstrap.ts` is 2743. The realistic path is an upstream "signer injection" PR (items 3-4, 9) to Jinn: their venue-base already declares signer-injection-only.

### Side finding (not run, likely upstream bug)
`packages/marketplace/venue-base/src/writers/settlement.ts:33` — `DEFAULT_MULTISEND_ADDRESS = "0x40A2aCCbd92BCA938b02010E17A5b8929b49130"`. This is **39 hex characters**, the trailing `D` is cut off (the correct MultiSendCallOnly 1.3.0 is `…130D`, as in `contracts/scripts/deploy-stolas-l2.ts:85`). `multiSendAddress` is never passed anywhere (lines 91, 384). Hence, `settleRevisedSolutionDelivery` should fail on viem's address validation **[I]**.

---

## 6. TypeScript sketch of the adapter

```ts
// operator/src/signer/agent-signer-cli.ts
import { spawn } from 'node:child_process';
import type { Address, Hex } from 'viem';

export interface AgentSignerConfig {
  readonly bin: string;          // path to agent-signer
  readonly configPath: string;   // --agent <config.json>
  readonly account: Address;     // Kernel address (pinned)
  readonly sponsored?: boolean;
  readonly timeoutMs?: number;   // > 120s, since the CLI itself waits up to 120s for inclusion
}

export interface AgentSignerResult {
  readonly account: Address;
  readonly userOpHash: Hex;
  readonly txHash: Hex;
  readonly blockNumber: bigint;
  readonly gasUsed: bigint;
}

export type AgentSignerErrorKind =
  | 'policy-denied'      // AA24/AA2x: AgentPolicy returned SIG_VALIDATION_FAILED
  | 'policy-expired'     // AA22: validUntil
  | 'nonce'              // AA25: nonce race — retryable AFTER reconcile
  | 'simulation-revert'  // eth_estimateUserOperationGas failed on an inner call revert
  | 'execution-revert'   // included, but UserOperationEvent.success == false
  | 'not-included'       // accepted by the bundler, not included within 120s — do NOT retry blindly
  | 'hardware'           // TPM/SE/TROPIC01
  | 'config'             // ENOENT, missing feature, invalid config
  | 'unknown';

export class AgentSignerError extends Error {
  readonly name = 'AgentSignerError';
  constructor(
    readonly kind: AgentSignerErrorKind,
    message: string,
    readonly stderr: string,
    readonly exitCode: number | null,
    readonly userOpHash: Hex | null, // parsed from stderr ("userOpHash:     0x…") for reconcile
  ) { super(message); }
}

const USER_OP_HASH_RE = /userOpHash:\s+(0x[0-9a-fA-F]{64})/;

function classify(stderr: string): AgentSignerErrorKind {
  if (/AA22/.test(stderr)) return 'policy-expired';
  if (/AA25|invalid account nonce/i.test(stderr)) return 'nonce';
  if (/AA2\d|signature error/i.test(stderr)) return 'policy-denied';
  if (/not included within/.test(stderr)) return 'not-included';
  if (/execution reverted:|its execution reverted/.test(stderr)) return 'execution-revert';
  if (/eth_estimateUserOperationGas/.test(stderr)) return 'simulation-revert';
  if (/TPM|tss|Secure Enclave|TROPIC01|enclave/i.test(stderr)) return 'hardware';
  if (/needs `--features|config|No such file/i.test(stderr)) return 'config';
  return 'unknown';
}

export async function agentSignerSend(
  cfg: AgentSignerConfig,
  call: { to: Address; value: bigint; data: Hex; root?: boolean },
  signal?: AbortSignal,
): Promise<AgentSignerResult> {
  const args = [
    'op', 'send', '--agent', cfg.configPath,
    '--target', call.to, '--wei', call.value.toString(), '--data', call.data, '--json',
  ];
  if (cfg.sponsored) args.push('--sponsored');
  if (call.root) args.push('--root');

  return new Promise((resolve, reject) => {
    const child = spawn(cfg.bin, args, { stdio: ['ignore', 'pipe', 'pipe'], signal });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (c) => { stdout += c; });
    child.stderr.setEncoding('utf8').on('data', (c) => { stderr += c; });
    const timer = setTimeout(() => child.kill('SIGTERM'), cfg.timeoutMs ?? 180_000);
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(new AgentSignerError('config', `agent-signer spawn failed: ${err.message}`, stderr, null, null));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const opHash = (stderr.match(USER_OP_HASH_RE)?.[1] ?? null) as Hex | null;
      if (code !== 0) {
        const last = stderr.trim().split('\n').at(-1) ?? '';
        reject(new AgentSignerError(classify(stderr), `agent-signer exit ${code}: ${last}`, stderr, code, opHash));
        return;
      }
      try {
        const j = JSON.parse(stdout.trim().split('\n').at(-1)!) as {
          account: string; userOpHash: string; tx: string; block: number; gasUsed: number;
        };
        if (j.account.toLowerCase() !== cfg.account.toLowerCase()) {
          throw new Error(`agent-signer used account ${j.account}, expected ${cfg.account}`);
        }
        resolve({
          account: j.account as Address, userOpHash: j.userOpHash as Hex, txHash: j.tx as Hex,
          blockNumber: BigInt(j.block), gasUsed: BigInt(j.gasUsed),
        });
      } catch (e) {
        reject(new AgentSignerError('unknown', `bad agent-signer JSON: ${String(e)}`, stderr, code, opHash));
      }
    });
  });
}
```

```ts
// operator/src/signer/kernel-safe-broadcaster.ts
import { decodeEventLog, encodeFunctionData, zeroAddress, type Address, type Hex, type Log, type PublicClient } from 'viem';
import {
  SAFE_ABI, JINN_ROUTER_V3_ABI, SafeInnerRevertError, decodeSafeInnerRevert, formatDecodedRevert,
  type PostingOutcome,
} from '@jinn-network/marketplace-binding';
import {
  encodePreValidatedSignature, classifyBroadcastError,
  type BaseVenueSafeBroadcaster, type SafeBroadcastRequest, type SafeBroadcastReceipt, type BroadcastLock,
} from '@jinn-network/venue-base';
import { agentSignerSend, AgentSignerError, type AgentSignerConfig } from './agent-signer-cli.js';

const ENTRY_POINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as const;
const USER_OP_EVENT_ABI = [{
  type: 'event', name: 'UserOperationEvent', inputs: [
    { name: 'userOpHash', type: 'bytes32', indexed: true }, { name: 'sender', type: 'address', indexed: true },
    { name: 'paymaster', type: 'address', indexed: true }, { name: 'nonce', type: 'uint256', indexed: false },
    { name: 'success', type: 'bool', indexed: false }, { name: 'actualGasCost', type: 'uint256', indexed: false },
    { name: 'actualGasUsed', type: 'uint256', indexed: false },
  ],
}] as const;

/** Logs of a single userOp in a bundle: everything after the previous UserOperationEvent (or BeforeExecution) up to its own. */
function userOpLogs(logs: readonly Log[], userOpHash: Hex): Log[] {
  let start = 0;
  for (let i = 0; i < logs.length; i++) {
    const l = logs[i]!;
    if (l.address.toLowerCase() !== ENTRY_POINT_V07.toLowerCase()) continue;
    try {
      const ev = decodeEventLog({ abi: USER_OP_EVENT_ABI, data: l.data, topics: l.topics as [Hex, ...Hex[]] });
      if ((ev.args.userOpHash as Hex).toLowerCase() === userOpHash.toLowerCase()) {
        return logs.slice(start, i).filter((x) => x.address.toLowerCase() !== ENTRY_POINT_V07.toLowerCase());
      }
      start = i + 1;
    } catch { /* BeforeExecution etc. */ }
  }
  throw new Error(`UserOperationEvent ${userOpHash} not found in bundle receipt`);
}

export function createKernelSafeBroadcaster(input: {
  readonly chainId: number;
  readonly safeAddress: Address;
  readonly publicClient: PublicClient;
  readonly signer: AgentSignerConfig;      // signer.account == Kernel == Safe owner
  readonly lock: BroadcastLock;            // the same durable venue-base lock, key = Kernel
}): BaseVenueSafeBroadcaster {
  const kernel = input.signer.account;
  const signature = encodePreValidatedSignature(kernel); // r=Kernel, s=0, v=1 → msg.sender == owner

  async function innerRevert(req: SafeBroadcastRequest, txHash: Hex | null) {
    if ((req.operation ?? 0) === 1) return undefined; // eth_call cannot do delegatecall (as in Jinn #3905)
    const inner = await decodeSafeInnerRevert(input.publicClient, {
      safeAddress: input.safeAddress, to: req.to, value: req.value, data: req.data,
    });
    if (inner.decodedName === null && inner.innerSelector === null) return undefined;
    return new SafeInnerRevertError(
      `Safe execTransaction inner revert (${req.logicalTx}): ${
        inner.decodedName ? formatDecodedRevert(inner.decodedName, inner.decodedArgs) : inner.innerSelector}`,
      inner.innerSelector, inner.innerData, inner.decodedName, inner.decodedArgs, txHash,
    );
  }

  async function executeInner(req: SafeBroadcastRequest): Promise<SafeBroadcastReceipt> {
    const data = encodeFunctionData({
      abi: SAFE_ABI, functionName: 'execTransaction',
      args: [req.to, req.value, req.data, req.operation ?? 0, 0n, 0n, 0n, zeroAddress, zeroAddress, signature],
    });
    try {
      // Safe.execTransaction does not carry value as payable: ETH is taken from the Safe's balance, outer value = 0.
      const r = await agentSignerSend(input.signer, { to: input.safeAddress, value: 0n, data });
      const receipt = await input.publicClient.getTransactionReceipt({ hash: r.txHash });
      return {
        txHash: r.txHash, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
        logs: userOpLogs(receipt.logs, r.userOpHash), alreadySettled: false,
      };
    } catch (err) {
      if (!(err instanceof AgentSignerError)) throw err;
      if (err.kind === 'simulation-revert' || err.kind === 'execution-revert') {
        const inner = await innerRevert(req, null);
        if (inner) {
          if (classifyBroadcastError(inner) === 'already-settled') {
            return { txHash: '0x', blockNumber: 0n, blockHash: '0x', logs: [], alreadySettled: true };
          }
          throw inner;
        }
      }
      // IMPORTANT: a v=1 signature does not commit the Safe nonce in calldata. If the op was already accepted by the bundler
      // ('not-included' / timeout), resending with a new Kernel nonce may execute
      // the same call TWICE. Before any retry — reconcile by err.userOpHash
      // (eth_getUserOperationReceipt), not a blind retry.
      throw err;
    }
  }

  return {
    classify: classifyBroadcastError,
    async execute(req) {
      return input.lock.withSender(input.chainId, kernel, () => executeInner(req));
    },
    async broadcastCreateTask(ct): Promise<PostingOutcome> {
      const receipt = await this.execute({ to: ct.to, value: ct.value, data: ct.data, logicalTx: 'posting.createTask' });
      for (const log of receipt.logs) {
        try {
          const d = decodeEventLog({ abi: JINN_ROUTER_V3_ABI, data: log.data, topics: log.topics as [Hex, ...Hex[]], strict: true });
          if (d.eventName === 'TaskCreated') return { taskId: (d.args as unknown as { taskId: bigint }).taskId, txHash: receipt.txHash };
        } catch { /* not a router event */ }
      }
      throw new Error(`no TaskCreated in ${receipt.txHash}`);
    },
  };
}
```

```ts
// operator/src/signer/agent-signer-transport.ts — direct calls (IdentityRegistry.setMetadata, ValidationRegistry)
import { custom, http, type Address, type Hex } from 'viem';
import { agentSignerSend, type AgentSignerConfig } from './agent-signer-cli.js';

export function agentSignerTransport(rpcUrl: string, cfg: AgentSignerConfig) {
  const rpc = http(rpcUrl)({});
  return custom({
    async request({ method, params }) {
      if (method === 'eth_sendTransaction') {
        const [tx] = params as [{ from: Address; to: Address; value?: Hex; data?: Hex }];
        if (tx.from.toLowerCase() !== cfg.account.toLowerCase()) throw new Error(`from ${tx.from} != Kernel ${cfg.account}`);
        const r = await agentSignerSend(cfg, { to: tx.to, value: BigInt(tx.value ?? '0x0'), data: tx.data ?? '0x' });
        return r.txHash; // the CLI has already waited for inclusion and success; waitForTransactionReceipt will return immediately
      }
      if (/^(personal_sign|eth_sign|eth_signTypedData(_v4)?|eth_signTransaction)$/.test(method)) {
        throw new Error(`${method}: off-chain signing is not available for the Kernel agent (ERC-1271 disabled)`);
      }
      return rpc.request({ method, params } as never);
    },
  });
}
// usage:
// const walletClient = createWalletClient({ account: kernelAddress, chain: baseSepolia, transport: agentSignerTransport(rpc, cfg) });
```

Notes on the sketch:
- `getTransactionReceipt(txHash)` is the receipt of the whole bundle. Logs are sliced by `UserOperationEvent`; otherwise, in someone else's userOp in the same bundle, you could catch "your own" `TaskCreated`/`claim`. It is better if the CLI itself returns `logs` (Phase 0.1).
- Each operation = spawn + two hardware signatures (the CLI signs before and after the bundler's estimate, `chain.rs:~335-350`) + waiting for inclusion (polling every 2 s). This is acceptable for Jinn's pace: claim → deliver → settle, a handful of operations per task.
- `viem custom` with a json-rpc account sends `eth_sendTransaction` without filling in nonce/gas locally **[I — viem behavior, not run]**.

---

## 7. What is verified and what is inferred

**Verified by reading the code [V]:** all file:line references from §1 and §3, including the logic of the Safe broadcasters, eth_sign v+4 vs v=1, `ExternalStakingDistributor` (v=1 with `msg.sender == owner`, swapOwner to agentInstance, guard+modules), `MultisigGuard` (guard slot, modules, no owner check), `StakingBase` (proxyHash/threshold), the activity checker (`nonce()`), `OlasMech.isOperator`, `JinnRouterV4` (msg.sender = mech operator/party), upstream `ServiceRegistryL2.registerAgents` (no EOA check), Kernel `onERC721Received`, ERC-8128 verify = ecrecover, the unwired ScopedSigner, the absence of sign endpoints in the HTTP API, the ceremony/anchor reader, readers decoding the outer `tx.input`, the truncated MultiSend address, our CLI's error messages (`chain.rs`).

**Inferred [I]:**
- Safe 1.3.0 `checkNSignatures` v==1 and the `approveHash` path for 1271 via CompatibilityFallbackHandler. The logic is standard, but the Safe/handler source is not vendored in this repo.
- ERC-8004 IdentityRegistry uses `_safeMint` and verifies `setAgentWallet` via ERC-1271 on `newWallet`. Seen from Jinn's comments/ABI; the registry source was not read.
- Different nonce keys for the root/agent paths of Kernel v3.
- Behavior of viem `custom` for a json-rpc account.
- Ed25519 support in TROPIC01.
- That `DEFAULT_MULTISEND_ADDRESS` actually breaks settlement V4 (not run).
- That all off-chain Jinn verifiers check the signature only against the address inside the document. Verified for `integrity.ts:96`, the rest — by grep.
- GnosisSafeSameAddressMultisig (self-bond deploy) checks the Safe owners against the agent instances — the upstream contract was not read. If so, Kernel as instance and owner is consistent.
