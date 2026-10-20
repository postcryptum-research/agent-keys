# Jinn operator on a hardware-signed owner

> **Кратко по-русски.** Jinn (Olas-экосистема) держит agent-ключ в
> keystore на диске; агент — единственный владелец 1/1 service Safe и
> подписывает Safe-транзакции eth_sign. Здесь владелец Safe — Kernel-аккаунт
> TPM_sign: ключ агента в TPM/TROPIC01, Kernel вызывает `execTransaction` с
> подписью `v = 1`, а `AgentPolicy` проверяет внутренний вызов Safe (и каждую
> ногу MultiSend-батча) по allow-list владельца. `src/kernelSafeBroadcaster.ts`
> структурно совместим с их `BaseVenueSafeBroadcaster`; полный разбор и план —
> `ADAPTATION.md`.

[Jinn](https://github.com/Jinn-Network/mono) operators claim, deliver,
settle and verify work through a 1/1 **service Safe** registered with Olas.
Today the Safe's owner is an agent EOA whose key is derived from a mnemonic
in a keystore on disk; every Safe transaction is signed with it (eth_sign,
`v + 4`) and sent from it.

This example keeps the Safe — Olas staking, the mech and Jinn's router all
require it — and replaces its **owner**:

```
Jinn venue writer ──execute({to, value, data, operation})──▶ KernelSafeBroadcaster
    │  Safe.execTransaction(to, value, data, op, 0,0,0,0,0, sig = r:Kernel s:0 v:1)
    ▼
agent-signer op send --json ──▶ UserOperation signed in TPM / TROPIC01
    ▼
EntryPoint ─▶ Kernel ─▶ AgentPolicy: judges the *inner* call / every batch leg
    ▼
Safe (owner = Kernel) ─▶ router / mech / registries   (msg.sender = Safe, as before)
```

Why this works for Olas/Jinn contracts (details and file:line in
`ADAPTATION.md` §2): `ServiceRegistryL2.registerAgents` does not require the
agent instance to be an EOA; staking checks the Safe proxy's codehash and
threshold, not its owner's type; mech and router check `msg.sender == Safe`,
which stays true. Bonus: rotating the agent key no longer changes the agent
instance — the Kernel address stays, only the hardware key behind it rotates.

## What the policy enforces through the Safe

With `(safe, execTransaction)` on the agent's allow-list, `AgentPolicy`
(v3) decodes the Safe transaction and requires:

- inner `(to, selector)` on the owner's allow-list — e.g. Jinn's router and
  mech entry points, nothing else;
- inner value within the per-operation cap and the budget;
- `gasPrice == 0` (no refunds paid out of the Safe);
- no nested Safe transaction;
- the Safe transaction arrives as a batch whose first call asserts the
  Safe's nonce (`SafeNonceAssert`), so a retry of one that already landed
  reverts on-chain — the adapter fixes that nonce per `logicalTx` at the
  first attempt;
- `operation == CALL`, or DELEGATECALL into an allow-listed
  `MultiSendCallOnly.multiSend` whose every leg is a CALL that passes the
  allow-list (values summed).

So the Safe's own admin functions (`addOwnerWithThreshold`, `enableModule`,
`setGuard`, …) are refused for the agent — a compromised host cannot take
over the Safe or survive a revocation of its key. See `docs/ERC1271.md`.

## Run

```sh
npm install
npm run demo        # BASE_SEPOLIA_RPC_URL / BUNDLER_URL from ../../../.env
```

Output on Base Sepolia (2026-10-20), agent key in a TROPIC01, permission
`trs3` on AgentPolicy v3 with `(MultiSendCallOnly, multiSend)` in the mandate
(rotation tx `0xef321bd0cfce69f617c4efc28628d88f148134d0d4cdadd9a33cfaa03d5ff4aa`):

```
Safe 0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A (owner: Kernel 0xEdB645B1…bC9E9), counter = 12
✔ single call (claim-like): tx 0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16, counter = 13
✔ MultiSendCallOnly batch (settlement-like): tx 0xd9bdc92ab3afac2baf9ab4ac8055c0cb5cbc195dd8a4db2b3f74025901c0fd31, counter = 15
✘ Safe adds an owner (compromised agent): policy-denied — refused by AgentPolicy on-chain
```

Under policy v2 (CALL only) the same batch was refused; the owner change is
refused under both.

## Integrating into Jinn

`ADAPTATION.md` §5 is the ordered plan. In short:

1. `createBaseVenue` accepts an injected `safeBroadcaster` (their venue-base
   is already "signer-injection only") — pass `createKernelSafeBroadcaster`
   with their `BroadcastLock` and `classifyBroadcastError`.
2. Direct agent calls (ERC-8004 `setMetadata`, validation) go through a viem
   transport backed by `agent-signer` (sketch in `ADAPTATION.md` §6).
3. Off-chain signatures (task.v1, `signCanonical`, ERC-8128) move to a
   separate unfunded attestation key; the native-mode trust ceremony needs a
   spec change (a transaction ceremony instead of EIP-191 by the Safe owner).
4. Readers that decode a peer's outer transaction as `Safe.execTransaction`
   (`venue-base/src/verdict.ts`, the settlement reader) must also accept
   `EntryPoint.handleOps` — otherwise other operators reject our verdicts.

Found on the way, worth an upstream fix: `DEFAULT_MULTISEND_ADDRESS` in
`packages/marketplace/venue-base/src/writers/settlement.ts:33` has 39 hex
digits — the final `D` of MultiSendCallOnly v1.3.0
(`0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`) is missing.
