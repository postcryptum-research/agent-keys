# Jinn (Jinn-Network/mono) → TPM_sign: разбор ключей и дизайн адаптации

Разбор `Jinn-Network/mono`, ветка `next`, коммит `a981363` (2026-10-20). Все пути ниже относительно корня того репозитория.
Легенда: **[V]** — проверено чтением кода (file:line), **[I]** — вывод/знание без прямой проверки в этом репо.

> **Статус на стороне TPM_sign (2026-10-20), обновляет §3 и §5 «Фаза 0»:**
> - **M1 реализован** в `AgentPolicy` v3 (`contracts/src/AgentPolicy.sol`, Base Sepolia
>   `0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24`), отдельный модуль `SafeExecPolicy` не понадобился:
>   запись `(safe, execTransaction)` в allow-list включает разбор Safe-транзакции; внутренний
>   `(to, selector)` проверяется по тому же allow-list, value — по тому же лимиту и бюджету;
>   `gasPrice ≠ 0` (refund) запрещён; вложенные Safe запрещены; DELEGATECALL — только в
>   allow-listed `(MultiSendCallOnly, multiSend)`, и каждая нога батча должна быть CALL,
>   проходящим allow-list (значения ног суммируются). Self-admin Safe (`addOwner`, `enableModule`,
>   `setGuard`) отклоняется, пока владелец не внёс его в allow-list. 44 forge-теста на настоящем
>   Safe v1.4.1 + MultiSendCallOnly, каждая защита проверена мутацией.
> - Отличия от предложенного M1: allow-list общий для прямых вызовов и вызовов через Safe (не
>   отдельный per-Safe); форма подписи не проверяется — она и не нужна: без 1271 и без
>   allow-listed `approveHash` Safe примет только `v = 1` от `msg.sender == Kernel`.
> - `agent-signer op send --json` есть; логи своего userOp режет адаптер
>   (`src/kernelSafeBroadcaster.ts`, `userOpLogs`).
> - Проверено на Base Sepolia: Safe v1.3.0 `0xd0b972a8…E52A` с единственным владельцем Kernel;
>   от ключа в TROPIC01 под v3 прошли одиночный вызов и MultiSendCallOnly-батч через Safe,
>   `addOwner` отклонён политикой (`README.md`, раздел Run).

> **Первая серия патчей (2026-10-21):** пункты 1–5 фазы 1 (и транспорт из пункта 8) — три
> коммита на `next` `151a464aa`: [`patches/`](patches/), описание в [`README.md`](README.md#integrating-into-jinn-the-patch-series-first-version).
> «Побочная находка» из §5 подтверждена и исправлена там же (патч 0001).

---

## 1. Как Jinn держит и использует ключи (сводка)

### 1.1 Хранилище и деривация
- Один BIP-39 мнемоник на оператора, зашифрован V3-keystore (scrypt) по ключу индекса 0 + XOR-обфускация мнемоника этим ключом: `operator/src/earning/wallet.ts:40-105` **[V]**. Файл `~/.jinn-client/earning/master_keystore.json` (`operator/src/earning/store.ts:5,23`) **[V]**.
- Пароль: `JINN_PASSWORD` / `--password-fd` / **автогенерируемый password-файл рядом** (`operator/src/cli/password.ts:6,111-124`, `operator/src/earning/password-file.ts`) **[V]** → на практике ключ в покое защищён только правами на файлы.
- Деривация `m/44'/60'/0'/0/{i}`: индекс 0 = **master** (фондер), 1+ = **agent EOA** на сервис (`wallet.ts:20,32,118-127`) **[V]**.
- Демон расшифровывает мнемоник при старте и держит raw private key агента в памяти (`operator/src/main.ts:1306-1340`), раздаёт его как `agentEoaPrivateKey`/`pk` в MechAdapter, харнессы, envelope/capture-подпись, SolverNet, corpus, legacy bridge (`main.ts:1422,1440,1552,1676,1753,1790,1839,2007`) **[V]**.
- Отдельные ключи: Hyperliquid API-wallet — свой secp256k1 ключ в `<implStateDir>/api-wallet.json` (0600) (`operator/src/harnesses/impls/claude-mcp-hyperliquid/api-wallet.ts:90-108`) **[V]**; «native» роль-ключи — Ed25519 в зашифрованном store `@jinn-network/trust-authoring` (`operator/src/daemon/role-identities.ts:1-12,121`) **[V]**.

### 1.2 «Signing HTTP API» демона — фактически отсутствует
- `ARCHITECTURE.md:240` утверждает, что runner и MCP «reach signing operations through the daemon's HTTP API». Перечень маршрутов (`operator/src/api/*`) не содержит ни одного sign/tx-эндпоинта; есть только `/api/admin/claim-rewards` (master tx) и т.п. **[V]**. MCP-сервер «wraps CLI command modules directly» (`operator/src/mcp/operator-server.ts:9`) — т.е. tx-глаголы MCP сами расшифровывают keystore **[V]**.
- Задуманный «scoped signer» (`operator/src/harnesses/capability/scoped-signer.ts:76-131`) имеет allow-list `(chainId, to, selector)` + allow-list EIP-712 доменов, но `sendAllowedCall` **бросает** «signing is wired in the daemon plan» (строка 126-129), а `createScopedSigner` нигде не вызывается **[V]**. Это 1:1 совпадает с моделью нашей AgentPolicy — естественная точка встраивания (см. §2).

### 1.3 Все места подписи

**On-chain через Safe (агент EOA = единственный владелец 1/1 Safe):**

| Место | Что подписывается | Через наш аккаунт? |
|---|---|---|
| `packages/marketplace/venue-base/src/broadcast/safe-broadcaster.ts:228-266` (`createSafeBroadcaster.executeInner`) | `signMessage(safeTxHash)` → eth_sign v+4 (стр. 96-103), затем EOA tx `Safe.execTransaction` (стр. 259). Единый broadcaster всех venue-писателей: claim (`writers/claim.ts:141`), settlement (`writers/settlement.ts:199,383` — **MultiSend DELEGATECALL**, op=1), lifecycle (`writers/lifecycle.ts:43,52,64,83`), deliver (`deliver-leg.ts:84`), verdict (`verdict.ts:495,539,580`), posting (`safe-broadcaster.ts:336`) | Да — заменить на v=1 + `agent-signer op send --target Safe` |
| `packages/marketplace/venue-base/src/broadcast/stuck-nonce.ts:52` | self-tx EOA для вытеснения застрявшего nonce | Нет смысла для Kernel — отключить |
| `operator/src/adapters/mech/direct-safe-broadcaster.ts:152-179` | то же (eth_sign v+4 + `writeContract execTransaction`), для CLI-глаголов (`cli/execution-context.ts:277`, `cli/commands/solver-plugins.ts:238,298`) | Да |
| `operator/src/adapters/mech/safe.ts:116-157` `executeSafeTransaction` | только делегирует в `VenueBroadcaster.execute` | Автоматически, если broadcaster наш |
| `operator/src/adapters/mech/contracts.ts:224,400,544,1202` | createTask, claimTask, claimDelivery, deliverToMarketplace через Safe | Автоматически (через broadcaster) |
| `operator/src/erc8004/reputation.ts:505` | giveFeedback/appendResponse/revokeFeedback через Safe | Автоматически |
| `operator/src/erc8004/plugin-registry.ts:250` | setMetadata через Safe | Автоматически |
| `operator/src/earning/safe-adapter.ts:222-292` `executeSafeTxBatch` | Safe SDK (protocol-kit) с raw `signerKey`: `signTransaction` + `executeTransaction` | Переписать: MultiSendCallOnly + execTransaction v=1 |
| `operator/src/earning/safe-adapter.ts:298-438` `executeSafeTxDirect` | `signMessage(safeTxHash)` v+4 (стр. 349-357) + `sendTransaction` (стр. 407) | Да |
| `operator/src/daemon/native-base-sepolia-infrastructure.ts:1684-1702` | **v=1** `encodePreValidatedSignature` — но только для `estimateContractGas`; реальная отправка идёт через `executeSafeTransaction` | Да |

> Важно: `buildSafeSignature` (v=01) в `operator/src/adapters/mech/safe.ts:17` и `packages/marketplace/binding/src/venue/safe.ts:75` сейчас **нигде не используется для отправки** — Jinn везде шлёт eth_sign-подписи (v+4). Pre-validated форма (`r = owner, s = 0, v = 1`) — именно то, что нужно Kernel: Safe 1.3.0 `checkNSignatures` при v==1 принимает `msg.sender == owner`. Тот же приём в vendored stOLAS: `contracts/src/vendor/stolas/ExternalStakingDistributor.sol:~389-392` (`abi.encodePacked(r, bytes32(0), uint8(1))` с `r = address(this)`) **[V]**.

**On-chain напрямую от agent EOA:**

| Место | Вызов |
|---|---|
| `operator/src/earning/bootstrap.ts:1884` | ERC-8004 `IdentityRegistry.register("")` (NFT владеет agent EOA) |
| `operator/src/earning/agent-wallet-binding.ts:285,296` | `account.sign(SafeMessage(AgentWalletSet digest))` (raw ECDSA, проверяется Safe через ERC-1271) + `IdentityRegistry.setAgentWallet(agentId, safe, deadline, sig)` |
| `operator/src/erc8004/identity.ts:680` | `IdentityRegistry.setMetadata` (per-execution anchoring) |
| `operator/src/erc8004/validation.ts:145,185` | `validationRequest` / `validationResponse` |
| `operator/src/solvernets/daemon-init.ts:223` | metadata publisher (IdentityRegistry) |
| `operator/src/earning/bootstrap.ts:2114,2153` | self-bond: top-up Safe, деплой Safe (protocol-kit deployment tx) |
| `operator/src/earning/bootstrap.ts:2219-2463` | self-bond: create/activate/registerAgents/deploy/approve/stake через `executeSafeTxBatch`/`executeSafeTxDirect` |
| `operator/src/earning/bootstrap.ts:1749` | mech `MechMarketplace.create` через Safe (`executeSafeTxDirect`) |
| `operator/src/earning/orphan-sweep.ts:175,251,284`, `withdraw/run-withdraw-plan.ts:150` | sweep/withdraw от агента |
| `operator/src/earning/migrate-agent-id.ts:226`, `earning/steps/fleet-identity-register.ts:43` | миграции/регистрация identity |

**On-chain от master EOA (индекс 0):** stOLAS `distributor.stake(..., agentInstance)` (`bootstrap.ts:1626`), фондирование агента/Safe (`bootstrap.ts:1729,2085`, `daemon/balance-topup-loop.ts:102,135`), `checkpoint()` (`main.ts:2393`), reStake (`bootstrap.ts:2709`, `adapters/mech/contracts.ts:120`, `daemon/degraded-recovery.ts:177`), retire `unstakeAndWithdraw` (`earning/fleet-retire.ts:76`), withdraw (`withdraw/run-withdraw-plan.ts:204,240`) **[V]**.

**Off-chain подписи:**

| Место | Схема | Кто проверяет |
|---|---|---|
| `operator/src/harnesses/engine/signing.ts:40-62` `signCanonical` | raw secp256k1 над keccak256(canonical JSON), без EIP-191 | `recoverAddress` == `signer`/`creator.agentEoa`: `harnesses/impls/prediction-v0-evaluator/checks/integrity.ts:96`, `conformance/checks/hash-signature.ts:59`, `solver-types/_swe-rebench-v2-verifier-facts.ts:488` |
| `operator/src/tasks/signing.ts:8` `signTaskV1` (вызовы: `adapters/mech/adapter.ts:505`, `requester-adapter.ts:277`, `cli/commands/tasks.ts:840`, `solver-types/*-auto.ts`, `swe-rebench-v2.ts:430`) | task.v1, `signature.algo: 'secp256k1'` | см. выше |
| `harnesses/engine/envelope-assembly.ts:128`, `captures/publish.ts:313`, `trajectory/emit.ts:122`, evaluator impls (`prediction*-evaluator/index.ts:262/265`, `portfolio-v0-evaluator/index.ts:237`), `packages/layer/src/publish.ts:1708`, `publish-skill.ts:226` | `signCanonical` | ecrecover |
| `operator/src/auth/erc8128.ts:77-85` `createPrivateKeyHttpSigner` | ERC-8128 (RFC 9421 + EIP-191) | `ethVerifyMessage` (стр. 63) — **чистый ecrecover через viem `verifyMessage`, без ERC-1271**; используется только в `api/server.ts:644` для `POST /artifacts` при `requireAuth`. Клиентская подпись (`signRequestWithErc8128`) **нигде не вызывается** **[V]** |
| `operator/src/daemon/trust-keys.ts:22` `deriveLegacyBridgeSigner` | синхронный raw secp256k1 тем же agent-ключом (legacy execution envelope) | ecrecover |
| `operator/src/solvernets/manifest.ts:174` | EIP-191 (`recoverMessageAddress`) — manifest лаунчера | ecrecover |
| Native announcements/discovery/submissions: `daemon/composition-root.ts:2302`, `daemon/native-signed-source.ts:885`, `native-requester/requester.ts:796,1173,1201`, `packages/discovery/serve/src/entry-signing.ts:39` | **Ed25519 DSSE** роль-ключами (не agent EOA) | DSSE verify + trust binding |
| Trust ceremony: `packages/trust/authoring/src/ceremony.ts:59-91` `performEoaCeremony`, вызов `cli/commands/ceremony.ts:720,1019`, ключ — agent EOA (`earning/ceremony-custody.ts:153,172`) | SIWE EIP-191 агентом E над `[agent IRI, did:key, did:pkh:Safe]`; цепочка: role key ← ceremony ← E ← `Safe.isOwner(E)` | **ERC-1271 явно запрещён** (`spec/2026-08-07-native-identity-ceremony.md:132,217-225`) |
| Trust anchor: `packages/trust/authoring/src/anchor.ts:107-130` | tx с calldata = sha256-digest; ридер `daemon/native-base-sepolia-infrastructure.ts:1460-1490` требует `tx.to == anchor` и digest в `tx.input` по смещению; `from` не проверяется | — |
| Hyperliquid `harnesses/impls/claude-mcp-hyperliquid/mcp-tools.ts:266-347` `signHlAction` | EIP-712 «Agent», chainId 1337, отдельным API-wallet ключом | HL L1 (только secp256k1) |

---

## 2. Шов интеграции (integration seam)

### 2.1 Вердикт по двум вариантам

**Вариант A — Kernel = agent instance и владелец 1/1 service Safe, вызовы через `Safe.execTransaction` с v=1. ЖИЗНЕСПОСОБЕН.**
- `ServiceRegistryL2.registerAgents` не проверяет, что agent instance — EOA: только `agentInstance != operator`, «не занят», слоты (upstream `autonolas-registries/contracts/ServiceRegistryL2.sol:424-462`, скачан и прочитан) **[V]**.
- stOLAS `_deployAndStake` создаёт Safe с owner = distributor и делает `swapOwner(..., agentInstance)` (`contracts/src/vendor/stolas/ExternalStakingDistributor.sol:349-381,440-462`) — адрес любого типа **[V]**. `RecoveryModule` меняет владельцев модулем, без EOA-проверок **[V]**.
- Staking проверяет `service.multisig.codehash == proxyHash` (Safe 1.3.0 proxy), threshold, число инстансов (`contracts/src/vendor/registries/staking/StakingBase.sol:769-790`) — не тип владельца **[V]**.
- Mech: `isOperator(msg.sender)` == service multisig (`contracts/src/vendor/mech/OlasMech.sol:309-325`) **[V]**; Router V4: `_validateMechOperator(priorityMech, msg.sender)`, `reservation.party == msg.sender` (`contracts/src/staking/JinnRouterV4.sol:401,484,633`) **[V]** — все ожидают Safe как `msg.sender`, что сохраняется.
- Kernel принимает ERC-721 (`contracts/lib/kernel/src/Kernel.sol:173` в TPM_sign) **[V]** → ERC-8004 NFT может принадлежать Kernel.
- Бонус: ротация agent-ключа в Kernel **не меняет адрес** agent instance / владельца Safe. Сейчас в Jinn ротация EOA = перерегистрация сервиса (`bootstrap.ts:1560-1592`, ошибка `agent_already_bound … rotate the agent EOA`).

**Вариант B — Kernel вместо Safe (сам как service multisig). НЕ ЖИЗНЕСПОСОБЕН для основного цикла.**
- `proxyHash` staking'а — codehash Safe-прокси; Kernel-прокси не пройдёт (`UnauthorizedMultisig`, `StakingBase.sol:787-790`) **[V]**.
- Activity checker вызывает `IMultisig(multisig).nonce()` (`StakingActivityChecker.sol:38`, `staking/TaskActivityCheckerV3.sol:156`) **[V]** — у Kernel нет такого метода; liveness = рост Safe nonce.
- Награды staking'а идут на multisig (`StakingBase.sol:226`) **[V]**.
- Прямо от Kernel (без Safe) разумно только: ERC-8004 IdentityRegistry (register/setMetadata/setAgentWallet — там и сейчас вызывает EOA), ValidationRegistry, а для requester-роли — `createEoaBroadcastPort` (`packages/marketplace/binding/src/venue/eoa-broadcast.ts:83-120`, creator = сам аккаунт) **[V]**.

**Итог:** гибрид. Сервисная работа (claim/deliver/settle/verdict/createTask/reputation) идёт через `Safe.execTransaction(v=1)` из Kernel. Identity-вызовы (ERC-8004) идут напрямую из Kernel. Bootstrap и админка идут по **root-пути** (owner key) Kernel, а не по agent-пути.

### 2.2 Где поставить единый интерфейс
У Jinn уже есть порт: `BaseVenueSafeBroadcaster` (`execute({to,value,data,logicalTx,operation}) → {txHash, blockNumber, blockHash, logs, alreadySettled}`, + `classify`, + `broadcastCreateTask`) — `packages/marketplace/venue-base/src/broadcast/safe-broadcaster.ts:40-78`. Его структурное подмножество — `VenueBroadcaster` / `DirectSafeBroadcaster` в operator (`adapters/mech/safe.ts:76-86`, `direct-safe-broadcaster.ts:66-74`). Все Safe-записи уже идут через этот порт (правило «single broadcaster per Safe»). Проектный принцип у них: «venue-base is signer-injection only» (`create-base-venue.ts:62-66`), и есть комментарий про «remote-signer/hardware-wallet compatible» (`daemon/trust-keys.ts:11-12`).

Предлагаемая иерархия (новый модуль `operator/src/signer/`):

```
AgentSigner (sendCall: {to,value,data,logicalTx,path:'agent'|'root'} → {txHash,userOpHash,blockNumber,blockHash,logs})
   └─ AgentSignerCli          — spawn `agent-signer op send --json` (§6)
KernelSafeBroadcaster implements BaseVenueSafeBroadcaster  — оборачивает execTransaction(v=1) → AgentSigner
agentSignerTransport (viem custom EIP-1193)                — eth_sendTransaction → AgentSigner (для прямых вызовов: setMetadata, validation)
ScopedSigner.sendAllowedCall                               — наконец «подключить» через AgentSigner (allow-list = AgentPolicy)
```

Точки инъекции:
1. `createBaseVenue` (`packages/marketplace/venue-base/src/create-base-venue.ts:80`): добавить в `BaseVenueConfig` опциональный `safeBroadcaster?: BaseVenueSafeBroadcaster`. Если он задан, использовать его вместо `createSafeBroadcaster` и снять требование `walletClient.account` (строка 62).
2. `operator/src/daemon/composition-root.ts:2246` — передать `KernelSafeBroadcaster` при `signer.kind === 'agent-signer'`.
3. `operator/src/cli/execution-context.ts:277`, `cli/commands/solver-plugins.ts:238,298` — вместо `createDirectSafeBroadcaster`.
4. Прямые EOA-вызовы (`erc8004/identity.ts:680`, `validation.ts:145,185`, `solvernets/daemon-init.ts:223`) — передать walletClient на `agentSignerTransport`. Тогда `writeContract`/`sendTransaction` уходят в CLI, а `signMessage`/`signTypedData` падают явно.
5. `tx-retry.ts` (`viemSendTransactionWithRetry`, `withNonceLedger`, `evictStuckNonce`) для Kernel-пути не использовать: EOA-nonce у Kernel бессмысленен. Сериализацию брать из `BroadcastLock.withSender(chainId, kernelAddress)`.

---

## 3. Безопасность: allow-list `Safe.execTransaction` ослепляет AgentPolicy

`AgentPolicy._decodeSingleExecute` видит только внешний `(target=Safe, selector=execTransaction, value=0)` (`TPM_sign/contracts/src/AgentPolicy.sol:109-152`). Что тогда может скомпрометированный agent-ключ:
- **Захват Safe навсегда.** `execTransaction(to=Safe, addOwnerWithThreshold/swapOwner)` добавляет свой EOA-owner. stOLAS `MultisigGuard.checkAfterExecution` проверяет только guard-слот, модули и залог оператора, **но не владельцев** (`contracts/src/vendor/stolas/MultisigGuard.sol:~118-200`) **[V]**. Такой owner переживёт отзыв agent-ключа в Kernel.
- **DELEGATECALL** (`operation=1`) в произвольный контракт: запись в любые слоты Safe.
- **Вывод активов Safe.** ETH/OLAS, награды staking'а приходят на multisig. Внешний `value=0`, поэтому budget/maxValuePerOp не срабатывают.
- **Gas-refund drain.** `gasPrice>0, gasToken, refundReceiver=attacker`: Safe платит «рефанд» атакующему.
- **Произвольный exec из mech.** `Mech.exec` с `onlyOperator` (`contracts/src/vendor/mech/lib/Mech.sol:107-120`) **[V]**. Через Safe можно опустошить mech.
- Злоупотребления роутером: createTask (тратит OLAS Safe), release/forfeit резерваций.

### Варианты защиты
**M1 (рекомендуется): AgentPolicy понимает Safe-обёртку.** Новый policy-модуль `SafeExecPolicy` (или режим в AgentPolicy): для `target ∈ registeredSafes` и `selector == execTransaction` декодировать аргументы и требовать:
- `operation == 0`, **или** `operation == 1 && to == MultiSendCallOnly 1.3.0` (`0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`). Каждую упакованную ногу декодировать, у каждой op-байт == 0;
- для каждого внутреннего вызова `(to, selector)` ∈ отдельного inner-allow-list для этого Safe; `to != Safe` (никаких self-admin), `to != Kernel`;
- inner `value` учитывать в `maxValuePerOp`/`budget` (это ETH Safe);
- `safeTxGas == baseGas == gasPrice == 0`, `gasToken == refundReceiver == 0`;
- `signatures` ровно 65 байт, `r == account`, `s == 0`, `v == 1`.

Чистое декодирование calldata + чтение собственного storage модуля по ключу `account` укладывается в правила ERC-7562. Работает и в stOLAS-режиме, и в self-bond. Стоимость: ~2-4 дня Solidity + тесты на стороне TPM_sign.

Минимальный inner-allow-list для основного цикла Jinn: Router V3/V4 `claimTask`, `createTask`, `claimDelivery`, `claimSolutionDelivery`, `prepareSolutionDelivery`, `claimEvaluation`, `claimVerdictDelivery`, `releaseAttempt`, `closeTask`, `refundUnusedTaskBudget`, `forfeitDeliveredReservation`; mech `deliverToMarketplace`; OLAS `approve(router, …)` (лучше с ограничением spender); ReputationRegistry `giveFeedback/appendResponse/revokeFeedback`; IdentityRegistry `setMetadata`. Источник: `venue-base/src/writers/*.ts`, `verdict.ts`, `adapters/mech/contracts.ts` **[V]**.

**M2: Safe Guard.** В stOLAS-режиме **невозможен**: слот guard занят `MultisigGuard`, и его `checkAfterExecution` делает `checkGuard(address(this))`, т.е. сравнивает слот со своим адресом и ревертит при подмене (`MultisigGuard.sol:~140-215`) **[V]**. В self-bond-режиме возможен, но guard видит `msgSender = Kernel` и не отличает root-путь от agent-пути, поэтому нужен отдельный admin-обход через вызов самого guard. Слабее M1.

**M3: обойти Safe и звать цели прямо из Kernel.** Для сервисного цикла невозможно (§2.1, B). Возможно только для identity/validation и requester-роли.

**Плюс к M1:** bootstrap/админку (`addOwner`, `enableModule`, `MechMarketplace.create`, ServiceManager-вызовы, `setGuard`) проводить **только по root-пути** (owner key). Agent-путь их вообще не должен видеть.

Побочно, на нашей стороне. Газ при agent-пути платится из deposit Kernel, а `budget` в AgentPolicy его не учитывает (только `value`). Скомпрометированный ключ может жечь deposit через `maxFeePerGas`. Лечится через `--sponsored` + `WhitelistPaymaster` с потолками на op.

---

## 4. Off-chain подписи без ERC-1271

| Подпись | Ломается? | Почему |
|---|---|---|
| task.v1 / `signCanonical` (envelopes, captures, trajectory, verdict manifests, layer publish) | **Да** | Raw secp256k1 + `recoverAddress` == адрес в документе. P-256 не подходит, 1271 никто не вызывает |
| ERC-8128 HTTP | **Да**, но сейчас неактивна на клиенте | Проверка = ecrecover (`erc8128.ts:63`); 1271 не поддерживается |
| Legacy bridge signer (`trust-keys.ts:22`) | **Да** | Синхронный raw secp256k1 |
| SolverNet manifest (EIP-191) | **Да** | `recoverMessageAddress` |
| Trust ceremony (native) | **Да, жёстко** | SIWE EIP-191 от E + `Safe.isOwner(E)`; спека прямо запрещает 1271 (§2.3d) |
| Trust anchor tx | Частично | Ридер требует `tx.to == anchor` и digest в `tx.input`; userOp прячет calldata внутри `handleOps`. Отправитель не проверяется, поэтому anchor может слать любой газовый EOA |
| ERC-8004 `setAgentWallet` | Решаемо on-chain | Подпись проверяет **Safe** (1271 Safe → `checkSignatures` владельцев) |
| Ed25519 DSSE (announcements/discovery) | Нет | Отдельные роль-ключи; ломается только их привязка (ceremony) |
| Hyperliquid | Нет | Отдельный API-wallet ключ; HL требует secp256k1, P-256 там невозможен в принципе |

### Варианты
1. **ERC-8004 setAgentWallet без 1271 в Kernel.** Kernel (root-путь) делает `Safe.approveHash(safeMessageHash)`: owner может вызвать его напрямую. Затем `setAgentWallet(agentId, safe, deadline, sig)` с `sig = r=Kernel, s=0, v=1`. В `checkNSignatures` ветка v==1 принимает `approvedHashes[owner][hash] != 0`. Два userOp, ноль off-chain подписей **[I: точная версия CompatibilityFallbackHandler на Safe не проверена, логика Safe 1.3.0]**. Поле `owner` в digest'е = Kernel (владелец NFT).
2. **Отдельный незафондированный «attestation key» (secp256k1, софт).** Для task.v1/`signCanonical`/ERC-8128/legacy bridge/manifest. Он не владеет средствами, не owner Safe, вращаем. Верификаторы Jinn сравнивают recover с адресом **внутри того же документа** (`creator.agentEoa`/`signer`) и не сверяют его с on-chain владельцем Safe **[V для integrity.ts:96; I — для всех остальных верификаторов]**. Значит, минимальный патч: подставить этот ключ как «agentEoa» в документах. Желательно связать его on-chain: Kernel пишет `IdentityRegistry.setMetadata(agentId, "jinn.attestationKey", addr)`. Честно: компрометация этого ключа даёт подделку off-chain аттестаций (репутационный риск), но не деньги и не on-chain полномочия.
3. **Узкий 1271 в Kernel не нужен.** Jinn-верификаторы 1271 не вызывают вовсе (ecrecover), ceremony его запрещает. Для единственного on-chain потребителя (setAgentWallet) хватает варианта 1. «Hash-allowlist 1271» не годится для ERC-8128: там уникальный nonce на каждый запрос.
4. **P-256 как второй `algo`.** В task.v1 уже есть `signature.algo: 'secp256k1'` (`operator/src/tasks/signing.ts:15`). Можно добавить `algo: 'p256'` с pubkey из ERC-8004 metadata и проверкой через `@noble/curves/p256` (или RIP-7212 on-chain). Это изменение протокола Jinn примерно в 5 верификаторах. Для таких подписей нужен **отдельный** P-256 ключ в железе (доменное разделение с ключом userOp), и CLI нужна команда `sign-digest`.
5. **Trust ceremony (native mode) — блокер, нужна поправка спеки Jinn.** Предложение: «tx-ceremony» — Kernel отправляет on-chain op с digest'ом SIWE-сообщения `[agent, did:key, Safe]`. Доказательство: включение в блок + `UserOperationEvent.sender == Kernel` + `Safe.isOwner(Kernel)`. Возражение спеки про мутабельность 1271 сюда не относится: включение транзакции неизменно, а `isOwner` они уже читают из chain state. Альтернатива без изменения спеки — ceremony-EOA как второй owner Safe. Она **отвергнута**: при threshold 1 он полностью контролирует Safe. Ed25519 роль-ключи можно было бы держать в TROPIC01 (Ed25519 поддерживается чипом **[I — по даташиту, в TPM_sign не проверено]**); TPM/Secure Enclave Ed25519 не умеют.

---

## 5. План патчей (по порядку) и оценка

### Фаза 0 — наша сторона (TPM_sign), до Jinn
0.1 `agent-signer op send --json`: добавить `logs` (логи только этого userOp из `eth_getUserOperationReceipt` / срез между `UserOperationEvent`), `blockHash`, `nonce`, `success`. Печатать `userOpHash` в JSON-ошибке (stderr уже печатает `userOpHash:` до ожидания, `chain.rs:~347`). Желательно `--nonce-key`/`--nonce` для идемпотентных ретраев. ~1 день.
0.2 `SafeExecPolicy` (M1) + forge-тесты: self-call, delegatecall, refund, MultiSendCallOnly, inner allow-list, inner value в budget. 2-4 дня.
0.3 Документировать, что root и agent пути имеют разные nonce-key Kernel v3 **[I]**, а параллельные вызовы одного пути сериализуются вызывающей стороной.

### Фаза 1 — steady-state цикл (сервис уже забутстраплен, legacy mode)
1. `operator/src/signer/agent-signer-cli.ts` (новый): spawn, парсинг, классификация ошибок (§6).
2. `operator/src/signer/kernel-safe-broadcaster.ts` (новый): `BaseVenueSafeBroadcaster` поверх `execTransaction(v=1)`. Включает `decodeSafeInnerRevert`, `classifyBroadcastError` → `alreadySettled`, lock по адресу Kernel и **запрет слепого ретрая** (§6).
3. `packages/marketplace/venue-base/src/create-base-venue.ts:58-90`: опциональный `safeBroadcaster`, ослабить assert на `walletClient.account`.
4. `operator/src/daemon/composition-root.ts:~2241-2260,2355`: выбор broadcaster'а по конфигу.
5. `operator/src/config.ts` + `config/native-sections.ts`: секция `signer: { kind: 'keystore' | 'agent-signer', bin, config, account, sponsored }`.
6. `operator/src/main.ts:1305-1440`: при `agent-signer` не расшифровывать agent-ключ. `agentEoaAddress := kernel`, `createClients` → `agentSignerTransport`.
7. `operator/src/cli/execution-context.ts:259-285`, `cli/commands/solver-plugins.ts:238,298` → `KernelSafeBroadcaster`.
8. `operator/src/erc8004/identity.ts:640-690`, `validation.ts:130-200`, `solvernets/daemon-init.ts:223`: walletClient на transport. Проверить, что `viemSendTransactionWithRetry` не пытается вести EOA-nonce для json-rpc аккаунта; иначе отдельный путь.
9. **Ридеры, декодирующие внешний `tx.input` как `Safe.execTransaction`** — критично и затрагивает **чужих** операторов, которые проверяют наши транзакции:
   - `packages/marketplace/venue-base/src/verdict.ts:322-345` (проверка verdict любой стороной),
   - `operator/src/daemon/native-base-sepolia-infrastructure.ts:1379-1390` (settlement reader).
   При 4337 внешний tx — `EntryPoint.handleOps`. Нужен декодер «handleOps → op.callData → Kernel.execute → Safe.execTransaction» (или trace). Без upstream-PR наши verdict/settlement-транзакции будут для пиров «orphaned/не bound».
10. Off-chain: attestation key (§4.2) вместо `agentEoaPrivateKey` в `signTaskV1`/`signCanonical`/`envelopeDeps`/`liveCapturePublisher`/`corpus`/`legacyBridgeSigner` (`main.ts:1676,1753,1790,1839,2007`, `adapters/mech/adapter.ts:462-505`, `requester-adapter.ts:240-277`, `cli/commands/tasks.ts:840`).
11. `daemon/balance-topup-loop.ts`: для Kernel либо отключить пополнение agent EOA, либо фондировать Kernel/paymaster deposit.

### Фаза 2 — bootstrap и master
12. `earning/bootstrap.ts`: `stepStolasStake` передаёт `agentInstance = kernel` (стр. 1609-1620). `stepDeployMech` (1702-1790) переходит на root-путь. В `stepRegisterAgent` (1816-…) `register` идёт от Kernel, `setAgentWallet` — по схеме approveHash+v=1. Self-bond шаги (2048-2475): `initPredictedSafe/initDeployedSafe` (protocol-kit с `signerKey`) заменяются на прямой `SafeProxyFactory.createProxyWithNonce` + `execTransaction` v=1, `executeSafeTxBatch` — на MultiSendCallOnly.
13. `earning/safe-adapter.ts`: kernel-варианты `executeSafeTxBatch/Direct`.
14. `earning/agent-wallet-binding.ts:226-330`: ветка `bindAgentWalletViaApprovedHash`.
15. Master-роль на Kernel root-путь или оставить master EOA в keystore. Затрагивает `bootstrap.ts:1626,1729,2709`, `main.ts:2393`, `fleet-retire.ts:76`, `withdraw/*`, `orphan-sweep.ts`, `daemon/degraded-recovery.ts:177`, `adapters/mech/contracts.ts:120`. Если stOLAS staking guard включён, master должен быть whitelisted как curating agent (`ExternalStakingDistributor.sol:614-621`), а значит Kernel надо вносить в whitelist.

### Фаза 3 — native mode
16. Поправка спеки ceremony (tx-ceremony) + `packages/trust/core/src/ceremony.ts`, `daemon/native-trust-catalog.ts:159-183` + anchor через газовый EOA (или ридер, понимающий handleOps). Это зависит от команды Jinn.

### Оценка (честно)
- Фаза 0: 3-5 дней (наша сторона).
- Фаза 1 (MVP: legacy mode, сервис забутстраплен вручную или старым способом): 2-3 недели на одного инженера, включая тесты на anvil-форке Base Sepolia с локальным bundler'ом. Самые рискованные места — п.9 (ридеры) и семантика ретраев/идемпотентности.
- Фаза 2: ещё 1-2 недели.
- Фаза 3: от 1-2 недель кода плюс неопределённое время ревью спеки upstream.
- Итого полный перенос: примерно 5-8 недель. Поддерживать форк дорого: `next` активно force-push'ится (при fetch был forced update), `main.ts` — 2591 строка, `bootstrap.ts` — 2743. Реалистичный путь — upstream-PR «signer injection» (п.3-4, 9) в Jinn: их venue-base уже декларирует signer-injection-only.

### Побочная находка (не запускал, вероятный баг upstream)
`packages/marketplace/venue-base/src/writers/settlement.ts:33` — `DEFAULT_MULTISEND_ADDRESS = "0x40A2aCCbd92BCA938b02010E17A5b8929b49130"`. Это **39 hex-символов**, обрезан хвостовой `D` (правильный MultiSendCallOnly 1.3.0 — `…130D`, как в `contracts/scripts/deploy-stolas-l2.ts:85`). `multiSendAddress` нигде не передаётся (стр. 91, 384). Значит, `settleRevisedSolutionDelivery` должен падать на валидации адреса viem **[I]**.

---

## 6. TypeScript-набросок адаптера

```ts
// operator/src/signer/agent-signer-cli.ts
import { spawn } from 'node:child_process';
import type { Address, Hex } from 'viem';

export interface AgentSignerConfig {
  readonly bin: string;          // путь к agent-signer
  readonly configPath: string;   // --agent <config.json>
  readonly account: Address;     // адрес Kernel (pinned)
  readonly sponsored?: boolean;
  readonly timeoutMs?: number;   // > 120s, т.к. CLI сам ждёт включения до 120s
}

export interface AgentSignerResult {
  readonly account: Address;
  readonly userOpHash: Hex;
  readonly txHash: Hex;
  readonly blockNumber: bigint;
  readonly gasUsed: bigint;
}

export type AgentSignerErrorKind =
  | 'policy-denied'      // AA24/AA2x: AgentPolicy вернула SIG_VALIDATION_FAILED
  | 'policy-expired'     // AA22: validUntil
  | 'nonce'              // AA25: гонка nonce — ретраибельно ПОСЛЕ reconcile
  | 'simulation-revert'  // eth_estimateUserOperationGas упал на revert внутреннего вызова
  | 'execution-revert'   // включён, но UserOperationEvent.success == false
  | 'not-included'       // принят bundler'ом, не включён за 120s — НЕ ретраить вслепую
  | 'hardware'           // TPM/SE/TROPIC01
  | 'config'             // ENOENT, нет фичи, неверный конфиг
  | 'unknown';

export class AgentSignerError extends Error {
  readonly name = 'AgentSignerError';
  constructor(
    readonly kind: AgentSignerErrorKind,
    message: string,
    readonly stderr: string,
    readonly exitCode: number | null,
    readonly userOpHash: Hex | null, // распарсен из stderr ("userOpHash:     0x…") для reconcile
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

/** Логи одного userOp в бандле: всё после предыдущего UserOperationEvent (или BeforeExecution) до своего. */
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
    } catch { /* BeforeExecution и др. */ }
  }
  throw new Error(`UserOperationEvent ${userOpHash} not found in bundle receipt`);
}

export function createKernelSafeBroadcaster(input: {
  readonly chainId: number;
  readonly safeAddress: Address;
  readonly publicClient: PublicClient;
  readonly signer: AgentSignerConfig;      // signer.account == Kernel == owner Safe
  readonly lock: BroadcastLock;            // тот же durable lock venue-base, ключ = Kernel
}): BaseVenueSafeBroadcaster {
  const kernel = input.signer.account;
  const signature = encodePreValidatedSignature(kernel); // r=Kernel, s=0, v=1 → msg.sender == owner

  async function innerRevert(req: SafeBroadcastRequest, txHash: Hex | null) {
    if ((req.operation ?? 0) === 1) return undefined; // eth_call не умеет delegatecall (как в Jinn #3905)
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
      // Safe.execTransaction не payable-переносит value: ETH берётся с баланса Safe, outer value = 0.
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
      // ВАЖНО: v=1 подпись не коммитит Safe-nonce в calldata. Если op уже принят bundler'ом
      // ('not-included' / таймаут), повторная отправка с новым Kernel-nonce может исполнить
      // тот же вызов ДВАЖДЫ. Перед любым ретраем — reconcile по err.userOpHash
      // (eth_getUserOperationReceipt), а не слепой retry.
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
        } catch { /* не событие роутера */ }
      }
      throw new Error(`no TaskCreated in ${receipt.txHash}`);
    },
  };
}
```

```ts
// operator/src/signer/agent-signer-transport.ts — прямые вызовы (IdentityRegistry.setMetadata, ValidationRegistry)
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
        return r.txHash; // CLI уже дождался включения и success; waitForTransactionReceipt вернётся сразу
      }
      if (/^(personal_sign|eth_sign|eth_signTypedData(_v4)?|eth_signTransaction)$/.test(method)) {
        throw new Error(`${method}: off-chain signing is not available for the Kernel agent (ERC-1271 disabled)`);
      }
      return rpc.request({ method, params } as never);
    },
  });
}
// использование:
// const walletClient = createWalletClient({ account: kernelAddress, chain: baseSepolia, transport: agentSignerTransport(rpc, cfg) });
```

Замечания к наброску:
- `getTransactionReceipt(txHash)` — receipt всего бандла. Логи режутся по `UserOperationEvent`, иначе в чужом userOp того же бандла можно поймать «свой» `TaskCreated`/`claim`. Лучше, если CLI сам будет отдавать `logs` (Фаза 0.1).
- Каждая операция = spawn + две аппаратные подписи (CLI подписывает до и после оценки bundler'а, `chain.rs:~335-350`) + ожидание включения (поллинг раз в 2 с). Это приемлемо для темпа Jinn: claim → deliver → settle, единицы операций на задачу.
- `viem custom` с json-rpc аккаунтом шлёт `eth_sendTransaction` без локального заполнения nonce/gas **[I — поведение viem, не прогонял]**.

---

## 7. Что проверено, а что выведено

**Проверено чтением кода [V]:** все file:line из §1 и §3, включая логику Safe-broadcaster'ов, eth_sign v+4 vs v=1, `ExternalStakingDistributor` (v=1 с `msg.sender == owner`, swapOwner на agentInstance, guard+modules), `MultisigGuard` (guard-слот, модули, без проверки владельцев), `StakingBase` (proxyHash/threshold), activity checker (`nonce()`), `OlasMech.isOperator`, `JinnRouterV4` (msg.sender = mech operator/party), upstream `ServiceRegistryL2.registerAgents` (нет EOA-проверки), Kernel `onERC721Received`, ERC-8128 verify = ecrecover, неподключённый ScopedSigner, отсутствие sign-эндпоинтов в HTTP API, ceremony/anchor-ридер, ридеры с декодом внешнего `tx.input`, обрезанный MultiSend-адрес, сообщения об ошибках нашего CLI (`chain.rs`).

**Выведено [I]:**
- Safe 1.3.0 `checkNSignatures` v==1 и путь `approveHash` для 1271 через CompatibilityFallbackHandler. Логика стандартная, но исходник Safe/handler в этом репо не vendored.
- ERC-8004 IdentityRegistry использует `_safeMint` и проверяет `setAgentWallet` через ERC-1271 у `newWallet`. Видно из комментариев/ABI Jinn, исходник реестра не читал.
- Разные nonce-key для root/agent путей Kernel v3.
- Поведение viem `custom` для json-rpc аккаунта.
- Поддержка Ed25519 в TROPIC01.
- Что `DEFAULT_MULTISEND_ADDRESS` реально ломает settlement V4 (не запускал).
- Что все off-chain верификаторы Jinn сверяют подпись только с адресом внутри документа. Проверено для `integrity.ts:96`, остальные — по grep.
- GnosisSafeSameAddressMultisig (self-bond deploy) сверяет владельцев Safe с agent instances — upstream-контракт не читал. Если это так, Kernel как instance и owner согласован.
