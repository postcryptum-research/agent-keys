# Olas (Autonolas) → agent-keys: где подключать аппаратного Kernel-владельца

Прочитаны следующие репозитории (пути ниже относительно корня каждого):

| Репозиторий | Коммит | Дата | Версия |
|---|---|---|---|
| `valory-xyz/open-autonomy` | `62033a2` | 2026-09-14 | 0.21.29 |
| `valory-xyz/open-aea` | `e2e8a83` | 2026-09-01 | 2.2.9 |
| `valory-xyz/olas-operate-middleware` (Pearl backend) | `1077ee7` | 2026-10-13 | — |
| `valory-xyz/autonolas-registries` | `cadf962` | 2026-10-16 | — |

Для справки по `checkNSignatures` использован `safe-global/safe-smart-account` с тегом `v1.3.0`.

Легенда: **[V]** — проверено чтением кода (file:line) или прогоном. **[I]** — вывод, в коде не проверялся.

> **Итог в одном абзаце.**
> Простая замена «agent EOA → Kernel» в Olas **не работает**, и дело не в контрактах. Контракты Kernel принимают: registries, Safe и staking не требуют, чтобы agent instance или owner был EOA (§4).
> Мешает то, что у агента Olas **один secp256k1-ключ несёт три роли**:
> - (1) консенсусная идентичность. Каждый ABCI-payload подписан и проверяется ecrecover'ом против `payload.sender`;
> - (2) on-chain agent instance и owner Safe;
> - (3) keeper-EOA, который сам шлёт `execTransaction` и платит газ.
>
> Kernel может забрать роли (2) и (3), но не роль (1). Поэтому правильный шов — **разделение идентичностей**:
> - консенсусный ключ остаётся (незафондированный, не owner, без денег);
> - owner Safe и agent instance становятся Kernel;
> - в `transaction_settlement_abci` меняются четыре точки: «подпись» (v=1 вместо ECDSA), отправитель и транспорт keeper'а (userOp вместо EOA-tx), верификация (событие Safe вместо декодирования внешнего tx) и nonce/ретраи.
>
> Для 1-of-1 сервисов (все сервисы Pearl) это небольшой, локализованный патч. Для n-of-m всё работает, но с оговорками, они в §2.3.
> Crypto-плагин open-aea (вариант B) в одиночку **не годится**. Годится только **LedgerApi-плагин как транспорт** внутри варианта A (§2.4).
> Демо на Base Sepolia, собранное из кода самого open-autonomy, уже частично прогнано (§6).

> **Статус на стороне agent-keys (2026-10-20), обновляет §3.1, §6 и «Фазу 0»:**
> - `agent-signer op send --nonce <uint256>` и `nonce` в JSON-выводе **сделаны** (п. 0.1, кроме
>   `logs`/`success` — логи своего userOp режет вызывающая сторона, см. `examples/jinn`).
>   Повтор с уже включённым nonce отклоняется до отправки («already used»).
> - **Полный прогон `--send` выполнен** на Base Sepolia, ключ агента в TROPIC01 (permission
>   `trs3`, AgentPolicy v3): Safe-tx, собранная функциями open-autonomy, исполнена через Kernel
>   (tx `0xd8bcb257868000bf3159dd84199cfcbc35e6e8cd972c3a4ec14bd6c38958d0a2`, Safe nonce 4 → 5);
>   upstream `verify_tx` → `False`, событийная проверка → `True`; повтор keeper'а с записанным
>   nonce отклонён — двойного исполнения нет. Вывод — `README.md`.
> - Баги §8.1 и §8.3 перепроверены по коду (`behaviours.py:252,575`, `contract.py:480`;
>   `behaviours.py:919-942`).
> - 0.2 (`SafeNonceAssert`) и 0.3 (`approveHash` с пересчётом хеша) не делались.

---

## 1. Как Olas подписывает и отправляет Safe-транзакцию сегодня

### 1.1 Ключ агента в open-aea

**Загрузка ключа:**
- Агент получает ключ из файла `ethereum_private_key.txt`, путь задан в `private_key_paths` aea-config. `Wallet` → `CryptoStore` вызывает `make_crypto(identifier, private_key_path, password)` для каждого ledger id (`aea/crypto/wallet.py:57-62`) **[V]**.
- `CryptoStore` **сразу читает `crypto.private_key`** (`wallet.py:62`) **[V]**.
- `EthereumCrypto.load_private_key_from_path` делает `Account.from_key` (keystore допускается при наличии пароля) (`plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py:837-864`) **[V]**.

**Подписи:**
- `EthereumCrypto.sign_message(message, is_deprecated_mode)`: если `is_deprecated_mode and len(message)==32`, то `unsafe_sign_hash`, то есть **сырой ECDSA над 32-байтным хешем**, v=27/28. Иначе EIP-191 `encode_defunct` (`ethereum.py:866-883`) **[V]**.
- `sign_transaction` подписывает EOA-tx и отдаёт `{raw_transaction, hash, r, s, v}` (`ethereum.py:885-898`, транслятор `ethereum.py:655-691`) **[V]**.

**Маршрут подписи:**
- Скилл → `SigningMessage` → DecisionMaker → `wallet.sign_message/sign_transaction(ledger_id, …)` (`aea/decision_maker/default.py:156-216`, `aea/crypto/wallet.py:149-186`) **[V]**.
- Crypto выбирается по `ledger_id`, на практике это `default_ledger_id` = `ethereum`.

**Прецедент `aea-ledger-ethereum-hwi`:**
- Плагин регистрируется через entry points `aea.cryptos` / `aea.ledger_apis` с **отдельным** id `ethereum_hwi` (`plugins/aea-ledger-ethereum-hwi/setup.py:55-60`) **[V]**.
- `private_key`, `load_private_key_from_path`, `generate_private_key`, `encrypt` и `decrypt` у него бросают `NotImplementedError` (`aea_ledger_ethereum_hwi/hwi.py:101-213`) **[V]**.
- Используется **только CLI `autonomy`** для owner/operator-операций (`autonomy mint … --hwi`, `autonomy/cli/mint.py:80`; `OnChainHelper.get_ledger_and_crypto_objects`, `autonomy/chain/config.py:249-280`) **[V]**.
- В рантайм агента его не загрузить: `CryptoStore` дёргает `crypto.private_key` (`wallet.py:62`) и получит исключение **[V по коду, не запускал]**.
- Значит, **аппаратного прецедента для агента в Olas нет**. Есть только прецедент для владельца сервиса.

### 1.2 Поток `transaction_settlement_abci` (одинаков для 1 и n агентов)

FSM: `RandomnessTransactionSubmissionRound → SelectKeeperTransactionSubmissionARound → CollectSignatureRound → FinalizationRound → ValidateTransactionRound → Finished`. Ветки ретраев идут через `SelectKeeper…B`, `CheckTransactionHistory`, `SynchronizeLateMessages`, `CheckLateTxHashes` (`skills/transaction_settlement_abci/rounds.py:632-805`) **[V]**.

| Шаг | Кто | Что именно | file:line |
|---|---|---|---|
| 0. safe tx hash | **Прикладной скилл**, каждый агент сам | `GnosisSafeContract.get_raw_safe_transaction_hash(to, value, data, operation, safe_tx_gas, …)`: EIP-712 `SafeTx` + домен `{chainId, verifyingContract}` для Safe ≥1.3.0. Nonce берётся из `Safe.nonce()`, если не задан. Хеш, параметры и calldata пакуются в `hash_payload_to_hex` и проходят консенсус как `most_voted_tx_hash`. Пример: `funds_forwarder_abci/behaviours.py:71-100,143-151` | `contracts/gnosis_safe/contract.py:246-348`; `transaction_settlement_abci/payload_tools.py:91-188` **[V]** |
| 1. keeper | Все | Детерминированно-случайный выбор из `participants − blacklisted` с seed из randomness-раунда. Список keepers сериализуется в консенсус | `abstract_round_abci/common.py:166-200`; `transaction_settlement_abci/behaviours.py:356-434` **[V]** |
| 2. подпись | **Каждый** агент | `SignatureBehaviour._get_safe_tx_signature`: `get_signature(safe_tx_hash_bytes, is_deprecated_mode=True)`, т.е. **сырой ECDSA над safeTxHash, не eth_sign**. Safe проверяет его веткой `ecrecover(dataHash, v, r, s)` (`GnosisSafe.sol:297-299` v1.3.0). Подпись (hex без `0x`) уходит в `SignaturePayload` | `behaviours.py:772-815`; `abstract_round_abci/behaviour_utils.py:968-1004,1492-1516` **[V]** |
| 3. сбор | Консенсус | `CollectSignatureRound(CollectDifferentUntilThresholdRound)` ждёт ≥ `consensus_threshold` разных подписей. Порог = `ceil((2n+1)/3)`, если не задан явно. Подписи раунд **не проверяет** | `rounds.py:256-263`; `abstract_round_abci/base.py:891-906,1860-1864`; `abstract_round_abci/utils.py:414-421` **[V]** |
| 4. упаковка | keeper (через contract_api) | `get_packed_signatures(owners=participants, signatures_by_owner)`: сортировка `owners` по `str.lower`, конкатенация 65-байтных подписей **ключом по адресу участника** | `contract.py:350-364` **[V]** |
| 5. отправка | **Только keeper** | `FinalizeBehaviour._sender_act`, затем `_send_safe_transaction` → `get_raw_safe_transaction(sender_address=self.context.agent_address, owners=participants, …, nonce=mutable_params.nonce, old_price=…)`. Внутри: `execTransaction(…, signatures)`, `from = keeper`, **EOA-nonce = `get_transaction_count(keeper)`**, газ = `try_get_gas_pricing(old_price)` (репрайсинг), `eth_estimateGas` **от имени keeper'а** | `behaviours.py:818-951`; `contract.py:366-481` **[V]** |
| 6. EOA-tx | keeper | `send_raw_transaction`: DecisionMaker → `EthereumCrypto.sign_transaction`, затем ledger connection → `eth_sendRawTransaction`. Хеш из ответа сверяется с `signed_tx["hash"]` | `behaviour_utils.py:1518-1623`; `open-aea/packages/valory/connections/ledger/ledger_dispatcher.py:385-418` **[V]** |
| 7. учёт | keeper | `_get_tx_data`: сохраняет `tx_hash`, **EOA-nonce** и газ-параметры в `mutable_params` (для замены tx по тому же nonce). Ошибки RPC классифицируются: INSUFFICIENT_FUNDS ведёт в blacklist keeper'а, INCORRECT_NONCE, ALREADY_KNOWN | `behaviours.py:165-283` **[V]** |
| 8. валидация | Все | `ValidateTransactionBehaviour`: `get_transaction_receipt(tx)`, затем `GnosisSafeContract.verify_tx`. Тот **декодирует `transaction.input` внешнего tx как `execTransaction`** ABI Safe, сравнивает to/value/data/…/signatures и требует `"execTransaction" in decoded[0]` и `receipt.status` | `behaviours.py:445-510`; `contract.py:500-612` **[V]** |
| 9. история | Все | `CheckTransactionHistoryBehaviour`: сравнивает `Safe.nonce()` с `mutable_params.nonce`, перебирает свои tx hashes через `verify_tx`. Для неудачных tx вызывает `revert_reason`, т.е. replay `eth_call(from=tx.from, to=tx.to, data=tx.input)` на блоке −1, и ищет GS026 («nonce reused») | `behaviours.py:513-678`; `contract.py:614-650` **[V]** |
| 10. late messages | Все | Поздние ответы contract_api (raw tx) кешируются и **переотправляются** в `SynchronizeLateMessagesBehaviour` | `behaviours.py:699-769,953-966` **[V]** |

**Single-agent и multi-agent отличаются только мощностью множеств:**
- В 1-of-1 keeper всегда сам агент, порог равен 1, подпись одна.
- В n-of-m keeper случаен, собирается ≥`ceil((2n+1)/3)` подписей, порог Safe = `service.threshold`. Реестр требует `threshold ≥ ceil((2n+1)/3)` (`autonolas-registries/contracts/ServiceRegistryL2.sol:190-197`) **[V]**.
- Owners Safe — это ровно агенты, так как `participants` = `ALL_PARTICIPANTS` = on-chain `agentInstances` (§4.4).

### 1.3 Где ещё используется тот же ключ (важно для шва)

| Роль | Как | file:line |
|---|---|---|
| Подпись **каждого ABCI-payload** | `_send_transaction` подписывает `payload.encode()` (EIP-191). `check_tx` и `deliver_tx` вызывают `Transaction.verify`, а тот делает `LedgerApis.recover_message(...)` и требует `payload.sender ∈ addresses` | `abstract_round_abci/behaviour_utils.py:~813-852`; `abstract_round_abci/base.py:284-296`; `abstract_round_abci/handlers.py:156-162,232` **[V]** |
| Членство в раунде | `sender ∈ participants` / `accepting_payloads_from` | `abstract_round_abci/base.py:1416-1425,1688-1700` **[V]** |
| On-chain самопроверка | `my_address ∈ getAgentInstances(serviceId)`. В `registration_abci` только при `share_tm_config_on_startup=true`; в `identify_service_owner_abci` всегда | `registration_abci/behaviours.py:258-262,421-427`; `identify_service_owner_abci/behaviours.py:140-170` **[V]** |
| ACN (libp2p) | Сертификат «agent key подписывает pubkey ACN-ноды» (`aea issue-certificates`); адресация сообщений по `agent_address` | `open-aea/aea/cli/issue_certificates.py:125-175`; `registration_abci/behaviours.py:297-316` **[V]** |
| Tendermint validator | **Отдельный** ed25519 из `tendermint init` (`priv_validator_key.json`), к агенту привязан по маппингу `validator address → agent address` | `autonomy/deploy/generators/localhost/tendermint/app.py:262`; `registration_abci/behaviours.py:321-325` **[V]** |

---

## 2. Шов интеграции

### 2.1 Вариант A: owner Safe и agent instance = Kernel, «подпись» = v=1, keeper = `agent-signer op send`

**Что подтверждено в Safe 1.3.0 (`contracts/GnosisSafe.sol`) [V]:**
- Ветка `v == 1` берёт `currentOwner = address(uint160(uint256(r)))` и требует `msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0`, иначе `GS025` (`GnosisSafe.sol:286-291`).
- Обрабатываются **только первые `threshold` подписей** (`for (i = 0; i < requiredSignatures; i++)`, `:255`). Они должны идти по возрастанию owner'а (`GS026`, `:301`).
- `nonce++` стоит до проверки подписей (`:143-145`). `ExecutionSuccess(txHash, payment)` эмитится при успехе (`:49,186`).

**1-of-1 (все сервисы Pearl, `threshold = len(agent_addresses) = 1`, см. §5) — валиден.**
- `signatures = r=Kernel ‖ s=0 ‖ v=1` и `msg.sender == Kernel` — ровно то, что agent-keys уже делает для Jinn.
- Проверено прогоном (§6): `get_raw_safe_transaction(sender=Kernel, signatures_by_owner={Kernel: v1})` из open-autonomy строит calldata. `eth_estimateGas` **от Kernel** проходит (63 733 gas). Та же подпись от `0x…dEaD` ревертит (оценка 0) **[V прогон]**.
- Порядок подписей в 1-of-1 неважен.

**n-of-m с одним Kernel среди EOA — валиден, с оговорками:**
- Если **keeper — агент Kernel**, его v=1 засчитывается, потому что `msg.sender == Kernel`. Остальные `t−1` подписи — обычные ECDSA. `checkNSignatures` принимает смесь, Safe не ограничивает число v=1 записей, нужен лишь правильный порядок owners **[V `:255-301`]**.
- Если **keeper — EOA-агент**, v=1-запись Kernel'а **ревертит GS025**, если она попала в первые `t` отсортированных записей. Сегодня `get_packed_signatures` пакует все собранные подписи без разбора (`contract.py:355-363`) **[V]**. Возможные выходы:
  - (a) упаковщик выбрасывает v=1-записи owner'ов ≠ sender. Тогда нужны `t` ECDSA от остальных, и толерантность к отказам EOA-части падает (n=4, t=3: нужны все три EOA);
  - (b) агент Kernel на шаге подписи делает on-chain `Safe.approveHash(safeTxHash)` (userOp). Тогда v=1 работает при любом keeper'е через `approvedHashes`. Цена — +1 userOp на каждую Safe-tx, плюс вопрос политики (§3.2);
  - (c) не годится: делать Kernel постоянным keeper'ом, это ломает BFT-ротацию keeper'ов (`behaviours.py:387-434`).
- ERC-1271 (v=0) был бы самым чистым путём для n-of-m: Safe сам позвал бы `Kernel.isValidSignature`. Но у агента 1271 **выключен**, и он не нужен — см. §3.2.

**Что ломается в `transaction_settlement_abci`, если поменять только owner [V для каждого пункта]:**
1. **Идентичность.** `get_packed_signatures(owners=participants, …)` сортирует и ключует по адресам **участников консенсуса**, а не owners Safe (`behaviours.py:925,931`; `contract.py:355`). `sender_address=self.context.agent_address` (`behaviours.py:924`) служит `from` для `eth_estimateGas`. Если agent_address — консенсусный EOA, а owner — Kernel, оценка ревертит (контроль в §6).
2. **Подпись.** `SignatureBehaviour` всегда зовёт ECDSA через DecisionMaker (`behaviours.py:801-815`). Для Kernel нужна константа `r=Kernel,s=0,v=1` (не подпись) или `approveHash`.
3. **Транспорт.** `_get_tx_data → send_raw_transaction` = DecisionMaker `sign_transaction` + `eth_sendRawTransaction` (`behaviours.py:211-217`; `behaviour_utils.py:1518-1623`). Kernel не умеет EOA-tx.
4. **Nonce/газ.** `mutable_params.nonce` — это **EOA-nonce keeper'а** (`contract.py:444-449,480`; `behaviours.py:252,268-281`). Репрайсинг через `try_get_gas_pricing(old_price)` (`contract.py:456-465`). INSUFFICIENT_FUNDS приводит к blacklist keeper'а (`behaviours.py:231-239`). Всё это EOA-семантика. У Kernel nonce в EntryPoint, газ — userOp-поля или paymaster.
5. **Верификация.** `verify_tx` декодирует **внешний** tx как `execTransaction` (`contract.py:583-602`). При 4337 внешний tx — это `EntryPoint.handleOps` от бандлера, поэтому `verified=False` **всегда**. Проверено на реальном tx `0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16` (Jinn-демо, Kernel → Safe v=1): upstream `verify_tx → verified=False, status=1`, событийная проверка `→ True` **[V прогон, §6]**.
6. **История/ревёрты.** `revert_reason` переигрывает внешний tx `eth_call(from=бандлер, to=EntryPoint, data=handleOps)` (`contract.py:631-650`). `handleOps` не ревертит при неудаче внутреннего вызова **[I, семантика EntryPoint v0.7]**, поэтому функция кидает `ValueError("…has not been reverted")`, и путь GS026 не срабатывает. Признак неуспеха при 4337 — `UserOperationEvent.success=false` или отсутствие `ExecutionSuccess(safeTxHash)`.
7. **Повторы — главная опасность, см. §3.1.** v=1 при `msg.sender == owner` **не привязан к safeTxHash и nonce**, поэтому тот же calldata исполнится при любом следующем nonce. А ретрай-логика Olas (keeper retry по PENDING `behaviours.py:412-421`, late messages `:699-769`) рассчитана на то, что повтор либо заменит EOA-tx по тому же nonce, либо упадёт с GS026.
8. **Прочее:** `get_amount_spent` считает `tx.gasPrice × gasUsed` внешнего tx (`contract.py:727-750`). Для бандла это бессмыслица (бандл включает чужие userOps, газ платит paymaster).

### 2.2 Обязательная поправка к A: разделение идентичностей

Kernel не может подписать ABCI-payload: `Transaction.verify` — это ecrecover против `payload.sender` (`base.py:284-296`, `handlers.py:162`) **[V]**. Поэтому вариант «agent_address = Kernel» невозможен без переписывания консенсуса. Делаем так:

```
consensus key  (secp256k1, ethereum_private_key.txt, НЕ owner, НЕ instance, баланс 0)
   ├─ подписи ABCI payload'ов, членство в participants, keeper-ротация
   ├─ ACN-сертификат, маппинг Tendermint validator → agent
   └─ off-chain подписи прикладных скиллов (если есть)  [I: зависит от приложения]
Kernel (ERC-4337, P-256 в TPM/TROPIC01, AgentPolicy)
   ├─ ServiceRegistry agent instance  (registerAgents)
   ├─ owner service Safe              (create(agentInstances, threshold))
   └─ keeper-отправка execTransaction (v=1, msg.sender = Kernel)
```

Нужен маппинг `participant (consensus addr) → safe owner`:
- Его знают **все** агенты: им нужно правильно паковать и проверять.
- Минимально — параметр скилла `safe_owner_address` (по умолчанию = `agent_address`, обратная совместимость).
- Для n-of-m — поле `owner` в `SignaturePayload` (протокол payload'а меняется, нужна координация версий всех агентов сервиса).
- Подделка маппинга безвредна для средств: чужая v=1-запись даст GS025 и обычный FINALIZATION_FAILED. По вреду это эквивалентно мусорной ECDSA-подписи сегодня, которую `CollectSignatureRound` тоже не проверяет (`rounds.py:256-263`) **[V]**.

### 2.3 Сводка по типам сервисов

| Сервис | Работает? | Что нужно |
|---|---|---|
| 1-of-1, Kernel — единственный агент (Pearl) | **Да** | §2.2 + патчи 2–7 из §2.1. Порядок подписей не важен |
| n-of-m, Kernel — один из агентов | **Да, с ухудшением** | + owner-aware упаковка (выбрасывать v=1 owner ≠ sender). Kernel реально «подписывает», только когда он keeper; иначе путь (b) `approveHash` |
| n-of-m, все агенты — Kernel'ы | Только через `approveHash` | При keeper'е K1 валидна лишь v=1 K1. Остальные t−1 Kernel'ов должны заранее сделать `approveHash(h)` (t−1 userOps на Safe-tx) |

### 2.4 Вариант B: свой Crypto/LedgerApi-плагин open-aea. Честная оценка

**Только Crypto-плагин (по образцу hwi) — не работает:**
- Адрес Crypto = `agent_address`, а это консенсусная идентичность. Её проверяют ecrecover'ом **все** агенты через `LedgerApis.recover_message(identifier=default_ledger_id)` (`handlers.py:162`, `base.py:291-293`) **[V]**. Kernel-адрес ecrecover'ом не получить.
- Можно завести свой ledger id со своим `Helper.recover_message` (P-256 + реестр ключей). Но `default_ledger_id` выбирает и ABI контрактов: `Contract.get_instance` берёт `contract_interface[ledger_api.identifier]` (`aea/contracts/base.py:92`), а все `contract.yaml` описывают только `ethereum` **[V]**. Тот же id `ethereum` занять нельзя: реестр кидает `Cannot re-register id` (`aea/crypto/registries/base.py:~191`) **[V]**. Остаётся либо форкать `open-aea-ledger-ethereum`, либо патчить все контракты. Плюс плагин нужен **всем** агентам сервиса.
- `sign_message(safe_tx_hash)` → константа v=1 — тривиально, железо не нужно.
- `sign_transaction(tx_dict)` должен вернуть `{raw_transaction, hash, r, s, v}`. `send_raw_transaction` требует, чтобы хеш от ledger-коннекшена совпал с `signed["hash"]` (`behaviour_utils.py:1615-1621`) **[V]**. Это достижимо, только если Crypto сам собирает и подписывает userOp и отдаёт `userOpHash`. Тогда (1) блокирующая аппаратная подпись и вызов бандлера идут **в потоке DecisionMaker'а**; (2) нужен ещё и `LedgerApi.send_signed_transaction`, который шлёт `eth_sendUserOperation`; (3) нужен свой `get_transaction_receipt` по userOpHash.
- `verify_tx` ходит в web3 **напрямую** (`ledger_api.api.eth.get_transaction`, `contract.py:557`) и декодирует `handleOps` — плагином это не обойти. Значит, контракт патчить всё равно придётся.
- **Вердикт:** B = форк базового плагина + патч контракта + те же ретрай-проблемы. Это больше работы и хрупче, чем A.

**LedgerApi-only плагин как транспорт внутри A — хороший шов:**
- Ledger connection выбирает класс API по `signed_transaction.ledger_id` (`ledger_dispatcher.py:99-115`). Синхронные обработчики он гоняет в executor'е (`connections/ledger/base.py:104-111`) **[V]**. Значит, блокирующий `agent-signer op send` (до 120 с) **не блокирует** цикл агента.
- Плагин `ethereum_userop` (entry point `aea.ledger_apis`, как у hwi) с `send_signed_transaction(body={"to","value","data","nonce"?})` → spawn `agent-signer … --json` → вернуть **хеш внешнего tx**. Тогда `get_transaction_receipt` и все последующие запросы через обычный `ethereum` работают без изменений.
- Crypto для этого id не нужен вовсе. `FinalizeBehaviour` формирует `SignedTransaction(ledger_id="ethereum_userop", body)` сам и шлёт через `_send_transaction_request` (`behaviour_utils.py:1033-1105`) **[V сигнатуры]**.
- Этот плагин можно держать в репо agent-keys: Olas достаточно принять «transport strategy» в скилле (§7, PR3).

---

## 3. Безопасность и корректность

### 3.1 Двойное исполнение из-за v=1 (критично для Olas-ретраев)
- В EOA-мире повторная отправка — это либо **замена** того же EOA-nonce (репрайсинг, `contract.py:444-449`), либо ревёрт GS026: ECDSA подписывает safeTxHash, а в нём Safe-nonce.
- С Kernel каждая отправка — новый userOp с новым nonce EntryPoint. Подпись v=1 от `msg.sender` не зависит от `dataHash` (`GnosisSafe.sol:286-291`) **[V]**. Поэтому **оба** userOp'а могут быть включены, и внутренний вызов исполнится дважды при nonce N и N+1.
- Пути в Olas, которые это провоцируют: keeper retry при PENDING (`behaviours.py:412-421`), повтор после FINALIZE_TIMEOUT (`rounds.py:738,770`), переотправка late messages (`behaviours.py:722-741`) **[V]**.
- Для порогов > 1 с ECDSA-подписями остальных защищает их подпись. Для 1-of-1 (Pearl) защиты нет.

Защиты (нужны обе стороны):
1. **Pin nonce Kernel на Safe-tx.**
   - keeper сохраняет nonce userOp'а в `mutable_params.nonce` (семантически это та же «замена по nonce»). Любая переотправка того же safeTxHash идёт с **тем же** nonce EntryPoint, поэтому включится максимум одна, а повтор после включения даст AA25.
   - Нужен флаг `agent-signer op send --nonce <uint256>` и вывод `nonce` в JSON.
   - Замена pending userOp с бампом комиссий — стандартное правило мемпула бандлеров **[I]**.
2. **On-chain-утверждение nonce.**
   - Kernel `executeBatch([SafeNonceAssert.check(safe, N), Safe.execTransaction(…)])`: крошечный хелпер ревертит, если `Safe.nonce() != N`. Тогда повтор при N+1 невозможен даже при потере локального состояния.
   - AgentPolicy должна разрешать этот батч: хелпер в allow-list, 2 ноги, вторая разбирается как сейчас.
   - Проверять nonce прямо в валидации AgentPolicy нельзя: это чтение чужого storage, запрещено ERC-7562 для незастейканных сущностей **[I]**.

### 3.2 Что видит AgentPolicy в Olas-трафике
- Внутренние Safe-tx Olas: CALL или DELEGATECALL в MultiSend, `safe_gas_price = 0` (Finalize не передаёт gas-поля Safe, `behaviours.py:919-942`) **[V]**.
- AgentPolicy пускает DELEGATECALL в любой allow-listed `(to, multiSend)` и требует, чтобы каждая нога была CALL (`agent-keys/contracts/src/AgentPolicy.sol:197-201,207+`) **[V]**. Значит, можно внести и полный MultiSend 1.3.0, которым пользуются Olas-скиллы (`funds_forwarder_abci` шлёт `DELEGATE_CALL` на `params.multisend_address`, `behaviours.py:143-150`) **[V]**. Адрес задаётся конфигом сервиса **[I]**.
- **Отклонено политикой (и это правильно):**
  - `termination_abci`: `removeOwner`/`swapOwner` через сам Safe (`termination_abci/behaviours.py:297-430`) **[V]**. В Pearl это закрывается RecoveryModule от Master Safe (§5);
  - ERC-8004 `setAgentWallet` в Pearl: MultiSend с ногой `SignMessageLib.signMessage` = DELEGATECALL (`olas-operate-middleware/operate/services/protocol.py:2031-2077`; `open-autonomy/packages/valory/contracts/sign_message_lib/contract.py:73`) **[V]**. Это должен делать root-путь Kernel или Master Safe.
- **`approveHash` для n-of-m (путь b)** — дыра, если разрешить его как есть: агент одобрит любой хеш, политика прообраз не видит.
  - Правильно: AgentPolicy принимает `Safe.approveHash(h)` только в батче вместе с полями SafeTx. Политика сама пересчитывает EIP-712 hash (домен `chainId + safe`, это чистое вычисление) и судит внутренний `(to, selector)` по allow-list.
  - Это ~1–2 дня Solidity на стороне agent-keys **[I, дизайн]**.
- Узкий 1271 для safeTxHash не решает ту же задачу: по хешу политика вызов не видит.

### 3.3 Что остаётся на софт-ключе (консенсусный ключ)
- Без денег, не owner, не instance. Компрометация позволяет голосовать в консенсусе от имени агента: в 1-of-1 — предлагать любые payload'ы.
- **Но** исполнить их можно только через Kernel → AgentPolicy (allow-list, value cap, budget, expiry). Это ровно граница доверия agent-keys.
- В n-of-m компрометация консенсусного ключа даёт не больше, чем сегодня компрометация одного агента (BFT-предположение), а то и меньше: денежных полномочий у ключа нет.
- ACN-сертификат тоже на этом ключе. Pearl делает `add-key ethereum`, `add-key --connection` и `issue-certificates` одним и тем же ключом (`olas-operate-middleware/operate/services/deployment_runner.py:379-403`) **[V]**. Это приемлемо.

---

## 4. Регистрация, деплой, стейкинг, консенсус

### 4.1 ServiceRegistry / ServiceManager
- `ServiceRegistryL2.registerAgents` проверяет manager, длины массивов, состояние, слоты и bond. Проверка «instance ≠ operator» `:439-441`, «instance не занят» `:443-445`. **Проверки на EOA нет** (`contracts/ServiceRegistryL2.sol:382-474`) **[V]**.
- `ServiceManager.registerAgents` добавляет `_checkAgentInstances`, который отвергает только адреса ≤ `0xffff` (`contracts/ServiceManager.sol:169,447-453,460-479`) **[V]**.
- Оговорка: HEAD registries может быть новее задеплоенных контрактов. Что задеплоено на Base, не сверял **[I]**.

### 4.2 Создание multisig
- `GnosisSafeMultisig.create(owners, threshold, data)` → `setup(owners, threshold, …)` через `createProxyWithNonce` + проверка singleton (`contracts/multisigs/GnosisSafeMultisig.sol:104-128`) **[V]**.
- Safe `setupOwners` проверяет только `≠ 0`, `≠ SENTINEL`, `≠ this` и уникальность. Контракт-owner допустим (`safe-1.3.0/contracts/base/OwnerManager.sol:35-37`) **[V]**.
- `SafeMultisigWithRecoveryModule` — дефолт Pearl. Делает то же и включает RecoveryModule (`contracts/multisigs/SafeMultisigWithRecoveryModule.sol:70-99`) **[V по отчёту + выборочно]**.
- `GnosisSafeSameAddressMultisig.create` (переиспользование Safe):
  - проверяет codehash прокси;
  - **вызывает `multisig.call(payload)`**, где payload — `execTransaction` с подписями текущих owners;
  - затем сверяет `getOwners()` (в обратном порядке) и `getThreshold()` с instances и threshold (`GnosisSafeSameAddressMultisig.sol:~106-180`) **[V]**.
  - Здесь `msg.sender` для Safe — сам контракт SameAddressMultisig. Поэтому если текущий owner — Kernel, его подпись в payload должна идти по пути `approvedHashes`: Kernel root-путём заранее делает `approveHash(h)`, затем v=1. Ровно так Pearl уже делает с Master Safe (`operate/services/protocol.py:2080-2098,2192-2213`) **[V]**.
- `RecoveryModule.recoverAccess` (service owner, `PreRegistration`) снимает всех agent-owners модулем и `swapOwner`-ом ставит service owner'а (`contracts/multisigs/RecoveryModule.sol:232-276`) **[V]**. Тип owner'а не важен. Потеря железа не равна потере Safe.

### 4.3 Staking
- `StakingBase` при stake проверяет `numAgentInstances`, `threshold` (если задан), `service.multisig.codehash == proxyHash` и agentIds (`contracts/staking/StakingBase.sol:880-913`) **[V]**. Тип owner'а не проверяется.
- `StakingActivityChecker.getMultisigNonces` = `IMultisig(multisig).nonce()` (`StakingActivityChecker.sol:36-39`) **[V]**. Safe-nonce растёт и при v=1-исполнении (`GnosisSafe.sol:143`) **[V]**. Прикладные checker'ы (mech-запросы и т.п.) считают действия по `msg.sender == multisig`, а тот не меняется **[I, в прочитанных репо их нет]**.
- Награды идут на multisig, без изменений.

### 4.4 Деплой open-autonomy
- `autonomy deploy from-token` берёт `agentInstances` из реестра в `ALL_PARTICIPANTS`, multisig — в `SAFE_CONTRACT_ADDRESS` (`autonomy/cli/helpers/deployment.py:338-358`; `autonomy/deploy/base.py:543-575`) **[V]**.
- Затем требует, чтобы ключи из `keys.json` совпадали с `all_participants` (`autonomy/deploy/base.py:392-401`) **[V]**.
- При Kernel-instance ключа с адресом Kernel нет и быть не может. Деплой должен класть в `ALL_PARTICIPANTS` **консенсусные адреса**, а Kernel передавать отдельным параметром (`SAFE_OWNER_ADDRESS`/маппинг).

### 4.5 Отдельный ключ — что остаётся и приемлемо ли
Остаются ровно:
1. **консенсусный secp256k1** (ABCI payloads, participants, ACN-сертификат);
2. **ed25519 Tendermint-валидатора** — так и сегодня (`tendermint init`).

Ни один не держит средств, не владеет Safe и не является on-chain instance. Это приемлемо и совпадает с подходом Jinn: незафондированный attestation key. Бонус: ротация железного ключа внутри Kernel не меняет agent instance. А ротация консенсусного ключа не требует on-chain-перерегистрации, нужен только новый `ALL_PARTICIPANTS`. В Pearl сейчас смена agent EOA = teardown и перерегистрация (`operate/services/manage.py:648-650`) **[V]**.

---

## 5. Pearl / olas-operate-middleware

### 5.1 Где ключи [V]
**Agent EOA:**
- Создаётся `KeysManager.create`: `EthereumCrypto()` → V3-keystore по `OPERATE_USER_PASSWORD`, **либо plaintext hex без пароля** (`operate/keys.py:168-196`).
- Файлы `<OPERATE_HOME>/keys/<address>` и `.bak`, где `OPERATE_HOME = cwd/.operate` (`operate/constants.py:26-30`; `operate/cli.py:202-212`).
- Один агент на сервис: `NUM_LOCAL_AGENT_INSTANCES = 1` (`operate/services/manage.py:105,294-297`).

**Передача агенту:**
- Host-деплой (дефолт): `keys.json` с зашифрованной записью → `ethereum_private_key.txt` (0600) → `aea add-key --password … ethereum`, `--connection`, `issue-certificates` (`operate/services/service.py:631-721`; `operate/services/deployment_runner.py:333-403`).
- Docker/k8s: `keys.json` **в plaintext** (`get_decrypted`), затем удаляется (`service.py:481-553`).
- Пароль агенту передаётся argv-аргументом `--password` или через stdin (`deployment_runner.py:656-691`).

**Master EOA:**
- Keystore `wallets/ethereum.txt` + зашифрованный мнемоник (`operate/wallet/master.py:993-1035`).
- **Master Safe**: owner = Master EOA (+ опциональный backup owner), threshold 1 (`operate/utils/gnosis.py:219-266`; `master.py:1207-1241`).

### 5.2 Цепочка
Master EOA → Master Safe (service owner) → mint (`threshold = len(agent_addresses) = 1`) → activate → `registerAgents(instances = agent_addresses)` → deploy через `SafeMultisigWithRecoveryModule` → stake. Обычно это **один MultiSend-tx Master Safe**, подписанный ECDSA Master EOA (`manage.py:444-993`, `750,863,896-989`; `protocol.py:107-238,1409-1638`).

### 5.3 `gas_abstraction.py` — не про агента
- EIP-7702 + ERC-4337 v0.8 + Circle Paymaster (газ в USDC) через публичный бандлер Candide, **только для Master EOA** в funding-run'ах (bridge/swap) (`operate/wallet/gas_abstraction.py:20-26,211-554`; использование `operate/funding_run/manager.py:83-89,185-198,1434-1450`).
- Это прецедент «Pearl уже умеет userOps». Kernel и agent-путь он не покрывает.

### 5.4 Что затронет замена agent EOA на Kernel [V места, I оценки]
| Область | Места | Изменение |
|---|---|---|
| Модель сервиса | `service.agent_addresses` (`manage.py:294-297`) — одновременно on-chain instance, owner и имя key-файла | Разделить на `agent_account` (Kernel) и `agent_key` (консенсус) |
| Регистрация | `manage.py:913-919,1124-1130`, сравнение `manage.py:648-650` | instances = Kernel |
| Runtime-env | `ALL_PARTICIPANTS = chain_data.instances` (`service.py:170-231,188-191`) | = консенсусные адреса + новый `SAFE_OWNER_ADDRESS` |
| Middleware **сам подписывает agent-ключом** | ERC-8004 `setAgentWallet` (`manage.py:1250-1271`); swap owner при terminate (`manage.py:1622-1636`, `protocol.py:998-1086`); `enableModule` на legacy Safe (`manage.py:1701-1767`); claim → transfer (`manage.py:2299-2306`); вывод из Safe (`operate/services/funding_manager.py:272-282`); drain agent EOA (`funding_manager.py:128-248`) | Root-путь Kernel или Master Safe (`recoverAccess` уже покрывает terminate, `manage.py:1456-1466,1689-1698`). Drain EOA не нужен — консенсусный ключ пуст |
| Фондирование | Начальное фондирование agent EOA (`service.py:1416-1440`), top-up по запросу агента (`service.py:1499-1546`, `funding_manager.py:1383-1390`), газ перед swap (`manage.py:1574-1620`) | Убрать. Газ Kernel идёт через paymaster или депозит |
| Ключи Kernel | Нет аналога | Новый менеджер: путь к `agent-signer` и конфигу. Kernel root = Master Safe/Master EOA (решение по дизайну) |
| Восстановление | `discard_all` + новые ключи (`operate/keys.py:202-234`; `operate/wallet/wallet_recovery_manager.py:172-182,495-500`) | Ротация консенсусного ключа без on-chain; ротация железа — `permission rotate` |

---

## 6. Демо: Olas-путь без полного стека, на Base Sepolia

Файл: `olas_kernel_safe_demo.py` (в этой папке). Он использует **код open-autonomy без изменений** и подменяет ровно два EOA-шага.

| Шаг Olas | Функция open-autonomy | В демо |
|---|---|---|
| safeTxHash (прикладной скилл) | `GnosisSafeContract.get_raw_safe_transaction_hash` | Как есть. Сверено с `Safe.getTransactionHash` on-chain |
| payload консенсуса | `payload_tools.hash_payload_to_hex` / `skill_input_hex_to_payload` | Как есть |
| `SignatureBehaviour` | `get_signature(..., is_deprecated_mode=True)` | **Замена:** `r=Kernel‖0‖01` |
| `FinalizeBehaviour` | `GnosisSafeContract.get_raw_safe_transaction(sender_address=Kernel, …)` | Как есть. `eth_estimateGas` от Kernel = on-chain-проверка v=1 |
| `send_raw_transaction` | DecisionMaker + `eth_sendRawTransaction` | **Замена:** `agent-signer op send --target Safe --data … --sponsored --json` |
| `ValidateTransactionBehaviour` | `GnosisSafeContract.verify_tx` | Как есть (ожидаемо `False`) + предлагаемая событийная проверка |

Контракты грузятся через `Contract.from_dir`, как это делает рантайм AEA. Сначала `gnosis_safe_proxy_factory`: его импортирует `gnosis_safe/contract.py:37`.

**Уже прогнано (read-only, публичный RPC `https://sepolia.base.org`, 2026-10-20) [V]:**
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
Проверка верификаторов на существующем tx Jinn-демо (Kernel → Safe, v=1):
```
$ python olas_kernel_safe_demo.py --check-tx 0x451c7214beb0d43dcacf299eb2828c9daeb253ceef3f2ccfdad683535c18dc16
  outer tx: from 0x43370277eCaAb8cb1F98622138Efc679F9aC3063 to 0x0000000071727De22E5E9d8BAf0edAc6f37da032
  upstream GnosisSafeContract.verify_tx -> verified=False status=1
  event-based verify (proposed)          -> {'verified': True, 'success': True, 'failure': False}
```
Полный прогон `--send` выполнен позже — см. статус в начале и `README.md`.

**Пакеты и окружение [V]:**
- Python 3.10–3.14 (`python_requires=">=3.10,<3.15"`, `open-aea/setup.py:123`). Прогон шёл на 3.12.3.
- `pip install open-autonomy==0.21.29 open-aea-ledger-ethereum==2.2.9`. Тянет `open-aea==2.2.9`, `web3==7.16.0`, `eth-account==0.13.7`, `hexbytes==2.0.0`. Ограничения плагина: `web3>=7,<8`, `eth-account>=0.13,<0.14` (`plugins/aea-ledger-ethereum/setup.py:49-53`).

**Подводные камни:**
1. **Колесо `open-autonomy` содержит контракты** (`autonomy/data/contracts/gnosis_safe/contract.py`, идентичен репо), но **не скиллы**. `payload_tools.py` берётся из git-клона (`OPEN_AUTONOMY_SRC`) или `autonomy packages sync`.
2. `GnosisSafeContract` нельзя просто импортировать: `contract_interface` заполняется только при `Contract.from_dir`. И сначала нужен `gnosis_safe_proxy_factory`, иначе `ModuleNotFoundError` **[V прогон]**.
3. `python3 -m venv` на Ubuntu без `python3.12-venv` падает. Обход: `python3 -m venv --without-pip` + `get-pip.py`.
4. hexbytes 2.x: `.hex()` без `0x`. В демо это нормализовано.
5. `chain_id` в contract_api-сообщениях — это **имя цепи** для ledger connection. Dispatcher его вынимает (`open-aea/packages/valory/connections/ledger/contract_dispatcher.py:423-443`), и `get_raw_safe_transaction_hash` берёт chainId из RPC. В демо он передаётся явно.

---

## 7. План патчей и оценка

### Фаза 0 — agent-keys (наша сторона)
0.1. `agent-signer op send`:
  - `--nonce <uint256>` (pin для идемпотентных повторов, §3.1);
  - в JSON добавить `nonce`, `success`, `logs` своего userOp;
  - `userOpHash` печатать в JSON-ошибке.

  ~1–2 дня.

0.2. `SafeNonceAssert` (10 строк) + разрешение батча `[assert, execTransaction]` в AgentPolicy. Либо осознанно полагаться только на 0.1. ~1–2 дня с forge-тестами.

0.3. (для n-of-m) `approveHash` с пересчётом safeTxHash в AgentPolicy (§3.2). ~2 дня.

0.4. LedgerApi-плагин `open-aea-ledger-ethereum-userop` (Python, в репо agent-keys). `send_signed_transaction` → spawn `agent-signer` → хеш внешнего tx, классификация ошибок AA2x/AA3x в строки, которые понимает `__parse_rpc_error` Olas. ~2–3 дня.

### Фаза 1 — open-autonomy, 1-of-1 (файл за файлом)
1. `packages/valory/contracts/gnosis_safe/contract.py`:
   - `verify_tx`: если внешний tx не декодируется как `execTransaction` или `to ≠ safe`, искать в receipt `ExecutionSuccess(safeTxHash)` от `contract_address` и отсутствие `ExecutionFailure(safeTxHash)`. Ожидаемый `safeTxHash` пересчитать из параметров и `safe_nonce`, переданного вызывающим (`contract.py:500-612`);
   - `revert_reason` для неуспеха: `UserOperationEvent.success` / `ExecutionFailure` вместо replay (`:614-650`);
   - `get_packed_signatures(owners, signatures_by_owner, sender=None)`: ключ — **owner Safe**; v=1-записи owner ≠ sender (без `approvedHashes`) выбрасывать (`:350-364`);
   - новый `get_safe_exec_calldata` — только calldata, без EOA-nonce и газа.
2. `packages/valory/skills/transaction_settlement_abci/models.py`: параметры `safe_owner_address` (по умолчанию `agent_address`), `signature_mode: ecdsa|prevalidated`, `tx_submitter: eoa|ledger_api:<id>`, `finalize_timeout` повыше для userOp.
3. `…/behaviours.py`:
   - `SignatureBehaviour._get_safe_tx_signature` (`:801-815`): при `prevalidated` возвращать `r=owner,s=0,v=1`, без DecisionMaker;
   - `FinalizeBehaviour._send_safe_transaction` (`:911-951`): `sender_address = safe_owner_address`, `owners` = owners Safe; при `ledger_api:<id>` — `SignedTransaction(ledger_id=id, body={to: safe, data, value: 0, nonce: pinned})` → `_send_transaction_request`;
   - `_get_tx_data` (`:165-283`): ветка без EOA-nonce и газа; pinned userOp-nonce в `mutable_params.nonce`;
   - `_check_tx_history` (`:554-654`): сравнивать Safe-nonce с **Safe-nonce**, не с EOA-nonce (это и баг, §8.1); события вместо GS026-replay;
   - `SynchronizeLateMessagesBehaviour` (`:722-741`): для userOp **не переотправлять**, а сверять по pinned nonce.
4. `…/rounds.py`: формат хешей (`TX_HASH_LENGTH = 66`, `payloads.py:30`) не меняется, если транспорт возвращает хеш внешнего tx. `fsm_specification.yaml` не трогаем.
5. `registration_abci/behaviours.py:258` и `identify_service_owner_abci/behaviours.py:161`: проверять `safe_owner_address ∈ agentInstances`, а не `agent_address`.
6. `autonomy/deploy/base.py:392-401,543-575` и `autonomy/cli/helpers/deployment.py:338-358`: `ALL_PARTICIPANTS` = консенсусные адреса из `keys.json`; новый override `SAFE_OWNER_ADDRESS` из on-chain instances.

Тест: e2e на Base Sepolia или anvil-форке с одноагентным сервисом (например, `funds_forwarder_abci` или `test_abci`) и Kernel-owner'ом.

### Фаза 2 — n-of-m
7. `SignaturePayload` + поле `owner` (`payloads.py`) и маппинг participant → owner в `SynchronizedData`. Это изменение wire-формата: все агенты сервиса должны обновиться одновременно.
8. Путь (b): `SignatureBehaviour` для Kernel-агента, не являющегося keeper'ом, отправляет `approveHash` (требует 0.3).
9. Тесты: смешанный 3-of-4 и ротация keeper'а.

### Фаза 3 — Pearl
10. Разделение `agent_addresses` (§5.4), регистрация Kernel, `SAFE_OWNER_ADDRESS` в env, отключение фондирования agent EOA.
11. Перевод «middleware подписывает agent-ключом»-мест на root-путь Kernel или Master Safe.
12. Конфигурация `agent-signer`. UI-флоу для привязки железа.

### Оценка (честно)
| Фаза | Срок |
|---|---|
| 0 (наша сторона) | 1–1.5 недели |
| 1 (1-of-1 PoC на форке open-autonomy, без Pearl) | 1.5–2.5 недели. Основные риски — семантика ретраев (§3.1) и требование 100% coverage в CI open-autonomy |
| 2 (n-of-m) | +2–3 недели, включая согласование изменения payload-протокола с Valory |
| 3 (Pearl) | 2–4 недели. Middleware большой: `manage.py` 2535 строк, `protocol.py` 2275 |
| **Итого** | **~6–10 недель**. Демонстрационный 1-of-1 на одном сервисе без Pearl — ~3 недели вместе с фазой 0 |

### Что предлагать upstream (Valory), по убыванию шансов
- **PR1 «transport-agnostic verify_tx»** (`gnosis_safe/contract.py`). Проверка по `ExecutionSuccess(safeTxHash)` с fallback на старое декодирование, плюс фикс §8.1.
  - Полезна и без нас: relayers, модули, 4337, 7702-обёртки.
  - Малый риск, обратная совместимость. **Лучший первый PR.**
- **PR2 «Safe owner ≠ consensus identity»**. Параметр `safe_owner_address` (по умолчанию `agent_address`), owner-keyed packing, правки двух проверок регистрации и `autonomy deploy`.
  - Обосновывается тем, что подпись консенсуса и подпись Safe — разные полномочия. Поворот консенсусного ключа без on-chain-перерегистрации — выгода и для обычных EOA-сервисов.
- **PR3 «signature_mode=prevalidated + tx_submitter=ledger_api:<id>»**. Стратегия отправки через LedgerApi-плагин по id.
  - Сам 4337-плагин остаётся у нас, в Olas — только точка расширения. Ровно так устроен прецедент hwi (entry points).
  - Обязательная часть: pin nonce или запрет слепой переотправки при `prevalidated`.

---

## 8. Побочные находки upstream (проверены чтением кода)

1. **`CheckTransactionHistoryBehaviour` сравнивает Safe-nonce с EOA-nonce keeper'а.**
   - `mutable_params.nonce` заполняется из `raw_transaction.body["nonce"]` (`transaction_settlement_abci/behaviours.py:252,279`). А это `get_transaction_count(sender)` keeper'а (`gnosis_safe/contract.py:444-449,480`), что подтверждает и docstring `models.py:81-85`.
   - Но `_check_tx_history` делает `if safe_nonce == self.params.mutable_params.nonce: … return NOT_VERIFIED` («Safe nonce is the same as the nonce used in the transaction») (`behaviours.py:574-582`) **[V]**.
   - При случайном совпадении чисел история не проверяется. У не-keeper'ов `mutable_params.nonce = None`, и они всегда идут в полную проверку **[I: эффект на практике слабый, не воспроизводил]**.
2. **`EthereumHWICrypto` нельзя загрузить в `Wallet` агента.** `CryptoStore` читает `crypto.private_key` (`open-aea/aea/crypto/wallet.py:62`), а HWI бросает `NotImplementedError` (`aea_ledger_ethereum_hwi/hwi.py:101-109`) **[V код, не запускал]**. Для CLI `autonomy … --hwi` это не баг, но «аппаратный агент» через hwi невозможен в принципе.
3. **Поля SafeTx теряются между хешем и исполнением.** `hash_payload_to_hex` несёт `base_gas`, `safe_gas_price`, `gas_token`, `refund_receiver` (`payload_tools.py:91-164`). А `FinalizeBehaviour` и `_verify_tx` передают в контракт только `safe_tx_gas` и `operation` (`behaviours.py:291-308,919-942`) **[V]**. Если прикладной скилл подпишет хеш с ненулевыми полями, исполнение даст GS026. Сейчас скиллы используют нули, поэтому баг латентный.

---

## 9. Что проверено, а что выведено

**Проверено [V]:**
- Чтением: весь поток `transaction_settlement_abci` (раунды, behaviours, payload tools); `GnosisSafeContract` (hash, packing, raw tx, verify, revert reason, nonce); подпись `EthereumCrypto` (deprecated mode = `unsafe_sign_hash`); DecisionMaker/Wallet; ledger connection (выбор API по ledger id, executor); hwi-плагин и его использование только в CLI; подпись и проверка ABCI-payload'ов; on-chain-самопроверки регистрации; ACN-сертификаты; Tendermint validator key.
- Registries: `registerAgents` L2 и `ServiceManager._checkAgentInstances`, `GnosisSafeMultisig`, `GnosisSafeSameAddressMultisig`, `RecoveryModule`, `StakingBase`, `StakingActivityChecker`.
- Safe 1.3.0: `checkNSignatures` (v=1, порядок, первые `threshold`), `nonce++`, события, `OwnerManager`.
- Pearl: ключи, деплой, места подписи agent-ключом, `gas_abstraction`. Собирал субагент, ключевые цитаты перепроверены выборочно (`keys.py:168-182`, `manage.py:294-297,913-919,1250-1271`, `deployment_runner.py:379-403`, `protocol.py:173-194,2060-2077`, `gas_abstraction.py:20-26`).
- AgentPolicy: DELEGATECALL в allow-listed `(to, multiSend)`.
- Прогоном на Base Sepolia (read-only): совпадение safeTxHash Olas с on-chain; `eth_estimateGas` от Kernel с v=1 проходит, от чужого адреса ревертит; upstream `verify_tx` даёт `False` на 4337-tx, событийная проверка — `True`.

**Выведено [I]:**
- Поведение `handleOps` при ревёрте внутреннего вызова и, как следствие, `revert_reason`.
- Правила замены userOp в мемпуле бандлера.
- Ограничения ERC-7562 на чтение Safe-nonce в валидации.
- Что задеплоенные на Base registries совпадают с HEAD.
- Прикладные activity checker'ы и off-chain подписи конкретных Olas-приложений (trader, optimus и др.) — в прочитанных репо их нет.
- Трудоёмкость.
- Полный `--send`-прогон демо не выполнялся (нужен TROPIC01).
