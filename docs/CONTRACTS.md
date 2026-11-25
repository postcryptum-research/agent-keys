# Contracts

The modules sit in an ERC-4337 smart account, a ZeroDev Kernel v3.3 behind
EntryPoint v0.7. Kernel calls each module from the account, so in every
module call `msg.sender` is the account; the modules have no owner, and they
keep their state per account, in slots of the form ERC-7562 lets an
account's validation touch, `keccak256(account ‖ x) + n` (rule 4 in
`CLAUDE.md`). The paymaster is the one contract with an owner. Addresses
are those of Base Sepolia (chain 84532), from
`contracts/deployments/84532.json`, which keeps earlier instances under
versioned names. Each contract answers `VERSION()`, from 0.1.0, raised
with any change to its bytecode; the instances listed predate it.

| Contract | What it is | Who calls it | Base Sepolia |
|---|---|---|---|
| `P256Validator` | the owner key, as the account's root | Kernel, from the account | `0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2` |
| `P256RecoveryValidator` | the recovery key, granted only `changeRootValidator` | Kernel, from the account | `0x63dd80Fc5E109A44fd179F85050487E02c5e6958` |
| `P256Signer` | the agent key, as one Kernel permission | Kernel, from the account | `0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E` |
| `AgentPolicy` | the agent's mandate, as that permission's policy | Kernel, from the account; the account, for x402 and orders | `0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2` |
| `P256Point` | the on-curve check (library) | the key modules, at install | none: compiled into them |
| `SafeNonceAssert` | the replay guard of an agent's Safe transaction | the account, in a batch | `0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279` |
| `WhitelistPaymaster` | a gas sponsor with a budget per account | the EntryPoint; its owner | `0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001` |
| `IVenueDecoder` | what a trading venue is to the policy (interface) | the policy; the owner's tools | none: an interface |
| `CowSwapDecoder` | CoW Protocol's orders under that interface | the policy; the owner's tools | none recorded |
| `DemoCounter` | a demo target | anyone; the agent in demos | `0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1` |

The addresses are the file's current entries [V `contracts/deployments/84532.json`].
The code at the first three addresses and at `SafeNonceAssert`'s equals what
commit `175acbf3a3127e804a45a3e4dd097165f0a4c922` compiles to, byte for byte; the paymaster's differs only in its
immutable EntryPoint address [V `cast code` against `forge inspect <Name>
deployedBytecode`, 2026-11-24].

## P256Validator

`contracts/src/P256Validator.sol`. An ERC-7579 validator for an account
owned by a raw P-256 key held in hardware: the owner's YubiKey, phone or
chip. The signature is the bare `abi.encodePacked(r, s)`, 64 bytes, over the
hash the account hands over, checked through the RIP-7212 precompile by
Solady's `P256.verifySignature`, which refuses a high `s` [V source;
`contracts/lib/solady/src/utils/P256.sol`].

**Who calls it, and when.** Kernel, from the account [V
`contracts/lib/kernel/src/Kernel.sol`, `core/ValidationManager.sol`]:

- `onInstall` when the account is created with this validator as root
  (`initialize`), when it is made root (`changeRootValidator`), or when it is
  installed as a further validator (`installValidations`);
- `validateUserOp` in the validation phase of an operation signed with the
  owner key (the EntryPoint calls the account, the account calls the
  validator);
- `isValidSignatureWithSender` when anyone asks the account
  `isValidSignature` with a signature for this validator, and, while it is
  root, to check the signature that enables a new validator (Kernel's enable
  mode);
- `onUninstall` from `uninstallValidation`. Kernel goes on with the
  uninstall even if this call reverts (`ModuleLib.uninstallModule`), and
  refuses to uninstall the root validator [V `utils/ModuleLib.sol`,
  `ValidationManager.sol` `_clearValidationData`].

**State per account.** `publicKeys[account] = (x, y)`; `x == 0` means no
key. The account is the mapping's key, so the two words sit at
`keccak256(account ‖ slot)` and the word after it: storage ERC-7562
associates with the account [V source]. One key per account per instance:
a second P-256 key on the same account needs a second contract, which is
what `P256RecoveryValidator` is.

**Functions.**

- `onInstall(abi.encode(x, y))`: enrolls the key. Reverts `AlreadyInitialized`
  if the account has one here, `InvalidPublicKey` if the data is not exactly
  64 bytes or the point is not on P-256. Emits
  `P256KeyRegistered(account, x, y)`.
- `onUninstall(bytes)`: deletes the key; reverts `NotInitialized` if there is
  none. The data is not read.
- `validateUserOp(userOp, userOpHash)`: `0` if `userOp.signature` verifies
  over `userOpHash` under the account's key, `1` otherwise, with no time
  range. A bad signature does not revert.
- `isValidSignatureWithSender(sender, hash, signature)`: the ERC-1271 magic
  value or `0xffffffff`. `sender` is not read.
- `isModuleType(t)`: true only for `MODULE_TYPE_VALIDATOR`;
  `isInitialized(account)`; the getter `publicKeys(account)`.

**Rules.** A signature is exactly 64 bytes; `s` is in the low half; the key
is on P-256 with both coordinates below p, checked once at install; the
install data is the key and nothing more, since #154: the Base
Sepolia instances, older, refuse only shorter data and ignore bytes past
the 64 [V source, `test_validatorInstallDataIsExactlyTheKey`].

**Base Sepolia.** `0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`
(`p256Validator`); earlier, `p256ValidatorV1` [V
`contracts/deployments/84532.json`].

## P256RecoveryValidator

`contracts/src/P256RecoveryValidator.sol`. `P256Validator` under its own
address, for a cold recovery key. Kernel keys a validator's state by
(validator contract, account), so a second key on the same account needs a
second contract. The owner installs it with the recovery key and grants it
the single selector `changeRootValidator`: with it, the recovery key makes
itself root and hands root to a new owner key [V source; `docs/RESILIENCE.md`].

**Who calls it, and when.** As `P256Validator`. In use, its
`validateUserOp` runs for the recovery operation (`owner recover`), whose
call Kernel admits only if its selector was granted to this validator [V
`contracts/lib/kernel/src/Kernel.sol` `validateUserOp`, `grantAccess`].

**State per account, functions, events and errors.** Those of
`P256Validator`, inherited unchanged, with one exception:
`isValidSignatureWithSender` returns `0xffffffff` (`ERC1271_INVALID`) to
every request [V source].

**Rule.** It never vouches for an ERC-1271 signature. Kernel asks an
installed validator to check one without looking at the selectors granted
to it, so a recovery key that could sign messages would sign permits for the
account without ever becoming root [V source; `docs/RESILIENCE.md` §0, item 5].

**Base Sepolia.** `0x63dd80Fc5E109A44fd179F85050487E02c5e6958`
(`p256RecoveryValidator`); earlier, `p256RecoveryValidatorV1` [V
`contracts/deployments/84532.json`].

## P256Signer

`contracts/src/P256Signer.sol`. A Kernel permission signer for a raw P-256
key held in hardware: the agent's key. Where `P256Validator` makes a key the
account's root, this module makes it one permission, which authorizes only
what the policies installed with it allow (`AgentPolicy`) [V source].

**Who calls it, and when.** Kernel, from the account [V
`contracts/lib/kernel/src/core/ValidationManager.sol`]:

- `onInstall` when the owner installs a permission whose signer this is
  (`permission add`, `permission rotate`), with
  `bytes32(id) ‖ abi.encode(x, y)`, where `id` is Kernel's 4-byte permission
  id, left-aligned (`_installPermission`);
- `checkUserOpSignature` in the validation phase of an operation whose nonce
  selects the permission, after the permission's policies have passed it (a
  refusing policy reverts the validation) (`_validateUserOp`,
  `_checkUserOpPolicy`). Kernel removes the policies' parts and the `0xff`
  signer marker from the signature and hands over `r ‖ s`;
- `checkSignature` for an ERC-1271 request naming the permission, after the
  policies' `checkSignaturePolicy` has passed it (`_checkPermissionSignature`).
  `AgentPolicy` refuses every such request but a registered x402
  authorization or order (`docs/ERC1271.md`);
- `onUninstall` when the owner uninstalls the permission (`permission
  revoke`, `permission rotate`), with `bytes32(id) ‖ …`; Kernel goes on even
  if this call reverts (`_uninstallPermission`, `ModuleLib.uninstallModule`).

**State per account.** `publicKeys[id][account] = (x, y)`, `x == 0` meaning
no key, and `usedIds[account]`, the number of the account's permissions with
a key here. The account is the innermost key of both mappings, so the slots
are `keccak256(account ‖ keccak256(id ‖ slot))` (+1) and
`keccak256(account ‖ slot)`: storage ERC-7562 associates with the account
[V source].

**Functions.**

- `onInstall(bytes32(id) ‖ abi.encode(x, y))`: enrolls the permission's key.
  Reverts `AlreadyInitialized` if that id has a key for the account,
  `InvalidPublicKey` if the data is not exactly 96 bytes or the point is not
  on P-256. Increments `usedIds`. Emits `P256SignerRegistered(account, id, x, y)`.
- `onUninstall(bytes32(id) ‖ …)`: deletes the key, decrements `usedIds`;
  reverts `NotInitialized` if that id has no key.
- `checkUserOpSignature(id, userOp, userOpHash)`: `0` if the signature
  verifies under the permission's key, `1` otherwise, with no time range; a
  bad signature does not revert.
- `checkSignature(id, sender, hash, signature)`: the ERC-1271 magic value or
  `0xffffffff`. `sender` is not read.
- `isModuleType(t)`: true only for `MODULE_TYPE_SIGNER`; `isInitialized(account)`
  (true while `usedIds[account] > 0`); the getters `publicKeys(id, account)`
  and `usedIds(account)`.

**Rules.** As `P256Validator`'s: 64-byte signature, low `s`, a key on P-256
checked at install, install data of exactly the id and the key since #154
(the Base Sepolia instances ignore bytes past the 96). Keys are scoped per
(permission id, account) [V source,
`test_signerInstallDataIsExactlyTheIdAndTheKey`].

**Base Sepolia.** `0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`
(`p256Signer`); earlier, `p256SignerV1` [V `contracts/deployments/84532.json`].

## AgentPolicy

`contracts/src/AgentPolicy.sol`. The agent's mandate: an ERC-7579 policy in
a Kernel permission, installed with `P256Signer` under one permission id.
The signer proves that the agent signed; this policy decides whether what
it signed is within the mandate the owner installed, and Kernel asks it
first [V source; `contracts/lib/kernel/src/core/ValidationManager.sol`
`_validateUserOp`]. One deployment serves every account; it has no owner
and no admin function, and an account reaches only its own mandates [V
source].

**Who calls it, and when.** [V
`contracts/lib/kernel/src/core/ValidationManager.sol`, source]

- Kernel, from the account: `onInstall` when a permission with this policy
  is installed (`permission add`, `permission rotate`, and the account's
  creation with its first permission), with `bytes32(id) ‖` the install
  data (`_installPermission`); `onUninstall` when it is uninstalled
  (`permission revoke`, `permission rotate`), with `bytes32(id) ‖ …`.
  Kernel goes on with the uninstall even if this call reverts
  (`_uninstallPermission`, `ModuleLib.uninstallModule`).
- The EntryPoint's validation path, through Kernel: `checkUserOpPolicy` for
  an operation whose nonce selects the permission, before the signer's
  `checkUserOpSignature`. Kernel hands the policy its part of the
  signature as `userOp.signature`, and reverts `PolicyFailed` when the
  policy returns a failure, which undoes what the policy wrote on the way
  (`_checkUserOpPolicy`).
- Kernel, from the account's `isValidSignature`: `checkSignaturePolicy`
  for an ERC-1271 request naming the permission, with the unwrapped hash.
  Kernel holds the window returned against the clock, then asks the signer
  (`_checkPermissionSignature`).
- The account, in the execution phase: `x402Authorize` and `orderRegister`,
  which only leave a record once validation has registered the call, and
  `x402Reclaim`, by the agent (with `(agentPolicy, x402Reclaim)` on its
  allow-list) or the owner [V source; `docs/AGENT_CONFIG.md`].

**State per account.** [V source; the slots from `forge inspect AgentPolicy
storageLayout`]

- `_configs[id][account]`: a permission's `Config`, in three slots:
  (`validUntil`, 0 meaning not installed; `epoch`; `maxValuePerOp`),
  (`budget`; `spent`), (`validAfter`; `period`; `periodSeen`).
- `usedIds[account]`: how many of the account's permissions have a mandate
  here.
- Keyed by the mandate, `m = keccak256(id, epoch)`, one installation of a
  permission: the allow-list `_allowed[keccak256(m, target, selector)]`;
  the token limits `_tokens[keccak256(m, token)]` (`TokenLimit`, three
  slots); the payee lists `_payees[keccak256(m, token, payee)]`; the
  registered x402 authorizations and orders `_x402[keccak256(m, digest)]`
  (`Pending`, two slots) and the window each was charged in,
  `_chargedIn[keccak256(m, digest)]`; the window each token's count is in,
  `_tokenPeriod[keccak256(m, token)]`; the venues
  `_venues[keccak256(m, decoder)]` (`VenuePin`, two slots).
- `_venuePlaces[place][account]`: every venue's own contract, decoder and
  spender the account has pinned in any mandate; never cleared.

In every mapping the account is the innermost key, so each slot is
`keccak256(account ‖ x) + n` with `n` at most 2: storage ERC-7562 lets the
account's validation read and write. With the account outermost the same
data would sit in slots a rule-enforcing bundler refuses (#83) [V source;
`contracts/test/SenderStorage.t.sol`
`test_senderStorage_theEarlierLayoutWouldNotPass`]. Uninstalling moves the
epoch on, so nothing of an earlier installation is found again, and a
reinstall starts from empty lists and zero counters [V
`test_probe2_reinstallForgetsTheEarlierLimitsAndEntries`]. What an
operation has moved of each token, and its notes (its period, its orders'
window), are kept in transient storage, in the account's slots too [V
source; `test_senderStorage_transientTotalsAreInTheAccountsSlots`].

**Install data.** `bytes32(id) ‖ abi.encode(...)` in one of three forms,
told apart by the first word, the offset of `targets`; a mandate is
encoded in the shortest form that holds it [V source]:

| Head words | Parameters | For |
|---|---|---|
| seven | `address[] targets, bytes4[] selectors, uint128 maxValuePerOp, uint128 budget, uint48 validUntil, TokenCap[] tokens, uint48 validAfter` | a plain mandate |
| eight | the seven, then `TokenPayees[] payees`, not empty | payee lists |
| ten | the eight (`payees` may be empty), then `uint32 period, Venue[] venues` | a budget per period, with venues or without |

`TokenCap` is `(token, maxPerOp, budget, domainSeparator)`, the token's
EIP-712 domain separator non-zero to allow x402 payments in it;
`TokenPayees` is `(token, payees)`; `Venue` is `(decoder, codeHash,
configHash)`. A first word that is none of the three is refused. The
contract decodes as loosely as `abi.decode` does; that the owner sees
exactly what is installed rests on the reviewing app, which accepts
canonical encodings only [V source].

**Functions.**

- `onInstall(data)`: installs the mandate. Reverts `AlreadyInitialized` if
  the id has one for the account, `UnknownEntryPoint` if the account does
  not answer `entrypoint()`, `ForbiddenTarget` for an entry no agent may
  have, `InvalidConfig` for malformed data or a broken rule. Emits
  `AgentPolicySet(account, id, validUntil, maxValuePerOp, budget)`.
- `onUninstall(bytes32(id) ‖ …)`: sets `validUntil` and `validAfter` to 0,
  moves the epoch on, decrements `usedIds`; reverts `NotInitialized` if
  the id has no mandate. The venue places stay.
- `checkUserOpPolicy(id, userOp)`: if every call passes,
  `packValidationData(validAfter, validUntil)` with the window cut to the
  operation's period and orders; `1` otherwise. Token amounts and the
  native spend are charged on the way.
- `checkSignaturePolicy(id, sender, hash, sig)` (view): if `hash` is a
  registered x402 authorization or order of the current installation, a
  window from the mandate's `validAfter` to the earlier of the
  registration's end and `validUntil`; `1` otherwise. `sender` and `sig`
  are not read.
- `x402Authorize(token, from, to, value, validAfter, validBefore, nonce)`:
  emits `X402Authorized`.
- `x402Reclaim(id, token, to, value, validAfter, validBefore, nonce)`:
  gives back the charge of an authorization that expired unused. Reverts
  `X402NotRegistered` (not registered, or for another token),
  `X402StillLive` (before `validBefore`) or `X402Settled` (the token
  reports the nonce used or cancelled). Emits `X402Reclaimed`.
- `orderRegister(decoder, config, order)`: emits `OrderRegistered`.
- Views: `configs(account, id)` (the first six fields of `Config`),
  `period(account, id)`, `isAllowed(account, id, target, selector)`,
  `tokenLimit(account, id, token)`, `payeeAllowed(account, id, token,
  payee)`, `x402Pending(account, id, digest)`, `venue(account, id,
  decoder)`, `venuePlace(account, place)`, `usedIds(account)`,
  `isModuleType(t)` (true only for `MODULE_TYPE_POLICY`) and
  `isInitialized(account)`; the constants `SAFE_EXEC_TRANSACTION`,
  `MULTI_SEND`, `NONCE_CHECK` and `TRANSFER_WITH_AUTHORIZATION_TYPEHASH`,
  and the immutable `NONCE_ASSERT`, the `SafeNonceAssert` address it was
  deployed with.

**Events and errors.** `AgentPolicySet` at install; `X402Authorized` and
`OrderRegistered`, records for wallets emitted in execution under
`msg.sender`, so an account can only emit them for itself; `X402Reclaimed`.
Errors: `InvalidConfig`, `ForbiddenTarget(target, selector)` (selector 0
for a target refused as a place of the mandate's own venues),
`UnknownEntryPoint`, `X402NotRegistered`, `X402StillLive`, `X402Settled`,
and Kernel's `AlreadyInitialized` and `NotInitialized` [V source]. In
validation a refusal is the result `1` where the policy can return one;
input that `abi.decode` or Solady's batch decoder cannot read reverts,
which refuses the operation all the same [I].

**Rules it enforces.** [V source; the tests named]

- *Calls.* Only `execute`, a single call or a batch, revert-on-failure: no
  delegatecall, no "try" mode, which would let a failed nonce assertion
  pass (`test_policy_rejectsBatchAndMalformedCalls`). Every call's
  (target, selector) is on the allow-list. Selector `0x00000000` is a
  plain transfer and admits empty calldata only: 1 to 3 bytes, or a body
  that starts with four zero bytes, would run the target's fallback
  (`test_probe2_oneToThreeBytesAreRefusedOnEveryPath`).
- *Native value.* What an operation moves, Safe transactions and batch
  legs included, is at most `maxValuePerOp`, and is charged to `budget`
  together with the gas the account pays for itself (the EntryPoint's
  prefund, when there is no paymaster) (`test_agent_valueCapAndBudget`,
  `test_gas_selfPaidCountsAgainstBudget`).
- *Tokens.* `transfer`, `transferFrom`, `approve` and `increaseAllowance`
  of a token need a limit. Their amounts, summed over the operation's
  calls with x402 registrations and orders, are at most the token's
  `maxPerOp`, and are charged to its budget. A token with a limit is
  callable through these four functions only: install refuses a mandate
  with another entry on it, and validation such a call
  (`test_token_selectorWithoutLimitIsRefused`,
  `test_tokenCapPerOperation_legsAddUp`,
  `test_probe2_installRefusesEveryUnmeteredFunctionOnALimitedToken`). And
  the four go to a token with a limit only: such an entry on any other
  target would be refused at every operation, so install refuses the
  mandate (#175, `test_probe2_installRefusesAMeteredFunctionWithoutALimit`).
  An approval is charged like a transfer; what the spender later pulls is
  not seen.
- *No standing allowances.* An allowance the agent grants (`approve` or
  `increaseAllowance` of more than 0) must be withdrawn with
  `approve(spender, 0)` later in the same operation, by the same holder:
  the account for its own calls, the Safe for calls inside its
  transaction. An operation that ends with one open is refused. So nothing
  the agent granted outlives the operation, and a revoke leaves no spender
  able to pull. Allowances the owner grants (a venue's spender, say) are
  not the agent's and are not counted (`test_allowances_noneOutlivesTheOperation`,
  `test_allowances_theHolderWithdrawsWhatItGranted`; the fuzzing model
  holds it too). [V source, tests] The same holds for an operator grant,
  `setApprovalForAll(operator, true)` of ERC-721 and ERC-1155: it must be
  withdrawn with `setApprovalForAll(operator, false)` in the same operation
  (`test_allowances_anOperatorGrantIsWithdrawnInTheSameOperation`, #176).
  Another approval-like function the owner allow-lists (ERC-777's
  `authorizeOperator`, ERC-6909's `setOperator`, a protocol's own operator
  grant) is a call the policy allows or refuses and does not read, as any
  unmetered selector, and what it grants can stand; the phone's review names
  the known ones on the entry. An allowance or a grant that has to stand
  across operations is the owner's to make.
- *Window.* The operation is valid from `validAfter` up to and at
  `validUntil`; the policy returns the window and the EntryPoint enforces
  it (`test_schedule_windowIsEnforced`). The window `checkUserOpPolicy`
  returns is never empty and never ends at 0, which the EntryPoint would
  read as no end [V source; `_parseValidationData` in
  `contracts/lib/account-abstraction/contracts/core/Helpers.sol`].
- *Payee lists.* For a token with a list, `transfer` and `transferFrom`
  pay a listed address only, `approve` and `increaseAllowance` name a
  listed spender only, and an x402 authorization pays a listed address
  only; an address word with bits above its 160 is refused
  (`test_payees_transferOnlyToAListedAddress`,
  `test_payees_dirtyAddressWordIsRefused`). A listed spender can move its
  allowance wherever it likes.
- *x402.* `x402Authorize` in an operation registers an EIP-3009
  authorization: the account's own call (not from a Safe), paying from the
  account, in a token with a limit and a domain separator, judged like a
  transfer, recorded once under its EIP-712 digest. A `validBefore` of 0
  is refused, here and for orders (their `validTo` is recorded the same
  way): Kernel reads an end of 0 as no end at all.
  `checkSignaturePolicy` vouches for that digest only, within the
  mandate's window and up to `validBefore`. `x402Reclaim` gives back the
  charge of one that expired unused (`test_x402_registrationIsHeldToTheMandate`,
  `test_x402_anAuthorizationWithoutAnEndIsRefused`,
  `test_x402_notFromInsideASafe`,
  `test_x402_reclaimReturnsBudgetOfExpiredUnused`; `docs/ERC1271.md`).
- *Orders through a venue's decoder.* `orderRegister` in an operation is
  put to the decoder it names (`IVenueDecoder.judge`), by `STATICCALL`
  with at most 150,000 gas, and only if the decoder is one of the
  mandate's venues, its code hash is the one pinned and `config` hashes to
  the pinned config hash; the answer must be exactly five words that fit
  their types. The most the order sells is charged like a transfer of its
  token, which must have a limit and no payee list: what is sold goes to
  whoever fills the order. The operation's window is cut to begin no
  earlier than the order's `notBefore` and to end at its `validTo`, so an
  order that can no longer be filled is not registered; its digest is
  then vouched for up to and at `validTo`. An order's charge is never
  given back, since whether a venue filled it cannot be read from the
  venue for good (`test_order_decoderCodeIsPinned`,
  `test_order_decoderAnswersAreHeldToTheirForm`,
  `test_order_onlyALimitedTokenWithoutAPayeeList`,
  `test_order_notRegisteredEarlierThanItsLifetime`).
- *Budget per period.* With `period` set, every budget, native and per
  token, counts in windows of `period` seconds from the Unix epoch.
  Validation reads no clock, so the operation names its window in six
  bytes of its signature, the policy's part; the validity is cut to that
  window, a window earlier than one seen is refused, and a later one
  starts the budgets afresh. An x402 authorization or order must end with
  the window it is charged in. Across a boundary an agent can spend two
  budgets in a short time, and no more
  (`test_period_theOperationNamesItsPeriod`,
  `test_period_twiceTheBudgetAcrossABoundaryAndNoMore`,
  `test_period_anOrderEndsWithThePeriodItIsChargedIn`). A mandate with
  venues needs a period: it is what returns an unfilled order's part of
  the budget.
- *Venue places.* Installing a venue asks its decoder for the venue's own
  contract (`venue()`) and its spender (`spender()`). The venue, the
  decoder and the spender may not be among the mandate's targets, and are
  marked for the account: no mandate of the account may name them,
  whichever was installed first, at install and again in validation. At
  the venue an order could be signed past the decoder (CoW:
  `setPreSignature`), and the spender holds the owner's allowance of the
  sold tokens (CoW: the vault relayer)
  (`test_trading_theVenueIsNoTargetUnderAnyMandate`,
  `test_trading_theVenuesSpenderIsNoTargetUnderAnyMandate`).
- *Forbidden targets.* The account itself (Kernel's `grantAccess`,
  `installValidations`, `changeRootValidator`, `execute`: the mandate
  would widen or replace itself), its EntryPoint (read from the account at
  install, so that the deposit's `withdrawTo` can never be allowed), this
  policy except `x402Authorize`, `x402Reclaim` and `orderRegister`,
  Permit2 at `0x000000000022D473030F116dDEE9F6B43aC78BA3`, and the venue
  places. All are refused at install, and all but the EntryPoint again in
  validation, where checking it would cost a call per operation
  (`test_policy_install_refusesSelfTargets`,
  `test_probe2_installRefusesPermit2WhateverTheFunction`,
  `test_probe2_permit2PlantedInStorageIsRefusedOnEveryPath`). Permit2
  holds one allowance per token and its own `approve` names who may pull
  it, a call the policy does not read. That closes the one well-known
  contract of the kind, not the kind: any allow-listed contract that holds
  an allowance from the account can move it. Permit2 sits at that address
  where the usual CREATE2 factory deployed it, not on every chain
  (zkSync-style chains differ), so the constant is to be checked before
  the policy goes to a new chain [V source].
- *Safes.* `(safe, execTransaction)` is admitted only as the leg right
  after `SafeNonceAssert.check(safe, n)` in the account's batch. The call
  inside is judged against the same mandate; `gasPrice` must be 0, or the
  Safe would pay a refund to a receiver the agent picks; Safes do not
  nest; a DELEGATECALL goes only into an allow-listed `multiSend` that is
  still a target the agent may reach (not made a venue's place since, by
  another mandate of the account), whose every leg is a CALL that passes
  the mandate. One allow-list entry admits
  its call directly, through a Safe and as a batch leg alike
  (`test_safe_unguardedIsRefused`,
  `test_safe_refusesDelegatecallRefundsAndNesting`,
  `test_trading_aVenuePlaceIsNoLongerASafesBatcher`,
  `test_batch_everyLegIsJudged`).
- *A permission with an execution hook.* Kernel requires such a
  permission's `callData` to be `executeUserOp`'s selector followed by the
  `execute(...)` call, and runs that call as it is (`Kernel.sol:264-271`,
  `300`). The policy strips that one prefix and judges the call as any
  other, so a hook (a price check, say) adds checks around the call and
  never replaces the mandate. A second prefix is refused
  (`test_hook_aHookedPermissionIsHeldToTheMandate`). [V source, test]
  Today the phone's review refuses an install that carries a hook and
  the CLI builds the plain form only; a hook needs those two, not a new
  policy.

**Instances.** Both predate master: each is recorded with the commit
named in `docs/DEPLOYMENTS.md`, and master's source no longer builds it.

- Sepolia: `0x2511FF556aa1534676A34F9B715232917e04FE5e` (`agentPolicy` in
  `contracts/deployments/11155111.json`; earlier, `agentPolicyV1` and
  `agentPolicyV2`). The runtime code of commit
  `8904478693c020e40f676b5161c67a1faa39105f`, with periods and venues; it
  marks the venue's contract and the decoder as venue places but not the
  spender (#149) [V `docs/DEPLOYMENTS.md`, Sepolia].
- Base Sepolia: `0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2` (`agentPolicy`
  in `contracts/deployments/84532.json`; earlier, `agentPolicyV1` to
  `agentPolicyV8`). The pre-trading policy, equal outside its immutable
  slots to what commit `175acbf3a3127e804a45a3e4dd097165f0a4c922` builds
  [V `docs/DEPLOYMENTS.md`, Base Sepolia]: it takes the seven- and
  eight-word forms only, and has no periods, no venues and no
  `orderRegister` [V `contracts/src/AgentPolicy.sol` at that commit].

## P256Point

`contracts/src/P256Point.sol`. A library with one internal function,
`isOnCurve(x, y)`, compiled into `P256Validator` and `P256Signer`, which call
it in `onInstall`; it has no instance of its own [V source]. An off-curve
key would make every signature fail and lock the account, or the
permission, out.

**Rules.** Both coordinates below the field prime p; not (0, 0);
y² ≡ x³ + a·x + b (mod p) with P-256's a = p − 3 and b [V source]. The
curve has two points with x = 0, (0, ±√b), since b is a square modulo p;
the check accepts them, while the modules read `x == 0` as "no key", so such
a key would install and then verify nothing [V source; b's Legendre symbol
modulo p computed as 1]. A key made in a chip is one of them with a chance
of about 2^-255 [I].

## SafeNonceAssert

`contracts/src/SafeNonceAssert.sol`. Binds an agent's Safe transaction to
the Safe nonce it was meant for. A Safe accepts a pre-validated signature
(`v = 1`) from an owner calling it whatever its nonce, so the same
`execTransaction` sent twice runs twice [V source].

**Who calls it, and when.** The account, in the execution phase, as the
first call of a Kernel batch `[check(safe, n), safe.execTransaction(...)]`.
`AgentPolicy` admits an agent's Safe transaction only in that form: it holds
this contract's address as `NONCE_ASSERT` and takes a call to it as the
guard of the call that follows, which must go to the same Safe [V
`contracts/src/AgentPolicy.sol` `_judgeAccountBatch`, `_judgeGuarded`]. The
first copy moves the Safe to `n + 1`; a replay fails the check and reverts
the batch.

**State.** None, and no owner. It reads the Safe's `nonce()` during
execution, where the validation rules of ERC-7562 do not apply [V source].

**Function.** `check(safe, expected)` (view): returns if `safe.nonce()` is
`expected`, else reverts `SafeNonceMismatch(safe, expected, actual)`.

**Base Sepolia.** `0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279`
(`safeNonceAssert`) [V `contracts/deployments/84532.json`].

## WhitelistPaymaster

`contracts/src/WhitelistPaymaster.sol`. Sponsors gas for the accounts its
owner lists, each with a gas budget and a per-operation cap, so that one
compromised agent cannot drain the deposit shared by all. It judges who
sends an operation, never what the operation does [V source]. Built on
eth-infinitism's `BasePaymaster` for EntryPoint v0.7. Each sponsor deploys
their own: the owner is a constructor argument, because a deployment through
the deterministic CREATE2 deployer would otherwise make that proxy the
owner [V source].

**Who calls it, and when.**

- The EntryPoint, in the validation phase of an operation that names this
  paymaster: `validatePaymasterUserOp`, which checks the caller and runs
  `_validatePaymasterUserOp` [V `contracts/lib/account-abstraction/contracts/core/BasePaymaster.sol`];
- the owner: `setSponsored`, and from `BasePaymaster` `withdrawTo`,
  `addStake`, `unlockStake` and `withdrawStake`;
- anyone: `deposit`, which adds to the paymaster's deposit at the EntryPoint.

**State per account.** `sponsorships[account] = (remaining, maxPerOp)`, two
`uint128` in one slot (2^128 − 1 wei is about 3.4e20 ETH). Keyed by the
operation's sender, so the slot is `keccak256(account ‖ slot)`: storage
ERC-7562 associates with the sender, which even an unstaked paymaster may
read and write [V source].

**Functions.**

- `setSponsored(account, budget, maxPerOp)` (owner): sets, and replaces,
  the account's sponsorship; a zero budget delists it. Emits
  `Sponsored(account, budget, maxPerOp)`.
- `sponsored(account)`: true while the account has budget left, whatever its
  `maxPerOp`.
- `sponsorships(account)`: the getter.
- `_validatePaymasterUserOp` (internal): refuses, with
  `SIG_VALIDATION_FAILED`, an operation whose `maxCost` exceeds `maxPerOp` or
  `remaining`; otherwise takes `maxCost` off `remaining` and sponsors it, with
  an empty context.

Errors are `BasePaymaster`'s (`"Sender not EntryPoint"`) and OpenZeppelin
`Ownable`'s (`OwnableUnauthorizedAccount`); it declares none of its own [V
source].

**Rules.** Every operation is charged its maximum cost (`maxCost`, from its
gas limits and fee cap) at validation, with no refund. The empty context
means the EntryPoint calls no `postOp` [V source]. By ERC-7562 that needs no
paymaster stake [I, the source's own comment]; `paymaster stake` exists for
bundlers that ask for one all the same (`docs/ARCHITECTURE.md`, roadmap
item 3.5).

**Base Sepolia.** `0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001`
(`whitelistPaymaster`; its owner is `paymasterOwner` in the same file);
earlier, `whitelistPaymasterV1` [V `contracts/deployments/84532.json`].

## IVenueDecoder

`contracts/src/venues/IVenueDecoder.sol`. What a trading venue is to the
policy (issue #80): a contract without state that reads one of the venue's
orders and says what it can cost. By the interface's terms, the mandate
names a decoder by its address, its code hash and the hash of the owner's
`config`; the policy asks it with `STATICCALL` inside validation and charges
and records what it answers, so a decoder reads no storage there [V source].
`AgentPolicy` asks `judge` when the agent registers an order, and `venue()`
and `spender()` when a mandate that trades at the venue is installed [V
`contracts/src/AgentPolicy.sol` `_askDecoder`, `_installTrading`].

**Functions.**

- `judge(account, config, order)` (inside validation): reverts unless the
  config allows the order; returns the token it spends, the most it can take
  (fees included), the earliest time it may be registered, its `validTo` and
  the digest the venue will ask the account to vouch for.
- `untouched(account, order)` (outside validation, after `validTo`; may read
  the venue's storage): whether the venue's present record shows nothing of
  the order filled or cancelled. No proof of the past: where a venue lets the
  record be cleared, a filled order reads as untouched.
- `venue()`: the venue's own contract, which a mandate may not name as a
  target.
- `spender()`: who takes the sell token from the account; the owner's tools
  approve it (the allowance). Like the venue's contract and the decoder, a
  mandate may not name it as a target, since through it the allowance
  would move (issue #149).

## CowSwapDecoder

`contracts/src/venues/CowSwapDecoder.sol`. `IVenueDecoder` for CoW
Protocol's GPv2 orders [V source].

**State.** None: no storage, no upgrade path, no `delegatecall`, no
`selfdestruct`. The settlement's address, its EIP-712 domain separator and
its vault relayer are read once in the constructor and kept as immutables
(`venue`, `domainSeparator`, `spender`) [V source].

**Config.** `abi.encode(Config)`: the one `appData` orders must carry,
`maxLife` (the most seconds between registering an order and its `validTo`)
and up to `MAX_PAIRS` = 16 pairs, each one way with a lowest price,
`minBuy` of the buy token per `perSell` of the sell token. The owner sets
the price; there is no oracle [V source].

**Rules of `judge`** [V source]:

- the order is exactly twelve ABI words, each in canonical form, so its
  digest covers all of it (`NotAnOrder`; `abi.decode` reverts on a
  non-canonical word [V `contracts/test/CowSwapDecoder.t.sol`
  `test_judge_refusesAnythingButTheTwelveCanonicalWords`]);
- the proceeds go to the account: `receiver` is zero or the account
  (`ProceedsLeaveTheAccount`);
- a sell order (`NotASellOrder`), filled whole or not at all
  (`PartiallyFillable`), both balances plain ERC-20 (`NotPlainErc20`);
- the pinned `appData` (`OtherAppData`); a non-zero `sellAmount`
  (`NothingToSell`); a zero `feeAmount` (`FeeNotZero`);
- the pair listed exactly once (`PairNotListed`, `PairListedTwice`), with
  two different tokens and a price, and
  `buyAmount · perSell ≥ sellAmount · minBuy` in 512 bits
  (`BelowTheLowestPrice`);
- a config of more than `MAX_PAIRS` pairs allows nothing (`InvalidConfig`).

It returns `mostSold = sellAmount`, `notBefore = validTo − maxLife` (zero if
`validTo` is not above `maxLife`) and the EIP-712 digest of the order under
the settlement's domain.

**Other functions.** `untouched(account, order)` reads the settlement's
`filledAmount` of the order's uid (digest ‖ owner ‖ `validTo`): zero means
neither filled nor cancelled now. After `validTo` an allowlisted solver may
reset that word (`freeFilledAmountStorage`), so a filled order can read as
untouched [V source]. `checkConfig(config)` (pure) returns true or reverts
`InvalidConfig`: one to `MAX_PAIRS` pairs, a non-zero `maxLife`, non-zero
and distinct tokens, a price in both terms, no pair twice; `judge` does not
rely on it having been asked.

**Base Sepolia.** No instance recorded [V `contracts/deployments/84532.json`].

## DemoCounter

`contracts/src/demo/DemoCounter.sol`. A demo target for the agent, after
the reference design's logger: it counts calls and records the caller, the
agent's smart account and not the bundler [V source].

**Who calls it, and when.** Anyone; in the demos and examples, the agent's
account calls `increment` [V `examples/agentkit/src/setup.ts`]. The tests
also send it plain value under a mandate's cap and budget [V
`contracts/test/AgentPermission.t.sol`].

**State.** `count`, the number of increments; no owner, no access control.
Value sent to it stays: it has no way to send it out [V source].

**Functions and events.** `increment()`: adds one and emits
`Incremented(by, count)`. `receive()`: accepts plain transfers. `count()`:
the getter.

**Base Sepolia.** `0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1`
(`demoCounter`) [V `contracts/deployments/84532.json`]. Its code there ends
in the compiler metadata of an earlier build (solc 0.8.34), so it is not
byte-equal to what commit `175acbf3a3127e804a45a3e4dd097165f0a4c922` compiles to; its source did not change
from 2026-10-20 until `VERSION` was added [V `cast code`, `git log`, 2026-11-24].
