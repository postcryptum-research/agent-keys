# Contracts

The modules sit in an ERC-4337 smart account, a ZeroDev Kernel v3.3 behind
EntryPoint v0.7. Kernel calls each module from the account, so in every
module call `msg.sender` is the account; the modules have no owner, and they
keep their state per account, in slots of the form ERC-7562 lets an
account's validation touch, `keccak256(account ‖ x) + n` (rule 4 in
`CLAUDE.md`). The paymaster is the one contract with an owner. Addresses
are those of Base Sepolia (chain 84532), from
`contracts/deployments/84532.json`, which keeps earlier instances under
versioned names. Each contract answers `VERSION()`: 0.1.0 for every
contract in development, until the commit given to the first external
audit or deployed first to a mainnet is tagged; from then on a change to a
contract's bytecode raises it (house rule 9). The instances listed are as
commit `e48b93e001f34f460bd4845d231b8e0ee5d26ad6` builds them, every contract at
0.1.0, and Sepolia has them at the same addresses
([`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md)).

| Contract | What it is | Who calls it | Base Sepolia |
|---|---|---|---|
| `P256Validator` | the owner key, as the account's root | Kernel, from the account | `0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63` |
| `P256RecoveryValidator` | the recovery key, granted only `changeRootValidator` | Kernel, from the account | `0xb7a06e6c7B5cC9852578EF89f38d161C31218047` |
| `P256Signer` | the agent key, as one Kernel permission | Kernel, from the account | `0xd88d25Ca3e042A28893781935756ee90Bc2d2769` |
| `AgentPolicy` | the agent's mandate, as that permission's policy | Kernel, from the account; the account, for x402 and orders | `0xdA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6` |
| `P256Point` | the on-curve check (library) | the key modules, at install | none: compiled into them |
| `SafeNonceAssert` | the replay guard of an agent's Safe transaction | the account, in a batch | `0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219` |
| `IShapeJudge` | what a shape judge is to the policy (interface, #251) | the policy; `PolicyInstall` | none: an interface |
| `SafeShapes` | the shape judge for Safes: where the calls inside a Safe transaction and a `multiSend` batch lie (#251) | the policy, in validation; `PolicyInstall`, at install | none yet: the instances above do not use it |
| `PolicyStorage` | the policy's storage, one layout (library) | the policy and its fixed parts | none: compiled into them |
| `PolicyRules` | the keys and rules the policy's validation and its install share (library) | the policy and `PolicyInstall` | none: compiled into them |
| `PolicyInstall` | the install of a mandate, as fixed code of the policy (#251) | the policy, by DELEGATECALL, in the owner's operation | none yet: created by the policy's constructor, at its CREATE address |
| `WhitelistPaymaster` | a gas sponsor with a budget per account | the EntryPoint; its owner | `0x657792557C1D40f2Da031FD7aB277078D2c0a4cb` |
| `IVenueDecoder` | what a trading venue is to the policy (interface) | the policy; the owner's tools | none: an interface |
| `CowSwapDecoder` | CoW Protocol's orders under that interface | the policy; the owner's tools | `0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a` |
| `VenuePairs` | the listed pairs and their lowest prices (library) | the 1inch and swap decoders | none: compiled into them |
| `OneInchLimitOrderDecoder` | plain 1inch limit orders under that interface | the policy; the owner's tools | `0xAD754dA240f27dCe0cF79F6d323e56d5C29D08E6` |
| `VenueCalls` | how a call is named between a decoder and the policy (library) | the policy; the swap decoder | none: compiled into them |
| `SwapRouter02Decoder` | a swap at Uniswap's SwapRouter02, as a call the account makes | the policy; the owner's tools | `0xB29a80662d989c1C0E73dB824cD82d5890e795bC` |
| `CallRulesDecoder` | calls at one contract, each argument word held to a rule | the policy; the owner's tools | one per contract it speaks for: `0x14b82e2cBF35926B6221d008e5A89DB1BD5D4887` for Aave V3's pool, `0xC5135aC6A911B692173F2626dD57ff1D80d16F62` for CCTP's messenger |
| `SeaportBidDecoder` | a bid for one NFT at Seaport 1.6 under that interface | the policy; the owner's tools | `0x713165a6157a4B2952A775A9D1C9948D9a703128` |
| `DemoCounter` | a demo target | anyone; the agent in demos | `0x29da894F3E456CAC92b3EC76710524E74411E99f` |

The addresses are the file's current entries [V `contracts/deployments/84532.json`].

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
install data is the key and nothing more, since #154: the instance before
it, `0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2` (`p256ValidatorV2` on Base
Sepolia), refuses only shorter data and ignores bytes past the 64 [V source,
`test_validatorInstallDataIsExactlyTheKey`].

**Base Sepolia.** `0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63`
(`p256Validator`); earlier, `p256ValidatorV1` and `p256ValidatorV2` [V
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

**Base Sepolia.** `0xb7a06e6c7B5cC9852578EF89f38d161C31218047`
(`p256RecoveryValidator`); earlier, `p256RecoveryValidatorV1` and
`p256RecoveryValidatorV2` [V `contracts/deployments/84532.json`].

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
(the instance before it, `0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`,
`p256SignerV2` on Base Sepolia, ignores bytes past the 96). Keys are scoped
per (permission id, account) [V source,
`test_signerInstallDataIsExactlyTheIdAndTheKey`].

**Base Sepolia.** `0xd88d25Ca3e042A28893781935756ee90Bc2d2769`
(`p256Signer`); earlier, `p256SignerV1` and `p256SignerV2` [V
`contracts/deployments/84532.json`].

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

**State per account.** [V source: `PolicyStorage.Layout`]

- `configs[id][account]`: a permission's `Config`, in three slots:
  (`validUntil`, 0 meaning not installed; `epoch`; `maxValuePerOp`),
  (`budget`; `spent`), (`validAfter`; `period`; `periodSeen`).
- `usedIds[account]`: how many of the account's permissions have a mandate
  here.
- Keyed by the mandate, `m = keccak256(id, epoch)`, one installation of a
  permission: the allow-list `allowed[keccak256(m, target, selector)]`,
  whose value is the call's kind (0 not allowed, 1 a plain call, 2 a
  wallet transaction and 3 a batch, read by the mandate's shape judge for
  the selector, #251); the shape judges `shapes[keccak256(m, selector)]`
  (`ShapePin`: the judge, its role and whether it is paused, one slot);
  the guardian `guardians[keccak256(m)]` and a module's pause
  `modulePaused[keccak256(m, module)]`, read in validation for a venue
  decoder (#251, decision 2);
  the token limits `tokens[keccak256(m, token)]` (`TokenLimit`, three
  slots); the payee lists `payees[keccak256(m, token, payee)]`; the
  registered x402 authorizations and orders `x402[keccak256(m, digest)]`
  (`Pending`, two slots) and the window each was charged in,
  `chargedIn[keccak256(m, digest)]`; the window each token's count is in,
  `tokenPeriod[keccak256(m, token)]`; the venues
  `venues[keccak256(m, decoder)]` (`VenuePin`, two slots).
- `venuePlaces[place][account]`: every venue's own contract, decoder and
  spender the account has pinned in any mandate; never cleared.

These mappings are the members of one layout, `PolicyStorage.Layout`
(`contracts/src/policy/PolicyStorage.sol`), so that the fixed code the
policy reaches by DELEGATECALL (#251) reads and writes the same storage
without inheritance. The layout sits at slot 0, and each mapping keeps the
slot it had as a state variable. In every mapping the account is the
innermost key, so each slot is
`keccak256(account ‖ x) + n` with `n` at most 2: storage ERC-7562 lets the
account's validation read and write. With the account outermost the same
data would sit in slots a rule-enforcing bundler refuses (#83) [V source;
`contracts/test/SenderStorage.t.sol`
`test_senderStorage_theEarlierLayoutWouldNotPass`]. Uninstalling moves the
epoch on, so nothing of an earlier installation is found again, and a
reinstall starts from empty lists and zero counters [V
`test_probe2_reinstallForgetsTheEarlierLimitsAndEntries`]. What an
operation has moved of each token, and its notes (its period, its orders'
window, the call a decoder judged in the leg before), are kept in
transient storage, in the account's slots too [V source;
`test_senderStorage_transientTotalsAreInTheAccountsSlots`].

**Install data.** `bytes32(id) ‖ abi.encode(...)` in one of five forms,
told apart by the first word, the offset of `targets`; a mandate is
encoded in the shortest form that holds it [V source]:

| Head words | Parameters | For |
|---|---|---|
| seven | `address[] targets, bytes4[] selectors, uint128 maxValuePerOp, uint128 budget, uint48 validUntil, TokenCap[] tokens, uint48 validAfter` | a plain mandate |
| eight | the seven, then `TokenPayees[] payees`, not empty | payee lists |
| ten | the eight (`payees` may be empty), then `uint32 period, Venue[] venues` | a budget per period, with venues or without |
| eleven | the ten (`period` may be 0 when there are no venues), then `IdCap[] ids`, not empty | limits per id of an ERC-6909 contract (#186) |
| twelve | the eleven (`ids` may be empty), then `ShapeJudge[] shapes`, not empty | a Safe transaction or a batch on the allow-list: each needs the shape judge that reads it (#251) |

`TokenCap` is `(token, maxPerOp, budget, domainSeparator)`, the token's
EIP-712 domain separator non-zero to allow x402 payments in it;
`TokenPayees` is `(token, payees)`; `Venue` is `(decoder, codeHash,
configHash)`; `IdCap` is `(token, id, maxPerOp, budget)`; `ShapeJudge`
is `(judge, codeHash)`. A first word that is none of the five is refused. The
contract decodes as loosely as `abi.decode` does; that the owner sees
exactly what is installed rests on the reviewing app, which accepts
canonical encodings only [V source].

**Functions.**

- `onInstall(data)`: installs the mandate. Reverts `AlreadyInitialized` if
  the id has one for the account, `UnknownEntryPoint` if the account does
  not answer `entrypoint()`, `ForbiddenTarget` for an entry no agent may
  have, `InvalidConfig` for malformed data or a broken rule. Emits
  `AgentPolicySet(account, id, validUntil, maxValuePerOp, budget)`. The
  code that does it is `PolicyInstall` (below), which the policy runs by
  DELEGATECALL on its own storage; the errors and the event are the
  policy's, with the same signatures.
- `setGuardian(id, guardian)`: from the account (the owner's step), names
  the guardian of the permission's current mandate, or zero for none;
  reverts `NotInitialized` if the id has no mandate. Emits
  `GuardianSet(account, id, guardian)`. `guardian(account, id)` reads it.
- `pause(account, id, module, paused)`: from the mandate's guardian or the
  account, pauses one module of the mandate, a shape judge (each of its
  pins) or a venue decoder, or lifts the pause. While paused, validation
  refuses its calls and the rest of the mandate runs. Reverts
  `NotTheGuardian` for anyone else, `NotAModule` for an address that is
  none of the mandate's modules. Emits `ModulePaused(account, id, module,
  paused)` (#251, decision 2; `test_guardian_*`,
  `test_order_aPausedVenueIsRefusedUntilThePauseIsLifted`). Both run in
  `PolicyInstall`, by DELEGATECALL. `paused(account, id, module)` reads
  whether a module of the mandate is paused. The CLI's `permission
  guardian` and `permission pause` send them from the account; the owner's
  phone reads both ([`AGENT_CONFIG.md`](AGENT_CONFIG.md)).
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
- `orderRegister(decoder, config, order)`: emits `OrderRegistered`, for
  an order and for a call a decoder judged alike.
- Views: `configs(account, id)` (the first six fields of `Config`),
  `period(account, id)`, `isAllowed(account, id, target, selector)`,
  `tokenLimit(account, id, token)`, `idAsset(token, tokenId)` (the key an
  ERC-6909 id's limit is read under: `tokenLimit(account, id,
  idAsset(token, tokenId))`), `payeeAllowed(account, id, token,
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
  (`test_probe2_oneToThreeBytesAreRefusedOnEveryPath`). A batch's pointer
  array ends within the batch's own bytes, or the batch is refused: the
  decoder the account runs does not check that, and past the end the
  account and the policy would read different bytes
  (`test_batch_aPointerArrayPastTheEndIsRefused`;
  [`THIRD_PARTIES.md`](THIRD_PARTIES.md), point 2).
  The policy cuts the batch's bytes out of the call by hand, and the
  account takes them through Solidity's decoder: a fuzz test lays a batch
  out with other offsets and declared lengths and holds that whatever the
  policy accepts, the account reads as calls on the allow-list with the
  values the policy charged
  (`testFuzz_batch_executionDataIsReadAsKernelReadsIt`). A batch whose
  array length is enormous is read by neither: the decoder checks its
  pointers in a loop that ends only with the gas, in the policy as in the
  account, and an operation whose validation runs out of gas is not
  included (`test_batch_anEnormousPointerArrayIsReadByNeither`).
- *Native value.* What an operation moves, Safe transactions and batch
  legs included, is at most `maxValuePerOp`, and is charged to `budget`
  together with the gas the account pays for itself (the EntryPoint's
  prefund, when there is no paymaster) (`test_agent_valueCapAndBudget`,
  `test_gas_selfPaidCountsAgainstBudget`). Who pays is read as the
  EntryPoint reads it, by the address in the paymaster field and not by
  the field's length: an empty field means the account, and its gas is
  counted; a field that names no paymaster (shorter than its 52 fixed
  bytes, or the zero address) is refused, because the EntryPoint would
  take that operation's prefund from the account with nothing counted
  (#244; `test_gas_aPaymasterFieldThatNamesNoPaymasterIsRefused`,
  `test_gas_aPaymasterFieldShorterThanItsFixedPartIsRefused`).
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
  `transferFrom(from, to, amount)` is held by its amount and its recipient;
  its source is not judged. A mandate that lists it lets the agent move
  what others approved to the account, and inside a Safe transaction what
  others approved to the Safe, within the token's limits and to its payees
  (#247; `test_token_transferFromMovesWhatOthersApproved`). ERC-6909's
  `transferFrom(sender, receiver, id, amount)` is held the same way: by
  the id's limits, not by its sender.
  ERC-721's `approve(to, tokenId)` and `transferFrom` carry the ERC-20
  selectors, so on an NFT contract they are metered functions and need a
  limit, which an NFT contract does not meaningfully have: they cannot be
  listed for one.
- *Ids of an ERC-6909 contract (#186).* `transfer(receiver, id, amount)`,
  `transferFrom(sender, receiver, id, amount)` and `approve(spender, id,
  amount)` need a limit for the id they name (`IdCap`, in the eleven-word
  form). The amounts, summed over the operation's calls, are at most the
  id's `maxPerOp` and are charged to its budget, which follows the
  mandate's period as a token's does; an id without a limit is refused. A
  contract with limits per id is callable through these three functions
  only, so not through `setOperator`, whose operator could move every id
  past the limits; and the three go to a contract with such limits only.
  Install refuses a mandate that breaks either, and one whose contract
  also has a `TokenCap`, an id listed twice, the zero address or a limit
  wider than 128 bits (`test_ids_anIdIsHeldToItsLimits`,
  `test_ids_installRules`, `test_period_anIdsBudgetIsPerPeriod`; through a
  Safe and the legs of its batch, `test_ids_heldThroughASafeAndItsBatch`). An
  allowance of an id still has to be withdrawn in the same operation,
  as below, and its amount is charged when it is given. An id has no
  payee list and no x402: the agent picks the receiver and the spender.
  An id's limit is kept as a token's, under a key made of the contract
  and the id (the low 160 bits of a tagged hash; `idAsset`). The
  contract's runtime size is 18,611 bytes of the 24,576 a
  contract may have, with the calls through a decoder (below) in it, the
  reading of Safe transactions in the `SafeShapes` judge and the install in
  `PolicyInstall` [V `forge build --sizes`, 2026-11-28]: the next change
  has 5,965 bytes
  ([#224](https://github.com/postcryptum-research/agent-keys/issues/224)).
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
  ERC-6909 is held whole: `setOperator(operator, true)` is withdrawn with
  `setOperator(operator, false)`, and an allowance of one id,
  `approve(spender, id, amount)`, with the same function, spender and id
  and amount 0; `setOperator` can be listed only for a contract without
  limits per id, and `approve(spender, id, amount)` only for one with them
  (`test_allowances_anERC6909OperatorIsWithdrawnByItsOwnFunction`,
  `test_allowances_anERC6909AllowanceIsWithdrawnForItsId`). A grant is
  withdrawn by its own function only: each kind has its own flag, so on a
  contract that has two of these functions one does not close what the
  other opened. ERC-777's `authorizeOperator` is withdrawn by a different
  function, `revokeOperator`, and the policy does not pair them: a mandate
  that lists `authorizeOperator` is refused at install
  (`test_allowances_noMandateListsAnERC777OperatorGrant`); `revokeOperator`
  only takes a grant away and may be listed. An ERC-777 token is best
  listed, if at all, as an ERC-20 with a limit, which confines it to the
  four metered functions. A protocol's own operator grant under another
  name is a call the policy allows or refuses and does not read, as any
  unmetered selector, and what it grants can stand. The phone's review
  names the grants it knows on the entry: beside the standards' own,
  Morpho Blue's `setAuthorization(address,bool)` (`0xeecea000`), Compound
  III's `allow(address,bool)` (`0x110496e5`) and Aave's
  `approveDelegation(address,uint256)` (`0xc04a8a10`), each with the line
  that the policy does not read it and the grant stands [V
  `an_operator_grant_is_named_on_the_screen`; the selectors by `cast sig`].
  A function the build does not know is shown by its selector alone. An allowance or a grant that has
  to stand across operations is the owner's to make.
  What the rule reads is the calls of the operation, and validation cannot
  see how they end. A call that reverts takes the whole operation's
  execution with it, the grant included (only the default execution type
  is admitted, and a Safe's batch is one `multiSend`). A token whose
  `approve(spender, 0)` returns `false` and changes nothing, where its
  `approve(spender, x)` took effect, would leave that allowance standing:
  the account does not read a token's return value. So a token given a
  limit must be one whose `approve(spender, 0)` clears the allowance; the
  widely used ones do. The same is assumed of an allow-listed contract's
  `setApprovalForAll(operator, false)`. [I: no such token is known to us; the requirement
  is on the owner's choice of tokens]
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
- *Calls through a venue's decoder.* A decoder that answers `judge` with
  a `validTo` of zero has judged a call the account makes now, not an
  order a venue fills later; its `digest` is then the hash of that call's
  value and calldata ([`VenueCalls`](#venuecalls)). The policy binds that
  hash to the decoder's own venue (`venue()`, as the pinned code gives
  it) and keeps it for the length of the operation. The next leg of the
  account's batch must then be exactly that call, at that venue, or the
  operation is refused; a registration that is the batch's last leg, or
  that is not in a batch, is refused where validation ends. So:
  - a decoder speaks for its own venue's contract only: not the account,
    not this policy, not a contract on the allow-list, not another venue's
    contract, not its own spender
    (`test_call_onlyAtTheDecodersOwnVenue`);
  - even where an owner pinned a decoder that names one as its venue, a
    call is never admitted at Permit2, at a token with a limit or at an
    ERC-6909 contract with id limits: what the mandate counts itself is
    reached by its own rules only (`test_call_whatNoDecoderOpens`,
    `test_call_aDecoderDoesNotOpenAContractWithIdLimits`);
  - the call's native value counts against the cap per operation and the
    budget like any leg's (`test_call_itsNativeValueCounts`);
  - when the decoder prices the call (`mostSold` not zero), that amount
    is charged like an order's: the token must have a limit and no payee
    list, and the cap per operation and the budget hold
    (`test_call_chargedAsTheDecoderSays`,
    `test_call_aTokenWithAPayeeListIsNotCharged`);
  - nothing is recorded and nothing is vouched for: a call registers as
    often as it is made (`test_call_theJudgedCallIsMadeAndNoOther`);
  - the decoder's `notBefore` holds as for an order: the operation is not
    valid earlier (`test_call_aDecodersNotBeforeHolds`).
  A call that reverts when the operation runs was still charged at
  validation, as a transfer is; the period returns it. An order that ends
  at second zero is taken for a call that no leg can be, and is refused
  (`test_call_anOrderEndingAtZeroIsNotACall`). The rule is held by
  `contracts/test/VenueCallPairing.t.sol`.
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
  `test_trading_theVenuesSpenderIsNoTargetUnderAnyMandate`). One path
  leads to a venue's own contract: a call its decoder judged, above.
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
  after `SafeNonceAssert.check(safe, n)` in the account's batch, with
  `safe` a whole address word: a word with bits above the low 160 is
  refused in validation, since `check` would revert on it at execution
  with the operation already charged
  (`test_safe_theGuardedAddressIsAWholeWord`). The same is asked of the
  address words of `execTransaction` itself (`to`, `gasToken`,
  `refundReceiver`): a Safe whose decoder validates them would revert at
  execution (`test_safe_theTransactionsAddressesAreWholeWords`). The call
  inside is judged against the same mandate; `gasPrice` must be 0, or the
  Safe would pay a refund to a receiver the agent picks; `safeTxGas` and
  `baseGas` must be 0 too, since a Safe given a `safeTxGas` does not
  revert when its inner call does, and validation would have counted a
  call that was not made, the withdrawal of an allowance among them
  (#190, `test_safe_aTransactionThatMayFailQuietlyIsRefused`). With all
  three at 0, an inner call that fails at execution fails the operation,
  and nothing of it stands (`test_safe_aFailingInnerCallFailsTheOperation`,
  run through the EntryPoint, the Safe and the token) [V
  `contracts/lib/safe-smart-account/contracts/Safe.sol`, the `GS013`
  rule]. A Safe's guard can only add a refusal to this. A module enabled
  on the Safe is another matter: `execTransactionFromModule` runs without
  `execTransaction`'s rules, so a mandate that lets the agent reach a
  module of the Safe rests on that module's own checks, and enabling one
  is the owner's to weigh [I from `ModuleManager.sol` in the same tree].
  Safes do not
  nest; a DELEGATECALL goes only into an allow-listed `multiSend` that is
  still a target the agent may reach (not made a venue's place since, by
  another mandate of the account), whose every leg is a CALL that passes
  the mandate. One allow-list entry admits
  its call directly, through a Safe and as a batch leg alike
  (`test_safe_unguardedIsRefused`,
  `test_safe_refusesDelegatecallRefundsAndNesting`,
  `test_trading_aVenuePlaceIsNoLongerASafesBatcher`,
  `test_batch_everyLegIsJudged`).
  The Safe transaction and the batch are read by the `SafeShapes` judge
  (below), which says where the calls inside them lie; the policy slices
  its own calldata at those positions, only within it, and judges each
  call itself (`test_safe_aJudgesPositionsOutsideTheCalldataAreRefused`).
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

**Instances.** The current one, `0xdA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6`,
is `agentPolicy` on both chains: built from commit
`b11adb7cf2dcb2660b4c93c81c62f8945e246706`, with every rule of this
section, periods, venues, a call a venue's decoder judged (#222) and the
venue's spender as a place (#149) [V
`contracts/deployments/84532.json`, `contracts/deployments/11155111.json`,
`docs/DEPLOYMENTS.md`]. The instances it replaced stay recorded, each with
the commit named in `docs/DEPLOYMENTS.md`; master's source no longer builds
them.

- Sepolia: `0x2511FF556aa1534676A34F9B715232917e04FE5e` (`agentPolicyV3` in
  `contracts/deployments/11155111.json`; before it, `agentPolicyV1` and
  `agentPolicyV2`). The runtime code of commit
  `8904478693c020e40f676b5161c67a1faa39105f`, with periods and venues; it
  marks the venue's contract and the decoder as venue places but not the
  spender (#149) [V `docs/DEPLOYMENTS.md`, Sepolia].
- Base Sepolia: `0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2` (`agentPolicyV9`
  in `contracts/deployments/84532.json`; before it, `agentPolicyV1` to
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

## SafeShapes

`contracts/src/judges/SafeShapes.sol`. The shape judge for Safes, the first
of the division of `AgentPolicy` (#251), and the interface it implements,
`IShapeJudge` (`contracts/src/judges/IShapeJudge.sol`): a contract without
state that reads a
`Safe.execTransaction` call and a `multiSend` batch and says where the
calls inside them lie, as positions in the bytes it was given. It reads
the words the Safe and `MultiSendCallOnly` read, the way they read them:
the head words of `execTransaction`, which must ask for no refund
(`safeTxGas`, `baseGas` and `gasPrice` 0) and carry whole address words;
and the packed legs of a batch, CALL legs only, at least one.

**Pinned per mandate.** A mandate with a Safe transaction or a batch on
its allow-list pins the judge in the twelve-word form, by address and code
hash. Its `shapes()` answers the selectors it reads and their roles:
`execTransaction` as a wallet transaction, `multiSend` as a batch. Install
pins each selector to it, once per mandate, and writes each such
allow-list entry with its kind. A Safe transaction or a batch without its
judge is refused at install
(`test_shapes_aSafeTransactionOrABatchWithoutItsJudgeIsRefused`); one
written into storage as a plain entry is refused at validation
(`test_shapes_aSafeTransactionAsAPlainEntryIsRefusedAtValidation`). The
policy knows no judge of its own: each mandate reads its Safe transactions
with the judge it pinned (`test_shapes_eachMandateUsesTheJudgeItPinned`).
Code at an address with code cannot change after (EIP-6780), so the code
hash is checked at install and not at every operation.

**Who calls it, and when.** `AgentPolicy`, with a static call to
`read(selector, data)`, in the validation phase; `PolicyInstall`, with
`shapes()`, at install. It reads no storage and no clock (ERC-7562), and it
does not revert on what it is given: what it cannot read is answered
`ok == false` (`testFuzz_theJudgeDoesNotRevert`).

**What it holds.** That its positions slice out exactly the inner call and
the legs Solidity's decoder reads from any well-formed encoding
(`testFuzz_aSafeTransactionIsReadAsTheSafeDecodesIt`,
`testFuzz_aBatchIsReadLegByLeg`), and that a refund, a gas figure for the
Safe's own call, a dirty address word, data outside the calldata, a
DELEGATECALL leg, a cut leg and an empty batch are refused
(`contracts/test/SafeShapes.t.sol`).

**What it costs** [V `test_measure_validationGas_*` in
`contracts/test/AgentPermission.t.sol`, 2026-11-28], against the policy
before the division: validation of a Safe transaction costs 7,013 gas more
(49,716), and of a Safe `multiSend` of two legs 19,533 more (79,746): for
each judge read, the read of its pin, a cold static call, the copy of the
calldata into it and the judge's own reading. A plain call and a token
transfer cost 11 more. A judge that read a wallet transaction and its
batch in one call would halve the batch's part [I].

## PolicyInstall

`contracts/src/policy/PolicyInstall.sol`. The install of a mandate, moved
out of `AgentPolicy` (#251): the decoding of the five forms of install
data, the shape judges and their selectors, the allow-list with each
entry's kind and its forbidden targets, the token limits, the payee lists,
the period and venues, the id limits, and the rules that tie them
together. Its code is what `AgentPolicy`'s was, reading the mandate's
keys through `PolicyRules` and its storage through `PolicyStorage`.

**Who calls it, and when.** `AgentPolicy`, from `onInstall`, and from `setGuardian` and `pause` (#251, decision 2), by
DELEGATECALL: in the execution phase of the owner's operation, not in
validation, so ERC-7562 does not bind it. The account stays the caller and
the policy's storage is what it writes. The policy creates it in its
constructor and holds its address as `INSTALL`, so the two are always a
pair; its address is the policy's CREATE address with nonce 1. Called
directly it writes its own storage, which installs no mandate anyone reads
(`test_install_theInstallCodeWritesThePolicysStorageOnlyThroughThePolicy`).

**What it costs** [V `test_measure_installGas` and
`test_measure_validationGas_*`, 2026-11-27]: `AgentPolicy` is 6,139 bytes
smaller (17,715); `PolicyInstall` is 8,145, with its own copy of the shared
rules. An install of two entries and a token limit costs 3,688 gas more
(182,034): one cold DELEGATECALL and the data encoded for it. Validation
costs 48 to 139 gas less by shape than before the step: the shared rules
are called directly.

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

**Base Sepolia.** `0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219`
(`safeNonceAssert`), the one the current `AgentPolicy` names; earlier,
`safeNonceAssertV1` [V `contracts/deployments/84532.json`].

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

**Base Sepolia.** `0x657792557C1D40f2Da031FD7aB277078D2c0a4cb`
(`whitelistPaymaster`; its owner is `paymasterOwner` in the same file);
earlier, `whitelistPaymasterV1` and `whitelistPaymasterV2` [V
`contracts/deployments/84532.json`].

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

**An order, or a call.** A decoder says which it judged by `validTo`. Not
zero: an order, recorded and vouched for until then. Zero: a call the
account makes in the next leg of the same operation, at `venue()`; `digest`
is then `VenueCalls.digest(value, calldata)`, `notBefore` is zero or the
earliest time the call may be made, and `mostSold` may be zero when the
call takes nothing the decoder prices [V
`contracts/src/AgentPolicy.sol` `_registerOrder`, `_judgeVenueCall`]. The
interface's own text describes orders: the file is not changed, so that the
source of the deployed `CowSwapDecoder` stays as it is.

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

**Base Sepolia.** `0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a`
(`cowSwapDecoder`), the address it has on Sepolia too, with other code: the
domain separator it keeps names the chain [V
`contracts/deployments/84532.json`, `docs/DEPLOYMENTS.md`]. Sepolia's
earlier decoder is `cowSwapDecoderV1` in
`contracts/deployments/11155111.json`.

## VenuePairs

`contracts/src/venues/VenuePairs.sol`. A library of internal functions: the
pairs an owner lets an agent trade, each one way with a lowest price, and
the two checks every decoder makes of them [V source]. The rules are those
of `CowSwapDecoder`, which keeps its own copy: its deployed code does not
change when a second venue arrives.

- `check(pairs, sellToken, buyToken, sellAmount, buyAmount)` reverts unless
  the pair is listed exactly once (`PairNotListed`, `PairListedTwice`), with
  two different tokens and a price, and
  `buyAmount · perSell ≥ sellAmount · minBuy` in 512 bits
  (`BelowTheLowestPrice`). A list of more than `MAX_PAIRS` = 16 allows
  nothing (`InvalidConfig`). It does not rest on `checkList`.
- `checkList(pairs)` reverts `InvalidConfig` unless the list has one to
  `MAX_PAIRS` pairs, non-zero and distinct tokens, a price in both terms and
  no pair twice.

## OneInchLimitOrderDecoder

`contracts/src/venues/OneInchLimitOrderDecoder.sol`. `IVenueDecoder` for a
plain order of 1inch's Limit Order Protocol v4, which is part of 1inch's
router, AggregationRouterV6, at `0x111111125421cA6dc452d289314280a0f8842A65`
[V source]. The CLI places such orders (`"kind": "1inch"` in a config's
`venues`, `order sell`), and the phone's core reads the venue's terms. It
is deployed on Sepolia and Base Sepolia since 2026-11-27, and the phone's
core names it there by address and code
([`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md),
[`docs/AGENT_CONFIG.md`](AGENT_CONFIG.md)). An order was registered
through it on Sepolia on 2026-11-27, and the account vouched for it there;
it was sent to no order book and not filled ([`docs/DAPPS.md`](DAPPS.md#on-a-chain-the-runs-on-sepolia-of-2026-11-27)).

**State.** None: no storage, no upgrade path, no `delegatecall`, no
`selfdestruct`. The router's address and its EIP-712 domain separator are
kept as immutables (`venue`, `spender`, `domainSeparator`). The router
pulls the sold token itself, so it is both the venue's contract and the
spender [V source].

**The constructor asks the router twice** [V source;
`test_constructor_refusesARouterItDoesNotHashLike`]:

- `eip712Domain()`: the domain must have a name, a version, this chain and
  this router, and no other field (`NotTheRoutersDomain`). The separator is
  built from the name and version the router gives.
- `hashOrder(probe)`: the router's own hash of an order with a different
  number in every word must be the one built here (`NotTheRoutersHash`). A
  decoder cannot be deployed for a router that hashes otherwise.

**Config.** `abi.encode(Config)`: `maxLife` (the most seconds between
registering an order and its expiration) and up to 16 pairs (`VenuePairs`).

**Rules of `judge`**, each with what it rests on in the router [V source;
V `contracts/test/OneInchTrading.t.sol` `OneInchRealRouterTest`, run against
the router's code from Ethereum, Base, Sepolia and Base Sepolia]:

| Rule | Error | Why |
|---|---|---|
| The order is exactly eight ABI words, read as numbers | `NotAnOrder` | the router hashes the eight words as the taker hands them over |
| The maker's word is the account's address, with nothing above it | `NotTheAccountsOrder` | the router reads an address from a word's low 160 bits and hashes the whole word: a word with high bits is the same maker under another hash (`test_real_aDirtyMakerWordIsTheSameMakerUnderAnotherHash`) |
| `receiver` is zero or the maker's word | `ProceedsLeaveTheAccount` | the router pays the receiver, and reads zero as the maker |
| Both token words are addresses | `NotAnAddress` | the pair is compared by address |
| No partial fills (bit 255 of `makerTraits`) | `PartiallyFillable` | of an order filled in parts the router asks the maker on the first fill only (`test_real_anOrderFilledInPartsIsAskedOnce`); an order filled whole fills once, by a bit per maker and nonce |
| Bits 160 to 254 of `makerTraits` are zero: no extension, no call before or after the fill, no Permit2, no unwrapping, no epoch, no several fills | `NotAPlainOrder` | without the extension flag the router refuses any extension, so no amount getter, predicate or transfer suffix runs; the two call flags would still call the maker itself (`test_real_theInteractionFlagsCallTheMaker`) |
| The expiration (bits 80 to 119) is not zero | `NeverExpires` | zero is "never" to the router (`test_real_anOrderWithoutAnExpirationNeverEnds`) |
| `makingAmount` is not zero; both amounts fit 128 bits | `NothingToSell`, `AmountTooLarge` | the range the router's own arithmetic is written for |
| The pair is listed, at no less than its lowest price | `VenuePairs` errors | as at every venue |

The agent picks the salt, the nonce (bits 120 to 159) and the one taker
allowed (bits 0 to 79) freely. It returns `mostSold = makingAmount` (the
router adds no fee to a plain order), `validTo` = the expiration,
`notBefore = expiration − maxLife` (zero if the expiration is not above
`maxLife`) and the EIP-712 digest of the eight words under the router's
domain. The digest is held to forge's EIP-712, and to the router's own
`hashOrder` on four chains [V `test_digest_agreesWithAnIndependentEip712`,
`test_digest_isTheOneTheRouterGave`].

**Other functions.**

- `untouched(account, order)` reads the order's one-fill bit at the router
  (`bitInvalidatorForOrder`). The bit belongs to the maker and the nonce:
  another order of the account with the same nonce sets it too, and a fill
  and a cancellation set it alike [V `test_untouched_readsTheOrdersBit`,
  `test_oneInch_ordersOfOneNonceFillOnce`].
- `checkConfig(config)` (a view) returns true or reverts `InvalidConfig`: a
  non-zero `maxLife`, a list `VenuePairs.checkList` accepts, and code at
  every token's address. The router takes a transfer at an address without
  code for done, so an order that buys such a "token" gives the sold amount
  away (`test_real_aTokenWithoutCodeIsTakenForPaid`). `judge` cannot ask
  for code inside validation; the owner's tools ask here before the mandate
  is made.

**What the owner accepts with this venue.**

- **The allowance is to the whole router.** Its other functions pull from
  their own caller only; the agent cannot call the router, which is a
  venue's place [V `test_oneInch_theRouterIsNotATarget`,
  `test_oneInch_theOwnerCancelsAtTheRouter`]. The router's code was read
  for the order path, not audited by us [I].
- **The router's owner can pause fills** [V source: `_fill` is
  `whenNotPaused`]. A paused router fills nothing; the charge of a
  registered order stays until the budget renews.
- **Who fills a plain order.** Any taker that has the order and its
  signature can fill it at the router. 1inch's own order book builds orders
  with a fee extension, which this decoder refuses; whether it lists a plain
  order was not tested [I]. Until a decoder reads that extension, a plain
  order is filled by a taker the agent's operator hands it to.

## VenueCalls

`contracts/src/venues/VenueCalls.sol`. A library of two internal functions:
how a call the account is to make is named between a decoder and the policy
[V source].

- `digest(value, data)` is `keccak256(abi.encode(value, keccak256(data)))`:
  what a decoder answers with for a call. The target is not in it: a
  decoder does not name one.
- `bound(place, callDigest)` is `keccak256(abi.encode(place, callDigest))`:
  what the policy keeps, with `place` the decoder's `venue()`, and compares
  with the same hash of the leg after the registration.

Both are hashes of two words, so neither is an EIP-712 digest (66 bytes) nor
any venue's order; the policy keeps the bound hash in transient storage for
one operation and vouches for it to nobody.

## SwapRouter02Decoder

`contracts/src/venues/SwapRouter02Decoder.sol`. `IVenueDecoder` for one
call: a swap of an exact amount through one Uniswap v3 pool, at Uniswap's
SwapRouter02 (`exactInputSingle`, selector `0x04e45aaf`) [V source]. It
judges a call, not an order. The CLI swaps there (`"kind": "uniswap"` in a
config's `venues`, `order swap`), and the phone's core reads the venue's
terms. It is deployed on Sepolia and Base Sepolia since 2026-11-27, and the
phone's core names it there by address and code
([`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md),
[`docs/AGENT_CONFIG.md`](AGENT_CONFIG.md)). The first swap through it on
a chain was made on Sepolia on 2026-11-27 ([`docs/DAPPS.md`](DAPPS.md#on-a-chain-the-runs-on-sepolia-of-2026-11-27)).

**State.** None: no storage, no upgrade path, no `delegatecall`, no
`selfdestruct`. The router's address is kept as two immutables (`venue`,
`spender`): the router takes the sold token from its caller itself. The
constructor asks only for code at the router's address (`NotARouter`).

**Config.** `abi.encode(Config)`: up to 16 pairs (`VenuePairs`), each one
way with a lowest price.

**What the agent names, and what it does not.** The decoder's "order" is
`abi.encode(Swap)`, exactly five words: `tokenIn`, `tokenOut`, `fee` (the
pool's fee tier), `amountIn`, `amountOutMinimum`. From them the decoder
builds the router call itself (`swapCall(account, order)` returns it), with
the rest written in: the recipient is the account, the price limit is zero,
and the call's hash is of no native value. The agent's leg must be those
bytes, or the policy refuses the operation.

**Rules of `judge`**, each with what it rests on in the router [V source;
V `contracts/test/SwapRouter02.t.sol` `SwapRouter02ForkTest`, run against
the router `0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4` and the pool
`0x46880b404CD35c165EDdefF7421019F8dD25F4Ad` on a fork of Base Sepolia,
2026-11-26]:

| Rule | Error | Why |
|---|---|---|
| The swap is exactly five ABI words, each as wide as its type | `NotASwap`, or the decoding reverts | the call is built from the values judged, and nothing rides along |
| `amountIn` is not zero | `NothingToSell` | zero means "what the router holds" to the router: whoever calls first swaps it for themselves (`test_real_anAmountOfZeroIsTheRoutersBalance`) |
| The pair is listed, at no less than its lowest price | `VenuePairs` errors | the router then requires the pool to pay at least `amountOutMinimum`, or the swap reverts |
| The recipient is the account (written in) | none | `address(1)` and `address(2)` mean the caller and the router to the router, and what the router holds anyone sweeps (`test_real_aRecipientOfTwoLeavesTheOutputToAnyone`) |
| No price limit (written in) | none | the check of the least bought is then of the whole swap |
| No native value (written in) | none | value sent to the router is spent as wrapped ether, and what is left anyone refunds to themselves |

It returns `sellToken = tokenIn`, `mostSold = amountIn`, `notBefore` and
`validTo` zero, and `VenueCalls.digest(0, the call)`.

**What the owner accepts with this venue.**

- **A standing allowance to the router,** given by the owner like the one
  to CoW's relayer. The router takes the sold token from its own caller
  only, so nobody else's call can spend the account's allowance
  (`test_real_theRouterTakesFromItsCallerOnly`), and the account's calls
  reach the router through this decoder alone: each is charged the amount
  sold, against the token's cap per operation and its budget
  (`test_swap_heldToTheCapAndTheBudget`). The router's other functions
  (`multicall`, the sweeps and unwraps, `pull`, the position-manager calls,
  the permits) are not this call, so the agent cannot reach them
  (`test_swap_theRouterTakesNoOtherCall`,
  `test_fork_theRouterTakesNoOtherCall`). The router's code was read for
  this path, not audited by us [I].
- **A swap that reverts is still charged.** The charge is made when the
  swap is registered, in validation; if the market moved under the least
  bought, the operation runs, the swap reverts, nothing moves, and the
  budget is shorter by the amount until the period turns
  (`test_swap_aSwapThatRevertsIsStillCharged`).
- **The pool is the agent's choice among the pair's pools.** The fee tier
  names it. Whatever pool it is, the account receives at least
  `amountOutMinimum` of the bought token or the swap reverts; the lowest
  price is the owner's, not the pool's.
- **One pool, exact input only.** Paths through several pools, exact-output
  swaps and the v2 functions are other functions of the router, not
  allowed here.

**Other functions.**

- `swapCall(account, order)`: the calldata the account must send to the
  router, with no value, in the leg after the registration.
- `untouched(account, order)`: always false. Nothing of a swap is left to
  be filled later, and the policy keeps no record of it to give back.
- `checkConfig(config)` (a view) returns true or reverts `InvalidConfig`: a
  list `VenuePairs.checkList` accepts, and code at every token's address.

## CallRulesDecoder

`contracts/src/venues/CallRulesDecoder.sol`. `IVenueDecoder` for calls at
one contract, its `venue`: the owner lists the functions the agent may call
there and, for each, a rule for every argument word [V source]. It judges a
call, not an order. One decoder is deployed for each contract it speaks for
(`contracts/script/DeployCallRules.s.sol`): the policy admits a decoder's
call at the decoder's own venue and nowhere else. The CLI calls there
(`"kind": "rules"` in a config's `venues`, `order call`), and the phone's
core shows each function with the rule for every argument. Two are
deployed on Sepolia and on Base Sepolia since 2026-11-27, one for Aave
V3's pool and one for CCTP's messenger, and the phone's core names them
there by address and code ([`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md),
[`docs/AGENT_CONFIG.md`](AGENT_CONFIG.md)). Both were used on Sepolia on
2026-11-27: a supply and a withdrawal at Aave, a transfer by CCTP
([`docs/DAPPS.md`](DAPPS.md#on-a-chain-the-runs-on-sepolia-of-2026-11-27)).

**State.** None. The venue and the spender (the contract the account
approves there; the venue itself where it pulls tokens itself) are
immutables; the constructor asks for code at both (`NotAContract`).

**Config.** `abi.encode(Config)`: one to 8 functions, each a selector and a
rule for each of its argument words, in order, at most 16. A rule is a kind
and a value:

| Kind | The word must be | `value` |
|---|---|---|
| `IS_ACCOUNT` (0) | the account's address, as a whole word | zero |
| `IS_VALUE` (1) | exactly `value` | the value |
| `AT_MOST` (2) | at most `value`, as an unsigned number | the bound |
| `CHARGED` (3) | an amount; it is charged in the token `value` names | the token |
| `ANY` (4) | anything: the agent's choice | zero |

Every word has a rule: a word left to the agent is written down as `ANY`,
so the owner's screen can show it as such. At most one word is charged.

**Rules of `judge`** [V source; V `contracts/test/CallRules.t.sol`, and
`PoolForkTest` there against Aave V3's pool
`0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27` on a fork of Base Sepolia,
2026-11-26]. The "order" it is handed is the call's calldata.

| Rule | Error |
|---|---|
| The call has a selector | `NotACall` |
| Its function is listed, once | `FunctionNotListed`, `FunctionListedTwice` |
| It is exactly as long as its function's rules: the selector and one word a rule | `NotTheFunctionsLength` |
| Every word passes its rule | `WordRefused(index)` |
| The config holds: at most 8 functions and 16 words, known kinds, a value only where its kind reads one, one charged word in a token | `InvalidConfig` |

It returns the charged word's token and amount as `sellToken` and
`mostSold` (zero where the function charges nothing), `notBefore` and
`validTo` zero, and `VenueCalls.digest(0, the calldata)`: no native value
goes with the call. A config at both limits is judged in 70,135 gas of the
150,000 the policy gives a decoder
[V `test_rules_aConfigAtTheLimitsIsJudgedWithinTheGasBound`].

**What it does not know, and the owner has to.**

- **What the contract does with the words.** The decoder reads 32-byte
  words. Which word is a beneficiary, and what a value means to the
  protocol, is what the owner writes the rules from.
- **Dynamic arguments.** A `bytes` or an array has an offset and a length
  among the words. Held to the values of the one encoding meant (an empty
  `bytes` is its offset and a zero length), the call has that shape and no
  other; left as `ANY`, they are the agent's.
- **The charge is the word, as the contract will read it.** A contract that
  takes more than the word says, or takes from a balance it already holds,
  is outside what a word can bound.
- **A standing allowance to the spender,** where a function is charged
  here: it must be one only the account's own calls can spend. Aave's pool
  takes a supply from its caller only
  [V `test_real_thePoolTakesFromItsCallerOnly`].
- **A call that reverts is still charged,** as at every venue of calls.

**Other functions.** `untouched` is always false. `checkConfig(config)`
returns true or reverts `InvalidConfig`: the rules above for every function
whether or not it is called, and code at each charged token.

## SeaportBidDecoder

`contracts/src/venues/SeaportBidDecoder.sol`. `IVenueDecoder` for a bid at
Seaport 1.6 (`0x0000000000000068F116a894984e2DB1123eB395`, the same
address on every chain it is on): the account offers an amount of an
ERC-20 token for one ERC-721 item of a collection the owner listed [V
source]. It judges an order: the account vouches for it when Seaport asks
(ERC-1271), as for a CoW or a 1inch order. The contract and its tests are
here; the CLI and the phone do not place or show such bids yet. The
decoder is deployed on Sepolia and Base Sepolia since 2026-11-27
([`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md)), and the phone refuses a mandate
that names it: its core knows it as a name and not as a venue.

**State.** None: no storage, no upgrade path, no `delegatecall`, no
`selfdestruct`. Immutables: `venue` (Seaport), `conduitKey` (the conduit an
order must name; zero is Seaport itself), `spender` (that conduit, or
Seaport: the address the owner's allowance is given to) and
`domainSeparator`.

**The constructor asks Seaport three things** [V source;
`test_aSeparatorOfAnotherChain_orAnotherAddress`,
`test_aKeyWithoutAConduit`, `test_aSeaportThatHashesOtherwise`]:

- its domain separator (`information()`), which must be the one of the
  name `Seaport`, Seaport's own version, this chain and Seaport's address,
  or `NotSeaportsDomain`;
- the conduit behind the key, from Seaport's conduit controller, or
  `NoSuchConduit`;
- its hash of a probe order with a different value in every field
  (`getOrderHash`), which must be the hash built here, or
  `NotSeaportsHash`: the decoder writes the hash from Seaport's type
  strings, and cannot be deployed for a Seaport that hashes otherwise.

**The config** is `abi.encode(Config{maxLife, pairs})`. A pair is
`VenuePairs.Pair`: `sellToken` the token paid, `buyToken` the collection,
and its price reads "at least `minBuy` items for each `perSell` of the
token", so one item costs at most `perSell / minBuy`. **The order** is
`abi.encode` of Seaport's order components, as Seaport lays them out.

**`judge` allows an order only if** [V source; one test for each in
`SeaportBidDecoder.t.sol`]:

| Rule | Refused with |
|---|---|
| the account is the offerer | `NotTheAccountsOrder` |
| one thing is offered: an amount of an ERC-20 token, not zero, without an id | `NotABid` |
| every amount is the same at the order's start and at its end | `AmountChangesWithTime` |
| one to eight things are asked for | `NotTheConsiderationOfABid` |
| the first is one ERC-721 item to the account: a named item, or one by criteria | `NotAnItemForTheAccount` |
| every other is an amount of the offered token (a fee), and together they are no more than the offered amount | `NotAFeeInTheOfferedToken`, `FeesAboveTheOffer` |
| the order is filled whole: Seaport's type 0, or type 2 (which its zone may refuse) | `NotFilledWhole` |
| it has an end that fits 48 bits | `NeverEnds` |
| its conduit key is the decoder's | `NotThisConduit` |
| the token and the collection are a listed pair, and the price is no more than the pair's | `VenuePairs.PairNotListed`, `BelowTheLowestPrice` |

It answers: the offered token, the offered amount as the most the order
can take, the order's end, the end less `maxLife` as the earliest time it
may be registered, and Seaport's EIP-712 digest of the order. The zone, its
word, the salt, the start, the counter and the item's id or criteria are
the agent's to choose: each is in the digest, and none changes what the
account pays or receives.

**What the rules rest on in Seaport** [V the source of seaport-core
v1.6.6, read on 2026-11-27; each also run against Seaport's own code on a
fork of Base Sepolia, `SeaportRealTest`]:

- Whichever of Seaport's ways an order is filled, the offered amount leaves
  the offerer and no more. The standard routes send it whole to the filler,
  who pays the fees; the basic route pays the fees, and what the filler
  adds, out of it; matching splits it
  [V `test_real_everyWayOfFillingTakesThePriceAndGivesTheItem`,
  `test_real_feesComeOutOfThePriceInTheBasicRoute`].
- What the order asks for goes to the recipient the order names, in full,
  or the fill reverts. With criteria the filler picks the item
  [V `test_real_aBidForAnyItemOfTheCollection`].
- A part of a "full" order is refused, and it fills once
  [V `test_real_aPartOfABidIsRefused`].
- With unequal start and end amounts Seaport takes what the moment says
  [V `test_real_anOfferThatRisesTakesMoreLater`].
- A zone can make a fill revert and can cancel the order; it changes
  nothing of what moves [V `test_real_aZoneCanOnlyRefuse`].
- The order's conduit key says whose allowance is spent
  [V `test_real_theKeySaysWhichAllowanceIsSpent`].
- The digest is of the components with the offerer's counter at the time of
  the fill: a bid carries the current counter, or it is dead.

**What the decoder cannot hold:**

- **Seaport keeps a signature it has checked.** Anyone may have an order
  the account vouches for validated at Seaport (`validate`); from then on
  Seaport fills it without asking the account, until the order's end.
  Removing the mandate does not stop such an order. Cancelling at Seaport
  (`cancel`, or `incrementCounter` for every order of the account) does,
  and so does taking the allowance back, which the owner's tools do when a
  mandate is removed. What a validated order can take is still its own
  price, once, before its end [V
  `test_seaport_aValidatedOrderIsNotAskedAgain`,
  `test_seaport_theOwnerCancelsAtSeaport`].
- **The allowance to a conduit** is an allowance to whoever the conduit's
  owner opens it to: an open channel can move any token approved to the
  conduit [V source, `Conduit.execute`]. It is bounded by what the owner
  approved: one budget.
- **Seaport does not check what a token is.** It moves an ERC-721 item and
  an ERC-20 amount by the same call: with a token listed as a collection,
  "the item 5" is five units of it [V
  `test_real_aTokenListedAsACollectionIsPaidInItsUnits`]. The collections
  are the owner's list, and `checkConfig` asks each whether it is an
  ERC-721.

**Other functions.** `untouched(account, order)` is true when Seaport's
record of the order shows no fill and no cancellation; Seaport keeps that
record for good. `checkConfig(config)` returns true or reverts
`InvalidConfig`: a lifetime, one to sixteen pairs, none twice, a price for
each, code at each token, and at each collection a contract that answers
ERC-165 that it is an ERC-721 (one word, true).

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

**Base Sepolia.** `0x29da894F3E456CAC92b3EC76710524E74411E99f`
(`demoCounter`) [V `contracts/deployments/84532.json`]. The earlier one,
`demoCounterV1` (`0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1`), has code
that ends in the compiler metadata of an earlier build (solc 0.8.34), so it
is not byte-equal to what commit `175acbf3a3127e804a45a3e4dd097165f0a4c922`
compiles to; its source did not change from 2026-10-20 until `VERSION` was
added [V `cast code`, `git log`, 2026-11-24].
