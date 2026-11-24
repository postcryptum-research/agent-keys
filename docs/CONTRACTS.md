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
`AgentPolicy`'s section follows with its next instance.

| Contract | What it is | Who calls it | Base Sepolia |
|---|---|---|---|
| `P256Validator` | the owner key, as the account's root | Kernel, from the account | `0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2` |
| `P256RecoveryValidator` | the recovery key, granted only `changeRootValidator` | Kernel, from the account | `0x63dd80Fc5E109A44fd179F85050487E02c5e6958` |
| `P256Signer` | the agent key, as one Kernel permission | Kernel, from the account | `0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E` |
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
install data is the key and nothing more, from 0.1.1 (#154): the Base
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
  authorization (`docs/ERC1271.md`);
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
checked at install, install data of exactly the id and the key from 0.1.1
(the Base Sepolia instances ignore bytes past the 96). Keys are scoped per
(permission id, account) [V source,
`test_signerInstallDataIsExactlyTheIdAndTheKey`].

**Base Sepolia.** `0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`
(`p256Signer`); earlier, `p256SignerV1` [V `contracts/deployments/84532.json`].

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
The `AgentPolicy` in this tree does not call decoders yet [V
`contracts/src/AgentPolicy.sol` has no reference to `IVenueDecoder`].

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
- `spender()`: who takes the sell token from the account, for the owner's
  tools (the allowance); the policy does not ask.

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
