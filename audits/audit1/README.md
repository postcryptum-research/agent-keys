# Audit 1: the whole repository at `73a707c`, 2026-11-24

An internal audit, the first one made of a named commit and meant to be
repeated: later audits compare with this date and this commit. It is not an
external audit.

- **Commit:** `73a707ca2cc573b85f117bab929f4528f61c2be2` (`master`,
  2026-11-24).
- **Pinned dependencies read where a finding needed them:** Kernel v3.3
  (`cd697c7`), account-abstraction v0.7.0 (`7af70c8`), OpenZeppelin 5.0.2
  (`dbb6104`), Solady 0.1.26 (`acd959a`), Safe 1.4.1 (`bf943f8`).
- **State of the project then:** test networks only (Base Sepolia, Sepolia),
  no real funds.

## Scope

The contracts in `contracts/src`, the Rust signer (`signer/`), the phone's
core (`mobile/owner-core`) and the ERC-7562 checker (`scripts/erc7562`).

## Method

Separate passes over the contracts, the Rust signer, and the phone's core
with the checker; then each key finding was run again with a proof of
concept at the audited commit. Everything ran locally (anvil, forge,
cargo): no transaction was sent to a network.

## Verdict

**No Critical. 1 High, 1 Medium, 5 Low, 8 notes. All resolved**; the audit
of 2026-11-27 read the fixes at
`4295e00bcf7ef19a2cde92b191d6ad40604a543b` and confirmed them
([`audit2`](../audit2/README.md#the-findings-of-audit-1-read-again)).

| # | Severity | Where | Summary | Issue | Fixed in |
|---|---|---|---|---|---|
| AK-M-1 | High | phone's core | The owner's confirmation screen can name the wrong key for a change of the root validator | #147 | #155 |
| AK-S-1 | Medium | CLI | A bundler's gas figures go into the signed operation unchecked: a bundler can bill the mandate's budget | #148 | #160, and #167 for #162 |
| AK-C-1 | Low | `AgentPolicy` | A venue's `spender()` is not refused as a mandate's target | #149 | #159 |
| AK-S-2 | Low | CLI | A gas quantity over 128 bits from a bundler or a node makes the CLI panic | #150 | #160 |
| AK-S-3 | Low | CLI | An x402 authorization's lifetime overflows on a huge `maxTimeoutSeconds`, and has no upper bound without a period | #151 | #161 |
| AK-E-1 | Low | ERC-7562 checker | Addresses in a trace are not brought to one case: three rules stop matching on a hand-written trace | #152 | #156 |
| AK-E-2 | Low | ERC-7562 checker | A first operation's trace is judged as if it had no factory: a false refusal with a misleading reason | #153 | #156 |
| notes | Info | several | Eight hardening notes, below | #154 | #156, #158, #159 |

## The findings

### AK-M-1 (High): the confirmation screen can name the wrong key

For `changeRootValidator` the phone's review took the key it shows from the
call's `validatorData`. Kernel v3.3 ignores that data when the validator is
already installed, also when it was installed earlier in the same batch:
only `installValidations` sets the key. A batch of
`installValidations(recovery, key A)` and then
`changeRootValidator(recovery, key B)` showed the owner "hand control of
this account to key B", and the root went to the validator holding key A.
The line the owner decides by was false.

What limited it then: the CLI's own flows send no `validatorData`, and the
line that installs key A was shown in bold.

**Fix (#155):** a `changeRootValidator` that carries `validatorData` is
refused by the phone.

### AK-S-1 (Medium): a bundler's gas figures were signed as given

The CLI wrote a bundler's `verificationGasLimit`, `callGasLimit` and
`preVerificationGas` into the operation without a check, took its gas
prices as given and raised them again without a ceiling.
`preVerificationGas` is charged to the account and paid to the bundler's
beneficiary, and no person confirms an agent's operation. The same
operation cost the account 0.00106 ETH with an honest estimate and 0.0766
ETH with an inflated one, inside a budget of 1 ETH: a bundler could turn
what is left of a mandate's budget into its own income.

**Fix (#160):** a bundler's figures are bounded by the CLI's own estimate,
made before the bundler is asked, and its fee by a floor and a ceiling. A
factor per chain on the `preVerificationGas` ceiling, 1 by default, came
with #167 (#162).

### AK-C-1 (Low): a venue's spender as a target

Installing a trading venue barred its settlement contract and its decoder
as targets of the mandate, and not the address its decoder names as
`spender()`: the holder of the account's allowance. A mandate with that
address on its allow-list installed, and tokens could have left past the
caps and the payee lists. It took an owner's mistake.

**Fix (#159):** the spender is barred with the other two.

### AK-S-2 (Low): panics on wide quantities

Conversions of 256-bit values from a bundler's or a node's answer to 128
bits panicked above 2^128: a bundler could stop the CLI before it signed.

**Fix (#160):** checked conversions, and the bounds of AK-S-1.

### AK-S-3 (Low): the lifetime of an x402 authorization

`now + max(timeout, minimum)` overflowed on a huge `maxTimeoutSeconds` from
a server: in a release build an authorization that had already expired,
with its amount held from the budget. And without a budget period nothing
bounded the lifetime: the amount stayed held until it ran out.

**Fix (#161):** the sum cannot overflow and the lifetime is held between
120 and 3600 seconds.

### AK-E-1 and AK-E-2 (Low): the ERC-7562 checker on traces it did not record

The checker did not bring a trace's addresses to one case, so an
EntryPoint written in checksum case turned three rules off: a false pass
on a trace written by hand or by another tool. And a first operation was
judged without its factory: a false refusal. Neither touched the gate CI
runs on the project's own traces.

**Fix (#156):** addresses are normalized throughout, and the factory and
the paymaster are read from the trace.

### Notes (Info), #154

| Note | Resolution |
|---|---|
| Registering an expired x402 authorization again after it was reclaimed: an agent can hold its own budget this way, and nothing is taken | accepted; stated in the docs (#158) |
| A comment spoke of two x402 entry points where the code admits three calls of the policy | the comments name the two x402 calls and the order call (#159) |
| A validator's `onInstall` accepted bytes after its 64 or 96 | exactly 64 or 96 bytes (#158) |
| A TPM key written without its tag lost its `authFile` silently | unknown fields are refused, and `pcrs` with `authFile` is refused (#158) |
| The mode of a file holding a secret was not checked | an auth file readable by group or others is refused (#158) |
| Enrollment records were written with the default mode | written for the owner only, also over an existing file (#158) |
| A malformed trace ended the checker with an uncaught error | refused with a reason (#156) |
| No recorded trace with a factory or a paymaster, or of the rule-breaking test policy's fifth mode | traces with a factory and with a paymaster are recorded and checked (#156); the audit of 2026-11-27 found them, with those of transient storage and of the rule-breaking policy, in the checked set |

## What was looked at and found sound

- **The allow-list:** the zero selector passes with an empty body only;
  bodies of one to three bytes, delegate calls and try-mode executions are
  refused; every leg of a batch is judged; a Safe transaction passes only
  after the nonce assertion; non-canonical offsets either revert or give
  the slice that Kernel's own decoder executes.
- **The limits:** the cap per operation and the budget for native value,
  with the most the gas can cost where the account pays it, and for the
  four metered ERC-20 functions; per-operation totals in transient storage;
  a payee word with bits above the address is refused; overflows fail
  closed.
- **Windows and periods:** a past period is refused and a future one is
  not credited early; x402 authorizations and orders end with their period.
- **Venues:** the decoder's code hash and configuration are pinned, its
  answer is exactly five words within a gas bound, and its settlement
  contract and decoder are never targets.
- **P-256:** an empty answer of the precompile is not a success; low `s` is
  enforced; the zero point and points off the curve are refused at install;
  where the precompile is missing, verification fails closed.
- **With Kernel:** a refusal by the policy reverts the validation and every
  write with it; an install cannot be front-run; a reinstall goes through
  an epoch.
- **The account's ERC-1271 path:** the root branch answers for the owner
  only, under a domain bound to the account and the chain; the permission
  branch refuses everything but a registered digest; the recovery branch
  does not answer at all.
- **The signer:** keys do not leave the hardware; software keys need a
  feature a release build does not carry; the operation's hash is compared
  with the chain's before signing; configuration files refuse unknown
  fields.
- **The phone's core:** one parse gives both the screen and the digest;
  decodings are checked by encoding them again; sums are checked; the
  session is authenticated by the QR's secret with a constant-time
  comparison; an Android attestation is verified to Google's roots.
- **The ERC-7562 gate in CI:** it does not pass by default: a staked
  factory, a fixed reason for a refusal, and an empty directory fails.

Named for the next audit: the policy's own decoder of `multiSend` and its
pass-through of Safe transactions, with deep fuzzing of non-canonical
encodings against a reference decoder; and the earlier `AgentPolicy`
instances that stay on the test networks while a mandate still points at
one.

## What was run

At the audited commit, all passing:

| Suite | Result |
|---|---|
| `contracts`: `forge test` (Osaka) | 497 of 497; 774 of 774 with the audit's own tests added |
| `signer`: `cargo test` | 34 passed, 2 ignored (they need hardware) |
| `mobile/owner-core`: `cargo test`, and with `ffi,test-chains` | 51 and 56 passed |
| `scripts/erc7562`: `npm run check` | passes: 8 traces in 2 modes |
| Fuzzing, 20000 runs: the policy, trading and the CoW Swap decoder | 26 of 26 |

## What it did not cover

Hardware backends on real devices; the native phone apps as built
applications; the integrations in `examples/`; a comparison of the
deployed bytecode with the source by the audit itself (the project's own
comparison of that date was read).
