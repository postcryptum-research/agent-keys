# Fuzzing

Fuzzing is a stage of its own beside the tests and the audit: it replaces
neither. The tests hold what someone thought of; the audit is a careful
read; fuzzing tries a great many inputs nobody wrote down and checks them
against a rule that must hold for all of them.

## Contracts: `AgentPolicy`

`contracts/test/PolicyFuzz.t.sol`. The policy is driven at its own
interface (`onInstall`, `checkUserOpPolicy`, the views), without Kernel,
keys or signatures, so a run is cheap. Operations come from a seed: mostly
well-formed and near the limits (a cap, one over, the last unit of a
budget, one past it), with a share of damaged ones.

| Test | What must hold |
|---|---|
| `testFuzz_model_decisionsAndCounters` | a second, plain statement of the rules (the model in the test) and the policy decide every operation alike, 40 in a row per seed, and count alike; no counter passes its limit |
| `testFuzz_model_arbitraryCallDataIsRefused` | bytes that are no `execute` call are never let through |
| `testFuzz_model_arbitraryExecuteBodyStaysWithinLimits` | an `execute` with arbitrary bytes behind it moves no counter past one operation's limits |
| `testFuzz_differential_sourceAgainstTheDeployedInstance` | the policy in the source and the runtime code deployed to Base Sepolia on 2026-11-26 agree on every decision, every returned validation word and every view, 40 operations per seed, across uninstall and reinstall; here the operations also go through a Safe, MultiSend batches and x402 registrations. Between operations the account asks for a registered authorization back (`x402Reclaim`), as registered or with one field changed, after time has moved or the token has come to say the nonce was used: both answer alike, and as the rule says on its own (only what is registered, past its `validBefore` and not settled comes back, once, and the token's counter falls by exactly its value) |
| `testFuzz_differential_mandatesFromTheSeed` | both install or both refuse a mandate built from the seed (it draws from everything install must refuse), and what is then readable of it is the same |
| `testFuzz_differential_arbitraryCallData`, `…arbitraryInstallData` | the same answer from both for arbitrary bytes |

The differential tests were written when the source and the deployed
instance differed only in where they kept their state
([#83](https://github.com/postcryptum-research/agent-keys/issues/83)): any
difference in behaviour was a bug in one of them, and 10,000 runs found
none. The vector in `contracts/test/vectors/` is now the runtime code of
the `AgentPolicy` deployed on 2026-11-26 from commit
`e48b93e001f34f460bd4845d231b8e0ee5d26ad6`, read from Base Sepolia, so both
sides are the same code: the tests hold what is deployed to the source, and
guard the next change to it. Approvals are drawn with any amount and every
mandate goes to both, since the instance has the source's rules (no
standing allowances, no metered function without a limit). With the
end-of-operation allowance check removed from the source, the first seed
fails [V 2026-11-25]. The model tests do not depend on the vector.

```sh
cd contracts
forge test --evm-version osaka --match-contract PolicyFuzz                      # 256 runs each, seconds
FOUNDRY_FUZZ_RUNS=10000 forge test --evm-version osaka --match-contract PolicyFuzz   # about six minutes
```

**That they bite.** Seventeen rules were broken in the source one at a time
(the payee's upper bits not checked; the per-operation sum replaced by a
per-call check; a token budget and the value cap each off by one; the zero
selector allowed with a body; gas not charged to the budget; the payee list
not held for x402; the epoch not moved at uninstall; a Safe gas refund
allowed; and at install: a function outside the four on a limited token,
a payee twice, Permit2, a token twice; and in `x402Reclaim`: before
`validBefore`, of a settled authorization, returning nothing, leaving the
record). Every one is found at 256 runs.
Two were missed by the first form of the generator (a budget off by one,
the payee list for x402), which is why it now aims at a budget's last unit
and gives the listed token an x402 domain.

**What they do not cover.**

- The model covers the account's own calls and batches; Safe, MultiSend and
  x402 are held by the differential tests only, that is, against the
  deployed instance and not against an independent statement of the rules.
- `x402Reclaim` runs against a stand-in for the token that answers the one
  question it asks (was the nonce used); no real token is involved.
- **Contracts that are not ours are taken to be correct:** Kernel, the
  EntryPoint, Safe, MultiSend and Solady's P-256 verifier. The fuzzing
  holds this project's own code to its rules and does not look for errors
  in theirs; the policy is driven without them. The existing tests run
  the whole path through them end to end, on examples.
- A generator finds what it can reach. These reach the limits by aiming at
  them; a rule nobody aimed at may go unvisited.

## Contracts: trading

`contracts/test/TradingFuzz.t.sol`, for the budget per period and the
orders of [#80](https://github.com/postcryptum-research/agent-keys/issues/80).
A mandate with a period and one venue (CoW's decoder over a stand-in for
the settlement, whose fills the test decides) is driven at the policy's own
interface while the clock moves: to a period's last second, its first one
and the one after, among others. An operation names its period, the right
one or a neighbour, and carries transfers, order registrations and plain
calls; between operations the venue fills an order or the account asks for
one back. The account in the test does the EntryPoint's part: the policy
answers with a window and may not read the clock, so an operation counts
as accepted only if the clock is inside that window.

| Test | What must hold |
|---|---|
| `testFuzz_trading_modelDecisionsCountersAndOutflow` | the model and the policy decide every operation alike (an order that would outlive the period it is charged in is refused by both), the policy gives no order's charge back when asked, 40 steps per seed, and count alike (native spent, token spent, the period seen); the account vouches for an order exactly while it is not past its end; and, without leaning on the model's counters, in no period does more of the token leave than its budget, counting the transfers of that period and every order charged to it that the venue filled |
| `testFuzz_trading_noMoreThanTwoBudgetsAcrossARenewal` | the number the owner is shown: what is transferred in two neighbouring periods together is never more than two budgets |

```sh
cd contracts
forge test --evm-version osaka --match-contract TradingFuzz                        # 256 runs each, seconds
FOUNDRY_FUZZ_RUNS=10000 forge test --evm-version osaka --match-contract TradingFuzz    # under two minutes
```

10,000 runs of each find nothing.

**What it found while it was written.** The policy cut an operation's
window to its period with a lower bound one second early: it took the
EntryPoint to read `validAfter` as exclusive, and EntryPoint v0.7 reads it
as inclusive. In a period's last second an operation naming the next period
was accepted. Nothing more could be spent than the two budgets across a
renewal that the owner is told of, and no earlier test held that second.
The bound is corrected and the model holds it.

**What it did not find, and a review did.** An order or an x402
authorization was charged in the period it was registered in and stayed
good after that period: with a lifetime longer than a period, several
periods' registrations could be taken together, past the "twice a budget
and no more" the owner is shown. The model missed it for two reasons a
generator should be checked for: its orders lived 600 seconds against a
period of 1,000 and were filled within the step that made them, and it has
no x402 at all. The policy now refuses a registration that ends after its
period; the model holds the rule for orders and aims at the period's last
second and the one after it, and `Trading.t.sol` holds it for x402
(`test_period_anAuthorizationEndsWithThePeriodItIsChargedIn`: three days'
authorizations, of which only the last can still be used). Breaking the new
rule five ways (no check for x402, none for orders, each bound off by one,
the period's end not noted) is found every time.

**That it bites.** Eighteen rules were broken in the source one at a time:
the period's first second, the reset of the native and of the token counter,
the period's end, a refund across periods, a reclaim at `validTo` and of a
filled order, the record left after a refund, an order's end and its
"not before", the same order twice, an order past the cap, the budget off
by one, an order with value attached, an order not charged, a window of a
single second; these sixteen are found at 256 runs. (Four of them were
rules of an order's refund, which the policy had then. The refund was
removed on 2026-11-24: a filled order could be made to read as untouched
at the venue after its end. The model now asks for the refund of orders
it registered, throughout a run, and holds that none is given.) Two are not, and cannot
be while the EntryPoint holds the window: accepting a period earlier than
one already seen (to have seen a later one, an operation must have been
accepted outside its window), and accepting a period index of fewer than
six bytes (it reads as an index 256 times larger or more, a window far
from now). Both checks stay in the policy; they do not rest on the clock.

**What it does not cover.** One venue, one pair, one token with a limit;
the decoder is the real one, the settlement is not. The mandate's own
window (`validAfter`, `validUntil`) is wide open here and is held by the
earlier tests. The Safe paths and x402 are not mixed in: x402 under a
period is held by examples in `Trading.t.sol`, not by the model.

## Contracts: the 1inch decoder

`contracts/test/OneInchLimitOrderDecoder.t.sol` holds
`OneInchLimitOrderDecoder` on its own, and
`contracts/test/OneInchTrading.t.sol` under the policy, with a Kernel
account and a mandate of two venues
([#80](https://github.com/postcryptum-research/agent-keys/issues/80)).

| Test | What must hold |
|---|---|
| `testFuzz_judge_acceptedMeansEveryRuleHolds` | for any eight words: an accepted order has the account as maker and receiver, a listed pair at its price, the one-fill flag and no other, an expiration; the sum and the window are as stated; the digest is the router's hash of the same words |
| `testFuzz_judge_theLowestPriceAgainstAReference` | the 512-bit price comparison against plain arithmetic, for amounts and prices below 2^128 |

**The router is a stand-in, and the router itself.** The stand-in is
written from the router's verified source. `OneInchRealRouterTest` runs
every test of `OneInchTradingTest` with the router's own code, read from a
chain when the test runs and placed at the router's address, and adds what
the router does with the orders the decoder refuses:

```sh
cd contracts
ONEINCH_RPC_URL=<an RPC of Ethereum, Base, Sepolia or Base Sepolia> \
  forge test --evm-version osaka --match-contract OneInchRealRouterTest
```

Run on 2026-11-26 with the code from Ethereum, Base, Sepolia and Base
Sepolia: 19 tests pass on each. Without the variable they are skipped, so
CI runs the stand-in only.

**That it bites.** Thirty-eight rules were broken in the source one at a
time, and each is found by a test:

- **who and where to:** the maker, the maker's word clean, the receiver,
  the receiver's word clean, both token words clean, the buy token's alone;
- **the traits:** filled whole; the other bits as a whole, and four let
  through one at a time (the extension flag, the call after the fill,
  several fills, the lowest series bit); an expiration, and its place in
  the word one bit off;
- **the amounts and the price:** something to sell, 128 bits, the pair and
  the price as a whole, the comparison the wrong way and off by one, a pair
  listed twice, a pair without a price;
- **the answer:** the most sold, the sold token, the order's end, the
  lifetime dropped and off by one, the digest's type hash, exactly eight
  words;
- **the constructor:** the domain's fields, its chain and its contract, and
  the router's hash of the probe order;
- **`untouched` and `checkConfig`:** the nonce's bit and the nonce's place,
  a lifetime, code at the buy token, a pair twice, at most sixteen pairs.

**What the first run of the breaks found in the tests.** Five went
unnoticed, and all five were faults of the tests:

- the constructor's test stopped at its first expected revert and passed:
  forge ends a test where an expected revert of a direct `new` stands, and
  the four cases after it never ran. Each deployment is now a call of its
  own (`build`). No other test in the repository has an expected revert
  right before a `new`;
- the price one unit below was tested with a price per 1,000,000 units,
  where one unit of the product is not one unit of the price;
- seventeen pairs were refused for a reason other than their number.

**The phone reads the venue's terms as the decoder does.**
`the_phone_reads_a_one_inch_config_as_the_decoder_does`, among the CLI's
local-chain tests, puts 400 configs from a seed, well-formed and damaged,
to the phone's reader (`one_inch_terms`) and to the decoder on a local
chain: 167 are accepted by both, 30 by the decoder only, 203 by
neither. For each one both accept, an order at a pair's lowest price passes
with the token, the amount and the lifetime the phone read, one unit under
it does not, and a pair the phone did not read is not traded. The phone
may refuse more than the decoder; it never reads other terms. One
difference is by design: the decoder's `checkConfig` asks for code at every
token, which a phone cannot see, so the CLI asks the chain before a mandate
is made (`one_inch_orders_under_a_mandate` holds that it does).

```sh
cd signer
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli one_inch -- --nocapture
```

**What it does not cover.** The stand-in models a plain order only. The
real router's code runs without its chain's state: no pause, no other
maker's bits. No order was sent to a chain.

## Contracts: a call a decoder judged, and the swap decoder

`contracts/test/VenueCallPairing.t.sol` holds what the policy keeps by
itself when a decoder judges a call instead of an order
([#80](https://github.com/postcryptum-research/agent-keys/issues/80)): the
decoder there judges nothing and answers what the test tells it to, so
every rule tested is the policy's. `contracts/test/SwapRouter02.t.sol`
holds `SwapRouter02Decoder` on its own, under the policy with a stand-in
router, and against Uniswap's router as deployed.

| Test | What must hold |
|---|---|
| `test_call_theJudgedCallIsMadeAndNoOther` | a venue's contract is refused by itself; registered and made in two legs it passes, as often as it is made; neither hash of the call is vouched for |
| `test_call_theLegAfterTheRegistrationMustBeThatCall` | another function, another value, another contract, one more byte, or a leg in between: refused |
| `test_call_aRegistrationWithoutItsCallIsRefused` | alone, as the last leg, as the only leg, or two registrations in a row: refused; each registration with its call passes |
| `test_call_onlyAtTheDecodersOwnVenue` | not the account, the policy, an allow-listed contract, an unpinned contract, another venue's contract or the decoder's own spender |
| `test_call_whatNoDecoderOpens`, `test_call_aDecoderDoesNotOpenAContractWithIdLimits` | Permit2, a token with a limit and a contract with id limits stay closed even to a decoder pinned with one of them as its venue |
| `test_call_chargedAsTheDecoderSays`, `test_call_aTokenWithAPayeeListIsNotCharged`, `test_call_itsNativeValueCounts` | what a call is charged: the decoder's price against the token's cap and budget, never a token with a payee list, and the call's native value like any leg's |
| `test_call_anAnswerWithAnEndIsAnOrder`, `test_call_anOrderEndingAtZeroIsNotACall` | an order stays an order: recorded, vouched for, taking no leg along; an order that ends at second zero is refused |
| `test_swap_*` (7) | a swap under a mandate of two venues: made and charged, no other call of the router, the decoder's refusals, the cap and the shared budget, a reverting swap still charged, the router off every allow-list, the decoder's code pinned |
| `test_decoder_*` (9) | the decoder alone: the call it builds, word for word; the recipient; the lowest price at its boundary; five clean words; a broken config; `checkConfig`; the constructor |

**Against Uniswap's router.** `SwapRouter02ForkTest` runs on a fork of Base
Sepolia with the router `0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4` and
the pool `0x46880b404CD35c165EDdefF7421019F8dD25F4Ad` (wrapped ether and
the test dollar, 0.3%): the agent's swap goes through the policy to the
router, and three tests show on the router's own code what the decoder's
rules keep out (an amount of zero, a recipient of `address(2)`, a
stranger's call against the account's allowance).

```sh
cd contracts
FORK_BASE_SEPOLIA_RPC_URL=<a Base Sepolia RPC> \
  forge test --evm-version osaka --match-contract SwapRouter02ForkTest
```

Run on 2026-11-26: 5 tests pass. Without the variable they are skipped, so
CI runs the stand-in only.

**That it bites.** Twenty-four parts of the policy's rule and twenty-five
of the decoder's were broken in the source one at a time, and each is found
by a test:

- **the pairing:** the check where validation ends; the leg after a
  registration judged as the registered call; the hash compared; the hash
  bound to the leg's target, with the place, the value and the calldata in
  it; the registration binding the decoder's venue (and not its spender);
  the expectation cleared by its call; the expectation set at all;
- **what stays closed:** Permit2, a token with a limit, a contract with id
  limits, each alone;
- **the charge:** the call's native value; a priced call held to the cap
  per operation, to the budget, charged at all, and never in a token with a
  payee list; a call not recorded as an order;
- **an order stays an order:** it sells something, it ends with its
  period, it is recorded; an answer with an end is an order and one
  without is a call;
- **the decoder:** five words; something sold; the pair and the price as a
  whole, the pair the wrong way round, the price of the wrong amounts; the
  amount charged, in full, in the sold token; a call and not an order; no
  native value; in the router call, the recipient (two ways), the order of
  the tokens, the fee tier, the amount sold, the least bought, the price
  limit and the selector; code at the router; the venue and the spender;
  `untouched`; `checkConfig`'s list and its code checks.

**What the first runs of the breaks found.** Six went unnoticed:

- three were faults of the tests. No test had a contract with id limits
  as a decoder's venue. The test decoder's spender was its venue, so a
  policy that bound the spender passed. Every swap in the decoder's tests
  used one fee tier, so a decoder that wrote that tier in passed;
- one was a fault of the rule as first written: the next leg was read
  without asking whether the batch had one, and a read past the end comes
  back as a call to nobody, which a registration could name. The rule no
  longer reads ahead: the leg after a registration is judged when the loop
  reaches it, and a registration that is the last leg is refused where
  validation ends;
- one was a condition that did nothing (a call exempted from a check it
  always passes); it was removed;
- one is no fault: with "a priced call needs a limited token" dropped, the
  cap per operation of a token without a limit is zero and refuses the
  same calls.

**The budget's proofs on the changed policy.** The eleven proofs of the
budget were run again on this policy on 2026-11-26, and each of the ten
breaks (`scripts/kontrol-break.py`) with them: all eleven pass and every
break fails its proof (the record is under "Beyond fuzzing" below). The
rule for a decoder's call has no proof of its own yet; the tests and the
breaks above hold it.

**The CLI swaps, and the phone reads the venue's terms as the decoder
does.** Two of the CLI's local-chain tests run the policy and the decoder
built from these sources, with the stand-in router:

- `swaps_under_a_mandate`: the owner installs a mandate with a venue of
  swaps and the router's allowance; `order swap` registers the swap and
  makes it in one operation; under the lowest price, the pair the other way,
  over the cap and past the budget go nowhere; a swap the pool would not
  honour is found when the calls are run before sending, and nothing is
  charged; the router's call without its registration is refused.
- `the_phone_reads_a_swap_config_as_the_decoder_does`: 400 configs from a
  seed, well-formed and damaged, are put to the phone's reader
  (`swap_terms`) and to the decoder: 187 are accepted by both, 30 by the
  decoder only, 183 by neither. For each one both accept, a swap at a
  pair's lowest price passes with the token and the amount the phone read,
  one unit under it does not, a pair the phone did not read is not swapped,
  and the hash the decoder answers with is the hash of the router call the
  CLI builds (`SwapOrder::call`), which is also the decoder's `swapCall`
  byte for byte.

```sh
cd signer
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli swap -- --nocapture
```

One swap's bytes are recorded on both sides: the decoder's test
(`test_decoder_theRecordedSwap`) and the core's (`a_swap_is_the_decoders`)
hold the config, the five words, the router call and its hash to the same
constants, which were computed with `cast`.

Eleven parts of the Rust side were broken one at a time (the recipient, the
price limit, the selector and the value in the call and its hash; the fee
tier's width; the config's shape; the reader's canonical-bytes rule, its
pair rules and which reader a swap venue gets; a swap's own rows; the
refusal's words), and each is found by the core's tests. The CLI's
comparison of its call with the decoder's `swapCall` before sending
was not broken on purpose: no test has a decoder that builds other bytes.

**What it does not cover.** The stand-in router models one function. The
fork run is of one pool on one test network at one block. No swap was sent
to a chain, and no chain has the decoder or this policy yet.

## Rust

Coverage-guided fuzzing with `cargo-fuzz` (libFuzzer, a nightly toolchain)
of the code that reads bytes it has no reason to trust. The targets are in
`mobile/owner-core/fuzz/`, a package of its own; the seeds they start from
are in `fuzz/seeds/`.

| Target | Input | What must hold |
|---|---|---|
| `sign_request` | the whole request a laptop serves to the phone, any bytes | no panic; a phone enrolled for nothing refuses; the rules of a review, below |
| `operation` | every field of an operation (nonce, gas, `initCode`, `paymasterAndData`, the laptop's label, the callData) inside a request whose hash is right, for an enrolled account | the rules of a review. The whole-request target cannot get here: a change to the operation breaks the hash and ends in the first refusal |
| `call_data` | the callData alone, the rest fixed | the same; all of the fuzzer's effort on the decoders of what the owner is shown |
| `enroll` | an enrollment request, and a response | an accepted request survives its own encoding and its label and pins are plain text; no panic on any response |
| `qr_uri` | the text of a scanned QR code | an accepted payload names a host in the local ranges, written out a second time by hand, carries no userinfo, and reads back as itself |
| `der` | bytes for the DER reader in front of key attestation | whatever is accepted is the one canonical encoding of what was read, by an encoder written a second time in the target; a number read is its own shortest form; children add up to their parent |
| `enclave_blob` | bytes as a Secure Enclave key file ([#78](https://github.com/postcryptum-research/agent-keys/issues/78)) | an accepted file is one element from the first byte to the last with a key on the curve; the same bytes with one more are refused |

**The rules of a review** (`fuzz_targets/common.rs`), for any bytes:

- every title, label, value, warning and reason of a refusal is printable ASCII or one of the
  four marks the review writes itself: nothing a laptop sends can put a line
  break, a control or a direction mark, or a letter of another script on the
  owner's screen;
- a refusal has no digest to sign;
- a review that can be signed is of a request that parses, its digest is the
  hash this code computed from the operation, the account is one the phone
  is enrolled for, the operation has no `initCode`, its nonce key is the
  root's, and its paymaster, if any, is one the build knows to charge
  nothing;
- the screen's text has one line per row and no more.

```sh
cd mobile/owner-core
cargo +nightly fuzz list
cargo +nightly fuzz run operation fuzz/corpus/operation fuzz/seeds/operation -- -max_total_time=1200 -max_len=8192
```

**The seeds.** `operation`, `call_data` and `sign_request` start from the 19
distinct root operations the CLI's local-chain tests send (the tests of
the agent's lifecycle, the schedule, recovery, the hand-over of root, the
phone as owner, x402 and the Safe path), taken from the traces the CI job of
`scripts/erc7562/README.md` leaves; `der` from the two public root
certificates in the tree; `enclave_blob` from a file built by hand around the
curve's base point. The corpus a run grows is not kept in the repository.

**Results (2026-11-21).** Twenty minutes of each target on one core, from
the seeds: no panic and no broken rule.

| Target | Runs |
|---|---|
| `enclave_blob` | 156.3 million |
| `qr_uri` | 92.3 million |
| `enroll` | 21.1 million |
| `sign_request` | 10.8 million |
| `call_data` | 1.1 million |
| `operation` | 1.8 million |
| `der` | 0.55 million |

The first minutes did stop twice, in `sign_request` and `call_data`, and both
times the rule was wrong and not the code: it took the four marks the review
writes itself (`—`, `·`, `→`, `‖`) for a laptop's text.

**That they bite.** Seven rules were broken in the source, one at a time; each
is found by its target from the seeds within two minutes:

| Broken rule | Found by | With |
|---|---|---|
| any bytes pass as a laptop's label | `operation` | "a row value carries a character that is not plain text" |
| an operation with `initCode` is reviewed | `operation` | "a review to sign of an operation with initCode" |
| any nonce key is taken | `operation` | "…under a nonce key that is not the root's" |
| any paymaster is taken | `operation` | "…with a paymaster the build does not know" |
| a DER length that is not minimal is read | `der` | "accepted, but not the canonical encoding" |
| a key file may have bytes after its end | `enclave_blob` | "accepted with a byte after the end" |
| any IPv4 host counts as local | `qr_uri` | "…host is outside the local ranges" |

**In CI:** the `fuzz` job runs every target for a minute from the seeds. That
shows the targets build and that nothing near a seed breaks a rule; it is not
the long run.

**Found in CI (2026-11-24).** The `operation` target panicked on a sponsored
operation whose two paymaster gas limits were near 2^128: the review added
them as u128, which panics in a build with overflow checks and wraps in one
without, showing a small maximum cost. The cost line now sums the gas
limits in 256 bits and adds `preVerificationGas` and multiplies by the fee
cap checked: the cost shown is exact, and one that does not fit 256 bits is
refused. `review::tests::the_largest_gas_numbers_neither_panic_nor_wrap`
holds the sum and the product each on its own, and the input is kept as the
seed `fuzz/seeds/operation/paymaster-gas-overflow`.

**Limits.**

- Not yet a target: `attestation.rs` and `x402.rs` in `agent-signer`, which
  is a binary and offers no library to link (the `der` target takes its file
  by path, which works for a file with no dependencies); and the response a
  laptop reads from the phone beyond enrollment.
- No coverage-guided target for the review against the chain; it would
  need an EVM beside the fuzzer. What the review says a mandate installs is
  held to what `AgentPolicy` does install by a seeded test on a local
  chain, in the next section.
- The whole-request target cannot make a second valid request of its own:
  the hash stops it. `operation` is the answer to that, and it frames the
  fields itself, so what it explores is bounded by that framing.
- Minutes of fuzzing, not days. No sanitizer finding is expected in safe
  Rust; what is looked for is a panic or a broken rule.

## The phone's review against the policy's install

What the owner is shown of a mandate and what `AgentPolicy` installs from
the same bytes are two readings in two languages. One test holds them
together: `the_phone_reads_a_mandate_as_the_policy_installs_it`, among the
CLI's local-chain tests (`signer/crates/agent-signer/tests/anvil_cli.rs`).

```sh
cd signer
cargo test -p agent-signer --features insecure-software-keys --test anvil_cli the_phone_reads_a_mandate -- --nocapture
MANDATE_DIFFERENTIAL_CASES=20000 cargo test ...    # more mandates than the 400 of a normal run
```

**Which policy it reads against.** The `AgentPolicy` of the local chain is
the one built from this repository's sources, held as bytecode in
`tests/fixtures/chain-code.json`. `scripts/test-fixtures.py` compares the
fixtures with the build and CI fails a pull request where they differ, so a
change to `onInstall` cannot leave this test on an earlier policy;
`scripts/test-fixtures.py --write` brings them up. Until 2026-11-25 the
fixture was the policy deployed to Base Sepolia on 2026-11-21, and the test
did not see the changes made to `onInstall` after it (issue #170). [V the
first run against master's policy, 2026-11-25: the test passes.] It says
nothing of an instance on a chain: comparing a deployed instance's
bytecode with the build's is a step of a redeploy, not of this test.

Mandates come from a seed: mostly well-formed and near what an install
must refuse, a quarter of them damaged (a bit flipped, the end cut off, a
word added, a word's top bit set). Each one goes two ways. The phone
reviews a root operation that installs it as a permission, built the way
`permission add` builds it, and the test also takes the terms the review
read (`owner_core::review::mandate_terms`, the function the review itself
calls). On a local chain with the deployed policy's code, the test
impersonates a Kernel account and calls the policy's `onInstall` with the
same bytes; Kernel's `installValidations` is not run here.

**The rules.**

- A mandate the review lets the owner sign is one the policy installs.
- For such a mandate the policy's views give back what the review read,
  and within the probes nothing more. The probes are the generator's pools
  (11 targets by 12 functions, 3 tokens, 3 payees, 3 ERC-6909 contracts
  by 4 ids) and every target, function, token, payee and id the review
  read in that case. Compared: the
  window and the two native limits (`configs`); every probed call allowed
  exactly when the review lists it (`isAllowed`); for each token whether
  it is limited, its two limits, its x402 domain and whether it has a
  payee list (`tokenLimit`); every probed payee reachable exactly when
  the review says so (`payeeAllowed`); the budget period (`period`); for
  each probed id whether it is limited and its two limits (`tokenLimit`
  under `idAsset`). The generator reaches all four forms of the install
  data: a normal run of 400 has 17 mandates shown and installed in the
  ten-word form and 12 in the eleven-word one [V the run of 2026-11-25];
  a venue it does not reach, since the local chain has none. The policy
  reads the eleven-word form's last word and its array by hand, so one
  such mandate in six is damaged there: the word replaced by another
  array's offset, or the count of limits one more or one less.
- The review refuses a mandate the policy installs for one reason only:
  bytes the policy decodes although they are not the one encoding of
  their values. Any other reason fails the test, so a review that refuses
  too much is caught as well.
- The generator reaches all three outcomes, or the test fails: at least a
  seventh shown and installed, a fifth refused by both, one in a hundred
  installed and not shown. The first floor guards the generator and not
  the rule: every mandate is compared whatever the share. Runs give 18.8
  to 20.0 percent shown and installed (75 of 400, 3,990 of 20,000), so a
  floor of a sixth (16.7 percent) left about two points and one of a
  seventh (14.3) leaves room for a seed's luck while a generator that stops producing
  installable mandates still fails.

**That it bites.** Sixteen rules were broken in the review's reader one at
a time: fourteen refusals (the account or its EntryPoint as a target; the
policy outside x402; a limit past 128 bits; a time past 48; a window never
open; no call; a token twice; Permit2; a function outside the four on a
limited token; a payee twice; a payee list for a token without a limit;
targets and functions of different lengths; the payee form without a
list; an encoding that is not canonical) and two misreadings (the budget
read as the value cap; a payee list dropped). Every one fails the test at
400 mandates. Dropping the canonical-encoding rule is seen only by the
count of mandates installed and not shown falling to none: over these
mandates the policy read such bytes as the review would have. Two were
missed by the first form of the generator (the lengths, the payee form
without a list), which is why it now makes both. A seventeenth break
goes the other way, a review that refuses too much (the policy's
`x402Reclaim` entry refused): the first form of the test only counted such
mandates and passed; it now holds their reason to the one known, and
fails.

**What it found.** The first run had 152 of 400 mandates that the review
showed and the policy refused to install: a limit past 128 bits or a time
past 48, no call at all, a window that is never open, a limit for the zero
address or two for one token, and a call to the account, to its EntryPoint
or to the policy outside its two x402 entries. No rights came of any of
them, since such an install fails on chain; but the owner would have
confirmed a screen that did not come true. The review now refuses each
(`a_mandate_the_policy_would_not_install_is_not_shown` in
`mobile/owner-core/src/review.rs` has one case per rule). No mandate was
found that the two sides read differently.

**What it does not cover.**

- It is a seeded test of a fixed number of mandates, not a campaign with
  coverage feedback.
- The views say what the policy stored. That the policy then enforces what
  it stored is the subject of the contract fuzzing above.
- An entry outside the probes that the policy stored and the review did
  not read would not be seen; that needs a trace of the policy's storage.
  A venue's configuration is not part of these mandates.
- One policy entry per permission. A permission with the same policy
  module twice does not install (the second `onInstall` reverts); the
  review refuses it, by a unit test, and the generator does not build it.
  That revert was not run on a chain.
- The review's wording of a term on the screen (units, dates, names) is
  not compared, only the values it read.

## Third-party fuzzing tools

Agentic tools that write and run tests on their own are a source of ideas
for properties, not a part of this repository's build. One is never run on
a developer's machine or on any machine that holds a key.

## Beyond fuzzing: a proof of the budget

`contracts/test/BudgetProof.t.sol` states the budget rule with symbolic
amounts, so a proof holds it for every value, not for the values a
generator tried. Kontrol (KEVM, by Runtime Verification) proves it. Halmos
cannot run this codebase: its symbolic EVM has no MCOPY, which the
bytecode needs.

| Proof | What holds, for any amounts |
|---|---|
| `check_tokenTransfer_oneOp` | a token `transfer` in one operation is accepted only within the token's cap per operation; the token's counter then equals the amount and stays within the budget; a refused one books nothing |
| `check_nativeTransfer_oneOp` | the same for a plain native transfer and the native cap and budget |
| `check_tokenTransfer_twoOps` | two token transfers in a row add up without wrapping and without passing the budget |
| `check_nativeTransfer_twoOps` | the same for two native transfers |
| `check_tokenBatch_twoLegs` | two token transfers in one account batch: the cap per operation holds for their sum, so splitting does not escape it |
| `check_nativeBatch_twoLegs` | the same for two native transfers in one batch |
| `check_safe_innerValue` | the value a nonce-guarded Safe transaction sends from the Safe is capped and booked as the account's |
| `check_safe_multiSend_twoLegs` | a Safe delegatecalling multiSend with two legs: their sum is capped and booked |
| `check_faithful_single` | value-faithfulness: an accepted token transfer, executed as Kernel v3.3 executes it, delivers exactly what was booked |
| `check_faithful_batch` | the same for a batch of a token transfer and a native transfer |
| `check_allowance_mustBeWithdrawn` | no standing allowances: an `approve` of a limited token is accepted alone only if it grants nothing; with `approve(spender, 0)` later in the same batch it is accepted within the cap per operation and booked as a transfer is |

[V] (`contracts/test/BudgetProof.t.sol`, `contracts/lib/kernel/src/Kernel.sol:330-332`, `contracts/lib/account-abstraction/contracts/core/EntryPoint.sol:571-573`):
- Kernel's `execute` is `ExecLib.execute(mode, data)` behind its access check. The harness's account runs exactly that on the `callData` the policy judged, so the faithfulness proofs execute what was validated.
- A refusal is modelled as the EntryPoint handles it: `handleOps` reverts with `FailedOp` ("AA24 signature error"). That revert also undoes what the policy booked for the earlier legs of a refused batch. The policy books leg by leg and returns its refusal without reverting, so this undo is the EntryPoint's.

**Each rule broken alone** (`scripts/kontrol-break.py`): the workflow breaks one rule at a time in a copy of the policy and requires its proof to fail with a counterexample.

| Break | Proof that must fail |
|---|---|
| `token-cap`: the token's cap per operation off by one | `check_tokenTransfer_oneOp` |
| `token-budget`: the token budget off by one | `check_tokenTransfer_twoOps` |
| `native-cap`: the native cap per operation off by one | `check_nativeTransfer_oneOp` |
| `native-budget`: the native budget off by one | `check_nativeTransfer_twoOps` |
| `token-sum-per-operation`: each leg counted alone | `check_tokenBatch_twoLegs` |
| `batch-legs-summed`: a batch's value is its last leg's | `check_nativeBatch_twoLegs` |
| `safe-inner-value`: a Safe transaction's inner value not counted | `check_safe_innerValue` |
| `multisend-legs-summed`: a multiSend's value is its last leg's | `check_safe_multiSend_twoLegs` |
| `call-value-counted`: a call's value not counted | `check_faithful_batch` |
| `allowance-left-open`: an allowance left open at the end of the operation accepted | `check_allowance_mustBeWithdrawn` |

What breaking them one at a time found: with the budgets set at first (a token cap of 100 and a token budget of 250, a native cap of 1 ether and a native budget of 5 ether), two operations could never reach the budget. A broken budget check could not show. The run below caught the token budget's break only because the cap was broken with it. The budgets are now 150 and 1.5 ether, reachable within two operations.

**The run of 2026-11-24** ([issue #124](https://github.com/postcryptum-research/agent-keys/issues/124#issuecomment-7131857893)):
- Setup: image `runtimeverificationinc/kontrol:ubuntu-jammy-1.0.255`, a copy of `contracts/` with this one test, the container limited to 12 CPUs and 11 GB.
- `kontrol build`: 3 min 24 s.
- `kontrol prove` with three workers: 6 min 41 s of wall time, about 4 GB of memory at the peak seen. The three proofs took 2 min 52 s, 2 min 42 s and 4 min 37 s.
- With three rules broken at once (the token budget off by one, the token's cap not checked, the native cap off by one), every proof fails, with the counterexamples `amount = 101` and `value = 1000000000000000001`, in 10 min 56 s.

**In CI:** `.github/workflows/kontrol.yml` runs the proofs, and each break in a job of its own, by hand, once a week, and on a pull request that changes `AgentPolicy.sol`, the harness, the breaks, `foundry.toml` or the workflow. A proof reported vacuous fails the run. The image is pinned by digest. Kontrol sends anonymous usage data unless `KPROFILE_TELEMETRY_DISABLED=true` is set, as the workflow does. The command to run it by hand is in the harness's header. Its first run, on GitHub's `ubuntu-latest` runner on 2026-11-24 ([#135](https://github.com/postcryptum-research/agent-keys/pull/135)), passed all three proofs: pulling the image took 45 s, `kontrol build` 2 min 9 s, and `kontrol prove` with three workers 6 min 49 s, about 10 min 30 s for the whole job.

**The run of the eleven proofs on 2026-11-25**, on the policy of master `60e773be7c7f071a4e5a69f84e7af3697092a4ef` (with #191, merged into this harness; [the run](https://github.com/postcryptum-research/agent-keys/actions/runs/45661617595), GitHub's `ubuntu-latest`, four vCPUs):
- **Proofs:** all eleven passed, none vacuous; the `prove` job took 34 min with three workers.
- **Each proof's time:**

  | Proof | Time |
  |---|---|
  | `check_faithful_single` | 3 min 43 s |
  | `check_nativeTransfer_oneOp` | 3 min 56 s |
  | `check_tokenTransfer_oneOp` | 4 min 31 s |
  | `check_safe_innerValue` | 5 min 2 s |
  | `check_faithful_batch` | 5 min 52 s |
  | `check_nativeBatch_twoLegs` | 5 min 54 s |
  | `check_tokenBatch_twoLegs` | 6 min 29 s |
  | `check_safe_multiSend_twoLegs` | 9 min 1 s |
  | `check_tokenTransfer_twoOps` | 10 min 5 s |
  | `check_nativeTransfer_twoOps` | 10 min 40 s |
  | `check_allowance_mustBeWithdrawn` | 14 min 14 s |

- **Breaks:** each of the ten made its proof fail, in a job of its own of 9 to 16 min, beside the proofs.
- **The policy deployed since 2026-11-26** adds the batch rule of #206. Kontrol ran on it in that pull request's checks ([run 45702180453](https://github.com/postcryptum-research/agent-keys/actions/runs/45702180453)): the eleven proofs passed and each of the ten breaks failed its proof.
- **The policy that admits a decoder's call** (#80, the section "a call a decoder judged" above): run on 2026-11-26 on a workstation of 24 cores with the same image. The eleven proofs passed, none vacuous, in 17 min 41 s with the build and eight workers; each of the ten breaks made its proof fail. The source proved differs from the committed one in sixteen comment lines, and comments are not in the bytecode (`bytecode_hash = "none"`).

**What it does not prove** ([#130](https://github.com/postcryptum-research/agent-keys/issues/130)):
- **A decoder's call.** That a call a venue's decoder judged is admitted only as the leg after its registration, only at that decoder's venue, with its value counted: tests and breaks hold it, no proof.
- **Any number of legs.** The batch, Safe and multiSend proofs fix the number of legs at two. A loop over a length the caller chooses stays with the fuzzing above.
- **Any encoding.** The shapes are well-formed encodings with symbolic amounts. Symbolic offsets, short or trailing bytes stay with the parsers' tests and the fuzzing.
- **Faithfulness inside a Safe.** The faithfulness proofs execute the account's single and batch paths. A Safe executing its transaction is not modelled; the differential tests are the evidence there, and that evidence missed #190: a Safe transaction with a nonzero `safeTxGas` does not revert when its inner call fails, so a call the policy judged could go unmade, a withdrawal of an allowance among them. The fuzzing and this harness built Safe transactions with `safeTxGas` and `baseGas` at 0 and varied only `gasPrice`. The policy refuses both words other than 0 since #191. Since #193 the differential in `PolicyFuzz.t.sol` draws each of the three words other than 0 now and then (1, or any word) and requires the refusal, not only that the source and the recorded instance agree. This harness still builds them at 0, and neither runs a Safe's execution. A unit test does: `test_safe_aFailingInnerCallFailsTheOperation` (`AgentPermission.t.sol`) sends #190's operation with all three words at 0 through the EntryPoint, Kernel's batch, a Safe and the token. Validation accepts it, the withdrawal reverts at execution, the Safe reverts with it, and the operation's execution fails: no allowance stands and the Safe's nonce does not move. With the rule on `safeTxGas` removed and the withdrawal given a `safeTxGas` of 1, that test fails [V 2026-11-25]. That is one shape of Safe transaction run, not a proof over all of them.
