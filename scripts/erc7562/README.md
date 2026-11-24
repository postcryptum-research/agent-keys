# ERC-7562 check of the validation path (issue #83)

What a bundler that enforces the ERC-7562 validation rules makes of an agent
operation, and a way to ask again after a change. Everything here is from runs
on Base Sepolia and on a local fork of it on 2026-11-20 (UTC); traces 7 and 8
are from 2026-11-21, after the policy's storage was changed (#87); traces 9
and 10 are from a run of the CI job below on 2026-11-24.

## The result in two tables

**1. The keyless public bundlers on Base Sepolia enforce none of the rules.**
`RuleBreaker.sol` is a policy for a Kernel permission that approves everything
and, during validation, does one thing chosen at deployment. Every operation
below was accepted, sent by the bundler's own address and included.

| Test policy | Bundler | Account | Included in |
|---|---|---|---|
| 1: reads `TIMESTAMP` | pimlico | `0x93673EC24A7666aa60F5a5e865FA4b75A838eD1d` | `0x5a2020f5a0d01e5f96d4d2d41f640b9b0c568989551c472b1899f3d58873e0f0` |
| 1: reads `TIMESTAMP` | candide | `0xf9E6356F21ac3d832E6d1F1e222C5758c3381541` | `0x7d5a3c577aa57b1b9906badf8ebea2e8c39a27e25af40440893fba47adc573bd` |
| 1: reads `TIMESTAMP` | etherspot | `0x03E71584daE2e7B1142D1a22f4d0A738bBF7b6e5` | `0x74b78336238520162342d795ed42af008eeca16fe022fae875772b35a124588e` |
| 2: persistent write at slot 0 | pimlico | `0xD708d6e8fC9C10410c05520bf88732B8992Be762` | `0x1db3ea9b378793c2285266ad72483a9b106989f1f120310d4471be834e90cbc2` |
| 2: persistent write at slot 0 | candide | `0xBe5279D8340a938d125221a42EF4644Ad6EFc701` | `0x57635cfc12dd856548a349dc22649e8b5d0e859cf2f68968e5789f7e5fe54ec5` |
| 2: persistent write at slot 0 | etherspot | `0xD80b0A26C48d0d3629D6C21DBACDcB642ED58C66` | `0xffacd7fdc89063cca410012c6e2effe618263680e7d69f431375c7d4d0852d52` |
| 3: transient write at slot 0 | pimlico | `0x066F42A1d2e8b93972cC181AB6636c4c808018aE` | `0x1fc0a801d4b7d1f5f6b787dc475cd594e7ea1b4ec1843de287c0147e87c7c962` |
| 3: transient write at slot 0 | candide | `0x23Ec5671CE0B84E1575131950557289d0C0D621F` | `0x77158cb0f56a4e24dcc54e4a3527c21619dc9d7d1488fc2afae6fb4b77f06515` |
| 3: transient write at slot 0 | etherspot | `0xab85Bf3B0E99f41d671E2aaC27D8e15b3b553A54` | `0x95b8c53f4a14dc9f289050a5004cadd8729588b75ab67574bb73d8cad7635805` |
| 4: transient write at `keccak(sender ‖ 1)` | pimlico | `0xF625db80b529D2dfa4DeB9c99Aae0344d61774A5` | `0x984f20ad4f1d3891979fdca34d11521c9e0e9234ef11940600174115bcf8ced7` |
| 4: transient write at `keccak(sender ‖ 1)` | candide | `0xf3C892A3f6be958AD9e6d3dE72ff4254dd2d7721` | `0x119d15e3a08b00573609eb8b76bcbb2d7ff83ceccfe3a656d03836ae0f5e6f62` |
| 4: transient write at `keccak(sender ‖ 1)` | etherspot | `0xcD8B7eD8208Af38f7aC941126b52AD1C7D250300` | `0x2d1165eaaf1524d802782c0889ea86e08b336c063ffc07a784d0439bd4104960` |

The slot-0 counter of test policy 2 reads 6 on chain: one write per validated
operation. So a public bundler including an operation says nothing about the
rules.

**2. The rule checker of a rule-enforcing bundler** (Pimlico's Alto 0.0.21,
`TracerResultParserV07`, a port of the reference implementation), fed the
traces in `traces/`:

| Trace | Verdict |
|---|---|
| 1 `AgentPolicy`, an operation without a token call | refused: forbidden access to the policy's slot `0x854e0b187d93efd5af455f72df5ca9f3da2e32b4209332a93f91da866b2070d8` = `configs[account][id]`, the word with `spent` |
| 2 `AgentPolicy`, a token operation | refused: forbidden access to slot `0xf4615f3a519cfc240186a2f064738f1fa15e222574a8d19a7af80be8201fcd1b` = `_mandates[account][id][epoch].tokens[token]`, the word with the token's `spent` |
| 3 test policy: reads `TIMESTAMP` | refused: banned opcode |
| 4 test policy: persistent write at slot 0 | refused: forbidden access to slot 0 |
| 5 test policy: transient write at slot 0 | refused: forbidden access to slot 0 |
| 6 test policy: transient write at `keccak(sender ‖ 1)` | storage passes; stops at the P-256 precompile, see below |
| 7 `AgentPolicy` as deployed on 2026-11-21 (`0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2`), an operation without a token call | storage passes: 6 slots of the policy, all the sender's; stops at the P-256 precompile |
| 8 the same instance, an `x402Authorize` under a token limit | storage passes: 11 slots of the policy, all the sender's; stops at the P-256 precompile |
| 9 the CLI's first operation of an account, sponsored: a factory and a paymaster | refused: the factory unstaked reads its own slot `0xc971c53e8faacbe9398308973b81e1992106aec7dde936e40d53f88839fe60a4`; passes with the factory staked, the paymaster not |
| 10 the same account's next operation, sponsored: a paymaster | stops at the P-256 precompile; passes with it allowed, the paymaster unstaked |

The exact messages are in `expected.json`, each trace twice: the checker as it
is, and with the P-256 precompile allowed (below); trace 9 a third time, with
that and its factory staked. The checker's message says "read from" also
where the slot is written; the branch it comes from is the one for written
slots.

- **Traces 9 and 10** come from CI and not from the bundler:
  `bundled-0007-0.json` and `bundled-0008-0.json` of the `erc7562-traces`
  artifact of the `cli-and-erc7562` job (below), run 45485209513 on master
  at commit `b9e9b3e96403f987629a948e9c73f9be968c0c5e`, copied unchanged. They
  are the `sponsored_and_bundled` test's account, deployed and run on the
  paymaster's deposit, and carry the `handleOps` call they are of, so the
  factory and the paymaster are read from it. The factory is the
  FactoryStaker `0xd703aaE79538628d27099B8c4f621bE4CCd142d5`, staked at the
  EntryPoint on chain (`docs/DEPLOYMENTS.md`, #102): for trace 9 the verdict
  that counts is the third. The paymaster is the test chain's
  `WhitelistPaymaster`, `0x5FbDB2315678afecb367f032d93F642f64180aa3`.
- **Test policy 5** (a persistent write at `keccak(sender ‖ 1)`) has no trace
  here: one would take a run of the bundler or of its tracer on a fork, and
  none was made for it.
- **Traces 7 and 8** are the policy after #87, whose every slot is
  `keccak(account ‖ x) + n`: operations of an account whose permission was
  rotated onto the instance on chain, traced on a fork at block 61724385
  where the policy's code was first compared with the code on chain. They
  are the answer to traces 1 and 2, which stay as the record of the layout
  before.
- **Traces 5 and 6:** the checker treats transient storage as storage, and
  accepts the form `keccak(sender ‖ x)`. The per-operation sum of #76 has that
  form.
- **Traces 1 and 2:** a slot counts as the sender's only as
  `keccak(sender ‖ x) + n`, `n < 128`. In
  `mapping(address account => mapping(bytes32 id => …))` the last hash is
  `keccak(id ‖ keccak(account ‖ p))`; the rule that would follow such nesting
  is disabled in the checker's source. Validation writes these slots, and a
  write to a slot that is not the sender's is refused, staked or not.
- **Trace 6 and the precompile:** this build of the checker calls the P-256
  precompile at `0x0000000000000000000000000000000000000100` an un-deployed
  contract. ERC-7562 allows the RIP-7212 precompile on networks that have
  it, so that is the bundler's configuration for the network and not the
  policy. `check-traces.mjs`
  therefore gives a second verdict with that one address left out of the
  trace's list of code sizes, which is what a bundler set up for such a
  network sees: trace 6 then passes, traces 1 to 5 are refused as before.
  **The mark of a fixed layout:** a trace of `AgentPolicy` gets the two
  verdicts of trace 6.

## Asking again

```sh
cd scripts/erc7562
npm install          # the checker comes with the bundler's package, pinned in package.json
npm run check        # the ten recorded traces against expected.json, then test.mjs; exit 1 on a difference
node check-traces.mjs my-trace.json     # the verdicts for a trace of your own
```

What `check-traces.mjs` takes, and how (`checker.mjs`, shared with
`check-run.mjs`):

- **A trace** as the bundler logs it, or a file of `check-run.mjs`'s, which
  also carries the `handleOps` call the trace is of and its EntryPoint.
- **Case.** Every hex string of the trace, keys and values (addresses,
  slots, selectors, keccak inputs), the EntryPoint and the operation's
  addresses are put in lower case before the checker sees them. The checker
  compares them as text: an address in checksum case would slip past the
  rules that name the EntryPoint (OP-052, OP-054) or the account (OP-041)
  (#152). A trace that names one address in two cases is refused.
- **The account, the factory and the paymaster** come from the operation
  when the file has it: the first 20 bytes of `initCode` and of
  `paymasterAndData`. A trace without it names them by the EntryPoint's
  calls: the account is the one called with `validateUserOp`, the paymaster
  the one called with `validatePaymasterUserOp`, the factory the one the
  SenderCreator calls. A first operation is so judged against its factory,
  and gets the third verdict, with the factory staked (#153).
- **A file that is not a trace** (empty, not JSON, without
  `callsFromEntryPoint`, `calls` and `keccak`, or with a level that lacks
  `opcodes`, `access`, `contractSize` or `extCodeAccessInfo`) gets one line
  on stderr and exit 1 (#154).

`test.mjs` holds the checker to that: every recorded trace with its
addresses in checksum case gives the recorded verdicts; a call into the
EntryPoint put into trace 7 is refused in either case; trace 9 without its
operation is read as with it; a file that is not a trace gets one line and
exit 1.

A trace of your own, with nothing spent:

1. A local fork: `anvil --fork-url <Base Sepolia RPC> --hardfork osaka --port 8545`.
2. The bundler in safe mode on it, with two of anvil's test keys:
   `npx alto -e 0x0000000071727De22E5E9d8BAf0edAc6f37da032 -r http://127.0.0.1:8545 -x <key> -u <key> --safe-mode true --port 4337 --log-level info > alto.log`
3. One operation through it: `agent-signer op send --bundler http://127.0.0.1:4337 …`
   with an `.env` whose `RPC_URL` is the fork. Alto 0.0.21 answers with an
   HTTP 500 (it cannot decode `DelegateAndRevert`, `0x99410554`, after
   tracing): the trace is in its log all the same.
4. The trace is the JSON after `tracerResult: ` in `alto.log`; save it to a
   file and give it to `check-traces.mjs`.

For a policy that is not deployed yet: deploy it on the fork with anvil's test
key, name it as `agentPolicy` in a copy of the deployments file, and make an
account with software keys (a CLI built with `--features insecure-software-keys`).

## In CI: every operation of the CLI's local-chain tests

The `cli-and-erc7562` job of `.github/workflows/ci.yml` asks the same checker about
every operation the CLI's integration tests get included on a local chain
(`signer/crates/agent-signer/tests/anvil_cli.rs`: an account's first
operation, agent operations plain, with tokens, in a batch, through a Safe,
x402, sponsored by the paymaster, and the owner's and the recovery key's own).
No bundler runs:

1. `write-tracer.mjs` writes the bundler's validation tracer to a file.
2. The tests run with `ERC7562_TRACER` and `ERC7562_TRACE_DIR` set. Each test
   then, at its end, takes every `handleOps` that was included and runs it
   again on the state before its block under that tracer
   (`debug_traceCall` with a JavaScript tracer: anvil 1.8.5 runs it, CI uses 1.10.0), through two forwarding contracts,
   since the tracer looks for the EntryPoint three calls deep.
3. `check-run.mjs` gives each trace to the checker, with the operation's
   factory and paymaster read from the operation itself, and prints three
   verdicts: the checker as it is; with the P-256 precompile allowed; and with
   that and the factory staked (the paymaster never: ours must not need a stake).

**The gate** (`--gate`), with the precompile allowed: an operation without a
factory must pass with nobody staked; a first operation must pass with its
factory staked and, unstaked, be refused for that one known reason and no
other. An operation that could not be checked, or a replay that does not
succeed, fails the job; so does a change that makes validation touch a slot
that is not the account's or use a banned opcode.

**What the first run showed** (2026-11-21, 54 operations):

| Operations | Verdict with the precompile allowed |
|---|---|
| 27 by the root key, 1 by the recovery key, 14 by the agent | pass |
| 1 by the agent with the paymaster paying | passes, the paymaster unstaked |
| 11 first operations of an account (with `initCode`) | **refused: "unstaked factory accessed … slot …"**; pass with the factory staked |

The last row is a finding and not a property of the test chain: creating the
account installs the validator and the agent's permission, which writes their
slots for the account, and ERC-7562 allows that during a first operation only
to a staked factory. The CLI names Kernel's factory itself in `initCode`, and
that contract holds no stake at the EntryPoint; ZeroDev's staked
meta-factory, which deploys through it, is what a rule-enforcing bundler
expects there ([#102](https://github.com/postcryptum-research/agent-keys/issues/102)). Until the CLI goes through it, an account's first
operation would be refused by such a bundler, and the gate holds these
operations to exactly that refusal.

**Limits of this check:** the local chain runs the runtime code of the
deployed contracts (`tests/fixtures/chain-code.json`), so a change to a
contract's source is seen here when that fixture is renewed; the stake of a
factory or paymaster is assumed, not read from a chain; the replay is on the
state before the operation's block, which a test that changes the chain
without a transaction would make another state (the replay must succeed, so
this shows as a failure and not as a wrong verdict); one checker, as above.

To run it by hand (the checker is another project's code: on a machine where
that is acceptable), with an empty directory for the traces:

```sh
cd scripts/erc7562 && npm ci --ignore-scripts
node write-tracer.mjs /tmp/tracer.js
(cd ../../signer && ERC7562_TRACER=/tmp/tracer.js ERC7562_TRACE_DIR=/tmp/traces \
   cargo test -p agent-signer --features insecure-software-keys --test anvil_cli)
node check-run.mjs /tmp/traces --gate
```

## What was used

- The throwaway copy of the policy in traces 1 and 2:
  `0xfae8704B823A56dE211268B40aE24af69693f7c2`, the same runtime code as the
  instance of #71, under the throwaway account
  `0x5c94B5bd52F9DcD28e2d65726F236c64fEa42073`.
- The test policies in traces 3 to 6 are the four of the table above, under the
  accounts of the Pimlico column.

## Limits

One rule-enforcing implementation, and its checker run by hand on its own
traces. Rundler, Voltaire and Skandha in their strict modes were not run, nor a
hosted bundler that enforces the rules.
