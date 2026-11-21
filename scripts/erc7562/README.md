# ERC-7562 check of the validation path (issue #83)

What a bundler that enforces the ERC-7562 validation rules makes of an agent
operation, and a way to ask again after a change. Everything here is from runs
on Base Sepolia and on a local fork of it on 2026-11-20 (UTC); traces 7 and 8
are from 2026-11-21, after the policy's storage was changed (#87).

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
| 1 `AgentPolicy`, an operation without a token call | refused: forbidden access to the policy's slot `0x854e…70d8` = `configs[account][id]`, the word with `spent` |
| 2 `AgentPolicy`, a token operation | refused: forbidden access to slot `0xf461…cd1b` = `_mandates[account][id][epoch].tokens[token]`, the word with the token's `spent` |
| 3 test policy: reads `TIMESTAMP` | refused: banned opcode |
| 4 test policy: persistent write at slot 0 | refused: forbidden access to slot 0 |
| 5 test policy: transient write at slot 0 | refused: forbidden access to slot 0 |
| 6 test policy: transient write at `keccak(sender ‖ 1)` | storage passes; stops at the P-256 precompile, see below |
| 7 `AgentPolicy` as deployed on 2026-11-21 (`0x12b7…e0E2`), an operation without a token call | storage passes: 6 slots of the policy, all the sender's; stops at the P-256 precompile |
| 8 the same instance, an `x402Authorize` under a token limit | storage passes: 11 slots of the policy, all the sender's; stops at the P-256 precompile |

The exact messages are in `expected.json`, each trace twice: the checker as it
is, and with the P-256 precompile allowed (below). The checker's message says
"read from" also where the slot is written; the branch it comes from is the
one for written slots.

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
  precompile at `0x…0100` an un-deployed contract. ERC-7562 allows the
  RIP-7212 precompile on networks that have it, so that is the bundler's
  configuration for the network and not the policy. `check-traces.mjs`
  therefore gives a second verdict with that one address left out of the
  trace's list of code sizes, which is what a bundler set up for such a
  network sees: trace 6 then passes, traces 1 to 5 are refused as before.
  **The mark of a fixed layout:** a trace of `AgentPolicy` gets the two
  verdicts of trace 6.

## Asking again

```sh
cd scripts/erc7562
npm install          # the checker comes with the bundler's package, pinned in package.json
npm run check        # the six recorded traces against expected.json; exit 1 on a difference
node check-traces.mjs my-trace.json     # both verdicts for a trace of your own
```

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
