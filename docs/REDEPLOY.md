# Redeploying the contracts

A checklist for deploying every contract again from one commit and
recording it, made from the redeploy of commit
`60e773be7c7f071a4e5a69f84e7af3697092a4ef` to Base Sepolia (84532) and
Sepolia (11155111). What is deployed where, with every earlier instance:
[`DEPLOYMENTS.md`](DEPLOYMENTS.md).

## When

- **In development**, before the first external audit or mainnet
  deployment, a fix to a contract is carried by the next redeploy, which
  gathers what changed since the last one: a redeploy is not made for each
  fix. Until it is made, `DEPLOYMENTS.md` says what the deployed instances
  lack. Every contract keeps `VERSION` 0.1.0 (house rule 9 in
  `CLAUDE.md`), so the commit an instance was built from is what tells two
  instances apart, and `DEPLOYMENTS.md` names it (house rule 3). Only test
  networks are deployed to.
- **From the first tag on** (the commit given to the first external audit,
  or deployed first to a mainnet), a change to a contract's bytecode raises
  its `VERSION` (house rule 9), and only an audited release tag goes to a
  mainnet (house rule 3). How a deployment on a mainnet answers a finding
  is a matter of its own (#253).

## Before the broadcast

1. **Master merged.** The commit to deploy is on master, and the branch for
   the record is made from it (house rule 1).
2. **Every contract's bytecode as intended.** `scripts/source-record.sh
   <the commit the current instances were built from>` names each contract
   whose bytecode differs; nothing should differ that the redeploy is not
   for. Against the commit to deploy it says that master builds every
   contract as that commit does.
3. **CI green on that commit**: `ci` (forge tests, `source-record`, clippy,
   the Rust tests, the fuzz targets, the ERC-7562 check), `kontrol` and
   `gitleaks` (`.github/workflows/`).
4. **A fork dry run on each chain.** The same command as the broadcast,
   without `--broadcast`, runs the script against the chain's state and
   writes the deployments file the broadcast will write:

   ```sh
   cd contracts
   REDEPLOY=true forge script script/Deploy.s.sol --rpc-url <the chain's RPC> \
       --sender <the deployer's address>
   ```

   `--sender` is the deployer that will broadcast: the paymaster's owner is
   whoever runs the script, and its address follows from it
   [V `contracts/script/Deploy.s.sol`]. Keep the written
   `deployments/<chainId>.json` aside and restore the tracked one
   (`git checkout -- deployments/<chainId>.json`). The modules have the
   same address on every chain; the decoder is deployed only where CoW's
   settlement has code.
5. **Gas on the deployer** on each chain. The script sizes each
   deployment's gas limit by the chain itself: it asks the chain's
   `eth_estimateGas` for the call to the CREATE2 deployer and adds 30%,
   and prints the limit beside each address [V `_deploy` and `chainGas` in
   `contracts/script/Deploy.s.sol`; `test/DeployScript.t.sol`]. forge's own
   estimate simulates under the `evm_version` the contracts are compiled
   for (`cancun`), not under the chain's rules: on a chain with EIP-8037
   (Glamsterdam: Sepolia since 2026-10-06), where a deployed byte costs
   1,530 gas of state gas instead of 200, it came out five to seven times
   too low, and the first deployment ran out of gas while its code was
   stored (2026-11-25, before the script asked the chain). With the
   chain's figure, a dry run against Sepolia gives `AgentPolicy` a limit
   of 48,273,733 gas; EIP-7825's cap of 2^24 applies to regular gas only,
   so such a transaction is valid [V the dry run, 2026-11-25; EIP-8037].
   The redeploy of 2026-11-26 was the first broadcast sized this way: on
   Sepolia `AgentPolicy` went out with a limit of 48,354,777 gas and used
   36,901,943 [V transaction
   `0x2d32ef7b1ea810ff4de1a24c441a6c5e336d81ec4bf9717d0d278efcffd56ea8`].
   Without an RPC to ask (a run with no `--rpc-url`), forge estimates as
   before. The addresses do not change: only the compilation decides them.

## The broadcast, per chain

```sh
cd contracts
REDEPLOY=true forge script script/Deploy.s.sol --rpc-url <the chain's RPC> --broadcast --slow \
    --private-key "$(cat <the deployer's key file>)"
```

`--slow` sends one transaction at a time and waits for its receipt. A run
that fails part-way has already rewritten `deployments/<chainId>.json` with
addresses that hold no code: restore the file (`git checkout --
deployments/<chainId>.json`) before running again, or the next run files
those empty addresses as superseded.

The key is the deployer's, read from a file outside the repository; it is
never written into a command that lands in a file. The deployer becomes the
owner of the new `WhitelistPaymaster` (the sponsor); to hand it to another
address, the deployer sends `transferOwnership(<address>)` to it. Then:

1. **The file.** The script rewrites `deployments/<chainId>.json`: every
   contract at its new address, each replaced one under the next versioned
   name (`agentPolicy` becomes `agentPolicyV10`, …). It equals the dry
   run's file.
2. **Each instance against the build**, at the commit it was built from:

   ```sh
   forge inspect <Name> deployedBytecode
   cast code <address> --rpc-url <the chain's RPC>
   ```

   Equal outside the immutable slots: `AgentPolicy`'s hold the
   `SafeNonceAssert` address, `WhitelistPaymaster`'s the EntryPoint,
   `CowSwapDecoder`'s CoW's settlement, its domain separator and its vault
   relayer.
3. **The decoder's code hash**, `cast keccak $(cast code <decoder> --rpc-url
   <the chain's RPC>)`, equals the hash `mobile/owner-core/src/facts.rs`
   names for that chain (`VENUES`). The phone compares the code a trading
   mandate pins with it; the domain separator names the chain, so each
   chain has its own hash.
4. **The transactions**: `contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json`
   lists them. That directory is a build output and stays out of the
   repository (house rule 7); the hashes go on `DEPLOYMENTS.md`, in full.
5. **The phone's review against the bytecode deployed.** The differential
   test that holds the phone's review of a mandate to
   `AgentPolicy.onInstall` ([`FUZZING.md`](FUZZING.md)) runs on a local
   chain whose contracts are installed from
   `signer/crates/agent-signer/tests/fixtures/chain-code.json` [V
   `Chain::install` in `tests/anvil_cli.rs`, `anvil_setCode`], and that
   fixture holds the build's code (`scripts/test-fixtures.py`, below). To run
   it once against what was deployed, with the fixture's addresses already
   the new ones: write the code from the chain (`cast code <address>`) of
   each of this project's contracts the fixture holds as runtime code
   (`p256Validator`, `p256RecoveryValidator`, `p256Signer`, `agentPolicy`,
   `safeNonceAssert`, `demoCounter`) into its `contracts.<key>.code`, in the
   working tree only; check that `scripts/test-fixtures.py` (a plain run)
   names no entry behind the build; run the test; and restore the file with
   `git checkout`:

   ```sh
   cd signer
   cargo test -p agent-signer --features insecure-software-keys --test anvil_cli the_phone_reads_a_mandate -- --nocapture
   MANDATE_DIFFERENTIAL_CASES=20000 cargo test -p agent-signer --features insecure-software-keys --test anvil_cli the_phone_reads_a_mandate
   ```

   The plain run of the script passing on the chain's code is step 2 again
   for those six: it fills `AgentPolicy`'s immutable in with the fixture's
   `safeNonceAssert` address, so the deployed code and the build's are then
   equal byte for byte [V 2026-11-25, Base Sepolia: the plain run passed
   with the six written from the chain].

## The record: one pull request

Built on fresh master (house rule 1), and naming the commit that was
deployed.

- **The deployments files**, `contracts/deployments/<chainId>.json`, as the
  broadcast wrote them, and the variant `84532.enclave.json`: the same
  current instances, each replaced one under the next versioned name within
  that file, and its own paymaster history.
- **`docs/DEPLOYMENTS.md`**: the current tables, built from the commit with
  every contract's `VERSION`; the date and the transactions in full; the
  replaced instances moved to the earlier lists with the commit each was
  built from. `contracts/test/DeploymentsRecord.t.sol` fails while an
  address of the files is missing from the page.
- **The phone's facts**, `mobile/owner-core/src/facts.rs`: the current
  `AgentPolicy` in the lists of what each policy instance enforces
  (`PAYEE_POLICIES`, `TRADING_POLICIES`, `ID_POLICIES`: without its entry
  there the phone refuses a mandate with limits per ERC-6909 id), the decoder of each chain with its
  code hash (`VENUES`), and every name a redeploy keeps as `<name>V<n>`
  marked as versioned in `CONTRACTS` (the test
  `every_key_of_the_embedded_file_is_accounted_for` fails on a key it
  cannot name). The CLI reads every `<name>V<n>` of the file by itself
  (`Deployments::superseded` in `agent-signer`): the earlier validators,
  recovery validators and signers stay refused as targets, and their keys
  readable for the checks before a root operation.
- **The CLI's fixtures**, `chain-code.json` and `trading-code.json` in
  `signer/crates/agent-signer/tests/fixtures/`: each project contract's
  `address` in `chain-code.json` set to its new one, then
  `scripts/test-fixtures.py --write` writes the build's code into both files;
  a plain run checks them, as CI does. The script writes code and never an
  address, and it writes `AgentPolicy`'s immutable from the fixture's
  `safeNonceAssert` address [V the script on the branch of #171]. The
  addresses matter: the phone's development build takes the local chain's
  facts from `84532.json` [V `for_chain(31337)` in
  `mobile/owner-core/src/facts.rs`]. The CLI's local-chain tests
  (`anvil_cli`) and the ERC-7562 job run on these fixtures.
- **The example configs**, `signer/agent.*.base-sepolia.json`: allow-list
  entries on the demo counter and on the policy itself (its x402 and
  `orderRegister` entries) name the new instances. The test
  `repository_configs_target_no_superseded_instance` fails on a target the
  deployments file keeps as superseded.
- **The policy's differential vector.** `testFuzz_differential_*` in
  `contracts/test/PolicyFuzz.t.sol` compare the source with the runtime code
  in `contracts/test/vectors/agent-policy-<chainId>-<address, 8 digits>.hex`:
  that file becomes the new `AgentPolicy`'s code from the chain
  (`cast code <address> | tr -d '\n'`), `setUp` reads it, and
  `NONCE_ASSERT` there becomes the new `SafeNonceAssert`, which the
  instance holds as its immutable (`setUp` checks it). Exceptions the test
  made for rules the earlier instance lacked go with it ([`FUZZING.md`](FUZZING.md)).
- **`contracts/test/DeployScript.t.sol`**: the next versioned names it
  expects from the file as recorded.
- **The docs that state current addresses.** For each replaced address,
  `git grep -il <address>` finds them. A statement of what is current (a
  table of contracts, "the policy is at …", a config example, a demo's
  default) takes the new address. A record of a past run stays as it was: a
  transcript, a dated run record, the audit report, the recorded ERC-7562
  traces, the patches under `examples/`, the fuzz seeds. Where a record
  stands next to current text and could mislead, a short note says that it
  names the instance then current.
- **The checks**: `forge test --evm-version osaka` (then `git checkout --
  benchmarks/gas.json`), `cargo test` and `cargo clippy` in `signer/` and
  `mobile/owner-core/`, `scripts/test-fixtures.py` and the `anvil_cli`
  tests on the renewed fixtures,
  `gitleaks git . --redact --log-opts="--all" --exit-code 1`, and
  `scripts/source-record.sh origin/master`, which finds no contract source
  changed by the record.

## After: the owner's steps

Each changes rights or moves funds on a chain: an agent session prepares the
command and explains it, and the owner signs with the owner key (house
rule 5).

- **The paymaster.** `paymaster deposit --wei …` funds its EntryPoint
  deposit from the gas wallet; `paymaster stake --wei …` (the paymaster's
  owner) for bundlers that ask for a stake; `paymaster sponsor --budget …
  --max-per-op …` (the owner) lists each test account. These move funds and
  wait for the owner's word.
- **Each test account's root**: `owner set-root --agent <config> --validator
  <the new P256Validator> --retire <the superseded P256Validator>`, with
  `--to-phone <label>` for a phone's key or `--not-a-phone --new-key '<the
  owner key as the config names it>'` (`AGENT_CONFIG.md`), signed with the
  current owner key. `owner status` afterwards shows the new validator.
- **Each test account's recovery key**, where one is installed. The CLI's
  recovery commands use the current `P256RecoveryValidator` only [V
  `recovery_validator` in `agent-signer/src/chain.rs`]: `owner add-recovery`
  installs the config's recovery key on it. The superseded recovery
  validator stays installed, with its grant of `changeRootValidator`, until
  `owner remove-recovery --earlier <its address>` takes the key off it,
  after `add-recovery` has installed the key on the current one [V
  `RemoveRecovery` in `agent-signer/src/main.rs`; the test
  `the_recovery_key_moves_to_a_redeployed_validator`; the run below].
- **Each permission**: `permission rotate --agent <config> --old-id <its id>`
  moves it onto the new `P256Signer` and `AgentPolicy`, with the config's
  allow-list already on the new instances; `--old-config` when the config no
  longer holds the venue terms the permission was installed with.
  `permission show` afterwards: every field `ok`.
- **The phone apps**, rebuilt so that they embed the new facts, and
  installed in place (`adb install -r`, `mobile/ios/install-phone.sh`);
  never uninstalled, since the app holds key handles
  ([`MOBILE_DEV_MODE.md`](MOBILE_DEV_MODE.md)). The regular build, not the
  development variant that knows the local test chain.

### A run of these steps (2026-11-26, Base Sepolia)

Account `0xD62Dd4afD4e77cDFA6f8eaD1D2655745cF5af628`, moved from the
instances of 2026-10-20 and 2026-11-21 to the current ones. The CLI was
built from master `93ccd9814adcc10afa501517af275e40b49eb496`. Each owner
step is one operation signed by the account's owner key, with gas paid by
the account and delivered through the CLI's own `handleOps`; every
transaction succeeded [V the receipts, and the reads named with each step].

| Step | Command | Transaction | Read afterwards |
|---|---|---|---|
| The root | `owner set-root --validator 0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63 --retire 0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2 --not-a-phone --new-key …` | `0x13989b281aa8b6d4da69e57539b6121fe0fda2122244b9d8f4b387c90256a45f` | `owner status`: the new validator is root, with the same key; `isInitialized(account)` on the retired validator is false |
| The recovery key, installed | `owner add-recovery` | `0x06ec2e32205520bc6b14400702f123d821c58167b5c4eaf5d4b3007050c6ce96` | `owner status`: installed on `0xb7a06e6c7B5cC9852578EF89f38d161C31218047`, may take root |
| The recovery key, off the earlier validator | `owner remove-recovery --earlier 0x63dd80Fc5E109A44fd179F85050487E02c5e6958` | `0xfa3eed7277707e565a311772b8ec606a68ceedc922b3a58dc410e4162cd5ebb7` | `isInitialized(account)` on the earlier validator is false, its key for the account zero |
| The permission | `permission rotate --old-id 0x73653032` | `0x9b8425edabc571a5798b2c928af569de5b67478ef865de358a27c9a3ed4e9d69` | `permission show`: policy module `0x530DD3C000b3939294072409834c4c4dd160BCd9`, every field `ok` |
| An agent operation | `op send` to the demo counter, signed by the agent key | `0x5fdecc0add779cf9186078a72df6fecb1b8078f7f4dda06e169598db31bb4de0` | the counter goes from 0 to 1; the mandate's `spent` rises by the operation's gas |
| The paymaster, funded | `paymaster deposit --wei 3000000000000000` | `0xc6aa137510cf4dbd04951d7340835572d5387ecafc10e61f1b44a8f0a5dd55b7` | the paymaster's deposit at the EntryPoint |
| The paymaster, the account listed | `paymaster sponsor --budget 2000000000000000 --max-per-op 300000000000000` | `0x6069d2344965adf3b02c86798144e966c18d0b84bad4160ed0891e76977b2a2b` | `sponsorships(account)`: that budget and cap |
| A sponsored agent operation | `op send --sponsored` to the demo counter | `0xb99ecb6bebaa48d3f4fc536ff040e3472a207238b34fbd7df9fdc8792e2a3c73` | the counter goes to 2; the account's balance is unchanged, the sponsorship's budget falls |

- **The order matters for the recovery key:** it stays on the earlier
  validator until it is on the current one, so the account has a recovery
  path at every step.
- **The paymaster starts empty.** A redeployed `WhitelistPaymaster` is a new
  contract: no deposit at the EntryPoint and no account listed. Its two
  steps are sent by the paymaster's owner, not by the account's.
- **`add-recovery` needs the config's `recovery` entry** (the key file's
  place). It reads the public half only, and the key stays cold.

Not run here: a root held by a phone (`--to-phone`), and `--old-config` for
a permission with venue terms.

## What stays

- **Superseded instances keep working** for every account and permission
  that still uses them, until the owner moves them: a permission keeps its
  policy and signer, an account its root validator. Nothing on chain is
  removed by a redeploy.
- They stay recorded: under `<name>V<n>` in the deployments files, on
  `DEPLOYMENTS.md` with the commit they were built from, named as
  superseded by the phone's build, and known to the CLI.
- The phone reads a mandate only on the current policy: an install on a
  superseded one is refused outside expert mode, and a rotation onto the
  current one is what it shows [V `module_known` in
  `mobile/owner-core/src/review.rs`].
