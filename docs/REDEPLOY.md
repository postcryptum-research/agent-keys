# Redeploying the contracts

A checklist for deploying every contract again from one commit and
recording it, made from the redeploy of commit
`60e773be7c7f071a4e5a69f84e7af3697092a4ef` to Base Sepolia (84532) and
Sepolia (11155111). What is deployed where, with every earlier instance:
[`DEPLOYMENTS.md`](DEPLOYMENTS.md).

## When

- **Before the first audited release**, a fix to a contract is carried by a
  redeploy. Every contract keeps `VERSION` 0.1.0 until that release (house
  rule 9 in `CLAUDE.md`), so the commit an instance was built from is what
  tells two instances apart, and `DEPLOYMENTS.md` names it (house rule 3).
  Only test networks are deployed to.
- **From the first audited release on**, only an audited release tag goes to
  a mainnet (house rule 3), and a change to a contract's bytecode raises its
  `VERSION` (house rule 9).

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
  `the_recovery_key_moves_to_a_redeployed_validator`].
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
