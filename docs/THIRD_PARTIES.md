# Third-party code: what we build on, its versions and its audits

The code of others that agent-keys runs on or calls: which version we use,
the latest release, what its maintainers call production, and the most
recent audit with the version it covers. Checked on 2026-11-25 (UTC) at
master `194e9259db18d4ac6dfce47f658c107499ff8bca`. `[V]` is verified at the
source given, `[I]` is inferred (house rule 6). An audit is named by its
firm, never by a person.

This project's own contracts have had internal reviews and no external audit
([`FAQ.md`](FAQ.md#is-it-audited)). This page is about the code around them.

## On chain

What the deployed contracts are compiled from, and what the accounts call.

| Dependency | What we use it for | Our version | Latest | Latest audit, and the version it covers |
|---|---|---|---|---|
| **ZeroDev Kernel** | the smart account; we import its interfaces, `ExecLib`, `Types` and `Constants` | v3.3 (tag commit `cd697c7e21715d015e0643af22310a99aa17433b`; the deployed implementation `0xd6CEDDe84be40893d153Be9d467CD6aD37875b28` reports `kernel.advanced.v0.3.3`) | v4.0, released 2026-10-05 [V] | **None published for v3.2 or v3.3.** The newest reports in the repository cover v3.0 (ChainLight, [2024-04-05](https://raw.githubusercontent.com/zerodevapp/kernel/v3.3/audits/chainlight_v3_0.pdf); Kalos, 2024-04-12) and a v3.0-to-3.x diff review of May to June 2024 with no Kernel commit named ([PDF](https://raw.githubusercontent.com/zerodevapp/kernel/v3.3/audits/v_3_1_incremental_audit.pdf)) [V] |
| **ERC-4337 EntryPoint** (eth-infinitism `account-abstraction`) | the EntryPoint every operation goes through; `BasePaymaster` and helpers for our paymaster | v0.7.0 (`7af70c8993a6f42973f520ae0752386a5032abe7`), at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | v0.9.0, 2025-11-16, at `0x433709009B8330FDa32311DF1C2AFA402eD8D009` [V] | v0.7: OpenZeppelin, [2024-02-20](https://github.com/eth-infinitism/account-abstraction/blob/develop/audits/ERC-4337%20Account%20Abstraction%20Incremental%20Audit%20Report%20Feb%2020%202024.pdf), at `9879c931ce92f0bee1bca1d1b1352eeb98b9a120`, fixes to `8086e7ba0d80e6f7e5d36306b73793cbcaa4ced6` [V]. v0.9: Cantina, [2025-11-16](https://github.com/eth-infinitism/account-abstraction/blob/develop/audits/ERC-4337%20Account%20Abstraction%20v0.9%20Security%20Review%20-%20Cantina.pdf) [V] |
| **Safe** | the agent's Safe in the Safe examples (Olas, Jinn); the tests build one from the library | on chain 1.3.0: the L2 singleton `0x3E5c63644E683549055b9Be8653de26E0B4CD36E`, its proxy factory `0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2`, MultiSendCallOnly `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`; the tests' library v1.4.1 (`bf943f80fec5ac647159d26161446ac5d716a294`) | v1.5.0, 2025-07-03 [V] | 1.3.0: Certora (2026-07-20 to 2026-07-29) and Nethermind (final [2026-08-17](https://github.com/safe-global/safe-smart-account/blob/main/docs/Safe_Audit_Report_1_3_0_Nethermind.pdf)), both at `767ef36bba88bdbc0c9fe3708a4290cabef4c376` [V]. 1.4.1: Ackee's audit of 1.4.0 (2023-03), plus one later fix not re-audited [V]. 1.5.0: Ackee and Certora (2024-12 to 2025-05) [V] |
| **Solady** | P-256 signature checks (`P256.sol`) and `ECDSA.sol` in our modules | v0.1.26 (`acd959aa4bd04720d640bf4e6a5c71037510cc4b`) | v0.1.26 [V] | Cantina/Spearbit for Coinbase, review 2024-12-03 to 2025-01-12 at `4c895b961d45c53a49ed500cfc76868b7ee1328b`, fixes in v0.1.1 ([PDF](https://github.com/Vectorized/solady/blob/main/audits/cantina-spearbit-coinbase-solady-report.pdf)). `P256.sol` changed after it (PRs 1363, 1391, 1394, 1396) [V] |
| **Solady inside Kernel** | `LibERC7579`: how `AgentPolicy` decodes the account's single and batch calls | Kernel's pin `3f2f5345261904463f5429c9031c3d2185c0f4fe` (2024-12-06) | v0.1.26 | The same Cantina/Spearbit review. **The pin predates two of its fixes in `LibERC7579`** (see below) [V] |
| **P-256 verifier** `0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a` | Solady's fallback where the P-256 precompile at `0x0000000000000000000000000000000000000100` is absent | as set in Solady (PR 1297, 2025-01-14) | the same | No audit of its own; its change was verified as a fix in the Cantina/Spearbit review (finding 5.6.8) [V] |
| **OpenZeppelin Contracts** | `Ownable`, through `BasePaymaster`, in `WhitelistPaymaster` | v5.0.2 (`dbb6104ce834628e473d2173bbc9d47f81a9eec3`) | v5.7.0, 2026-07-29 [V] | v5.0.0: OpenZeppelin, [October 2023](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/audits/2023-10-v5.0.pdf). The newest listed covers v5.6.0; none is listed for v5.7.0 [V] |
| **CoW Protocol** | the venue of trading mandates: GPv2Settlement `0x9008D19f58AAbD9eD0D60971565AA8510560ab41`, its vault relayer `0xC92E8bdf79f0507f65a392b0ab4667716BFE0110`; read by our decoder | the deployed contracts | immutable | G0 Group, [May 2021](https://github.com/cowprotocol/contracts/blob/main/audits/GnosisProtocolV2May2021.pdf), at `7184fc98c05d2d336d90ee4e6b36429457a56d43`; Hacken, [2021-12-10](https://github.com/cowprotocol/contracts/blob/main/audits/%5BCowswap_10122021%5DSCAudit_Report_2.pdf), at `40c349d52d14f8f3c9f787fe2fca5a496bb10ea9` [V] |
| **1inch** | a second venue of trading mandates: AggregationRouterV6 `0x111111125421cA6dc452d289314280a0f8842A65`, which carries Limit Order Protocol v4; read by `OneInchLimitOrderDecoder`. In the CLI and the phone's core; its decoder is deployed on Sepolia and Base Sepolia since 2026-11-27 ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)), and an order was registered through it on Sepolia on 2026-11-27, unfilled | the deployed router: its verified source names `limit-order-protocol` 4.0.0-prerelease-19 and `solidity-utils` 3.7.1 [V Sourcify, chain 1] | the deployed contract is fixed; its owner can pause fills. The repository is at 4.3.x, with a fee flow the deployed router's orders use through extensions [V] | 1inch's audits repository lists reports for "Aggregation Router V6" and "Limit Order Protocol v4" by OpenZeppelin, Consensys, Decurity, Hexens, PeckShield and Pessimistic ([folder](https://github.com/1inch/1inch-audits/tree/master/Aggregation%20Pr.%20V6%20and%20Limit%20Order%20Pr.V4)). Their dates and audited commits were not read [I] |
| **Seaport and a marketplace's conduit** | a venue of bids for NFTs: Seaport 1.6 `0x0000000000000068F116a894984e2DB1123eB395`, read by `SeaportBidDecoder`; the account's allowance goes to the conduit of the key `0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000`, `0x1E0049783F008A0085193E00003D00cd54003c71` (OpenSea's) on Base Sepolia [V Seaport's conduit controller there, 2026-11-27]. In the contracts and their tests only, not in the CLI or the phone; the decoder is deployed on Sepolia and Base Sepolia since 2026-11-27 ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)) | the deployed Seaport; the source read is seaport-core v1.6.6 and seaport-types v1.6.3 [V the tags]. That this source compiles to the deployed code was not checked; the decoder's constructor holds its hash to the deployed contract's, and the fork tests run the deployed code [V] | Seaport has no owner and no upgrade path [I its source]. **A conduit has an owner, who opens channels on it; an open channel can move any token approved to the conduit** [V `Conduit.execute`, `ConduitController.updateChannel`]: the owner's allowance, one budget of the token paid, is in that owner's hands. Which channels are open was not read | **No audit of Seaport or of the conduit was looked for or read** [I] |
| **Uniswap** | a third venue of trading mandates, by a call and not an order: SwapRouter02 (`exactInputSingle` only), at `0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45` on Ethereum and Arbitrum, `0x2626664c2603336E57B271c5C0b26F421741e481` on Base, `0xB971eF87ede563556b2ED4b1C0b0019111Dd85d2` on BNB Chain, `0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E` on Sepolia, `0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4` on Base Sepolia; the call is built by `SwapRouter02Decoder`. In the CLI and the phone's core; its decoder is deployed on Sepolia and Base Sepolia since 2026-11-27 ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)), and one swap was made through it on Sepolia on 2026-11-27 | the deployed routers: their verified sources are `swap-router-contracts` at `70bc2e40dfca294c1cea9bf67a4036732ee54303` (package 1.3.1) with `v3-periphery` at `24ccf014fe7f81d74a14c1689d6fdf123f280e45`, the same files on all six chains [V Sourcify, 2026-11-26]. Each has 24,497 bytes of code and answers `factory()` and `positionManager()` [V the chains, 2026-11-26] | the deployed contracts are fixed: no `owner()`, `admin()` or `paused()` function, and no proxy slot [V the router on Base Sepolia, 2026-11-26; the others have code of the same length] | **No audit of SwapRouter02 was looked for or read** [I]. The path used was read in the source and run against the router on a fork of Base Sepolia (`SwapRouter02ForkTest`) |
| **Aave** | a protocol an agent uses under a mandate: the V3 pool, by its compact forms on an allow-list and by its forms with a beneficiary through `CallRulesDecoder`. Tested against the pool `0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27` on Base Sepolia (implementation `0xE9fb54369E85b9714F9d86366D918c5C7C87783A`), and by the forms with a beneficiary against the pools of Ethereum `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`, BNB Chain `0x6807dc923806fE8Fd134338EABCA509979a7e0cB`, Sepolia `0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951`, Arbitrum `0x794a61358D6845594F94dc1DB02A252b5b4814aD` and Base `0xA238Dd80C259a72e81d7e4664a9801593F98d1c5`, each on a fork on 2026-11-27. A decoder of rules for the pool is deployed on Sepolia and Base Sepolia since 2026-11-27, and the phone's core names it there ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)); a supply and a withdrawal went through it on Sepolia on 2026-11-27 | the deployed pools, which are upgradeable proxies behind Aave's governance [I] | governed by Aave: an upgrade can change what a function does with its words, and the rules a mandate pins do not follow it [I] | **No audit of Aave V3 was looked for or read** [I]. The functions used were read in the pool's verified source on 2026-11-26 and run on a fork (`AaveRecipeTest`, `PoolForkTest`) |
| **Compound, Lido, Sky's sDAI, Circle's CCTP** | protocols an agent uses under a mandate, by the recipes of `docs/DAPPS.md`. Tested on forks against: Compound v3's USDC market on Base Sepolia `0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017`; Lido's stETH on Ethereum `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`; the sDAI vault on Ethereum `0x83F20F44975D03b1b09e64809B757c47f942BEeA`; CCTP's V2 messenger on Base Sepolia `0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA`. A decoder of rules for CCTP's messenger is deployed on Sepolia and Base Sepolia since 2026-11-27, and the phone's core names it there; a transfer went through it on Sepolia on 2026-11-27. Compound and Lido need no deployment of ours, and the vault has none | the deployed contracts | each is upgradeable or governed by its own project: an upgrade can change what a function does with its arguments, and the rules a mandate pins do not follow it [I] | **No audit of any of them was looked for or read** [I]. The functions used were run on forks on 2026-11-26 (`ProtocolRecipes.t.sol`) |
| **Morpho, ether.fi, Rocket Pool, EigenLayer, Curve, Sky's farm and sUSDS, the Base bridge; more of Lido, Compound and Aave** | protocols an agent uses under a mandate, by the recipes of `docs/DAPPS.md`. Tested on a fork of Ethereum against: Lido's wstETH `0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0` and withdrawal queue `0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1`; ether.fi's pool `0x308861A430be4cce5502d0A12724771Fc6DaF216`, eETH `0x35fA164735182de50811E8e2E824cFb9B6118ac2` and weETH `0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee`; Rocket Pool's rETH `0xae78736Cd615f374D3085123A210448E74Fc6393` and the deposit pool its storage contract `0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46` named on that day, `0xCE15294273CFb9D9b628F4D61636623decDF4fdC`; EigenLayer's strategy manager `0x858646372CC42E1A627fcE94aa7A7033e7CF075A` with the stETH strategy `0x93c4b944D05dfe6df7645A86cd2206016c51564D`; Sky's staking rewards `0x173e314C7635B45322cd8Cb14f44b312e079F3af` and savings vault `0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD`; Curve's 3pool `0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7`; Compound v3's rewards `0x1B0e765F6224C21223AeA2af16c1C46E38885a40` and USDC market `0xc3d688B66703497DAA19211EEdff47f25384cdc3`; Aave V3's pool `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`; Morpho Blue `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`, its market `0xb323495f7e4148be5643a4ea4a8221eef163e4bccfdedc2a6f4696baacbc86cc`, and a MetaMorpho vault `0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB`; the Base bridge on Ethereum `0x3154Cf16ccdb4C6d922629664174b904d80F2C35`. None needs a deployment of ours for the allow-list recipes; a recipe by rules needs a rules decoder deployed for its contract, and none is deployed for these | the deployed contracts | each is upgradeable or governed by its own project: an upgrade can change what a function does with its arguments, and the rules a mandate pins do not follow it [I] | **No audit of any of them was looked for or read** [I]. The functions used were run on a fork on 2026-11-27 (`MoreRecipes.t.sol`) |
| **CREATE2 deployer** `0x4e59b44847b379578588920cA78FbF26c0B4956C` | deploys our contracts at the same address on every chain | the deployed contract | unchanged | **No public audit found.** It is six instructions with no access control; front-running a deployment gives the same address and code [V/I] |

### Compiler and tools

| Tool | Ours | Latest | Notes |
|---|---|---|---|
| solc | 0.8.38 | 0.8.39, 2026-11-19 [V] | The one bug listed for 0.8.38 (SOL-2026-8, a storage corruption when copying overlapping recursive structs) does not reach us: `contracts/src` has no recursive struct [V by scan]. A new compiler changes every contract's bytecode and address, so it comes with a redeploy only (house rules 3 and 9) |
| Foundry | 1.8.x | v1.10.0, 2026-11-19 [V] | 1.10.0 replaces revm and changes gas snapshots, remappings and test discovery [V]: a move to try on a branch |
| Kontrol | `runtimeverificationinc/kontrol:ubuntu-jammy-1.0.255` | v1.0.255 [V] | current |

### What follows for us

1. **Kernel v3.3 has no published audit that covers it** [V]. v3.2
   (2024-12-11) and v3.3 (2025-04-03) changed `Kernel.sol` and
   `ValidationManager.sol` substantially after the last published review;
   v3.3 added EIP-7702 [V]. A maintainer answered "Yes it has been audited"
   in [kernel issue 145](https://github.com/zerodevapp/kernel/issues/145)
   (2025-10-17), without a report [V]. Kernel v4.0 is released, its source
   cites Trail of Bits findings, its report is not published, and ZeroDev's
   own SDK supports versions up to v3.3 only [V/I]. So v3.3 is the newest
   line in production use. Asking ZeroDev for the v3.3 report is the owner's
   step before an audit of this project. Moving to v4 means EntryPoint v0.9
   and a redeploy.

   **What is deployed is that source.** The deployed implementation
   `0xd6CEDDe84be40893d153Be9d467CD6aD37875b28` and factory
   `0x2577507b78c2008Ff367261CB6285d44ba5eF2E9` are built from tag v3.3
   (`contracts/lib/kernel`) with via-IR, `prague`, the optimizer at 200 runs
   and no metadata. solc 0.8.28 and 0.8.29 both give that code; Kernel's
   repository records no compiler. ZeroDev deploys through the CREATE2
   deployer with salt 0, so the build's CREATE2 address being the deployed
   one means the creation code is the same; and on Base Sepolia and Sepolia
   the runtime code equals the build outside its immutable slots. Without
   via-IR the build gives other addresses. The build uses Kernel's own
   remappings, so the deployed Kernel decodes with the pinned Solady of
   point 2 [V `scripts/third-party-code.sh`, 2026-11-25]. The FactoryStaker
   `0xd703aaE79538628d27099B8c4f621bE4CCd142d5` is not reproduced: its owner
   and salt are not those of Kernel's deploy script.
2. **`AgentPolicy` decodes calls with Kernel's own `LibERC7579`, on
   purpose** [V `contracts/foundry.toml`: `lib/kernel/:solady/=lib/kernel/lib/solady/src/`;
   `AgentPolicy.sol` imports `kernel/lib/solady/src/accounts/LibERC7579.sol`;
   Kernel's `ExecLib` imports `solady/accounts/LibERC7579.sol`]. The
   policy judges each call of a batch with the function Kernel then
   executes it with, byte for byte, so the two cannot read one batch
   differently. That pin predates two fixes of the Cantina/Spearbit review
   (PR 1239, finding 5.2.2, High: the mode selector; PR 1244, finding
   5.3.7, Medium: `decodeBatch` bounds) [V]. The newer `decodeBatch`
   bounds-checks differently [V by diff], so moving the policy alone to a
   newer Solady would make the policy and the deployed Kernel differ. 5.2.2
   is in functions we do not call [V]. 5.3.7 is a batch whose pointer
   array runs past the declared end of `executionData`; the old decoder
   reads the missing pointer words from whatever follows:
   - **The report's proof of concept**, with those words in the call's own
     trailing bytes: Kernel and the policy read the same bytes, and the
     same four calls to address 0, which the policy refuses; Solady v0.1.26
     refuses the batch itself [V
     `test_batch_theSoladyReviewsBatchIsReadAsKernelReadsIt` in
     `AgentPermission.t.sol`, with a control batch that passes; with
     Kernel's side decoded by v0.1.26 instead, the test fails].
   - **Past the end of `callData`** the two readings differ. Kernel reads
     zeros past its calldata; the policy reads what follows `callData` in
     the encoded operation. With no `paymasterAndData` that is zeros too,
     and the policy refuses the calls as Kernel reads them. With a
     `paymasterAndData`, the policy reads its length word as the pointer,
     past the batch's bounds, and refuses the batch [V
     `test_batch_pastTheEndOfTheCallThePolicyRefuses`]. In both cases the
     policy refuses.
   - **The policy now refuses every such batch by a rule of its own:** a
     batch whose pointer array does not end within `executionData` is
     refused, whatever its legs are [V
     `test_batch_aPointerArrayPastTheEndIsRefused`: with a mandate made to
     allow the calls the batch reads as, it passes without the rule and is
     refused with it]. In a batch the policy accepts, every pointer word
     and every leg lies inside `executionData`, which the policy and
     Kernel read alike. The instances current since 2026-11-26 have the
     rule; the ones of 2026-11-25 they replaced predate it
     ([`DEPLOYMENTS.md`](DEPLOYMENTS.md)). There the case is closed by
     argument [I]: a leg read through a
     pointer past the end must fit, head and data, in the last words of
     `executionData`, which are the first pointer words themselves, so
     its target is read from those pointer words: address 0 or a small
     number, which no mandate of real contracts lists.

   Kernel's
   [issue 137](https://github.com/zerodevapp/kernel/issues/137) acknowledges
   the stale pin [V].
3. **EntryPoint v0.7 is two releases behind.** These are fixed only from
   v0.8 on, none of them a security advisory [V]:
   - initCode front-running;
   - a paymaster's `postOp` gas figure that misses the unused-gas penalty.
     `WhitelistPaymaster` returns no context and has no `postOp` [I];
   - a zero-address paymaster accepted with data;
   - `BasePaymaster`'s single-step `Ownable`, which `WhitelistPaymaster`
     inherits;
   - the lower time bound. In v0.7 `block.timestamp == validAfter` is
     inside the window, which is what `AgentPolicy` documents. From v0.8 it
     is outside, so moving shifts a mandate's start by one second [V].

   Kernel v3.3 is built for v0.7 [V], so v0.7 stays as long as Kernel v3.3
   does.
4. **Safe 1.3.0 was audited again in 2026.** Certora's one new Low needs a
   Safe transaction with a nonzero `safeTxGas` or `gasPrice` [V]. The
   policy refuses all three gas words other than 0 since #191, which
   closes that path for an agent [I]. Nethermind's two findings are fixed
   from 1.4.0 on [V]. The Safe version is the Safe owner's choice; the
   policy reads `execTransaction`, which is the same in 1.3.0, 1.4.1 and
   1.5.0 [I].
5. **No security advisory** in GitHub's database affects Kernel,
   `account-abstraction`, Safe, CoW, or `Ownable` in OpenZeppelin 5.0.2 [V].
   Solady's GHSA-8xvx-4mvg-m9v8 is in a contract we do not use, and is fixed
   from 0.1.24 [V].

## Off chain

The signer, the CLI, the phone's core and apps, and the tools around them.
Advisories were checked with `cargo audit` on the three `Cargo.lock` files
against the RustSec database of 2026-11-25, OSV for every locked crate and
the Android and npm packages, and GitHub's advisories [V].

| Dependency | What we use it for | Ours | Latest stable | Audit, and the version it covers | Advisories on ours |
|---|---|---|---|---|---|
| `p256` / `ecdsa` / `elliptic-curve` (RustCrypto) | P-256 keys and signatures in software and in checks | 0.14.0 / 0.17.0, and 0.16.9 through alloy's secp256k1 / 0.14.3, and 0.13.8 through alloy | the same [V] | zkSecurity for NEAR, [2025-04-07](https://reports.zksecurity.xyz/reports/near-p256/), `p256` 0.14.0-pre.2, **verification only**; signing and constant time out of scope [V]. The READMEs say "never been independently audited" [V] | none [V] |
| `aes-gcm`, `scrypt`, `sha2`, `hmac`, `zeroize`, `rand_core`, `getrandom` | the cold recovery key file, hashing, secrets | 0.10.3, 0.11.0, 0.11.1, 0.13.0, 1.9.1, 0.6/0.9/0.10, 0.2/0.3/0.4 | `aes-gcm` 0.11.1, `scrypt` 0.12.0, `sha2` 0.11.2, `zeroize` 1.9.2; the rest current [V] | `aes-gcm`: NCC Group, 2020, version 0.3.0 [V]. The others: no public audit found | none (`aes-gcm`'s RUSTSEC-2023-0096 is fixed in 0.10.3) [V] |
| `x25519-dalek` | the secure channel to TROPIC01 | 2.0.1, and 3.0.0 through `yubikey` | 3.0.0 [V] | Quarkslab, 2019, version 0.5.2, a quick look only [V] | none [V] |
| `aws-lc-rs` / `aws-lc-sys` | TLS crypto under `rustls` | 1.18.2 / 0.46.0 | 1.19.0 / 0.47.0 [V] | FIPS 140-3 certificates cover the separate FIPS build, **not the `aws-lc-sys` we link** [V]; no third-party report found | none (GHSA-xv35-xp83-5wrf is fixed in our version) [V] |
| `rustls` | TLS to RPC nodes | 0.23.46 | the same [V] | Cure53, 2020, version 0.16 or newer [V] | none [V] |
| `alloy` | Ethereum RPC, ABI, the CLI's chain access | 2.5.0 (`alloy-primitives` 1.7.3) | 2.6.1 [V] | no public audit found | none directly. Through it, **`crypto-bigint` 0.5.5: RUSTSEC-2026-0387** (timing in constant-time code), with no 0.5 fix; alloy 2.6.1 still needs it. Our P-256 path uses `crypto-bigint` 0.7.x, which is fixed [V]. `url` is 2.5.9, which has the fix of RUSTSEC-2026-0592 (a crash in `Url::origin()`) [V `signer/Cargo.lock`] |
| `tss-esapi` | the TPM 2.0 backend | 7.7.0 | the same [V] | no public audit found | none in the crate. **The system `tpm2-tss` library it links had 13 advisories** published 2026-10-26 to 2026-11-04, fixed in 4.1.5 and 4.2.1 (latest 4.2.2); a Linux host needs one of those [V] |
| `yubikey` | the YubiKey backend | 0.9.0-rc.0 | no stable 0.9 (0.8.0 is the last stable) [V] | none: its README says no audit was ever done [V] | through it, **`rsa` 0.10.0-rc.19: RUSTSEC-2023-0071** (we use P-256 slots only, the RSA code is not called [I]). It cannot be moved: `yubikey` 0.9.0-rc.0 asks `rsa` for a feature `sha2` that `rsa` 0.10.0 no longer has, so the fix waits for a `yubikey` release [V `cargo update -p rsa --precise 0.10.0` fails to resolve]. `inout` is 0.2.6, which has the fix of GHSA-2943-gp7x-qg39 [V `signer/Cargo.lock`] |
| `tropic01` (libtropic-rs, git) | the TROPIC01 backend | rev `3310775775c211496d514f9110554884afa3ba80` | that rev is its master; no releases [V] | none. **Its README calls it a community project, not maintained by Tropic Square, not for production** [V]. The chip itself was audited by Ledger Donjon; the full report is due in spring 2027 [V] | none published [V] |
| `windows`, `uniffi`, `tokio`, `reqwest`, `serialport`, `clap` | Windows CNG, the phone bindings, the runtime, HTTP, serial, the CLI | 0.62.2, 0.32.2, 1.54.1, 0.13.5, 4.10.1, 4.6.7 | current, except `clap` 4.6.10 [V] | not researched | none [V] |
| Rust | the toolchain | 1.94.1 minimum, 1.95.0 for clippy in CI | 1.100.0 [V] | n/a | Cargo's CVE-2026-5222 and CVE-2026-5223 matter only with third-party registries; we use crates.io and one git dependency [V/I] |
| `@pimlico/alto` (npm) | the bundler of the ERC-7562 check | 0.0.21 | the same [V] | not researched | none (GHSA-c9v7-pgv6-hrcc is fixed in it) [V] |
| Node.js | CI | 22 | 26 is the active LTS; 22 is in maintenance until 2027-04-30 [V] | n/a | n/a |
| Android: AGP, Kotlin, `appcompat`, `biometric`, ZXing core, `zxing-android-embedded`, JNA | the Android app | 8.13.2, 2.4.21, 1.7.1, 1.1.0, 3.5.4, 4.3.0, 5.17.0 | AGP 9.5.3, `appcompat` 1.8.0, JNA 5.19.1; the rest current [V] | n/a | none [V]. AGP and `appcompat` are held back on purpose (the build file says why); `zxing-android-embedded` has had no release since 2021 [V] |
| iOS | the iPhone app | deployment target iOS 16.0; Apple's CryptoKit, Secure Enclave and LocalAuthentication only | iOS 27.2.1 [V] | n/a | iOS 16's last update was 16.7.16 on 2026-05-11, while 18, 26 and 27 were updated on 2026-11-09: treat iOS 16 as out of security support [V/I] |

### What follows for us

1. **Two of three locked crates with fixes are taken:** `inout` 0.2.6 and
   `url` 2.5.9, in `signer/Cargo.lock`, the only lock file that holds them
   [V]. **`rsa` stays at 0.10.0-rc.19** until `yubikey` has a release that
   builds with `rsa` 0.10.0; the RSA code is not called with our P-256
   slots [I]. `crypto-bigint` 0.5.5 stays until
   alloy moves to `k256` 0.14 [V]. It is not on the P-256 path; it touches
   secp256k1 arithmetic inside alloy, which signs with a real secret only
   under `insecure-software-keys` [I].
2. **A Linux TPM host needs `tpm2-tss` 4.1.5 or later, or 4.2.1 or later**
   [V]: the crate links whatever the host has installed. The install
   steps in `ARCHITECTURE.md` and `GETTING_STARTED.md` say so. The CLI
   does not print the version: `tss-esapi` exposes only the version found
   at build time, while the advisories concern the library installed at
   run time.
3. **No audit covers P-256 signing at the versions we ship** [V]. It signs
   wherever a key is held in software: the cold recovery key file of the
   CLI (kept under scrypt and AES-GCM), the software backend, and the
   tests. The hardware backends sign in the device.
4. **The TROPIC01 binding is a community project its authors call not for
   production** [V]. The TROPIC01 backend stays experimental for that
   reason as well as for the chip's open report.
5. **The iOS deployment target** (16.0) is below what Apple still updates
   [I]. Raising it is a change to the app and its doc (design D7).
6. **Unaudited and in use:** `yubikey`, `alloy`, `tss-esapi`,
   libtropic-rs, and RustCrypto's hashing, MAC, KDF and RNG crates. No
   public audit was found for any of them [V].

## Not checked

- The audit reports were read for scope, dates, commits and the findings
  named here, not end to end.
- Whether ZeroDev holds an unpublished report on Kernel v3.2 or v3.3.
- The FactoryStaker against its source (its owner and salt are unknown).
- The P-256 verifier against its source: its salt is unknown, so its
  address cannot be derived. Its code is the same on both chains, 2,066
  bytes with the keccak hash
  `0x9933b3f70809361dcfebe1f731b129890454cc29af5b32840dcae92400a8826b`
  [V 2026-11-25].
- On the instances deployed on 2026-11-25 and replaced on 2026-11-26, every arrangement of a batch
  whose pointer words lie past the end of `callData` (point 2 of the
  on-chain list): two are tested, the rest argued. The source refuses
  them all by rule.
- Audits of `windows`, `uniffi`, `tokio`, `reqwest`, `serialport`, `clap`
  and the bundler; the `tpm2-tss` version on any given host.

## To refresh

- Our versions: `git submodule status --recursive`, the `Cargo.lock`
  files, `mobile/android/app/build.gradle.kts`, `mobile/ios/project.yml`.
- Advisories: `cargo audit` in `signer/`, `mobile/owner-core/` and
  `mobile/owner-core/fuzz/`.
- Audits: each project's own `audits/` folder or security page, as linked
  above.
