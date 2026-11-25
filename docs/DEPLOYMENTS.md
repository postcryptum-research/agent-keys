# Deployed contracts

agent-keys runs on test networks only and has had no external audit
([`docs/FAQ.md`](FAQ.md#is-it-audited)). This page lists where its contracts
are deployed, chain by chain, with every earlier instance that is still
recorded. How a redeploy is done and recorded: [`docs/REDEPLOY.md`](REDEPLOY.md).

**An account set up before 2026-11-25 still uses instances this page lists
as earlier ones.** A permission keeps its policy and signer, and an account
its root validator, until the owner moves them (`REDEPLOY.md`, "After: the
owner's steps"). Until then the phone names those instances as superseded
and reads no mandate on them, and a config written before that date names
them too.

The record itself is `contracts/deployments/<chainId>.json`: the CLI reads
it, the phone's build embeds them, and
`contracts/test/DeploymentsRecord.t.sol` fails when an address in it is
missing from this page.

## How the addresses come about

- **The same address on every chain.** The modules are deployed through the
  canonical CREATE2 deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C`
  with salt 0, so an address follows from the creation code alone. The
  creation code depends on the source and the compiler settings, and
  `AgentPolicy`'s also on its one constructor argument, the `SafeNonceAssert`
  address [V `contracts/script/Deploy.s.sol`].
- **The paymaster is the exception.** `WhitelistPaymaster` takes its owner as
  a constructor argument, so each sponsor's instance has its own address.
  The current instance's owner, and so the sponsor, is the wallet that
  deployed it, `0x52370eE170c0E2767B32687166791973a0dE7966`, on both chains:
  the owner asked for no other.
- **No metadata in the bytecode.** `bytecode_hash = "none"` and
  `cbor_metadata = false`, so comments and paths do not move an address. Each
  file records the compiler settings its current instances were built with:
  `solc` 0.8.38 and `evmVersion` cancun [V `contracts/foundry.toml`].
- **The current instances are built from one commit.** Every contract
  carries `string public constant VERSION`. Until the first audited release
  every contract stays at 0.1.0 and a fix is carried by a redeploy, not by
  a version change (house rule 9, `CLAUDE.md`). The current instances on
  both chains are built from commit
  `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, every contract at `VERSION`
  0.1.0. On Base Sepolia seven of them were deployed earlier the same day
  from commit `772e8f1608bcdf8bc966cb81ef27c7446c0677d0`, which builds those
  seven as `60e773be7c7f071a4e5a69f84e7af3697092a4ef` does; only
  `AgentPolicy` differs between the two [V `scripts/source-record.sh
  772e8f1608bcdf8bc966cb81ef27c7446c0677d0` on 2026-11-25]. Master may move ahead of them: `scripts/source-record.sh <commit>`
  names every contract whose bytecode master no longer builds as that commit
  does [V `scripts/source-record.sh 60e773be7c7f071a4e5a69f84e7af3697092a4ef`
  on 2026-11-25, at this record's commit: `contracts/src` and
  `foundry.toml` are as at that commit]. The earlier instances predate
  `VERSION`: master's source no longer builds them, the commit named with
  each does.
- **Earlier instances stay recorded** under versioned names (`agentPolicyV1`,
  …). A permission installed with one keeps pointing there until the owner
  rotates it, and an account whose root is an earlier validator keeps it
  until the owner moves it.

To check an instance against the commit it was built from:

```sh
git checkout <commit> && cd contracts
forge inspect AgentPolicy deployedBytecode     # the build
cast code <address> --rpc-url <chain's RPC>   # the chain
```

The two are equal outside a contract's immutable slots. `AgentPolicy`'s hold
the `SafeNonceAssert` address, `WhitelistPaymaster`'s the EntryPoint.
`CowSwapDecoder`'s hold CoW's settlement, its EIP-712 domain separator and
its vault relayer, read when the decoder is created: the domain separator
names the chain, so the decoder has the same address and other code on each
chain.

## Base Sepolia (chain 84532)

### This project's contracts

| Contract | Address | What it is |
|---|---|---|
| `P256Validator` | [`0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63`](https://sepolia.basescan.org/address/0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63) | the owner key: the account's root validator |
| `P256RecoveryValidator` | [`0xb7a06e6c7B5cC9852578EF89f38d161C31218047`](https://sepolia.basescan.org/address/0xb7a06e6c7B5cC9852578EF89f38d161C31218047) | the cold recovery key, granted only `changeRootValidator` |
| `P256Signer` | [`0xd88d25Ca3e042A28893781935756ee90Bc2d2769`](https://sepolia.basescan.org/address/0xd88d25Ca3e042A28893781935756ee90Bc2d2769) | the agent key, as one Kernel permission |
| `AgentPolicy` | [`0xe52825D44396d72cA17adF0c0260d468e94F8C94`](https://sepolia.basescan.org/address/0xe52825D44396d72cA17adF0c0260d468e94F8C94) | the agent's mandate: targets, caps, budget, window, payees, x402, a budget per period, orders through a venue's decoder, and limits per ERC-6909 id |
| `SafeNonceAssert` | [`0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219`](https://sepolia.basescan.org/address/0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219) | the replay guard of an agent's Safe transaction |
| `CowSwapDecoder` | [`0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a`](https://sepolia.basescan.org/address/0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a) | reads a CoW Swap order for the policy |
| `WhitelistPaymaster` | [`0x657792557C1D40f2Da031FD7aB277078D2c0a4cb`](https://sepolia.basescan.org/address/0x657792557C1D40f2Da031FD7aB277078D2c0a4cb) | a gas sponsor with a budget per account; owner [`0x52370eE170c0E2767B32687166791973a0dE7966`](https://sepolia.basescan.org/address/0x52370eE170c0E2767B32687166791973a0dE7966) |
| `DemoCounter` | [`0x29da894F3E456CAC92b3EC76710524E74411E99f`](https://sepolia.basescan.org/address/0x29da894F3E456CAC92b3EC76710524E74411E99f) | a demo target, with no rights over anything |

Built from commit `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, every contract
at `VERSION` 0.1.0, with `contracts/script/Deploy.s.sol` and `REDEPLOY=true`.

Deployed on 2026-11-25 by `0x52370eE170c0E2767B32687166791973a0dE7966`,
each through the CREATE2 deployer, every transaction successful:

| Contract | Built from | Transaction |
|---|---|---|
| `AgentPolicy` | `60e773b` | [`0x274bf3dbc4a9745bd743d58499a5b7864a2964bb18c85d3913941b5859b4377a`](https://sepolia.basescan.org/tx/0x274bf3dbc4a9745bd743d58499a5b7864a2964bb18c85d3913941b5859b4377a) |
| `P256Validator` | `772e8f1` | [`0x17b09e1bb3e937b2ebb9381be132a9c7f8191f31b486bf3cc4b381f6a56355a5`](https://sepolia.basescan.org/tx/0x17b09e1bb3e937b2ebb9381be132a9c7f8191f31b486bf3cc4b381f6a56355a5) |
| `P256RecoveryValidator` | `772e8f1` | [`0x2c74c492e604d31ac3c0322e26c2d1150491d17a3a794e0c2cc68d6baf221598`](https://sepolia.basescan.org/tx/0x2c74c492e604d31ac3c0322e26c2d1150491d17a3a794e0c2cc68d6baf221598) |
| `P256Signer` | `772e8f1` | [`0x2bd74f20bf982107a19b97f4ac50de16c583aa45aec5eb0af127be94fb215333`](https://sepolia.basescan.org/tx/0x2bd74f20bf982107a19b97f4ac50de16c583aa45aec5eb0af127be94fb215333) |
| `SafeNonceAssert` | `772e8f1` | [`0x93aed7d5f10a0dab31ad0f419d77433fcb72332a3e9e14afa21c72a03cc84581`](https://sepolia.basescan.org/tx/0x93aed7d5f10a0dab31ad0f419d77433fcb72332a3e9e14afa21c72a03cc84581) |
| `DemoCounter` | `772e8f1` | [`0x0d95768d66e519a7c1443dcf7d07a1cf747c47e618dd2932481c44d331a3c75a`](https://sepolia.basescan.org/tx/0x0d95768d66e519a7c1443dcf7d07a1cf747c47e618dd2932481c44d331a3c75a) |
| `WhitelistPaymaster` | `772e8f1` | [`0x7bfb78272819a92e3dc4e0224dc6898e0f9b27857b009dda3a5a3542b2255a28`](https://sepolia.basescan.org/tx/0x7bfb78272819a92e3dc4e0224dc6898e0f9b27857b009dda3a5a3542b2255a28) |
| `CowSwapDecoder` | `772e8f1` | [`0x91c71c7b01d236ad37f0e057783c3fbafc6993a6a895ecce40e8439e88658186`](https://sepolia.basescan.org/tx/0x91c71c7b01d236ad37f0e057783c3fbafc6993a6a895ecce40e8439e88658186) |

[V] Each instance compared on chain on 2026-11-25 with the build of
`60e773be7c7f071a4e5a69f84e7af3697092a4ef`: `P256Validator`,
`P256RecoveryValidator`, `P256Signer`, `SafeNonceAssert` and `DemoCounter`
are equal byte for byte; `AgentPolicy`, `WhitelistPaymaster` and
`CowSwapDecoder` are equal outside their immutable slots, which hold
`SafeNonceAssert`, the EntryPoint, and CoW's settlement, its
`domainSeparator()` on this chain and its vault relayer.

`contracts/deployments/84532.enclave.json`, the variant the Secure Enclave
runs use ([`SECURE_ENCLAVE.md`](SECURE_ENCLAVE.md)), names the same current
instances. The paymaster it named before them is `whitelistPaymasterV2`
there: `0x05a97329397200dF8795A882da0b5b1aD894EB97`, owner
`0x52370eE170c0E2767B32687166791973a0dE7966`.

### Earlier instances, still recorded

| Name in the file | Address | First recorded | With |
|---|---|---|---|
| `agentPolicyV1` | [`0x12854c1C0ce3F7506065111f9d8f73EF19CeD1c7`](https://sepolia.basescan.org/address/0x12854c1C0ce3F7506065111f9d8f73EF19CeD1c7) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first instance, with the agent account of phase 2 |
| `agentPolicyV2` | [`0xEA80a8bd8a02930b1218fE6cDeF5fE712C52F6C0`](https://sepolia.basescan.org/address/0xEA80a8bd8a02930b1218fE6cDeF5fE712C52F6C0) | 2026-10-20, `791ac53b201cd381e966db1964d3448d3db52928` | recorded in the same commit as `agentPolicyV3`, which superseded it the same day |
| `agentPolicyV3` | [`0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24`](https://sepolia.basescan.org/address/0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24) | 2026-10-20, `791ac53b201cd381e966db1964d3448d3db52928` | Safe transactions and MultiSend batches held to the mandate |
| `agentPolicyV4` | [`0x3f590A5879B5f28466b6DAeF69FfA9777f84b424`](https://sepolia.basescan.org/address/0x3f590A5879B5f28466b6DAeF69FfA9777f84b424) | 2026-10-20, `96d56ada9969304afafdddc126129dd472febea0` | the fixes of the audit of 2026-10-20 |
| `agentPolicyV5` | [`0xe0f3C8B707Dceff7299DD8E95D57b30aFE0B7c2d`](https://sepolia.basescan.org/address/0xe0f3C8B707Dceff7299DD8E95D57b30aFE0B7c2d) | 2026-10-20, `b0734b16c92b52bf7e7f28d9f7141569d61af856` | mandate time windows |
| `agentPolicyV6` | [`0x8347dBC3d7A71DAFDeED5975ce85638494865F73`](https://sepolia.basescan.org/address/0x8347dBC3d7A71DAFDeED5975ce85638494865F73) | 2026-10-21, `662d77c07cec515dbf93c6aeb8a8c7c7790fb62d` | x402 payments from the agent account |
| `agentPolicyV7` | [`0xdd544A6F0220778Fff16F51B468656e73E32ae85`](https://sepolia.basescan.org/address/0xdd544A6F0220778Fff16F51B468656e73E32ae85) | 2026-11-10, `0e368bdc8f5b593844ec0a75bfc0e056993ea650` | the forbidden-target guard (#11) |
| `agentPolicyV8` | [`0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95`](https://sepolia.basescan.org/address/0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95) | 2026-11-20, `933b3d27f3d3bb74d94e535ca815f4765c821912` | payee lists and the per-operation token cap (#66, #76, #79) |
| `agentPolicyV9` | [`0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2`](https://sepolia.basescan.org/address/0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2) | 2026-11-21, `50a95a679cb44963263ba97aeb264c421277a323` | storage owned by the account (#83); no budget per period and no venues |
| `agentPolicyV10` | [`0x6b8F14421007FC49251F6B2d48071795A077B2D8`](https://sepolia.basescan.org/address/0x6b8F14421007FC49251F6B2d48071795A077B2D8) | 2026-11-25, `772e8f1608bcdf8bc966cb81ef27c7446c0677d0` (built from; transaction [`0x885578ae77e16c4428481f37b176d9562f223583f3201b5026e067e49ecfc031`](https://sepolia.basescan.org/tx/0x885578ae77e16c4428481f37b176d9562f223583f3201b5026e067e49ecfc031)) | carries #190: a Safe transaction with a nonzero `safeTxGas` lets its inner call fail without reverting the operation; replaced the same day by the instance of #191. Not for a mandate with a Safe |
| `p256ValidatorV1` | [`0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1`](https://sepolia.basescan.org/address/0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first owner-key validator |
| `p256ValidatorV2` | [`0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`](https://sepolia.basescan.org/address/0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2) | 2026-10-20, `96d56ada9969304afafdddc126129dd472febea0` | the fixes of the audit of 2026-10-20 |
| `p256SignerV1` | [`0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9`](https://sepolia.basescan.org/address/0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first agent-key signer |
| `p256SignerV2` | [`0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`](https://sepolia.basescan.org/address/0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E) | 2026-10-20, `96d56ada9969304afafdddc126129dd472febea0` | the fixes of the audit of 2026-10-20 |
| `p256RecoveryValidatorV1` | [`0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D`](https://sepolia.basescan.org/address/0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D) | 2026-10-20, `3a0126cbe21f4b2bf7ebb20fce5f98604078cd57` | the first recovery validator |
| `p256RecoveryValidatorV2` | [`0x63dd80Fc5E109A44fd179F85050487E02c5e6958`](https://sepolia.basescan.org/address/0x63dd80Fc5E109A44fd179F85050487E02c5e6958) | 2026-10-20, `3a0126cbe21f4b2bf7ebb20fce5f98604078cd57` | recorded in the same commit as `p256RecoveryValidatorV1`, which it superseded the same day |
| `safeNonceAssertV1` | [`0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279`](https://sepolia.basescan.org/address/0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279) | 2026-10-20, `96d56ada9969304afafdddc126129dd472febea0` | the first replay guard |
| `whitelistPaymasterV1` | [`0xe314e95bef9b891c48429aD127D79e601240BB52`](https://sepolia.basescan.org/address/0xe314e95bef9b891c48429aD127D79e601240BB52) | 2026-10-20, `0efbeec32d31d1e92333265d0042c1b49672e763` | the first sponsor paymaster |
| `whitelistPaymasterV2` | [`0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001`](https://sepolia.basescan.org/address/0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001) | 2026-10-20, `96d56ada9969304afafdddc126129dd472febea0` | owner [`0xDf52800CfeBc64951816F958c4E12fD68E4dCC22`](https://sepolia.basescan.org/address/0xDf52800CfeBc64951816F958c4E12fD68E4dCC22) |
| `demoCounterV1` | [`0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1`](https://sepolia.basescan.org/address/0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first demo target |

[V] First recorded: the commit that added the address to
`contracts/deployments/84532.json` (`git log -S <address>`); for
`agentPolicyV10`, which this record is the first to name, the commit it was
built from. Its code was compared on chain on 2026-11-25 with that build:
equal outside the immutable slots.

[V] The instances the redeploy replaced (`agentPolicyV9`, `p256ValidatorV2`,
`p256RecoveryValidatorV2`, `p256SignerV2`, `safeNonceAssertV1`,
`whitelistPaymasterV2`, `demoCounterV1`) are built from commit
`175acbf3a3127e804a45a3e4dd097165f0a4c922`: compared on chain on 2026-11-24
against a build of it (`docs/ARCHITECTURE.md`, Phase 1). Four contracts are
equal byte for byte: `P256Validator`, `P256RecoveryValidator`, `P256Signer`
and `SafeNonceAssert`. `AgentPolicy` and `WhitelistPaymaster` are equal
outside their immutable slots. `DemoCounter` was deployed before metadata was
turned off: its code is that build's followed by solc's metadata.

What the current instances change against them [V `git diff` and `git log`
of `contracts/src` from `175acbf3a3127e804a45a3e4dd097165f0a4c922` to
`60e773be7c7f071a4e5a69f84e7af3697092a4ef`]: every contract gains `VERSION`;
`P256Validator` and `P256Signer` take install data of the exact length only
(#154); `AgentPolicy` brings the budget per period and venues (#80), an x402
refund only of the token that was charged (#134), the venue's spender
refused as a target (#149), and then:
- a signed x402 authorization needs an expiry, and a Safe's delegatecall
  target is held to the allow-list (#169);
- a call made through Kernel's hook (`executeUserOp`) is judged as the call
  inside it (#172);
- no standing allowances: an allowance or an operator grant the agent gives
  must be withdrawn later in the same operation (#174, #185);
- a period's end bounded, a metered function allowed only on a token with a
  limit, and operator grants (ERC-721 and ERC-1155) held like allowances
  (#181);
- a guarded Safe's addresses read as whole words (#183);
- ERC-6909 grants held like allowances and ERC-777's operator grant refused
  (#185), and limits per ERC-6909 id (#187);
- a Safe transaction's `safeTxGas` and `baseGas` must be 0, as its
  `gasPrice` is, so that the Safe reverts with its inner call (#191, fixing
  #190).

### Contracts of others that the account uses

| Contract | Address | Whose |
|---|---|---|
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.basescan.org/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) | eth-infinitism's canonical deployment |
| Kernel v3.3 implementation | [`0xd6CEDDe84be40893d153Be9d467CD6aD37875b28`](https://sepolia.basescan.org/address/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) | ZeroDev; each account is a proxy to it |
| Kernel v3.3 factory | [`0x2577507b78c2008Ff367261CB6285d44ba5eF2E9`](https://sepolia.basescan.org/address/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) | ZeroDev; derives an account's address from its data and salt |
| FactoryStaker | [`0xd703aaE79538628d27099B8c4f621bE4CCd142d5`](https://sepolia.basescan.org/address/0xd703aaE79538628d27099B8c4f621bE4CCd142d5) | ZeroDev; staked at the EntryPoint, it creates accounts through Kernel's factory (#102) |
| GPv2Settlement | [`0x9008D19f58AAbD9eD0D60971565AA8510560ab41`](https://sepolia.basescan.org/address/0x9008D19f58AAbD9eD0D60971565AA8510560ab41) | CoW Protocol; its vault relayer [`0xC92E8bdf79f0507f65a392b0ab4667716BFE0110`](https://sepolia.basescan.org/address/0xC92E8bdf79f0507f65a392b0ab4667716BFE0110) takes the sold tokens [V `vaultRelayer()` read on 2026-11-25] |

## Sepolia (chain 11155111)

The chain the trading mandate was first tried on. The tables are written from
`contracts/deployments/11155111.json`.

### This project's contracts

| Contract | Address | What it is |
|---|---|---|
| `P256Validator` | [`0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63`](https://sepolia.etherscan.io/address/0x9b6f7A83e10F3360af6B34F672c0AC5295f72d63) | the owner key: the account's root validator |
| `P256RecoveryValidator` | [`0xb7a06e6c7B5cC9852578EF89f38d161C31218047`](https://sepolia.etherscan.io/address/0xb7a06e6c7B5cC9852578EF89f38d161C31218047) | the cold recovery key, granted only `changeRootValidator` |
| `P256Signer` | [`0xd88d25Ca3e042A28893781935756ee90Bc2d2769`](https://sepolia.etherscan.io/address/0xd88d25Ca3e042A28893781935756ee90Bc2d2769) | the agent key, as one Kernel permission |
| `AgentPolicy` | [`0xe52825D44396d72cA17adF0c0260d468e94F8C94`](https://sepolia.etherscan.io/address/0xe52825D44396d72cA17adF0c0260d468e94F8C94) | the agent's mandate: targets, caps, budget, window, payees, x402, a budget per period, orders through a venue's decoder, and limits per ERC-6909 id |
| `CowSwapDecoder` | [`0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a`](https://sepolia.etherscan.io/address/0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a) | reads a CoW Swap order for the policy |
| `SafeNonceAssert` | [`0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219`](https://sepolia.etherscan.io/address/0x29f600cBcdC5221a63bD5c88F4a75E20c5CBe219) | the replay guard of an agent's Safe transaction |
| `WhitelistPaymaster` | [`0x657792557C1D40f2Da031FD7aB277078D2c0a4cb`](https://sepolia.etherscan.io/address/0x657792557C1D40f2Da031FD7aB277078D2c0a4cb) | a gas sponsor with a budget per account; owner [`0x52370eE170c0E2767B32687166791973a0dE7966`](https://sepolia.etherscan.io/address/0x52370eE170c0E2767B32687166791973a0dE7966) |
| `DemoCounter` | [`0x29da894F3E456CAC92b3EC76710524E74411E99f`](https://sepolia.etherscan.io/address/0x29da894F3E456CAC92b3EC76710524E74411E99f) | a demo target, with no rights over anything |

Built from commit `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, every contract
at `VERSION` 0.1.0, with `contracts/script/Deploy.s.sol` and `REDEPLOY=true`.
The same addresses as on Base Sepolia: the same creation code.

Deployed on 2026-11-25 by `0x52370eE170c0E2767B32687166791973a0dE7966`,
each through the CREATE2 deployer, all eight transactions successful. The
chain runs Glamsterdam, so the gas limits were raised
([`REDEPLOY.md`](REDEPLOY.md)); `AgentPolicy`'s deployment used 36,840,068
gas.

| Contract | Transaction |
|---|---|
| `P256Validator` | [`0xe558cd8d13e4bf3f4f384ea280c0f04ac9ac9c4a0e1fd760fbe414a23dd55e7a`](https://sepolia.etherscan.io/tx/0xe558cd8d13e4bf3f4f384ea280c0f04ac9ac9c4a0e1fd760fbe414a23dd55e7a) |
| `P256RecoveryValidator` | [`0xc2c7d83f6f22be38668673eb72cf7af039190e1801ccb95805dd2f5ef260d051`](https://sepolia.etherscan.io/tx/0xc2c7d83f6f22be38668673eb72cf7af039190e1801ccb95805dd2f5ef260d051) |
| `P256Signer` | [`0x435e480d64f5a35cc3462bdc5d351e92851f56a0cb847a4f2e3b2187c6fa6a3d`](https://sepolia.etherscan.io/tx/0x435e480d64f5a35cc3462bdc5d351e92851f56a0cb847a4f2e3b2187c6fa6a3d) |
| `SafeNonceAssert` | [`0x57b39de67de42fabb71488813fdf337b0d3cbb0e2fb7b41c7657f968aaf38d0c`](https://sepolia.etherscan.io/tx/0x57b39de67de42fabb71488813fdf337b0d3cbb0e2fb7b41c7657f968aaf38d0c) |
| `AgentPolicy` | [`0xb9ef70388a7a9be68ac37a65834b9b55cd47ef610e303d22651ff7bb963208a4`](https://sepolia.etherscan.io/tx/0xb9ef70388a7a9be68ac37a65834b9b55cd47ef610e303d22651ff7bb963208a4) |
| `DemoCounter` | [`0x605bca9362a3f2195b432d94c893646ad66b5cddc8845ad362f577fbd967dd62`](https://sepolia.etherscan.io/tx/0x605bca9362a3f2195b432d94c893646ad66b5cddc8845ad362f577fbd967dd62) |
| `WhitelistPaymaster` | [`0xa0e7428b05f6f8bd435be3748e58d2f7d862d8ac507431c647414ba639e650c0`](https://sepolia.etherscan.io/tx/0xa0e7428b05f6f8bd435be3748e58d2f7d862d8ac507431c647414ba639e650c0) |
| `CowSwapDecoder` | [`0x9b6db47bf3edcf3f4d24203485bc9a9c85eff26b184267e9287efd991390f14c`](https://sepolia.etherscan.io/tx/0x9b6db47bf3edcf3f4d24203485bc9a9c85eff26b184267e9287efd991390f14c) |

[V] Each instance compared on chain on 2026-11-25 with the build of that
commit: the same result as on Base Sepolia, with CoW's domain separator on
this chain in the decoder, and the decoder's code hash
`0xe11511d23d679dd68a71be1cfd2d6714ba3fb10e077c4db6c4bf3fe96d21e47e`, the
one the phone's build names.

### Earlier instances, still recorded

| Key | Address | Why it was replaced |
|---|---|---|
| `agentPolicyV3` | [`0x2511FF556aa1534676A34F9B715232917e04FE5e`](https://sepolia.etherscan.io/address/0x2511FF556aa1534676A34F9B715232917e04FE5e) | it does not refuse a venue's spender as a target (#149); the redeploy from `60e773be7c7f071a4e5a69f84e7af3697092a4ef` carries that fix and `VERSION` |
| `agentPolicyV2` | [`0xb15700E18D058BF83f5d9D38b5407f214df5E410`](https://sepolia.etherscan.io/address/0xb15700E18D058BF83f5d9D38b5407f214df5E410) | it refunded an order's charge on the venue's word that the order was unfilled, and the venue lets a filled order's record be cleared |
| `agentPolicyV1` | [`0x5Cfa68d42e4245c9Ba71e6103D4E2D99F3E40b42`](https://sepolia.etherscan.io/address/0x5Cfa68d42e4245c9Ba71e6103D4E2D99F3E40b42) | a registration could outlive its budget period |
| `cowSwapDecoderV1` | [`0x085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0`](https://sepolia.etherscan.io/address/0x085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0) | the redeploy: `VERSION`, and the compiler settings pinned since (#123) |
| `p256ValidatorV1` | [`0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`](https://sepolia.etherscan.io/address/0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2) | the redeploy: `VERSION`, and install data of the exact length only (#154) |
| `p256RecoveryValidatorV1` | [`0x63dd80Fc5E109A44fd179F85050487E02c5e6958`](https://sepolia.etherscan.io/address/0x63dd80Fc5E109A44fd179F85050487E02c5e6958) | the redeploy: `VERSION`, and install data of the exact length only (#154) |
| `p256SignerV1` | [`0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`](https://sepolia.etherscan.io/address/0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E) | the redeploy: `VERSION`, and install data of the exact length only (#154) |
| `safeNonceAssertV1` | [`0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279`](https://sepolia.etherscan.io/address/0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279) | the redeploy: `VERSION` |
| `whitelistPaymasterV1` | [`0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001`](https://sepolia.etherscan.io/address/0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001) | the redeploy: `VERSION`; owner [`0xDf52800CfeBc64951816F958c4E12fD68E4dCC22`](https://sepolia.etherscan.io/address/0xDf52800CfeBc64951816F958c4E12fD68E4dCC22) |
| `demoCounterV1` | [`0x0F5912777DFd7E385c1896b68885d1CC229DF559`](https://sepolia.etherscan.io/address/0x0F5912777DFd7E385c1896b68885d1CC229DF559) | the redeploy: `VERSION` |

[V] `agentPolicyV3` was read from the chain on 2026-11-24: 20,133 bytes with
the keccak hash
`0xb7badf47dd8d0015de6128859c35990184d114aef0f790bc31d954e25f69a72a`, which is
the runtime code of commit `8904478693c020e40f676b5161c67a1faa39105f` with the
`SafeNonceAssert` address in its immutable slots. It was deployed in transaction
`0x8316c81d2fc68015872cb11d1291fc81bb3d76f15266358565475cb79936f49a`. The
other earlier instances were first recorded in commit
`6fd20fb65f3bc9dd4786405fedd08ce3f1fef1e8` (2026-11-21, `git log -S
<address>`) and were not compared on chain for this page. The validators,
the signer, the replay guard and the paymaster among them have the addresses
of Base Sepolia's instances of `175acbf3a3127e804a45a3e4dd097165f0a4c922`, so
the same creation code [I CREATE2 with the same deployer and salt].

That code does not refuse a venue's spender as a target (for CoW, the vault
relayer `0xC92E8bdf79f0507f65a392b0ab4667716BFE0110`): it marks only the
venue's contract and the decoder [V `_installTrading` at commit
`8904478693c020e40f676b5161c67a1faa39105f`]. The current `AgentPolicy` marks
the spender too (#149). On `agentPolicyV3` the phone refuses a mandate that
names the spender, and so does the CLI when the mandate's config trades at
that venue [V the tests `a_trading_mandate_the_build_cannot_vouch_for_is_refused`
in `mobile/owner-core` and `the_agent_never_targets_a_place_of_its_venues`
in `agent-signer`].

### Contracts of others that the account uses

| Contract | Address |
|---|---|
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) |
| Kernel v3.3 | [`0xd6CEDDe84be40893d153Be9d467CD6aD37875b28`](https://sepolia.etherscan.io/address/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) |
| Kernel's factory | [`0x2577507b78c2008Ff367261CB6285d44ba5eF2E9`](https://sepolia.etherscan.io/address/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) |
| The staked factory in front of it | [`0xd703aaE79538628d27099B8c4f621bE4CCd142d5`](https://sepolia.etherscan.io/address/0xd703aaE79538628d27099B8c4f621bE4CCd142d5) |
