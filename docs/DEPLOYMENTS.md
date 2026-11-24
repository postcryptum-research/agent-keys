# Deployed contracts

agent-keys runs on test networks only and has had no external audit
([`docs/FAQ.md`](FAQ.md#is-it-audited)). This page lists where its contracts
are deployed, chain by chain, with every earlier instance that is still
recorded.

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
- **No metadata in the bytecode.** `bytecode_hash = "none"` and
  `cbor_metadata = false`, so comments and paths do not move an address. Each
  file records the compiler settings its current instances were built with:
  `solc` 0.8.38 and `evmVersion` cancun [V `contracts/foundry.toml`].
- **Master moves ahead of the instances.** Every contract carries
  `string public constant VERSION`, 0.1.0 until the first audited release.
  The instances listed here predate it: master's source no longer builds
  them, the commit named with each table does.
- **Earlier instances stay recorded** under versioned names (`agentPolicyV1`,
  …). A permission installed with one keeps pointing there until the owner
  rotates it.

To check an instance against the commit it was built from:

```sh
git checkout <commit> && cd contracts
forge inspect AgentPolicy deployedBytecode     # the build
cast code <address> --rpc-url <chain's RPC>   # the chain
```

The two are equal outside a contract's immutable slots. `AgentPolicy`'s hold
the `SafeNonceAssert` address, `WhitelistPaymaster`'s the EntryPoint.

## Base Sepolia (chain 84532)

### This project's contracts

| Contract | Address | What it is |
|---|---|---|
| `P256Validator` | [`0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`](https://sepolia.basescan.org/address/0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2) | the owner key: the account's root validator |
| `P256RecoveryValidator` | [`0x63dd80Fc5E109A44fd179F85050487E02c5e6958`](https://sepolia.basescan.org/address/0x63dd80Fc5E109A44fd179F85050487E02c5e6958) | the cold recovery key, granted only `changeRootValidator` |
| `P256Signer` | [`0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`](https://sepolia.basescan.org/address/0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E) | the agent key, as one Kernel permission |
| `AgentPolicy` | [`0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2`](https://sepolia.basescan.org/address/0x12b7E79974CC4F4181a40Aa11f9d3170018ae0E2) | the agent's mandate: targets, caps, budget, window, payees, x402 |
| `SafeNonceAssert` | [`0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279`](https://sepolia.basescan.org/address/0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279) | the replay guard of an agent's Safe transaction |
| `WhitelistPaymaster` | [`0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001`](https://sepolia.basescan.org/address/0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001) | a gas sponsor with a budget per account; owner [`0xDf52800CfeBc64951816F958c4E12fD68E4dCC22`](https://sepolia.basescan.org/address/0xDf52800CfeBc64951816F958c4E12fD68E4dCC22) |
| `DemoCounter` | [`0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1`](https://sepolia.basescan.org/address/0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1) | a demo target, with no rights over anything |

[V] Built from commit `175acbf3a3127e804a45a3e4dd097165f0a4c922`: compared on chain on 2026-11-24 against a
build of it (`docs/ARCHITECTURE.md`, Phase 1). Four contracts are equal byte for byte:
`P256Validator`, `P256RecoveryValidator`, `P256Signer` and `SafeNonceAssert`.
`AgentPolicy` and `WhitelistPaymaster` are equal outside their immutable
slots. `DemoCounter` was deployed before metadata was turned off: its code is
that build's followed by solc's metadata.

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
| `p256ValidatorV1` | [`0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1`](https://sepolia.basescan.org/address/0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first owner-key validator |
| `p256SignerV1` | [`0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9`](https://sepolia.basescan.org/address/0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9) | 2026-10-20, `2759d0e3a06505a5d5d1d44aae95ef050b7cc814` | the first agent-key signer |
| `p256RecoveryValidatorV1` | [`0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D`](https://sepolia.basescan.org/address/0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D) | 2026-10-20, `3a0126cbe21f4b2bf7ebb20fce5f98604078cd57` | the first recovery validator |
| `whitelistPaymasterV1` | [`0xe314e95bef9b891c48429aD127D79e601240BB52`](https://sepolia.basescan.org/address/0xe314e95bef9b891c48429aD127D79e601240BB52) | 2026-10-20, `0efbeec32d31d1e92333265d0042c1b49672e763` | the first sponsor paymaster |

[V] First recorded: the commit that added the address to
`contracts/deployments/84532.json` (`git log -S <address>`).

### Contracts of others that the account uses

| Contract | Address | Whose |
|---|---|---|
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.basescan.org/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) | eth-infinitism's canonical deployment |
| Kernel v3.3 implementation | [`0xd6CEDDe84be40893d153Be9d467CD6aD37875b28`](https://sepolia.basescan.org/address/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) | ZeroDev; each account is a proxy to it |
| Kernel v3.3 factory | [`0x2577507b78c2008Ff367261CB6285d44ba5eF2E9`](https://sepolia.basescan.org/address/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) | ZeroDev; derives an account's address from its data and salt |
| FactoryStaker | [`0xd703aaE79538628d27099B8c4f621bE4CCd142d5`](https://sepolia.basescan.org/address/0xd703aaE79538628d27099B8c4f621bE4CCd142d5) | ZeroDev; staked at the EntryPoint, it creates accounts through Kernel's factory (#102) |

## Sepolia (chain 11155111)

The chain the trading mandate is tried on. The tables are written from
`contracts/deployments/11155111.json`.

### This project's contracts

| Contract | Address | What it is |
|---|---|---|
| `P256Validator` | [`0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2`](https://sepolia.etherscan.io/address/0xdA4cd5c37a5B888826A7A9e09dF6A9033A1550c2) | the owner key: the account's root validator |
| `P256RecoveryValidator` | [`0x63dd80Fc5E109A44fd179F85050487E02c5e6958`](https://sepolia.etherscan.io/address/0x63dd80Fc5E109A44fd179F85050487E02c5e6958) | the cold recovery key, granted only `changeRootValidator` |
| `P256Signer` | [`0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E`](https://sepolia.etherscan.io/address/0xa19e6061b1C193573e5fe46c39363FfDd5CCA22E) | the agent key, as one Kernel permission |
| `AgentPolicy` | [`0x2511FF556aa1534676A34F9B715232917e04FE5e`](https://sepolia.etherscan.io/address/0x2511FF556aa1534676A34F9B715232917e04FE5e) | the agent's mandate, with a budget per period and orders through a venue's decoder; an order's charge is not refunded |
| `CowSwapDecoder` | [`0x085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0`](https://sepolia.etherscan.io/address/0x085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0) | reads a CoW Swap order for the policy |
| `SafeNonceAssert` | [`0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279`](https://sepolia.etherscan.io/address/0xC14AbFF54D40f4DAf665391E0B7079bd53EB8279) | the replay guard of an agent's Safe transaction |
| `WhitelistPaymaster` | [`0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001`](https://sepolia.etherscan.io/address/0x50Ab706dA586895D5775a1e51DcF1a66eAaAE001) | a gas sponsor with a budget per account; owner [`0xDf52800CfeBc64951816F958c4E12fD68E4dCC22`](https://sepolia.etherscan.io/address/0xDf52800CfeBc64951816F958c4E12fD68E4dCC22) |
| `DemoCounter` | [`0x0F5912777DFd7E385c1896b68885d1CC229DF559`](https://sepolia.etherscan.io/address/0x0F5912777DFd7E385c1896b68885d1CC229DF559) | a demo target, with no rights over anything |

[V] `AgentPolicy` was read from the chain on 2026-11-24: 20,133 bytes with
the keccak hash
`0xb7badf47dd8d0015de6128859c35990184d114aef0f790bc31d954e25f69a72a`, which is
the runtime code of commit `8904478693c020e40f676b5161c67a1faa39105f` with the
`SafeNonceAssert` address in its immutable slots. It was deployed in transaction
`0x8316c81d2fc68015872cb11d1291fc81bb3d76f15266358565475cb79936f49a`. The
other rows are the file's record and were not compared again for this page.

### Earlier instances, still recorded

| Key | Address | Why it was replaced |
|---|---|---|
| `agentPolicyV2` | [`0xb15700E18D058BF83f5d9D38b5407f214df5E410`](https://sepolia.etherscan.io/address/0xb15700E18D058BF83f5d9D38b5407f214df5E410) | it refunded an order's charge on the venue's word that the order was unfilled, and the venue lets a filled order's record be cleared |
| `agentPolicyV1` | [`0x5Cfa68d42e4245c9Ba71e6103D4E2D99F3E40b42`](https://sepolia.etherscan.io/address/0x5Cfa68d42e4245c9Ba71e6103D4E2D99F3E40b42) | a registration could outlive its budget period |

### Contracts of others that the account uses

| Contract | Address |
|---|---|
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) |
| Kernel v3.3 | [`0xd6CEDDe84be40893d153Be9d467CD6aD37875b28`](https://sepolia.etherscan.io/address/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) |
| Kernel's factory | [`0x2577507b78c2008Ff367261CB6285d44ba5eF2E9`](https://sepolia.etherscan.io/address/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) |
| The staked factory in front of it | [`0xd703aaE79538628d27099B8c4f621bE4CCd142d5`](https://sepolia.etherscan.io/address/0xd703aaE79538628d27099B8c4f621bE4CCd142d5) |
