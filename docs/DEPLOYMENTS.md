# Deployed contracts

agent-keys runs on test networks only and has had no external audit
([`docs/FAQ.md`](FAQ.md#is-it-audited)). This page lists where its contracts
are deployed, chain by chain, with every earlier instance that is still
recorded.

The record itself is `contracts/deployments/<chainId>.json`: the CLI reads
it, the phone's build embeds Base Sepolia's, and
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
  file records the compiler settings that build its current instances:
  `solc` 0.8.38 and `evmVersion` cancun [V `contracts/foundry.toml`].
- **Earlier instances stay recorded** under versioned names (`agentPolicyV1`,
  …). A permission installed with one keeps pointing there until the owner
  rotates it.

To check an instance against the source:

```sh
cd contracts
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

[V] Compared on chain on 2026-11-24 against a build of this source
(`docs/ARCHITECTURE.md`, Phase 1). Four contracts are equal byte for byte:
`P256Validator`, `P256RecoveryValidator`, `P256Signer` and `SafeNonceAssert`.
`AgentPolicy` and `WhitelistPaymaster` are equal outside their immutable
slots. `DemoCounter` was deployed before metadata was turned off: its code is
this build's followed by solc's metadata.

### Earlier instances, still recorded

| Name in the file | Address | First recorded | With |
|---|---|---|---|
| `agentPolicyV1` | [`0x12854c1C0ce3F7506065111f9d8f73EF19CeD1c7`](https://sepolia.basescan.org/address/0x12854c1C0ce3F7506065111f9d8f73EF19CeD1c7) | 2026-10-20, `2759d0e` | the first instance, with the agent account of phase 2 |
| `agentPolicyV2` | [`0xEA80a8bd8a02930b1218fE6cDeF5fE712C52F6C0`](https://sepolia.basescan.org/address/0xEA80a8bd8a02930b1218fE6cDeF5fE712C52F6C0) | 2026-10-20, `791ac53` | recorded in the same commit as `agentPolicyV3`, which superseded it the same day |
| `agentPolicyV3` | [`0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24`](https://sepolia.basescan.org/address/0x460fD3bcfE23985Bcd5E05bbdb68Ec1789529E24) | 2026-10-20, `791ac53` | Safe transactions and MultiSend batches held to the mandate |
| `agentPolicyV4` | [`0x3f590A5879B5f28466b6DAeF69FfA9777f84b424`](https://sepolia.basescan.org/address/0x3f590A5879B5f28466b6DAeF69FfA9777f84b424) | 2026-10-20, `96d56ad` | the fixes of the audit of 2026-10-20 |
| `agentPolicyV5` | [`0xe0f3C8B707Dceff7299DD8E95D57b30aFE0B7c2d`](https://sepolia.basescan.org/address/0xe0f3C8B707Dceff7299DD8E95D57b30aFE0B7c2d) | 2026-10-20, `b0734b1` | mandate time windows |
| `agentPolicyV6` | [`0x8347dBC3d7A71DAFDeED5975ce85638494865F73`](https://sepolia.basescan.org/address/0x8347dBC3d7A71DAFDeED5975ce85638494865F73) | 2026-10-21, `662d77c` | x402 payments from the agent account |
| `agentPolicyV7` | [`0xdd544A6F0220778Fff16F51B468656e73E32ae85`](https://sepolia.basescan.org/address/0xdd544A6F0220778Fff16F51B468656e73E32ae85) | 2026-11-10, `0e368bd` | the forbidden-target guard (#11) |
| `agentPolicyV8` | [`0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95`](https://sepolia.basescan.org/address/0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95) | 2026-11-20, `933b3d2` | payee lists and the per-operation token cap (#66, #76, #79) |
| `p256ValidatorV1` | [`0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1`](https://sepolia.basescan.org/address/0xDe1Af9b0Fcc5Dda03380b069F26EA2bfbd3c24D1) | 2026-10-20, `2759d0e` | the first owner-key validator |
| `p256SignerV1` | [`0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9`](https://sepolia.basescan.org/address/0x68544284bfDbbd6bDB9F6A1D80D05C387015daA9) | 2026-10-20, `2759d0e` | the first agent-key signer |
| `p256RecoveryValidatorV1` | [`0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D`](https://sepolia.basescan.org/address/0xe1dcC2CC7F5D01931d8Ee2c00A8c2f555b0dA64D) | 2026-10-20, `3a0126c` | the first recovery validator |
| `whitelistPaymasterV1` | [`0xe314e95bef9b891c48429aD127D79e601240BB52`](https://sepolia.basescan.org/address/0xe314e95bef9b891c48429aD127D79e601240BB52) | 2026-10-20, `0efbeec` | the first sponsor paymaster |

[V] First recorded: the commit that added the address to
`contracts/deployments/84532.json` (`git log -S <address>`).

### Contracts of others that the account uses

| Contract | Address | Whose |
|---|---|---|
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.basescan.org/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) | eth-infinitism's canonical deployment |
| Kernel v3.3 implementation | [`0xd6CEDDe84be40893d153Be9d467CD6aD37875b28`](https://sepolia.basescan.org/address/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) | ZeroDev; each account is a proxy to it |
| Kernel v3.3 factory | [`0x2577507b78c2008Ff367261CB6285d44ba5eF2E9`](https://sepolia.basescan.org/address/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) | ZeroDev; derives an account's address from its data and salt |
| FactoryStaker | [`0xd703aaE79538628d27099B8c4f621bE4CCd142d5`](https://sepolia.basescan.org/address/0xd703aaE79538628d27099B8c4f621bE4CCd142d5) | ZeroDev; staked at the EntryPoint, it creates accounts through Kernel's factory (#102) |

