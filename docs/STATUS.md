# Status: what runs today

**Status: it runs on Base Sepolia.** An account whose owner key and agent key
both live in a TPM 2.0 executed its first operation on 2026-10-20 — the agent
key, bound by `AgentPolicy`, incremented the demo counter; the operation was
built and submitted by `agent-signer`, with no bundler, paymaster or custodian
in between:
account [`0xEdB645B14e2f952C5784e34949b58F0826fBc9E9`](https://sepolia.basescan.org/address/0xEdB645B14e2f952C5784e34949b58F0826fBc9E9),
tx [`0x785332105fd8085d50e542ff9f677eba964399bbc0d71333ddd71fed03e669bb`](https://sepolia.basescan.org/tx/0x785332105fd8085d50e542ff9f677eba964399bbc0d71333ddd71fed03e669bb).

- Phase 0 — a signature produced inside a real TPM verifies on-chain (RIP-7212).
- Phase 1 — on ZeroDev Kernel v3.3 (ERC-7579): `P256Validator` makes the chip
  the account's root; `P256Signer` + `AgentPolicy` make it an *agent
  permission* bound by a call allow-list, value cap, budget and expiry.
- Phase 2 — `agent-signer` (Rust) derives the account, builds the
  UserOperation, signs its hash in the TPM and submits it through
  `EntryPoint.handleOps` itself.
- Phase 3 — `WhitelistPaymaster` sponsors listed accounts, so an agent
  account need not hold ETH at all (`demo --sponsored`,
  tx [`0xae73b53d17b74ad8c7b6d65f8cc98abd40c513a808b09764828dff8a3a5f2106`](https://sepolia.basescan.org/tx/0xae73b53d17b74ad8c7b6d65f8cc98abd40c513a808b09764828dff8a3a5f2106));
  the owner key rotates or revokes the agent's mandate in one root operation
  (tx [`0x4519a35b5acdc19ffe713326964b5214677825d11040684f9869adbd8b195370`](https://sepolia.basescan.org/tx/0x4519a35b5acdc19ffe713326964b5214677825d11040684f9869adbd8b195370));
  TPM keys can be sealed to the measured boot state (`key create --pcrs
  0,2,4,7`) and a sealed agent key ran on-chain
  (tx [`0xc8117420694a9c17d3c91a14df3ce70f00298d2bc0fcd38f55997c1bfc75db4b`](https://sepolia.basescan.org/tx/0xc8117420694a9c17d3c91a14df3ce70f00298d2bc0fcd38f55997c1bfc75db4b));
  operations can also go through an ERC-4337 bundler instead of our own
  `handleOps` — a public bundler accepted and included one
  (tx [`0xb42e30ae72ac8d676c33198b65ae85e8ef06936d15b28cda5832ed4cc0527675`](https://sepolia.basescan.org/tx/0xb42e30ae72ac8d676c33198b65ae85e8ef06936d15b28cda5832ed4cc0527675)).
- More hardware — the agent permission was rotated onto a key inside a
  **TROPIC01** open-architecture secure element, which then signed a
  sponsored operation
  (tx [`0x6c1060b43c1a40e3d123fe766adad914edccac8e9596cc1dc658617cf53622b5`](https://sepolia.basescan.org/tx/0x6c1060b43c1a40e3d123fe766adad914edccac8e9596cc1dc658617cf53622b5));
  the **Windows TPM** backend (CNG) ran on a Windows 11 PC and its signature
  is one of the test vectors; the **Apple Secure Enclave** backend ran on an
  M1 Mac — an account whose owner and agent keys both live in the enclave
  executed an agent operation
  (tx [`0xc431bafe3588431c82b96aac7318c3c4340e16be784322bba5d801f3a401300c`](https://sepolia.basescan.org/tx/0xc431bafe3588431c82b96aac7318c3c4340e16be784322bba5d801f3a401300c))
  and a root operation
  (tx [`0x547e4fa8caf1b5725f9043ece7df13f3e713c98107f1b1726ac24139674da40c`](https://sepolia.basescan.org/tx/0x547e4fa8caf1b5725f9043ece7df13f3e713c98107f1b1726ac24139674da40c)),
  and its signature is one of the test vectors.
- Safes — `AgentPolicy` v3 lets the agent drive a Safe its account owns
  (Olas / Jinn service Safes) and still judges the Safe transaction's
  *inner* call, or every leg of a MultiSend batch, against the mandate
  ([`docs/ERC1271.md`](ERC1271.md)).
- x402 payments — `AgentPolicy` v6 gives the agent a narrow ERC-1271: it
  vouches only for USDC payment authorizations the agent registered first,
  inside the mandate's token budget. An agent with its key in a TROPIC01
  paid an x402 API through the public x402.org facilitator
  (settlement tx [`0xd3535c28f33cc63de48733332e8c37c9ca9b2d559097b56b5d4b81e06379a31d`](https://sepolia.basescan.org/tx/0xd3535c28f33cc63de48733332e8c37c9ca9b2d559097b56b5d4b81e06379a31d))
  ([`docs/ERC1271.md`](ERC1271.md#x402--registered-authorizations-implemented-since-agentpolicy-v6)).
- Trading — the agent places orders at a venue within terms the owner set:
  a pair, a lowest price, a cap per order and a budget per period. On
  Sepolia an agent key sold 0.001 WETH for 47.258592 USDC through CoW Swap,
  under a mandate approved in the Android owner app
  (settlement tx [`0xc7cc5d07e3156edde4cb85ac264544f508f931e4f1fdaf1eb0811622a3f98fa0`](https://sepolia.etherscan.io/tx/0xc7cc5d07e3156edde4cb85ac264544f508f931e4f1fdaf1eb0811622a3f98fa0));
  the whole run, step by step:
  [`docs/TRADING_WALKTHROUGH.md`](TRADING_WALKTHROUGH.md).
- Protocols — an agent supplies to Aave V3 and withdraws from it under a
  mandate with a token limit and the pool's two compact calls, shown against
  the pool's own code on a fork of Base Sepolia; which calls of Aave,
  Compound, Lido and others can go on a mandate, and which never:
  [`docs/DAPPS.md`](DAPPS.md).
- Existing agent frameworks on top — Coinbase AgentKit, a Claude Code /
  OpenClaw skill, Jinn, Olas and ElizaOS, each run on Base Sepolia; the
  ElizaOS agent also pays for APIs with x402
  (tx [`0x344e94449df0a5fbb363136b8de4f02f4b78850992e7fc16352aaa10d46f1757`](https://sepolia.basescan.org/tx/0x344e94449df0a5fbb363136b8de4f02f4b78850992e7fc16352aaa10d46f1757);
  see [Examples](../README.md#examples)).

## Backends

| Backend | Platform | Status |
|---|---|---|
| `tpm` | Linux, TPM 2.0 (tss-esapi) | on-chain since phase 0; PCR-sealed keys |
| `windows-tpm` | Windows, TPM 2.0 via CNG | run on Windows 11; vector in the tests ([`docs/WINDOWS.md`](WINDOWS.md)) |
| `tropic01` | any, TROPIC01 USB DevKit | on-chain agent key ([`docs/TROPIC01.md`](TROPIC01.md)) |
| `yubikey-piv` | any, YubiKey 5 over PC/SC | owner key with PIN + touch per signature; attestation certificate written by the CLI, its chain to Yubico's root checked off-device by hand; root of the Base Sepolia account since 2026-11-02 ([`docs/YUBIKEY.md`](YUBIKEY.md)) |
| `secure-enclave` | macOS, Secure Enclave via CryptoKit | run on an Apple M1 Mac: hardware test, vector in the tests, owner + agent keys on-chain — sponsored, via a bundler, x402, recovery drill ([`docs/SECURE_ENCLAVE.md`](SECURE_ENCLAVE.md)) |
| `software` | any | dev/CI only |
