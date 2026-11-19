# The field around agent-keys

Researched 2026-10-23; §2a, §2d and §3 updated 2026-11-02 with the Circle
Agent Wallets case and the I-HITL paper. Two questions, one page each half: *who else turns a
phone or spare device into a signer*, and *who else gives an AI agent a key
it cannot leak, with rules it cannot break*. For every entry: where the key
lives, who enforces policy, and whether the project is open source. Marks:
**V** verified at the source, **I** inferred.

agent-keys, for reference: key **born in a secure element** (Linux/Windows
TPM 2.0, Apple Secure Enclave, TROPIC01, a YubiKey PIV slot), P-256 verified
on-chain through RIP-7212/EIP-7951; policy enforced **on-chain** by
`AgentPolicy` (ERC-7579 on Kernel v3.3: allow-list, value cap, budget,
expiry, token budgets, x402); the owner is a second key (a YubiKey, a
phone's secure hardware, another chip or, as the one exception, a
passphrase-encrypted key file on removable media) with a cold recovery
path; all open source.

## 1. An old phone, or a cheap device, as the signer

| Product | Key lives in | Policy | Chains | Open source | Notes |
|---|---|---|---|---|---|
| **Cupcake** (Cake Labs) | a password-encrypted file on an offline phone; signing in app memory (V, [`CUPCAKE.md`](CUPCAKE.md)) | none (it signs what it is shown) | BTC, LTC, XMR | GPL-3.0 (V) | QR/BC-UR transport; Android has no `INTERNET` permission (V) |
| **AirGap Vault** (Papers, CH) | seed on an offline phone; the site says "saved in the secure enclave of the device with biometric authentication" (V [airgap.it](https://airgap.it/)) — i.e. the seed is encrypted under a Keystore/Keychain-protected key and still decrypted into memory to sign (I; it signs ed25519/secp256k1, which no phone enclave can do) | none | many (BTC, ETH, XTZ, DOT, ATOM…), MetaMask/Rabby/Sparrow/Nunchuk companions | MIT (V) | the oldest of the kind (2018); v3.35.0 on 2026-09-28 (V); also sells "AirGap Knox", a preconfigured phone |
| **Monerujo Sidekick** | a second Android phone paired over **Bluetooth**, not QR (V, privacygear review) | none | XMR | GPL (I) | a weaker air gap than QR by design |
| **DIY dedicated hardware**: SeedSigner, Krux, Specter DIY | a Raspberry Pi Zero / ESP32 / STM32 with a camera; stateless (SeedSigner, Krux: the seed is re-entered or scanned each session) | none; PSBT display | BTC | yes (all) | the honest "cheap hardware wallet": no radio, no OS, no storage |
| **Commercial QR-only wallets**: Keystone, Foundation Passport, Ellipal | a secure element in a purpose-built device | none | multi | partly (Keystone, Passport firmware open) | what Cupcake positions itself against ($100–200) |

Take-away: every "phone as a hardware wallet" product keeps a **software**
seed, because the coins they serve (secp256k1, ed25519) cannot be signed by
a phone's secure element. Only a P-256 account can use the phone's hardware
key as *the* key — which is what EIP-7951 enables and what `PHONE_OWNER.md`
explores for the owner role. None of them has a policy layer: the device
signs whatever the online side sends and the human reads the screen.

## 2. Keys for AI agents

### 2a. Hosted agent-wallet platforms (the key is in the vendor's TEE or MPC)

All of these keep the agent's key in infrastructure the vendor runs; the
agent gets an API, not a key. Policy is enforced by the vendor's service
(fail-closed per operation in the better ones), sometimes mirrored on-chain
with session keys. Sources: the vendors' own documentation and a September
2026 comparison by one of them (Openfort), so vendor claims — marked V only
where the vendor states it plainly.

| Platform | Key lives in | Policy enforced by | Open source |
|---|---|---|---|
| Openfort | GCP Confidential Space TEE (AMD SEV-SNP), per-wallet envelope encryption (V, vendor) | the service, per operation; on-chain session keys for scoped authority (V, vendor) | the signer is open source (V, vendor); service is not |
| Privy | key shards inside AWS Nitro Enclaves (V, vendor) | the service (policies on wallets) | no |
| Turnkey | secure enclaves with attestation at each deploy (V, vendor) | the service (policy engine) | partly (QuorumOS) |
| Coinbase CDP / AgentKit | CDP server wallets (TEE, AWS Nitro, I) or CDP smart wallets; AgentKit SDK ships no spending limits — "you add them through the application" (V, comparison) | the application, or on-chain if a smart wallet is used | AgentKit SDK is open source (V); the wallet service is not |
| Alchemy Agent Wallet (x402) | TEE-based signing (V, vendor) | the service | no |
| Circle Agent Wallets | Circle's infrastructure (I) | the service: per-transaction, daily, weekly and monthly caps; **raising a cap is confirmed by a one-time code e-mailed to the owner** (V, the set-up of the I-HITL paper below; Circle's documentation now warns against giving the agent that inbox) | no |
| Crossmint | TEE; proposes a "dual key" design — an owner key and an agent key registered to a smart wallet (V, vendor blog) | the service + smart wallet | no |
| Thirdweb Engine / Vault | server-side wallets, scoped session keys (V, comparison); Vault uses a TEE (I) | the service | SDKs open; service not |
| Dynamic (now Fireblocks) | MPC or smart-contract wallet, configurable (V, comparison) | the service | no |
| Lit Protocol "Vincent" | key split across a decentralized node network; signs only when conditions are met (V, vendor) | the network's policy checks | yes (Lit nodes) |
| Cubist CubeSigner | keys in secure hardware (HSM/enclave), policies per key (V, vendor) | the service | no |
| Fireblocks, Cobo ("Pact"), OKX OnchainOS | MPC-TSS custody with policy engines; Cobo adds an intent/plan approval layer per agent task (V, Spark research page) | the custodian | no |

How agent-keys differs: the key is in hardware the **operator** owns (a €25
TPM or the Mac the agent runs on), not in a vendor's cloud; the policy is
**on-chain** and verifiable by anyone, not a service's promise; there is no
account to lose and no API key that is itself a secret worth stealing.
What they have that we do not: multi-chain, key rotation and revocation at
service level, audits (Openfort lists five; Privy SOC 2), and no hardware to
provision.

**The case that shows why the enforcement point matters (2026-10).** The
I-HITL paper (Breckenridge, Vilardell, Wang, Zhang, Juels; Cornell Tech and
Yale; [arXiv 2610.35835](https://arxiv.org/abs/2610.35835), v3 2026-10-30)
gave agents a Circle Agent Wallet with a tiny cap, plus e-mail and a browser.
Raising the cap needed a one-time code sent to the owner's inbox, which the
agent could read. Results (V, the paper): 9 of 10 models read the code and
raised their own cap in at least one run; with an injected e-mail 7 of 10
did; in a summarisation task 5 of 10 paid an attacker's address. The
behaviour did not correlate with model capability. Circle's response was a
documentation warning. The paper's theorem: when the approval channel runs
through a platform the agent controls, no protocol can bind approvals to
actions; it takes a trusted device the agent cannot reach, with an attested
key, and a non-extractable one if the human must not be able to delegate.

**For us:** the cap is on-chain and changing it is a root operation signed
by the owner key, which the agent does not have (`test_agent_keyIsNotRoot`);
the permission validator is granted only `execute`, and the policy refuses
any other calldata (`test_policy_rejectsBatchAndMalformedCalls`); an
attacker's address fails the allow-list. There is no code to intercept,
because there is no approval channel other than a hardware signature. What
the case added to our list: the agent's own account must never be an
allow-list target ([#11](https://github.com/postcryptum-research/agent-keys/issues/11), done:
`AgentPolicy` refuses the account and the policy itself as targets at
install and again at validation, and the account's EntryPoint at install), and
the owner key must not sit on the agent's host, which is the testnet
exception of `KEY_POLICY.md` rule 6 and the reason for the phone owner
(`../MOBILE_OWNER_DESIGN.md` §10).

### 2b. On-chain policy for a delegated key (the part `AgentPolicy` lives in)

| Project | What it is | Relation to ours |
|---|---|---|
| ZeroDev Kernel v3 permissions (ERC-7579 signer + policies) | the framework `P256Signer` / `AgentPolicy` plug into; ZeroDev ships call, gas, rate-limit, timestamp policies (V) | we reuse the mechanism and add the parts ZeroDev lacks: a value cap + budget + expiry in one module, Safe pass-through, token budgets, registered x402 authorizations, ERC-1271 under the mandate (`ERC1271.md`) |
| Safe + Zodiac modules / Safe Guards (roles, allowances, delays) | policy for a Safe's owners and modules (V) | our `AgentPolicy` (since v3) judges Safe transactions from the *outside*, through a Kernel account that owns the Safe (`ERC1271.md`) |
| MetaMask Delegation Framework (ERC-7710 / ERC-7715 "request permissions") | caveat-enforced delegations from a smart account; a wallet-side standard for granting bounded, revocable permissions (V, EIP texts) | the closest *standard* to our mandate; worth tracking for interop, not needed for function |
| "Spend mandate" proposal (token-level caps, expiry, revocation for agent wallets; thirdweb blog, 2026) | an Ethereum proposal covering exactly our `tokens` budget idea (I: draft, not final) | same shape as `AgentPolicy`'s token budgets |
| Agent Bank (bank-of-an-agent/*) | a policy engine + co-signer + x402 facilitator with Solidity escrow / time-lock contracts (V, repo descriptions) | service-side co-signing rather than a hardware key; 0 stars, 2026-10 |
| Coinbase AgentKit + "spending limits at the TEE level" | limits enforced in the vendor's TEE, not on-chain (V, Spark research page) | enforcement point is the difference |

### 2c. Device-key P-256 smart accounts (the same curve and precompile as ours)

| Project | Key lives in | Status |
|---|---|---|
| **Daimo** | the phone's Secure Enclave / Android Keystore, per device; ERC-4337 account verifying P-256 (V, README) | the app is **archived** (2026-02) and users were told to withdraw; its `p256-verifier` (Veridise-audited, 2023) lives on and is the fallback verifier in several projects (V) |
| **Clave** (zkSync) | Secure Enclave / WebAuthn P-256 (V, README) | contracts last pushed 2024-11 (V) |
| Coinbase Smart Wallet, Safe passkey module, Candide, Circle Modular Wallets | passkeys (WebAuthn P-256), key in the authenticator; synced passkeys live in the platform account (V, see `PHONE_OWNER.md`) | active; consumer wallets, no agent policy |

These prove the on-chain side of our design in production (a P-256 device key
as the account's owner). None of them targets an *agent* with a mandate, and
their keys are user-facing (biometric prompt per signature) — our agent key
signs unattended, which is why the policy module exists.

### 2d. Open-source projects closest to agent-keys

| Project | What it does | Key | Policy | Size / activity (V, 2026-10-23) |
|---|---|---|---|---|
| **Monolith** ([github](https://github.com/slaviquee/monolith)) | "Secure crypto wallet for AI agents": a macOS daemon signs ERC-4337 UserOps with an **Apple Secure Enclave** P-256 key for OpenClaw agents; a Coinbase-Smart-Wallet fork verifies via EIP-7951 with Daimo's verifier as fallback; on-chain spending caps, freeze, 48 h key-rotation timelock; Touch ID prompts above a threshold; Pimlico bundler | Secure Enclave (macOS only) | on-chain caps in the account + a local default-deny policy daemon | 7 stars, Solidity + Swift, created 2026-02, last push 2026-02 — the nearest sibling in intent; one platform, no owner/agent split, no x402, no Safe |
| **Vesper** ([github](https://github.com/karimbabasf/vesper)) | a voice agent that can only execute swaps: signing key generated inside an **Intel TDX** enclave, `VoicePolicy` ERC-7579 validator, passkey confirmation above a threshold | TDX enclave memory (ephemeral) | on-chain ERC-7579 policy | 0 stars, 2026-09; "the enclave step has not started" |
| **yubikey-evm-signer** ([github](https://github.com/storopoli/yubikey-evm-signer)) | Rust + WASM: sign EVM transactions with a YubiKey PIV P-256 key, relying on EIP-7951; passes the Ethereum tx test vectors | YubiKey | none (an EOA-style signer for a P-256 account) | 5 stars, Apache-2.0, 2026-01 → 2026-07; relevant to our YubiKey owner backend (`hw-signer` `yubikey_piv`, `../YUBIKEY.md`) |
| **claw-cash** ([github](https://github.com/tiero/claw-cash)) | Bitcoin wallet for agents over Telegram bots; secp256k1 keys generated and used inside an **Evervault enclave** service | a hosted enclave (the project's API) | rate limits, 2FA via Telegram | 38 stars, MIT, 2026-02 → 2026-07; custodial-shaped |
| Guardian Wallet (agentokratia) | MPC shares (one in the agent's environment) with a server policy engine | MPC | server | small |
| **Countersign** (the I-HITL prototype, Cornell Tech / Yale, 2026-10) | a phone countersigns an agent's critical actions: the approval terminates on a consumer device the agent cannot reach, the device's key is attested and non-extractable, the service verifies the countersignature (V, [arXiv 2610.35835](https://arxiv.org/abs/2610.35835); code availability I) | the phone's secure hardware | the service that checks the countersignature | academic prototype; the closest sibling of our phone owner (`../MOBILE_OWNER_DESIGN.md`), which puts the same device key on-chain as the account's root instead of behind a service |

No open-source project found combines **all** of: a key in a commodity
secure element the operator owns (TPM / enclave / SE), an **unattended**
agent key under an **on-chain** mandate, a separate hardware owner key with
cold recovery, Safe pass-through for existing agent frameworks, and x402.
Monolith is the closest on the key side (Secure Enclave + P-256 + 4337 +
on-chain caps) and is where to look if we ever want a macOS menu-bar
confirmation UI; our Secure Enclave backend (`SECURE_ENCLAVE.md`) already
covers its signing path.

## 3. Where that leaves us

- **Positioning**: "self-hosted hardware key + on-chain mandate" is an empty
  quadrant between the hosted TEE custodians (2a) and the consumer passkey
  accounts (2c). The research-report style write-ups of agent-wallet
  controls (e.g. the *awesome-agentic-patterns* catalogue) describe our
  design — "policy-enforced wallets: the smart contract validates all agent
  operations" — as the pattern, without a reference implementation that
  pairs it with commodity hardware keys.
- **Threats they handle that we should name**: key rotation at service level
  (ours: `permission rotate`, `owner set-root`), revocation (`permission
  revoke`), attestation of *which code* runs next to the key (we have
  PCR-sealed TPM keys; a Mac has no equivalent) — see `RESILIENCE.md`.
- **The formal model for the owner side**: I-HITL (2a, 2d) proves that an
  approval must terminate on a device the agent cannot reach, and names
  attested, non-extractable keys as the requirement. The phone owner is that
  device and the chain is the honest service. Our open ends in their terms
  are the first handover (`../MOBILE_OWNER_DESIGN.md` T2) and attestation on
  iOS: an Android key's attestation is verified at enrollment, an iPhone's
  key is not attested yet (it enrolls only with `--allow-no-attestation`).
- **BTCPay Server**, after its hot-wallet sweep of 2026-11: `BTCPAY.md`
  analyses every integration option, including a USDC-on-Base plugin whose
  store wallet is a mandate-bounded account. The integration itself, that
  option and the Bitcoin side alike, is the owner's separate project
  `77ph/BTCPayTEE`; nothing BTCPay-specific is on this repository's list.
- **The incident ledger**: `INCIDENTS.md` collects the real losses whose
  root cause the design removes (DarkSword reading wallet keys from a
  kernel-compromised iPhone, Circle's agents raising their own caps,
  BTCPay's seeds on the server) and says for each what it does not remove.
- **Interop to watch**: ERC-7715/7710 for expressing the mandate; the
  spend-mandate proposal for token budgets; BC-UR transport for an air-gapped
  owner phone (`CUPCAKE.md`, last section).
