# The agent config file

`agent-signer` reads one JSON file per agent permission — for example
`signer/agent.base-sepolia.json`, `signer/agent.tropic01.base-sepolia.json`,
`signer/agent.window-demo.base-sepolia.json`. This document lists every
field, its syntax and allowed values, and — just as important — how the file
relates to what the smart contracts enforce.

## The one rule: the file is intent, the chain is state

**Editing the file changes nothing on-chain.** The account enforces only what
was written into the contracts by an operation signed with the **owner** key
(or, after a recovery, the recovery key). The file is read:

- by the **owner**, as the description of what to install — the next
  `permission rotate` / `permission add` / `owner add-recovery` writes it
  on-chain, and only then;
- by the **agent**, to know which key to sign with, which permission it acts
  under (`permissionId`) and which account it acts for (`account`).

So a file edited on the agent's machine — by mistake or by malware — cannot
widen the agent's rights: raise `budget` to 1,000 ETH or add a target to
`allow`, and every operation outside the installed mandate is still refused
on-chain. What a wrong file *can* do is break the agent's own operations
(a wrong key or permission id makes them fail), or, on the owner's machine,
get installed by the next owner operation — check with `permission show`
and, for `permission rotate` / `permission add` (the two commands that have
it), `--dry-run` before signing one.

To see what the chain actually enforces for a file's permission, field by
field next to the file:

```sh
agent-signer permission show --agent my-agent.json --env-file .env
```

```
  ok agent key       chain and config: fingerprint BPQBJ-WZ7L7-7AHTA-QCCMZ
                  x = 0x2f23ebb1c38db28363df39984086922a0585f3fa7fd315d8925ebd1663548c9f
                  y = 0x689bdaa9d3c18660d3666e2e507f0bb1a485d2c002b1129f5a0c1a20d6ef51c9
policy module:  0x3f590A5879B5f28466b6DAeF69FfA9777f84b424
  ok validUntil      chain 1795046400 / config 1795046400
DIFF budget          chain 3000000000000000 / config 999000000000000000000
DIFF allow           0x000000000000000000000000000000000000dEaD 0x00000000  — in the config, NOT allowed on chain
```

(`DIFF` lines here come from a deliberately edited copy: the chain kept its
values; the key is the software key of the local-chain tests.) A key that
differs is shown twice, `chain:` and `config:`, each whole. `account status`
and `owner status` show the account, its balances and its root / recovery
keys the same way.

**Every command shows a public key the same way**: its fingerprint, then
`x` and `y` in full, never cut
([#115](https://github.com/postcryptum-research/agent-keys/issues/115)).
That holds for `permission show` (the agent key), `owner status` (`root
key:` and, when one is installed, `recovery key:`), `key show` (a
`fingerprint` field beside `x` and `y`), `key check`, and the refusals that
name a key that does not match. So any two of them can be compared: the
root key with `key show` of the owner's device, the recovery key with `key
show --keyfile` of the recovery file, and either with the fingerprint a
phone shows before a key is deleted there
([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md) §5.4).

## Example

```json
{
  "deployments": "../contracts/deployments/84532.json",
  "owner": { "tpm": "0x81010010" },
  "ownerPublicKey": { "x": "0xa6167e4e202449fb153735e02464f56b136e8e86d60c9ef083e7d3441387dc09", "y": "0xebe5715052910fe678f525cd3420b7e1abeb0c7bc2b6a11a89b1c48f2f5bfa45" },
  "agent": { "tropic01": { "port": "/dev/ttyACM0", "slot": 1 } },
  "recovery": { "keyfile": "/media/me/USB/recovery.json" },
  "permissionId": "0x74727334",
  "salt": "0x0",
  "account": "0xEdB645B14e2f952C5784e34949b58F0826fBc9E9",
  "policy": {
    "allow": [
      { "target": "0x29da894F3E456CAC92b3EC76710524E74411E99f", "selector": "0xd09de08a" },
      { "target": "0x29da894F3E456CAC92b3EC76710524E74411E99f", "selector": "0x00000000" }
    ],
    "maxValuePerOp": "1000000000000000",
    "budget": "3000000000000000",
    "validAfter": 0,
    "validUntil": 1795046400,
    "tokens": [
      { "token": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "maxPerOp": "20000000", "budget": "100000000", "payees": "anyone" }
    ]
  }
}
```

(The public keys are shortened here; a real file carries all 64 hex digits.
The `tokens` entry is illustrative.) Unknown fields are an **error** at the
top level, in `policy`, `allow`, `tokens` and public keys (a misspelled
`validAfter` must not silently become 0); inside a key spec an unknown field
is ignored. Field names are case-sensitive. A token listed twice in
`tokens`, or a decoder listed twice in `venues`, is an error when the config
is read: the phone's review and the policy both refuse such a mandate, and
the CLI says so before anything is sent.

## Fields

### Top level

| Field | Required | Type and syntax | Meaning |
|---|---|---|---|
| `deployments` | yes | path, relative to this file's directory (or absolute) | the module addresses for the chain: `contracts/deployments/<chainId>.json`. Where the mandate allows a Safe transaction or a batch (`execTransaction`, `multiSend`), the CLI pins the shape judge the file names as `safeShapes`, at the code the chain holds, and refuses the config where the file names none: the policy installs such a mandate only with its judge ([#251](https://github.com/postcryptum-research/agent-keys/issues/251)) |
| `owner` | yes | key spec (below) | where the owner (root) key lives; opened **only** to sign an owner operation |
| `agent` | yes | key spec | where the agent key lives; opened to sign the agent's operations |
| `permissionId` | yes | `0x` + exactly 8 hex digits (4 bytes) | which permission of the account this file describes; unique per account — a schedule uses one id per window |
| `account` | no | address | **pins** the deployed account. Without it the address is *derived* from the file (owner key, first permission, salt) — which changes as soon as the mandate changes, so pin it once the account exists |
| `ownerPublicKey` | no | `{"x": "0x…64 hex", "y": "0x…64 hex"}` | the owner's public key, as `key show` prints it. Lets the agent derive and deploy the account without the owner key being reachable. Needed when `account` is not pinned, and for the first operation that deploys the account |
| `agentPublicKey` | no | same | the agent's public key. Without it every command that opens a chain session opens the agent key for its public half, so it is needed on any machine that cannot reach the agent's chip — status, revoke and recovery commands included, not only install and rotate |
| `recovery` | no | key spec (`keyfile` or a hardware key) | the cold recovery key (`owner add-recovery`, `owner recover`, `owner set-root --as-recovery`) |
| `salt` | no | hex number, default `0x0` | the factory salt; only affects the address of an account not deployed yet. The address does not depend on whether the account is created through the staked factory (`kernelFactoryStaker` in the deployments file, [#102](https://github.com/postcryptum-research/agent-keys/issues/102)) or through Kernel's factory itself |
| `bundlerPreVerificationFactor` | no | whole number from 1 to 64, default 1 | widens the CLI's ceiling on a bundler's `preVerificationGas` by this factor, for the agent's operations and nothing else: the owner's and the recovery key's operations keep the ordinary ceiling, since no mandate bounds them. For a chain whose bundlers fold the L1 data fee into that figure, where an honest one can exceed the ordinary ceiling and every operation would be refused. It is not part of the mandate and changes nothing on chain: a bundler may then be paid up to that many times more for an agent operation's bytes, from the mandate's budget, or from the paymaster's deposit when the operation is sponsored, which the budget does not bound. Leave it out unless the CLI refuses an honest bundler's figure on that chain ([FAQ](FAQ.md#do-i-need-a-bundler-or-a-gas-wallet)) |
| `policy` | yes | object (below) | the mandate this permission should have |

### Key specs

Exactly one of:

| JSON | Backend | Notes |
|---|---|---|
| `{"tpm": "0x81010011"}` | TPM 2.0 (Linux), persistent handle | build with `--features tpm` |
| `{"tpm": {"handle": "0x81010012", "pcrs": [0, 2, 4, 7]}}` | TPM key sealed to those PCRs | signs only while the boot state matches |
| `{"tpm": {"handle": "0x81010013", "authFile": "/etc/tpm_sign/owner.auth"}}` | TPM key protected by a secret (created with `key create --auth-file`) | for an owner key on the agent's chip; the file root-only, mode 0600 ([`KEY_POLICY.md`](KEY_POLICY.md) rule 3): one that group or others may access is refused. `authFile` does not combine with `pcrs`: a TPM key with both, or with any other field, is refused |
| `{"secure-enclave": "label"}` | Apple Secure Enclave | `--features secure-enclave`, macOS |
| `{"windows-tpm": "name"}` | Windows TPM through CNG | `--features windows-tpm`, Windows |
| `{"tropic01": {"port": "/dev/ttyACM0", "slot": 1}}` | TROPIC01 USB devkit, ECC slot 0–31 | `--features tropic01` |
| `{"yubikey": {"slot": "9c", "serial": 12345678}}` | YubiKey 5 PIV slot (`9a`, `9c`, `9d`, `9e`, `82`–`95`); `serial` is optional and picks one of several YubiKeys | `--features yubikey`; the PIN is asked at use. As the agent key only a slot with PIN policy never and touch policy never is accepted. Keys are generated with ykman, not `key create` ([`YUBIKEY.md`](YUBIKEY.md)) |
| `{"keyfile": "/media/…/owner.json"}` | encrypted key file | **owner or recovery only**, refused for the agent; asks the passphrase at use |
| `{"phone": {"label": "owner-phone", "publicKey": {"x": "0x…", "y": "0x…"}, "fingerprint": "ABCDE-FGHIJ-KLMNO-PQRST"}}` | the owner's phone ([`MOBILE_OWNER_DESIGN.md`](MOBILE_OWNER_DESIGN.md)) | **owner only**. `key create --phone <label> --agent <cfg>` enrolls the key and prints this snippet, with five records of the enrollment that the CLI does not act on: `"platform"`, `"attestation"` (`strongbox` or `tee` as the verified attestation says, `none` without evidence), `"revocation"` (`checked` or `not checked` against Google's list at that time), `"bootState"` (`verified`, `self-signed` or `unverified` as the phone's verified boot reported its operating system, `none` without evidence; `unverified` is refused unless the enrollment passed `--allow-unverified-boot`) and `"deviceCredential"`. `key show --phone` prints `attestation`, `revocation` and `bootState` (not `platform` or `deviceCredential`). The phone's answer is authenticated by a secret in the QR, and the CLI also asks for the fingerprint on the phone's screen (`--phone-skip-fingerprint` to rely on the secret alone, `--phone-fingerprint` for scripts); `fingerprint` is what the phone showed, and the key is refused before any session when it is not its `publicKey`'s. Every owner operation opens a one-shot LAN session behind a QR (`--listen`, `--phone-timeout`) |
| `{"software": "0x…64 hex"}` | plaintext scalar | **tests only**: refused in every role unless built with `--features insecure-software-keys` (the integration tests' build; never a release) |

### `policy` — the mandate

| Field | Required | Type and syntax | Meaning |
|---|---|---|---|
| `allow` | yes, non-empty | list of `{"target": address, "selector": "0x" + 8 hex}` | the calls the agent may make. `selector` `0x00000000` = a plain value transfer: empty calldata only (a body of 1–3 bytes is refused, and so is a longer one that starts with four zero bytes, [#76](https://github.com/postcryptum-research/agent-keys/issues/76)). One entry admits its call directly, through an owned Safe and as a Safe batch leg alike |
| `maxValuePerOp` | yes | decimal string, wei (≤ 2¹²⁸−1) | most native value one operation may move (including value moved inside a Safe transaction) |
| `budget` | yes | decimal string, wei | total native value over the permission's life, **plus** the maximum gas cost of each operation the account pays for itself |
| `validUntil` | yes | integer, Unix seconds, > 0 | end of the window: after it the EntryPoint refuses the agent's operations |
| `validAfter` | no, default 0 | integer, Unix seconds, < `validUntil` | start of the window (0 = at once); several permissions with their own windows make a schedule |
| `tokens` | no | list of `{"token": address, "maxPerOp": decimal string, "budget": decimal string, "x402": bool, "payees": "anyone" or [address, …]}` | per-token limits in the token's base units (USDC: 6 decimals, so `"20000000"` = 20 USDC). `maxPerOp` is the most one operation may move of the token, summed over its calls: transfers, approvals and x402 registrations, in a batch and inside a Safe batch alike ([#76](https://github.com/postcryptum-research/agent-keys/issues/76); an `AgentPolicy` instance from before 2026-11-20 checks each call on its own). An approval the agent makes must be withdrawn (`approve(spender, 0)`) later in the same operation: approve, use, withdraw, in one batch. An operation that leaves one standing is refused, so that no allowance of the agent's outlives a revoke; the same holds for an operator grant (`setApprovalForAll(operator, true)` of ERC-721 and ERC-1155, withdrawn with `false`; the same for ERC-6909's `setOperator`, and for its `approve(spender, id, amount)`, withdrawn with amount 0). ERC-777's `authorizeOperator` (`0x959b8c3f`) cannot be listed in `allow`: the CLI refuses the config, as `AgentPolicy` refuses the mandate. `allow` lists `transfer`, `transferFrom`, `approve` or `increaseAllowance` only on a token that has its entry here: on any other target the CLI refuses the config, as `AgentPolicy` refuses the mandate at install. Required for every token whose `transfer` / `transferFrom` / `approve` / `increaseAllowance` is in `allow` — without one the call is refused. A token with an entry here is callable through those four functions only: a mandate with any other `allow` entry on it (`permit`, a `mint`, a vault's `withdraw`) is refused whole, by the CLI before anything is signed and by `AgentPolicy` at install (`InvalidConfig`), because through such a function the token would move past its limits (an `AgentPolicy` instance from before 2026-11-20 lets such an entry through unmetered, [#79](https://github.com/postcryptum-research/agent-keys/issues/79): rotate a mandate that sits on one). One entry per token. `x402` (default `false`): the agent may also pay x402 in this token (EIP-3009, e.g. USDC) from the same budget; the CLI reads the token's `DOMAIN_SEPARATOR()` and installs it with the limit ([`ERC1271.md`](ERC1271.md)). `payees` says who the token may go to, and every entry must say it before a mandate is installed from the config (`permission add`, `rotate`, the account's first operation refuse otherwise; a config without it still loads for status, show and revoke). `"anyone"`: the limit bounds the amount only and the agent picks who gets it — what x402 needs, since it pays whichever server asks. A list: the only addresses the token may go to — the recipient of `transfer` and `transferFrom`, the spender of `approve` and `increaseAllowance`, the payee of an x402 payment. A listed spender can move its allowance wherever it likes, so list a spender only if you would list everyone it pays. A list binds the agent's calls to the token contract and nothing else, which leaves two things to the owner. Allowances that already exist stay valid: installing a list revokes none, and the agent cannot clear one either (`approve(spender, 0)` to an unlisted spender is refused like any other), so before moving a token to a list, read the account's allowances for it and zero the unwanted ones with a root operation. And another contract in `allow` that holds an allowance from the account (a router, a vault) is not the token, so what it moves is not checked against the list. Permit2 is the plain case (the token's allowance goes to Permit2 once, and `Permit2.approve(token, spender, …)` then names who may pull it), which is why Permit2 is never a valid `allow` target, see below; the same holds for any other such contract, and those cannot be enumerated. Lists need the `AgentPolicy` deployed to Base Sepolia on 2026-11-20 (`0x2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95`, [#66](https://github.com/postcryptum-research/agent-keys/issues/66)) or a later one: an earlier instance would ignore them, so the CLI refuses a config with a list rather than install its mandate there, and the phone shows payees for this instance only |
| `tokenIds` | no | list of `{"token": address, "id": decimal string or 0x hex, "maxPerOp": decimal string, "budget": decimal string}` | limits per token id of an ERC-6909 contract, in the id's base units ([#186](https://github.com/postcryptum-research/agent-keys/issues/186)). ERC-6909's `transfer` (`0x095bcdb6`), `transferFrom` (`0xfe99049a`) and `approve` (`0x426a8493`) in `allow` need a limit here for their target, and each call is held to the limit of the id it names: `maxPerOp` summed over the operation's calls, `budget` over the mandate's life or per `period`. An id without an entry cannot be moved. A contract with entries here may have only these three functions in `allow` (not `setOperator`: an operator could move every id), and no entry in `tokens`. An allowance the agent gives for an id must be withdrawn in the same operation, as for a token. There is no payee list and no x402 for an id: the agent picks the receiver and the spender, and the phone says so. Needs an `AgentPolicy` that has these limits: the CLI asks the deployed one (`idAsset`) before anything is signed, and `status` shows each id's limit and what it has spent |
| `period` | no | seconds | every budget of the mandate (native and per token) starts afresh each `period` seconds, counted from 1970-01-01 00:00 UTC: `86400` is a budget per UTC day. `0` or absent: a budget is for the mandate's whole life. Across a renewal the agent can spend one period's budget just before it and the next one's just after, so up to twice a budget in a short time, and no more; that is the number the phone shows. It holds for what the agent registers as for what it transfers: under a period an x402 authorization or an order must end with the period it is charged in (`validBefore` no later than the next period's first second, an order's `validTo` no later than the period's last one), and the policy refuses one that would still be usable in a later period, beside that period's own budget. The CLI shortens an order or an authorization to the period's end and refuses to make one in the period's last minute (with or without a period, it signs an x402 authorization for an hour at most, whatever the server allows); an operation built in a period's last 20 seconds waits for the next period. Validation may not read the clock (ERC-7562), so each agent operation names its period in the signature and is valid in that period only; the CLI does this. Needs an `AgentPolicy` that knows periods: the CLI refuses the config where `deployments.agentPolicy` does not answer `period`, and the phone refuses such a mandate for a module its build does not know to enforce it. The instance on Sepolia (`contracts/deployments/11155111.json`) is of this policy; no instance on Base Sepolia knows periods yet |
| `venues` | no | list of `{"kind": "cowswap", "1inch", "uniswap" or "rules", "decoder": address, "codeHash": bytes32 (optional; required for rules), "appData": bytes32 (cowswap only), "maxLife": seconds (cowswap and 1inch), "functions": […] (rules only, see below), "pairs": [{"sellToken": address, "buyToken": address, "minBuy": decimal string, "perSell": decimal string}, …]}` | where the agent may place orders, and on what terms ([#80](https://github.com/postcryptum-research/agent-keys/issues/80)). The agent never calls the venue: it registers an order with the policy (`orderRegister`, which must be in `allow`), the policy asks the venue's `decoder` contract whether the order is within these terms and charges the sold amount to the token's `maxPerOp` and budget, and from then on the account vouches for exactly that order when the venue asks (ERC-1271). The terms, for `cowswap` (`CowSwapDecoder`): sell orders only, filled whole or not at all, no fee, the proceeds to the account itself, `appData` exactly as given, a lifetime of at most `maxLife`, and one of `pairs` at no less than its lowest price: at least `minBuy` of the buy token for each `perSell` of the sell token, both in base units (`"minBuy": "200000000000000", "perSell": "1000000"`: never under 0.0002 WETH for 1 USDC). The terms, for `1inch` (`OneInchLimitOrderDecoder`): a plain limit order of the account at 1inch's router, filled whole and once or not at all, with an expiration within `maxLife`, no extension and no call before or after the fill, the proceeds to the account itself, and one of `pairs` at no less than its lowest price; it has no `appData`. Such an order is filled by whoever holds it and its signature. The terms, for `uniswap` (`SwapRouter02Decoder`): not an order but a swap the account makes itself at Uniswap's SwapRouter02, at once, through one pool of the pair (`order swap`); the agent picks the pool's fee tier, the amount sold and the least bought, the bought token goes to the account itself, and the swap is one of `pairs` at no less than its lowest price. It has no `appData` and no `maxLife`: nothing of a swap is left to be filled later. The router call is reached only through the swap's registration, in the same operation. The terms, for `rules` (`CallRulesDecoder`): calls the account makes itself at one contract, the decoder's venue (`order call`). There are no `pairs`: `"functions"` lists the functions the agent may call there, each `{"selector": "0x" + 8 hex, "words": […]}` with a rule for **every** 32-byte argument word, in order: `"account"` (the word is the account's address: a beneficiary held to the account), `{"is": value}` (exactly this value: a token, a market, a zero; decimal or `0x` hex), `{"atMost": bound}`, `{"charged": token}` (the word is an amount, charged to that token's `maxPerOp` and budget; at most one a function) or `"any"` (the agent's choice; the phone shows it in bold and warns). A call passes only if its selector is listed, it is exactly as long as its rules and every word passes; no native value goes with it. Aave's `supply(asset, amount, onBehalfOf, referralCode)` for one asset and the account only is `{"selector": "0x617ba037", "words": [{"is": asset}, {"charged": asset}, "account", {"is": "0"}]}`. One such decoder is deployed for each contract (`contracts/script/DeployCallRules.s.sol`), so the deployments file names none by kind and `codeHash` is always stated. The decoder reads words, not the protocol: which word is a beneficiary, and what an offset or a length among the words has to be, is the owner's reading of that protocol ([`DAPPS.md`](DAPPS.md)). The CLI puts the terms of every kind to the decoder's own `checkConfig` before a mandate is made of them; for `1inch`, `uniswap` and a charged token of `rules` it refuses a token address without code: the router takes a transfer there for done, so an order or a swap that buys such a "token" would give the sold amount away. A pair is one direction; at most 16 pairs, each once. Every sold token, and every token a venue of rules charges, needs an entry in `tokens` and no payee list there (what is sold goes to whoever fills the order, and what is charged goes to the venue). **A mandate with venues needs a `period`**, and the policy refuses one without: an order is charged to the budget when it is registered, filled or not, and the charge is not given back; an unfilled order's part of the budget returns when the period turns. (Whether a venue filled an order cannot be read from the venue for good after the order's end, so there is no refund.) The mandate pins the decoder's code hash and the hash of these terms. `codeHash` may be left out only for the decoder the deployments file names for the chain and the kind (`cowSwapDecoder`, `oneInchLimitOrderDecoder`, `swapRouter02Decoder`), and then the code at that address when the mandate is installed is pinned; any other decoder is refused until its `codeHash` is stated, because the owner approves a budget to whatever spender that code names; a decoder whose code changed judges nothing. The venue's own contract, the decoder and the venue's spender (CoW's vault relayer, or 1inch's router or Uniswap's, each of which is both the venue and the spender; it holds the owner's allowance) are never valid `allow` targets, in this mandate or in any other of the account, installed before or after, and they stay so when the trading mandate is revoked (`AgentPolicy.venuePlace(account, address)`; the spender since [#149](https://github.com/postcryptum-research/agent-keys/issues/149)). Nothing clears that: these addresses stay out of reach as targets for every mandate of the account on this policy instance, and only a mandate under a new instance of the policy could name them again. The owner's operation that installs the mandate (`permission add`, `rotate`) also approves the venue's spender for each sold token: one budget of it and no more, with or without a `period`, because what the spender takes through the allowance does not pass through the mandate, so the allowance is what a fault at the venue could cost. Under a mandate with a period the owner gives the next one with `permission allowance` when it is used up. An allowance does not outlive its mandate: `permission revoke` and `permission rotate` set to zero the allowances of the permission they remove that the new mandate does not take over. The chain keeps only the hash of a venue's terms, so the sold tokens are read from the config whose terms have that hash; when this config no longer holds them, `permission rotate` refuses until the config the permission was installed from is passed with `--old-config`. `permission revoke` never waits for it: revoking is the owner's move when the agent's machine is lost, made from wherever the owner is. It removes the permission in any case; without the terms it reads the allowance to the venue's spender on the chain for every token the configs at hand name and zeroes those it finds, and prints the spender and the tokens it looked at, so that an allowance of any other token can be cleared with the owner key (`approve(spender, 0)`). The phone shows the allowance of a trading install as "Allowance to the venue" and refuses the operation when a token the mandate sells is approved to anyone but the venue's spender, or for more than one budget. A config with venues therefore pins `account`. The phone shows a venue only when its build knows the decoder by address and code. Today, on Sepolia (11155111) and on Base Sepolia (84532), on the policy `0xdA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6`: CoW Swap (decoder `0x42F62bF7134F5eF6d46d4BC07d806E77D1Df641a`), 1inch's limit orders (`0xAD754dA240f27dCe0cF79F6d323e56d5C29D08E6`), a swap at Uniswap's router (`0xB29a80662d989c1C0E73dB824cD82d5890e795bC` on Base Sepolia, `0x6D7e83461cd295AEf006F9A76009b662d6b06b6b` on Sepolia), rules for Aave V3's pool (`0x14b82e2cBF35926B6221d008e5A89DB1BD5D4887` on Base Sepolia, `0x112b620C87A7C4b9f53566dD422f20704140dbfe` on Sepolia) and rules for CCTP's messenger (`0xC5135aC6A911B692173F2626dD57ff1D80d16F62`), each the decoder of that chain's deployments file with that chain's code; USDC in its units on both chains (`0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` on Sepolia, `0x036CbD53842c5426634e7929541eC2318f3dCF7e` on Base Sepolia) and WETH `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14` on Sepolia; any other token is shown by its address, in its smallest units. The decoder of bids at Seaport (`0x713165a6157a4B2952A775A9D1C9948D9a703128`) is deployed and is no venue of the phone's: a mandate that names it is refused. A mandate on the policy instance that this one replaced on 2026-11-27 (`0x530DD3C000b3939294072409834c4c4dd160BCd9`) is refused too: the build names that instance as superseded and reads no mandate on it. A phone app built before 2026-11-24 does not know Sepolia, and one built from an earlier record of the deployments knows only the decoder and policy then current; both refuse |

**`transferFrom` on the allow-list reaches what others approved.** For a
token with a limit the policy holds `transferFrom(from, to, amount)` by
its amount (the token's `maxPerOp` and `budget`) and its recipient (the
token's `payees`). It does not hold `from`. Listing it lets the agent move
tokens that any address approved to the account, and inside a Safe
transaction tokens that any address approved to the Safe, to the payees
and within the limits. Paying out of the account's own balance needs
`transfer` only: list `transferFrom` where collecting from those who
approved the account is what the agent is for, and not otherwise
([`CONTRACTS.md`](CONTRACTS.md), #247). The same holds for ERC-6909's
`transferFrom` on a contract with `tokenIds`.

**A venue and a payee list do not share a token.** A venue takes what it
charges for itself: a bridge burns it, a pool holds it. That is not a
payment to a listed payee, so the owner's phone refuses a mandate where a
venue charges a token whose `payees` are a list (`rules` with a `charged`
word, or a trading venue that sells it). Give the venue a mandate of its
own, a second permission of the same account: there the token has a limit,
`"payees": "anyone"` and no function of the token on the allow-list, so
that the agent cannot transfer or approve it and the limit bounds what the
venue takes. The first account on Arc testnet is set up so
([`CIRCLE.md`](CIRCLE.md)): one mandate for payments, one for the bridge.

Never valid `allow` targets, refused by the CLI before anything is signed and
by `AgentPolicy` at install (`ForbiddenTarget`): the **account itself**
(Kernel's `grantAccess`, `installValidations`, `changeRootValidator`,
`execute`: the mandate would widen or replace itself), its **EntryPoint**
(`withdrawTo` on the deposit), the project's **validators, signer, Kernel
implementation and factory** (CLI only: they could replace the owner,
recovery or agent key), the **policy itself** except its two x402 entry
points and its order entry point (`x402Authorize`, `x402Reclaim`,
`orderRegister`), a **venue's own contract and its decoder** (there the
agent could sign any order, past the terms) and **its spender** (it holds
the owner's allowance of the sold tokens, which through it would leave past
their limits and payee lists), and **Permit2** (`0x000000000022D473030F116dDEE9F6B43aC78BA3`: its
own `approve` would hand a token's allowance to any address, a call the
policy does not read; refused by `AgentPolicy`, the CLI and the phone;
metering it is part of
[#80](https://github.com/postcryptum-research/agent-keys/issues/80)).
`AgentPolicy` refuses the account, the policy, a venue's places and Permit2
again at validation (the EntryPoint at install only). The Circle Agent Wallets case is why
(`related/INCIDENTS.md`).

Special `allow` entries:

| Entry | Effect |
|---|---|
| `(safe, 0x6a761202)` — `Safe.execTransaction` | the account may drive that Safe (which it owns); the call *inside* each Safe transaction is judged against the same `allow`, value cap, budget and token limits; refunds and nested Safes are refused outright; the Safe's own administration (`addOwnerWithThreshold` and the like) is refused because the Safe's own functions are not in `allow` — an owner who allow-lists one admits it; each Safe transaction must come with an on-chain nonce assertion (`op send --safe-nonce`) |
| `(multiSendCallOnly, 0x8d80ff0a)` — `multiSend` | Safe transactions may delegatecall this batcher; every leg must be a CALL that passes the mandate |
| `(agentPolicy, 0x4993d616)` — `x402Authorize` | the agent may register x402 payments in its `x402` tokens; each is held to the token's `maxPerOp` and budget, and only registered ones get an ERC-1271 yes |
| `(agentPolicy, 0xf3ea183e)` — `x402Reclaim` | the agent may return expired, unused registrations to the budget (`x402 reclaim`) |
| `(agentPolicy, 0x27ddae76)` — `orderRegister` | the agent may register orders at the mandate's `venues` (`order sell`), and swaps and calls at a venue of kind `uniswap` or `rules` (`order swap`, `order call`: the registration and the one call it admits, in one operation); each is held to the venue's terms and to the sold token's `maxPerOp` and budget, and only registered ones get an ERC-1271 yes, until their `validTo`. An order's charge is not given back; it returns with the next budget period |

## From file to contracts

Where each field ends up, and which signed operation puts it there:

| Field | On-chain state | Written by |
|---|---|---|
| `owner` / `ownerPublicKey` | the root validator's key for the account: `P256Validator.publicKeys(account)` (Kernel's `rootValidator()`) | account creation (its first operation's `initCode`), or `owner set-root` (signed by the current root) |
| `agent` / `agentPublicKey` | `P256Signer.publicKeys(permissionId, account)` | `permission rotate` / `permission add` (owner) — and account creation for the first permission |
| `permissionId` | the Kernel permission `0x02 ‖ id`, with its signer and policy (`permissionConfig(id)`) and its EntryPoint nonce space | same |
| `policy.allow` | `AgentPolicy.isAllowed(account, id, target, selector)` | same |
| `policy.maxValuePerOp`, `budget`, `validUntil`, `validAfter` | `AgentPolicy.configs(account, id)` (with `spent`, which the chain updates) | same |
| `policy.tokens` | `AgentPolicy.tokenLimit(account, id, token)` (with its `spent`; for `x402` tokens also the token's EIP-712 domain); a payee list: `AgentPolicy.payeeAllowed(account, id, token, payee)` | same |
| `policy.period`, `policy.venues` | `AgentPolicy.period(account, id)`; `AgentPolicy.venue(account, id, decoder)` (the pinned code hash and the hash of the terms) | same |
| `recovery` | `P256RecoveryValidator.publicKeys(account)` + Kernel `isAllowedSelector(recovery, changeRootValidator)` | `owner add-recovery`, `owner replace-recovery`, `owner remove-recovery` (owner) |
| `account`, `salt` | the account's address (`salt` only before deployment) | — (identifies the account) |
| `deployments` | — | — (which module addresses the CLI uses for *new* installs) |
| key locations (`tpm` handle, `pcrs`, `authFile`, `port`/`slot`, `keyfile` path, labels) | nothing | — (how this machine reaches its key) |

An installed mandate is fixed: to change it, install a new one —
`permission rotate --old-id <old>` (replace) or `permission add` (alongside,
e.g. a schedule window) — and remove ones you no longer want with
`permission revoke`. The policy module a permission was installed with stays
its module until then; `permission show` names it.

## Which commands read what, and what they change

| Command | Reads from the file | Changes on-chain | Signed by |
|---|---|---|---|
| `op send`, `demo` | `agent`, `permissionId`, `account` (or derivation fields) | executes the call — **only within the installed mandate** | agent key |
| `op batch` | same | several calls as one operation, each judged by the mandate, executed together or not at all. `--allow <token>:<spender>:<amount>` wraps them in an allowance that is taken back in the same operation, which is how the agent uses a protocol that pulls tokens ([`DAPPS.md`](DAPPS.md)) | agent key |
| `op send --root` | `owner`, `account` | executes the call on the root path — no mandate applies | owner key |
| `x402 fetch`, `x402 reclaim` | same, + `policy.tokens` (which are `x402`) | registers / reclaims an x402 payment — within the mandate | agent key |
| `order sell` | same, + `policy.venues` | registers an order under the mandate and prints it signed, in the form the venue takes (it is sent nowhere: an order is live once an order book or a taker has it). CoW Swap: the body of `POST /api/v1/orders`. 1inch: the order's hash, the signature and its eight fields as 1inch's order book takes them, and the same eight words encoded (`order`) for a taker that fills at the router itself; each 1inch order gets a nonce of its own from the system's random source. The order is charged to the budget at once, filled or not, until the period turns | agent key |
| `order swap` | same, + a venue of kind `uniswap` | swaps at the venue's router in one operation of two calls: the swap's registration with the policy, and the router call the venue's decoder builds (`--sell`, `--buy`, `--sell-amount`, `--buy-amount` the least to receive, `--fee` the pool's fee tier, 3000 by default). What is bought comes to the account; the router reverts if the pool pays less than `--buy-amount`. Prints the transaction, the amount sold and the amount bought. The calls are run before anything is sent, so a swap the pool would not honour now costs nothing; a swap that is included and then reverts was charged to the budget all the same, until the period turns | agent key |
| `order call` | same, + a venue of kind `rules` | makes a call at the venue's contract in one operation of two calls: the call's registration with the policy, and the call (`--data` its calldata, `0x` hex: the selector and the arguments). The venue's decoder is asked first, so a call the rules refuse costs nothing; the policy asks it again. Prints the transaction and what was charged. A call that is included and then reverts was charged to the budget all the same, until the period turns | agent key |
| `account status`, `owner status`, `permission show`, `account init-data` | everything | nothing (`init-data` prints the account's `initialize` calldata and initCode, for debugging) | — |
| `permission rotate` / `add` | `agent`, `permissionId`, `policy`, `account`, `deployments` | installs this file's permission (rotate: and removes `--old-id`, and names the old permission's guardian, if any, for the new one; refused where the new permission's policy has no guardian, until the old one's is removed) | owner key |
| `permission revoke --id` | `account` | removes a permission | owner key |
| `permission guardian --guardian <address or none>` | `permissionId` (or `--id`), `account` | names the guardian of the permission's mandate, or removes it ([#251](https://github.com/postcryptum-research/agent-keys/issues/251)): the guardian may pause a shape judge or a venue of that mandate and lift the pause; it cannot widen the mandate or move funds. `permission rotate` carries the old permission's guardian over to the new one, in the same operation; `permission add` starts with none. The call is tried from the account first, so a policy from before the guardian (every instance deployed so far) is refused before the owner signs. `permission show` names the guardian | owner key |
| `permission pause --module <address>` (`--lift` to lift it) | `permissionId` (or `--id`), `account` | pauses one module of the mandate, a shape judge or a venue decoder: the policy refuses its calls and the rest of the mandate runs. An address that is none of the mandate's modules is refused before the owner signs. `permission show` lists what is paused. The guardian sends the same call from its own address: `cast send <agentPolicy> "pause(address,bytes32,address,bool)" <account> <permission id, right-padded to 32 bytes> <module> true` | owner key (the guardian from its own address) |
| `owner add-recovery` | `recovery`, `account` | installs the recovery key; refused when it is the account's root key or the agent's key | owner key |
| `owner replace-recovery` | `recovery` (the new key), `account` | replaces the installed recovery key in one operation: the old key can sign nothing afterwards. The new key is opened here and signs a fresh digest before anything is sent (a key file asks for its passphrase), so a key that cannot sign is found now and not when it is needed; `--skip-key-check` leaves it unopened, and then only its public half is read. A recovery key equal to the account's root key or to the agent's key is refused, here and in `owner add-recovery`. Refused while the recovery key is root (after `owner recover`: finish the handover first) | owner key |
| `owner remove-recovery --leave-no-recovery` | `account` | removes the recovery key and installs none: losing the owner key then loses the account, and the root validator's key cannot be replaced in place until a recovery key is installed again | owner key |
| `owner remove-recovery --earlier <address>` | `account`, `recovery` (on the current validator) | after a redeploy: removes the recovery key from an earlier recovery validator the deployments file keeps (`p256RecoveryValidatorV<n>`), which could otherwise still take root. Refused for any other address, and while the current recovery validator holds no key (`owner add-recovery` first) unless `--leave-no-recovery` ([`REDEPLOY.md`](REDEPLOY.md)) | owner key |
| `owner recover` | `recovery`, `account` | makes the recovery key root | recovery key |
| `owner set-root` | `account` (+ arguments; `--validator <P256Validator>`, required, names the validator instance the new key is installed on; `--expect-fingerprint` refuses a `--public-key` that is not the one the owner saw; one of `--to-phone <label>`, which makes a handover to a phone key wait until the phone has shown that it holds it, and `--not-a-phone` is required. With `--not-a-phone` the new key also shows that it can sign before anything is sent: `--new-key '<its key spec>'` for a key on this machine, or else the command prints a challenge for `key prove` on the key's machine and waits for the proof. `--no-proof-of-possession` skips that and says what it risks) | hands root to a new key on `--validator`; with `--retire <validator>` (required after `recover`) uninstalls the old one | current root (owner, or recovery after `recover`) |
| `key prove --key '<key spec>' --challenge <line>` | nothing (no config) | nothing on-chain: the key signs the challenge that `owner set-root --not-a-phone` printed on another machine, and prints the proof to paste there | the key being proven |
| `key create --phone` | `account`, `deployments` | nothing on-chain: enrolls a new key on the phone for the account and prints the `phone` key spec | — (the phone's user confirms) |
| `key show --phone <label> --agent <cfg>` | the `phone` key spec with that label | nothing: prints the enrolled key from the file, no session | — |
| `key check --phone <label> --agent <cfg>` | the `phone` key spec, `account`, `deployments` | nothing on-chain: the phone signs a fresh digest, which shows that it still holds the key | — (the phone's user confirms) |
| `account fund`, `paymaster deposit` / `sponsor` / `stake` | `account`, `deployments` | ETH transfers / paymaster settings; each fails, naming the transaction, when it was included and reverted | gas wallet / paymaster owner |

Every command that takes `--agent` parses the whole file and reads
`deployments`. `permission rotate` / `add`, `key create --phone` and
`key check --phone` refuse a file that does not pin `account`. The `key`
commands for chip keys and key files (`create`, `show`, `evict`, `check`,
`attest`), `vector` and `verify` take no config.

The agent's own key can only ever do the first row. Every row that changes
the account's rights needs the owner (or recovery) key — which, by the key
policy, is not on the agent's machine.
