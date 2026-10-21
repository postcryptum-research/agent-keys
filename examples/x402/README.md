# x402: an agent pays for an API from a hardware-signed account

[x402](https://x402.org) turns `HTTP 402 Payment Required` into a payment:
the server names a price, the client signs a USDC
`transferWithAuthorization` (EIP-3009), a facilitator settles it. The payer
here is the agent's Kernel account, so the signature is checked with
ERC-1271 — and `AgentPolicy` vouches only for payments the agent registered
first, inside the mandate's USDC budget. How and why:
[`docs/ERC1271.md`](../../docs/ERC1271.md#x402--registered-authorizations-implemented-agentpolicy-v6).

The server below is an ordinary x402 server (`@x402/express`, the public
x402.org facilitator): nothing on its side knows about smart accounts.

## Run it

```sh
# 1. a paid endpoint: GET /quote for 0.001 USDC on Base Sepolia
cd examples/x402
npm install
PAY_TO=0x<your address> npm run server

# 2. the owner installs a mandate that may pay x402 (once)
cd signer
agent-signer permission add --agent agent.x402.base-sepolia.json --env-file ../../.env

# 3. the account needs Base Sepolia USDC: https://faucet.circle.com

# 4. the agent pays
agent-signer x402 fetch --agent agent.x402.base-sepolia.json --env-file ../../.env \
    http://localhost:4021/quote
```

`x402 fetch` prints the progress on stderr and the paid response on stdout
(shape of a successful run):

```
x402:           pay 1000 of 0x036C…CF7e to 0xDf52…CC22, valid until …
path:           permission (agent key)
registered:     tx 0x8f57…ea08 (block 48406232)
status:         200
settlement:     {"success":true,"transaction":"0x…",…}
{"quote":"The key never leaves the chip.",…}
```

What the mandate in `signer/agent.x402.base-sepolia.json` allows: two calls
on the policy (`x402Authorize`, `x402Reclaim`) and USDC with
`"x402": true` — at most 0.1 USDC per payment, 1 USDC in total. A payment
outside that is refused when it is registered, before any signature exists.

Payments that expired unused (the server never settled them) stay booked
against the budget until the agent returns them:

```sh
agent-signer x402 reclaim --agent agent.x402.base-sepolia.json --env-file ../../.env
```

## Cost

Each payment costs one UserOperation (the registration, ~231k gas on Base
Sepolia, a fraction of a cent on Base) plus the facilitator's settlement, which the server
side pays. x402 through this account makes sense for payments well above
the gas of one operation.
