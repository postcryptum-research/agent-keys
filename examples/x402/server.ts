// A paid endpoint: GET /quote costs 0.001 USDC on Base Sepolia, settled by
// the public x402.org facilitator. Nothing here knows about smart accounts:
// the facilitator checks the agent account's signature with ERC-1271, and
// AgentPolicy decides what that account vouches for.
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";

const payTo = process.env.PAY_TO as `0x${string}` | undefined;
if (!payTo) {
  console.error("set PAY_TO to the address that receives the payments");
  process.exit(1);
}
const facilitator = new HTTPFacilitatorClient({
  url: process.env.FACILITATOR_URL ?? "https://x402.org/facilitator",
});
const port = Number(process.env.PORT ?? 4021);

const app = express();
app.use(
  paymentMiddleware(
    {
      "GET /quote": {
        accepts: [{ scheme: "exact", price: "$0.001", network: "eip155:84532", payTo }],
        description: "A quote of the day, for 0.001 USDC",
        mimeType: "application/json",
      },
    },
    new x402ResourceServer(facilitator).register("eip155:84532", new ExactEvmScheme()),
  ),
);

app.get("/quote", (_req, res) => {
  res.json({ quote: "The key never leaves the chip.", paidAt: new Date().toISOString() });
});

app.listen(port, () => console.log(`x402 demo: http://localhost:${port}/quote (pays to ${payTo})`));
