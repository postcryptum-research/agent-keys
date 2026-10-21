/**
 * No LLM: boot a real ElizaOS runtime with the plugin, then run its actions
 * directly. An allow-listed call lands; a transfer to an outsider is refused
 * by the account's on-chain mandate.
 *
 *   bun run smoke            # read + increment + refused transfer
 *   bun run smoke --dry      # boot and read only, no transaction
 *
 * With X402_AGENT_CONFIG and X402_URL set (examples/x402 server), also pays
 * for X402_URL through PAY_FOR_URL.
 */
import { type Memory, stringToUuid } from "@elizaos/core";

import { startAgent } from "./agent.ts";

const dry = process.argv.includes("--dry");
const { eliza, runtime } = await startAgent({ withLlm: false });

const act = async (name: string, text = "") => {
  const action = runtime.actions.find((a) => a.name === name);
  if (!action) throw new Error(`action ${name} is not registered`);
  const message = {
    entityId: stringToUuid("smoke-user"),
    roomId: stringToUuid("smoke-room"),
    agentId: runtime.agentId,
    content: { text },
  } as Memory;
  const r = await action.handler(runtime, message, undefined, {}, async (c) => {
    console.log(`[${name}] ${c.text}`);
    return [];
  });
  return r ?? undefined;
};

try {
  console.log("actions:", runtime.actions.map((a) => a.name).join(", "));
  await act("GET_AGENT_WALLET");
  await act("READ_DEMO_COUNTER");
  if (!dry) {
    const ok = await act("INCREMENT_DEMO_COUNTER");
    if (!ok?.success) throw new Error("allowed call did not land");
    await act("READ_DEMO_COUNTER");

    // Bypass the LLM extraction step: call the bridge with a fixed outsider target.
    const { TpmWalletService } = await import("./plugin/index.ts");
    const w = runtime.getService<InstanceType<typeof TpmWalletService>>(TpmWalletService.serviceType)!.wallet;
    try {
      await w.send({ to: "0x000000000000000000000000000000000000dEaD", value: 100_000_000_000n });
      throw new Error("transfer to an outsider was NOT refused");
    } catch (e) {
      const refused = (e as { rejectedByPolicy?: boolean }).rejectedByPolicy;
      if (!refused) throw e;
      console.log("[transfer to 0x…dEaD] refused by AgentPolicy, as expected");
    }
    if (process.env.X402_URL) {
      const paid = await act("PAY_FOR_URL", `get ${process.env.X402_URL}`);
      console.log(`[PAY_FOR_URL] success=${paid?.success}`);
    }
  }
} finally {
  await eliza.stopAgents();
}
process.exit(0);
