/**
 * End-to-end check without an LLM: drive the AgentKit actions directly.
 *
 *  1. wallet details — reads only;
 *  2. demo_counter_increment — allowed by the mandate, must land on-chain;
 *  3. native_transfer to an outsider — what a prompt injection would ask for;
 *     the hardware signs, the account's AgentPolicy must refuse it.
 */
import { agentKitFromEnv } from "./setup";

const OUTSIDER = "0x000000000000000000000000000000000000dEaD";

async function main() {
  const { agentkit } = await agentKitFromEnv();
  const actions = new Map(agentkit.getActions().map((a) => [a.name, a]));
  const run = async (suffix: string, args: Record<string, unknown> = {}) => {
    const action = [...actions.values()].find((a) => a.name.endsWith(suffix));
    if (!action) throw new Error(`no action *${suffix}; have ${[...actions.keys()].join(", ")}`);
    console.log(`\n> ${action.name} ${JSON.stringify(args)}`);
    const out = await action.invoke(args);
    console.log(out);
    return String(out);
  };

  await run("get_wallet_details");
  await run("demo_counter_read");
  await run("demo_counter_increment");
  await run("demo_counter_read");

  const refused = await run("native_transfer", { to: OUTSIDER, value: "0.0000001" });
  if (!/error/i.test(refused)) {
    throw new Error("the transfer to an outsider went through — the mandate did not hold");
  }
  console.log("\nOK: allowed call executed, out-of-mandate transfer refused on-chain policy.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
