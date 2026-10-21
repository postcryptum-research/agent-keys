/**
 * Interactive Claude-driven ElizaOS agent in the terminal (no server, no UI).
 *
 *   ANTHROPIC_API_KEY=... bun run chat
 */
import { createInterface } from "node:readline";

import { stringToUuid } from "@elizaos/core";

import { loadEnv, startAgent } from "./agent.ts";

loadEnv();
if (!process.env.ANTHROPIC_API_KEY) {
  console.error("set ANTHROPIC_API_KEY (environment, ./.env or AGENT_ENV_FILE)");
  process.exit(1);
}

const { eliza, runtime } = await startAgent({ withLlm: true });
const entityId = stringToUuid("terminal-user");
const roomId = stringToUuid(`terminal-room-${runtime.agentId}`);
const rl = createInterface({ input: process.stdin, output: process.stdout });

console.log(`${runtime.character.name} is ready. Try: "what's your address?", "increment the counter", ` +
  `"send 0.0000001 ETH to 0x000000000000000000000000000000000000dEaD". Ctrl+D to quit.`);

try {
  rl.setPrompt("> ");
  rl.prompt();
  // The async iterator ends on Ctrl+D / EOF (rl.question() would hang there).
  for await (const line of rl) {
    const text = line.trim();
    if (!text) {
      rl.prompt();
      continue;
    }
    // ASYNC mode (onResponse set) so that action callbacks print as they happen;
    // wait for onComplete before the next prompt.
    await new Promise<void>((done) => {
      void eliza.handleMessage(runtime, { entityId, roomId, content: { text, source: "terminal" } }, {
        onResponse: async (c) => {
          if (c.text) console.log(`${runtime.character.name}: ${c.text}`);
        },
        onError: async (e) => {
          console.error(`error: ${e.message}`);
          done();
        },
        onComplete: async () => done(),
      });
    });
    rl.prompt();
  }
} finally {
  rl.close();
  await eliza.stopAgents();
}
process.exit(0);
