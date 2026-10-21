/**
 * Headless ElizaOS host: one agent, PGlite storage, no HTTP server and no web
 * UI (so none of @elizaos/server's default Sentry reporting). Shared by the
 * smoke test and the chat REPL.
 */
import { resolve } from "node:path";

import { ElizaOS, type IAgentRuntime, type Plugin } from "@elizaos/core";
import bootstrapPlugin from "@elizaos/plugin-bootstrap";
import sqlPlugin, { createDatabaseAdapter, DatabaseMigrationService } from "@elizaos/plugin-sql";
import { anthropicPlugin } from "@elizaos/plugin-anthropic";
import * as dotenv from "dotenv";

import { character } from "./character.ts";
import { tpmSignPlugin } from "./plugin/index.ts";

const repo = resolve(import.meta.dir, "../../..");

/** Keys the runtime may read; ElizaOS 1.x `getSetting` does not look at process.env. */
const SETTINGS = [
  "BASE_SEPOLIA_RPC_URL",
  "AGENT_SIGNER_BIN",
  "AGENT_CONFIG",
  "X402_AGENT_CONFIG",
  "AGENT_ENV_FILE",
  "AGENT_SPONSORED",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_SMALL_MODEL",
  "ANTHROPIC_LARGE_MODEL",
  "PGLITE_DATA_DIR",
];

export function loadEnv() {
  // The project's .env (RPC, bundler) first, then a local one for overrides.
  process.env.AGENT_ENV_FILE ??= resolve(repo, "../.env");
  dotenv.config({ path: process.env.AGENT_ENV_FILE });
  dotenv.config({ override: true });
  process.env.TPM_SIGN_REPO ??= repo;
  // plugin-anthropic 1.5.x always sends `temperature`, which the newest models reject;
  // its built-in defaults (claude-3-5-haiku-20241022) are retired.
  process.env.ANTHROPIC_SMALL_MODEL ??= "claude-haiku-4-5";
  process.env.ANTHROPIC_LARGE_MODEL ??= "claude-sonnet-4-6";
  process.env.PGLITE_DATA_DIR ??= resolve(import.meta.dir, "../.eliza/pglite");
  const settings: Record<string, string> = { TPM_SIGN_REPO: process.env.TPM_SIGN_REPO };
  for (const k of SETTINGS) if (process.env[k]) settings[k] = process.env[k]!;
  return settings;
}

/**
 * ElizaOS 1.7.2 `runtime.initialize()` reads the `agents` table before it runs
 * plugin migrations, so a fresh PGlite fails with `relation "agents" does not
 * exist`. `elizaos start` (@elizaos/server) migrates first; do the same here.
 */
async function migrate(dataDir: string) {
  const db = createDatabaseAdapter({ dataDir }, "00000000-0000-0000-0000-000000000000");
  await db.init();
  const m = new DatabaseMigrationService();
  await m.initializeWithDatabase(db.getDatabase());
  m.discoverAndRegisterPluginSchemas([sqlPlugin]);
  await m.runAllPluginMigrations();
}

export async function startAgent({ withLlm }: { withLlm: boolean }): Promise<{ eliza: ElizaOS; runtime: IAgentRuntime }> {
  const settings = loadEnv();
  await migrate(process.env.PGLITE_DATA_DIR!);
  const plugins: Plugin[] = [sqlPlugin, ...(withLlm ? [anthropicPlugin, bootstrapPlugin] : []), tpmSignPlugin];
  const eliza = new ElizaOS();
  const [runtime] = await eliza.addAgents(
    [{ character: { ...character, plugins: [], settings: { ...character.settings, secrets: settings } }, plugins }],
    { autoStart: true, returnRuntimes: true },
  );
  return { eliza, runtime };
}
