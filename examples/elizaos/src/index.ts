/**
 * Optional: project entry for the stock `elizaos start` (web UI on :3000).
 * The headless `bun run chat` is the primary path; see README for the Sentry
 * caveat of @elizaos/server.
 */
import type { Project, ProjectAgent } from "@elizaos/core";

import { loadEnv } from "./agent.ts";
import { character } from "./character.ts";
import { tpmSignPlugin } from "./plugin/index.ts";

const settings = loadEnv();

export const projectAgent: ProjectAgent = {
  character: { ...character, settings: { ...character.settings, secrets: settings } },
  plugins: [tpmSignPlugin],
};

const project: Project = { agents: [projectAgent] };
export default project;
