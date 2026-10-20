/**
 * Thin bridge to the Rust `agent-signer` CLI.
 *
 * The CLI owns everything that touches the key: it builds the UserOperation,
 * asks the hardware (TPM / Secure Enclave / TROPIC01) to sign the
 * userOpHash, and delivers it through a bundler or `handleOps`. This process
 * only ever sees the result — there is no key here to steal.
 */
import { spawn } from "node:child_process";

export interface AgentSignerOptions {
  /** Path to the `agent-signer` binary (built with the backend features you need). */
  bin: string;
  /** Agent account config (keys, mandate, deployments), e.g. signer/agent.tropic01.base-sepolia.json. */
  agentConfig: string;
  /** Optional .env with BASE_SEPOLIA_RPC_URL, BUNDLER_URL, GAS_WALLET_KEYFILE. */
  envFile?: string;
  /** Let the whitelist paymaster pay the gas. */
  sponsored?: boolean;
  /** Give up on a single operation after this long (hardware + inclusion). */
  timeoutMs?: number;
}

export interface Call {
  to: `0x${string}`;
  value?: bigint;
  data?: `0x${string}`;
}

export interface Included {
  account: `0x${string}`;
  userOpHash: `0x${string}`;
  tx: `0x${string}`;
  block: number;
  gasUsed: number;
}

/** Kernel's `PolicyFailed(uint256)` selector: a permission policy refused the operation. */
const POLICY_FAILED = "3e4983f6";

/** The operation never made it on-chain. `reason` is the CLI's own explanation. */
export class AgentSignerError extends Error {
  constructor(
    readonly reason: string,
    readonly stderr: string,
  ) {
    super(reason);
    this.name = "AgentSignerError";
  }

  /**
   * True when the account itself refused the operation at validation — the
   * hardware signed, but the on-chain mandate (AgentPolicy) said no: target
   * or selector not allow-listed, value over the cap, budget spent, expired.
   */
  get rejectedByPolicy(): boolean {
    return this.stderr.includes(POLICY_FAILED);
  }
}

/** Send one call from the agent account, signed in hardware, and wait for inclusion. */
export function sendCall(opts: AgentSignerOptions, call: Call): Promise<Included> {
  const args = [
    "op",
    "send",
    "--agent",
    opts.agentConfig,
    "--target",
    call.to,
    "--wei",
    (call.value ?? 0n).toString(),
    "--data",
    call.data ?? "0x",
    "--json",
  ];
  if (opts.envFile) args.push("--env-file", opts.envFile);
  if (opts.sponsored) args.push("--sponsored");

  return new Promise((resolve, reject) => {
    const child = spawn(opts.bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => (stdout += b));
    child.stderr.on("data", (b) => (stderr += b));

    const timer = setTimeout(() => child.kill("SIGTERM"), opts.timeoutMs ?? 180_000);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new AgentSignerError(`cannot run ${opts.bin}: ${e.message}`, ""));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new AgentSignerError(explain(stderr), stderr));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim().split("\n").pop()!) as Included);
      } catch {
        reject(new AgentSignerError(`unexpected agent-signer output: ${stdout}`, stderr));
      }
    });
  });
}

/** One readable line from the CLI's `Error: … Caused by: …` report. */
function explain(stderr: string): string {
  if (stderr.includes(POLICY_FAILED)) {
    return "refused by the account's on-chain mandate (AgentPolicy): the target, selector, value or budget is not allowed for this agent";
  }
  const at = stderr.lastIndexOf("Error: ");
  const report = (at >= 0 ? stderr.slice(at + 7) : stderr).split("\n").filter((l) => !l.startsWith("ERROR:tcti"));
  return report.map((l) => l.trim()).filter(Boolean).join(" ").replace(/\s*Caused by:\s*/g, ": ") || "agent-signer failed";
}
