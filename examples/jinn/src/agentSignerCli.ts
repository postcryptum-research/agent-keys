/**
 * `agent-signer op send --json` as a typed function, with the failure kinds a
 * Safe broadcaster has to tell apart (policy refusal vs. inner revert vs. a
 * submission whose fate is unknown).
 */
import { spawn } from "node:child_process";

import type { Address, Hex } from "viem";

export interface AgentSignerConfig {
  /** Path to the `agent-signer` binary. */
  readonly bin: string;
  /** Agent account config (`--agent`). */
  readonly configPath: string;
  /** The Kernel account the config pins; every result is checked against it. */
  readonly account: Address;
  /** `.env` with BASE_SEPOLIA_RPC_URL / BUNDLER_URL (`--env-file`). */
  readonly envFile?: string;
  /** Gas from the whitelist paymaster instead of the account's deposit. */
  readonly sponsored?: boolean;
  /** The CLI itself waits up to 120 s for inclusion; keep this above that. */
  readonly timeoutMs?: number;
}

export interface AgentSignerResult {
  readonly account: Address;
  readonly userOpHash: Hex;
  /** EntryPoint nonce the operation used; pass it back as `nonce` to retry safely. */
  readonly nonce: Hex;
  readonly txHash: Hex;
  readonly blockNumber: bigint;
  readonly gasUsed: bigint;
}

export type AgentSignerErrorKind =
  /** The account's AgentPolicy refused the call (Kernel `PolicyFailed`): never retry. */
  | "policy-denied"
  /** The permission's `validUntil` passed (AA22). */
  | "policy-expired"
  /** Nonce race (AA25): retry only after reconciling the previous userOpHash. */
  | "nonce"
  /** The bundler's simulation hit a revert of the inner call. */
  | "simulation-revert"
  /** Included, but UserOperationEvent.success == false. */
  | "execution-revert"
  /** Accepted by the bundler, not seen included: the outcome is UNKNOWN. */
  | "not-included"
  /** TPM / Secure Enclave / TROPIC01 access. */
  | "hardware"
  | "config"
  | "unknown";

/** Kernel's `PolicyFailed(uint256)` selector. */
const POLICY_FAILED = "3e4983f6";
const USER_OP_HASH_RE = /userOpHash:\s+(0x[0-9a-fA-F]{64})/;

export class AgentSignerError extends Error {
  override readonly name = "AgentSignerError";
  constructor(
    readonly kind: AgentSignerErrorKind,
    message: string,
    readonly stderr: string,
    readonly exitCode: number | null,
    /** Set once the CLI computed it — the handle to reconcile an unknown outcome. */
    readonly userOpHash: Hex | null,
  ) {
    super(message);
  }
}

function classify(stderr: string): AgentSignerErrorKind {
  if (stderr.includes(POLICY_FAILED)) return "policy-denied";
  if (/AA22/.test(stderr)) return "policy-expired";
  if (/AA25|invalid account nonce|is already used/i.test(stderr)) return "nonce";
  if (/AA2\d|signature error/i.test(stderr)) return "policy-denied";
  if (/its execution reverted/.test(stderr)) return "execution-revert";
  if (/reverted during simulation|eth_estimateUserOperationGas/.test(stderr)) return "simulation-revert";
  if (/not included|timed out|waiting for/i.test(stderr)) return "not-included";
  if (/tpmrm0|ttyACM|TROPIC01|Secure Enclave|tcti/i.test(stderr)) return "hardware";
  if (/needs `--features|No such file|loading /i.test(stderr)) return "config";
  return "unknown";
}

/** The CLI's `Error: … Caused by: …` report as one line. */
function reason(stderr: string): string {
  const at = stderr.lastIndexOf("Error: ");
  return (at >= 0 ? stderr.slice(at + 7) : stderr)
    .split("\n")
    .filter((l) => !l.startsWith("ERROR:tcti"))
    .map((l) => l.trim())
    .filter(Boolean)
    .join(" ")
    .replace(/\s*Caused by:\s*/g, ": ");
}

/** Send one call from the Kernel account (agent permission), signed in hardware. */
export function agentSignerSend(
  cfg: AgentSignerConfig,
  call: {
    readonly to: Address;
    readonly value: bigint;
    readonly data: Hex;
    /**
     * Pin the EntryPoint nonce (from an earlier attempt's result). A Safe
     * `v = 1` signature does not commit to the Safe nonce, so a retry of the
     * same Safe transaction must reuse its first nonce: at most one copy is
     * ever included, and a retry after inclusion fails fast ("already used").
     */
    readonly nonce?: Hex;
    /**
     * For `Safe.execTransaction` calldata: the Safe nonce it is meant for.
     * agent-signer sends it as a batch that asserts that nonce on-chain
     * first — the only shape the agent's mandate admits — so a replay
     * reverts instead of executing twice.
     */
    readonly safeNonce?: bigint;
  },
): Promise<AgentSignerResult> {
  const args = ["op", "send", "--agent", cfg.configPath, "--target", call.to, "--wei", call.value.toString(), "--data", call.data, "--json"];
  if (cfg.envFile) args.push("--env-file", cfg.envFile);
  if (cfg.sponsored) args.push("--sponsored");
  if (call.nonce) args.push("--nonce", call.nonce);
  if (call.safeNonce !== undefined) args.push("--safe-nonce", call.safeNonce.toString());

  return new Promise((resolve, reject) => {
    const child = spawn(cfg.bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => (stdout += c));
    child.stderr.setEncoding("utf8").on("data", (c: string) => (stderr += c));
    const timer = setTimeout(() => child.kill("SIGTERM"), cfg.timeoutMs ?? 180_000);

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new AgentSignerError("config", `cannot run ${cfg.bin}: ${err.message}`, stderr, null, null));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const opHash = (stderr.match(USER_OP_HASH_RE)?.[1] ?? null) as Hex | null;
      if (code !== 0) {
        // Killed by our timeout after the bundler accepted: the outcome is unknown.
        const kind = code === null && opHash ? "not-included" : classify(stderr);
        reject(new AgentSignerError(kind, reason(stderr) || `agent-signer exited with ${code}`, stderr, code, opHash));
        return;
      }
      try {
        const j = JSON.parse(stdout.trim().split("\n").pop()!) as {
          account: string;
          userOpHash: string;
          nonce: string;
          tx: string;
          block: number;
          gasUsed: number;
        };
        if (j.account.toLowerCase() !== cfg.account.toLowerCase()) {
          throw new Error(`agent-signer used account ${j.account}, expected ${cfg.account}`);
        }
        resolve({
          account: j.account as Address,
          userOpHash: j.userOpHash as Hex,
          nonce: j.nonce as Hex,
          txHash: j.tx as Hex,
          blockNumber: BigInt(j.block),
          gasUsed: BigInt(j.gasUsed),
        });
      } catch (e) {
        reject(new AgentSignerError("unknown", `unexpected agent-signer output: ${String(e)}`, stderr, code, opHash));
      }
    });
  });
}
