/**
 * The agent's on-chain identity for ElizaOS: a ZeroDev Kernel account on
 * Base Sepolia whose agent key lives in hardware (TPM / Secure Enclave /
 * TROPIC01). Writes go through `agent-signer op send --json` (the same bridge
 * as examples/agentkit), x402 payments through `agent-signer x402 fetch`;
 * reads use a plain viem client. There is no key and no signing method here.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { createPublicClient, formatEther, http, type Hex } from "viem";
import { baseSepolia } from "viem/chains";

import {
  type AgentSignerOptions,
  type Call,
  type Included,
  type PaidResponse,
  sendCall,
  x402Fetch,
} from "../../../agentkit/src/agentSigner.ts";

export interface TpmWalletConfig extends AgentSignerOptions {
  rpcUrl: string;
  /**
   * A second permission of the same account whose mandate pays x402
   * (signer/agent.x402.base-sepolia.json). Without it the agent cannot pay.
   */
  x402Config?: string;
}

interface X402Mandate {
  tokens?: { token: Hex; maxPerOp: string; budget: string; x402?: boolean }[];
}

interface AgentConfigFile {
  account?: Hex;
  deployments: string;
  policy?: { maxValuePerOp?: string; budget?: string; validUntil?: number; allow?: { target: Hex; selector: Hex }[] };
}

export class TpmAgentWallet {
  readonly address: Hex;
  /** Contract addresses of this deployment (demoCounter, entryPoint, ...). */
  readonly deployments: Record<string, string>;
  /** The mandate as configured locally (the on-chain AgentPolicy is what actually enforces it). */
  readonly policy: AgentConfigFile["policy"];
  readonly client;
  /** x402 tokens of the paying permission, if one is configured. */
  readonly x402Tokens: { token: Hex; maxPerOp: string; budget: string }[] = [];
  readonly #opts: AgentSignerOptions;
  readonly #x402?: AgentSignerOptions;

  constructor(config: TpmWalletConfig) {
    const file = JSON.parse(readFileSync(config.agentConfig, "utf8")) as AgentConfigFile;
    if (!file.account) {
      throw new Error(`${config.agentConfig} has no pinned "account"; run \`agent-signer account status\` and pin it`);
    }
    this.address = file.account;
    this.policy = file.policy;
    this.deployments = JSON.parse(readFileSync(resolve(dirname(config.agentConfig), file.deployments), "utf8"));
    this.#opts = config;
    if (config.x402Config) {
      const x = JSON.parse(readFileSync(config.x402Config, "utf8")) as AgentConfigFile & { policy?: X402Mandate };
      if (x.account !== this.address) {
        throw new Error(`${config.x402Config} is for account ${x.account}, not ${this.address}`);
      }
      this.x402Tokens = (x.policy?.tokens ?? []).filter((t) => t.x402);
      this.#x402 = { ...config, agentConfig: config.x402Config };
    }
    this.client = createPublicClient({ chain: baseSepolia, transport: http(config.rpcUrl) });
  }

  readonly chainId = baseSepolia.id;

  async balanceEth(): Promise<string> {
    return formatEther(await this.client.getBalance({ address: this.address }));
  }

  /** One call -> one UserOperation, signed in hardware, checked by AgentPolicy, waited for inclusion. */
  send(call: Call): Promise<Included> {
    return sendCall(this.#opts, call);
  }

  /** GET a URL, paying with x402 under the paying permission's token budget. */
  fetchPaid(url: string, maxAmount?: bigint): Promise<PaidResponse> {
    if (!this.#x402) throw new Error("no x402 permission configured (X402_AGENT_CONFIG)");
    return x402Fetch(this.#x402, url, maxAmount);
  }
}
