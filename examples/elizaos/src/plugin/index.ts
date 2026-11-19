/**
 * plugin-agent-keys: ElizaOS actions for an agent whose only wallet is a
 * hardware-signed ERC-4337 account bounded on-chain by AgentPolicy.
 *
 *   TPM_WALLET (provider)      address, balance, mandate -> into the prompt
 *   GET_AGENT_WALLET           same, as an explicit answer
 *   READ_DEMO_COUNTER          view call, no signature
 *   INCREMENT_DEMO_COUNTER     allow-listed call -> lands
 *   SEND_TX_WITHIN_MANDATE     arbitrary (to, value, data) the user asks for;
 *                              the account itself decides (PolicyFailed if not allowed)
 *   PAY_FOR_URL                GET a URL and pay its x402 price (USDC) from the
 *                              mandate's token budget
 *
 * Deliberately not loaded together with @elizaos/plugin-wallet / plugin-evm:
 * those resolve EVM_PRIVATE_KEY and generate one if missing.
 */
import {
  type Action,
  type ActionResult,
  type HandlerCallback,
  type IAgentRuntime,
  logger,
  type Memory,
  ModelType,
  type Plugin,
  type Provider,
  Service,
  type State,
} from "@elizaos/core";
import { encodeFunctionData, formatEther, isAddress, isHex, parseAbi, parseEther, type Hex } from "viem";
import { resolve } from "node:path";

import { AgentSignerError } from "../../../agentkit/src/agentSigner.ts";
import { TpmAgentWallet } from "./wallet.ts";

const counterAbi = parseAbi(["function increment()", "function count() view returns (uint256)"]);
const explorer = (tx: string) => `https://sepolia.basescan.org/tx/${tx}`;

// ---------------------------------------------------------------- service

export class TpmWalletService extends Service {
  static override serviceType = "tpm_wallet";
  capabilityDescription = "Hardware-signed ERC-4337 agent account (agent-keys); on-chain calls only, no off-chain signatures";
  wallet!: TpmAgentWallet;

  static override async start(runtime: IAgentRuntime): Promise<TpmWalletService> {
    const s = new TpmWalletService(runtime);
    const get = (k: string) => {
      const v = runtime.getSetting(k);
      return v === null || v === undefined || v === "" ? undefined : String(v);
    };
    const repo = get("TPM_SIGN_REPO") ?? resolve(import.meta.dir, "../../../..");
    const rpcUrl = get("BASE_SEPOLIA_RPC_URL");
    if (!rpcUrl) throw new Error("plugin-agent-keys: set BASE_SEPOLIA_RPC_URL");
    s.wallet = new TpmAgentWallet({
      rpcUrl,
      bin: get("AGENT_SIGNER_BIN") ?? resolve(repo, "signer/target/debug/agent-signer"),
      agentConfig: get("AGENT_CONFIG") ?? resolve(repo, "signer/agent.tropic01.base-sepolia.json"),
      x402Config: get("X402_AGENT_CONFIG"),
      envFile: get("AGENT_ENV_FILE") ?? resolve(repo, "../.env"),
      sponsored: get("AGENT_SPONSORED") !== "0",
    });
    logger.info(`[agent-keys] agent account ${s.wallet.address} on Base Sepolia`);
    return s;
  }

  async stop(): Promise<void> {}
}

const walletOf = (runtime: IAgentRuntime) => {
  const s = runtime.getService<TpmWalletService>(TpmWalletService.serviceType);
  if (!s) throw new Error("tpm_wallet service is not running");
  return s.wallet;
};

/** Turn a bridge failure into a result the LLM can explain truthfully. */
function failure(e: unknown, what: string): ActionResult {
  const refused = e instanceof AgentSignerError && e.rejectedByPolicy;
  const reason = e instanceof Error ? e.message : String(e);
  return {
    success: false,
    text: refused
      ? `${what} was refused by the account's on-chain mandate (AgentPolicy). Nothing was sent.`
      : `${what} failed: ${reason}`,
    values: { refusedByPolicy: refused },
    error: reason,
  };
}

async function reply(callback: HandlerCallback | undefined, r: ActionResult, action: string) {
  await callback?.({ text: r.text ?? "", actions: [action] });
  return r;
}

// ---------------------------------------------------------------- provider

const walletProvider: Provider = {
  name: "TPM_WALLET",
  description: "The agent's own on-chain account and its mandate",
  get: async (runtime) => {
    const w = walletOf(runtime);
    const p = w.policy;
    const text =
      `Your on-chain account: ${w.address} (Base Sepolia, chain ${w.chainId}), balance ${await w.balanceEth()} ETH. ` +
      `It is an ERC-4337 smart account; your key is in hardware and you never see it. ` +
      (p
        ? `Mandate: max ${formatEther(BigInt(p.maxValuePerOp ?? 0))} ETH per call, budget ${formatEther(BigInt(p.budget ?? 0))} ETH, ` +
          `${p.allow?.length ?? 0} allow-listed (target, selector) pairs, valid until ${new Date((p.validUntil ?? 0) * 1000).toISOString()}. `
        : "") +
      (w.x402Tokens.length
        ? `You can pay for HTTP resources that ask for x402 payment (action PAY_FOR_URL), up to ` +
          w.x402Tokens.map((t) => `${Number(t.maxPerOp) / 1e6} per request and ${Number(t.budget) / 1e6} in total of token ${t.token}`).join("; ") +
          ` (USDC has 6 decimals). `
        : "") +
      `You cannot sign messages, permits or typed data. Anything outside the mandate is refused on-chain.`;
    return { text, values: { tpmAccount: w.address } };
  },
};

// ---------------------------------------------------------------- actions

const always = async () => true;

const getWallet: Action = {
  name: "GET_AGENT_WALLET",
  similes: ["WALLET_ADDRESS", "MY_BALANCE"],
  description: "Report the agent's own account address, ETH balance and on-chain mandate.",
  validate: always,
  handler: async (runtime, _m, _s, _o, callback) => {
    const w = walletOf(runtime);
    const r: ActionResult = {
      success: true,
      text: `My account is ${w.address} on Base Sepolia with ${await w.balanceEth()} ETH. Its key is held in hardware; the mandate is enforced on-chain.`,
      values: { address: w.address },
    };
    return reply(callback, r, "GET_AGENT_WALLET");
  },
  examples: [[
    { name: "{{user}}", content: { text: "what is your wallet address?" } },
    { name: "{{agent}}", content: { text: "Let me check.", actions: ["GET_AGENT_WALLET"] } },
  ]],
};

const readCounter: Action = {
  name: "READ_DEMO_COUNTER",
  similes: ["COUNTER_VALUE"],
  description: "Read the current value of the DemoCounter contract (no transaction).",
  validate: always,
  handler: async (runtime, _m, _s, _o, callback) => {
    const w = walletOf(runtime);
    const address = w.deployments.demoCounter as Hex;
    const n = await w.client.readContract({ address, abi: counterAbi, functionName: "count" });
    return reply(callback, { success: true, text: `DemoCounter ${address} = ${n}`, values: { count: n.toString() } }, "READ_DEMO_COUNTER");
  },
  examples: [[
    { name: "{{user}}", content: { text: "what's the counter at?" } },
    { name: "{{agent}}", content: { text: "Reading it.", actions: ["READ_DEMO_COUNTER"] } },
  ]],
};

const incrementCounter: Action = {
  name: "INCREMENT_DEMO_COUNTER",
  similes: ["BUMP_COUNTER"],
  description: "Increment the DemoCounter contract by one. Sends an on-chain transaction from the agent account.",
  validate: always,
  handler: async (runtime, _m, _s, _o, callback) => {
    const w = walletOf(runtime);
    try {
      const inc = await w.send({
        to: w.deployments.demoCounter as Hex,
        data: encodeFunctionData({ abi: counterAbi, functionName: "increment" }),
      });
      return reply(callback, {
        success: true,
        text: `Incremented DemoCounter in block ${inc.block}: ${explorer(inc.tx)}`,
        values: { tx: inc.tx, userOpHash: inc.userOpHash },
      }, "INCREMENT_DEMO_COUNTER");
    } catch (e) {
      return reply(callback, failure(e, "Incrementing the counter"), "INCREMENT_DEMO_COUNTER");
    }
  },
  examples: [[
    { name: "{{user}}", content: { text: "bump the counter" } },
    { name: "{{agent}}", content: { text: "Sending the transaction.", actions: ["INCREMENT_DEMO_COUNTER"] } },
  ]],
};

const extractCall = `Extract the single on-chain call the user asked for from the message below.
Return JSON: {"to": "0x...40 hex", "valueEth": "decimal string, 0 if none", "data": "0x calldata or 0x"}.
If the message does not name a target address, return {"to": null}.

Message: {{text}}`;

const sendWithinMandate: Action = {
  name: "SEND_TX_WITHIN_MANDATE",
  similes: ["SEND_ETH", "TRANSFER", "SEND_TRANSACTION", "CALL_CONTRACT"],
  description:
    "Send one transaction (ETH and/or calldata) from the agent account to an address the user gives. " +
    "The account's on-chain mandate decides whether it goes through; report a refusal plainly.",
  validate: always,
  handler: async (runtime: IAgentRuntime, message: Memory, _s?: State, _o?, callback?: HandlerCallback) => {
    const w = walletOf(runtime);
    const obj = (await runtime.useModel(ModelType.OBJECT_SMALL, {
      prompt: extractCall.replace("{{text}}", message.content.text ?? ""),
    })) as { to?: string | null; valueEth?: string; data?: string };
    if (!obj?.to || !isAddress(obj.to)) {
      return reply(callback, { success: false, text: "Which address should I send to?" }, "SEND_TX_WITHIN_MANDATE");
    }
    const data = obj.data && isHex(obj.data) ? (obj.data as Hex) : "0x";
    let value: bigint;
    try {
      value = parseEther(obj.valueEth ?? "0");
    } catch {
      return reply(callback, { success: false, text: `Unclear amount "${obj.valueEth}".` }, "SEND_TX_WITHIN_MANDATE");
    }
    try {
      const inc = await w.send({ to: obj.to, value, data });
      return reply(callback, {
        success: true,
        text: `Sent ${formatEther(value)} ETH to ${obj.to}${data !== "0x" ? " with calldata" : ""}: ${explorer(inc.tx)}`,
        values: { tx: inc.tx },
      }, "SEND_TX_WITHIN_MANDATE");
    } catch (e) {
      return reply(callback, failure(e, `Sending ${formatEther(value)} ETH to ${obj.to}`), "SEND_TX_WITHIN_MANDATE");
    }
  },
  examples: [[
    { name: "{{user}}", content: { text: "send 0.0000001 ETH to 0x000000000000000000000000000000000000dEaD" } },
    { name: "{{agent}}", content: { text: "Trying it; my mandate decides.", actions: ["SEND_TX_WITHIN_MANDATE"] } },
  ]],
};

const payForUrl: Action = {
  name: "PAY_FOR_URL",
  similes: ["X402_FETCH", "BUY_API_CALL", "FETCH_PAID_URL"],
  description:
    "Fetch an http(s) URL the user gives; if the server asks for an x402 payment, pay it in USDC from the agent " +
    "account (registered on-chain against the mandate's token budget) and return the content.",
  validate: async (runtime, message) =>
    /https?:\/\/\S+/.test(message.content.text ?? "") && walletOf(runtime).x402Tokens.length > 0,
  handler: async (runtime: IAgentRuntime, message: Memory, _s?: State, _o?, callback?: HandlerCallback) => {
    const w = walletOf(runtime);
    const url = (message.content.text ?? "").match(/https?:\/\/[^\s"'<>]+/)?.[0];
    if (!url) return reply(callback, { success: false, text: "Which URL?" }, "PAY_FOR_URL");
    try {
      const r = await w.fetchPaid(url);
      if (r.status >= 400) {
        const why = r.refused ? ` (${r.refused})` : "";
        return reply(callback, {
          success: false,
          text:
            `${url} answered ${r.status}${why}; nothing was paid. The registered amount returns to the ` +
            `budget once the authorization expires (agent-signer x402 reclaim).`,
          values: { status: r.status },
        }, "PAY_FOR_URL");
      }
      const paid = r.settlement?.transaction ? ` Paid: ${explorer(r.settlement.transaction)}.` : "";
      const body = r.body.length > 1500 ? `${r.body.slice(0, 1500)}…` : r.body;
      return reply(callback, {
        success: true,
        text: `${url} →${paid}\n${body}`,
        values: { status: r.status, settlementTx: r.settlement?.transaction },
      }, "PAY_FOR_URL");
    } catch (e) {
      return reply(callback, failure(e, `Paying for ${url}`), "PAY_FOR_URL");
    }
  },
  examples: [[
    { name: "{{user}}", content: { text: "get me the quote from http://localhost:4021/quote" } },
    { name: "{{agent}}", content: { text: "Fetching it; I pay if it asks.", actions: ["PAY_FOR_URL"] } },
  ]],
};

export const tpmSignPlugin: Plugin = {
  name: "plugin-agent-keys",
  description: "On-chain actions through a hardware-signed ERC-4337 account bounded by AgentPolicy",
  services: [TpmWalletService],
  providers: [walletProvider],
  actions: [getWallet, readCounter, incrementCounter, sendWithinMandate, payForUrl],
};

export default tpmSignPlugin;
