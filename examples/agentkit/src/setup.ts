/**
 * Wiring shared by the smoke test and the chatbot: the wallet provider from
 * environment variables, plus two demo actions for the DemoCounter contract
 * that the agent's mandate allow-lists.
 */
import "./noTelemetry";

import { resolve } from "node:path";

import { AgentKit, customActionProvider, walletActionProvider } from "@coinbase/agentkit";
import * as dotenv from "dotenv";
import { encodeFunctionData, parseAbi } from "viem";
import { z } from "zod";

import { TpmKernelWalletProvider } from "./tpmKernelWalletProvider";

const repo = resolve(__dirname, "../../..");

export function walletFromEnv(): TpmKernelWalletProvider {
  // The project's .env (RPC, bundler) first, then a local one for overrides.
  const envFile = process.env.AGENT_ENV_FILE ?? resolve(repo, "../.env");
  dotenv.config({ path: envFile });
  dotenv.config();

  const rpcUrl = process.env.BASE_SEPOLIA_RPC_URL;
  if (!rpcUrl) throw new Error("set BASE_SEPOLIA_RPC_URL (or AGENT_ENV_FILE pointing at a .env with it)");

  return new TpmKernelWalletProvider({
    rpcUrl,
    bin: process.env.AGENT_SIGNER_BIN ?? resolve(repo, "signer/target/debug/agent-signer"),
    agentConfig: process.env.AGENT_CONFIG ?? resolve(repo, "signer/agent.tropic01.base-sepolia.json"),
    envFile,
    sponsored: process.env.AGENT_SPONSORED !== "0",
  });
}

const counterAbi = parseAbi(["function increment()", "function count() view returns (uint256)"]);

export function demoCounterActions(wallet: TpmKernelWalletProvider) {
  const counter = wallet.deployments.demoCounter as `0x${string}`;
  // AgentKit passes the wallet only to invoke functions of arity 2.
  return customActionProvider<TpmKernelWalletProvider>([
    {
      name: "demo_counter_read",
      description: "Read the current value of the DemoCounter contract.",
      schema: z.object({}),
      invoke: async (w: TpmKernelWalletProvider, _args: object) => {
        const n = await w.readContract({ address: counter, abi: counterAbi, functionName: "count" });
        return `DemoCounter ${counter} = ${n}`;
      },
    },
    {
      name: "demo_counter_increment",
      description:
        "Increment the DemoCounter contract by one. Sends an on-chain transaction from the agent account.",
      schema: z.object({}),
      invoke: async (w: TpmKernelWalletProvider, _args: object) => {
        const tx = await w.sendTransaction({
          to: counter,
          data: encodeFunctionData({ abi: counterAbi, functionName: "increment" }),
        });
        return `Incremented DemoCounter: tx ${tx}`;
      },
    },
  ]);
}

export async function agentKitFromEnv() {
  const wallet = walletFromEnv();
  const agentkit = await AgentKit.from({
    walletProvider: wallet,
    actionProviders: [walletActionProvider(), demoCounterActions(wallet)],
  });
  return { wallet, agentkit };
}
