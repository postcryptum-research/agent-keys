/**
 * Jinn-shaped Safe traffic from a hardware-signed Kernel owner, on Base Sepolia.
 *
 *   1. a single Safe call (operation 0) — what claim / deliver / lifecycle do;
 *   2. a MultiSendCallOnly batch (operation 1) — what settlement does;
 *   3. the Safe adding an owner — what a compromised agent would try first.
 *
 * Each request goes through `KernelSafeBroadcaster.execute`, exactly as Jinn's
 * venue writers call their broadcaster.
 */
import { resolve } from "node:path";
import { readFileSync } from "node:fs";

import * as dotenv from "dotenv";
import { concatHex, createPublicClient, encodeFunctionData, encodePacked, http, parseAbi, size, type Address, type Hex, type PublicClient } from "viem";
import { baseSepolia } from "viem/chains";

import { AgentSignerError } from "./agentSignerCli";
import { createKernelSafeBroadcaster, type SafeBroadcastRequest } from "./kernelSafeBroadcaster";

const repo = resolve(__dirname, "../../..");
const envFile = process.env.AGENT_ENV_FILE ?? resolve(repo, "../.env");
dotenv.config({ path: envFile });

/** Safe v1.3.0 MultiSendCallOnly — the batcher Jinn's settlement writer targets. */
const MULTI_SEND_CALL_ONLY: Address = "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D";
const SAFE: Address = (process.env.AGENT_SAFE as Address) ?? "0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A";

const counterAbi = parseAbi(["function increment()", "function count() view returns (uint256)"]);
const multiSendAbi = parseAbi(["function multiSend(bytes transactions)"]);

function leg(to: Address, value: bigint, data: Hex): Hex {
  return encodePacked(["uint8", "address", "uint256", "uint256", "bytes"], [0, to, value, BigInt(size(data)), data]);
}

async function main() {
  const configPath = process.env.AGENT_CONFIG ?? resolve(repo, "signer/agent.tropic01.base-sepolia.json");
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  const deployments = JSON.parse(readFileSync(resolve(dirnameOf(configPath), config.deployments), "utf8"));
  const counter = deployments.demoCounter as Address;

  const publicClient = createPublicClient({ chain: baseSepolia, transport: http(process.env.BASE_SEPOLIA_RPC_URL) }) as unknown as PublicClient;
  const broadcaster = createKernelSafeBroadcaster({
    chainId: baseSepolia.id,
    safeAddress: SAFE,
    publicClient,
    signer: {
      bin: process.env.AGENT_SIGNER_BIN ?? resolve(repo, "signer/target/debug/agent-signer"),
      configPath,
      account: config.account,
      envFile,
      sponsored: true,
    },
  });

  const increment = encodeFunctionData({ abi: counterAbi, functionName: "increment" });
  const requests: [string, SafeBroadcastRequest][] = [
    ["single call (claim-like)", { to: counter, value: 0n, data: increment, logicalTx: "demo.increment" }],
    [
      "MultiSendCallOnly batch (settlement-like)",
      {
        to: MULTI_SEND_CALL_ONLY,
        value: 0n,
        operation: 1,
        logicalTx: "demo.batch",
        data: encodeFunctionData({
          abi: multiSendAbi,
          functionName: "multiSend",
          args: [concatHex([leg(counter, 0n, increment), leg(counter, 0n, increment)])],
        }),
      },
    ],
    [
      "Safe adds an owner (compromised agent)",
      {
        to: SAFE,
        value: 0n,
        logicalTx: "demo.attack",
        data: encodeFunctionData({
          abi: parseAbi(["function addOwnerWithThreshold(address owner, uint256 threshold)"]),
          functionName: "addOwnerWithThreshold",
          args: ["0x000000000000000000000000000000000000dEaD", 1n],
        }),
      },
    ],
  ];

  const read = () => publicClient.readContract({ address: counter, abi: counterAbi, functionName: "count" });
  console.log(`Safe ${SAFE} (owner: Kernel ${config.account}), counter = ${await read()}`);
  for (const [label, req] of requests) {
    try {
      const r = await broadcaster.execute(req);
      console.log(`✔ ${label}: tx ${r.txHash}, ${r.logs.length} logs of this op, counter = ${await read()}`);
    } catch (e) {
      if (!(e instanceof AgentSignerError)) throw e;
      console.log(`✘ ${label}: ${e.kind} — ${e.kind === "policy-denied" ? "refused by AgentPolicy on-chain" : e.message}`);
    }
  }
}

function dirnameOf(p: string) {
  return resolve(p, "..");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
