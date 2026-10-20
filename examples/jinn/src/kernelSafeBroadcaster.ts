/**
 * A drop-in for Jinn's `BaseVenueSafeBroadcaster`
 * (`packages/marketplace/venue-base/src/broadcast/safe-broadcaster.ts`) where
 * the Safe's owner is a TPM_sign Kernel account instead of an agent EOA.
 *
 * Jinn's broadcaster signs the Safe transaction hash with the agent's private
 * key (eth_sign, v + 4) and sends `execTransaction` from that EOA. Here the
 * Kernel account itself calls `execTransaction` with a *pre-validated*
 * signature (r = owner, s = 0, v = 1), which Safe accepts because
 * msg.sender is that owner — no off-chain signature, no ERC-1271. The call is
 * one UserOperation signed by the agent's hardware key; on-chain, AgentPolicy
 * judges the Safe transaction's inner call (or every leg of a MultiSend batch)
 * against the owner's allow-list.
 *
 * The types below mirror Jinn's structurally, so this file compiles on its
 * own; inside Jinn, import theirs and pass `classify` / `innerRevert` from
 * `@jinn-network/venue-base` and `@jinn-network/marketplace-binding`.
 */
import {
  decodeEventLog,
  encodeFunctionData,
  parseAbi,
  zeroAddress,
  type Address,
  type Hex,
  type Log,
  type PublicClient,
} from "viem";

import { agentSignerSend, AgentSignerError, type AgentSignerConfig } from "./agentSignerCli";

// --- Jinn's port, structurally (safe-broadcaster.ts:40-78, classify.ts:8) ---

export interface SafeBroadcastRequest {
  readonly to: Address;
  readonly value: bigint;
  readonly data: Hex;
  readonly logicalTx: string;
  /** 0 = CALL; 1 = DELEGATECALL, only into MultiSendCallOnly. */
  readonly operation?: 0 | 1;
}

export interface SafeBroadcastReceipt {
  readonly txHash: Hex;
  readonly blockNumber: bigint;
  readonly blockHash: Hex;
  readonly logs: readonly Log[];
  readonly alreadySettled: boolean;
}

export type VenueRevertClassification = "permanent" | "retryable" | "already-settled";

export interface BroadcastLock {
  withSender<T>(chainId: number, sender: Address, fn: () => Promise<T>): Promise<T>;
}

export interface KernelSafeBroadcaster {
  execute(request: SafeBroadcastRequest): Promise<SafeBroadcastReceipt>;
  classify(error: unknown): VenueRevertClassification;
}

// ---------------------------------------------------------------------------

const ENTRY_POINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const SAFE_ABI = parseAbi([
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)",
]);
const ENTRY_POINT_ABI = parseAbi([
  "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)",
]);

/** Safe's pre-validated signature: r = owner, s = 0, v = 1 (same as Jinn's `encodePreValidatedSignature`). */
export function preValidatedSignature(owner: Address): Hex {
  return `0x${owner.slice(2).toLowerCase().padStart(64, "0")}${"0".repeat(64)}01`;
}

/**
 * One bundle can carry several UserOperations. The logs of ours are those
 * between the previous UserOperationEvent (or the start) and our own —
 * without this cut, a `TaskCreated` from someone else's operation in the same
 * bundle would look like ours.
 */
export function userOpLogs(logs: readonly Log[], userOpHash: Hex): Log[] {
  let start = 0;
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i]!;
    if (log.address.toLowerCase() !== ENTRY_POINT_V07.toLowerCase()) continue;
    try {
      const ev = decodeEventLog({ abi: ENTRY_POINT_ABI, data: log.data, topics: log.topics as [Hex, ...Hex[]] });
      if (ev.args.userOpHash.toLowerCase() === userOpHash.toLowerCase()) {
        return logs.slice(start, i).filter((l) => l.address.toLowerCase() !== ENTRY_POINT_V07.toLowerCase());
      }
      start = i + 1;
    } catch {
      // BeforeExecution, Deposited, ... — not a boundary
    }
  }
  throw new Error(`UserOperationEvent ${userOpHash} not in the bundle receipt`);
}

export function createKernelSafeBroadcaster(input: {
  readonly chainId: number;
  readonly safeAddress: Address;
  readonly publicClient: PublicClient;
  /** `signer.account` is the Kernel account, the Safe's (sole) owner. */
  readonly signer: AgentSignerConfig;
  /** Jinn's durable per-sender lock; keyed by the Kernel account. Optional standalone. */
  readonly lock?: BroadcastLock;
  /** Jinn's `classifyBroadcastError`; the default treats a policy refusal as permanent. */
  readonly classify?: (error: unknown) => VenueRevertClassification;
}): KernelSafeBroadcaster {
  const kernel = input.signer.account;
  const signature = preValidatedSignature(kernel);
  const classify =
    input.classify ??
    ((error: unknown): VenueRevertClassification =>
      error instanceof AgentSignerError && (error.kind === "nonce" || error.kind === "hardware") ? "retryable" : "permanent");

  async function executeInner(req: SafeBroadcastRequest): Promise<SafeBroadcastReceipt> {
    const data = encodeFunctionData({
      abi: SAFE_ABI,
      functionName: "execTransaction",
      // no refund (gasPrice 0): AgentPolicy refuses anything else
      args: [req.to, req.value, req.data, req.operation ?? 0, 0n, 0n, 0n, zeroAddress, zeroAddress, signature],
    });
    // The Safe pays `req.value` from its own balance; the outer call carries none.
    const sent = await agentSignerSend(input.signer, { to: input.safeAddress, value: 0n, data });
    const receipt = await input.publicClient.getTransactionReceipt({ hash: sent.txHash });
    return {
      txHash: sent.txHash,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      logs: userOpLogs(receipt.logs, sent.userOpHash),
      alreadySettled: false,
    };
    // NOTE for a retry layer: a v = 1 signature does not commit to the Safe
    // nonce, so an unpinned resend after an AgentSignerError of kind
    // "not-included" may execute the call twice. Record the first attempt's
    // EntryPoint nonce per logicalTx and resend only with
    // `agentSignerSend(..., { ..., nonce })`, or reconcile `error.userOpHash`
    // (eth_getUserOperationReceipt on the bundler) first.
  }

  return {
    classify,
    execute(req) {
      return input.lock ? input.lock.withSender(input.chainId, kernel, () => executeInner(req)) : executeInner(req);
    },
  };
}
