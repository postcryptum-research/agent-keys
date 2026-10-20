/**
 * Coinbase AgentKit wallet provider for a TPM_sign agent account.
 *
 * Every write goes through `agent-signer`: one call becomes one ERC-4337
 * UserOperation on the Kernel account, signed by the agent's P-256 key inside
 * hardware and checked on-chain by AgentPolicy. Reads use a plain viem client.
 *
 * Off-chain signatures (`sign`, `signMessage`, `signTypedData`) are refused:
 * the agent permission has ERC-1271 disabled on purpose, because a signed
 * permit or order would bypass the call allow-list. Raw transactions do not
 * exist for a smart account either.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { EvmWalletProvider, Network } from "@coinbase/agentkit";
import {
  Abi,
  ContractFunctionArgs,
  ContractFunctionName,
  createPublicClient,
  http,
  PublicClient,
  ReadContractParameters,
  ReadContractReturnType,
  TransactionReceipt,
  TransactionRequest,
} from "viem";
import { baseSepolia } from "viem/chains";

import { AgentSignerOptions, sendCall } from "./agentSigner";

export interface TpmKernelWalletConfig extends AgentSignerOptions {
  rpcUrl: string;
}

interface AgentConfigFile {
  account?: `0x${string}`;
  deployments: string;
}

export class TpmKernelWalletProvider extends EvmWalletProvider {
  readonly #opts: AgentSignerOptions;
  readonly #client: PublicClient;
  readonly #account: `0x${string}`;
  /** Contract addresses of this deployment (demoCounter, entryPoint, ...). */
  readonly deployments: Record<string, string>;

  constructor(config: TpmKernelWalletConfig) {
    super();
    const file = JSON.parse(readFileSync(config.agentConfig, "utf8")) as AgentConfigFile;
    if (!file.account) {
      throw new Error(
        `${config.agentConfig} has no pinned "account"; run \`agent-signer account status\` and pin it`,
      );
    }
    this.#account = file.account;
    this.deployments = JSON.parse(
      readFileSync(resolve(dirname(config.agentConfig), file.deployments), "utf8"),
    );
    this.#opts = config;
    // Base's OP-stack formatters make the client's type narrower than the
    // generic PublicClient AgentKit declares; the runtime object is the same.
    this.#client = createPublicClient({
      chain: baseSepolia,
      transport: http(config.rpcUrl),
    }) as unknown as PublicClient;
  }

  getAddress(): string {
    return this.#account;
  }

  getNetwork(): Network {
    return { protocolFamily: "evm", networkId: "base-sepolia", chainId: String(baseSepolia.id) };
  }

  getName(): string {
    return "tpm_kernel_wallet_provider";
  }

  getPublicClient(): PublicClient {
    return this.#client;
  }

  getBalance(): Promise<bigint> {
    return this.#client.getBalance({ address: this.#account });
  }

  /**
   * Returns the hash of the transaction that included the UserOperation.
   * `agent-signer` waits for inclusion and checks the operation actually
   * executed, so the returned hash is final.
   */
  async sendTransaction(tx: TransactionRequest): Promise<`0x${string}`> {
    if (!tx.to) throw new Error("contract creation is not allowed for the agent");
    const included = await sendCall(this.#opts, { to: tx.to, value: tx.value, data: tx.data });
    return included.tx;
  }

  async nativeTransfer(to: string, value: string): Promise<string> {
    return this.sendTransaction({ to: to as `0x${string}`, value: BigInt(value) });
  }

  waitForTransactionReceipt(txHash: `0x${string}`): Promise<TransactionReceipt> {
    return this.#client.waitForTransactionReceipt({ hash: txHash });
  }

  readContract<
    const abi extends Abi | readonly unknown[],
    functionName extends ContractFunctionName<abi, "pure" | "view">,
    const args extends ContractFunctionArgs<abi, "pure" | "view", functionName>,
  >(params: ReadContractParameters<abi, functionName, args>): Promise<ReadContractReturnType<abi, functionName, args>> {
    return this.#client.readContract<abi, functionName, args>(params);
  }

  sign(_hash: `0x${string}`): Promise<`0x${string}`> {
    return refuse("raw hash signing");
  }

  signMessage(_message: string | Uint8Array): Promise<`0x${string}`> {
    return refuse("message signing (ERC-1271)");
  }

  signTypedData(_typedData: unknown): Promise<`0x${string}`> {
    return refuse("typed-data signing (ERC-1271)");
  }

  signTransaction(_tx: TransactionRequest): Promise<`0x${string}`> {
    return refuse("raw transaction signing");
  }
}

function refuse(what: string): Promise<never> {
  return Promise.reject(
    new Error(
      `${what} is disabled for this agent: its key is a hardware P-256 key behind an ERC-4337 ` +
        `account whose mandate only allows on-chain calls. Use a transaction instead.`,
    ),
  );
}
