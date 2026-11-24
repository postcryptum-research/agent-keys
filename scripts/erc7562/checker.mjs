// The rule checker of the pinned bundler (Pimlico's Alto) and the one way
// this kit asks it for a verdict; check-traces.mjs and check-run.mjs both
// use it.
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
// the package's "exports" do not name the checker, so it is taken by path
const { tracerResultParserV07 } = await import(
  path.join(here, "node_modules/@pimlico/alto/esm/rpc/validation/TracerResultParserV07.js")
);

// lower case, as the traces have it: the checker compares addresses as text
export const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
export const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100";

// The checker's verdict for a validation trace.
//   op:               { sender, factory?, paymaster? }, the sender defaulting to the trace's
//   precompileAllowed the P-256 precompile (RIP-7212) is not taken for an
//                     un-deployed contract: a bundler set up for a network that has it
//   staked            true: the factory and the paymaster are taken as staked;
//                     "factory": the factory alone
export function verdict(recorded, { op = {}, precompileAllowed = false, staked = false, entryPoint = ENTRY_POINT } = {}) {
  const trace = structuredClone(recorded);
  if (precompileAllowed) for (const level of trace.callsFromEntryPoint) delete level.contractSize?.[P256_PRECOMPILE];
  const sender = op.sender ?? trace.callsFromEntryPoint[0].topLevelTargetAddress;
  const entity = (addr, stake) => (addr ? { addr, stake, unstakeDelaySec: stake } : undefined);
  const userOp = { sender, nonce: op.nonce ?? 0n, callData: op.callData ?? "0x", signature: "0x", factory: op.factory, paymaster: op.paymaster };
  const validation = {
    returnInfo: {},
    senderInfo: { addr: sender, stake: 0n, unstakeDelaySec: 0n },
    factoryInfo: entity(op.factory, staked ? 1n : 0n),
    paymasterInfo: entity(op.paymaster, staked === true ? 1n : 0n),
  };
  try {
    tracerResultParserV07(userOp, trace, validation, entryPoint);
    return "PASSES";
  } catch (e) {
    return "REFUSED: " + String(e.message);
  }
}
