// The rule checker of the pinned bundler (Pimlico's Alto) and the one way
// this kit asks it for a verdict; check-traces.mjs and check-run.mjs both
// use it.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decodeFunctionData, parseAbi, size, slice } from "viem";

const here = path.dirname(fileURLToPath(import.meta.url));
// the package's "exports" do not name the checker, so it is taken by path
const { tracerResultParserV07 } = await import(
  path.join(here, "node_modules/@pimlico/alto/esm/rpc/validation/TracerResultParserV07.js")
);

export const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
export const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100";

const handleOps = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "function handleOps(PackedUserOperation[] ops, address beneficiary)",
]);
// the EntryPoint's (v0.7) calls into the SenderCreator, the account and the paymaster
const CREATE_SENDER = "0x570e1a36";
const VALIDATE_USER_OP = "0x19822f7c";
const VALIDATE_PAYMASTER_USER_OP = "0x52b7512c";
const LEVEL_MAPS = ["opcodes", "access", "contractSize", "extCodeAccessInfo"];

// The operations of a handleOps call, each with its factory and paymaster:
// the first 20 bytes of its initCode and of its paymasterAndData.
export function operations(input) {
  const { args: [ops] } = decodeFunctionData({ abi: handleOps, data: input });
  const first20 = (bytes) => (size(bytes) >= 20 ? slice(bytes, 0, 20).toLowerCase() : undefined);
  return ops.map((p) => ({ sender: p.sender.toLowerCase(), nonce: p.nonce, callData: p.callData, factory: first20(p.initCode), paymaster: first20(p.paymasterAndData) }));
}

// Every hex string of a value, keys included, in lower case: the checker
// compares addresses, selectors and keccak inputs as text (#152).
function lower(value) {
  if (typeof value === "string") return /^0x[0-9a-f]*$/i.test(value) ? value.toLowerCase() : value;
  if (Array.isArray(value)) return value.map(lower);
  if (value === null || typeof value !== "object") return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    const key = lower(k);
    // merged, one of the two would go unchecked
    if (Object.hasOwn(out, key)) throw new Error(`not a validation trace: ${key} is named twice, in two cases`);
    out[key] = lower(v);
  }
  return out;
}

// A trace as the checker takes it: a copy, in lower case. What is not a trace
// is refused here with a message, not as a TypeError further in (#154).
export function ingest(recorded) {
  const levels = recorded?.callsFromEntryPoint;
  const isMap = (m) => m !== null && typeof m === "object" && !Array.isArray(m);
  const shaped =
    Array.isArray(levels) && levels.length > 0 && Array.isArray(recorded.calls) && Array.isArray(recorded.keccak) &&
    levels.every((l) => typeof l?.topLevelMethodSig === "string" && typeof l.topLevelTargetAddress === "string" && LEVEL_MAPS.every((k) => isMap(l[k])));
  if (!shaped) throw new Error(`not a validation trace: it needs callsFromEntryPoint (levels with ${LEVEL_MAPS.join(", ")}), calls and keccak`);
  return lower(recorded);
}

// The account, factory and paymaster of a trace that comes without its
// operation: whom the EntryPoint calls, the factory being whom its
// SenderCreator calls (#153).
export function entitiesOf(recorded) {
  const trace = ingest(recorded);
  const target = (sig) => trace.callsFromEntryPoint.find((l) => l.topLevelMethodSig === sig)?.topLevelTargetAddress;
  const creator = target(CREATE_SENDER);
  const op = {
    sender: target(VALIDATE_USER_OP),
    factory: creator && trace.calls.find((c) => c.type === "CALL" && c.from === creator)?.to,
    paymaster: target(VALIDATE_PAYMASTER_USER_OP),
  };
  if (!op.sender) throw new Error("not a validation trace: no call into validateUserOp");
  if (creator && !op.factory) throw new Error("not a validation trace: the SenderCreator calls no factory");
  return op;
}

// A trace file as check-traces.mjs takes it: a bare tracer result (as the
// bundler logs it), or one of check-run.mjs's, which carries the handleOps
// call the trace is of and its EntryPoint.
export function load(text) {
  let given;
  try {
    given = JSON.parse(text);
  } catch (e) {
    throw new Error(`not JSON (${e.message})`);
  }
  if (given?.input === undefined) return { trace: given, op: entitiesOf(given) };
  const ops = operations(given.input);
  if (ops.length !== 1) throw new Error(`a bundle of ${ops.length} operations: not checked`);
  ingest(given.trace);
  return { trace: given.trace, op: ops[0], entryPoint: given.entryPoint };
}

// The checker's verdict for a validation trace.
//   op:               { sender, factory?, paymaster? }; by default read from the trace
//   precompileAllowed the P-256 precompile (RIP-7212) is not taken for an
//                     un-deployed contract: a bundler set up for a network that has it
//   staked            true: the factory and the paymaster are taken as staked;
//                     "factory": the factory alone
export function verdict(recorded, { op, precompileAllowed = false, staked = false, entryPoint = ENTRY_POINT } = {}) {
  const trace = ingest(recorded);
  op = lower(op ?? entitiesOf(trace));
  entryPoint = entryPoint.toLowerCase();
  if (precompileAllowed) for (const level of trace.callsFromEntryPoint) delete level.contractSize[P256_PRECOMPILE];
  const entity = (addr, stake) => (addr ? { addr, stake, unstakeDelaySec: stake } : undefined);
  const userOp = { sender: op.sender, nonce: op.nonce ?? 0n, callData: op.callData ?? "0x", signature: "0x", factory: op.factory, paymaster: op.paymaster };
  const validation = {
    returnInfo: {},
    senderInfo: { addr: op.sender, stake: 0n, unstakeDelaySec: 0n },
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

// The verdicts check-traces.mjs records, by name.
const VERDICTS = {
  asItIs: {},
  precompileAllowed: { precompileAllowed: true },
  factoryStaked: { precompileAllowed: true, staked: "factory" },
};
export const judge = ({ trace, op, entryPoint }, name) => verdict(trace, { op, entryPoint, ...VERDICTS[name] });
